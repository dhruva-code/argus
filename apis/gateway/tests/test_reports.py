"""M6: priority scoring, report generation, exposure delta."""

from __future__ import annotations

import uuid

from app.models import (
    FindingSeverity,
    FindingStatus,
    JobStatus,
    Organization,
    Project,
    RiskProfile,
    ScanJob,
)
from app.services.findings import upsert_finding
from app.services.monitoring import exposure_delta
from app.services.priority import finding_priority
from app.services.reports import render_report


class _F:
    def __init__(self, **kw):
        self.__dict__.update(
            {
                "severity": FindingSeverity.high,
                "status": FindingStatus.confirmed,
                "confidence": 90,
                "cvss_score": 0,
            }
        )
        self.__dict__.update(kw)


def test_priority_scoring_ordering():
    high_conf_high = _F(severity=FindingSeverity.high, confidence=90, status=FindingStatus.confirmed)
    low_conf_crit = _F(severity=FindingSeverity.critical, confidence=25, status=FindingStatus.needs_review)
    fp = _F(severity=FindingSeverity.critical, confidence=99, status=FindingStatus.false_positive)

    a = finding_priority(high_conf_high, RiskProfile.moderate)
    b = finding_priority(low_conf_crit, RiskProfile.moderate)
    assert a > b > 0
    assert finding_priority(fp, RiskProfile.moderate) == 0
    # risk profile scales it
    assert finding_priority(high_conf_high, RiskProfile.critical) > a


async def _project(session, risk=RiskProfile.moderate):
    org = Organization(name="O", slug=f"o-{uuid.uuid4().hex[:6]}")
    session.add(org)
    await session.flush()
    p = Project(org_id=org.id, name="Acme", program_name="Acme BB", risk_profile=risk)
    session.add(p)
    await session.flush()
    return org, p


async def test_report_formats(db_session):
    org, p = await _project(db_session)
    await upsert_finding(db_session, org_id=org.id, project_id=p.id, scan_id=None, data={
        "fingerprint": "f1", "template_id": "wordpress-db-exposure", "name": "WP DB exposure",
        "severity": "high", "host": "app.acme.com", "matched_at": "https://app.acme.com/db.sql",
        "normalized_path": "/db.sql", "cve": [], "level": "safe_verify", "matcher_name": "word",
    })
    await db_session.commit()

    for fmt in ("json", "md", "csv", "html"):
        body, media, filename = await render_report(db_session, p, fmt)
        assert body and filename.endswith(f".{fmt}")
        assert "WP DB exposure" in body or "wordpress-db-exposure" in body
    md, _, _ = await render_report(db_session, p, "md")
    assert "# Security assessment — Acme" in md
    pdf, media, filename = await render_report(db_session, p, "pdf")
    assert isinstance(pdf, bytes) and pdf[:5] == b"%PDF-" and filename.endswith(".pdf")


async def test_unified_finding_engine(db_session):
    """secrets, sensitive paths and dangerous exposed services become findings."""
    from sqlalchemy import select

    from app.models import Finding
    from app.services.assets import upsert_endpoint, upsert_secret
    from app.services.findings import upsert_port

    org, p = await _project(db_session)
    common = {"org_id": org.id, "project_id": p.id, "scan_id": None}

    await upsert_secret(db_session, **common, data={
        "fingerprint": "s1", "detector_type": "AWSAccessKeyID", "severity": "high",
        "source_kind": "js", "source": "https://app.acme.com/a.js", "location": "a.js:12",
        "value": "AKIAIOSFODNN7EXAMPLE",
    })
    await upsert_endpoint(db_session, **common, data={
        "method": "GET", "normalized_url": "app.acme.com/.git/config", "host": "app.acme.com",
        "path": "/.git/config", "sample_url": "https://app.acme.com/.git/config",
        "sensitivity": "critical", "sensitivity_reason": "Exposed .git",
    })
    await upsert_port(db_session, **common, data={
        "ip": "203.0.113.9", "port": 6379, "protocol": "tcp", "service": "redis",
        "hostnames": ["cache.acme.com"],
    })
    await db_session.commit()

    fnds = {f.template_id: f for f in (await db_session.execute(select(Finding))).scalars().all()}
    assert "exposed-secret-awsaccesskeyid" in fnds
    assert "sensitive-path-critical" in fnds
    assert "exposed-service-redis" in fnds
    assert fnds["exposed-service-redis"].severity.value == "critical"
    assert "derived" in fnds["exposed-secret-awsaccesskeyid"].tags


async def test_exposure_delta(db_session):
    from datetime import UTC, datetime, timedelta

    org, p = await _project(db_session)
    t0 = datetime.now(UTC) - timedelta(hours=2)
    prev = ScanJob(org_id=org.id, project_id=p.id, type="recon.scan", status=JobStatus.completed,
                   params={}, rate_limits={}, finished_at=t0)
    cur = ScanJob(org_id=org.id, project_id=p.id, type="recon.scan", status=JobStatus.completed,
                  params={}, rate_limits={}, finished_at=datetime.now(UTC))
    db_session.add_all([prev, cur])
    await db_session.flush()

    await upsert_finding(db_session, org_id=org.id, project_id=p.id, scan_id=cur.id, data={
        "fingerprint": "new1", "template_id": "phpinfo-files", "severity": "low",
        "host": "x.acme.com", "matched_at": "http://x.acme.com/i.php", "normalized_path": "/i.php",
    })
    await db_session.commit()

    delta = await exposure_delta(db_session, p.id)
    assert delta["has_baseline"] is True
    assert delta["counts"]["new_findings"] >= 1
    assert any(f["host"] == "x.acme.com" for f in delta["new"]["findings"])


async def test_ai_heuristic_summary(db_session):
    from sqlalchemy import select

    from app.models import Finding
    from app.services.ai import analyse

    org, p = await _project(db_session)
    for i, (sev, host) in enumerate([("critical", "a.com"), ("high", "a.com"), ("low", "b.com")]):
        await upsert_finding(db_session, org_id=org.id, project_id=p.id, scan_id=None, data={
            "fingerprint": f"f{i}", "template_id": "t" + str(i % 2), "severity": sev,
            "host": host, "matched_at": f"http://{host}/", "normalized_path": "/",
        })
    await db_session.commit()
    findings = (await db_session.execute(select(Finding))).scalars().all()
    out = await analyse(db_session, org.id, p, findings)
    assert out["engine"] == "heuristic"
    assert "actionable finding" in out["summary"]
    assert out["recommended_order"][0]["severity"] == "critical"
