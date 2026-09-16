"""AI triage for findings & secrets: fingerprint caching, heuristic
classification, background-task wiring, and default-view suppression."""

from __future__ import annotations

import uuid

from app.models import (
    Finding,
    FindingSeverity,
    FindingStatus,
    Organization,
    Project,
    Secret,
    SecretStatus,
    Sensitivity,
)
from app.services import ai
from app.services.assets import upsert_secret
from app.services.events import _run_finding_triage, _run_secret_triage
from app.services.findings import upsert_finding


async def _project(session):
    org = Organization(name="O", slug=f"o-{uuid.uuid4().hex[:6]}")
    session.add(org)
    await session.flush()
    p = Project(org_id=org.id, name="P")
    session.add(p)
    await session.flush()
    return org, p


# ── fingerprinting ──────────────────────────────────────────────────────


def test_finding_fingerprint_stable_and_sensitive_to_evidence():
    f1 = Finding(
        template_id="t1",
        name="XSS",
        severity=FindingSeverity.high,
        status=FindingStatus.open,
        confidence=70,
        verification="unverified",
        engine="nuclei",
        host="a.example.com",
        normalized_path="/x",
        tags=[],
        cwe=[],
        cve=[],
        description="d",
        remediation="r",
        response_excerpt="",
        request="",
    )
    fp1 = ai.finding_fingerprint(f1)
    fp2 = ai.finding_fingerprint(f1)
    assert fp1 == fp2, "same evidence must hash identically"

    f1.confidence = 90
    assert ai.finding_fingerprint(f1) != fp1, "changed evidence must change the fingerprint"


def test_secret_fingerprint_stable_and_sensitive_to_evidence():
    s1 = Secret(
        detector_type="AWSAccessKeyID",
        detector="custom",
        source_kind="js",
        source="https://x/app.js",
        location="js:https://x/app.js:1",
        value_preview="AKIAEXAMPLE",
        verified=False,
        confidence=60,
        severity=Sensitivity.high,
    )
    fp1 = ai.secret_fingerprint(s1)
    assert fp1 == ai.secret_fingerprint(s1)
    s1.verified = True
    assert ai.secret_fingerprint(s1) != fp1


# ── heuristic secret classification (no AI provider configured) ──────────


def test_heuristic_secret_analysis_verified_is_true_positive():
    s = Secret(detector_type="AWS", value_preview="AKIAREALLOOKING1234", verified=True, confidence=90)
    out = ai._heuristic_secret_analysis(s)
    assert out["classification"] == "true_positive"
    assert out["engine"] == "heuristic"


def test_heuristic_secret_analysis_placeholder_is_false_positive():
    s = Secret(detector_type="Generic", value_preview="example_api_key_1234", verified=False, confidence=60)
    out = ai._heuristic_secret_analysis(s)
    assert out["classification"] == "false_positive"


def test_heuristic_secret_analysis_confidence_bands():
    hi = Secret(detector_type="Generic", value_preview="a9f7c2e1b4d6890f", verified=False, confidence=85)
    mid = Secret(detector_type="Generic", value_preview="a9f7c2e1b4d6890f", verified=False, confidence=60)
    lo = Secret(detector_type="Generic", value_preview="a9f7c2e1b4d6890f", verified=False, confidence=10)
    assert ai._heuristic_secret_analysis(hi)["classification"] == "likely"
    assert ai._heuristic_secret_analysis(mid)["classification"] == "potential"
    assert ai._heuristic_secret_analysis(lo)["classification"] == "potential"


# ── end-to-end triage against a real DB row (AI unconfigured -> heuristic) ─


async def test_finding_triage_persists_and_caches(db_session):
    org, p = await _project(db_session)
    row = await upsert_finding(
        db_session,
        org_id=org.id,
        project_id=p.id,
        scan_id=None,
        data={
            "fingerprint": "fp-triage-1",
            "template_id": "t1",
            "severity": "low",
            "host": "a.example.com",
            "normalized_path": "/x",
        },
    )
    await db_session.commit()
    finding_id = row.id

    await _run_finding_triage(finding_id, org.id)

    refreshed = await db_session.get(Finding, finding_id)
    await db_session.refresh(refreshed)
    assert refreshed.ai_engine == "heuristic"
    assert refreshed.ai_false_positive_likelihood in ("low", "medium", "high")
    assert refreshed.ai_analyzed_at is not None
    assert refreshed.ai_fingerprint == ai.finding_fingerprint(refreshed)
    first_analyzed_at = refreshed.ai_analyzed_at

    # Unchanged evidence -> the cache check must skip re-analysis entirely
    # (not just re-store the same result) — verify by monkeypatching
    # analyse_finding to blow up if it's ever called again.
    async def _boom(*a, **kw):
        raise AssertionError("analyse_finding must not be called when evidence is unchanged")

    orig = ai.analyse_finding
    ai.analyse_finding = _boom
    try:
        await _run_finding_triage(finding_id, org.id)
    finally:
        ai.analyse_finding = orig

    refreshed2 = await db_session.get(Finding, finding_id)
    await db_session.refresh(refreshed2)
    assert refreshed2.ai_analyzed_at == first_analyzed_at


async def test_secret_triage_persists_and_caches(db_session):
    org, p = await _project(db_session)
    row = await upsert_secret(
        db_session,
        org_id=org.id,
        project_id=p.id,
        scan_id=None,
        data={
            "fingerprint": "fp-secret-triage-1",
            "detector_type": "AWSAccessKeyID",
            "value": "AKIAIOSFODNN7REALISH",
            "severity": "high",
            "confidence": 90,
        },
    )
    await db_session.commit()
    secret_id = row.id

    await _run_secret_triage(secret_id, org.id)

    refreshed = await db_session.get(Secret, secret_id)
    await db_session.refresh(refreshed)
    assert refreshed.ai_engine == "heuristic"
    assert refreshed.ai_classification in ("true_positive", "likely", "potential", "false_positive")
    assert refreshed.ai_analyzed_at is not None
    assert refreshed.ai_fingerprint == ai.secret_fingerprint(refreshed)

    # never touches detector-owned fields
    assert refreshed.status == SecretStatus.unverified
    assert refreshed.confidence == 90


async def test_finding_triage_never_overwrites_raw_evidence(db_session):
    org, p = await _project(db_session)
    row = await upsert_finding(
        db_session,
        org_id=org.id,
        project_id=p.id,
        scan_id=None,
        data={
            "fingerprint": "fp-triage-2",
            "template_id": "sqli-1",
            "severity": "critical",
            "host": "b.example.com",
            "normalized_path": "/y",
            "verification_tier": "verified",
        },
    )
    await db_session.commit()
    confidence_before = row.confidence
    status_before = row.status
    verification_before = row.verification

    await _run_finding_triage(row.id, org.id)

    refreshed = await db_session.get(Finding, row.id)
    await db_session.refresh(refreshed)
    assert refreshed.confidence == confidence_before
    assert refreshed.status == status_before
    assert refreshed.verification == verification_before


# ── default-view suppression via the /findings and /secrets routers ──────


async def test_findings_router_suppresses_ai_high_fp_by_default(admin_client):
    r = await admin_client.post("/api/projects", json={"name": "Triage Proj"})
    pid = r.json()["id"]
    me = (await admin_client.get("/api/auth/me")).json()
    org_id = uuid.UUID(me["active_org"])

    from app.db import SessionLocal

    async with SessionLocal() as s:
        row = await upsert_finding(
            s,
            org_id=org_id,
            project_id=uuid.UUID(pid),
            scan_id=None,
            data={
                "fingerprint": "fp-suppress-1",
                "template_id": "t1",
                "severity": "low",
                "host": "c.example.com",
                "normalized_path": "/z",
            },
        )
        await s.commit()
        finding_id = row.id
        # simulate a high-FP-likelihood AI assessment on a not-independently
        # -verified finding, as the background triage task would store it
        row2 = await s.get(Finding, finding_id)
        row2.ai_false_positive_likelihood = "high"
        row2.ai_engine = "heuristic"
        await s.commit()

    default_view = await admin_client.get(f"/api/projects/{pid}/findings")
    assert default_view.status_code == 200
    assert all(f["id"] != str(finding_id) for f in default_view.json())

    full_view = await admin_client.get(f"/api/projects/{pid}/findings?include_suppressed=true")
    assert any(f["id"] == str(finding_id) for f in full_view.json())

    summary = await admin_client.get(f"/api/projects/{pid}/findings/summary")
    assert summary.json()["suppressed_total"] == 1


async def test_secrets_router_suppresses_ai_false_positive_by_default(admin_client):
    r = await admin_client.post("/api/projects", json={"name": "Triage Proj 2"})
    pid = r.json()["id"]
    me = (await admin_client.get("/api/auth/me")).json()
    org_id = uuid.UUID(me["active_org"])

    from app.db import SessionLocal

    async with SessionLocal() as s:
        row = await upsert_secret(
            s,
            org_id=org_id,
            project_id=uuid.UUID(pid),
            scan_id=None,
            data={
                "fingerprint": "fp-secret-suppress-1",
                "detector_type": "Generic",
                "value": "example_placeholder_value",
                "severity": "low",
            },
        )
        await s.commit()
        secret_id = row.id
        row2 = await s.get(Secret, secret_id)
        row2.ai_classification = "false_positive"
        row2.ai_engine = "heuristic"
        await s.commit()

    default_view = await admin_client.get(f"/api/projects/{pid}/secrets")
    assert all(sec["id"] != str(secret_id) for sec in default_view.json())

    full_view = await admin_client.get(f"/api/projects/{pid}/secrets?include_suppressed=true")
    assert any(sec["id"] == str(secret_id) for sec in full_view.json())

    summary = await admin_client.get(f"/api/projects/{pid}/secrets/summary")
    assert summary.json()["suppressed_total"] == 1


async def test_explicit_status_filter_bypasses_default_suppression(admin_client):
    """Requesting status=false_positive explicitly is itself a deliberate
    choice — it must not be stripped right back out by the default
    suppression filter."""
    r = await admin_client.post("/api/projects", json={"name": "Triage Proj 3"})
    pid = r.json()["id"]
    me = (await admin_client.get("/api/auth/me")).json()
    org_id = uuid.UUID(me["active_org"])

    from app.db import SessionLocal

    async with SessionLocal() as s:
        row = await upsert_finding(
            s,
            org_id=org_id,
            project_id=uuid.UUID(pid),
            scan_id=None,
            data={
                "fingerprint": "fp-explicit-1",
                "template_id": "t1",
                "severity": "low",
                "host": "d.example.com",
                "normalized_path": "/w",
            },
        )
        finding_id = row.id
        row.status = FindingStatus.false_positive
        await s.commit()

    r2 = await admin_client.get(f"/api/projects/{pid}/findings?status=false_positive")
    assert any(f["id"] == str(finding_id) for f in r2.json())
