"""Asset Identity Engine — dedup, source merge, status upgrade, confidence."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.models import Asset, AssetEdge, AssetStatus, Organization, Project
from app.services.assets import compute_confidence, upsert_asset, upsert_edge


async def _project(session):
    org = Organization(name="O", slug=f"o-{uuid.uuid4().hex[:6]}")
    session.add(org)
    await session.flush()
    p = Project(org_id=org.id, name="P")
    session.add(p)
    await session.flush()
    return org, p


def test_confidence_curve():
    assert compute_confidence(sources=1, resolved=False, alive=False) == 55
    assert compute_confidence(sources=1, resolved=True, alive=True) == 95
    assert compute_confidence(sources=3, resolved=True, alive=False) == 99  # 40+45+15 capped
    assert compute_confidence(sources=5, resolved=True, alive=True) == 99  # capped


async def test_upsert_dedups_and_merges_sources(db_session):
    org, p = await _project(db_session)
    common = {"org_id": org.id, "project_id": p.id, "scan_id": None}

    await upsert_asset(
        db_session,
        **common,
        data={
            "type": "subdomain",
            "value": "API.example.com",
            "sources": ["subfinder:crtsh"],
            "in_scope": True,
        },
    )
    await upsert_asset(
        db_session,
        **common,
        data={
            "type": "subdomain",
            "value": "api.example.com",
            "sources": ["assetfinder"],
            "status": "resolved",
            "ip_addresses": ["203.0.113.5"],
        },
    )
    await db_session.commit()

    count = await db_session.scalar(select(func.count(Asset.id)))
    assert count == 1, "case-insensitive value should dedup to one asset"
    a = await db_session.scalar(
        select(Asset).where(Asset.value == "api.example.com").options(selectinload(Asset.sources))
    )
    assert {s.source for s in a.sources} == {"subfinder:crtsh", "assetfinder"}
    assert a.status == AssetStatus.resolved
    assert a.ip_addresses == ["203.0.113.5"]
    assert a.in_scope is True
    assert a.confidence >= 70


async def test_status_only_upgrades(db_session):
    org, p = await _project(db_session)
    common = {"org_id": org.id, "project_id": p.id, "scan_id": None}
    await upsert_asset(
        db_session, **common, data={"type": "subdomain", "value": "x.example.com", "status": "alive"}
    )
    await upsert_asset(
        db_session, **common, data={"type": "subdomain", "value": "x.example.com", "status": "unknown"}
    )
    await db_session.commit()
    got = await db_session.scalar(select(Asset))
    assert got.status == AssetStatus.alive, "status must not downgrade alive -> unknown"


async def test_edge_creates_both_endpoints(db_session):
    org, p = await _project(db_session)
    await upsert_edge(
        db_session,
        org_id=org.id,
        project_id=p.id,
        scan_id=None,
        data={
            "src_type": "subdomain",
            "src_value": "a.example.com",
            "dst_type": "ip",
            "dst_value": "203.0.113.9",
            "kind": "resolves_to",
        },
    )
    await db_session.commit()
    assert await db_session.scalar(select(func.count(Asset.id))) == 2
    # idempotent
    await upsert_edge(
        db_session,
        org_id=org.id,
        project_id=p.id,
        scan_id=None,
        data={
            "src_type": "subdomain",
            "src_value": "a.example.com",
            "dst_type": "ip",
            "dst_value": "203.0.113.9",
            "kind": "resolves_to",
        },
    )
    await db_session.commit()
    assert await db_session.scalar(select(func.count(AssetEdge.id))) == 1


# ── M3: vhosts & endpoints ────────────────────────────────────────────────

from app.models import Endpoint, VHost, VHostClass  # noqa: E402
from app.services.assets import upsert_endpoint, upsert_vhost  # noqa: E402


async def test_infra_enrichment_maps_to_columns(db_session):
    org, p = await _project(db_session)
    await upsert_asset(
        db_session,
        org_id=org.id,
        project_id=p.id,
        scan_id=None,
        data={
            "type": "ip",
            "value": "203.0.113.10",
            "status": "resolved",
            "sources": ["cymru"],
            "infra": {
                "asn": "AS13335",
                "asn_org": "CLOUDFLARENET",
                "netblock": "203.0.113.0/24",
                "geo_country": "US",
                "ptr": "host.example.test",
                "cloud_provider": "Cloudflare",
            },
        },
    )
    await db_session.commit()
    a = await db_session.scalar(select(Asset).where(Asset.value == "203.0.113.10"))
    assert a.asn == "AS13335"
    assert a.asn_org == "CLOUDFLARENET"
    assert a.netblock == "203.0.113.0/24"
    assert a.cloud_provider == "Cloudflare"
    assert a.geo_country == "US"


async def test_vhost_upsert_and_classification(db_session):
    org, p = await _project(db_session)
    common = {"org_id": org.id, "project_id": p.id, "scan_id": None}
    await upsert_vhost(
        db_session,
        **common,
        data={
            "ip": "203.0.113.5",
            "hostname": "Internal.example.com",
            "classification": "potential_internal",
            "status_code": 200,
            "response_bytes": 4096,
            "baseline_status": 404,
            "baseline_bytes": 300,
            "similarity": 0.2,
        },
    )
    # re-emit → update, not duplicate
    await upsert_vhost(
        db_session,
        **common,
        data={
            "ip": "203.0.113.5",
            "hostname": "internal.example.com",
            "classification": "potential_internal",
            "status_code": 200,
        },
    )
    await db_session.commit()
    rows = (await db_session.execute(select(VHost))).scalars().all()
    assert len(rows) == 1
    assert rows[0].classification == VHostClass.potential_internal
    assert rows[0].hostname == "internal.example.com"


async def test_endpoint_dedup_by_normalized_url(db_session):
    org, p = await _project(db_session)
    common = {"org_id": org.id, "project_id": p.id, "scan_id": None}
    for sample in (
        "https://api.example.com/api/users/1?page=2",
        "https://api.example.com/api/users/9999?page=7",
    ):
        await upsert_endpoint(
            db_session,
            **common,
            data={
                "method": "GET",
                "host": "api.example.com",
                "path": "/api/users/1",
                "normalized_url": "api.example.com/api/users/{id}?page",
                "sample_url": sample,
                "query_keys": ["page"],
                "params": [
                    {"name": "id", "kind": "int", "in": "path"},
                    {"name": "page", "kind": "int", "in": "query"},
                ],
                "tags": ["api"],
                "sources": ["katana"],
                "in_scope": True,
            },
        )
    await db_session.commit()
    rows = (await db_session.execute(select(Endpoint))).scalars().all()
    assert len(rows) == 1, "two sample URLs with the same signature must dedup"
    assert set(rows[0].sources) == {"katana"}
    assert rows[0].tags == ["api"]


async def test_endpoint_wayback_timestamps_track_min_max(db_session):
    org, p = await _project(db_session)
    common = {"org_id": org.id, "project_id": p.id, "scan_id": None}
    base = {
        "method": "GET",
        "host": "old.example.com",
        "path": "/legacy.php",
        "normalized_url": "old.example.com/legacy.php?id",
        "sample_url": "https://old.example.com/legacy.php?id=1",
        "query_keys": ["id"],
        "params": [{"name": "id", "kind": "int", "in": "query"}],
        "tags": [],
        "sources": ["wayback"],
        "in_scope": True,
    }
    for ts in ("2020-06-15T00:00:00Z", "2018-01-01T00:00:00Z", "2022-11-30T00:00:00Z"):
        await upsert_endpoint(db_session, **common, data={**base, "wayback_observed_at": ts})
    await db_session.commit()
    rows = (await db_session.execute(select(Endpoint))).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.wayback_first_seen.year == 2018
    assert row.wayback_last_seen.year == 2022


# ── M4: secrets & repositories ────────────────────────────────────────────

from app.core.crypto import decrypt  # noqa: E402
from app.models import Repository, Secret, SecretStatus  # noqa: E402
from app.services.assets import upsert_repository, upsert_secret  # noqa: E402


async def test_secret_dedup_and_encryption(db_session):
    org, p = await _project(db_session)
    common = {"org_id": org.id, "project_id": p.id, "scan_id": None}
    data = {
        "fingerprint": "abc123",
        "detector_type": "AWSAccessKeyID",
        "detector": "custom",
        "source_kind": "js",
        "source": "https://x/app.js",
        "location": "js:https://x/app.js:42",
        "value": "AKIAIOSFODNN7EXAMPLE",
        "severity": "high",
        "confidence": 60,
    }
    await upsert_secret(db_session, **common, data=data)
    await upsert_secret(db_session, **common, data={**data, "confidence": 80})
    await db_session.commit()

    rows = (await db_session.execute(select(Secret))).scalars().all()
    assert len(rows) == 1, "same fingerprint must dedup"
    s = rows[0]
    assert s.value_preview == "AKIAIOSFODNN7EXAMPLE"
    # still encrypted at rest (DB/backup-leak protection) even though the API
    # returns it to authorized operators
    assert s.value_enc is not None and "AKIA" not in s.value_enc
    assert decrypt(s.value_enc) == "AKIAIOSFODNN7EXAMPLE"
    assert s.status == SecretStatus.unverified
    assert s.confidence == 80


async def test_secret_returns_full_value_to_authorized(admin_client):
    """The /secrets endpoint returns the full value (masking defeats validation),
    but the ciphertext column itself is never serialized."""
    from app.db import SessionLocal

    r = await admin_client.post("/api/projects", json={"name": "Secret Proj"})
    pid = r.json()["id"]
    me = (await admin_client.get("/api/auth/me")).json()

    async with SessionLocal() as s:
        await upsert_secret(
            s,
            org_id=uuid.UUID(me["active_org"]),
            project_id=uuid.UUID(pid),
            scan_id=None,
            data={
                "fingerprint": "fp1",
                "detector_type": "JWT",
                "value": "eyJhbGciOiJIUzI1NiJ9.payload.sig",
                "severity": "medium",
            },
        )
        await s.commit()

    r = await admin_client.get(f"/api/projects/{pid}/secrets")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    assert body[0]["value"] == "eyJhbGciOiJIUzI1NiJ9.payload.sig"
    assert body[0]["has_encrypted_value"] is True
    assert "value_enc" not in body[0]


async def test_repository_upsert(db_session):
    org, p = await _project(db_session)
    common = {"org_id": org.id, "project_id": p.id, "scan_id": None}
    await upsert_repository(
        db_session,
        **common,
        data={
            "provider": "github",
            "full_name": "acme/api",
            "url": "https://github.com/acme/api",
            "iac_files": ["docker", "terraform"],
            "matched_terms": ["acme.com"],
            "in_scope": True,
        },
    )
    await upsert_repository(
        db_session, **common, data={"provider": "github", "full_name": "acme/api", "stars": 5}
    )
    await db_session.commit()
    rows = (await db_session.execute(select(Repository))).scalars().all()
    assert len(rows) == 1
    assert rows[0].iac_files == ["docker", "terraform"]
    assert rows[0].stars == 5


# ── M5: ports & findings + verification engine ───────────────────────────

from app.models import Finding, FindingStatus, Port  # noqa: E402
from app.services.findings import upsert_finding, upsert_port, verify_finding  # noqa: E402


async def test_port_upsert_dedup_and_service_merge(db_session):
    org, p = await _project(db_session)
    common = {"org_id": org.id, "project_id": p.id, "scan_id": None}
    await upsert_port(
        db_session, **common, data={"ip": "203.0.113.5", "port": 22, "protocol": "tcp", "service": "ssh"}
    )
    # re-emit with product/version, and a bare re-emit must not wipe them
    await upsert_port(
        db_session,
        **common,
        data={"ip": "203.0.113.5", "port": 22, "protocol": "tcp", "product": "OpenSSH", "version": "8.9p1"},
    )
    await upsert_port(db_session, **common, data={"ip": "203.0.113.5", "port": 22, "protocol": "tcp"})
    await db_session.commit()
    rows = (await db_session.execute(select(Port))).scalars().all()
    assert len(rows) == 1
    assert rows[0].service == "ssh" and rows[0].product == "OpenSSH" and rows[0].version == "8.9p1"


async def test_finding_verification_engine(db_session):
    org, p = await _project(db_session)
    common = {"org_id": org.id, "project_id": p.id, "scan_id": None}

    # 1. low-signal info template → needs_review, low confidence
    await upsert_finding(
        db_session,
        **common,
        data={
            "fingerprint": "f-noise",
            "template_id": "http-missing-security-headers",
            "severity": "info",
            "host": "app.acme.com",
            "matched_at": "https://app.acme.com/",
            "normalized_path": "/",
            "tags": ["misconfig"],
            "level": "passive",
        },
    )
    # 2. critical CVE with OOB confirmation → confirmed, high confidence
    await upsert_finding(
        db_session,
        **common,
        data={
            "fingerprint": "f-log4j",
            "template_id": "CVE-2021-44228",
            "name": "Log4j RCE",
            "severity": "critical",
            "host": "api.acme.com",
            "matched_at": "https://api.acme.com/x",
            "normalized_path": "/x",
            "cve": ["CVE-2021-44228"],
            "oob_confirmed": True,
            "level": "safe_verify",
            "matcher_name": "dns",
        },
    )
    # 3. medium exposure, matcher + extracted → probable
    await upsert_finding(
        db_session,
        **common,
        data={
            "fingerprint": "f-exp",
            "template_id": "phpinfo-files",
            "severity": "medium",
            "host": "api.acme.com",
            "matched_at": "https://api.acme.com/info.php",
            "normalized_path": "/info.php",
            "matcher_name": "word",
            "extracted": ["PHP 7.4"],
            "level": "safe_verify",
        },
    )
    await db_session.commit()

    rows = {f.fingerprint: f for f in (await db_session.execute(select(Finding))).scalars().all()}
    assert rows["f-noise"].status == FindingStatus.needs_review
    assert rows["f-noise"].confidence <= 40
    assert rows["f-log4j"].status == FindingStatus.confirmed
    assert rows["f-log4j"].verification == "oob_confirmed"
    assert rows["f-log4j"].confidence >= 85
    assert rows["f-exp"].status == FindingStatus.probable

    # a human triage decision must survive a later automated re-emit
    rows["f-exp"].status = FindingStatus.false_positive
    await db_session.commit()
    await upsert_finding(
        db_session,
        **common,
        data={
            "fingerprint": "f-exp",
            "template_id": "phpinfo-files",
            "severity": "medium",
            "host": "api.acme.com",
            "matched_at": "https://api.acme.com/info.php",
            "normalized_path": "/info.php",
            "level": "safe_verify",
        },
    )
    await db_session.commit()
    f = await db_session.scalar(select(Finding).where(Finding.fingerprint == "f-exp"))
    assert f.status == FindingStatus.false_positive


def test_verify_finding_scoring():
    from app.models import FindingSeverity

    score, status, verification, _ = verify_finding(
        {"template_id": "tech-detect", "severity": "info", "tags": ["tech"], "level": "passive"},
        FindingSeverity.info,
    )
    assert score <= 35 and status == FindingStatus.needs_review

    score, status, verification, _ = verify_finding(
        {"template_id": "some-rce", "severity": "high", "oob_confirmed": True, "level": "safe_verify"},
        FindingSeverity.high,
    )
    assert verification == "oob_confirmed" and status == FindingStatus.confirmed


def test_contains_filtered_json_columns_compile_to_postgres_containment():
    """Regression test for a real production 500: Endpoint.tags/.sources and
    Asset.technologies are filtered with `.contains()` in
    app/routers/assets.py (`tag=`/`source=`/`technology=` query params).
    SQLAlchemy resolves `.contains()`'s SQL from the column's *declared*
    type — on a plain `JSON` column (or one JSONB-typed only via
    `.with_variant`, which does NOT change the resolved comparator) it
    silently compiles to `col LIKE '%' || value || '%'`, which Postgres
    rejects outright for a json/jsonb operand (`operator does not exist`).
    The columns must be declared as real `postgresql.JSONB` so this
    compiles to the `@>` containment operator instead. This doesn't need a
    live Postgres connection — compiling the statement against the
    postgresql dialect is enough to catch a regression back to plain JSON
    (or another `.with_variant` mistake) without running against SQLite,
    which can't distinguish the two at all.
    """
    from sqlalchemy import select
    from sqlalchemy.dialects import postgresql as pg_dialect

    from app.models import Asset, Endpoint

    for stmt in (
        select(Endpoint).where(Endpoint.tags.contains(["api"])),
        select(Endpoint).where(Endpoint.sources.contains(["wayback"])),
        select(Asset).where(Asset.technologies.contains(["nginx"])),
    ):
        compiled = str(stmt.compile(dialect=pg_dialect.dialect()))
        assert "@>" in compiled, f"expected Postgres @> containment, got: {compiled}"
        assert "LIKE" not in compiled.upper(), f"regressed to LIKE-based contains(): {compiled}"
