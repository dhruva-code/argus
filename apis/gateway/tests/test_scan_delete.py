"""Deleting finished scans, with and without purging the data they introduced."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select

from app.models import (
    Asset,
    Finding,
    JobEvent,
    JobStatus,
    Organization,
    Project,
    ScanJob,
)
from app.services.assets import upsert_asset
from app.services.findings import upsert_finding
from app.services.scans import delete_scans


async def _project(session):
    org = Organization(name="O", slug=f"o-{uuid.uuid4().hex[:6]}")
    session.add(org)
    await session.flush()
    p = Project(org_id=org.id, name="P")
    session.add(p)
    await session.flush()
    return org, p


async def _job(session, org, p, status=JobStatus.completed):
    j = ScanJob(org_id=org.id, project_id=p.id, type="recon.scan", status=status, params={}, rate_limits={})
    session.add(j)
    await session.flush()
    return j


async def _count(session, model, *where):
    return await session.scalar(select(func.count()).select_from(model).where(*where))


async def test_delete_scan_keeps_inventory_by_default(db_session):
    org, p = await _project(db_session)
    j1 = await _job(db_session, org, p)
    j2 = await _job(db_session, org, p)
    j1_id, j2_id = j1.id, j2.id
    db_session.add(JobEvent(job_id=j1_id, type="log", level="INFO", message="hi", data={}))
    await upsert_asset(db_session, org_id=org.id, project_id=p.id, scan_id=j1_id,
                       data={"type": "domain", "value": "a.com", "status": "alive"})
    await db_session.commit()

    res = await delete_scans(db_session, org_id=org.id, jobs=[j1], purge_data=False)
    await db_session.commit()

    assert res["deleted"] == 1
    assert await _count(db_session, ScanJob, ScanJob.id == j1_id) == 0
    assert await _count(db_session, ScanJob, ScanJob.id == j2_id) == 1
    assert await _count(db_session, JobEvent, JobEvent.job_id == j1_id) == 0
    # inventory stays; scan ref nulled
    assert await _count(db_session, Asset, Asset.value == "a.com") == 1
    assert await db_session.scalar(select(Asset.first_seen_scan).where(Asset.value == "a.com")) is None


async def test_delete_scan_with_purge_removes_what_it_introduced(db_session):
    org, p = await _project(db_session)
    j1 = await _job(db_session, org, p)
    j2 = await _job(db_session, org, p)
    j1_id = j1.id
    await upsert_asset(db_session, org_id=org.id, project_id=p.id, scan_id=j1_id,
                       data={"type": "domain", "value": "old.com", "status": "alive"})
    await upsert_asset(db_session, org_id=org.id, project_id=p.id, scan_id=j2.id,
                       data={"type": "domain", "value": "new.com", "status": "alive"})
    await upsert_finding(db_session, org_id=org.id, project_id=p.id, scan_id=j1_id, data={
        "fingerprint": "fp1", "template_id": "phpinfo-files", "severity": "low",
        "host": "old.com", "matched_at": "http://old.com/i.php", "normalized_path": "/i.php",
    })
    await db_session.commit()

    res = await delete_scans(db_session, org_id=org.id, jobs=[j1], purge_data=True)
    await db_session.commit()

    assert res["deleted"] == 1
    assert res["purged"].get("assets") == 1
    assert res["purged"].get("findings") == 1
    assert await _count(db_session, Asset, Asset.value == "old.com") == 0
    assert await _count(db_session, Asset, Asset.value == "new.com") == 1
    assert await _count(db_session, Finding) == 0


async def test_delete_scans_api_skips_running(admin_client):
    from app.db import SessionLocal

    r = await admin_client.post("/api/projects", json={"name": "Del Proj"})
    pid = r.json()["id"]
    me = (await admin_client.get("/api/auth/me")).json()

    async with SessionLocal() as s:
        org_id = uuid.UUID(me["active_org"])
        done = ScanJob(org_id=org_id, project_id=uuid.UUID(pid), type="recon.scan",
                       status=JobStatus.completed, params={}, rate_limits={})
        run = ScanJob(org_id=org_id, project_id=uuid.UUID(pid), type="recon.scan",
                      status=JobStatus.running, params={}, rate_limits={})
        s.add_all([done, run])
        await s.commit()
        done_id, run_id = str(done.id), str(run.id)

    r = await admin_client.request(
        "POST", f"/api/projects/{pid}/scans/delete",
        json={"job_ids": [done_id, run_id]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["deleted"] == 1
    assert run_id in body["skipped"]

    # the finished one is gone, the running one stays
    async with SessionLocal() as s:
        assert await s.get(ScanJob, uuid.UUID(done_id)) is None
        assert await s.get(ScanJob, uuid.UUID(run_id)) is not None
