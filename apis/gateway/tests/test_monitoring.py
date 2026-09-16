"""Scheduler due-detection + notification dispatch (M6)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.models import JobStatus, Organization, Project, ScanJob, ScopeEffect, ScopeMatcher, ScopeRule
from app.services.notify import notify_scan_complete
from app.services.scheduler import _due_projects


async def _proj(session, cron=None):
    org = Organization(name="O", slug=f"o-{uuid.uuid4().hex[:6]}")
    session.add(org)
    await session.flush()
    p = Project(org_id=org.id, name="Sched", schedule_cron=cron)
    session.add(p)
    await session.flush()
    session.add(
        ScopeRule(
            project_id=p.id,
            position=0,
            effect=ScopeEffect.allow,
            matcher=ScopeMatcher.domain,
            value="example.com",
        )
    )
    await session.flush()
    return org, p


async def test_scheduler_detects_due_project(db_session):
    org, p = await _proj(db_session, cron="*/5 * * * *")
    # last scan 20 min ago → due
    old = ScanJob(
        org_id=org.id,
        project_id=p.id,
        type="recon.scan",
        status=JobStatus.completed,
        params={},
        rate_limits={},
        created_at=datetime.now(UTC) - timedelta(minutes=20),
    )
    db_session.add(old)
    await db_session.commit()

    due = await _due_projects(db_session)
    assert p.id in {d.id for d in due}


async def test_scheduler_skips_recently_scanned(db_session):
    org, p = await _proj(db_session, cron="0 3 * * *")  # daily 03:00
    recent = ScanJob(
        org_id=org.id,
        project_id=p.id,
        type="recon.scan",
        status=JobStatus.completed,
        params={},
        rate_limits={},
        created_at=datetime.now(UTC) - timedelta(minutes=2),
    )
    db_session.add(recent)
    await db_session.commit()

    due = await _due_projects(db_session)
    assert p.id not in {d.id for d in due}


async def test_notify_dispatch_to_webhook(db_session, monkeypatch):
    org, p = await _proj(db_session)
    p.notification_policy = {"webhook_url": "https://example.com/hook", "min_severity": "medium"}
    await db_session.flush()
    job = ScanJob(
        org_id=org.id,
        project_id=p.id,
        type="recon.scan",
        status=JobStatus.completed,
        params={},
        rate_limits={},
        result_count=42,
    )
    db_session.add(job)
    await db_session.flush()

    posted = []

    async def fake_post(url, payload, *, slack):
        posted.append((url, payload, slack))

    monkeypatch.setattr("app.services.notify._post", fake_post)
    delta = {
        "counts": {"new_findings": 2, "new_assets": 3, "resolved_findings": 0},
        "new": {"findings": [{"severity": "high", "name": "SQLi", "host": "x.example.com"}]},
    }
    await notify_scan_complete(db_session, p, job, delta)

    assert posted and posted[0][0] == "https://example.com/hook"
    assert posted[0][1]["event"] == "new_finding"
