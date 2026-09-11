"""Project Deletion workflow (§18-19).

Two steps, both auditable and both requiring the caller to retype the
project's name as a confirmation:

* **soft delete** — reversible. Stamps `deleted_at`, archives the project,
  and stops/purges any in-flight scan jobs (queue entries, checkpoints,
  heartbeats) so nothing keeps running against a "deleted" project. The
  project and its data still exist and `restore_project` undoes this.
* **permanent delete** — irreversible. Every table with a `project_id`
  foreign key is defined `ON DELETE CASCADE` (see the Project model's
  `scope_rules`/`jobs` relationships and every other model's `project_id`
  column), so deleting the `projects` row itself lets Postgres cascade the
  entire inventory (assets, endpoints, findings, secrets, ports, injection
  points, auth profiles, scope rules, scan jobs, job events, ...) in one
  transaction — nothing is left orphaned in the database. Redis job keys
  (queue entries, heartbeats, checkpoints) are not covered by that
  constraint, so they're purged explicitly first, and any still-running job
  is sent a cancel signal so no orchestrator worker keeps touching a project
  that no longer exists.

Known limitation: this runs synchronously in the request. For a project with
a very large inventory, §18's "asynchronous, job-id/progress-tracked
deletion" is not yet implemented — see PERFORMANCE.md.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import purge_job_keys, send_control
from app.models import (
    Asset,
    AuthProfile,
    Endpoint,
    Finding,
    InjectionPoint,
    JobStatus,
    OASTEvent,
    Port,
    Project,
    Repository,
    ScanJob,
    ScopeRule,
    Secret,
    VHost,
)

# Every table this project's deletion touches, for the "show exactly what's
# deleted" preview (§18). Order doesn't matter here — these are read-only counts.
_PREVIEW_MODELS: tuple[tuple[str, Any], ...] = (
    ("assets", Asset),
    ("endpoints", Endpoint),
    ("vhosts", VHost),
    ("findings", Finding),
    ("secrets", Secret),
    ("ports", Port),
    ("repositories", Repository),
    ("injection_points", InjectionPoint),
    ("auth_profiles", AuthProfile),
    ("oast_events", OASTEvent),
    ("scope_rules", ScopeRule),
    ("scan_jobs", ScanJob),
)

_NON_TERMINAL = {JobStatus.queued, JobStatus.running, JobStatus.paused}


async def deletion_preview(session: AsyncSession, project_id: uuid.UUID) -> dict[str, int]:
    counts: dict[str, int] = {}
    for label, model in _PREVIEW_MODELS:
        n = await session.scalar(
            select(func.count()).select_from(model).where(model.project_id == project_id)
        )
        counts[label] = n or 0
    return counts


async def _stop_active_jobs(session: AsyncSession, project_id: uuid.UUID) -> int:
    """Cancel/purge every non-terminal scan job so nothing keeps running (or
    sitting queued) against a project that's being deleted. Returns the count
    stopped."""
    rows = (
        (
            await session.execute(
                select(ScanJob).where(
                    ScanJob.project_id == project_id, ScanJob.status.in_(_NON_TERMINAL)
                )
            )
        )
        .scalars()
        .all()
    )
    for job in rows:
        if job.status == JobStatus.running:
            await send_control("stop", str(job.id))
        await purge_job_keys(str(job.id))
        job.status = JobStatus.cancelled
        job.finished_at = datetime.now(UTC)
        job.error = "project deleted"
    return len(rows)


async def soft_delete_project(session: AsyncSession, project: Project) -> int:
    """Reversible: stamp deleted_at, archive, stop anything in flight."""
    stopped = await _stop_active_jobs(session, project.id)
    project.deleted_at = datetime.now(UTC)
    project.is_archived = True
    return stopped


async def restore_project(project: Project) -> None:
    project.deleted_at = None


async def permanent_delete_project(session: AsyncSession, project: Project) -> dict[str, int]:
    """Irreversible. Returns the pre-deletion counts (§18 "show exactly what's
    deleted") for the audit record / response."""
    counts = await deletion_preview(session, project.id)
    await _stop_active_jobs(session, project.id)
    # every job's redis keys, not just the ones that were still active —
    # completed jobs can still have a stale wire payload/checkpoint key.
    job_ids = (
        (await session.execute(select(ScanJob.id).where(ScanJob.project_id == project.id)))
        .scalars()
        .all()
    )
    for jid in job_ids:
        await purge_job_keys(str(jid))
    await session.delete(project)  # DB-level ON DELETE CASCADE removes everything else
    return counts
