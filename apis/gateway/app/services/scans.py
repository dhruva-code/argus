"""Job creation: build the wire payload and enqueue it for the orchestrator."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import enqueue_job, purge_job_keys, send_control
from app.models import (
    Asset,
    AssetEdge,
    AssetSource,
    AuthProfile,
    Endpoint,
    Finding,
    JobEvent,
    Port,
    Project,
    Repository,
    ScanJob,
    ScanProfile,
    Secret,
    VHost,
)
from app.services.scope_policy import build_policy_dict, root_domains

# Inventory tables that carry `first_seen_scan` — used when a scan is deleted
# with `purge_data=true` to also drop what that scan first introduced. Order
# matters: children before Asset (its delete cascades sources/edges).
_SCAN_SCOPED_MODELS = (Finding, Port, Secret, Repository, Endpoint, VHost, Asset)

# Phases the recon pipeline can actually execute (M2–M6).
RECON_PHASES = [
    "passive_subdomain_enum",
    "active_subdomain_enum",
    "merge_resolve_alive",
    "infrastructure_mapping",
    "waf_cdn_origin_intel",
    "vhost_enum",
    "url_endpoint_discovery",
    "js_analysis_secrets",
    "directory_discovery",
    "source_code_intel",
    "port_service_fingerprint",
    "automated_vuln_scan",
    "injection_testing",
]

# `finding_verification` is not an orchestrator phase — it is the always-on
# gateway verification engine. A profile that enables it runs the vuln scan at
# the `safe_verify` level (out-of-band confirmation on).
VERIFICATION_PHASE = "finding_verification"

DEFAULT_RATE_LIMITS = {
    "concurrency": 5,
    "requests_per_second": 10,
    "dns_per_second": 20,
    "timeout_seconds": 15,
    "retries": 2,
    "max_targets": 5000,
    "max_response_bytes": 2_097_152,
}

# Job types that touch target infrastructure and therefore need an explicit
# authorization acknowledgement before they can be queued.
ACTIVE_JOB_TYPES: set[str] = {"recon.scan"}

# A small, safe permutation set for active enumeration (only expanded against
# in-scope roots).
DEFAULT_BRUTE_WORDS = [
    "www",
    "api",
    "dev",
    "staging",
    "test",
    "admin",
    "app",
    "portal",
    "mail",
    "vpn",
    "beta",
    "internal",
    "gateway",
    "auth",
    "cdn",
]


class ReconPlanError(ValueError):
    """The project can't be scanned yet (no scope, no phases, …)."""


async def plan_recon_scan(
    session: AsyncSession,
    project: Project,
    *,
    profile_key: str | None,
    extra_phases: list[str] | None = None,
    bruteforce: bool = True,
    vuln_level: str | None = None,
    injection_ack: bool = False,
    ssrf_ack: bool = False,
    auth_profile_id: str | None = None,
) -> tuple[dict, dict]:
    """Return (params, rate_limits) for a recon.scan job, or raise ReconPlanError."""
    roots = await root_domains(session, project.id)
    if not roots:
        raise ReconPlanError(
            "the project scope has no in-scope domain / subdomain / wildcard rule to enumerate"
        )

    profile: ScanProfile | None = None
    if profile_key:
        profile = await session.scalar(
            select(ScanProfile).where(
                ScanProfile.key == profile_key,
                (ScanProfile.org_id == project.org_id) | (ScanProfile.org_id.is_(None)),
            )
        )
    elif project.default_profile_id:
        profile = await session.get(ScanProfile, project.default_profile_id)

    verification_on = False
    if profile is not None:
        enabled = [p for p in RECON_PHASES if profile.phases.get(p)]
        rate_limits = {**DEFAULT_RATE_LIMITS, **(profile.rate_limits or {})}
        verification_on = bool(profile.phases.get(VERIFICATION_PHASE))
    else:
        # No profile: the conservative core (passive → active → alive). The
        # infra / vhost / endpoint phases are opted into via a profile.
        enabled = RECON_PHASES[:3]
        rate_limits = dict(DEFAULT_RATE_LIMITS)

    if extra_phases:
        enabled = [p for p in RECON_PHASES if p in set(enabled) | set(extra_phases)]
        if VERIFICATION_PHASE in extra_phases:
            verification_on = True
    if not enabled:
        raise ReconPlanError(
            f"scan profile '{profile_key or 'default'}' has no recon phases enabled "
            f"(need one of: {', '.join(RECON_PHASES)})"
        )

    # vuln model: explicit param wins, else safe_verify when the verification
    # phase is on, else the conservative passive default. The `aggressive` level
    # (active injection fuzzing) is only honoured with an explicit ack.
    if vuln_level not in ("passive", "safe_verify", "manual_review", "aggressive"):
        vuln_level = "safe_verify" if verification_on else "passive"
    if vuln_level == "aggressive" and not injection_ack:
        raise ReconPlanError(
            "vuln_level 'aggressive' performs active injection fuzzing (SQLi / XSS / SSTI / "
            "command injection / LFI payloads) against in-scope parameters — set "
            "params.injection_ack=true to confirm these targets are authorized for it"
        )

    # Injection Testing Engine (§1-13) — a dedicated, more thorough active-testing
    # phase than the legacy `aggressive` vuln level. Requires the same
    # authorization acknowledgement (it also sends live payloads).
    if "injection_testing" in enabled and not injection_ack:
        raise ReconPlanError(
            "the 'injection_testing' phase actively tests discovered parameters for SQLi / XSS / "
            "command injection / LFI / SSRF / other injection classes — set params.injection_ack=true "
            "to confirm this target is authorized for active testing"
        )
    # SSRF/RFI verification additionally requires its own explicit advanced-testing
    # acknowledgement (§7) — it makes the target perform outbound requests, which is
    # a materially different risk from the other, purely-response-based classes.
    if "injection_testing" in enabled and ssrf_ack and not injection_ack:
        raise ReconPlanError("params.ssrf_ack requires params.injection_ack to also be set")

    auth_header_ok = False
    if auth_profile_id:
        try:
            prof_uuid = uuid.UUID(auth_profile_id)
        except ValueError as exc:
            raise ReconPlanError("auth_profile_id is not a valid UUID") from exc
        prof = await session.get(AuthProfile, prof_uuid)
        if prof is None or prof.project_id != project.id:
            raise ReconPlanError("auth_profile_id does not belong to this project")
        auth_header_ok = True

    params = {
        "roots": roots,
        "phases": enabled,
        "brute_words": DEFAULT_BRUTE_WORDS if (bruteforce and "active_subdomain_enum" in enabled) else [],
        "profile_key": profile.key if profile else None,
        "vuln_level": vuln_level,
        "ssrf_ack": bool(ssrf_ack),
    }
    if auth_header_ok:
        # Only the profile's *id* ever travels through job params / Redis / the
        # database — the orchestrator fetches the decrypted secret just-in-time
        # over the internal-token-guarded endpoint and holds it in memory only.
        params["auth_profile_id"] = auth_profile_id
    return params, rate_limits


async def create_scan_job(
    session: AsyncSession,
    *,
    project: Project,
    job_type: str,
    params: dict,
    rate_limits: dict,
    created_by: uuid.UUID | None,
) -> ScanJob:
    job = ScanJob(
        org_id=project.org_id,
        project_id=project.id,
        type=job_type,
        params=params,
        rate_limits=rate_limits,
        created_by=created_by,
    )
    session.add(job)
    await session.flush()
    return job


async def enqueue(session: AsyncSession, job: ScanJob) -> None:
    policy = await build_policy_dict(session, job.project_id)
    payload = {
        "id": str(job.id),
        "project_id": str(job.project_id),
        "org_id": str(job.org_id),
        "type": job.type,
        "params": job.params or {},
        "scope_policy": policy,
        "rate_limits": job.rate_limits or DEFAULT_RATE_LIMITS,
        "enqueued_at": datetime.now(UTC).isoformat(),
    }
    await enqueue_job(str(job.id), payload)


async def request_cancel(job_id: str) -> None:
    await send_control("stop", job_id)


async def request_pause(job_id: str) -> None:
    await send_control("pause", job_id)


async def emergency_stop_all() -> None:
    await send_control("stop_all")


async def clear_emergency_stop() -> None:
    await send_control("resume_all")


TERMINAL_STATUSES = {"completed", "failed", "cancelled", "partially_completed"}


async def delete_scans(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    jobs: list[ScanJob],
    purge_data: bool,
) -> dict:
    """Delete finished scan jobs and their event logs. When `purge_data` is set,
    also drop the inventory rows each scan first introduced
    (`first_seen_scan == job.id`) — rows re-seen by a later scan keep that
    scan's stamp, so this removes exactly what the deleted scan contributed and
    nothing a surviving scan still vouches for.

    Everything is done with explicit statements rather than relying on database
    ON DELETE behaviour, so it is predictable across backends.
    """
    if not jobs:
        return {"deleted": 0, "purged": {}}
    job_ids = [j.id for j in jobs]
    purged: dict[str, int] = {}

    if purge_data:
        asset_ids = (
            (await session.execute(select(Asset.id).where(Asset.first_seen_scan.in_(job_ids))))
            .scalars()
            .all()
        )
        if asset_ids:
            for child in (AssetSource, AssetEdge):
                cond = (
                    child.asset_id.in_(asset_ids)
                    if child is AssetSource
                    else child.src_asset_id.in_(asset_ids) | child.dst_asset_id.in_(asset_ids)
                )
                await session.execute(sa_delete(child).where(cond))
        for model in _SCAN_SCOPED_MODELS:
            res = await session.execute(sa_delete(model).where(model.first_seen_scan.in_(job_ids)))
            if res.rowcount:
                purged[model.__tablename__] = res.rowcount
    else:
        # keep the inventory but drop the dangling scan reference
        for model in _SCAN_SCOPED_MODELS:
            await session.execute(
                sa_update(model).where(model.first_seen_scan.in_(job_ids)).values(first_seen_scan=None)
            )

    await session.execute(sa_delete(JobEvent).where(JobEvent.job_id.in_(job_ids)))
    await session.execute(sa_delete(ScanJob).where(ScanJob.id.in_(job_ids)))
    await session.flush()

    for jid in job_ids:
        await purge_job_keys(str(jid))

    return {"deleted": len(job_ids), "purged": purged}
