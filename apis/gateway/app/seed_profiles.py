"""The six predefined scan profiles (spec §7). Seeded per-organization so an
org admin can clone and tweak them without affecting other tenants.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ScanProfile

# Phase keys mirror the 13-phase pipeline (spec §8). Milestone 1 ships the
# profile definitions; later milestones wire the phases to real engines.
ALL_PHASES = [
    "passive_subdomain_enum",
    "active_subdomain_enum",
    "infrastructure_mapping",
    "waf_cdn_origin_intel",
    "merge_resolve_alive",
    "vhost_enum",
    "url_endpoint_discovery",
    "js_analysis_secrets",
    "directory_discovery",
    "source_code_intel",
    "port_service_fingerprint",
    "automated_vuln_scan",
    "injection_testing",
    "finding_verification",
]

# The "core" recon phases every non-injection profile below is built from —
# spelled out explicitly (rather than sliced off ALL_PHASES) so inserting a
# new phase into ALL_PHASES above can never silently opt an existing profile
# into it.
_CORE_RECON_PHASES = (
    "passive_subdomain_enum",
    "active_subdomain_enum",
    "infrastructure_mapping",
    "waf_cdn_origin_intel",
    "merge_resolve_alive",
    "vhost_enum",
    "url_endpoint_discovery",
    "js_analysis_secrets",
    "directory_discovery",
    "source_code_intel",
    "port_service_fingerprint",
    "automated_vuln_scan",
)

_CONSERVATIVE = {
    "concurrency": 5,
    "requests_per_second": 10,
    "dns_per_second": 20,
    "timeout_seconds": 15,
    "retries": 2,
    "max_targets": 5000,
    "max_response_bytes": 2_097_152,
    "max_crawl_depth": 2,
    "max_crawl_duration_seconds": 900,
}


def _phases(*enabled: str) -> dict[str, bool]:
    return {p: (p in enabled) for p in ALL_PHASES}


BUILTIN_PROFILES = [
    {
        "key": "passive_only",
        "name": "Passive Only",
        "description": "No direct interaction with target infrastructure beyond approved public APIs and passive datasets.",
        "phases": _phases("passive_subdomain_enum", "infrastructure_mapping", "waf_cdn_origin_intel"),
        "rate_limits": {**_CONSERVATIVE, "requests_per_second": 0},
        "requires_active_ack": False,
    },
    {
        "key": "safe_recon",
        "name": "Safe Recon",
        "description": "DNS resolution, HTTP verification, and low-impact crawling only.",
        "phases": _phases(
            "passive_subdomain_enum",
            "infrastructure_mapping",
            "waf_cdn_origin_intel",
            "merge_resolve_alive",
            "url_endpoint_discovery",
        ),
        "rate_limits": {**_CONSERVATIVE, "requests_per_second": 5, "max_crawl_depth": 1},
        "requires_active_ack": True,
    },
    {
        "key": "standard_bug_bounty",
        "name": "Standard Bug Bounty",
        "description": "All normal reconnaissance phases with conservative rate limits. "
        "Does not run active injection testing — use Injection Discovery or Full Web "
        "Assessment for that, with explicit authorization.",
        "phases": _phases(*_CORE_RECON_PHASES, "finding_verification"),
        "rate_limits": _CONSERVATIVE,
        "requires_active_ack": True,
    },
    {
        "key": "deep_recon",
        "name": "Deep Recon",
        "description": "More extensive discovery, still no active injection testing. "
        "Requires explicit authorization for the expanded footprint.",
        "phases": _phases(*_CORE_RECON_PHASES, "finding_verification"),
        "rate_limits": {
            **_CONSERVATIVE,
            "concurrency": 10,
            "requests_per_second": 25,
            "max_targets": 25000,
            "max_crawl_depth": 3,
        },
        "requires_active_ack": True,
    },
    {
        "key": "injection_discovery",
        "name": "Injection Discovery",
        "description": "Endpoint/parameter discovery plus the Injection Testing Engine (§1-13) — "
        "SQLi/XSS/command injection/LFI/SSRF and related classes, safe-verification tier only. "
        "Still requires params.injection_ack=true at scan creation regardless of this profile.",
        "phases": _phases(*_CORE_RECON_PHASES, "injection_testing"),
        "rate_limits": _CONSERVATIVE,
        "requires_active_ack": True,
    },
    {
        "key": "full_web_assessment",
        "name": "Full Web Assessment",
        "description": "Every recon phase, finding verification, and the Injection Testing Engine. "
        "The most thorough profile; requires params.injection_ack=true (and params.ssrf_ack=true "
        "for SSRF/RFI OAST verification) at scan creation.",
        "phases": _phases(*ALL_PHASES),
        "rate_limits": {
            **_CONSERVATIVE,
            "concurrency": 10,
            "requests_per_second": 20,
            "max_targets": 25000,
            "max_crawl_depth": 3,
        },
        "requires_active_ack": True,
    },
    {
        "key": "continuous_monitoring",
        "name": "Continuous Monitoring",
        "description": "Runs selected phases on a recurring schedule and alerts on attack-surface changes.",
        "phases": _phases(
            "passive_subdomain_enum",
            "active_subdomain_enum",
            "merge_resolve_alive",
            "port_service_fingerprint",
            "automated_vuln_scan",
        ),
        "rate_limits": {**_CONSERVATIVE, "requests_per_second": 5},
        "requires_active_ack": True,
    },
    {
        "key": "custom",
        "name": "Custom",
        "description": "Enable or disable every phase individually.",
        "phases": _phases("passive_subdomain_enum"),
        "rate_limits": _CONSERVATIVE,
        "requires_active_ack": True,
    },
]


async def ensure_builtin_profiles(session: AsyncSession, org_id: uuid.UUID) -> None:
    existing = set(
        (
            await session.execute(
                select(ScanProfile.key).where(ScanProfile.org_id == org_id, ScanProfile.is_builtin.is_(True))
            )
        )
        .scalars()
        .all()
    )
    for spec in BUILTIN_PROFILES:
        if spec["key"] in existing:
            continue
        session.add(
            ScanProfile(
                org_id=org_id,
                key=spec["key"],
                name=spec["name"],
                description=spec["description"],
                is_builtin=True,
                phases=spec["phases"],
                rate_limits=spec["rate_limits"],
                requires_active_ack=spec["requires_active_ack"],
            )
        )
    await session.flush()
