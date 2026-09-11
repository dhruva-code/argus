"""Demo/seed data. Run with:  python -m app.seed  (needs ARGUS_ALLOW_SEED=true).

All data is synthetic (RFC 2606 / RFC 5737 reserved names and ranges). The
dashboard looks populated immediately after this runs.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.config import settings
from app.core import security
from app.db import SessionLocal, create_all
from app.models import (
    JobEvent,
    JobStatus,
    Membership,
    Organization,
    Project,
    RiskProfile,
    Role,
    ScanJob,
    ScopeEffect,
    ScopeMatcher,
    ScopeRule,
    ToolHealth,
    ToolIntegration,
    User,
)
from app.seed_profiles import ensure_builtin_profiles
from app.tool_catalog import CATALOG

DEMO_ADMIN = ("admin@demo.argus.test", "argus-demo-admin-1")
DEMO_ANALYST = ("analyst@demo.argus.test", "argus-demo-analyst-1")
DEMO_VIEWER = ("viewer@demo.argus.test", "argus-demo-viewer-1")


async def _user(session, email: str, password: str, name: str, *, superuser=False) -> User:
    u = await session.scalar(select(User).where(User.email == email))
    if u is None:
        u = User(
            email=email,
            full_name=name,
            password_hash=security.hash_password(password),
            is_superuser=superuser,
            email_verified=True,
        )
        session.add(u)
        await session.flush()
    return u


async def seed() -> None:
    if not settings.allow_seed:
        print("Refusing to seed: set ARGUS_ALLOW_SEED=true first.", file=sys.stderr)
        sys.exit(1)

    await create_all()
    async with SessionLocal() as session:
        org = await session.scalar(select(Organization).where(Organization.slug == "demo-corp"))
        if org is None:
            org = Organization(name="Demo Corp", slug="demo-corp")
            session.add(org)
            await session.flush()

        admin = await _user(session, *DEMO_ADMIN, "Demo Admin", superuser=True)
        analyst = await _user(session, *DEMO_ANALYST, "Demo Analyst")
        viewer = await _user(session, *DEMO_VIEWER, "Demo Viewer")
        for u, role in (
            (admin, Role.org_admin),
            (analyst, Role.security_analyst),
            (viewer, Role.viewer),
        ):
            m = await session.scalar(
                select(Membership).where(Membership.user_id == u.id, Membership.org_id == org.id)
            )
            if m is None:
                session.add(Membership(user_id=u.id, org_id=org.id, role=role))

        await ensure_builtin_profiles(session, org.id)

        project = await session.scalar(
            select(Project).where(Project.org_id == org.id, Project.name == "Demo Corp Public Bug Bounty")
        )
        if project is None:
            project = Project(
                org_id=org.id,
                name="Demo Corp Public Bug Bounty",
                program_name="Demo Corp VDP",
                client="Demo Corp",
                program_url="https://example.com/security",
                description="Synthetic demo program for the Argus platform.",
                rules_of_engagement=(
                    "In scope: *.example.test. No DoS, no social engineering, "
                    "conservative rate limits, report within 90 days."
                ),
                risk_profile=RiskProfile.high,
            )
            session.add(project)
            await session.flush()

            rules = [
                (
                    ScopeEffect.allow,
                    ScopeMatcher.wildcard,
                    "*.example.test",
                    "Primary bug-bounty scope",
                ),
                (ScopeEffect.allow, ScopeMatcher.domain, "example.test", "Apex domain"),
                (
                    ScopeEffect.deny,
                    ScopeMatcher.subdomain,
                    "internal.example.test",
                    "Corporate/internal — out of scope",
                ),
                (
                    ScopeEffect.deny,
                    ScopeMatcher.domain,
                    "legacy.example.test",
                    "Decommissioned host",
                ),
                (
                    ScopeEffect.allow,
                    ScopeMatcher.cidr,
                    "203.0.113.0/24",
                    "Published hosting range (RFC 5737)",
                ),
            ]
            for i, (effect, matcher, value, note) in enumerate(rules):
                session.add(
                    ScopeRule(
                        project_id=project.id,
                        position=i,
                        effect=effect,
                        matcher=matcher,
                        value=value,
                        note=note,
                    )
                )

        # Tool integration rows with a plausible health mix.
        health_mix = {
            "subfinder": (ToolHealth.ok, "2.16.0"),
            "dnsx": (ToolHealth.ok, "1.3.1"),
            "httpx": (ToolHealth.ok, "1.11.0"),
            "katana": (ToolHealth.ok, "1.7.0"),
            "nuclei": (ToolHealth.ok, "3.11.1"),
            "naabu": (ToolHealth.ok, "2.6.1"),
            "ffuf": (ToolHealth.ok, "2.1.0"),
        }
        # The seed sets a plausible starting state; run a real health check from
        # Tool Manager (or `argus tools check`) to replace it with live results.
        for spec in CATALOG:
            row = await session.scalar(
                select(ToolIntegration).where(
                    ToolIntegration.org_id == org.id, ToolIntegration.name == spec["name"]
                )
            )
            state, ver = health_mix.get(spec["name"], (ToolHealth.unknown, ""))
            if row is None:
                session.add(
                    ToolIntegration(
                        org_id=org.id,
                        name=spec["name"],
                        display_name=spec["display_name"],
                        capabilities=spec["capabilities"],
                        safety_class=spec["safety_class"],
                        needs_api_key=spec["needs_api_key"],
                        min_version=spec["min_version"],
                        tested_version=spec["tested_version"],
                        health=state,
                        installed_version=ver,
                        health_detail="seeded demo state"
                        if state != ToolHealth.missing
                        else "binary not found on PATH",
                        last_checked_at=datetime.now(UTC) - timedelta(hours=2),
                    )
                )

        # A couple of finished demo jobs with a log trail.
        existing_jobs = await session.scalar(select(ScanJob).where(ScanJob.project_id == project.id).limit(1))
        if existing_jobs is None:
            for days_ago, jtype, jstatus, results in (
                (3, "tool.health", JobStatus.partially_completed, 7),
                (1, "scope.selftest", JobStatus.completed, 5),
            ):
                created = datetime.now(UTC) - timedelta(days=days_ago)
                job = ScanJob(
                    org_id=org.id,
                    project_id=project.id,
                    type=jtype,
                    status=jstatus,
                    params={},
                    created_by=analyst.id,
                    worker="orch-demo",
                    result_count=results,
                    started_at=created,
                    finished_at=created + timedelta(minutes=2),
                )
                job.created_at = created
                session.add(job)
                await session.flush()
                for msg, level in (
                    (f"worker orch-demo started job {job.id} ({jtype})", "INFO"),
                    (f"produced {results} result(s)", "RESULT"),
                    (f"job {job.id} finished: {jstatus.value}", "INFO"),
                ):
                    session.add(JobEvent(job_id=job.id, type="log", level=level, message=msg, at=created))

        await session.commit()

    print("Seed complete.")
    print(f"  Admin   : {DEMO_ADMIN[0]} / {DEMO_ADMIN[1]}")
    print(f"  Analyst : {DEMO_ANALYST[0]} / {DEMO_ANALYST[1]}")
    print(f"  Viewer  : {DEMO_VIEWER[0]} / {DEMO_VIEWER[1]}")


if __name__ == "__main__":
    asyncio.run(seed())
