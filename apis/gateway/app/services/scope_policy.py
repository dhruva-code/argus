"""Translate a project's ScopeRule rows into the wire policy the Go
orchestrator and the Python scope engine both consume."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ScopeEffect, ScopeMatcher, ScopeRule
from app.scope import Policy, compile_policy


async def build_policy_dict(session: AsyncSession, project_id: uuid.UUID) -> dict:
    rows = (
        (
            await session.execute(
                select(ScopeRule).where(ScopeRule.project_id == project_id).order_by(ScopeRule.position)
            )
        )
        .scalars()
        .all()
    )
    return {
        "rules": [
            {
                "id": str(r.id),
                "effect": r.effect.value,
                "type": r.matcher.value,
                "value": r.value,
                "ports": r.ports or [],
                "paths": r.paths or [],
            }
            for r in rows
        ]
    }


def validate_policy_dict(policy: dict) -> None:
    """Raise ScopePolicyError if the policy will not compile."""
    compile_policy(Policy.from_dict(policy))


async def root_domains(session: AsyncSession, project_id: uuid.UUID) -> list[str]:
    """The apex domains a recon scan should enumerate: every allow rule of type
    domain / subdomain / wildcard, reduced to its registrable-ish base."""
    rows = (
        (
            await session.execute(
                select(ScopeRule).where(
                    ScopeRule.project_id == project_id,
                    ScopeRule.effect == ScopeEffect.allow,
                )
            )
        )
        .scalars()
        .all()
    )
    domainish = {ScopeMatcher.domain, ScopeMatcher.subdomain, ScopeMatcher.wildcard}
    out: set[str] = set()
    for r in rows:
        if r.matcher not in domainish:
            continue
        v = r.value.strip().lower().removeprefix("*.").rstrip(".")
        if v and "." in v and "/" not in v:
            out.add(v)
    # drop a domain that is a subdomain of another listed root
    roots = sorted(out)
    return [d for d in roots if not any(d != o and d.endswith("." + o) for o in roots)]
