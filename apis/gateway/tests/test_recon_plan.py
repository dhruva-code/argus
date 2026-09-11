"""recon.scan planning: root extraction, phase selection, guardrails."""

from __future__ import annotations

import uuid

import pytest

from app.models import Organization, Project, ScanProfile, ScopeEffect, ScopeMatcher, ScopeRule
from app.services.scans import ReconPlanError, plan_recon_scan
from app.services.scope_policy import root_domains


async def _project_with_scope(session, rules):
    org = Organization(name="O", slug=f"o-{uuid.uuid4().hex[:6]}")
    session.add(org)
    await session.flush()
    p = Project(org_id=org.id, name="P")
    session.add(p)
    await session.flush()
    for i, (effect, matcher, value) in enumerate(rules):
        session.add(ScopeRule(project_id=p.id, position=i, effect=effect, matcher=matcher, value=value))
    await session.flush()
    return org, p


async def test_root_domains_extraction(db_session):
    _, p = await _project_with_scope(
        db_session,
        [
            (ScopeEffect.allow, ScopeMatcher.wildcard, "*.example.com"),
            (ScopeEffect.allow, ScopeMatcher.subdomain, "api.example.com"),  # child of example.com
            (ScopeEffect.allow, ScopeMatcher.domain, "example.org"),
            (ScopeEffect.allow, ScopeMatcher.cidr, "203.0.113.0/24"),  # ignored
            (ScopeEffect.deny, ScopeMatcher.domain, "secret.example.com"),  # ignored (deny)
        ],
    )
    roots = await root_domains(db_session, p.id)
    assert set(roots) == {"example.com", "example.org"}


async def test_plan_uses_profile_phases(db_session):
    org, p = await _project_with_scope(
        db_session, [(ScopeEffect.allow, ScopeMatcher.wildcard, "*.example.com")]
    )
    db_session.add(
        ScanProfile(
            org_id=org.id,
            key="passive_only",
            name="Passive Only",
            is_builtin=True,
            phases={"passive_subdomain_enum": True, "merge_resolve_alive": False},
            rate_limits={"requests_per_second": 0},
        )
    )
    await db_session.flush()

    params, rl = await plan_recon_scan(db_session, p, profile_key="passive_only")
    assert params["phases"] == ["passive_subdomain_enum"]
    assert params["brute_words"] == []  # active enum not enabled
    assert rl["requests_per_second"] == 0


async def test_plan_rejects_project_without_domain_scope(db_session):
    _, p = await _project_with_scope(db_session, [(ScopeEffect.allow, ScopeMatcher.cidr, "203.0.113.0/24")])
    with pytest.raises(ReconPlanError):
        await plan_recon_scan(db_session, p, profile_key=None)


async def test_plan_default_when_no_profile(db_session):
    _, p = await _project_with_scope(db_session, [(ScopeEffect.allow, ScopeMatcher.domain, "example.com")])
    params, _ = await plan_recon_scan(db_session, p, profile_key=None)
    assert set(params["phases"]) == {
        "passive_subdomain_enum",
        "active_subdomain_enum",
        "merge_resolve_alive",
    }
    assert "www" in params["brute_words"]


async def test_aggressive_vuln_level_needs_injection_ack(db_session):
    _, p = await _project_with_scope(db_session, [(ScopeEffect.allow, ScopeMatcher.domain, "example.com")])
    with pytest.raises(ReconPlanError, match="injection_ack"):
        await plan_recon_scan(db_session, p, profile_key=None, vuln_level="aggressive")
    params, _ = await plan_recon_scan(
        db_session, p, profile_key=None, vuln_level="aggressive", injection_ack=True
    )
    assert params["vuln_level"] == "aggressive"
