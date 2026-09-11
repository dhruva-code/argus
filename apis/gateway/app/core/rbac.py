"""Role → permission matrix and FastAPI dependencies enforcing it."""

from __future__ import annotations

from app.models import Role

# Fine-grained permissions (spec §28).
PERMISSIONS = [
    "project.read",
    "project.write",
    "scope.write",
    "scan.execute",
    "scan.cancel",
    "finding.read",
    "finding.modify",
    "report.generate",
    "tool.configure",
    "settings.modify",
    "audit.read",
    "org.manage",
    "user.manage",
    "auth_profile.manage",
]

_VIEWER = {"project.read", "finding.read"}
_RESEARCHER = _VIEWER | {"scan.execute", "report.generate"}
_ANALYST = _RESEARCHER | {
    "project.write",
    "scope.write",
    "scan.cancel",
    "finding.modify",
    "auth_profile.manage",
}
_LEAD = _ANALYST | {"tool.configure", "audit.read"}
_ORG_ADMIN = _LEAD | {"settings.modify", "org.manage", "user.manage"}
_SUPER = set(PERMISSIONS)

ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.viewer: _VIEWER,
    Role.researcher: _RESEARCHER,
    Role.security_analyst: _ANALYST,
    Role.security_lead: _LEAD,
    Role.org_admin: _ORG_ADMIN,
    Role.super_admin: _SUPER,
}

# Role rank for "at least this role" checks.
ROLE_RANK: dict[Role, int] = {
    Role.viewer: 0,
    Role.researcher: 1,
    Role.security_analyst: 2,
    Role.security_lead: 3,
    Role.org_admin: 4,
    Role.super_admin: 5,
}


def permissions_for(role: Role, *, is_superuser: bool = False) -> set[str]:
    if is_superuser:
        return set(PERMISSIONS)
    return set(ROLE_PERMISSIONS.get(role, set()))


def has_permission(role: Role, permission: str, *, is_superuser: bool = False) -> bool:
    return permission in permissions_for(role, is_superuser=is_superuser)
