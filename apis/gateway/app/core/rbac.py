"""Permissions.

Single-role model: every account is a super admin (app.models.Role has
exactly one member) and holds every permission — there is no matrix to
look up. permissions_for/has_permission keep their existing signatures
(role, is_superuser kwarg included) purely so every call site across
deps.py/auth.py/routers stays unchanged; the role/is_superuser arguments
are accepted but no longer change the result.
"""

from __future__ import annotations

from app.models import Role

# Fine-grained permission names, still enforced at each endpoint via
# Principal.require()/require_permission() — only the "which roles get
# which of these" matrix has been removed, not the checks themselves.
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


def permissions_for(role: Role | None = None, *, is_superuser: bool = False) -> set[str]:  # noqa: ARG001
    return set(PERMISSIONS)


def has_permission(role: Role | None = None, permission: str = "", *, is_superuser: bool = False) -> bool:  # noqa: ARG001
    return permission in PERMISSIONS
