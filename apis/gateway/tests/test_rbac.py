"""Single-role model: every account holds every permission — see
app/core/rbac.py's module docstring for why the matrix went away."""

from app.core.rbac import PERMISSIONS, has_permission, permissions_for
from app.models import Role


def test_super_admin_gets_everything():
    assert permissions_for(Role.super_admin) == set(PERMISSIONS)


def test_has_permission_true_for_every_known_permission():
    for p in PERMISSIONS:
        assert has_permission(Role.super_admin, p)


def test_has_permission_false_for_unknown_permission():
    assert not has_permission(Role.super_admin, "not.a.real.permission")


def test_only_one_role_exists():
    assert list(Role) == [Role.super_admin]
