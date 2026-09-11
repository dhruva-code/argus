from app.core.rbac import ROLE_PERMISSIONS, has_permission, permissions_for
from app.models import Role


def test_viewer_is_read_only():
    perms = permissions_for(Role.viewer)
    assert perms == {"project.read", "finding.read"}
    assert not has_permission(Role.viewer, "scan.execute")


def test_permissions_are_monotonic_by_rank():
    order = [
        Role.viewer,
        Role.researcher,
        Role.security_analyst,
        Role.security_lead,
        Role.org_admin,
        Role.super_admin,
    ]
    for lower, higher in zip(order, order[1:], strict=False):
        assert ROLE_PERMISSIONS[lower] <= ROLE_PERMISSIONS[higher], (lower, higher)


def test_superuser_gets_everything():
    from app.core.rbac import PERMISSIONS

    assert permissions_for(Role.viewer, is_superuser=True) == set(PERMISSIONS)


def test_only_lead_and_up_configure_tools():
    assert not has_permission(Role.security_analyst, "tool.configure")
    assert has_permission(Role.security_lead, "tool.configure")
    assert has_permission(Role.org_admin, "settings.modify")
    assert not has_permission(Role.security_lead, "settings.modify")
