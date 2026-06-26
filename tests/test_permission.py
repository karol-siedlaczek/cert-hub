from cert_hub.domain.permission.permission import Permission, PermissionAction
from cert_hub.domain.identity import Identity


def test_new_actions_present():
    assert "revoke" in PermissionAction.values()
    assert "reload" in PermissionAction.values()


def test_permission_from_string_parses_reload():
    p = Permission.from_string(0, "*:reload")
    assert p.scope == "*"
    assert p.action == PermissionAction.RELOAD


def test_permission_from_string_parses_revoke():
    p = Permission.from_string(0, "example.com:revoke")
    assert p.scope == "example.com"
    assert p.action == PermissionAction.REVOKE


def _identity(permissions):
    return Identity(id="admin", hmac_hex="x" * 64, allowed_cidrs=[], permissions=permissions)


def test_has_global_action_true_for_star_reload():
    ident = _identity([Permission("*", PermissionAction.RELOAD)])
    assert ident.has_global_action(PermissionAction.RELOAD) is True


def test_has_global_action_true_for_star_any():
    ident = _identity([Permission("*", PermissionAction.ANY)])
    assert ident.has_global_action(PermissionAction.RELOAD) is True


def test_has_global_action_false_for_scoped_or_missing():
    assert _identity([Permission("example.com", PermissionAction.RELOAD)]).has_global_action(PermissionAction.RELOAD) is False
    assert _identity([Permission("*", PermissionAction.READ)]).has_global_action(PermissionAction.RELOAD) is False
