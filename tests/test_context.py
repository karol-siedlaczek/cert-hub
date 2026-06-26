import re
import pytest
from types import SimpleNamespace
from dataclasses import dataclass

from cert_hub.api.context import Context
from cert_hub.conf.config import Config
from cert_hub.domain.permission.permission_action import PermissionAction
from cert_hub.exception.api_exceptions import InvalidRequestError, ResourceNotFound, PermissionDenied

@dataclass
class FakeCert:
    """Minimal stand-in for Cert: an id plus the actions it grants to anyone."""
    id: str
    allowed: frozenset = frozenset()


@dataclass
class FakeIdentity:
    """Stand-in for Identity: authorization lives here via allows(cert, action)."""
    id: str = "tester"

    def allows(self, cert: FakeCert, action: PermissionAction) -> bool:
        return action in cert.allowed


def _identity(ident_id="tester"):
    return FakeIdentity(id=ident_id)


def _ctx():
    return Context(remote_ip="127.0.0.1", identity=_identity())


def _use_certs(monkeypatch, certs):
    monkeypatch.setattr(Config, "get_from_global_context", lambda: SimpleNamespace(certs=certs))


# ── _match_certs (pure scope matching) ────────────────────────────────────────
def test_match_certs_star_returns_all():
    certs = [FakeCert("a.example"), FakeCert("b.example")]
    assert Context._match_certs(["*"], certs) == certs


def test_match_certs_exact_id():
    certs = [FakeCert("a.example"), FakeCert("b.example")]
    result = Context._match_certs(["b.example"], certs)
    assert [c.id for c in result] == ["b.example"]


def test_match_certs_regex():
    certs = [FakeCert("web.example.com"), FakeCert("api.example.com"), FakeCert("db.internal")]
    result = Context._match_certs([r".*\.example\.com"], certs)
    assert sorted(c.id for c in result) == ["api.example.com", "web.example.com"]


def test_match_certs_no_match_returns_empty():
    certs = [FakeCert("a.example")]
    assert Context._match_certs(["nope.zzz"], certs) == []


def test_match_certs_invalid_regex_raises_invalid_request():
    with pytest.raises(InvalidRequestError) as exc:
        Context._match_certs(["("], [FakeCert("a.example")])
    assert exc.value.code == 400


# ── resolve_certs (matching + authorization → 200/403/404) ─────────────────────
def test_resolve_certs_returns_only_authorized(monkeypatch):
    certs = [
        FakeCert("a.example", allowed=frozenset({PermissionAction.READ})),
        FakeCert("b.example", allowed=frozenset()),  # matched but not authorized
    ]
    _use_certs(monkeypatch, certs)
    result = _ctx().resolve_certs(["*"], PermissionAction.READ)
    assert [c.id for c in result] == ["a.example"]


def test_resolve_certs_no_matching_cert_raises_not_found(monkeypatch):
    _use_certs(monkeypatch, [FakeCert("a.example")])
    with pytest.raises(ResourceNotFound) as exc:
        _ctx().resolve_certs(["ghost.zzz"], PermissionAction.READ)
    assert exc.value.code == 404


def test_resolve_certs_matched_but_unauthorized_raises_forbidden(monkeypatch):
    # cert exists for the scope, but identity has no READ permission on it → 403, not 404
    _use_certs(monkeypatch, [FakeCert("a.example", allowed=frozenset())])
    with pytest.raises(PermissionDenied) as exc:
        _ctx().resolve_certs(["a.example"], PermissionAction.READ)
    assert exc.value.code == 403


def test_resolve_certs_star_without_permission_raises_forbidden(monkeypatch):
    # "*" matches all certs, but none grant the action → 403 (per design decision)
    _use_certs(monkeypatch, [FakeCert("a.example"), FakeCert("b.example")])
    with pytest.raises(PermissionDenied) as exc:
        _ctx().resolve_certs(["*"], PermissionAction.ISSUE)
    assert exc.value.code == 403


def test_resolve_certs_accepts_single_string_scope(monkeypatch):
    # a bare str must be treated as one scope, not exploded into characters
    _use_certs(monkeypatch, [FakeCert("a.example", allowed=frozenset({PermissionAction.READ}))])
    result = _ctx().resolve_certs("a.example", PermissionAction.READ)
    assert [c.id for c in result] == ["a.example"]


# ── resolve_cert (exact id, never regex → 200/403/404) ─────────────────────────
def test_resolve_cert_returns_exact_authorized(monkeypatch):
    certs = [
        FakeCert("a.example", allowed=frozenset({PermissionAction.ISSUE})),
        FakeCert("b.example", allowed=frozenset({PermissionAction.ISSUE})),
    ]
    _use_certs(monkeypatch, certs)
    cert = _ctx().resolve_cert("b.example", PermissionAction.ISSUE)
    assert cert.id == "b.example"


def test_resolve_cert_unknown_id_raises_not_found(monkeypatch):
    _use_certs(monkeypatch, [FakeCert("a.example", allowed=frozenset({PermissionAction.ISSUE}))])
    with pytest.raises(ResourceNotFound) as exc:
        _ctx().resolve_cert("ghost.zzz", PermissionAction.ISSUE)
    assert exc.value.code == 404


def test_resolve_cert_existing_but_unauthorized_raises_forbidden(monkeypatch):
    _use_certs(monkeypatch, [FakeCert("a.example", allowed=frozenset())])
    with pytest.raises(PermissionDenied) as exc:
        _ctx().resolve_cert("a.example", PermissionAction.ISSUE)
    assert exc.value.code == 403


def test_resolve_cert_does_not_regex_match(monkeypatch):
    # 'web.api' must NOT be interpreted as a regex matching 'webXapi'; it has no
    # exact id → 404. This is the safety guarantee for destructive per-cert actions.
    _use_certs(monkeypatch, [FakeCert("webXapi", allowed=frozenset({PermissionAction.REVOKE}))])
    with pytest.raises(ResourceNotFound):
        _ctx().resolve_cert("web.api", PermissionAction.REVOKE)


def test_resolve_cert_matches_id_with_regex_metachars(monkeypatch):
    # an id that contains regex metacharacters resolves by its literal value
    _use_certs(monkeypatch, [FakeCert("web.api", allowed=frozenset({PermissionAction.REVOKE}))])
    cert = _ctx().resolve_cert("web.api", PermissionAction.REVOKE)
    assert cert.id == "web.api"
