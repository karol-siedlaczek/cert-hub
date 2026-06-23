import re
import pytest
from types import SimpleNamespace
from dataclasses import dataclass

from cert_hub.api.context import Context
from cert_hub.conf.config import Config
from cert_hub.domain.permission import PermissionAction
from cert_hub.exception.api_exceptions import (
    InvalidRequestError,
    ResourceNotFound,
    PermissionDenied,
)


@dataclass
class FakeCert:
    """Minimal stand-in for Cert: an id plus the actions it grants to anyone."""
    id: str
    allowed: frozenset = frozenset()

    def has_permission(self, identity, action: PermissionAction) -> bool:
        return action in self.allowed


def _identity(ident_id="tester"):
    return SimpleNamespace(id=ident_id)


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


# ── resolve_scope (matching + authorization → 200/403/404) ─────────────────────
def test_resolve_scope_returns_only_authorized(monkeypatch):
    certs = [
        FakeCert("a.example", allowed=frozenset({PermissionAction.READ})),
        FakeCert("b.example", allowed=frozenset()),  # matched but not authorized
    ]
    _use_certs(monkeypatch, certs)
    result = _ctx().resolve_scope(["*"], PermissionAction.READ)
    assert [c.id for c in result] == ["a.example"]


def test_resolve_scope_no_matching_cert_raises_not_found(monkeypatch):
    _use_certs(monkeypatch, [FakeCert("a.example")])
    with pytest.raises(ResourceNotFound) as exc:
        _ctx().resolve_scope(["ghost.zzz"], PermissionAction.READ)
    assert exc.value.code == 404


def test_resolve_scope_matched_but_unauthorized_raises_forbidden(monkeypatch):
    # cert exists for the scope, but identity has no READ permission on it → 403, not 404
    _use_certs(monkeypatch, [FakeCert("a.example", allowed=frozenset())])
    with pytest.raises(PermissionDenied) as exc:
        _ctx().resolve_scope(["a.example"], PermissionAction.READ)
    assert exc.value.code == 403


def test_resolve_scope_star_without_permission_raises_forbidden(monkeypatch):
    # "*" matches all certs, but none grant the action → 403 (per design decision)
    _use_certs(monkeypatch, [FakeCert("a.example"), FakeCert("b.example")])
    with pytest.raises(PermissionDenied) as exc:
        _ctx().resolve_scope(["*"], PermissionAction.ISSUE)
    assert exc.value.code == 403


def test_resolve_scope_accepts_single_string_scope(monkeypatch):
    # a bare str must be treated as one scope, not exploded into characters
    _use_certs(monkeypatch, [FakeCert("a.example", allowed=frozenset({PermissionAction.READ}))])
    result = _ctx().resolve_scope("a.example", PermissionAction.READ)
    assert [c.id for c in result] == ["a.example"]
