from types import SimpleNamespace

import pytest
from cert_hub.domain.cert.letsencrypt_cert import LetsEncryptCert
from cert_hub.domain.dns_provider import DnsProvider
from cert_hub.domain.cert.cert_status import CertStatus
from cert_hub.exception.cert_exceptions import CertException


def _le_cert():
    return LetsEncryptCert(
        id="x",
        email="a@b.com",
        domains=("example.com",),
        custom_attrs={},
        dns_provider=DnsProvider.AWS,
    )


def _fake_certbot(tmp_path, cert_bytes):
    cert_file = tmp_path / "cert.pem"
    cert_file.write_bytes(cert_bytes)
    chain_file = tmp_path / "chain.pem"
    chain_file.write_text("chain")
    key_file = tmp_path / "privkey.pem"
    key_file.write_text("key")
    return SimpleNamespace(
        get_cert_path=lambda _id: cert_file,
        get_chain_path=lambda _id: chain_file,
        get_private_key_path=lambda _id: key_file,
        renew_before_days=30,
    )


def _patch_certbot(monkeypatch, fake):
    import cert_hub.domain.cert.letsencrypt_cert as le_mod
    monkeypatch.setattr(le_mod.CertBot, "get_from_global_context", staticmethod(lambda: fake))


def test_get_expire_date_raises_invalid_on_corrupt_cert(tmp_path, monkeypatch):
    _patch_certbot(monkeypatch, _fake_certbot(tmp_path, b"not a pem"))
    with pytest.raises(CertException) as exc:
        _le_cert().get_expire_date()
    assert exc.value.status == CertStatus.INVALID_CERT_FILE


def test_get_status_does_not_raise_on_corrupt_cert(tmp_path, monkeypatch):
    # An issued-but-corrupt cert must yield a status, never propagate an exception
    # (so /api/metrics and /api/certs/status can't 500 on one bad cert).
    _patch_certbot(monkeypatch, _fake_certbot(tmp_path, b"not a pem"))
    assert _le_cert().get_status() == CertStatus.INVALID_CERT_FILE


def _fake_certbot_no_files(tmp_path, *, revoked: bool, calls: dict | None = None):
    # cert files absent → is_issued() False; is_revoked controllable; record mark/clear calls
    missing = tmp_path / "nope"
    _calls = calls if calls is not None else {}
    ns = SimpleNamespace(
        get_cert_path=lambda _id: missing / "cert.pem",
        get_chain_path=lambda _id: missing / "chain.pem",
        get_private_key_path=lambda _id: missing / "privkey.pem",
        renew_before_days=30,
        is_revoked=lambda _id: revoked,
        mark_revoked=lambda _id: _calls.__setitem__("mark", _id),
        clear_revoked=lambda _id: _calls.__setitem__("clear", _id),
        revoke=lambda _id: _calls.__setitem__("revoke", _id),
    )
    return ns


def test_get_status_revoked_when_marker_present(tmp_path, monkeypatch):
    _patch_certbot(monkeypatch, _fake_certbot_no_files(tmp_path, revoked=True))
    assert _le_cert().get_status() == CertStatus.REVOKED


def test_get_status_not_issued_when_no_marker(tmp_path, monkeypatch):
    _patch_certbot(monkeypatch, _fake_certbot_no_files(tmp_path, revoked=False))
    assert _le_cert().get_status() == CertStatus.NOT_ISSUED


def test_revoke_marks_revoked(tmp_path, monkeypatch):
    calls: dict = {}
    fake = _fake_certbot_no_files(tmp_path, revoked=False, calls=calls)
    # make is_issued() True so revoke()'s _require_issued passes: point files at real ones
    cert_file = tmp_path / "cert.pem"; cert_file.write_text("x")
    chain_file = tmp_path / "chain.pem"; chain_file.write_text("x")
    key_file = tmp_path / "privkey.pem"; key_file.write_text("x")
    fake.get_cert_path = lambda _id: cert_file
    fake.get_chain_path = lambda _id: chain_file
    fake.get_private_key_path = lambda _id: key_file
    _patch_certbot(monkeypatch, fake)
    _le_cert().revoke()
    assert calls.get("revoke") == "x"
    assert calls.get("mark") == "x"


def test_revoke_succeeds_when_marker_write_fails(tmp_path, monkeypatch):
    calls: dict = {}
    fake = _fake_certbot_no_files(tmp_path, revoked=False, calls=calls)
    cert_file = tmp_path / "cert.pem"; cert_file.write_text("x")
    chain_file = tmp_path / "chain.pem"; chain_file.write_text("x")
    key_file = tmp_path / "privkey.pem"; key_file.write_text("x")
    fake.get_cert_path = lambda _id: cert_file
    fake.get_chain_path = lambda _id: chain_file
    fake.get_private_key_path = lambda _id: key_file

    def _boom(_id):
        raise OSError("revoked dir not writable")
    fake.mark_revoked = _boom

    _patch_certbot(monkeypatch, fake)
    # revoke must NOT raise even though the marker write fails (cert is already revoked at the CA)
    _le_cert().revoke()
    assert calls.get("revoke") == "x"
