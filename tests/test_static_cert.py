import datetime as dt
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cert_hub.domain.cert.static_cert import StaticCert
from cert_hub.domain.cert.cert_type import CertType
from cert_hub.domain.cert.cert_status import CertStatus
from cert_hub.exception.cert_exceptions import CertException


@pytest.fixture(autouse=True)
def _fake_certbot(monkeypatch):
    # is_expiring()/get_next_renew_date() read renew_before_days from the global CertBot
    import cert_hub.domain.cert.cert as cert_mod
    monkeypatch.setattr(
        cert_mod.CertBot, "get_from_global_context",
        staticmethod(lambda: SimpleNamespace(renew_before_days=30)),
    )


def _make_cert(tmp_path: Path, *, days_valid: int = 365, sans=("example.com", "www.example.com")):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    not_before = now - dt.timedelta(days=max(1, -days_valid + 1))
    not_after = now + dt.timedelta(days=days_valid)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sans[0])]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sans[0])]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    )
    cert = builder.sign(key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def _write(tmp_path, cert_pem=None, key_pem=None, chain_pem=None, with_chain=False):
    cert_file = tmp_path / "cert.pem"
    key_file = tmp_path / "privkey.pem"
    chain_file = tmp_path / "chain.pem"
    if cert_pem is not None:
        cert_file.write_text(cert_pem)
    if key_pem is not None:
        key_file.write_text(key_pem)
    if chain_pem is not None:
        chain_file.write_text(chain_pem)
    return StaticCert(
        id="static-a",
        cert_file=cert_file,
        privkey_file=key_file,
        chain_file=(chain_file if (with_chain or chain_pem is not None) else None),
        custom_attrs={},
    )


def test_cert_type_is_static(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem, key_pem)
    assert sc.type is CertType.STATIC


def test_status_ok_when_valid_and_far_from_expiry(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path, days_valid=365)
    sc = _write(tmp_path, cert_pem, key_pem)
    assert sc.get_status() == CertStatus.OK


def test_status_expiring_within_window(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path, days_valid=10)
    sc = _write(tmp_path, cert_pem, key_pem)
    assert sc.get_status() == CertStatus.EXPIRING


def test_status_expired(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path, days_valid=-5)
    sc = _write(tmp_path, cert_pem, key_pem)
    assert sc.get_status() == CertStatus.EXPIRED


def test_status_cert_missing(tmp_path):
    _, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem=None, key_pem=key_pem)
    assert sc.get_status() == CertStatus.CERT_MISSING


def test_status_key_missing(tmp_path):
    cert_pem, _ = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem=cert_pem, key_pem=None)
    assert sc.get_status() == CertStatus.KEY_MISSING


def test_status_chain_missing_when_declared_but_absent(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem, key_pem, with_chain=True)  # chain_file declared, file not written
    assert sc.get_status() == CertStatus.CHAIN_MISSING


def test_status_invalid_cert_file(tmp_path):
    _, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem="not a pem", key_pem=key_pem)
    assert sc.get_status() == CertStatus.INVALID_CERT_FILE


def test_domains_from_san(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path, sans=("a.example", "b.example"))
    sc = _write(tmp_path, cert_pem, key_pem)
    assert sc.domains == ("a.example", "b.example")


def test_domains_empty_when_cert_missing(tmp_path):
    _, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem=None, key_pem=key_pem)
    assert sc.domains == ()


def test_get_full_chain_without_chain_is_cert_only(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem, key_pem)
    assert sc.get_full_chain().strip() == cert_pem.strip()


def test_get_certificate_raises_on_invalid_cert(tmp_path):
    _, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem="not a pem", key_pem=key_pem)
    with pytest.raises(CertException) as exc:
        sc.get_certificate()
    assert exc.value.status == CertStatus.INVALID_CERT_FILE


def test_issue_and_renew_not_supported(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem, key_pem)
    for op in (sc.issue, sc.renew):
        with pytest.raises(CertException) as exc:
            op()
        assert exc.value.status == CertStatus.NOT_SUPPORTED


def test_revoke_not_supported(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem, key_pem)
    with pytest.raises(CertException) as exc:
        sc.revoke()
    assert exc.value.status == CertStatus.NOT_SUPPORTED
