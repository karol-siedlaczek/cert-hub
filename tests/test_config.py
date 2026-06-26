from pathlib import Path

import pytest
from cert_hub.domain.cert.static_cert import StaticCert
from cert_hub.conf.config import Config
from cert_hub.exception.validator_exceptions import ValidationError


STATIC_DIR = Path("/static-certs")


def test_static_from_dict_resolves_paths_under_dir():
    sc = StaticCert.from_dict(
        {"id": "s1", "cert_file": "s1.crt", "privkey_file": "s1.key", "chain_file": "s1.chain"},
        STATIC_DIR,
    )
    assert sc.cert_file == STATIC_DIR / "s1.crt"
    assert sc.privkey_file == STATIC_DIR / "s1.key"
    assert sc.chain_file == STATIC_DIR / "s1.chain"


def test_static_from_dict_chain_optional():
    sc = StaticCert.from_dict({"id": "s1", "cert_file": "s1.crt", "privkey_file": "s1.key"}, STATIC_DIR)
    assert sc.chain_file is None


def test_static_from_dict_requires_cert_and_key():
    with pytest.raises(ValidationError):
        StaticCert.from_dict({"id": "s1", "privkey_file": "s1.key"}, STATIC_DIR)
    with pytest.raises(ValidationError):
        StaticCert.from_dict({"id": "s1", "cert_file": "s1.crt"}, STATIC_DIR)


@pytest.mark.parametrize("bad", ["/abs/path.pem", "../escape.pem", "sub/../../x.pem", ""])
def test_static_from_dict_rejects_unsafe_filenames(bad):
    with pytest.raises(ValidationError):
        StaticCert.from_dict({"id": "s1", "cert_file": bad, "privkey_file": "ok.key"}, STATIC_DIR)


def test_parse_static_certs_detects_duplicate_ids():
    raw = [
        {"id": "dup", "cert_file": "a.crt", "privkey_file": "a.key"},
        {"id": "dup", "cert_file": "b.crt", "privkey_file": "b.key"},
    ]
    with pytest.raises(ValidationError):
        Config._parse_static_certs(raw, STATIC_DIR, set())


def test_parse_static_certs_collides_with_existing_letsencrypt_id():
    raw = [{"id": "shared", "cert_file": "a.crt", "privkey_file": "a.key"}]
    with pytest.raises(ValidationError):
        Config._parse_static_certs(raw, STATIC_DIR, {"shared"})


def test_parse_static_certs_empty_returns_empty():
    assert Config._parse_static_certs(None, STATIC_DIR, set()) == []
