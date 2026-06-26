import pytest

import certhub
from certhub import PemType, pem_filename, parse_pem_extensions


def test_pem_filename_uses_mapped_extension():
    ext_map = {PemType.CERT: "crt", PemType.PRIV_KEY: "key"}
    assert pem_filename("foo", PemType.CERT, ext_map) == "foo_cert.crt"
    assert pem_filename("foo", PemType.PRIV_KEY, ext_map) == "foo_privkey.key"


def test_pem_filename_default_pem_extension():
    ext_map = {PemType.BUNDLE: "pem"}
    assert pem_filename("bar", PemType.BUNDLE, ext_map) == "bar_bundle.pem"


def test_parse_default_all_pem():
    types = [PemType.CERT, PemType.PRIV_KEY]
    assert parse_pem_extensions([], types) == {PemType.CERT: "pem", PemType.PRIV_KEY: "pem"}


def test_parse_override():
    types = [PemType.CERT, PemType.PRIV_KEY]
    result = parse_pem_extensions(["cert=crt", "privkey=key"], types)
    assert result == {PemType.CERT: "crt", PemType.PRIV_KEY: "key"}


def test_parse_strips_leading_dot_and_whitespace():
    types = [PemType.CERT]
    assert parse_pem_extensions([" cert=.crt "], types) == {PemType.CERT: "crt"}


def test_parse_unknown_type_raises():
    with pytest.raises(certhub.typer.BadParameter):
        parse_pem_extensions(["bogus=crt"], [PemType.CERT])


def test_parse_invalid_ext_chars_raises():
    with pytest.raises(certhub.typer.BadParameter):
        parse_pem_extensions(["cert=cr/t"], [PemType.CERT])


def test_parse_empty_ext_raises():
    with pytest.raises(certhub.typer.BadParameter):
        parse_pem_extensions(["cert="], [PemType.CERT])


def test_parse_missing_equals_raises():
    with pytest.raises(certhub.typer.BadParameter):
        parse_pem_extensions(["cert"], [PemType.CERT])


def test_parse_type_not_in_pem_raises():
    with pytest.raises(certhub.typer.BadParameter):
        parse_pem_extensions(["privkey=key"], [PemType.CERT])
