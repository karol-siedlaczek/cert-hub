import importlib.metadata
import pytest
from datetime import datetime
from flask import Flask
from cert_hub.api import validators as v
from cert_hub.exception.api_exceptions import InvalidRequestError
from cert_hub.validation.require import Require
from cert_hub.exception.validator_exceptions import ValidationError

app = Flask(__name__)


def test_query_date_parses_iso_date():
    with app.test_request_context("/?since=2026-06-01"):
        assert v.query_date("since", default=None) == datetime(2026, 6, 1)


def test_query_date_parses_iso_datetime():
    with app.test_request_context("/?since=2026-06-01T12:30:00"):
        assert v.query_date("since", default=None) == datetime(2026, 6, 1, 12, 30, 0)


def test_query_date_absent_returns_none():
    with app.test_request_context("/"):
        assert v.query_date("since", default=None) is None


def test_query_date_absent_returns_default():
    default = datetime(2000, 1, 1)
    with app.test_request_context("/"):
        assert v.query_date("since", default=default) == default


def test_query_date_absent_required_raises():
    with app.test_request_context("/"):
        with pytest.raises(InvalidRequestError):
            v.query_date("since", default=None, required=True)


def test_query_date_invalid_format_raises():
    with app.test_request_context("/?since=not-a-date"):
        with pytest.raises(InvalidRequestError) as exc:
            v.query_date("since", default=None)
        assert exc.value.code == 400


def test_secret_envs_accepts_file_variant(monkeypatch):
    monkeypatch.delenv("CH_FAKE_SECRET", raising=False)
    monkeypatch.setenv("CH_FAKE_SECRET__FILE", "/some/path")
    Require.secret_envs(["CH_FAKE_SECRET"])  # must not raise


def test_secret_envs_accepts_plain_variant(monkeypatch):
    monkeypatch.setenv("CH_FAKE_SECRET", "value")
    monkeypatch.delenv("CH_FAKE_SECRET__FILE", raising=False)
    Require.secret_envs(["CH_FAKE_SECRET"])  # must not raise


def test_secret_envs_missing_raises(monkeypatch):
    monkeypatch.delenv("CH_FAKE_SECRET", raising=False)
    monkeypatch.delenv("CH_FAKE_SECRET__FILE", raising=False)
    with pytest.raises(ValidationError):
        Require.secret_envs(["CH_FAKE_SECRET"])


def test_installed_module_passes_when_present(monkeypatch):
    seen = {}

    def fake_version(name):
        seen["name"] = name
        return "5.2.2"

    monkeypatch.setattr(importlib.metadata, "version", fake_version)
    # A hyphenated pip distribution name must be queried verbatim. The old
    # importlib.util.find_spec() check returned None for hyphenated names
    # (illegal in module names), wrongly reporting installed packages as missing.
    Require.installed_module("dns_provider", "aws", "certbot-dns-route53")  # must not raise
    assert seen["name"] == "certbot-dns-route53"


def test_installed_module_raises_when_missing(monkeypatch):
    def fake_version(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", fake_version)
    with pytest.raises(ValidationError) as exc:
        Require.installed_module("dns_provider", "aws", "certbot-dns-route53")
    assert "certbot-dns-route53" in str(exc.value)


def test_installed_module_accepts_real_hyphenated_distribution():
    # Regression guard against the find_spec hyphen bug, exercised against the
    # real installed distribution when available (e.g. in the Docker image).
    try:
        importlib.metadata.version("certbot-dns-route53")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("certbot-dns-route53 not installed in this environment")
    Require.installed_module("dns_provider", "aws", "certbot-dns-route53")  # must not raise


def test_query_one_of_returns_value_when_allowed():
    with app.test_request_context("/?type=static"):
        assert v.query_one_of("type", default="all", allowed=["letsencrypt", "static", "all"]) == "static"


def test_query_one_of_returns_default_when_absent():
    with app.test_request_context("/"):
        assert v.query_one_of("type", default="all", allowed=["letsencrypt", "static", "all"]) == "all"


def test_query_one_of_rejects_disallowed():
    with app.test_request_context("/?type=bogus"):
        with pytest.raises(InvalidRequestError) as exc:
            v.query_one_of("type", default="all", allowed=["letsencrypt", "static", "all"])
        assert exc.value.code == 400
