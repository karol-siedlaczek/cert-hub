"""Tests for `cert show` and single-row (vertical) rendering."""

import json

import pytest
import typer
from typer.testing import CliRunner

import certhub

ENV = {"CERTHUB_API_URL": "http://x", "CERTHUB_TOKEN": "t"}


@pytest.fixture(autouse=True)
def _isolate_settings_file(tmp_path, monkeypatch):
    # Same isolation as tests/test_sync.py: ignore any real ~/.certhub and keep
    # the logger disabled by giving no LOG_FILE.
    monkeypatch.setattr(certhub, "SETTINGS_FILE", tmp_path / "nonexistent-certhub")


def _pin_format(monkeypatch, fmt):
    settings = certhub.Settings(
        api_url="http://x", token="t", log_file=None, log_level=None, format=fmt,
    )
    monkeypatch.setattr(certhub, "get_ctx_settings", lambda: settings)


def test_single_row_table_is_vertical(monkeypatch, capsys):
    _pin_format(monkeypatch, certhub.Format.TABLE)
    result = certhub.CmdResult.from_dict(
        {"id": "siedlaczek.com.pl", "status": "OK"}, certhub.ExitCode.OK)

    with pytest.raises(typer.Exit) as exc:
        result.render_and_exit(single_row=True)

    assert exc.value.exit_code == 0
    out = capsys.readouterr().out
    assert "Field" in out and "Value" in out
    assert "siedlaczek.com.pl" in out
    assert "status" in out


class _FakeResponse:
    def __init__(self, payload, ok=True, status_code=200):
        self._payload = payload
        self.ok = ok
        self.status_code = status_code
        self.text = "" if payload is None else str(payload)

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, payload):
        self._payload = payload

    def request(self, method, path, *, params=None, json_body=None):
        return _FakeResponse(self._payload)


def _patch_client(monkeypatch, payload):
    monkeypatch.setattr(
        certhub.Client, "init",
        classmethod(lambda cls, ctx, fmt, *, timeout: _FakeClient(payload)),
    )


def _show(monkeypatch, payload, cert_id, extra_args=None, fmt=certhub.Format.JSON):
    _pin_format(monkeypatch, fmt)
    _patch_client(monkeypatch, payload)
    runner = CliRunner()
    args = ["cert", "show", cert_id] + (extra_args or [])
    return runner.invoke(certhub.app, args, env=ENV)


def test_show_json_is_single_object(monkeypatch):
    payload = [{"id": "siedlaczek.com.pl", "status": "OK", "type": "letsencrypt"}]
    result = _show(monkeypatch, payload, "siedlaczek.com.pl")
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert isinstance(parsed, dict)          # {} not [{}]
    assert parsed["id"] == "siedlaczek.com.pl"


def test_show_not_found_is_critical(monkeypatch):
    result = _show(monkeypatch, [], "missing.example")
    assert result.exit_code == 2, result.output
    assert "not found" in result.output.lower()


def test_show_ambiguous_is_critical(monkeypatch):
    payload = [{"id": "a.example"}, {"id": "b.example"}]
    result = _show(monkeypatch, payload, "*.example")
    assert result.exit_code == 2, result.output
    assert "ambiguous" in result.output.lower()


def test_show_exact_match_wins_over_glob_siblings(monkeypatch):
    payload = [{"id": "a.example", "status": "OK"},
               {"id": "b.example", "status": "OK"}]
    result = _show(monkeypatch, payload, "a.example")
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert parsed["id"] == "a.example"


def test_show_column_filter(monkeypatch):
    payload = [{"id": "siedlaczek.com.pl", "status": "OK", "type": "letsencrypt"}]
    result = _show(monkeypatch, payload, "siedlaczek.com.pl", ["-c", "id"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert parsed == {"id": "siedlaczek.com.pl"}
