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
