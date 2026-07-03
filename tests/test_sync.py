"""Command-level integration tests for `cert sync`.

These exercise `cert_sync` end-to-end (CLI invocation through to
on-disk files), locking in the three-site filename-consistency invariant and
the configurable-extension behaviour that the helper unit tests do not cover.

Network and settings are stubbed: `Client.init` is monkeypatched to return a
fake client whose `.request()` yields a fake response, and dummy CERTHUB_*
env vars satisfy the command's own `load_settings` call.
"""

import datetime as dt
import json
import hashlib

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from typer.testing import CliRunner
import pytest

import certhub


DATE_FMT = certhub.DATE_FMT
ENV = {"CERTHUB_API_URL": "http://x", "CERTHUB_TOKEN": "t"}


@pytest.fixture(autouse=True)
def _isolate_settings_file(tmp_path, monkeypatch):
    # Ignore any real ~/.certhub on the developer's machine so the command's
    # load_settings reads only our env vars (and, crucially, no LOG_FILE -> the
    # logger stays disabled instead of trying to open a missing log path).
    monkeypatch.setattr(certhub, "SETTINGS_FILE", tmp_path / "nonexistent-certhub")

    # render_and_exit re-fetches the active click context via
    # click.get_current_context(); under CliRunner the command callback is run
    # through ctx.invoke(), which doesn't push onto click's global context
    # stack, so that lookup raises. Pin the output settings here (JSON keeps the
    # rendered result deterministic). This only affects how the result is
    # rendered, not the file-writing logic under test.
    settings = certhub.Settings(
        api_url="http://x", token="t", log_file=None, log_level=None,
        format=certhub.Format.JSON,
    )
    monkeypatch.setattr(certhub, "get_ctx_settings", lambda: settings)


def _make_cert(*, days_valid: int = 365, cn: str = "example.com"):
    """Build a self-signed cert + key. Returns (cert_pem, key_pem, not_after)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    not_before = now - dt.timedelta(days=max(1, -days_valid + 1))
    not_after = now + dt.timedelta(days=days_valid)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem, not_after


class _FakeResponse:
    """Minimal stand-in for requests.Response consumed by CmdResult."""

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


def _patch_client(monkeypatch, cert_dicts):
    """Make Client.init return a fake client serving `cert_dicts` as /api/certs."""
    monkeypatch.setattr(
        certhub.Client, "init",
        classmethod(lambda cls, ctx, fmt, *, timeout: _FakeClient(cert_dicts)),
    )


def _invoke(tmp_path, extra_args, cert_dicts, monkeypatch):
    _patch_client(monkeypatch, cert_dicts)
    runner = CliRunner()
    args = ["cert", "sync", str(tmp_path)] + extra_args
    return runner.invoke(certhub.app, args, env=ENV)


def _cert_dict(*, cert_id, certificate=None, private_key=None, chain=None,
               expire_date=None, status="ISSUED", pem_prefix=None):
    d = {
        "id": cert_id,
        "status": status,
        "certificate": certificate,
        "chain": chain,
        "private_key": private_key,
        "expire_date": expire_date,
    }
    if pem_prefix is not None:
        d["custom_attrs"] = {"pem_prefix": pem_prefix}
    return d


def test_default_writes_pem(tmp_path, monkeypatch):
    """No --ext, future expiry, empty dir -> writes <prefix>_bundle.pem on disk."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(
        cert_id="mycert",
        certificate=cert_pem,
        private_key=key_pem,
        expire_date=not_after.strftime(DATE_FMT),
    )

    result = _invoke(tmp_path, [], [cert], monkeypatch)

    assert result.exit_code == 0, result.output
    bundle = tmp_path / "mycert_bundle.pem"
    assert bundle.exists()
    content = bundle.read_text()
    assert "-----BEGIN CERTIFICATE-----" in content
    assert "-----BEGIN RSA PRIVATE KEY-----" in content
    # No stray .crt/.key variants from a default run.
    assert not (tmp_path / "mycert_bundle.crt").exists()


def test_ext_writes_custom(tmp_path, monkeypatch):
    """-P cert -P privkey with custom exts -> writes .crt/.key, not .pem."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(
        cert_id="mycert",
        certificate=cert_pem,
        private_key=key_pem,
        expire_date=not_after.strftime(DATE_FMT),
    )

    result = _invoke(
        tmp_path,
        ["-P", "cert", "-P", "privkey", "--ext", "cert=crt", "--ext", "privkey=key"],
        [cert],
        monkeypatch,
    )

    assert result.exit_code == 0, result.output
    crt = tmp_path / "mycert_cert.crt"
    key = tmp_path / "mycert_privkey.key"
    assert crt.exists()
    assert key.exists()
    assert "-----BEGIN CERTIFICATE-----" in crt.read_text()
    assert "-----BEGIN RSA PRIVATE KEY-----" in key.read_text()
    # The .pem variants must NOT be created.
    assert not (tmp_path / "mycert_cert.pem").exists()
    assert not (tmp_path / "mycert_privkey.pem").exists()


def test_expiry_update_custom_ext(tmp_path, monkeypatch):
    """Pre-existing custom-ext cert that expires earlier than server -> rewritten.

    Proves the expiry-reference path reads the custom-extension file, not a
    hardcoded .pem.
    """
    old_cert_pem, old_key_pem, _ = _make_cert(days_valid=10)
    new_cert_pem, new_key_pem, new_not_after = _make_cert(days_valid=365)

    crt = tmp_path / "mycert_cert.crt"
    key = tmp_path / "mycert_privkey.key"
    crt.write_text(old_cert_pem)
    key.write_text(old_key_pem)

    cert = _cert_dict(
        cert_id="mycert",
        certificate=new_cert_pem,
        private_key=new_key_pem,
        expire_date=new_not_after.strftime(DATE_FMT),
    )

    result = _invoke(
        tmp_path,
        ["-P", "cert", "-P", "privkey", "--ext", "cert=crt", "--ext", "privkey=key"],
        [cert],
        monkeypatch,
    )

    assert result.exit_code == 0, result.output
    # File rewritten with the new server cert content.
    assert crt.read_text().strip() == new_cert_pem.strip()
    assert key.read_text().strip() == new_key_pem.strip()
    assert "Updated" in result.output
    # No .pem sibling should have appeared.
    assert not (tmp_path / "mycert_cert.pem").exists()


def test_fullchain_writes_cert_and_chain_without_key(tmp_path, monkeypatch):
    """-P fullchain -> <prefix>_fullchain.pem holds cert + chain, never the private key."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    chain_pem, _, _ = _make_cert(days_valid=730, cn="intermediate")
    cert = _cert_dict(
        cert_id="mycert",
        certificate=cert_pem,
        private_key=key_pem,
        chain=chain_pem,
        expire_date=not_after.strftime(DATE_FMT),
    )

    result = _invoke(tmp_path, ["-P", "fullchain"], [cert], monkeypatch)

    assert result.exit_code == 0, result.output
    fullchain = tmp_path / "mycert_fullchain.pem"
    assert fullchain.exists()
    content = fullchain.read_text()
    assert content.strip() == f"{cert_pem.strip()}\n{chain_pem.strip()}"
    assert "PRIVATE KEY" not in content
    # bundle sibling must not appear from a fullchain-only run
    assert not (tmp_path / "mycert_bundle.pem").exists()


def test_fullchain_missing_chain_is_critical(tmp_path, monkeypatch):
    """fullchain requires the chain; server returning none -> CRITICAL, no file written."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(
        cert_id="mycert",
        certificate=cert_pem,
        private_key=key_pem,
        chain=None,
        expire_date=not_after.strftime(DATE_FMT),
    )

    result = _invoke(tmp_path, ["-P", "fullchain"], [cert], monkeypatch)

    assert "Chain is missing on server side" in result.output
    assert not (tmp_path / "mycert_fullchain.pem").exists()


def test_status_file_on_success(tmp_path, monkeypatch):
    """--status-file writes JSON: OK status/exit_code, OK message, and the result rows."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(
        cert_id="mycert",
        certificate=cert_pem,
        private_key=key_pem,
        expire_date=not_after.strftime(DATE_FMT),
    )

    status_path = tmp_path / "status" / "result.json"
    result = _invoke(
        tmp_path, ["--status-file", str(status_path)], [cert], monkeypatch
    )

    assert result.exit_code == 0, result.output
    assert status_path.exists()  # parent dir created on demand
    status = json.loads(status_path.read_text())
    assert status["status"] == "OK"
    assert status["exit_code"] == 0
    assert status["msg"] == "OK: All certificates synced and up to date"
    # result mirrors the console rows
    assert isinstance(status["result"], list)
    assert status["result"][0]["id"] == "mycert"
    assert status["result"][0]["updated"] is True


def test_status_file_on_warning(tmp_path, monkeypatch):
    """Cert not issued on server -> status file records WARNING + the same message text."""
    cert = _cert_dict(cert_id="mycert", certificate=None, private_key=None)

    status_path = tmp_path / "result.json"
    result = _invoke(
        tmp_path, ["--status-file", str(status_path)], [cert], monkeypatch
    )

    assert result.exit_code == 0, result.output
    status = json.loads(status_path.read_text())
    assert status["status"] == "WARNING"
    assert status["exit_code"] == 1
    assert status["msg"].startswith("WARNING:")
    assert "mycert" in status["msg"]
    assert "Not issued on server side" in status["msg"]


def test_revoke_removes_custom_ext(tmp_path, monkeypatch):
    """A previously-synced cert reported REVOKED has its files removed (tracked-cert cleanup)."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    issued = _cert_dict(cert_id="mycert", certificate=cert_pem, private_key=key_pem,
                        expire_date=not_after.strftime(DATE_FMT))
    args = ["-P", "cert", "-P", "privkey", "--ext", "cert=crt", "--ext", "privkey=key"]
    _invoke(tmp_path, args, [issued], monkeypatch)  # first run: writes + records state
    crt = tmp_path / "mycert_cert.crt"
    key = tmp_path / "mycert_privkey.key"
    assert crt.exists() and key.exists()

    revoked = _cert_dict(cert_id="mycert", status="REVOKED")
    result = _invoke(tmp_path, args, [revoked], monkeypatch)

    assert result.exit_code == 0, result.output
    assert not crt.exists()
    assert not key.exists()


def test_sha256_file(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"hello world")
    assert certhub.sha256_file(p) == hashlib.sha256(b"hello world").hexdigest()


def test_state_filter_obj_sorts_patterns():
    assert certhub.state_filter_obj(["b", "a"], "letsencrypt") == {
        "type": "letsencrypt", "patterns": ["a", "b"],
    }


def test_state_filter_obj_handles_none_patterns():
    assert certhub.state_filter_obj(None, "all") == {"type": "all", "patterns": []}


def test_load_sync_state_missing_returns_empty(tmp_path):
    assert certhub.load_sync_state(tmp_path / "nope.json") == {}


def test_load_sync_state_corrupt_returns_empty(tmp_path):
    p = tmp_path / "state.json"
    p.write_text("{ not valid json")
    assert certhub.load_sync_state(p) == {}


def test_write_then_load_roundtrip(tmp_path):
    p = tmp_path / "state.json"
    certhub.write_sync_state(
        p,
        {"type": "all", "patterns": []},
        [{"id": "c", "files": [{"file": "c_bundle.pem", "sha256": "abc"}]}],
        dt.datetime(2026, 7, 3, tzinfo=dt.timezone.utc),
    )
    loaded = certhub.load_sync_state(p)
    assert loaded["version"] == 1
    assert loaded["filter"] == {"type": "all", "patterns": []}
    assert loaded["certs"][0]["id"] == "c"
    assert loaded["certs"][0]["files"][0]["sha256"] == "abc"


def test_dry_run_does_not_write_pem(tmp_path, monkeypatch):
    """--dry-run on an empty dir reports "Would add", writes no PEM file, and no status file."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(
        cert_id="mycert", certificate=cert_pem, private_key=key_pem,
        expire_date=not_after.strftime(DATE_FMT),
    )
    status_path = tmp_path / "status.json"

    result = _invoke(
        tmp_path, ["--dry-run", "--status-file", str(status_path)], [cert], monkeypatch
    )

    assert result.exit_code == 0, result.output
    assert not (tmp_path / "mycert_bundle.pem").exists()
    assert not status_path.exists()  # dry-run writes no status file
    assert '"msg": "Would add"' in result.output
    assert '"updated": false' in result.output


def test_dry_run_keeps_revoked_files(tmp_path, monkeypatch):
    """--dry-run leaves a tracked, now-revoked cert's files and writes no status file."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    issued = _cert_dict(cert_id="mycert", certificate=cert_pem, private_key=key_pem,
                        expire_date=not_after.strftime(DATE_FMT))
    _invoke(tmp_path, [], [issued], monkeypatch)  # first run: writes bundle + state
    bundle = tmp_path / "mycert_bundle.pem"
    assert bundle.exists()

    status_path = tmp_path / "status.json"
    revoked = _cert_dict(cert_id="mycert", status="REVOKED")
    result = _invoke(
        tmp_path, ["--dry-run", "--status-file", str(status_path)], [revoked], monkeypatch
    )

    assert result.exit_code == 0, result.output
    assert bundle.exists()  # not deleted under dry-run
    assert not status_path.exists()  # dry-run writes no status file


def test_state_file_written_with_checksums(tmp_path, monkeypatch):
    """A successful sync records the cert and its file's sha256 in the state file."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(
        cert_id="mycert", certificate=cert_pem, private_key=key_pem,
        expire_date=not_after.strftime(DATE_FMT),
    )

    result = _invoke(tmp_path, [], [cert], monkeypatch)

    assert result.exit_code == 0, result.output
    state_path = tmp_path / ".certhub-sync-state.json"
    assert state_path.exists()
    state = json.loads(state_path.read_text())
    assert state["version"] == 1
    assert state["filter"] == {"type": "all", "patterns": []}
    assert state["certs"][0]["id"] == "mycert"
    bundle = tmp_path / "mycert_bundle.pem"
    entry = state["certs"][0]["files"][0]
    assert entry["file"] == "mycert_bundle.pem"
    assert entry["sha256"] == certhub.sha256_file(bundle)


def test_state_file_not_written_on_dry_run(tmp_path, monkeypatch):
    """--dry-run must not create or update the state file."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(
        cert_id="mycert", certificate=cert_pem, private_key=key_pem,
        expire_date=not_after.strftime(DATE_FMT),
    )

    result = _invoke(tmp_path, ["--dry-run"], [cert], monkeypatch)

    assert result.exit_code == 0, result.output
    assert not (tmp_path / ".certhub-sync-state.json").exists()


def test_prune_removes_disappeared_cert(tmp_path, monkeypatch):
    """A cert present last run but absent now has its files removed and drops from state."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(
        cert_id="mycert", certificate=cert_pem, private_key=key_pem,
        expire_date=not_after.strftime(DATE_FMT),
    )
    # First run: writes the cert and records it in the state file.
    _invoke(tmp_path, [], [cert], monkeypatch)
    bundle = tmp_path / "mycert_bundle.pem"
    assert bundle.exists()

    # Second run: server returns nothing -> cert is pruned.
    result = _invoke(tmp_path, [], [], monkeypatch)

    assert result.exit_code == 0, result.output
    assert not bundle.exists()
    state = json.loads((tmp_path / ".certhub-sync-state.json").read_text())
    assert state["certs"] == []


def test_prune_checksum_mismatch_keeps_file_and_warns(tmp_path, monkeypatch):
    """A locally modified file is not deleted during prune; the run reports WARNING."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(
        cert_id="mycert", certificate=cert_pem, private_key=key_pem,
        expire_date=not_after.strftime(DATE_FMT),
    )
    _invoke(tmp_path, [], [cert], monkeypatch)
    bundle = tmp_path / "mycert_bundle.pem"
    bundle.write_text(bundle.read_text() + "\n# locally edited\n")

    status_path = tmp_path / "status.json"
    result = _invoke(
        tmp_path, ["--status-file", str(status_path)], [], monkeypatch
    )

    assert result.exit_code == 0, result.output
    assert bundle.exists()  # not deleted
    status = json.loads(status_path.read_text())
    assert status["status"] == "WARNING"
    row = next(r for r in status["result"] if r["id"] == "mycert")
    assert "checksum mismatch" in row["msg"]


def test_prune_respects_dry_run(tmp_path, monkeypatch):
    """--dry-run reports the prune but neither deletes files nor rewrites state."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(
        cert_id="mycert", certificate=cert_pem, private_key=key_pem,
        expire_date=not_after.strftime(DATE_FMT),
    )
    _invoke(tmp_path, [], [cert], monkeypatch)
    bundle = tmp_path / "mycert_bundle.pem"

    result = _invoke(tmp_path, ["--dry-run"], [], monkeypatch)

    assert result.exit_code == 0, result.output
    assert bundle.exists()  # not deleted under dry-run
    state = json.loads((tmp_path / ".certhub-sync-state.json").read_text())
    assert state["certs"][0]["id"] == "mycert"  # state unchanged


def test_filter_change_prunes_nonmatching(tmp_path, monkeypatch):
    """A cert dropped because the filter narrowed is pruned like any absent cert."""
    a_cert_pem, a_key_pem, a_exp = _make_cert(days_valid=365, cn="a.example")
    b_cert_pem, b_key_pem, b_exp = _make_cert(days_valid=365, cn="b.example")
    a = _cert_dict(cert_id="aaa", certificate=a_cert_pem, private_key=a_key_pem,
                   expire_date=a_exp.strftime(DATE_FMT))
    b = _cert_dict(cert_id="bbb", certificate=b_cert_pem, private_key=b_key_pem,
                   expire_date=b_exp.strftime(DATE_FMT))
    # First run: no filter, both certs recorded.
    _invoke(tmp_path, [], [a, b], monkeypatch)
    assert (tmp_path / "aaa_bundle.pem").exists()
    assert (tmp_path / "bbb_bundle.pem").exists()

    # Second run: narrowed filter, server returns only aaa -> bbb pruned.
    result = _invoke(tmp_path, ["--pattern", "aaa"], [a], monkeypatch)

    assert result.exit_code == 0, result.output
    assert (tmp_path / "aaa_bundle.pem").exists()
    assert not (tmp_path / "bbb_bundle.pem").exists()


def test_revoked_cert_drops_from_state(tmp_path, monkeypatch):
    """A tracked cert reported REVOKED is removed and drops from the rewritten state."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    issued = _cert_dict(cert_id="mycert", certificate=cert_pem, private_key=key_pem,
                        expire_date=not_after.strftime(DATE_FMT))
    _invoke(tmp_path, [], [issued], monkeypatch)
    bundle = tmp_path / "mycert_bundle.pem"
    assert bundle.exists()

    revoked = _cert_dict(cert_id="mycert", status="REVOKED")
    result = _invoke(tmp_path, [], [revoked], monkeypatch)

    assert result.exit_code == 0, result.output
    assert not bundle.exists()
    state = json.loads((tmp_path / ".certhub-sync-state.json").read_text())
    assert state["certs"] == []


def test_filter_change_warns_in_result(tmp_path, monkeypatch):
    """A narrowed filter that drops a cert surfaces a WARNING row in the status file."""
    a_pem, a_key, a_exp = _make_cert(days_valid=365, cn="a.example")
    b_pem, b_key, b_exp = _make_cert(days_valid=365, cn="b.example")
    a = _cert_dict(cert_id="aaa", certificate=a_pem, private_key=a_key,
                   expire_date=a_exp.strftime(DATE_FMT))
    b = _cert_dict(cert_id="bbb", certificate=b_pem, private_key=b_key,
                   expire_date=b_exp.strftime(DATE_FMT))
    _invoke(tmp_path, [], [a, b], monkeypatch)  # no filter -> records aaa, bbb

    status_path = tmp_path / "status.json"
    result = _invoke(
        tmp_path, ["--pattern", "aaa", "--status-file", str(status_path)], [a], monkeypatch
    )

    assert result.exit_code == 0, result.output
    status = json.loads(status_path.read_text())
    assert status["status"] == "WARNING"
    assert any("Filter changed since last run" in r["msg"] for r in status["result"])


def test_prune_triggers_post_hook(tmp_path, monkeypatch):
    """Pruning a disappeared cert counts as a change and fires --post-hook."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(cert_id="mycert", certificate=cert_pem, private_key=key_pem,
                      expire_date=not_after.strftime(DATE_FMT))
    _invoke(tmp_path, [], [cert], monkeypatch)

    marker = tmp_path / "hook-ran"
    result = _invoke(tmp_path, ["--post-hook", f"touch {marker}"], [], monkeypatch)

    assert result.exit_code == 0, result.output
    assert marker.exists()


def test_omit_post_hook_on_cleanup_suppresses(tmp_path, monkeypatch):
    """--omit-post-hook-on-cleanup stops prune cleanup from firing --post-hook."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(cert_id="mycert", certificate=cert_pem, private_key=key_pem,
                      expire_date=not_after.strftime(DATE_FMT))
    _invoke(tmp_path, [], [cert], monkeypatch)

    marker = tmp_path / "hook-ran"
    result = _invoke(
        tmp_path,
        ["--omit-post-hook-on-cleanup", "--post-hook", f"touch {marker}"],
        [],
        monkeypatch,
    )

    assert result.exit_code == 0, result.output
    assert not marker.exists()


def test_corrupt_state_entry_does_not_crash(tmp_path, monkeypatch):
    """A JSON-valid state entry missing the 'file' key is tolerated, not a crash."""
    state = {
        "version": 1,
        "filter": {"type": "all", "patterns": []},
        "timestamp": "2026-07-03T00:00:00+00:00",
        "certs": [{"id": "ghost", "files": [{"sha256": "deadbeef"}]}],
    }
    (tmp_path / ".certhub-sync-state.json").write_text(json.dumps(state))

    result = _invoke(tmp_path, [], [], monkeypatch)

    assert result.exit_code == 0, result.output


def test_revoke_checksum_mismatch_keeps_file_and_warns(tmp_path, monkeypatch):
    """A locally modified file for a now-revoked tracked cert is kept; run reports WARNING."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    issued = _cert_dict(cert_id="mycert", certificate=cert_pem, private_key=key_pem,
                        expire_date=not_after.strftime(DATE_FMT))
    _invoke(tmp_path, [], [issued], monkeypatch)
    bundle = tmp_path / "mycert_bundle.pem"
    bundle.write_text(bundle.read_text() + "\n# locally edited\n")

    status_path = tmp_path / "status.json"
    revoked = _cert_dict(cert_id="mycert", status="REVOKED")
    result = _invoke(
        tmp_path, ["--status-file", str(status_path)], [revoked], monkeypatch
    )

    assert result.exit_code == 0, result.output
    assert bundle.exists()  # not deleted (checksum mismatch)
    status = json.loads(status_path.read_text())
    assert status["status"] == "WARNING"
    row = next(r for r in status["result"] if r["id"] == "mycert")
    assert "Revoked on server" in row["msg"]
    assert "checksum mismatch" in row["msg"]


def test_untracked_revoked_cert_not_removed(tmp_path, monkeypatch):
    """A revoked cert never recorded in state (files placed out-of-band) is left alone."""
    cert_pem, key_pem, _ = _make_cert(days_valid=365)
    bundle = tmp_path / "mycert_bundle.pem"
    bundle.write_text(cert_pem + key_pem)  # placed manually, no prior sync -> not in state

    revoked = _cert_dict(cert_id="mycert", status="REVOKED")
    result = _invoke(tmp_path, [], [revoked], monkeypatch)

    assert result.exit_code == 0, result.output
    assert bundle.exists()  # untracked -> unified cleanup does not touch it


def test_errored_cert_still_returned_is_not_pruned(tmp_path, monkeypatch):
    """A tracked cert still returned but with a server-side error keeps its local files."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    issued = _cert_dict(cert_id="mycert", certificate=cert_pem, private_key=key_pem,
                        expire_date=not_after.strftime(DATE_FMT))
    _invoke(tmp_path, [], [issued], monkeypatch)
    bundle = tmp_path / "mycert_bundle.pem"
    assert bundle.exists()

    # Second run: server returns the cert but with no private key (a CRITICAL error),
    # NOT revoked and NOT absent -> must keep the local file.
    errored = _cert_dict(cert_id="mycert", certificate=cert_pem, private_key=None,
                         expire_date=not_after.strftime(DATE_FMT))
    result = _invoke(tmp_path, [], [errored], monkeypatch)

    assert result.exit_code == 0, result.output
    assert bundle.exists()  # still returned (errored, not revoked) -> not pruned
