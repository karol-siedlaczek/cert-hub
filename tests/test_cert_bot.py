import os
import stat
import pytest
from pathlib import Path
from types import SimpleNamespace

from cert_hub.domain.cert.cert_bot import CertBot
from cert_hub.domain.dns_provider import DnsProvider
from cert_hub.exception.validator_exceptions import ValidationError


def _make_certbot(token=None):
    return CertBot.load(
        acme_server="https://acme.example/directory",
        base_dir=Path("/tmp/certbot-test"),
        exe_path=Path("/usr/bin/certbot"),
        renew_before_days=30,
        cloudflare_dns_api_token=token,
    )


def test_aws_provider_args_is_plugin_flag_only():
    certbot = _make_certbot()
    with certbot._dns_provider_args(DnsProvider.AWS) as args:
        assert args == ["--dns-route53"]


def test_cloudflare_provider_args_and_credentials_file_lifecycle():
    certbot = _make_certbot(token="secret-token")
    with certbot._dns_provider_args(DnsProvider.CF) as args:
        assert args[0] == "--dns-cloudflare"
        assert "--dns-cloudflare-credentials" in args
        cred_path = Path(args[args.index("--dns-cloudflare-credentials") + 1])
        # File exists, is 0600, and holds the token while the block is open
        assert cred_path.exists()
        mode = stat.S_IMODE(os.stat(cred_path).st_mode)
        assert mode == 0o600
        assert cred_path.read_text() == "dns_cloudflare_api_token = secret-token\n"
    # File is removed after the block closes
    assert not cred_path.exists()


def test_cloudflare_missing_token_raises():
    certbot = _make_certbot(token=None)
    with pytest.raises(ValidationError):
        with certbot._dns_provider_args(DnsProvider.CF):
            pass


def test_revoke_builds_command(monkeypatch):
    from cert_hub.domain.cert.cert_bot import CertBot as _CertBot
    certbot = _make_certbot()
    captured = {}

    def fake_run(self, args, **kwargs):
        captured["cmd"] = [str(a) for a in args]
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(_CertBot, "_run_cmd", fake_run)
    certbot.revoke("example")

    cmd = captured["cmd"]
    assert cmd[1] == "revoke"
    assert "--delete-after-revoke" in cmd
    assert "--cert-path" in cmd
    assert str(certbot.get_cert_path("example")) in cmd


def test_revoke_raises_certbot_error_on_failure(monkeypatch):
    from cert_hub.domain.cert.cert_bot import CertBot as _CertBot
    from cert_hub.exception.cert_exceptions import CertBotError
    certbot = _make_certbot()

    def fake_run(self, args, **kwargs):
        return SimpleNamespace(returncode=1, stderr="boom")

    monkeypatch.setattr(_CertBot, "_run_cmd", fake_run)
    with pytest.raises(CertBotError):
        certbot.revoke("example")


def test_revoked_marker_mark_is_clear(tmp_path):
    certbot = CertBot.load(
        acme_server="https://acme.example/directory",
        base_dir=tmp_path,
        exe_path=Path("/usr/bin/certbot"),
        renew_before_days=30,
    )
    assert certbot.revoked_dir == tmp_path / "revoked"
    assert certbot.is_revoked("example") is False

    certbot.mark_revoked("example")
    assert certbot.is_revoked("example") is True
    assert (tmp_path / "revoked" / "example").exists()

    certbot.clear_revoked("example")
    assert certbot.is_revoked("example") is False
    certbot.clear_revoked("example")  # idempotent, must not raise
