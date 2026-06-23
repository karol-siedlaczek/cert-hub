import os
import stat
import pytest
from pathlib import Path

from cert_hub.domain.cert_bot import CertBot
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
