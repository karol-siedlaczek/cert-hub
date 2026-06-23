import os
import subprocess
import logging
import tempfile
from pathlib import Path
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Sequence, Optional, cast, Iterator
from flask import current_app as app, g
from cert_hub.domain.dns_provider import DnsProvider
from cert_hub.exception.cert_exceptions import CertBotError
from cert_hub.exception.validator_exceptions import ValidationError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class CertBot:
    acme_server: str
    work_dir: Path
    logs_dir: Path
    conf_dir: Path
    exe_path: Path
    renew_before_days: int
    base_args: Sequence[str]
    cloudflare_dns_api_token: Optional[str] = None

    @classmethod
    def load(
        cls,
        acme_server: str,
        base_dir: Path,
        exe_path: Path,
        renew_before_days: int,
        test_cert: bool = False,
        cloudflare_dns_api_token: Optional[str] = None
    ) -> "CertBot":
        work_dir = base_dir / "work"
        logs_dir = base_dir / "logs"
        conf_dir = base_dir / "config"

        base_args = [
            "--non-interactive",
            "--server", acme_server,
            "--config-dir", str(conf_dir),
            "--work-dir", str(work_dir),
            "--logs-dir", str(logs_dir),
            "--max-log-backups", "100",
            "--issuance-timeout", "90",
            "--force-renewal"
        ]
        if test_cert:
            base_args.append("--test-cert")

        return cls(
            acme_server = acme_server,
            work_dir = work_dir,
            logs_dir = logs_dir,
            conf_dir = conf_dir,
            exe_path = exe_path,
            renew_before_days = renew_before_days,
            base_args = base_args,
            cloudflare_dns_api_token = cloudflare_dns_api_token
        )
    

    @staticmethod
    def get_from_global_context() -> "CertBot":
        if "certbot" not in g:
            g.certbot = cast(CertBot, app.extensions["certbot"])
        return g.certbot


    def issue(self, cert_name: str, domains: list[str], email: str, dns_provider: DnsProvider) -> None:
        with self._dns_provider_args(dns_provider) as dns_args:
            cmd = [
                str(self.exe_path),
                "certonly",
                "--cert-name", cert_name,
                "-d", (',').join(domains),
                "--email", email,
                *dns_args,
                "--agree-tos",
                *self.base_args
            ]
            log.debug(f"Certbot issue command for '{cert_name}' certificate: {' '.join(cmd)}")

            result = self._run_cmd(cmd)
            if result.returncode != 0:
                raise CertBotError(cert_name, return_code=result.returncode, cmd=cmd, output=result.stderr)

    
    def renew(self, cert_name: str, dns_provider: DnsProvider) -> None:
        with self._dns_provider_args(dns_provider) as dns_args:
            cmd = [
                str(self.exe_path),
                "renew",
                "--cert-name", cert_name,
                *dns_args,
                *self.base_args
            ]
            log.debug(f"Certbot renew command for '{cert_name}' certificate: {' '.join(cmd)}")

            result = self._run_cmd(cmd)
            if result.returncode != 0:
                raise CertBotError(cert_name, return_code=result.returncode, cmd=cmd, output=result.stderr)
    
        
    def get_cert_path(self, cert_name: str) -> Path:
        return self.conf_dir / "live" / cert_name / "cert.pem"


    def get_chain_path(self, cert_name: str) -> Path:
        return self.conf_dir / "live" / cert_name / "chain.pem"


    def get_private_key_path(self, cert_name: str) -> Path:
        return self.conf_dir / "live" / cert_name / "privkey.pem"

    @contextmanager
    def _dns_provider_args(self, dns_provider: DnsProvider) -> Iterator[list[str]]:
        if dns_provider == DnsProvider.CF:
            if not self.cloudflare_dns_api_token:
                raise ValidationError(
                    "Cloudflare DNS API token is not configured "
                    "(set CLOUDFLARE_DNS_API_TOKEN or CLOUDFLARE_DNS_API_TOKEN__FILE)"
                )
            with tempfile.NamedTemporaryFile("w", suffix=".ini", encoding="utf-8") as f:
                os.chmod(f.name, 0o600)
                f.write(f"dns_cloudflare_api_token = {self.cloudflare_dns_api_token}\n")
                f.flush()
                yield [f"--{dns_provider.get_plugin()}", "--dns-cloudflare-credentials", f.name]
        else:
            yield [f"--{dns_provider.get_plugin()}"]

    def _run_cmd(
        self,
        args: Sequence[str],
        *,
        shell: bool = False,
        timeout: Optional[int] = None
    ) -> subprocess.CompletedProcess[str]:
        args = [str(a) for a in args]
        
        result = subprocess.run(
            args, 
            stdin=subprocess.DEVNULL, 
            stderr=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            shell=shell, 
            text=True, 
            #executable="/bin/bash",
            timeout=timeout
        )
        return result
    