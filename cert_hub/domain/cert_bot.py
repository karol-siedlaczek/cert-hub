import subprocess
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import Sequence, Optional, cast
from flask import current_app as app, g
from cert_hub.domain.dns_provider import DnsProvider
from cert_hub.exception.cert_exceptions import CertBotError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class CertBot:
    acme_server: str
    work_dir: Path
    logs_dir: Path
    conf_dir: Path
    lock_dir: Path
    exe_path: Path
    renew_before_days: int
    base_args: Sequence[str]
    
    @classmethod
    def load(
        cls,
        acme_server: str,
        base_dir: Path,
        exe_path: Path,
        renew_before_days: int
    ) -> "CertBot":
        work_dir = base_dir / "work"
        logs_dir = base_dir / "logs"
        conf_dir = base_dir / "config"
        lock_dir = base_dir / "lock"
        
        return cls(
            acme_server = acme_server,
            work_dir = work_dir,
            logs_dir = logs_dir,
            conf_dir = conf_dir,
            lock_dir = lock_dir,
            exe_path = exe_path,
            renew_before_days = renew_before_days,
            base_args = [
                "--non-interactive",
                "--server", acme_server,
                "--config-dir", str(conf_dir),
                "--work-dir", str(work_dir),
                "--logs-dir", str(logs_dir),
                "--max-log-backups", "100",
                "--issuance-timeout", "90",
                "--test-cert",
                #"--quiet",
                "--force-renewal"
            ]
        )
    

    @staticmethod
    def get_from_global_context() -> "CertBot":
        if "certbot" not in g:
            g.certbot = cast(CertBot, app.extensions["certbot"])
        return g.certbot


    def issue(self, cert_name: str, domains: list[str], email: str, dns_provider: DnsProvider) -> None:
        cmd = [
            str(self.exe_path), 
            "certonly",
            "--cert-name", cert_name,
            "-d", (',').join(domains),
            "--email", email,
            f"--{dns_provider.get_plugin()}",
            "--agree-tos",
            *self.base_args
        ]
        log.debug(f"Certbot issue command for '{cert_name}' certificate: {' '.join(cmd)}")
        
        result = self._run_cmd(cmd)
        if result.returncode != 0:
            raise CertBotError(cert_name, return_code=result.returncode, cmd=cmd, output=result.stderr)

    
    def renew(self, cert_name: str, dns_provider: DnsProvider) -> None:
        cmd = [
            str(self.exe_path), 
            "renew",
            "--cert-name", cert_name,
            f"--{dns_provider.get_plugin()}",
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
    