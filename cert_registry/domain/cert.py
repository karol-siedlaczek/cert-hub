import re
import logging
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from enum import Enum
from datetime import datetime
from dataclasses import dataclass
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cert_registry.domain.base import DomainEnum
from cert_registry.errors.cert_error import CertNotIssuedException
from cert_registry.domain.permission import PermissionAction
from cert_registry.domain.identity import Identity
from cert_registry.validation.require import Require

log = logging.getLogger(__name__)


class DnsProvider(Enum):
    AWS = "aws"
    
    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]
    
    def get_plugin(self) -> str:
        if self == DnsProvider.AWS:
            return 'dns-route53'
        else:
            return None
        
    def get_required_module(self) -> str:
        if self == DnsProvider.AWS:
            return "certbot-dns-route53"
        else:
            return None


class CertStatus(Enum):
    NOT_ISSUED = "NOT_ISSUED"
    EXPIRING = "EXPIRING"
    OK = "OK"
    

@dataclass(frozen=True)
class Cert:   
    id: str
    email: str
    domains: tuple[str, ...] # TODO - Do I need tuple?
    base_path: Path
    dns_provider: DnsProvider
    
    @classmethod
    def from_dict(cls, data: dict[str, Any], certbot_conf_dir: Path) -> "Cert":
        def get_required(name: str) -> Any:
            val = data.get(name)
            Require.present(name, val)
            return val
        
        id = get_required("id")
        email = get_required("email")
        domains = get_required("domains")
        dns_provider_raw = get_required("dns_provider")
        base_path = certbot_conf_dir / "live" / id
        
        Require.type("id", id, str)
        Require.email("email", email)
        Require.type("domains", domains, list)
        
        for i, domain in enumerate(domains):
            Require.domain(f"domains[{i}]", domain)
            
        Require.one_of("dns_provider", dns_provider_raw, DnsProvider.values())
        dns_provider = DnsProvider(dns_provider_raw)
        
        Require.installed_module("dns_provider", dns_provider.value, dns_provider.get_required_module()) 
    
        return cls(id, email, tuple(domains), base_path, DnsProvider(dns_provider_raw))

    
    def has_permission(self, identity: Identity, action: PermissionAction) -> bool:
        log.debug(f"Perform permission check (cert='{self.id}'; identity='{identity.id}'; action='{action.value}')")
        
        if not identity:
            return False
        
        for permission in identity.permissions:
            if permission.action != PermissionAction.ANY and permission.action != action:
                continue
            
            if permission.scope == "*" or permission.scope == self.id:
                return True
            
            try:
                if re.fullmatch(permission.scope, self.id):
                    return True
            except re.error:
                continue
        
        return False
    
    
    def issue(
        self, 
        acme_server: str, 
        certbot_bin: Path, 
        certbot_conf_dir: Path, 
        certbot_work_dir: Path, 
        certbot_logs_dir: Path
    ) -> None:
        cmd = [
            str(certbot_bin), "certonly",
            f"--{self.dns_provider.get_plugin()}",
            "--cert-name", self.id,
            "--agree-tos",
            "-d", (',').join(self.domains),
            "--email", self.email,
            "--non-interactive",
            "--server", acme_server,
            "--config-dir", str(certbot_conf_dir),
            "--work-dir", str(certbot_work_dir),
            "--logs-dir", str(certbot_logs_dir),
            "--max-log-backups", "100"
            "--issuance-timeout", "90",
            "--test-cert",
            "--dry-run"
            #"--quiet"
            #"--force-renewal"
        ]
        #print(cmd)
        print((" ").join(cmd))
        # result = run_cmd(cmd, check=True)  
        # print(result)
    
    
    def renew(self) -> None:
        self._require_issued(f"Failed to renew '{self.id}' certificate")
        pass
    
    
    def get_full_chain(self) -> str:
        return f"{self.get_cert()}\n{self.get_chain()}"
    

    def get_chain(self) -> str:
        self._require_issued(f"Failed to get chain for '{self.id}' certificate") # TODO
        return self._read_text(self._get_chain_path())
    
    
    def get_cert(self) -> str:
        self._require_issued(f"Failed to get cert content for '{self.id}' certificate")
        return self._read_text(self._get_cert_path())
    
    
    def get_private_key(self) -> str:
        self._require_issued(f"Failed to get private key for '{self.id}' certificate")
        return self._read_text(self._get_private_key_path())


    def get_expire_date(self) -> datetime:
        self._require_issued(f"Failed to check expiry date for '{self.id}' certificate")
        
        cert_file = self._get_cert_path()
        
        try:
            pem_bytes = cert_file.read_bytes()
            cert = x509.load_pem_x509_certificate(pem_bytes, default_backend())
            expire_date = cert.not_valid_after
            
            if expire_date.tzinfo is None:
                expire_date = expire_date.replace(tzinfo=timezone.utc)
            return expire_date.astimezone(timezone.utc)
        except ModuleNotFoundError:
            info = ssl._ssl._test_do
    
    
    def get_status(self) -> CertStatus:
        if not self.is_issued():
            return CertStatus.NOT_ISSUED
        if self.get_expire_date() == 5: # TODO - Fix condition
            return CertStatus.EXPIRING
        else:
            return CertStatus.OK
    
    
    def is_issued(self) -> bool:
        required_paths = [
            self._get_cert_path(),
            self._get_chain_path(),
            self._get_private_key_path()
        ]
        for path in required_paths:
            if not path.exists():
                return False

        return True
        
        
    def is_to_renew(self) -> bool:
        return True

        
    def _require_issued(self, msg: str) -> None:
        if not self.is_issued():
            raise CertNotIssuedException(msg)

    
    def _read_text(self, file_path: Path) -> str:
        try:
            return file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return file_path.read_text(encoding="ascii", errors="ignore")


    def _get_cert_path(self) -> Path:
        return self.base_path / "cert.pem"


    def _get_chain_path(self) -> Path:
        return self.base_path / "chain.pem"


    def _get_private_key_path(self) -> Path:
        return self.base_path / "privkey.pem"
