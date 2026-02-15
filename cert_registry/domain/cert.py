import re
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, ClassVar
from datetime import datetime
from dataclasses import dataclass
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cert_registry.exception.cert_exceptions import CertException
from cert_registry.domain.permission import PermissionAction
from cert_registry.domain.identity import Identity
from cert_registry.domain.cert_bot import CertBot
from cert_registry.domain.cert_status import CertStatus
from cert_registry.domain.dns_provider import DnsProvider
from cert_registry.validation.require import Require

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Cert:
    DATE_FORMAT: ClassVar[str] = '%Y-%m-%d %H:%M'
    
    id: str
    email: str
    domains: tuple[str, ...]
    pem_filename: str
    dns_provider: DnsProvider
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Cert":
        def get_required(name: str) -> Any:
            val = data.get(name)
            Require.present(name, val)
            return val
        
        id = get_required("id")
        email = get_required("email")
        domains = get_required("domains")
        pem_filename = get_required("pem_filename")
        dns_provider_raw = get_required("dns_provider")
        
        Require.type("id", id, str)
        Require.email("email", email)
        Require.type("domains", domains, list)
        
        for i, domain in enumerate(domains):
            Require.domain(f"domains[{i}]", domain)
            
        Require.one_of("dns_provider", dns_provider_raw, DnsProvider.values())
        dns_provider = DnsProvider(dns_provider_raw)
        Require.installed_module("dns_provider", dns_provider.value, dns_provider.get_required_module()) 
    
        return cls(id, email, tuple(domains), pem_filename, dns_provider)

    
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
    
    
    def issue(self, force: bool = False) -> None:
        log.debug(f"Issuing '{self}' certificate...")
        
        if not force and self.is_issued():
            raise CertException(
                self.id,
                f"Certificate is already issued with expiration date to {self.get_expire_date_as_str()}",
                status=CertStatus.ALREADY_ISSUED
            ) 
        
        certbot = CertBot.get_from_global_context()
        certbot.issue(self.id, self.domains, self.email, self.dns_provider)    
        
        log.info(f"Successfully issued '{self}' certificate with expiration date to {self.get_expire_date_as_str()}")
        
    
    def renew(self, force: bool = False) -> None:
        log.debug(f"Renewing '{self}' certificate...")
        certbot = CertBot.get_from_global_context()
        
        if not force and not self.is_expiring():
            raise CertException(
                self.id,
                f"Certificate can be renewed {certbot.renew_before_days} days before expiration, current expiration date is {self.get_expire_date_as_str()}",
                status=CertStatus.NOT_YET_RENEWABLE
            )
        
        certbot.renew(self.id, self.dns_provider)
        
        log.info(f"Successfully renewed '{self}' certificate with new expiration date {self.get_expire_date_as_str()}")
    
    
    def get_full_chain(self) -> str:
        return f"{self.get_cert()}\n{self.get_chain()}"
    

    def get_chain(self) -> str:
        self._require_issued()
        certbot = CertBot.get_from_global_context()
        chain_path = certbot.get_chain_path(self.id)
        
        return self._read_text(chain_path)
    
    
    def get_cert(self) -> str:
        self._require_issued()
        certbot = CertBot.get_from_global_context()
        cert_path = certbot.get_cert_path(self.id)
        
        return self._read_text(cert_path)
    
    
    def get_private_key(self) -> str:
        self._require_issued()
        certbot = CertBot.get_from_global_context()
        private_key_path = certbot.get_private_key_path(self.id)
        
        return self._read_text(private_key_path)


    def get_expire_date_as_str(self) -> str:
        return datetime.strftime(self.get_expire_date(), self.DATE_FORMAT)
    

    def get_expire_date(self) -> datetime:
        self._require_issued()
        
        certbot = CertBot.get_from_global_context()
        cert_file = certbot.get_cert_path(self.id)
        pem_bytes = cert_file.read_bytes()
        
        cert = x509.load_pem_x509_certificate(pem_bytes, default_backend())
        expire_date = cert.not_valid_after_utc
        
        if expire_date.tzinfo is None:
            expire_date = expire_date.replace(tzinfo=timezone.utc)
        return expire_date.astimezone(timezone.utc)
    
    
    def get_status(self) -> CertStatus:
        if not self.is_issued():
            return CertStatus.NOT_ISSUED
        elif self.is_expired():
            return CertStatus.EXPIRED
        elif self.is_expiring():
            return CertStatus.EXPIRING
        else:
            return CertStatus.OK
    
    
    def is_expiring(self) -> bool:
        certbot = CertBot.get_from_global_context()
        return self._get_time_left().days <= certbot.renew_before_days


    def is_expired(self) -> bool:
        return self._get_time_left().total_seconds() <= 0
    
    
    def is_issued(self) -> bool:
        certbot = CertBot.get_from_global_context()
        required_paths = [
            certbot.get_cert_path(self.id),
            certbot.get_chain_path(self.id),
            certbot.get_private_key_path(self.id)
        ]
        for path in required_paths:
            if not path.exists():
                return False

        return True
    
    
    def _get_time_left(self) -> timedelta:
        self._require_issued()
        return self.get_expire_date() - datetime.now(timezone.utc)
        
        
    def _require_issued(self) -> None:
        if not self.is_issued():
            raise CertException(self.id, f"Certificate '{self}' is not issued", status=CertStatus.NOT_ISSUED)

    
    def _read_text(self, file_path: Path) -> str:
        try:
            return file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return file_path.read_text(encoding="ascii", errors="ignore")


    def __str__(self) -> str:
        return self.id
