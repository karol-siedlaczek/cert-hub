import re
import logging
from pathlib import Path
from typing import Any
from enum import Enum
from datetime import datetime
from dataclasses import dataclass
from cert_registry.errors.cert_error import CertNotIssuedException
from cert_registry.domain.permission import PermissionAction
from cert_registry.domain.identity import Identity
from cert_registry.validation.require import Require

log = logging.getLogger(__name__)


class CertPlugin(Enum):
    DNS_ROUTE_53 = "dns-route53"
    
    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]
    

@dataclass(frozen=True)
class Cert:   
    id: str
    email: str
    domains: tuple[str, ...] # TODO - Do I need tuple?
    path: Path
    plugin: CertPlugin
    
    @classmethod
    def from_dict(cls, data: dict[str, Any], certbot_conf_dir: Path) -> "Cert":
        def get_required(name: str) -> Any:
            val = data.get(name)
            Require.present(name, val)
            return val
        
        id = get_required("id")
        email = get_required("email")
        domains = get_required("domains")
        raw_plugin = get_required("plugin")
        path = certbot_conf_dir / "live" / id
        
        Require.type("id", id, str)
        Require.email("email", email)
        Require.one_of("plugin", raw_plugin, CertPlugin.values())
        Require.installed_module("plugin", raw_plugin, "certbot-dns-route53")
        Require.type("domains", domains, list)
        
        for i, domain in enumerate(domains):
            Require.domain(f"domains[{i}]", domain)
        
        return cls(id, email, tuple(domains), path, CertPlugin(raw_plugin))

    
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
    

    def get_chain(self) -> str:
        if not self.is_issued():
            raise CertNotIssuedException(f"Failed to get chain for '{self.id}' certificate")
    
    
    def get_cert(self) -> str:
        if not self.is_issued():
            raise CertNotIssuedException(f"Failed to get cert content for '{self.id}' certificate")
    
    
    def get_full_chain(self) -> str:
        return f"{self.get_cert()}\n{self.get_chain()}"
    
    
    def get_private_key(self) -> str:
        if not self.is_issued():
            raise CertNotIssuedException(f"Failed to get private key for '{self.id}' certificate")


    def get_expire_date(self) -> datetime:
        if not self.is_issued():
            raise CertNotIssuedException(f"Failed to check expiry date for '{self.id}' certificate")
    
    
    def is_issued(self) -> bool:
        pass

        
    def is_to_renew(self) -> bool:
        pass
