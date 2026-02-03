import re
from typing import Any
from enum import Enum
from dataclasses import dataclass
from cert_registry.domain.permission import PermissionAction
from cert_registry.domain.identity import Identity
from cert_registry.validation.require import Require

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
    plugin: CertPlugin
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Cert":
        def get_required(name: str) -> Any:
            val = data.get(name)
            Require.present(name, val)
            return val
        
        id = get_required("id")
        email = get_required("email")
        domains = get_required("domains")
        raw_plugin = get_required("plugin")
        
        Require.type("id", id, str)
        Require.email("email", email)
        Require.one_of("plugin", raw_plugin, CertPlugin.values())
        Require.installed_module("plugin", raw_plugin, "certbot-dns-route53")
        Require.type("domains", domains, list)
        
        for i, domain in enumerate(domains):
            Require.domain(f"domains[{i}]", domain)
        
        return cls(id, email, tuple(domains), CertPlugin(raw_plugin))

    
    def has_permission(self, identity: Identity, action: PermissionAction) -> bool:
        if not identity:
            return False
        
        for permission in identity.permissions:
            if permission.action != PermissionAction.ANY and permission.action != action:
                continue
            
            if permission.scope == "*":
                return True
            
            if permission.scope == self.id:
                return True
            
            try:
                if re.fullmatch(permission.scope, self.id):
                    return True
            except re.error:
                continue
        
        return False
            
