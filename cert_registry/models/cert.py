from dataclasses import dataclass
from .require import Require
from typing import Any
from enum import Enum

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
    plugin: str
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Cert":
        def get_required(name: str) -> Any:
            val = data.get(name)
            Require.present(name, val)
            return val
        
        id = get_required("id")
        email = get_required("email")
        domains = get_required("domains")
        plugin = get_required("plugin")
        
        Require.type("id", id, str)
        Require.email("email", email)
        Require.one_of("plugin", plugin, CertPlugin.values())
        Require.installed_module("plugin", plugin, "certbot-dns-route53")
        Require.type("domains", domains, list)
        for i, domain in enumerate(domains):
            Require.domain(f"domains[{i}]", domain)
        
        return cls(id, email, tuple(domains), plugin)
