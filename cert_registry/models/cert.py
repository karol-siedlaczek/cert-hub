from dataclasses import dataclass
from .require import Require
from typing import ClassVar, Any
from enum import Enum

class CertPlugin(Enum):
    DNS_ROUTE_53 = "dns-route53"
    
    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]
    

@dataclass(frozen=True)
class Cert:   
    key: str
    email: str
    domains: tuple[str, ...]
    plugin: str
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Cert":
        def get_required(name: str) -> Any:
            val = data.get(name)
            Require.present(name, val)
            return val
        
        key = get_required("key")
        email = get_required("email")
        domains = get_required("domains")
        plugin = get_required("plugin")
        
        Require.type("key", key, str)
        Require.email("email", email)
        Require.one_of("plugin", plugin, CertPlugin.values())
        Require.installed_module("plugin", plugin, "certbot-dns-route53")
        Require.type("domains", domains, list)
        for i, domain in enumerate(domains):
            Require.domain(f"domains[{i}]", domain)
        
        return cls(
            key=key,
            email=email,
            domains=tuple(domains),
            plugin=plugin
        )


#class Cert:
#    pass
