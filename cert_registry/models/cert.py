from dataclasses import dataclass
from .require import Require
from typing import ClassVar, Any

@dataclass(frozen=True)
class CertEntry:
    ALLOWED_PLUGINS: ClassVar[set[str]] = { "dns-route53" }
    
    key: str
    email: str
    domains: tuple[str, ...]
    plugin: str
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CertEntry":
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
        Require.one_of("plugin", plugin, cls.ALLOWED_PLUGINS)
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
