import re
from dataclasses import dataclass
from .require import Require
from typing import ClassVar, Any

@dataclass(frozen=True)
class TokenPermission:
    ALLOWED_ACTIONS: ClassVar[set[str]] = { "read", "issue", "renew", "health" }
    
    scope: str
    action: str    
    
    @classmethod
    def init(cls, index: int, permission: str) -> "TokenPermission":
        allowed_actions_escaped = [re.escape(k) for k in cls.ALLOWED_ACTIONS]
        permission_pattern = re.compile(rf'^(.*):(\*|{"|".join(allowed_actions_escaped)})$')
        permission = permission.strip()
        
        match = Require.match(
            f"permissions[{index}]", 
            permission, 
            permission_pattern,
            f"Key 'permissions[{index}]' with '{permission}' permission is invalid, value needs to be provided in following format: '(*|<cert_key>):(*|read|issue|renew|health)'"
        )
        scope, action = match.groups()
        Require.one_of(f"permissions[{index}]", action, cls.ALLOWED_ACTIONS)
        
        return cls(scope, action)

    
@dataclass(frozen=True)
class Token:
    value: str
    allowed_ips: list[str]
    permissions: list[TokenPermission]
     
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Token":
        def get_required(name: str) -> Any:
            val = data.get(name)
            Require.present(name, val)
            return val
        
        env = get_required("env")
        allowed_ips = get_required("allowed_ips")
        raw_permissions = get_required("permissions")
        permissions = []
        
        Require.type("env", env, str)
        token_value = Require.env("env", env)
        
        Require.type("allowed_ips", allowed_ips, list)
        for i, ip_addr in enumerate(allowed_ips):
            Require.ip_address(f"allowed_ips[{i}]", ip_addr)
            
        Require.type("permissions", raw_permissions, list)
        for i, permission in enumerate(raw_permissions):
            permission = TokenPermission.init(i, permission)
            permissions.append(permission)
        
        return cls(token_value, allowed_ips, permissions)
