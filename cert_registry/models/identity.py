import re
import os
import hmac
import ipaddress
from hashlib import sha256
from dataclasses import dataclass
from typing import Any
from enum import Enum
from .require import Require

class PermissionAction(Enum):
    READ = "read"
    ISSUE = "issue"
    RENEW = "renew"
    HEALTH = "health"
    
    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]
    
    
@dataclass(frozen=True)
class IdentityPermission:    
    scope: str
    action: str    
    
    @classmethod
    def from_string(cls, index: int, permission: str) -> "IdentityPermission":
        allowed_actions_escaped = [re.escape(v) for v in PermissionAction.values()]
        permission_pattern = re.compile(rf'^(.*):(\*|{"|".join(allowed_actions_escaped)})$')
        permission = permission.strip()
        
        match = Require.match(
            field=f"permissions[{index}]", 
            val=permission, 
            pattern=permission_pattern,
            custom_err=f"Key 'permissions[{index}]' with '{permission}' permission is invalid, value needs to be provided in following format: '(*|<cert_key>):(*|read|issue|renew|health)'"
        )
        scope, action = match.groups()
        Require.one_of(f"permissions[{index}]", action, PermissionAction.values())
        
        return cls(scope, action)

    
@dataclass(frozen=True)
class Identity:
    id: str
    hmac_hex: str
    allowed_cidrs: list[str]
    permissions: list[IdentityPermission]
     

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Identity":
        def get_required(name: str) -> Any:
            val = data.get(name)
            Require.present(name, val)
            return val
        
        id = get_required("id")
        allowed_cidrs = get_required("allowed_cidrs")
        raw_permissions = get_required("permissions")
        permissions = []
        
        Require.type("id", id, str)
        Require.match("id", id, r'^[A-Za-z_0-9]*$')
        
        hmac_env = f"TOKEN_{str(id).upper()}_HMAC"
        hmac_hex = Require.env(hmac_env)
        Require.min_len(hmac_env, os.getenv(hmac_env), 64)
        
        Require.type("allowed_cidrs", allowed_cidrs, list)
        for i, ip_addr in enumerate(allowed_cidrs):
            Require.ip_address(f"allowed_cidrs[{i}]", ip_addr)
            
        Require.type("permissions", raw_permissions, list)
        for i, permission in enumerate(raw_permissions):
            permission = IdentityPermission.from_string(i, permission)
            permissions.append(permission)
        
        return cls(id, hmac_hex, allowed_cidrs, permissions)


    def is_token_matches(self, hmac_key: bytes, token: str) -> bool:
        token_hmac_hex = hmac.new(hmac_key, token.encode("UTF-8"), sha256).hexdigest()
        return hmac.compare_digest(token_hmac_hex, self.hmac_hex)
    
    
    def is_ip_allowed(self, ip_addr: str | None = None) -> bool:
        if not ip_addr:
            return False
        
        try:
            ip_obj = ipaddress.ip_address(ip_addr)
        except ValueError: # Invalid ip_addr format
            return False
        
        for cidr in self.allowed_cidrs:
            network = ipaddress.ip_network(cidr, strict=False)
            if ip_obj in network:
                return True
        
        return False
    
    
    def has_permission(self, scope: str | None = None, action: str | None = None) -> bool:
        if not scope or not isinstance(scope, str):
            return False
        elif not action or action not in PermissionAction.values():
            raise ValueError(f"Invalid action: {action}")
        
        scope = scope.strip()
        action = action.strip()
        
        for p in self.permissions:
            scope_ok = (p.scope == "*" or p.scope == scope)
            action_ok = (p.action == "*" or p.action == action)
            
            if scope_ok and action_ok:
                return True
        
        return False

        
