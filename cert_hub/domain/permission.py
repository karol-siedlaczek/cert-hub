import re
from enum import Enum
from dataclasses import dataclass
from cert_hub.validation.require import Require

class PermissionAction(Enum):
    ANY = "*"
    READ = "read"
    ISSUE = "issue"
    RENEW = "renew"
    HEALTH = "health"
    
    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]
    
    
@dataclass(frozen=True)
class Permission:    
    scope: str
    action: PermissionAction
    
    @classmethod
    def from_string(cls, index: int, permission: str) -> "Permission":
        allowed_actions_escaped = [re.escape(v) for v in PermissionAction.values()]
        permission_pattern = re.compile(rf'^(.*):(\*|{"|".join(allowed_actions_escaped)})$')
        permission = permission.strip()
        
        match = Require.match(
            field=f"permissions[{index}]", 
            val=permission, 
            pattern=permission_pattern,
            custom_err=f"Key 'permissions[{index}]' with '{permission}' permission is invalid, value needs to be provided in following format: '(*|<cert_pattern>):({('|').join(PermissionAction.values())})'"
        )
        scope, action_raw = match.groups()
        Require.one_of(f"permissions[{index}]", action_raw, PermissionAction.values())
        
        return cls(scope, PermissionAction(action_raw))
    