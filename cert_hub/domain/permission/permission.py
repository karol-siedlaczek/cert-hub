import re
from dataclasses import dataclass
from cert_hub.domain.cert.cert import Cert
from cert_hub.validation.require import Require
from cert_hub.domain.permission.permission_action import PermissionAction

    
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
            custom_err=(
                f"Key 'permissions[{index}]' with '{permission}' permission is invalid, "
                f"value needs to be provided in following format: "
                f"'(*|<cert_pattern>):({('|').join(PermissionAction.values())})'")
        )
        scope, action_raw = match.groups()
        Require.present(f"permissions[{index}].scope", scope)
        Require.one_of(f"permissions[{index}]", action_raw, PermissionAction.values())
        
        return cls(scope, PermissionAction(action_raw))
    
    
    def allows(self, cert: Cert, action: PermissionAction) -> bool:
        if self.action != PermissionAction.ANY and self.action != action:
            return False

        if self.scope == "*" or self.scope == cert.id:
            return True

        try:
            return re.fullmatch(self.scope, cert.id) is not None
        except re.error:
            return False
