from dataclasses import dataclass
from flask import Request
from .config import Config
from .identity import Identity
from .error import AuthTokenMissingError, AuthFailedError

@dataclass
class Auth:
    token: str
    remote_ip: str
    identity: Identity
    
    def __init__(self, request: Request, conf: Config, scope: str, action: str) -> None:
        auth_header = request.headers.get("Authorization", None)
        
        if not auth_header or auth_header == "":
            raise AuthTokenMissingError("Missing or empty Authorization header")
        elif not auth_header.startswith("Bearer "):
            raise AuthTokenMissingError("Authorization header does not start with 'Bearer '")
        
        token_raw = auth_header[len("Bearer "):].strip()
    
        try:
            identity_id, identity_token = token_raw.split(".", 1)
            if not identity_id or not identity_token:
                raise ValueError()
        except ValueError:
            raise AuthFailedError("Invalid token format, expected: 'Authorization: Bearer <id>.<token>'")
        
        self.token = identity_token
        self.identity = next((i for i in conf.identities if i.id == identity_id), None)
        
        if self.identity is None :
            raise AuthFailedError(f"Unknown identity '{identity_id}'")
        elif not self.identity.is_token_matches(conf.hmac_key, identity_token):
            raise AuthFailedError(f"Invalid token for identity '{identity_id}'")
        
        self.remote_ip = self._get_remote_ip(request)
        
        if not self.identity.is_ip_allowed(self.remote_ip):
            raise AuthFailedError(f"IP address '{self.remote_ip}' is not allowed for identity '{identity_id}'")
        
        if not self.identity.has_permission(scope, action):
            raise AuthFailedError(f"Permission denied for action '{action}' on scope '{scope}' for identity '{identity_id}'")
        
    
    def _get_remote_ip(self, request: Request) -> str | None:
        if request.remote_addr:
            return request.remote_addr
        
        xff = request.headers.get("X-Forwarder-For", "")
        return xff.split(",")[0].strip() if xff else None
    
    
    
