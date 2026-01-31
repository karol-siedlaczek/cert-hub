import ipaddress
from flask import Request
from .config import Config
from .error import AuthTokenError, AuthIpNotAllowedError

class Auth:
    bearer_token: str
    remote_ip: str
    
    def __init__(self, request: Request, action: str, scope: str, conf: Config) -> None:
        auth_header = request.headers.get("Authorization", None)
        
        if not auth_header or auth_header == "":
            raise AuthTokenError("Request header 'Authorization' is missing or empty")
        
        if not auth_header.startswith("Bearer "):
            raise AuthTokenError("Request header 'Authorization' does not start with 'Bearer '")
        
        token_raw = auth_header[len("Bearer "):].strip()
    
        try:
            token_key, token_secret = token_raw.split(".", 1)
            if not token_key or not token_secret:
                raise ValueError()
        except ValueError:
            raise AuthTokenError("Token has invalid format, expected: 'Authorization: Bearer <token_key>.<token_secret>'")
        
        token = next((t for t in conf.tokens if t.key == token_key), None)
        
        if token is None:
            raise AuthTokenError(f"Token with key '{token_key}' not found in configuration")
        
        remote_ip = self._get_remote_ip(request)
        
        if not token.is_ip_allowed(remote_ip):
            raise AuthIpNotAllowedError(f"Access for '{remote_ip}' is forbidden")
        
        if not token.is_secret_matches(conf.hmac_key, token_secret):
            raise AuthTokenError("Invalid token")

    
    def _get_remote_ip(self, request: Request) -> str | None:
        if request.remote_addr:
            return request.remote_addr
        
        xff = request.headers.get("X-Forwarder-For", "")
        return xff.split(",")[0].strip() if xff else None
    
    
    
