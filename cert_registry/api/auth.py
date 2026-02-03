from flask import request
from cert_registry.api.helpers import get_conf
from cert_registry.domain.identity import Identity
from cert_registry.errors.auth_error import AuthTokenMissingError, AuthFailedError, AuthIpNotAllowedError

def require_auth(remote_ip: str) -> Identity:
    auth_header = request.headers.get("Authorization", None)
    
    if not auth_header or auth_header == "":
        raise AuthTokenMissingError("Authorization header is missing or empty")
    elif not auth_header.startswith("Bearer "):
        raise AuthTokenMissingError("Authorization header does not start with 'Bearer '")
    
    token_raw = auth_header[len("Bearer "):].strip()

    try:
        identity_id, identity_token = token_raw.split(".", 1)
        if not identity_id or not identity_token:
            raise ValueError()
    except ValueError:
        raise AuthFailedError("Invalid token format, expected: 'Authorization: Bearer <id>.<token>'")
    
    conf = get_conf()
    identity = next((i for i in conf.identities if i.id == identity_id), None)
    
    if identity is None:
        raise AuthFailedError(f"Unknown identity '{identity_id}'")
    elif not identity.is_token_valid(conf.hmac_key, identity_token):
        raise AuthFailedError(f"Invalid token for identity '{identity_id}'")
    
    if not identity.is_ip_allowed(remote_ip):
        raise AuthIpNotAllowedError(remote_ip)
    
    return identity
