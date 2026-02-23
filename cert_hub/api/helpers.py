import logging
from datetime import datetime, timezone
from typing import Any, NoReturn
from http import HTTPStatus
from flask import Response, abort, jsonify, request
from cert_hub.domain.identity import Identity
from cert_hub.conf.config import Config
from cert_hub.exception.auth_exceptions import AuthTokenMissingException, AuthFailedException, AuthIpNotAllowedException

log = logging.getLogger(__name__)


@staticmethod
def get_remote_ip() -> str | None:
    if request.remote_addr:
        return request.remote_addr
    
    xff = request.headers.get("X-Forwarder-For", "")
    return xff.split(",")[0].strip() if xff else None


def log_request(msg: str, level: str = "info") -> None:
    level = level.lower()
    log_fn = getattr(log, level, None)
    
    if not callable(log_fn):
        raise ValueError(f"Invalid log level: {level}")
    log_fn(f"{request.remote_addr} {request.method} {request.path} {msg}")


def build_response(
    code: int,
    *,
    msg: str | None = None,
    data: Any = None, 
    detail: Any | None = None
) -> Response:
    payload = {}
    
    if msg is not None:
        payload["message"] = msg
    if detail is not None:
        payload["detail"] = detail
    if data is not None:
        payload["data"] = data
        
    
    payload = {
        "http_code": code,
        "http_status": HTTPStatus(code).phrase,
        "method": request.method,
        "path": request.path,
        **payload,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    response = jsonify(payload)
    response.status_code = code
    return response


def require_auth(remote_ip: str) -> Identity:
    auth_header = request.headers.get("Authorization", None)
    
    if not auth_header or auth_header == "":
        raise AuthTokenMissingException("Authorization header is missing or empty")
    elif not auth_header.startswith("Bearer "):
        raise AuthTokenMissingException("Authorization header does not start with 'Bearer '")
    
    token_raw = auth_header[len("Bearer "):].strip()

    try:
        identity_id, identity_token = token_raw.split(".", 1)
        if not identity_id or not identity_token:
            raise ValueError()
    except ValueError:
        raise AuthFailedException("Invalid token format, expected: 'Authorization: Bearer <id>.<token>'")
    
    conf = Config.get_from_global_context()
    identity = next((i for i in conf.identities if i.id == identity_id), None)
    
    if identity is None:
        raise AuthFailedException(f"Unknown identity '{identity_id}'")
    elif not identity.is_token_valid(conf.hmac_key, identity_token):
        raise AuthFailedException(f"Invalid token for identity '{identity_id}'")
    
    if not identity.is_ip_allowed(remote_ip):
        raise AuthIpNotAllowedException(remote_ip)
    
    return identity
