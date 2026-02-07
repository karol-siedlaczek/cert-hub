import os
import time
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, NoReturn, cast
from http import HTTPStatus
from flask import Response, abort, jsonify, request, current_app as app, g
from cert_registry.conf.config import Config
from cert_registry.domain.identity import Identity
from cert_registry.errors.auth_error import AuthTokenMissingError, AuthFailedError, AuthIpNotAllowedError

log = logging.getLogger(__name__)

def get_conf() -> Config:
    if "conf" not in g:
        g.conf = cast(Config, app.extensions["config"])
    return g.conf

def log_request(msg: str, level: str = "info") -> None:
    level = level.lower()
    log_fn = getattr(log, level, None)
    
    if not callable(log_fn):
        raise ValueError(f"Invalid log level: {level}")
    log_fn(f"{request.remote_addr} {request.method} {request.path} {msg}")


def abort_response(
    code: int,
    *,
    msg: str, 
    detail: Any | None = None
) -> NoReturn:
    response = build_response(code, msg=msg, detail=detail)
    abort(response)


def build_response(
    code: int,
    *,
    msg: str | None = None,
    data: Any = None, 
    detail: Any | None = None
) -> Response:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": HTTPStatus(code).phrase,
        "path": request.path,
        "code": code
    }
    
    if msg is not None:
        payload["message"] = msg
    if detail is not None:
        payload["detail"] = detail
    if data is not None:
        payload["data"] = data
    
    response = jsonify(payload)
    response.status_code = code
    return response


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


# 5 minutes of TTL
def acquire_lock(*, max_ttl: int = 5 * 60) -> bool:
    conf = get_conf()
    lock_file = Path(f"{conf.certbot_lock_dir}/certbot.lock")
    now = time.time()
    
    if lock_file.exists():
        age = now - lock_file.stat().st_mtime
        if age < max_ttl:
            return False
        lock_file.unlink(missing_ok=True)
    
    lock_file.write_text(str(os.getpid()))
    return True


def release_lock() -> None:
    conf = get_conf()
    lock_file = Path(f"{conf.certbot_lock_dir}/certbot.lock")
    lock_file.unlink(missing_ok=True)
