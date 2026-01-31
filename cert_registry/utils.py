import subprocess
import logging
from datetime import datetime, timezone
from typing import cast, Any, NoReturn
from http import HTTPStatus
from flask import Response, abort, jsonify, g, request, current_app as app
from .models.config import Config
from .models.auth import Auth
from .models.error import AuthError, AuthTokenMissingError

log = logging.getLogger(__name__)

def get_conf() -> Config:
    if "conf" not in g:
        g.conf = cast(Config, app.extensions["config"])
    return g.conf


def require_auth(scope: str, action: str) -> None:
    conf = get_conf()
    try:
        auth = Auth(request, conf, scope, action)
    except AuthError as e:
        log_request(f"Authorization failed ({type(e).__name__}): {e}", "warning")
        
        if isinstance(e, AuthTokenMissingError):
            abort_response(401, msg="Authorization is required", error=str(e))
        else:
            abort_response(403, msg="Authorization failed")
    
    return auth


def log_request(msg: str, level: str = "info") -> None:
    level = level.lower()
    log_fn = getattr(log, level, None)
    if not callable(log_fn):
        raise ValueError(f"Invalid log level: {level}")
    log_fn(f"{request.remote_addr} {request.method} {request.path} {msg}")


def build_response(code: int = 200, data: Any = None, msg: str | None = None, error: str | None = None) -> Response:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": HTTPStatus(code).phrase,
        "path": request.path,
        "code": code
    }
    
    if msg is not None:
        payload["message"] = msg
    if error is not None:
        payload["error"] = error
    if data is not None:
        payload["data"] = data
    
    response = jsonify(payload)
    response.status_code = code
    return response


def abort_response(code: int, msg: str, error: str | None = None) -> NoReturn:
    abort(build_response(code=code, msg=msg, error=error))
    

def run_cmd(cmd: str, check: bool=True) -> str:
    process = subprocess.run(
        cmd, 
        shell=True, 
        stdin=subprocess.DEVNULL, 
        stderr=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        check=check, 
        text=True, 
        executable="/bin/bash"
    )
    return process.stdout or process.stderr
