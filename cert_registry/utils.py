import subprocess
import logging
from datetime import datetime, timezone
from typing import cast, Any, NoReturn
from http import HTTPStatus
from flask import Response, abort, jsonify, g, request, current_app as app
from .models.config import Config
from .models.auth import Auth
from .models.error import AuthTokenError, AuthMissingPermission, AuthIpNotAllowedError
import hmac, hashlib

log = logging.getLogger(__name__)

def get_conf() -> Config:
    if "conf" not in g:
        g.conf = cast(Config, app.extensions["config"])
    return g.conf


def require_api_access(action: str, scope: str | None = None) -> None:
    try:
        auth = Auth(request, action, scope, get_conf())
    except AuthTokenError | AuthIpNotAllowedError | AuthMissingPermission as e:
        log.warning(
            "Authorization failed", # "Authorization failed: %s %s from %s (%s)"
            extra={
                "path": request.path,
                "method": request.method,
                "remote_addr": request.remote_addr,
                "error_type": type(e).__name__,
                "error_msg": e
            }
        )
        abort_response(401, error="Authorization is required to access this endpoint")
    #else:
    #    conf = get_conf()
    #    matched_token = [t for t in conf.tokens if t.value == token]
    #    print(matched_token)
        
        
        
        
    #[env for env in cls.REQUIRED_ENVS if not params.get(env)]
    #You do not have access to this page or resource
    # print(request.headers)
    
    # print(token)
    # print(src_addr)
    # print(action)
    
    
    #if not expected: # TODO - make required in config.py or implements different tokens for each remote addr and domain
    #    abort(500, "API_TOKEN not configured")
    
    #token = request.headers.get("X-API-Token")
    #if token != expected:
    #    abort (401, "Unauthorized") # TODO - Make json



def test(token: str, pepper: str) -> str:
    return hmac.new(
        pepper.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def build_response(code: int = 200, data: Any = None, error: str | None = None) -> Response:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": HTTPStatus(code).phrase,
        "code": code
    }
    
    if error is not None:
        payload["error"] = error
    else:
        payload["data"] = data
    
    response = jsonify(payload)
    response.status_code = code
    return response


def abort_response(code: int, error: str) -> NoReturn:
    abort(build_response(code, error=error))
    

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
