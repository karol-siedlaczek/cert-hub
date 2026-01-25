import subprocess
from datetime import datetime, timezone
from typing import cast, Any
from http import HTTPStatus
from flask import Response, abort, jsonify, g, request, current_app as app
from .models.config import Config

def get_conf() -> Config:
    if "conf" not in g:
        g.conf = cast(Config, app.extensions["config"])
    return g.conf


def require_api_access(action: str, scope: str | None = None) -> None:
    conf = get_conf()
    expected = app.config.get("API_TOKEN")
    
    if not expected: # TODO - make required in config.py or implements different tokens for each remote addr and domain
        abort(500, "API_TOKEN not configured")
    
    token = request.headers.get("X-API-Token")
    if token != expected:
        abort (401, "Unauthorized") # TODO - Make json


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
