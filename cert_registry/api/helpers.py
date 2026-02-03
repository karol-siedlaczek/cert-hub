import subprocess
import logging
from datetime import datetime, timezone
from typing import cast, Any, NoReturn
from http import HTTPStatus
from flask import Response, abort, jsonify, g, request, current_app as app
from cert_registry.conf.config import Config

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
    code: int = 200,
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

    
def run_cmd(cmd: str, check: bool = True) -> str:
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
