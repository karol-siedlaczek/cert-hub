import os
import time
import subprocess
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import cast, Any, NoReturn, Sequence, Union, Optional
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


def run_cmd(
    args: Sequence[Union[str, Path]],
    *,
    check: bool = True,
    shell: bool = False,
    timeout: Optional[int] = None
) -> str:
    args = [str(a) for a in args]
    
    process = subprocess.run(
        args, 
        shell=shell, 
        stdin=subprocess.DEVNULL, 
        stderr=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        check=check, 
        text=True, 
        #executable="/bin/bash",
        timeout=timeout
    )
    return process.stdout or process.stderr


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
