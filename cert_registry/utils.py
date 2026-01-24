import subprocess
from flask import abort, request, current_app as app

def require_api_access(domain_key: str, scope: str) -> None:
    expected = app.config.get("API_TOKEN")
    
    if not expected: # TODO - make required in config.py or implements different tokens for each remote addr and domain
        abort(500, "API_TOKEN not configured")
    
    token = request.headers.get("X-API-Token")
    if token != expected:
        abort (401, "Unauthorized") # TODO - Make json


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
