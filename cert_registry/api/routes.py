
import os
from flask import Blueprint, Response, jsonify
from cert_registry.api.context import Context
from cert_registry.api.validators import query_list
from cert_registry.api.helpers import build_response, abort_response, run_cmd, get_conf, acquire_lock, release_lock
from cert_registry.domain.permission import PermissionAction

api = Blueprint("api", __name__)


@api.route("/health", methods=["GET"])
def health() -> Response:
    certs_arg = query_list("cert", required=True)
    ctx = Context.build(certs_arg, PermissionAction.HEALTH)

    certs_health = []

    for cert in ctx.certs:
        certs_health.append({ 
            "id": cert.id, 
            "status": "NOT_ISSUED", 
            "expireDate": "null" 
        })
    
    return build_response(200, data={ "health": "OK", "certs": certs_health })


@api.route("/api/certs/issue", methods=["POST"])
def issue_cert() -> Response:
    certs = query_list("cert", required=True)
    ctx = Context.build(certs, PermissionAction.ISSUE)
    conf = get_conf()
    
    if not acquire_lock():
        abort_response(409, msg="Certificate issuance already in progress")
    
    try:
        for cert in ctx.certs:

            cmd = [
                conf.certbot_bin, "certonly",
                f"--{cert.plugin.value}",
                "--cert-name", cert.id,
                "--agree-tos",
                "-d", (',').join(cert.domains),
                "--email", cert.email,
                "--non-interactive",
                "--server", conf.acme_server,
                "--config-dir", conf.certbot_conf_dir,
                "--work-dir", conf.certbot_work_dir,
                "--logs-dir", conf.certbot_logs_dir,
                "--test-cert",
                "--max-log-backups", "100"
                "--issuance-timeout", "90",
                "--dry-run"
                #"--quiet"
                #"--force-renewal"
            ]
            #print(cmd)
            print((" ").join(cmd))
            # result = run_cmd(cmd, check=True)  
            # print(result)
    finally:
        pass
        #release_lock()
        
    return build_response(200, msg="TODO - issue_cert", data={ "cert": "test" })



@api.route("/api/certs/renew", methods=["POST"])
def renew_certs() -> Response:
    #require_auth("domain", PermissionAction.RENEW)
    
    return jsonify(method="TODO - renew_certs")


@api.route("/api/certs/", methods=["GET"])
def get_cert() -> Response:
    #require_auth("domain", PermissionAction.READ)
    return jsonify(method="TODO - get_cert")
