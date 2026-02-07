
import os
from flask import Blueprint, Response
from cert_registry.api.context import Context
from cert_registry.api.validators import query_list
from cert_registry.api.helpers import build_response, abort_response, acquire_lock, release_lock, get_conf
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
            "status": cert.get_status(), 
            "expireDate": cert.get_expire_date()
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
            if cert.is_to_renew():
                cert.issue(
                    conf.acme_server, 
                    conf.certbot_bin, 
                    conf.certbot_conf_dir, 
                    conf.certbot_work_dir, 
                    conf.certbot_logs_dir
                )
    finally:
        pass
        #release_lock()
        
    return build_response(200, msg="TODO - issue_cert", data={ "cert": "test" })



@api.route("/api/certs/renew", methods=["POST"])
def renew_certs() -> Response:
    certs = query_list("cert", required=True)
    ctx = Context.build(certs, PermissionAction.RENEW)
    
    return build_response(200, msg="TODO - renew_cert")


@api.route("/api/certs", methods=["GET"])
def get_cert() -> Response:
    certs = query_list("cert", required=True)
    ctx = Context.build(certs, PermissionAction.READ)
    payload = {}
    
    for cert in ctx.certs:
        payload[cert.id] = {
            "chain.pem": cert.get_chain(),
            "cert.pem": cert.get_cert(),
            "privkey.pem": cert.get_private_key(),
            "expire_date": cert.get_expire_date()
        }
    
    return build_response(200, msg="TODO - get_cert", data=payload)
