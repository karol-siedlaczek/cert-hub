from flask import Blueprint, Response
from cert_registry.api.context import Context
from cert_registry.api.validators import query_list
from cert_registry.api.helpers import build_response
from cert_registry.domain.permission import PermissionAction
from cert_registry.domain.cert_status import CertStatus
from cert_registry.errors.cert_error import CertException

api = Blueprint("api", __name__)


@api.route("/health", methods=["GET"])
def health() -> Response:
    certs_arg = query_list("cert", required=True)
    ctx = Context.build(certs_arg, PermissionAction.HEALTH)

    certs_health = []

    for cert in ctx.certs:
        certs_health.append({ 
            "id": cert.id, 
            "status": cert.get_status().value, 
            "expire_date": cert.get_expire_date_as_str()
        })
    
    return build_response(200, data={ "health": "OK", "certs": certs_health })


@api.route("/api/certs/issue", methods=["POST"])
def issue_cert() -> Response:
    certs = query_list("cert", required=True)
    ctx = Context.build(certs, PermissionAction.ISSUE)
    payload = {}
    
    #if not acquire_lock():
    #    abort_response(409, msg="Certificate issuance already in progress")
        
    #try:
    for cert in ctx.certs:
        try:
            cert.issue()
            payload[cert.id] = {
                "status": CertStatus.ISSUED.value,
                "msg": f"Successfully issued '{cert.id}' certificate",
                "expire_date": cert.get_expire_date_as_str()
            }
        except CertException as e:
            payload[cert.id] = {
                "status": e.status.value,
                "msg": e.msg
            }
    #finally:
    #    print("release lock")
    #    release_lock()
    #    
    return build_response(200, data=payload)



@api.route("/api/certs/renew", methods=["POST"])
def renew_certs() -> Response:
    certs = query_list("cert", required=True)
    ctx = Context.build(certs, PermissionAction.RENEW)
    payload = {}
    
    for cert in ctx.certs:
        try:
            cert.renew()
            payload[cert.id] = {
                "status": CertStatus.RENEWED.value,
                "msg": f"Successfully renewed '{cert.id}' certificate",
                "expire_date": cert.get_expire_date_as_str()
            }
        except CertException as e:
            payload[cert.id] = {
                "status": e.status.value,
                "msg": e.msg
            }
    
    return build_response(200, data=payload)


@api.route("/api/certs", methods=["GET"])
def get_cert() -> Response:
    certs = query_list("cert", required=True)
    ctx = Context.build(certs, PermissionAction.READ)
    payload = {}
    
    for cert in ctx.certs:
        payload[cert.id] = {
            "content": {
                "chain.pem": cert.get_chain(),
                "cert.pem": cert.get_cert(),
                "privkey.pem": cert.get_private_key()
            },
            "expire_date": cert.get_expire_date_as_str(),
            "status": cert.get_status().value
        }
    
    return build_response(200, data=payload)
