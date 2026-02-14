import platform
from flask import Blueprint, Response
from cert_registry.api.context import Context
from cert_registry.api.validators import query_list, query_bool
from cert_registry.api.helpers import build_response, log_request
from cert_registry.domain.permission import PermissionAction
from cert_registry.domain.cert_status import CertStatus
from cert_registry.exception.cert_exceptions import CertException

api = Blueprint("api", __name__)


@api.route("/api/version", methods=["GET"])
def version() -> Response:
    payload = {
        "name": "cert-registry",
        "author": "karol@siedlaczek.com.pl",
        "version": "1.0.0",
        "python": platform.python_version()
    }
    return build_response(200, data=payload)
    

@api.route("/api/health", methods=["GET"])
def health() -> Response:
    certs = query_list("cert", default=["*"])
    exclude_ok = query_bool("exclude_ok")
    
    ctx = Context.build(certs, PermissionAction.HEALTH)

    certs_health = []
    is_critical = False
    is_warning = False

    for cert in ctx.certs:
        status = cert.get_status()
        
        if status == CertStatus.EXPIRED:
            is_critical = True
        elif status != CertStatus.OK:
            is_warning = True
            
        if exclude_ok and status == CertStatus.OK:
            continue
        
        certs_health.append({ 
            "id": cert.id, 
            "status": status.value, 
            "expire_date": cert.get_expire_date_as_str()
        })
    
    if is_critical:
        overall_health = "CRITICAL"
    elif is_warning:
        overall_health = "WARNING"
    else:
        overall_health = "OK"
    
    return build_response(
        200, 
        data={ 
            "health": overall_health, 
            "certs": certs_health 
        }
    )


@api.route("/api/certs/issue", methods=["POST"])
def issue_cert() -> Response:
    certs = query_list("cert", default=["*"])
    ctx = Context.build(certs, PermissionAction.ISSUE)
    payload = {}

    for cert in ctx.certs:
        try:
            cert.issue()
            payload[cert.id] = {
                "status": CertStatus.ISSUED.value,
                "msg": f"Successfully issued '{cert}' certificate",
                "expire_date": cert.get_expire_date_as_str()
            }
        except CertException as e:
            log_request(e.msg, level="info")
            payload[cert.id] = {
                "status": e.status.value,
                "msg": e.msg
            }
    return build_response(200, data=payload)



@api.route("/api/certs/renew", methods=["POST"])
def renew_certs() -> Response:
    certs = query_list("cert", default=["*"])
    ctx = Context.build(certs, PermissionAction.RENEW)
    payload = {}
    
    for cert in ctx.certs:
        try:
            cert.renew()
            payload[cert.id] = {
                "status": CertStatus.RENEWED.value,
                "msg": f"Successfully renewed '{cert}' certificate",
                "expire_date": cert.get_expire_date_as_str()
            }
        except CertException as e:
            log_request(e.msg, level="info")
            payload[cert.id] = {
                "status": e.status.value,
                "msg": e.msg
            }
    
    return build_response(200, data=payload)


@api.route("/api/certs", methods=["GET"])
def get_cert() -> Response:
    certs = query_list("cert", default=["*"])
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
