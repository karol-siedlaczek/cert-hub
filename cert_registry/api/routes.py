import platform
from flask import Blueprint, Response
from cert_registry.api.context import Context
from cert_registry.api.validators import query_list, query_bool
from cert_registry.api.helpers import build_response, log_request, require_auth, get_remote_ip
from cert_registry.conf.config import Config
from cert_registry.domain.permission import PermissionAction
from cert_registry.domain.cert_status import CertStatus
from cert_registry.exception.cert_exceptions import CertException

api = Blueprint("api", __name__)


@api.route("/ping", methods=["GET"])
def ping() -> str:
    return "pong"


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
    
    context = Context.build(certs, PermissionAction.HEALTH)

    certs_health = []
    is_critical = False
    is_warning = False

    for cert in context.certs:
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
            "expire_date": cert.get_expire_date_as_str(),
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
    force = query_bool("force")
    context = Context.build(certs, PermissionAction.ISSUE)
    payload = {}

    for cert in context.certs:
        try:
            cert.issue(force)
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
    force = query_bool("force")
    context = Context.build(certs, PermissionAction.RENEW)
    payload = {}
    
    for cert in context.certs:
        try:
            cert.renew(force)
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
    context = Context.build(certs, PermissionAction.READ)
    payload = {}
    
    for cert in context.certs:
        payload[cert.id] = {
            "content": {
                "chain.pem": cert.get_chain(),
                "cert.pem": cert.get_cert(),
                "privkey.pem": cert.get_private_key()
            },
            "domains": cert.domains,
            "expire_date": cert.get_expire_date_as_str(),
            "status": cert.get_status().value
        }
    
    return build_response(200, data=payload)


# @api.route("/api/scope", methods=["GET"])
# def get_scope() -> Response:
#     remote_ip = get_remote_ip()
#     identity = require_auth(remote_ip)
#     conf = Config.get_from_global_context()
#     actions = [a for a in PermissionAction if a != PermissionAction.ANY]
    
#     payload = {}             

#     for cert in conf.certs:
#         cert_scope = {}
#         has_any_access = False

#         for action in actions:
#             is_allowed = cert.has_permission(identity, action)
#             cert_scope[action.value] = "True" if is_allowed else "False"

#             if is_allowed:
#                 has_any_access = True

#         if has_any_access:
#             payload[cert.id] = cert_scope

#     return build_response(200, data=payload)

@api.route("/api/scope", methods=["GET"])
def get_scope() -> Response:
    remote_ip = get_remote_ip()
    identity = require_auth(remote_ip)
    conf = Config.get_from_global_context()
    actions = [a for a in PermissionAction if a != PermissionAction.ANY]
    
    payload = { action.value: [] for action in actions }

    for cert in conf.certs:
        for action in actions:
            if cert.has_permission(identity, action):
                payload[action.value].append(cert.id)

    return build_response(200, data=payload)


@api.route("/api/identity", methods=["GET"])
def get_identity() -> Response:
    remote_ip = get_remote_ip()
    identity = require_auth(remote_ip)
    payload = {
        "id": identity.id,
        "allowed_cidrs": identity.allowed_cidrs,
        "permissions": [{ "scope": p.scope, "action": p.action.value } for p in identity.permissions]
    }
    
    return build_response(200, data=payload)
