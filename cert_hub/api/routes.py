import platform
from flask import Blueprint, Response
from cert_hub.api.context import Context
from cert_hub.api.validators import query_list, query_bool
from cert_hub.api.helpers import build_response, log_request, require_auth, get_remote_ip
from cert_hub.conf.config import Config
from cert_hub.domain.permission import PermissionAction
from cert_hub.domain.cert_status import CertStatus
from cert_hub.exception.cert_exceptions import CertException

api = Blueprint("api", __name__)


@api.route("/ping", methods=["GET"])
def ping() -> str:
    return "pong"


@api.route("/api/version", methods=["GET"])
def version() -> Response:
    payload = {
        "name": "Cert Hub",
        "author": "karol@siedlaczek.com.pl",
        "app": "1.0.0",
        "python": platform.python_version()
    }
    return build_response(200, data=payload)
    

@api.route("/api/certs/health", methods=["GET"])
def health() -> Response:
    patterns = query_list("match", default=["*"])
    exclude_ok = query_bool("exclude_ok")
    
    context = Context.build(patterns, PermissionAction.HEALTH)

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
        
        try:
            certs_health.append({ 
                "id": cert.id, 
                "status": status.value,
                "msg": f"Certificate '{cert}' is issued",
                "expire_date": cert.get_expire_date_as_str()
            })
        except CertException as e: # Not issued
            log_request(e.get_full_msg(), level="info")
            certs_health.append({
                "id": cert.id,
                "status": status.value,
                "msg": e.msg,
                "expire_date": None
            })
    
    if is_critical:
        overall_health = "CRITICAL"
    elif is_warning:
        overall_health = "WARNING"
    else:
        overall_health = "OK"
    
    payload = {
        "health": overall_health, 
        "certs": certs_health 
    }
    
    return build_response(200, data=payload)


@api.route("/api/certs/issue", methods=["POST"])
def issue_cert() -> Response:
    patterns = query_list("match", default=["*"])
    force = query_bool("force")
    context = Context.build(patterns, PermissionAction.ISSUE)
    payload = []

    for cert in context.certs:
        try:
            cert.issue(force)
            payload.append({
                "id": cert.id,
                "status": CertStatus.ISSUED.value,
                "msg": f"Successfully issued '{cert}' certificate",
                "expire_date": cert.get_expire_date_as_str()             
            })
        except CertException as e: # Already issued
            log_request(e.get_full_msg(), level="info")
            payload.append({
                "id": cert.id,
                "status": e.status.value,
                "msg": e.msg,
                "expire_date": cert.get_expire_date_as_str()
            })
    return build_response(200, data=payload)


@api.route("/api/certs/renew", methods=["POST"])
def renew_cert() -> Response:
    patterns = query_list("match", default=["*"])
    force = query_bool("force")
    context = Context.build(patterns, PermissionAction.RENEW)
    payload = []
    
    for cert in context.certs:
        try:
            cert.renew(force)
            payload.append({
                "id": cert.id,
                "status": CertStatus.RENEWED.value,
                "msg": f"Successfully renewed '{cert}' certificate",
                "expire_date": cert.get_expire_date_as_str()
            })
        except CertException as e: # Not expiring / Not issued
            log_request(e.get_full_msg(), level="info")
            payload.append({
                "id": cert.id,
                "status": e.status.value,
                "msg": e.msg,
                "expire_date": cert.get_expire_date_as_str() if cert.is_issued() else None
            })
    
    return build_response(200, data=payload)


@api.route("/api/certs", methods=["GET"])
def get_cert() -> Response:
    patterns = query_list("match", default=["*"])
    context = Context.build(patterns, PermissionAction.READ)
    payload = []
    
    for cert in context.certs:
        try:
            payload.append({
                "id": cert.id,
                "status": cert.get_status().value,
                "msg": f"Successfully fetched '{cert}' certificate",
                "custom_attrs": cert.custom_attrs,
                "domains": cert.domains,
                "expire_date": cert.get_expire_date_as_str(),
                "chain": cert.get_chain(),
                "certificate": cert.get_certificate(),
                "private_key": cert.get_private_key(),
            })
        except CertException as e: # Not issued
            log_request(e.get_full_msg(), level="info")
            payload.append({
                "id": cert.id,
                "status": e.status.value,
                "msg": e.msg,
                "custom_attrs": cert.custom_attrs,
                "domains": cert.domains,
                "expire_date": None,
                "chain": None,
                "certificate": None,
                "private_key": None,
            })
    
    return build_response(200, data=payload)


@api.route("/api/token/scope", methods=["GET"])
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


@api.route("/api/token/identity", methods=["GET"])
def get_identity() -> Response:
    remote_ip = get_remote_ip()
    identity = require_auth(remote_ip)
    payload = {
        "id": identity.id,
        "allowed_cidrs": identity.allowed_cidrs,
        "permissions": [{ "scope": p.scope, "action": p.action.value } for p in identity.permissions]
    }
    
    return build_response(200, data=payload)
