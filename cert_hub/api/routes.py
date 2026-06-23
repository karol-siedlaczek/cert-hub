import os
import platform
from flask import Blueprint, Response
from cert_hub.api.context import Context
from cert_hub.api.validators import query_list, query_bool
from cert_hub.api.helpers import build_response, log_request, require_auth, get_remote_ip, get_log_record
from cert_hub.conf.config import Config
from cert_hub.domain.permission import PermissionAction
from cert_hub.domain.cert_status import CertStatus
from cert_hub.exception.cert_exceptions import CertException

api = Blueprint("api", __name__)

# ── liveness / introspection ────────────────────────────────────────────────

@api.route("/ping", methods=["GET"])
def ping() -> str:
    return "pong"


@api.route("/api/version", methods=["GET"])
def version() -> Response:
    payload = {
        "name": "Cert Hub",
        "author": "karol@siedlaczek.com.pl",
        "app": os.environ.get("APP_VERSION", "unknown"),
        "python": platform.python_version()
    }
    return build_response(200, data=payload)

# ── token  ────────────────────────────────────────────────

@api.route("/api/token/scope", methods=["GET"])
def token_scope() -> Response:
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
def token_identity() -> Response:
    remote_ip = get_remote_ip()
    identity = require_auth(remote_ip)
    payload = {
        "id": identity.id,
        "allowed_cidrs": identity.allowed_cidrs,
        "permissions": [{ "scope": p.scope, "action": p.action.value } for p in identity.permissions]
    }
    
    return build_response(200, data=payload)

# ── certs ──────────────────────────────────────────────────────────────────

@api.route("/api/certs", methods=["GET"])
def cert_list() -> Response:
    patterns = query_list("match", default=["*"])
    ctx = Context.authenticate()
    certs = ctx.resolve_scope(patterns, PermissionAction.READ)
    payload = []

    for cert in certs:
        try:
            status = cert.get_status()
            msg = f"Certificate successfully fetched"
            
            payload.append({
                "id": cert.id,
                "status": status.value,
                "msg": msg,
                "custom_attrs": cert.custom_attrs,
                "domains": cert.domains,
                "expire_date": cert.get_expire_date_as_str(),
                "chain": cert.get_chain(),
                "certificate": cert.get_certificate(),
                "private_key": cert.get_private_key()
            })
            log_request(get_log_record(status, cert, msg), identity=ctx.identity, level="info")
        except CertException as e: # Not issued
            payload.append({
                "id": cert.id,
                "status": e.status.value,
                "msg": e.msg,
                "custom_attrs": cert.custom_attrs,
                "domains": cert.domains,
                "expire_date": None,
                "chain": None,
                "certificate": None,
                "private_key": None
            })
            log_request(get_log_record(e.status, e.cert_id, e.msg), identity=ctx.identity, level="info")
    
    return build_response(200, data=payload)


@api.route("/api/certs/status", methods=["GET"])
def cert_status() -> Response:
    patterns = query_list("match", default=["*"])
    exclude_ok = query_bool("exclude_ok")
    
    ctx = Context.authenticate()
    certs = ctx.resolve_scope(patterns, PermissionAction.STATUS)

    certs_statuses = []
    is_critical = False
    is_warning = False

    for cert in certs:
        status = cert.get_status()
        
        if status == CertStatus.EXPIRED:
            is_critical = True
        elif status != CertStatus.OK:
            is_warning = True
        
        msg = f"Certificate {"issued and does not require renewal" if status == CertStatus.OK else status.value.lower().replace("_", " ")}"
        
        try:
            if not (exclude_ok and status == CertStatus.OK):
                certs_statuses.append({
                    "id": cert.id,
                    "status": status.value,
                    "msg": msg,
                    "expire_date": cert.get_expire_date_as_str(),
                    "days_to_expire": cert.get_days_to_expire()
                })
            log_request(get_log_record(status, cert, msg), identity=ctx.identity, level="info")
        except CertException as e: # Not issued
            certs_statuses.append({
                "id": cert.id,
                "status": status.value,
                "msg": e.msg,
                "expire_date": None,
                "days_to_expire": None
            })
            log_request(get_log_record(e.status, e.cert_id, e.msg), identity=ctx.identity, level="info")
    
    if is_critical:
        overall_status = "CRITICAL"
    elif is_warning:
        overall_status = "WARNING"
    else:
        overall_status = "OK"
    
    payload = {
        "status": overall_status, 
        "certs": certs_statuses 
    }
    
    return build_response(200, data=payload)


@api.route("/api/certs/issue", methods=["POST"])
def cert_issue() -> Response:
    patterns = query_list("match", default=["*"])
    force = query_bool("force")
    ctx = Context.authenticate()
    certs = ctx.resolve_scope(patterns, PermissionAction.ISSUE)
    payload = []

    for cert in certs:
        try:
            cert.issue(force)
            status = CertStatus.ISSUED
            msg = "Certificate successfully issued"
            
            payload.append({
                "id": cert.id,
                "status": status.value,
                "msg": msg,
                "expire_date": cert.get_expire_date_as_str()             
            })
            log_request(get_log_record(status, cert, msg), identity=ctx.identity, level="info")
        except CertException as e: # Already issued
            payload.append({
                "id": cert.id,
                "status": e.status.value,
                "msg": e.msg,
                "expire_date": cert.get_expire_date_as_str()
            })
            log_request(get_log_record(e.status, e.cert_id, e.msg), identity=ctx.identity, level="info")
            
    return build_response(200, data=payload)


@api.route("/api/certs/renew", methods=["POST"])
def cert_renew() -> Response:
    patterns = query_list("match", default=["*"])
    force = query_bool("force")
    ctx = Context.authenticate()
    certs = ctx.resolve_scope(patterns, PermissionAction.RENEW)
    payload = []

    for cert in certs:
        try:
            cert.renew(force)
            status = CertStatus.RENEWED
            msg = f"Certificate successfully renewed"
            
            payload.append({
                "id": cert.id,
                "status": status.value,
                "msg": msg,
                "next_renew_date": cert.get_next_renew_date_as_str(),
                "expire_date": cert.get_expire_date_as_str()
            })
            log_request(get_log_record(status, cert, msg), identity=ctx.identity, level="info")
        except CertException as e: # Not expiring / Not issued
            is_issued = cert.is_issued()
            payload.append({
                "id": cert.id,
                "status": e.status.value,
                "msg": e.msg,
                "next_renew_date": cert.get_next_renew_date_as_str() if is_issued else None,
                "expire_date": cert.get_expire_date_as_str() if is_issued else None
            })
            log_request(get_log_record(e.status, e.cert_id, e.msg), identity=ctx.identity, level="info")
    
    return build_response(200, data=payload)
