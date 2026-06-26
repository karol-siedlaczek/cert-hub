import os
import platform
import signal
from flask import Blueprint, Response
from cert_hub.api.context import Context
from cert_hub.api.validators import query_list, query_bool, query_one_of
from cert_hub.api.helpers import build_response, log_request, get_log_record, filter_certs_by_type, render_metrics
from cert_hub.conf.config import Config
from cert_hub.domain.permission.permission_action import PermissionAction
from cert_hub.domain.cert.cert_status import CertStatus
from cert_hub.domain.cert.cert_type import CertType
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
        "git_sha": os.environ.get("GIT_SHA", "unknown"),
        "build_date": os.environ.get("BUILD_DATE", "unknown"),
        "python": platform.python_version()
    }
    return build_response(200, data=payload)


@api.route("/api/metrics", methods=["GET"])
def metrics() -> Response:
    ctx = Context.authenticate()
    conf = Config.get_from_global_context()

    records = []
    for cert in conf.certs:
        if not ctx.identity.allows(cert, PermissionAction.STATUS):
            continue
        status = cert.get_status()
        expiry_ts = None
        days_to_expire = None
        try:
            expiry_ts = int(cert.get_expire_date().timestamp())
            days_to_expire = cert.get_days_to_expire()
        except CertException:
            pass
        records.append({
            "id": cert.id,
            "type": cert.type.value,
            "status": status.value,
            "expiry_ts": expiry_ts,
            "days_to_expire": days_to_expire
        })

    build_info = {
        "version": os.environ.get("APP_VERSION", "unknown"),
        "git_sha": os.environ.get("GIT_SHA", "unknown")
    }
    body = render_metrics(records, build_info)
    return Response(body, mimetype="text/plain; version=0.0.4")

# ── token  ────────────────────────────────────────────────

@api.route("/api/token/scope", methods=["GET"])
def token_scope() -> Response:
    ctx = Context.authenticate()
    identity = ctx.identity
    conf = Config.get_from_global_context()
    actions = [a for a in PermissionAction if a not in (PermissionAction.ANY, PermissionAction.RELOAD)]
    payload = { action.value: [] for action in actions }

    for cert in conf.certs:
        for action in actions:
            if identity.allows(cert, action):
                payload[action.value].append(cert.id)
                
    return build_response(200, data=payload)


@api.route("/api/token/identity", methods=["GET"])
def token_identity() -> Response:
    ctx = Context.authenticate()
    identity = ctx.identity
    payload = {
        "id": identity.id,
        "allowed_cidrs": identity.allowed_cidrs,
        "permissions": [{"scope": p.scope, "action": p.action.value} for p in identity.permissions]
    }
    return build_response(200, data=payload)

# ── certs ──────────────────────────────────────────────────────────────────

@api.route("/api/certs", methods=["GET"])
def cert_list() -> Response:
    patterns = query_list("match", default=["*"])
    ctx = Context.authenticate()
    certs = ctx.resolve_certs(patterns, PermissionAction.READ)
    certs = filter_certs_by_type(certs)
    payload = []

    for cert in certs:
        status = cert.get_status()
        try:
            msg = "Certificate successfully fetched"
            payload.append({
                "id": cert.id,
                "type": cert.type.value,
                "status": status.value,
                "msg": msg,
                "custom_attrs": cert.custom_attrs,
                "domains": cert.domains,
                "expire_date": cert.get_expire_date_as_str(),
                "days_to_expire": cert.get_days_to_expire(),
                "chain": cert.get_chain(),
                "certificate": cert.get_certificate(),
                "private_key": cert.get_private_key()
            })
            log_request(get_log_record(status, cert, msg), identity=ctx.identity, level="info")
        except CertException as e:  # e.g. not issued / revoked (PEM material unavailable)
            payload.append({
                "id": cert.id,
                "type": cert.type.value,
                "status": status.value,
                "msg": e.msg,
                "custom_attrs": cert.custom_attrs,
                "domains": cert.domains,
                "expire_date": None,
                "days_to_expire": None,
                "chain": None,
                "certificate": None,
                "private_key": None
            })
            log_request(get_log_record(status, cert, e.msg), identity=ctx.identity, level="info")

    return build_response(200, data=payload)


@api.route("/api/certs/status", methods=["GET"])
def cert_status() -> Response:
    patterns = query_list("match", default=["*"])
    exclude_ok = query_bool("exclude_ok")
    
    ctx = Context.authenticate()
    certs = ctx.resolve_certs(patterns, PermissionAction.STATUS)
    certs = filter_certs_by_type(certs)

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
                    "type": cert.type.value,
                    "status": status.value,
                    "msg": msg,
                    "next_renew_date": cert.get_next_renew_date_as_str(),
                    "expire_date": cert.get_expire_date_as_str(),
                    "days_to_expire": cert.get_days_to_expire()
                })
            log_request(get_log_record(status, cert, msg), identity=ctx.identity, level="info")
        except CertException as e: # Not issued
            certs_statuses.append({
                "id": cert.id,
                "type": cert.type.value,
                "status": status.value,
                "msg": e.msg,
                "next_renew_date": None,
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


@api.route("/api/certs/catalog", methods=["GET"])
def cert_catalog() -> Response:
    ctx = Context.authenticate()
    conf = Config.get_from_global_context()

    patterns = query_list("match", default=["*"])
    certs = Context._match_certs(patterns, conf.certs)
    certs = filter_certs_by_type(certs, default=CertType.ALL)

    permission = query_one_of("permission", default=None, allowed=["read", "issue", "renew", "status", "revoke"])
    if permission is not None:
        action = PermissionAction(permission)
        certs = [c for c in certs if ctx.identity.allows(c, action)]

    payload = [{"id": c.id, "type": c.type.value} for c in certs]
    return build_response(200, data=payload)


@api.route("/api/certs/<cert_id>/pem", methods=["GET"])
def cert_pem(cert_id: str) -> Response:
    pem_type = query_one_of("type", default="bundle", allowed=["bundle", "cert", "chain", "privkey"])
    ctx = Context.authenticate()
    cert = ctx.resolve_cert(cert_id, PermissionAction.READ)

    try:
        if pem_type == "cert":
            body = cert.get_certificate()
        elif pem_type == "chain":
            body = cert.get_chain()
        elif pem_type == "privkey":
            body = cert.get_private_key()
        else:
            parts = [p.strip() for p in (cert.get_certificate(), cert.get_chain(), cert.get_private_key()) if p]
            body = "\n".join(parts) + "\n"
        
        log_request(get_log_record(cert.get_status(), cert, f"Served PEM '{pem_type}'"), identity=ctx.identity, level="info")
        return Response(body, mimetype="text/plain")
    except CertException as e:
        log_request(get_log_record(e.status, e.cert_id, e.msg), identity=ctx.identity, level="warning")
        return build_response(409, msg=e.msg, detail={"id": cert.id, "status": e.status.value})


@api.route("/api/certs/<cert_id>/issue", methods=["POST"])
def cert_issue(cert_id: str) -> Response:
    force = query_bool("force")
    ctx = Context.authenticate()
    cert = ctx.resolve_cert(cert_id, PermissionAction.ISSUE)

    try:
        cert.issue(force)
        status = CertStatus.ISSUED
        msg = "Certificate successfully issued"
        log_request(get_log_record(status, cert, msg), identity=ctx.identity, level="info")
        payload = {
            "id": cert.id,
            "type": cert.type.value,
            "status": status.value,
            "msg": msg,
            "next_renew_date": cert.get_next_renew_date_as_str(),
            "expire_date": cert.get_expire_date_as_str(),
            "days_to_expire": cert.get_days_to_expire()
        }
        return build_response(200, data=payload)
    except CertException as e:
        log_request(get_log_record(e.status, e.cert_id, e.msg), identity=ctx.identity, level="warning")
        payload = {
            "id": cert.id, 
            "type": cert.type.value,
            "status": e.status.value,
            "msg": e.msg,
            "next_renew_date": None,
            "expire_date": None,
            "days_to_expire": None
        }
        return build_response(409, data=payload)


@api.route("/api/certs/<cert_id>/renew", methods=["POST"])
def cert_renew(cert_id: str) -> Response:
    force = query_bool("force")
    ctx = Context.authenticate()
    cert = ctx.resolve_cert(cert_id, PermissionAction.RENEW)

    try:
        cert.renew(force)
        status = CertStatus.RENEWED
        msg = "Certificate successfully renewed"
        log_request(get_log_record(status, cert, msg), identity=ctx.identity, level="info")
        payload = {
            "id": cert.id,
            "type": cert.type.value,
            "status": status.value,
            "msg": msg,
            "next_renew_date": cert.get_next_renew_date_as_str(),
            "expire_date": cert.get_expire_date_as_str(),
            "days_to_expire": cert.get_days_to_expire()
        }
        return build_response(200, data=payload)
    except CertException as e:
        log_request(get_log_record(e.status, e.cert_id, e.msg), identity=ctx.identity, level="info")
        payload = {
            "id": cert.id,
            "type": cert.type.value,
            "status": e.status.value,
            "msg": e.msg,
            "next_renew_date": None,
            "expire_date": None,
            "days_to_expire": None
        }
        return build_response(409, data=payload)


@api.route("/api/certs/<cert_id>/revoke", methods=["POST"])
def cert_revoke(cert_id: str) -> Response:
    ctx = Context.authenticate()
    cert = ctx.resolve_cert(cert_id, PermissionAction.REVOKE)

    try:
        cert.revoke()
        status = CertStatus.REVOKED
        msg = "Certificate successfully revoked"
        log_request(get_log_record(status, cert, msg), identity=ctx.identity, level="info")
        payload = {
            "id": cert.id, 
            "type": cert.type.value, 
            "status": status.value, 
            "msg": msg
        }
        return build_response(200, data=payload)
    except CertException as e:
        log_request(get_log_record(e.status, e.cert_id, e.msg), identity=ctx.identity, level="warning")
        payload = {
            "id": cert.id,
            "type": cert.type.value,
            "status": e.status.value,
            "msg": e.msg
        }
        return build_response(409, data=payload)


@api.route("/api/admin/reload", methods=["POST"])
def admin_reload() -> Response:
    identity = Context.authenticate().identity

    if not identity.has_global_action(PermissionAction.RELOAD):
        return build_response(403, msg="Not allowed to reload configuration", detail={"identity": identity.id, "required": "*:reload"})

    master_pid = os.getppid()
    try:
        os.kill(master_pid, signal.SIGHUP)
    except OSError as e:
        log_request(f"Reload failed to signal master process: {e}", identity=identity, level="error")
        return build_response(502, msg="Failed to signal master process for reload", detail=str(e))

    log_request("Reload signal (SIGHUP) sent to master process", identity=identity, level="info")
    return build_response(202, msg="Reload signal sent to master process", data={"master_pid": master_pid})
