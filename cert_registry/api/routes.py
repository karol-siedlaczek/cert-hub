
from flask import Blueprint, Response, jsonify
from cert_registry.domain.permission import PermissionAction
from cert_registry.api.auth import require_auth
from cert_registry.api.context import Context
from cert_registry.api.validators import query_list
from cert_registry.api.helpers import build_response

api = Blueprint("api", __name__)


@api.route("/health", methods=["GET"])
def health() -> Response:
    certs = query_list("cert", required=True)
    ctx = Context.build(certs, PermissionAction.HEALTH)

    certs_health = []

    print("context:")
    print(ctx)
    for cert in ctx.certs:
        certs_health.append({ 
            "id": cert.id, 
            "status": "NOT_ISSUED", 
            "expireDate": "null" 
        })
    
    return build_response(200, data={ "health": "OK", "certs": certs_health })


@api.route("/api/certs/renew", methods=["POST"])
def renew_certs() -> Response:
    require_auth("domain", PermissionAction.RENEW)
    
    return jsonify(method="TODO - renew_certs")


@api.route("/api/certs/issue", methods=["POST"])
def issue_cert() -> Response:
    require_auth("domain", PermissionAction.ISSUE)
    
    return jsonify(method="TODO - issue_cert")


@api.route("/api/certs/<cert>", methods=["GET"])
def get_cert() -> Response:
    require_auth("domain", PermissionAction.READ)    
    
    return jsonify(method="TODO - get_cert")
