from .models.identity import PermissionAction
from flask import Blueprint, Response, jsonify, send_file, abort, request, current_app as app
from .utils import require_auth, build_response, run_cmd, get_conf

api = Blueprint("api", __name__)


@api.route("/health", methods=["GET"])
def health() -> Response:
    require_auth("*", PermissionAction.HEALTH.value) # TODO - Add multiple scopes
    conf = get_conf()
    certs_health = []
    print(conf.certs)
    
    for cert in conf.certs:
        certs_health.append({ 
            "id": cert.id, 
            "status": "OK", 
            "expireDate": "null" 
        })
    
    payload = {
        "health": "OK",
        "certs": certs_health
    }
    return build_response(code=200, data=payload)


@api.route("/api/certs/renew", methods=["POST"])
def renew_certs() -> Response:
    require_auth("domain", PermissionAction.RENEW.value)
    
    return jsonify(method="TODO - renew_certs")


@api.route("/api/certs/issue", methods=["POST"])
def issue_cert() -> Response:
    require_auth("domain", PermissionAction.ISSUE.value)
    
    return jsonify(method="TODO - issue_cert")


@api.route("/api/certs/<cert>", methods=["GET"])
def get_cert() -> Response:
    require_auth("domain", PermissionAction.READ.value)    
    
    return jsonify(method="TODO - get_cert")
