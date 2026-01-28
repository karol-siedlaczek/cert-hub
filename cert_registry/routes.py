from .models.token import PermissionAction
from flask import Blueprint, Response, jsonify, send_file, abort, request, current_app as app
from .utils import require_api_access, build_response, run_cmd, get_conf

api = Blueprint("api", __name__)


# @api.before_request
# def _load_cfg_and_auth():
#     g.cfg = cast(Config, app.extensions["config"])
#     require_api_access(g.cfg)


@api.route("/health", methods=["GET"])
def health() -> Response:
    require_api_access(PermissionAction.HEALTH.value)
    conf = get_conf()
    certs_health = []
    print(conf.certs)
    
    for cert in conf.certs:
        certs_health.append({ 
            "key": cert.key, 
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
    require_api_access(PermissionAction.RENEW.value)
    
    return jsonify(method="TODO - renew_certs")


@api.route("/api/certs/issue", methods=["POST"])
def issue_cert() -> Response:
    require_api_access(PermissionAction.ISSUE.value)
    
    return jsonify(method="TODO - issue_cert")


@api.route("/api/certs/<cert>", methods=["GET"])
def get_cert() -> Response:
    require_api_access(PermissionAction.READ.value)    
    
    return jsonify(method="TODO - get_cert")
