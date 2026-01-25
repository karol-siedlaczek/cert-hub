
from typing import cast
from flask import Blueprint, Response, jsonify, send_file, abort, request, current_app as app
from .utils import require_api_access, build_response, run_cmd, get_conf

api = Blueprint("api", __name__)


# @api.before_request
# def _load_cfg_and_auth():
#     g.cfg = cast(Config, app.extensions["config"])
#     require_api_access(g.cfg)


@api.route("/health", methods=["GET"])
def health() -> Response:
    # require_api_access("health")
    # conf = get_conf()
    #certs_health = []
    # print(conf.CERTS)
    #for cert in conf.CERTS:
    #    certs_health.append(cert["key"])
    payload = {
        "health": "OK",
    #    "certs": certs_health
    }
    return build_response(code=200, data=payload)


@api.route("/api/certs/renew", methods=["POST"])
def renew_certs() -> Response:
    require_api_access("renew")
    
    return jsonify(method="TODO - renew_certs")


@api.route("/api/certs/issue", methods=["POST"])
def issue_cert() -> Response:
    require_api_access("issue")
    
    return jsonify(method="TODO - issue_cert")


@api.route("/api/certs/<cert>", methods=["GET"])
def get_cert() -> Response:
    require_api_access("read")    
    
    return jsonify(method="TODO - get_cert")
