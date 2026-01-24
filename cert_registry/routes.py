
from typing import cast
from flask import Blueprint, Response, jsonify, send_file, abort, request, current_app as app
from .utils import require_api_access, build_response, run_cmd
from .config import Config

api = Blueprint("api", __name__)


# @api.before_request
# def _load_cfg_and_auth():
#     g.cfg = cast(Config, app.extensions["config"])
#     require_api_access(g.cfg)


@api.route("/health", methods=["GET"])
def health() -> Response:
    # require_api_access("health")
    return build_response(code=200, data={ "health": "OK" })


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
