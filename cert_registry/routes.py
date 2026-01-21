from flask import Blueprint, Response, jsonify, send_file, abort, request, current_app as app
from .utils import require_api_access, run_cmd

api = Blueprint("api", __name__)


@api.route("/health", methods=["GET"])
def health() -> Response:
    return jsonify(status="ok")


@api.route("/api/certs/renew", methods=["POST"])
def renew_certs() -> Response:
    require_api_access()
    
    return jsonify(method="TODO - renew_certs")


@api.route("/api/certs/issue", methods=["POST"])
def issue_cert() -> Response:
    require_api_access()
    
    return jsonify(method="TODO -issue_cert")


@api.route("/api/certs/<cert>", methods=["GET"])
def get_cert() -> Response:
    require_api_access()    
    
    return jsonify(method="TODO get_cert")
