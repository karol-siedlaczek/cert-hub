from flask import Blueprint, Response, jsonify, send_file, abort, request, current_app as app
from .utils import require_token, run_cmd

api = Blueprint("api", __name__)


@api.route("/health", methods=["GET"])
def health() -> Response:
    return jsonify(status="ok")


@api.route("/api/certs/renew", methods=["POST"])
def renew_certs() -> Response:
    require_token()
    
    return jsonify(method="renew_certs")


@api.route("/api/certs/issue", methods=["POST"])
def issue_cert() -> Response:
    require_token()
    
    return jsonify(method="issue_cert")


@api.route("/api/certs/<cert>", methods=["GET"])
def get_cert() -> Response:
    require_token()    
    
    return jsonify(method="get_cert")
