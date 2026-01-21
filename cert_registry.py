#!/usr/bin/env python3

# Karol Siedlaczek 2026

import os
import argparse
from flask import Flask, Response, jsonify, send_file, abort
from pathlib import Path

CERTS_DIR = Path("certs")

app = Flask(__name__)

@app.route("/health")
def health() -> Response:
    return jsonify(status="ok")

@app.route("/certs/<domain>")
def certs(domain: str) -> Response:
    cert_path = CERTS_DIR / domain
    
    if not cert_path.exists():
        abort(404, "Certificate not found")

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cert registry", add_help=True)
    
    parser.add_argument("-p", "--port", 
        default=os.getenv("BIND_PORT", default=8080),
        type = int, # TODO - Change to port validator
        help = ""
    )
    parser.add_argument("-a", "--address",
        default=os.getenv("BIND_ADDR", default="0.0.0.0"),
        type = str, # TODO - Change to ip_addr validator
        help = ""
    )
    parser.add_argument("-P", "--path",
        default=os.getenv("CERTS_PATH", default="/etc/ssl/certs"),
        type = str, # TODO - Change to absolute_path validator
        help = ""
    )
    parser.add_argument("-d", "--debug",
        default=os.getenv("DEBUG", default=False),
        action="store_true",
        help = ""
    )
    
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    app.run(
        host=args.address, 
        port=args.port, 
        debug=args.debug,
    )
