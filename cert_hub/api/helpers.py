import logging
from datetime import datetime, timezone
from typing import Any
from http import HTTPStatus
from flask import Response, jsonify, request
from cert_hub.api.validators import query_one_of
from cert_hub.domain.cert.cert import Cert
from cert_hub.domain.cert.cert_type import CertType
from cert_hub.domain.cert.cert_status import CertStatus
from cert_hub.domain.identity import Identity

log = logging.getLogger(__name__)


def log_request(msg: str, *, identity: Identity | None = None, level: str = "info") -> None:
    level = level.lower()
    log_fn = getattr(log, level, None)
    
    if not callable(log_fn):
        raise ValueError(f"Invalid log level: {level}")
    log_fn(f"{request.remote_addr} {request.method} {request.path} {f"({identity.id}) " if identity else ""}{msg}")


def build_response(
    code: int,
    *,
    msg: str | None = None,
    data: Any = None, 
    detail: Any | None = None
) -> Response:
    payload: dict[str, Any] = {}
    
    if msg is not None:
        payload["message"] = msg
    if detail is not None:
        payload["detail"] = detail
    if data is not None:
        payload["data"] = data
        
    payload = {
        "method": request.method,
        "http_code": code,
        "http_status": HTTPStatus(code).phrase,
        "path": request.path,
        **payload,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    response = jsonify(payload)
    response.status_code = code
    return response


def get_log_record(status: CertStatus, cert: Cert | str, msg: str) -> str:
    return f"cert_id='{cert.id if isinstance(cert, Cert) else cert}', status='{status.value}', msg='{msg}'"


def filter_certs_by_type(certs: list[Cert], *, default: CertType = CertType.ALL) -> list[Cert]:
    type_filter = query_one_of("type", default=default, allowed=CertType.values())
    if type_filter == CertType.ALL:
        return certs
    return [c for c in certs if c.type.value == type_filter]


def render_metrics(records: list[dict], build_info: dict) -> str:
    def _escape_label(value: object) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    lines: list[str] = []

    lines.append("# HELP certhub_build_info Build information.")
    lines.append("# TYPE certhub_build_info gauge")
    lines.append(
        f'certhub_build_info{{version="{_escape_label(build_info.get("version", ""))}",'
        f'git_sha="{_escape_label(build_info.get("git_sha", ""))}"}} 1'
    )

    lines.append("# HELP certhub_cert_expiry_timestamp_seconds Certificate expiry as a unix timestamp.")
    lines.append("# TYPE certhub_cert_expiry_timestamp_seconds gauge")
    for record in records:
        if record.get("expiry_ts") is not None:
            lines.append(
                f'certhub_cert_expiry_timestamp_seconds{{id="{_escape_label(record["id"])}",'
                f'type="{_escape_label(record["type"])}"}} {int(record["expiry_ts"])}'
            )

    lines.append("# HELP certhub_cert_days_to_expire Days until certificate expiry.")
    lines.append("# TYPE certhub_cert_days_to_expire gauge")
    for record in records:
        if record.get("days_to_expire") is not None:
            lines.append(
                f'certhub_cert_days_to_expire{{id="{_escape_label(record["id"])}",'
                f'type="{_escape_label(record["type"])}"}} {int(record["days_to_expire"])}'
            )

    lines.append("# HELP certhub_cert_status Current certificate status (value is always 1; the status is a label).")
    lines.append("# TYPE certhub_cert_status gauge")
    for record in records:
        lines.append(
            f'certhub_cert_status{{id="{_escape_label(record["id"])}",'
            f'type="{_escape_label(record["type"])}",'
            f'status="{_escape_label(record["status"])}"}} 1'
        )

    return "\n".join(lines) + "\n"
