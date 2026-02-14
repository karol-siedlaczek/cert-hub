import re
from dataclasses import dataclass
from flask import request
from typing import Pattern
from cert_registry.exception.api_exceptions import ApiError
from cert_registry.api.helpers import require_auth
from cert_registry.domain.identity import Identity
from cert_registry.domain.permission import PermissionAction
from cert_registry.domain.cert import Cert
from cert_registry.conf.config import Config

@dataclass(frozen=True)
class Context():
    remote_ip: str
    identity: Identity
    certs: list[Cert]
    
    @classmethod
    def build(
        cls,
        scopes: str | list[str], 
        action: PermissionAction
    ) -> "Context":
        remote_ip = Context.get_remote_ip()
        identity = require_auth(remote_ip)

        selected_certs = []
        requested_scopes = set(scopes)
        conf = Config.get_from_global_context()
    
        if "*" in scopes:
            for cert in conf.certs:
                if cert.has_permission(identity, action):
                    selected_certs.append(cert)
        else:
            matched_cert_ids: set[str] = set()
            cert_map = { c.id: c for c in conf.certs }
            
            for scope_pattern in requested_scopes:
                if scope_pattern in cert_map:
                    matched_cert_ids.add(scope_pattern)
                    continue
                
                try:
                    match: Pattern = re.compile(scope_pattern)
                except re.error as e:
                    raise ApiError(400, msg=f"Invalid cert scope pattern", detail={ "pattern": scope_pattern, "error": str(e) })
                
                for cert_id in cert_map.keys():
                    if match.fullmatch(cert_id):
                        matched_cert_ids.add(cert_id)
                
            for cert in conf.certs:
                if cert.id in matched_cert_ids and cert.has_permission(identity, action):
                    selected_certs.append(cert)
                
        if not selected_certs:
            raise ApiError(404, msg="Not found any certificate for selected scope and action", detail={ "scope": list(requested_scopes), "action": action.value })
                
        return cls(remote_ip, identity, selected_certs)
    
    
    @staticmethod
    def get_remote_ip() -> str | None:
        if request.remote_addr:
            return request.remote_addr
        
        xff = request.headers.get("X-Forwarder-For", "")
        return xff.split(",")[0].strip() if xff else None
