import re
from dataclasses import dataclass
from flask import request
from cert_registry.errors.auth_error import AuthError, AuthFailedError
from cert_registry.api.auth import require_auth
from cert_registry.api.helpers import get_conf, abort_response, log_request
from cert_registry.domain.identity import Identity
from cert_registry.domain.permission import PermissionAction
from cert_registry.domain.cert import Cert

@dataclass(frozen=True)
class Context():
    remote_ip: str
    identity: Identity
    certs: list[Cert]
    
    @classmethod
    def build(
        cls,
        scopes: str | list[str], 
        action: PermissionAction,
        *,
        enforce_auth: bool = True
    ) -> "Context":
        conf = get_conf()
        remote_ip = Context.get_remote_ip()
        identity = None
        
        if enforce_auth:
            try:
                identity = require_auth(remote_ip)
            except AuthError as e:
                log_request(f"{type(e).__name__}: {e.msg}, details: {e.detail}", "warning")
                abort_response(e.code, msg=e.msg, detail=None if isinstance(e, AuthFailedError) else e.detail)
        
        selected_certs = []
        
        if "*" in scopes:
            for cert in conf.certs:
                if cert.has_permission(identity, action):
                    selected_certs.append(cert)
        else:
            matched_cert_ids: set[str] = set()
            requested_scopes = set(scopes)
            cert_map = { c.id: c for c in conf.certs }
            
            for scope_pattern in enumerate(requested_scopes):
                if scope_pattern in cert_map:
                    matched_cert_ids.add(scope_pattern)
                    continue
                
                try:
                    match = re.compile(scope_pattern)
                except re.error as e:
                    abort_response(400, msg=f"Invalid cert scope pattern", detail={ "pattern": scope_pattern, "error": str(e) })
                
                for cert_id in cert_map.keys():
                    if match.fullmatch(cert_id):
                        matched_cert_ids.add(cert_id)
                
            for cert in conf.certs:
                if cert.id in matched_cert_ids and cert.has_permission(identity, action):
                    selected_certs.append(cert)
                
        # TODO - It probably does not make sense when enforce_auth is false, so delete below or add condition
        if not selected_certs:
            abort_response(404, msg="Not found any certificate", detail={ "scopes": list(requested_scopes), "action": action.value })
                
        return cls(remote_ip, identity, selected_certs)
    
    
    @staticmethod
    def get_remote_ip() -> str | None:
        if request.remote_addr:
            return request.remote_addr
        
        xff = request.headers.get("X-Forwarder-For", "")
        return xff.split(",")[0].strip() if xff else None
