import re
from dataclasses import dataclass
from typing import Pattern
from flask import request
from cert_hub.exception.api_exceptions import InvalidRequestError, ResourceNotFound, PermissionDenied
from cert_hub.domain.identity import Identity
from cert_hub.domain.permission.permission_action import PermissionAction
from cert_hub.domain.cert.cert import Cert
from cert_hub.conf.config import Config
from cert_hub.exception.auth_exceptions import AuthTokenMissingException, AuthFailedException, AuthIpNotAllowedException


@dataclass
class Context:
    remote_ip: str | None = None
    identity: Identity | None = None


    @classmethod
    def authenticate(cls) -> "Context":
        ctx = cls()
        ctx.remote_ip = ctx.get_remote_ip()
        ctx.identity = ctx.resolve_identity()
        return ctx


    def resolve_cert(self, cert_id: str, action: PermissionAction) -> Cert:
        # Per-cert endpoints address a single certificate by its exact id. Unlike
        # resolve_certs (which treats scopes as match patterns / regex), this never
        # interprets cert_id as a pattern — so a path like 'web.api' can't silently
        # match another cert. 404 when no such id, 403 when the id exists but is denied.
        conf = Config.get_from_global_context()
        cert = next((c for c in conf.certs if c.id == cert_id), None)

        if cert is None:
            raise ResourceNotFound(
                "Certificate not found",
                detail={"id": cert_id, "action": action.value}
            )
        if not self.identity.allows(cert, action):
            raise PermissionDenied(
                "Not allowed to perform action on certificate",
                detail={"identity": self.identity.id, "id": cert_id, "action": action.value}
            )
        return cert


    def resolve_certs(self, cert_patterns: str | list[str], action: PermissionAction) -> list[Cert]:
        conf = Config.get_from_global_context()
        requested_scope = [cert_patterns] if isinstance(cert_patterns, str) else list(cert_patterns)

        matched = self._match_certs(requested_scope, conf.certs)
        if not matched:
            # The scope names no existing certificate -> genuinely not found
            raise ResourceNotFound(
                "Not found any certificate for selected scope",
                detail={"scope": requested_scope, "action": action.value}
            )

        resolved_certs = [c for c in matched if self.identity.allows(c, action)]
        
        if not resolved_certs:
            # Certs exist for the scope, but this identity may not act on them -> forbidden
            raise PermissionDenied(
                "Not allowed to perform action on selected certificates",
                detail={"identity": self.identity.id, "scope": requested_scope, "action": action.value}
            )
        return resolved_certs


    def resolve_identity(self) -> Identity:
        auth_header = request.headers.get("Authorization", None)
        
        if not auth_header or auth_header == "":
            raise AuthTokenMissingException("Authorization header is missing or empty")
        elif not auth_header.startswith("Bearer "):
            raise AuthTokenMissingException("Authorization header does not start with 'Bearer '")
        
        token_raw = auth_header[len("Bearer "):].strip()

        try:
            identity_id, identity_token = token_raw.split(".", 1)
            if not identity_id or not identity_token:
                raise ValueError()
        except ValueError:
            raise AuthFailedException("Invalid token format, expected: 'Authorization: Bearer <id>.<token>'")
        
        conf = Config.get_from_global_context()
        identity = next((i for i in conf.identities if i.id == identity_id), None)
        
        if identity is None:
            raise AuthFailedException(f"Unknown identity '{identity_id}'")
        if not identity.is_token_valid(conf.hmac_key, identity_token):
            raise AuthFailedException(f"Invalid token for identity '{identity_id}'")
        if not identity.is_ip_allowed(self.remote_ip):
            raise AuthIpNotAllowedException(self.remote_ip)

        return identity


    def get_remote_ip(self) -> str | None:
        # request.remote_addr is the real client when connected directly, or when
        # ProxyFix is enabled (TRUSTED_PROXY_HOPS > 0) the client behind the trusted
        # proxy. We deliberately do NOT parse X-Forwarded-For here — that would be
        # spoofable; trust is configured centrally via ProxyFix in create_app.
        return request.remote_addr


    @staticmethod
    def _match_certs(scopes: list[str], certs: list[Cert]) -> list[Cert]:
        if "*" in scopes:
            return list(certs)
        
        cert_map = {c.id: c for c in certs}
        matched_ids: set[str] = set()
        
        for pattern in scopes:
            if pattern in cert_map:
                matched_ids.add(pattern)
                continue
            try:
                rx: Pattern = re.compile(pattern)
            except re.error as e:
                raise InvalidRequestError(
                    "Invalid cert scope pattern", 
                    detail={
                        "pattern": pattern, 
                        "error": str(e)
                    }
                )
            matched_ids.update(cid for cid in cert_map if rx.fullmatch(cid))
        return [c for c in certs if c.id in matched_ids]
