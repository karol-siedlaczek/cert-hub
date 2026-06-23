import re
from dataclasses import dataclass
from typing import Pattern
from cert_hub.exception.api_exceptions import InvalidRequestError, ResourceNotFound, PermissionDenied
from cert_hub.api.helpers import require_auth, get_remote_ip
from cert_hub.domain.identity import Identity
from cert_hub.domain.permission import PermissionAction
from cert_hub.domain.cert import Cert
from cert_hub.conf.config import Config


@dataclass(frozen=True)
class Context:
    remote_ip: str
    identity: Identity


    @classmethod
    def authenticate(cls) -> "Context":
        remote_ip = get_remote_ip()
        identity = require_auth(remote_ip)
        return cls(remote_ip, identity)


    def resolve_scope(self, scopes: str | list[str], action: PermissionAction) -> list[Cert]:
        conf = Config.get_from_global_context()
        requested = [scopes] if isinstance(scopes, str) else list(scopes)

        matched = self._match_certs(requested, conf.certs)
        if not matched:
            # the scope names no existing certificate → genuinely not found
            raise ResourceNotFound(
                "Not found any certificate for selected scope",
                detail={"scope": requested, "action": action.value},
            )

        authorized = [c for c in matched if c.has_permission(self.identity, action)]
        if not authorized:
            # certs exist for the scope, but this identity may not act on them → forbidden
            raise PermissionDenied(
                "Not allowed to perform action on selected certificates",
                detail={"identity": self.identity.id, "scope": requested, "action": action.value},
            )
        return authorized


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
                raise InvalidRequestError("Invalid cert scope pattern", detail={"pattern": pattern, "error": str(e)})
            matched_ids.update(cid for cid in cert_map if rx.fullmatch(cid))
        return [c for c in certs if c.id in matched_ids]
