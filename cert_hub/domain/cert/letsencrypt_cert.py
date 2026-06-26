import logging
from datetime import datetime, timezone
from typing import Any, ClassVar
from dataclasses import dataclass
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cert_hub.exception.cert_exceptions import CertException
from cert_hub.domain.cert.cert import Cert
from cert_hub.domain.cert.cert_bot import CertBot
from cert_hub.domain.cert.cert_type import CertType
from cert_hub.domain.cert.cert_status import CertStatus
from cert_hub.domain.dns_provider import DnsProvider
from cert_hub.validation.require import Require

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class LetsEncryptCert(Cert):
    type: ClassVar[CertType] = CertType.LETSENCRYPT

    id: str
    email: str
    domains: tuple[str, ...]
    custom_attrs: dict
    dns_provider: DnsProvider


    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LetsEncryptCert":
        def get_required(name: str) -> Any:
            val = data.get(name)
            Require.present(name, val)
            return val

        id = get_required("id")
        email = get_required("email")
        domains = get_required("domains")
        custom_attrs = data.get("custom_attrs")
        dns_provider_raw = get_required("dns_provider")

        Require.type("id", id, str)
        Require.email("email", email)
        Require.type("domains", domains, list)
        
        if custom_attrs is not None:
            Require.type("custom_attrs", custom_attrs, dict)

        for i, domain in enumerate(domains):
            Require.domain(f"domains[{i}]", domain)

        Require.one_of("dns_provider", dns_provider_raw, DnsProvider.values())
        dns_provider = DnsProvider(dns_provider_raw)
        Require.installed_module("dns_provider", dns_provider.value, dns_provider.get_required_module())
        Require.secret_envs(dns_provider.get_required_envs())

        return cls(id, email, tuple(domains), custom_attrs, dns_provider)


    def is_issued(self) -> bool:
        certbot = CertBot.get_from_global_context()
        required_paths = [
            certbot.get_cert_path(self.id),
            certbot.get_chain_path(self.id),
            certbot.get_private_key_path(self.id)
        ]
        for path in required_paths:
            if not path.exists():
                return False
        return True


    def get_status(self) -> CertStatus:
        if not self.is_issued():
            certbot = CertBot.get_from_global_context()
            return CertStatus.REVOKED if certbot.is_revoked(self.id) else CertStatus.NOT_ISSUED
        try:
            return self._expiry_status()
        except CertException as e:
            return e.status


    def issue(self, force: bool = False) -> None:
        log.debug(f"Issuing '{self}' certificate...")

        if not force and self.is_issued():
            raise CertException(
                self.id,
                f"Certificate is already issued with expiration date to {self.get_expire_date_as_str()}",
                status=CertStatus.ALREADY_ISSUED
            )

        certbot = CertBot.get_from_global_context()
        certbot.issue(self.id, self.domains, self.email, self.dns_provider)
        try:
            certbot.clear_revoked(self.id)
        except OSError as e:
            log.warning(f"Issued '{self}' but failed to clear revoked marker: {e}")

        log.info(f"Successfully issued '{self}' certificate with expiration date to {self.get_expire_date_as_str()}")


    def renew(self, force: bool = False) -> None:
        log.debug(f"Renewing '{self}' certificate...")
        certbot = CertBot.get_from_global_context()

        if not force and not self.is_expiring():
            raise CertException(
                self.id,
                f"Certificate can be renewed {certbot.renew_before_days} days before expiration, current expiration date is {self.get_expire_date_as_str()}",
                status=CertStatus.NOT_YET_RENEWABLE
            )

        certbot.renew(self.id, self.dns_provider)

        log.info(f"Successfully renewed '{self}' certificate with new expiration date {self.get_expire_date_as_str()}")


    def revoke(self) -> None:
        log.debug(f"Revoking '{self}' certificate...")
        self._require_issued()
        certbot = CertBot.get_from_global_context()
        certbot.revoke(self.id)
        try:
            certbot.mark_revoked(self.id)
        except OSError as e:
            log.warning(f"Revoked '{self}' but failed to write revoked marker: {e}")
        log.info(f"Successfully revoked '{self}' certificate")


    def get_chain(self) -> str:
        self._require_issued()
        certbot = CertBot.get_from_global_context()
        return self._read_text(certbot.get_chain_path(self.id))


    def get_certificate(self) -> str:
        self._require_issued()
        certbot = CertBot.get_from_global_context()
        return self._read_text(certbot.get_cert_path(self.id))


    def get_private_key(self) -> str:
        self._require_issued()
        certbot = CertBot.get_from_global_context()
        return self._read_text(certbot.get_private_key_path(self.id))


    def get_expire_date(self) -> datetime:
        self._require_issued()
        certbot = CertBot.get_from_global_context()
        
        try:
            pem_bytes = certbot.get_cert_path(self.id).read_bytes()
            cert = x509.load_pem_x509_certificate(pem_bytes, default_backend())
        except (ValueError, OSError) as e:
            raise CertException(self.id, f"Certificate file is not a valid PEM X.509 certificate: {e}", status=CertStatus.INVALID_CERT_FILE)
        expire_date = cert.not_valid_after_utc
        
        if expire_date.tzinfo is None:
            expire_date = expire_date.replace(tzinfo=timezone.utc)
        return expire_date.astimezone(timezone.utc)


    def _require_issued(self) -> None:
        if not self.is_issued():
            raise CertException(self.id, "Certificate not issued", status=CertStatus.NOT_ISSUED)
