import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar
from dataclasses import dataclass
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cert_hub.exception.cert_exceptions import CertException
from cert_hub.exception.validator_exceptions import ValidationError
from cert_hub.domain.cert.cert import Cert
from cert_hub.domain.cert.cert_type import CertType
from cert_hub.domain.cert.cert_status import CertStatus
from cert_hub.validation.require import Require

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class StaticCert(Cert):
    type: ClassVar[CertType] = CertType.STATIC

    id: str
    cert_file: Path
    privkey_file: Path
    chain_file: Path | None
    custom_attrs: dict


    @classmethod
    def from_dict(cls, data: dict[str, Any], static_certs_dir: Path) -> "StaticCert":
        def get_required(name: str) -> Any:
            val = data.get(name)
            Require.present(name, val)
            return val

        def resolve_file(field: str, name: str) -> Path:
            Require.type(field, name, str)
            if name.startswith("/") or ".." in Path(name).parts or name.strip() == "":
                raise ValidationError(
                    f"Value '{field}={name}' must be a plain file name under STATIC_CERTS_DIR (no absolute path, no '..')"
                )
            return static_certs_dir / name

        id = get_required("id")
        Require.type("id", id, str)
        cert_file = resolve_file("cert_file", get_required("cert_file"))
        privkey_file = resolve_file("privkey_file", get_required("privkey_file"))

        chain_raw = data.get("chain_file")
        chain_file = resolve_file("chain_file", chain_raw) if chain_raw else None

        custom_attrs = data.get("custom_attrs")
        if custom_attrs is not None:
            Require.type("custom_attrs", custom_attrs, dict)

        return cls(id, cert_file, privkey_file, chain_file, custom_attrs)


    @property
    def domains(self) -> tuple[str, ...]:
        try:
            cert = self._load_cert()
        except CertException:
            return ()
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return tuple(san.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            return ()


    def is_issued(self) -> bool:
        if not self.cert_file.exists() or not self.privkey_file.exists():
            return False
        if self.chain_file is not None and not self.chain_file.exists():
            return False
        return True


    def get_status(self) -> CertStatus:
        if not self.cert_file.exists():
            return CertStatus.CERT_MISSING
        try:
            self._load_cert()
        except CertException:
            return CertStatus.INVALID_CERT_FILE
        if not self.privkey_file.exists():
            return CertStatus.KEY_MISSING
        if self.chain_file is not None and not self.chain_file.exists():
            return CertStatus.CHAIN_MISSING
        return self._expiry_status()


    def get_certificate(self) -> str:
        self._load_cert()
        return self._read_text(self.cert_file)


    def get_chain(self) -> str:
        if self.chain_file is None:
            return ""
        if not self.chain_file.exists():
            raise CertException(self.id, f"Chain file not found: {self.chain_file.name}", status=CertStatus.CHAIN_MISSING)
        return self._read_text(self.chain_file)


    def get_private_key(self) -> str:
        if not self.privkey_file.exists():
            raise CertException(self.id, f"Private key file not found: {self.privkey_file.name}", status=CertStatus.KEY_MISSING)
        return self._read_text(self.privkey_file)


    def get_expire_date(self) -> datetime:
        cert = self._load_cert()
        expire_date = cert.not_valid_after_utc
        if expire_date.tzinfo is None:
            expire_date = expire_date.replace(tzinfo=timezone.utc)
        return expire_date.astimezone(timezone.utc)


    def issue(self, force: bool = False) -> None:
        raise CertException(self.id, "Static certificates cannot be issued; manage their files manually", status=CertStatus.NOT_SUPPORTED)


    def renew(self, force: bool = False) -> None:
        raise CertException(self.id, "Static certificates cannot be renewed; manage their files manually", status=CertStatus.NOT_SUPPORTED)


    def revoke(self) -> None:
        raise CertException(self.id, "Static certificates cannot be revoked; manage their files manually", status=CertStatus.NOT_SUPPORTED)


    def _load_cert(self) -> x509.Certificate:
        if not self.cert_file.exists():
            raise CertException(self.id, f"Certificate file not found: {self.cert_file.name}", status=CertStatus.CERT_MISSING)
        try:
            return x509.load_pem_x509_certificate(self.cert_file.read_bytes(), default_backend())
        except ValueError as e:
            raise CertException(self.id, f"Certificate file is not a valid PEM X.509 certificate: {e}", status=CertStatus.INVALID_CERT_FILE)
