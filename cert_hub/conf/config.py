import os
import shutil
import yaml
import base64
from flask import current_app as app, g
from pathlib import Path
from typing import ClassVar, Any, cast
from dataclasses import dataclass, field
from cert_hub.validation.require import Require
from cert_hub.domain.cert.cert import Cert
from cert_hub.domain.cert.letsencrypt_cert import LetsEncryptCert
from cert_hub.domain.cert.static_cert import StaticCert
from cert_hub.domain.identity import Identity
from cert_hub.exception.validator_exceptions import ValidationError

@dataclass(frozen=True)
class Config:
    REQUIRED_ENVS: ClassVar[set[str]] = {"HMAC_KEY_B64"}
    ALLOWED_LOG_LEVELS: ClassVar[set[str]] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    
    log_level: str = "INFO"
    logs_dir: Path = "/logs"
    conf_file: Path = "/config/config.yaml"
    certbot_acme_server: str = "https://acme-v02.api.letsencrypt.org/directory"
    certbot_bin: Path = None
    certbot_dir: Path = "/letsencrypt"
    certbot_renew_before_days: int = None
    certbot_test_cert: bool = False
    hmac_key: bytes = None 
    aws_access_key_id: str = None
    aws_secret_access_key: str = None
    cloudflare_dns_api_token: str = None
    static_certs_dir: Path = "/static-certs"
    trusted_proxy_hops: int = 0
    certs: list[Cert] = field(default_factory=list)
    identities: list[Identity] = field(default_factory=list)
    
    
    @classmethod
    def load(cls) -> "Config":
        Require.envs(cls.REQUIRED_ENVS)

        log_level = os.getenv("LOG_LEVEL", "INFO")
        Require.one_of("LOG_LEVEL", log_level, cls.ALLOWED_LOG_LEVELS)

        Require.base64("HMAC_KEY_B64", os.getenv("HMAC_KEY_B64"), 32)
        hmac_key = base64.b64decode(os.getenv("HMAC_KEY_B64"), validate=True)

        certbot_bin = os.getenv("CERTBOT_BIN")
        if certbot_bin is None:
            certbot_bin = shutil.which("certbot")
        certbot_bin = Path(certbot_bin) if certbot_bin is not None else None
        Require.file_exists("CERTBOT_BIN", certbot_bin)

        certbot_renew_before_days = int(os.getenv("CERTBOT_RENEW_BEFORE_DAYS", "30"))
        Require.type("CERTBOT_RENEW_BEFORE_DAYS", certbot_renew_before_days, int)
        Require.min("CERTBOT_RENEW_BEFORE_DAYS", certbot_renew_before_days, 1)
        Require.max("CERTBOT_RENEW_BEFORE_DAYS", certbot_renew_before_days, 60)

        certbot_test_cert = os.getenv("CERTBOT_TEST_CERT", "").strip().lower() in ("true", "1", "yes")

        aws_secret_access_key = cls._resolve_secret("AWS_SECRET_ACCESS_KEY")
        cloudflare_dns_api_token = cls._resolve_secret("CLOUDFLARE_DNS_API_TOKEN")

        conf_file = Path(os.getenv("CONF_FILE", "/config/config.yaml"))
        conf_path = Require.file_exists("CONF_FILE", conf_file)

        static_certs_dir = Path(os.getenv("STATIC_CERTS_DIR", "/static-certs"))

        trusted_proxy_hops = int(os.getenv("TRUSTED_PROXY_HOPS", "0"))
        Require.type("TRUSTED_PROXY_HOPS", trusted_proxy_hops, int)
        Require.min("TRUSTED_PROXY_HOPS", trusted_proxy_hops, 0)

        try:
            raw_conf = yaml.safe_load(conf_path.read_text(encoding="UTF-8")) or {}
        except yaml.YAMLError as e:
            raise ValidationError(f"Failed to parse '{conf_file}' config file as valid YAML file: {e}")

        try:
            seen_ids: set[str] = set()
            le_certs = cls._parse_letsencrypt_certs(raw_conf.get("letsencrypt_certs"), seen_ids)
            static_certs = cls._parse_static_certs(raw_conf.get("static_certs"), static_certs_dir, seen_ids)
            certs = [*le_certs, *static_certs]
            identities = cls._parse_identities(raw_conf.get("identities"))
        except ValidationError as e:
            raise ValidationError(f"Failed to parse '{conf_file}' config file: {e}")

        return cls(
            log_level=log_level,
            logs_dir=Path(os.getenv("LOGS_DIR", "/logs")),
            conf_file=conf_file,
            certbot_acme_server=os.getenv("CERTBOT_ACME_SERVER", "https://acme-v02.api.letsencrypt.org/directory"),
            certbot_bin=certbot_bin,
            certbot_dir=Path(os.getenv("CERTBOT_DIR", "/letsencrypt")),
            certbot_renew_before_days=certbot_renew_before_days,
            certbot_test_cert=certbot_test_cert,
            hmac_key=hmac_key,
            aws_access_key_id=cls._resolve_secret("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=aws_secret_access_key,
            cloudflare_dns_api_token=cloudflare_dns_api_token,
            static_certs_dir=static_certs_dir,
            trusted_proxy_hops=trusted_proxy_hops,
            certs=certs,
            identities=identities
        )


    @staticmethod
    def _resolve_secret(name: str) -> str | None:
        file_var = f"{name}__FILE"
        if os.getenv(file_var):
            path = Require.file_exists(file_var, os.getenv(file_var))
            return path.read_text(encoding="UTF-8").rstrip("\n")
        return os.getenv(name)


    @staticmethod
    def _parse_letsencrypt_certs(certs_raw: Any, seen_ids: set[str]) -> list[LetsEncryptCert]:
        if certs_raw is None:
            return []

        Require.type("letsencrypt_certs", certs_raw, list)
        certs: list[LetsEncryptCert] = []

        for i, item in enumerate(certs_raw):
            Require.type(f"letsencrypt_certs[{i}]", item, dict)
            Require.not_one_of(f"letsencrypt_certs[{i}].id", item.get("id"), list(seen_ids))
            try:
                cert = LetsEncryptCert.from_dict(item)
            except ValidationError as e:
                raise ValidationError(f"Error found at letsencrypt_certs[{i}]: {e}")
            seen_ids.add(cert.id)
            certs.append(cert)

        return certs


    @staticmethod
    def _parse_static_certs(certs_raw: Any, static_certs_dir: Path, seen_ids: set[str]) -> list[StaticCert]:
        if certs_raw is None:
            return []

        Require.type("static_certs", certs_raw, list)
        certs: list[StaticCert] = []

        for i, item in enumerate(certs_raw):
            Require.type(f"static_certs[{i}]", item, dict)
            Require.not_one_of(f"static_certs[{i}].id", item.get("id"), list(seen_ids))
            try:
                cert = StaticCert.from_dict(item, static_certs_dir)
            except ValidationError as e:
                raise ValidationError(f"Error found at static_certs[{i}]: {e}")
            seen_ids.add(cert.id)
            certs.append(cert)

        return certs
    
    
    @staticmethod
    def _parse_identities(identities_raw: Any) -> list[Identity]:
        if identities_raw is None:
            return []
        
        Require.type("identities", identities_raw, list)
        identities: list[Identity] = []
        
        for i, item in enumerate(identities_raw):
            Require.type(f"identities[{i}]", item, dict)
            Require.not_one_of(f"identities[{i}].id", item.get("id"), [x.id for x in identities])
            try:
                identities.append(Identity.from_dict(item))
            except ValidationError as e:
                raise ValidationError(f"Error found at identities[{i}]: {e}")
        
        return identities


    @staticmethod
    def get_from_global_context() -> "Config":
        if "conf" not in g:
            g.conf = cast(Config, app.extensions["config"])
        return g.conf

