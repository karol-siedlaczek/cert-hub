import os
import yaml
import base64
from typing import ClassVar, Dict, Any
from dataclasses import dataclass, fields, field
from .require import Require
from .cert import Cert
from .identity import Identity
from .error import ConfigError

@dataclass(frozen=True)
class Config:
    REQUIRED_ENVS: ClassVar[set[str]] = { "HMAC_KEY_B64", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY" }
    ALLOWED_LOG_LEVELS: ClassVar[set[str]] = { "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL" }
    
    log_level: str = "INFO"
    acme_server: str = "https://acme-v02.api.letsencrypt.org/directory"
    certs_dir: str = "/certs"
    logs_dir: str = "/logs"
    conf_file: str = "/config/config.yaml"
    certbot_bin: str = "/usr/bin/certbot"
    certbot_lock_file: str = "/locks/certbot.lock"
    hmac_key: bytes = None 
    aws_access_key_id: str = None
    aws_secret_access_key: str = None
    certs: list[Cert] = field(default_factory=list)
    identities: list[Identity] = field(default_factory=list)
    
    @classmethod
    def load(cls) -> "Config":
        params: Dict[str, Any] = {}
        skip_fields = ["certs", "identities"]
        
        # Load environments
        for f in fields(cls):
            if f.name in skip_fields:
                continue
            
            val = os.getenv(f.name.upper())
            if val is None:
                val = f.default
            params[f.name] = val

        Require.envs(cls.REQUIRED_ENVS)
        Require.one_of("LOG_LEVEL", params["log_level"], cls.ALLOWED_LOG_LEVELS)
        Require.base64("HMAC_KEY_B64", os.getenv("HMAC_KEY_B64"), 32)
        conf_file = Require.file_exists("CONF_FILE", params["conf_file"])
        params["hmac_key"] = base64.b64decode(os.getenv("HMAC_KEY_B64"), validate=True)
        
        try:
            raw_conf = yaml.safe_load(conf_file.read_text(encoding="UTF-8")) or {}
        except yaml.YAMLError as e:
            raise ConfigError(f"Failed to parse '{conf_file}' config file as valid YAML file: {e}")
        
        try:
            params["certs"] = cls._parse_certs(raw_conf.get("certs"))
            params["identities"] = cls._parse_identities(raw_conf.get("identities"))
        except Exception as e:
            raise ConfigError(f"Failed to parse '{conf_file}' config file: {e}")
        
        return cls(**params)

    @staticmethod
    def _parse_certs(certs_raw: Any) -> list[Cert]:
        if certs_raw is None:
            return []
        
        Require.type("certs", certs_raw, list)
        certs: list[Cert] = []
        
        for i, item in enumerate(certs_raw):
            Require.type(f"certs[{i}]", item, dict)
            Require.not_one_of(f"certs[{i}].id", item.get("id"), [c.id for c in certs])
            try:
                certs.append(Cert.from_dict(item))
            except Exception as e:
                raise ConfigError(f"Error found at certs[{i}]: {e}")
        
        return certs
    
    @staticmethod
    def _parse_identities(identities_raw: Any) -> list[Identity]:
        if identities_raw is None:
            return []
        
        Require.type("identities", identities_raw, list)
        identities: list[Identity] = []
        
        for i, item in enumerate(identities_raw):
            Require.type(f"identities[{i}]", item, dict)
            Require.not_one_of(f"identities[{i}].id", item.get("id"), [i.id for i in identities])
            try:
                identities.append(Identity.from_dict(item))
            except Exception as e:
                raise ConfigError(f"Error found at identities[{i}]: {e}")
        
        return identities
