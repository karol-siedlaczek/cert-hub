import os
import yaml
from .require import Require
from .cert import CertEntry
from .token import Token
from typing import Optional, ClassVar, Dict, Any
from dataclasses import dataclass, fields, field

class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    REQUIRED_ENVS: ClassVar[set[str]] = { "aws_access_key_id", "aws_secret_access_key" }
    ALLOWED_LOG_LEVELS: ClassVar[set[str]] = { "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL" }
    
    log_level: str = "INFO"
    acme_server: str = "https://acme-v02.api.letsencrypt.org/directory"
    certs_dir: str = "/certs"
    logs_dir: str = "/logs"
    conf_file: str = "/config/config.yaml"
    certbot_bin: str = "/usr/bin/certbot"
    certbot_lock_file: str = "/locks/certbot.lock"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    certs: list[CertEntry] = field(default_factory=list)
    tokens: list[Token] = field(default_factory=list)
    
    @classmethod
    def load(cls) -> "Config":
        params: Dict[str, Any] = {}
        skip_env_params = { "certs", "tokens" }
        
        # Load envs
        for f in fields(cls):
            if f.name in skip_env_params:
                continue
            
            val = os.getenv(f.name.upper())
            if val is None:
                val = f.default
            params[f.name] = val
        
        log_level = str(params.get("log_level", "INFO")).strip().upper()
        if log_level not in cls.ALLOWED_LOG_LEVELS:
            raise ConfigError(f"Invalid LOG_LEVEL={log_level}, allowed choices: {', '.join(cls.ALLOWED_LOG_LEVELS)}")
        params["log_level"] = log_level
        
        missing_envs = [env for env in cls.REQUIRED_ENVS if not params.get(env)]
        if missing_envs:
            raise ConfigError(f"Missing required environment variables: {', '.join(env.upper() for env in missing_envs)}")
        
        try:
            conf_file = Require.file_exists(None, params["conf_file"])
        except ValueError:
            raise ConfigError(f"Config file not found: {params['conf_file']}")
        
        # Load YAML config
        try:
            raw_conf = yaml.safe_load(conf_file.read_text(encoding="UTF-8")) or {}
        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML in {conf_file}: {e}")
        
        try:
            certs = cls._parse_certs(raw_conf.get("certs"))
            tokens = cls._parse_tokens(raw_conf.get("tokens"))
        except ValueError as e:
            raise ConfigError(f"Failed to parse '{conf_file}' config file: {e}")
        
        params["certs"] = certs
        params["tokens"] = tokens
        
        return cls(**params)

    @staticmethod
    def _parse_certs(certs_raw: Any) -> list[CertEntry]:
        if certs_raw is None:
            return []
        Require.type("certs", certs_raw, list)
        
        certs: list[CertEntry] = []
        for i, item in enumerate(certs_raw):
            Require.type(f"certs[{i}]", item, dict)
            Require.not_one_of(f"certs[{i}].key", item.get("key"), certs)
            try:
                certs.append(CertEntry.from_dict(item))
            except ValueError as e:
                raise ValueError(f"Error found at certs[{i}]: {e}")
        
        return certs
    
    @staticmethod
    def _parse_tokens(tokens_raw: Any) -> list[Token]:
        if tokens_raw is None:
            return []
        Require.type("tokens", tokens_raw, list)

        tokens: list[Token] = []
        for i, item in enumerate(tokens_raw):
            Require.type(f"tokens[{i}]", item, dict)
            try:
                tokens.append(Token.from_dict(item))
            except ValueError as e:
                raise ValueError(f"Error found at tokens[{i}]: {e}")
        
        return tokens
