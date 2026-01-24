import os
import re
import yaml
import ipaddress
from pathlib import Path
from typing import Optional, ClassVar, Tuple, Dict, Any, List
from dataclasses import dataclass, field, fields

class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class CertConfig:
    key: str
    email: str
    domains: list[str]
    plugin: str
    
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CertConfig":
        pass
  

@dataclass(frozen=True)
class TokenPermissionConfig:
    scope: str
    action: str    
    
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TokenPermissionConfig":
        pass

    
@dataclass(frozen=True)
class TokenConfig:
    env_ref: str
    value: str
    allowed_ips: list[str]
    permissions: list[TokenPermissionConfig]
    
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TokenConfig":
        pass
  

@dataclass(frozen=True)
class Config:
    LOG_LEVEL: str = "INFO"
    ACME_SERVER: str = "https://acme-v02.api.letsencrypt.org/directory"
    CERTS_DIR: str = "/certs"
    LOGS_DIR: str = "/logs"
    CONFIG_FILE: str = "/config/config.yaml"
    CERTBOT_BIN: str = "/usr/bin/certbot"
    CERTBOT_LOCK_FILE: str = "/locks/certbot.lock"
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    
    CERTS: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # CERTS: Tuple[CertConfig, ...] = ()
    TOKENS: List[Dict[str, Any]] = field(default_factory=List)
    
    REQUIRED_ENVS: ClassVar[Tuple[str, ...]] = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
    ALLOWED_LOG_LEVELS: ClassVar[Tuple[str, ...]] = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
    
    
    @classmethod
    def load(cls) -> "Config":
        params: Dict[str, Any] = {}
        skip_env_params = {"CERTS", "TOKENS"}
        
        # Load envs
        for f in fields(cls):
            if f.name in skip_env_params:
                continue
            
            val = os.getenv(f.name)
            if val is None:
                val = f.default
            params[f.name] = val
        
        log_level = str(params.get("LOG_LEVEL", "INFO")).strip().upper()
        if log_level not in cls.ALLOWED_LOG_LEVELS:
            raise ConfigError(f"Invalid LOG_LEVEL={log_level}, allowed choices: {', '.join(cls.ALLOWED_LOG_LEVELS)}")
        params["LOG_LEVEL"] = log_level
        
        missing_envs = [name for name in cls.REQUIRED_ENVS if not params.get(name)]
        if missing_envs:
            raise ConfigError(f"Missing required environment variables: {(', ').join(missing_envs)}")
        
        conf_file = Path(params["CONFIG_FILE"])
        if not conf_file.exists():
            raise ConfigError(f"Config file not found: {conf_file}")
        
        # Load YAML config
        try:
            raw_conf = yaml.safe_load(conf_file.read_text(encoding="UTF-8")) or {}
        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML in {conf_file}: {e}")
        
        try:
            certs = cls._parse_certs(raw_conf.get("certs"))
            tokens = cls._parse_tokens(raw_conf.get("tokens"), certs)
        except ConfigError as e:
            raise ConfigError(f"Failed to parse '{conf_file}' config file: {e}")
        
        params["CERTS"] = certs
        params["TOKENS"] = tokens
        print(params) # TODO - For testing
        
        return cls(**params)

    
    @staticmethod
    def _parse_certs(certs_raw: Any) -> Dict[str, Dict[str, Any]]:
        if certs_raw is None:
            return {}
        elif not isinstance(certs_raw, list):
            raise ConfigError("param 'certs' must be a list")
        
        certs: Dict[str, Dict[str, Any]] = {}
        for item in certs_raw:
            if not isinstance(item, dict):
                raise ConfigError("each item defined under 'certs' param must be a dict")
            
            key = item.get("key")
            email = item.get("email")
            domains = item.get("domains")
            plugin = item.get("plugin")
            
            if not key or not isinstance(key, str):
                raise ConfigError(f"certs[].key is required and must be a string")
            elif key in certs:
                raise ConfigError(f"found duplicate for '{key}' cert, param 'key' needs to unique for all certs")
            elif not email or not isinstance(email, str):
                raise ConfigError(f"param 'email' is missing for '{key}' cert")
            elif not plugin or not isinstance(plugin, str): # TODO - Add validation for choices
                raise ConfigError(f"param 'plugin' is missing for '{key}' cert")
            elif not isinstance(domains, list) or not all(isinstance(d, str) for d in domains):
                raise ConfigError(f"param 'domains' is invalid for '{key}' cert, value must be a list of strings")
            
            certs[key] = { # TODO - Change to object
                "email": email,
                "domains": domains,
                "plugin": plugin,
            }
        
        return certs
    
    
    @staticmethod
    def _parse_tokens(tokens_raw: Any, certs: Dict[str, Dict[str, Any]]) -> None:
        if tokens_raw is None:
            return []
        elif not isinstance(tokens_raw, list):
            raise ConfigError("param 'tokens' must be a list")
        
        cert_keys = set(certs.keys())
        cert_keys_escaped = [re.escape(k) for k in cert_keys]
        permission_regex = re.compile(rf'^(\*|{"|".join(cert_keys_escaped)}):(\*|read|issue|renew)$')
        tokens: List[Dict[str, Any]] = []
        
        for item in tokens_raw:
            if not isinstance(item, dict):
                raise ConfigError("each item defined under 'tokens' param must be a dict")
            
            env_ref = item.get("env_ref")
            allowed_ips = item.get("allowed_ips", [])
            permissions = item.get("permissions", [])
            
            if not env_ref or not isinstance(env_ref, str):
                raise ConfigError("tokens[].env_ref is required and must be a string")
            
            token_value = os.getenv(env_ref)
            if not token_value:
                raise ConfigError(f"environment '{env_ref}' is missing, cannot resolve token value")
            
            if not isinstance(allowed_ips, list) or not all(isinstance(i, str) for i in allowed_ips):
                raise ConfigError(f"param 'allowed_ips' for '{env_ref}' token must be a list of strings")
            
            for cidr in allowed_ips:
                try:
                    ipaddress.ip_network(cidr, strict=False)
                except ValueError as e:
                    raise ConfigError(f"invalid '{cidr}' CIDR for '{env_ref}' token, details: {e}")
            
            if not isinstance(permissions, list) or not all(isinstance(p, str) for p in permissions):
                raise ConfigError(f"param 'permissions' for '{env_ref}' token must be a list of string")
            
            parsed_permissions = []
            for permission in permissions:
                if not isinstance(permission, str):
                    raise ConfigError(f"each item defined under 'permissions' param must be a string, entry '{permission}' for '{env_ref}' token is invalid")
                
                permission = permission.strip()
                matched = permission_regex.match(permission)
                
                if not matched:
                    raise ConfigError(f"permission entry '{permission}' is invalid for '{env_ref}' token, value needs to be provided in following format: '(*|<cert_key>):(*|read|issue|renew)'")
                
                cert_key, action = matched.groups()
                parsed_permissions.append((cert_key, action))
            
            tokens.append({ # TODO - Change to object
                "env_ref": env_ref,
                "value": token_value,
                "allowed_ips": allowed_ips,
                "permissions": parsed_permissions
            })
        
        return tokens
