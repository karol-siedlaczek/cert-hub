import os
from typing import Optional, ClassVar, Tuple
from dataclasses import dataclass, fields

class ConfigError(RuntimeError):
    pass

@dataclass(frozen = True)
class Config:
    LOG_LEVEL: str = "INFO"
    ACME_SERVER: str = "https://acme-v02.api.letsencrypt.org/directory"
    CERTS_DIR: str = "/certs"
    CERTBOT_BIN: str = "/usr/bin/certbot"
    CERTBOT_JOBS_DIR: str = "/jobs"
    CERTBOT_LOCK_FILE: str = "/var/lock/certbot.lock"
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    
    REQUIRED_ENVS: ClassVar[Tuple[str, ...]] = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
    ALLOWED_LOG_LEVELS: ClassVar[Tuple[str, ...]] = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
    
    @classmethod
    def load_from_env(cls) -> "Config":
        kwargs = {}
        
        for f in fields(cls):
            val = os.getenv(f.name)
            
            if val is None:
                val = f.default
            kwargs[f.name] = val
        
        log_level = str(kwargs.get("LOG_LEVEL", "INFO")).strip().upper()
        if log_level not in cls.ALLOWED_LOG_LEVELS:
            raise ConfigError(f"Invalid LOG_LEVEL={log_level}, allowed choices: {(', ').join(cls.ALLOWED_LOG_LEVELS)}")
        kwargs["LOG_LEVEL"] = log_level
        
        conf = cls(**kwargs)
        
        missing_envs = [name for name in cls.REQUIRED_ENVS if not getattr(conf, name)]
        if missing_envs:
            raise ConfigError(f"Missing required environment variables: {(', ').join(missing_envs)}")
        
        return conf
