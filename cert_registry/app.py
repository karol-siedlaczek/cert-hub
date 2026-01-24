import logging
from pathlib import Path
from flask import Flask
from dataclasses import asdict
from .config import Config
from .routes import api as api_blueprint

def create_app(config: Config | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(asdict(config))
        
    setup_paths(app)
    setup_logging(app)
    app.register_blueprint(api_blueprint)
    
    return app


def setup_paths(app: Flask) -> None:
    dir_params = ["LOGS_DIR", "CERTS_DIR"]
    file_params = ["CONFIG_FILE", "CERTBOT_LOCK_FILE"]
    
    for param in dir_params:
        value = app.config.get(param)
        if not value:
            continue
        Path(value).expanduser().mkdir(parents=True, exist_ok=True)

    for param in file_params:
        value = app.config.get(param)
        if not value:
            continue
        Path(value).expanduser().parent.mkdir(parents=True, exist_ok=True)


def setup_logging(app: Flask) -> None:    
    level_name = (app.config.get("LOG_LEVEL") or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    log_file = f"{app.config.get("LOGS_DIR")}/app.log"
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [pid=%(process)d] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    
    root = logging.getLogger()
    root.setLevel(level)
    
    if not any(isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", "") == log_file for h in root.handlers):
        f_handler = logging.FileHandler(log_file)
        f_handler.setFormatter(formatter)
        f_handler.setLevel(level)
        root.addHandler(f_handler)

    logging.getLogger(__name__).info("Logging initialized (level=%s)", level_name)
