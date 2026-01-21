import logging
from pathlib import Path
from flask import Flask
from dataclasses import asdict
from .config import Config
from .routes import api as api_blueprint

def create_app(config: Config | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(asdict(config))
        
    setup_logging(app)
    app.register_blueprint(api_blueprint)
    
    return app


def setup_logging(app: Flask) -> None:
    Path("logs").mkdir(parents=True, exist_ok=True)
    
    level_name = (app.config.get("LOG_LEVEL") or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    log_path = str(Path("logs") / "app.log")
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [pid=%(process)d] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    
    root = logging.getLogger()
    root.setLevel(level)
    
    if not any(isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", "") == log_path for h in root.handlers):
        f_handler = logging.FileHandler(log_path)
        f_handler.setFormatter(formatter)
        f_handler.setLevel(level)
        root.addHandler(f_handler)

    logging.getLogger(__name__).info("Logging initialized (level=%s)", level_name)
