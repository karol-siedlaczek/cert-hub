import logging
from pathlib import Path
from flask import Flask, Response
from cert_registry.conf.config import Config
from cert_registry.api.routes import api as api_blueprint
from cert_registry.api.helpers import build_response, log_request

def create_app() -> Flask:
    app = Flask(__name__)
    config = Config.load()
    print(config) # TODO - For testing
    app.extensions["config"] = config
        
    setup_paths(config)
    setup_logging(config)
    setup_error_handlers(app)
    app.register_blueprint(api_blueprint)
    
    return app


def setup_paths(config: Config) -> None:
    dir_params = ["logs_dir", "certs_dir"]
    file_params = ["conf_file", "certbot_lock_file"]
    
    for param in dir_params:
        value = getattr(config, param)
        if not value:
            continue
        Path(value).expanduser().mkdir(parents=True, exist_ok=True)

    for param in file_params:
        value = getattr(config, param)
        if not value:
            continue
        Path(value).expanduser().parent.mkdir(parents=True, exist_ok=True)


def setup_logging(config: Config) -> None:    
    level_name = (config.log_level or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    log_file = f"{config.logs_dir}/app.log"
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


def setup_error_handlers(app: Flask) -> None:
    @app.errorhandler(404)
    def handle_not_found(error) -> Response:
        log_request(error, "warning")
        return build_response(404, msg="Resource not found")
    
    @app.errorhandler(500)
    def handle_internal_server_error(error) -> Response:
        log_request(error, "error")
        return build_response(500, msg="Internal server error")
