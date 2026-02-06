import logging
import subprocess
from pathlib import Path
from flask import Flask, Response
from werkzeug.exceptions import MethodNotAllowed, NotFound
from cert_registry.errors.auth_error import AuthError, AuthFailedError
from cert_registry.errors.api_error import ApiError
from cert_registry.conf.config import Config
from cert_registry.api.routes import api as api_blueprint
from cert_registry.api.helpers import build_response, log_request

def create_app() -> Flask:
    app = Flask(__name__)
    config = Config.load()
    app.extensions["config"] = config
    
    print(config)
        
    setup_paths(config)
    setup_logging(config)
    setup_error_handlers(app)
    app.register_blueprint(api_blueprint)
    
    return app


def setup_paths(config: Config) -> None:
    dir_params = ["logs_dir", "certbot_work_dir", "certbot_logs_dir", "certbot_conf_dir", "certbot_lock_dir"]
    file_params = ["conf_file"]
    
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
    def handle_not_found(e: NotFound) -> Response:
        log_request(e, "warning")
        return build_response(404, msg="Resource not found")
    
    @app.errorhandler(405)
    def handle_method_not_allowed(e: MethodNotAllowed) -> Response:
        log_request(e, "warning")
        return build_response(405, msg=f"Method not allowed, valid methods are: {', '.join(e.valid_methods)}")
    
    # @app.errorhandler(Exception)
    # def handle_any_exception(e) -> Response:
    #     log_request(f"Unhandled exception: {e}", "error")
    #     return build_response(500, msg="Internal server error")
    
    @app.errorhandler(500)
    def handle_any_exception(e) -> Response:
        log_request(f"Unhandled exception: {e}", "error")
        return build_response(500, msg="Internal server error")
    
    @app.errorhandler(ApiError)
    def handle_api_error(e: ApiError) -> Response:
        log_request(f"{type(e).__name__}: {e.msg}{f", details: {e.detail}" if e.detail else ""}", "warning")
        return build_response(e.code, msg=e.msg, detail=e.detail)

    
    @app.errorhandler(AuthError)
    def handle_auth_error(e: AuthError) -> Response:
        log_request(f"{type(e).__name__}: {e.msg}, details: {e.detail}", "warning")
        return build_response(e.code, msg=e.msg, detail=None if isinstance(e, AuthFailedError) else e.detail)

    @app.errorhandler(subprocess.CalledProcessError)
    def handle_called_process_error(e: subprocess.CalledProcessError) -> Response:
        detail = {
            "error": type(e).__name__,
            "exit_code": e.returncode,
            "cmd": e.cmd,
            "stdout": getattr(e, "output", ""),
            "stderr": getattr(e, "stderr", "")
        }
        log_request(f"Failed to execute command: {detail}")
        return build_response(502, msg="Command execution failed", detail=detail)
