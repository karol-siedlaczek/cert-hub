import os
from cert_hub.app import create_app
from cert_hub.validation.require import Require
from werkzeug.middleware.proxy_fix import ProxyFix

bind_ip = os.getenv("GUNICORN_BIND_IP")
if bind_ip:
    Require.ip_address("GUNICORN_BIND_IP", bind_ip)

bind_port = os.getenv("GUNICORN_BIND_PORT")
if bind_port:
    Require.port("GUNICORN_BIND_PORT", bind_port)

workers = os.getenv("GUNICORN_WORKERS")
if workers:
    Require.type("GUNICORN_WORKERS", workers, int)
    Require.min("GUNICORN_WORKERS", workers, 1)
    Require.min("GUNICORN_WORKERS", workers, 24)

threads = os.getenv("GUNICORN_THREADS")
if threads:
    Require.type("GUNICORN_THREADS", threads, int)
    Require.min("GUNICORN_THREADS", threads, 1)
    Require.min("GUNICORN_THREADS", threads, 24)
    
timeout = os.getenv("GUNICORN_TIMEOUT")
if timeout:
    Require.type("GUNICORN_TIMEOUT", timeout, int)
    Require.min("GUNICORN_TIMEOUT", timeout, 1)

app = create_app()
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
    x_port=1,
    x_prefix=1
)
