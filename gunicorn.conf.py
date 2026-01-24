import os

daemon = False
bind = f"{os.getenv("GUNICORN_BIND_IP", "0.0.0.0")}:{os.getenv("GUNICORN_BIND_PORT", "8080")}"
workers = int(os.getenv("GUNICORN_WORKERS", "1"))
threads = int(os.getenv("GUNICORN_THREADS", "1"))

# Logs
accesslog = "-" # Value '-' means log to stdout
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info").lower()
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
