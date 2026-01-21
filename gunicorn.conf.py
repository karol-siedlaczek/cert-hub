import os

daemon = False
bind = f"{os.getenv("BIND_IP", "0.0.0.0")}:{os.getenv("BIND_PORT", "8080")}"
workers = int(os.getenv("WORKERS", "2"))
threads = int(os.getenv("THREADS", "1"))

# Logs
accesslog = "-" # Value '-' means log to stdout
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info").lower() # Valid options: debug, info, warning, error, critical
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
