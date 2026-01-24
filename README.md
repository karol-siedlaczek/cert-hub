# cert-registry

before start gunicorn run:
```
gunicorn --check-config
```



# @api.route("/certs/<domain>")
# def certs(domain: str) -> Response:
#     cert_path = Path(app.config["CERTS_DIR"], domain)
    
#     if not cert_path.exists():
#         abort(404, "Certificate not found")

global_envs:
* LOG_LEVEL (INFO)

gunicron envs:
* GUNICORN_BIND_IP (0.0.0.0)
* GUNICORN_BIND_PORT (8080)
* GUNICORN_WORKERS (2)
* GUNICORN_THREADS (1)

app envs:
* AWS_ACCESS_KEY_ID (required)
* AWS_SECRET_ACCESS_KEY (required)
* ACME_SERVER (https://acme-v02.api.letsencrypt.org/directory)
