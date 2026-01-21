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
