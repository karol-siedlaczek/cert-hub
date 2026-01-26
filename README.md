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

## Environments
| Key | Type | Required | Default | Description |
|:----|:-----|:---------|:--------|:------------|
| `GUNICORN_BIND_IP` | `str` | :x: | `0.0.0.0` | TODO |
| `GUNICORN_BIND_PORT` | `int` | :x: | `8080` | TODO |
| `GUNICORN_WORKERS` | `int` | :x: | `2` | TODO |
| `GUNICORN_THREADS` | `int` | :x: | `1` | TODO |
| `LOG_LEVEL` | `str` | :x: | `INFO` | TODO |
| `ACME_SERVER` | `str` | :x: | `https://acme-v02.api.letsencrypt.org/directory` | TODO |
| `CERTS_DIR` | `str` | :x: | `/certs` | TODO |
| `LOGS_DIR` | `str` | :x: | `/logs` | TODO |
| `CONF_FILE` | `str` | :x: | `/config/config.yaml` | TODO |
| `CERTBOT_BIN` | `str` | :x: | `/usr/bin/certbot` | TODO |
| `CERTBOT_LOCK_FILE` | `str` | :x: | `/locks/certbot.lock` | TODO |
| `AWS_ACCESS_KEY_ID` | `str` | :heavy_check_mark: | - | TODO |
| `AWS_SECRET_ACCESS_KEY` | `str` | :heavy_check_mark: | - | TODO |
