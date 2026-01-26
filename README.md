# Cert registry

## Development
TODO

## Production
TODO

## Environments
| Key | Type | Required | Default | Description |
|:----|:-----|:---------|:--------|:------------|
| `GUNICORN_BIND_IP` | `string` | :x: | `0.0.0.0` | TODO |
| `GUNICORN_BIND_PORT` | `number` | :x: | `8080` | TODO |
| `GUNICORN_WORKERS` | `number` | :x: | `2` | TODO |
| `GUNICORN_THREADS` | `number` | :x: | `1` | TODO |
| `LOG_LEVEL` | `string` | :x: | `INFO` | TODO |
| `ACME_SERVER` | `string` | :x: | `https://acme-v02.api.letsencrypt.org/directory` | TODO |
| `CERTS_DIR` | `string` | :x: | `/certs` | TODO |
| `LOGS_DIR` | `string` | :x: | `/logs` | TODO |
| `CONF_FILE` | `string` | :x: | `/config/config.yaml` | TODO |
| `CERTBOT_BIN` | `string` | :x: | `/usr/bin/certbot` | TODO |
| `CERTBOT_LOCK_FILE` | `string` | :x: | `/locks/certbot.lock` | TODO |
| `AWS_ACCESS_KEY_ID` | `string` | :heavy_check_mark: | - | TODO |
| `AWS_SECRET_ACCESS_KEY` | `string` | :heavy_check_mark: | - | TODO |

# Notes
before start gunicorn run:
```
gunicorn --check-config
```
