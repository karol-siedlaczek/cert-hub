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

## Configuration
TODO
Application needs config file with defined certs and tokens, example:
```yaml
certs:
  - key: "example.com"
    email: "admin@example.com"
    domains: 
      - "*.example.com"
      - "example.com"
    plugin: "dns-route53"

tokens:
  - env: TOKEN_ADMIN
    allowed_ips:
      - 127.0.0.1/32
    permissions:
      - "*:health"
      - "*:read"
      - "*:renew"
      - "*:issue"
  - env: TOKEN_EXAMPLE
    allowed_ips:
      - "192.0.0.0/24"
    permissions:
      - "example.com:read"
      - "example.com:renew"
```

# Notes
before start gunicorn run:
```
gunicorn --check-config
```

Generate HMAC_KEY:
```bash
openssl rand -base64 32
```

# For testing 
```bash
Cjsiv2JsX3b0i3MDlI7DFg7FiIaw+/79/fzFYkKhnjU=
```
