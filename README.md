# Cert Hub

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
| `LOGS_DIR` | `string` | :x: | `/logs` | TODO |
| `CONF_FILE` | `string` | :x: | `/config/config.yaml` | TODO |
| `CERTBOT_ACME_SERVER` | `string` | :x: | `https://acme-v02.api.letsencrypt.org/directory` | TODO |
| `CERTBOT_BIN` | `string` | :x: | `/usr/bin/certbot` | TODO |
| `CERTBOT_DIR` | `string` | :x: | `/letsencrypt` | TODO |
| `CERTBOT_RENEW_BEFORE_DAYS` | `number` | :x: | `30` | TODO |
| `HMAC_KEY_B64` | `string` | :heavy_check_mark: | - | TODO |
| `AWS_ACCESS_KEY_ID` | `string` | :x: | - | Required only if `aws` DNS provider is used |
| `AWS_SECRET_ACCESS_KEY` | `string` | :x: | - | Required only if `aws` DNS provider is used |

## Configuration
TODO
Application needs config file with defined certs and tokens, example:
```yaml
certs:
  - id: "example.com"
    email: "admin@example.com"
    pem_filename: "*.example.com"
    domains: 
      - "*.example.com"
      - "example.com"
    dns_provider: "aws"

identities:
  - id: "admin"
    allowed_ips:
      - "127.0.0.1/32"
    permissions:
      - "*:health"
      - "*:read"
      - "*:renew"
      - "*:issue"
  - id: "example"
    allowed_ips:
      - "192.0.0.0/24"
    permissions:
      - "example.com:read"
      - "example.com:renew"
```

Above config requires to provide 2 more environments with encrypted tokens for provided identities:
```ini
TOKEN_ADMIN_HMAC="value"
TOKEN_EXAMPLE_HMAC="value"
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
