# Cert Hub

## Development
### 1) Requirements
- Python `3.12+`
- Installed `certbot` (by default the app expects `/usr/bin/certbot`)

### 2) Install dependencies
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3) Environment configuration
Minimal setup:
```bash
export HMAC_KEY_B64="<HMAC_KEY>" # Generate key using: openssl rand -base64 32
```

For local development it is also recommended to change environments that points to files or directories, because default values are predefined for docker container, e. g.:
```bash
export CONF_FILE="$(pwd)/config.yaml"
export CERTBOT_DIR="$(pwd)/letsencrypt"
export LOGS_DIR="$(pwd)/logs"
```

### 4) Start the application
```bash
gunicorn wsgi:app
```

Quick test:
```bash
curl -s http://127.0.0.1:8080/ping
```

## Production
### Docker (`docker run`)
Build image:
```bash
docker build -t cert-hub:latest .
```

Run container:
```bash
docker run -d \
  --name cert-hub \
  -p 8080:8080 \
  -e HMAC_KEY_B64="<HMAC_KEY>" \
  -e CONF_FILE="/config/config.yaml" \
  -e LOGS_DIR="/logs" \
  -e CERTBOT_DIR="/letsencrypt" \
  -e CERTBOT_BIN="/usr/local/bin/certbot" \
  -v "$(pwd)/config.yaml:/config/config.yaml:ro" \
  -v "$(pwd)/logs:/logs" \
  -v "$(pwd)/letsencrypt:/letsencrypt" \
  cert-hub:latest
```

Stop and remove:
```bash
docker stop cert-hub && docker rm cert-hub
```

### Docker Compose
Set required environment:
```bash
export HMAC_KEY_B64="<HMAC_KEY>"
```

Build and start:
```bash
docker compose up -d --build
```

Check logs:
```bash
docker compose logs -f cert-hub
```

Stop:
```bash
docker compose down
```



## Environments
| Key | Type | Required | Default | Description |
|:----|:-----|:---------|:--------|:------------|
| `GUNICORN_BIND_IP` | `string` | :x: | `0.0.0.0` | Gunicorn bind IP |
| `GUNICORN_BIND_PORT` | `number` | :x: | `8080` | Gunicorn bind port |
| `GUNICORN_WORKERS` | `number` | :x: | `1` | Number of Gunicorn workers |
| `GUNICORN_THREADS` | `number` | :x: | `1` | Threads per Gunicorn worker |
| `GUNICORN_TIMEOUT` | `number` | :x: | `600` | Request timeout in seconds, it is recommended to keep minimum at least 360 for certificate issue and renew operations |
| `LOG_LEVEL` | `string` | :x: | `INFO` | Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |
| `LOGS_DIR` | `string` | :x: | `/logs` | Application logs directory (`app.log`) |
| `CONF_FILE` | `string` | :x: | `/config/config.yaml` | Path to YAML config with certificates and identities |
| `CERTBOT_ACME_SERVER` | `string` | :x: | `https://acme-v02.api.letsencrypt.org/directory` | Certbot ACME endpoint |
| `CERTBOT_BIN` | `string` | :x: | `/usr/bin/certbot` | Path to `certbot` executable binary |
| `CERTBOT_DIR` | `string` | :x: | `/letsencrypt` | Certbot working directory |
| `AWS_ACCESS_KEY_ID` | `string` | :x: | - | Access key ID to access Amazon Route 53. Required only if `aws` DNS provider is used in certificate configuration |
| `AWS_SECRET_ACCESS_KEY` | `string` | :x: | - | Secret access key to access Amazon Route 53. Required only if `aws` DNS provider is used in certificate configuration |
| `CERTBOT_RENEW_BEFORE_DAYS` | `number` | :x: | `30` | Days before expiration when a cert becomes renewable (1-60) |
| `HMAC_KEY_B64` | `string` | :heavy_check_mark: | - | Base64 HMAC key (minimum 32 bytes after decoding), used to verify tokens. Changing this value requires regenerate all identity passwords! |
| `TOKEN_<ID>_HMAC` | `string` | :x: | - | Token HMAC-SHA256 (hex) for identity `<ID>` from `config.yaml`. Theoretically not required to start the application, but it is nice to have at least one identity  |

## Configuration
`CONF_FILE` is a YAML file defining certificates (`certs`) and identities (`identities`).

Example:
```yaml
certs:
  - id: "example"
    email: "admin@example.com"
    domains: 
      - "*.example.com"
      - "example.com"
    dns_provider: "aws"
    custom_attrs: # Custom attributes returned by API, can be used by CLI
      pem_filename: "*.example.com"
      custom_key: custom_value

identities:
  - id: "admin"
    allowed_cidrs:
      - "127.0.0.1/32"
    permissions:
      - "*:health"
      - "*:read"
      - "*:renew"
      - "*:issue"
  - id: "example"
    allowed_cidrs:
      - "192.0.0.0/24"
    permissions:
      - "example.com:read"
      - "example.com:renew"
```

### Field meanings

- `certs[].id` - unique certificate identifier.
- `certs[].domains` - domain list passed to certbot.
- `certs[].dns_provider` - currently supported value is `aws`.
- `certs[].custom_attrs` - custom metadata returned by API (for example PEM filename for CLI workflows).
- `identities[].id` - identity identifier used in token format `Bearer <id>.<token>`.
- `identities[].allowed_cidrs` - CIDR list allowed to make requests for this identity.
- `identities[].permissions` - permission entries in `"<scope>:<action>"` format, where:
  - `scope` - `*`, full `cert id`, or regex matched against `cert id`.
  - `action` - `health`, `read`, `issue`, `renew`, or `*`.

If you have identities such as `admin` and `example`, you must provide following environments:
```ini
TOKEN_ADMIN_HMAC="<hex_hmac>"
TOKEN_EXAMPLE_HMAC="<hex_hmac>"
```

### How to generate `HMAC_KEY_B64`
```bash
openssl rand -base64 32
```

### How to generate `TOKEN_<ID>_HMAC`
Use the built-in CLI command:
```bash
# Variables can be provided by flags (use --help to show) or by prompt if any required variable is missing
./certhub token gen-hmac --id admin
```

CLI will print a ready-to-use value:
```ini
TOKEN_ADMIN_HMAC=<hex_hmac>
```

## API
Required authorization header:
```http
Authorization: Bearer <identity_id>.<token_raw>
```

Endpoints:
| Method | Endpoint | Auth required | Query params |
|:-------|:---------|:--------------|:-------------|
| `GET` | `/ping` | :x: | - |
| `GET` | `/api/version` | :x: | - |
| `GET` | `/api/certs/health` | :heavy_check_mark: | `match` (0..n), `exclude_ok` (bool, default: `false`) |
| `POST` | `/api/certs/issue` | :heavy_check_mark: | `match` (0..n), `force` (bool, default: `false`) |
| `POST` | `/api/certs/renew` | :heavy_check_mark: | `match` (0..n), `force` (bool, default: `false`) |
| `GET` | `/api/certs` | :heavy_check_mark: | `match` (0..n) |
| `GET` | `/api/token/scope` | :heavy_check_mark: | - |
| `GET` | `/api/token/identity` | :heavy_check_mark: | - |

Query params:
- `match`:
  - repeatable param (for example `?match=cert-a&match=cert-b`)
  - accepted values: `*`, exact cert ID, or regex pattern (full match against cert ID)
  - default: `*` (all allowed certificates)
- `exclude_ok` (`/api/certs/health`): bool, default `false`
- `force` (`/api/certs/issue`, `/api/certs/renew`): bool, default `false`
- accepted bool values:
  - true: `1`, `true`, `True`, `yes`, `Yes`, or empty value (for example `?force=`)
  - false: `0`, `false`, `False`, `no`, `No`

Examples:
```bash
curl -s \
  -H "Authorization: Bearer admin.my-raw-token" \
  "http://127.0.0.1:8080/api/certs/health?match=*&exclude_ok=true"

curl -s \
  -X POST \
  -H "Authorization: Bearer admin.my-raw-token" \
  "http://127.0.0.1:8080/api/certs/renew?match=example&force=true"
```

## CLI (`certhub`)
Example usage:
```bash
export CERTHUB_API_URL="http://127.0.0.1:8080"
export CERTHUB_TOKEN="admin.my-raw-token"

./certhub version
./certhub token identity
./certhub token scope
./certhub cert health --exclude-ok
./certhub cert get --pattern "example*"
./certhub cert issue
./certhub cert renew --pattern "example" --force
./certhub cert update-in-place --dest-dir /etc/ssl/private --post-hook "systemctl reload nginx"
```

Optionally, you can store settings in `~/.certhub`:
```ini
API_URL=http://127.0.0.1:8080
TOKEN=admin.my-raw-token
LOG_FILE=/var/log/certhub-cli.log # (Optional) Enables logging, also can be defined by env CERTHUB_LOG_FILE
LOG_LEVEL=INFO # (Optional) Can be also defined by env CERTHUB_LOG_LEVEL
```
The file must have `600` permissions (`chmod 600 ~/.certhub`).

## Recommendations
- Store `HMAC_KEY_B64` and all `TOKEN_<ID>_HMAC` values in a secret manager.
- Restrict `allowed_cidrs` to trusted source networks.
- Keep `CONF_FILE`, `CERTBOT_DIR`, and `LOGS_DIR` on persistent storage.
- Put a reverse proxy (Nginx/HAProxy) in front of the app.
- Validate config before restart:
```bash
gunicorn wsgi:app --check-config
```

## Notes
- Application logs are written to `${LOGS_DIR}/app.log`.
- `CERTBOT_DIR` stores certbot data (`config`, `work`, `logs`, `lock`), changing this directory cause loss of current certificates.
