# Cert Hub

A management service for Let's Encrypt TLS certificates. It exposes a Flask + gunicorn HTTP API plus a `certhub` CLI that perform RBAC-checked operations over certificates issued by `certbot` using DNS-01 challenges — issue, renew, read status and check status. Certificates and access policies are declared in a `config.yaml` file, and authentication uses HMAC bearer tokens with per-identity RBAC (`<cert>:<action>` permissions) combined with allowed-CIDR checks. The CLI (`certhub.py`, built with Typer + Rich) is a thin client over the API and can additionally report certificate status to Nagios via NSCA.

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
gunicorn wsgi:app -c gunicorn.conf.py
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
Example `compose.yml`:
```yaml
services:
  cert-hub:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: cert-hub
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      HMAC_KEY_B64: ${HMAC_KEY_B64}
    volumes:
      - ./config.yaml:/config/config.yaml:ro
      - ./logs:/logs
      - ./letsencrypt:/letsencrypt
```

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
| `CERTBOT_BIN` | `string` | :x: | - | Path to `certbot` executable binary, if not provided path will be autodetected |
| `CERTBOT_DIR` | `string` | :x: | `/letsencrypt` | Certbot working directory |
| `AWS_ACCESS_KEY_ID` | `string` | :x: | - | Access key ID to access Amazon Route 53. Required only if `aws` DNS provider is used in certificate configuration. Also accepts `AWS_ACCESS_KEY_ID__FILE` pointing to a file with the value. |
| `AWS_SECRET_ACCESS_KEY` | `string` | :x: | - | Secret access key to access Amazon Route 53. Required only if `aws` DNS provider is used in certificate configuration. Also accepts `AWS_SECRET_ACCESS_KEY__FILE` pointing to a file with the value. |
| `CLOUDFLARE_DNS_API_TOKEN` | `string` | :x: | - | Cloudflare scoped API token (with `Zone:DNS:Edit`). Required only if `cloudflare` DNS provider is used in certificate configuration. Also accepts `CLOUDFLARE_DNS_API_TOKEN__FILE` pointing to a file with the token. |
| `CERTBOT_RENEW_BEFORE_DAYS` | `number` | :x: | `30` | Days before expiration when a cert becomes renewable (1-60) |
| `CERTBOT_TEST_CERT` | `bool` | :x: | `false` | If `true`, passes `--test-cert` to certbot (uses Let's Encrypt staging environment) |
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
      - "*:status"
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
- `certs[].dns_provider` - supported values are `aws` (Route 53) and `cloudflare`.
- `certs[].custom_attrs` - custom metadata returned by API (for example PEM filename for CLI workflows).
- `identities[].id` - identity identifier used in token format `Bearer <id>.<token>`.
- `identities[].allowed_cidrs` - CIDR list allowed to make requests for this identity.
- `identities[].permissions` - permission entries in `"<scope>:<action>"` format, where:
  - `scope` - `*`, full `cert id`, or regex matched against `cert id`.
  - `action` - `status`, `read`, `issue`, `renew`, or `*`.

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
python certhub.py token gen-hmac --id admin --hmac-key-b64 "$HMAC_KEY_B64"
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

A request authenticates when:
1. `<identity_id>` resolves to an identity declared in `config.yaml`.
2. `HMAC-SHA256(token_raw, key) == TOKEN_<ID>_HMAC` (where `key` is the decoded `HMAC_KEY_B64`).
3. The source IP is inside one of the identity's `allowed_cidrs`.

Every request resolves to a **target certificate** and is authorized against the identity's permissions.

Endpoints:
| Method | Endpoint | Auth required | Query params | Description |
|:-------|:---------|:--------------|:-------------|:------------|
| `GET` | `/ping` | :x: | - | Liveness probe, returns `pong`. |
| `GET` | `/api/version` | :x: | - | Returns app metadata (name, author, app version, Python version). |
| `GET` | `/api/token/identity` | :heavy_check_mark: | - | Returns the authenticated identity (`id`, `allowed_cidrs`, `permissions`). |
| `GET` | `/api/token/scope` | :heavy_check_mark: | - | Returns, per action (`status`, `read`, `issue`, `renew`), the certificate IDs the identity is allowed to operate on. |
| `GET` | `/api/certs` | :heavy_check_mark: | `match` (0..n) | Reads matched certificates — status, domains, expiration date, custom attributes and PEM material (chain, certificate, private key). Requires `read`. |
| `GET` | `/api/certs/status` | :heavy_check_mark: | `match` (0..n), `exclude_ok` (bool, default: `false`) | Returns per-certificate status and an overall status (`OK` / `WARNING` / `CRITICAL`) based on expiration; intended for monitoring. Requires `status`. |
| `POST` | `/api/certs/issue` | :heavy_check_mark: | `match` (0..n), `force` (bool, default: `false`) | Issues matched certificates via certbot (DNS-01). `force` re-issues even if already issued. Requires `issue`. |
| `POST` | `/api/certs/renew` | :heavy_check_mark: | `match` (0..n), `force` (bool, default: `false`) | Renews matched certificates that are within the renewal window; `force` renews regardless. Returns next renewal/expiration dates. Requires `renew`. |

Query params:
- `match`:
  - repeatable param (for example `?match=cert-a&match=cert-b`)
  - accepted values: `*`, exact cert ID, or regex pattern (full match against cert ID)
  - default: `*` (all allowed certificates)
- `exclude_ok` (`/api/certs/status`): bool, default `false`
- `force` (`/api/certs/issue`, `/api/certs/renew`): bool, default `false`
- accepted bool values:
  - true: `1`, `true`, `True`, `yes`, `Yes`, or empty value (for example `?force=`)
  - false: `0`, `false`, `False`, `no`, `No`

Examples:
```bash
curl -s \
  -H "Authorization: Bearer admin.my-raw-token" \
  "http://127.0.0.1:8080/api/certs/stattus?match=*&exclude_ok=true"

curl -s \
  -X POST \
  -H "Authorization: Bearer admin.my-raw-token" \
  "http://127.0.0.1:8080/api/certs/renew?match=example&force=true"
```

## CLI (`certhub.py`)
`certhub` is a Typer + Rich thin client over the API. It ships inside the image at `/app/certhub.py` and can also be run standalone (needs requests, typer, rich).

Command tree:
```text
certhub
├── version                         Show app/CLI versions and author
├── token                           Manage token identity
│   ├── identity                    Show current identity (allowed CIDRs, permissions)
│   ├── scope                       List certificates permitted for the current identity
│   └── gen-hmac                    Generate a TOKEN_<ID>_HMAC value for server configuration
└── cert                            Manage certificates
    ├── list                        List certificates available for the identity or pattern
    ├── status                      Show statuses (expiring, not issued, etc.)
    ├── issue                       Issue new certificates for the identity or pattern
    ├── renew                       Renew existing certificates for the identity or pattern
    └── update-in-place             Download and replace local expiring/expired certificate files in place
```

Run `certhub --help`, or `certhub <group> --help` / `certhub <group> <command> --help`, to see all options for each command.

Each subcommand accepts `-t/--timeout` (default `10`), `-f/--format` (`table` (default), `json`, `kv`, `value`) and `-c/--column` (repeatable). Passwords are never echoed; they are read via a confirm prompt when omitted.

Example usage:
```bash
export CERTHUB_API_URL="http://127.0.0.1:8080"
export CERTHUB_TOKEN="admin.my-raw-token"

# Show base information about app
certhub version

# Show token identity 
certhub token identity

# Show scope of current token
certhub token scope

# Show status for certs
certhub cert status --exclude-ok

# Show certificate information
certhub cert list --pattern "example*"

# Issue all not yet issued certificates
certhub cert issue

# Renew expiring or expired certificate (only for certs matching --pattern)
certhub cert renew --pattern "example" --force

# Update locally stored cert in place if server has newer version
certhub cert update-in-place --dest-dir /etc/ssl/private --post-hook "systemctl reload nginx"
```

Settings are resolved in this order (highest priority first):
1. CLI flags (`--api-url`, `--token`, `--log-file`, `--log-level`).
2. Environment variables: `CERTHUB_API_URL`, `CERTHUB_TOKEN`, `CERTHUB_LOG_FILE`, `CERTHUB_LOG_LEVEL`.
3. `~/.certhub` file (must have `600` permissions, `chmod 600 ~/.certhub`):

```ini
API_URL=http://127.0.0.1:8080
TOKEN=admin.my-secret-token
LOG_FILE=/var/log/mailctl.log  # (Optional) Enables logging, also can be defined by env CERTHUB_LOG_FILE
LOG_LEVEL=INFO # (Optional) Can be also defined by env CERTHUB_LOG_LEVEL
```

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

## Publishing Docker image

The CI/CD pipeline builds and pushes the Docker image only when a git tag matching `v*` is pushed.

Push without tag (no image build):
```bash
git add .
git commit -m "your message"
git push origin main
```

Push with tag (triggers image build and push):
```bash
git add .
git commit -m "your message"
git push origin main
git tag v1.0.1
git push origin v1.0.1
```

The following image tags will be published:
- `cert-hub:1.0.1`
- `cert-hub:1.0`
- `cert-hub:latest`
- `cert-hub:<short-sha>`
