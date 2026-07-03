# Cert Hub

A management service for TLS certificates. It handles two kinds of certificates: **Let's Encrypt** certificates issued and renewed by `certbot` using DNS-01 challenges, and **static** (file-backed) certificates managed outside the app. It exposes a Flask + gunicorn HTTP API plus a `certhub` CLI that perform RBAC-checked operations over them — read, check status, issue, renew, revoke, fetch PEM material, and update local files in place (static certificates support read/status only; issue/renew/revoke return `NOT_SUPPORTED`). Certificates and access policies are declared in a `config.yaml` file, and authentication uses HMAC bearer tokens with per-identity RBAC (`<cert>:<action>` permissions) combined with allowed-CIDR checks. The CLI (`certhub.py`, built with Typer + Rich) is a thin client over the API.

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
export STATIC_CERTS_DIR="$(pwd)/static_certs"
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
| `STATIC_CERTS_DIR` | `string` | :x: | `/static-certs` | Directory containing files for `static` certificates (referenced by name in config). |
| `AWS_ACCESS_KEY_ID` | `string` | :x: | - | Access key ID to access Amazon Route 53. Required only if `aws` DNS provider is used in certificate configuration. Also accepts `AWS_ACCESS_KEY_ID__FILE` pointing to a file with the value. |
| `AWS_SECRET_ACCESS_KEY` | `string` | :x: | - | Secret access key to access Amazon Route 53. Required only if `aws` DNS provider is used in certificate configuration. Also accepts `AWS_SECRET_ACCESS_KEY__FILE` pointing to a file with the value. |
| `CLOUDFLARE_DNS_API_TOKEN` | `string` | :x: | - | Cloudflare scoped API token (with `Zone:DNS:Edit`). Required only if `cloudflare` DNS provider is used in certificate configuration. Also accepts `CLOUDFLARE_DNS_API_TOKEN__FILE` pointing to a file with the token. |
| `CERTBOT_RENEW_BEFORE_DAYS` | `number` | :x: | `30` | Days before expiration when a cert becomes renewable (1-60) |
| `CERTBOT_TEST_CERT` | `bool` | :x: | `false` | If `true`, passes `--test-cert` to certbot (uses Let's Encrypt staging environment) |
| `TRUSTED_PROXY_HOPS` | `number` | :x: | `0` | Number of trusted reverse proxies in front of the app. `0` (default) uses the direct peer IP for `allowed_cidrs` checks. When behind a proxy, set this to the proxy count so the real client IP is read from the rightmost `X-Forwarded-For` entries (via `ProxyFix`); otherwise the IP allowlist sees the proxy, not the client. |
| `HMAC_KEY_B64` | `string` | :heavy_check_mark: | - | Base64 HMAC key (minimum 32 bytes after decoding), used to verify tokens. Changing this value requires regenerate all identity passwords! |
| `TOKEN_<ID>_HMAC` | `string` | :x: | - | Token HMAC-SHA256 (hex) for identity `<ID>` from `config.yaml`. Theoretically not required to start the application, but it is nice to have at least one identity  |

## Configuration
`CONF_FILE` is a YAML file defining certificates (`letsencrypt_certs`, `static_certs`) and identities (`identities`).

Example:
```yaml
letsencrypt_certs:
  - id: "example"
    email: "admin@example.com"
    domains:
      - "*.example.com"
      - "example.com"
    dns_provider: "aws"
    custom_attrs: # Custom attributes returned by API, can be used by CLI
      pem_prefix: "example"   # base name for files written by `cert sync` (defaults to cert id)
      custom_key: custom_value

static_certs:
  - id: "internal"
    cert_file: "internal.crt"        # under STATIC_CERTS_DIR
    privkey_file: "internal.key"
    chain_file: "internal.chain"     # optional
    custom_attrs:
      pem_prefix: "internal"   # base name for files written by `cert sync` (defaults to cert id)

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

`letsencrypt_certs[]` (Let's Encrypt certificates issued via certbot DNS-01):
- `letsencrypt_certs[].id` - unique certificate identifier.
- `letsencrypt_certs[].domains` - domain list passed to certbot.
- `letsencrypt_certs[].dns_provider` - supported values are `aws` (Route 53) and `cloudflare`.
- `letsencrypt_certs[].custom_attrs` - custom metadata returned by API (for example PEM filename for CLI workflows).

`static_certs[]` (externally managed certificates read from `STATIC_CERTS_DIR`):
- `static_certs[].id` - unique certificate identifier.
- `static_certs[].cert_file` - (required) certificate filename, resolved under `STATIC_CERTS_DIR`.
- `static_certs[].privkey_file` - (required) private key filename, resolved under `STATIC_CERTS_DIR`.
- `static_certs[].chain_file` - (optional) chain/CA bundle filename, resolved under `STATIC_CERTS_DIR`.
- `static_certs[].custom_attrs` - custom metadata returned by API (for example PEM filename for CLI workflows).

- `identities[].id` - identity identifier used in token format `Bearer <id>.<token>`.
- `identities[].allowed_cidrs` - CIDR list allowed to make requests for this identity.
- `identities[].permissions` - permission entries in `"<scope>:<action>"` format, where:
  - `scope` - `*`, full `cert id`, or regex matched against `cert id`.
  - `action` - `status`, `read`, `issue`, `renew`, `revoke`, `reload`, or `*`. Note: `reload` is a global action and must be scoped as `*:reload`.

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

Each certificate object in API responses includes a `"type"` field with value `letsencrypt` or `static`.

Endpoints:
| Method | Endpoint | Auth required | Query params | Description |
|:-------|:---------|:--------------|:-------------|:------------|
| `GET` | `/ping` | :x: | - | Liveness probe, returns `pong`. |
| `GET` | `/api/version` | :x: | - | Returns app metadata (name, author, app version, build commit SHA, build date, Python version). |
| `GET` | `/api/token/identity` | :heavy_check_mark: | - | Returns the authenticated identity (`id`, `allowed_cidrs`, `permissions`). |
| `GET` | `/api/token/scope` | :heavy_check_mark: | - | Returns, per action (`read`, `issue`, `renew`, `status`, `revoke`), the certificate IDs the identity is allowed to operate on. |
| `GET` | `/api/certs` | :heavy_check_mark: | `match` (0..n), `type` | Reads matched certificates — status, domains, expiration date, custom attributes and PEM material (chain, certificate, private key). Requires `read`. |
| `GET` | `/api/certs/status` | :heavy_check_mark: | `match` (0..n), `exclude_ok` (bool, default: `false`), `type` | Returns per-certificate status and an overall status (`OK` / `WARNING` / `CRITICAL`) based on expiration; intended for monitoring. Requires `status`. |
| `GET` | `/api/certs/catalog` | :heavy_check_mark: | `match` (0..n), `type` (`letsencrypt`\|`static`\|`all`), `permission` (`read`\|`issue`\|`renew`\|`status`\|`revoke`) | Lightweight catalog of certificates as `{id, type}`; filtered by match/type/permission. Auth only (no per-cert permission to call). |
| `GET` | `/api/metrics` | :heavy_check_mark: | - | Prometheus metrics for certificates the identity may `status` (expiry timestamp, days-to-expire, status). Requires `status`. |
| `GET` | `/api/certs/<id>/pem` | :heavy_check_mark: | `type` (`bundle`\|`cert`\|`chain`\|`privkey`, default `bundle`) | Returns raw PEM (`text/plain`) for one certificate. Requires `read`. |
| `POST` | `/api/certs/<id>/issue` | :heavy_check_mark: | `force` (bool) | Issues one certificate. Requires `issue`. Static → `NOT_SUPPORTED`. |
| `POST` | `/api/certs/<id>/renew` | :heavy_check_mark: | `force` (bool) | Renews one certificate. Requires `renew`. Static → `NOT_SUPPORTED`. |
| `POST` | `/api/certs/<id>/revoke` | :heavy_check_mark: | - | Revokes a Let's Encrypt certificate (`certbot revoke --delete-after-revoke`) and deletes its files; `static` → `NOT_SUPPORTED`. Requires `revoke`. After revocation the certificate's status becomes `REVOKED` (persisted via a marker under `<CERTBOT_DIR>/revoked/<id>`); a subsequent successful `issue` clears it. |
| `POST` | `/api/admin/reload` | :heavy_check_mark: | - | Reloads configuration by sending `SIGHUP` to the gunicorn master (reloads all workers). Requires `*:reload`. |

Query params:
- `match`:
  - repeatable param (for example `?match=cert-a&match=cert-b`)
  - accepted values: `*`, exact cert ID, or regex pattern (full match against cert ID)
  - default: `*` (all allowed certificates)
- `type` (`/api/certs`, `/api/certs/status`, `/api/certs/catalog`): filter by certificate kind; accepted values: `letsencrypt`, `static`, `all`; default: `all`
- `permission` (`/api/certs/catalog`): filter catalog to certs the identity holds a given permission for; accepted values: `read`, `issue`, `renew`, `status`, `revoke`
- `exclude_ok` (`/api/certs/status`): bool, default `false`
- `force` (`/api/certs/<id>/issue`, `/api/certs/<id>/renew`): bool, default `false`
- accepted bool values:
  - true: `1`, `true`, `True`, `yes`, `Yes`, or empty value (for example `?force=`)
  - false: `0`, `false`, `False`, `no`, `No`

> **Breaking change:** The bulk `POST /api/certs/issue` and `POST /api/certs/renew` endpoints (with `?match=` filtering) have been removed. Use `GET /api/certs/catalog` to list matching certificates, then call `POST /api/certs/<id>/issue` or `POST /api/certs/<id>/renew` per certificate. The `certhub` CLI retains the `--pattern`/`--type` UX by querying `/api/certs/catalog` and looping per-cert internally.

Examples:
```bash
curl -s \
  -H "Authorization: Bearer admin.my-raw-token" \
  "http://127.0.0.1:8080/api/certs/status?match=*&exclude_ok=true"

curl -s \
  -H "Authorization: Bearer admin.my-raw-token" \
  "http://127.0.0.1:8080/api/certs/catalog?match=example&permission=renew"

curl -s \
  -X POST \
  -H "Authorization: Bearer admin.my-raw-token" \
  "http://127.0.0.1:8080/api/certs/example/renew?force=true"
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
    ├── show                        Show details for a single certificate
    ├── status                      Show statuses (expiring, not issued, etc.)
    ├── pem                         Print raw PEM material (bundle/cert/chain/privkey) for one certificate
    ├── issue                       Issue new certificates for the identity or pattern
    ├── renew                       Renew existing certificates for the identity or pattern
    ├── revoke                      Revoke one or more certificates (requires confirmation)
    └── sync                        Sync local certificate files with the server (replace expiring/expired/missing, remove revoked and no-longer-accessible)
```

Run `certhub --help`, or `certhub <group> --help` / `certhub <group> <command> --help`, to see all options for each command.

Each subcommand accepts `-t/--timeout` (default `10`), `-f/--format` (`table` (default), `json`, `kv`, `value`) and `-c/--column` (repeatable). Passwords are never echoed; they are read via a confirm prompt when omitted.

The `cert` subcommands that operate across certificate types accept a `--type` flag (`letsencrypt|static|all`) to filter which certificates are targeted:
- `cert list`, `cert status`, `cert sync`: default `all`
- `cert issue`, `cert renew`: default `letsencrypt` (static certificates return `NOT_SUPPORTED`)

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

# Show cert information
certhub cert list --pattern "example*"

# Show details for a single certificate
certhub cert show example

# Print raw PEM for one certificate (default bundle; use --type cert|chain|privkey)
certhub cert pem example > example.pem

# Issue all not yet issued certificates
certhub cert issue

# Renew expiring or expired certificate (only for certs matching --pattern)
certhub cert renew --pattern "example" --force

# Revoke certificates — lists matching certs, then requires typing "Yes i really mean it"
certhub cert revoke --pattern "example"

# Bypass the confirmation prompt (use with caution)
certhub cert revoke --pattern "example" --yes-i-really-mean-it

# Sync locally stored cert files with the server if it has a newer version
certhub cert sync /etc/ssl/private --post-hook "systemctl reload nginx"

# Write a deploy bundle plus standalone cert and key files
certhub cert sync /etc/ssl/private --pem bundle --pem cert --pem privkey --post-hook "systemctl reload nginx"

# Write cert and key with nginx-friendly extensions
certhub cert sync /etc/ssl/private --pem cert --pem privkey --ext cert=crt --ext privkey=key --post-hook "systemctl reload nginx"

# Preview what would change without writing, deleting, or updating state
certhub cert sync /etc/ssl/private --dry-run
```

`cert show <cert_id>` shows details for a single certificate. Unlike `cert list`, the default `table`
format renders one record vertically as a `Field` / `Value` table:

```
$ certhub cert show siedlaczek.com.pl
╭────────────┬─────────────────────╮
│ Field      │ Value               │
├────────────┼─────────────────────┤
│ id         │ siedlaczek.com.pl   │
│ status     │ OK                  │
│ ...        │ ...                 │
╰────────────┴─────────────────────╯
```

`--format json` prints a single object (`{}`), and `-c/--column` filters fields.
An unknown id exits `CRITICAL` (code 2).

`cert sync` writes PEM files controlled by the `-P/--pem` option (repeatable, default `bundle`). Accepted values:
- `bundle` — certificate + chain + private key concatenated into one file
- `cert` — certificate only
- `chain` — chain/CA bundle only
- `privkey` — private key only

Each requested type produces a separate file named `<prefix>_<type>.pem` (extension configurable via `--ext`, see below) inside the destination directory (the positional `DEST_DIR` argument), where `<prefix>` is taken from the certificate's `pem_prefix` custom attr (see Configuration) or falls back to the cert id.

The `--ext` option (repeatable, form `type=ext`) overrides the file extension for a given PEM type. The default extension is `.pem` for every type; omitting `--ext` produces behaviour identical to previous releases. Example:

```
--ext cert=crt --ext privkey=key
```

produces `<prefix>_cert.crt` and `<prefix>_privkey.key` instead of the default `.pem` files. This is useful for web servers like nginx or Apache that key off the file extension. HAProxy ignores the extension and parses PEM content directly — use `bundle` as the type for HAProxy's `crt` directive; `--ext` is not needed there.

`cert sync` maintains a `.certhub-sync-state.json` file in the destination directory recording each certificate it materialised (wrote, or confirmed already up to date) and the `sha256` of every file it wrote. This state drives a single, unified cleanup pass: on each run, any certificate recorded there but **no longer synced** — because the server reports it `REVOKED`, the identity lost access to it, or a narrower `--pattern`/`--type` filter now excludes it — has its recorded files removed. Revoked certificates and certificates that simply vanished from the response are handled by the same path.

Before deleting a file, its on-disk checksum is compared against the recorded one; on a mismatch (the file was modified outside `cert sync`) the file is left untouched and the run reports `WARNING`. Because cleanup is checksum-guarded against the state file, only files that `cert sync` itself wrote and still tracks are ever removed — a revoked or vanished certificate whose files were placed out-of-band, or whose state entry is missing, is left alone. Cleanup counts as a change and triggers `--post-hook` unless `--omit-post-hook-on-cleanup` is passed. A certificate still returned by the server with a non-`REVOKED` error status (e.g. not yet issued) keeps its local files.

If the filter changed since the previous run, the certificates dropped by the new filter are cleaned up as above; the run reports a `WARNING` — both as a row in the result (so `--status-file` and monitoring see it) and in the log — naming them so the change is visible.

Use `--dry-run` to preview a run: it reports what would be added, updated, or removed (rows read "Would add" / "would remove") and makes **no changes at all** — no PEM file is written, nothing is deleted, and neither the state file nor the `--status-file` is updated.

The `--status-file <path>` option writes a JSON summary of the run after it completes, useful for monitoring or automation. It is written on every real outcome (success, certificate-fetch failure, post-hook failure) but never under `--dry-run`; parent directories are created if missing. The file contains:

```json
{
  "status": "OK",
  "exit_code": 0,
  "message": "OK: All certificates are up to date",
  "result": [ { "id": "example", "status": "OK", "updated": true, "...": "..." } ]
}
```

- `status` / `exit_code` — the overall outcome: the highest severity across all certificates (`OK`/`WARNING`/`CRITICAL`/`UNKNOWN` and `0`/`1`/`2`/`3`).
- `message` — a human-readable summary; on success `OK: All certificates are up to date`, otherwise one line per problem certificate (joined with newlines).
- `result` — the same per-certificate rows printed to the console.

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
- Put a reverse proxy (Nginx/HAProxy) in front of the app. When you do, set `TRUSTED_PROXY_HOPS` to the number of proxies so `allowed_cidrs` is checked against the real client IP (not the proxy) — see the env table.
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
