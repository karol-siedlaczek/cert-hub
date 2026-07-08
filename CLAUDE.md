# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Twin repository — keep in sync

`cert-hub` and its sibling `mail-controller` (`~/repo/python/mail-controller`,
GitHub `karol-siedlaczek/mail-controller`) are deliberately built on the same
skeleton and have historically mirrored each other. Before diverging from a
pattern here, check how the other repo does it; when you change a shared
convention, apply the equivalent change in both.

What is shared (structurally identical, names differ):
- **CLI skeleton** — `certhub.py` ↔ `mailctl.py`: the `ExitCode`, `Format`
  (`table`/`json`/`kv`/`value`), `Opt` option factory, `Settings`, `CmdResult`
  (`from_response`/`_parse_response`/`_filter_data`/`_mask_sensitive`/
  `render_and_exit`) and `Client` classes, the `token gen-hmac` command, and
  settings resolution (flags → env vars → `~/.<tool>` file requiring `600`).
- **`render_and_exit()` rendering** — including the `single_row=True` mode that
  renders one record as a vertical two-column `Field`/`Value` table (list/`show`
  commands stay horizontal). This must behave identically in both CLIs.
- **Server package layout** — `<pkg>/api/{routes,context,helpers,validators}.py`,
  `<pkg>/domain/`, `<pkg>/domain/permission/`, `<pkg>/exception/`,
  `<pkg>/validation/require.py`, `<pkg>/conf/config.py`, `app.py`, `wsgi.py`,
  `gunicorn.conf.py`.
- **Auth model** — HMAC bearer tokens, per-identity RBAC `<scope>:<action>`
  permissions plus allowed-CIDR checks, resolved in `api/context.py`.
- **Tooling** — `Makefile` targets and `tests/` layout (see below).

## Common commands

Run from the repo root:

- `make test` — all unit tests (creates `tests/.venv` on first run, no Docker).
- `make lint` — `py_compile` over `certhub.py`, `wsgi.py`, `gunicorn.conf.py`, `cert_hub/**`.
- `make build` — build the `cert-hub:test` Docker image.
- `make venv` / `make clean` — create / tear down the test virtualenv.

Single test (tests use `pythonpath=..` via `tests/pytest.ini`, so run from `tests/`):

```bash
cd tests && .venv/bin/python -m pytest test_cert_show.py::test_show_not_found_is_critical -v
```

Run the API locally (see README for env vars like `HMAC_KEY_B64`, `CONF_FILE`, `CERTBOT_DIR`):

```bash
gunicorn wsgi:app -c gunicorn.conf.py   # then: curl -s http://127.0.0.1:8080/ping
```

## Architecture

Two halves talking over HTTP:

1. **`certhub.py`** — the Typer + Rich CLI. It is a **thin HTTP client**: each
   command builds request params, calls the API via `Client`, wraps the
   response in `CmdResult`, and prints through `render_and_exit()`. It contains
   no certificate logic except the local `cert sync` command, which writes/refreshes
   PEM files on disk from data the API returns.

2. **`cert_hub/` package** — the Flask app (served by `wsgi.py` + gunicorn) that
   does the real work. Request flow: `cert_hub/api/routes.py` endpoints →
   `Context.authenticate()` (`api/context.py`, token + RBAC + CIDR) →
   `ctx.resolve_certs()/resolve_cert()` → domain objects.

Domain model (`cert_hub/domain/cert/`): `Cert` is the base; `LetsencryptCert`
(certbot-issued via DNS-01, supports issue/renew/revoke — see `cert_bot.py` and
`dns_provider.py`) and `StaticCert` (file-backed, read/status only — issue/renew/
revoke return `NOT_SUPPORTED`) are the two `CertType`s (`letsencrypt`/`static`/
`all`). Certificates, identities, and RBAC policies are declared in `config.yaml`
(loaded by `cert_hub/conf/config.py`).

The `cert show <id>` CLI command reuses the list endpoint
(`GET /api/certs?match=<id>`, `type=all`), promotes an exact `id` match over glob
siblings, and renders single-row; 0 matches → CRITICAL "not found", >1 → CRITICAL
"ambiguous". (In `mail-controller`, `show` hits a dedicated `/{id}` endpoint, so it
has no such client-side match logic — a deliberate difference driven by the API.)
