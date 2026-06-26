# Per-cert Actions + Catalog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unify certificate actions to per-cert HTTP endpoints (`/api/certs/<id>/issue|renew|revoke`), add a lightweight `GET /api/certs/catalog` discovery endpoint, and make the CLI keep its list/`--pattern` UX by fanning out over per-cert calls (incl. a new `cert revoke` command with a typed confirmation).

**Architecture:** Server drops the bulk `?match=` issue/renew routes and exposes per-cert action routes (mirroring the existing `/api/certs/<id>/revoke`). A new auth-only `GET /api/certs/catalog?match=&type=&permission=` returns `[{id, type}]` filtered server-side. The CLI `issue`/`renew`/`revoke` commands query the catalog (scoped to the action) and POST per cert, aggregating results.

**Tech Stack:** Python 3.12+, Flask, Typer/Click + requests (CLI), pytest.

## Global Constraints

- Server actions are **per-cert only**: `POST /api/certs/<id>/issue`, `/renew`, `/revoke`. Bulk `POST /api/certs/issue` and `/api/certs/renew` (the `?match=` variants) are **removed**.
- Per-cert action response mirrors revoke: success → `200 data={id,type,status,...}`; `CertException` (ALREADY_ISSUED / NOT_YET_RENEWABLE / NOT_SUPPORTED / NOT_ISSUED) → `409 {msg, detail:{id,status}}`; `CertBotError` → 502 (existing ApiError handler; do not catch).
- issue success status `ISSUED` (+`expire_date`,`days_to_expire`); renew success status `RENEWED` (+`next_renew_date`,`expire_date`,`days_to_expire`).
- `GET /api/certs/catalog`: auth-only (no per-cert permission to call). Returns `data=[{ "id":..., "type":... }]`. Optional cumulative filters: `match` (default `["*"]`, via `Context._match_certs`), `type` (via `filter_certs_by_type`, default `CertType.ALL`), `permission` (one of `read|issue|renew|status|revoke`, default none → no filter; value out of that set → 400; filter via `identity.allows(cert, action)`).
- CLI keeps `--pattern`, `--force`, `--type` (issue/renew), `-t/-f/-c`. issue/renew/revoke fan out: query catalog scoped to the action, then `POST` per cert; aggregate 200 and 409 rows without aborting on 409. Exit non-zero only on 403 or 5xx responses.
- CLI `cert revoke` is NEW: lists the certs to be revoked, then requires typing exactly `Yes i really mean it` to proceed; `--yes-i-really-mean-it` bypasses the prompt; non-interactive without the flag aborts with a clear error.
- Current import paths (domain restructured into packages): `from cert_hub.domain.permission.permission_action import PermissionAction`, `from cert_hub.domain.cert.cert_status import CertStatus`, `from cert_hub.domain.cert.cert_type import CertType`. `routes.py` already imports `Context`, `Config`, `build_response`, `log_request`, `get_log_record`, `filter_certs_by_type`, `query_list`, `query_bool`, `query_one_of`, `PermissionAction`, `CertStatus`, `CertType`, `CertException`.
- Breaking change: external clients using `POST /api/certs/issue?match=` / `renew?match=` must migrate to per-cert. Document in README.
- Flask routes and the CLI are not unit-tested in this project (no HTTP fixture; venv lacks typer/requests). Verify with `make lint` + `python -c "import cert_hub.api.routes"` (import-check) + review. The domain test suite (`make test`) must stay green and unchanged.
- This work is intentionally NOT committed (user instruction). Each task ends WITHOUT a git commit; do not stage/branch/revert or touch unrelated pre-existing working-tree changes.

---

### Task 1: `GET /api/certs/catalog` endpoint

**Files:**
- Modify: `cert_hub/api/routes.py`

**Interfaces:**
- Consumes: `Context.authenticate`, `Context._match_certs`, `Config.get_from_global_context`, `filter_certs_by_type`, `query_list`, `query_one_of`, `PermissionAction`, `CertType`, `identity.allows`, `build_response`.
- Produces: `GET /api/certs/catalog` → `200 data=[{"id":str,"type":str}]`.

- [ ] **Step 1: Add the catalog route**

In `cert_hub/api/routes.py`, add (e.g. just after the `/api/certs/status` route):

```python
@api.route("/api/certs/catalog", methods=["GET"])
def cert_catalog() -> Response:
    ctx = Context.authenticate()
    conf = Config.get_from_global_context()

    patterns = query_list("match", default=["*"])
    certs = Context._match_certs(patterns, conf.certs)
    certs = filter_certs_by_type(certs, default=CertType.ALL)

    permission = query_one_of("permission", default=None, allowed=["read", "issue", "renew", "status", "revoke"])
    if permission is not None:
        action = PermissionAction(permission)
        certs = [c for c in certs if ctx.identity.allows(c, action)]

    payload = [{"id": c.id, "type": c.type.value} for c in certs]
    return build_response(200, data=payload)
```

- [ ] **Step 2: Verify import + compile + suite**

Run: `python -c "import cert_hub.api.routes" ` (from repo root, using the test venv python: `tests/.venv/bin/python -c "import cert_hub.api.routes"`)
Expected: no output / clean import.

Run: `make lint`
Expected: `py_compile` → `OK`.

Run: `make test`
Expected: domain suite unchanged and green.

(No commit.)

---

### Task 2: Per-cert `issue`/`renew` routes; remove bulk

**Files:**
- Modify: `cert_hub/api/routes.py`

**Interfaces:**
- Consumes: `Context.resolve_scope`, `cert.issue/renew`, `cert.get_expire_date_as_str/get_days_to_expire/get_next_renew_date_as_str`, `cert.type`, `PermissionAction.ISSUE/RENEW`, `CertStatus.ISSUED/RENEWED`, `CertException`, `query_bool`.
- Produces: `POST /api/certs/<cert_id>/issue`, `POST /api/certs/<cert_id>/renew`.

- [ ] **Step 1: Replace the bulk `cert_issue` route with a per-cert one**

In `cert_hub/api/routes.py`, delete the entire existing bulk `@api.route("/api/certs/issue", ...)` function and replace with:

```python
@api.route("/api/certs/<cert_id>/issue", methods=["POST"])
def cert_issue(cert_id: str) -> Response:
    force = query_bool("force")
    ctx = Context.authenticate()
    cert = ctx.resolve_scope([cert_id], PermissionAction.ISSUE)[0]

    try:
        cert.issue(force)
        status = CertStatus.ISSUED
        msg = "Certificate successfully issued"
        log_request(get_log_record(status, cert, msg), identity=ctx.identity, level="info")
        return build_response(200, data={
            "id": cert.id,
            "type": cert.type.value,
            "status": status.value,
            "msg": msg,
            "expire_date": cert.get_expire_date_as_str(),
            "days_to_expire": cert.get_days_to_expire()
        })
    except CertException as e:
        log_request(get_log_record(e.status, e.cert_id, e.msg), identity=ctx.identity, level="warning")
        return build_response(409, msg=e.msg, detail={"id": cert.id, "status": e.status.value})
```

- [ ] **Step 2: Replace the bulk `cert_renew` route with a per-cert one**

Delete the existing bulk `@api.route("/api/certs/renew", ...)` function and replace with:

```python
@api.route("/api/certs/<cert_id>/renew", methods=["POST"])
def cert_renew(cert_id: str) -> Response:
    force = query_bool("force")
    ctx = Context.authenticate()
    cert = ctx.resolve_scope([cert_id], PermissionAction.RENEW)[0]

    try:
        cert.renew(force)
        status = CertStatus.RENEWED
        msg = "Certificate successfully renewed"
        log_request(get_log_record(status, cert, msg), identity=ctx.identity, level="info")
        return build_response(200, data={
            "id": cert.id,
            "type": cert.type.value,
            "status": status.value,
            "msg": msg,
            "next_renew_date": cert.get_next_renew_date_as_str(),
            "expire_date": cert.get_expire_date_as_str(),
            "days_to_expire": cert.get_days_to_expire()
        })
    except CertException as e:
        log_request(get_log_record(e.status, e.cert_id, e.msg), identity=ctx.identity, level="warning")
        return build_response(409, msg=e.msg, detail={"id": cert.id, "status": e.status.value})
```

- [ ] **Step 3: Verify import + compile + suite**

Run: `tests/.venv/bin/python -c "import cert_hub.api.routes"`
Expected: clean import (confirms the two new `<cert_id>` routes don't collide with `/catalog` or `/<cert_id>/revoke` and the old bulk names are gone).

Run: `make lint` → `py_compile` OK.
Run: `make test` → domain suite green.

- [ ] **Step 4: Self-check**

Confirm by reading routes.py:
- no remaining `@api.route("/api/certs/issue"` or `/api/certs/renew"` (bulk) routes.
- the per-cert `issue`/`renew`/`revoke` routes all use `resolve_scope([cert_id], <action>)[0]` and catch `CertException` → 409, letting `CertBotError` propagate.

(No commit.)

---

### Task 3: CLI fan-out for `cert issue` / `cert renew`

**Files:**
- Modify: `certhub.py`

**Interfaces:**
- Consumes: `Client.init`, `Client.request` (returns `requests.Response`, never raises on non-2xx), `CmdResult.from_dict`, `CmdResult.from_response`, `ExitCode`, `validate_cert_type`, `Opt.*`.
- Produces: module-level helpers `_catalog_cert_ids(client, *, permission, patterns, cert_type=None) -> list[str]`, `_action_row(cert_id, response) -> dict`, `_fanout(client, cert_ids, action, *, force=False) -> tuple[list[dict], ExitCode]`; rewritten `cert_issue`/`cert_renew`.

- [ ] **Step 1: Add the fan-out helpers**

In `certhub.py`, in the `# ── helpers ──` section, add:

```python
def _catalog_cert_ids(client: "Client", *, permission: str, patterns: list[str], cert_type: str | None = None) -> list[str]:
    params: dict[str, Any] = {"permission": permission}
    if patterns:
        params["match"] = patterns
    if cert_type and cert_type != "all":
        params["type"] = cert_type
    response = client.request("GET", "/api/certs/catalog", params=params)
    if not response.ok:
        CmdResult.from_response(response).render_and_exit()
    payload = response.json().get("data", [])
    return [entry["id"] for entry in payload]


def _action_row(cert_id: str, response: requests.Response) -> dict:
    try:
        body = response.json()
    except ValueError:
        body = {}
    if response.ok:
        data = body.get("data", {}) if isinstance(body, dict) else {}
        return data if isinstance(data, dict) else {"id": cert_id, "result": data}
    detail = body.get("detail", {}) if isinstance(body, dict) else {}
    return {
        "id": detail.get("id", cert_id) if isinstance(detail, dict) else cert_id,
        "status": detail.get("status") if isinstance(detail, dict) else None,
        "msg": body.get("message") if isinstance(body, dict) else str(body),
    }


def _fanout(client: "Client", cert_ids: list[str], action: str, *, force: bool = False) -> tuple[list[dict], ExitCode]:
    rows: list[dict] = []
    exit_code = ExitCode.OK
    for cert_id in cert_ids:
        params = {"force": "true"} if force else {}
        response = client.request("POST", f"/api/certs/{cert_id}/{action}", params=params)
        rows.append(_action_row(cert_id, response))
        if response.status_code == 403 or response.status_code >= 500:
            exit_code = ExitCode.CRITICAL
    return rows, exit_code
```

- [ ] **Step 2: Rewrite `cert_issue` to fan out**

Replace the body of the `cert_issue` command (keep its signature/decorator and `--type` default `"letsencrypt"`):

```python
    client = Client.init(ctx, format, timeout=timeout)
    cert_type = validate_cert_type(type)
    cert_ids = _catalog_cert_ids(client, permission="issue", patterns=patterns, cert_type=cert_type)
    if not cert_ids:
        return CmdResult.from_dict({"message": "No matching certificates"}, ExitCode.OK).render_and_exit(ctx.info_name)
    rows, exit_code = _fanout(client, cert_ids, "issue", force=force)
    return CmdResult.from_dict(rows, exit_code).render_and_exit(ctx.info_name, columns)
```

- [ ] **Step 3: Rewrite `cert_renew` to fan out**

Replace the body of the `cert_renew` command (keep signature/decorator, `--type` default `"letsencrypt"`):

```python
    client = Client.init(ctx, format, timeout=timeout)
    cert_type = validate_cert_type(type)
    cert_ids = _catalog_cert_ids(client, permission="renew", patterns=patterns, cert_type=cert_type)
    if not cert_ids:
        return CmdResult.from_dict({"message": "No matching certificates"}, ExitCode.OK).render_and_exit(ctx.info_name)
    rows, exit_code = _fanout(client, cert_ids, "renew", force=force)
    return CmdResult.from_dict(rows, exit_code).render_and_exit(ctx.info_name, columns)
```

- [ ] **Step 4: Verify compile**

Run: `make lint`
Expected: `py_compile` → `OK` (covers `certhub.py`).

(No commit.)

---

### Task 4: New CLI `cert revoke` command (confirmation + `--yes-i-really-mean-it`)

**Files:**
- Modify: `certhub.py`

**Interfaces:**
- Consumes: `_catalog_cert_ids`, `_fanout` (Task 3), `Client.init`, `CmdResult`, `ExitCode`, `Opt.*`, `typer`, `sys`.
- Produces: `cert revoke` command under `cert_app`.

- [ ] **Step 1: Ensure `sys` is imported**

In `certhub.py`, confirm `import sys` is present at the top; if absent, add it with the other stdlib imports.

- [ ] **Step 2: Add the `cert revoke` command**

Add near the other `@cert_app.command(...)` definitions:

```python
@cert_app.command(name="revoke", help="Revoke certificates for the current identity or selected pattern (irreversible)")
def cert_revoke(
    ctx: typer.Context,
    timeout: int = Opt.timeout(360),
    format: str = Opt.format(),
    patterns: list[str] = Opt.patterns(),
    columns: list[str] = Opt.columns(),
    assume_yes: bool = typer.Option(
        False, "--yes-i-really-mean-it",
        help="Skip the interactive confirmation prompt (for automation)"
    ),
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    cert_ids = _catalog_cert_ids(client, permission="revoke", patterns=patterns)
    if not cert_ids:
        return CmdResult.from_dict({"message": "No matching certificates to revoke"}, ExitCode.OK).render_and_exit(ctx.info_name)

    typer.echo("The following certificates will be REVOKED (irreversible):")
    for cert_id in cert_ids:
        typer.echo(f"  - {cert_id}")

    if not assume_yes:
        if not sys.stdin.isatty():
            raise typer.BadParameter(
                'Refusing to revoke without confirmation in a non-interactive shell; pass --yes-i-really-mean-it'
            )
        confirmation = typer.prompt('Type "Yes i really mean it" to proceed')
        if confirmation != "Yes i really mean it":
            typer.echo("Aborted, no certificates were revoked.")
            raise typer.Exit(code=1)

    rows, exit_code = _fanout(client, cert_ids, "revoke")
    return CmdResult.from_dict(rows, exit_code).render_and_exit(ctx.info_name, columns)
```

- [ ] **Step 3: Verify compile**

Run: `make lint`
Expected: `py_compile` → `OK`.

- [ ] **Step 4: Self-check**

Confirm by reading:
- exact phrase compared is `"Yes i really mean it"` (case-sensitive, full match).
- `--yes-i-really-mean-it` sets `assume_yes=True` and bypasses the prompt; list is still printed.
- non-interactive (`not sys.stdin.isatty()`) without the flag → `typer.BadParameter` (no revoke).
- discovery uses `permission="revoke"`.

(No commit.)

---

### Task 5: README documentation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the API endpoints table**

In `README.md`:
- Remove the bulk `POST /api/certs/issue` and `POST /api/certs/renew` rows.
- Add rows:
```
| `GET` | `/api/certs/catalog` | :heavy_check_mark: | `match` (0..n), `type` (`letsencrypt`\|`static`\|`all`), `permission` (`read`\|`issue`\|`renew`\|`status`\|`revoke`) | Lightweight catalog of certificates as `{id, type}`; filtered by match/type/permission. Auth only (no per-cert permission to call). |
| `POST` | `/api/certs/<id>/issue` | :heavy_check_mark: | `force` (bool) | Issues one certificate. Requires `issue`. Static → `NOT_SUPPORTED`. |
| `POST` | `/api/certs/<id>/renew` | :heavy_check_mark: | `force` (bool) | Renews one certificate. Requires `renew`. Static → `NOT_SUPPORTED`. |
```
(The `POST /api/certs/<id>/revoke` row already exists.)

- [ ] **Step 2: Note the breaking change + CLI behavior**

Add a short note: bulk `?match=` issue/renew endpoints were removed; act per-cert via `/api/certs/<id>/...`. The `certhub` CLI keeps `--pattern`/list UX by querying `/api/certs/catalog` and looping per-cert. Document the new `certhub cert revoke` command (lists certs, requires typing `Yes i really mean it`, or `--yes-i-really-mean-it` to bypass).

- [ ] **Step 3: Verify references**

Run: `grep -n "api/certs/catalog\|certs/<id>/issue\|certs/<id>/renew\|yes-i-really-mean-it" README.md`
Expected: matches for each.

(No commit.)

---

### Task 6: Full verification sweep

**Files:** none (verification only).

- [ ] **Step 1: Import-check the API**

Run: `tests/.venv/bin/python -c "import cert_hub.api.routes; import cert_hub.api.context; print('ok')"`
Expected: `ok` (no ImportError; routes wire up).

- [ ] **Step 2: Lint**

Run: `make lint`
Expected: `py_compile` → `OK` (includes `certhub.py`).

- [ ] **Step 3: Domain test suite**

Run: `make test`
Expected: all tests pass, unchanged by this routes/CLI-only feature.

---

## Self-Review

**Spec coverage:**
- Per-cert issue/renew routes + removal of bulk → Task 2. ✓
- Response semantics 200/409, CertBotError→502 → Task 2 (per-cert) + existing revoke route. ✓
- `GET /api/certs/catalog` with match/type/permission filters, auth-only, returns `[{id,type}]` → Task 1. ✓
- CLI issue/renew fan-out via catalog (permission-scoped, `--type` passed through) with aggregation + non-zero exit only on 403/5xx → Task 3. ✓
- New CLI `cert revoke` with cert list + `Yes i really mean it` + `--yes-i-really-mean-it` + non-interactive guard → Task 4. ✓
- README (remove bulk, add catalog + per-cert; breaking-change note; revoke command) → Task 5. ✓
- token_scope unchanged → respected (not modified by any task). ✓
- Follow-up REVOKED-lifecycle explicitly out of scope → no task (correct). ✓

**Placeholder scan:** No TBD/TODO/"handle errors"/"similar to" — every code step has concrete code. README Task 5 uses concrete table rows + grep. ✓

**Type consistency:** `_catalog_cert_ids(client, *, permission, patterns, cert_type=None)`, `_action_row(cert_id, response)`, `_fanout(client, cert_ids, action, *, force=False) -> (list, ExitCode)` — signatures defined in Task 3, consumed in Tasks 3 & 4. Catalog `permission` allowed-set (`read|issue|renew|status|revoke`) consistent between route (Task 1) and CLI callers (`issue`/`renew`/`revoke`, Tasks 3-4). `cert.type.value` and `CertStatus.ISSUED/RENEWED` match existing usage. Per-cert routes reuse the revoke route's 200/409 shape. ✓
