# New API Endpoints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add five HTTP API features to cert-hub: Prometheus `/api/metrics` (auth+RBAC), `/api/version` build metadata, raw-PEM download, single-cert revoke, and a config reload endpoint.

**Architecture:** New RBAC actions (`revoke`, `reload`) extend the existing `<scope>:<action>` model; a new abstract `Cert.revoke` with subclass implementations and a `CertBot.revoke` certbot wrapper back the revoke endpoint; a pure `render_metrics` function backs the metrics endpoint; new Flask routes wire it all into `routes.py`. Reload sends `SIGHUP` to the gunicorn master.

**Tech Stack:** Python 3.12+, Flask, certbot, cryptography, pytest.

## Global Constraints

- New `PermissionAction` members: `REVOKE = "revoke"`, `RELOAD = "reload"`. New `CertStatus.REVOKED = "REVOKED"`.
- `/api/metrics`: requires Bearer auth; emits metrics only for certs the identity has `status` permission on. Prometheus text format, `Content-Type: text/plain; version=0.0.4`.
- `/api/version`: stays unauthenticated; adds `git_sha` (env `GIT_SHA`, default `"unknown"`) and `build_date` (env `BUILD_DATE`, default `"unknown"`).
- `GET /api/certs/<id>/pem?type=bundle|cert|chain|privkey` (default `bundle`): requires `read`; returns raw PEM `text/plain`; `bundle` = certificate+chain+private_key (empty parts skipped).
- `POST /api/certs/<id>/revoke`: requires `revoke`; static cert → `CertException(NOT_SUPPORTED)`; LE → `certbot revoke --cert-path <live/<id>/cert.pem> --delete-after-revoke` then status becomes `NOT_ISSUED`; success response reports `REVOKED`.
- `POST /api/admin/reload`: requires `*:reload` (`identity.has_global_action(RELOAD)`); sends `os.kill(os.getppid(), signal.SIGHUP)`; returns `202`. Requires gunicorn.
- Cert type attribute is `cert.type` (ClassVar[CertType]); `CertType` lives in `cert_hub/domain/cert_type.py`.
- `CertException` is a plain `Exception` (NOT auto-handled by an errorhandler) — routes that call cert methods must catch it and return a JSON response. `CertBotError` IS an `ApiError` (auto-handled → 502).
- Tests must not require the `certbot` binary nor the route53/cloudflare DNS plugins (venv has only Flask, PyYAML, cryptography, pytest). Flask routes and SIGHUP are not unit-tested — verify via `make lint` + review; domain/pure logic IS unit-tested.
- `make test` runs pytest from inside `tests/`; `PYTEST_FLAGS` paths are relative to `tests/`.
- This work is intentionally NOT committed (user instruction). Each task ends WITHOUT a git commit; do not stage/branch/revert or touch unrelated pre-existing working-tree changes.

---

### Task 1: New RBAC actions + `Identity.has_global_action`

**Files:**
- Modify: `cert_hub/domain/permission.py`
- Modify: `cert_hub/domain/identity.py`
- Test: `tests/test_permission.py` (create)

**Interfaces:**
- Produces: `PermissionAction.REVOKE` (`"revoke"`), `PermissionAction.RELOAD` (`"reload"`); `Identity.has_global_action(action: PermissionAction) -> bool`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_permission.py`:

```python
import pytest
from cert_hub.domain.permission import Permission, PermissionAction
from cert_hub.domain.identity import Identity


def test_new_actions_present():
    assert "revoke" in PermissionAction.values()
    assert "reload" in PermissionAction.values()


def test_permission_from_string_parses_reload():
    p = Permission.from_string(0, "*:reload")
    assert p.scope == "*"
    assert p.action == PermissionAction.RELOAD


def test_permission_from_string_parses_revoke():
    p = Permission.from_string(0, "example.com:revoke")
    assert p.scope == "example.com"
    assert p.action == PermissionAction.REVOKE


def _identity(permissions):
    return Identity(id="admin", hmac_hex="x" * 64, allowed_cidrs=[], permissions=permissions)


def test_has_global_action_true_for_star_reload():
    ident = _identity([Permission("*", PermissionAction.RELOAD)])
    assert ident.has_global_action(PermissionAction.RELOAD) is True


def test_has_global_action_true_for_star_any():
    ident = _identity([Permission("*", PermissionAction.ANY)])
    assert ident.has_global_action(PermissionAction.RELOAD) is True


def test_has_global_action_false_for_scoped_or_missing():
    assert _identity([Permission("example.com", PermissionAction.RELOAD)]).has_global_action(PermissionAction.RELOAD) is False
    assert _identity([Permission("*", PermissionAction.READ)]).has_global_action(PermissionAction.RELOAD) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test PYTEST_FLAGS="-q test_permission.py"`
Expected: FAIL — `RELOAD`/`REVOKE` and `has_global_action` don't exist.

- [ ] **Step 3: Add the new actions**

In `cert_hub/domain/permission.py`, add to `PermissionAction` after `STATUS = "status"`:

```python
    REVOKE = "revoke"
    RELOAD = "reload"
```

- [ ] **Step 4: Add `has_global_action` to `Identity`**

In `cert_hub/domain/identity.py`, import the action type — change `from cert_hub.domain.permission import Permission` to:
```python
from cert_hub.domain.permission import Permission, PermissionAction
```
and add this method to `Identity` (e.g. after `is_ip_allowed`):
```python
    def has_global_action(self, action: PermissionAction) -> bool:
        for permission in self.permissions:
            if permission.scope == "*" and permission.action in (action, PermissionAction.ANY):
                return True
        return False
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `make test PYTEST_FLAGS="-q test_permission.py"`
Expected: all PASS.

- [ ] **Step 6: Full sweep**

Run: `make test && make lint`
Expected: all pass; `py_compile` → `OK`.

(No commit.)

---

### Task 2: Revoke — domain + certbot

**Files:**
- Modify: `cert_hub/domain/cert_status.py` (add `REVOKED`)
- Modify: `cert_hub/domain/cert.py` (abstract `revoke`)
- Modify: `cert_hub/domain/static_cert.py` (`revoke` → NOT_SUPPORTED)
- Modify: `cert_hub/domain/letsencrypt_cert.py` (`revoke`)
- Modify: `cert_hub/domain/cert_bot.py` (`revoke(cert_name)`)
- Test: `tests/test_cert_bot.py` (extend), `tests/test_static_cert.py` (extend)

**Interfaces:**
- Consumes: existing `CertBot.get_cert_path`, `CertBot._run_cmd`, `CertBot.base_args`, `CertBotError`, `CertException`, `CertStatus`.
- Produces: `CertStatus.REVOKED`; abstract `Cert.revoke(self) -> None`; `StaticCert.revoke` raises `CertException(NOT_SUPPORTED)`; `LetsEncryptCert.revoke` calls `CertBot.revoke`; `CertBot.revoke(cert_name: str) -> None`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cert_bot.py` (add `from types import SimpleNamespace` at the top if not present; `CertBot` is already imported):

```python
def test_revoke_builds_command(monkeypatch):
    from cert_hub.domain.cert_bot import CertBot as _CertBot
    certbot = _make_certbot()
    captured = {}

    def fake_run(self, args, **kwargs):
        captured["cmd"] = [str(a) for a in args]
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(_CertBot, "_run_cmd", fake_run)
    certbot.revoke("example")

    cmd = captured["cmd"]
    assert cmd[1] == "revoke"
    assert "--delete-after-revoke" in cmd
    assert "--cert-path" in cmd
    assert str(certbot.get_cert_path("example")) in cmd


def test_revoke_raises_certbot_error_on_failure(monkeypatch):
    from cert_hub.domain.cert_bot import CertBot as _CertBot
    from cert_hub.exception.cert_exceptions import CertBotError
    certbot = _make_certbot()

    def fake_run(self, args, **kwargs):
        return SimpleNamespace(returncode=1, stderr="boom")

    monkeypatch.setattr(_CertBot, "_run_cmd", fake_run)
    with pytest.raises(CertBotError):
        certbot.revoke("example")
```

Append to `tests/test_static_cert.py`:

```python
def test_revoke_not_supported(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem, key_pem)
    with pytest.raises(CertException) as exc:
        sc.revoke()
    assert exc.value.status == CertStatus.NOT_SUPPORTED
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test PYTEST_FLAGS="-q test_cert_bot.py test_static_cert.py"`
Expected: FAIL — `CertBot.revoke` and `StaticCert.revoke` don't exist.

- [ ] **Step 3: Add `CertStatus.REVOKED`**

In `cert_hub/domain/cert_status.py`, add inside the enum:
```python
    REVOKED = "REVOKED"
```

- [ ] **Step 4: Add `CertBot.revoke`**

In `cert_hub/domain/cert_bot.py`, add after `renew` (before `get_cert_path`):
```python
    def revoke(self, cert_name: str) -> None:
        cmd = [
            str(self.exe_path),
            "revoke",
            "--cert-path", str(self.get_cert_path(cert_name)),
            "--delete-after-revoke",
            *self.base_args
        ]
        log.debug(f"Certbot revoke command for '{cert_name}' certificate: {' '.join(cmd)}")

        result = self._run_cmd(cmd)
        if result.returncode != 0:
            raise CertBotError(cert_name, return_code=result.returncode, cmd=cmd, output=result.stderr)
```

- [ ] **Step 5: Add abstract `revoke` to `Cert`**

In `cert_hub/domain/cert.py`, add after the abstract `renew`:
```python
    @abstractmethod
    def revoke(self) -> None: ...
```

- [ ] **Step 6: Implement `StaticCert.revoke`**

In `cert_hub/domain/static_cert.py`, add (next to `issue`/`renew`):
```python
    def revoke(self) -> None:
        raise CertException(self.id, "Static certificates cannot be revoked; manage their files manually", status=CertStatus.NOT_SUPPORTED)
```

- [ ] **Step 7: Implement `LetsEncryptCert.revoke`**

In `cert_hub/domain/letsencrypt_cert.py`, add (next to `issue`/`renew`):
```python
    def revoke(self) -> None:
        log.debug(f"Revoking '{self}' certificate...")
        if not self.is_issued():
            raise CertException(self.id, "Certificate not issued", status=CertStatus.NOT_ISSUED)
        certbot = CertBot.get_from_global_context()
        certbot.revoke(self.id)
        log.info(f"Successfully revoked '{self}' certificate")
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `make test PYTEST_FLAGS="-q test_cert_bot.py test_static_cert.py"`
Expected: all PASS (existing + new).

- [ ] **Step 9: Full sweep**

Run: `make test && make lint`
Expected: all pass; `py_compile` → `OK`.

(No commit.)

---

### Task 3: Prometheus metrics renderer

**Files:**
- Create: `cert_hub/api/metrics.py`
- Test: `tests/test_metrics.py` (create)

**Interfaces:**
- Produces: `render_metrics(records: list[dict], build_info: dict) -> str`. Each record: `{"id": str, "type": str, "status": str, "expiry_ts": int | None, "days_to_expire": int | None}`. `build_info`: `{"version": str, "git_sha": str}`. Output is Prometheus text exposition ending with a newline.

- [ ] **Step 1: Write the failing test**

Create `tests/test_metrics.py`:

```python
from cert_hub.api.metrics import render_metrics


def test_render_metrics_emits_families_and_values():
    records = [
        {"id": "a", "type": "letsencrypt", "status": "OK", "expiry_ts": 1800000000, "days_to_expire": 40},
        {"id": "b", "type": "static", "status": "CERT_MISSING", "expiry_ts": None, "days_to_expire": None},
    ]
    out = render_metrics(records, {"version": "1.2.3", "git_sha": "abc123"})

    assert 'certhub_build_info{version="1.2.3",git_sha="abc123"} 1' in out
    assert 'certhub_cert_expiry_timestamp_seconds{id="a",type="letsencrypt"} 1800000000' in out
    assert 'certhub_cert_days_to_expire{id="a",type="letsencrypt"} 40' in out
    assert 'certhub_cert_status{id="a",type="letsencrypt",status="OK"} 1' in out
    assert 'certhub_cert_status{id="b",type="static",status="CERT_MISSING"} 1' in out
    # b has no expiry/days metrics
    assert 'certhub_cert_expiry_timestamp_seconds{id="b"' not in out
    assert 'certhub_cert_days_to_expire{id="b"' not in out
    assert "# TYPE certhub_cert_status gauge" in out
    assert out.endswith("\n")


def test_render_metrics_escapes_label_values():
    records = [{"id": 'a"x', "type": "static", "status": "OK", "expiry_ts": None, "days_to_expire": None}]
    out = render_metrics(records, {"version": "v", "git_sha": "s"})
    assert 'id="a\\"x"' in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `make test PYTEST_FLAGS="-q test_metrics.py"`
Expected: FAIL — `cert_hub.api.metrics` does not exist.

- [ ] **Step 3: Implement the renderer**

Create `cert_hub/api/metrics.py`:

```python
def _escape_label(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_metrics(records: list[dict], build_info: dict) -> str:
    lines: list[str] = []

    lines.append("# HELP certhub_build_info Build information.")
    lines.append("# TYPE certhub_build_info gauge")
    lines.append(
        f'certhub_build_info{{version="{_escape_label(build_info.get("version", ""))}",'
        f'git_sha="{_escape_label(build_info.get("git_sha", ""))}"}} 1'
    )

    lines.append("# HELP certhub_cert_expiry_timestamp_seconds Certificate expiry as a unix timestamp.")
    lines.append("# TYPE certhub_cert_expiry_timestamp_seconds gauge")
    for record in records:
        if record.get("expiry_ts") is not None:
            lines.append(
                f'certhub_cert_expiry_timestamp_seconds{{id="{_escape_label(record["id"])}",'
                f'type="{_escape_label(record["type"])}"}} {int(record["expiry_ts"])}'
            )

    lines.append("# HELP certhub_cert_days_to_expire Days until certificate expiry.")
    lines.append("# TYPE certhub_cert_days_to_expire gauge")
    for record in records:
        if record.get("days_to_expire") is not None:
            lines.append(
                f'certhub_cert_days_to_expire{{id="{_escape_label(record["id"])}",'
                f'type="{_escape_label(record["type"])}"}} {int(record["days_to_expire"])}'
            )

    lines.append("# HELP certhub_cert_status Current certificate status (value is always 1; the status is a label).")
    lines.append("# TYPE certhub_cert_status gauge")
    for record in records:
        lines.append(
            f'certhub_cert_status{{id="{_escape_label(record["id"])}",'
            f'type="{_escape_label(record["type"])}",'
            f'status="{_escape_label(record["status"])}"}} 1'
        )

    return "\n".join(lines) + "\n"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `make test PYTEST_FLAGS="-q test_metrics.py"`
Expected: all PASS.

- [ ] **Step 5: Full sweep**

Run: `make test && make lint`
Expected: all pass; `py_compile` → `OK`.

(No commit.)

---

### Task 4: Routes — version metadata, PEM download, metrics

**Files:**
- Modify: `cert_hub/api/routes.py`

**Interfaces:**
- Consumes: `render_metrics` (Task 3), `query_one_of` (existing in `validators.py`), `Context.resolve_scope`, `Config.get_from_global_context`, `cert.get_certificate/get_chain/get_private_key/get_status/get_expire_date/get_days_to_expire`, `cert.type`, `PermissionAction.READ/STATUS`, `CertException`.
- Produces: extended `/api/version`; `GET /api/certs/<cert_id>/pem`; `GET /api/metrics`.

- [ ] **Step 1: Update imports**

In `cert_hub/api/routes.py`, change the validators import line to add `query_one_of`:
```python
from cert_hub.api.validators import query_list, query_bool, query_one_of
```
and add after the existing imports:
```python
from cert_hub.api.metrics import render_metrics
```

- [ ] **Step 2: Add `git_sha` and `build_date` to `/api/version`**

Replace the `payload` dict in `version()`:
```python
    payload = {
        "name": "Cert Hub",
        "author": "karol@siedlaczek.com.pl",
        "app": os.environ.get("APP_VERSION", "unknown"),
        "git_sha": os.environ.get("GIT_SHA", "unknown"),
        "build_date": os.environ.get("BUILD_DATE", "unknown"),
        "python": platform.python_version()
    }
```

- [ ] **Step 3: Add the PEM download route**

Add (e.g. after the `/api/certs/status` route):
```python
@api.route("/api/certs/<cert_id>/pem", methods=["GET"])
def cert_pem(cert_id: str) -> Response:
    pem_type = query_one_of("type", default="bundle", allowed=["bundle", "cert", "chain", "privkey"])
    ctx = Context.authenticate()
    cert = ctx.resolve_scope([cert_id], PermissionAction.READ)[0]

    try:
        if pem_type == "cert":
            body = cert.get_certificate()
        elif pem_type == "chain":
            body = cert.get_chain()
        elif pem_type == "privkey":
            body = cert.get_private_key()
        else:
            parts = [p.strip() for p in (cert.get_certificate(), cert.get_chain(), cert.get_private_key()) if p]
            body = "\n".join(parts) + "\n"
        log_request(get_log_record(cert.get_status(), cert, f"Served PEM '{pem_type}'"), identity=ctx.identity, level="info")
        return Response(body, mimetype="text/plain")
    except CertException as e:
        log_request(get_log_record(e.status, e.cert_id, e.msg), identity=ctx.identity, level="warning")
        return build_response(409, msg=e.msg, detail={"id": cert.id, "status": e.status.value})
```

- [ ] **Step 4: Add the metrics route**

Add (e.g. after `/api/version`):
```python
@api.route("/api/metrics", methods=["GET"])
def metrics() -> Response:
    ctx = Context.authenticate()
    conf = Config.get_from_global_context()

    records = []
    for cert in conf.certs:
        if not cert.has_permission(ctx.identity, PermissionAction.STATUS):
            continue
        status = cert.get_status()
        expiry_ts = None
        days_to_expire = None
        try:
            expiry_ts = int(cert.get_expire_date().timestamp())
            days_to_expire = cert.get_days_to_expire()
        except CertException:
            pass
        records.append({
            "id": cert.id,
            "type": cert.type.value,
            "status": status.value,
            "expiry_ts": expiry_ts,
            "days_to_expire": days_to_expire,
        })

    build_info = {
        "version": os.environ.get("APP_VERSION", "unknown"),
        "git_sha": os.environ.get("GIT_SHA", "unknown"),
    }
    return Response(render_metrics(records, build_info), mimetype="text/plain; version=0.0.4")
```

- [ ] **Step 5: Verify compile + suite**

Run: `make lint`
Expected: `py_compile` → `OK`.

Run: `make test`
Expected: domain suite green (unchanged by routes).

- [ ] **Step 6: Self-check the routes**

Confirm by reading:
- `/api/metrics` only includes certs passing `has_permission(identity, STATUS)`; `get_expire_date()` is wrapped in `try/except CertException` so a missing/invalid cert still emits its `_status` line.
- the PEM route catches `CertException` (returns 409 JSON) and otherwise returns `text/plain`; `resolve_scope([cert_id], READ)[0]` is safe because `resolve_scope` raises (404/403) rather than returning an empty list.
- `query_one_of("type", default="bundle", allowed=[...])` rejects bad `type` with 400.

(No commit.)

---

### Task 5: Routes — revoke + admin reload

**Files:**
- Modify: `cert_hub/api/routes.py`

**Interfaces:**
- Consumes: `cert.revoke` (Task 2), `CertStatus.REVOKED` (Task 2), `PermissionAction.REVOKE/RELOAD` (Task 1), `identity.has_global_action` (Task 1), `require_auth`, `get_remote_ip`, `Context.resolve_scope`, `CertException`.
- Produces: `POST /api/certs/<cert_id>/revoke`; `POST /api/admin/reload`.

- [ ] **Step 1: Add `signal` import**

In `cert_hub/api/routes.py`, add to the top imports:
```python
import signal
```

- [ ] **Step 2: Add the revoke route**

Add (e.g. after the `/api/certs/renew` route):
```python
@api.route("/api/certs/<cert_id>/revoke", methods=["POST"])
def cert_revoke(cert_id: str) -> Response:
    ctx = Context.authenticate()
    cert = ctx.resolve_scope([cert_id], PermissionAction.REVOKE)[0]

    try:
        cert.revoke()
        status = CertStatus.REVOKED
        msg = "Certificate successfully revoked"
        log_request(get_log_record(status, cert, msg), identity=ctx.identity, level="info")
        return build_response(200, data={"id": cert.id, "type": cert.type.value, "status": status.value, "msg": msg})
    except CertException as e:
        log_request(get_log_record(e.status, e.cert_id, e.msg), identity=ctx.identity, level="warning")
        return build_response(409, msg=e.msg, detail={"id": cert.id, "status": e.status.value})
```

- [ ] **Step 3: Add the admin reload route**

Add (e.g. after the revoke route):
```python
@api.route("/api/admin/reload", methods=["POST"])
def admin_reload() -> Response:
    remote_ip = get_remote_ip()
    identity = require_auth(remote_ip)

    if not identity.has_global_action(PermissionAction.RELOAD):
        return build_response(403, msg="Not allowed to reload configuration", detail={"identity": identity.id, "required": "*:reload"})

    master_pid = os.getppid()
    try:
        os.kill(master_pid, signal.SIGHUP)
    except OSError as e:
        log_request(f"Reload failed to signal master process: {e}", identity=identity, level="error")
        return build_response(502, msg="Failed to signal master process for reload", detail=str(e))

    log_request("Reload signal (SIGHUP) sent to master process", identity=identity, level="info")
    return build_response(202, msg="Reload signal sent to master process", data={"master_pid": master_pid})
```

- [ ] **Step 4: Verify compile + suite**

Run: `make lint`
Expected: `py_compile` → `OK`.

Run: `make test`
Expected: domain suite green.

- [ ] **Step 5: Self-check the routes**

Confirm by reading:
- revoke uses `PermissionAction.REVOKE` for scope resolution; static-cert `CertException(NOT_SUPPORTED)` and LE not-issued `CertException(NOT_ISSUED)` are caught → 409; a `CertBotError` (certbot failure) propagates to the existing `ApiError` handler → 502.
- reload uses `require_auth` + `has_global_action(RELOAD)` (NOT cert-scoped `resolve_scope`); returns 403 when unauthorized, 202 on signal sent, 502 on `OSError`.

(No commit.)

---

### Task 6: README documentation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add `GIT_SHA` and `BUILD_DATE` to the Environments table**

In `README.md`, after the `CERTBOT_TEST_CERT` row (or near other build/runtime envs), add:
```
| `GIT_SHA` | `string` | :x: | `unknown` | Build commit SHA, surfaced by `GET /api/version`. Set at image build time. |
| `BUILD_DATE` | `string` | :x: | `unknown` | Build date, surfaced by `GET /api/version`. Set at image build time. |
```

- [ ] **Step 2: Document the new endpoints in the API table**

In the API endpoints table, add rows:
```
| `GET` | `/api/metrics` | :heavy_check_mark: | - | Prometheus metrics for certificates the identity may `status` (expiry timestamp, days-to-expire, status). Requires `status`. |
| `GET` | `/api/certs/<id>/pem` | :heavy_check_mark: | `type` (`bundle`\|`cert`\|`chain`\|`privkey`, default `bundle`) | Returns raw PEM (`text/plain`) for one certificate. Requires `read`. |
| `POST` | `/api/certs/<id>/revoke` | :heavy_check_mark: | - | Revokes a Let's Encrypt certificate (`certbot revoke --delete-after-revoke`) and deletes its files; `static` → `NOT_SUPPORTED`. Requires `revoke`. |
| `POST` | `/api/admin/reload` | :heavy_check_mark: | - | Reloads configuration by sending `SIGHUP` to the gunicorn master (reloads all workers). Requires `*:reload`. |
```

- [ ] **Step 3: Document the new permission actions**

In the `identities[].permissions` section where actions are listed (currently `status`, `read`, `issue`, `renew`, or `*`), add `revoke` and `reload`, noting that `reload` is a global action used as `*:reload`.

- [ ] **Step 4: Verify references**

Run: `grep -n "api/metrics\|/revoke\|/reload\|GIT_SHA\|BUILD_DATE\|api/certs/<id>/pem" README.md`
Expected: matches for each new env/endpoint.

(No commit.)

---

### Task 7: Full verification sweep

**Files:** none (verification only).

- [ ] **Step 1: Run the entire test suite**

Run: `make test`
Expected: all tests pass (existing + `test_permission.py`, `test_metrics.py`, extended `test_cert_bot.py`/`test_static_cert.py`).

- [ ] **Step 2: Run lint**

Run: `make lint`
Expected: `py_compile` → `OK`.

- [ ] **Step 3 (optional, if Docker available): build the image**

Run: `make build`
Expected: image builds.

---

## Self-Review

**Spec coverage:**
- New actions `revoke`/`reload` + `has_global_action` → Task 1. ✓
- `CertStatus.REVOKED`, `Cert.revoke` abstract, static/LE `revoke`, `CertBot.revoke` → Task 2. ✓
- `render_metrics` pure function → Task 3. ✓
- `/api/version` git_sha+build_date; `/api/certs/<id>/pem`; `/api/metrics` (RBAC by STATUS) → Task 4. ✓
- `/api/certs/<id>/revoke`; `/api/admin/reload` (SIGHUP, `*:reload`) → Task 5. ✓
- README env + endpoints + permissions → Task 6. ✓
- CertException caught in pem/revoke routes (not auto-handled); CertBotError → 502 via ApiError handler → noted in Tasks 4/5. ✓
- Tests avoid certbot/DNS plugins; routes/SIGHUP lint-only → respected across tasks. ✓

**Placeholder scan:** No TBD/TODO/"handle errors"/"similar to" — every code step has concrete code. README Task 6 uses concrete table rows + grep checks. ✓

**Type consistency:** `PermissionAction.REVOKE`/`RELOAD` and `has_global_action(action)` defined in Task 1, consumed in Tasks 2/5. `CertBot.revoke(cert_name)` defined Task 2, called by `LetsEncryptCert.revoke` (Task 2) and indirectly by route (Task 5). `cert.revoke()` (no args) consistent across base/subclasses/routes. `render_metrics(records, build_info)` signature identical in Task 3 (def) and Task 4 (call); record keys (`id`,`type`,`status`,`expiry_ts`,`days_to_expire`) consistent. `cert.type.value` used in routes matches the `type: ClassVar[CertType]` attribute. `query_one_of("type", default="bundle", allowed=[...])` returns a plain string compared against `"cert"/"chain"/"privkey"/"bundle"`. ✓
