# REVOKED Lifecycle + update-in-place Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist a `REVOKED` status across `certbot revoke --delete-after-revoke` (which wipes the cert files) via a marker file, surface it through `/api/certs`, and have the CLI `update-in-place` remove a revoked cert's local files.

**Architecture:** `CertBot` writes/reads/clears a marker `<CERTBOT_DIR>/revoked/<id>`; `LetsEncryptCert.revoke` marks, `issue` clears, and `get_status` reports `REVOKED` when the cert is not issued but a marker exists. `cert_list` is fixed to report the (non-raising) status even when PEM accessors raise. `update-in-place` deletes `<prefix>_<type>.pem` files for certs whose server status is `REVOKED`.

**Tech Stack:** Python 3.12+, Flask, certbot, Typer/requests (CLI), pytest.

## Global Constraints

- Marker file: `<CERTBOT_DIR>/revoked/<cert_id>` (i.e. `CertBot` base_dir `/ "revoked" / <id>`), content = UTC ISO timestamp. `CERTBOT_DIR` is the persistent certbot base dir.
- `CertStatus.REVOKED` already exists — reused as the persistent status.
- `is_issued()` (files present) takes precedence in `get_status()`: a re-issued cert never reports REVOKED; the marker is only consulted when files are absent.
- Static certs: revoke unsupported → never marked; `StaticCert.get_status` unchanged.
- `update-in-place` on server status `REVOKED`: delete the run's `<prefix>_<type>.pem` files (the `--pem` types); result code `OK`, msg lists removed files; counts toward `is_any_updated` (→ triggers `--post-hook`) UNLESS `--omit-post-hook-on-revoke` is set (then it does not trigger the hook).
- Current module paths: `cert_hub/domain/cert/cert_bot.py`, `cert_hub/domain/cert/letsencrypt_cert.py`, `cert_hub/api/routes.py`, `certhub.py`. `CertBot` is a frozen dataclass; `CertException`, `CertStatus`, `CertBotError` live under `cert_hub/exception/*` and `cert_hub/domain/cert/cert_status.py`.
- Flask routes and the Typer CLI are NOT unit-tested (no HTTP fixture; venv lacks typer/requests). Verify routes/CLI via `make lint` + `tests/.venv/bin/python -c "import cert_hub.api.routes"` + review. Domain logic IS unit-tested. `make test` must stay green.
- This work is intentionally NOT committed (user instruction). Each task ends WITHOUT a git commit; do not stage/branch/revert or touch unrelated pre-existing working-tree changes.

---

### Task 1: `CertBot` revoke marker (`revoked_dir` + mark/is/clear)

**Files:**
- Modify: `cert_hub/domain/cert/cert_bot.py`
- Test: `tests/test_cert_bot.py` (extend)

**Interfaces:**
- Produces: `CertBot.revoked_dir: Path` (= base_dir/"revoked"); `CertBot.mark_revoked(cert_name: str) -> None`; `CertBot.is_revoked(cert_name: str) -> bool`; `CertBot.clear_revoked(cert_name: str) -> None`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_cert_bot.py` (add `from pathlib import Path` if not already imported; `CertBot` is imported):

```python
def test_revoked_marker_mark_is_clear(tmp_path):
    certbot = CertBot.load(
        acme_server="https://acme.example/directory",
        base_dir=tmp_path,
        exe_path=Path("/usr/bin/certbot"),
        renew_before_days=30,
    )
    assert certbot.revoked_dir == tmp_path / "revoked"
    assert certbot.is_revoked("example") is False

    certbot.mark_revoked("example")
    assert certbot.is_revoked("example") is True
    assert (tmp_path / "revoked" / "example").exists()

    certbot.clear_revoked("example")
    assert certbot.is_revoked("example") is False
    certbot.clear_revoked("example")  # idempotent, must not raise
```

- [ ] **Step 2: Run test to verify it fails**

Run: `make test PYTEST_FLAGS="-q test_cert_bot.py::test_revoked_marker_mark_is_clear"`
Expected: FAIL — `revoked_dir` / `mark_revoked` don't exist.

- [ ] **Step 3: Add the `revoked_dir` field**

In `cert_hub/domain/cert/cert_bot.py`, add to the `CertBot` dataclass after `base_args: Sequence[str]` (before the defaulted `cloudflare_dns_api_token`):

```python
    revoked_dir: Path
```

- [ ] **Step 4: Compute `revoked_dir` in `load`**

In `load()`, after `conf_dir = base_dir / "config"`, add:
```python
        revoked_dir = base_dir / "revoked"
```
and add to the `return cls(...)` call (before `cloudflare_dns_api_token=...`):
```python
            revoked_dir = revoked_dir,
```

- [ ] **Step 5: Add the marker methods + datetime import**

At the top of `cert_bot.py`, ensure `from datetime import datetime, timezone` is imported (add it if missing).

Add these methods to `CertBot` (e.g. after `get_private_key_path`):
```python
    def mark_revoked(self, cert_name: str) -> None:
        self.revoked_dir.mkdir(parents=True, exist_ok=True)
        (self.revoked_dir / cert_name).write_text(datetime.now(timezone.utc).isoformat(), encoding="UTF-8")

    def is_revoked(self, cert_name: str) -> bool:
        return (self.revoked_dir / cert_name).exists()

    def clear_revoked(self, cert_name: str) -> None:
        (self.revoked_dir / cert_name).unlink(missing_ok=True)
```

- [ ] **Step 6: Run test to verify it passes**

Run: `make test PYTEST_FLAGS="-q test_cert_bot.py"`
Expected: all PASS (existing + new).

- [ ] **Step 7: Full sweep**

Run: `make test && make lint`
Expected: all pass; `py_compile` → `OK`.

(No commit.)

---

### Task 2: `LetsEncryptCert` marker integration (revoke/issue/get_status)

**Files:**
- Modify: `cert_hub/domain/cert/letsencrypt_cert.py`
- Test: `tests/test_letsencrypt_cert.py` (extend)

**Interfaces:**
- Consumes: `CertBot.mark_revoked/is_revoked/clear_revoked` (Task 1), `CertStatus.REVOKED`.
- Produces: `LetsEncryptCert.revoke` marks revoked; `issue` clears marker; `get_status` returns `REVOKED` when not issued and marker present.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_letsencrypt_cert.py` (reuses `_le_cert`, `_patch_certbot`; uses `SimpleNamespace`):

```python
def _fake_certbot_no_files(tmp_path, *, revoked: bool, calls: dict | None = None):
    # cert files absent → is_issued() False; is_revoked controllable; record mark/clear calls
    missing = tmp_path / "nope"
    ns = SimpleNamespace(
        get_cert_path=lambda _id: missing / "cert.pem",
        get_chain_path=lambda _id: missing / "chain.pem",
        get_private_key_path=lambda _id: missing / "privkey.pem",
        renew_before_days=30,
        is_revoked=lambda _id: revoked,
        mark_revoked=lambda _id: (calls or {}).__setitem__("mark", _id),
        clear_revoked=lambda _id: (calls or {}).__setitem__("clear", _id),
        revoke=lambda _id: (calls or {}).__setitem__("revoke", _id),
    )
    return ns


def test_get_status_revoked_when_marker_present(tmp_path, monkeypatch):
    _patch_certbot(monkeypatch, _fake_certbot_no_files(tmp_path, revoked=True))
    assert _le_cert().get_status() == CertStatus.REVOKED


def test_get_status_not_issued_when_no_marker(tmp_path, monkeypatch):
    _patch_certbot(monkeypatch, _fake_certbot_no_files(tmp_path, revoked=False))
    assert _le_cert().get_status() == CertStatus.NOT_ISSUED


def test_revoke_marks_revoked(tmp_path, monkeypatch):
    calls: dict = {}
    fake = _fake_certbot_no_files(tmp_path, revoked=False, calls=calls)
    # make is_issued() True so revoke()'s _require_issued passes: point files at real ones
    cert_file = tmp_path / "cert.pem"; cert_file.write_text("x")
    chain_file = tmp_path / "chain.pem"; chain_file.write_text("x")
    key_file = tmp_path / "privkey.pem"; key_file.write_text("x")
    fake.get_cert_path = lambda _id: cert_file
    fake.get_chain_path = lambda _id: chain_file
    fake.get_private_key_path = lambda _id: key_file
    _patch_certbot(monkeypatch, fake)
    _le_cert().revoke()
    assert calls.get("revoke") == "x"
    assert calls.get("mark") == "x"
```

(Note: `_le_cert()` builds a `LetsEncryptCert` with `id="x"`; adjust the id assertions to whatever `_le_cert` uses — confirm by reading the existing helper at the top of `tests/test_letsencrypt_cert.py`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test PYTEST_FLAGS="-q test_letsencrypt_cert.py"`
Expected: FAIL — `get_status` doesn't consult the marker; `revoke` doesn't call `mark_revoked`.

- [ ] **Step 3: Update `get_status` to consult the marker**

In `cert_hub/domain/cert/letsencrypt_cert.py`, change the `not is_issued()` branch:
```python
    def get_status(self) -> CertStatus:
        if not self.is_issued():
            certbot = CertBot.get_from_global_context()
            return CertStatus.REVOKED if certbot.is_revoked(self.id) else CertStatus.NOT_ISSUED
        try:
            return self._expiry_status()
        except CertException as e:
            return e.status
```

- [ ] **Step 4: Mark on revoke**

In `revoke()`, after `certbot.revoke(self.id)`:
```python
    def revoke(self) -> None:
        log.debug(f"Revoking '{self}' certificate...")
        self._require_issued()
        certbot = CertBot.get_from_global_context()
        certbot.revoke(self.id)
        certbot.mark_revoked(self.id)
        log.info(f"Successfully revoked '{self}' certificate")
```

- [ ] **Step 5: Clear on issue**

In `issue()`, after the successful `certbot.issue(...)` call, add `certbot.clear_revoked(self.id)`:
```python
        certbot = CertBot.get_from_global_context()
        certbot.issue(self.id, self.domains, self.email, self.dns_provider)
        certbot.clear_revoked(self.id)

        log.info(f"Successfully issued '{self}' certificate with expiration date to {self.get_expire_date_as_str()}")
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `make test PYTEST_FLAGS="-q test_letsencrypt_cert.py"`
Expected: all PASS.

- [ ] **Step 7: Full sweep**

Run: `make test && make lint`
Expected: all pass; `py_compile` → `OK`.

(No commit.)

---

### Task 3: Surface `REVOKED` in `/api/certs` (`cert_list` fix)

**Files:**
- Modify: `cert_hub/api/routes.py`

**Interfaces:**
- Consumes: `cert.get_status()` (non-raising; Task 2).
- Produces: `cert_list` reports the persistent status (incl. `REVOKED`) even when PEM accessors raise.

- [ ] **Step 1: Move status out of the try and use it in the except**

In `cert_hub/api/routes.py`, replace the `for cert in certs:` loop body of `cert_list` with:

```python
    for cert in certs:
        status = cert.get_status()
        try:
            msg = "Certificate successfully fetched"
            payload.append({
                "id": cert.id,
                "type": cert.type.value,
                "status": status.value,
                "msg": msg,
                "custom_attrs": cert.custom_attrs,
                "domains": cert.domains,
                "expire_date": cert.get_expire_date_as_str(),
                "days_to_expire": cert.get_days_to_expire(),
                "chain": cert.get_chain(),
                "certificate": cert.get_certificate(),
                "private_key": cert.get_private_key()
            })
            log_request(get_log_record(status, cert, msg), identity=ctx.identity, level="info")
        except CertException as e:  # e.g. not issued / revoked (PEM material unavailable)
            payload.append({
                "id": cert.id,
                "type": cert.type.value,
                "status": status.value,
                "msg": e.msg,
                "custom_attrs": cert.custom_attrs,
                "domains": cert.domains,
                "expire_date": None,
                "days_to_expire": None,
                "chain": None,
                "certificate": None,
                "private_key": None
            })
            log_request(get_log_record(status, cert, e.msg), identity=ctx.identity, level="info")
```

- [ ] **Step 2: Verify import + compile + suite**

Run: `tests/.venv/bin/python -c "import cert_hub.api.routes"`
Expected: clean import.

Run: `make lint` → `py_compile` OK.
Run: `make test` → domain suite green.

- [ ] **Step 3: Self-check**

Confirm: `status` is computed once before the `try` (so it survives the PEM-accessor exception), the `except` reports `status.value` (REVOKED/NOT_ISSUED) with `e.msg` as the message, and `get_log_record` uses `status`.

(No commit.)

---

### Task 4: `update-in-place` cleanup of REVOKED certs (CLI)

**Files:**
- Modify: `certhub.py`

**Interfaces:**
- Consumes: server `/api/certs` now reports `status == "REVOKED"` (Task 3); existing `CertUpdateResult`, `ExitCode`, `pem_files`, `is_any_updated`/`--post-hook` machinery.
- Produces: `--omit-post-hook-on-revoke` option; a REVOKED cleanup branch in the per-cert loop.

- [ ] **Step 1: Add the `--omit-post-hook-on-revoke` option**

In `certhub.py`, in the `cert_update_in_place` command signature, add (next to the other options, e.g. after `post_hook`):
```python
    omit_post_hook_on_revoke: bool = typer.Option(
        False, "--omit-post-hook-on-revoke",
        help="Do not let revoked-cert cleanup trigger --post-hook (cleanup still happens and is reported)"
    ),
```

- [ ] **Step 2: Add the REVOKED cleanup branch**

In the per-cert loop, immediately after `private_key = cert.get("private_key")` and BEFORE the `if "certificate" in fields and not certificate:` check, insert:

```python
        if cert.get("status") == "REVOKED":
            removed = []
            for pem_file in pem_files:
                if pem_file.exists():
                    pem_file.unlink()
                    removed.append(pem_file.name)
            results.append(CertUpdateResult(
                cert=cert_id,
                code=ExitCode.OK,
                pem_files=pem_files,
                remote_expire_date=None,
                local_expire_date=None,
                updated=bool(removed) and not omit_post_hook_on_revoke,
                msg=(f"Revoked on server; removed local files: {', '.join(removed)}" if removed
                     else "Revoked on server; no local files to remove")
            ))
            continue
```

- [ ] **Step 3: Verify compile**

Run: `make lint`
Expected: `py_compile` → `OK`.

Run: `make test`
Expected: domain suite green (unchanged by CLI edits).

- [ ] **Step 4: Self-check**

Confirm by reading:
- the REVOKED branch is placed before the "not issued"/missing-field checks (a revoked cert has null `certificate`, so it must be caught first).
- `updated` is True only when files were actually removed AND `--omit-post-hook-on-revoke` is not set, so the post-hook fires for cleanup by default and is suppressed by the flag.
- only existing `pem_files` are unlinked; owner/group/chmod are not applied.

(No commit.)

---

### Task 5: README documentation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document the REVOKED status + marker**

In `README.md`, where statuses / revoke are described, note: after `POST /api/certs/<id>/revoke` the certificate's files are deleted and its status becomes `REVOKED` (persisted via a marker under `<CERTBOT_DIR>/revoked/<id>`); a subsequent successful `issue` clears it.

- [ ] **Step 2: Document update-in-place cleanup + the flag**

In the `update-in-place` CLI docs, note: a certificate whose server status is `REVOKED` has its local `<prefix>_<type>.pem` files removed; this counts as a change and triggers `--post-hook` unless `--omit-post-hook-on-revoke` is passed.

- [ ] **Step 3: Verify references**

Run: `grep -n "REVOKED\|revoked/\|omit-post-hook-on-revoke" README.md`
Expected: matches for the status, marker dir, and the flag.

(No commit.)

---

### Task 6: Full verification sweep

**Files:** none (verification only).

- [ ] **Step 1: Import-check + lint + tests**

Run: `tests/.venv/bin/python -c "import cert_hub.api.routes; print('ok')"`
Expected: `ok`.

Run: `make lint`
Expected: `py_compile` → `OK`.

Run: `make test`
Expected: all tests pass (existing + new marker/get_status tests).

---

## Self-Review

**Spec coverage:**
- Marker persistence (revoked_dir + mark/is/clear) → Task 1. ✓
- revoke marks / issue clears / get_status reports REVOKED → Task 2. ✓
- `/api/certs` surfaces REVOKED (cert_list fix) → Task 3. ✓
- update-in-place cleanup of `<prefix>_<type>.pem` + `--omit-post-hook-on-revoke` + post-hook semantics → Task 4. ✓
- Marker at `<CERTBOT_DIR>/revoked/<id>` → Task 1 (base_dir/"revoked"). ✓
- is_issued precedence (re-issued never REVOKED) → Task 2 (get_status checks is_issued first). ✓
- Static unaffected → no task touches StaticCert (correct). ✓
- README → Task 5. ✓

**Placeholder scan:** No TBD/TODO/"handle errors"/"similar to" — every code step has concrete code. README Task 5 is prose-described doc edits with concrete grep checks. The Task 2 test note about `_le_cert`'s id is a real instruction to verify an existing helper, not a placeholder. ✓

**Type consistency:** `revoked_dir`/`mark_revoked`/`is_revoked`/`clear_revoked` defined in Task 1, consumed in Task 2 and the fake certbot in tests. `get_status` returns `CertStatus` (REVOKED/NOT_ISSUED/expiry). `cert_list` uses `status.value`. `update-in-place` matches `cert.get("status") == "REVOKED"` (the string value of `CertStatus.REVOKED`). `omit_post_hook_on_revoke` param name consistent between signature and the cleanup branch. ✓
