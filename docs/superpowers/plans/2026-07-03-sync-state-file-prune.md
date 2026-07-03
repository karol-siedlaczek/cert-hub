# cert sync state file + prune Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `cert sync` maintains a `.certhub-sync-state.json` file in dest-dir recording each synced cert's files with sha256, and on the next run removes files for certs no longer returned by the server (lost access / filter change), verifying the checksum before deleting.

**Architecture:** Extend the existing `cert_sync` command in `certhub.py`. Add module-level helpers for hashing and reading/writing the state file. After the per-cert loop, prune certs present in the prior state but absent from the current API response, then write the fresh state. A `--dry-run` flag makes every write/delete a no-op that is only reported.

**Tech Stack:** Python 3.12, Typer/Click CLI, `hashlib` (already imported), `pytest` with `typer.testing.CliRunner`.

## Global Constraints

- Target Python 3.12 (matches `tests/.venv`).
- State file fixed name: `.certhub-sync-state.json`, always active (no opt-in flag).
- State is a single flat document (NOT keyed per filter). The run's filter is stored informationally only.
- Checksum mismatch on prune → file left untouched, result row is `WARNING`.
- Prune cleanup counts as a change (triggers `--post-hook`) unless `--omit-post-hook-on-prune`.
- `--dry-run`: no PEM writes, no deletions, no state-file write; report "Would …".
- `--dest-dir`/`-d` becomes a clean positional argument (the short/long option is removed).
- Never abort the run on a state-file read/write error — log and continue (certs are already written).
- Follow existing code style in `certhub.py`; reuse `LOGGER`, `safe_str`, `_json_default`, `ExitCode`, `CertUpdateResult`.

---

### Task 1: Make `dest_dir` a positional argument

**Files:**
- Modify: `certhub.py:822-825` (the `dest_dir` option in `cert_sync`)
- Modify: `tests/test_sync.py` (`_invoke` helper, ~line 102)

**Interfaces:**
- Produces: `cert sync <DEST_DIR> [options]` — dest-dir is now positional (arg 1). No `-d`/`--dest-dir`.

- [ ] **Step 1: Update the `_invoke` test helper to pass dest-dir positionally**

In `tests/test_sync.py`, change the `_invoke` helper:

```python
def _invoke(tmp_path, extra_args, cert_dicts, monkeypatch):
    _patch_client(monkeypatch, cert_dicts)
    runner = CliRunner()
    args = ["cert", "sync", str(tmp_path)] + extra_args
    return runner.invoke(certhub.app, args, env=ENV)
```

- [ ] **Step 2: Run the existing suite to confirm it fails**

Run: `cd /home/karol-siedlaczek/repo/python/cert-hub && python -m pytest tests/test_sync.py -q`
Expected: FAIL — the command still declares `-d/--dest-dir` as an option, so a bare positional is rejected ("Got unexpected extra argument").

- [ ] **Step 3: Change the option to a positional argument**

In `certhub.py`, replace the `dest_dir` option (currently lines 822-825):

```python
    dest_dir: str = typer.Argument(
        ...,
        help="Directory containing certificate files to check and update"
    ),
```

- [ ] **Step 4: Run the suite to confirm it passes**

Run: `python -m pytest tests/test_sync.py -q`
Expected: PASS (all existing sync tests green with the positional argument).

- [ ] **Step 5: Commit**

```bash
git add certhub.py tests/test_sync.py
git commit -m "feat: make cert sync dest-dir a positional argument"
```

---

### Task 2: State-file helpers (hash, load, write, filter object)

**Files:**
- Modify: `certhub.py` (add helpers next to `write_status_file`, after line ~1393)
- Modify: `tests/test_sync.py` (add `import hashlib` near the top; add helper unit tests at end of file)

**Interfaces:**
- Produces:
  - `SYNC_STATE_FILENAME = ".certhub-sync-state.json"` (module constant)
  - `sha256_file(path: Path) -> str`
  - `state_filter_obj(patterns: list[str] | None, cert_type: str) -> dict` → `{"type": cert_type, "patterns": sorted(patterns or [])}` (the `--pattern` option defaults to `None`)
  - `load_sync_state(path: Path) -> dict` — returns `{}` on missing/corrupt (logs WARNING)
  - `write_sync_state(path: Path, filter_obj: dict, certs: list[dict], timestamp: datetime) -> None` — writes `{"version": 1, "filter": ..., "timestamp": ..., "certs": ...}`; never raises (logs on OSError)

- [ ] **Step 1: Write the failing tests**

Add `import hashlib` to the imports block of `tests/test_sync.py`, then append:

```python
def test_sha256_file(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"hello world")
    assert certhub.sha256_file(p) == hashlib.sha256(b"hello world").hexdigest()


def test_state_filter_obj_sorts_patterns():
    assert certhub.state_filter_obj(["b", "a"], "letsencrypt") == {
        "type": "letsencrypt", "patterns": ["a", "b"],
    }


def test_state_filter_obj_handles_none_patterns():
    assert certhub.state_filter_obj(None, "all") == {"type": "all", "patterns": []}


def test_load_sync_state_missing_returns_empty(tmp_path):
    assert certhub.load_sync_state(tmp_path / "nope.json") == {}


def test_load_sync_state_corrupt_returns_empty(tmp_path):
    p = tmp_path / "state.json"
    p.write_text("{ not valid json")
    assert certhub.load_sync_state(p) == {}


def test_write_then_load_roundtrip(tmp_path):
    p = tmp_path / "state.json"
    certhub.write_sync_state(
        p,
        {"type": "all", "patterns": []},
        [{"id": "c", "files": [{"file": "c_bundle.pem", "sha256": "abc"}]}],
        dt.datetime(2026, 7, 3, tzinfo=dt.timezone.utc),
    )
    loaded = certhub.load_sync_state(p)
    assert loaded["version"] == 1
    assert loaded["filter"] == {"type": "all", "patterns": []}
    assert loaded["certs"][0]["id"] == "c"
    assert loaded["certs"][0]["files"][0]["sha256"] == "abc"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_sync.py -q -k "sha256_file or state_filter_obj or sync_state or roundtrip"`
Expected: FAIL with `AttributeError: module 'certhub' has no attribute 'sha256_file'`.

- [ ] **Step 3: Implement the helpers**

In `certhub.py`, immediately after `write_status_file` (before `_json_default`, i.e. after line ~1393), add:

```python
SYNC_STATE_FILENAME = ".certhub-sync-state.json"


def sha256_file(path: Path) -> str:
    # Hash the raw bytes on disk so it matches for both freshly written PEM files
    # and pre-existing ("up to date") ones.
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def state_filter_obj(patterns: list[str] | None, cert_type: str) -> dict:
    # Recorded informationally in the state file; patterns sorted for a stable,
    # order-independent comparison against the previous run's filter. The
    # --pattern option defaults to None, so coalesce to an empty list.
    return {"type": cert_type, "patterns": sorted(patterns or [])}


def load_sync_state(path: Path) -> dict:
    # Read the persisted sync state. A missing or unparseable file is treated as
    # "no prior state" (empty) rather than aborting the run.
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="UTF-8"))
    except (OSError, ValueError) as e:
        LOGGER.warning(f"Failed to read sync state file '{path}', treating as empty: {safe_str(e)}")
        return {}


def write_sync_state(path: Path, filter_obj: dict, certs: list[dict], timestamp: datetime) -> None:
    # Persist the certs (and their file checksums) materialised this run so the
    # next run can detect and clean up ones the server no longer returns. Failure
    # to write is logged but does not abort — the certificate files are already on disk.
    payload = {
        "version": 1,
        "filter": filter_obj,
        "timestamp": timestamp,
        "certs": certs,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=_json_default) + "\n", encoding="UTF-8")
    except OSError as e:
        LOGGER.error(f"Failed to write sync state file '{path}': {safe_str(e)}")
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_sync.py -q -k "sha256_file or state_filter_obj or sync_state or roundtrip"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add certhub.py tests/test_sync.py
git commit -m "feat: add sync state file helpers (sha256, load, write)"
```

---

### Task 3: Add `--dry-run` and `--omit-post-hook-on-prune`; guard writes/deletes/post-hook

**Files:**
- Modify: `certhub.py` (`cert_sync` signature ~line 856-862; add/update write branch ~1029-1032; msg ~1043-1047; revoke branch ~940-955; post-hook guard ~1051)
- Modify: `tests/test_sync.py` (add dry-run tests)

**Interfaces:**
- Consumes: `_invoke` positional dest-dir (Task 1).
- Produces: two new options on `cert_sync` — `dry_run: bool` (`--dry-run`), `omit_post_hook_on_prune: bool` (`--omit-post-hook-on-prune`). In `--dry-run` mode no file is written or deleted and no post-hook runs.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_sync.py`:

```python
def test_dry_run_does_not_write_pem(tmp_path, monkeypatch):
    """--dry-run on an empty dir reports "Would add" and writes no PEM file."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(
        cert_id="mycert", certificate=cert_pem, private_key=key_pem,
        expire_date=not_after.strftime(DATE_FMT),
    )
    status_path = tmp_path / "status.json"

    result = _invoke(
        tmp_path, ["--dry-run", "--status-file", str(status_path)], [cert], monkeypatch
    )

    assert result.exit_code == 0, result.output
    assert not (tmp_path / "mycert_bundle.pem").exists()
    status = json.loads(status_path.read_text())
    assert status["result"][0]["msg"] == "Would add"
    assert status["result"][0]["updated"] is False


def test_dry_run_keeps_revoked_files(tmp_path, monkeypatch):
    """--dry-run leaves REVOKED cert files on disk and reports "would remove"."""
    cert_pem, key_pem, _ = _make_cert(days_valid=365)
    bundle = tmp_path / "mycert_bundle.pem"
    bundle.write_text(cert_pem + key_pem)
    cert = _cert_dict(cert_id="mycert", status="REVOKED")
    status_path = tmp_path / "status.json"

    result = _invoke(
        tmp_path, ["--dry-run", "--status-file", str(status_path)], [cert], monkeypatch
    )

    assert result.exit_code == 0, result.output
    assert bundle.exists()
    status = json.loads(status_path.read_text())
    assert "would remove" in status["result"][0]["msg"]
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/test_sync.py -q -k "dry_run"`
Expected: FAIL — `--dry-run` is an unknown option (Click errors, non-zero exit).

- [ ] **Step 3: Add the options to the signature**

In `certhub.py`, insert into `cert_sync`'s parameters immediately before `type: str = Opt.type()` (line ~862):

```python
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Report what would be added, updated or removed without writing PEM files, "
             "deleting anything, or updating the sync state file"
    ),
    omit_post_hook_on_prune: bool = typer.Option(
        False, "--omit-post-hook-on-prune",
        help="Do not let cleanup of certs no longer returned by the server trigger --post-hook "
             "(cleanup still happens and is reported)"
    ),
```

- [ ] **Step 4: Guard the revoke-branch deletion**

In `certhub.py`, replace the REVOKED branch body (lines ~940-955) with:

```python
        if cert.get("status") == "REVOKED":
            removed = []
            for pem_file in pem_files:
                if pem_file.exists():
                    if not dry_run:
                        pem_file.unlink()
                    removed.append(pem_file.name)
            verb = "would remove" if dry_run else "removed"
            results.append(CertUpdateResult(
                cert=cert_id,
                code=ExitCode.OK,
                pem_files=pem_files,
                remote_expire_date=None,
                local_expire_date=None,
                updated=bool(removed) and not omit_post_hook_on_revoke and not dry_run,
                msg=(f"Revoked on server; {verb} local files: {', '.join(removed)}" if removed else "Revoked on server; no local files to remove")
            ))
            continue
```

- [ ] **Step 5: Guard the add/update write and its result message**

In `certhub.py`, replace the write block (lines ~1029-1032):

```python
        # Add or update local certificate files
        if not dry_run:
            for pem_type, pem_file in zip(pem_types, pem_files):
                content = pem_content_for(pem_type, certificate, chain, private_key)
                _write_secure(pem_file, content, mode=chmod_mode, owner=owner, group=group)
```

Then replace the final `results.append(...)` of that branch (lines ~1043-1047):

```python
        if dry_run:
            msg = "Would update" if existed_before else "Would add"
        else:
            msg = "Updated" if existed_before else "Added"
        results.append(CertUpdateResult(
            cert=cert_id, code=ExitCode.OK, pem_files=pem_files,
            remote_expire_date=expire_date, local_expire_date=local_expire_date,
            updated=not dry_run, msg=msg
        ))
```

- [ ] **Step 6: Guard the post-hook**

In `certhub.py`, change the post-hook condition (line ~1051) from `if is_any_updated and post_hook:` to:

```python
    if is_any_updated and post_hook and not dry_run:
```

- [ ] **Step 7: Run to verify tests pass**

Run: `python -m pytest tests/test_sync.py -q`
Expected: PASS (new dry-run tests plus all existing tests).

- [ ] **Step 8: Commit**

```bash
git add certhub.py tests/test_sync.py
git commit -m "feat: add --dry-run and --omit-post-hook-on-prune to cert sync"
```

---

### Task 4: Write the state file after each run

**Files:**
- Modify: `certhub.py` (`cert_sync`: add `materialized` accumulator near `results` ~line 915; append in up-to-date branch ~1021-1027 and add/update branch ~end; write state before the final `CmdResult.from_dict` ~line 1067)
- Modify: `tests/test_sync.py` (add state-write tests)

**Interfaces:**
- Consumes: `sha256_file`, `state_filter_obj`, `write_sync_state`, `SYNC_STATE_FILENAME` (Task 2); `dry_run` (Task 3); `cert_type` (already computed at line ~899 as `CertType.from_string(type)`); `patterns` option.
- Produces: after a non-dry-run, `certs_dir / SYNC_STATE_FILENAME` exists with `version=1`, the run's `filter`, a `timestamp`, and `certs=[{id, files:[{file, sha256}]}]` for every materialised cert.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_sync.py`:

```python
def test_state_file_written_with_checksums(tmp_path, monkeypatch):
    """A successful sync records the cert and its file's sha256 in the state file."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(
        cert_id="mycert", certificate=cert_pem, private_key=key_pem,
        expire_date=not_after.strftime(DATE_FMT),
    )

    result = _invoke(tmp_path, [], [cert], monkeypatch)

    assert result.exit_code == 0, result.output
    state_path = tmp_path / ".certhub-sync-state.json"
    assert state_path.exists()
    state = json.loads(state_path.read_text())
    assert state["version"] == 1
    assert state["filter"] == {"type": "all", "patterns": []}
    assert state["certs"][0]["id"] == "mycert"
    bundle = tmp_path / "mycert_bundle.pem"
    entry = state["certs"][0]["files"][0]
    assert entry["file"] == "mycert_bundle.pem"
    assert entry["sha256"] == certhub.sha256_file(bundle)


def test_state_file_not_written_on_dry_run(tmp_path, monkeypatch):
    """--dry-run must not create or update the state file."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(
        cert_id="mycert", certificate=cert_pem, private_key=key_pem,
        expire_date=not_after.strftime(DATE_FMT),
    )

    result = _invoke(tmp_path, ["--dry-run"], [cert], monkeypatch)

    assert result.exit_code == 0, result.output
    assert not (tmp_path / ".certhub-sync-state.json").exists()
```

Note: the default `--type` is `all`, so the recorded filter is `{"type": "all", "patterns": []}`.

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/test_sync.py -q -k "state_file_written or not_written_on_dry"`
Expected: FAIL — no state file is produced yet.

- [ ] **Step 3: Add the `materialized` accumulator**

In `certhub.py`, right after `results: list[CertUpdateResult] = []` (line ~915), add:

```python
    # (cert_id, pem_files) for every cert whose files were materialised (added,
    # updated, or already up to date) — used to build the sync state file.
    materialized: list[tuple[str, list[Path]]] = []
```

- [ ] **Step 4: Record materialised certs in the up-to-date and add/update branches**

In the up-to-date branch, after its `results.append(...)` (the `msg="Up to date"` block, ~line 1021-1027) and before `continue`, add:

```python
            materialized.append((cert_id, pem_files))
```

At the very end of the add/update branch, after its `results.append(...)` (the block from Task 3 Step 5), add:

```python
        materialized.append((cert_id, pem_files))
```

- [ ] **Step 5: Write the state file before finalising the result**

In `certhub.py`, immediately before `result = CmdResult.from_dict([r.to_serializable() for r in results], ExitCode.OK)` (line ~1067), add:

```python
    if not dry_run:
        current_certs = []
        for cert_id, pem_files in materialized:
            file_entries = [
                {"file": p.name, "sha256": sha256_file(p)}
                for p in pem_files if p.exists()
            ]
            if file_entries:
                current_certs.append({"id": cert_id, "files": file_entries})
        write_sync_state(
            certs_dir / SYNC_STATE_FILENAME,
            state_filter_obj(patterns, cert_type.value),
            current_certs,
            datetime.now(timezone.utc),
        )
```

- [ ] **Step 6: Run to verify tests pass**

Run: `python -m pytest tests/test_sync.py -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add certhub.py tests/test_sync.py
git commit -m "feat: write cert sync state file with per-file checksums"
```

---

### Task 5: Prune certs the server no longer returns

**Files:**
- Modify: `certhub.py` (`cert_sync`: load prior state after dir validation ~line 898; capture `response_ids` near line 915; insert prune loop after the per-cert loop, before `is_any_updated` at line ~1049)
- Modify: `tests/test_sync.py` (add prune tests)

**Interfaces:**
- Consumes: `load_sync_state`, `SYNC_STATE_FILENAME`, `sha256_file`, `state_filter_obj` (Task 2); `dry_run`, `omit_post_hook_on_prune` (Task 3); `materialized`/state-write (Task 4).
- Produces: for each cert in the prior state whose id is absent from the current API response, its recorded files are deleted (if their on-disk sha256 matches) and a `CertUpdateResult` row is appended. On checksum mismatch the file is kept and the row is `WARNING`. Pruned/revoked certs do not enter `materialized`, so they drop out of the freshly written state.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_sync.py`:

```python
def test_prune_removes_disappeared_cert(tmp_path, monkeypatch):
    """A cert present last run but absent now has its files removed and drops from state."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(
        cert_id="mycert", certificate=cert_pem, private_key=key_pem,
        expire_date=not_after.strftime(DATE_FMT),
    )
    # First run: writes the cert and records it in the state file.
    _invoke(tmp_path, [], [cert], monkeypatch)
    bundle = tmp_path / "mycert_bundle.pem"
    assert bundle.exists()

    # Second run: server returns nothing -> cert is pruned.
    result = _invoke(tmp_path, [], [], monkeypatch)

    assert result.exit_code == 0, result.output
    assert not bundle.exists()
    state = json.loads((tmp_path / ".certhub-sync-state.json").read_text())
    assert state["certs"] == []


def test_prune_checksum_mismatch_keeps_file_and_warns(tmp_path, monkeypatch):
    """A locally modified file is not deleted during prune; the run reports WARNING."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(
        cert_id="mycert", certificate=cert_pem, private_key=key_pem,
        expire_date=not_after.strftime(DATE_FMT),
    )
    _invoke(tmp_path, [], [cert], monkeypatch)
    bundle = tmp_path / "mycert_bundle.pem"
    bundle.write_text(bundle.read_text() + "\n# locally edited\n")

    status_path = tmp_path / "status.json"
    result = _invoke(
        tmp_path, ["--status-file", str(status_path)], [], monkeypatch
    )

    assert result.exit_code == 0, result.output
    assert bundle.exists()  # not deleted
    status = json.loads(status_path.read_text())
    assert status["status"] == "WARNING"
    row = next(r for r in status["result"] if r["id"] == "mycert")
    assert "checksum mismatch" in row["msg"]


def test_prune_respects_dry_run(tmp_path, monkeypatch):
    """--dry-run reports the prune but neither deletes files nor rewrites state."""
    cert_pem, key_pem, not_after = _make_cert(days_valid=365)
    cert = _cert_dict(
        cert_id="mycert", certificate=cert_pem, private_key=key_pem,
        expire_date=not_after.strftime(DATE_FMT),
    )
    _invoke(tmp_path, [], [cert], monkeypatch)
    bundle = tmp_path / "mycert_bundle.pem"

    result = _invoke(tmp_path, ["--dry-run"], [], monkeypatch)

    assert result.exit_code == 0, result.output
    assert bundle.exists()  # not deleted under dry-run
    state = json.loads((tmp_path / ".certhub-sync-state.json").read_text())
    assert state["certs"][0]["id"] == "mycert"  # state unchanged


def test_filter_change_prunes_nonmatching(tmp_path, monkeypatch):
    """A cert dropped because the filter narrowed is pruned like any absent cert."""
    a_cert_pem, a_key_pem, a_exp = _make_cert(days_valid=365, cn="a.example")
    b_cert_pem, b_key_pem, b_exp = _make_cert(days_valid=365, cn="b.example")
    a = _cert_dict(cert_id="aaa", certificate=a_cert_pem, private_key=a_key_pem,
                   expire_date=a_exp.strftime(DATE_FMT))
    b = _cert_dict(cert_id="bbb", certificate=b_cert_pem, private_key=b_key_pem,
                   expire_date=b_exp.strftime(DATE_FMT))
    # First run: no filter, both certs recorded.
    _invoke(tmp_path, [], [a, b], monkeypatch)
    assert (tmp_path / "aaa_bundle.pem").exists()
    assert (tmp_path / "bbb_bundle.pem").exists()

    # Second run: narrowed filter, server returns only aaa -> bbb pruned.
    result = _invoke(tmp_path, ["--pattern", "aaa"], [a], monkeypatch)

    assert result.exit_code == 0, result.output
    assert (tmp_path / "aaa_bundle.pem").exists()
    assert not (tmp_path / "bbb_bundle.pem").exists()


def test_revoked_cert_drops_from_state(tmp_path, monkeypatch):
    """A REVOKED cert is removed and does not appear in the rewritten state."""
    cert_pem, key_pem, _ = _make_cert(days_valid=365)
    bundle = tmp_path / "mycert_bundle.pem"
    bundle.write_text(cert_pem + key_pem)
    cert = _cert_dict(cert_id="mycert", status="REVOKED")

    result = _invoke(tmp_path, [], [cert], monkeypatch)

    assert result.exit_code == 0, result.output
    assert not bundle.exists()
    state = json.loads((tmp_path / ".certhub-sync-state.json").read_text())
    assert state["certs"] == []
```

Note: `_cert_dict`'s `--pattern`/match value is irrelevant to the fake client (it ignores params); the second run's payload is what drives which certs are "returned".

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/test_sync.py -q -k "prune or filter_change or revoked_cert_drops"`
Expected: FAIL — nothing prunes disappeared certs yet (`bundle` still exists / state still lists the cert).

- [ ] **Step 3: Load prior state and capture the response id set**

In `certhub.py`, after the dest-dir validation block (after line ~897, before `cert_type = CertType.from_string(type)`), add:

```python
    state_path = certs_dir / SYNC_STATE_FILENAME
    prior_state = load_sync_state(state_path)
    prior_certs = prior_state.get("certs") or []
```

Then, right after `results: list[CertUpdateResult] = []` (and the `materialized` line from Task 4), add:

```python
    response_ids = {c.get("id") for c in result.data}
```

- [ ] **Step 4: Insert the prune loop after the per-cert loop**

In `certhub.py`, immediately after the per-cert `for cert in result.data:` loop ends and before `is_any_updated = any(r.updated for r in results)` (line ~1049), add:

```python
    current_filter = state_filter_obj(patterns, cert_type.value)
    stale_ids = [c.get("id") for c in prior_certs if c.get("id") not in response_ids]
    if stale_ids and prior_state.get("filter") not in (None, current_filter):
        LOGGER.warning(
            f"Sync filter changed since last run (was {prior_state.get('filter')}, now {current_filter}); "
            f"certificates no longer matching the filter will be removed: {', '.join(stale_ids)}"
        )

    for prior_cert in prior_certs:
        prior_id = prior_cert.get("id")
        if prior_id in response_ids:
            continue
        removed, mismatched = [], []
        prune_files = [certs_dir / e.get("file", "") for e in prior_cert.get("files", [])]
        for pem_file, entry in zip(prune_files, prior_cert.get("files", [])):
            if not pem_file.exists():
                continue
            if sha256_file(pem_file) != entry.get("sha256"):
                mismatched.append(pem_file.name)
                continue
            if not dry_run:
                pem_file.unlink()
            removed.append(pem_file.name)
        if not removed and not mismatched:
            continue  # nothing left on disk; the cert simply drops from the new state
        verb = "would remove" if dry_run else "removed"
        parts = []
        if removed:
            parts.append(f"{verb} files: {', '.join(removed)}")
        if mismatched:
            parts.append(f"skipped (checksum mismatch): {', '.join(mismatched)}")
        results.append(CertUpdateResult(
            cert=prior_id,
            code=ExitCode.WARNING if mismatched else ExitCode.OK,
            pem_files=prune_files,
            remote_expire_date=None,
            local_expire_date=None,
            updated=bool(removed) and not omit_post_hook_on_prune and not dry_run,
            msg="No longer returned by server; " + "; ".join(parts),
        ))
```

- [ ] **Step 5: Run to verify tests pass**

Run: `python -m pytest tests/test_sync.py -q`
Expected: PASS (all prune/filter/revoke tests plus the full existing suite).

- [ ] **Step 6: Commit**

```bash
git add certhub.py tests/test_sync.py
git commit -m "feat: prune cert sync files for certs the server no longer returns"
```

---

### Task 6: Documentation

**Files:**
- Modify: `README.md` (sync examples ~lines 350-357; command tree line ~301; `--dest-dir` mention ~line 383; add state-file / prune / dry-run subsections after line ~393)

**Interfaces:**
- Consumes: final behaviour from Tasks 1-5.
- Produces: no code; documents the positional argument, `.certhub-sync-state.json`, prune-on-disappearance, filter-change behaviour, `--dry-run`, and `--omit-post-hook-on-prune`.

- [ ] **Step 1: Update the sync usage examples to the positional argument**

In `README.md`, replace the four example lines (350-357) so dest-dir is positional and one example shows dry-run:

```bash
# Sync locally stored cert files with the server if it has a newer version
certhub cert sync /etc/ssl/private --post-hook "systemctl reload nginx"

# Write a deploy bundle plus standalone cert and key files
certhub cert sync /etc/ssl/private --pem bundle --pem cert --pem privkey --post-hook "systemctl reload nginx"

# Write cert and key with nginx-friendly extensions
certhub cert sync /etc/ssl/private --pem cert --pem privkey --ext cert=crt --ext privkey=key --post-hook "systemctl reload nginx"

# Preview what would change without writing, deleting, or updating state
certhub cert sync /etc/ssl/private --dry-run
```

- [ ] **Step 2: Fix the `--dest-dir` reference in prose**

In `README.md` line ~383, change "inside `--dest-dir`" to "inside the destination directory (the positional `DEST_DIR` argument)".

- [ ] **Step 3: Add the state-file / prune / dry-run subsection**

In `README.md`, immediately after the REVOKED paragraph (line ~393), insert:

```markdown
`cert sync` maintains a `.certhub-sync-state.json` file in the destination directory recording each certificate it materialised and the `sha256` of every file it wrote. On the next run, any certificate present in that state file but **no longer returned** by the server — because the identity lost access to it, or because a narrower `--pattern`/`--type` filter excludes it — has its recorded files removed. Before deleting a file, its on-disk checksum is compared against the recorded one: on a mismatch (the file was modified outside `cert sync`) the file is left untouched and the run reports `WARNING`. This cleanup counts as a change and triggers `--post-hook` unless `--omit-post-hook-on-prune` is passed.

If the filter changed since the previous run, the certificates dropped by the new filter are cleaned up as above; the run logs a warning naming them so the change is visible.

Use `--dry-run` to preview a run: it reports what would be added, updated, or removed (rows read "Would add" / "would remove") without writing any PEM file, deleting anything, or updating the state file.
```

- [ ] **Step 4: Update the command tree note**

In `README.md` line ~301, change the sync line to mention cleanup of certs no longer returned:

```
    └── sync                        Sync local certificate files with the server (replace expiring/expired/missing, remove revoked and no-longer-accessible)
```

- [ ] **Step 5: Verify docs match behaviour and commit**

Run: `python -m pytest tests/test_sync.py -q`
Expected: PASS (sanity check that nothing regressed).

```bash
git add README.md
git commit -m "docs: document cert sync state file, prune, and --dry-run"
```

---

## Self-Review Notes

- **Spec coverage:** state file structure (Task 2/4), fixed name always-on (Task 4), flat single state (Task 4), filter recorded informationally + filter-change warning (Task 5), prune on disappearance (Task 5), sha256 guard → WARNING (Task 5), post-hook on prune + `--omit-post-hook-on-prune` (Tasks 3/5), `--dry-run` for writes/deletes/state (Tasks 3/4/5), positional dest-dir (Task 1), API-fetch failure does not prune (unchanged early `render_and_exit`; prune runs only after the successful loop), corrupt state tolerated (Task 2), REVOKED drops from state (Task 5), docs (Task 6). All covered.
- **Type consistency:** `state_filter_obj`, `sha256_file`, `load_sync_state`, `write_sync_state`, `SYNC_STATE_FILENAME`, `materialized`, `response_ids`, `prior_certs` used consistently across tasks.
- **Known limitation (documented in spec, not a bug):** syncing one dest-dir with overlapping filters can prune a file another filter still tracks; the checksum guard does not catch this because the file legitimately matches.
```
