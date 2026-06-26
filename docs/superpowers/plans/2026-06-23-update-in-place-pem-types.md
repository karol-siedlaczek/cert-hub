# `update-in-place` multiple `--pem` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `certhub cert update-in-place` produce multiple PEM output files per certificate, selected by a repeatable `--pem/-P` option (default `bundle`), named `<prefix>_<type>.pem` where prefix is the `pem_prefix` custom attr or the cert id.

**Architecture:** All changes are in the single standalone `certhub.py` CLI plus `README.md`. A handful of pure helper functions encapsulate PEM-type parsing/dedup, prefix resolution, per-type content building, required-field computation, and the expiry-reference choice; the per-cert loop in `cert_update_in_place` is rewritten to use them and write all requested files under one per-cert update decision.

**Tech Stack:** Python 3.12+, Typer/Click, Rich, requests (CLI runtime only).

## Global Constraints

- `--pem/-P` is repeatable (`list[str]`), default `["bundle"]`; values from `PemType.values()` = `{"cert", "privkey", "chain", "bundle"}`. Invalid value → `typer.BadParameter`. Duplicates removed, order preserved.
- Filename scheme: `<prefix>_<type>.pem`; prefix = `custom_attrs["pem_prefix"]` if set else cert `id`; prefix must match `PEM_FILENAME_PATTERN` = `^[\w.-]+$`. The old `pem_filename` custom attr is **removed** (breaking change).
- Per-type content: `cert`→`certificate`, `privkey`→`private_key`, `chain`→`chain`, `bundle`→`certificate`+`chain`+`private_key` (empty parts skipped).
- Required server fields are the union over requested types: `certificate` for `cert`/`bundle`; `private_key` for `privkey`/`bundle`; `chain` for `chain` only (bundle includes chain only if present); `expire_date` only if a cert-bearing type (`bundle`/`cert`) is requested.
- Update decision is per-cert: rewrite ALL requested files iff any requested file is missing OR (a cert-bearing reference is requested AND remote `expire_date` > local expiry read from the reference file). Reference = `bundle` if requested else `cert` if requested else none. With no reference, decide purely by existence.
- `chmod` + (optional) `owner`/`group` applied to EVERY written file.
- Result: one row per cert; `CertUpdateResult.pem_file` becomes `pem_files: list[Path]`, serialized under key `pem_files`.
- CLI is not unit-tested in this project (venv lacks typer/requests/rich; `certhub.py` cannot be imported there). Verification per task: `make lint` (`py_compile`) + review; `make test` (domain suite) must remain green and unchanged.
- This work is intentionally NOT committed (user instruction). Each task ends WITHOUT a git commit; do not stage/branch/revert or touch unrelated pre-existing working-tree changes.

---

### Task 1: Add pure PEM helper functions and make `--pem` repeatable

**Files:**
- Modify: `certhub.py` (add helper functions near the other module-level helpers; change the `--pem` option type/default in `cert_update_in_place`)

**Interfaces:**
- Consumes: existing `PemType` enum (`CERT="cert"`, `PRIV_KEY="privkey"`, `CHAIN="chain"`, `BUNDLE="bundle"`, with `values()`, `default()`, `from_string()`), `PEM_FILENAME_PATTERN`.
- Produces (module-level functions in `certhub.py`):
  - `parse_pem_types(values: list[str]) -> list[PemType]` — maps each value via `PemType.from_string` (raises `typer.BadParameter` on bad value), dedups preserving order.
  - `resolve_pem_prefix(cert: dict) -> str` — `custom_attrs["pem_prefix"]` if truthy else `str(cert["id"])`.
  - `pem_content_for(pem_type: PemType, certificate, chain, private_key) -> str` — content for one type, empty parts skipped, trailing newline.
  - `required_server_fields(pem_types: list[PemType]) -> set[str]` — subset of `{"certificate","private_key","chain","expire_date"}`.
  - `expiry_reference_type(pem_types: list[PemType]) -> PemType | None` — `BUNDLE` else `CERT` else `None`.

- [ ] **Step 1: Add the helper functions**

In `certhub.py`, in the `# ── helpers ──` section (near `get_cert_expire_date`, ~line 1040+), add:

```python
def parse_pem_types(values: list[str]) -> list["PemType"]:
    result: list[PemType] = []
    for value in values:
        pem_type = PemType.from_string(value)
        if pem_type not in result:
            result.append(pem_type)
    return result


def resolve_pem_prefix(cert: dict) -> str:
    custom_attrs = cert.get("custom_attrs")
    if isinstance(custom_attrs, dict) and custom_attrs.get("pem_prefix"):
        return str(custom_attrs["pem_prefix"])
    return str(cert.get("id"))


def pem_content_for(
    pem_type: "PemType",
    certificate: str | None,
    chain: str | None,
    private_key: str | None,
) -> str:
    if pem_type == PemType.CERT:
        parts = [certificate]
    elif pem_type == PemType.CHAIN:
        parts = [chain]
    elif pem_type == PemType.PRIV_KEY:
        parts = [private_key]
    else:  # PemType.BUNDLE
        parts = [certificate, chain, private_key]
    parts = [part.strip() for part in parts if part]
    return "\n".join(parts) + "\n"


def required_server_fields(pem_types: list["PemType"]) -> set[str]:
    fields: set[str] = set()
    for pem_type in pem_types:
        if pem_type in (PemType.CERT, PemType.BUNDLE):
            fields.add("certificate")
        if pem_type in (PemType.PRIV_KEY, PemType.BUNDLE):
            fields.add("private_key")
        if pem_type == PemType.CHAIN:
            fields.add("chain")
    if any(pem_type in (PemType.BUNDLE, PemType.CERT) for pem_type in pem_types):
        fields.add("expire_date")
    return fields


def expiry_reference_type(pem_types: list["PemType"]) -> "PemType | None":
    if PemType.BUNDLE in pem_types:
        return PemType.BUNDLE
    if PemType.CERT in pem_types:
        return PemType.CERT
    return None
```

- [ ] **Step 2: Make `--pem` repeatable in `cert_update_in_place`**

In `certhub.py`, in `cert_update_in_place`'s signature, replace the existing `pem` option:

```python
    pem: str = typer.Option( # TODO - add option to add multiple options
        PemType.default().value, "--pem", "-P",
        help=f"Choose produced PEM file types after successful run, available choices: {", ".join(PemType.values())}"
    ),
```
with:
```python
    pem: list[str] = typer.Option(
        [PemType.default().value], "--pem", "-P",
        help=f"PEM file type(s) to produce; repeatable. Files are named <prefix>_<type>.pem. Choices: {', '.join(PemType.values())}"
    ),
```

- [ ] **Step 3: Verify it compiles and the domain suite is unaffected**

Run: `make lint`
Expected: `py_compile` → `OK`.

Run: `make test`
Expected: domain suite unchanged and green (52 passing).

(No commit.)

---

### Task 2: Rewrite the per-cert loop to write multiple files under one update decision

**Files:**
- Modify: `certhub.py` (`cert_update_in_place`: `CertUpdateResult` dataclass, and the whole `for cert in result.data:` loop body)

**Interfaces:**
- Consumes: `parse_pem_types`, `resolve_pem_prefix`, `pem_content_for`, `required_server_fields`, `expiry_reference_type` (Task 1); existing `get_cert_expire_date`, `PEM_FILENAME_PATTERN`, `safe_str`, `ExitCode`, `DATE_FMT`, `chmod_mode`, `owner`, `group`, `certs_dir`.
- Produces: `CertUpdateResult.pem_files: list[Path]` (serialized as `"pem_files": [str, ...]`); per-cert results writing all requested PEM files.

- [ ] **Step 1: Update the `CertUpdateResult` dataclass**

In `cert_update_in_place`, replace the inner dataclass:

```python
    @dataclass
    class CertUpdateResult:
        cert: str
        code: ExitCode
        pem_file: Path | None
        remote_expire_date: datetime | None
        local_expire_date: datetime | None
        updated: bool
        msg: str
        
        def to_serializable(self) -> dict:
            return {
                "id": self.cert,
                "status": self.code.name,
                "pem_file": str(self.pem_file),
                "local_expire_date": datetime.strftime(self.local_expire_date, DATE_FMT) if self.local_expire_date else None,
                "remote_expire_date": datetime.strftime(self.remote_expire_date, DATE_FMT) if self.remote_expire_date else None,
                "updated": self.updated,
                "msg": self.msg
            }
```
with:
```python
    @dataclass
    class CertUpdateResult:
        cert: str
        code: ExitCode
        pem_files: list[Path]
        remote_expire_date: datetime | None
        local_expire_date: datetime | None
        updated: bool
        msg: str

        def to_serializable(self) -> dict:
            return {
                "id": self.cert,
                "status": self.code.name,
                "pem_files": [str(p) for p in self.pem_files],
                "local_expire_date": datetime.strftime(self.local_expire_date, DATE_FMT) if self.local_expire_date else None,
                "remote_expire_date": datetime.strftime(self.remote_expire_date, DATE_FMT) if self.remote_expire_date else None,
                "updated": self.updated,
                "msg": self.msg
            }
```

- [ ] **Step 2: Parse `--pem` once before the loop**

In `cert_update_in_place`, immediately after `chmod_mode` is computed (the `try/except ValueError` block that sets `chmod_mode`), add:

```python
    pem_types = parse_pem_types(pem)
```

- [ ] **Step 3: Replace the entire `for cert in result.data:` loop body**

Replace everything from `for cert in result.data:` down to (but NOT including) the line `is_any_updated = any(r.updated for r in results)` with:

```python
    for cert in result.data:
        cert_id = cert.get("id")
        prefix = resolve_pem_prefix(cert)

        if not re.compile(PEM_FILENAME_PATTERN).fullmatch(prefix):
            results.append(CertUpdateResult(
                cert=cert_id,
                code=ExitCode.CRITICAL,
                pem_files=[],
                remote_expire_date=None,
                local_expire_date=None,
                updated=False,
                msg=f"Invalid file name prefix '{prefix}' (from custom_attr 'pem_prefix' or cert id), needs to match pattern: {PEM_FILENAME_PATTERN}"
            ))
            continue

        pem_files = [certs_dir / f"{prefix}_{pem_type.value}.pem" for pem_type in pem_types]
        fields = required_server_fields(pem_types)

        certificate = cert.get("certificate")
        chain = cert.get("chain")
        private_key = cert.get("private_key")

        if "certificate" in fields and not certificate:
            results.append(CertUpdateResult(
                cert=cert_id, code=ExitCode.WARNING, pem_files=pem_files,
                remote_expire_date=None, local_expire_date=None, updated=False,
                msg="Not issued on server side"
            ))
            continue

        if "private_key" in fields and not private_key:
            results.append(CertUpdateResult(
                cert=cert_id, code=ExitCode.CRITICAL, pem_files=pem_files,
                remote_expire_date=None, local_expire_date=None, updated=False,
                msg="Private key is missing on server side"
            ))
            continue

        if "chain" in fields and not chain:
            results.append(CertUpdateResult(
                cert=cert_id, code=ExitCode.CRITICAL, pem_files=pem_files,
                remote_expire_date=None, local_expire_date=None, updated=False,
                msg="Chain is missing on server side"
            ))
            continue

        expire_date = None
        if "expire_date" in fields:
            expire_date_str = cert.get("expire_date")
            if not expire_date_str:
                results.append(CertUpdateResult(
                    cert=cert_id, code=ExitCode.CRITICAL, pem_files=pem_files,
                    remote_expire_date=None, local_expire_date=None, updated=False,
                    msg="Expire date is missing on server side"
                ))
                continue
            try:
                expire_date = datetime.strptime(expire_date_str, DATE_FMT).replace(tzinfo=timezone.utc)
            except ValueError as e:
                results.append(CertUpdateResult(
                    cert=cert_id, code=ExitCode.CRITICAL, pem_files=pem_files,
                    remote_expire_date=None, local_expire_date=None, updated=False,
                    msg=f"Failed to parse expire date from server side: {safe_str(e)}"
                ))
                continue

        ref_type = expiry_reference_type(pem_types)
        existed_before = any(f.exists() for f in pem_files)
        need_update = any(not f.exists() for f in pem_files)
        local_expire_date = None

        if ref_type is not None:
            ref_file = certs_dir / f"{prefix}_{ref_type.value}.pem"
            if ref_file.exists():
                try:
                    local_expire_date = get_cert_expire_date(ref_file)
                except Exception as e:
                    results.append(CertUpdateResult(
                        cert=cert_id, code=ExitCode.CRITICAL, pem_files=pem_files,
                        remote_expire_date=expire_date, local_expire_date=None, updated=False,
                        msg=safe_str(str(e))
                    ))
                    continue
                if expire_date > local_expire_date:
                    need_update = True

        if not need_update:
            results.append(CertUpdateResult(
                cert=cert_id, code=ExitCode.OK, pem_files=pem_files,
                remote_expire_date=expire_date, local_expire_date=local_expire_date, updated=False,
                msg="Up to date"
            ))
            continue

        # Add or update local certificate files
        for pem_type, pem_file in zip(pem_types, pem_files):
            pem_file.write_text(pem_content_for(pem_type, certificate, chain, private_key), encoding="UTF-8")
            os.chmod(pem_file, chmod_mode)

            if owner is not None or group is not None:
                try:
                    shutil.chown(pem_file, user=owner, group=group)
                except LookupError:
                    uid = pwd.getpwnam(owner).pw_uid if owner is not None else -1
                    gid = int(group) if group is not None and str(group).isdigit() else (grp.getgrnam(group).gr_gid if group is not None else -1)
                    os.lchown(pem_file, uid, gid)

        results.append(CertUpdateResult(
            cert=cert_id, code=ExitCode.OK, pem_files=pem_files,
            remote_expire_date=expire_date, local_expire_date=local_expire_date, updated=True,
            msg="Updated" if existed_before else "Added"
        ))
```

- [ ] **Step 4: Verify it compiles and the domain suite is unaffected**

Run: `make lint`
Expected: `py_compile` → `OK`.

Run: `make test`
Expected: domain suite unchanged and green (52 passing).

- [ ] **Step 5: Self-check the logic by reading the new loop**

Confirm by reading the code:
- `pem_files` order matches `pem_types` order (zip is aligned).
- `expire_date` is guaranteed non-None where compared (`expire_date > local_expire_date` only runs when `ref_type is not None`, which implies `"expire_date" in fields`, which was parsed-or-`continue`d above).
- every error branch passes `pem_files=` (a list), never the removed `pem_file=`.
- Nagios block below the loop (`r.local_expire_date`, `r.code`, `r.cert`) still works — it does not reference `pem_file`.

(No commit.)

---

### Task 3: README documentation

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the shipped `--pem` behavior, `<prefix>_<type>.pem` scheme, `pem_prefix` custom attr.

- [ ] **Step 1: Replace `pem_filename` references with `pem_prefix`**

In `README.md`, find references to `pem_filename` (in the config `custom_attrs` examples and the `update-in-place` description). Replace the `custom_attrs` example key `pem_filename` with `pem_prefix` in both the `letsencrypt_certs` and `static_certs` example blocks, e.g.:
```yaml
    custom_attrs:
      pem_prefix: "example"   # base name for files written by `cert update-in-place` (defaults to cert id)
```

- [ ] **Step 2: Document the `--pem` option in the CLI section**

In the `update-in-place` documentation, add a description of `--pem/-P`: repeatable, default `bundle`, choices `cert|privkey|chain|bundle`; output files are written as `<dest-dir>/<prefix>_<type>.pem` where `<prefix>` is the `pem_prefix` custom attr or the cert id; `bundle` = certificate + chain + private key concatenated. Add an example:
```bash
# Write a deploy bundle plus standalone cert and key files
certhub cert update-in-place -d /etc/ssl/private --pem bundle --pem cert --pem privkey --post-hook "systemctl reload nginx"
```

- [ ] **Step 3: Verify the doc references are consistent**

Run: `grep -n "pem_filename" README.md`
Expected: no matches (all replaced by `pem_prefix`).

Run: `grep -n "\-\-pem" README.md`
Expected: at least the new `--pem` documentation/example.

(No commit.)

---

### Task 4: Full verification sweep

**Files:** none (verification only).

- [ ] **Step 1: Lint**

Run: `make lint`
Expected: `py_compile` → `OK`.

- [ ] **Step 2: Domain test suite**

Run: `make test`
Expected: all tests pass (52), unchanged by this CLI-only feature.

---

## Self-Review

**Spec coverage:**
- `--pem` repeatable, default bundle, validated, deduped → Task 1 (`parse_pem_types`, option change). ✓
- Filename `<prefix>_<type>.pem`, prefix from `pem_prefix` else id, validated by pattern → Task 1 (`resolve_pem_prefix`) + Task 2 (prefix validation, `pem_files`). ✓
- `pem_filename` removed → Task 2 (loop no longer reads it) + Task 3 (docs). ✓
- Per-type content incl. bundle skipping empty chain → Task 1 (`pem_content_for`). ✓
- Required server fields per requested types → Task 1 (`required_server_fields`) + Task 2 (checks). ✓
- Per-cert update decision with bundle>cert>none reference, existence-or-expiry → Task 1 (`expiry_reference_type`) + Task 2 (decision block). ✓
- chmod/owner/group on every written file → Task 2 (write loop). ✓
- Result one row per cert with `pem_files` list → Task 2 (dataclass + serialization). ✓
- README → Task 3. ✓
- CLI not unit-tested; lint + domain suite green → all tasks' verification steps. ✓

**Placeholder scan:** No TBD/TODO/"handle errors"/"similar to" — every code step has concrete code. Task 3 doc edits are prose-described (documentation, not logic) with concrete examples and grep checks. The `# TODO` text appears only as the literal old code being REMOVED in Task 1 Step 2. ✓

**Type consistency:** `parse_pem_types`/`resolve_pem_prefix`/`pem_content_for`/`required_server_fields`/`expiry_reference_type` signatures identical between Task 1 (definitions) and Task 2 (call sites). `pem_files` (list[Path]) named identically in the dataclass, all result constructions, and serialization. `pem_types` derived once and zipped with `pem_files` in the same order. `required_server_fields` returns the string keys (`certificate`/`private_key`/`chain`/`expire_date`) checked verbatim in Task 2. ✓
