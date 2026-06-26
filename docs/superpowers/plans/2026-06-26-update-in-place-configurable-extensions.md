# Configurable file extensions for `cert update-in-place` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `cert update-in-place` write each produced PEM type with a configurable file extension (`--ext type=ext`), defaulting every type to `.pem` so current behaviour is unchanged.

**Architecture:** Add two pure helper functions in `certhub.py` (`pem_filename`, `parse_pem_extensions`), add a repeatable `--ext` option to the `cert update-in-place` command, and replace the three hardcoded `.pem` filename sites with the helper so the "is up to date" / revoke-cleanup / expiry-reference logic keeps matching the files actually written. Make the CLI module importable from tests by adding its runtime deps to the test venv, then unit-test the helpers.

**Tech Stack:** Python 3, Typer (CLI), pytest. Test venv at `tests/.venv`, tests run from `tests/` with `pythonpath = ..` (set in `tests/pytest.ini`), so `import certhub` resolves the top-level `certhub.py`.

## Global Constraints

- Default extension for **every** `PemType` (`cert`, `privkey`, `chain`, `bundle`) is `pem`. No type gets a non-`.pem` default. With no `--ext` flag, behaviour is byte-for-byte identical to today.
- Validation errors must raise `typer.BadParameter` (a subclass of `click.exceptions.BadParameter`).
- The basename scheme stays `<prefix>_<type>` — only the extension is configurable. The `_<type>` suffix is never dropped.
- Follow existing `certhub.py` style: module-level helper functions near `parse_pem_types` (around line 1281+), Typer `typer.Option(...)` for CLI flags.
- Tests live in `tests/`, run via `make test` (which is `cd tests && .venv/bin/python -m pytest -q`). Test files are named `test_*.py`.

---

### Task 1: Make the CLI module importable in tests, add `pem_filename` helper

This task bundles the test-venv dependency fix with the first helper, because the helper's test cannot run until `import certhub` works in the test venv.

**Files:**
- Modify: `tests/requirements.txt` (add CLI runtime deps)
- Modify: `certhub.py` (add `pem_filename` near other PEM helpers, ~line 1287 after `parse_pem_types`)
- Create: `tests/test_pem_extensions.py`

**Interfaces:**
- Produces: `pem_filename(prefix: str, pem_type: PemType, ext_map: dict[PemType, str]) -> str` — returns `f"{prefix}_{pem_type.value}.{ext_map[pem_type]}"`. Used by Task 3 at the three filename sites.

- [ ] **Step 1: Add CLI runtime deps to the test venv requirements**

Edit `tests/requirements.txt` to add the three packages `certhub.py` imports at module load (`typer`, `rich`, `requests`). Result:

```
pytest
Flask>=3.0.2,<4.0
PyYAML>=6.0
cryptography>=42.0
typer
rich
requests
```

- [ ] **Step 2: Reinstall the test venv so the new deps are present**

Run (from repo root):
```bash
tests/.venv/bin/pip install -q -r tests/requirements.txt
```
Then verify the CLI module now imports:
```bash
cd tests && PYTHONPATH=.. ./.venv/bin/python -c "import certhub; print(certhub.PemType.values())"
```
Expected: `['cert', 'privkey', 'chain', 'bundle']`

- [ ] **Step 3: Write the failing test for `pem_filename`**

Create `tests/test_pem_extensions.py`:
```python
import pytest

import certhub
from certhub import PemType, pem_filename, parse_pem_extensions


def test_pem_filename_uses_mapped_extension():
    ext_map = {PemType.CERT: "crt", PemType.PRIV_KEY: "key"}
    assert pem_filename("foo", PemType.CERT, ext_map) == "foo_cert.crt"
    assert pem_filename("foo", PemType.PRIV_KEY, ext_map) == "foo_privkey.key"


def test_pem_filename_default_pem_extension():
    ext_map = {PemType.BUNDLE: "pem"}
    assert pem_filename("bar", PemType.BUNDLE, ext_map) == "bar_bundle.pem"
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cd tests && PYTHONPATH=.. ./.venv/bin/python -m pytest test_pem_extensions.py -q`
Expected: FAIL with `ImportError: cannot import name 'pem_filename'` (and `parse_pem_extensions`).

- [ ] **Step 5: Implement `pem_filename` in `certhub.py`**

Insert immediately after the `parse_pem_types` function (after its `return result`, ~line 1287):
```python
def pem_filename(prefix: str, pem_type: "PemType", ext_map: dict["PemType", str]) -> str:
    return f"{prefix}_{pem_type.value}.{ext_map[pem_type]}"
```

- [ ] **Step 6: Run the `pem_filename` tests to verify they pass**

Run: `cd tests && PYTHONPATH=.. ./.venv/bin/python -m pytest test_pem_extensions.py -q -k pem_filename`
Expected: 2 passed. (The `parse_pem_extensions` import still resolves because it does not exist yet — it will fail collection; if so, temporarily expect the two `pem_filename` tests; Task 2 adds `parse_pem_extensions`.)

> Note: the file imports `parse_pem_extensions` which Task 2 implements. If pytest fails at import/collection, that is expected until Task 2 — run with `make lint` to confirm `pem_filename` compiles and proceed; the green bar comes at the end of Task 2.

- [ ] **Step 7: Commit**

```bash
git add tests/requirements.txt certhub.py tests/test_pem_extensions.py
git commit -m "Add pem_filename helper and make CLI importable in tests"
```

---

### Task 2: `parse_pem_extensions` helper with validation

**Files:**
- Modify: `certhub.py` (add `parse_pem_extensions` next to `pem_filename`)
- Modify: `tests/test_pem_extensions.py` (add validation tests)

**Interfaces:**
- Consumes: `PemType` (existing enum, values `cert`/`privkey`/`chain`/`bundle`), `pem_filename` (Task 1).
- Produces: `parse_pem_extensions(values: list[str], pem_types: list[PemType]) -> dict[PemType, str]` — returns a map covering every `PemType` in `pem_types`, default `"pem"`, overridden by parsed `--ext` entries. Raises `typer.BadParameter` on bad input. Used by Task 3.

Semantics (copy verbatim into the implementation):
- Each entry in `values` must be `type=ext`. Missing `=` → `BadParameter`.
- `type` must be a valid `PemType` value, else `BadParameter` (reuse `PemType.from_string`, which already raises `BadParameter`).
- `ext` normalized: `.strip()` then strip a single leading `.` (`ext.lstrip(".")` is wrong — only strip one; use `ext[1:] if ext.startswith(".") else ext` after strip). Must match `^[A-Za-z0-9_-]+$`, else `BadParameter`.
- A `type` present in `values` but **not** in `pem_types` → `BadParameter` ("set extension for a type not in --pem").
- Result starts as `{t: "pem" for t in pem_types}` and applies overrides.

- [ ] **Step 1: Write the failing tests for `parse_pem_extensions`**

Append to `tests/test_pem_extensions.py`:
```python
def test_parse_default_all_pem():
    types = [PemType.CERT, PemType.PRIV_KEY]
    assert parse_pem_extensions([], types) == {PemType.CERT: "pem", PemType.PRIV_KEY: "pem"}


def test_parse_override():
    types = [PemType.CERT, PemType.PRIV_KEY]
    result = parse_pem_extensions(["cert=crt", "privkey=key"], types)
    assert result == {PemType.CERT: "crt", PemType.PRIV_KEY: "key"}


def test_parse_strips_leading_dot_and_whitespace():
    types = [PemType.CERT]
    assert parse_pem_extensions([" cert=.crt "], types) == {PemType.CERT: "crt"}


def test_parse_unknown_type_raises():
    with pytest.raises(certhub.typer.BadParameter):
        parse_pem_extensions(["bogus=crt"], [PemType.CERT])


def test_parse_invalid_ext_chars_raises():
    with pytest.raises(certhub.typer.BadParameter):
        parse_pem_extensions(["cert=cr/t"], [PemType.CERT])


def test_parse_empty_ext_raises():
    with pytest.raises(certhub.typer.BadParameter):
        parse_pem_extensions(["cert="], [PemType.CERT])


def test_parse_missing_equals_raises():
    with pytest.raises(certhub.typer.BadParameter):
        parse_pem_extensions(["cert"], [PemType.CERT])


def test_parse_type_not_in_pem_raises():
    with pytest.raises(certhub.typer.BadParameter):
        parse_pem_extensions(["privkey=key"], [PemType.CERT])
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd tests && PYTHONPATH=.. ./.venv/bin/python -m pytest test_pem_extensions.py -q`
Expected: FAIL — `cannot import name 'parse_pem_extensions'` / `AttributeError`.

- [ ] **Step 3: Implement `parse_pem_extensions` in `certhub.py`**

Insert directly after `pem_filename` (which has access to `re` and `typer`, both imported at top of file):
```python
EXT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def parse_pem_extensions(values: list[str], pem_types: list["PemType"]) -> dict["PemType", str]:
    ext_map: dict[PemType, str] = {pem_type: "pem" for pem_type in pem_types}
    for value in values:
        if "=" not in value:
            raise typer.BadParameter(f"Invalid --ext entry '{value}', expected form type=ext")
        raw_type, raw_ext = value.split("=", 1)
        pem_type = PemType.from_string(raw_type.strip())
        ext = raw_ext.strip()
        if ext.startswith("."):
            ext = ext[1:]
        if not EXT_PATTERN.fullmatch(ext):
            raise typer.BadParameter(
                f"Invalid extension '{raw_ext}' for type '{raw_type.strip()}', must match {EXT_PATTERN.pattern}"
            )
        if pem_type not in ext_map:
            raise typer.BadParameter(
                f"--ext set for type '{pem_type.value}' which is not in --pem; add '-P {pem_type.value}' or remove the --ext entry"
            )
        ext_map[pem_type] = ext
    return ext_map
```

- [ ] **Step 4: Run the whole test file to verify all pass**

Run: `cd tests && PYTHONPATH=.. ./.venv/bin/python -m pytest test_pem_extensions.py -q`
Expected: all tests pass (2 from Task 1 + 8 here = 10 passed).

- [ ] **Step 5: Commit**

```bash
git add certhub.py tests/test_pem_extensions.py
git commit -m "Add parse_pem_extensions helper with validation"
```

---

### Task 3: Wire `--ext` into `cert update-in-place` and remove hardcoded `.pem`

**Files:**
- Modify: `certhub.py` — `cert_update_in_place` (def at line 829): add `--ext` option in the signature near `--pem` (lines 839-842), build `ext_map`, replace the three `.pem` sites (943, 1017, 1049).

**Interfaces:**
- Consumes: `parse_pem_extensions` (Task 2), `pem_filename` (Task 1).

- [ ] **Step 1: Add the `--ext` option to the command signature**

In `cert_update_in_place`, immediately after the `pem` option block (ends line 842), add:
```python
    ext: list[str] = typer.Option(
        [], "--ext",
        help="Override file extension per PEM type; repeatable, form type=ext (e.g. --ext cert=crt --ext privkey=key). "
             "Default is .pem for every type. NOTE: HAProxy ignores the extension (it parses PEM content) and 'bundle' "
             "is the right type for HAProxy's crt; --ext is for consumers like nginx/Apache that key off the extension."
    ),
```

- [ ] **Step 2: Build the extension map after `pem_types` is resolved**

After the existing line `pem_types = parse_pem_types(pem)` (line 895), add:
```python
    ext_map = parse_pem_extensions(ext, pem_types)
```

- [ ] **Step 3: Replace the `pem_files` construction (current line 943)**

Change:
```python
        pem_files = [certs_dir / f"{prefix}_{pem_type.value}.pem" for pem_type in pem_types]
```
to:
```python
        pem_files = [certs_dir / pem_filename(prefix, pem_type, ext_map) for pem_type in pem_types]
```

- [ ] **Step 4: Replace the expiry-reference `ref_file` (current line 1017)**

Change:
```python
            ref_file = certs_dir / f"{prefix}_{ref_type.value}.pem"
```
to:
```python
            ref_file = certs_dir / pem_filename(prefix, ref_type, ext_map)
```

- [ ] **Step 5: Replace the post-write re-read reference file (current line 1049)**

Change:
```python
                local_expire_date = get_cert_expire_date(certs_dir / f"{prefix}_{ref_type.value}.pem")
```
to:
```python
                local_expire_date = get_cert_expire_date(certs_dir / pem_filename(prefix, ref_type, ext_map))
```

- [ ] **Step 6: Verify the module compiles**

Run: `make lint`
Expected: completes with no `py_compile` error on `certhub.py`.

- [ ] **Step 7: Verify the option is wired and help renders**

Run:
```bash
cd tests && PYTHONPATH=.. ./.venv/bin/python -c "import certhub; from typer.testing import CliRunner; r=CliRunner().invoke(certhub.app, ['cert','update-in-place','--help']); print(r.exit_code); print('--ext' in r.output)"
```
Expected: `0` then `True`.

- [ ] **Step 8: Run the full test suite**

Run: `make test`
Expected: all tests pass, including `test_pem_extensions.py` (10) and the pre-existing suite.

- [ ] **Step 9: Commit**

```bash
git add certhub.py
git commit -m "Add --ext option to cert update-in-place for configurable extensions"
```

---

### Task 4: Document `--ext` in the README

**Files:**
- Modify: `README.md` (the `cert update-in-place` section)

- [ ] **Step 1: Locate the update-in-place docs**

Run: `grep -n "update-in-place\|--pem\|update_in_place" README.md`
Expected: line numbers of the section describing the command and its options.

- [ ] **Step 2: Add `--ext` documentation**

In the `cert update-in-place` options near `--pem`/`-P`, add a description of `--ext`:
- form `type=ext`, repeatable, default `.pem` for every type;
- example `--ext cert=crt --ext privkey=key` producing `<prefix>_cert.crt`, `<prefix>_privkey.key`;
- the HAProxy note: HAProxy ignores the extension and parses PEM content, `bundle` is the right type for HAProxy's `crt`, and `--ext` is for consumers like nginx/Apache.

Match the surrounding README formatting (same heading/table/list style already used for `--pem`).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "Document --ext option for cert update-in-place"
```

---

## Self-Review

- **Spec coverage:** CLI flag + parsing/validation (Tasks 1-2), defaults all `.pem` (Global Constraints + Task 2 default map), `parse_pem_extensions` helper (Task 2), `pem_filename` helper (Task 1), three call-site replacements (Task 3 steps 3-5), HAProxy/docs note (Task 3 step 1 help text + Task 4 README), tests incl. regression/normalization/errors (Tasks 1-2). All spec sections mapped.
- **Out-of-scope items** (basename scheme, `cert get` extensions, changing defaults) are not introduced by any task. ✓
- **Type consistency:** `pem_filename(prefix, pem_type, ext_map)` and `parse_pem_extensions(values, pem_types) -> dict[PemType,str]` signatures are identical everywhere they appear. `ext_map` keys are `PemType`. ✓
- **Note on Task 1 Step 6:** the test file imports `parse_pem_extensions` (added in Task 2), so the file only goes fully green at Task 2 Step 4. This is called out explicitly so the implementer is not surprised by a red collection in Task 1.
