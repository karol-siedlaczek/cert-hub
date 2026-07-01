# cert show + single-row render Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `certhub cert show <cert_id>` command that displays one certificate, with `table` output rendered vertically (Field/Value) via a top-down `single_row` flag on `render_and_exit()`.

**Architecture:** Reuse `GET /api/certs?match=<id>` (no server change). The command unwraps the single matching cert dict and calls `render_and_exit(..., single_row=True)`. `single_row` only changes the `Format.TABLE` branch to a two-column vertical table; `json`/`value`/`key_value` already render a dict correctly (JSON becomes `{}` instead of `[{}]` simply because the data is a dict).

**Tech Stack:** Python 3.12, Typer, Rich (`Table`, `Console`), pytest + `typer.testing.CliRunner`.

## Global Constraints

- CLI lives entirely in `certhub.py` (single-file CLI). Add commands/params there, following existing `cert_app` command style.
- Tests follow the `tests/test_sync.py` pattern: monkeypatch `certhub.Client.init` to a fake client, pin output via monkeypatched `certhub.get_ctx_settings`, use `CliRunner` / `capsys`.
- Sensitive columns for logging masking are always `("certificate", "chain", "private_key")`.
- Existing commands (`list`, `status`, etc.) must keep horizontal tables — `single_row` defaults to `False`.

---

### Task 1: `single_row` flag + vertical table render in `render_and_exit()`

**Files:**
- Modify: `certhub.py` — signature at `certhub.py:273-279`; `Format.TABLE` branch at `certhub.py:384-398`
- Test: `tests/test_cert_show.py` (create)

**Interfaces:**
- Consumes: existing `CmdResult`, `ExitCode`, `Format`, `get_ctx_settings`, nested `_render_table_cell`.
- Produces: `CmdResult.render_and_exit(context_info=None, columns=None, *, sensitive_columns=None, single_row=False) -> NoReturn`. When `single_row=True` and `fmt == Format.TABLE` and data is a dict, prints a two-column table with header `Field` / `Value`, one row per key (insertion order).

- [ ] **Step 1: Write the failing test**

Create `tests/test_cert_show.py`:

```python
"""Tests for `cert show` and single-row (vertical) rendering."""

import json

import pytest
import typer
from typer.testing import CliRunner

import certhub

ENV = {"CERTHUB_API_URL": "http://x", "CERTHUB_TOKEN": "t"}


@pytest.fixture(autouse=True)
def _isolate_settings_file(tmp_path, monkeypatch):
    # Same isolation as tests/test_sync.py: ignore any real ~/.certhub and keep
    # the logger disabled by giving no LOG_FILE.
    monkeypatch.setattr(certhub, "SETTINGS_FILE", tmp_path / "nonexistent-certhub")


def _pin_format(monkeypatch, fmt):
    settings = certhub.Settings(
        api_url="http://x", token="t", log_file=None, log_level=None, format=fmt,
    )
    monkeypatch.setattr(certhub, "get_ctx_settings", lambda: settings)


def test_single_row_table_is_vertical(monkeypatch, capsys):
    _pin_format(monkeypatch, certhub.Format.TABLE)
    result = certhub.CmdResult.from_dict(
        {"id": "siedlaczek.com.pl", "status": "OK"}, certhub.ExitCode.OK)

    with pytest.raises(typer.Exit) as exc:
        result.render_and_exit(single_row=True)

    assert exc.value.exit_code == 0
    out = capsys.readouterr().out
    assert "Field" in out and "Value" in out
    assert "siedlaczek.com.pl" in out
    assert "status" in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd tests && . .venv/bin/activate && cd .. && python -m pytest tests/test_cert_show.py::test_single_row_table_is_vertical -v`
Expected: FAIL — `render_and_exit()` got an unexpected keyword argument `single_row`.

- [ ] **Step 3: Add the `single_row` parameter**

In `certhub.py`, change the signature (currently `certhub.py:273-279`):

```python
    def render_and_exit(
        self,
        context_info: str | None = None,
        columns: tuple[str] | None = None,
        *,
        sensitive_columns: tuple[str] | None = None,
        single_row: bool = False
    ) -> NoReturn:
```

- [ ] **Step 4: Add the vertical branch to `Format.TABLE`**

In `certhub.py`, replace the `elif fmt == Format.TABLE:` block (currently `certhub.py:384-398`) with:

```python
        elif fmt == Format.TABLE:
            if single_row and isinstance(data, dict):
                table = Table(show_header=True, header_style="bold", expand=True, show_lines=True, box=box.ROUNDED)
                table.add_column("Field", overflow="fold")
                table.add_column("Value", overflow="fold")
                for key, val in data.items():
                    table.add_row(str(key), _render_table_cell(val))
                _print(table)
            else:
                rows = data if isinstance(data, list) else [data]
                rows = [r for r in rows if isinstance(r, dict)]
                if rows:
                    table = Table(show_header=True, header_style="bold", expand=True, show_lines=True, box=box.ROUNDED)

                    cols = list(rows[0].keys())
                    for c in cols:
                        table.add_column(str(c), overflow="fold") # Fold helps if mucho text

                    for row in rows:
                        table.add_row(*[_render_table_cell(row.get(c, "")) for c in cols])
                    _print(table)
                elif data:
                    _print(data)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/test_cert_show.py::test_single_row_table_is_vertical -v`
Expected: PASS

- [ ] **Step 6: Run the full suite to confirm no regressions**

Run: `python -m pytest tests/ -q`
Expected: PASS (existing horizontal-table behavior unchanged — `single_row` defaults to `False`).

- [ ] **Step 7: Commit**

```bash
git add certhub.py tests/test_cert_show.py
git commit -m "feat: add single_row vertical table render to render_and_exit

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `cert show` command

**Files:**
- Modify: `certhub.py` — add command in `cert_app` group (near `cert_list` at `certhub.py:736`)
- Test: `tests/test_cert_show.py` (extend)

**Interfaces:**
- Consumes: `render_and_exit(..., single_row=True)` from Task 1; existing `Client`, `CmdResult.from_response`/`from_dict`, `Opt`, `CertType`, `ExitCode`.
- Produces: `cert show <cert_id>` subcommand. On success renders one cert dict single-row; not-found and ambiguous cases exit `CRITICAL` (code 2).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cert_show.py`:

```python
class _FakeResponse:
    def __init__(self, payload, ok=True, status_code=200):
        self._payload = payload
        self.ok = ok
        self.status_code = status_code
        self.text = "" if payload is None else str(payload)

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, payload):
        self._payload = payload

    def request(self, method, path, *, params=None, json_body=None):
        return _FakeResponse(self._payload)


def _patch_client(monkeypatch, payload):
    monkeypatch.setattr(
        certhub.Client, "init",
        classmethod(lambda cls, ctx, fmt, *, timeout: _FakeClient(payload)),
    )


def _show(monkeypatch, payload, cert_id, extra_args=None, fmt=certhub.Format.JSON):
    _pin_format(monkeypatch, fmt)
    _patch_client(monkeypatch, payload)
    runner = CliRunner()
    args = ["cert", "show", cert_id] + (extra_args or [])
    return runner.invoke(certhub.app, args, env=ENV)


def test_show_json_is_single_object(monkeypatch):
    payload = [{"id": "siedlaczek.com.pl", "status": "OK", "type": "letsencrypt"}]
    result = _show(monkeypatch, payload, "siedlaczek.com.pl")
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert isinstance(parsed, dict)          # {} not [{}]
    assert parsed["id"] == "siedlaczek.com.pl"


def test_show_not_found_is_critical(monkeypatch):
    result = _show(monkeypatch, [], "missing.example")
    assert result.exit_code == 2, result.output
    assert "not found" in result.output.lower()


def test_show_ambiguous_is_critical(monkeypatch):
    payload = [{"id": "a.example"}, {"id": "b.example"}]
    result = _show(monkeypatch, payload, "*.example")
    assert result.exit_code == 2, result.output
    assert "ambiguous" in result.output.lower()


def test_show_exact_match_wins_over_glob_siblings(monkeypatch):
    payload = [{"id": "a.example", "status": "OK"},
               {"id": "b.example", "status": "OK"}]
    result = _show(monkeypatch, payload, "a.example")
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert parsed["id"] == "a.example"


def test_show_column_filter(monkeypatch):
    payload = [{"id": "siedlaczek.com.pl", "status": "OK", "type": "letsencrypt"}]
    result = _show(monkeypatch, payload, "siedlaczek.com.pl", ["-c", "id"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert parsed == {"id": "siedlaczek.com.pl"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cert_show.py -v -k "show"`
Expected: FAIL — no such command `show` (CliRunner exit_code 2 with usage error, or missing command message), so the JSON/exact-match assertions fail.

- [ ] **Step 3: Implement the command**

In `certhub.py`, add after the `cert_list` command (after `certhub.py:763`):

```python
@cert_app.command(name="show", help="Show details for a single certificate")
def cert_show(
    ctx: typer.Context,
    cert_id: str = typer.Argument(..., help="Certificate id to show"),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns(),
    type: str = Opt.type(CertType.ALL),
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    cert_type = CertType.from_string(type)
    response = client.request(
        "GET", "/api/certs", params={"match": [cert_id], "type": cert_type.value})

    result = CmdResult.from_response(response)
    sensitive_columns = ("certificate", "chain", "private_key")

    if response.ok:
        certs = result.data
        exact = [c for c in certs if c.get("id") == cert_id]
        matched = exact or certs
        if not matched:
            result = CmdResult.from_dict(
                {"id": cert_id, "msg": "Certificate not found"}, ExitCode.CRITICAL)
        elif len(matched) > 1:
            result = CmdResult.from_dict(
                {
                    "id": cert_id,
                    "msg": f"Ambiguous id, matched {len(matched)} certs",
                    "matched": [c["id"] for c in matched],
                },
                ExitCode.CRITICAL,
            )
        else:
            result.data = matched[0]

    return result.render_and_exit(
        ctx.info_name, columns, sensitive_columns=sensitive_columns, single_row=True)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cert_show.py -v`
Expected: PASS (all `show` tests plus the Task 1 render test).

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest tests/ -q`
Expected: PASS

- [ ] **Step 6: Manual smoke check of the vertical view**

Run: `python -m pytest tests/test_cert_show.py -v` already covers it; optionally verify help text:
Run: `python certhub.py cert show --help`
Expected: shows the `show` command usage with the `CERT_ID` argument.

- [ ] **Step 7: Commit**

```bash
git add certhub.py tests/test_cert_show.py
git commit -m "feat: add 'cert show' command for single-cert vertical view

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Document `cert show` in README

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the `cert show` command from Task 2. No code produced.

- [ ] **Step 1: Locate the command reference**

Run: `grep -n "cert list\|cert status\|cert pem" README.md`
Expected: line numbers of the existing cert command docs.

- [ ] **Step 2: Add a `cert show` entry**

Insert a `cert show` section next to the existing `cert list` docs, matching the surrounding format. Use this content:

````markdown
### `cert show <cert_id>`

Show details for a single certificate. Unlike `cert list`, the default `table`
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
````

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document 'cert show' command

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- Data source (reuse `/api/certs?match`) → Task 2. ✓
- Show all sensitive fields, mask in logs → Task 2 (`sensitive_columns` passed, no `--long` gate). ✓
- `single_row` flag, top-down → Task 1 (param) + Task 2 (passes `single_row=True`). ✓
- JSON single object, value/kv unchanged, table vertical → Task 1 (table branch) + normalization to dict in Task 2 (`result.data = matched[0]`). JSON `{}` verified by `test_show_json_is_single_object`. ✓
- Error handling: not-found, ambiguous, HTTP error → Task 2 + tests. ✓
- README + tests → Task 3, Tasks 1-2. ✓

**Placeholder scan:** No TBD/TODO; every code step shows full code. ✓

**Type consistency:** `render_and_exit(..., single_row=False)` defined in Task 1 and called with `single_row=True` in Task 2. `CertType.ALL` exists (`cert_hub/domain/cert/cert_type.py:4`). `sensitive_columns` tuple matches existing `cert_list` usage. ✓

Note for implementer: the pytest commands assume the venv at `tests/.venv`. If your shell already has pytest + project deps, run `python -m pytest tests/...` directly.
