# Design: `cert show` command + single-row (vertical) render

Date: 2026-07-01

## Goal

Add a `certhub cert show <cert_id>` command that displays a single certificate,
mirroring the `<resource> show <id>` convention from the mail-controller CLI.
For the default `table` format, render the record **vertically** (a two-column
`Field` / `Value` table) instead of the current horizontal one-column-per-field
table. Whether the vertical layout is used is decided **top-down by the calling
command**, not inferred from data shape — a list command that happens to return
one row still uses the classic horizontal table.

## Data source

Reuse the existing `GET /api/certs?match=<id>` endpoint (in `cert_hub/api/routes.py`).
It already returns full per-cert data for each match: `id`, `type`, `status`,
`msg`, `custom_attrs`, `domains`, `expire_date`, `days_to_expire`, `chain`,
`certificate`, `private_key`. No server-side changes are required.

The command queries with `type=all` so a cert is found by id regardless of its
type.

## Component 1 — `render_and_exit()` gains a `single_row` flag

New keyword-only parameter on `CmdResult.render_and_exit` (in `certhub.py`):

```python
def render_and_exit(self, context_info=None, columns=None, *,
                    sensitive_columns=None, single_row=False) -> NoReturn
```

Key observation: when `self.data` is already a single **dict** (not a list), the
`json`, `value` and `key_value` formats already render correctly on their own —
JSON emits `{}`, `key_value` emits vertical `key = val`, `value` emits the values.
The only format that renders a dict as a horizontal one-row table is `table`.

Therefore `single_row` has two effects:

1. **Data normalization is done by the command** (see Component 2): `cert show`
   sets `result.data = matched[0]` so the payload is a dict, not a
   single-element list. This alone makes JSON output `{}` instead of `[{}]`, and
   `value` / `key_value` keep working unchanged.
2. **`Format.TABLE` branch:** when `single_row=True`, build a vertical table with
   two columns, `Field` and `Value`, adding one row per key of the dict
   (preserving the dict's insertion order from the API), using the existing
   `_render_table_cell()` helper to format each value. When `single_row=False`,
   keep the current horizontal behavior.

Everything else is unchanged and already dict-aware:
- `_filter_data()` with `--column` already filters dict keys.
- Sensitive-column masking in the log already recurses over dicts.
- Error coloring and exit-code handling are format-agnostic.

Format behavior summary under `single_row=True` (data is a dict):

| Format     | Output                                             |
|------------|----------------------------------------------------|
| `json`     | single object `{}` (not a list)                    |
| `value`    | values, one per line (unchanged dict path)         |
| `key_value`| `key = val`, one per line (unchanged dict path)    |
| `table`    | **NEW** vertical `Field` / `Value` table           |

## Component 2 — new `cert show` command

Added to `cert_app` in `certhub.py`, alongside `list` / `status` / `pem`:

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
    response = client.request("GET", "/api/certs",
                              params={"match": [cert_id], "type": cert_type.value})

    result = CmdResult.from_response(response)
    sensitive_columns = ("certificate", "chain", "private_key")

    if response.ok:
        certs = result.data                       # list of dicts
        exact = [c for c in certs if c.get("id") == cert_id]
        matched = exact or certs
        if not matched:
            result = CmdResult.from_dict(
                {"id": cert_id, "msg": "Certificate not found"}, ExitCode.CRITICAL)
        elif len(matched) > 1:
            result = CmdResult.from_dict(
                {"id": cert_id,
                 "msg": f"Ambiguous id, matched {len(matched)} certs",
                 "matched": [c["id"] for c in matched]}, ExitCode.CRITICAL)
        else:
            result.data = matched[0]              # dict -> triggers single-row render

    return result.render_and_exit(ctx.info_name, columns,
                                  sensitive_columns=sensitive_columns, single_row=True)
```

Decisions baked in:
- **Sensitive fields are shown** (`certificate`, `chain`, `private_key`) since this
  is an intentional single-cert view — no `--long` gate. They are still masked in
  the log via `sensitive_columns`.
- `type` defaults to `CertType.ALL` so `show <id>` finds the cert regardless of type.

### Error handling

- **0 matches** → `CRITICAL`, `{id, msg: "Certificate not found"}`, still rendered
  vertically (single_row=True).
- **>1 matches** (only possible if `match` contains glob chars) → first retry with
  exact `id == cert_id`; if still ambiguous → `CRITICAL` "Ambiguous id" including
  the list of matched ids.
- **HTTP error from server** (403/404/500) → `from_response` already sets the error
  envelope dict + `CRITICAL`; renders in red, vertically under single_row.

## Component 3 — docs & tests

- **README.md**: add `cert show` to the command list with an example of the
  vertical output.
- **Tests** (`tests/`, following the `test_sync.py` `CliRunner` + monkeypatched
  `Client.init` pattern):
  - vertical `table` render when `single_row=True` (Field/Value layout);
  - list→dict normalization: JSON output is `{}`, not `[{}]`;
  - `--column` filtering still works in single-row mode;
  - not-found → CRITICAL exit + message;
  - ambiguous (glob) → CRITICAL exit + matched ids.

## Out of scope (YAGNI)

- No new server endpoint (`/api/certs/<id>`).
- No `--long` flag on `show`.
- No change to `list` / `status` / other commands' rendering (they keep
  horizontal tables; `single_row` defaults to `False`).
