# Configurable file extensions for `cert update-in-place`

**Date:** 2026-06-26
**Status:** Approved

## Problem

`cert update-in-place` always writes produced PEM material with a hardcoded
`.pem` extension. Files are named `<prefix>_<type>.pem` where `<type>` is one of
the `PemType` values (`cert`, `privkey`, `chain`, `bundle`). Consumers other than
HAProxy (e.g. nginx, Apache) conventionally expect type-specific extensions such
as `.crt` for certificates and `.key` for private keys.

HAProxy itself does not care about the extension — it parses files by their PEM
content markers, and `bundle` is the correct type to feed to `crt`. So extension
control is purely for the benefit of other consumers; it must be opt-in and must
not change existing behaviour by default.

## Goal

Allow each produced PEM type to be written with a configurable extension, while
keeping `.pem` as the default for every type so existing deployments and hooks
are unaffected.

## CLI

New repeatable option on the `cert update-in-place` command, consistent with the
existing repeatable `--pem`/`-P` option:

```
--ext type=ext        # repeatable
```

Example:

```
certhub cert update-in-place -d /etc/ssl -P cert -P privkey \
    --ext cert=crt --ext privkey=key
# produces: <prefix>_cert.crt, <prefix>_privkey.key
```

### Parsing and validation

- `type` must be a valid `PemType` value (`cert`/`privkey`/`chain`/`bundle`).
  Otherwise raise `typer.BadParameter`.
- `ext` is normalized: strip surrounding whitespace and a single leading dot, so
  `--ext cert=.crt` is equivalent to `--ext cert=crt`.
- `ext` must match `^[A-Za-z0-9_-]+$` (no path separators, no empty value).
  Otherwise raise `typer.BadParameter`.
- An `--ext` entry for a type that is **not** in `--pem` raises
  `typer.BadParameter` — protects against typos where an extension is set but no
  matching file is produced.
- Each value must be in `type=ext` form; malformed entries raise
  `typer.BadParameter`.

### Defaults

Every `PemType` defaults to extension `pem`. This includes `chain` and `bundle`
— no type gets a non-`.pem` default. Behaviour with no `--ext` flag is identical
to today.

## Implementation

### New helper: extension map

Alongside `parse_pem_types`:

```python
def parse_pem_extensions(values: list[str], pem_types: list[PemType]) -> dict[PemType, str]
```

Returns `{PemType: ext}` for every produced type, defaulting to `"pem"` and
overridden by parsed `--ext` entries. Performs the validation above.

### New helper: filename construction

To avoid duplicating the name-joining logic across the three current hardcoded
`.pem` sites:

```python
def pem_filename(prefix: str, pem_type: PemType, ext_map: dict[PemType, str]) -> str:
    return f"{prefix}_{pem_type.value}.{ext_map[pem_type]}"
```

### Call sites to update

The hardcoded `.pem` currently appears in three places inside
`cert_update_in_place` and all must use the resolved extension so the
"is up to date" / revoke-cleanup / expiry-reference logic keeps matching the
files that are actually written:

1. Building `pem_files` (the list of files to produce/remove).
2. Building `ref_file` when reading the local expiry date before writing.
3. Re-reading the just-written reference file to report its expiry.

The expiry-reference type is chosen by `expiry_reference_type(pem_types)`; its
filename must be built with the same `ext_map`.

## HAProxy / documentation note

Document (in the `--ext` help text and/or README) that:

- HAProxy ignores the file extension and parses by PEM content; `bundle` is the
  correct type to use with HAProxy's `crt`.
- `--ext` exists for other consumers (nginx, Apache) that key off conventional
  extensions.

## Testing

Extend the existing `cert update-in-place` tests:

- Regression: with no `--ext`, files are still written as `<prefix>_<type>.pem`.
- `--ext cert=crt --ext privkey=key` produces the correctly-named files.
- Leading-dot normalization: `--ext cert=.crt` produces `_cert.crt`.
- Expiry/update logic works with a custom extension (existing file with custom
  ext is detected, compared, and updated correctly).
- Revoke cleanup removes the custom-extension files.
- Errors raise `BadParameter`: unknown `PemType`, invalid `ext` characters,
  `--ext` for a type not in `--pem`, and malformed `type=ext` entries.

## Out of scope

- Changing the `<prefix>_<type>` basename scheme (the `_<type>` suffix stays).
- Per-type extensions for the plain `cert get`/fetch command.
- Changing default extensions away from `.pem`.
