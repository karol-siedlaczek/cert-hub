# certbot-dns-cloudflare Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fully enable the Cloudflare DNS provider (`certbot-dns-cloudflare`) alongside the existing AWS Route 53 support.

**Architecture:** The Cloudflare certbot plugin requires a credentials INI file (it does not read env vars). The API token arrives via the `CLOUDFLARE_DNS_API_TOKEN` env var, flows `Config` → `CertBot`, and at issue/renew time `CertBot` writes an ephemeral `0600` INI file (auto-deleted after the certbot run) passed via `--dns-cloudflare-credentials`. Provider-specific certbot args are produced by a context manager so the credentials file lives only for the duration of the certbot call.

**Tech Stack:** Python 3.12+, Flask, certbot 5.2.2 + certbot-dns-cloudflare, pytest.

## Global Constraints

- All `certbot*` / `acme` pins are exactly `==5.2.2`. New dependency must be `certbot-dns-cloudflare==5.2.2`.
- Cloudflare auth: **API Token only** (`dns_cloudflare_api_token`). No legacy Global API Key + email.
- The Cloudflare credentials INI file must be ephemeral (per operation), `0600`, and never written to the persistent `CERTBOT_DIR` volume.
- One global Cloudflare token per instance (mirrors AWS), not per-cert.
- Leave `--dns-cloudflare-propagation-seconds` at certbot's default (no config).
- Tests must not require the `certbot` binary/package to be installed (test venv only has Flask, PyYAML, cryptography, pytest).
- `make test` runs pytest from inside `tests/`, so `PYTEST_FLAGS` test paths are relative to `tests/` (e.g. `test_dns_provider.py`, not `tests/test_dns_provider.py`).
- Commit messages end with: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`

---

### Task 1: Complete `DnsProvider.CF.get_required_envs()` and add tests

**Files:**
- Modify: `cert_hub/domain/dns_provider.py:25-29`
- Test: `tests/test_dns_provider.py` (create)

**Interfaces:**
- Consumes: nothing (pure enum).
- Produces:
  - `DnsProvider.values() -> list[str]` returning `["aws", "cloudflare"]`
  - `DnsProvider.CF.get_plugin() -> "dns-cloudflare"`
  - `DnsProvider.CF.get_required_module() -> "certbot-dns-cloudflare"`
  - `DnsProvider.CF.get_required_envs() -> ("CLOUDFLARE_DNS_API_TOKEN",)`
  - `DnsProvider.AWS.get_required_envs() -> ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_dns_provider.py`:

```python
from cert_hub.domain.dns_provider import DnsProvider


def test_values_lists_all_providers():
    assert DnsProvider.values() == ["aws", "cloudflare"]


def test_aws_metadata():
    assert DnsProvider.AWS.get_plugin() == "dns-route53"
    assert DnsProvider.AWS.get_required_module() == "certbot-dns-route53"
    assert DnsProvider.AWS.get_required_envs() == ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")


def test_cloudflare_metadata():
    assert DnsProvider.CF.get_plugin() == "dns-cloudflare"
    assert DnsProvider.CF.get_required_module() == "certbot-dns-cloudflare"
    assert DnsProvider.CF.get_required_envs() == ("CLOUDFLARE_DNS_API_TOKEN",)
```

- [ ] **Step 2: Run tests to verify the Cloudflare one fails**

Run: `make test PYTEST_FLAGS="-q test_dns_provider.py"`
Expected: `test_cloudflare_metadata` FAILS (`get_required_envs()` returns `("TODO")`, not `("CLOUDFLARE_DNS_API_TOKEN",)`).

- [ ] **Step 3: Fix `get_required_envs`**

In `cert_hub/domain/dns_provider.py`, replace the CF branch:

```python
    def get_required_envs(self) -> tuple[str, ...]:
        if self == DnsProvider.AWS:
            return ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
        elif self == DnsProvider.CF:
            return ("CLOUDFLARE_DNS_API_TOKEN",)
```

(Note the return type annotation changes from `tuple[str]` to `tuple[str, ...]`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `make test PYTEST_FLAGS="-q test_dns_provider.py"`
Expected: all 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add cert_hub/domain/dns_provider.py tests/test_dns_provider.py
git commit -m "Complete Cloudflare DnsProvider required envs

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Thread the Cloudflare token through `Config`

**Files:**
- Modify: `cert_hub/conf/config.py:28-29` (add field), `:57` (resolve secret), `:73-87` (pass to constructor)

**Interfaces:**
- Consumes: existing `Config._resolve_secret(name: str) -> str | None` (supports `<name>__FILE`).
- Produces: `Config.cloudflare_dns_api_token: str | None` populated from `CLOUDFLARE_DNS_API_TOKEN` (or `CLOUDFLARE_DNS_API_TOKEN__FILE`).

- [ ] **Step 1: Add the dataclass field**

In `cert_hub/conf/config.py`, after the `aws_secret_access_key` field (line 29), add:

```python
    cloudflare_dns_api_token: str = None
```

- [ ] **Step 2: Resolve the secret in `load()`**

After the `aws_secret_access_key = cls._resolve_secret("AWS_SECRET_ACCESS_KEY")` line (line 57), add:

```python
        cloudflare_dns_api_token = cls._resolve_secret("CLOUDFLARE_DNS_API_TOKEN")
```

- [ ] **Step 3: Pass it to the constructor**

In the `return cls(...)` call, after `aws_secret_access_key=aws_secret_access_key,`, add:

```python
            cloudflare_dns_api_token=cloudflare_dns_api_token,
```

- [ ] **Step 4: Verify the module imports cleanly**

Run: `make lint`
Expected: `py_compile` prints `OK` (no syntax errors).

- [ ] **Step 5: Commit**

```bash
git add cert_hub/conf/config.py
git commit -m "Resolve Cloudflare DNS API token in Config

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Build provider args + ephemeral credentials file in `CertBot`

**Files:**
- Modify: `cert_hub/domain/cert_bot.py` (imports, dataclass field, `load()` signature, new `_dns_provider_args`, `issue`, `renew`)
- Test: `tests/test_cert_bot.py` (create)

**Interfaces:**
- Consumes: `Config.cloudflare_dns_api_token` (Task 2), `DnsProvider.get_plugin()` (Task 1).
- Produces:
  - `CertBot.load(acme_server, base_dir, exe_path, renew_before_days, test_cert=False, cloudflare_dns_api_token=None) -> CertBot`
  - `CertBot.cloudflare_dns_api_token: str | None` field
  - `CertBot._dns_provider_args(self, dns_provider: DnsProvider)` — a `@contextmanager` yielding `list[str]` of certbot args; for CF it also creates/destroys a `0600` INI temp file.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_cert_bot.py`:

```python
import os
import stat
from pathlib import Path

from cert_hub.domain.cert_bot import CertBot
from cert_hub.domain.dns_provider import DnsProvider


def _make_certbot(token=None):
    return CertBot.load(
        acme_server="https://acme.example/directory",
        base_dir=Path("/tmp/certbot-test"),
        exe_path=Path("/usr/bin/certbot"),
        renew_before_days=30,
        cloudflare_dns_api_token=token,
    )


def test_aws_provider_args_is_plugin_flag_only():
    certbot = _make_certbot()
    with certbot._dns_provider_args(DnsProvider.AWS) as args:
        assert args == ["--dns-route53"]


def test_cloudflare_provider_args_and_credentials_file_lifecycle():
    certbot = _make_certbot(token="secret-token")
    with certbot._dns_provider_args(DnsProvider.CF) as args:
        assert args[0] == "--dns-cloudflare"
        assert "--dns-cloudflare-credentials" in args
        cred_path = Path(args[args.index("--dns-cloudflare-credentials") + 1])
        # File exists, is 0600, and holds the token while the block is open
        assert cred_path.exists()
        mode = stat.S_IMODE(os.stat(cred_path).st_mode)
        assert mode == 0o600
        assert cred_path.read_text() == "dns_cloudflare_api_token = secret-token\n"
    # File is removed after the block closes
    assert not cred_path.exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test PYTEST_FLAGS="-q test_cert_bot.py"`
Expected: FAIL — `CertBot.load()` does not accept `cloudflare_dns_api_token`, and `_dns_provider_args` does not exist.

- [ ] **Step 3: Add imports and the dataclass field**

In `cert_hub/domain/cert_bot.py`, update the top imports (lines 1-5) to add `os`, `tempfile`, and `contextmanager`:

```python
import os
import subprocess
import logging
import tempfile
from pathlib import Path
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Sequence, Optional, cast, Iterator
```

In the `CertBot` dataclass, after `base_args: Sequence[str]` (line 21), add:

```python
    cloudflare_dns_api_token: Optional[str] = None
```

- [ ] **Step 4: Extend `load()` signature and constructor call**

Change the `load` signature to accept the token (add after `test_cert: bool = False`):

```python
    @classmethod
    def load(
        cls,
        acme_server: str,
        base_dir: Path,
        exe_path: Path,
        renew_before_days: int,
        test_cert: bool = False,
        cloudflare_dns_api_token: Optional[str] = None
    ) -> "CertBot":
```

In the `return cls(...)` block, after `base_args = base_args`, add:

```python
            cloudflare_dns_api_token = cloudflare_dns_api_token
```

- [ ] **Step 5: Add the `_dns_provider_args` context manager**

Add this method to `CertBot` (e.g. just above `_run_cmd`):

```python
    @contextmanager
    def _dns_provider_args(self, dns_provider: DnsProvider) -> Iterator[list[str]]:
        if dns_provider == DnsProvider.CF:
            with tempfile.NamedTemporaryFile("w", suffix=".ini", encoding="utf-8") as f:
                os.chmod(f.name, 0o600)
                f.write(f"dns_cloudflare_api_token = {self.cloudflare_dns_api_token}\n")
                f.flush()
                yield ["--dns-cloudflare", "--dns-cloudflare-credentials", f.name]
        else:
            yield [f"--{dns_provider.get_plugin()}"]
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `make test PYTEST_FLAGS="-q test_cert_bot.py"`
Expected: both tests PASS.

- [ ] **Step 7: Rewrite `issue` to use the context manager**

Replace the body of `issue` so the command is built and run inside the `with` block:

```python
    def issue(self, cert_name: str, domains: list[str], email: str, dns_provider: DnsProvider) -> None:
        with self._dns_provider_args(dns_provider) as dns_args:
            cmd = [
                str(self.exe_path),
                "certonly",
                "--cert-name", cert_name,
                "-d", (',').join(domains),
                "--email", email,
                *dns_args,
                "--agree-tos",
                *self.base_args
            ]
            log.debug(f"Certbot issue command for '{cert_name}' certificate: {' '.join(cmd)}")

            result = self._run_cmd(cmd)
            if result.returncode != 0:
                raise CertBotError(cert_name, return_code=result.returncode, cmd=cmd, output=result.stderr)
```

- [ ] **Step 8: Rewrite `renew` to use the context manager**

```python
    def renew(self, cert_name: str, dns_provider: DnsProvider) -> None:
        with self._dns_provider_args(dns_provider) as dns_args:
            cmd = [
                str(self.exe_path),
                "renew",
                "--cert-name", cert_name,
                *dns_args,
                *self.base_args
            ]
            log.debug(f"Certbot renew command for '{cert_name}' certificate: {' '.join(cmd)}")

            result = self._run_cmd(cmd)
            if result.returncode != 0:
                raise CertBotError(cert_name, return_code=result.returncode, cmd=cmd, output=result.stderr)
```

- [ ] **Step 9: Verify lint + tests**

Run: `make lint && make test PYTEST_FLAGS="-q test_cert_bot.py"`
Expected: `py_compile` OK; both tests PASS.

- [ ] **Step 10: Commit**

```bash
git add cert_hub/domain/cert_bot.py tests/test_cert_bot.py
git commit -m "Generate ephemeral Cloudflare credentials file for certbot

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Wire the token from `create_app` into `CertBot.load`

**Files:**
- Modify: `cert_hub/app.py:20-26`

**Interfaces:**
- Consumes: `Config.cloudflare_dns_api_token` (Task 2), `CertBot.load(..., cloudflare_dns_api_token=...)` (Task 3).
- Produces: a `CertBot` instance carrying the Cloudflare token, registered at `app.extensions["certbot"]`.

- [ ] **Step 1: Pass the token in `create_app`**

In `cert_hub/app.py`, extend the `CertBot.load(...)` call (lines 20-26):

```python
    certbot = CertBot.load(
        config.certbot_acme_server,
        config.certbot_dir,
        config.certbot_bin,
        config.certbot_renew_before_days,
        config.certbot_test_cert,
        config.cloudflare_dns_api_token
    )
```

- [ ] **Step 2: Verify lint passes**

Run: `make lint`
Expected: `py_compile` prints `OK`.

- [ ] **Step 3: Commit**

```bash
git add cert_hub/app.py
git commit -m "Wire Cloudflare token from Config into CertBot

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Add the `certbot-dns-cloudflare` dependency

**Files:**
- Modify: `requirements.txt:4` (after `certbot-dns-route53==5.2.2`)

**Interfaces:**
- Consumes: nothing.
- Produces: the `certbot-dns-cloudflare` plugin installed in the image (Dockerfile already runs `pip install -r requirements.txt`, so no Dockerfile change).

- [ ] **Step 1: Add the pin**

In `requirements.txt`, after the `certbot-dns-route53==5.2.2` line, add:

```
certbot-dns-cloudflare==5.2.2
```

- [ ] **Step 2: Commit**

```bash
git add requirements.txt
git commit -m "Add certbot-dns-cloudflare dependency

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Update README documentation

**Files:**
- Modify: `README.md` (environments table ~line 123-124; "currently supported value is `aws`" notes at lines 167, and config example commentary as needed)

**Interfaces:**
- Consumes: env name `CLOUDFLARE_DNS_API_TOKEN` (Task 2).
- Produces: docs reflecting Cloudflare support.

- [ ] **Step 1: Add the env var to the environments table**

In `README.md`, after the `AWS_SECRET_ACCESS_KEY` row (line 124), add:

```
| `CLOUDFLARE_DNS_API_TOKEN` | `string` | :x: | - | Cloudflare scoped API token (with `Zone:DNS:Edit`). Required only if `cloudflare` DNS provider is used in certificate configuration. Also accepts `CLOUDFLARE_DNS_API_TOKEN__FILE` pointing to a file with the token. |
```

- [ ] **Step 2: Update the supported-providers note**

In `README.md`, change the field description line (line 167) from:

```
- `certs[].dns_provider` - currently supported value is `aws`.
```

to:

```
- `certs[].dns_provider` - supported values are `aws` (Route 53) and `cloudflare`.
```

- [ ] **Step 3: Verify the table renders (no broken pipes)**

Run: `grep -n "CLOUDFLARE_DNS_API_TOKEN" README.md`
Expected: one matching row in the environments table.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "Document Cloudflare DNS provider support

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Full test + lint sweep

**Files:** none (verification only).

- [ ] **Step 1: Run the entire test suite**

Run: `make test`
Expected: all tests PASS (existing `test_validators.py`, `test_context.py`, plus new `test_dns_provider.py`, `test_cert_bot.py`).

- [ ] **Step 2: Run lint**

Run: `make lint`
Expected: `py_compile` prints `OK`.

- [ ] **Step 3 (optional, if Docker available): build the image to confirm the new dependency installs**

Run: `make build`
Expected: image builds; `pip install` resolves `certbot-dns-cloudflare==5.2.2`.

---

## Self-Review

**Spec coverage:**
- Env `CLOUDFLARE_DNS_API_TOKEN` + `_resolve_secret` → Task 2. ✓
- `get_required_envs` for CF → Task 1. ✓
- Ephemeral `0600` INI file via context manager → Task 3. ✓
- `issue`/`renew` run certbot inside the `with` block → Task 3 (steps 7-8). ✓
- Token flow Config → CertBot → create_app → Task 2, 3, 4. ✓
- `requirements.txt` dependency → Task 5. ✓
- README env table + supported-providers note → Task 6. ✓
- Tests runnable without certbot installed → Tasks 1 & 3 import only `DnsProvider`/`CertBot` (cert_bot.py imports `flask`, present in test venv). ✓
- `--dns-cloudflare-propagation-seconds` left default; legacy auth out of scope; one global token → respected (no tasks added). ✓

**Placeholder scan:** No TBD/TODO/"handle errors"/"similar to" — all steps contain concrete code/commands. ✓

**Type consistency:** `cloudflare_dns_api_token` named identically across Config field, CertBot field, `load()` param, and `create_app` call. `_dns_provider_args` signature/return (`list[str]` via `@contextmanager`) consistent between definition (Task 3) and usage (Task 3 steps 7-8). `get_required_envs` return type `tuple[str, ...]`. ✓
