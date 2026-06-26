# Static Certificates + Cert Polymorphism Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add manually-managed "static" certificates alongside Let's Encrypt certificates, by turning `Cert` into an abstract base with `LetsEncryptCert` and `StaticCert` subclasses, and exposing the cert type through API and CLI.

**Architecture:** `cert_hub/domain/cert.py` becomes an abstract base `Cert` (plus a `CertType` enum) holding shared status/expiry/permission logic over abstract file accessors. `LetsEncryptCert` (new file) keeps today's certbot-backed behavior; `StaticCert` (new file) reads three files (`cert_file`, `privkey_file`, optional `chain_file`) under `STATIC_CERTS_DIR`. Config parses two top-level keys (`letsencrypt_certs`, `static_certs`) into one merged `conf.certs` list with globally-unique ids. API/CLI gain a `type` field and a `letsencrypt|static|all` filter.

**Tech Stack:** Python 3.12+, Flask, certbot, Typer (CLI), `cryptography` (X.509 parsing), pytest.

## Global Constraints

- Cert type values are exactly `"letsencrypt"` and `"static"`; the type filter value set is exactly `{"letsencrypt", "static", "all"}` (`all` = no filter).
- Config top-level keys are `letsencrypt_certs:` and `static_certs:`. The old `certs:` key is **removed** (breaking change) — no backward-compat alias.
- Static cert requires `cert_file` and `privkey_file`; `chain_file` is optional. Files are referenced by **name** (no absolute paths, no `..`) resolved against `STATIC_CERTS_DIR` (env, default `/static-certs`).
- API field/order: each cert object in `/api/certs`, `/api/certs/status`, `/api/certs/issue`, `/api/certs/renew` includes `"type"`.
- `issue`/`renew` on a static cert raise `CertException(status=CertStatus.NOT_SUPPORTED)` (reported per-cert, never aborts the batch).
- Static `domains` come from the certificate's SAN when parseable, else `None`/empty.
- Python attribute for the type is `cert_type` (a `ClassVar[CertType]`); the JSON field is `"type"` serialized as `cert.cert_type.value`.
- Tests must not require the `certbot` binary/package nor the route53 DNS plugin (test venv has only Flask, PyYAML, cryptography, pytest). Do not write tests that call `LetsEncryptCert.from_dict` (it calls `Require.installed_module("certbot-dns-route53")`, absent in the venv) or that invoke certbot.
- `make test` runs pytest from inside `tests/`; `PYTEST_FLAGS` paths are relative to `tests/`.
- This work is intentionally NOT committed (user instruction). Each task ends WITHOUT a git commit. Do not stage, branch, revert, or touch the unrelated pre-existing working-tree changes.

---

### Task 1: Add new CertStatus values

**Files:**
- Modify: `cert_hub/domain/cert_status.py`
- Test: `tests/test_cert_status.py` (create)

**Interfaces:**
- Produces: `CertStatus.CERT_MISSING`, `CertStatus.KEY_MISSING`, `CertStatus.CHAIN_MISSING`, `CertStatus.INVALID_CERT_FILE`, `CertStatus.NOT_SUPPORTED` (each `.value` equals its name).

- [ ] **Step 1: Write the failing test**

Create `tests/test_cert_status.py`:

```python
from cert_hub.domain.cert_status import CertStatus


def test_new_static_statuses_exist_with_matching_values():
    for name in ("CERT_MISSING", "KEY_MISSING", "CHAIN_MISSING", "INVALID_CERT_FILE", "NOT_SUPPORTED"):
        member = CertStatus[name]
        assert member.value == name
```

- [ ] **Step 2: Run test to verify it fails**

Run: `make test PYTEST_FLAGS="-q test_cert_status.py"`
Expected: FAIL with `KeyError: 'CERT_MISSING'`.

- [ ] **Step 3: Add the enum members**

In `cert_hub/domain/cert_status.py`, append inside `class CertStatus(Enum)` after `NOT_YET_RENEWABLE`:

```python
    CERT_MISSING = "CERT_MISSING"
    KEY_MISSING = "KEY_MISSING"
    CHAIN_MISSING = "CHAIN_MISSING"
    INVALID_CERT_FILE = "INVALID_CERT_FILE"
    NOT_SUPPORTED = "NOT_SUPPORTED"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `make test PYTEST_FLAGS="-q test_cert_status.py"`
Expected: PASS.

- [ ] **Step 5: Verify nothing else broke**

Run: `make test`
Expected: all prior tests still pass plus the new one.

(No commit — per Global Constraints.)

---

### Task 2: Refactor `Cert` into an abstract base + `LetsEncryptCert`

**Files:**
- Modify: `cert_hub/domain/cert.py` (becomes abstract base + `CertType`)
- Create: `cert_hub/domain/letsencrypt_cert.py`
- Modify: `cert_hub/conf/config.py` (parse via `LetsEncryptCert`)
- Test: rely on existing suite + `make lint` (LE parsing/cert-bot paths are not unit-testable in the venv; the base's shared logic is covered by Task 3 via `StaticCert`)

**Interfaces:**
- Consumes: `CertStatus` (Task 1), `CertBot`, `DnsProvider`, `Identity`, `PermissionAction`, `CertException`.
- Produces:
  - `cert.py`: `class CertType(Enum)` with `LETSENCRYPT="letsencrypt"`, `STATIC="static"`, `@classmethod values() -> list[str]`. `CertStatus` re-exported from `cert.py` (keep the import). Abstract `class Cert(ABC)` exposing: `cert_type: ClassVar[CertType]`, `id: str`, `custom_attrs: dict`, `domains: tuple[str, ...]`, and methods `has_permission`, `get_full_chain`, `get_expire_date_as_str`, `get_days_to_expire`, `get_next_renew_date`, `get_next_renew_date_as_str`, `is_expiring`, `is_expired`, `_expiry_status`, `_get_time_left`, `_read_text`, `__str__`; abstract `is_issued`, `get_certificate`, `get_chain`, `get_private_key`, `get_expire_date`, `get_status`, `issue`, `renew`.
  - `letsencrypt_cert.py`: `@dataclass(frozen=True) class LetsEncryptCert(Cert)` with fields `id, email, domains, custom_attrs, dns_provider`, `cert_type = CertType.LETSENCRYPT`, classmethod `from_dict(data: dict) -> "LetsEncryptCert"`.

- [ ] **Step 1: Rewrite `cert_hub/domain/cert.py` as the abstract base**

Replace the entire file with:

```python
import re
import logging
from abc import ABC, abstractmethod
from enum import Enum
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import ClassVar
from cert_hub.exception.cert_exceptions import CertException
from cert_hub.domain.permission_action import PermissionAction
from cert_hub.domain.identity import Identity
from cert_hub.domain.cert_bot import CertBot
from cert_hub.domain.cert_status import CertStatus

log = logging.getLogger(__name__)


class CertType(Enum):
    LETSENCRYPT = "letsencrypt"
    STATIC = "static"

    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]


class Cert(ABC):
    DATE_FMT: ClassVar[str] = '%Y-%m-%d %H:%M'

    # Provided by subclasses (annotations only — not dataclass fields here):
    cert_type: ClassVar[CertType]
    id: str
    custom_attrs: dict
    domains: tuple[str, ...]

    # ── abstract interface ───────────────────────────────────────────────
    @abstractmethod
    def is_issued(self) -> bool: ...

    @abstractmethod
    def get_certificate(self) -> str: ...

    @abstractmethod
    def get_chain(self) -> str: ...

    @abstractmethod
    def get_private_key(self) -> str: ...

    @abstractmethod
    def get_expire_date(self) -> datetime: ...

    @abstractmethod
    def get_status(self) -> CertStatus: ...

    @abstractmethod
    def issue(self, force: bool = False) -> None: ...

    @abstractmethod
    def renew(self, force: bool = False) -> None: ...

    # ── shared behavior ──────────────────────────────────────────────────
    def has_permission(self, identity: Identity, action: PermissionAction) -> bool:
        log.debug(f"Perform permission check (cert='{self.id}'; identity='{identity.id}'; action='{action.value}')")

        if not identity:
            return False

        for permission in identity.permissions:
            if permission.action != PermissionAction.ANY and permission.action != action:
                continue

            if permission.scope == "*" or permission.scope == self.id:
                return True

            try:
                if re.fullmatch(permission.scope, self.id):
                    return True
            except re.error:
                continue

        return False

    def get_full_chain(self) -> str:
        chain = self.get_chain()
        certificate = self.get_certificate()
        return f"{certificate}\n{chain}" if chain else certificate

    def get_next_renew_date_as_str(self) -> str:
        return datetime.strftime(self.get_next_renew_date(), self.DATE_FMT)

    def get_next_renew_date(self) -> datetime:
        certbot = CertBot.get_from_global_context()
        return self.get_expire_date() - timedelta(days=certbot.renew_before_days)

    def get_expire_date_as_str(self) -> str:
        return datetime.strftime(self.get_expire_date(), self.DATE_FMT)

    def get_days_to_expire(self) -> int:
        return self._get_time_left().days

    def is_expiring(self) -> bool:
        certbot = CertBot.get_from_global_context()
        return self.get_days_to_expire() <= certbot.renew_before_days

    def is_expired(self) -> bool:
        return self._get_time_left().total_seconds() <= 0

    def _expiry_status(self) -> CertStatus:
        if self.is_expired():
            return CertStatus.EXPIRED
        elif self.is_expiring():
            return CertStatus.EXPIRING
        else:
            return CertStatus.OK

    def _get_time_left(self) -> timedelta:
        return self.get_expire_date() - datetime.now(timezone.utc)

    def _read_text(self, file_path: Path) -> str:
        try:
            return file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return file_path.read_text(encoding="ascii", errors="ignore")

    def __str__(self) -> str:
        return self.id
```

- [ ] **Step 2: Create `cert_hub/domain/letsencrypt_cert.py`**

```python
import logging
from datetime import datetime, timezone
from typing import Any, ClassVar
from dataclasses import dataclass
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cert_hub.exception.cert_exceptions import CertException
from cert_hub.domain.cert import Cert, CertType
from cert_hub.domain.cert_bot import CertBot
from cert_hub.domain.cert_status import CertStatus
from cert_hub.domain.dns_provider import DnsProvider
from cert_hub.validation.require import Require

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class LetsEncryptCert(Cert):
    cert_type: ClassVar[CertType] = CertType.LETSENCRYPT

    id: str
    email: str
    domains: tuple[str, ...]
    custom_attrs: dict
    dns_provider: DnsProvider

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LetsEncryptCert":
        def get_required(name: str) -> Any:
            val = data.get(name)
            Require.present(name, val)
            return val

        id = get_required("id")
        email = get_required("email")
        domains = get_required("domains")
        custom_attrs = data.get("custom_attrs")
        dns_provider_raw = get_required("dns_provider")

        Require.type("id", id, str)
        Require.email("email", email)
        Require.type("domains", domains, list)
        if custom_attrs is not None:
            Require.type("custom_attrs", custom_attrs, dict)

        for i, domain in enumerate(domains):
            Require.domain(f"domains[{i}]", domain)

        Require.one_of("dns_provider", dns_provider_raw, DnsProvider.values())
        dns_provider = DnsProvider(dns_provider_raw)
        Require.installed_module("dns_provider", dns_provider.value, dns_provider.get_required_module())
        Require.secret_envs(dns_provider.get_required_envs())

        return cls(id, email, tuple(domains), custom_attrs, dns_provider)

    def is_issued(self) -> bool:
        certbot = CertBot.get_from_global_context()
        required_paths = [
            certbot.get_cert_path(self.id),
            certbot.get_chain_path(self.id),
            certbot.get_private_key_path(self.id)
        ]
        for path in required_paths:
            if not path.exists():
                return False
        return True

    def get_status(self) -> CertStatus:
        if not self.is_issued():
            return CertStatus.NOT_ISSUED
        return self._expiry_status()

    def issue(self, force: bool = False) -> None:
        log.debug(f"Issuing '{self}' certificate...")

        if not force and self.is_issued():
            raise CertException(
                self.id,
                f"Certificate is already issued with expiration date to {self.get_expire_date_as_str()}",
                status=CertStatus.ALREADY_ISSUED
            )

        certbot = CertBot.get_from_global_context()
        certbot.issue(self.id, self.domains, self.email, self.dns_provider)

        log.info(f"Successfully issued '{self}' certificate with expiration date to {self.get_expire_date_as_str()}")

    def renew(self, force: bool = False) -> None:
        log.debug(f"Renewing '{self}' certificate...")
        certbot = CertBot.get_from_global_context()

        if not force and not self.is_expiring():
            raise CertException(
                self.id,
                f"Certificate can be renewed {certbot.renew_before_days} days before expiration, current expiration date is {self.get_expire_date_as_str()}",
                status=CertStatus.NOT_YET_RENEWABLE
            )

        certbot.renew(self.id, self.dns_provider)

        log.info(f"Successfully renewed '{self}' certificate with new expiration date {self.get_expire_date_as_str()}")

    def get_chain(self) -> str:
        self._require_issued()
        certbot = CertBot.get_from_global_context()
        return self._read_text(certbot.get_chain_path(self.id))

    def get_certificate(self) -> str:
        self._require_issued()
        certbot = CertBot.get_from_global_context()
        return self._read_text(certbot.get_cert_path(self.id))

    def get_private_key(self) -> str:
        self._require_issued()
        certbot = CertBot.get_from_global_context()
        return self._read_text(certbot.get_private_key_path(self.id))

    def get_expire_date(self) -> datetime:
        self._require_issued()
        certbot = CertBot.get_from_global_context()
        pem_bytes = certbot.get_cert_path(self.id).read_bytes()
        cert = x509.load_pem_x509_certificate(pem_bytes, default_backend())
        expire_date = cert.not_valid_after_utc
        if expire_date.tzinfo is None:
            expire_date = expire_date.replace(tzinfo=timezone.utc)
        return expire_date.astimezone(timezone.utc)

    def _require_issued(self) -> None:
        if not self.is_issued():
            raise CertException(self.id, "Certificate not issued", status=CertStatus.NOT_ISSUED)
```

- [ ] **Step 3: Point config parsing at `LetsEncryptCert`**

In `cert_hub/conf/config.py`:
- Change the import `from cert_hub.domain.cert import Cert` to:
```python
from cert_hub.domain.cert import Cert
from cert_hub.domain.letsencrypt_cert import LetsEncryptCert
```
- In `_parse_certs`, change `certs.append(Cert.from_dict(item))` to `certs.append(LetsEncryptCert.from_dict(item))`.

- [ ] **Step 4: Verify imports compile and existing tests pass**

Run: `make lint`
Expected: `py_compile` → `OK`.

Run: `make test`
Expected: all existing tests still pass (25 from the prior feature). The refactor is behavior-preserving; `helpers.py`'s `from cert_hub.domain.cert import Cert, CertStatus` still resolves (both names live in `cert.py`).

(No commit.)

---

### Task 3: Implement `StaticCert`

**Files:**
- Create: `cert_hub/domain/static_cert.py`
- Test: `tests/test_static_cert.py` (create)

**Interfaces:**
- Consumes: `Cert`, `CertType` (Task 2), `CertStatus` (Task 1), `CertException`, `cryptography.x509`.
- Produces: `@dataclass(frozen=True) class StaticCert(Cert)` with fields `id: str`, `cert_file: Path`, `privkey_file: Path`, `chain_file: Path | None`, `custom_attrs: dict`, `cert_type = CertType.STATIC`; `domains` property; concrete `is_issued`, `get_certificate`, `get_chain`, `get_private_key`, `get_expire_date`, `get_status`, `issue`, `renew`. Constructed directly (config wiring is Task 4).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_static_cert.py`:

```python
import datetime as dt
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cert_hub.domain.static_cert import StaticCert
from cert_hub.domain.cert import CertType
from cert_hub.domain.cert_status import CertStatus
from cert_hub.exception.cert_exceptions import CertException


@pytest.fixture(autouse=True)
def _fake_certbot(monkeypatch):
    # is_expiring()/get_next_renew_date() read renew_before_days from the global CertBot
    import cert_hub.domain.cert as cert_mod
    monkeypatch.setattr(
        cert_mod.CertBot, "get_from_global_context",
        staticmethod(lambda: SimpleNamespace(renew_before_days=30)),
    )


def _make_cert(tmp_path: Path, *, days_valid: int = 365, sans=("example.com", "www.example.com")):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sans[0])]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sans[0])]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    )
    cert = builder.sign(key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def _write(tmp_path, cert_pem=None, key_pem=None, chain_pem=None, with_chain=False):
    cert_file = tmp_path / "cert.pem"
    key_file = tmp_path / "privkey.pem"
    chain_file = tmp_path / "chain.pem"
    if cert_pem is not None:
        cert_file.write_text(cert_pem)
    if key_pem is not None:
        key_file.write_text(key_pem)
    if chain_pem is not None:
        chain_file.write_text(chain_pem)
    return StaticCert(
        id="static-a",
        cert_file=cert_file,
        privkey_file=key_file,
        chain_file=(chain_file if (with_chain or chain_pem is not None) else None),
        custom_attrs={},
    )


def test_cert_type_is_static(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem, key_pem)
    assert sc.cert_type is CertType.STATIC


def test_status_ok_when_valid_and_far_from_expiry(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path, days_valid=365)
    sc = _write(tmp_path, cert_pem, key_pem)
    assert sc.get_status() == CertStatus.OK


def test_status_expiring_within_window(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path, days_valid=10)
    sc = _write(tmp_path, cert_pem, key_pem)
    assert sc.get_status() == CertStatus.EXPIRING


def test_status_expired(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path, days_valid=-5)
    sc = _write(tmp_path, cert_pem, key_pem)
    assert sc.get_status() == CertStatus.EXPIRED


def test_status_cert_missing(tmp_path):
    _, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem=None, key_pem=key_pem)
    assert sc.get_status() == CertStatus.CERT_MISSING


def test_status_key_missing(tmp_path):
    cert_pem, _ = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem=cert_pem, key_pem=None)
    assert sc.get_status() == CertStatus.KEY_MISSING


def test_status_chain_missing_when_declared_but_absent(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem, key_pem, with_chain=True)  # chain_file declared, file not written
    assert sc.get_status() == CertStatus.CHAIN_MISSING


def test_status_invalid_cert_file(tmp_path):
    _, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem="not a pem", key_pem=key_pem)
    assert sc.get_status() == CertStatus.INVALID_CERT_FILE


def test_domains_from_san(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path, sans=("a.example", "b.example"))
    sc = _write(tmp_path, cert_pem, key_pem)
    assert sc.domains == ("a.example", "b.example")


def test_domains_empty_when_cert_missing(tmp_path):
    _, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem=None, key_pem=key_pem)
    assert sc.domains == ()


def test_get_full_chain_without_chain_is_cert_only(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem, key_pem)
    assert sc.get_full_chain().strip() == cert_pem.strip()


def test_issue_and_renew_not_supported(tmp_path):
    cert_pem, key_pem = _make_cert(tmp_path)
    sc = _write(tmp_path, cert_pem, key_pem)
    for op in (sc.issue, sc.renew):
        with pytest.raises(CertException) as exc:
            op()
        assert exc.value.status == CertStatus.NOT_SUPPORTED
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test PYTEST_FLAGS="-q test_static_cert.py"`
Expected: FAIL with `ModuleNotFoundError: cert_hub.domain.static_cert`.

- [ ] **Step 3: Implement `cert_hub/domain/static_cert.py`**

```python
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar
from dataclasses import dataclass
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cert_hub.exception.cert_exceptions import CertException
from cert_hub.domain.cert import Cert, CertType
from cert_hub.domain.cert_status import CertStatus

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class StaticCert(Cert):
    cert_type: ClassVar[CertType] = CertType.STATIC

    id: str
    cert_file: Path
    privkey_file: Path
    chain_file: Path | None
    custom_attrs: dict

    @property
    def domains(self) -> tuple[str, ...]:
        try:
            cert = self._load_cert()
        except CertException:
            return ()
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return tuple(san.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            return ()

    def is_issued(self) -> bool:
        if not self.cert_file.exists() or not self.privkey_file.exists():
            return False
        if self.chain_file is not None and not self.chain_file.exists():
            return False
        return True

    def get_status(self) -> CertStatus:
        if not self.cert_file.exists():
            return CertStatus.CERT_MISSING
        try:
            self._load_cert()
        except CertException:
            return CertStatus.INVALID_CERT_FILE
        if not self.privkey_file.exists():
            return CertStatus.KEY_MISSING
        if self.chain_file is not None and not self.chain_file.exists():
            return CertStatus.CHAIN_MISSING
        return self._expiry_status()

    def get_certificate(self) -> str:
        if not self.cert_file.exists():
            raise CertException(self.id, f"Certificate file not found: {self.cert_file.name}", status=CertStatus.CERT_MISSING)
        return self._read_text(self.cert_file)

    def get_chain(self) -> str:
        if self.chain_file is None:
            return ""
        if not self.chain_file.exists():
            raise CertException(self.id, f"Chain file not found: {self.chain_file.name}", status=CertStatus.CHAIN_MISSING)
        return self._read_text(self.chain_file)

    def get_private_key(self) -> str:
        if not self.privkey_file.exists():
            raise CertException(self.id, f"Private key file not found: {self.privkey_file.name}", status=CertStatus.KEY_MISSING)
        return self._read_text(self.privkey_file)

    def get_expire_date(self) -> datetime:
        cert = self._load_cert()
        expire_date = cert.not_valid_after_utc
        if expire_date.tzinfo is None:
            expire_date = expire_date.replace(tzinfo=timezone.utc)
        return expire_date.astimezone(timezone.utc)

    def issue(self, force: bool = False) -> None:
        raise CertException(self.id, "Static certificates cannot be issued; manage their files manually", status=CertStatus.NOT_SUPPORTED)

    def renew(self, force: bool = False) -> None:
        raise CertException(self.id, "Static certificates cannot be renewed; manage their files manually", status=CertStatus.NOT_SUPPORTED)

    def _load_cert(self) -> x509.Certificate:
        if not self.cert_file.exists():
            raise CertException(self.id, f"Certificate file not found: {self.cert_file.name}", status=CertStatus.CERT_MISSING)
        try:
            return x509.load_pem_x509_certificate(self.cert_file.read_bytes(), default_backend())
        except ValueError as e:
            raise CertException(self.id, f"Certificate file is not a valid PEM X.509 certificate: {e}", status=CertStatus.INVALID_CERT_FILE)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make test PYTEST_FLAGS="-q test_static_cert.py"`
Expected: all PASS.

- [ ] **Step 5: Full sweep**

Run: `make test && make lint`
Expected: all tests pass; `py_compile` → `OK`.

(No commit.)

---

### Task 4: Config — `STATIC_CERTS_DIR`, key rename, static parsing, global id uniqueness

**Files:**
- Modify: `cert_hub/conf/config.py`
- Modify: `cert_hub/app.py` (create `STATIC_CERTS_DIR`)
- Test: `tests/test_config.py` (create)

**Interfaces:**
- Consumes: `StaticCert` (Task 3), `LetsEncryptCert` (Task 2), `Require`.
- Produces:
  - `Config.static_certs_dir: Path` field (env `STATIC_CERTS_DIR`, default `/static-certs`).
  - `Config._parse_letsencrypt_certs(raw, seen_ids: set[str]) -> list[LetsEncryptCert]`
  - `Config._parse_static_certs(raw, static_certs_dir: Path, seen_ids: set[str]) -> list[StaticCert]`
  - `StaticCert.from_dict(data: dict, static_certs_dir: Path) -> StaticCert` (added to `static_cert.py`).
  - `conf.certs` is the concatenation `letsencrypt + static`, ids unique across both.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_config.py`:

```python
from pathlib import Path

import pytest
from cert_hub.domain.static_cert import StaticCert
from cert_hub.conf.config import Config
from cert_hub.exception.validator_exceptions import ValidationError


STATIC_DIR = Path("/static-certs")


def test_static_from_dict_resolves_paths_under_dir():
    sc = StaticCert.from_dict(
        {"id": "s1", "cert_file": "s1.crt", "privkey_file": "s1.key", "chain_file": "s1.chain"},
        STATIC_DIR,
    )
    assert sc.cert_file == STATIC_DIR / "s1.crt"
    assert sc.privkey_file == STATIC_DIR / "s1.key"
    assert sc.chain_file == STATIC_DIR / "s1.chain"


def test_static_from_dict_chain_optional():
    sc = StaticCert.from_dict({"id": "s1", "cert_file": "s1.crt", "privkey_file": "s1.key"}, STATIC_DIR)
    assert sc.chain_file is None


def test_static_from_dict_requires_cert_and_key():
    with pytest.raises(ValidationError):
        StaticCert.from_dict({"id": "s1", "privkey_file": "s1.key"}, STATIC_DIR)
    with pytest.raises(ValidationError):
        StaticCert.from_dict({"id": "s1", "cert_file": "s1.crt"}, STATIC_DIR)


@pytest.mark.parametrize("bad", ["/abs/path.pem", "../escape.pem", "sub/../../x.pem", ""])
def test_static_from_dict_rejects_unsafe_filenames(bad):
    with pytest.raises(ValidationError):
        StaticCert.from_dict({"id": "s1", "cert_file": bad, "privkey_file": "ok.key"}, STATIC_DIR)


def test_parse_static_certs_detects_duplicate_ids():
    raw = [
        {"id": "dup", "cert_file": "a.crt", "privkey_file": "a.key"},
        {"id": "dup", "cert_file": "b.crt", "privkey_file": "b.key"},
    ]
    with pytest.raises(ValidationError):
        Config._parse_static_certs(raw, STATIC_DIR, set())


def test_parse_static_certs_collides_with_existing_letsencrypt_id():
    raw = [{"id": "shared", "cert_file": "a.crt", "privkey_file": "a.key"}]
    with pytest.raises(ValidationError):
        Config._parse_static_certs(raw, STATIC_DIR, {"shared"})


def test_parse_static_certs_empty_returns_empty():
    assert Config._parse_static_certs(None, STATIC_DIR, set()) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test PYTEST_FLAGS="-q test_config.py"`
Expected: FAIL — `StaticCert.from_dict` and `Config._parse_static_certs` don't exist.

- [ ] **Step 3: Add `StaticCert.from_dict` with filename validation**

In `cert_hub/domain/static_cert.py`, add these imports at the top:
```python
from typing import Any
from cert_hub.validation.require import Require
```
and add this classmethod to `StaticCert`:

```python
    @classmethod
    def from_dict(cls, data: dict[str, Any], static_certs_dir: Path) -> "StaticCert":
        def get_required(name: str) -> Any:
            val = data.get(name)
            Require.present(name, val)
            return val

        def resolve_file(field: str, name: str) -> Path:
            Require.type(field, name, str)
            if name.startswith("/") or ".." in Path(name).parts or name.strip() == "":
                raise ValidationError(
                    f"Value '{field}={name}' must be a plain file name under STATIC_CERTS_DIR (no absolute path, no '..')"
                )
            return static_certs_dir / name

        id = get_required("id")
        Require.type("id", id, str)
        cert_file = resolve_file("cert_file", get_required("cert_file"))
        privkey_file = resolve_file("privkey_file", get_required("privkey_file"))

        chain_raw = data.get("chain_file")
        chain_file = resolve_file("chain_file", chain_raw) if chain_raw else None

        custom_attrs = data.get("custom_attrs")
        if custom_attrs is not None:
            Require.type("custom_attrs", custom_attrs, dict)

        return cls(id, cert_file, privkey_file, chain_file, custom_attrs)
```

Add the import for `ValidationError` to `static_cert.py` top:
```python
from cert_hub.exception.validator_exceptions import ValidationError
```

- [ ] **Step 4: Update `config.py` — field, env, dual parsing, global uniqueness**

In `cert_hub/conf/config.py`:

a) Add the import:
```python
from cert_hub.domain.static_cert import StaticCert
```

b) Add the dataclass field (after `certs: list[Cert] = field(default_factory=list)` group; place before `certs`):
```python
    static_certs_dir: Path = "/static-certs"
```

c) In `load()`, after the `certbot_dir` handling, resolve the static dir (near other env reads). Add:
```python
        static_certs_dir = Path(os.getenv("STATIC_CERTS_DIR", "/static-certs"))
```

d) Replace the certs parsing block. Change:
```python
        try:
            certs = cls._parse_certs(raw_conf.get("certs"))
            identities = cls._parse_identities(raw_conf.get("identities"))
        except ValidationError as e:
            raise ValidationError(f"Failed to parse '{conf_file}' config file: {e}")
```
to:
```python
        try:
            seen_ids: set[str] = set()
            le_certs = cls._parse_letsencrypt_certs(raw_conf.get("letsencrypt_certs"), seen_ids)
            static_certs = cls._parse_static_certs(raw_conf.get("static_certs"), static_certs_dir, seen_ids)
            certs = [*le_certs, *static_certs]
            identities = cls._parse_identities(raw_conf.get("identities"))
        except ValidationError as e:
            raise ValidationError(f"Failed to parse '{conf_file}' config file: {e}")
```

e) Pass `static_certs_dir` to the constructor — in the `return cls(...)` add:
```python
            static_certs_dir=static_certs_dir,
```

f) Replace the `_parse_certs` static method with two methods:
```python
    @staticmethod
    def _parse_letsencrypt_certs(certs_raw: Any, seen_ids: set[str]) -> list[LetsEncryptCert]:
        if certs_raw is None:
            return []

        Require.type("letsencrypt_certs", certs_raw, list)
        certs: list[LetsEncryptCert] = []

        for i, item in enumerate(certs_raw):
            Require.type(f"letsencrypt_certs[{i}]", item, dict)
            Require.not_one_of(f"letsencrypt_certs[{i}].id", item.get("id"), list(seen_ids))
            try:
                cert = LetsEncryptCert.from_dict(item)
            except ValidationError as e:
                raise ValidationError(f"Error found at letsencrypt_certs[{i}]: {e}")
            seen_ids.add(cert.id)
            certs.append(cert)

        return certs

    @staticmethod
    def _parse_static_certs(certs_raw: Any, static_certs_dir: Path, seen_ids: set[str]) -> list[StaticCert]:
        if certs_raw is None:
            return []

        Require.type("static_certs", certs_raw, list)
        certs: list[StaticCert] = []

        for i, item in enumerate(certs_raw):
            Require.type(f"static_certs[{i}]", item, dict)
            Require.not_one_of(f"static_certs[{i}].id", item.get("id"), list(seen_ids))
            try:
                cert = StaticCert.from_dict(item, static_certs_dir)
            except ValidationError as e:
                raise ValidationError(f"Error found at static_certs[{i}]: {e}")
            seen_ids.add(cert.id)
            certs.append(cert)

        return certs
```

- [ ] **Step 5: Create `STATIC_CERTS_DIR` in `app.setup_paths`**

In `cert_hub/app.py`, in `setup_paths`, change:
```python
    dir_params = ["logs_dir", "certbot_dir"]
```
to:
```python
    dir_params = ["logs_dir", "certbot_dir", "static_certs_dir"]
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `make test PYTEST_FLAGS="-q test_config.py"`
Expected: all PASS.

- [ ] **Step 7: Full sweep**

Run: `make test && make lint`
Expected: all pass; `py_compile` → `OK`.

(No commit.)

---

### Task 5: API — `type` field, `type` filter, `query_one_of` validator

**Files:**
- Modify: `cert_hub/api/validators.py`
- Modify: `cert_hub/api/routes.py`
- Test: `tests/test_validators.py` (extend)

**Interfaces:**
- Consumes: `cert.cert_type` (Task 2/3).
- Produces: `query_one_of(name, *, default, allowed: list[str]) -> str` in `validators.py`; `/api/certs`, `/api/certs/status`, `/api/certs/issue`, `/api/certs/renew` each apply a `type` filter and include `"type"` in every cert object.

- [ ] **Step 1: Write the failing test for the validator**

Append to `tests/test_validators.py`:

```python
def test_query_one_of_returns_value_when_allowed():
    with app.test_request_context("/?type=static"):
        assert v.query_one_of("type", default="all", allowed=["letsencrypt", "static", "all"]) == "static"


def test_query_one_of_returns_default_when_absent():
    with app.test_request_context("/"):
        assert v.query_one_of("type", default="all", allowed=["letsencrypt", "static", "all"]) == "all"


def test_query_one_of_rejects_disallowed():
    with app.test_request_context("/?type=bogus"):
        with pytest.raises(InvalidRequestError) as exc:
            v.query_one_of("type", default="all", allowed=["letsencrypt", "static", "all"])
        assert exc.value.code == 400
```

- [ ] **Step 2: Run to verify it fails**

Run: `make test PYTEST_FLAGS="-q test_validators.py"`
Expected: FAIL — `module 'cert_hub.api.validators' has no attribute 'query_one_of'`.

- [ ] **Step 3: Implement `query_one_of`**

In `cert_hub/api/validators.py`, add after `query_str`:

```python
def query_one_of(
    name: str,
    *,
    default: str,
    allowed: list[str],
    required: bool = False
) -> str:
    val = request.args.get(name)

    if val is None or val.strip() == "":
        if required:
            raise InvalidRequestError("Missing required query parameter", detail={ "parameter": name, "allowed_choices": allowed })
        return default

    val = val.strip()
    if val not in allowed:
        raise InvalidRequestError("Invalid query parameter", detail={ "parameter": name, "allowed_choices": allowed })
    return val
```

- [ ] **Step 4: Run to verify it passes**

Run: `make test PYTEST_FLAGS="-q test_validators.py"`
Expected: all PASS.

- [ ] **Step 5: Add the `type` filter + field to routes**

In `cert_hub/api/routes.py`:

a) Update the import line:
```python
from cert_hub.api.validators import query_list, query_bool
```
to:
```python
from cert_hub.api.validators import query_list, query_bool, query_one_of
```

b) Add this module-level helper after `api = Blueprint(...)`:
```python
CERT_TYPES = ["letsencrypt", "static", "all"]

def _filter_by_type(certs):
    type_filter = query_one_of("type", default="all", allowed=CERT_TYPES)
    if type_filter == "all":
        return certs
    return [c for c in certs if c.cert_type.value == type_filter]
```

c) In `cert_list`, after `certs = ctx.resolve_scope(patterns, PermissionAction.READ)` add:
```python
    certs = _filter_by_type(certs)
```
and add `"type": cert.cert_type.value,` as the first field of BOTH appended dicts (the success branch and the `except CertException` branch), e.g.:
```python
            payload.append({
                "id": cert.id,
                "type": cert.cert_type.value,
                "status": status.value,
                ...
            })
```

d) In `cert_status`, after `certs = ctx.resolve_scope(patterns, PermissionAction.STATUS)` add `certs = _filter_by_type(certs)`, and add `"type": cert.cert_type.value,` to both appended dicts.

e) In `cert_issue`, after `certs = ctx.resolve_scope(patterns, PermissionAction.ISSUE)` add `certs = _filter_by_type(certs)`, and add `"type": cert.cert_type.value,` to both appended dicts. (Static certs that pass the filter raise `CertException(NOT_SUPPORTED)` from `cert.issue(force)` and are reported via the existing `except`.)

f) In `cert_renew`, after `certs = ctx.resolve_scope(patterns, PermissionAction.RENEW)` add `certs = _filter_by_type(certs)`, and add `"type": cert.cert_type.value,` to both appended dicts.

- [ ] **Step 6: Full sweep**

Run: `make test && make lint`
Expected: all pass; `py_compile` → `OK`.

(No commit.)

---

### Task 6: CLI — `--type` option

**Files:**
- Modify: `certhub.py`
- Verify: `make lint` (CLI is not unit-testable in the venv — no `typer`/`requests` installed)

**Interfaces:**
- Consumes: API `type` query param (Task 5).
- Produces: `Opt.type(default)` and `--type` on `cert status` (default `all`), `cert list` (default `all`), `cert update-in-place` (default `all`), `cert issue` (default `letsencrypt`), `cert renew` (default `letsencrypt`).

- [ ] **Step 1: Add `CERT_TYPES` constant and `Opt.type`**

In `certhub.py`, add near the top-level constants (e.g. just above `class Opt:`):
```python
CERT_TYPES = ["letsencrypt", "static", "all"]
```
and add this static method inside `class Opt:`:
```python
    @staticmethod
    def type(default: str = "all") -> Any:
        return typer.Option(
            default, "--type",
            help=f"Filter by certificate type: {', '.join(CERT_TYPES)}"
        )
```

- [ ] **Step 2: Add a shared validator helper**

In `certhub.py`, add a module-level function near `Opt`:
```python
def validate_cert_type(value: str) -> str:
    if value not in CERT_TYPES:
        raise typer.BadParameter(f"Invalid --type '{value}', must be one of: {', '.join(CERT_TYPES)}")
    return value
```

- [ ] **Step 3: Wire `--type` into `cert status`**

In `cert_status` (the CLI command, ~line 613), add parameter `type: str = Opt.type("all"),` to the signature, then after `client = Client.init(...)` validate and include it in params:
```python
    cert_type = validate_cert_type(type)
    params = {
        **({"exclude_ok": "true"} if exclude_ok else {}),
        **({"match": patterns} if patterns else {}),
        "type": cert_type,
    }
```

- [ ] **Step 4: Wire `--type` into `cert list`**

In `cert_list`, add `type: str = Opt.type("all"),` to the signature and:
```python
    cert_type = validate_cert_type(type)
    params = {
        **({"match": patterns} if patterns else {}),
        "type": cert_type,
    }
```

- [ ] **Step 5: Wire `--type` into `cert issue` (default letsencrypt)**

In `cert_issue`, add `type: str = Opt.type("letsencrypt"),` and:
```python
    cert_type = validate_cert_type(type)
    params = {
        **({"force": "true"} if force else {}),
        **({"match": patterns} if patterns else {}),
        "type": cert_type,
    }
```

- [ ] **Step 6: Wire `--type` into `cert renew` (default letsencrypt)**

In `cert_renew`, add `type: str = Opt.type("letsencrypt"),` and:
```python
    cert_type = validate_cert_type(type)
    params = {
        **({"force": "true"} if force else {}),
        **({"match": patterns} if patterns else {}),
        "type": cert_type,
    }
```

- [ ] **Step 7: Wire `--type` into `cert update-in-place` (default all)**

In `cert_update_in_place`, add `type: str = Opt.type("all"),` to the signature and update the params built before the `/api/certs` request:
```python
    cert_type = validate_cert_type(type)
    params = {
        **({"match": patterns} if patterns else {}),
        "type": cert_type,
    }
```

- [ ] **Step 8: Verify it compiles**

Run: `make lint`
Expected: `py_compile` → `OK` (covers `certhub.py`).

(No commit.)

---

### Task 7: README documentation

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: `STATIC_CERTS_DIR`, `static_certs`/`letsencrypt_certs` config keys, `type` field/filter, `--type` flag.

- [ ] **Step 1: Add `STATIC_CERTS_DIR` to the Environments table**

In `README.md`, after the `CERTBOT_DIR` row, add:
```
| `STATIC_CERTS_DIR` | `string` | :x: | `/static-certs` | Directory containing files for `static` certificates (referenced by name in config). |
```

- [ ] **Step 2: Update the config section for the two cert kinds**

Replace the example `certs:` block and the `certs[].dns_provider` field-meaning note. Change the YAML example's top-level `certs:` to `letsencrypt_certs:` and add a `static_certs:` block:
```yaml
letsencrypt_certs:
  - id: "example"
    email: "admin@example.com"
    domains:
      - "*.example.com"
      - "example.com"
    dns_provider: "aws"
    custom_attrs:
      pem_filename: "*.example.com"

static_certs:
  - id: "internal"
    cert_file: "internal.crt"        # under STATIC_CERTS_DIR
    privkey_file: "internal.key"
    chain_file: "internal.chain"     # optional
    custom_attrs:
      pem_filename: "internal"
```
And update the field-meaning bullets: note that `dns_provider` applies to `letsencrypt_certs` (values `aws` / `cloudflare`), and document `static_certs[]` fields (`cert_file`, `privkey_file` required; `chain_file` optional; resolved under `STATIC_CERTS_DIR`).

- [ ] **Step 3: Document the `type` field and filter in the API section**

In the API endpoints/query-params section, note that each cert object carries a `type` (`letsencrypt`/`static`), and that `/api/certs`, `/api/certs/status`, `/api/certs/issue`, `/api/certs/renew` accept a `type` query param (`letsencrypt|static|all`, default `all`). Note that issue/renew on a `static` cert returns status `NOT_SUPPORTED`.

- [ ] **Step 4: Document the CLI `--type` flag**

In the CLI section, note `--type` on `cert status`/`list`/`update-in-place` (default `all`) and `cert issue`/`renew` (default `letsencrypt`), with values `letsencrypt|static|all`.

- [ ] **Step 5: Verify the new env row is present**

Run: `grep -n "STATIC_CERTS_DIR" README.md`
Expected: at least the environments-table row.

(No commit.)

---

### Task 8: Full verification sweep

**Files:** none (verification only).

- [ ] **Step 1: Run the entire test suite**

Run: `make test`
Expected: all tests pass (existing + `test_cert_status.py`, `test_static_cert.py`, `test_config.py`, extended `test_validators.py`).

- [ ] **Step 2: Run lint**

Run: `make lint`
Expected: `py_compile` → `OK`.

- [ ] **Step 3 (optional, if Docker available): build the image**

Run: `make build`
Expected: image builds.

---

## Self-Review

**Spec coverage:**
- Hierarchy: abstract `Cert` + `CertType` in cert.py, `LetsEncryptCert`, `StaticCert` → Tasks 2, 3. ✓ (CertType in cert.py per decision 7.)
- New statuses (CERT_MISSING/KEY_MISSING/CHAIN_MISSING/INVALID_CERT_FILE/NOT_SUPPORTED) + precedence → Task 1 (values), Task 3 (`get_status` precedence). ✓
- Config: STATIC_CERTS_DIR, key rename certs→letsencrypt_certs, static parsing, global id uniqueness, filename validation, setup_paths → Task 4. ✓
- API type field + filter on all 4 cert endpoints + query_one_of → Task 5. ✓
- CLI --type with per-command defaults (issue/renew=letsencrypt, others=all), values letsencrypt|static|all → Task 6. ✓
- issue/renew static → NOT_SUPPORTED → Task 3 (`StaticCert.issue/renew`), surfaced by existing route `except`. ✓
- domains from SAN → Task 3. ✓
- README → Task 7. ✓
- chain optional (self-signed) → Task 3 (`chain_file: Path | None`, `get_chain` returns "" when None; CHAIN_MISSING only when declared-but-absent). ✓

**Placeholder scan:** No TBD/TODO/"handle errors"/"similar to" — every code step contains concrete code. README Task 7 steps 2-4 are prose-described doc edits (acceptable: documentation, not logic). ✓

**Type consistency:** `cert_type` (ClassVar[CertType]) named identically across base annotation, both subclasses, routes filter/serialization, and CLI param name `type` (CLI flag) → server query `type` → `query_one_of`. `StaticCert.from_dict(data, static_certs_dir)` signature matches its caller `Config._parse_static_certs`. `_parse_letsencrypt_certs`/`_parse_static_certs(seen_ids)` thread one shared `set` for global uniqueness. `CERT_TYPES` value set identical in routes and CLI. ✓
