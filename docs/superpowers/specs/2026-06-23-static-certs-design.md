# Design: statyczne certy + polimorfizm `Cert`

Data: 2026-06-23

## Cel

Dodać obsługę certyfikatów dostarczanych ręcznie ("static") obok dotychczasowych
certów Let's Encrypt. Static cert jest definiowany w configu i wskazuje pliki na
dysku (zarządzane/rotowane ręcznie). Wprowadzić polimorfizm: `Cert` staje się
bazą dla `LetsEncryptCert` i `StaticCert`. API i CLI rozróżniają typ certa.

## Decyzje (potwierdzone)

1. Nazewnictwo: typy `letsencrypt` / `static`. Klucze conf: `letsencrypt_certs:` /
   `static_certs:` (zastępują dotychczasowy `certs:` — **zmiana łamiąca**).
2. Static cert wskazuje pliki **nazwami** względem katalogu z env `STATIC_CERTS_DIR`.
3. Pliki: `cert_file` i `privkey_file` **wymagane**, `chain_file` **opcjonalny**
   (dla self-signed / prywatnych CA). Mapowanie 1:1 na pola API.
4. `issue`/`renew` na static → status `NOT_SUPPORTED` (per-cert, nie wywraca całości).
5. `domains` static certa czytane z SAN certu (gdy ważny); `null` gdy brak/niepoprawny.
6. Statusy braku/niepoprawności rozróżniane per plik.
7. `CertType` mieszka w `cert.py` (jak `PermissionAction` w `permission.py`).
8. Filtr `--type` / query `type`: wartości `letsencrypt | static | all`.

## Architektura

### 1. Hierarchia klas (domena)

- `cert_hub/domain/cert.py` — abstrakcyjna baza `Cert` + enum `CertType`
  (`LETSENCRYPT="letsencrypt"`, `STATIC="static"`).
  - Wspólne (konkretne): `has_permission`, `get_status`, `is_expiring`,
    `is_expired`, `get_expire_date`, `get_expire_date_as_str`,
    `get_days_to_expire`, `get_next_renew_date(_as_str)`, `get_full_chain`,
    `_get_time_left`, `_read_text`, `__str__`.
  - Abstrakcyjne: `type` (→ `CertType`), `domains` (→ `tuple[str,...]`),
    `is_issued()`, `get_certificate()`, `get_chain()`, `get_private_key()`,
    `get_expire_date()` (źródło daty), `issue(force)`, `renew(force)`.
  - Pola wspólne: `id`, `custom_attrs`.
- `cert_hub/domain/letsencrypt_cert.py` — `LetsEncryptCert(Cert)`: dotychczasowe
  zachowanie. Pola: `email`, `domains` (z conf), `dns_provider`. Pliki przez
  `CertBot` (`get_cert_path`/`get_chain_path`/`get_private_key_path`). `issue`/
  `renew` jak dziś. `type → LETSENCRYPT`. `get_expire_date` z `cert.pem` (leaf).
- `cert_hub/domain/static_cert.py` — `StaticCert(Cert)`: pola `cert_file`,
  `privkey_file`, `chain_file` (opcjonalny) jako bezwzględne `Path` rozwiązane z
  `STATIC_CERTS_DIR`. `type → STATIC`. `domains` z SAN certu. `issue`/`renew`
  rzucają `CertException(status=NOT_SUPPORTED)`. `get_*` czytają wskazane pliki.

`get_full_chain()` w bazie = `f"{get_certificate()}\n{get_chain()}"`. Dla static
bez chaina `get_chain()` zwraca `""` (pusty), więc fullchain = sam cert.

### 2. Statusy (`cert_status.py`)

Dodać: `CERT_MISSING`, `KEY_MISSING`, `CHAIN_MISSING`, `INVALID_CERT_FILE`,
`NOT_SUPPORTED`. Istniejące zostają.

`StaticCert.get_status()` — precedencja od najpoważniejszego:
1. brak `cert_file` na dysku → `CERT_MISSING`
2. `cert_file` nieparsowalny jako X.509 → `INVALID_CERT_FILE`
3. brak `privkey_file` na dysku → `KEY_MISSING`
4. `chain_file` zadeklarowany w conf, ale brak na dysku → `CHAIN_MISSING`
5. inaczej z daty wygaśnięcia (leaf z `cert_file`) → `EXPIRED` / `EXPIRING` / `OK`

`StaticCert.is_issued()` = `cert_file` i `privkey_file` istnieją (+ `chain_file`
jeśli zadeklarowany). Akcesory treści (`get_certificate`/`get_chain`/
`get_private_key`) rzucają `CertException` z odpowiednim statusem, gdy ich plik
brakuje (`CERT_MISSING`/`CHAIN_MISSING`/`KEY_MISSING`) lub jest nieparsowalny
(`INVALID_CERT_FILE`) — spójnie z obecną obsługą `except CertException` w
`routes.py`. `get_chain()` przy braku zadeklarowanego `chain_file` zwraca `""`.

### 3. Konfiguracja (`config.py`)

- Nowe pole `static_certs_dir: Path` (env `STATIC_CERTS_DIR`, domyślnie
  `/static-certs`); tworzone w `app.setup_paths`.
- Parsowanie dwóch kluczy: `letsencrypt_certs` → `LetsEncryptCert.from_dict`,
  `static_certs` → `StaticCert.from_dict`. Wynik scalony do jednej listy
  `conf.certs` (jak dziś) — `resolve_scope`/`routes` nie wymagają zmian w doborze.
- **Globalna unikalność `id`** sprawdzana w obu listach łącznie.
- `static_certs[]`: wymagane `id`, `cert_file`, `privkey_file`; opcjonalne
  `chain_file`, `custom_attrs`. Walidacja nazw plików: niepuste, bez separatora
  ścieżki absolutnej i bez `..` (plik musi leżeć w `STATIC_CERTS_DIR`).
- `StaticCert.from_dict` dostaje `static_certs_dir`, by zbudować bezwzględne
  ścieżki. (Przekazać dir przez parametr parsowania.)

Zmiana łamiąca: dotychczasowe `certs:` przestaje być rozpoznawane — trzeba
zmienić na `letsencrypt_certs:`. README i przykłady zaktualizowane.

### 4. API (`routes.py`, `validators.py`)

- Pole `"type"` (`letsencrypt`/`static`) w odpowiedziach `/api/certs` i
  `/api/certs/status` (oraz w issue/renew payloadach dla spójności).
- Filtr query `type` na wszystkich 4 endpointach certów: walidacja do
  `{letsencrypt, static, all}`; `all` lub brak = bez filtra. Filtr stosowany po
  `resolve_scope` (proste `[c for c in certs if type==all or c.type.value==type]`).
- Nowy walidator `query_one_of(name, default, allowed)` w `validators.py`.
- `issue`/`renew`: `cert.issue()/renew()` static rzuca `CertException(
  NOT_SUPPORTED)` → istniejący `except CertException` raportuje per-cert.

### 5. CLI (`certhub.py`)

- Wspólny `Opt.type(default)` → `typer.Option(..., "--type", help=...)`,
  walidujący wartość do `letsencrypt|static|all`.
- Dodany do: `cert status` (default `all`), `cert list` (default `all`),
  `cert update-in-place` (default `all`), `cert issue` (default `letsencrypt`),
  `cert renew` (default `letsencrypt`). Wartość przekazywana jako query `type`
  (zawsze wysyłana, łącznie z `all`).
- `update-in-place`: logika bundla bez zmian (cert+chain+privkey sklejane w
  kodzie; pusty chain pomijany — już `if part`). Uwaga: dla static z 3 plikami
  bundel działa identycznie jak dla LE.

### 6. Testy

- `tests/test_static_cert.py`:
  - status: brak cert/key/chain, nieparsowalny cert, wygasły/wygasający/OK
    (certy generowane w teście przez `cryptography`, jest w venv).
  - `domains` z SAN; `null` gdy cert brak/niepoprawny.
  - `issue`/`renew` → `CertException(NOT_SUPPORTED)`.
  - akcesory `get_certificate`/`get_chain`/`get_private_key` (treść + wyjątki).
  - `type == CertType.STATIC`.
- `tests/test_config.py` (lub rozszerzenie istniejącego):
  - parsowanie `letsencrypt_certs` i `static_certs` do jednej listy;
  - globalna unikalność `id` (kolizja między listami → błąd);
  - walidacja nazw plików static (puste / `..` / absolutna → błąd).
- Testy nie wymagają `certbot` (static i baza są od niego niezależne; LE parsowanie
  wymaga modułu pluginu DNS, więc testy configu używają wyłącznie static lub
  mockują walidację modułu — testować przez `StaticCert`/parser static).

## Poza zakresem (YAGNI)

- Alias `certs:` dla wstecznej zgodności (świadoma zmiana łamiąca).
- Issue/renew static (z definicji niemożliwe; zawsze `NOT_SUPPORTED`).
- Automatyczne przeładowanie static certów bez restartu (czytane z dysku przy
  każdym żądaniu, więc rotacja pliku działa od razu — bez dodatkowego mechanizmu).
- Walidacja zgodności klucza prywatnego z certem (sprawdzamy obecność/parsowalność,
  nie dopasowanie pary).

## Pliki

- Modyfikacja: `cert_hub/domain/cert.py` (baza + `CertType`),
  `cert_hub/domain/cert_status.py`, `cert_hub/conf/config.py`,
  `cert_hub/app.py` (setup_paths), `cert_hub/api/routes.py`,
  `cert_hub/api/validators.py`, `certhub.py`, `README.md`.
- Nowe: `cert_hub/domain/letsencrypt_cert.py`, `cert_hub/domain/static_cert.py`,
  `tests/test_static_cert.py`, `tests/test_config.py`.
