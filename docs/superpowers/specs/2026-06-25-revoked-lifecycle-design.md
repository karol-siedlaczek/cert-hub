# Design: trwałość statusu REVOKED + cleanup w update-in-place

Data: 2026-06-25

## Cel

Po unieważnieniu certu (`certbot revoke --delete-after-revoke` kasuje pliki) serwer
ma raportować trwały status `REVOKED` (zamiast nieodróżnialnego `NOT_ISSUED`), a CLI
`update-in-place` ma na tej podstawie usuwać lokalne pliki revoked certa.

## Problem

`--delete-after-revoke` usuwa pliki lineage, więc `is_issued()` = False i bez dodatkowej
informacji status jest `NOT_ISSUED` — nieodróżnialny od „nigdy nie wystawiony". To dwa
różne przypadki dla `update-in-place`: `NOT_ISSUED` → zostaw lokalny plik; `REVOKED` →
usuń. Rozróżnienie wymaga utrwalenia stanu revoke (marker), bo pliki znikają.

## Decyzje (potwierdzone)

1. Marker: plik `<CERTBOT_DIR>/revoked/<cert_id>` (obok certbotowych `config/`/`work/`/
   `logs/`, na trwałym wolumenie). Treść: timestamp UTC.
2. `update-in-place` przy `REVOKED` usuwa pliki `<prefix>_<typ>.pem` (typy z `--pem`).
3. Cleanup domyślnie liczy się jako zmiana → odpala `--post-hook`; nowa flaga
   `--omit-post-hook-on-revoke` wyłącza wliczanie cleanupu do wyzwalania post-hooka.

## Architektura

### 1. Marker REVOKED (serwer)

`CertBot` (`cert_hub/domain/cert/cert_bot.py`):
- nowe pole `revoked_dir: Path`, w `load()` = `base_dir / "revoked"`.
- `mark_revoked(cert_name)`: `revoked_dir.mkdir(parents=True, exist_ok=True)`, zapis pliku
  `revoked_dir/<cert_name>` z timestampem UTC (ISO).
- `is_revoked(cert_name) -> bool`: `(revoked_dir / cert_name).exists()`.
- `clear_revoked(cert_name)`: usuń marker jeśli istnieje (`missing_ok=True`).

`LetsEncryptCert` (`.../cert/letsencrypt_cert.py`):
- `revoke()`: po `certbot.revoke(self.id)` → `certbot.mark_revoked(self.id)`.
- `issue()`: po sukcesie `certbot.issue(...)` → `certbot.clear_revoked(self.id)`.
- `get_status()`: w gałęzi `not self.is_issued()` → `REVOKED` jeśli
  `certbot.is_revoked(self.id)`, inaczej `NOT_ISSUED`.

`is_issued()` (pliki obecne) zachowuje pierwszeństwo: re-wystawiony cert nigdy nie pokaże
REVOKED, więc zalegający marker jest nieszkodliwy (konsultowany tylko gdy brak plików);
`issue()` i tak go czyści. `CertStatus.REVOKED` już istnieje. Static: revoke nieobsługiwany
→ markera nie dotyczy (`StaticCert.get_status` bez zmian).

### 2. Ujawnienie REVOKED w `/api/certs` (poprawka `cert_list`)

Obecnie `cert_list` liczy `status = cert.get_status()` wewnątrz `try`, a akcesory PEM
(`get_certificate()` itd.) rzucają `CertException(NOT_ISSUED)` dla revoked certa (pliki
usunięte) → `except` raportuje `e.status` (`NOT_ISSUED`), **gubiąc** `REVOKED`.

Poprawka: policzyć `status = cert.get_status()` **przed** `try` i w gałęzi `except` użyć
tego `status` zamiast `e.status`. `get_status()` jest bezpieczne (nie rzuca). Dla zwykłego
nie-wystawionego certu zwróci `NOT_ISSUED` (zachowanie bez zmian), dla revoked `REVOKED`.
(`/api/certs/status` już liczy status przed `try` — bez zmian.)

### 3. `update-in-place` cleanup (CLI `certhub.py`)

- Nowa opcja: `--omit-post-hook-on-revoke` (`bool`, domyślnie `False`).
- W pętli per-cert, **przed** gałęzią „not issued" (brak `certificate`): jeśli
  `cert.get("status") == "REVOKED"`:
  - usuń istniejące pliki z `pem_files` (`<prefix>_<typ>.pem` dla typów `--pem`),
  - zbuduj wynik: status `REVOKED`, `msg` „Revoked on server; removed local files: …"
    (lista usuniętych; jeśli żaden nie istniał — „no local files to remove"),
  - `updated = True` (liczy się do `is_any_updated`) **chyba że** `--omit-post-hook-on-revoke`
    → `updated = False`,
  - `continue` (nie wchodzi w dalsze gałęzie issue/expiry).
- `--post-hook` odpala się jak dziś, gdy `is_any_updated` (więc cleanup go wyzwala, o ile
  flaga nie ustawiona).
- owner/group/chmod nie dotyczą usuwania.

### 4. Pliki

- `cert_hub/domain/cert/cert_bot.py` — `revoked_dir` + `mark_revoked`/`is_revoked`/`clear_revoked`.
- `cert_hub/domain/cert/letsencrypt_cert.py` — `revoke`/`issue`/`get_status`.
- `cert_hub/api/routes.py` — `cert_list` (status przed try; except używa status).
- `certhub.py` — `--omit-post-hook-on-revoke` + gałąź cleanup w `update-in-place`.
- `README.md` — opis statusu REVOKED, zachowania update-in-place, nowej flagi,
  katalogu `revoked/`.

## Testy

- `CertBot.mark_revoked/is_revoked/clear_revoked` — unit z `base_dir=tmp_path`
  (`CertBot.load(...)`), bez certbota.
- `LetsEncryptCert.get_status()` → `REVOKED` gdy `is_revoked` True i pliki nieobecne;
  `NOT_ISSUED` gdy marker nieobecny. `revoke()` woła `mark_revoked`; `issue()` woła
  `clear_revoked` — przez fake `CertBot` (wzorzec `tests/test_letsencrypt_cert.py`,
  monkeypatch `CertBot.get_from_global_context`).
- `cert_list` i `update-in-place`: routes/CLI nietestowane jednostkowo → `make lint`
  + import-check (`python -c "import cert_hub.api.routes"`) + review. Istniejący `make test`
  zielony.

## Poza zakresem (YAGNI)

- Cleanup static certów (revoke nieobsługiwany).
- TTL / automatyczne wygasanie markerów (czyszczone tylko przez `issue`).
- Osobny env `REVOKED_DIR` (lokalizacja wyprowadzona z `CERTBOT_DIR`).
- Endpoint API do listowania/zarządzania markerami.
