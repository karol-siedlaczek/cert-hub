# Design: `--pem` (multiple) w `cert update-in-place`

Data: 2026-06-23

## Cel

Rozszerzyć CLI `cert update-in-place`, aby pojedyncze wywołanie mogło wyprodukować
wiele plików PEM danego certa, wskazanych wielokrotną opcją `--pem/-P`. Domyślnie
`bundle`. Nazwa pliku: `<prefix>_<typ>.pem`, gdzie prefix pochodzi z custom_attr
`pem_prefix` lub `<cert_id>`.

## Decyzje (potwierdzone)

1. `--pem/-P` jest wielokrotny (`list[str]`), domyślnie `["bundle"]`; wartości z
   `{cert, privkey, chain, bundle}` (`PemType`, już istnieje). Duplikaty usuwane,
   kolejność zachowana.
2. Nazewnictwo: prefix = `custom_attrs["pem_prefix"]` jeśli ustawiony, inaczej
   `<cert_id>`. Plik dla typu T: `<dest_dir>/<prefix>_<T>.pem`. `pem_filename`
   **usunięty** (zmiana łamiąca dla obecnych użytkowników `pem_filename`).
3. Wymagane pola serwera = tylko te potrzebne dla żądanych typów `--pem`.
4. Decyzja o aktualizacji jest **per-cert** (wspólna dla wszystkich żądanych plików).
5. Wynik: 1 wiersz na cert; pole `pem_file` → `pem_files` (lista).

## Zachowanie

### Treść per typ
- `cert` → pole API `certificate`
- `privkey` → pole API `private_key`
- `chain` → pole API `chain`
- `bundle` → `certificate` + `chain` + `private_key` sklejone (puste części pomijane,
  więc bundle bez chaina dla self-signed działa)

### Walidacja wejścia
- Każda wartość `--pem` musi należeć do `PemType.values()`; inaczej `typer.BadParameter`.
- Prefix (`pem_prefix` lub `cert_id`) musi pasować do `PEM_FILENAME_PATTERN`
  (`^[\w.-]+$`); inaczej wynik błędu dla tego certa (CRITICAL).

### Wymagane pola serwera (suma po żądanych typach)
- `certificate` wymagane gdy żądany `bundle` lub `cert`
- `private_key` wymagane gdy żądany `bundle` lub `privkey`
- `chain` wymagane gdy żądany `chain` (dla `bundle` chain jest opcjonalny — dołączany
  tylko jeśli niepusty)
- `expire_date` wymagane tylko gdy żądany typ zawierający cert (`bundle`/`cert`)

Brak wymaganego pola → wynik błędu tylko dla danego certa (pozostałe lecą dalej):
- brak `certificate` (gdy potrzebny) → WARNING „Not issued on server side"
- brak `chain` (gdy żądany `chain`) → CRITICAL „Chain is missing on server side"
- brak `private_key` (gdy potrzebny) → CRITICAL „Private key is missing on server side"
- brak/niepoprawny `expire_date` (gdy potrzebny) → CRITICAL

### Decyzja o aktualizacji (per-cert)
- referencja daty = `bundle` jeśli w żądanych, inaczej `cert` jeśli w żądanych,
  inaczej brak (`chain`/`privkey` nie są wiarygodnym źródłem daty leafa).
- Aktualizuj WSZYSTKIE żądane pliki, jeśli:
  - którykolwiek żądany plik nie istnieje na dysku, **lub**
  - jest referencja i `remote_expire_date > local_expire_date` (lokalna czytana z
    pliku referencyjnego przez `get_cert_expire_date`).
- Gdy brak referencji daty: decyzja wyłącznie po istnieniu żądanych plików (brakuje
  któregoś → zapisz wszystkie; wszystkie są → „Up to date").
- Przy aktualizacji: zapisz każdy żądany plik, ustaw `chmod` oraz (jeśli podane)
  `owner`/`group` na KAŻDYM pliku.

### Wynik / raport
- Jeden `CertUpdateResult` na cert. Pole `pem_file: Path` zastąpione przez
  `pem_files: list[Path]` (serializowane jako lista stringów pod kluczem `pem_files`).
- `status`, `updated`, `local_expire_date`, `remote_expire_date`, `msg` pozostają
  per-cert. `local/remote_expire_date` pochodzą z referencji daty (lub `None` gdy brak).
- `post_hook` (raz, jeśli cokolwiek zaktualizowano) i raportowanie Nagios — bez zmian.

## Architektura / pliki

- `certhub.py` (wszystko zostaje w tym jednym, samodzielnym pliku — bez wydzielania
  nowego modułu, by nie komplikować dystrybucji standalone):
  - `--pem` jako `list[str]` z domyślnym `[PemType.default().value]`.
  - Pomocnicze funkcje/metody (dla czytelności i DRY; mogą być metodami `PemType`
    lub funkcjami modułowymi w `certhub.py`):
    - walidacja + dedup żądanych typów (`PemType`), z zachowaniem kolejności.
    - `resolve_pem_prefix(cert: dict) -> str` — `pem_prefix` lub `id`.
    - budowa treści dla typu: `cert`/`privkey`/`chain`/`bundle` (bundle pomija puste części).
    - zbiór wymaganych pól serwera dla żądanych typów.
    - typ-referencja daty: `bundle`>`cert`>`None`.
  - Pętla per-cert przepisana, by używać tych funkcji i zapisywać wiele plików.
- `README.md`: opis `--pem`, schematu `<prefix>_<typ>.pem`, custom_attr `pem_prefix`
  (zastępuje `pem_filename`).

## Testy

- Spójnie z resztą tego projektu, `certhub.py` (CLI) NIE jest testowany jednostkowo:
  importuje `typer`/`requests`/`rich`, których brak w venv testowym, więc nie da się go
  zaimportować w teście bez restrukturyzacji i komplikacji dystrybucji standalone (a
  projekt dziś nie ma żadnych testów CLI).
- Weryfikacja: `make lint` (`py_compile certhub.py`) oraz uważny przegląd diffu (review).
- Logika serwera/domeny nie zmienia się, więc istniejący zestaw testów (`make test`)
  musi nadal przechodzić bez zmian.

## Poza zakresem (YAGNI)

- Per-plik decyzja o aktualizacji (świadomie per-cert).
- Wsteczna zgodność `pem_filename` (świadomie usunięty).
- Dodatkowe typy PEM poza istniejącym `PemType`.
