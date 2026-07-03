# Design: plik stanu `cert sync` + sprzątanie zagubionych certów

Data: 2026-07-03

## Cel

`cert sync` ma utrzymywać w dest-dir trwały **plik stanu** (`.certhub-sync-state.json`)
z listą certów i ich plików (z sumami `sha256`) zapisanych podczas ostatniego runa.
Dzięki temu przy kolejnym runie sync wykrywa certy, które **zniknęły z odpowiedzi API**
(identity straciło dostęp, lub cert wypadł przez zmianę filtra) i sprząta po nich pliki —
analogicznie do obecnego zachowania dla `REVOKED`. Przed usunięciem weryfikuje `sha256`,
żeby mieć pewność, że to plik wygenerowany podczas ostatniego runa.

## Problem

Dziś `cert sync` iteruje tylko po tym, co zwróci `GET /api/certs`. Jeśli cert znika z
odpowiedzi (odebrano uprawnienia tokenowi), lokalne pliki `<prefix>_<typ>.pem` zostają
osierocone — sync ich nie widzi i nie sprząta. `REVOKED` jest obsługiwany, bo cert nadal
jest zwracany ze statusem. Brakuje pamięci o poprzednim stanie, żeby wykryć zniknięcia.

## Decyzje (potwierdzone)

1. **Plik stanu**: stała nazwa `.certhub-sync-state.json` w dest-dir, zawsze aktywny
   (bez flagi opt-in).
2. **Bez kluczowania per filtr** — jeden płaski stan. Użyty filtr (`type` + `patterns`)
   zapisywany informacyjnie. Jeśli filtr się zmienił od ostatniego runa, certy niepasujące
   do nowego filtra **zostaną usunięte** (zamierzone) — sync o tym ostrzega (`WARNING` + log).
3. **Niezgodna `sha256`** przy sprzątaniu → plik **nietknięty**, wynik `WARNING`.
4. **Sprzątanie zagubionego certa** liczy się jako zmiana → wyzwala `--post-hook`; tłumione
   nową flagą `--omit-post-hook-on-prune` (niezależną od `--omit-post-hook-on-revoke`).
5. **`--dry-run`**: raportuje, co zostałoby dodane/zaktualizowane/usunięte; nie zapisuje
   plików PEM, nie usuwa niczego, nie aktualizuje pliku stanu.
6. **`--dest-dir` → argument pozycyjny** (czysty; znika `-d/--dest-dir`).

## Architektura

### 1. Zmiany w sygnaturze `cert_sync` (`certhub.py`)

- `dest_dir` z `typer.Option(..., "--dest-dir", "-d", ...)` → `typer.Argument(..., help=...)`.
  Walidacja (istnieje / jest katalogiem) bez zmian.
- Nowa opcja `dry_run: bool = typer.Option(False, "--dry-run", help=...)`.
- Nowa opcja `omit_post_hook_on_prune: bool = typer.Option(False, "--omit-post-hook-on-prune", help=...)`.

### 2. Struktura pliku stanu

```json
{
  "version": 1,
  "filter": { "type": "letsencrypt", "patterns": [] },
  "timestamp": "2026-07-03T12:00:00+00:00",
  "certs": [
    {
      "id": "siedlaczek.com.pl",
      "files": [
        { "file": "siedlaczek.com.pl_bundle.pem",  "sha256": "…" },
        { "file": "siedlaczek.com.pl_privkey.pem", "sha256": "…" }
      ]
    }
  ]
}
```

- `filter` — informacyjny zapis filtra tego runa (`type` oraz posortowana lista `patterns`).
- `certs` — wyłącznie certy zmaterializowane pomyślnie (status OK, pliki obecne na dysku).
- `file` — nazwa pliku (basename, w dest-dir); `sha256` — hex digest z **bajtów pliku** na
  dysku (spójne dla świeżo zapisanych i „up to date").
- Uszkodzony / niesparsowalny plik stanu → log `WARNING`, traktowany jak pusty (run nie
  jest przerywany).

### 3. Helpery (`certhub.py`)

- `sha256_file(path: Path) -> str` — czyta bajty, zwraca `hexdigest`.
- `load_sync_state(path: Path) -> dict` — czyta i parsuje JSON; zwraca `{}` (i loguje
  `WARNING`) przy braku pliku / błędzie parsowania.
- `write_sync_state(path, filter_obj, certs, timestamp)` — zapis atomowy (wzorzec jak
  `_write_secure` / `write_status_file`), tworzy katalog nadrzędny; błąd zapisu logowany,
  nie przerywa runa. Pomijany całkowicie w `--dry-run`.
- `state_filter_obj(patterns, cert_type) -> dict` — `{"type": <type>, "patterns": sorted(patterns)}`.

### 4. Przepływ w `cert_sync`

Rozszerzenie istniejącej pętli i finalizacji (`certhub.py:815`+):

1. Przed pętlą: `state_path = certs_dir / ".certhub-sync-state.json"`; wczytaj
   `prior = load_sync_state(state_path)`; `prior_certs = prior.get("certs", [])`.
2. Istniejąca pętla per-cert bez zmian w logice issue/expiry/revoke; dodatkowo dla każdego
   certa zakończonego statusem **OK z plikami na dysku** zbierz wpis
   `{"id": cert_id, "files": [{"file": p.name, "sha256": sha256_file(p)} for p in pem_files if p.exists()]}`
   → `current_certs`. (W `--dry-run` certy wymagające zapisu nie są zapisywane, więc ich
   `sha256` nie liczymy — stan i tak nie jest zapisywany.)
3. **Ostrzeżenie o zmianie filtra**: jeśli `prior` niepuste i `prior.get("filter") != state_filter_obj(...)`,
   dodaj `CertUpdateResult` informacyjny `WARNING` (bez `cert`/pseudo-id) + log:
   „Filtr zmieniony od ostatniego runa (było: …, jest: …); certy niepasujące zostaną usunięte: …".
4. **Prune**: `response_ids = {cert.get("id") for cert in result.data}`. Dla każdego wpisu w
   `prior_certs`, którego `id` **nie ma** w `response_ids`:
   - dla każdego zapisanego pliku istniejącego na dysku (`certs_dir / file`):
     policz `sha256`; **zgodny** z zapisanym → usuń (`unlink`; w `--dry-run` tylko oznacz);
     **niezgodny** → pomiń, oznacz cert jako `WARNING`.
   - dodaj `CertUpdateResult`: `code=OK` (lub `WARNING` gdy była niezgodność),
     `updated = bool(removed) and not omit_post_hook_on_prune`,
     `msg = "Removed: identity no longer has access; removed files: …"`
     (lub „… skipped (checksum mismatch): …" dla niezgodnych; „no local files to remove"
     gdy nic nie istniało).
   - Certy `REVOKED` są w `response_ids` (obsługa istniejącą gałęzią revoke) i **nie** trafiają
     do `current_certs` → **naturalnie wypadają ze stanu** w następnym zapisie.
5. **Post-hook**: mechanika `is_any_updated` bez zmian; wpisy prune z `updated=True` też go
   wyzwalają (tłumione `--omit-post-hook-on-prune`).
6. **Zapis stanu**: po pętli i prune, jeśli **nie** `--dry-run`:
   `write_sync_state(state_path, state_filter_obj(...), current_certs, now)`.
   Plik stanu (`.certhub-sync-state.json`) nigdy nie trafia do `current_certs` (nie jest
   plikiem PEM certa).
7. Istniejący `--status-file` i `render_and_exit` — bez zmian; `results` zawiera teraz wpisy
   prune i ewentualne ostrzeżenie o zmianie filtra.

### 5. Tryb `--dry-run`

- Brak `_write_secure` (certy do zapisu raportowane jako „Would add/update").
- Brak `unlink` w gałęziach revoke i prune (raport „Would remove").
- Brak zapisu pliku stanu.
- Wynik i `--status-file` renderowane normalnie (odzwierciedlają hipotetyczny run).

### 6. Pliki

- `certhub.py` — sygnatura `cert_sync` (pozycyjny `dest_dir`, `--dry-run`,
  `--omit-post-hook-on-prune`), helpery stanu, rozszerzenie pętli + prune + zapis stanu,
  gałęzie `--dry-run`.
- `README.md` (i/lub docs komendy sync) — pozycyjny argument, plik stanu, sprzątanie
  zagubionych certów, zachowanie przy zmianie filtra, `--dry-run`, `--omit-post-hook-on-prune`.

## Obsługa błędów

- Fetch z API nieudany → jak dziś (`render_and_exit`), **żadnego prune** (brak wiarygodnej listy).
- Błąd odczytu/zapisu stanu → log `WARNING`/`error`, run nie jest przerywany.
- Niezgodna `sha256` przy prune → `WARNING`, plik nietknięty.

## Testy (`tests/test_sync.py`)

- Plik stanu tworzony po runie z poprawną strukturą (`version`/`filter`/`certs`) i sumami `sha256`.
- Zniknięty cert (obecny w stanie, brak w odpowiedzi API) → jego pliki usunięte + wpis prune.
- Niezgodna `sha256` → plik nietknięty + `WARNING`.
- `--dry-run` → żaden plik PEM ani stan nie zmieniony na dysku, raport zawiera „would".
- Zmiana filtra od ostatniego runa → ostrzeżenie `WARNING` w wyniku; niepasujące certy sprzątane.
- Cert `REVOKED` → usunięty istniejącą gałęzią i **wypada ze stanu** w następnym zapisie.
- Prune wyzwala `--post-hook`; `--omit-post-hook-on-prune` go tłumi.
- Uszkodzony plik stanu → run nie wywala się, traktowany jak pusty.

## Poza zakresem (YAGNI)

- Kluczowanie stanu per filtr (świadomie odrzucone — jeden płaski stan).
- Konfigurowalna nazwa/ścieżka pliku stanu (stała `.certhub-sync-state.json`).
- Blokowanie/potwierdzanie sprzątania interaktywnie (od tego jest `--dry-run`).
- Sprzątanie / śledzenie certów `static` innego niż obecne (bez zmian w logice typów).
- Historia wielu runów w pliku stanu (trzymamy tylko ostatni stan).
