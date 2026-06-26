# Design: ujednolicenie akcji do per-cert (issue/renew/revoke)

Data: 2026-06-25

## Cel

Ujednolicić akcje na certyfikatach do stylu **per-cert** (zasób `<cert_id>`),
spójnie z istniejącym `POST /api/certs/<id>/revoke` i `GET /api/certs/<id>/pem`.
Usunąć bulkowe (`?match=`) endpointy issue/renew z serwerowego API. CLI zachowuje
UX listy/`--pattern`, realizując operację jako fan-out po per-cert wywołaniach.

## Decyzje (potwierdzone)

1. Serwerowe API akcji: **tylko per-cert**. Bulk `POST /api/certs/issue|renew?match=`
   **usunięte**.
2. Revoke pozostaje per-cert (bez bulk).
3. CLI `cert issue`/`cert renew`: UX bez zmian; wewnętrznie discovery + pętla per-cert.
4. Discovery w CLI: **nowy `GET /api/certs/catalog`** (tylko auth) z opcjonalnymi
   filtrami `?match=`, `?type=`, `?permission=`. Zwraca lekką listę `[{id, type}]`.
   Matching i filtr typu/uprawnień po stronie serwera; brak wymogu `read`.

## Architektura

### 1. Serwerowe API (per-cert)

- **Nowe:** `POST /api/certs/<cert_id>/issue` (query `force`),
  `POST /api/certs/<cert_id>/renew` (query `force`).
- **Bez zmian:** `POST /api/certs/<cert_id>/revoke`.
- **Usunięte:** `POST /api/certs/issue` i `POST /api/certs/renew` (warianty `?match=`).
- Rozwiązanie pojedynczego certa: `Context.authenticate().resolve_scope([cert_id],
  action)[0]` (`action` = `ISSUE`/`RENEW`) — daje 404 (brak), 403 (brak uprawnień).
- Wykonanie: `cert.issue(force)` / `cert.renew(force)`.
- Semantyka odpowiedzi (spójna z `revoke`):
  - sukces → `200` `data={id, type, status, ...}`:
    - issue → `status="ISSUED"`, `expire_date`
    - renew → `status="RENEWED"`, `next_renew_date`, `expire_date`
  - `CertException` (np. `ALREADY_ISSUED`, `NOT_YET_RENEWABLE`, static `NOT_SUPPORTED`)
    → `409` `{msg, detail:{id, status}}`
  - `CertBotError` → 502 (istniejący `ApiError` handler; nie łapać w trasie)
- DRY: wspólny helper budujący sukcesowy payload akcji per-cert (id + type + status +
  daty), używany przez issue/renew (i analogicznie revoke).

### 2. `GET /api/certs/catalog` (nowy, lekki katalog certów)

Tylko auth (jak `token_scope`; bez `read`, bez konkretnej akcji do *wywołania*).
Zwraca `data=[{ "id": ..., "type": ... }]`. Opcjonalne filtry (kumulatywne, AND):
- `match` (`query_list`, domyślnie `["*"]`) → `Context._match_certs(match, conf.certs)`.
- `type` (`query_one_of`, dozwolone `CertType.values()`, domyślnie `all`) → filtr po
  `cert.type` (reuse `filter_certs_by_type`).
- `permission` (`query_one_of`, dozwolone akcje **per-cert**: `read`, `issue`, `renew`,
  `status`, `revoke`; domyślnie brak filtra) → zostaw tylko certy, gdzie
  `identity.allows(cert, action)`. Wartości spoza per-cert (`reload`, `*`) → 400.
- Brak `permission` → bez filtra uprawnień (wszystkie dopasowane).

Token_scope pozostaje bez zmian (redundancja akceptowalna; katalog jest dla CLI fan-out).

### 3. CLI `cert issue` / `cert renew` (fan-out)

UX bez zmian (`--pattern`, `--force`, `--type`, `-t/--timeout`, `-f/--format`,
`-c/--column`). Przepływ:
1. `GET /api/certs/catalog?match=<pattern>&type=<--type>&permission=issue` (dla renew
   `permission=renew`). Zwraca `[{id, type}]` — tylko dozwolone+dopasowane+typu.
2. Z odpowiedzi wziąć listę `id`.
3. Dla każdego `id`: `POST /api/certs/<id>/issue|renew` (z `force` gdy podano).
4. Agregować wyniki: każde 200 i każde 409 → jeden wiersz wyniku (id, status, daty,
   msg), bez przerywania pętli na 409. Render jak dziś (lista per-cert).
5. Pusty katalog → czytelny komunikat (jak dziś „not found"/pusto), bez wywołań akcji.
- `--type` przekazywany do katalogu (filtr serwerowy) — CLI nie matchuje sam.
- Timeout `-t` stosuje się do każdego pojedynczego żądania.
- `update-in-place` bez zmian (dalej `GET /api/certs`).

### 3b. CLI `cert revoke` (NOWA komenda + bramka potwierdzenia)

Dziś revoke istnieje tylko w API — dochodzi komenda CLI `cert revoke`. Fan-out jak
issue/renew, ale z obowiązkowym potwierdzeniem:
1. `GET /api/certs/catalog?match=<pattern>&permission=revoke` → lista `[{id, type}]`.
2. Jeśli pusto → komunikat „brak certów do unieważnienia", wyjście bez akcji.
3. **Wypisać listę certów, które zostaną unieważnione** (ich `id`).
4. **Potwierdzenie:** użytkownik musi wpisać dokładnie `Yes i really mean it`
   (dopasowanie pełne, z zachowaniem wielkości liter). Cokolwiek innego → przerwij,
   żadnego revoke.
5. Po potwierdzeniu: dla każdego `id` `POST /api/certs/<id>/revoke`, agreguj wyniki
   (200/409 per cert) i renderuj jak issue/renew.
- **Bypass:** flaga `--yes-i-really-mean-it` pomija interaktywny prompt (krok 4) —
  do automatyzacji. Lista certów (krok 3) i tak jest wypisywana. Bez tej flagi prompt
  jest zawsze wymagany; w środowisku nieinteraktywnym (brak TTY) brak flagi → przerwij
  z czytelnym komunikatem zamiast zawieszać się na promptcie. Brak `--force`.

### 4. Pliki

- `cert_hub/api/routes.py`:
  - usunąć `cert_issue`/`cert_renew` bulk (match) trasy,
  - dodać `cert_issue(cert_id)`/`cert_renew(cert_id)` per-cert trasy,
  - dodać `GET /api/certs/catalog` (filtry `match`/`type`/`permission`),
  - (opcjonalnie) wspólny helper payloadu akcji.
  - `token_scope` bez zmian.
- `certhub.py`: przepisać komendy `cert_issue`/`cert_renew` na discovery+fan-out z
  agregacją; **dodać nową komendę `cert_revoke`** (fan-out + bramka potwierdzenia
  „Yes i really mean it"); logika dopasowania zostaje na serwerze (CLI nie matchuje).
- `README.md`: tabela endpointów (usunąć bulk issue/renew, dodać per-cert; `scope`
  zyskuje `match`); zaznaczyć, że revoke i issue/renew są per-cert.

## Testy

- Serwer: filtr `match` w `token_scope` opiera się na czystym `Context._match_certs`
  (już testowane w `test_context.py`); ewentualny dodatkowy test dla zawężania scope
  jeśli wykonalny bez pełnego app-contextu (inaczej lint + review).
- Trasy Flask i CLI nie są testowane jednostkowo w tym projekcie (brak fixtur/typer w
  venv) — weryfikacja `make lint` + import-check (`python -c "import cert_hub.api.routes"`)
  + review. Istniejący zestaw (`make test`) musi pozostać zielony.

## Poza zakresem (YAGNI)

- Bulk revoke (świadomie tylko per-cert).
- Bulk issue/renew w serwerowym API (świadomie usunięte; lista realizowana przez CLI).
- Klient-side matching w CLI (matching/filtrowanie zostaje serwerowe via `/api/certs/catalog`).
- Zmiany w `update-in-place`.

## Follow-up (osobny spec, poza tym zakresem)

Trwałość statusu **REVOKED** i sprzątanie po stronie klienta: ponieważ
`certbot revoke --delete-after-revoke` kasuje pliki, serwer nie odróżnia REVOKED od
NOT_ISSUED. Przyszły spec doda marker REVOKED (np. `<certbot_dir>/revoked/<id>`,
czyszczony przy następnym `issue`) oraz logikę `update-in-place`, która dla statusu
REVOKED usuwa lokalne pliki `<prefix>_<typ>.pem`. Tu tego NIE robimy — bieżący spec
dostarcza tylko revoke per-cert + komendę CLI.

## Uwaga o kompatybilności

To **zmiana łamiąca** dla zewnętrznych klientów wołających dotąd
`POST /api/certs/issue?match=` / `renew?match=` — muszą przejść na per-cert
(`/api/certs/<id>/issue|renew`) lub na fan-out jak CLI. Udokumentowane w README.
