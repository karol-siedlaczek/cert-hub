# Design: nowe endpointy API (metrics, version, pem, revoke, reload)

Data: 2026-06-25

## Cel

Dodać pięć rozszerzeń HTTP API cert-hub:
1. `GET /api/metrics` — metryki Prometheus (auth + RBAC).
2. `GET /api/version` — rozszerzyć o `git_sha` i `build_date`.
3. `GET /api/certs/<id>/pem?type=bundle|cert|chain|privkey` — surowy PEM.
4. `POST /api/certs/<id>/revoke` — unieważnienie certu (LE) + usunięcie plików.
5. `POST /api/admin/reload` — przeładowanie konfiguracji (SIGHUP do mastera).

## Decyzje (potwierdzone)

1. `/api/metrics`: wymaga Bearer; emituje metryki tylko dla certów, na których
   tożsamość ma akcję `status`.
2. `/api/admin/reload`: autoryzacja przez nową akcję RBAC `reload` (wpis `*:reload`);
   wysyła `SIGHUP` do mastera gunicorna → graceful reload wszystkich workerów.
3. `POST /api/certs/<id>/revoke`: `certbot revoke --delete-after-revoke` → status
   potem `NOT_ISSUED`; static → `NOT_SUPPORTED`.

## Architektura

### 1. Uprawnienia (cross-cutting)

`cert_hub/domain/permission.py` — do `PermissionAction` dodać:
- `REVOKE = "revoke"`
- `RELOAD = "reload"`

`Permission.from_string` buduje regex z `PermissionAction.values()`, więc nowe akcje
są akceptowane automatycznie. `/api/token/scope` iteruje po akcjach (poza `ANY`), więc
`revoke`/`reload` pojawią się w zakresie tożsamości.

`reload` jest akcją globalną (nie per-cert). Autoryzacja: nowa metoda na `Identity`:
`has_global_action(action: PermissionAction) -> bool` — `True`, gdy istnieje permisja
ze `scope == "*"` i akcją równą `action` lub `ANY`. Używana przez `/api/admin/reload`.

Istniejące `Cert.has_permission(identity, action)` obsługuje akcje per-cert (`read`,
`revoke`, `status`, …) bez zmian.

### 2. `GET /api/version` (+git_sha, +build_date)

Bez auth (jak dziś). Do payloadu dodać:
- `"git_sha": os.getenv("GIT_SHA", "unknown")`
- `"build_date": os.getenv("BUILD_DATE", "unknown")`

(`GIT_SHA`/`BUILD_DATE` ustawiane przy buildzie obrazu/CI.)

### 3. `GET /api/certs/<id>/pem`

Wymaga `read` na danym certcie. Rozwiązanie pojedynczego certa:
`Context.authenticate().resolve_scope([id], PermissionAction.READ)` → lista 0/1; brak
dopasowania → 404, brak uprawnień → 403 (istniejąca semantyka `resolve_scope`).

`type` walidowany przez `query_one_of` do `{bundle, cert, chain, privkey}`, domyślnie
`bundle`. Treść:
- `cert` → `cert.get_certificate()`
- `chain` → `cert.get_chain()`
- `privkey` → `cert.get_private_key()`
- `bundle` → `certificate` + `chain` + `private_key` sklejone (puste pomijane)

Sukces: `Response(pem_text, mimetype="text/plain")` (nie `build_response`). Cert nie
wystawiony / brak pliku → akcesory rzucają `CertException` → odpowiedź JSON 4xx (jak
dziś przez handler). Poziom ekspozycji klucza prywatnego = ten sam co `/api/certs`
(które już zwraca `private_key` dla `read`).

### 4. `POST /api/certs/<id>/revoke`

Wymaga `revoke`. Rozwiązanie certa: `resolve_scope([id], PermissionAction.REVOKE)`.
- `cert.revoke()` na bazie `Cert` jako nowa metoda abstrakcyjna.
- `StaticCert.revoke()` → `CertException(status=CertStatus.NOT_SUPPORTED)`.
- `LetsEncryptCert.revoke()` → jeśli nie wystawiony: `CertException(NOT_ISSUED)`; inaczej
  `CertBot.revoke(self.id)`.
- `CertBot.revoke(cert_name)` (nowa metoda) buduje:
  `<exe> revoke --cert-path <conf_dir>/live/<cert_name>/cert.pem --delete-after-revoke
  *base_args` i uruchamia przez `_run_cmd`; `returncode != 0` → `CertBotError`.
- Po sukcesie pliki lineage znikają → `is_issued()` = False → status `NOT_ISSUED`.
- Nowy `CertStatus.REVOKED` używany w odpowiedzi akcji (analogicznie do `ISSUED`/
  `RENEWED`). Odpowiedź: `200` z `{id, status: "REVOKED", msg}`.

### 5. `GET /api/metrics` (Prometheus, auth + RBAC)

Wymaga Bearer (`Context.authenticate()`). Zbiór certów = te, na których tożsamość ma
`PermissionAction.STATUS` (`cert.has_permission(identity, STATUS)`).

Format: Prometheus text exposition, `Response(text, mimetype="text/plain; version=0.0.4")`.
Renderowanie wydzielone do czystej funkcji `render_metrics(records, build_info) -> str`,
gdzie `records` to lista policzonych słowników (testowalna bez Flaska). Metryki:
- `# HELP`/`# TYPE` dla każdej rodziny.
- `certhub_build_info{version="…",git_sha="…"} 1`
- per cert (gdy data wygaśnięcia dostępna, tj. status liczbowy z certu):
  - `certhub_cert_expiry_timestamp_seconds{id="…",type="…"} <unix_ts>`
  - `certhub_cert_days_to_expire{id="…",type="…"} <int>`
- per cert (zawsze):
  - `certhub_cert_status{id="…",type="…",status="OK|EXPIRING|EXPIRED|NOT_ISSUED|CERT_MISSING|KEY_MISSING|CHAIN_MISSING|INVALID_CERT_FILE"} 1`

Etykiety escapowane wg reguł Prometheusa (`\`, `"`, nowa linia). Cert bez daty
(nie wystawiony / brak pliku) → pomijamy metryki czasowe, emitujemy tylko `_status`.
Liczenie statusu/daty per cert opakowane w `try/except CertException`, by jeden zły cert
nie wywrócił całości.

### 6. `POST /api/admin/reload` (auth `*:reload`, SIGHUP)

Wymaga `*:reload` (`identity.has_global_action(PermissionAction.RELOAD)`; brak → 403).
Wysyła `SIGHUP` do procesu-mastera gunicorna: `os.kill(os.getppid(), signal.SIGHUP)`.
W gunicornie workery są bezpośrednimi dziećmi mastera, więc `getppid()` = master; SIGHUP
wyzwala graceful reload (ponowny `create_app` w nowych workerach → świeży `Config` i
`CertBot`). Zwraca `202 Accepted` z komunikatem „Reload signal sent to master process".

Best-effort: `os.kill` opakowane w `try/except`; błąd (np. brak uprawnień procesu,
nie pod gunicornem) → `500`/`502` z jasnym komunikatem. Endpoint wymaga uruchomienia pod
gunicornem (udokumentowane). Nie obsługujemy reloadu dla flask dev-servera.

## Pliki

- `cert_hub/domain/permission.py` — `REVOKE`, `RELOAD`.
- `cert_hub/domain/identity.py` — `has_global_action`.
- `cert_hub/domain/cert_status.py` — `REVOKED`.
- `cert_hub/domain/cert.py` — abstrakcyjna `revoke`.
- `cert_hub/domain/static_cert.py` — `revoke` → `NOT_SUPPORTED`.
- `cert_hub/domain/letsencrypt_cert.py` — `revoke`.
- `cert_hub/domain/cert_bot.py` — `revoke(cert_name)`.
- `cert_hub/api/metrics.py` (nowy) — `render_metrics(...)` czysta funkcja.
- `cert_hub/api/routes.py` — endpointy: version (+pola), `/api/metrics`,
  `/api/certs/<id>/pem`, `/api/certs/<id>/revoke`, `/api/admin/reload`.
- `README.md` — env `GIT_SHA`/`BUILD_DATE`, opis nowych endpointów i uprawnień
  `revoke`/`reload`.
- testy: `tests/test_permission.py` (nowe akcje, `*:reload` parsuje),
  `tests/test_cert_bot.py` (rozszerzenie: `revoke` buduje komendę),
  `tests/test_static_cert.py` (rozszerzenie: `revoke` → NOT_SUPPORTED),
  `tests/test_metrics.py` (nowy: `render_metrics`).

## Testy

- Domena/czyste funkcje testowane jednostkowo (pytest, bez certbota/sieci):
  `PermissionAction` + `Permission.from_string("*:reload")`, `Identity.has_global_action`,
  `CertBot.revoke` (budowa komendy, jak testy `_dns_provider_args`), `StaticCert.revoke`
  (`NOT_SUPPORTED`), `render_metrics` (poprawny tekst Prometheus + escaping), pem bundle
  builder, `query_one_of` dla typu pem.
- Trasy Flask i SIGHUP-reload: weryfikacja `make lint` + review (brak fixtury HTTP w
  projekcie; logika domeny pokryta jednostkowo).

## Poza zakresem (YAGNI)

- Rozszerzenia CLI (`certhub.py`) dla nowych endpointów (można dodać później).
- Reload dla flask dev-servera (tylko gunicorn).
- Powody/`reason` przy revoke (certbot domyślny).
- Histogramy/dodatkowe metryki ponad wymienione.
