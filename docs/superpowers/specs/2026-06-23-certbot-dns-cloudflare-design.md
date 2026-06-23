# Design: obsługa `certbot-dns-cloudflare`

Data: 2026-06-23

## Cel

Dokończyć i w pełni włączyć wsparcie dla DNS providera Cloudflare
(`certbot-dns-cloudflare`) obok istniejącego AWS Route 53. Enum
`DnsProvider.CF` już istnieje, ale jest niekompletny (`get_required_envs`
zwraca `("TODO")`), a `requirements.txt` nie zawiera pluginu.

## Kontekst / różnica względem AWS

- **AWS Route 53** — plugin certbota czyta zmienne środowiskowe
  (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), które subprocess certbota
  dziedziczy z procesu gunicorna. Do komendy wystarczy dopisać flagę
  `--dns-route53`.
- **Cloudflare** — plugin `certbot-dns-cloudflare` **nie czyta** zmiennych
  środowiskowych. Wymaga pliku credentials INI przekazanego przez
  `--dns-cloudflare-credentials <ścieżka>`.

## Decyzje (potwierdzone)

1. Credentiale dostarczane przez zmienną środowiskową; aplikacja sama
   generuje plik INI w runtime.
2. Wspierana tylko metoda **API Token** (`dns_cloudflare_api_token`).
   Bez legacy Global API Key + email.
3. Plik INI jest **efemeryczny per operacja** (issue/renew), nie trzymany
   na stałe na dysku.

## Architektura

### 1. Przepływ credentiali

- Nowa zmienna środowiskowa: **`CLOUDFLARE_DNS_API_TOKEN`**.
- W `Config.load()` rozwiązywana przez istniejące
  `Config._resolve_secret("CLOUDFLARE_DNS_API_TOKEN")` — daje za darmo
  wsparcie dla wariantu `CLOUDFLARE_DNS_API_TOKEN__FILE` (spójnie z
  `AWS_SECRET_ACCESS_KEY`).
- Nowe pole w `Config`: `cloudflare_dns_api_token: str = None`.
- Wartość przekazywana z `create_app` (`app.py`) do `CertBot.load(...)`
  jako nowy argument; przechowywana jako nowe pole `CertBot`
  (`cloudflare_dns_api_token: str | None`).

### 2. Walidacja

- `DnsProvider.CF.get_required_envs()` zwraca `("CLOUDFLARE_DNS_API_TOKEN",)`
  (zamiast `("TODO")`).
- Istniejące `Require.envs(dns_provider.get_required_envs())` w
  `Cert.from_dict` wymusza obecność zmiennej tylko gdy w configu istnieje
  certyfikat z `dns_provider: cloudflare` — dokładnie tak jak dla AWS dziś.

### 3. Generowanie pliku INI (lifecycle)

W `CertBot` powstaje context manager budujący provider-specyficzne
argumenty certbota i zarządzający efemerycznym plikiem credentials:

```python
@contextmanager
def _dns_provider_args(self, dns_provider: DnsProvider):
    if dns_provider == DnsProvider.CF:
        with tempfile.NamedTemporaryFile("w", suffix=".ini") as f:
            os.chmod(f.name, 0o600)
            f.write(f"dns_cloudflare_api_token = {self.cloudflare_dns_api_token}\n")
            f.flush()
            yield ["--dns-cloudflare", "--dns-cloudflare-credentials", f.name]
    else:
        yield [f"--{dns_provider.get_plugin()}"]
```

- Plik tworzony z uprawnieniami `0600`, usuwany automatycznie po wyjściu z
  bloku `with` (czyli zaraz po zakończeniu wywołania certbota).
- Token **nigdy nie trafia** na zamontowany wolumen `CERTBOT_DIR`; istnieje
  na dysku tylko na czas pojedynczej operacji.
- `--dns-cloudflare-propagation-seconds` pozostaje domyślne (10s) — bez
  dodatkowej konfiguracji (YAGNI).

### 4. Budowanie komendy w issue/renew

`CertBot.issue` i `CertBot.renew` obecnie wstawiają
`f"--{dns_provider.get_plugin()}"` bezpośrednio. Po zmianie owijają
budowanie i uruchomienie `cmd` w `with self._dns_provider_args(dns_provider)
as dns_args:` i wstawiają `*dns_args` w miejsce flagi pluginu. Uruchomienie
certbota musi nastąpić **wewnątrz** bloku `with`, póki plik istnieje.

## Zmiany w plikach

- `cert_hub/domain/dns_provider.py` — dokończyć `get_required_envs` dla CF.
- `cert_hub/domain/cert_bot.py` — nowe pole `cloudflare_dns_api_token`,
  nowy param w `load(...)`, context manager `_dns_provider_args`,
  przebudowane `issue`/`renew`.
- `cert_hub/conf/config.py` — nowe pole + rozwiązanie sekretu w `load()`.
- `cert_hub/app.py` — przekazanie tokena do `CertBot.load(...)`.
- `requirements.txt` — dodać `certbot-dns-cloudflare==5.2.2`.
- `README.md` — env `CLOUDFLARE_DNS_API_TOKEN` w tabeli, aktualizacja miejsc
  mówiących „currently supported value is `aws`".

## Testy

Nowy `tests/test_dns_provider.py`:

- `DnsProvider.values()` zwraca `["aws", "cloudflare"]`.
- `get_plugin()`, `get_required_module()`, `get_required_envs()` dla obu
  providerów.
- `CertBot._dns_provider_args`:
  - dla AWS: `["--dns-route53"]`, brak pliku.
  - dla CF: zawiera `--dns-cloudflare` i `--dns-cloudflare-credentials`,
    plik istnieje wewnątrz bloku `with` z uprawnieniami `0600` i poprawną
    treścią, oraz **nie istnieje** po wyjściu z bloku.

Testy działają bez zainstalowanego `certbot` — `cert_bot.py` importuje
jedynie `DnsProvider`, `CertBotError` i `flask` (flask jest w
`tests/requirements.txt`); `_dns_provider_args` nie uruchamia binarki.

## Poza zakresem (YAGNI)

- Legacy Global API Key + email.
- Konfigurowalny `--dns-cloudflare-propagation-seconds`.
- Per-cert credentiale (jeden globalny token na całą instancję, jak dla AWS).
- Naprawa istniejącej niespójności AWS `__FILE` vs `Require.envs`.
