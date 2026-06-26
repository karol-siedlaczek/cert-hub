#!/usr/bin/env python3

# Karol Siedlaczek 2026

import os
import sys
import grp
import pwd
import re
import json
import shlex
import shutil
import tempfile
import typer
import hmac
import hashlib
import base64
import click
import binascii
import subprocess
import logging
import requests
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from enum import Enum
from getpass import getpass
from pathlib import Path
from rich.console import Console
from rich.table import Table, box
from dataclasses import dataclass
from typing import Any, Optional, Dict, Sequence, NoReturn, ClassVar
from cryptography import x509

ENV_VAR_API_URL = "CERTHUB_API_URL"
ENV_VAR_TOKEN = "CERTHUB_TOKEN"
ENV_VAR_LOG_FILE = "CERTHUB_LOG_FILE"
ENV_VAR_LOG_LEVEL = "CERTHUB_LOG_LEVEL"
ENV_VAR_NSCA_SERVER = "CERTHUB_NSCA_SERVER"
ENV_VAR_NSCA_PORT = "CERTHUB_NSCA_PORT"
ENV_VAR_NAGIOS_HOSTNAME = "CERTHUB_NAGIOS_HOSTNAME"
SETTINGS_FILE = Path("~/.certhub").expanduser()
DATE_FMT = "%Y-%m-%d %H:%M"
NAGIOS_ESCAPE_CHAR = "</br>"
PEM_FILENAME_PATTERN = r"^[\w.-]+$"
LOGGER = logging.getLogger("certhub-cli")

app = typer.Typer(add_completion=True, help="CLI for managing certificates in Cert Hub")
cert_app = typer.Typer(help="Manage certificates: list, issue, renew, check status, and update local certificate files in place")
token_app = typer.Typer(help="Manage token identity: view scope and permissions, or generate HMAC values for server configuration")
app.add_typer(cert_app, name="cert")
app.add_typer(token_app, name="token")
console = Console()


# ── base classes ────────────────────────────────────────────────────────


class ExitCode(Enum):
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3
    

class Format(Enum):
    TABLE = "table"
    JSON = "json"
    KEY_VALUE = "kv"
    VALUE = "value"
    
    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]
    
    @classmethod
    def default(cls) -> "Format":
        return Format.TABLE
    
    @classmethod
    def from_string(cls, val: str) -> "Format":
        try:
            return Format(val)
        except ValueError:
            raise typer.BadParameter(f"Unknown format: {val}, must be one of: {(', ').join(Format.values())}")


class PemType(Enum):
    CERT = "cert"
    PRIV_KEY = "privkey"
    CHAIN = "chain"
    BUNDLE = "bundle"
    
    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]
    
    @classmethod
    def default(cls) -> "PemType":
        return PemType.BUNDLE
    
    @classmethod
    def from_string(cls, val: str) -> "PemType":
        try:
            return PemType(val)
        except ValueError:
            raise typer.BadParameter(f"Unknown PEM type: {val}, must be one of: {(', ').join(PemType.values())}")
    
    
class CertType(str, Enum):
    LETSENCRYPT = "letsencrypt"
    STATIC = "static"
    ALL = "all"

    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]

    @classmethod
    def from_string(cls, val: str) -> "CertType":
        try:
            return cls(val)
        except ValueError:
            raise typer.BadParameter(f"Invalid --type '{val}', must be one of: {', '.join(cls.values())}")


class Opt:
    @staticmethod
    def timeout(default: int = 10) -> Any:
        return typer.Option(
            default, "--timeout", "-t",
            help="API request timeout in seconds"
        )

    @staticmethod
    def format(default: str | None = None) -> Any:
        return typer.Option(
            default or Format.default().value, "--format", "-f",
            help=f"Output format: {", ".join(Format.values())}"
        )

    @staticmethod
    def columns() -> Any:
        return typer.Option(
            None, "-c", "--column",
            help="Specify the column(s) to include, can be repeated to show multiple columns"
        )

    @staticmethod
    def patterns() -> Any:
        return typer.Option(
            None, "--pattern", "-p",
            help="Certificate pattern, can be specified multiple times. Defaults to all certificates allowed for the current identity"
        )

    @staticmethod
    def force(help_text: str) -> Any:
        return typer.Option(
            None, "--force",
            help=help_text
        )

    @staticmethod
    def type(default: str = "all") -> Any:
        return typer.Option(
            default, "--type",
            help=f"Filter by certificate type: {', '.join(CertType.values())}"
        )


@dataclass
class Settings:
    api_url: str | None
    token: str | None
    log_file: str | None
    log_level: str | None
    format: Format | None
    nsca_server: str | None
    nsca_port: int | None
    nagios_hostname: str | None


@dataclass
class CmdResult:
    data: dict | list[dict]
    exit_code: ExitCode
    
    @classmethod
    def from_response(
        cls,
        response: requests.Response, 
        exit_code: ExitCode | None = None
    ) -> "CmdResult":
        data = cls._parse_response(response)
        exit_code = exit_code or (ExitCode.OK if response.ok else ExitCode.CRITICAL)

        return cls(data, exit_code)
    
    @classmethod
    def from_dict(
        cls, 
        data: dict | list[dict],
        exit_code: ExitCode | None = None
    ) -> "CmdResult":
        return cls(data, exit_code or ExitCode.OK)

    @staticmethod
    def _parse_response(response: requests.Response) -> dict | list[dict]:
        try:
            payload = response.json()
        except ValueError:
            return {"message": response.text}

        if not isinstance(payload, dict):
            return payload

        payload.pop("timestamp", None)
        if response.ok:
            payload = payload.get("data", payload)
            
        return payload
    
    def _filter_data(self, columns: tuple[str] | None = None) -> Any:
        if not columns:
            return self.data

        available_columns: set[str] = set()
        
        if isinstance(self.data, dict):
            available_columns = set(self.data.keys())
        elif isinstance(self.data, list):
            for row in self.data:
                if isinstance(row, dict):
                    available_columns.update(row.keys())

        missing_columns = [col for col in columns if col not in available_columns]
        if missing_columns:
            possible_columns = ", ".join(sorted(available_columns)) if available_columns else "<none>"
            missing = ", ".join(missing_columns)
            raise typer.BadParameter(f"Unknown column(s): {missing}, available choices: {possible_columns}")

        if isinstance(self.data, list):
            filtered_data = []
            for row in self.data:
                if isinstance(row, dict):
                    filtered_data.append({col: row.get(col) for col in columns})
                else:
                    filtered_data.append(row)
            return filtered_data

        if isinstance(self.data, dict):
            return {col: self.data.get(col) for col in columns}

        return self.data
    
    def _mask_sensitive(self, obj: Any, sensitive: set[str]) -> Any:
        if not sensitive:
            return obj

        if isinstance(obj, dict):
            out: dict[Any, Any] = {}
            for k, v in obj.items():
                if isinstance(k, str) and k in sensitive:
                    out[k] = "****"
                else:
                    out[k] = self._mask_sensitive(v, sensitive)
            return out

        if isinstance(obj, list):
            return [self._mask_sensitive(x, sensitive) for x in obj]

        return obj

    def render_and_exit(
        self,
        context_info: str | None = None,
        columns: tuple[str] | None = None,
        *,
        sensitive_columns: tuple[str] | None = None
    ) -> NoReturn:
        def _convert_val_as_str(val: Any) -> str:
            if isinstance(val, (dict, list)):
                return json.dumps(val, ensure_ascii=False)
            return str(val)

        def _render_field(key: Any, val: Any, key_width: int) -> str:
            key_as_str = str(key)
            val_as_str = _convert_val_as_str(val)
            return f"{key_as_str:<{key_width}} = {val_as_str}"
        
        def _render_table_cell(value) -> str:
            def format_kv_block(obj: dict, indent: str = "  ") -> str:
                key_width = max((len(str(k)) for k in obj.keys()), default=0)
                lines = []
                for k in sorted(obj.keys(), key=lambda x: str(x)):
                    v = obj[k]
                    if isinstance(v, (dict, list)):
                        v_str = json.dumps(v, ensure_ascii=False)
                    else:
                        v_str = str(v)
                    lines.append(f"{indent}{str(k):<{key_width}} = {v_str}")
                return "\n".join(lines)
            
            if value is None:
                return "-"

            if isinstance(value, dict):
                if not value:
                    return "{}"
                return format_kv_block(value, indent="")

            if isinstance(value, list):
                if not value:
                    return "-"

                if all(isinstance(x, dict) for x in value):
                    blocks = []
                    for i, item in enumerate(value, start=1):
                        header = f"• #{i}"
                        blocks.append(header)
                        blocks.append(format_kv_block(item, indent="  "))
                    return "\n".join(blocks)

                lines = []
                for item in value:
                    if isinstance(item, dict):
                        lines.append("•")
                        lines.append(format_kv_block(item, indent="  "))
                    elif isinstance(item, list):
                        lines.append("• " + json.dumps(item, ensure_ascii=False))
                    else:
                        lines.append(f"• {item}")
                return "\n".join(lines)
            return str(value)

        def _print(value: Any = "") -> None:
            if self.exit_code == ExitCode.OK:
                console.print(value)
                return
            if isinstance(value, str):
                console.print(value, style="red", markup=False, highlight=False)
                return
            console.print(value, style="red", highlight=False)
        
        data = self._filter_data(columns) if self.exit_code == ExitCode.OK else self.data
        settings = get_ctx_settings()
        fmt = settings.format
        
        if fmt == Format.JSON:
            _print(json.dumps(data, indent=2, ensure_ascii=False))
        elif fmt == Format.VALUE:
            if isinstance(data, dict):
                for val in data.values():
                    _print(_convert_val_as_str(val))
            elif isinstance(data, list):
                if all(isinstance(item, dict) for item in data):
                    for item in data:
                        for val in item.values():
                            _print(_convert_val_as_str(val))
                        if item != data[-1]: # Do not print on last iteration
                            _print()
                else:
                    for item in data:
                        _print(item)
        elif fmt == Format.KEY_VALUE:
            if isinstance(data, dict):
                key_width = max((len(str(key)) for key in data.keys()), default=0)
                for key, val in data.items():
                    _print(_render_field(key, val, key_width))
                    
            elif isinstance(data, list):
                if all(isinstance(item, dict) for item in data):
                    key_width = max((len(str(key)) for item in data for key in item.keys()), default=0)
                    
                    for item in data:
                        for key, val in item.items():
                            _print(_render_field(key, val, key_width))
                        if item != data[-1]: # Do not print on last iteration
                            _print()
                else:
                    for item in data:
                        _print(item)
            else:
                _print(data)
        elif fmt == Format.TABLE:
            rows = data if isinstance(data, list) else [data]
            rows = [r for r in rows if isinstance(r, dict)]
            if rows:
                table = Table(show_header=True, header_style="bold", expand=True, show_lines=True, box=box.ROUNDED)

                cols = list(rows[0].keys())
                for c in cols:
                    table.add_column(str(c), overflow="fold") # Fold helps if mucho text

                for row in rows:
                    table.add_row(*[_render_table_cell(row.get(c, "")) for c in cols])
                _print(table)
            elif data:
                _print(data)
        
        data_to_log = data
        if not LOGGER.disabled and sensitive_columns:
            data_to_log = self._mask_sensitive(data, sensitive_columns)
            
        LOGGER.log(
            logging.INFO if self.exit_code == ExitCode.OK else logging.ERROR,
            f"{f"Result for {context_info} command: " if context_info else ""}{data_to_log}"
        )
        raise typer.Exit(code=self.exit_code.value)


@dataclass(frozen=True)
class Client():
    base_url: str
    session: requests.Session
    timeout: int
    
    @classmethod
    def init(
        cls,
        ctx: typer.Context,
        fmt: str | None,
        *,
        timeout: int, 
        nagios: "Nagios | None" = None
    ) -> "Client":
        settings = load_settings(ctx, fmt)
        
        base_url = settings.api_url.rstrip("/")
        session = requests.Session()
        
        if settings.token:
            session.headers.update({"Authorization": f"Bearer {settings.token}"})

        session.headers.update({"Accept": "application/json"})
        
        try:
            session.request("GET", f"{base_url}/ping", timeout=10)
        except requests.RequestException as e:
            msg = "Error connecting to API server"
            exit_code = ExitCode.CRITICAL
            
            if nagios:
                nagios.send_passive_check_result(f"{exit_code.name}: {msg}, error: {e}", exit_code)
            result = CmdResult.from_dict({"msg": msg, "error": str(e)}, exit_code)
            return result.render_and_exit()
            
        return cls(base_url, session, timeout or 10)
    
    def request(
        self, 
        method: str, 
        path: str, 
        *, 
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        url = f"{self.base_url}{path}"
        
        response = self.session.request(
            method=method.upper(),
            url=url,
            params=params,
            json=json_body,
            timeout=self.timeout
        )
        
        return response


@dataclass
class Nagios():
    NSCA_CMD: ClassVar[str] = "/usr/sbin/send_nsca"
    server: str
    port: int
    hostname: str
    service: str
    
    @classmethod
    def from_options(cls, server: str, port: int, hostname: str, service: str) -> "Nagios | None":
        if not service:
            return None
            
        if service and not all([server, port, hostname]):
            raise typer.BadParameter(
                "To send passive check result to Nagios all NSCA related options must be provided together. Run --help for details"
            )
        
        nsca_cmd_path = Path(Nagios.NSCA_CMD)
        
        if not (nsca_cmd_path.exists() and os.access(nsca_cmd_path, os.X_OK)):
            raise typer.BadParameter(
                f"Failed to setup sending passive check result to Nagios: Path '{nsca_cmd_path}' not found or not executable"
            )

        return cls(server, port, hostname, service)
    
    def send_passive_check_result(self, msg: str, code: ExitCode) -> str:
        cmd = f"echo -e \"{self.hostname}\t{self.service}\t{code.value}\t{msg}\" | {Nagios.NSCA_CMD} -H {self.server} -p {self.port} --quiet"
        result = run_cmd(cmd, shell=True)
        
        if result.returncode != 0:
            data = {
                "msg": "Failed to send passive check result to Nagios",
                "error": result.stderr,
                "return_code": result.returncode,
                "cmd": repr(cmd)
            }
            result = CmdResult.from_dict(data, ExitCode.CRITICAL)
            return result.render_and_exit()
            
        return result.stdout


# ── callback + root commands ─────────────────────────────────────────────────


@app.callback()
def main(
    ctx: typer.Context,
    api_url: str = typer.Option(
        None, "-u", "--api-url",
        envvar=ENV_VAR_API_URL,
        help=f"API base URL. You can set environment or set API_URL=<value> in {SETTINGS_FILE}"
    ),
    token: str = typer.Option(
        None, "-T", "--token",
        envvar=ENV_VAR_TOKEN,
        help=f"Bearer token. You can set environment or set TOKEN=<value> in {SETTINGS_FILE}"
    ),
    log_file: str = typer.Option(
        None, "--log-file",
        envvar=ENV_VAR_LOG_FILE,
        help=f"Log file. You can set environment or set LOG_FILE=<value> in {SETTINGS_FILE}"
    ),
    log_level: str = typer.Option(
        None, "--log-level",
        envvar=ENV_VAR_LOG_LEVEL,
        help=f"Log level. You can set environment or set LOG_LEVEL=<value> in {SETTINGS_FILE}"
    ),
    nsca_server: str = typer.Option(
        None, "--nsca-server",
        envvar=ENV_VAR_NSCA_SERVER,
        help=f"NSCA server address used by 'cert update-in-place' to send passive check results to Nagios via send_nsca. Requires send_nsca to be installed and configured on this host. Must be used together with --nagios-hostname and --nagios-service (on the command). You can set environment or set NSCA_SERVER=<value> in {SETTINGS_FILE}"
    ),
    nsca_port: int = typer.Option(
        None, "--nsca-port",
        envvar=ENV_VAR_NSCA_PORT,
        help=f"NSCA server port used by 'cert update-in-place' when sending passive check results to Nagios. Defaults to 5667 if not specified. Only effective when --nsca-server is set. You can set environment or set NSCA_PORT=<value> in {SETTINGS_FILE}"
    ),
    nagios_hostname: str = typer.Option(
        None, "--nagios-hostname",
        envvar=ENV_VAR_NAGIOS_HOSTNAME,
        help=f"Nagios host_name as defined in Nagios host object configuration, used by 'cert update-in-place' to identify the monitored host when sending passive check results via NSCA. Must be used together with --nsca-server and --nagios-service (on the command). You can set environment or set NAGIOS_HOSTNAME=<value> in {SETTINGS_FILE}"
    )
) -> None:
    ctx.obj = Settings(api_url=api_url, token=token, log_file=log_file, log_level=log_level, format=None, nsca_server=nsca_server, nsca_port=nsca_port, nagios_hostname=nagios_hostname)
    

@app.command(help="Versions and author")
def version(
    ctx: typer.Context,
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("GET", "/api/version")
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@app.command(help="Reload server configuration (requires '*:reload' permission)")
def reload(
    ctx: typer.Context,
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("POST", "/api/admin/reload")
    
    if response.ok:
        print(response.json().get("message"))
        return ExitCode.OK
    else:
        result = CmdResult.from_response(response)
        return result.render_and_exit(ctx.info_name, columns)

# ── token commands ───────────────────────────────────────────────────────────

@token_app.command(name = "scope", help="Permissions for the current identity")
def token_scope(
    ctx: typer.Context,
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("GET", "/api/token/scope")
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)
    
    
@token_app.command(name = "identity", help="Current identity (allowed CIDRs, permissions)")
def token_identity(
    ctx: typer.Context,
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("GET", "/api/token/identity")
    result = CmdResult.from_response(response)
    
    if isinstance(result.data, dict) and result.data.get("permissions"):
        result.data["permissions"] = [f"{p['scope']}:{p['action']}" for p in result.data["permissions"]]
    return result.render_and_exit(ctx.info_name, columns)


@token_app.command(name="gen-hmac", help="Generate TOKEN_<ID>_HMAC for server configuration") 
def token_gen_hmac(
    hmac_key_b64: str = typer.Option(
        None, "--hmac-key-b64",
        help="Base64-encoded HMAC key, min length is at least 32 bytes (must match server HMAC_KEY_B64). If not provided, you will be prompted (Recommended)",
    ),
    token_id: str = typer.Option(
        None, "--id", "-i",
        help="Identity ID used as <id> in 'Authorization: Bearer <id>.<token>'. If not provided, you will be prompted",
    ),
    token_value: str = typer.Option(
        None, "--token", "-t",
        help="Raw token value used as <token> in 'Authorization: Bearer <id>.<token>'. If not provided, you will be prompted (Recommended)",
    )
) -> None:
    if token_id is None:
        token_id = input("Token ID: ").strip()
    if hmac_key_b64 is None:
        hmac_key_b64 = getpass("HMAC key (base64): ").strip()
    if token_value is None:
        t1, t2 = getpass("Token value: ").strip(), getpass("Confirm token value: ").strip()
        
        if t1 != t2:
            raise typer.BadParameter("Token values do not match")
        if not t1:
            raise typer.BadParameter("Token value cannot be empty")
        token_value = t1
        
    try:
        hmac_key = base64.b64decode(hmac_key_b64, validate=True)
    except binascii.Error:
        raise typer.BadParameter(
            "Invalid HMAC key: not valid base64.\n"
            "Generate a new one with:\n"
            "  openssl rand -base64 32\n\n"
            "NOTE !!!\nHMAC key must match server HMAC_KEY_B64"
        )
    
    if len(hmac_key) < 32:
        raise typer.BadParameter(
            "Invalid HMAC key: decoded key must be at least 32 bytes.\n"
            "Generate a secure key with:\n"
            "  openssl rand -base64 32\n\n"
            "NOTE !!!\nHMAC key must match server HMAC_KEY_B64"
        )

    token = str(token_value).encode()
    digest = hmac.new(hmac_key, token, hashlib.sha256).hexdigest()
    
    typer.secho("\nSuccess!\n", fg=typer.colors.GREEN)
    print("Add the following environment variable to the server:")
    print(f"TOKEN_{token_id.upper()}_HMAC={digest}\n")


# ── cert commands ────────────────────────────────────────────────────────────


@cert_app.command(name = "status", help="Show statuses (expiring, not issued etc.) for the current identity or selected pattern")
def cert_status(
    ctx: typer.Context,
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    patterns: list[str] = Opt.patterns(),
    columns: list[str] = Opt.columns(),
    exclude_ok: bool = typer.Option(
        None, "--exclude-ok",
        help="Hide certificates with OK status"
    ),
    type: str = Opt.type("all"),
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    cert_type = CertType.from_string(type)
    params = {
        **({"exclude_ok": "true"} if exclude_ok else {}),
        **({"match": patterns} if patterns else {}),
        "type": cert_type.value,
    }
    response = client.request("GET", "/api/certs/status", params=params)
    
    result = CmdResult.from_response(response)
    if result.data.get("certs"):
        result.data = result.data["certs"] 
    
    return result.render_and_exit(ctx.info_name, columns)
    

@cert_app.command(name = "issue", help="Issue new certificates for the current identity or selected pattern")
def cert_issue(
    ctx: typer.Context,
    timeout: int = Opt.timeout(360),
    format: str = Opt.format(),
    patterns: list[str] = Opt.patterns(),
    columns: list[str] = Opt.columns(),
    force: bool = Opt.force("Force reissue of certificate even if it already exists"),
    type: str = Opt.type("letsencrypt"),
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    cert_type = CertType.from_string(type)
    cert_ids = resolve_cert_ids(client, permission="issue", patterns=patterns, cert_type=cert_type.value)
    
    rows, exit_code = fanout_certs(client, cert_ids, "issue", force=force)
    return CmdResult.from_dict(rows, exit_code).render_and_exit(ctx.info_name, columns)


@cert_app.command(name = "renew", help="Renew existing certificates for the current identity or selected pattern")
def cert_renew(
    ctx: typer.Context,
    timeout: int = Opt.timeout(1000),
    format: str = Opt.format(),
    patterns: list[str] = Opt.patterns(),
    columns: list[str] = Opt.columns(),
    force: bool = Opt.force("Force certificate renew even if it does not need to be renewed"),
    type: str = Opt.type("letsencrypt"),
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    cert_type = CertType.from_string(type)
    cert_ids = resolve_cert_ids(client, permission="renew", patterns=patterns, cert_type=cert_type.value)
    
    rows, exit_code = fanout_certs(client, cert_ids, "renew", force=force)
    return CmdResult.from_dict(rows, exit_code).render_and_exit(ctx.info_name, columns)
    

@cert_app.command(name="revoke", help="Revoke certificates for the current identity or selected pattern (irreversible)")
def cert_revoke(
    ctx: typer.Context,
    timeout: int = Opt.timeout(360),
    format: str = Opt.format(),
    patterns: list[str] = Opt.patterns(),
    columns: list[str] = Opt.columns(),
    assume_yes: bool = typer.Option(
        False, "--yes-i-really-mean-it",
        help="Skip the interactive confirmation prompt (for automation)"
    )
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    cert_ids = resolve_cert_ids(client, permission="revoke", patterns=patterns)

    typer.echo("The following certificates will be REVOKED (irreversible):")
    for cert_id in cert_ids:
        typer.echo(f"  - {cert_id}")

    if not assume_yes:
        if not sys.stdin.isatty():
            raise typer.BadParameter(
                'Refusing to revoke without confirmation in a non-interactive shell; pass --yes-i-really-mean-it'
            )
        confirmation = typer.prompt('Type "Yes i really mean it" to proceed')
        if confirmation != "Yes i really mean it":
            typer.echo("Aborted, no certificates were revoked.")
            raise typer.Exit(code=1)

    rows, exit_code = fanout_certs(client, cert_ids, "revoke")
    return CmdResult.from_dict(rows, exit_code).render_and_exit(ctx.info_name, columns)


@cert_app.command(name = "pem", help="Print raw PEM material (bundle, cert, chain or privkey) for a single certificate")
def cert_pem(
    ctx: typer.Context,
    cert_id: str = typer.Argument(..., help="Certificate id to fetch PEM material for"),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    type: str = typer.Option(
        PemType.default().value, "--type", "-T",
        help=f"PEM material to fetch. Choices: {', '.join(PemType.values())}"
    ),
) -> None:
    pem_type = PemType.from_string(type)
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("GET", f"/api/certs/{cert_id}/pem", params={"type": pem_type.value})

    if response.ok:
        typer.echo(response.text, nl=False)
        raise typer.Exit(ExitCode.OK.value)

    # Error responses are JSON envelopes (e.g. 409 not issued, 403, 404) — render them.
    CmdResult.from_response(response).render_and_exit(ctx.info_name)


@cert_app.command(name = "list", help="List certificates available for the current identity or selected pattern")
def cert_list(
    ctx: typer.Context,
    timeout: int = Opt.timeout(360),
    format: str = Opt.format(),
    patterns: list[str] = Opt.patterns(),
    columns: list[str] = Opt.columns(),
    long: bool = typer.Option(
        None, "-l", "--long",
        help="Add to output sensitive data like certificate, chain and private key"
    ),
    type: str = Opt.type("all"),
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    cert_type = CertType.from_string(type)
    params = {
        **({"match": patterns} if patterns else {}),
        "type": cert_type.value,
    }
    response = client.request("GET", "/api/certs", params=params)
    sensitive_columns = ("certificate", "chain", "private_key")
    
    result = CmdResult.from_response(response)
    if not long and response.ok:
        for d in result.data:
            for col in sensitive_columns:
                d.pop(col, None)
    return result.render_and_exit(ctx.info_name, columns, sensitive_columns=sensitive_columns)
    
    
@cert_app.command(name = "update-in-place", help="Update local expiring or expired certificates in place by downloading new certificates from the server")
def cert_update_in_place(
    ctx: typer.Context,
    timeout: int = Opt.timeout(10),
    format: str = Opt.format(),
    patterns: list[str] = Opt.patterns(),
    columns: list[str] = Opt.columns(),
    dest_dir: str = typer.Option(
        ..., "--dest-dir", "-d",
        help="Directory containing certificate files to check and update"
    ),
    pem: list[str] = typer.Option(
        [PemType.default().value], "--pem", "-P",
        help=f"PEM file type(s) to produce; repeatable. Files are named <prefix>_<type>.pem. Choices: {', '.join(PemType.values())}"
    ),
    post_hook: str = typer.Option(
        None, "--post-hook",
        help="Executable to run after successful update of any locally expiring or expired certificate"
    ),
    omit_post_hook_on_revoke: bool = typer.Option(
        False, "--omit-post-hook-on-revoke",
        help="Do not let revoked-cert cleanup trigger --post-hook (cleanup still happens and is reported)"
    ),
    owner: str = typer.Option(
        None, "--owner", "-O",
        help="Owner of the certificate file (username or UID)"
    ),
    group: str = typer.Option(
        None, "--group", "-G",
        help="Group of the certificate file (group name or GID)"
    ),
    chmod: str = typer.Option(
        "640", "--chmod",
        help="Permissions for the certificate file in octal notation"
    ),
    nagios_service: str = typer.Option(
        None, '--nagios-service',
        help="Nagios service description to report (the 'service_description' used in Nagios objects definition)",
    ),
    type: str = Opt.type("all"),
) -> None:
    @dataclass
    class CertUpdateResult:
        cert: str
        code: ExitCode
        pem_files: list[Path]
        remote_expire_date: datetime | None
        local_expire_date: datetime | None
        updated: bool
        msg: str

        def to_serializable(self) -> dict:
            return {
                "id": self.cert,
                "status": self.code.name,
                "pem_files": [str(p) for p in self.pem_files],
                "local_expire_date": datetime.strftime(self.local_expire_date, DATE_FMT) if self.local_expire_date else None,
                "remote_expire_date": datetime.strftime(self.remote_expire_date, DATE_FMT) if self.remote_expire_date else None,
                "updated": self.updated,
                "msg": self.msg
            }
            
    try:
        chmod_mode = int(chmod, 8)
    except ValueError:
        raise typer.BadParameter(f"Invalid --chmod value '{chmod}', must be an octal number (e.g. 600, 640, 644)")
    
    pem_types = parse_pem_types(pem)
    settings = load_settings(ctx, format)
    nagios = Nagios.from_options(
        settings.nsca_server,
        settings.nsca_port,
        settings.nagios_hostname,
        nagios_service
    )
    certs_dir = Path(dest_dir)
    
    if not certs_dir.exists():
        raise typer.BadParameter(f"Directory provided by -d/--dest-dir does not exist: {certs_dir}")
    if not certs_dir.is_dir():
        raise typer.BadParameter(f"Value provided by -d/--dest-dir is not a directory: {certs_dir}")
    
    cert_type = CertType.from_string(type)
    params = {
        **({"match": patterns} if patterns else {}),
        "type": cert_type.value,
    }

    client = Client.init(ctx, format, timeout=timeout, nagios=nagios)
    response = client.request("GET", "/api/certs", params=params)
    result = CmdResult.from_response(response)
    
    if not response.ok:
        if nagios:
            nagios.send_passive_check_result(f"{ExitCode.CRITICAL.name}: Failed to fetch certificates, response: {result.data}", ExitCode.CRITICAL)
        result.render_and_exit(ctx.info_name)
    
    results: list[CertUpdateResult] = []

    for cert in result.data:
        cert_id = cert.get("id")
        prefix = resolve_pem_prefix(cert)

        if not re.compile(PEM_FILENAME_PATTERN).fullmatch(prefix):
            results.append(CertUpdateResult(
                cert=cert_id,
                code=ExitCode.CRITICAL,
                pem_files=[],
                remote_expire_date=None,
                local_expire_date=None,
                updated=False,
                msg=f"Invalid file name prefix '{prefix}' (from custom_attr 'pem_prefix' or cert id), needs to match pattern: {PEM_FILENAME_PATTERN}"
            ))
            continue

        pem_files = [certs_dir / f"{prefix}_{pem_type.value}.pem" for pem_type in pem_types]
        fields = required_server_fields(pem_types)

        certificate = cert.get("certificate")
        chain = cert.get("chain")
        private_key = cert.get("private_key")

        if cert.get("status") == "REVOKED":
            removed = []
            for pem_file in pem_files:
                if pem_file.exists():
                    pem_file.unlink()
                    removed.append(pem_file.name)
            results.append(CertUpdateResult(
                cert=cert_id,
                code=ExitCode.OK,
                pem_files=pem_files,
                remote_expire_date=None,
                local_expire_date=None,
                updated=bool(removed) and not omit_post_hook_on_revoke,
                msg=(f"Revoked on server; removed local files: {', '.join(removed)}" if removed else "Revoked on server; no local files to remove")
            ))
            continue

        if "certificate" in fields and not certificate:
            results.append(CertUpdateResult(
                cert=cert_id, code=ExitCode.WARNING, pem_files=pem_files,
                remote_expire_date=None, local_expire_date=None, updated=False,
                msg="Not issued on server side"
            ))
            continue

        if "private_key" in fields and not private_key:
            results.append(CertUpdateResult(
                cert=cert_id, code=ExitCode.CRITICAL, pem_files=pem_files,
                remote_expire_date=None, local_expire_date=None, updated=False,
                msg="Private key is missing on server side"
            ))
            continue

        if "chain" in fields and not chain:
            results.append(CertUpdateResult(
                cert=cert_id, code=ExitCode.CRITICAL, pem_files=pem_files,
                remote_expire_date=None, local_expire_date=None, updated=False,
                msg="Chain is missing on server side"
            ))
            continue

        expire_date = None
        if "expire_date" in fields:
            expire_date_str = cert.get("expire_date")
            if not expire_date_str:
                results.append(CertUpdateResult(
                    cert=cert_id, code=ExitCode.CRITICAL, pem_files=pem_files,
                    remote_expire_date=None, local_expire_date=None, updated=False,
                    msg="Expire date is missing on server side"
                ))
                continue
            try:
                expire_date = datetime.strptime(expire_date_str, DATE_FMT).replace(tzinfo=timezone.utc)
            except ValueError as e:
                results.append(CertUpdateResult(
                    cert=cert_id, code=ExitCode.CRITICAL, pem_files=pem_files,
                    remote_expire_date=None, local_expire_date=None, updated=False,
                    msg=f"Failed to parse expire date from server side: {safe_str(e)}"
                ))
                continue

        ref_type = expiry_reference_type(pem_types)
        existed_before = any(f.exists() for f in pem_files)
        need_update = any(not f.exists() for f in pem_files)
        local_expire_date = None

        if ref_type is not None:
            ref_file = certs_dir / f"{prefix}_{ref_type.value}.pem"
            if ref_file.exists():
                try:
                    local_expire_date = get_cert_expire_date(ref_file)
                except Exception as e:
                    results.append(CertUpdateResult(
                        cert=cert_id, code=ExitCode.CRITICAL, pem_files=pem_files,
                        remote_expire_date=expire_date, local_expire_date=None, updated=False,
                        msg=safe_str(str(e))
                    ))
                    continue
                if expire_date > local_expire_date:
                    need_update = True

        if not need_update:
            results.append(CertUpdateResult(
                cert=cert_id, code=ExitCode.OK, pem_files=pem_files,
                remote_expire_date=expire_date, local_expire_date=local_expire_date, updated=False,
                msg="Up to date"
            ))
            continue

        # Add or update local certificate files
        for pem_type, pem_file in zip(pem_types, pem_files):
            content = pem_content_for(pem_type, certificate, chain, private_key)
            _write_secure(pem_file, content, mode=chmod_mode, owner=owner, group=group)

        # Report the freshly written cert's expiry: keep the pre-write local date when
        # we had one (an existing cert being replaced), otherwise read it back from the
        # just-written reference file. With no cert-bearing reference (e.g. only privkey) it stays None.
        if local_expire_date is None and ref_type is not None:
            try:
                local_expire_date = get_cert_expire_date(certs_dir / f"{prefix}_{ref_type.value}.pem")
            except Exception:
                local_expire_date = None

        results.append(CertUpdateResult(
            cert=cert_id, code=ExitCode.OK, pem_files=pem_files,
            remote_expire_date=expire_date, local_expire_date=local_expire_date, updated=True,
            msg="Updated" if existed_before else "Added"
        ))

    is_any_updated = any(r.updated for r in results)        
    
    if is_any_updated and post_hook:
        result = run_cmd(post_hook, shell=True)
        if result.returncode != 0:
            data = {
                "msg": "Failed to run post-hook after successful local certificates update",
                "updated_certs": ", ".join([r.cert for r in results if r.updated]),
                "error": safe_str(result.stderr),
                "return_code": result.returncode,
                "cmd": post_hook
            }
            result = CmdResult.from_dict(data, ExitCode.CRITICAL)
            if nagios:
                nagios.send_passive_check_result(f"{ExitCode.CRITICAL.name}: {data['msg']}, updated certs: {data['updated_certs']}, error: {data['error']}", ExitCode.CRITICAL)
            return result.render_and_exit(ctx.info_name)
    
    result = CmdResult.from_dict([r.to_serializable() for r in results], ExitCode.OK)
    
    if nagios:
        highest_exit_code = max((r.code for r in results), key=lambda code: code.value, default=ExitCode.OK)
        
        if highest_exit_code == ExitCode.OK:
            nagios_msg = f"{ExitCode.OK.name}: All certificates are up to date"
        else:
            err_msg_parts = []
            for r in results:
                if r.code != ExitCode.OK:
                    err_msg_parts.append(f"{r.code.name}: Certificate {r.cert}: {r.msg}{f" ({r.local_expire_date})" if r.local_expire_date else ""}")
            nagios_msg = (NAGIOS_ESCAPE_CHAR).join(err_msg_parts)
        
        nagios.send_passive_check_result(nagios_msg, highest_exit_code)

    return result.render_and_exit(ctx.info_name, columns)
    

# ── helpers ───────────────────────────────────────────────────────────────────


def resolve_cert_ids(client: "Client", *, permission: str, patterns: list[str], cert_type: str | None = None) -> list[str]:
    params: dict[str, Any] = {"permission": permission}
    
    if patterns:
        params["match"] = patterns
    if cert_type and cert_type != "all":
        params["type"] = cert_type
        
    response = client.request("GET", "/api/certs/catalog", params=params)
    if not response.ok:
        CmdResult.from_response(response).render_and_exit()
        
    payload = response.json().get("data", [])
    cert_ids = [entry["id"] for entry in payload]
    
    if not cert_ids:
        data: dict[str, Any] = {
            "msg": f"No certificate found allowed for '{permission}' action for the current identity",
            "permission": permission,
        }
        if patterns:
            data["pattern"] = ", ".join(patterns)
        if cert_type and cert_type != "all":
            data["cert_type"] = cert_type
        return CmdResult.from_dict(data, ExitCode.CRITICAL).render_and_exit()
    return cert_ids


def fanout_certs(client: "Client", cert_ids: list[str], action: str, *, force: bool = False) -> tuple[list[dict], ExitCode]:
    rows: list[dict] = []
    exit_code = ExitCode.OK
    
    for cert_id in cert_ids:
        params = {"force": "true"} if force else {}
        response = client.request("POST", f"/api/certs/{cert_id}/{action}", params=params)
        rows.append(_action_row(cert_id, response))
        # 409 is an expected per-cert condition (already issued, not yet renewable,
        # not supported, revoke of a not-issued cert) -> not a failure. Any other
        # non-2xx (400/403/404/5xx) is a real error and fails the whole command.
        if not response.ok and response.status_code != 409:
            exit_code = ExitCode.CRITICAL
    return rows, exit_code


def _action_row(cert_id: str, response: requests.Response) -> dict:
    # Per-cert action endpoints always carry the result row under "data",
    # whether the action succeeded (200) or failed with a CertException (409).
    try:
        body = response.json()
    except ValueError:
        return {"id": cert_id, "msg": response.text}

    if isinstance(body, dict) and isinstance(body.get("data"), dict):
        return body["data"]

    # Envelope without a per-cert data block (e.g. 401/403/500): surface what we can.
    message = body.get("message") if isinstance(body, dict) else str(body)
    return {"id": cert_id, "msg": message}


def get_ctx_settings() -> Settings:
    ctx = click.get_current_context()
    s = ctx.obj
    if not isinstance(s, Settings):
        raise typer.Exit(code=2)
    return s


def setup_logging(log_file: str | None, log_level: str | None) -> None:
    if not log_file:
        LOGGER.disabled = True
        return

    logger = logging.getLogger()
    if any(getattr(h, "_certhub_handler", False) for h in logger.handlers):
        return

    level_name = (log_level or "INFO").upper()
    level = getattr(logging, level_name, None)
    if not isinstance(level, int):
        raise typer.BadParameter(
            f"Unknown log level: {log_level}, must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL"
        )

    handler = RotatingFileHandler(
        filename=log_file,
        maxBytes=2 * 1024 * 1024,
        backupCount=5,
        encoding="UTF-8"
    )
    handler._certhub_handler = True
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s [pid=%(process)d] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    logger.addHandler(handler)
    logger.setLevel(level)


def load_settings(ctx: typer.Context, format: str | None = None) -> Settings:
    settings = ctx.obj
    if not isinstance(settings, Settings):
        raise typer.Exit(code=2)
    
    file_settings: dict[str, str] = {}
    if SETTINGS_FILE.exists():
        file_mode = SETTINGS_FILE.stat().st_mode & 0o777
        if file_mode != 0o600:
            raise typer.BadParameter(
                f"Invalid permissions for {SETTINGS_FILE}: expected 'rw-------' (600), got {file_mode:o}, use command:\nchmod 600 {SETTINGS_FILE}"
            )

        for line in read_file(SETTINGS_FILE).splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            file_settings[key.strip().upper()] = value.strip()

    if not settings.api_url:
        settings.api_url = file_settings.get("API_URL")
    if not settings.token:
        settings.token = file_settings.get("TOKEN")
    if not settings.log_file:
        settings.log_file = file_settings.get("LOG_FILE")
    if not settings.log_level:
        settings.log_level = file_settings.get("LOG_LEVEL")
    if not settings.nsca_server:
        settings.nsca_server = file_settings.get("NSCA_SERVER")
    if settings.nsca_port is None:
        port = file_settings.get("NSCA_PORT")
        settings.nsca_port = int(port) if port else None
    if not settings.nagios_hostname:
        settings.nagios_hostname = file_settings.get("NAGIOS_HOSTNAME")

    setup_logging(settings.log_file, settings.log_level)
    settings.format = Format.from_string(format)
    
    if not settings.api_url:
        raise typer.BadParameter(
            f"Provide --api-url, set {ENV_VAR_API_URL} environment variable, or add API_URL=<value> in {SETTINGS_FILE}"
        )
    return settings


def read_file(file_path: Path) -> str:
    try:
        return file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return file_path.read_text(encoding="ascii", errors="ignore")


def get_cert_expire_date(cert_file: Path) -> datetime:
    pem_content = read_file(cert_file)
    begin_marker = "-----BEGIN CERTIFICATE-----"
    end_marker = "-----END CERTIFICATE-----"
    cert_start = pem_content.find(begin_marker)
    cert_end = pem_content.find(end_marker, cert_start)
    if cert_start == -1 or cert_end == -1:
        raise ValueError(f"File '{cert_file}' does not contain a valid PEM certificate block")
    
    cert_end += len(end_marker)
    cert_pem = pem_content[cert_start:cert_end].encode("utf-8")
    
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except ValueError as e:
        raise ValueError(f"Cannot parse certificate from file '{cert_file}': {e}")
    
    expire_date_utc = getattr(cert, "not_valid_after_utc", None)
    if expire_date_utc is not None:
        return expire_date_utc.astimezone(timezone.utc)
    
    expire_date = cert.not_valid_after
    if expire_date.tzinfo is None:
        expire_date = expire_date.replace(tzinfo=timezone.utc)
    return expire_date.astimezone(timezone.utc)


def parse_pem_types(values: list[str]) -> list["PemType"]:
    result: list[PemType] = []
    for value in values:
        pem_type = PemType.from_string(value)
        if pem_type not in result:
            result.append(pem_type)
    return result


def pem_filename(prefix: str, pem_type: "PemType", ext_map: dict["PemType", str]) -> str:
    return f"{prefix}_{pem_type.value}.{ext_map[pem_type]}"


def resolve_pem_prefix(cert: dict) -> str:
    custom_attrs = cert.get("custom_attrs")
    if isinstance(custom_attrs, dict) and custom_attrs.get("pem_prefix"):
        return str(custom_attrs["pem_prefix"])
    return str(cert.get("id"))


def pem_content_for(
    pem_type: "PemType",
    certificate: str | None,
    chain: str | None,
    private_key: str | None,
) -> str:
    if pem_type == PemType.CERT:
        parts = [certificate]
    elif pem_type == PemType.CHAIN:
        parts = [chain]
    elif pem_type == PemType.PRIV_KEY:
        parts = [private_key]
    else:  # PemType.BUNDLE
        parts = [certificate, chain, private_key]
    parts = [part.strip() for part in parts if part]
    return "\n".join(parts) + "\n"


def required_server_fields(pem_types: list["PemType"]) -> set[str]:
    fields: set[str] = set()
    for pem_type in pem_types:
        if pem_type in (PemType.CERT, PemType.BUNDLE):
            fields.add("certificate")
        if pem_type in (PemType.PRIV_KEY, PemType.BUNDLE):
            fields.add("private_key")
        if pem_type == PemType.CHAIN:
            fields.add("chain")
    if any(pem_type in (PemType.BUNDLE, PemType.CERT) for pem_type in pem_types):
        fields.add("expire_date")
    return fields


def expiry_reference_type(pem_types: list["PemType"]) -> "PemType | None":
    if PemType.BUNDLE in pem_types:
        return PemType.BUNDLE
    if PemType.CERT in pem_types:
        return PemType.CERT
    return None


def _chown(path: Path, owner: str | None, group: str | None) -> None:
    if owner is None and group is None:
        return
    try:
        shutil.chown(path, user=owner, group=group)
    except LookupError:
        uid = pwd.getpwnam(owner).pw_uid if owner is not None else -1
        gid = int(group) if group is not None and str(group).isdigit() else (grp.getgrnam(group).gr_gid if group is not None else -1)
        os.lchown(path, uid, gid)


def _write_secure(path: Path, content: str, *, mode: int, owner: str | None, group: str | None) -> None:
    # Write atomically through a same-dir temp file created at 0600, then rename into
    # place. This guarantees a private key is never briefly world-readable (the old
    # write_text+chmod left a window) and that consumers (e.g. an nginx reload from a
    # post-hook) never observe a half-written file. os.replace is atomic within a dir.
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="UTF-8") as f:
            f.write(content)
        os.chmod(tmp, mode)
        _chown(tmp, owner, group)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def safe_str(x: object) -> str:
    return str(x).encode("unicode_escape").decode()


def run_cmd(
    args: Sequence[str] | str,
    *,
    shell: bool = False,
    timeout: Optional[int] = 15
) -> subprocess.CompletedProcess[str]:
    cmd: str | list[str]
    if shell:
        if isinstance(args, str):
            cmd = args
        else:
            cmd = " ".join(shlex.quote(str(a)) for a in args)
    else:
        if isinstance(args, str):
            cmd = shlex.split(args)
        else:
            cmd = [str(a) for a in args]
    
    result = subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL, 
        stderr=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        text=True,
        shell=shell,
        executable="/bin/bash",
        timeout=timeout
    )
    LOGGER.debug(f"Command executed shell={shell} return_code={result.returncode} cmd={cmd} stderr={safe_str(result.stderr.strip()) if result.stderr else ""}",)
    return result


if __name__ == "__main__":
    app()
