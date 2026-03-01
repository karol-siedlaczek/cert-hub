#!/usr/bin/env python3

# Karol Siedlaczek 2026

import os
import re
import json
import shlex
import typer
import hmac
import hashlib
import base64
import sys
import click
import binascii
import subprocess
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from enum import Enum
from getpass import getpass
from pathlib import Path
from rich.console import Console
from rich.table import Table, box
from dataclasses import dataclass
from typing import Any, Optional, Dict, Sequence, NoReturn, ClassVar
import requests
from cryptography import x509

ENV_VAR_API_URL = "CERTHUB_API_URL"
ENV_VAR_TOKEN = "CERTHUB_TOKEN"
ENV_VAR_LOG_FILE = "CERTHUB_LOG_FILE"
ENV_VAR_LOG_LEVEL = "CERTHUB_LOG_LEVEL"
SETTINGS_FILE = Path("~/.certhub").expanduser()
DATE_FMT = "%Y-%m-%d %H:%M"
NAGIOS_ESCAPE_CHAR = "</br>"
PEM_FILENAME_PATTERN = r"^[\w.-]+$"
LOGGER = logging.getLogger("certhub-cli")

app = typer.Typer(
    add_completion=True, 
    help="CLI for managing certificates in Cert Hub"
)
cert_app = typer.Typer(help=f"Certificate commands, use '{sys.argv[0]} cert --help' for details")
token_app = typer.Typer(help=f"Token commands, add '{sys.argv[0]} token --help' for details")
app.add_typer(cert_app, name="cert")
app.add_typer(token_app, name="token")
console = Console()


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


@dataclass
class CertUpdateResult:
    cert: str
    code: ExitCode
    pem_file: Path | None
    remote_expire_date: datetime | None
    local_expire_date: datetime | None
    updated: bool
    msg: str
    
    def to_serializable(self) -> dict:
        return {
            "id": self.cert,
            "status": self.code.name,
            "pem_file": str(self.pem_file),
            "local_expire_date": datetime.strftime(self.local_expire_date, DATE_FMT) if self.local_expire_date else None,
            "remote_expire_date": datetime.strftime(self.remote_expire_date, DATE_FMT) if self.remote_expire_date else None,
            "updated": self.updated,
            "msg": self.msg
        }
        

@dataclass
class Settings:
    api_url: str | None
    token: str | None
    log_file: str | None
    log_level: str | None
    format: Format | None


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
            payload.pop("path", None)
            payload.pop("code", None)
            payload = payload['data']
            
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
            if rows:
                table = Table(show_header=True, header_style="bold", expand=True, show_lines=True, box=box.ROUNDED)

                cols = list(rows[0].keys())
                for c in cols:
                    table.add_column(str(c), overflow="fold") # fold helps if mucho text

                for row in rows:
                    table.add_row(*[_render_table_cell(row.get(c, "")) for c in cols])
                _print(table)
        
        data_to_log = data
        if not LOGGER.disabled and sensitive_columns:
            data_to_log = self._mask_sensitive(data, sensitive_columns)
            
        LOGGER.log(
            logging.INFO if self.exit_code == ExitCode.OK else logging.ERROR,
            f"{f"Result for {context_info} command: " if context_info else ""}{data_to_log}"
        )
        raise typer.Exit(code=self.exit_code.value)


@dataclass
class Nagios():
    NSCA_CMD: ClassVar[str] = "/usr/sbin/send_nsca"
    server: str
    hostname: str
    service: str
    
    @classmethod
    def from_options(cls, server: str, hostname: str, service: str) -> "Nagios | None":
        if not any((server, hostname, service)):
            return None
            
        if not all([server, hostname, service]):
            raise typer.BadParameter(
                "To send passive check result to Nagios options --nagios-server, --nagios-hostname and --nagios-service must be provided together"
            )
        
        nsca_cmd_path = Path(Nagios.NSCA_CMD)
        
        if not (nsca_cmd_path.exists() and os.access(nsca_cmd_path, os.X_OK)):
            raise typer.BadParameter(
                f"Failed to setup sending passive check result to Nagios: Path '{nsca_cmd_path}' not found or not executable"
            )

        return cls(server, hostname, service)
    
    def send_passive_check_result(self, msg: str, code: ExitCode) -> str:
        cmd = f"echo -e \"{self.hostname}\t{self.service}\t{code.value}\t{msg}\" | {Nagios.NSCA_CMD} -H {self.server}"
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
    

@dataclass(frozen=True)
class Client():
    base_url: str
    session: requests.Session
    timeout: int
    
    @classmethod
    def init(
        cls, 
        base_url: str, 
        token: Optional[str] = None, 
        *,
        timeout: int, 
        nagios: Nagios | None = None
    ) -> "Client":
        base_url = base_url.rstrip("/")
        session = requests.Session()
        
        if token:
            session.headers.update({"Authorization": f"Bearer {token}"})

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

# Commands

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
    )
) -> None:
    ctx.obj = Settings(api_url=api_url, token=token, log_file=log_file, log_level=log_level, format=None)
    
    
@app.command(help="Versions and author")
def version(
    ctx: typer.Context,
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    settings = load_settings(ctx, format)
    client = Client.init(settings.api_url, settings.token, timeout=timeout)
    response = client.request("GET", "/api/version")
    
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@token_app.command(help="Permitted certificates for current identity")
def scope(
    ctx: typer.Context,
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    settings = load_settings(ctx, format)
    client = Client.init(settings.api_url, settings.token, timeout=timeout)
    response = client.request("GET", "/api/token/scope")
    
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)
    
    
@token_app.command(help="Current identity information (e.g. allowed CIDRs, permissions)")
def identity(
    ctx: typer.Context,
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    settings = load_settings(ctx, format)
    client = Client.init(settings.api_url, settings.token, timeout=timeout)
    response = client.request("GET", "/api/token/identity")
    
    result = CmdResult.from_response(response)
    if result.data.get("permissions"):
        result.data["permissions"] = [f"{p['scope']}:{p['action']}" for p in result.data["permissions"]]
    
    return result.render_and_exit(ctx.info_name, columns)


@token_app.command(help="Generate TOKEN_<ID>_HMAC value for server configuration") 
def gen_hmac(
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
        token_value_1 = getpass("Token value: ").strip()
        token_value_2 = getpass("Confirm token value: ").strip()
        
        if token_value_1 != token_value_2:
            raise typer.BadParameter("Token values do not match")
        
        if not token_value_1:
            raise typer.BadParameter("Token value cannot be empty")
        
        token_value = token_value_1
        
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
    hmac_key = hmac.new(hmac_key, token, hashlib.sha256)
    
    typer.secho("\nSuccess!\n", fg=typer.colors.GREEN)
    print("Add the following environment variable to the server:")
    print(f"TOKEN_{token_id.upper()}_HMAC={hmac_key.hexdigest()}\n")


@cert_app.command(help="Show statuses (expiring, not issued etc.) for the current identity or selected pattern")
def health(
    ctx: typer.Context,
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    patterns: list[str] = Opt.patterns(),
    columns: list[str] = Opt.columns(),
    exclude_ok: bool = typer.Option(
        None, "--exclude-ok", 
        help="Hide certificates with OK status"
    )
) -> None:
    settings = load_settings(ctx, format)
    client = Client.init(settings.api_url, settings.token, timeout=timeout)
    params = {
        **({"exclude_ok": "true"} if exclude_ok else {}),
        **({"match": patterns} if patterns else {})
    }
    response = client.request("GET", "/api/certs/health", params=params)
    
    result = CmdResult.from_response(response)
    if result.data.get("certs"):
        result.data = result.data["certs"] 
    
    return result.render_and_exit(ctx.info_name, columns)
    

@cert_app.command(help="Issue new certificates for the current identity or selected pattern")
def issue(
    ctx: typer.Context,
    timeout: int = Opt.timeout(360),
    format: str = Opt.format(),
    patterns: list[str] = Opt.patterns(),
    columns: list[str] = Opt.columns(),
    force: bool = Opt.force("Force reissue of certificate even if it already exists")
) -> None:
    settings = load_settings(ctx, format)
    client = Client.init(settings.api_url, settings.token, timeout=timeout)
    params = {
        **({"force": "true"} if force else {}),
        **({"match": patterns} if patterns else {})
    }
    response = client.request("POST", "/api/certs/issue", params=params)
    
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@cert_app.command(help="Renew existing certificates for the current identity or selected pattern")
def renew(
    ctx: typer.Context,
    timeout: int = Opt.timeout(360),
    format: str = Opt.format(),
    patterns: list[str] = Opt.patterns(),
    columns: list[str] = Opt.columns(),
    force: bool = Opt.force("Force certificate renew even if it does not expire")
) -> None:
    settings = load_settings(ctx, format)
    client = Client.init(settings.api_url, settings.token, timeout=timeout)
    params = {
        **({"force": "true"} if force else {}),
        **({"match": patterns} if patterns else {})
    }
    response = client.request("POST", "/api/certs/renew", params=params)
    
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)
    

@cert_app.command(help="List certificates available for the current identity or selected pattern")
def get(
    ctx: typer.Context,
    timeout: int = Opt.timeout(360),
    format: str = Opt.format(),
    patterns: list[str] = Opt.patterns(),
    columns: list[str] = Opt.columns(),
    long: bool = typer.Option(
        None, "-l", "--long",
        help="Add to output sensitive data like certificate, chain and private key"
    )
) -> None:
    settings = load_settings(ctx, format)
    client = Client.init(settings.api_url, settings.token, timeout=timeout)
    params = {
        **({"match": patterns} if patterns else {})
    }
    response = client.request("GET", "/api/certs", params=params)
    sensitive_columns = ("certificate", "chain", "private_key")
    
    result = CmdResult.from_response(response)
    if not long:
        for d in result.data:
            for col in sensitive_columns:
                d.pop(col, None)
    return result.render_and_exit(ctx.info_name, columns, sensitive_columns=sensitive_columns)
    

@cert_app.command(help="Update local expired certificates in place by downloading new certificates from the server")
def update_in_place(
    ctx: typer.Context,
    timeout: int = Opt.timeout(10),
    format: str = Opt.format(),
    patterns: list[str] = Opt.patterns(),
    columns: list[str] = Opt.columns(),
    dest_dir: str = typer.Option(
        ..., "--dest-dir", "-d",
        help="Directory containing certificate files to check and update"
    ),
    post_hook: str = typer.Option(
        None, "--post-hook",
        help="Executable to run after successful update of any locally expired certificate"
    ),
    nagios_server: str = typer.Option(
        None, "--nagios-server",
        help="Nagios/nsca server address (host or host:port). If set the command will send a passive check result via NSCA using 'send_nsca' (requires 'send_nsca' installed and configured)"  
    ),
    nagios_hostname: str = typer.Option(
        None, "--nagios-hostname",
        help="Nagios hostname to report (the 'host_name' used in Nagios objects definition)"
    ),
    nagios_service: str = typer.Option(
        None, '--nagios-service',
        help="Nagios service description to report (the 'service_description' used in Nagios objects definition)",
    )
) -> None: 
    settings = load_settings(ctx, format)
    nagios = Nagios.from_options(nagios_server, nagios_hostname, nagios_service)
    certs_dir = Path(dest_dir)
    
    if not certs_dir.exists():
        raise typer.BadParameter(f"Directory provided by -d/--dest-dir does not exist: {certs_dir}")
    if not certs_dir.is_dir():
        raise typer.BadParameter(f"Value provided by -d/--dest-dir is not a directory: {certs_dir}")
    
    params = {
        **({"match": patterns} if patterns else {})
    }
    
    client = Client.init(settings.api_url, settings.token, timeout=timeout, nagios=nagios)
    response = client.request("GET", "/api/certs", params=params)
    result = CmdResult.from_response(response)
    
    if not response.ok:
        if nagios:
            nagios.send_passive_check_result(f"{ExitCode.CRITICAL.name}: Failed to fetch certificates, response: {result.data}", ExitCode.CRITICAL)
        result.render_and_exit(ctx.info_name)
    
    results: list[CertUpdateResult] = []

    for cert in result.data:
        cert_id = cert.get("id")
        
        try:
            pem_filename = str(dict(cert.get("custom_attrs"))["pem_filename"])
        except (TypeError, KeyError):
            results.append(CertUpdateResult(
                cert=cert_id,
                code=ExitCode.UNKNOWN,
                pem_file=None,
                remote_expire_date=None,
                local_expire_date=None,
                updated=False,
                msg="Missing custom attribute 'pem_filename' on server side"
            ))
            continue
        
        if not bool(re.compile(PEM_FILENAME_PATTERN).fullmatch(pem_filename)):
            results.append(CertUpdateResult(
                cert=cert_id,
                code=ExitCode.CRITICAL,
                pem_file=None,
                remote_expire_date=None,
                local_expire_date=None,
                updated=False,
                msg=f"Invalid custom attribute 'pem_filename' value on server side, needs to match pattern: {PEM_FILENAME_PATTERN}"
            ))
            continue
            
        if not pem_filename.endswith(".pem"):
            pem_filename += ".pem"
        
        pem_file = certs_dir / pem_filename
        
        certificate = cert.get("certificate")
        if not certificate:
            results.append(CertUpdateResult(
                cert=cert_id,
                code=ExitCode.WARNING,
                pem_file=pem_file,
                remote_expire_date=None,
                local_expire_date=None,
                updated=False,
                msg="Not issued on server side"
            ))
            continue
        
        expire_date_str = cert.get("expire_date")
        if not expire_date_str:
            results.append(CertUpdateResult(
                cert=cert_id,
                code=ExitCode.CRITICAL,
                pem_file=pem_file,
                remote_expire_date=None,
                local_expire_date=None,
                updated=False,
                msg="Expire date is missing on server side"
            ))
            continue
        
        try:
            expire_date = datetime.strptime(expire_date_str, DATE_FMT).replace(tzinfo=timezone.utc)
        except ValueError as e:
            results.append(CertUpdateResult(
                cert=cert_id,
                code=ExitCode.CRITICAL,
                pem_file=pem_file,
                remote_expire_date=None,
                local_expire_date=None,
                updated=False,
                msg=f"Failed to parse expire date from server side: {safe_str(e)}"
            ))
            continue
            
        chain = cert.get("chain")
        if not chain:
            results.append(CertUpdateResult(
                cert=cert_id,
                code=ExitCode.CRITICAL,
                pem_file=pem_file,
                remote_expire_date=expire_date,
                local_expire_date=None,
                updated=False,
                msg="Chain is missing on server side"
            ))
            continue
        
        private_key = cert.get("private_key")
        if not private_key:
            results.append(CertUpdateResult(
                cert=cert_id,
                code=ExitCode.CRITICAL,
                pem_file=pem_file,
                remote_expire_date=expire_date,
                local_expire_date=None,
                updated=False,
                msg="Private key is missing on server side"
            ))
            continue
        
        pem_parts = [part.strip() for part in [certificate, chain, private_key] if part]
        pem_bundle = "\n".join(pem_parts) + "\n"
        is_pem_file_exists = pem_file.exists()
        local_expire_date = None
        
        if is_pem_file_exists:
            try:
                local_expire_date = get_cert_expire_date(pem_file)
            except Exception as e:
                results.append(CertUpdateResult(
                    cert=cert_id,
                    code=ExitCode.CRITICAL,
                    pem_file=pem_file,
                    remote_expire_date=expire_date,
                    local_expire_date=None,
                    updated=False,
                    msg=safe_str(str(e))
                ))
                continue
            
            if expire_date <= local_expire_date:
                results.append(CertUpdateResult(
                    cert=cert_id,
                    code=ExitCode.OK,
                    pem_file=pem_file,
                    remote_expire_date=expire_date,
                    local_expire_date=local_expire_date,
                    updated=False,
                    msg="Up to date"
                ))
                continue
            
        # Add or update local certificate
            
        pem_file.write_text(pem_bundle, encoding="UTF-8") 
        
        results.append(CertUpdateResult(
            cert=cert_id,
            code=ExitCode.OK,
            pem_file=pem_file,
            remote_expire_date=expire_date,
            local_expire_date=local_expire_date if local_expire_date is not None else get_cert_expire_date(pem_file),
            updated=True,
            msg="Updated" if is_pem_file_exists else "Added"
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
        msg_parts = []
        for r in results:
            msg_parts.append(f"{r.code.name}: Certificate {r.cert}: {r.msg}{f" ({r.local_expire_date})" if r.local_expire_date else ""}")
            
        nagios.send_passive_check_result((NAGIOS_ESCAPE_CHAR).join(msg_parts), highest_exit_code)

    return result.render_and_exit(ctx.info_name, columns)
    
# Helper functions

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
            if not line or line.startswith("#"):
                continue

            if "=" not in line:
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

    setup_logging(settings.log_file, settings.log_level)
    settings.format = Format.from_string(format)
    
    if not settings.api_url:
        raise typer.BadParameter(
            f"Provide --api-url, set {ENV_VAR_API_URL} environment variable, or add API_URL=<value> in {SETTINGS_FILE}"
        )
    return settings


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
    print(level_name)

    logger.addHandler(handler)
    logger.setLevel(level)


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
