import re
import os
import ipaddress
from pathlib import Path
from typing import Any, Match, Type, TypeVar, Pattern

T = TypeVar("T")


class Require():
    @staticmethod
    def present(
        field: str, 
        val: Any, 
        custom_msg: str | None = None
    ) -> None:
        if val is None or val == "":
            Require._raise_error(
                default_msg=f"Field '{field}' is required",
                custom_msg=custom_msg
            )

    @staticmethod
    def match(
        field: str, 
        val: Any, 
        pattern: str | Pattern[str], 
        custom_msg: str | None = None
    ) -> Match[str]:
        match = re.fullmatch(pattern, str(val))
        if not match:
            Require._raise_error(
                default_msg=f"Field '{field}={val}' does not match to '{pattern}' pattern",
                custom_msg=custom_msg
            )
        return match

    @staticmethod
    def min(
        field: str, 
        val: int, 
        min_val: int, 
        custom_msg: str | None = None
    ) -> None:
        if val < min_val:
            Require._raise_error(
                default_msg=f"Field '{field}={val}' is too small, minimal value is {min_val}",
                custom_msg=custom_msg
            )
    
    @staticmethod
    def max(
        field: str, 
        val: int, 
        max_val: int, 
        custom_msg: str | None = None
    ) -> None:
        if val > max_val:
            Require._raise_error(
                default_msg=f"Field '{field}={val}' is too big, maximum value is {max_val}",
                custom_msg=custom_msg
            )

    @staticmethod
    def port(
        field: str, 
        val: int, 
        custom_msg: str | None = None
    ) -> None:
        min_val = 1
        max_val = 65535
        try:
            Require.type(field, val, int)
            Require.min(field, val, min_val)
            Require.max(field, val, max_val)
        except ValueError as _:
            Require._raise_error(
                default_msg=f"Field '{field}={val}' is not valid port number, value is out of range ({min_val}-{max_val})",
                custom_msg=custom_msg
            )

    @staticmethod
    def env(
        field: str,
        env_name: str,
        custom_msg: str | None = None
    ) -> str:
        val = os.getenv(env_name)
        if not val:
            Require._raise_err(
                default_msg=f"Environment variable '{env_name}' referenced by '{field}' field is not set",
                custom_msg=custom_msg,
            )
        return val

    @staticmethod
    def ip_address(
        field: str,
        val: str, 
        custom_msg: str | None = None
    ) -> None:
        try:
            ipaddress.ip_network(val, strict=False)
        except ValueError as e:
            Require._raise_error(
                default_msg=f"Field '{field}={val}' is invalid CIDR, details: {e}",
                custom_msg=custom_msg
            )
            
    
    @staticmethod
    def email(
        field: str,
        val: str, 
        custom_msg: str | None = None
    ) -> None:
        email_pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
        Require.match(
            field=field,
            val=val,
            pattern=email_pattern,
            custom_msg=custom_msg or f"Field '{field}={val}' is not a valid email address"
        )
    
    @staticmethod
    def domain(
        field: str,
        val: str,
        custom_msg: str | None = None
    ) -> None:
        domain_pattern = (
            r"^(?:\*\.)?" # optional wildcard
            r"(?:[a-zA-Z0-9]" # label start
            r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+" # middle labels
            r"[A-Za-z]{2,}$" # TLD
        )
        Require.match(
            field=field,
            val=val,
            pattern=domain_pattern,
            custom_msg=custom_msg or f"Field '{field}={val}' is not a valid domain"
        )
    
    @staticmethod
    def type(
        field: str, 
        val: object, 
        class_type: Type[T], 
        custom_msg: str | None = None
    ) -> None:
        if not isinstance(val, class_type):
            Require._raise_error(
                default_msg=f"Field '{field}={val}' has invalid type, must be a {class_type.__name__}",
                custom_msg=custom_msg
            )
    
    @staticmethod
    def file_path(
        field: str, 
        val: str, 
        custom_msg: str | None = None
    ) -> None:
        try:
            return Path(val).expanduser()
        except Exception:
            Require._raise_error(
                default_msg=f"Field '{field}={val}' is not a valid path to a file",
                custom_msg=custom_msg
            )

    @staticmethod 
    def file_exists(
        field: str, 
        val: str, 
        custom_msg: str | None = None
    ) -> Path:
        if not os.path.exists(val):
            Require._raise_error(
                default_msg=f"Field '{field}={val}' points to a file that does not exist",
                custom_msg=custom_msg
            )
        return Path(val).expanduser()

    @staticmethod
    def one_of(
        field: str, 
        val: str, 
        allowed_values: list[Any], 
        custom_msg: str | None = None
    ) -> None:
        if val not in allowed_values:
            Require._raise_error(
                default_msg=f"Field '{field}={val}' is invalid, allowed choices: {(', ').join(allowed_values)}",
                custom_msg=custom_msg
            )

    @staticmethod
    def not_one_of(
        field: str, 
        val: str, 
        not_allowed_values: list[Any], 
        custom_msg: str | None = None
    ) -> None:
        if val in not_allowed_values:
            Require._raise_error(
                default_msg=f"Field '{field}={val}' is duplicated, cannot be one of: {(', ').join(not_allowed_values)}",
                custom_msg=custom_msg
            )

    @staticmethod
    def _raise_error(
        default_msg: str, 
        custom_msg: str | None = None
    ) -> None:
        raise ValueError(custom_msg or default_msg)
