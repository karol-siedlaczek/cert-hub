from flask import request
from typing import Any, Callable, TypeVar
from cert_registry.errors.api_error import InvalidRequestError

T = TypeVar("T")

def query_list(
    name: str, 
    *, 
    required: bool = False,
    allow_star: bool = False,
    strip: bool = True
) -> list[str]:
    vals = request.args.getlist(name)
    if strip:
        vals = [v.strip() for v in vals if isinstance(v, str)]
    
    vals = [v for v in vals if v] # Remove empty values
    
    if required and not vals:
        raise InvalidRequestError("Missing required query parameter", detail={ "parameter": name, "example": f"?{name}=val_1&{name}=val_2" })

    if allow_star and "*" in vals:
        return ["*"]
    
    return vals


def query_str(
    name: str, 
    *, 
    required: bool = False
) -> str | None:
    val = request.args.get(name)
    
    if val is None or val == "*":
        if required:
            raise InvalidRequestError("Missing required query parameter", detail={ "parameter": name })
        return None
    
    return str(val).strip()


def query_int(
    name: str,
    *,
    required: bool = False,
    min_val: int | None = None,
    max_val: int | None = None
) -> int | None:
    raw_val = request.args.get(name)
    
    if raw_val is None or raw_val == "":
        if required:
            raise InvalidRequestError("Missing required query parameter", detail={ "parameter": name })
        return None
    
    try:
        val = int(raw_val)
    except ValueError:
        raise InvalidRequestError("Invalid query parameter", detail={ "parameter": name, "expecter": "integer" })
    
    if min_val is not None and val < min_val:
        raise InvalidRequestError("Invalid query parameter", detail={ "parameter": name, "min": min_val })
    if max_val is not None and val > max_val:
        raise InvalidRequestError("Invalid query parameter", detail={ "parameter": name, "max": max_val })
    
    return val


def json_body(
    *, 
    required=True
) -> dict[str, Any]:
    data = request.get_json(silent=True)
    
    if data is None:
        if required:
            raise InvalidRequestError("Missing JSON body", detail={ "expected": "application/json" })
        return {}
    
    if not isinstance(data, dict):
        raise InvalidRequestError("Invalid JSON body", detail={ "expected", "JSON object" })
    
    return data


def json_body_field(
    data: dict[str, Any],
    name: str,
    *,
    required: bool = True,
    cast_fn: Callable[[Any], T] | None = None
) -> T | Any | None:
    if name not in data or data[name] in (None, ""):
        if required:
            raise InvalidRequestError("Missing required JSON field in body", detail={ "field": name })
        return None
    
    val: Any = data[name]
    if cast_fn is None:
        return val
    
    try:
        return cast_fn(val)
    except Exception:
        expected_type = getattr(cast_fn, "__name__", "value")
        raise InvalidRequestError("Invalid JSON field in body", detail={ "field": name, "expected": expected_type })

