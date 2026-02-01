from __future__ import annotations

from collections.abc import Sequence
from typing import Any


def normalize_bool(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    v = str(value).strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    return None


def normalize_int(value: object, *, default: int = -1) -> int:
    if value is None:
        return default
    try:
        return int(str(value).strip())
    except Exception:
        return default


def bool_or(value: object, *, default: bool) -> bool:
    b = normalize_bool(value)
    return default if b is None else b


def domain_key(domains: Sequence[object] | None) -> tuple[str, ...] | None:
    if not domains:
        return None
    out = [s for d in domains if (s := str(d).strip().lower())]
    return tuple(sorted(set(out))) if out else None


def parse_port(value: object, *, field: str) -> int:
    if value is None:
        raise ValueError(f"Missing {field}")
    try:
        port = int(str(value).strip())
    except Exception as e:
        raise ValueError(f"Invalid {field}") from e
    if port <= 0 or port > 65535:
        raise ValueError(f"Invalid {field}")
    return port


def parse_domain_names(value: str | Sequence[str]) -> list[str]:
    if isinstance(value, str):
        domains = [d.strip() for part in (value or "").split(",") if (d := part.strip())]
    else:
        domains = [s for d in value if (s := str(d).strip())]
    if not domains:
        raise ValueError("domain_names must not be empty")
    return domains


def parse_location(value: str) -> dict[str, Any]:
    raw = (value or "").strip()
    parts = raw.split(":")
    if len(parts) != 4:
        raise ValueError("location must be in format path:scheme:host:port")
    path, scheme, host, port_s = (p.strip() for p in parts)
    if not path or not scheme or not host or not port_s:
        raise ValueError("location must be in format path:scheme:host:port")
    port = parse_port(port_s, field="location port")
    return {
        "path": path,
        "forward_scheme": scheme,
        "forward_host": host,
        "forward_port": port,
        "location_type": "",
    }


def parse_access_list_clients(*, allow: Sequence[str], deny: Sequence[str]) -> list[dict[str, str]]:
    clients: list[dict[str, str]] = []
    for address in allow:
        addr = str(address or "").strip()
        if not addr:
            raise ValueError("--allow must not be empty")
        clients.append({"address": addr, "directive": "allow"})
    for address in deny:
        addr = str(address or "").strip()
        if not addr:
            raise ValueError("--deny must not be empty")
        clients.append({"address": addr, "directive": "deny"})
    return clients


def parse_access_list_auth_items(*, auth_user: Sequence[str]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for spec in auth_user:
        raw = str(spec or "").strip()
        if not raw:
            raise ValueError("--auth-user must not be empty")
        if ":" not in raw:
            raise ValueError("--auth-user must be USERNAME:PASSWORD")
        username, password = raw.split(":", 1)
        username = username.strip()
        password = password.strip()
        if not username or not password:
            raise ValueError("--auth-user must be USERNAME:PASSWORD")
        items.append({"username": username, "password": password})
    return items


def access_list_name_from_value(value: object) -> str | None:
    if isinstance(value, dict):
        name = value.get("name") or value.get("title")
        if name is None:
            return None
        s = str(name).strip()
        return s or None
    if isinstance(value, str):
        s = value.strip()
        return s or None
    return None


def certificate_nice_name_from_value(value: object) -> str | None:
    if isinstance(value, dict):
        nice_name = value.get("nice_name")
        if nice_name is None:
            return None
        s = str(nice_name).strip()
        return s or None
    if isinstance(value, str):
        s = value.strip()
        return s or None
    return None
