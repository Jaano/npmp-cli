from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

KIND_VALUES = {
    "proxy-hosts",
    "redirection-hosts",
    "dead-hosts",
    "streams",
    "access-lists",
}


def infer_kind(
    path: Path, payload: Mapping[str, Any], *, kind_override: str | None = None
) -> str:
    if kind_override:
        k = kind_override.strip().lower()
        if k not in KIND_VALUES:
            raise ValueError(f"Unknown kind: {kind_override}")
        return k

    # 1) folder name
    parent = path.parent.name.strip().lower()
    if parent in KIND_VALUES:
        return parent

    # 2) filename prefix: <kind>__...
    name = path.name.strip().lower()
    for k in sorted(KIND_VALUES, key=len, reverse=True):
        if name.startswith(k + "__") or name == k + ".yaml":
            return k

    # 3) heuristics from payload keys
    keys = {str(k).lower() for k in payload.keys()}
    if (
        "satisfy_any" in keys
        or "pass_auth" in keys
        or "proxy_host_count" in keys
        or "clients" in keys
    ):
        return "access-lists"
    if "incomingport" in keys:
        return "streams"
    if "forward_host" in keys or "forward_port" in keys or "forward_scheme" in keys:
        return "proxy-hosts"
    if "redirect_host" in keys or "redirect_code" in keys:
        return "redirection-hosts"
    # dead-hosts are more sparse; fall back last
    return "dead-hosts"


def _schema_request_properties(
    schema: Mapping[str, Any], path: str, method: str
) -> set[str]:
    paths = schema.get("paths") or {}
    op = (paths.get(path) or {}).get(method.lower()) or {}
    rb = op.get("requestBody") or {}
    content = rb.get("content") or {}
    app_json = content.get("application/json") or {}
    s = app_json.get("schema") or {}
    props = s.get("properties") or {}
    # keep exact key spellings from schema (snake_case)
    return {str(k) for k in props.keys()}


def _schema_array_item_properties(
    schema: Mapping[str, Any], path: str, method: str, prop_name: str
) -> set[str]:
    paths = schema.get("paths") or {}
    op = (paths.get(path) or {}).get(method.lower()) or {}
    rb = op.get("requestBody") or {}
    content = rb.get("content") or {}
    app_json = content.get("application/json") or {}
    s = app_json.get("schema") or {}
    props = s.get("properties") or {}
    arr = props.get(prop_name) or {}
    items = (arr.get("items") or {}) if isinstance(arr, dict) else {}
    item_props = items.get("properties") or {}
    return {str(k) for k in item_props.keys()}


def filter_payload_for_write(
    schema: Mapping[str, Any], kind: str, payload: Mapping[str, Any], *, mode: str
) -> dict[str, Any]:
    """Filter a saved payload to only fields accepted by the create/update endpoint.

    mode must be "create" or "update".
    """
    k = kind.strip().lower()
    if k not in KIND_VALUES:
        raise ValueError(f"Unknown kind: {kind}")
    m = mode.strip().lower()
    if m not in {"create", "update"}:
        raise ValueError("mode must be create or update")

    if k == "streams":
        write_path = "/nginx/streams" if m == "create" else "/nginx/streams/{streamID}"
        method = "post" if m == "create" else "put"
    elif k == "access-lists":
        write_path = (
            "/nginx/access-lists" if m == "create" else "/nginx/access-lists/{listID}"
        )
        method = "post" if m == "create" else "put"
    else:
        write_path = f"/nginx/{k}" if m == "create" else f"/nginx/{k}/{{hostID}}"
        method = "post" if m == "create" else "put"

    allowed = _schema_request_properties(schema, write_path, method)
    if not allowed:
        # If schema parsing fails for any reason, do a conservative cleanup instead of
        # blocking loads entirely.
        deny = {"id", "created_on", "modified_on"}
        return {k: v for k, v in payload.items() if str(k) not in deny}

    out = {k: v for k, v in payload.items() if str(k) in allowed}

    # access-lists contain nested arrays with strict schemas; strip extra fields.
    if k == "access-lists":
        for nested in ("clients", "items"):
            val = out.get(nested)
            if not isinstance(val, list):
                continue
            allowed_nested = _schema_array_item_properties(
                schema, write_path, method, nested
            )
            if not allowed_nested:
                continue
            filtered_list: list[Any] = []
            for entry in val:
                if not isinstance(entry, dict):
                    continue
                filtered_list.append(
                    {k: v for k, v in entry.items() if str(k) in allowed_nested}
                )
            out[nested] = filtered_list

    return out
