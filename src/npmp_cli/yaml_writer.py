from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any

import yaml

_STRIP_KEYS = {
    "id",
    "owner_user_id",
    "ownerUserId",
    "meta",
    "access_list_id",
    "accessListId",
    "certificate_id",
    "certificateId",
    "proxy_host_count",
    "proxyHostCount",
    "created_on",
    "modified_on",
    "createdOn",
    "modifiedOn",
}


def _strip_timestamps(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for k, v in value.items():
            if str(k) in _STRIP_KEYS:
                continue
            out[k] = _strip_timestamps(v)
        return out
    if isinstance(value, list):
        return [_strip_timestamps(v) for v in value]
    return value


def sanitize_filename(value: str, *, max_len: int = 120) -> str:
    value = (value or "").strip().lower()
    if not value:
        return "item"
    value = value.replace(" ", "_")
    value = re.sub(r"[^a-z0-9._-]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("._-")
    return value[:max_len] or "item"


def dumps_deterministic(data: Any) -> str:
    # YAML output must be stable across runs: sort keys, fixed indentation, newline at EOF.
    # We avoid flow style to keep diffs readable.
    return (
        yaml.safe_dump(
            data,
            allow_unicode=True,
            sort_keys=True,
            default_flow_style=False,
        )
        or ""
    )


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        Path(tmp_path).replace(path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise


def write_yaml_file(path: Path, payload: Any, *, skip_unchanged: bool) -> bool:
    """Returns True if wrote/updated the file."""
    content = dumps_deterministic(_strip_timestamps(payload))
    if skip_unchanged and path.exists():
        try:
            existing = path.read_text(encoding="utf-8")
            if existing == content:
                return False
        except Exception:
            pass
    atomic_write_text(path, content)
    return True


def host_filename(kind: str, item: dict[str, Any]) -> str:
    item_id = item.get("id")
    id_part = str(item_id) if item_id is not None else "unknown"
    return f"{kind}__{id_part}.yaml"
