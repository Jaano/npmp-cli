from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, ClassVar, Protocol

from .configmanager import ConfigManager
from .models import (
    AccessListItem,
    DeadHostItem,
    Kind,
    ProxyHostItem,
    RedirectionHostItem,
    StreamItem,
)
from .npmplus_client import NPMplusClient

logger = ConfigManager.get_logger(__name__)


class JsonSavableItem(Protocol):
    kind: ClassVar[Kind]

    @property
    def id(self) -> int: ...

    def to_json(self) -> Any: ...


def write_json_file(path: Path, payload: Any) -> None:
    content = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)
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


class JsonFileManager:
    def __init__(self, client: NPMplusClient) -> None:
        self._client = client

    def _save_items(self, items: Mapping[int, JsonSavableItem], *, out: Path) -> None:
        for item in items.values():
            path = out / f"{item.kind.value}__{item.id}.json"
            write_json_file(path, item.to_json())
            natural_index = getattr(item, "natural_index", "")
            logger.info("Saved %s %s -> %s", item.kind.value, natural_index, path)

    def save(self, *, out: Path) -> None:
        self._save_items(self._client.list_proxy_hosts(), out=out)
        self._save_items(self._client.list_redirection_hosts(), out=out)
        self._save_items(self._client.list_dead_hosts(), out=out)
        self._save_items(self._client.list_streams(), out=out)
        self._save_items(self._client.list_access_lists(), out=out)

    def load(self, *, file: Path, take_ownership: bool = False) -> tuple[Kind, str, object]:
        try:
            payload = json.loads(file.read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"Invalid JSON: {str(e)}") from None
        if not isinstance(payload, dict):
            raise ValueError("JSON file must contain an object")

        kind = Kind.infer_json_kind(payload)

        item: object

        if kind == Kind.PROXY_HOSTS:
            item = ProxyHostItem.from_json(self._client, payload)
            mode, result = item.save(take_ownership=take_ownership)
        elif kind == Kind.REDIRECTION_HOSTS:
            item = RedirectionHostItem.from_json(self._client, payload)
            mode, result = item.save(take_ownership=take_ownership)
        elif kind == Kind.DEAD_HOSTS:
            item = DeadHostItem.from_json(self._client, payload)
            mode, result = item.save(take_ownership=take_ownership)
        elif kind == Kind.STREAMS:
            item = StreamItem.from_json(self._client, payload)
            mode, result = item.save(take_ownership=take_ownership)
        elif kind == Kind.ACCESS_LISTS:
            item = AccessListItem.from_json(self._client, payload)
            mode, result = item.save()
        else:
            raise ValueError(f"Unsupported kind: {kind.value}")

        new_id = result.get("id")
        natural_index = getattr(item, "natural_index", "")
        logger.info("Loaded %s %s <- %s", kind.value, natural_index, file)
        return kind, mode, new_id
