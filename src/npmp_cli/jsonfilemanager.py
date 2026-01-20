from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .configmanager import ConfigManager
from .npmplus_client import NPMplusClient, NPMplusItemType

logger = ConfigManager.get_logger(__name__)


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

    def _save_items(self, items: Mapping[int, NPMplusItemType], *, out: Path) -> None:
        for item in items.values():
            path = out / f"{item.kind.value}__{item.id}.json"
            write_json_file(path, dict(item))
            logger.info("Saved %s %s -> %s", item.kind.value, item.natural_index, path)

    def save(self, *, out: Path) -> None:
        self._save_items(self._client.list_proxy_hosts(), out=out)
        self._save_items(self._client.list_redirection_hosts(), out=out)
        self._save_items(self._client.list_dead_hosts(), out=out)
        self._save_items(self._client.list_streams(), out=out)
        self._save_items(self._client.list_access_lists(), out=out)

    def load(self, *, file: Path, takeownership: bool = False) -> tuple[NPMplusClient.Kind, str, object]:
        try:
            payload = json.loads(file.read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"Invalid JSON: {str(e)}") from None
        if not isinstance(payload, dict):
            raise ValueError("JSON file must contain an object")

        kind = NPMplusClient.Kind.infer_json_kind(payload)
        item = kind.item_type()

        skip_result = item.load_from_json(self._client, payload)
        if skip_result == "skip":
            logger.info("Skipped loading from %s", file)
            return kind, "skip", item.id

        logger.info("Loading from %s", file)
        mode, result = item.set(self._client, takeownership=takeownership)
        new_id = item.normalize_int(result.get("id"))
        return kind, mode, new_id
