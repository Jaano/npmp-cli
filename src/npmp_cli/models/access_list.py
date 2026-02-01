from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from .. import utils
from .kinds import Kind

if TYPE_CHECKING:
    from ..npmplus_client import NPMplusClient


class AccessListItem:
    kind: ClassVar[Kind] = Kind.ACCESS_LISTS

    def __init__(
        self,
        *,
        api: NPMplusClient,
        name: str,
        satisfy_any: object = False,
        pass_auth: object = False,
        items: list | None = None,
        clients: list | None = None,
        id: object = -1,
    ) -> None:
        self.api = api
        self.name = name
        self.satisfy_any = satisfy_any
        self.pass_auth = pass_auth
        self.items = [] if items is None else items
        self.clients = [] if clients is None else clients
        self.id = id

    @property
    def natural_index(self) -> str:
        return self.name

    @classmethod
    def from_json(cls, api: NPMplusClient, data: dict[str, Any]) -> AccessListItem:
        return cls(
            api=api,
            name=str(data.get("name", "")).strip(),
            satisfy_any=utils.bool_or(data.get("satisfy_any", False), default=False),
            pass_auth=utils.bool_or(data.get("pass_auth", False), default=False),
            items=list(data.get("items", [])),
            clients=list(data.get("clients", [])),
            id=utils.normalize_int(data.get("id"), default=-1),
        )

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        if not value.strip():
            raise ValueError("name must not be empty")
        self._name = value.strip()

    @property
    def satisfy_any(self) -> bool:
        return self._satisfy_any

    @satisfy_any.setter
    def satisfy_any(self, value: object) -> None:
        self._satisfy_any = utils.bool_or(value, default=False)

    @property
    def pass_auth(self) -> bool:
        return self._pass_auth

    @pass_auth.setter
    def pass_auth(self, value: object) -> None:
        self._pass_auth = utils.bool_or(value, default=False)

    @property
    def items(self) -> list:
        return self._items

    @items.setter
    def items(self, value: object) -> None:
        if not isinstance(value, list):
            raise ValueError("items must be a list")
        self._items = value

    @property
    def clients(self) -> list:
        return self._clients

    @clients.setter
    def clients(self, value: object) -> None:
        if not isinstance(value, list):
            raise ValueError("clients must be a list")
        self._clients = value

    @property
    def id(self) -> int:
        return self._id

    @id.setter
    def id(self, value: object) -> None:
        self._id = utils.normalize_int(value, default=-1)

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "satisfy_any": self.satisfy_any,
            "pass_auth": self.pass_auth,
            "items": self.items,
            "clients": self.clients,
            "id": self.id,
        }

    @staticmethod
    def _sanitize_clients(clients: list) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        for entry in clients:
            if not isinstance(entry, Mapping):
                continue
            address = str(entry.get("address") or "").strip()
            directive = str(entry.get("directive") or "").strip().lower()
            if not address:
                continue
            if directive not in {"allow", "deny"}:
                raise ValueError(f"Invalid access-list client directive: {directive!r}")
            out.append({"address": address, "directive": directive})
        return out

    @staticmethod
    def _sanitize_items(items: list) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        for entry in items:
            if not isinstance(entry, Mapping):
                continue
            username = str(entry.get("username") or "").strip()
            password = str(entry.get("password") or "").strip()
            if not username:
                continue
            if not password:
                raise ValueError(f"Invalid access-list auth item: missing password for user {username!r}")
            out.append({"username": username, "password": password})
        return out

    def to_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "satisfy_any": bool(self.satisfy_any),
            "pass_auth": bool(self.pass_auth),
            "items": self._sanitize_items(list(self.items)),
            "clients": self._sanitize_clients(list(self.clients)),
        }

    def save(self) -> tuple[Literal["create", "update"], dict[str, Any]]:
        effective_id = self.api.get_access_list_id(self.name)
        if effective_id <= 0:
            result = self.api.create_access_list(self.to_payload())
            self.id = result.get("id")
            return "create", result

        try:
            result = self.api.update_access_list(effective_id, self.to_payload())
        except RuntimeError as e:
            if "HTTP 404" in str(e) and "Not Found" in str(e):
                result = self.api.create_access_list(self.to_payload())
                self.id = result.get("id")
                return "create", result
            raise

        self.id = result.get("id")
        return "update", result

    def delete(self) -> None:
        if self.id <= 0:
            raise ValueError(f"Cannot delete {self.kind.value}: invalid id={self.id}")
        self.api.delete_access_list(self.id)
