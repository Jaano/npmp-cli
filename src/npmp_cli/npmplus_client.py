from __future__ import annotations

from typing import Any

from . import utils
from .models import (
    AccessListItem,
    CertificateItem,
    DeadHostItem,
    ProxyHostItem,
    RedirectionHostItem,
    StreamItem,
    UserItem,
)
from .npmplus_api import (
    EXPAND_ACCESS_LIST,
    EXPAND_CERTIFICATE,
    EXPAND_CLIENTS,
    EXPAND_DEAD_HOSTS,
    EXPAND_ITEMS,
    EXPAND_OWNER,
    EXPAND_PERMISSIONS,
    EXPAND_PROXY_HOSTS,
    EXPAND_REDIRECTION_HOSTS,
    EXPAND_STREAMS,
    EXPAND_USER,
    NPMplusApi,
)

__all__ = ["NPMplusClient"]


class NPMplusClient(NPMplusApi):
    """High-level NPMplus client with typed item wrappers."""

    def __post_init__(self) -> None:
        super().__post_init__()
        self._my_id_cache: int = -1
        self._my_natural_index_cache: str = ""

    def __post_login__(self) -> None:
        data = self.get_current_user(expand=(EXPAND_PERMISSIONS,))
        self._my_id_cache = utils.normalize_int(data.get("id"), default=-1)
        self._my_natural_index_cache = str(data.get("nickname") or "").strip()

    def set_token_cookie(self, token: str) -> None:
        super().set_token_cookie(token)
        self.__post_login__()

    def login(self, identity: str, secret: str) -> dict[str, Any]:
        result = super().login(identity, secret)
        self.__post_login__()
        return result

    def __enter__(self) -> NPMplusClient:
        return self

    def list_audit_log(self, *, query: str | None = None) -> list[dict[str, Any]]:
        return super().list_audit_log(expand=(EXPAND_USER,), query=query)

    @property
    def my_id(self) -> int:
        return self._my_id_cache

    @property
    def my_natural_index(self) -> str:
        return self._my_natural_index_cache

    def list_users(self) -> dict[int, UserItem]:
        items = super().list_users(expand=(EXPAND_PERMISSIONS,))
        result: dict[int, UserItem] = {}
        for item in items:
            obj = UserItem.from_json(self, dict(item))
            if obj.id > 0:
                result[obj.id] = obj
        return result

    def list_access_lists(self) -> dict[int, AccessListItem]:
        items = super().list_access_lists(expand=(EXPAND_OWNER, EXPAND_ITEMS, EXPAND_CLIENTS))
        result: dict[int, AccessListItem] = {}
        for item in items:
            obj = AccessListItem.from_json(self, dict(item))
            if obj.id > 0:
                result[obj.id] = obj
        return result

    def get_access_list_id(self, natural_index: str) -> int:
        for item in self.list_access_lists().values():
            if item.natural_index == natural_index:
                return item.id
        return -1

    def list_certificates(self) -> dict[int, CertificateItem]:
        items = super().list_certificates(
            expand=(EXPAND_OWNER, EXPAND_PROXY_HOSTS, EXPAND_REDIRECTION_HOSTS, EXPAND_DEAD_HOSTS, EXPAND_STREAMS)
        )
        result: dict[int, CertificateItem] = {}
        for item in items:
            obj = CertificateItem.from_json(self, dict(item))
            if obj.id > 0:
                result[obj.id] = obj
        return result

    def get_certificate_id(self, natural_index: str) -> int:
        for item in self.list_certificates().values():
            if item.natural_index == natural_index:
                return item.id
        return -1

    def list_proxy_hosts(self) -> dict[int, ProxyHostItem]:
        items = super().list_proxy_hosts(expand=(EXPAND_CERTIFICATE, EXPAND_OWNER, EXPAND_ACCESS_LIST))
        result: dict[int, ProxyHostItem] = {}
        for item in items:
            obj = ProxyHostItem.from_json(self, dict(item))
            if obj.id > 0:
                result[obj.id] = obj
        return result

    def get_proxy_host_id(self, natural_index: str) -> int:
        for item in self.list_proxy_hosts().values():
            if item.natural_index == natural_index:
                return item.id
        return -1

    def list_redirection_hosts(self) -> dict[int, RedirectionHostItem]:
        items = super().list_redirection_hosts(expand=(EXPAND_CERTIFICATE, EXPAND_OWNER))
        result: dict[int, RedirectionHostItem] = {}
        for item in items:
            obj = RedirectionHostItem.from_json(self, dict(item))
            if obj.id > 0:
                result[obj.id] = obj
        return result

    def get_redirection_host_id(self, natural_index: str) -> int:
        for item in self.list_redirection_hosts().values():
            if item.natural_index == natural_index:
                return item.id
        return -1

    def list_dead_hosts(self) -> dict[int, DeadHostItem]:
        items = super().list_dead_hosts(expand=(EXPAND_CERTIFICATE, EXPAND_OWNER))
        result: dict[int, DeadHostItem] = {}
        for item in items:
            obj = DeadHostItem.from_json(self, dict(item))
            if obj.id > 0:
                result[obj.id] = obj
        return result

    def get_dead_host_id(self, natural_index: str) -> int:
        for item in self.list_dead_hosts().values():
            if item.natural_index == natural_index:
                return item.id
        return -1

    def list_streams(self) -> dict[int, StreamItem]:
        items = super().list_streams(expand=(EXPAND_CERTIFICATE, EXPAND_OWNER))
        result: dict[int, StreamItem] = {}
        for item in items:
            obj = StreamItem.from_json(self, dict(item))
            if obj.id > 0:
                result[obj.id] = obj
        return result

    def get_stream_id(self, natural_index: str) -> int:
        for item in self.list_streams().values():
            if item.natural_index == natural_index:
                return item.id
        return -1
