from __future__ import annotations

from npmp_cli.filemanager import (
    _expand_attempts_for_kind,
    _fetch_with_expand_fallback,
    _find_existing_id_by_natural_key,
)
from npmp_cli.npmplus_api import NPMplusApi


def test_expand_attempts_for_access_lists_includes_clients() -> None:
    assert _expand_attempts_for_kind("access-lists")[0] == ["clients", "items"]


def test_expand_attempts_for_proxy_hosts_start_full() -> None:
    assert _expand_attempts_for_kind("proxy-hosts")[0] == ["owner", "certificate", "access_list"]


def test_fetch_with_expand_fallback_retries_on_error() -> None:
    seen: list[object] = []

    def method(*, expand, query):
        seen.append(expand)
        # Fail on first attempt, succeed on fallback.
        if expand is not None:
            raise RuntimeError("HTTP 500")
        return [{"ok": True}]

    items = _fetch_with_expand_fallback(method, kind_name="proxy-hosts", query=None)
    assert items == [{"ok": True}]
    assert seen[0] is not None
    assert seen[-1] is None


class _StubClient:
    def __init__(
        self,
        *,
        proxy_hosts=None,
        redirection_hosts=None,
        dead_hosts=None,
        streams=None,
        access_lists=None,
        certificates=None,
    ):
        self._proxy_hosts = proxy_hosts or []
        self._redirection_hosts = redirection_hosts or []
        self._dead_hosts = dead_hosts or []
        self._streams = streams or []
        self._access_lists = access_lists or []
        self._certificates = certificates or []

    def list_proxy_hosts(self, *, expand=None, query=None):
        return self._proxy_hosts

    def list_redirection_hosts(self, *, expand=None, query=None):
        return self._redirection_hosts

    def list_dead_hosts(self, *, expand=None, query=None):
        return self._dead_hosts

    def list_streams(self, *, expand=None, query=None):
        return self._streams

    def list_access_lists(self, *, expand=None, query=None):
        return self._access_lists

    def list_certificates(self, *, expand=None, query=None):
        return self._certificates


def test_find_existing_id_proxy_hosts_matches_domain_set_case_insensitive() -> None:
    client: NPMplusApi = _StubClient(  # type: ignore[assignment]
        proxy_hosts=[
            {"id": 10, "domainNames": ["B.EXAMPLE", "a.example"]},
            {"id": 11, "domainNames": ["other.example"]},
        ],
    )
    obj_id = _find_existing_id_by_natural_key(client, "proxy-hosts", {"domain_names": ["a.example", "b.example"]})  # type: ignore
    assert obj_id == 10


def test_find_existing_id_access_lists_matches_name_case_insensitive() -> None:
    client: NPMplusApi = _StubClient(access_lists=[{"id": 3, "name": "LAN"}, {"id": 4, "name": "Office"}])  # type: ignore[assignment]
    obj_id = _find_existing_id_by_natural_key(client, "access-lists", {"name": "lan"})  # type: ignore
    assert obj_id == 3


def test_find_existing_id_streams_matches_incoming_port() -> None:
    client: NPMplusApi = _StubClient(streams=[{"id": 7, "incomingPort": 1234}, {"id": 8, "incomingPort": 9999}])  # type: ignore[assignment]
    obj_id = _find_existing_id_by_natural_key(client, "streams", {"incomingPort": 1234})  # type: ignore
    assert obj_id == 7


def test_find_existing_id_returns_none_when_not_found() -> None:
    client: NPMplusApi = _StubClient(proxy_hosts=[{"id": 10, "domainNames": ["a.example"]}])  # type: ignore[assignment]
    obj_id = _find_existing_id_by_natural_key(client, "proxy-hosts", {"domain_names": ["missing.example"]})  # type: ignore
    assert obj_id is None
