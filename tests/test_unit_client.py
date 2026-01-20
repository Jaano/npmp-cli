from __future__ import annotations

from typing import cast

import httpx

from npmp_cli.npmplus_client import NPMplusClient, ProxyHostItem


class StubApi:
    @staticmethod
    def _as_key(value: object) -> str | None:
        if value is None:
            return None
        s = str(value).strip().lower()
        return s or None

    def list_proxy_hosts(self, query: str | None = None):  # noqa: ARG002
        return {}

    def list_access_lists(self, query: str | None = None):  # noqa: ARG002
        return {}

    def get_access_list_id(self, natural_index: str) -> int:  # noqa: ARG002
        return -1

    def get_certificate_id(self, natural_index: str) -> int:  # noqa: ARG002
        return -1


def test_kind_inference() -> None:
    assert NPMplusClient.Kind.infer_json_kind({"forward_host": "x", "forward_port": 80}) == NPMplusClient.Kind.PROXY_HOSTS
    assert NPMplusClient.Kind.infer_json_kind({"forward_domain_name": "x"}) == NPMplusClient.Kind.REDIRECTION_HOSTS
    assert NPMplusClient.Kind.infer_json_kind({"incoming_port": 1234}) == NPMplusClient.Kind.STREAMS
    assert NPMplusClient.Kind.infer_json_kind({"pass_auth": True}) == NPMplusClient.Kind.ACCESS_LISTS
    assert NPMplusClient.Kind.infer_json_kind({"domain_names": ["x"]}) == NPMplusClient.Kind.DEAD_HOSTS


def test_payload_for_api_strips_internal_fields() -> None:
    item = ProxyHostItem({
        "id": 123,
        "created_on": "now",
        "owner": {"id": 1},
        "domain_names": ["example.invalid"],
        "forward_host": "new.example",
        "forward_port": 8080,
        "forward_scheme": "http",
    })
    payload = item._payload_for_api()

    assert isinstance(payload, dict)
    assert "id" not in payload
    assert "created_on" not in payload
    assert "owner" not in payload
    assert payload.get("domain_names") == ["example.invalid"]
    assert payload.get("forward_host") == "new.example"


def test_item_type_natural_index() -> None:
    t = NPMplusClient.Kind.PROXY_HOSTS.item_type()
    assert t.kind == NPMplusClient.Kind.PROXY_HOSTS
    t.update({"id": 5})
    assert t.natural_index == ""
    t.update({"domain_names": ["example.com", "www.example.com"]})
    assert t.natural_index == "example.com,www.example.com"


def test_load_from_json_keeps_api_fields_only() -> None:
    item = ProxyHostItem({"id": 999, "forward_host": "old"})

    result = item.load_from_json(
        cast(NPMplusClient, StubApi()),
        {
            "id": 1,
            "owner": {"id": 2},
            "created_on": "2025-01-01",
            "modified_on": "2025-01-02",
            "meta": {"nginx_online": True},
            "certificate_id": 123,
            "access_list_id": 456,
            "domain_names": ["Example.com"],
            "forward_host": "127.0.0.1",
            "forward_port": 8080,
        }
    )

    assert result is True
    assert "id" not in item
    assert "owner" not in item
    assert "created_on" not in item
    assert "modified_on" not in item
    assert item.get("meta") == {"nginx_online": True}
    assert item.get("certificate_id") == 123
    assert item.get("access_list_id") == 456
    assert item.get("domain_names") == ["Example.com"]
    assert item.get("forward_host") == "127.0.0.1"


def test_load_from_json_sets_minus_one_when_access_list_not_found() -> None:
    item = ProxyHostItem({})
    result = item.load_from_json(
        cast(NPMplusClient, StubApi()),
        {"access_list": {"name": "nonexistent"}},
    )
    assert result is True
    assert item.get("access_list_id") == -1


def test_get_audit_event_expand_parameter() -> None:
    seen: dict[str, object] = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["query"] = dict(request.url.params)
        return httpx.Response(200, json={"id": 5, "user": {"id": 1}})

    transport = httpx.MockTransport(_handler)

    with NPMplusClient(base_url="http://example.invalid/api", transport=transport) as api:
        api.get_audit_event(5, expand=("user",))

    assert seen.get("method") == "GET"
    assert seen.get("path") == "/api/audit-log/5"
    query = seen.get("query")
    assert isinstance(query, dict)
    assert query.get("expand") == "user"
