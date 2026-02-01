from __future__ import annotations

from typing import cast

import pytest

from npmp_cli.models import Kind, ProxyHostItem
from npmp_cli.npmplus_client import NPMplusClient
from tests.test_configuration import StubNPMplusClient


def test_kind_inference() -> None:
    assert Kind.infer_json_kind({"forward_host": "x", "forward_port": 80}) == Kind.PROXY_HOSTS
    assert Kind.infer_json_kind({"forward_domain_name": "x"}) == Kind.REDIRECTION_HOSTS
    assert Kind.infer_json_kind({"incoming_port": 1234}) == Kind.STREAMS
    assert Kind.infer_json_kind({"pass_auth": True}) == Kind.ACCESS_LISTS
    assert Kind.infer_json_kind({"domain_names": ["x"]}) == Kind.DEAD_HOSTS


def test_proxy_host_from_json_normalizes_domains() -> None:
    api = cast(NPMplusClient, StubNPMplusClient())
    item = ProxyHostItem.from_json(
        api,
        {
            "id": 123,
            "domain_names": ["Example.com", "www.EXAMPLE.com", ""],
            "forward_host": "127.0.0.1",
            "forward_port": 8080,
            "forward_scheme": "http",
        },
    )

    assert item.id == 123
    assert item.domain_names == ["example.com", "www.example.com"]
    assert item.forward_host == "127.0.0.1"
    assert item.forward_port == 8080
    assert item.forward_scheme == "http"


def test_proxy_host_to_payload_does_not_include_readonly_fields() -> None:
    api = cast(NPMplusClient, StubNPMplusClient())
    item = ProxyHostItem(
        api=api,
        id=999,
        owner="someone",
        owner_user_id=42,
        domain_names=["example.invalid"],
        forward_host="new.example",
        forward_port=8080,
        forward_scheme="http",
    )

    payload = item.to_payload()

    assert "id" not in payload
    assert "owner" not in payload
    assert "owner_user_id" not in payload
    assert payload["domain_names"] == ["example.invalid"]
    assert payload["forward_host"] == "new.example"


def test_proxy_host_to_payload_resolves_access_list_and_certificate_ids() -> None:
    api = cast(NPMplusClient, StubNPMplusClient(access_lists={"al": 456}, certs={"cert": 123}))

    item = ProxyHostItem(
        api=api,
        domain_names=["example.invalid"],
        forward_host="example.com",
        forward_port=80,
        forward_scheme="http",
        access_list="al",
        certificate="cert",
    )

    payload = item.to_payload()
    assert payload["access_list_id"] == 456
    assert payload["certificate_id"] == 123


def test_proxy_host_to_payload_raises_for_unknown_access_list() -> None:
    api = cast(NPMplusClient, StubNPMplusClient())
    item = ProxyHostItem(
        api=api,
        domain_names=["example.invalid"],
        forward_host="example.com",
        forward_port=80,
        forward_scheme="http",
        access_list="missing",
    )

    with pytest.raises(ValueError, match="Unknown access list"):
        item.to_payload()
