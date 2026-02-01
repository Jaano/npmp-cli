from __future__ import annotations

import pytest

from npmp_cli.models import (
    AccessListItem,
    DeadHostItem,
    ProxyHostItem,
    RedirectionHostItem,
    StreamItem,
)
from npmp_cli.npmplus_api import (
    EXPAND_ACCESS_LIST,
    EXPAND_CERTIFICATE,
    EXPAND_CLIENTS,
    EXPAND_ITEMS,
    EXPAND_OWNER,
)
from npmp_cli.npmplus_client import NPMplusClient
from tests.test_configuration import find_item_by_domains, find_item_by_name, wait_for_field

pytestmark = pytest.mark.integration


def test_schema_and_list_hosts(npmplus_client: NPMplusClient) -> None:
    schema = npmplus_client.get_schema()
    assert isinstance(schema, dict)
    assert "paths" in schema

    assert isinstance(npmplus_client.list_proxy_hosts(), dict)
    assert isinstance(npmplus_client.list_redirection_hosts(), dict)
    assert isinstance(npmplus_client.list_dead_hosts(), dict)
    assert isinstance(npmplus_client.list_streams(), dict)
    assert isinstance(npmplus_client.list_access_lists(), dict)


def test_proxy_host_crud(npmplus_client: NPMplusClient, unique_suffix: str) -> None:
    domains = (f"npmp-cli-it-{unique_suffix}.invalid",)
    created_id: int | None = None

    item = ProxyHostItem(
        api=npmplus_client,
        domain_names=list(domains),
        forward_host="example.com",
        forward_port=80,
        forward_scheme="http",
        enabled=True,
    )

    mode, created = item.save()
    assert mode == "create"
    created_id_raw = created.get("id")
    assert created_id_raw is not None
    created_id = int(str(created_id_raw).strip())

    try:
        found = find_item_by_domains(npmplus_client.list_proxy_hosts(), domains)
        assert found is not None
        assert int(found.id) == created_id

        update_payload = npmplus_client.get_proxy_host(
            created_id,
            expand=(EXPAND_ACCESS_LIST, EXPAND_CERTIFICATE, EXPAND_OWNER),
        )
        update = ProxyHostItem.from_json(npmplus_client, update_payload)
        update.forward_host = "example.org"
        update.enabled = False
        update.save()

        wait_for_field(npmplus_client.list_proxy_hosts, created_id, "enabled", False)

    finally:
        if created_id is not None:
            npmplus_client.delete_proxy_host(created_id)


def test_access_list_crud(npmplus_client: NPMplusClient, unique_suffix: str) -> None:
    name = f"npmp-cli-it-al-{unique_suffix}"
    created_id: int | None = None

    item = AccessListItem(
        api=npmplus_client,
        name=name,
        satisfy_any=True,
        pass_auth=False,
        items=[],
        clients=[],
    )

    mode, created = item.save()
    assert mode == "create"
    created_id_raw = created.get("id")
    assert created_id_raw is not None
    created_id = int(str(created_id_raw).strip())

    try:
        found = find_item_by_name(npmplus_client.list_access_lists(), name)
        assert found is not None
        assert int(found.id) == created_id

        update_payload = npmplus_client.get_access_list(
            created_id,
            expand=(EXPAND_CLIENTS, EXPAND_ITEMS, EXPAND_OWNER),
        )
        update = AccessListItem.from_json(npmplus_client, update_payload)
        update.satisfy_any = False
        update.save()

        wait_for_field(npmplus_client.list_access_lists, created_id, "satisfy_any", False)

    finally:
        if created_id is not None:
            npmplus_client.delete_access_list(created_id)


def test_redirection_host_crud(npmplus_client: NPMplusClient, unique_suffix: str) -> None:
    domains = (f"npmp-cli-it-redir-{unique_suffix}.invalid",)
    created_id: int | None = None

    item = RedirectionHostItem(
        api=npmplus_client,
        domain_names=list(domains),
        forward_scheme="http",
        forward_domain_name="example.com",
        forward_http_code=302,
        enabled=True,
    )

    mode, created = item.save()
    assert mode == "create"
    created_id_raw = created.get("id")
    assert created_id_raw is not None
    created_id = int(str(created_id_raw).strip())

    try:
        found = find_item_by_domains(npmplus_client.list_redirection_hosts(), domains)
        assert found is not None
        assert int(found.id) == created_id

        update_payload = npmplus_client.get_redirection_host(
            created_id,
            expand=(EXPAND_CERTIFICATE, EXPAND_OWNER),
        )
        update = RedirectionHostItem.from_json(npmplus_client, update_payload)
        update.forward_http_code = 301
        update.enabled = False
        update.save()

        wait_for_field(npmplus_client.list_redirection_hosts, created_id, "enabled", False)

    finally:
        if created_id is not None:
            npmplus_client.delete_redirection_host(created_id)


def test_dead_host_crud(npmplus_client: NPMplusClient, unique_suffix: str) -> None:
    domains = (f"npmp-cli-it-dead-{unique_suffix}.invalid",)
    created_id: int | None = None

    item = DeadHostItem(
        api=npmplus_client,
        domain_names=list(domains),
        enabled=True,
    )

    mode, created = item.save()
    assert mode == "create"
    created_id_raw = created.get("id")
    assert created_id_raw is not None
    created_id = int(str(created_id_raw).strip())

    try:
        found = find_item_by_domains(npmplus_client.list_dead_hosts(), domains)
        assert found is not None
        assert int(found.id) == created_id

        update_payload = npmplus_client.get_dead_host(
            created_id,
            expand=(EXPAND_CERTIFICATE, EXPAND_OWNER),
        )
        update = DeadHostItem.from_json(npmplus_client, update_payload)
        update.enabled = False
        update.save()

        wait_for_field(npmplus_client.list_dead_hosts, created_id, "enabled", False)

    finally:
        if created_id is not None:
            npmplus_client.delete_dead_host(created_id)


def test_stream_crud(npmplus_client: NPMplusClient, unique_suffix: str) -> None:
    incoming_port = 30000 + (hash(unique_suffix) % 10000)
    created_id: int | None = None

    item = StreamItem(
        api=npmplus_client,
        incoming_port=incoming_port,
        forwarding_host="example.com",
        forwarding_port=80,
        tcp_forwarding=True,
        udp_forwarding=False,
        enabled=True,
    )

    mode, created = item.save()
    assert mode in {"create", "update"}
    created_id_raw = created.get("id")
    assert created_id_raw is not None
    created_id = int(str(created_id_raw).strip())

    try:
        found = npmplus_client.list_streams().get(created_id)
        assert found is not None
        assert int(found.incoming_port) == incoming_port

        update_payload = npmplus_client.get_stream(
            created_id,
            expand=(EXPAND_CERTIFICATE, EXPAND_OWNER),
        )
        update = StreamItem.from_json(npmplus_client, update_payload)
        update.enabled = False
        update.save()

        wait_for_field(npmplus_client.list_streams, created_id, "enabled", False)

    finally:
        if created_id is not None:
            npmplus_client.delete_stream(created_id)
