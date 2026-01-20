from __future__ import annotations

import random
import time

import pytest

from npmp_cli.npmplus_client import (
    AccessListItem,
    DeadHostItem,
    NPMplusClient,
    ProxyHostItem,
    RedirectionHostItem,
    StreamItem,
)
from tests.conftest import (
    domain_key,
    find_item_by_domains,
    find_item_by_id,
    schema_array_item_properties,
    schema_request_properties,
    wait_for_field,
)

pytestmark = pytest.mark.integration


def test_schema_and_list_hosts(npmplus_client: NPMplusClient) -> None:
    schema = npmplus_client.get_schema()
    assert isinstance(schema, dict)
    assert "paths" in schema

    proxy_hosts = npmplus_client.list_proxy_hosts()
    assert isinstance(proxy_hosts, list)

    redirection_hosts = npmplus_client.list_redirection_hosts()
    assert isinstance(redirection_hosts, list)

    dead_hosts = npmplus_client.list_dead_hosts()
    assert isinstance(dead_hosts, list)

    streams = npmplus_client.list_streams()
    assert isinstance(streams, list)


def test_proxy_host_crud(npmplus_client: NPMplusClient, unique_suffix: str) -> None:
    domains = (f"npmp-cli-it-{unique_suffix}.invalid",)
    create_payload: dict[str, object] = {
        "domain_names": list(domains),
        "forward_host": "example.com",
        "forward_port": 80,
        "forward_scheme": "http",
        "enabled": True,
    }

    item = ProxyHostItem(data=dict(create_payload))  # type: ignore[arg-type]
    _mode, created = item.set(npmplus_client)
    created_id_raw = created.get("id")
    assert created_id_raw is not None
    created_id = int(str(created_id_raw).strip())

    try:
        items = npmplus_client.list_proxy_hosts()
        found = find_item_by_domains(items, domains)
        assert found is not None
        assert int(str(found.get("id")).strip()) == created_id

        schema = npmplus_client.get_schema()
        assert isinstance(schema, dict)
        put_props = schema_request_properties(schema, "/nginx/proxy-hosts/{hostID}", "put")
        assert put_props

        ssl_fields = {"certificate_id", "ssl_forced", "http2_support", "hsts_enabled", "hsts_subdomains"}
        cert_id = None
        if put_props & ssl_fields:
            certs = npmplus_client.list_certificates()
            if not certs:
                pytest.skip("No certificates available on server")
            cert_id_raw = next(iter(certs.values())).get("id")
            assert cert_id_raw is not None
            cert_id = int(str(cert_id_raw).strip())

        access_list_id: int | None = None
        if "access_list_id" in put_props:
            al_item = AccessListItem(
                data={
                    "name": f"npmp-cli-it-al-{unique_suffix}",
                    "satisfy_any": True,
                    "pass_auth": False,
                    "items": [],
                    "clients": [],
                }
            )
            _mode, al = al_item.set(npmplus_client)
            al_id_raw = al.get("id")
            assert al_id_raw is not None
            access_list_id = int(str(al_id_raw).strip())

        new_domains = (f"npmp-cli-it2-{unique_suffix}.invalid",)
        updates: list[tuple[str, object]] = []
        for k in (
            "enabled",
            "forward_host",
            "forward_port",
            "forward_scheme",
            "allow_websocket_upgrade",
            "block_exploits",
            "caching_enabled",
            "advanced_config",
            "meta",
            "locations",
            "access_list_id",
            "certificate_id",
            "ssl_forced",
            "http2_support",
            "hsts_enabled",
            "hsts_subdomains",
            "domain_names",
        ):
            if k not in put_props:
                continue
            if k == "enabled":
                updates.append((k, False))
            elif k == "forward_host":
                updates.append((k, "example.org"))
            elif k == "forward_port":
                updates.append((k, 81))
            elif k == "forward_scheme":
                updates.append((k, "https"))
            elif k in {"allow_websocket_upgrade", "block_exploits", "caching_enabled"}:
                updates.append((k, True))
            elif k == "advanced_config":
                updates.append((k, "# npmp-cli integration test\nproxy_set_header X-NPMP-IT 1;\n"))
            elif k == "meta":
                updates.append((k, {}))
            elif k == "locations":
                updates.append((k, []))
            elif k == "access_list_id":
                assert access_list_id is not None
                updates.append((k, access_list_id))
            elif k == "certificate_id":
                assert cert_id is not None
                updates.append((k, cert_id))
            elif k in {"ssl_forced", "http2_support", "hsts_enabled", "hsts_subdomains"}:
                updates.append((k, True))
            elif k == "domain_names":
                updates.append((k, list(new_domains)))

        assert updates

        for field, value in updates:
            item = ProxyHostItem(data={field: value, "id": created_id})
            item.set(npmplus_client)
            if field == "domain_names":
                found = wait_for_field(
                    npmplus_client.list_proxy_hosts,
                    created_id,
                    field,
                    value,
                    compare=lambda a, e: domain_key(a) == domain_key(e),
                )
            else:
                found = wait_for_field(npmplus_client.list_proxy_hosts, created_id, field, value)
            assert found is not None
    finally:
        npmplus_client.delete_proxy_host(created_id)

    for _ in range(10):
        items = npmplus_client.list_proxy_hosts()
        found = find_item_by_id(items, created_id)
        if found is None:
            break
        time.sleep(0.3)
    assert find_item_by_id(npmplus_client.list_proxy_hosts(), created_id) is None


def test_access_list_crud_with_proxy_host(npmplus_client: NPMplusClient, unique_suffix: str) -> None:
    access_list_name = f"npmp-cli-it-al-{unique_suffix}"
    new_access_list_name = f"npmp-cli-it-al2-{unique_suffix}"
    proxy_domains = (f"npmp-cli-it-alhost-{unique_suffix}.invalid",)

    schema = npmplus_client.get_schema()
    assert isinstance(schema, dict)
    put_props = schema_request_properties(schema, "/nginx/access-lists/{listID}", "put")
    assert put_props
    allowed_client_props = schema_array_item_properties(schema, "/nginx/access-lists/{listID}", "put", "clients")

    create_payload: dict[str, object] = {
        "name": access_list_name,
        "satisfy_any": True,
        "pass_auth": False,
        "items": [],
        "clients": [],
    }
    item = AccessListItem(data=dict(create_payload))  # type: ignore[arg-type]
    _mode, created = item.set(npmplus_client)
    created_id_raw = created.get("id")
    assert created_id_raw is not None
    access_list_id = int(str(created_id_raw).strip())

    proxy_id: int | None = None
    try:
        items = npmplus_client.list_access_lists()
        found = find_item_by_id(items, access_list_id)
        assert found is not None
        assert (found.get("name") or found.get("title")) == access_list_name

        proxy_payload: dict[str, object] = {
            "domain_names": list(proxy_domains),
            "forward_host": "example.com",
            "forward_port": 80,
            "forward_scheme": "http",
            "enabled": True,
            "access_list_id": access_list_id,
        }
        proxy_item = ProxyHostItem(data=dict(proxy_payload))  # type: ignore[arg-type]
        _mode, proxy_created = proxy_item.set(npmplus_client)
        proxy_id_raw = proxy_created.get("id")
        assert proxy_id_raw is not None
        proxy_id = int(str(proxy_id_raw).strip())

        proxy_items = npmplus_client.list_proxy_hosts()
        proxy_found = find_item_by_id(proxy_items, proxy_id)
        assert proxy_found is not None

        update: dict[str, object] = {}
        if "name" in put_props or "title" in put_props:
            update["name"] = new_access_list_name
        if "satisfy_any" in put_props:
            update["satisfy_any"] = False
        if "pass_auth" in put_props:
            update["pass_auth"] = True
        if "clients" in put_props:
            client_entry: dict[str, object] = {"address": "10.0.0.0/8", "directive": "allow", "meta": {}}
            if allowed_client_props:
                client_entry = {k: v for k, v in client_entry.items() if k in allowed_client_props}
            update["clients"] = [client_entry]
        if "items" in put_props:
            update["items"] = []
        if "meta" in put_props:
            update["meta"] = {}

        assert update
        update_item = AccessListItem(dict(update))  # type: ignore[arg-type]
        update_item["id"] = access_list_id
        update_item.set(npmplus_client)

        if "name" in update:
            found = wait_for_field(npmplus_client.list_access_lists, access_list_id, "name", new_access_list_name)
            assert found is not None
    finally:
        if proxy_id is not None:
            npmplus_client.delete_proxy_host(proxy_id)
            for _ in range(10):
                proxy_items = npmplus_client.list_proxy_hosts()
                if find_item_by_id(proxy_items, proxy_id) is None:
                    break
                time.sleep(0.3)
        npmplus_client.delete_access_list(access_list_id)

    for _ in range(10):
        items = npmplus_client.list_access_lists()
        if find_item_by_id(items, access_list_id) is None:
            break
        time.sleep(0.3)
    assert find_item_by_id(npmplus_client.list_access_lists(), access_list_id) is None


def test_redirection_host_crud(npmplus_client: NPMplusClient, unique_suffix: str) -> None:
    domains = (f"npmp-cli-redir-{unique_suffix}.invalid",)

    schema = npmplus_client.get_schema()
    post_props = schema_request_properties(schema, "/nginx/redirection-hosts", "post")

    create_payload: dict[str, object] = {
        "domain_names": list(domains),
        "forward_http_code": 301,
        "forward_scheme": "https",
        "forward_domain_name": "example.com",
    }
    if "preserve_path" in post_props:
        create_payload["preserve_path"] = True
    if "enabled" in post_props:
        create_payload["enabled"] = True

    try:
        item = RedirectionHostItem(data=dict(create_payload))  # type: ignore[arg-type]
        _mode, created = item.set(npmplus_client)
    except RuntimeError as e:
        if "500" in str(e):
            pytest.skip(f"Server returned 500 for redirection-hosts: {e}")
        raise

    created_id_raw = created.get("id")
    assert created_id_raw is not None
    created_id = int(str(created_id_raw).strip())

    try:
        items = npmplus_client.list_redirection_hosts()
        found = find_item_by_domains(items, domains)
        assert found is not None
        assert int(str(found.get("id")).strip()) == created_id

        put_props = schema_request_properties(schema, "/nginx/redirection-hosts/{hostID}", "put")
        assert put_props

        updates: list[tuple[str, object]] = []
        for k in (
            "enabled",
            "domain_names",
            "forward_scheme",
            "forward_domain_name",
            "preserve_path",
            "block_exploits",
            "advanced_config",
            "meta",
        ):
            if k not in put_props:
                continue
            if k == "enabled":
                updates.append((k, False))
            elif k == "domain_names":
                updates.append((k, [f"npmp-cli-redir2-{unique_suffix}.invalid"]))
            elif k == "forward_scheme":
                updates.append((k, "http"))
            elif k == "forward_domain_name":
                updates.append((k, "example.org"))
            elif k == "preserve_path":
                updates.append((k, False))
            elif k == "block_exploits":
                updates.append((k, True))
            elif k == "advanced_config":
                updates.append((k, "# test\n"))
            elif k == "meta":
                updates.append((k, {}))

        assert updates

        for field, value in updates:
            item = RedirectionHostItem(data={field: value, "id": created_id})
            item.set(npmplus_client)
            if field == "domain_names":
                found = wait_for_field(
                    npmplus_client.list_redirection_hosts,
                    created_id,
                    field,
                    value,
                    compare=lambda a, e: domain_key(a) == domain_key(e),
                )
            else:
                found = wait_for_field(npmplus_client.list_redirection_hosts, created_id, field, value)
            assert found is not None
    finally:
        npmplus_client.delete_redirection_host(created_id)

    for _ in range(10):
        items = npmplus_client.list_redirection_hosts()
        if find_item_by_id(items, created_id) is None:
            break
        time.sleep(0.3)
    assert find_item_by_id(npmplus_client.list_redirection_hosts(), created_id) is None


def test_dead_host_crud(npmplus_client: NPMplusClient, unique_suffix: str) -> None:
    domains = (f"npmp-cli-dead-{unique_suffix}.invalid",)

    schema = npmplus_client.get_schema()
    post_props = schema_request_properties(schema, "/nginx/dead-hosts", "post")

    create_payload: dict[str, object] = {"domain_names": list(domains)}
    if "enabled" in post_props:
        create_payload["enabled"] = True

    item = DeadHostItem(data=dict(create_payload))  # type: ignore[arg-type]
    _mode, created = item.set(npmplus_client)
    created_id_raw = created.get("id")
    assert created_id_raw is not None
    created_id = int(str(created_id_raw).strip())

    try:
        items = npmplus_client.list_dead_hosts()
        found = find_item_by_domains(items, domains)
        assert found is not None
        assert int(str(found.get("id")).strip()) == created_id

        put_props = schema_request_properties(schema, "/nginx/dead-hosts/{hostID}", "put")
        assert put_props

        ssl_fields = {"certificate_id", "ssl_forced", "http2_support", "hsts_enabled", "hsts_subdomains"}
        cert_id = None
        if put_props & ssl_fields:
            certs = npmplus_client.list_certificates()
            if certs:
                cert_id_raw = next(iter(certs.values())).get("id")
                if cert_id_raw is not None:
                    cert_id = int(str(cert_id_raw).strip())

        updates: list[tuple[str, object]] = []
        for k in (
            "enabled",
            "domain_names",
            "certificate_id",
            "ssl_forced",
            "http2_support",
            "hsts_enabled",
            "hsts_subdomains",
            "advanced_config",
            "meta",
        ):
            if k not in put_props:
                continue
            if k == "enabled":
                updates.append((k, False))
            elif k == "domain_names":
                updates.append((k, [f"npmp-cli-dead2-{unique_suffix}.invalid"]))
            elif k == "certificate_id" and cert_id is not None:
                updates.append((k, cert_id))
            elif k in {"ssl_forced", "http2_support", "hsts_enabled", "hsts_subdomains"} and cert_id is not None:
                updates.append((k, True))
            elif k == "advanced_config":
                updates.append((k, "# test\n"))
            elif k == "meta":
                updates.append((k, {}))

        assert updates

        for field, value in updates:
            item = DeadHostItem(data={field: value, "id": created_id})
            item.set(npmplus_client)
            if field == "domain_names":
                found = wait_for_field(
                    npmplus_client.list_dead_hosts,
                    created_id,
                    field,
                    value,
                    compare=lambda a, e: domain_key(a) == domain_key(e),
                )
            else:
                found = wait_for_field(npmplus_client.list_dead_hosts, created_id, field, value)
            assert found is not None
    finally:
        npmplus_client.delete_dead_host(created_id)

    for _ in range(10):
        items = npmplus_client.list_dead_hosts()
        if find_item_by_id(items, created_id) is None:
            break
        time.sleep(0.3)
    assert find_item_by_id(npmplus_client.list_dead_hosts(), created_id) is None


def test_stream_crud(npmplus_client: NPMplusClient, unique_suffix: str) -> None:
    incoming_port = random.randint(40000, 60000)

    schema = npmplus_client.get_schema()
    post_props = schema_request_properties(schema, "/nginx/streams", "post")

    create_payload: dict[str, object] = {
        "incoming_port": incoming_port,
        "forwarding_host": "example.com",
        "forwarding_port": 80,
    }
    if "tcp_forwarding" in post_props:
        create_payload["tcp_forwarding"] = True
    if "udp_forwarding" in post_props:
        create_payload["udp_forwarding"] = False
    if "enabled" in post_props:
        create_payload["enabled"] = True

    existing_streams = npmplus_client.list_streams()
    for item in existing_streams.values():
        if item.get("incoming_port") == incoming_port:
            pytest.skip(f"Port {incoming_port} already in use")

    stream_item = StreamItem(data=dict(create_payload))  # type: ignore[arg-type]
    _mode, created = stream_item.set(npmplus_client)
    created_id_raw = created.get("id")
    assert created_id_raw is not None
    created_id = int(str(created_id_raw).strip())

    try:
        items = npmplus_client.list_streams()
        found = find_item_by_id(items, created_id)
        assert found is not None

        put_props = schema_request_properties(schema, "/nginx/streams/{streamID}", "put")
        assert put_props

        updates: list[tuple[str, object]] = []
        for k in ("enabled", "forwarding_host", "forwarding_port", "tcp_forwarding", "udp_forwarding", "meta"):
            if k not in put_props:
                continue
            if k == "enabled":
                updates.append((k, False))
            elif k == "forwarding_host":
                updates.append((k, "example.org"))
            elif k == "forwarding_port":
                updates.append((k, 81))
            elif k == "tcp_forwarding":
                updates.append((k, False))
            elif k == "udp_forwarding":
                updates.append((k, True))
            elif k == "meta":
                updates.append((k, {}))

        assert updates

        for field, value in updates:
            item = StreamItem(data={field: value, "id": created_id})
            item.set(npmplus_client)
            found = wait_for_field(npmplus_client.list_streams, created_id, field, value)
            assert found is not None
    finally:
        npmplus_client.delete_stream(created_id)

    for _ in range(10):
        items = npmplus_client.list_streams()
        if find_item_by_id(items, created_id) is None:
            break
        time.sleep(0.3)
    assert find_item_by_id(npmplus_client.list_streams(), created_id) is None


def test_certificate_operations(npmplus_client: NPMplusClient) -> None:
    certs = npmplus_client.list_certificates()
    assert isinstance(certs, dict)

    dns_providers = npmplus_client.list_certificate_dns_providers()
    assert isinstance(dns_providers, list)

    if certs:
        cert = next(iter(certs.values()))
        cert_id_raw = cert.get("id")
        assert cert_id_raw is not None
        cert_id = int(str(cert_id_raw).strip())

        fetched = certs.get(cert_id)
        assert fetched is not None
        assert fetched.get("id") == cert_id

        resp = npmplus_client.download_certificate(cert_id)
        assert resp.status_code == 200
