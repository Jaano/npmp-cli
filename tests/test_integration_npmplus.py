from __future__ import annotations

import os
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any

import pytest

from npmp_cli.npmplus_api import NPMplusApi


def _bool_env(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


@pytest.mark.integration
@pytest.mark.skipif(
    not _bool_env("NPMP_RUN_INTEGRATION", False),
    reason="Set NPMP_RUN_INTEGRATION=1 to run integration tests",
)
def test_integration_schema_and_list_hosts() -> None:
    base_url = os.getenv("NPMP_BASE_URL")
    identity = os.getenv("NPMP_IDENTITY")
    secret = os.getenv("NPMP_SECRET")
    token = os.getenv("NPMP_TOKEN")
    verify_tls = _bool_env("NPMP_VERIFY_TLS", False)

    if not base_url:
        pytest.skip("NPMP_BASE_URL not set")

    with NPMplusApi(base_url=base_url, verify_tls=verify_tls) as client:
        if token:
            client.set_token_cookie(token)
        elif identity and secret:
            client.login(identity, secret)
        else:
            pytest.skip("Need either NPMP_TOKEN or both NPMP_IDENTITY and NPMP_SECRET")

        schema = client.get_schema()
        assert isinstance(schema, dict)
        assert "paths" in schema

        # Read-only smoke checks
        proxy_hosts = client.list_proxy_hosts()
        assert isinstance(proxy_hosts, list)

        redirection_hosts = client.list_redirection_hosts()
        assert isinstance(redirection_hosts, list)

        dead_hosts = client.list_dead_hosts()
        assert isinstance(dead_hosts, list)

        streams = client.list_streams()
        assert isinstance(streams, list)


def _domain_key(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    parts = [str(v).strip().lower() for v in value]
    parts = [p for p in parts if p]
    if not parts:
        return None
    return tuple(sorted(set(parts)))


def _find_proxy_host_by_domains(items: list[dict[str, object]], domains: tuple[str, ...]) -> dict[str, object] | None:
    for item in items:
        key = _domain_key(item.get("domain_names") or item.get("domainNames"))
        if key == domains:
            return item
    return None


def _find_proxy_host_by_id(items: list[dict[str, object]], host_id: int) -> dict[str, object] | None:
    for item in items:
        try:
            if int(str(item.get("id")).strip()) == host_id:
                return item
        except Exception:
            continue
    return None


def _schema_request_properties(schema: Mapping[str, Any], path: str, method: str) -> set[str]:
    paths = schema.get("paths")
    if not isinstance(paths, dict):
        return set()
    op = paths.get(path)
    if not isinstance(op, dict):
        return set()
    op_method = op.get(method.lower())
    if not isinstance(op_method, dict):
        return set()
    rb = op_method.get("requestBody")
    if not isinstance(rb, dict):
        return set()
    content = rb.get("content")
    if not isinstance(content, dict):
        return set()
    app_json = content.get("application/json")
    if not isinstance(app_json, dict):
        return set()
    s = app_json.get("schema")
    if not isinstance(s, dict):
        return set()
    props = s.get("properties")
    if not isinstance(props, dict):
        return set()
    return {str(k) for k in props.keys()}


def _schema_array_item_properties(schema: Mapping[str, Any], path: str, method: str, prop_name: str) -> set[str]:
    paths = schema.get("paths")
    if not isinstance(paths, dict):
        return set()
    op = paths.get(path)
    if not isinstance(op, dict):
        return set()
    op_method = op.get(method.lower())
    if not isinstance(op_method, dict):
        return set()
    rb = op_method.get("requestBody")
    if not isinstance(rb, dict):
        return set()
    content = rb.get("content")
    if not isinstance(content, dict):
        return set()
    app_json = content.get("application/json")
    if not isinstance(app_json, dict):
        return set()
    s = app_json.get("schema")
    if not isinstance(s, dict):
        return set()
    props = s.get("properties")
    if not isinstance(props, dict):
        return set()
    arr = props.get(prop_name)
    if not isinstance(arr, dict):
        return set()
    items = arr.get("items")
    if not isinstance(items, dict):
        return set()
    item_props = items.get("properties")
    if not isinstance(item_props, dict):
        return set()
    return {str(k) for k in item_props.keys()}


def _find_access_list_by_id(items: list[dict[str, object]], list_id: int) -> dict[str, object] | None:
    for item in items:
        try:
            if int(str(item.get("id")).strip()) == list_id:
                return item
        except Exception:
            continue
    return None


def _find_access_list_by_name(items: list[dict[str, object]], name: str) -> dict[str, object] | None:
    wanted = (name or "").strip().lower()
    for item in items:
        n = item.get("name") or item.get("title")
        if n is None:
            continue
        if str(n).strip().lower() == wanted:
            return item
    return None


def _wait_for_access_list_field(
    client: NPMplusApi,
    list_id: int,
    field: str,
    expected: object,
    *,
    attempts: int = 12,
    sleep_s: float = 0.3,
) -> dict[str, object]:
    for _ in range(attempts):
        items = client.list_access_lists(expand=["clients", "items"], query=None)
        found = _find_access_list_by_id(items, list_id)
        if found is not None and found.get(field) == expected:
            return found
        time.sleep(sleep_s)
    items = client.list_access_lists(expand=["clients", "items"], query=None)
    found = _find_access_list_by_id(items, list_id)
    assert found is not None
    return found


def _wait_for_proxy_host_field(
    client: NPMplusApi,
    host_id: int,
    field: str,
    expected: object,
    *,
    compare: Callable[[object, object], bool] | None = None,
    attempts: int = 12,
    sleep_s: float = 0.3,
) -> dict[str, object]:
    for _ in range(attempts):
        items = client.list_proxy_hosts(expand=[], query=None)
        found = _find_proxy_host_by_id(items, host_id)
        if found is not None:
            actual = found.get(field)
            if compare is not None:
                if compare(actual, expected):
                    return found
            else:
                if actual == expected:
                    return found
        time.sleep(sleep_s)
    items = client.list_proxy_hosts(expand=[], query=None)
    found = _find_proxy_host_by_id(items, host_id)
    assert found is not None
    return found


@pytest.mark.integration
@pytest.mark.skipif(
    not _bool_env("NPMP_RUN_INTEGRATION", False),
    reason="Set NPMP_RUN_INTEGRATION=1 to run integration tests",
)
def test_integration_proxy_host_crud_roundtrip() -> None:
    base_url = os.getenv("NPMP_BASE_URL")
    identity = os.getenv("NPMP_IDENTITY")
    secret = os.getenv("NPMP_SECRET")
    token = os.getenv("NPMP_TOKEN")
    verify_tls = _bool_env("NPMP_VERIFY_TLS", False)

    if not base_url:
        pytest.skip("NPMP_BASE_URL not set")

    suffix = uuid.uuid4().hex[:12]
    domains = (f"npmp-cli-it-{suffix}.invalid",)
    create_payload: dict[str, object] = {
        "domain_names": list(domains),
        "forward_host": "example.com",
        "forward_port": 80,
        "forward_scheme": "http",
        "enabled": True,
    }

    created_id: int | None = None
    with NPMplusApi(base_url=base_url, verify_tls=verify_tls) as client:
        if token:
            client.set_token_cookie(token)
        elif identity and secret:
            client.login(identity, secret)
        else:
            pytest.skip("Need either NPMP_TOKEN or both NPMP_IDENTITY and NPMP_SECRET")

        created = client.create_proxy_host(create_payload)  # type: ignore[arg-type]
        created_id_raw = created.get("id")
        assert created_id_raw is not None
        created_id = int(str(created_id_raw).strip())

        # Read back
        items = client.list_proxy_hosts(expand=[], query=None)
        found = _find_proxy_host_by_domains(items, domains)
        assert found is not None
        assert int(str(found.get("id")).strip()) == created_id

        schema = client.get_schema()
        assert isinstance(schema, dict)
        put_props = _schema_request_properties(schema, "/nginx/proxy-hosts/{hostID}", "put")
        assert put_props, "Schema did not expose writable PUT properties for proxy-hosts"

        ssl_fields = {"certificate_id", "ssl_forced", "http2_support", "hsts_enabled", "hsts_subdomains"}
        if put_props & ssl_fields:
            certs = client.list_certificates(expand=[], query=None)
            if not certs:
                pytest.skip("No certificates available on server; cannot test SSL-related proxy-host fields")
            cert_id_raw = certs[0].get("id")
            assert cert_id_raw is not None
            cert_id = int(str(cert_id_raw).strip())
        else:
            cert_id = None

        # Create an access list so we can exercise access_list_id
        access_list_id: int | None = None
        if "access_list_id" in put_props:
            al = client.create_access_list(
                {
                    "name": f"npmp-cli-it-al-{suffix}",
                    "satisfy_any": True,
                    "pass_auth": False,
                    "items": [],
                    "clients": [],
                }
            )
            al_id_raw = al.get("id")
            assert al_id_raw is not None
            access_list_id = int(str(al_id_raw).strip())

        new_domains = (f"npmp-cli-it2-{suffix}.invalid",)
        updates: list[tuple[str, object]] = []
        # Order matters for validity (set certificate before enabling SSL/HSTS/HTTP2).
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
            else:
                raise AssertionError(f"Unhandled writable field in test: {k}")

        assert updates, "No writable fields selected for modification"
        assert {k for k, _ in updates} == put_props & {k for k, _ in updates}, "Missing expected modifiable fields"

        # Modify all schema-writable fields and verify each.
        for field, value in updates:
            client.update_proxy_host(created_id, {field: value})
            if field == "domain_names":

                def _cmp_domains(actual: object, expected: object) -> bool:
                    return _domain_key(actual) == _domain_key(expected)

                found = _wait_for_proxy_host_field(client, created_id, field, value, compare=_cmp_domains)
            else:
                found = _wait_for_proxy_host_field(client, created_id, field, value)
            assert found is not None

        # Delete
        client.delete_proxy_host(created_id)

        # Verify deleted (retry a bit)
        for _ in range(10):
            items = client.list_proxy_hosts(expand=[], query=None)
            found = _find_proxy_host_by_id(items, created_id)
            if found is None:
                break
            time.sleep(0.3)
        assert _find_proxy_host_by_id(client.list_proxy_hosts(expand=[], query=None), created_id) is None


@pytest.mark.integration
@pytest.mark.skipif(
    not _bool_env("NPMP_RUN_INTEGRATION", False),
    reason="Set NPMP_RUN_INTEGRATION=1 to run integration tests",
)
def test_integration_access_list_crud_with_proxy_host_usage() -> None:
    base_url = os.getenv("NPMP_BASE_URL")
    identity = os.getenv("NPMP_IDENTITY")
    secret = os.getenv("NPMP_SECRET")
    token = os.getenv("NPMP_TOKEN")
    verify_tls = _bool_env("NPMP_VERIFY_TLS", False)

    if not base_url:
        pytest.skip("NPMP_BASE_URL not set")

    suffix = uuid.uuid4().hex[:12]
    access_list_name = f"npmp-cli-it-al-{suffix}"
    new_access_list_name = f"npmp-cli-it-al2-{suffix}"
    proxy_domains = (f"npmp-cli-it-alhost-{suffix}.invalid",)

    with NPMplusApi(base_url=base_url, verify_tls=verify_tls) as client:
        if token:
            client.set_token_cookie(token)
        elif identity and secret:
            client.login(identity, secret)
        else:
            pytest.skip("Need either NPMP_TOKEN or both NPMP_IDENTITY and NPMP_SECRET")

        schema = client.get_schema()
        assert isinstance(schema, dict)
        put_props = _schema_request_properties(schema, "/nginx/access-lists/{listID}", "put")
        assert put_props, "Schema did not expose writable PUT properties for access-lists"
        allowed_client_props = _schema_array_item_properties(schema, "/nginx/access-lists/{listID}", "put", "clients")

        create_payload: dict[str, object] = {
            "name": access_list_name,
            "satisfy_any": True,
            "pass_auth": False,
            "items": [],
            "clients": [],
        }
        created = client.create_access_list(create_payload)  # type: ignore[arg-type]
        created_id_raw = created.get("id")
        assert created_id_raw is not None
        access_list_id = int(str(created_id_raw).strip())

        # Verify created
        items = client.list_access_lists(expand=["clients", "items"], query=None)
        found = _find_access_list_by_id(items, access_list_id)
        assert found is not None
        assert (found.get("name") or found.get("title")) == access_list_name

        # Create a proxy host that uses this fresh access list
        proxy_payload: dict[str, object] = {
            "domain_names": list(proxy_domains),
            "forward_host": "example.com",
            "forward_port": 80,
            "forward_scheme": "http",
            "enabled": True,
            "access_list_id": access_list_id,
        }
        proxy_created = client.create_proxy_host(proxy_payload)  # type: ignore[arg-type]
        proxy_id_raw = proxy_created.get("id")
        assert proxy_id_raw is not None
        proxy_id = int(str(proxy_id_raw).strip())

        proxy_items = client.list_proxy_hosts(expand=["access_list"], query=None)
        proxy_found = _find_proxy_host_by_id(proxy_items, proxy_id)
        assert proxy_found is not None
        # Depending on expand behavior, access list may be id or expanded object.
        al_id = proxy_found.get("access_list_id")
        if al_id is not None:
            assert int(str(al_id).strip()) == access_list_id
        else:
            al_obj = proxy_found.get("access_list") or proxy_found.get("accessList")
            assert isinstance(al_obj, dict)
            assert (al_obj.get("name") or al_obj.get("title")) == access_list_name

        # Modify access list (name + booleans + clients)
        update: dict[str, object] = {}
        if "name" in put_props or "title" in put_props:
            update["name"] = new_access_list_name
        if "satisfy_any" in put_props:
            update["satisfy_any"] = False
        if "pass_auth" in put_props:
            update["pass_auth"] = True
        if "clients" in put_props:
            client_entry: dict[str, object] = {
                "address": "10.0.0.0/8",
                "directive": "allow",
                "meta": {},
            }
            if allowed_client_props:
                client_entry = {k: v for k, v in client_entry.items() if k in allowed_client_props}
            update["clients"] = [client_entry]
        if "items" in put_props:
            update["items"] = []
        if "meta" in put_props:
            update["meta"] = {}

        assert update, "No writable access-list fields were selected for update"
        client.update_access_list(access_list_id, update)  # type: ignore[arg-type]

        # Verify modifications
        if "name" in update:
            found = _wait_for_access_list_field(client, access_list_id, "name", new_access_list_name)
            assert found is not None
        if "satisfy_any" in update:
            found = _wait_for_access_list_field(client, access_list_id, "satisfy_any", False)
            assert found is not None
        if "pass_auth" in update:
            found = _wait_for_access_list_field(client, access_list_id, "pass_auth", True)
            assert found is not None
        if "clients" in update:
            items = client.list_access_lists(expand=["clients", "items"], query=None)
            found = _find_access_list_by_id(items, access_list_id)
            assert found is not None
            clients_val = found.get("clients")
            assert isinstance(clients_val, list)
            assert any(isinstance(c, dict) and c.get("address") == "10.0.0.0/8" for c in clients_val)

        # Delete proxy host first (it references the access list)
        client.delete_proxy_host(proxy_id)
        for _ in range(10):
            proxy_items = client.list_proxy_hosts(expand=[], query=None)
            if _find_proxy_host_by_id(proxy_items, proxy_id) is None:
                break
            time.sleep(0.3)
        assert _find_proxy_host_by_id(client.list_proxy_hosts(expand=[], query=None), proxy_id) is None

        # Delete access list
        client.delete_access_list(access_list_id)
        for _ in range(10):
            items = client.list_access_lists(expand=[], query=None)
            if _find_access_list_by_id(items, access_list_id) is None:
                break
            time.sleep(0.3)
        assert _find_access_list_by_id(client.list_access_lists(expand=[], query=None), access_list_id) is None
        assert _find_access_list_by_name(client.list_access_lists(expand=[], query=None), access_list_name) is None
