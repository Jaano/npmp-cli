from __future__ import annotations

import os
import time
import uuid
from collections.abc import Callable, Generator, Mapping
from typing import Any

import pytest

from npmp_cli.npmplus_client import NPMplusClient


@pytest.fixture(scope="session", autouse=True)
def _set_env_test_file() -> None:
    if "NPMP_ENV_FILE" not in os.environ:
        os.environ["NPMP_ENV_FILE"] = ".env.test"


def bool_env(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


@pytest.fixture(scope="session")
def npmp_base_url() -> str:
    base_url = os.getenv("NPMP_BASE_URL")
    if not base_url:
        pytest.skip("NPMP_BASE_URL not set")
    return base_url


@pytest.fixture(scope="session")
def npmp_verify_tls() -> bool:
    return bool_env("NPMP_VERIFY_TLS", False)


@pytest.fixture(scope="session")
def npmplus_client(npmp_base_url: str, npmp_verify_tls: bool) -> Generator[NPMplusClient, None, None]:
    token = os.getenv("NPMP_TOKEN")
    identity = os.getenv("NPMP_IDENTITY")
    secret = os.getenv("NPMP_SECRET")

    if not token and not (identity and secret):
        pytest.skip("Need either NPMP_TOKEN or both NPMP_IDENTITY and NPMP_SECRET")

    with NPMplusClient(base_url=npmp_base_url, verify_tls=npmp_verify_tls) as client:
        if token:
            client.set_token_cookie(token)
        else:
            assert identity is not None and secret is not None
            client.login(identity, secret)
        yield client


@pytest.fixture
def unique_suffix() -> str:
    return uuid.uuid4().hex[:12]


@pytest.fixture
def unique_invalid_domain(unique_suffix: str) -> str:
    return f"npmp-cli-it-{unique_suffix}.invalid"


def docker_available() -> bool:
    try:
        import docker

        client = docker.from_env()
        client.ping()
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def require_docker() -> bool:
    if not docker_available():
        pytest.skip("Docker daemon not available")
    return True


def domain_key(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    parts = [str(v).strip().lower() for v in value]
    parts = [p for p in parts if p]
    if not parts:
        return None
    return tuple(sorted(set(parts)))


def find_item_by_domains(
    items: Mapping[int, Mapping[str, object]], domains: tuple[str, ...]
) -> Mapping[str, object] | None:
    for item in items.values():
        key = domain_key(item.get("domain_names") or item.get("domainNames"))
        if key == domains:
            return item
    return None


def find_item_by_id(items: Mapping[int, Mapping[str, object]], item_id: int) -> Mapping[str, object] | None:
    for item in items.values():
        try:
            if int(str(item.get("id")).strip()) == item_id:
                return item
        except Exception:
            continue
    return None


def find_item_by_name(items: Mapping[int, Mapping[str, object]], name: str) -> Mapping[str, object] | None:
    wanted = (name or "").strip().lower()
    for item in items.values():
        n = item.get("name") or item.get("title")
        if n is None:
            continue
        if str(n).strip().lower() == wanted:
            return item
    return None


def schema_request_properties(schema: Mapping[str, Any], path: str, method: str) -> set[str]:
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


def schema_array_item_properties(schema: Mapping[str, Any], path: str, method: str, prop_name: str) -> set[str]:
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


def wait_for_field(
    list_func: Callable[..., Mapping[int, Mapping[str, object]]],
    item_id: int,
    field: str,
    expected: object,
    *,
    compare: Callable[[object, object], bool] | None = None,
    attempts: int = 12,
    sleep_s: float = 0.3,
) -> Mapping[str, object]:
    for _ in range(attempts):
        items_map = list_func()
        found = find_item_by_id(items_map, item_id)
        if found is not None:
            actual = found.get(field)
            if compare is not None:
                if compare(actual, expected):
                    return found
            elif actual == expected:
                return found
        time.sleep(sleep_s)
    items_map = list_func()
    found = find_item_by_id(items_map, item_id)
    assert found is not None
    return found
