from __future__ import annotations

from typing import cast

import httpx
import pytest

from npmp_cli.models import Kind, ProxyHostItem
from npmp_cli.npmplus_api import NPMplusApi
from npmp_cli.npmplus_client import NPMplusClient
from tests.test_configuration import StubNPMplusClient

# ---------------------------------------------------------------------------
# Helpers for login() guard tests
# ---------------------------------------------------------------------------

def _make_api(handler: httpx.MockTransport) -> NPMplusApi:
    return NPMplusApi(base_url="http://npmplus.test", transport=handler, verify_tls=False)


def _mock_transport(*responses: httpx.Response) -> httpx.MockTransport:
    """Return a MockTransport that serves each response in order."""
    queue = list(responses)

    def _handler(request: httpx.Request) -> httpx.Response:
        return queue.pop(0)

    return httpx.MockTransport(_handler)


def _health_response(*, password: bool = True, oidc: bool = False) -> httpx.Response:
    body = {"status": "OK", "setup": True, "version": "0.0.0", "password": password, "oidc": oidc}
    return httpx.Response(200, json=body)


def _token_response() -> httpx.Response:
    return httpx.Response(200, json={"expires": "2099-01-01T00:00:00.000Z"})


def _error_response(status: int, message: str) -> httpx.Response:
    body = {"error": {"message": message, "code": status}}
    return httpx.Response(status, json=body)


# ---------------------------------------------------------------------------
# login() guard tests
# ---------------------------------------------------------------------------

def test_login_succeeds_when_password_enabled() -> None:
    transport = _mock_transport(_health_response(password=True), _token_response())
    api = _make_api(transport)
    result = api.login("user@example.com", "secret")
    assert "expires" in result


def test_login_raises_when_oidc_only() -> None:
    transport = _mock_transport(_health_response(password=False, oidc=True))
    api = _make_api(transport)
    with pytest.raises(PermissionError, match="OIDC"):
        api.login("user@example.com", "secret")


def test_login_raises_when_original_npm_detected() -> None:
    npm_health = httpx.Response(200, json={
        "status": "OK",
        "setup": True,
        "version": {"major": 2, "minor": 1, "revision": 0},
    })
    transport = _mock_transport(npm_health)
    api = _make_api(transport)
    with pytest.raises(PermissionError, match="original Nginx Proxy Manager"):
        api.login("user@example.com", "secret")


def test_login_raises_clear_2fa_error_on_401_with_2fa_message() -> None:
    transport = _mock_transport(
        _health_response(password=True),
        _error_response(401, "2FA code required"),
    )
    api = _make_api(transport)
    with pytest.raises(PermissionError, match="2FA"):
        api.login("user@example.com", "secret")


def test_login_raises_clear_2fa_error_on_401_with_otp_message() -> None:
    transport = _mock_transport(
        _health_response(password=True),
        _error_response(401, "Invalid OTP token"),
    )
    api = _make_api(transport)
    with pytest.raises(PermissionError, match="2FA"):
        api.login("user@example.com", "secret")


def test_login_raises_generic_error_on_401_without_2fa_message() -> None:
    transport = _mock_transport(
        _health_response(password=True),
        _error_response(401, "Invalid credentials"),
    )
    api = _make_api(transport)
    with pytest.raises(PermissionError, match=r"Login failed \(401\)"):
        api.login("user@example.com", "wrongpassword")


# ---------------------------------------------------------------------------
# _web_request retry-on-transport-error tests
# ---------------------------------------------------------------------------

def _counting_raising_transport(exc: Exception, *, fail_times: int, ok_response: httpx.Response) -> tuple[httpx.MockTransport, list[str]]:
    calls: list[str] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if len(calls) <= fail_times:
            raise exc
        return ok_response

    return httpx.MockTransport(_handler), calls


def test_web_request_retries_get_on_read_timeout() -> None:
    transport, calls = _counting_raising_transport(
        httpx.ReadTimeout("timed out"), fail_times=1, ok_response=httpx.Response(200, json={})
    )
    api = _make_api(transport)
    resp = api._web_request("GET", "nginx/proxy-hosts")
    assert resp.status_code == 200
    assert calls == ["GET", "GET"]


def test_web_request_does_not_retry_post_on_read_timeout() -> None:
    transport, calls = _counting_raising_transport(
        httpx.ReadTimeout("timed out"), fail_times=1, ok_response=httpx.Response(200, json={})
    )
    api = _make_api(transport)
    with pytest.raises(httpx.ReadTimeout):
        api._web_request("POST", "nginx/proxy-hosts", json={})
    assert calls == ["POST"]


def test_web_request_retries_post_on_connect_error() -> None:
    transport, calls = _counting_raising_transport(
        httpx.ConnectError("connection refused"), fail_times=1, ok_response=httpx.Response(200, json={})
    )
    api = _make_api(transport)
    resp = api._web_request("POST", "nginx/proxy-hosts", json={})
    assert resp.status_code == 200
    assert calls == ["POST", "POST"]


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
    assert payload["npmplus_access_list_ids"] == [456]
    assert payload["npmplus_access_list_type"] == "custom"
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
