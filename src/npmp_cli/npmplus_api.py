from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import httpx

from .configmanager import ConfigManager

logger = ConfigManager.get_logger(__name__)


EXPAND_PERMISSIONS = "permissions"
EXPAND_USER = "user"
EXPAND_CERTIFICATE = "certificate"
EXPAND_OWNER = "owner"
EXPAND_ITEMS = "items"
EXPAND_CLIENTS = "clients"
EXPAND_ACCESS_LIST = "access_list"
EXPAND_PROXY_HOSTS = "proxy_hosts"
EXPAND_REDIRECTION_HOSTS = "redirection_hosts"
EXPAND_DEAD_HOSTS = "dead_hosts"
EXPAND_STREAMS = "streams"


@dataclass
class NPMplusApi:
    """NPMplus API wrapper.

    NPMplus auth is cookie-based: `POST /api/tokens` sets an httpOnly `token` cookie.

    Endpoint coverage is based on the NPMplus backend routes included in this repo under
    `NPMplus/backend/routes/*`.
    """

    base_url: str
    verify_tls: bool = True
    timeout_s: float = 30.0
    transport: httpx.BaseTransport | None = None
    retry_count: int = 3
    readonly: bool = False

    def __post_init__(self) -> None:
        url = self.base_url.strip()
        if not url:
            raise ValueError("base_url is required")
        url = url.rstrip("/")
        if not url.endswith("/api"):
            url = url + "/api"
        self.base_url = url
        if self.retry_count < 0:
            raise ValueError("retry_count must be >= 0")
        logger.debug(
            "Initializing NPMplusApi base_url=%s verify_tls=%s timeout_s=%s",
            self.base_url,
            self.verify_tls,
            self.timeout_s,
        )
        self._request_seq = 0

        def _log_request(request: httpx.Request) -> None:
            if not logger.isEnabledFor(10):
                return
            self._request_seq += 1
            req_id = self._request_seq
            request.extensions["npmp.req_id"] = req_id
            request.extensions["npmp.start"] = time.perf_counter()

            body_len: int | None
            try:
                body_len = len(request.content) if request.content is not None else 0
            except Exception:
                body_len = None

            logger.debug(
                "HTTP -> #%s %s %s headers=%s body_bytes=%s",
                req_id,
                request.method,
                request.url,
                dict(request.headers),
                body_len,
            )

        def _log_response(response: httpx.Response) -> None:
            if not logger.isEnabledFor(10):
                return
            req = response.request
            req_id = req.extensions.get("npmp.req_id")
            start = req.extensions.get("npmp.start")
            ms: float | None = None
            if isinstance(start, (int, float)):
                ms = (time.perf_counter() - float(start)) * 1000.0

            ct = response.headers.get("content-type")
            cl = response.headers.get("content-length")
            logger.debug(
                "HTTP <- #%s %s %s status=%s elapsed_ms=%s content_type=%s content_length=%s",
                req_id,
                req.method,
                req.url,
                response.status_code,
                f"{ms:.1f}" if ms is not None else None,
                ct,
                cl,
            )

        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout_s,
            verify=self.verify_tls,
            headers={"accept": "application/json"},
            transport=self.transport,
            event_hooks={"request": [_log_request], "response": [_log_response]},
        )

    def _web_request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Execute an HTTP request with retry-on-disconnect behavior.

        Retries are intended for transient disconnect/transport errors.
        Total attempts = retry_count + 1.
        """
        attempts = self.retry_count + 1
        for attempt in range(1, attempts + 1):
            try:
                return self._client.request(method, path, **kwargs)
            except httpx.TransportError as e:
                if attempt >= attempts:
                    raise
                # Small backoff; keep it short to avoid long CLI stalls.
                time.sleep(min(0.25 * attempt, 2.0))
                logger.debug(
                    "HTTP transport error on %s %s (attempt %s/%s): %s; retrying",
                    method,
                    path,
                    attempt,
                    attempts,
                    str(e),
                )
        raise RuntimeError("request failed")

    def _web_close(self) -> None:
        self._client.close()

    def __enter__(self) -> NPMplusApi:
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:  # type: ignore[no-untyped-def]
        self._web_close()

    def set_token_cookie(self, token: str) -> None:
        if not token:
            raise ValueError("token is required")
        logger.debug("Setting token cookie for API base_url=%s", self.base_url)
        base = httpx.URL(self.base_url)
        self._client.cookies.set(
            "token",
            token,
            domain=base.host,
            path="/api",
        )

    def login(self, identity: str, secret: str) -> dict[str, Any]:
        """Login via `/tokens`.

        Returns the JSON body (typically `{"expires": <unix>}`) and stores the cookie.
        """
        if not identity:
            raise ValueError("identity is required")
        if not secret:
            raise ValueError("secret is required")
        logger.info("Logging in to NPMplus")
        resp = self._web_request("POST", "tokens", json={"identity": identity, "secret": secret})
        if resp.status_code in (401, 403):
            logger.warning("Login failed with status_code=%s", resp.status_code)
            raise PermissionError(f"Login failed ({resp.status_code})")
        self._raise_for_status(resp)
        logger.debug("Login succeeded")
        return resp.json()

    def refresh_token(self, *, expiry: str | None = None, scope: str | None = None) -> dict[str, Any]:
        """Refresh an existing token (or request a scoped one).

        Maps to: `GET /api/tokens?expiry=...&scope=...`
        """
        logger.debug("Refreshing NPMplus token")
        params: dict[str, Any] = {}
        if expiry is not None:
            params["expiry"] = expiry
        if scope is not None:
            params["scope"] = scope
        resp = self._web_request("GET", "tokens", params=params if params else None)
        if resp.status_code in (401, 403):
            logger.warning("Token refresh failed with status_code=%s", resp.status_code)
            raise PermissionError(f"Not authenticated ({resp.status_code})")
        self._raise_for_status(resp)
        return resp.json()

    def logout(self) -> bool:
        """Logout by clearing token cookie on the server.

        Maps to: `DELETE /api/tokens`
        """
        resp = self._web_request("DELETE", "tokens")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for DELETE tokens")
        self._raise_for_status(resp)
        try:
            data = resp.json()
        except Exception:
            return True
        return bool(data)

    def get_health(self) -> dict[str, Any]:
        """Health check.

        Maps to: `GET /api` (base_url already ends with `/api`)
        """
        resp = self._web_request("GET", "")
        self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError(f"Expected object response from GET /api, got {type(data).__name__}")
        return data

    def get_schema(self) -> dict[str, Any]:
        logger.debug("Fetching /schema")
        resp = self._web_request("GET", "schema")
        self._raise_for_status(resp)
        return resp.json()

    # --- Users ---
    def list_users(self, *, expand: Sequence[str] | None = None, query: str | None = None) -> list[dict[str, Any]]:
        return self._get_list("users", expand=expand, query=query)

    def get_user(self, user_id: int | str, *, expand: Sequence[str] | None = None) -> dict[str, Any]:
        return self._get_object(f"users/{user_id}", expand=expand)

    def get_current_user(self, *, expand: Sequence[str] | None = None) -> dict[str, Any]:
        return self._get_object("users/me", expand=expand)

    def create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] create_user payload=%s", payload)
            return {"id": -1, **payload}
        return self._form_json("post", "users", payload)

    def update_user(self, user_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] update_user id=%s payload=%s", user_id, payload)
            return {"id": user_id, **payload}
        return self._form_json("put", f"users/{user_id}", payload)

    def delete_user(self, user_id: int | str) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] delete_user id=%s", user_id)
            return {"id": user_id}
        return self._delete_object(f"users/{user_id}")

    def delete_all_users_ci_only(self) -> bool:
        """Delete ALL users.

        This is only enabled by the server in CI/debug mode.
        Maps to: `DELETE /api/users`
        """
        if self.readonly:
            logger.info("[dry-run] delete_all_users_ci_only")
            return True
        resp = self._web_request("DELETE", "users")
        self._raise_for_status(resp)
        try:
            data = resp.json()
        except Exception:
            return True
        return bool(data)

    def set_user_password(self, user_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] set_user_password id=%s", user_id)
            return {"id": user_id}
        return self._form_json("put", f"users/{user_id}/auth", payload)

    def set_user_permissions(self, user_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] set_user_permissions id=%s payload=%s", user_id, payload)
            return {"id": user_id, **payload}
        return self._form_json("put", f"users/{user_id}/permissions", payload)

    def login_as_user(self, user_id: int | str) -> dict[str, Any]:
        return self._post_object(f"users/{user_id}/login")

    # --- Audit Log ---
    def list_audit_log(self, *, expand: Sequence[str] | None = None, query: str | None = None) -> list[dict[str, Any]]:
        return self._get_list("audit-log", expand=expand, query=query)

    def get_audit_event(self, event_id: int | str, *, expand: Sequence[str] | None = None) -> dict[str, Any]:
        return self._get_object(f"audit-log/{event_id}", expand=expand)

    # --- Reports ---
    def get_hosts_report(self) -> dict[str, Any]:
        return self._get_object("reports/hosts", expand=None)

    # --- Settings ---
    def list_settings(self) -> Any:
        resp = self._web_request("GET", "settings")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for GET settings")
        self._raise_for_status(resp)
        return resp.json()

    def get_setting(self, setting_id: str) -> dict[str, Any]:
        if not setting_id or not str(setting_id).strip():
            raise ValueError("setting_id is required")
        return self._get_object(f"settings/{setting_id}", expand=None)

    def _update_setting(self, setting_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not setting_id or not str(setting_id).strip():
            raise ValueError("setting_id is required")
        return self._form_json("put", f"settings/{setting_id}", payload)

    def set_setting(self, setting_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._update_setting(setting_id, payload)

    # --- Version ---
    def check_version(self) -> dict[str, Any]:
        return self._get_object("version/check", expand=None)

    def list_proxy_hosts(
        self, *, expand: Sequence[str] | None = None, query: str | None = None
    ) -> list[dict[str, Any]]:
        return self._get_list("nginx/proxy-hosts", expand=expand, query=query)

    def get_proxy_host(
        self, host_id: int | str, *, expand: Sequence[str] | None = None
    ) -> dict[str, Any]:
        return self._get_object(f"nginx/proxy-hosts/{host_id}", expand=expand)

    def list_redirection_hosts(
        self, *, expand: Sequence[str] | None = None, query: str | None = None
    ) -> list[dict[str, Any]]:
        return self._get_list("nginx/redirection-hosts", expand=expand, query=query)

    def get_redirection_host(
        self, host_id: int | str, *, expand: Sequence[str] | None = None
    ) -> dict[str, Any]:
        return self._get_object(f"nginx/redirection-hosts/{host_id}", expand=expand)

    def list_dead_hosts(self, *, expand: Sequence[str] | None = None, query: str | None = None) -> list[dict[str, Any]]:
        return self._get_list("nginx/dead-hosts", expand=expand, query=query)

    def get_dead_host(
        self, host_id: int | str, *, expand: Sequence[str] | None = None
    ) -> dict[str, Any]:
        return self._get_object(f"nginx/dead-hosts/{host_id}", expand=expand)

    def list_streams(self, *, expand: Sequence[str] | None = None, query: str | None = None) -> list[dict[str, Any]]:
        return self._get_list("nginx/streams", expand=expand, query=query)

    def get_stream(
        self, stream_id: int | str, *, expand: Sequence[str] | None = None
    ) -> dict[str, Any]:
        return self._get_object(f"nginx/streams/{stream_id}", expand=expand)

    def list_access_lists(
        self, *, expand: Sequence[str] | None = None, query: str | None = None
    ) -> list[dict[str, Any]]:
        return self._get_list("nginx/access-lists", expand=expand, query=query)

    def get_access_list(
        self, list_id: int | str, *, expand: Sequence[str] | None = None
    ) -> dict[str, Any]:
        return self._get_object(f"nginx/access-lists/{list_id}", expand=expand)

    def list_certificates(
        self, *, expand: Sequence[str] | None = None, query: str | None = None
    ) -> list[dict[str, Any]]:
        return self._get_list("nginx/certificates", expand=expand, query=query)

    def get_certificate(
        self, certificate_id: int | str, *, expand: Sequence[str] | None = None
    ) -> dict[str, Any]:
        return self._get_object(f"nginx/certificates/{certificate_id}", expand=expand)

    def create_certificate(self, payload: dict[str, Any], *, timeout_s: float = 900.0) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] create_certificate payload=%s", payload)
            return {"id": -1, **payload}
        return self._form_json("post", "nginx/certificates", payload, timeout_s=timeout_s)

    def delete_certificate(self, certificate_id: int | str) -> None:
        if self.readonly:
            logger.info("[dry-run] delete_certificate id=%s", certificate_id)
            return
        logger.debug("DELETE nginx/certificates/%s", certificate_id)
        resp = self._web_request("DELETE", f"nginx/certificates/{certificate_id}")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for DELETE nginx/certificates/{certificate_id}")
        self._raise_for_status(resp)

    def list_certificate_dns_providers(self) -> list[dict[str, Any]]:
        return self._get_list("nginx/certificates/dns-providers", expand=None, query=None)

    def test_certificate_http_challenge(
        self, payload: dict[str, Any], *, timeout_s: float = 60.0
    ) -> dict[str, Any]:
        return self._form_json("post", "nginx/certificates/test-http", payload, timeout_s=timeout_s)

    def validate_certificate_files(self, files: dict[str, Any]) -> dict[str, Any]:
        """Validate a certificate/key/chain upload.

        Maps to: `POST /api/nginx/certificates/validate` (multipart form upload)
        """
        resp = self._web_request("POST", "nginx/certificates/validate", files=files)
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for POST nginx/certificates/validate")
        self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError(
                f"Expected object response from POST nginx/certificates/validate, got {type(data).__name__}"
            )
        return data

    def upload_certificate_files(self, certificate_id: int | str, files: dict[str, Any]) -> dict[str, Any]:
        """Upload certificate files.

        Maps to: `POST /api/nginx/certificates/{certificate_id}/upload` (multipart)
        """
        if self.readonly:
            logger.info("[dry-run] upload_certificate_files id=%s", certificate_id)
            return {"id": certificate_id}
        resp = self._web_request("POST", f"nginx/certificates/{certificate_id}/upload", files=files)
        if resp.status_code in (401, 403):
            raise PermissionError(
                f"Unauthorized ({resp.status_code}) for POST nginx/certificates/{certificate_id}/upload"
            )
        self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError(
                f"Expected object response from POST nginx/certificates/{certificate_id}/upload, got {type(data).__name__}"
            )
        return data

    def renew_certificate(self, certificate_id: int | str, *, timeout_s: float = 900.0) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] renew_certificate id=%s", certificate_id)
            return {"id": certificate_id}
        resp = self._web_request("POST", f"nginx/certificates/{certificate_id}/renew", timeout=timeout_s)
        if resp.status_code in (401, 403):
            raise PermissionError(
                f"Unauthorized ({resp.status_code}) for POST nginx/certificates/{certificate_id}/renew"
            )
        self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError(
                f"Expected object response from POST nginx/certificates/{certificate_id}/renew, got {type(data).__name__}"
            )
        return data

    def download_certificate(self, certificate_id: int | str) -> httpx.Response:
        """Download a certificate bundle.

        Maps to: `GET /api/nginx/certificates/{certificate_id}/download`
        Returns the raw response (typically an attachment).
        """
        resp = self._web_request("GET", f"nginx/certificates/{certificate_id}/download")
        if resp.status_code in (401, 403):
            raise PermissionError(
                f"Unauthorized ({resp.status_code}) for GET nginx/certificates/{certificate_id}/download"
            )
        self._raise_for_status(resp)
        return resp

    def create_access_list(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] create_access_list payload=%s", payload)
            return {"id": -1, **payload}
        return self._form_json("post", "nginx/access-lists", payload)

    def update_access_list(self, list_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] update_access_list id=%s payload=%s", list_id, payload)
            return {"id": list_id, **payload}
        return self._form_json("put", f"nginx/access-lists/{list_id}", payload)

    def delete_access_list(self, list_id: int | str) -> None:
        if self.readonly:
            logger.info("[dry-run] delete_access_list id=%s", list_id)
            return
        logger.debug("DELETE nginx/access-lists/%s", list_id)
        resp = self._web_request("DELETE", f"nginx/access-lists/{list_id}")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for DELETE nginx/access-lists/{list_id}")
        self._raise_for_status(resp)

    def create_proxy_host(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] create_proxy_host payload=%s", payload)
            return {"id": -1, **payload}
        return self._form_json("post", "nginx/proxy-hosts", payload)

    def update_proxy_host(self, host_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] update_proxy_host id=%s payload=%s", host_id, payload)
            return {"id": host_id, **payload}
        return self._form_json("put", f"nginx/proxy-hosts/{host_id}", payload)

    def delete_proxy_host(self, host_id: int | str) -> None:
        if self.readonly:
            logger.info("[dry-run] delete_proxy_host id=%s", host_id)
            return
        logger.debug("DELETE nginx/proxy-hosts/%s", host_id)
        resp = self._web_request("DELETE", f"nginx/proxy-hosts/{host_id}")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for DELETE nginx/proxy-hosts/{host_id}")
        self._raise_for_status(resp)

    def enable_proxy_host(self, host_id: int | str) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] enable_proxy_host id=%s", host_id)
            return {"id": host_id, "enabled": True}
        return self._post_object(f"nginx/proxy-hosts/{host_id}/enable")

    def disable_proxy_host(self, host_id: int | str) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] disable_proxy_host id=%s", host_id)
            return {"id": host_id, "enabled": False}
        return self._post_object(f"nginx/proxy-hosts/{host_id}/disable")

    def create_redirection_host(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] create_redirection_host payload=%s", payload)
            return {"id": -1, **payload}
        return self._form_json("post", "nginx/redirection-hosts", payload)

    def update_redirection_host(self, host_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] update_redirection_host id=%s payload=%s", host_id, payload)
            return {"id": host_id, **payload}
        return self._form_json("put", f"nginx/redirection-hosts/{host_id}", payload)

    def delete_redirection_host(self, host_id: int | str) -> None:
        if self.readonly:
            logger.info("[dry-run] delete_redirection_host id=%s", host_id)
            return
        logger.debug("DELETE nginx/redirection-hosts/%s", host_id)
        resp = self._web_request("DELETE", f"nginx/redirection-hosts/{host_id}")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for DELETE nginx/redirection-hosts/{host_id}")
        self._raise_for_status(resp)

    def enable_redirection_host(self, host_id: int | str) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] enable_redirection_host id=%s", host_id)
            return {"id": host_id, "enabled": True}
        return self._post_object(f"nginx/redirection-hosts/{host_id}/enable")

    def disable_redirection_host(self, host_id: int | str) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] disable_redirection_host id=%s", host_id)
            return {"id": host_id, "enabled": False}
        return self._post_object(f"nginx/redirection-hosts/{host_id}/disable")

    def create_dead_host(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] create_dead_host payload=%s", payload)
            return {"id": -1, **payload}
        return self._form_json("post", "nginx/dead-hosts", payload)

    def update_dead_host(self, host_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] update_dead_host id=%s payload=%s", host_id, payload)
            return {"id": host_id, **payload}
        return self._form_json("put", f"nginx/dead-hosts/{host_id}", payload)

    def delete_dead_host(self, host_id: int | str) -> None:
        if self.readonly:
            logger.info("[dry-run] delete_dead_host id=%s", host_id)
            return
        logger.debug("DELETE nginx/dead-hosts/%s", host_id)
        resp = self._web_request("DELETE", f"nginx/dead-hosts/{host_id}")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for DELETE nginx/dead-hosts/{host_id}")
        self._raise_for_status(resp)

    def enable_dead_host(self, host_id: int | str) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] enable_dead_host id=%s", host_id)
            return {"id": host_id, "enabled": True}
        return self._post_object(f"nginx/dead-hosts/{host_id}/enable")

    def disable_dead_host(self, host_id: int | str) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] disable_dead_host id=%s", host_id)
            return {"id": host_id, "enabled": False}
        return self._post_object(f"nginx/dead-hosts/{host_id}/disable")

    def create_stream(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] create_stream payload=%s", payload)
            return {"id": -1, **payload}
        return self._form_json("post", "nginx/streams", payload)

    def update_stream(self, stream_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] update_stream id=%s payload=%s", stream_id, payload)
            return {"id": stream_id, **payload}
        return self._form_json("put", f"nginx/streams/{stream_id}", payload)

    def delete_stream(self, stream_id: int | str) -> None:
        if self.readonly:
            logger.info("[dry-run] delete_stream id=%s", stream_id)
            return
        logger.debug("DELETE nginx/streams/%s", stream_id)
        resp = self._web_request("DELETE", f"nginx/streams/{stream_id}")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for DELETE nginx/streams/{stream_id}")
        self._raise_for_status(resp)

    def enable_stream(self, stream_id: int | str) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] enable_stream id=%s", stream_id)
            return {"id": stream_id, "enabled": True}
        return self._post_object(f"nginx/streams/{stream_id}/enable")

    def disable_stream(self, stream_id: int | str) -> dict[str, Any]:
        if self.readonly:
            logger.info("[dry-run] disable_stream id=%s", stream_id)
            return {"id": stream_id, "enabled": False}
        return self._post_object(f"nginx/streams/{stream_id}/disable")

    # --- Internal helpers ---
    def _get_object(self, path: str, *, expand: Sequence[str] | None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if expand:
            params["expand"] = ",".join(expand)
        logger.debug("GET %s params=%s", path, params if params else None)
        resp = self._web_request("GET", path, params=params if params else None)
        if resp.status_code in (401, 403):
            logger.warning("Unauthorized status_code=%s for GET %s", resp.status_code, path)
            raise PermissionError(f"Unauthorized ({resp.status_code}) for GET {path}")
        self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError(f"Expected object response from GET {path}, got {type(data).__name__}")
        return data

    def _post_object(
        self, path: str, payload: dict[str, Any] | None = None, *, timeout_s: float | None = None
    ) -> dict[str, Any]:
        logger.debug("POST %s", path)
        resp = self._web_request(
            "POST",
            path,
            json=dict(payload) if payload is not None else None,
            timeout=timeout_s,
        )
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for POST {path}")
        self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError(f"Expected object response from POST {path}, got {type(data).__name__}")
        return data

    def _delete_object(self, path: str) -> dict[str, Any]:
        logger.debug("DELETE %s", path)
        resp = self._web_request("DELETE", path)
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for DELETE {path}")
        self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError(f"Expected object response from DELETE {path}, got {type(data).__name__}")
        return data

    def _get_list(self, path: str, *, expand: Sequence[str] | None, query: str | None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {}
        if expand:
            params["expand"] = ",".join(expand)
        if query:
            params["query"] = query
        logger.debug("GET %s params=%s", path, params if params else None)
        resp = self._web_request("GET", path, params=params)
        if resp.status_code in (401, 403):
            logger.warning("Unauthorized status_code=%s for GET %s", resp.status_code, path)
            raise PermissionError(f"Unauthorized ({resp.status_code}) for GET {path}")
        self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, list):
            raise RuntimeError(f"Expected list response from {path}, got {type(data).__name__}")
        return data

    def _form_json(
        self, method: str, path: str, payload: dict[str, Any], *, timeout_s: float | None = None
    ) -> dict[str, Any]:
        method_l = method.lower().strip()
        if method_l not in ("post", "put"):
            raise ValueError("method must be post or put")

        logger.debug("%s %s (json body keys=%s)", method_l.upper(), path, sorted(payload.keys()))
        resp = self._web_request(method_l.upper(), path, json=dict(payload), timeout=timeout_s)
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for {method_l.upper()} {path}")
        self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError(f"Expected object response from {method_l.upper()} {path}, got {type(data).__name__}")
        return data

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            msg = f"HTTP {resp.status_code} for {resp.request.method} {resp.request.url}"
            try:
                payload = resp.json()
            except Exception:
                raise RuntimeError(msg) from e
            raise RuntimeError(f"{msg}: {payload}") from e
