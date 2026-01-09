from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import httpx

from .configmanager import ConfigManager

logger = ConfigManager.get_logger(__name__)


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

    def __post_init__(self) -> None:
        url = self.base_url.strip()
        if not url:
            raise ValueError("base_url is required")
        url = url.rstrip("/")
        if not url.endswith("/api"):
            url = url + "/api"
        self.base_url = url
        logger.debug(
            "Initializing NPMplusApi base_url=%s verify_tls=%s timeout_s=%s",
            self.base_url,
            self.verify_tls,
            self.timeout_s,
        )
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout_s,
            verify=self.verify_tls,
            headers={"accept": "application/json"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> NPMplusApi:
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:  # type: ignore[no-untyped-def]
        self.close()

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

    def login(self, identity: str, secret: str) -> Mapping[str, Any]:
        """Login via `/tokens`.

        Returns the JSON body (typically `{"expires": <unix>}`) and stores the cookie.
        """
        if not identity:
            raise ValueError("identity is required")
        if not secret:
            raise ValueError("secret is required")
        logger.info("Logging in to NPMplus")
        resp = self._client.post("tokens", json={"identity": identity, "secret": secret})
        if resp.status_code in (401, 403):
            logger.warning("Login failed with status_code=%s", resp.status_code)
            raise PermissionError(f"Login failed ({resp.status_code})")
        self._raise_for_status(resp)
        logger.debug("Login succeeded")
        return resp.json()

    def refresh_token(self, *, expiry: str | None = None, scope: str | None = None) -> Mapping[str, Any]:
        """Refresh an existing token (or request a scoped one).

        Maps to: `GET /api/tokens?expiry=...&scope=...`
        """
        logger.debug("Refreshing NPMplus token")
        params: dict[str, Any] = {}
        if expiry is not None:
            params["expiry"] = expiry
        if scope is not None:
            params["scope"] = scope
        resp = self._client.get("tokens", params=params if params else None)
        if resp.status_code in (401, 403):
            logger.warning("Token refresh failed with status_code=%s", resp.status_code)
            raise PermissionError(f"Not authenticated ({resp.status_code})")
        self._raise_for_status(resp)
        return resp.json()

    def logout(self) -> bool:
        """Logout by clearing token cookie on the server.

        Maps to: `DELETE /api/tokens`
        """
        resp = self._client.delete("tokens")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for DELETE tokens")
        self._raise_for_status(resp)
        try:
            data = resp.json()
        except Exception:
            return True
        return bool(data)

    def get_health(self) -> Mapping[str, Any]:
        """Health check.

        Maps to: `GET /api` (base_url already ends with `/api`)
        """
        resp = self._client.get("")
        self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError(f"Expected object response from GET /api, got {type(data).__name__}")
        return data

    def get_schema(self) -> Mapping[str, Any]:
        logger.debug("Fetching /schema")
        resp = self._client.get("schema")
        self._raise_for_status(resp)
        return resp.json()

    # --- Users ---
    def list_users(self, *, expand: Sequence[str] | None = None, query: str | None = None) -> list[dict[str, Any]]:
        return self._get_list("users", expand=expand, query=query)

    def get_user(self, user_id: int | str, *, expand: Sequence[str] | None = None) -> Mapping[str, Any]:
        return self._get_object(f"users/{user_id}", expand=expand)

    def create_user(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("post", "users", payload)

    def update_user(self, user_id: int | str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("put", f"users/{user_id}", payload)

    def delete_user(self, user_id: int | str) -> Mapping[str, Any]:
        return self._delete_object(f"users/{user_id}")

    def delete_all_users_ci_only(self) -> bool:
        """Delete ALL users.

        This is only enabled by the server in CI/debug mode.
        Maps to: `DELETE /api/users`
        """
        resp = self._client.delete("users")
        self._raise_for_status(resp)
        try:
            data = resp.json()
        except Exception:
            return True
        return bool(data)

    def set_user_password(self, user_id: int | str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("put", f"users/{user_id}/auth", payload)

    def set_user_permissions(self, user_id: int | str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("put", f"users/{user_id}/permissions", payload)

    def login_as_user(self, user_id: int | str) -> Mapping[str, Any]:
        return self._post_object(f"users/{user_id}/login")

    # --- Audit Log ---
    def list_audit_log(self, *, expand: Sequence[str] | None = None, query: str | None = None) -> list[dict[str, Any]]:
        return self._get_list("audit-log", expand=expand, query=query)

    def get_audit_log_event(self, event_id: int | str, *, expand: Sequence[str] | None = None) -> Mapping[str, Any]:
        return self._get_object(f"audit-log/{event_id}", expand=expand)

    # --- Reports ---
    def get_hosts_report(self) -> Mapping[str, Any]:
        return self._get_object("reports/hosts", expand=None)

    # --- Settings ---
    def list_settings(self) -> Any:
        resp = self._client.get("settings")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for GET settings")
        self._raise_for_status(resp)
        return resp.json()

    def get_setting(self, setting_id: str) -> Mapping[str, Any]:
        if not setting_id or not str(setting_id).strip():
            raise ValueError("setting_id is required")
        return self._get_object(f"settings/{setting_id}", expand=None)

    def update_setting(self, setting_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        if not setting_id or not str(setting_id).strip():
            raise ValueError("setting_id is required")
        return self._write_json("put", f"settings/{setting_id}", payload)

    # --- Version ---
    def check_version(self) -> Mapping[str, Any]:
        return self._get_object("version/check", expand=None)

    def list_proxy_hosts(
        self, *, expand: Sequence[str] | None = None, query: str | None = None
    ) -> list[dict[str, Any]]:
        return self._get_list("nginx/proxy-hosts", expand=expand, query=query)

    def get_proxy_host(self, host_id: int | str, *, expand: Sequence[str] | None = None) -> Mapping[str, Any]:
        return self._get_object(f"nginx/proxy-hosts/{host_id}", expand=expand)

    def list_redirection_hosts(
        self, *, expand: Sequence[str] | None = None, query: str | None = None
    ) -> list[dict[str, Any]]:
        return self._get_list("nginx/redirection-hosts", expand=expand, query=query)

    def get_redirection_host(self, host_id: int | str, *, expand: Sequence[str] | None = None) -> Mapping[str, Any]:
        return self._get_object(f"nginx/redirection-hosts/{host_id}", expand=expand)

    def list_dead_hosts(self, *, expand: Sequence[str] | None = None, query: str | None = None) -> list[dict[str, Any]]:
        return self._get_list("nginx/dead-hosts", expand=expand, query=query)

    def get_dead_host(self, host_id: int | str, *, expand: Sequence[str] | None = None) -> Mapping[str, Any]:
        return self._get_object(f"nginx/dead-hosts/{host_id}", expand=expand)

    def list_streams(self, *, expand: Sequence[str] | None = None, query: str | None = None) -> list[dict[str, Any]]:
        return self._get_list("nginx/streams", expand=expand, query=query)

    def get_stream(self, stream_id: int | str, *, expand: Sequence[str] | None = None) -> Mapping[str, Any]:
        return self._get_object(f"nginx/streams/{stream_id}", expand=expand)

    def list_access_lists(
        self, *, expand: Sequence[str] | None = None, query: str | None = None
    ) -> list[dict[str, Any]]:
        return self._get_list("nginx/access-lists", expand=expand, query=query)

    def get_access_list(self, list_id: int | str, *, expand: Sequence[str] | None = None) -> Mapping[str, Any]:
        return self._get_object(f"nginx/access-lists/{list_id}", expand=expand)

    def list_certificates(
        self, *, expand: Sequence[str] | None = None, query: str | None = None
    ) -> list[dict[str, Any]]:
        return self._get_list("nginx/certificates", expand=expand, query=query)

    def get_certificate(self, certificate_id: int | str, *, expand: Sequence[str] | None = None) -> Mapping[str, Any]:
        return self._get_object(f"nginx/certificates/{certificate_id}", expand=expand)

    def create_certificate(self, payload: Mapping[str, Any], *, timeout_s: float = 900.0) -> Mapping[str, Any]:
        # certbot / DNS challenges can take a long time
        return self._write_json("post", "nginx/certificates", payload, timeout_s=timeout_s)

    def delete_certificate(self, certificate_id: int | str) -> None:
        logger.debug("DELETE nginx/certificates/%s", certificate_id)
        resp = self._client.delete(f"nginx/certificates/{certificate_id}")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for DELETE nginx/certificates/{certificate_id}")
        self._raise_for_status(resp)

    def list_certificate_dns_providers(self) -> list[dict[str, Any]]:
        return self._get_list("nginx/certificates/dns-providers", expand=None, query=None)

    def test_certificate_http_challenge(
        self, payload: Mapping[str, Any], *, timeout_s: float = 60.0
    ) -> Mapping[str, Any]:
        return self._write_json("post", "nginx/certificates/test-http", payload, timeout_s=timeout_s)

    def validate_certificate_files(self, files: Mapping[str, Any]) -> Mapping[str, Any]:
        """Validate a certificate/key/chain upload.

        Maps to: `POST /api/nginx/certificates/validate` (multipart form upload)
        """
        resp = self._client.post("nginx/certificates/validate", files=files)
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for POST nginx/certificates/validate")
        self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError(
                f"Expected object response from POST nginx/certificates/validate, got {type(data).__name__}"
            )
        return data

    def upload_certificate_files(self, certificate_id: int | str, files: Mapping[str, Any]) -> Mapping[str, Any]:
        """Upload certificate files.

        Maps to: `POST /api/nginx/certificates/{certificate_id}/upload` (multipart)
        """
        resp = self._client.post(f"nginx/certificates/{certificate_id}/upload", files=files)
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

    def renew_certificate(self, certificate_id: int | str, *, timeout_s: float = 900.0) -> Mapping[str, Any]:
        resp = self._client.post(f"nginx/certificates/{certificate_id}/renew", timeout=timeout_s)
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
        resp = self._client.get(f"nginx/certificates/{certificate_id}/download")
        if resp.status_code in (401, 403):
            raise PermissionError(
                f"Unauthorized ({resp.status_code}) for GET nginx/certificates/{certificate_id}/download"
            )
        self._raise_for_status(resp)
        return resp

    def create_access_list(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("post", "nginx/access-lists", payload)

    def update_access_list(self, list_id: int | str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("put", f"nginx/access-lists/{list_id}", payload)

    def delete_access_list(self, list_id: int | str) -> None:
        """Delete an access list by ID."""
        logger.debug("DELETE nginx/access-lists/%s", list_id)
        resp = self._client.delete(f"nginx/access-lists/{list_id}")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for DELETE nginx/access-lists/{list_id}")
        self._raise_for_status(resp)

    def create_proxy_host(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("post", "nginx/proxy-hosts", payload)

    def update_proxy_host(self, host_id: int | str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("put", f"nginx/proxy-hosts/{host_id}", payload)

    def delete_proxy_host(self, host_id: int | str) -> None:
        """Delete a proxy host by ID."""
        logger.debug("DELETE nginx/proxy-hosts/%s", host_id)
        resp = self._client.delete(f"nginx/proxy-hosts/{host_id}")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for DELETE nginx/proxy-hosts/{host_id}")
        self._raise_for_status(resp)

    def enable_proxy_host(self, host_id: int | str) -> Mapping[str, Any]:
        return self._post_object(f"nginx/proxy-hosts/{host_id}/enable")

    def disable_proxy_host(self, host_id: int | str) -> Mapping[str, Any]:
        return self._post_object(f"nginx/proxy-hosts/{host_id}/disable")

    def create_redirection_host(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("post", "nginx/redirection-hosts", payload)

    def update_redirection_host(self, host_id: int | str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("put", f"nginx/redirection-hosts/{host_id}", payload)

    def delete_redirection_host(self, host_id: int | str) -> None:
        logger.debug("DELETE nginx/redirection-hosts/%s", host_id)
        resp = self._client.delete(f"nginx/redirection-hosts/{host_id}")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for DELETE nginx/redirection-hosts/{host_id}")
        self._raise_for_status(resp)

    def enable_redirection_host(self, host_id: int | str) -> Mapping[str, Any]:
        return self._post_object(f"nginx/redirection-hosts/{host_id}/enable")

    def disable_redirection_host(self, host_id: int | str) -> Mapping[str, Any]:
        return self._post_object(f"nginx/redirection-hosts/{host_id}/disable")

    def create_dead_host(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("post", "nginx/dead-hosts", payload)

    def update_dead_host(self, host_id: int | str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("put", f"nginx/dead-hosts/{host_id}", payload)

    def delete_dead_host(self, host_id: int | str) -> None:
        logger.debug("DELETE nginx/dead-hosts/%s", host_id)
        resp = self._client.delete(f"nginx/dead-hosts/{host_id}")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for DELETE nginx/dead-hosts/{host_id}")
        self._raise_for_status(resp)

    def enable_dead_host(self, host_id: int | str) -> Mapping[str, Any]:
        return self._post_object(f"nginx/dead-hosts/{host_id}/enable")

    def disable_dead_host(self, host_id: int | str) -> Mapping[str, Any]:
        return self._post_object(f"nginx/dead-hosts/{host_id}/disable")

    def create_stream(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("post", "nginx/streams", payload)

    def update_stream(self, stream_id: int | str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("put", f"nginx/streams/{stream_id}", payload)

    def delete_stream(self, stream_id: int | str) -> None:
        logger.debug("DELETE nginx/streams/%s", stream_id)
        resp = self._client.delete(f"nginx/streams/{stream_id}")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for DELETE nginx/streams/{stream_id}")
        self._raise_for_status(resp)

    def enable_stream(self, stream_id: int | str) -> Mapping[str, Any]:
        return self._post_object(f"nginx/streams/{stream_id}/enable")

    def disable_stream(self, stream_id: int | str) -> Mapping[str, Any]:
        return self._post_object(f"nginx/streams/{stream_id}/disable")

    # --- Internal helpers ---
    def _get_object(self, path: str, *, expand: Sequence[str] | None) -> Mapping[str, Any]:
        params: dict[str, Any] = {}
        if expand:
            params["expand"] = ",".join(expand)
        logger.debug("GET %s params=%s", path, params if params else None)
        resp = self._client.get(path, params=params if params else None)
        if resp.status_code in (401, 403):
            logger.warning("Unauthorized status_code=%s for GET %s", resp.status_code, path)
            raise PermissionError(f"Unauthorized ({resp.status_code}) for GET {path}")
        self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError(f"Expected object response from GET {path}, got {type(data).__name__}")
        return data

    def _post_object(
        self, path: str, payload: Mapping[str, Any] | None = None, *, timeout_s: float | None = None
    ) -> Mapping[str, Any]:
        logger.debug("POST %s", path)
        resp = self._client.post(path, json=dict(payload) if payload is not None else None, timeout=timeout_s)
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized ({resp.status_code}) for POST {path}")
        self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError(f"Expected object response from POST {path}, got {type(data).__name__}")
        return data

    def _delete_object(self, path: str) -> Mapping[str, Any]:
        logger.debug("DELETE %s", path)
        resp = self._client.delete(path)
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
        resp = self._client.get(path, params=params)
        if resp.status_code in (401, 403):
            logger.warning("Unauthorized status_code=%s for GET %s", resp.status_code, path)
            raise PermissionError(f"Unauthorized ({resp.status_code}) for GET {path}")
        self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, list):
            raise RuntimeError(f"Expected list response from {path}, got {type(data).__name__}")
        return data

    def _write_json(
        self, method: str, path: str, payload: Mapping[str, Any], *, timeout_s: float | None = None
    ) -> Mapping[str, Any]:
        method_l = method.lower().strip()
        if method_l not in ("post", "put"):
            raise ValueError("method must be post or put")

        logger.debug("%s %s (json body keys=%s)", method_l.upper(), path, sorted(payload.keys()))
        req = getattr(self._client, method_l)
        resp = req(path, json=dict(payload), timeout=timeout_s)
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
