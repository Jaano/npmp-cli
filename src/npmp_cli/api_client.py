from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class NPMplusError(RuntimeError):
    pass


class NPMplusAuthError(NPMplusError):
    pass


def _normalize_api_base_url(base_url: str) -> str:
    url = base_url.strip()
    if not url:
        raise ValueError("base_url is required")
    url = url.rstrip("/")
    if url.endswith("/api"):
        return url
    return url + "/api"


@dataclass
class NPMplusClient:
    """Minimal NPMplus API client.

    NPMplus auth is cookie-based: `POST /api/tokens` sets an httpOnly `token` cookie.
    """

    base_url: str
    verify_tls: bool = True
    timeout_s: float = 30.0

    def __post_init__(self) -> None:
        self.base_url = _normalize_api_base_url(self.base_url)
        logger.debug(
            "Initializing NPMplusClient base_url=%s verify_tls=%s timeout_s=%s",
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

    def __enter__(self) -> NPMplusClient:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
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
        resp = self._client.post(
            "tokens", json={"identity": identity, "secret": secret}
        )
        if resp.status_code in (401, 403):
            logger.warning("Login failed with status_code=%s", resp.status_code)
            raise NPMplusAuthError(f"Login failed ({resp.status_code})")
        self._raise_for_status(resp)
        logger.debug("Login succeeded")
        return resp.json()

    def logout(self) -> None:
        logger.info("Logging out from NPMplus")
        resp = self._client.delete("tokens")
        self._raise_for_status(resp)

    def refresh_token(self) -> Mapping[str, Any]:
        logger.debug("Refreshing NPMplus token")
        resp = self._client.get("tokens")
        if resp.status_code in (401, 403):
            logger.warning("Token refresh failed with status_code=%s", resp.status_code)
            raise NPMplusAuthError(f"Not authenticated ({resp.status_code})")
        self._raise_for_status(resp)
        return resp.json()

    def get_schema(self) -> Mapping[str, Any]:
        logger.debug("Fetching /schema")
        resp = self._client.get("schema")
        self._raise_for_status(resp)
        return resp.json()

    def list_proxy_hosts(
        self, *, expand: Sequence[str] | None = None, query: str | None = None
    ) -> list[dict[str, Any]]:
        return self._get_list("nginx/proxy-hosts", expand=expand, query=query)

    def list_redirection_hosts(
        self, *, expand: Sequence[str] | None = None, query: str | None = None
    ) -> list[dict[str, Any]]:
        return self._get_list("nginx/redirection-hosts", expand=expand, query=query)

    def list_dead_hosts(
        self, *, expand: Sequence[str] | None = None, query: str | None = None
    ) -> list[dict[str, Any]]:
        return self._get_list("nginx/dead-hosts", expand=expand, query=query)

    def list_streams(
        self, *, expand: Sequence[str] | None = None, query: str | None = None
    ) -> list[dict[str, Any]]:
        return self._get_list("nginx/streams", expand=expand, query=query)

    def list_access_lists(
        self, *, expand: Sequence[str] | None = None, query: str | None = None
    ) -> list[dict[str, Any]]:
        return self._get_list("nginx/access-lists", expand=expand, query=query)

    def list_certificates(
        self, *, expand: Sequence[str] | None = None, query: str | None = None
    ) -> list[dict[str, Any]]:
        return self._get_list("nginx/certificates", expand=expand, query=query)

    def create_access_list(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("post", "nginx/access-lists", payload)

    def update_access_list(
        self, list_id: int | str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        return self._write_json("put", f"nginx/access-lists/{list_id}", payload)

    def create_proxy_host(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("post", "nginx/proxy-hosts", payload)

    def update_proxy_host(
        self, host_id: int | str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        return self._write_json("put", f"nginx/proxy-hosts/{host_id}", payload)

    def create_redirection_host(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("post", "nginx/redirection-hosts", payload)

    def update_redirection_host(
        self, host_id: int | str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        return self._write_json("put", f"nginx/redirection-hosts/{host_id}", payload)

    def create_dead_host(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("post", "nginx/dead-hosts", payload)

    def update_dead_host(
        self, host_id: int | str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        return self._write_json("put", f"nginx/dead-hosts/{host_id}", payload)

    def create_stream(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._write_json("post", "nginx/streams", payload)

    def update_stream(
        self, stream_id: int | str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        return self._write_json("put", f"nginx/streams/{stream_id}", payload)

    def delete_proxy_host(self, host_id: int | str) -> None:
        """Delete a proxy host by ID."""
        logger.debug("DELETE nginx/proxy-hosts/%s", host_id)
        resp = self._client.delete(f"nginx/proxy-hosts/{host_id}")
        if resp.status_code in (401, 403):
            raise NPMplusAuthError(
                f"Unauthorized ({resp.status_code}) for DELETE nginx/proxy-hosts/{host_id}"
            )
        self._raise_for_status(resp)

    def _get_list(
        self, path: str, *, expand: Sequence[str] | None, query: str | None
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {}
        if expand:
            params["expand"] = ",".join(expand)
        if query:
            params["query"] = query
        logger.debug("GET %s params=%s", path, params if params else None)
        resp = self._client.get(path, params=params)
        if resp.status_code in (401, 403):
            logger.warning(
                "Unauthorized status_code=%s for GET %s", resp.status_code, path
            )
            raise NPMplusAuthError(f"Unauthorized ({resp.status_code}) for GET {path}")
        self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, list):
            raise NPMplusError(
                f"Expected list response from {path}, got {type(data).__name__}"
            )
        return data

    def _write_json(
        self, method: str, path: str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        method_l = method.lower().strip()
        if method_l not in ("post", "put"):
            raise ValueError("method must be post or put")

        logger.debug(
            "%s %s (json body keys=%s)", method_l.upper(), path, sorted(payload.keys())
        )
        req = getattr(self._client, method_l)
        resp = req(path, json=dict(payload))
        if resp.status_code in (401, 403):
            raise NPMplusAuthError(
                f"Unauthorized ({resp.status_code}) for {method_l.upper()} {path}"
            )
        self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, dict):
            raise NPMplusError(
                f"Expected object response from {method_l.upper()} {path}, got {type(data).__name__}"
            )
        return data

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            msg = (
                f"HTTP {resp.status_code} for {resp.request.method} {resp.request.url}"
            )
            try:
                payload = resp.json()
            except Exception:
                raise NPMplusError(msg) from e
            raise NPMplusError(f"{msg}: {payload}") from e


def ensure_str_list(values: Iterable[str] | None) -> list[str] | None:
    if values is None:
        return None
    out: list[str] = []
    for v in values:
        v = v.strip()
        if v:
            out.append(v)
    return out
