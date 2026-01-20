from __future__ import annotations

from collections.abc import Callable, Sequence
from enum import Enum
from typing import Any, Literal

from .configmanager import ConfigManager
from .npmplus_api import (
    EXPAND_ACCESS_LIST,
    EXPAND_CERTIFICATE,
    EXPAND_CLIENTS,
    EXPAND_DEAD_HOSTS,
    EXPAND_ITEMS,
    EXPAND_OWNER,
    EXPAND_PERMISSIONS,
    EXPAND_PROXY_HOSTS,
    EXPAND_REDIRECTION_HOSTS,
    EXPAND_STREAMS,
    NPMplusApi,
)


class _Kind(str, Enum):
    ACCESS_LISTS = "access-lists"
    CERTIFICATES = "certificates"
    PROXY_HOSTS = "proxy-hosts"
    REDIRECTION_HOSTS = "redirection-hosts"
    DEAD_HOSTS = "dead-hosts"
    STREAMS = "streams"
    USERS = "users"

    def item_type(self) -> NPMplusItemType:
        """Factory method for the item wrapper type for this kind.

        Uses the module-level `_ITEM_TYPES` registry (kind → item-wrapper class) and
        returns a fresh `NPMplusItemType` instance. These wrappers are lightweight
        adapters over raw API payloads and implement kind-specific behaviors like
        natural keys, diffing, and create/update logic.
        """
        item_type_cls = _ITEM_TYPES.get(self)
        if item_type_cls is None:
            allowed = ", ".join(sorted(k.value for k in _ITEM_TYPES.keys()))
            raise ValueError(f"Unsupported kind: {self.value}. Use one of: {allowed}")
        return item_type_cls({})

    @staticmethod
    def infer_json_kind(payload: dict[str, Any]) -> _Kind:
        keys = {str(k).lower() for k in payload.keys()}
        if "pass_auth" in keys:
            return _Kind.ACCESS_LISTS
        if "incoming_port" in keys:
            return _Kind.STREAMS
        if "forward_domain_name" in keys:
            return _Kind.REDIRECTION_HOSTS
        if "forward_host" in keys:
            return _Kind.PROXY_HOSTS
        return _Kind.DEAD_HOSTS

__all__ = [
    "NPMplusClient",
    "NPMplusItemType",
    "UserItem",
    "AccessListItem",
    "ProxyHostItem",
    "RedirectionHostItem",
    "DeadHostItem",
    "StreamItem",
    "CertificateItem",
]

logger = ConfigManager.get_logger(__name__)


class NPMplusItemType(dict[str, Any]):
    kind: _Kind
    API_FIELDS: frozenset[str] = frozenset()

    @property
    def id(self) -> int:
        try:
            return int(str(self.get("id")).strip())
        except Exception:
            return -1

    @property
    def natural_index(self) -> str:
        raise NotImplementedError(f"{type(self).__name__} does not implement natural_index()")

    @property
    def owner(self) -> str:
        owner_data = self.get("owner")
        if isinstance(owner_data, dict):
            nickname = owner_data.get("nickname")
            if nickname is not None:
                return str(nickname).strip()
        return ""

    def _payload_for_api(self) -> dict[str, Any]:
        """Build payload with only fields required for API create/update."""
        return {k: v for k, v in self.items() if k in self.API_FIELDS}

    def set(
        self,
        api: NPMplusClient,
        *,
        takeownership: bool = False,
    ) -> tuple[Literal["create", "update"], dict[str, Any]]:
        raise NotImplementedError(f"{type(self).__name__} does not implement set()")

    def _resolve_relation_ids(self, api: NPMplusClient, payload: dict[str, Any]) -> None:
        """Resolve relation fields from raw payload to IDs and update self."""
        access_list_ref = payload.get("access_list")
        if access_list_ref is not None:
            if isinstance(access_list_ref, dict):
                access_name = AccessListItem(access_list_ref).natural_index
            else:
                access_name = str(access_list_ref).strip()
            if access_name:
                self["access_list_id"] = api.get_access_list_id(access_name)

        nice_name = payload.get("nice_name")
        if nice_name is not None:
            cert_name = str(nice_name).strip()
            if cert_name:
                self["certificate_id"] = api.get_certificate_id(cert_name)

    def load_from_json(
        self,
        api: NPMplusClient,
        payload: dict[str, Any],
    ) -> bool:
        raise NotImplementedError(f"{type(self).__name__} does not implement load_from_json()")

    @staticmethod
    def normalize_domains(value: object) -> tuple[str, ...] | None:
        if not isinstance(value, list):
            return None
        parts = [str(v).strip().lower() for v in value]
        parts = [p for p in parts if p]
        return tuple(sorted(parts))

    @staticmethod
    def normalize_int(value: object) -> int:
        if value is None:
            return -1
        try:
            return int(str(value).strip())
        except Exception:
            return -1

    @staticmethod
    def normalize_bool(value: object) -> bool | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        v = str(value).strip().lower()
        if v in {"1", "true", "yes", "on"}:
            return True
        if v in {"0", "false", "no", "off"}:
            return False
        return None

    @classmethod
    def are_equal(cls, desired: dict[str, Any], existing: dict[str, Any]) -> bool:
        """Compare two dicts using only API_FIELDS.

        Returns True if the dicts are equal for fields relevant to API.
        """
        desired_clean = {k: v for k, v in desired.items() if k in cls.API_FIELDS}
        existing_clean = {k: v for k, v in existing.items() if k in cls.API_FIELDS}
        return desired_clean == existing_clean


class UserItem(NPMplusItemType):
    kind = _Kind.USERS
    API_FIELDS: frozenset[str] = frozenset({
        "email",
        "name",
        "nickname",
        "is_disabled",
        "roles",
        "permissions",
    })

    @property
    def enabled(self) -> bool:
        return self.normalize_bool(self.get("is_disabled")) is not True

    @property
    def natural_index(self) -> str:
        u = self.get("nickname")
        return str(u).strip() if u is not None else ""


class AccessListItem(NPMplusItemType):
    kind = _Kind.ACCESS_LISTS
    API_FIELDS: frozenset[str] = frozenset({
        "name",
        "satisfy_any",
        "pass_auth",
        "items",
        "clients",
    })

    @property
    def name(self) -> str:
        v = self.get("name")
        if v is None:
            return "undefined_access_list_" + str(id(self))
        return v

    @property
    def natural_index(self) -> str:
        return self.name

    @staticmethod
    def name_from_value(value: object) -> str | None:
        if isinstance(value, dict):
            name = value.get("name") or value.get("title")
            if name is None:
                return None
            s = str(name).strip()
            return s or None
        if isinstance(value, str):
            s = value.strip()
            return s or None
        return None

    def load_from_json(
        self,
        api: NPMplusClient,
        payload: dict[str, Any],
    ) -> bool:
        _ = api
        desired_payload: dict[str, object] = {k: v for k, v in payload.items() if k in self.API_FIELDS}
        items = desired_payload.get("items")
        if isinstance(items, list):
            desired_payload["items"] = [
                {"username": e.get("username"), "password": e.get("password")}
                for e in items
                if isinstance(e, dict) and e.get("username")
            ]
        clients = desired_payload.get("clients")
        if isinstance(clients, list):
            desired_payload["clients"] = [
                {"address": e.get("address"), "directive": e.get("directive")}
                for e in clients
                if isinstance(e, dict) and e.get("address")
            ]
        self.clear()
        self.update(desired_payload)
        return True

    def set(
        self,
        api: NPMplusClient,
        *,
        takeownership: bool = False,
    ) -> tuple[Literal["create", "update"], dict[str, Any]]:
        _ = takeownership
        clients_val = self.get("clients")
        clients_have_addresses = False
        if isinstance(clients_val, list):
            for entry in clients_val:
                if not isinstance(entry, dict):
                    continue
                addr = entry.get("address")
                if addr is not None and str(addr).strip():
                    clients_have_addresses = True
                    break

        if clients_have_addresses and self.id > 0:
            saved_clients = self.get("clients")
            self["clients"] = []
            try:
                effective_id = self.id if self.id > 0 else None
                if effective_id is None:
                    found_id = api.get_access_list_id(self.natural_index)
                    effective_id = found_id if found_id > 0 else None
                if effective_id is not None:
                    api.update_access_list(effective_id, self._payload_for_api())
            except Exception:
                raise
            finally:
                self["clients"] = saved_clients

        effective_id = self.id if self.id > 0 else None
        if effective_id is None:
            found_id = api.get_access_list_id(self.natural_index)
            effective_id = found_id if found_id > 0 else None
        if effective_id is None:
            result = api.create_access_list(self._payload_for_api())
            logger.info("Created %s (%s)", self.kind.value, self.natural_index)
            return "create", result
        try:
            result = api.update_access_list(effective_id, self._payload_for_api())
            logger.info("Updated %s (%s)", self.kind.value, self.natural_index)
            return "update", result
        except RuntimeError as e:
            if "HTTP 404" in str(e) and "Not Found" in str(e):
                result = api.create_access_list(self._payload_for_api())
                logger.info("Created %s (%s)", self.kind.value, self.natural_index)
                return "create", result
            raise

    def delete(self, api: NPMplusApi) -> None:
        item_id = self.id
        if item_id < 0:
            raise ValueError(f"Cannot delete {self.kind.value}: invalid id={item_id}")
        api.delete_access_list(item_id)


class StreamItem(NPMplusItemType):
    kind = _Kind.STREAMS
    API_FIELDS: frozenset[str] = frozenset({
        "incoming_port",
        "forwarding_host",
        "forwarding_port",
        "tcp_forwarding",
        "udp_forwarding",
        "proxy_protocol_forwarding",
        "proxy_ssl",
        "certificate_id",
        "meta",
    })

    @property
    def enabled(self) -> bool:
        return self.normalize_bool(self.get("enabled")) is not False

    @property
    def natural_index(self) -> str:
        port = self.get("incoming_port")
        if port is None:
            return ""
        parts = [str(port).strip()]
        if self.get("tcp_forwarding"):
            parts.append("tcp")
        if self.get("udp_forwarding"):
            parts.append("udp")
        if self.get("proxy_protocol_forwarding"):
            parts.append("proxy")
        return "/".join(parts)

    @staticmethod
    def parse_natural_index(index: str) -> tuple[int, bool, bool, bool] | None:
        """Parse natural index into (port, tcp, udp, proxy). Returns None if invalid."""
        parts = [p.strip().lower() for p in index.split("/")]
        if not parts or not parts[0]:
            return None
        try:
            port = int(parts[0])
        except ValueError:
            return None
        flags = set(parts[1:])
        return (port, "tcp" in flags, "udp" in flags, "proxy" in flags)

    def load_from_json(
        self,
        api: NPMplusClient,
        payload: dict[str, Any],
    ) -> bool:
        self.clear()
        self.update({k: v for k, v in payload.items() if k in self.API_FIELDS})
        self._resolve_relation_ids(api, payload)
        return True

    def set(
        self,
        api: NPMplusClient,
        *,
        takeownership: bool = False,
    ) -> tuple[Literal["create", "update"], dict[str, Any]]:
        effective_id = self.id if self.id > 0 else None
        if effective_id is None:
            found_id = api.get_stream_id(self.natural_index)
            effective_id = found_id if found_id > 0 else None

        replace = False
        if takeownership and effective_id is not None:
            existing = api.list_streams().get(effective_id)
            if existing is not None:
                owner_key = existing.owner
                if owner_key and owner_key != api.my_natural_index:
                    replace = True

        def _apply_enabled(result: dict[str, Any]) -> None:
            stream_id = result.get("id")
            if stream_id is None:
                return
            current_enabled = result.get("enabled")
            if current_enabled == self.enabled:
                return
            if self.enabled:
                api.enable_stream(stream_id)
            else:
                api.disable_stream(stream_id)

        if effective_id is None:
            result = api.create_stream(self._payload_for_api())
            logger.info("Created %s (%s)", self.kind.value, self.natural_index)
            _apply_enabled(result)
            return "create", result
        if replace:
            api.delete_stream(effective_id)
            result = api.create_stream(self._payload_for_api())
            logger.info("Replaced %s (%s)", self.kind.value, self.natural_index)
            _apply_enabled(result)
            return "create", result
        try:
            result = api.update_stream(effective_id, self._payload_for_api())
            logger.info("Updated %s (%s)", self.kind.value, self.natural_index)
            _apply_enabled(result)
            return "update", result
        except RuntimeError as e:
            if "HTTP 404" in str(e) and "Not Found" in str(e):
                result = api.create_stream(self._payload_for_api())
                logger.info("Created %s (%s)", self.kind.value, self.natural_index)
                _apply_enabled(result)
                return "create", result
            raise

    def delete(self, api: NPMplusApi) -> None:
        item_id = self.id
        if item_id < 0:
            raise ValueError(f"Cannot delete {self.kind.value}: invalid id={item_id}")
        api.delete_stream(item_id)


class CertificateItem(NPMplusItemType):
    kind = _Kind.CERTIFICATES
    API_FIELDS: frozenset[str] = frozenset({
        "provider",
        "nice_name",
        "domain_names",
        "meta",
    })

    @property
    def enabled(self) -> bool:
        return self.normalize_bool(self.get("enabled")) is not False

    @property
    def nice_name(self) -> str | None:
        v = self.get("nice_name")
        if v is None:
            return None
        s = str(v).strip()
        return s or None

    @property
    def natural_index(self) -> str:
        return self.nice_name or ""

    def delete(self, api: NPMplusApi) -> None:
        item_id = self.id
        if item_id < 0:
            raise ValueError(f"Cannot delete {self.kind.value}: invalid id={item_id}")
        api.delete_certificate(item_id)


class ProxyHostItem(NPMplusItemType):
    kind = _Kind.PROXY_HOSTS
    API_FIELDS: frozenset[str] = frozenset({
        "domain_names",
        "forward_host",
        "forward_port",
        "forward_scheme",
        "access_list_id",
        "certificate_id",
        "ssl_forced",
        "caching_enabled",
        "block_exploits",
        "advanced_config",
        "allow_websocket_upgrade",
        "http2_support",
        "meta",
        "locations",
        "hsts_enabled",
        "hsts_subdomains",
    })

    @property
    def enabled(self) -> bool:
        return self.normalize_bool(self.get("enabled")) is not False

    @staticmethod
    def _domain_key(domains: Sequence[object] | None) -> tuple[str, ...] | None:
        if not domains:
            return None
        out: list[str] = []
        for d in domains:
            s = str(d).strip().lower()
            if s:
                out.append(s)
        if not out:
            return None
        return tuple(sorted(set(out)))

    @property
    def natural_index(self) -> str:
        domains = self.get("domain_names")
        norm = self._domain_key(domains if isinstance(domains, list) else None)
        return ",".join(norm) if norm else ""

    def load_from_json(
        self,
        api: NPMplusClient,
        payload: dict[str, Any],
    ) -> bool:
        self.clear()
        self.update({k: v for k, v in payload.items() if k in self.API_FIELDS})
        self._resolve_relation_ids(api, payload)
        locations = self.get("locations")
        if locations is None:
            self["locations"] = []
        elif isinstance(locations, dict):
            self["locations"] = [locations]
        elif isinstance(locations, list):
            self["locations"] = [x for x in locations if isinstance(x, dict)]
        else:
            self.pop("locations", None)
        return True

    def set(
        self,
        api: NPMplusClient,
        *,
        takeownership: bool = False,
    ) -> tuple[Literal["create", "update"], dict[str, Any]]:
        effective_id = self.id if self.id > 0 else None
        if effective_id is None:
            found_id = api.get_proxy_host_id(self.natural_index)
            effective_id = found_id if found_id > 0 else None

        replace = False
        if takeownership and effective_id is not None:
            existing = api.list_proxy_hosts().get(effective_id)
            if existing is not None:
                owner_key = existing.owner
                if owner_key and owner_key != api.my_natural_index:
                    replace = True

        def _apply_enabled(result: dict[str, Any]) -> None:
            host_id = result.get("id")
            if host_id is None:
                return
            current_enabled = result.get("enabled")
            if current_enabled == self.enabled:
                return
            if self.enabled:
                api.enable_proxy_host(host_id)
            else:
                api.disable_proxy_host(host_id)

        if effective_id is None:
            result = api.create_proxy_host(self._payload_for_api())
            logger.info("Created %s (%s)", self.kind.value, self.natural_index)
            _apply_enabled(result)
            return "create", result
        if replace:
            api.delete_proxy_host(effective_id)
            result = api.create_proxy_host(self._payload_for_api())
            logger.info("Replaced %s (%s)", self.kind.value, self.natural_index)
            _apply_enabled(result)
            return "create", result
        try:
            result = api.update_proxy_host(effective_id, self._payload_for_api())
            logger.info("Updated %s (%s)", self.kind.value, self.natural_index)
            _apply_enabled(result)
            return "update", result
        except RuntimeError as e:
            if "HTTP 404" in str(e) and "Not Found" in str(e):
                result = api.create_proxy_host(self._payload_for_api())
                logger.info("Created %s (%s)", self.kind.value, self.natural_index)
                _apply_enabled(result)
                return "create", result
            raise

    def delete(self, api: NPMplusApi) -> None:
        item_id = self.id
        if item_id < 0:
            raise ValueError(f"Cannot delete {self.kind.value}: invalid id={item_id}")
        api.delete_proxy_host(item_id)


class RedirectionHostItem(NPMplusItemType):
    kind = _Kind.REDIRECTION_HOSTS
    API_FIELDS: frozenset[str] = frozenset({
        "domain_names",
        "forward_http_code",
        "forward_scheme",
        "forward_domain_name",
        "preserve_path",
        "certificate_id",
        "ssl_forced",
        "hsts_enabled",
        "hsts_subdomains",
        "http2_support",
        "block_exploits",
        "advanced_config",
        "meta",
    })

    @property
    def enabled(self) -> bool:
        return self.normalize_bool(self.get("enabled")) is not False

    @staticmethod
    def _domain_key(domains: Sequence[object] | None) -> tuple[str, ...] | None:
        if not domains:
            return None
        out: list[str] = []
        for d in domains:
            s = str(d).strip().lower()
            if s:
                out.append(s)
        if not out:
            return None
        return tuple(sorted(set(out)))

    @property
    def natural_index(self) -> str:
        domains = self.get("domain_names")
        norm = self._domain_key(domains if isinstance(domains, list) else None)
        return ",".join(norm) if norm else ""

    def load_from_json(
        self,
        api: NPMplusClient,
        payload: dict[str, Any],
    ) -> bool:
        self.clear()
        self.update({k: v for k, v in payload.items() if k in self.API_FIELDS})
        self._resolve_relation_ids(api, payload)
        return True

    def set(
        self,
        api: NPMplusClient,
        *,
        takeownership: bool = False,
    ) -> tuple[Literal["create", "update"], dict[str, Any]]:
        effective_id = self.id if self.id > 0 else None
        if effective_id is None:
            found_id = api.get_redirection_host_id(self.natural_index)
            effective_id = found_id if found_id > 0 else None

        replace = False
        if takeownership and effective_id is not None:
            existing = api.list_redirection_hosts().get(effective_id)
            if existing is not None:
                owner_key = existing.owner
                if owner_key and owner_key != api.my_natural_index:
                    replace = True

        def _apply_enabled(result: dict[str, Any]) -> None:
            host_id = result.get("id")
            if host_id is None:
                return
            current_enabled = result.get("enabled")
            if current_enabled == self.enabled:
                return
            if self.enabled:
                api.enable_redirection_host(host_id)
            else:
                api.disable_redirection_host(host_id)

        if effective_id is None:
            result = api.create_redirection_host(self._payload_for_api())
            logger.info("Created %s (%s)", self.kind.value, self.natural_index)
            _apply_enabled(result)
            return "create", result
        if replace:
            api.delete_redirection_host(effective_id)
            result = api.create_redirection_host(self._payload_for_api())
            logger.info("Replaced %s (%s)", self.kind.value, self.natural_index)
            _apply_enabled(result)
            return "create", result
        try:
            result = api.update_redirection_host(effective_id, self._payload_for_api())
            logger.info("Updated %s (%s)", self.kind.value, self.natural_index)
            _apply_enabled(result)
            return "update", result
        except RuntimeError as e:
            if "HTTP 404" in str(e) and "Not Found" in str(e):
                result = api.create_redirection_host(self._payload_for_api())
                logger.info("Created %s (%s)", self.kind.value, self.natural_index)
                _apply_enabled(result)
                return "create", result
            raise

    def delete(self, api: NPMplusApi) -> None:
        item_id = self.id
        if item_id < 0:
            raise ValueError(f"Cannot delete {self.kind.value}: invalid id={item_id}")
        api.delete_redirection_host(item_id)


class DeadHostItem(NPMplusItemType):
    kind = _Kind.DEAD_HOSTS
    API_FIELDS: frozenset[str] = frozenset({
        "domain_names",
        "certificate_id",
        "ssl_forced",
        "hsts_enabled",
        "hsts_subdomains",
        "http2_support",
        "advanced_config",
        "meta",
    })

    @property
    def enabled(self) -> bool:
        return self.normalize_bool(self.get("enabled")) is not False

    @staticmethod
    def _domain_key(domains: Sequence[object] | None) -> tuple[str, ...] | None:
        if not domains:
            return None
        out: list[str] = []
        for d in domains:
            s = str(d).strip().lower()
            if s:
                out.append(s)
        if not out:
            return None
        return tuple(sorted(set(out)))

    @property
    def natural_index(self) -> str:
        domains = self.get("domain_names")
        norm = self._domain_key(domains if isinstance(domains, list) else None)
        return ",".join(norm) if norm else ""

    def load_from_json(
        self,
        api: NPMplusClient,
        payload: dict[str, Any],
    ) -> bool:
        self.clear()
        self.update({k: v for k, v in payload.items() if k in self.API_FIELDS})
        self._resolve_relation_ids(api, payload)
        return True

    def set(
        self,
        api: NPMplusClient,
        *,
        takeownership: bool = False,
    ) -> tuple[Literal["create", "update"], dict[str, Any]]:
        effective_id = self.id if self.id > 0 else None
        if effective_id is None:
            found_id = api.get_dead_host_id(self.natural_index)
            effective_id = found_id if found_id > 0 else None

        replace = False
        if takeownership and effective_id is not None:
            existing = api.list_dead_hosts().get(effective_id)
            if existing is not None:
                owner_key = existing.owner
                if owner_key and owner_key != api.my_natural_index:
                    replace = True

        def _apply_enabled(result: dict[str, Any]) -> None:
            host_id = result.get("id")
            if host_id is None:
                return
            current_enabled = result.get("enabled")
            if current_enabled == self.enabled:
                return
            if self.enabled:
                api.enable_dead_host(host_id)
            else:
                api.disable_dead_host(host_id)

        if effective_id is None:
            result = api.create_dead_host(self._payload_for_api())
            logger.info("Created %s (%s)", self.kind.value, self.natural_index)
            _apply_enabled(result)
            return "create", result
        if replace:
            api.delete_dead_host(effective_id)
            result = api.create_dead_host(self._payload_for_api())
            logger.info("Replaced %s (%s)", self.kind.value, self.natural_index)
            _apply_enabled(result)
            return "create", result
        try:
            result = api.update_dead_host(effective_id, self._payload_for_api())
            logger.info("Updated %s (%s)", self.kind.value, self.natural_index)
            _apply_enabled(result)
            return "update", result
        except RuntimeError as e:
            if "HTTP 404" in str(e) and "Not Found" in str(e):
                result = api.create_dead_host(self._payload_for_api())
                logger.info("Created %s (%s)", self.kind.value, self.natural_index)
                _apply_enabled(result)
                return "create", result
            raise

    def delete(self, api: NPMplusApi) -> None:
        item_id = self.id
        if item_id < 0:
            raise ValueError(f"Cannot delete {self.kind.value}: invalid id={item_id}")
        api.delete_dead_host(item_id)


_ItemTypeFactory = Callable[[dict[str, Any]], NPMplusItemType]


_ITEM_TYPES: dict[_Kind, _ItemTypeFactory] = {
    _Kind.ACCESS_LISTS: AccessListItem,
    _Kind.CERTIFICATES: CertificateItem,
    _Kind.PROXY_HOSTS: ProxyHostItem,
    _Kind.REDIRECTION_HOSTS: RedirectionHostItem,
    _Kind.DEAD_HOSTS: DeadHostItem,
    _Kind.STREAMS: StreamItem,
    _Kind.USERS: UserItem,
}


class NPMplusClient(NPMplusApi):
    """High-level NPMplus client with item type resolution and set operations."""

    Kind = _Kind

    def __post_init__(self) -> None:
        super().__post_init__()
        self._users_cache: dict[int, UserItem] | None = None
        self._access_lists_cache: dict[int, AccessListItem] | None = None
        self._certificates_cache: dict[int, CertificateItem] | None = None
        self._proxy_hosts_cache: dict[int, ProxyHostItem] | None = None
        self._redirection_hosts_cache: dict[int, RedirectionHostItem] | None = None
        self._dead_hosts_cache: dict[int, DeadHostItem] | None = None
        self._streams_cache: dict[int, StreamItem] | None = None
        self._my_id_cache: int = -1
        self._my_natural_index_cache: str = ""

    def __post_login__(self) -> None:
        data = self.get_current_user(expand=(EXPAND_PERMISSIONS,))
        self._my_id_cache = NPMplusItemType.normalize_int(data.get("id"))
        self._my_natural_index_cache = str(data.get("nickname") or "").strip()

    def set_token_cookie(self, token: str) -> None:
        super().set_token_cookie(token)
        self.__post_login__()

    def login(self, identity: str, secret: str) -> dict[str, Any]:
        result = super().login(identity, secret)
        self.__post_login__()
        return result

    def __enter__(self) -> NPMplusClient:
        return self

    # Users

    @property
    def my_id(self) -> int:
        return self._my_id_cache

    @property
    def my_natural_index(self) -> str:
        return self._my_natural_index_cache

    def list_users(self) -> dict[int, UserItem]:
        cached = getattr(self, "_users_cache", None)
        if isinstance(cached, dict):
            return cached
        items = super().list_users(expand=(EXPAND_PERMISSIONS,))
        result: dict[int, UserItem] = {}
        for item in items:
            user_item = UserItem(dict(item))
            item_id = user_item.id
            if item_id > 0:
                result[item_id] = user_item
        self._users_cache = result
        return result

    # Access lists

    def list_access_lists(self) -> dict[int, AccessListItem]:
        cached = getattr(self, "_access_lists_cache", None)
        if isinstance(cached, dict):
            return cached
        items = super().list_access_lists(
            expand=(
                EXPAND_OWNER,
                EXPAND_ITEMS,
                EXPAND_CLIENTS,
            ),
        )
        result: dict[int, AccessListItem] = {}
        for item in items:
            access_item = AccessListItem(dict(item))
            item_id = access_item.id
            if item_id > 0:
                result[item_id] = access_item
        self._access_lists_cache = result
        return result

    def get_access_list_id(self, natural_index: str) -> int:
        for item in self.list_access_lists().values():
            if item.natural_index == natural_index:
                return item.id
        return -1

    # Certificates

    def list_certificates(self) -> dict[int, CertificateItem]:
        cached = getattr(self, "_certificates_cache", None)
        if isinstance(cached, dict):
            return cached
        items = super().list_certificates(
            expand=(
                EXPAND_OWNER,
                EXPAND_PROXY_HOSTS,
                EXPAND_REDIRECTION_HOSTS,
                EXPAND_DEAD_HOSTS,
                EXPAND_STREAMS,
            ),
        )
        result: dict[int, CertificateItem] = {}
        for item in items:
            cert_item = CertificateItem(dict(item))
            item_id = cert_item.id
            if item_id > 0:
                result[item_id] = cert_item
        self._certificates_cache = result
        return result

    def get_certificate_id(self, natural_index: str) -> int:
        for item in self.list_certificates().values():
            if item.natural_index == natural_index:
                return item.id
        return -1

    # Proxy hosts

    def list_proxy_hosts(self) -> dict[int, ProxyHostItem]:
        cached = getattr(self, "_proxy_hosts_cache", None)
        if isinstance(cached, dict):
            return cached
        items = super().list_proxy_hosts(
            expand=(
                EXPAND_CERTIFICATE,
                EXPAND_OWNER,
                EXPAND_ACCESS_LIST,
            ),
        )
        result: dict[int, ProxyHostItem] = {}
        for item in items:
            proxy_item = ProxyHostItem(dict(item))
            item_id = proxy_item.id
            if item_id > 0:
                result[item_id] = proxy_item
        self._proxy_hosts_cache = result
        return result

    def get_proxy_host_id(self, natural_index: str) -> int:
        for item in self.list_proxy_hosts().values():
            if item.natural_index == natural_index:
                return item.id
        return -1

    # Redirection hosts

    def list_redirection_hosts(self) -> dict[int, RedirectionHostItem]:
        cached = getattr(self, "_redirection_hosts_cache", None)
        if isinstance(cached, dict):
            return cached
        items = super().list_redirection_hosts(
            expand=(
                EXPAND_CERTIFICATE,
                EXPAND_OWNER,
            ),
        )
        result: dict[int, RedirectionHostItem] = {}
        for item in items:
            redir_item = RedirectionHostItem(dict(item))
            item_id = redir_item.id
            if item_id > 0:
                result[item_id] = redir_item
        self._redirection_hosts_cache = result
        return result

    def get_redirection_host_id(self, natural_index: str) -> int:
        for item in self.list_redirection_hosts().values():
            if item.natural_index == natural_index:
                return item.id
        return -1

    # Dead hosts

    def list_dead_hosts(self) -> dict[int, DeadHostItem]:
        cached = getattr(self, "_dead_hosts_cache", None)
        if isinstance(cached, dict):
            return cached
        items = super().list_dead_hosts(
            expand=(
                EXPAND_CERTIFICATE,
                EXPAND_OWNER,
            ),
        )
        result: dict[int, DeadHostItem] = {}
        for item in items:
            dead_item = DeadHostItem(dict(item))
            item_id = dead_item.id
            if item_id > 0:
                result[item_id] = dead_item
        self._dead_hosts_cache = result
        return result

    def get_dead_host_id(self, natural_index: str) -> int:
        for item in self.list_dead_hosts().values():
            if item.natural_index == natural_index:
                return item.id
        return -1

    # Streams

    def list_streams(self) -> dict[int, StreamItem]:
        cached = getattr(self, "_streams_cache", None)
        if isinstance(cached, dict):
            return cached
        items = super().list_streams(
            expand=(
                EXPAND_CERTIFICATE,
                EXPAND_OWNER,
            ),
        )
        result: dict[int, StreamItem] = {}
        for item in items:
            stream_item = StreamItem(dict(item))
            item_id = stream_item.id
            if item_id > 0:
                result[item_id] = stream_item
        self._streams_cache = result
        return result

    def get_stream_id(self, natural_index: str) -> int:
        for item in self.list_streams().values():
            if item.natural_index == natural_index:
                return item.id
        return -1

    # Cache-invalidating wrappers for mutations

    def create_access_list(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._access_lists_cache = None
        return super().create_access_list(payload)

    def update_access_list(self, list_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        self._access_lists_cache = None
        return super().update_access_list(list_id, payload)

    def delete_access_list(self, list_id: int | str) -> None:
        self._access_lists_cache = None
        super().delete_access_list(list_id)

    def delete_certificate(self, cert_id: int | str) -> None:
        self._certificates_cache = None
        super().delete_certificate(cert_id)

    def create_proxy_host(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._proxy_hosts_cache = None
        return super().create_proxy_host(payload)

    def update_proxy_host(self, host_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        self._proxy_hosts_cache = None
        return super().update_proxy_host(host_id, payload)

    def delete_proxy_host(self, host_id: int | str) -> None:
        self._proxy_hosts_cache = None
        super().delete_proxy_host(host_id)

    def enable_proxy_host(self, host_id: int | str) -> None:
        self._proxy_hosts_cache = None
        super().enable_proxy_host(host_id)

    def disable_proxy_host(self, host_id: int | str) -> None:
        self._proxy_hosts_cache = None
        super().disable_proxy_host(host_id)

    def create_redirection_host(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._redirection_hosts_cache = None
        return super().create_redirection_host(payload)

    def update_redirection_host(self, host_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        self._redirection_hosts_cache = None
        return super().update_redirection_host(host_id, payload)

    def delete_redirection_host(self, host_id: int | str) -> None:
        self._redirection_hosts_cache = None
        super().delete_redirection_host(host_id)

    def enable_redirection_host(self, host_id: int | str) -> None:
        self._redirection_hosts_cache = None
        super().enable_redirection_host(host_id)

    def disable_redirection_host(self, host_id: int | str) -> None:
        self._redirection_hosts_cache = None
        super().disable_redirection_host(host_id)

    def create_dead_host(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._dead_hosts_cache = None
        return super().create_dead_host(payload)

    def update_dead_host(self, host_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        self._dead_hosts_cache = None
        return super().update_dead_host(host_id, payload)

    def delete_dead_host(self, host_id: int | str) -> None:
        self._dead_hosts_cache = None
        super().delete_dead_host(host_id)

    def enable_dead_host(self, host_id: int | str) -> None:
        self._dead_hosts_cache = None
        super().enable_dead_host(host_id)

    def disable_dead_host(self, host_id: int | str) -> None:
        self._dead_hosts_cache = None
        super().disable_dead_host(host_id)

    def create_stream(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._streams_cache = None
        return super().create_stream(payload)

    def update_stream(self, stream_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        self._streams_cache = None
        return super().update_stream(stream_id, payload)

    def delete_stream(self, stream_id: int | str) -> None:
        self._streams_cache = None
        super().delete_stream(stream_id)

    def enable_stream(self, stream_id: int | str) -> None:
        self._streams_cache = None
        super().enable_stream(stream_id)

    def disable_stream(self, stream_id: int | str) -> None:
        self._streams_cache = None
        super().disable_stream(stream_id)


