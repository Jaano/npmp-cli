from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from .. import utils
from .kinds import Kind

if TYPE_CHECKING:
    from ..npmplus_client import NPMplusClient


@dataclass
class ProxyHostItem:
    kind: ClassVar[Kind] = Kind.PROXY_HOSTS

    BOOL_LABEL_FIELDS: ClassVar[tuple[str, ...]] = (
        "allow_websocket_upgrade",
        "block_exploits",
        "caching_enabled",
        "enabled",
        "hsts_enabled",
        "hsts_subdomains",
        "http2_support",
        "ssl_forced",
    )

    LOCATION_BOOL_LABEL_FIELDS: ClassVar[tuple[str, ...]] = (
        "allow_websocket_upgrade",
        "block_exploits",
        "caching_enabled",
    )

    api: NPMplusClient
    domain_names: list[str]
    forward_scheme: str
    forward_host: str
    forward_port: int
    enabled: bool = True
    access_list: str | None = None
    access_list_id: int = 0
    certificate: str | None = None
    certificate_id: int = 0
    ssl_forced: bool = False
    caching_enabled: bool = False
    block_exploits: bool = False
    allow_websocket_upgrade: bool = False
    http2_support: bool = False
    hsts_enabled: bool = False
    hsts_subdomains: bool = False
    advanced_config: str = ""
    locations: list[dict[str, Any]] = field(default_factory=list)
    id: int = -1
    owner: str = ""
    owner_user_id: int = 0

    @property
    def natural_index(self) -> str:
        norm = utils.domain_key(self.domain_names)
        return ",".join(norm) if norm else ""

    @classmethod
    def from_json(cls, api: NPMplusClient, payload: Mapping[str, Any]) -> ProxyHostItem:
        domains_v = payload.get("domain_names")
        if not isinstance(domains_v, list):
            domains: list[str] = []
        else:
            domains = [s for d in domains_v if (s := str(d).strip().lower())]
        forward_host = str(payload.get("forward_host") or "").strip()
        forward_scheme = str(payload.get("forward_scheme") or "").strip().lower()
        forward_port = utils.normalize_int(payload.get("forward_port"), default=0)
        access_name = utils.access_list_name_from_value(payload.get("access_list") or payload.get("accessList"))
        cert_name = utils.certificate_nice_name_from_value(payload.get("certificate") or payload.get("nice_name"))

        locs = payload.get("locations")
        locations: list[dict[str, Any]] = []
        if isinstance(locs, Mapping):
            locations = [dict(locs)]
        elif isinstance(locs, list):
            locations = [dict(x) for x in locs if isinstance(x, Mapping)]

        owner = payload.get("owner")
        owner_name = ""
        owner_id = 0
        if isinstance(owner, Mapping):
            owner_name = str(owner.get("nickname") or "").strip()
            owner_id = utils.normalize_int(owner.get("id"), default=0)

        return cls(
            api=api,
            id=utils.normalize_int(payload.get("id")),
            enabled=utils.bool_or(payload.get("enabled"), default=True),
            domain_names=domains,
            forward_scheme=forward_scheme,
            forward_host=forward_host,
            forward_port=utils.parse_port(forward_port, field="forward_port") if forward_port else 0,
            access_list=access_name,
            access_list_id=utils.normalize_int(payload.get("access_list_id"), default=0),
            certificate=cert_name,
            certificate_id=utils.normalize_int(payload.get("certificate_id"), default=0),
            ssl_forced=utils.bool_or(payload.get("ssl_forced"), default=False),
            caching_enabled=utils.bool_or(payload.get("caching_enabled"), default=False),
            block_exploits=utils.bool_or(payload.get("block_exploits"), default=False),
            allow_websocket_upgrade=utils.bool_or(payload.get("allow_websocket_upgrade"), default=False),
            http2_support=utils.bool_or(payload.get("http2_support"), default=False),
            hsts_enabled=utils.bool_or(payload.get("hsts_enabled"), default=False),
            hsts_subdomains=utils.bool_or(payload.get("hsts_subdomains"), default=False),
            advanced_config=str(payload.get("advanced_config") or ""),
            locations=locations,
            owner=owner_name,
            owner_user_id=utils.normalize_int(payload.get("owner_user_id"), default=owner_id),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "enabled": self.enabled,
            "domain_names": list(self.domain_names),
            "forward_scheme": self.forward_scheme,
            "forward_host": self.forward_host,
            "forward_port": self.forward_port,
            "access_list": self.access_list,
            "access_list_id": self.access_list_id,
            "certificate": self.certificate,
            "certificate_id": self.certificate_id,
            "ssl_forced": self.ssl_forced,
            "caching_enabled": self.caching_enabled,
            "block_exploits": self.block_exploits,
            "allow_websocket_upgrade": self.allow_websocket_upgrade,
            "http2_support": self.http2_support,
            "hsts_enabled": self.hsts_enabled,
            "hsts_subdomains": self.hsts_subdomains,
            "advanced_config": self.advanced_config,
            "locations": list(self.locations),
            "owner": self.owner,
            "owner_user_id": self.owner_user_id,
        }

    def to_payload(self) -> dict[str, Any]:
        if not self.domain_names:
            raise ValueError("domain_names must not be empty")
        if not self.forward_host:
            raise ValueError("forward_host must not be empty")
        if not self.forward_scheme:
            raise ValueError("forward_scheme must not be empty")
        payload: dict[str, Any] = {
            "domain_names": list(self.domain_names),
            "forward_scheme": self.forward_scheme,
            "forward_host": self.forward_host,
            "forward_port": utils.parse_port(self.forward_port, field="forward_port"),
            "ssl_forced": bool(self.ssl_forced),
            "caching_enabled": bool(self.caching_enabled),
            "block_exploits": bool(self.block_exploits),
            "allow_websocket_upgrade": bool(self.allow_websocket_upgrade),
            "http2_support": bool(self.http2_support),
            "hsts_enabled": bool(self.hsts_enabled),
            "hsts_subdomains": bool(self.hsts_subdomains),
            "advanced_config": self.advanced_config,
            "locations": list(self.locations),
        }

        if self.access_list is not None:
            if self.access_list.strip() == "":
                payload["access_list_id"] = 0
            else:
                access_id = self.api.get_access_list_id(self.access_list)
                if access_id <= 0:
                    raise ValueError(f"Unknown access list: {self.access_list}")
                payload["access_list_id"] = access_id
        elif self.access_list_id:
            payload["access_list_id"] = int(self.access_list_id)

        if self.certificate is not None:
            if self.certificate.strip() == "":
                payload["certificate_id"] = 0
            else:
                cert_id = self.api.get_certificate_id(self.certificate)
                if cert_id <= 0:
                    raise ValueError(f"Unknown certificate: {self.certificate}")
                payload["certificate_id"] = cert_id
        elif self.certificate_id:
            payload["certificate_id"] = int(self.certificate_id)

        return payload

    def save(self, *, take_ownership: bool = False) -> tuple[Literal["create", "update"], dict[str, Any]]:
        found_id = self.api.get_proxy_host_id(self.natural_index)
        effective_id = found_id if found_id > 0 else None

        replace = False
        if take_ownership and effective_id is not None:
            existing = self.api.list_proxy_hosts().get(effective_id)
            if existing is not None:
                owner_id = getattr(existing, "owner_user_id", 0)
                if owner_id and owner_id != self.api.my_id:
                    replace = True
                else:
                    owner_key = existing.owner
                    if owner_key and owner_key != self.api.my_natural_index:
                        replace = True

        def _apply_enabled(result: Mapping[str, Any]) -> None:
            host_id = result.get("id")
            if host_id is None:
                return
            current_enabled = result.get("enabled")
            if current_enabled == self.enabled:
                return
            if self.enabled:
                self.api.enable_proxy_host(host_id)
            else:
                self.api.disable_proxy_host(host_id)

        if effective_id is None:
            result = self.api.create_proxy_host(self.to_payload())
            self.id = utils.normalize_int(result.get("id"))
            _apply_enabled(result)
            return "create", result
        if replace:
            self.api.delete_proxy_host(effective_id)
            result = self.api.create_proxy_host(self.to_payload())
            self.id = utils.normalize_int(result.get("id"))
            _apply_enabled(result)
            return "create", result

        try:
            result = self.api.update_proxy_host(effective_id, self.to_payload())
            self.id = utils.normalize_int(result.get("id"))
            _apply_enabled(result)
            return "update", result
        except RuntimeError as e:
            if "HTTP 404" in str(e) and "Not Found" in str(e):
                result = self.api.create_proxy_host(self.to_payload())
                self.id = utils.normalize_int(result.get("id"))
                _apply_enabled(result)
                return "create", result
            raise

    def delete(self) -> None:
        if self.id <= 0:
            raise ValueError(f"Cannot delete {self.kind.value}: invalid id={self.id}")
        self.api.delete_proxy_host(self.id)
