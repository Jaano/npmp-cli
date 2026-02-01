from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from .. import utils
from .kinds import Kind

if TYPE_CHECKING:
    from ..npmplus_client import NPMplusClient


@dataclass
class RedirectionHostItem:
    kind: ClassVar[Kind] = Kind.REDIRECTION_HOSTS

    BOOL_LABEL_FIELDS: ClassVar[tuple[str, ...]] = (
        "block_exploits",
        "enabled",
        "hsts_enabled",
        "hsts_subdomains",
        "http2_support",
        "preserve_path",
        "ssl_forced",
    )

    api: NPMplusClient
    domain_names: list[str]
    forward_scheme: str
    forward_domain_name: str
    forward_http_code: int
    enabled: bool = True
    preserve_path: bool = False
    block_exploits: bool = False
    ssl_forced: bool = False
    http2_support: bool = False
    hsts_enabled: bool = False
    hsts_subdomains: bool = False
    certificate: str | None = None
    certificate_id: int = 0
    advanced_config: str = ""
    id: int = -1
    owner: str = ""
    owner_user_id: int = 0

    @property
    def natural_index(self) -> str:
        norm = utils.domain_key(self.domain_names)
        return ",".join(norm) if norm else ""

    @classmethod
    def from_json(cls, api: NPMplusClient, payload: Mapping[str, Any]) -> RedirectionHostItem:
        domains_v = payload.get("domain_names")
        domains = [s for d in domains_v if (s := str(d).strip().lower())] if isinstance(domains_v, list) else []
        owner = payload.get("owner")
        owner_name = str(owner.get("nickname") or "").strip() if isinstance(owner, Mapping) else ""
        owner_id = utils.normalize_int(owner.get("id"), default=0) if isinstance(owner, Mapping) else 0
        cert_name = utils.certificate_nice_name_from_value(payload.get("certificate") or payload.get("nice_name"))
        http_code = utils.normalize_int(payload.get("forward_http_code"), default=0)
        return cls(
            api=api,
            id=utils.normalize_int(payload.get("id")),
            enabled=utils.bool_or(payload.get("enabled"), default=True),
            domain_names=domains,
            forward_scheme=str(payload.get("forward_scheme") or "").strip().lower(),
            forward_domain_name=str(payload.get("forward_domain_name") or "").strip(),
            forward_http_code=http_code,
            preserve_path=utils.bool_or(payload.get("preserve_path"), default=False),
            block_exploits=utils.bool_or(payload.get("block_exploits"), default=False),
            ssl_forced=utils.bool_or(payload.get("ssl_forced"), default=False),
            http2_support=utils.bool_or(payload.get("http2_support"), default=False),
            hsts_enabled=utils.bool_or(payload.get("hsts_enabled"), default=False),
            hsts_subdomains=utils.bool_or(payload.get("hsts_subdomains"), default=False),
            certificate=cert_name,
            certificate_id=utils.normalize_int(payload.get("certificate_id"), default=0),
            advanced_config=str(payload.get("advanced_config") or ""),
            owner=owner_name,
            owner_user_id=utils.normalize_int(payload.get("owner_user_id"), default=owner_id),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "enabled": self.enabled,
            "domain_names": list(self.domain_names),
            "forward_scheme": self.forward_scheme,
            "forward_domain_name": self.forward_domain_name,
            "forward_http_code": self.forward_http_code,
            "preserve_path": self.preserve_path,
            "block_exploits": self.block_exploits,
            "ssl_forced": self.ssl_forced,
            "http2_support": self.http2_support,
            "hsts_enabled": self.hsts_enabled,
            "hsts_subdomains": self.hsts_subdomains,
            "certificate": self.certificate,
            "certificate_id": self.certificate_id,
            "advanced_config": self.advanced_config,
            "owner": self.owner,
            "owner_user_id": self.owner_user_id,
        }

    def to_payload(self) -> dict[str, Any]:
        if not self.domain_names:
            raise ValueError("domain_names must not be empty")
        if not self.forward_domain_name:
            raise ValueError("forward_domain_name must not be empty")
        if not self.forward_scheme:
            raise ValueError("forward_scheme must not be empty")
        if self.forward_http_code <= 0:
            raise ValueError("forward_http_code must be a positive integer")

        payload: dict[str, Any] = {
            "domain_names": list(self.domain_names),
            "forward_scheme": self.forward_scheme,
            "forward_domain_name": self.forward_domain_name,
            "forward_http_code": int(self.forward_http_code),
            "preserve_path": bool(self.preserve_path),
            "block_exploits": bool(self.block_exploits),
            "ssl_forced": bool(self.ssl_forced),
            "http2_support": bool(self.http2_support),
            "hsts_enabled": bool(self.hsts_enabled),
            "hsts_subdomains": bool(self.hsts_subdomains),
            "advanced_config": self.advanced_config,
        }

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
        found_id = self.api.get_redirection_host_id(self.natural_index)
        effective_id = found_id if found_id > 0 else None

        replace = False
        if take_ownership and effective_id is not None:
            existing = self.api.list_redirection_hosts().get(effective_id)
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
                self.api.enable_redirection_host(host_id)
            else:
                self.api.disable_redirection_host(host_id)

        if effective_id is None:
            result = self.api.create_redirection_host(self.to_payload())
            self.id = utils.normalize_int(result.get("id"))
            _apply_enabled(result)
            return "create", result
        if replace:
            self.api.delete_redirection_host(effective_id)
            result = self.api.create_redirection_host(self.to_payload())
            self.id = utils.normalize_int(result.get("id"))
            _apply_enabled(result)
            return "create", result

        try:
            result = self.api.update_redirection_host(effective_id, self.to_payload())
            self.id = utils.normalize_int(result.get("id"))
            _apply_enabled(result)
            return "update", result
        except RuntimeError as e:
            if "HTTP 404" in str(e) and "Not Found" in str(e):
                result = self.api.create_redirection_host(self.to_payload())
                self.id = utils.normalize_int(result.get("id"))
                _apply_enabled(result)
                return "create", result
            raise

    def delete(self) -> None:
        if self.id <= 0:
            raise ValueError(f"Cannot delete {self.kind.value}: invalid id={self.id}")
        self.api.delete_redirection_host(self.id)
