from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from .. import utils
from .kinds import Kind

if TYPE_CHECKING:
    from ..npmplus_client import NPMplusClient


class StreamItem:
    kind: ClassVar[Kind] = Kind.STREAMS

    BOOL_LABEL_FIELDS: ClassVar[tuple[str, ...]] = (
        "enabled",
        "proxy_protocol_forwarding",
        "tcp_forwarding",
        "udp_forwarding",
    )

    def __init__(
        self,
        *,
        api: NPMplusClient,
        incoming_port: object,
        forwarding_host: object,
        forwarding_port: object,
        tcp_forwarding: object = True,
        udp_forwarding: object = False,
        proxy_protocol_forwarding: object = False,
        proxy_ssl: object = False,
        certificate: object = None,
        enabled: object = True,
        id: object = -1,
        owner: object = "",
        owner_user_id: object = 0,
    ) -> None:
        self.api = api
        self.incoming_port = incoming_port
        self.forwarding_host = forwarding_host
        self.forwarding_port = forwarding_port
        self.tcp_forwarding = tcp_forwarding
        self.udp_forwarding = udp_forwarding
        self.proxy_protocol_forwarding = proxy_protocol_forwarding
        self.proxy_ssl = proxy_ssl
        self.certificate = certificate
        self.enabled = enabled
        self.id = id
        self.owner = owner
        self.owner_user_id = owner_user_id

    @property
    def natural_index(self) -> str:
        parts = [str(self.incoming_port)]
        if self.tcp_forwarding:
            parts.append("tcp")
        if self.udp_forwarding:
            parts.append("udp")
        if self.proxy_protocol_forwarding:
            parts.append("proxy")
        return "/".join(parts)

    @property
    def incoming_port(self) -> int:
        return self._incoming_port

    @incoming_port.setter
    def incoming_port(self, value: object) -> None:
        port = utils.parse_port(value, field="incoming_port")
        self._incoming_port = port

    @property
    def forwarding_host(self) -> str:
        return self._forwarding_host

    @forwarding_host.setter
    def forwarding_host(self, value: object) -> None:
        s = str(value or "").strip()
        if not s:
            raise ValueError("Missing forwarding_host")
        self._forwarding_host = s

    @property
    def forwarding_port(self) -> int:
        return self._forwarding_port

    @forwarding_port.setter
    def forwarding_port(self, value: object) -> None:
        port = utils.parse_port(value, field="forwarding_port")
        self._forwarding_port = port

    @property
    def tcp_forwarding(self) -> bool:
        return self._tcp_forwarding

    @tcp_forwarding.setter
    def tcp_forwarding(self, value: object) -> None:
        self._tcp_forwarding = utils.bool_or(value, default=False)

    @property
    def udp_forwarding(self) -> bool:
        return self._udp_forwarding

    @udp_forwarding.setter
    def udp_forwarding(self, value: object) -> None:
        self._udp_forwarding = utils.bool_or(value, default=False)

    @property
    def proxy_protocol_forwarding(self) -> bool:
        return self._proxy_protocol_forwarding

    @proxy_protocol_forwarding.setter
    def proxy_protocol_forwarding(self, value: object) -> None:
        self._proxy_protocol_forwarding = utils.bool_or(value, default=False)

    @property
    def proxy_ssl(self) -> bool:
        return self._proxy_ssl

    @proxy_ssl.setter
    def proxy_ssl(self, value: object) -> None:
        self._proxy_ssl = utils.bool_or(value, default=False)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: object) -> None:
        self._enabled = utils.bool_or(value, default=True)

    @property
    def certificate(self) -> str | None:
        return self._certificate

    @certificate.setter
    def certificate(self, value: object) -> None:
        if value is None:
            self._certificate = None
            return
        extracted = utils.certificate_nice_name_from_value(value)
        if extracted is not None:
            self._certificate = extracted
            return
        s = str(value).strip()
        self._certificate = s

    @property
    def id(self) -> int:
        return self._id

    @id.setter
    def id(self, value: object) -> None:
        self._id = utils.normalize_int(value)

    @property
    def owner(self) -> str:
        return self._owner

    @owner.setter
    def owner(self, value: object) -> None:
        self._owner = str(value or "").strip()

    @property
    def owner_user_id(self) -> int:
        return self._owner_user_id

    @owner_user_id.setter
    def owner_user_id(self, value: object) -> None:
        self._owner_user_id = utils.normalize_int(value, default=0)

    def load_from_json(self, payload: Mapping[str, Any]) -> None:
        if "id" in payload:
            self.id = payload.get("id")
        if "incoming_port" in payload:
            self.incoming_port = payload.get("incoming_port")
        if "forwarding_host" in payload:
            self.forwarding_host = payload.get("forwarding_host")
        if "forwarding_port" in payload:
            self.forwarding_port = payload.get("forwarding_port")
        if "tcp_forwarding" in payload:
            self.tcp_forwarding = payload.get("tcp_forwarding")
        if "udp_forwarding" in payload:
            self.udp_forwarding = payload.get("udp_forwarding")
        if "proxy_protocol_forwarding" in payload:
            self.proxy_protocol_forwarding = payload.get("proxy_protocol_forwarding")
        if "proxy_ssl" in payload:
            self.proxy_ssl = payload.get("proxy_ssl")
        if "enabled" in payload:
            self.enabled = payload.get("enabled")
        if "certificate" in payload:
            self.certificate = payload.get("certificate")
        owner_data = payload.get("owner")
        if isinstance(owner_data, Mapping):
            self.owner = owner_data.get("nickname")
            self.owner_user_id = owner_data.get("id")
        if "owner_user_id" in payload:
            self.owner_user_id = payload.get("owner_user_id")

    @classmethod
    def from_json(cls, api: NPMplusClient, payload: dict[str, Any]) -> StreamItem:
        item = cls(
            api=api,
            incoming_port=payload.get("incoming_port"),
            forwarding_host=payload.get("forwarding_host"),
            forwarding_port=payload.get("forwarding_port"),
        )
        item.load_from_json(payload)
        return item

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "incoming_port": self.incoming_port,
            "forwarding_host": self.forwarding_host,
            "forwarding_port": self.forwarding_port,
            "tcp_forwarding": self.tcp_forwarding,
            "udp_forwarding": self.udp_forwarding,
            "proxy_protocol_forwarding": self.proxy_protocol_forwarding,
            "proxy_ssl": self.proxy_ssl,
        }
        if self.certificate is not None:
            if self.certificate.strip() == "":
                payload["certificate_id"] = 0
            else:
                cert_id = self.api.get_certificate_id(self.certificate)
                if cert_id <= 0:
                    raise ValueError(f"Unknown certificate: {self.certificate}")
                payload["certificate_id"] = cert_id
        return payload

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "enabled": self.enabled,
            "incoming_port": self.incoming_port,
            "forwarding_host": self.forwarding_host,
            "forwarding_port": self.forwarding_port,
            "tcp_forwarding": self.tcp_forwarding,
            "udp_forwarding": self.udp_forwarding,
            "proxy_protocol_forwarding": self.proxy_protocol_forwarding,
            "proxy_ssl": self.proxy_ssl,
            "certificate": self.certificate,
            "owner": self.owner,
            "owner_user_id": self.owner_user_id,
        }

    def save(self, *, take_ownership: bool = False) -> tuple[Literal["create", "update"], dict[str, Any]]:
        matched_existing: StreamItem | None = None
        found_id = self.api.get_stream_id(self.natural_index)
        effective_id = found_id if found_id > 0 else None
        if effective_id is not None:
            matched_existing = self.api.list_streams().get(effective_id)

        replace = False
        if take_ownership and effective_id is not None:
            if matched_existing is None:
                matched_existing = self.api.list_streams().get(effective_id)
            if matched_existing is not None:
                owner_id = getattr(matched_existing, "owner_user_id", 0)
                if owner_id and owner_id != self.api.my_id:
                    replace = True
                else:
                    owner_key = matched_existing.owner
                    if owner_key and owner_key != self.api.my_natural_index:
                        replace = True

        if effective_id is None:
            result = self.api.create_stream(self.to_payload())
            self.id = result.get("id")
            self._apply_enabled(result)
            return "create", result

        if replace:
            self.api.delete_stream(effective_id)
            result = self.api.create_stream(self.to_payload())
            self.id = result.get("id")
            self._apply_enabled(result)
            return "create", result

        result = self.api.update_stream(effective_id, self.to_payload())
        self.id = result.get("id")
        self._apply_enabled(result)
        return "update", result

    def _apply_enabled(self, result: Mapping[str, Any]) -> None:
        stream_id = result.get("id")
        if stream_id is None:
            return
        current_enabled = result.get("enabled")
        desired = self.enabled
        if current_enabled == desired:
            return
        if desired:
            self.api.enable_stream(stream_id)
        else:
            self.api.disable_stream(stream_id)

    def delete(self) -> None:
        if self.id <= 0:
            raise ValueError(f"Cannot delete {self.kind.value}: invalid id={self.id}")
        self.api.delete_stream(self.id)
