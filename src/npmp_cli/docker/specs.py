from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .. import utils
from ..configmanager import ConfigManager
from ..models import DeadHostItem, ProxyHostItem, RedirectionHostItem, StreamItem
from ..npmplus_client import NPMplusClient

logger = ConfigManager.get_logger(__name__)


@dataclass(frozen=True)
class DockerProxyHostSpec:
    @dataclass(frozen=True)
    class CustomLocation:
        path: str
        forward_host: str
        forward_port: str | int
        forward_scheme: str
        advanced_config: str | None = None
        allow_websocket_upgrade: str | bool | None = None
        block_exploits: str | bool | None = None
        caching_enabled: str | bool | None = None
        location_type: str | None = None

    domain_names: list[str]
    forward_host: str
    forward_port: str | int
    forward_scheme: str
    locations: list[CustomLocation] = field(default_factory=list)
    access_list: str | None = None
    advanced_config: str | None = None
    allow_websocket_upgrade: str | bool | None = None
    block_exploits: str | bool | None = None
    caching_enabled: str | bool | None = None
    certificate: str | None = None
    enabled: str | bool | None = None
    hsts_enabled: str | bool | None = None
    hsts_subdomains: str | bool | None = None
    http2_support: str | bool | None = None
    ssl_forced: str | bool | None = None


@dataclass(frozen=True)
class DockerDeadHostSpec:
    domain_names: list[str]
    certificate: str | None = None
    enabled: str | bool | None = None
    ssl_forced: str | bool | None = None
    hsts_enabled: str | bool | None = None
    hsts_subdomains: str | bool | None = None
    http2_support: str | bool | None = None
    advanced_config: str | None = None


@dataclass(frozen=True)
class DockerRedirectionHostSpec:
    domain_names: list[str]
    forward_domain_name: str
    forward_http_code: str | int
    forward_scheme: str
    preserve_path: str | bool | None = None
    certificate: str | None = None
    enabled: str | bool | None = None
    ssl_forced: str | bool | None = None
    block_exploits: str | bool | None = None
    hsts_enabled: str | bool | None = None
    hsts_subdomains: str | bool | None = None
    http2_support: str | bool | None = None
    advanced_config: str | None = None


@dataclass(frozen=True)
class DockerStreamSpec:
    incoming_port: str | int
    forwarding_host: str
    forwarding_port: str | int
    tcp_forwarding: str | bool | None = None
    udp_forwarding: str | bool | None = None
    proxy_protocol_forwarding: str | bool | None = None
    certificate: str | None = None
    enabled: str | bool | None = None


def warn_if_missing_access_list(
    *,
    client: NPMplusClient,
    access_list: str | None,
    kind: str,
    natural_index: str,
) -> None:
    ref = (access_list or "").strip()
    if not ref:
        return
    try:
        access_id = client.get_access_list_id(ref)
    except Exception:
        access_id = -1
    if access_id <= 0:
        logger.warning(
            "Docker spec references missing access-list; %s %s access_list=%s",
            kind,
            natural_index,
            ref,
        )


def warn_if_missing_certificate(
    *,
    client: NPMplusClient,
    certificate: str | None,
    kind: str,
    natural_index: str,
) -> None:
    ref = (certificate or "").strip()
    if not ref:
        return
    try:
        cert_id = client.get_certificate_id(ref)
    except Exception:
        cert_id = -1
    if cert_id <= 0:
        logger.warning(
            "Docker spec references missing certificate; %s %s certificate=%s",
            kind,
            natural_index,
            ref,
        )


def _label_bool(value: object) -> str | None:
    b = utils.normalize_bool(value)
    if b is None:
        return None
    return "true" if b else "false"


def _bool_label_pairs(payload: Mapping[str, Any], *, fields: tuple[str, ...], prefix: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for field_name in fields:
        if field_name not in payload:
            continue
        v = _label_bool(payload.get(field_name))
        if v is not None:
            out.append((f"{prefix}{field_name}", v))
    return out


def _normalize_proxy_locations(locs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for loc in locs:
        if not isinstance(loc, dict):
            continue
        out.append(
            {
                "path": str(loc.get("path") or "").strip(),
                "forward_host": str(loc.get("forward_host") or "").strip(),
                "forward_port": utils.normalize_int(loc.get("forward_port"), default=0),
                "forward_scheme": str(loc.get("forward_scheme") or "").strip().lower(),
                "advanced_config": str(loc.get("advanced_config") or ""),
                "location_type": str(loc.get("location_type") or ""),
                "allow_websocket_upgrade": utils.bool_or(loc.get("allow_websocket_upgrade"), default=False),
                "block_exploits": utils.bool_or(loc.get("block_exploits"), default=False),
                "caching_enabled": utils.bool_or(loc.get("caching_enabled"), default=False),
            }
        )
    return out


class ProxyHostFields:
    @staticmethod
    def _get_locations(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
        locs = payload.get("locations")
        if locs is None:
            return []
        if isinstance(locs, dict):
            return [locs]
        if isinstance(locs, list):
            return [x for x in locs if isinstance(x, dict)]
        return []

    @staticmethod
    def labels_from_proxy_host_payload(
        payload: Mapping[str, Any],
        *,
        label_prefix: str,
    ) -> list[tuple[str, str]]:
        prefix = (label_prefix or "").strip() or "npmp."
        if not prefix.endswith((".", "-")):
            prefix += "."

        domains_v = payload.get("domain_names") or payload.get("domainNames")
        if isinstance(domains_v, list):
            domains = [str(d).strip() for d in domains_v if str(d).strip()]
        else:
            domains = utils.parse_domain_names(str(domains_v or "")) if domains_v is not None else []
        forward_host = str(payload.get("forward_host") or payload.get("forwardHost") or "").strip()
        forward_scheme = str(payload.get("forward_scheme") or payload.get("forwardScheme") or "").strip().lower()
        forward_port_int = utils.parse_port(payload.get("forward_port") or payload.get("forwardPort"), field="forward_port")

        labels: list[tuple[str, str]] = []
        labels.append((f"{prefix}domain_names", ",".join(domains)))
        labels.append((f"{prefix}forward_host", forward_host))
        labels.append((f"{prefix}forward_port", str(forward_port_int)))
        labels.append((f"{prefix}forward_scheme", forward_scheme))

        locations = ProxyHostFields._get_locations(payload)
        for idx, loc in enumerate(locations, start=1):
            path = str(loc.get("path") or "").strip()
            loc_forward_host = str(loc.get("forward_host")).strip()
            loc_forward_port = loc.get("forward_port")
            loc_forward_scheme = str(loc.get("forward_scheme") or str(forward_scheme)).strip()
            if not path or not loc_forward_host or loc_forward_port is None:
                continue
            try:
                loc_forward_port_int = utils.parse_port(loc_forward_port, field="forward_port")
            except Exception:
                continue
            labels.append((f"{prefix}loc{idx}_path", path))
            labels.append((f"{prefix}loc{idx}_forward_host", loc_forward_host))
            labels.append((f"{prefix}loc{idx}_forward_port", str(loc_forward_port_int)))
            labels.append((f"{prefix}loc{idx}_forward_scheme", loc_forward_scheme.strip().lower()))

            loc_adv = loc.get("advanced_config")
            if loc_adv is not None and str(loc_adv).strip():
                labels.append((f"{prefix}loc{idx}_advanced_config", str(loc_adv)))

            loc_type = loc.get("location_type")
            if loc_type is not None and str(loc_type).strip():
                labels.append((f"{prefix}loc{idx}_location_type", str(loc_type).strip()))

            allow_websocket_upgrade = loc.get("allow_websocket_upgrade")
            if allow_websocket_upgrade is not None:
                b = _label_bool(allow_websocket_upgrade)
                if b is not None:
                    labels.append((f"{prefix}loc{idx}_allow_websocket_upgrade", b))

            block_exploits = loc.get("block_exploits")
            if block_exploits is not None:
                b = _label_bool(block_exploits)
                if b is not None:
                    labels.append((f"{prefix}loc{idx}_block_exploits", b))

            caching_enabled = loc.get("caching_enabled")
            if caching_enabled is not None:
                b = _label_bool(caching_enabled)
                if b is not None:
                    labels.append((f"{prefix}loc{idx}_caching_enabled", b))

        cert_name = utils.certificate_nice_name_from_value(payload.get("certificate"))
        if cert_name:
            labels.append((f"{prefix}certificate", cert_name))

        if access_list := utils.access_list_name_from_value(payload.get("access_list") or payload.get("accessList")):
            labels.append((f"{prefix}access_list", access_list))

        if (adv := payload.get("advanced_config")) is not None and str(adv).strip():
            labels.append((f"{prefix}advanced_config", str(adv)))

        labels.extend(_bool_label_pairs(payload, fields=ProxyHostItem.BOOL_LABEL_FIELDS, prefix=prefix))

        return labels

    @staticmethod
    def item_from_docker_spec(
        docker_spec: DockerProxyHostSpec,
        *,
        client: NPMplusClient,
    ) -> ProxyHostItem:
        locations: list[dict[str, Any]] = []
        for loc in docker_spec.locations:
            locations.append(
                {
                    "path": str(loc.path or "").strip(),
                    "forward_host": str(loc.forward_host or "").strip(),
                    "forward_port": utils.parse_port(loc.forward_port, field="forward_port"),
                    "forward_scheme": str(loc.forward_scheme or "").strip().lower(),
                    "advanced_config": str(loc.advanced_config or ""),
                    "location_type": str(loc.location_type or ""),
                    "allow_websocket_upgrade": utils.bool_or(loc.allow_websocket_upgrade, default=False),
                    "block_exploits": utils.bool_or(loc.block_exploits, default=False),
                    "caching_enabled": utils.bool_or(loc.caching_enabled, default=False),
                }
            )

        return ProxyHostItem(
            api=client,
            domain_names=list(docker_spec.domain_names),
            forward_scheme=str(docker_spec.forward_scheme or "").strip().lower(),
            forward_host=str(docker_spec.forward_host or "").strip(),
            forward_port=utils.parse_port(docker_spec.forward_port, field="forward_port"),
            enabled=utils.bool_or(docker_spec.enabled, default=True),
            access_list=(docker_spec.access_list or None),
            certificate=(docker_spec.certificate or None),
            ssl_forced=utils.bool_or(docker_spec.ssl_forced, default=False),
            caching_enabled=utils.bool_or(docker_spec.caching_enabled, default=False),
            block_exploits=utils.bool_or(docker_spec.block_exploits, default=False),
            allow_websocket_upgrade=utils.bool_or(docker_spec.allow_websocket_upgrade, default=False),
            http2_support=utils.bool_or(docker_spec.http2_support, default=False),
            hsts_enabled=utils.bool_or(docker_spec.hsts_enabled, default=False),
            hsts_subdomains=utils.bool_or(docker_spec.hsts_subdomains, default=False),
            advanced_config=str(docker_spec.advanced_config or ""),
            locations=locations,
        )

    @staticmethod
    def items_equal(desired: ProxyHostItem, existing: ProxyHostItem) -> bool:
        if desired.enabled != existing.enabled:
            return False
        desired_payload = desired.to_payload()
        existing_payload = existing.to_payload()
        desired_payload["domain_names"] = list(utils.domain_key(desired_payload.get("domain_names")) or [])
        existing_payload["domain_names"] = list(utils.domain_key(existing_payload.get("domain_names")) or [])
        desired_payload["locations"] = _normalize_proxy_locations(desired_payload.get("locations") or [])
        existing_payload["locations"] = _normalize_proxy_locations(existing_payload.get("locations") or [])
        return desired_payload == existing_payload


class DeadHostFields:
    @staticmethod
    def labels_from_dead_host_payload(
        payload: Mapping[str, Any],
        *,
        label_prefix: str,
    ) -> list[tuple[str, str]]:
        prefix = (label_prefix or "").strip() or "npmp.dead."
        if not prefix.endswith((".", "-")):
            prefix += "."

        domains_v = payload.get("domain_names") or payload.get("domainNames")
        if isinstance(domains_v, list):
            domains = [str(d).strip() for d in domains_v if str(d).strip()]
        else:
            domains = utils.parse_domain_names(str(domains_v or "")) if domains_v is not None else []

        labels: list[tuple[str, str]] = [(f"{prefix}domain_names", ",".join(domains))]

        cert_name = utils.certificate_nice_name_from_value(payload.get("certificate"))
        if cert_name:
            labels.append((f"{prefix}certificate", cert_name))

        if (adv := payload.get("advanced_config")) is not None and str(adv).strip():
            labels.append((f"{prefix}advanced_config", str(adv)))

        labels.extend(_bool_label_pairs(payload, fields=DeadHostItem.BOOL_LABEL_FIELDS, prefix=prefix))

        return labels

    @staticmethod
    def item_from_docker_spec(
        docker_spec: DockerDeadHostSpec,
        *,
        client: NPMplusClient,
    ) -> DeadHostItem:
        return DeadHostItem(
            api=client,
            domain_names=list(docker_spec.domain_names),
            enabled=utils.bool_or(docker_spec.enabled, default=True),
            ssl_forced=utils.bool_or(docker_spec.ssl_forced, default=False),
            http2_support=utils.bool_or(docker_spec.http2_support, default=False),
            hsts_enabled=utils.bool_or(docker_spec.hsts_enabled, default=False),
            hsts_subdomains=utils.bool_or(docker_spec.hsts_subdomains, default=False),
            certificate=(docker_spec.certificate or None),
            advanced_config=str(docker_spec.advanced_config or ""),
        )

    @staticmethod
    def items_equal(desired: DeadHostItem, existing: DeadHostItem) -> bool:
        if desired.enabled != existing.enabled:
            return False
        return desired.to_payload() == existing.to_payload()


class RedirectionHostFields:
    @staticmethod
    def labels_from_redirection_host_payload(
        payload: Mapping[str, Any],
        *,
        label_prefix: str,
    ) -> list[tuple[str, str]]:
        prefix = (label_prefix or "").strip() or "npmp.redirect."
        if not prefix.endswith((".", "-")):
            prefix += "."

        domains_v = payload.get("domain_names") or payload.get("domainNames")
        if isinstance(domains_v, list):
            domains = [str(d).strip() for d in domains_v if str(d).strip()]
        else:
            domains = utils.parse_domain_names(str(domains_v or "")) if domains_v is not None else []
        forward_domain_name = str(payload.get("forward_domain_name") or payload.get("forwardDomainName") or "").strip()
        forward_http_code = utils.normalize_int(payload.get("forward_http_code") or payload.get("forwardHttpCode"), default=0)
        forward_scheme = str(payload.get("forward_scheme") or payload.get("forwardScheme") or "").strip().lower()

        labels: list[tuple[str, str]] = [
            (f"{prefix}domain_names", ",".join(domains)),
            (f"{prefix}forward_domain_name", forward_domain_name),
            (f"{prefix}forward_http_code", str(forward_http_code)),
            (f"{prefix}forward_scheme", forward_scheme),
        ]

        cert_name = utils.certificate_nice_name_from_value(payload.get("certificate"))
        if cert_name:
            labels.append((f"{prefix}certificate", cert_name))
        if (adv := payload.get("advanced_config")) is not None and str(adv).strip():
            labels.append((f"{prefix}advanced_config", str(adv)))

        labels.extend(_bool_label_pairs(payload, fields=RedirectionHostItem.BOOL_LABEL_FIELDS, prefix=prefix))

        return labels

    @staticmethod
    def item_from_docker_spec(
        docker_spec: DockerRedirectionHostSpec,
        *,
        client: NPMplusClient,
    ) -> RedirectionHostItem:
        return RedirectionHostItem(
            api=client,
            domain_names=list(docker_spec.domain_names),
            forward_scheme=str(docker_spec.forward_scheme or "").strip().lower(),
            forward_domain_name=str(docker_spec.forward_domain_name or "").strip(),
            forward_http_code=utils.normalize_int(docker_spec.forward_http_code, default=0),
            enabled=utils.bool_or(docker_spec.enabled, default=True),
            preserve_path=utils.bool_or(docker_spec.preserve_path, default=False),
            block_exploits=utils.bool_or(docker_spec.block_exploits, default=False),
            ssl_forced=utils.bool_or(docker_spec.ssl_forced, default=False),
            http2_support=utils.bool_or(docker_spec.http2_support, default=False),
            hsts_enabled=utils.bool_or(docker_spec.hsts_enabled, default=False),
            hsts_subdomains=utils.bool_or(docker_spec.hsts_subdomains, default=False),
            certificate=(docker_spec.certificate or None),
            advanced_config=str(docker_spec.advanced_config or ""),
        )

    @staticmethod
    def items_equal(desired: RedirectionHostItem, existing: RedirectionHostItem) -> bool:
        if desired.enabled != existing.enabled:
            return False
        desired_payload = desired.to_payload()
        existing_payload = existing.to_payload()
        desired_payload["domain_names"] = list(utils.domain_key(desired_payload.get("domain_names")) or [])
        existing_payload["domain_names"] = list(utils.domain_key(existing_payload.get("domain_names")) or [])
        return desired_payload == existing_payload


class StreamFields:
    @staticmethod
    def labels_from_stream_payload(
        payload: Mapping[str, Any],
        *,
        label_prefix: str,
    ) -> list[tuple[str, str]]:
        prefix = (label_prefix or "").strip() or "npmp.stream."
        if not prefix.endswith((".", "-")):
            prefix += "."

        incoming_port_int = utils.parse_port(payload.get("incoming_port") or payload.get("incomingPort"), field="incoming_port")
        forwarding_host = str(payload.get("forwarding_host") or payload.get("forwardingHost") or "").strip()
        forwarding_port_int = utils.parse_port(payload.get("forwarding_port") or payload.get("forwardingPort"), field="forwarding_port")

        labels: list[tuple[str, str]] = [
            (f"{prefix}incoming_port", str(incoming_port_int)),
            (f"{prefix}forwarding_host", forwarding_host),
            (f"{prefix}forwarding_port", str(forwarding_port_int)),
        ]

        cert_name = utils.certificate_nice_name_from_value(payload.get("certificate"))
        if cert_name:
            labels.append((f"{prefix}certificate", cert_name))

        labels.extend(_bool_label_pairs(payload, fields=StreamItem.BOOL_LABEL_FIELDS, prefix=prefix))

        return labels

    @staticmethod
    def item_from_docker_spec(
        docker_spec: DockerStreamSpec,
        *,
        client: NPMplusClient,
    ) -> StreamItem:
        incoming_port = int(utils.parse_port(docker_spec.incoming_port, field="incoming_port"))
        forwarding_port = int(utils.parse_port(docker_spec.forwarding_port, field="forwarding_port"))
        item = StreamItem(
            api=client,
            incoming_port=incoming_port,
            forwarding_host=docker_spec.forwarding_host,
            forwarding_port=forwarding_port,
        )
        if docker_spec.tcp_forwarding is not None:
            item.tcp_forwarding = docker_spec.tcp_forwarding
        if docker_spec.udp_forwarding is not None:
            item.udp_forwarding = docker_spec.udp_forwarding
        if docker_spec.proxy_protocol_forwarding is not None:
            item.proxy_protocol_forwarding = docker_spec.proxy_protocol_forwarding
        if docker_spec.enabled is not None:
            item.enabled = docker_spec.enabled
        item.certificate = docker_spec.certificate
        return item

    @staticmethod
    def items_equal(desired: StreamItem, existing: StreamItem) -> bool:
        if desired.enabled != existing.enabled:
            return False
        return desired.to_payload() == existing.to_payload()


def domain_key(domain_names: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted(d.strip().lower() for d in domain_names if str(d).strip()))


def index_proxy_hosts_by_domains(
    items: Mapping[int, ProxyHostItem],
) -> dict[tuple[str, ...], ProxyHostItem]:
    out: dict[tuple[str, ...], ProxyHostItem] = {}
    for item in items.values():
        key = domain_key(item.domain_names)
        if not key:
            continue
        out.setdefault(key, item)
    return out


def find_orphan_proxy_hosts(
    *,
    existing_items: Mapping[int, ProxyHostItem],
    managed_domain_keys: set[tuple[str, ...]],
    owner_user_id: int,
) -> list[ProxyHostItem]:
    orphans: list[ProxyHostItem] = []
    for item in existing_items.values():
        if item.owner_user_id != owner_user_id:
            continue
        key = domain_key(item.domain_names)
        if not key:
            continue
        if key in managed_domain_keys:
            continue
        orphans.append(item)
    return orphans


def index_dead_hosts_by_domains(
    items: Mapping[int, DeadHostItem],
) -> dict[tuple[str, ...], DeadHostItem]:
    out: dict[tuple[str, ...], DeadHostItem] = {}
    for item in items.values():
        key = domain_key(item.domain_names)
        if not key:
            continue
        out.setdefault(key, item)
    return out


def find_orphan_dead_hosts(
    *,
    existing_items: Mapping[int, DeadHostItem],
    managed_domain_keys: set[tuple[str, ...]],
    owner_user_id: int,
) -> list[DeadHostItem]:
    orphans: list[DeadHostItem] = []
    for item in existing_items.values():
        if item.owner_user_id != owner_user_id:
            continue
        key = domain_key(item.domain_names)
        if not key:
            continue
        if key in managed_domain_keys:
            continue
        orphans.append(item)
    return orphans


def index_redirection_hosts_by_domains(
    items: Mapping[int, RedirectionHostItem],
) -> dict[tuple[str, ...], RedirectionHostItem]:
    out: dict[tuple[str, ...], RedirectionHostItem] = {}
    for item in items.values():
        key = domain_key(item.domain_names)
        if not key:
            continue
        out.setdefault(key, item)
    return out


def find_orphan_redirection_hosts(
    *,
    existing_items: Mapping[int, RedirectionHostItem],
    managed_domain_keys: set[tuple[str, ...]],
    owner_user_id: int,
) -> list[RedirectionHostItem]:
    orphans: list[RedirectionHostItem] = []
    for item in existing_items.values():
        if item.owner_user_id != owner_user_id:
            continue
        key = domain_key(item.domain_names)
        if not key:
            continue
        if key in managed_domain_keys:
            continue
        orphans.append(item)
    return orphans


def index_streams_by_port(
    items: Mapping[int, StreamItem],
) -> dict[int, StreamItem]:
    out: dict[int, StreamItem] = {}
    for item in items.values():
        port = item.incoming_port
        if not port:
            continue
        port_int = int(port)
        out.setdefault(port_int, item)
    return out


def find_orphan_streams(
    *,
    existing_items: Mapping[int, StreamItem],
    managed_port_keys: set[int],
    owner_user_id: int,
) -> list[StreamItem]:
    orphans: list[StreamItem] = []
    for item in existing_items.values():
        if item.owner_user_id != owner_user_id:
            continue
        port = item.incoming_port
        if not port:
            continue
        port_int = int(port)
        if port_int in managed_port_keys:
            continue
        orphans.append(item)
    return orphans
