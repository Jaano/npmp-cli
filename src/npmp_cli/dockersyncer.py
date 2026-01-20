from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .configmanager import ConfigManager
from .npmplus_client import (
    AccessListItem,
    DeadHostItem,
    NPMplusClient,
    NPMplusItemType,
    ProxyHostItem,
    RedirectionHostItem,
    StreamItem,
)

logger = ConfigManager.get_logger(__name__)


@dataclass(frozen=True)
class DockerLocationSpec:
    path: str
    forward_host: str
    forward_port: int
    forward_scheme: str
    advanced_config: str | None = None
    allow_websocket_upgrade: bool | None = None
    block_exploits: bool | None = None
    caching_enabled: bool | None = None
    location_type: str | None = None


@dataclass(frozen=True)
class DockerProxyHostSpec:
    container_id: str
    container_name: str
    domain_names: list[str]
    forward_host: str
    forward_port: int
    forward_scheme: str
    locations: list[DockerLocationSpec] = field(default_factory=list)
    access_list: str | None = None
    advanced_config: str | None = None
    allow_websocket_upgrade: bool | None = None
    block_exploits: bool | None = None
    caching_enabled: bool | None = None
    certificate: str | None = None
    enabled: bool | None = None
    hsts_enabled: bool | None = None
    hsts_subdomains: bool | None = None
    http2_support: bool | None = None
    ssl_forced: bool | None = None


@dataclass(frozen=True)
class DockerDeadHostSpec:
    container_id: str
    container_name: str
    domain_names: list[str]
    certificate: str | None = None
    enabled: bool | None = None
    ssl_forced: bool | None = None
    hsts_enabled: bool | None = None
    hsts_subdomains: bool | None = None
    http2_support: bool | None = None
    advanced_config: str | None = None


@dataclass(frozen=True)
class DockerRedirectionHostSpec:
    container_id: str
    container_name: str
    domain_names: list[str]
    forward_domain_name: str
    forward_http_code: int
    forward_scheme: str
    preserve_path: bool | None = None
    certificate: str | None = None
    enabled: bool | None = None
    ssl_forced: bool | None = None
    block_exploits: bool | None = None
    hsts_enabled: bool | None = None
    hsts_subdomains: bool | None = None
    http2_support: bool | None = None
    advanced_config: str | None = None


@dataclass(frozen=True)
class DockerStreamSpec:
    container_id: str
    container_name: str
    incoming_port: int
    forwarding_host: str
    forwarding_port: int
    tcp_forwarding: bool | None = None
    udp_forwarding: bool | None = None
    proxy_protocol_forwarding: bool | None = None
    certificate: str | None = None
    enabled: bool | None = None


def _split_csv(value: str) -> list[str]:
    parts = [p.strip() for p in (value or "").split(",")]
    return [p for p in parts if p]


def _parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return None


class DockerSyncer:
    _LABEL_PATTERN = re.compile(r"^npmp\.(proxy|dead|redirect|stream)(\d*)\.(.+)$")

    @staticmethod
    def _parse_grouped_labels(
        labels: dict[str, str],
        base_prefix: str,
    ) -> dict[str, dict[str, str]]:
        """Group labels by type and index.

        Returns dict keyed by (type, index) -> field_dict.
        Index is empty string for unnumbered labels.
        """
        grouped: dict[str, dict[str, str]] = {}
        prefix = base_prefix.rstrip(".")
        pattern = re.compile(rf"^{re.escape(prefix)}\.(proxy|dead|redirect|stream)(\d*)\.(.+)$")

        for key, value in labels.items():
            m = pattern.match(key)
            if not m:
                continue
            item_type = m.group(1)
            idx = m.group(2)
            field = m.group(3)
            group_key = f"{item_type}{idx}"
            grouped.setdefault(group_key, {})[field] = value

        return grouped

    @staticmethod
    def extract_proxy_host_spec_from_grouped_labels(
        fields: dict[str, str],
        *,
        container_id: str,
        container_name: str,
        base_prefix: str,
    ) -> DockerProxyHostSpec | None:
        """Extract a proxy-host spec from grouped label fields."""
        domains_raw = fields.get("domain_names")
        forward_host = fields.get("forward_host")
        forward_port_raw = fields.get("forward_port")
        forward_scheme = fields.get("forward_scheme")

        if not domains_raw or not forward_host or not forward_port_raw or not forward_scheme:
            return None

        domain_names = [d.lower() for d in _split_csv(domains_raw)]
        if not domain_names:
            return None

        try:
            forward_port = int(str(forward_port_raw).strip())
        except Exception:
            return None
        if forward_port <= 0 or forward_port > 65535:
            return None

        loc_pattern = re.compile(r"^loc(\d+)_(.+)$")
        loc_groups: dict[int, dict[str, str]] = {}
        for k, v in fields.items():
            m = loc_pattern.match(k)
            if not m:
                continue
            try:
                idx = int(m.group(1))
            except Exception:
                continue
            if idx <= 0:
                continue
            loc_groups.setdefault(idx, {})[m.group(2)] = v

        locations: list[DockerLocationSpec] = []
        for idx in sorted(loc_groups.keys()):
            g = loc_groups[idx]
            path = str(g.get("path") or "").strip()
            loc_forward_host = str(g.get("forward_host") or "").strip()
            loc_forward_port_raw = g.get("forward_port")
            loc_forward_scheme = str(g.get("forward_scheme") or str(forward_scheme)).strip()
            if not path or not loc_forward_host or not loc_forward_port_raw:
                continue
            try:
                loc_forward_port = int(str(loc_forward_port_raw).strip())
            except Exception:
                continue
            if loc_forward_port <= 0 or loc_forward_port > 65535:
                continue
            locations.append(
                DockerLocationSpec(
                    path=path,
                    forward_host=loc_forward_host,
                    forward_port=loc_forward_port,
                    forward_scheme=loc_forward_scheme,
                    advanced_config=(None if g.get("advanced_config") is None else str(g.get("advanced_config"))),
                    allow_websocket_upgrade=_parse_bool(g.get("allow_websocket_upgrade")),
                    block_exploits=_parse_bool(g.get("block_exploits")),
                    caching_enabled=_parse_bool(g.get("caching_enabled")),
                    location_type=(None if g.get("location_type") is None else str(g.get("location_type")).strip()),
                )
            )

        return DockerProxyHostSpec(
            container_id=container_id,
            container_name=(container_name.lstrip("/") if container_name else container_id[:12]),
            domain_names=domain_names,
            forward_host=str(forward_host).strip(),
            forward_port=forward_port,
            forward_scheme=str(forward_scheme).strip(),
            locations=locations,
            access_list=None if fields.get("access_list") is None else str(fields.get("access_list")).strip(),
            advanced_config=None if fields.get("advanced_config") is None else str(fields.get("advanced_config")),
            allow_websocket_upgrade=_parse_bool(fields.get("allow_websocket_upgrade")),
            block_exploits=_parse_bool(fields.get("block_exploits")),
            caching_enabled=_parse_bool(fields.get("caching_enabled")),
            certificate=(None if fields.get("certificate") is None else str(fields.get("certificate")).strip()),
            enabled=_parse_bool(fields.get("enabled")),
            hsts_enabled=_parse_bool(fields.get("hsts_enabled")),
            hsts_subdomains=_parse_bool(fields.get("hsts_subdomains")),
            http2_support=_parse_bool(fields.get("http2_support")),
            ssl_forced=_parse_bool(fields.get("ssl_forced")),
        )

    @staticmethod
    def extract_dead_host_spec_from_grouped_labels(
        fields: dict[str, str],
        *,
        container_id: str,
        container_name: str,
    ) -> DockerDeadHostSpec | None:
        """Extract a dead-host spec from grouped label fields."""
        domains_raw = fields.get("domain_names")
        if not domains_raw:
            return None

        domain_names = [d.lower() for d in _split_csv(domains_raw)]
        if not domain_names:
            return None

        return DockerDeadHostSpec(
            container_id=container_id,
            container_name=(container_name.lstrip("/") if container_name else container_id[:12]),
            domain_names=domain_names,
            certificate=(None if fields.get("certificate") is None else str(fields.get("certificate")).strip()),
            enabled=_parse_bool(fields.get("enabled")),
            ssl_forced=_parse_bool(fields.get("ssl_forced")),
            hsts_enabled=_parse_bool(fields.get("hsts_enabled")),
            hsts_subdomains=_parse_bool(fields.get("hsts_subdomains")),
            http2_support=_parse_bool(fields.get("http2_support")),
            advanced_config=None if fields.get("advanced_config") is None else str(fields.get("advanced_config")),
        )

    @staticmethod
    def extract_redirection_host_spec_from_grouped_labels(
        fields: dict[str, str],
        *,
        container_id: str,
        container_name: str,
    ) -> DockerRedirectionHostSpec | None:
        """Extract a redirection-host spec from grouped label fields."""
        domains_raw = fields.get("domain_names")
        forward_domain_name = fields.get("forward_domain_name")
        forward_http_code_raw = fields.get("forward_http_code")
        forward_scheme = fields.get("forward_scheme")

        if not domains_raw or not forward_domain_name or not forward_http_code_raw or not forward_scheme:
            return None

        domain_names = [d.lower() for d in _split_csv(domains_raw)]
        if not domain_names:
            return None

        try:
            forward_http_code = int(str(forward_http_code_raw).strip())
        except Exception:
            return None

        return DockerRedirectionHostSpec(
            container_id=container_id,
            container_name=(container_name.lstrip("/") if container_name else container_id[:12]),
            domain_names=domain_names,
            forward_domain_name=str(forward_domain_name).strip(),
            forward_http_code=forward_http_code,
            forward_scheme=str(forward_scheme).strip(),
            preserve_path=_parse_bool(fields.get("preserve_path")),
            certificate=(None if fields.get("certificate") is None else str(fields.get("certificate")).strip()),
            enabled=_parse_bool(fields.get("enabled")),
            ssl_forced=_parse_bool(fields.get("ssl_forced")),
            block_exploits=_parse_bool(fields.get("block_exploits")),
            hsts_enabled=_parse_bool(fields.get("hsts_enabled")),
            hsts_subdomains=_parse_bool(fields.get("hsts_subdomains")),
            http2_support=_parse_bool(fields.get("http2_support")),
            advanced_config=None if fields.get("advanced_config") is None else str(fields.get("advanced_config")),
        )

    @staticmethod
    def extract_stream_spec_from_grouped_labels(
        fields: dict[str, str],
        *,
        container_id: str,
        container_name: str,
    ) -> DockerStreamSpec | None:
        """Extract a stream spec from grouped label fields."""
        incoming_port_raw = fields.get("incoming_port")
        forwarding_host = fields.get("forwarding_host")
        forwarding_port_raw = fields.get("forwarding_port")

        if not incoming_port_raw or not forwarding_host or not forwarding_port_raw:
            return None

        try:
            incoming_port = int(str(incoming_port_raw).strip())
        except Exception:
            return None
        if incoming_port <= 0 or incoming_port > 65535:
            return None

        try:
            forwarding_port = int(str(forwarding_port_raw).strip())
        except Exception:
            return None
        if forwarding_port <= 0 or forwarding_port > 65535:
            return None

        return DockerStreamSpec(
            container_id=container_id,
            container_name=(container_name.lstrip("/") if container_name else container_id[:12]),
            incoming_port=incoming_port,
            forwarding_host=str(forwarding_host).strip(),
            forwarding_port=forwarding_port,
            tcp_forwarding=_parse_bool(fields.get("tcp_forwarding")),
            udp_forwarding=_parse_bool(fields.get("udp_forwarding")),
            proxy_protocol_forwarding=_parse_bool(fields.get("proxy_protocol_forwarding")),
            certificate=(None if fields.get("certificate") is None else str(fields.get("certificate")).strip()),
            enabled=_parse_bool(fields.get("enabled")),
        )

    @staticmethod
    def extract_all_specs_from_labels(
        *,
        labels: dict[str, str] | None,
        container_id: str,
        container_name: str,
    ) -> tuple[
        list[DockerProxyHostSpec],
        list[DockerDeadHostSpec],
        list[DockerRedirectionHostSpec],
        list[DockerStreamSpec],
    ]:
        """Extract all spec types from Docker container labels.

        Uses the new label schema: npmp.<type>[N].<field>
        """
        labels = labels or {}
        base_prefix = ConfigManager.docker_label_prefix().rstrip(".")

        proxy_specs: list[DockerProxyHostSpec] = []
        dead_specs: list[DockerDeadHostSpec] = []
        redirect_specs: list[DockerRedirectionHostSpec] = []
        stream_specs: list[DockerStreamSpec] = []

        grouped = DockerSyncer._parse_grouped_labels(labels, base_prefix + ".")
        for group_key, fields in grouped.items():
            if group_key.startswith("proxy"):
                spec = DockerSyncer.extract_proxy_host_spec_from_grouped_labels(
                    fields, container_id=container_id, container_name=container_name, base_prefix=base_prefix
                )
                if spec is not None:
                    proxy_specs.append(spec)
            elif group_key.startswith("dead"):
                spec = DockerSyncer.extract_dead_host_spec_from_grouped_labels(
                    fields, container_id=container_id, container_name=container_name
                )
                if spec is not None:
                    dead_specs.append(spec)
            elif group_key.startswith("redirect"):
                spec = DockerSyncer.extract_redirection_host_spec_from_grouped_labels(
                    fields, container_id=container_id, container_name=container_name
                )
                if spec is not None:
                    redirect_specs.append(spec)
            elif group_key.startswith("stream"):
                spec = DockerSyncer.extract_stream_spec_from_grouped_labels(
                    fields, container_id=container_id, container_name=container_name
                )
                if spec is not None:
                    stream_specs.append(spec)

        return proxy_specs, dead_specs, redirect_specs, stream_specs

    @staticmethod
    def extract_proxy_host_spec_from_labels(
        *,
        labels: dict[str, str] | None,
        container_id: str,
        container_name: str,
    ) -> DockerProxyHostSpec | None:
        """Extract a proxy-host spec from Docker container labels.

        Parses labels with the configured prefix and returns a DockerProxyHostSpec
        if all required fields are present and valid.
        """
        labels = labels or {}
        prefix = ConfigManager.docker_label_prefix()
        prefixed = {k: v for k, v in labels.items() if isinstance(k, str) and k.startswith(prefix)}
        if not prefixed:
            return None

        domains_raw = labels.get(f"{prefix}domain_names")
        forward_host = labels.get(f"{prefix}forward_host")
        forward_port_raw = labels.get(f"{prefix}forward_port")
        forward_scheme = labels.get(f"{prefix}forward_scheme")

        access_list = labels.get(f"{prefix}access_list")
        advanced_config = labels.get(f"{prefix}advanced_config")
        allow_websocket_upgrade = _parse_bool(labels.get(f"{prefix}allow_websocket_upgrade"))
        block_exploits = _parse_bool(labels.get(f"{prefix}block_exploits"))
        caching_enabled = _parse_bool(labels.get(f"{prefix}caching_enabled"))
        certificate_raw = labels.get(f"{prefix}certificate")
        enabled = _parse_bool(labels.get(f"{prefix}enabled"))
        hsts_enabled = _parse_bool(labels.get(f"{prefix}hsts_enabled"))
        hsts_subdomains = _parse_bool(labels.get(f"{prefix}hsts_subdomains"))
        http2_support = _parse_bool(labels.get(f"{prefix}http2_support"))
        ssl_forced = _parse_bool(labels.get(f"{prefix}ssl_forced"))

        loc_pattern = re.compile(rf"^{re.escape(prefix)}loc(\d+)_(.+)$")
        loc_groups: dict[int, dict[str, str]] = {}
        for k, v in prefixed.items():
            m = loc_pattern.match(k)
            if not m:
                continue
            try:
                idx = int(m.group(1))
            except Exception:
                continue
            if idx <= 0:
                continue
            loc_groups.setdefault(idx, {})[m.group(2)] = v

        if not domains_raw or not forward_host or not forward_port_raw or not forward_scheme:
            return None

        domain_names = [d.lower() for d in _split_csv(domains_raw)]
        if not domain_names:
            return None

        try:
            forward_port = int(str(forward_port_raw).strip())
        except Exception:
            return None
        if forward_port <= 0 or forward_port > 65535:
            return None

        locations: list[DockerLocationSpec] = []
        for idx in sorted(loc_groups.keys()):
            g = loc_groups[idx]
            path = str(g.get("path") or "").strip()
            loc_forward_host = str(g.get("forward_host") or "").strip()
            loc_forward_port_raw = g.get("forward_port")
            loc_forward_scheme = str(g.get("forward_scheme") or str(forward_scheme)).strip()
            if not path or not loc_forward_host or not loc_forward_port_raw:
                continue
            try:
                loc_forward_port = int(str(loc_forward_port_raw).strip())
            except Exception:
                continue
            if loc_forward_port <= 0 or loc_forward_port > 65535:
                continue
            locations.append(
                DockerLocationSpec(
                    path=path,
                    forward_host=loc_forward_host,
                    forward_port=loc_forward_port,
                    forward_scheme=loc_forward_scheme,
                    advanced_config=(None if g.get("advanced_config") is None else str(g.get("advanced_config"))),
                    allow_websocket_upgrade=_parse_bool(g.get("allow_websocket_upgrade")),
                    block_exploits=_parse_bool(g.get("block_exploits")),
                    caching_enabled=_parse_bool(g.get("caching_enabled")),
                    location_type=(None if g.get("location_type") is None else str(g.get("location_type")).strip()),
                )
            )

        return DockerProxyHostSpec(
            container_id=container_id,
            container_name=(container_name.lstrip("/") if container_name else container_id[:12]),
            domain_names=domain_names,
            forward_host=str(forward_host).strip(),
            forward_port=forward_port,
            forward_scheme=str(forward_scheme).strip(),
            locations=locations,
            access_list=None if access_list is None else str(access_list).strip(),
            advanced_config=None if advanced_config is None else str(advanced_config),
            allow_websocket_upgrade=allow_websocket_upgrade,
            block_exploits=block_exploits,
            caching_enabled=caching_enabled,
            certificate=(None if certificate_raw is None else str(certificate_raw).strip()),
            enabled=enabled,
            hsts_enabled=hsts_enabled,
            hsts_subdomains=hsts_subdomains,
            http2_support=http2_support,
            ssl_forced=ssl_forced,
        )

    @staticmethod
    def extract_proxy_host_specs_from_inspect(
        inspect_data: Sequence[dict[str, Any]],
    ) -> list[DockerProxyHostSpec]:
        """Extract proxy-host specs from Docker inspect data.

        Parses inspect data (like container.attrs from Docker SDK) and returns
        proxy-host specs for containers with valid label configuration.
        """
        specs: list[DockerProxyHostSpec] = []
        for item in inspect_data:
            container_id = str(item.get("Id") or "").strip()
            container_name = str(item.get("Name") or "").strip()
            labels = ((item.get("Config") or {}) if isinstance(item.get("Config"), dict) else {}).get("Labels") or {}
            if not isinstance(labels, dict):
                labels = {}
            spec = DockerSyncer.extract_proxy_host_spec_from_labels(
                labels={str(k): str(v) for k, v in labels.items() if k is not None and v is not None},
                container_id=container_id,
                container_name=container_name,
            )
            if spec is not None:
                specs.append(spec)
        return specs

    @classmethod
    def scan_docker_proxy_host_specs(cls) -> list[DockerProxyHostSpec]:
        """Scan all Docker containers and extract proxy-host specs from labels.

        Uses the Python Docker SDK (`docker` module) via `docker.from_env()`.
        Respects the DOCKER_HOST environment variable; if not set, connects to
        the local Docker socket (unix:///var/run/docker.sock on Unix systems).
        """
        try:
            import docker  # type: ignore[import-not-found]
        except Exception as e:
            raise RuntimeError("Python docker module not installed; install 'docker' package") from e

        try:
            client = docker.from_env()
        except Exception as e:
            raise RuntimeError("Failed to initialize Docker client from environment") from e

        try:
            containers = client.containers.list(all=True)
        except Exception as e:
            raise RuntimeError("Failed to list docker containers") from e

        inspect_items: list[dict[str, Any]] = []
        for c in containers:
            try:
                attrs = getattr(c, "attrs", None) or {}
                if isinstance(attrs, dict):
                    inspect_items.append(attrs)
            except Exception:
                # Skip containers that cannot be inspected.
                continue

        specs = cls.extract_proxy_host_specs_from_inspect(inspect_items)
        logger.info(
            "Found %s docker container specs with required prefix=%s",
            len(specs),
            ConfigManager.docker_label_prefix(),
        )
        return specs

    @classmethod
    def _get_docker_inspect_items(cls) -> list[dict[str, Any]]:
        """Get Docker inspect data for all containers."""
        try:
            import docker  # type: ignore[import-not-found]
        except Exception as e:
            raise RuntimeError("Python docker module not installed; install 'docker' package") from e

        try:
            client = docker.from_env()
        except Exception as e:
            raise RuntimeError("Failed to initialize Docker client from environment") from e

        try:
            containers = client.containers.list(all=True)
        except Exception as e:
            raise RuntimeError("Failed to list docker containers") from e

        inspect_items: list[dict[str, Any]] = []
        for c in containers:
            try:
                attrs = getattr(c, "attrs", None) or {}
                if isinstance(attrs, dict):
                    inspect_items.append(attrs)
            except Exception:
                continue

        return inspect_items

    @classmethod
    def scan_docker_specs(
        cls,
    ) -> tuple[
        list[DockerProxyHostSpec],
        list[DockerDeadHostSpec],
        list[DockerRedirectionHostSpec],
        list[DockerStreamSpec],
    ]:
        """Scan all Docker containers and extract all spec types from labels.

        Uses the new label schema: npmp.<type>[N].<field>
        Returns tuple of (proxy_specs, dead_specs, redirect_specs, stream_specs).
        """
        inspect_items = cls._get_docker_inspect_items()

        all_proxy: list[DockerProxyHostSpec] = []
        all_dead: list[DockerDeadHostSpec] = []
        all_redirect: list[DockerRedirectionHostSpec] = []
        all_stream: list[DockerStreamSpec] = []

        for item in inspect_items:
            container_id = str(item.get("Id") or "").strip()
            container_name = str(item.get("Name") or "").strip()
            labels = ((item.get("Config") or {}) if isinstance(item.get("Config"), dict) else {}).get("Labels") or {}
            if not isinstance(labels, dict):
                labels = {}

            proxy_specs, dead_specs, redirect_specs, stream_specs = cls.extract_all_specs_from_labels(
                labels={str(k): str(v) for k, v in labels.items() if k is not None and v is not None},
                container_id=container_id,
                container_name=container_name,
            )
            all_proxy.extend(proxy_specs)
            all_dead.extend(dead_specs)
            all_redirect.extend(redirect_specs)
            all_stream.extend(stream_specs)

        prefix = ConfigManager.docker_label_prefix()
        logger.info(
            "Scan found proxy=%d dead=%d redirect=%d stream=%d with prefix=%s",
            len(all_proxy),
            len(all_dead),
            len(all_redirect),
            len(all_stream),
            prefix,
        )

        return all_proxy, all_dead, all_redirect, all_stream

    @classmethod
    def scan_docker_dead_host_specs(cls) -> list[DockerDeadHostSpec]:
        """Scan all Docker containers and extract dead-host specs from labels."""
        _, dead_specs, _, _ = cls.scan_docker_specs()
        return dead_specs

    @classmethod
    def scan_docker_redirection_host_specs(cls) -> list[DockerRedirectionHostSpec]:
        """Scan all Docker containers and extract redirection-host specs from labels."""
        _, _, redirect_specs, _ = cls.scan_docker_specs()
        return redirect_specs

    @classmethod
    def scan_docker_stream_specs(cls) -> list[DockerStreamSpec]:
        """Scan all Docker containers and extract stream specs from labels."""
        _, _, _, stream_specs = cls.scan_docker_specs()
        return stream_specs

    @classmethod
    def sync_docker_proxy_hosts(
        cls,
        *,
        client: NPMplusClient,
        specs: Sequence[DockerProxyHostSpec],
        takeownership: bool = False,
        disable_orphans: bool = False,
        delete_orphans: bool = False,
    ) -> tuple[int, int, int]:
        """Create/update proxy-hosts from docker label specs.

        If disable_orphans is True, proxy-hosts owned by the current user but not present
        in docker specs will be updated to enabled=false.

        If delete_orphans is True, proxy-hosts owned by the current user but not present
        in docker specs will be deleted.

        Returns (created, updated, skipped).
        """

        def _natural_index_for_spec(spec: DockerProxyHostSpec) -> str:
            parts = [str(d).strip().lower() for d in (spec.domain_names or [])]
            parts = [p for p in parts if p]
            parts = sorted(set(parts))
            return ",".join(parts)

        def _existing_owner_user_id(item: dict[str, Any]) -> int | None:
            return NPMplusItemType.normalize_int(item.get("owner_user_id"))

        existing = client.list_proxy_hosts()
        by_domains = index_proxy_hosts_by_domains(existing)

        effective_owner_id: int | None = None
        if takeownership or disable_orphans or delete_orphans:
            try:
                effective_owner_id = client.my_id
            except Exception:
                effective_owner_id = None
        if takeownership and effective_owner_id is None:
            raise ValueError("--takeownership requires determining current user_id (ensure /api/users/me works)")

        created = 0
        updated = 0
        skipped = 0
        disabled = 0

        seen_domain_keys: set[tuple[str, ...]] = set()
        for spec in specs:
            key = _domain_key(spec.domain_names)
            natural_index = _natural_index_for_spec(spec)
            if key in seen_domain_keys:
                logger.warning(
                    "Duplicate domain_names in docker specs; skipping container %s",
                    spec.container_name,
                )
                logger.info(
                    "Synced %s %s (skip) id=%s from docker container=%s",
                    "proxy-hosts",
                    natural_index,
                    None,
                    spec.container_name,
                )
                skipped += 1
                continue
            seen_domain_keys.add(key)

            base_payload = ProxyHostFields.payload_from_docker_spec(
                spec,
                client=client,
            )
            # Preserve existing warnings for unresolved relations.
            if spec.access_list is not None:
                name = spec.access_list.strip()
                if name and "access_list_id" not in base_payload:
                    logger.warning(
                        "Docker spec references access_list=%s but no matching access-list found; leaving unset (container=%s)",
                        name,
                        spec.container_name,
                    )
            if spec.certificate is not None:
                cert_name = spec.certificate.strip()
                if cert_name and "certificate_id" not in base_payload:
                    logger.warning(
                        "Docker spec references certificate=%s but no matching certificate found; leaving unset (container=%s)",
                        cert_name,
                        spec.container_name,
                    )

            existing_item = by_domains.get(key)
            mode = "create" if existing_item is None else "update"
            obj_id_raw = None if existing_item is None else existing_item.get("id")
            obj_id: int | None
            if obj_id_raw is None:
                obj_id = None
            else:
                try:
                    obj_id = int(str(obj_id_raw).strip())
                except Exception:
                    obj_id = None
            if mode == "update" and obj_id is None:
                logger.warning(
                    "Existing proxy-host matched domains but has no id; skipping domains=%s",
                    list(key),
                )
                logger.info(
                    "Synced %s %s (skip) id=%s from docker container=%s",
                    "proxy-hosts",
                    natural_index,
                    None,
                    spec.container_name,
                )
                skipped += 1
                continue

            if mode == "update" and takeownership:
                assert existing_item is not None
                assert obj_id is not None
                existing_owner_id = _existing_owner_user_id(existing_item)

                if existing_owner_id is not None and existing_owner_id != effective_owner_id:
                    item = ProxyHostItem(dict(base_payload))
                    item["id"] = obj_id
                    _mode, result = item.set(client, takeownership=True)
                    created += 1
                    logger.info(
                        "Synced %s %s (create) id=%s from docker container=%s",
                        "proxy-hosts",
                        natural_index,
                        result.get("id"),
                        spec.container_name,
                    )
                    logger.info(
                        "Docker sync: took ownership of proxy-host domains=%s (previous_owner_user_id=%s new_owner_user_id=%s)",
                        list(key),
                        existing_owner_id,
                        effective_owner_id,
                    )
                    continue

            if mode == "update":
                assert existing_item is not None
                if ProxyHostItem.are_equal(base_payload, existing_item):
                    assert obj_id is not None
                    logger.info(
                        "Synced %s %s (skip) id=%s from docker container=%s",
                        "proxy-hosts",
                        natural_index,
                        obj_id,
                        spec.container_name,
                    )
                    skipped += 1
                    continue

            if mode == "create":
                item = ProxyHostItem(data=dict(base_payload))
                _mode, result = item.set(client)
                created += 1
                logger.info(
                    "Synced %s %s (create) id=%s from docker container=%s",
                    "proxy-hosts",
                    natural_index,
                    result.get("id"),
                    spec.container_name,
                )
            else:
                assert obj_id is not None
                host_id: int = obj_id
                item = ProxyHostItem(dict(base_payload))
                item["id"] = host_id
                _mode, result = item.set(client)
                updated += 1
                logger.info(
                    "Synced %s %s (update) id=%s from docker container=%s",
                    "proxy-hosts",
                    natural_index,
                    host_id,
                    spec.container_name,
                )

        if disable_orphans:
            if effective_owner_id is None:
                logger.warning(
                    "disable_orphans requested but could not determine authenticated owner_user_id; skipping orphan disable"
                )
            else:
                orphans = find_orphan_proxy_hosts(
                    existing_items=existing,
                    managed_domain_keys=seen_domain_keys,
                    owner_user_id=effective_owner_id,
                )
                for item in orphans:
                    item_id = item.get("id")
                    try:
                        host_id = int(str(item_id).strip())
                    except Exception:
                        logger.warning(
                            "Orphan proxy-host missing id; skipping domains=%s",
                            item.get("domain_names") or item.get("domainNames"),
                        )
                        continue
                    if item.get("enabled") is False:
                        continue
                    proxy_item = ProxyHostItem(data={"enabled": False, "id": host_id})
                    _mode, result = proxy_item.set(client)
                    disabled += 1
                    logger.info(
                        "Docker sync: disabled orphan proxy-host id=%s domains=%s",
                        result.get("id") if isinstance(result, dict) else host_id,
                        item.get("domain_names") or item.get("domainNames"),
                    )

                logger.info(
                    "Disabled %s orphan proxy-host(s) for owner_user_id=%s",
                    disabled,
                    effective_owner_id,
                )

        if delete_orphans:
            if effective_owner_id is None:
                logger.warning(
                    "delete_orphans requested but could not determine authenticated owner_user_id; skipping orphan deletion"
                )
            else:
                orphans = find_orphan_proxy_hosts(
                    existing_items=existing,
                    managed_domain_keys=seen_domain_keys,
                    owner_user_id=effective_owner_id,
                )
                deleted = 0
                for item in orphans:
                    item_id = item.get("id")
                    try:
                        host_id = int(str(item_id).strip())
                    except Exception:
                        logger.warning(
                            "Orphan proxy-host missing id; skipping domains=%s",
                            item.get("domain_names") or item.get("domainNames"),
                        )
                        continue
                    client.delete_proxy_host(host_id)
                    logger.info(
                        "Docker sync: deleted orphan proxy-host id=%s domains=%s",
                        host_id,
                        item.get("domain_names") or item.get("domainNames"),
                    )
                    deleted += 1

                logger.info(
                    "Deleted %s orphan proxy-host(s) for owner_user_id=%s",
                    deleted,
                    effective_owner_id,
                )

        return created, updated, skipped

    @classmethod
    def sync_docker_dead_hosts(
        cls,
        *,
        client: NPMplusClient,
        specs: Sequence[DockerDeadHostSpec],
        takeownership: bool = False,
        disable_orphans: bool = False,
        delete_orphans: bool = False,
    ) -> tuple[int, int, int]:
        """Create/update dead-hosts from docker label specs.

        Returns (created, updated, skipped).
        """

        def _natural_index_for_spec(spec: DockerDeadHostSpec) -> str:
            parts = [str(d).strip().lower() for d in (spec.domain_names or [])]
            parts = [p for p in parts if p]
            parts = sorted(set(parts))
            return ",".join(parts)

        def _existing_owner_user_id(item: dict[str, Any]) -> int | None:
            return NPMplusItemType.normalize_int(item.get("owner_user_id"))

        existing = client.list_dead_hosts()
        by_domains = index_dead_hosts_by_domains(existing)

        effective_owner_id: int | None = None
        if takeownership or disable_orphans or delete_orphans:
            try:
                effective_owner_id = client.my_id
            except Exception:
                effective_owner_id = None
        if takeownership and effective_owner_id is None:
            raise ValueError("--takeownership requires determining current user_id")

        created = 0
        updated = 0
        skipped = 0
        disabled = 0

        seen_domain_keys: set[tuple[str, ...]] = set()
        for spec in specs:
            key = _domain_key(spec.domain_names)
            natural_index = _natural_index_for_spec(spec)
            if key in seen_domain_keys:
                logger.warning("Duplicate domain_names in docker specs; skipping container %s", spec.container_name)
                skipped += 1
                continue
            seen_domain_keys.add(key)

            base_payload = DeadHostFields.payload_from_docker_spec(spec, client=client)
            if spec.certificate is not None:
                cert_name = spec.certificate.strip()
                if cert_name and "certificate_id" not in base_payload:
                    logger.warning(
                        "Docker spec references certificate=%s but no matching certificate found (container=%s)",
                        cert_name,
                        spec.container_name,
                    )

            existing_item = by_domains.get(key)
            mode = "create" if existing_item is None else "update"
            obj_id: int | None = None
            if existing_item is not None:
                try:
                    obj_id = int(str(existing_item.get("id")).strip())
                except Exception:
                    obj_id = None
            if mode == "update" and obj_id is None:
                logger.warning("Existing dead-host matched domains but has no id; skipping domains=%s", list(key))
                skipped += 1
                continue

            if mode == "update" and takeownership:
                assert existing_item is not None
                existing_owner_id = _existing_owner_user_id(existing_item)
                if existing_owner_id is not None and existing_owner_id != effective_owner_id:
                    item = DeadHostItem(dict(base_payload))
                    item["id"] = obj_id
                    _mode, result = item.set(client, takeownership=True)
                    created += 1
                    logger.info(
                        "Synced dead-hosts %s (create) id=%s from docker container=%s",
                        natural_index,
                        result.get("id"),
                        spec.container_name,
                    )
                    continue

            if mode == "update":
                assert existing_item is not None
                if DeadHostItem.are_equal(base_payload, existing_item):
                    logger.info(
                        "Synced dead-hosts %s (skip) id=%s from docker container=%s",
                        natural_index,
                        obj_id,
                        spec.container_name,
                    )
                    skipped += 1
                    continue

            if mode == "create":
                item = DeadHostItem(data=dict(base_payload))
                _mode, result = item.set(client)
                created += 1
                logger.info(
                    "Synced dead-hosts %s (create) id=%s from docker container=%s",
                    natural_index,
                    result.get("id"),
                    spec.container_name,
                )
            else:
                item = DeadHostItem(dict(base_payload))
                item["id"] = obj_id
                _mode, result = item.set(client)
                updated += 1
                logger.info(
                    "Synced dead-hosts %s (update) id=%s from docker container=%s",
                    natural_index,
                    obj_id,
                    spec.container_name,
                )

        if disable_orphans and effective_owner_id is not None:
            orphans = find_orphan_dead_hosts(
                existing_items=existing,
                managed_domain_keys=seen_domain_keys,
                owner_user_id=effective_owner_id,
            )
            for item in orphans:
                item_id = item.get("id")
                try:
                    host_id = int(str(item_id).strip())
                except Exception:
                    continue
                if item.get("enabled") is False:
                    continue
                dead_item = DeadHostItem(data={"enabled": False, "id": host_id})
                _mode, result = dead_item.set(client)
                disabled += 1
                logger.info(
                    "Docker sync: disabled orphan dead-host id=%s domains=%s",
                    host_id,
                    item.get("domain_names") or item.get("domainNames"),
                )
            logger.info("Disabled %s orphan dead-host(s) for owner_user_id=%s", disabled, effective_owner_id)

        if delete_orphans and effective_owner_id is not None:
            orphans = find_orphan_dead_hosts(
                existing_items=existing,
                managed_domain_keys=seen_domain_keys,
                owner_user_id=effective_owner_id,
            )
            deleted = 0
            for item in orphans:
                item_id = item.get("id")
                try:
                    host_id = int(str(item_id).strip())
                except Exception:
                    continue
                client.delete_dead_host(host_id)
                logger.info(
                    "Docker sync: deleted orphan dead-host id=%s domains=%s",
                    host_id,
                    item.get("domain_names") or item.get("domainNames"),
                )
                deleted += 1
            logger.info("Deleted %s orphan dead-host(s) for owner_user_id=%s", deleted, effective_owner_id)

        return created, updated, skipped

    @classmethod
    def sync_docker_redirection_hosts(
        cls,
        *,
        client: NPMplusClient,
        specs: Sequence[DockerRedirectionHostSpec],
        takeownership: bool = False,
        disable_orphans: bool = False,
        delete_orphans: bool = False,
    ) -> tuple[int, int, int]:
        """Create/update redirection-hosts from docker label specs.

        Returns (created, updated, skipped).
        """

        def _natural_index_for_spec(spec: DockerRedirectionHostSpec) -> str:
            parts = [str(d).strip().lower() for d in (spec.domain_names or [])]
            parts = [p for p in parts if p]
            parts = sorted(set(parts))
            return ",".join(parts)

        def _existing_owner_user_id(item: dict[str, Any]) -> int | None:
            return NPMplusItemType.normalize_int(item.get("owner_user_id"))

        existing = client.list_redirection_hosts()
        by_domains = index_redirection_hosts_by_domains(existing)

        effective_owner_id: int | None = None
        if takeownership or disable_orphans or delete_orphans:
            try:
                effective_owner_id = client.my_id
            except Exception:
                effective_owner_id = None
        if takeownership and effective_owner_id is None:
            raise ValueError("--takeownership requires determining current user_id")

        created = 0
        updated = 0
        skipped = 0
        disabled = 0

        seen_domain_keys: set[tuple[str, ...]] = set()
        for spec in specs:
            key = _domain_key(spec.domain_names)
            natural_index = _natural_index_for_spec(spec)
            if key in seen_domain_keys:
                logger.warning("Duplicate domain_names in docker specs; skipping container %s", spec.container_name)
                skipped += 1
                continue
            seen_domain_keys.add(key)

            base_payload = RedirectionHostFields.payload_from_docker_spec(spec, client=client)
            if spec.certificate is not None:
                cert_name = spec.certificate.strip()
                if cert_name and "certificate_id" not in base_payload:
                    logger.warning(
                        "Docker spec references certificate=%s but no matching certificate found (container=%s)",
                        cert_name,
                        spec.container_name,
                    )

            existing_item = by_domains.get(key)
            mode = "create" if existing_item is None else "update"
            obj_id: int | None = None
            if existing_item is not None:
                try:
                    obj_id = int(str(existing_item.get("id")).strip())
                except Exception:
                    obj_id = None
            if mode == "update" and obj_id is None:
                logger.warning(
                    "Existing redirection-host matched domains but has no id; skipping domains=%s", list(key)
                )
                skipped += 1
                continue

            if mode == "update" and takeownership:
                assert existing_item is not None
                existing_owner_id = _existing_owner_user_id(existing_item)
                if existing_owner_id is not None and existing_owner_id != effective_owner_id:
                    item = RedirectionHostItem(dict(base_payload))
                    item["id"] = obj_id
                    _mode, result = item.set(client, takeownership=True)
                    created += 1
                    logger.info(
                        "Synced redirection-hosts %s (create) id=%s from docker container=%s",
                        natural_index,
                        result.get("id"),
                        spec.container_name,
                    )
                    continue

            if mode == "update":
                assert existing_item is not None
                if RedirectionHostItem.are_equal(base_payload, existing_item):
                    logger.info(
                        "Synced redirection-hosts %s (skip) id=%s from docker container=%s",
                        natural_index,
                        obj_id,
                        spec.container_name,
                    )
                    skipped += 1
                    continue

            if mode == "create":
                item = RedirectionHostItem(data=dict(base_payload))
                _mode, result = item.set(client)
                created += 1
                logger.info(
                    "Synced redirection-hosts %s (create) id=%s from docker container=%s",
                    natural_index,
                    result.get("id"),
                    spec.container_name,
                )
            else:
                item = RedirectionHostItem(dict(base_payload))
                item["id"] = obj_id
                _mode, result = item.set(client)
                updated += 1
                logger.info(
                    "Synced redirection-hosts %s (update) id=%s from docker container=%s",
                    natural_index,
                    obj_id,
                    spec.container_name,
                )

        if disable_orphans and effective_owner_id is not None:
            orphans = find_orphan_redirection_hosts(
                existing_items=existing,
                managed_domain_keys=seen_domain_keys,
                owner_user_id=effective_owner_id,
            )
            for item in orphans:
                item_id = item.get("id")
                try:
                    host_id = int(str(item_id).strip())
                except Exception:
                    continue
                if item.get("enabled") is False:
                    continue
                redir_item = RedirectionHostItem(data={"enabled": False, "id": host_id})
                _mode, result = redir_item.set(client)
                disabled += 1
                logger.info(
                    "Docker sync: disabled orphan redirection-host id=%s domains=%s",
                    host_id,
                    item.get("domain_names") or item.get("domainNames"),
                )
            logger.info("Disabled %s orphan redirection-host(s) for owner_user_id=%s", disabled, effective_owner_id)

        if delete_orphans and effective_owner_id is not None:
            orphans = find_orphan_redirection_hosts(
                existing_items=existing,
                managed_domain_keys=seen_domain_keys,
                owner_user_id=effective_owner_id,
            )
            deleted = 0
            for item in orphans:
                item_id = item.get("id")
                try:
                    host_id = int(str(item_id).strip())
                except Exception:
                    continue
                client.delete_redirection_host(host_id)
                logger.info(
                    "Docker sync: deleted orphan redirection-host id=%s domains=%s",
                    host_id,
                    item.get("domain_names") or item.get("domainNames"),
                )
                deleted += 1
            logger.info("Deleted %s orphan redirection-host(s) for owner_user_id=%s", deleted, effective_owner_id)

        return created, updated, skipped

    @classmethod
    def sync_docker_streams(
        cls,
        *,
        client: NPMplusClient,
        specs: Sequence[DockerStreamSpec],
        takeownership: bool = False,
        disable_orphans: bool = False,
        delete_orphans: bool = False,
    ) -> tuple[int, int, int]:
        """Create/update streams from docker label specs.

        Returns (created, updated, skipped).
        """

        def _existing_owner_user_id(item: dict[str, Any]) -> int | None:
            return NPMplusItemType.normalize_int(item.get("owner_user_id"))

        existing = client.list_streams()
        by_port = index_streams_by_port(existing)

        effective_owner_id: int | None = None
        if takeownership or disable_orphans or delete_orphans:
            try:
                effective_owner_id = client.my_id
            except Exception:
                effective_owner_id = None
        if takeownership and effective_owner_id is None:
            raise ValueError("--takeownership requires determining current user_id")

        created = 0
        updated = 0
        skipped = 0
        disabled = 0

        seen_port_keys: set[int] = set()
        for spec in specs:
            port_key = spec.incoming_port
            natural_index = str(port_key)
            if port_key in seen_port_keys:
                logger.warning(
                    "Duplicate incoming_port in docker specs; skipping container %s", spec.container_name
                )
                skipped += 1
                continue
            seen_port_keys.add(port_key)

            base_payload = StreamFields.payload_from_docker_spec(spec, client=client)
            if spec.certificate is not None:
                cert_name = spec.certificate.strip()
                if cert_name and "certificate_id" not in base_payload:
                    logger.warning(
                        "Docker spec references certificate=%s but no matching certificate found (container=%s)",
                        cert_name,
                        spec.container_name,
                    )

            existing_item = by_port.get(port_key)
            mode = "create" if existing_item is None else "update"
            obj_id: int | None = None
            if existing_item is not None:
                try:
                    obj_id = int(str(existing_item.get("id")).strip())
                except Exception:
                    obj_id = None
            if mode == "update" and obj_id is None:
                logger.warning("Existing stream matched port but has no id; skipping incoming_port=%s", port_key)
                skipped += 1
                continue

            if mode == "update" and takeownership:
                assert existing_item is not None
                existing_owner_id = _existing_owner_user_id(existing_item)
                if existing_owner_id is not None and existing_owner_id != effective_owner_id:
                    item = StreamItem(dict(base_payload))
                    item["id"] = obj_id
                    _mode, result = item.set(client, takeownership=True)
                    created += 1
                    logger.info(
                        "Synced streams %s (create) id=%s from docker container=%s",
                        natural_index,
                        result.get("id"),
                        spec.container_name,
                    )
                    continue

            if mode == "update":
                assert existing_item is not None
                if StreamItem.are_equal(base_payload, existing_item):
                    logger.info(
                        "Synced streams %s (skip) id=%s from docker container=%s",
                        natural_index,
                        obj_id,
                        spec.container_name,
                    )
                    skipped += 1
                    continue

            if mode == "create":
                item = StreamItem(data=dict(base_payload))
                _mode, result = item.set(client)
                created += 1
                logger.info(
                    "Synced streams %s (create) id=%s from docker container=%s",
                    natural_index,
                    result.get("id"),
                    spec.container_name,
                )
            else:
                item = StreamItem(dict(base_payload))
                item["id"] = obj_id
                _mode, result = item.set(client)
                updated += 1
                logger.info(
                    "Synced streams %s (update) id=%s from docker container=%s",
                    natural_index,
                    obj_id,
                    spec.container_name,
                )

        if disable_orphans and effective_owner_id is not None:
            orphans = find_orphan_streams(
                existing_items=existing,
                managed_port_keys=seen_port_keys,
                owner_user_id=effective_owner_id,
            )
            for item in orphans:
                item_id = item.get("id")
                try:
                    stream_id = int(str(item_id).strip())
                except Exception:
                    continue
                if item.get("enabled") is False:
                    continue
                stream_item = StreamItem(data={"enabled": False, "id": stream_id})
                _mode, result = stream_item.set(client)
                disabled += 1
                logger.info(
                    "Docker sync: disabled orphan stream id=%s incoming_port=%s",
                    stream_id,
                    item.get("incoming_port") or item.get("incomingPort"),
                )
            logger.info("Disabled %s orphan stream(s) for owner_user_id=%s", disabled, effective_owner_id)

        if delete_orphans and effective_owner_id is not None:
            orphans = find_orphan_streams(
                existing_items=existing,
                managed_port_keys=seen_port_keys,
                owner_user_id=effective_owner_id,
            )
            deleted = 0
            for item in orphans:
                item_id = item.get("id")
                try:
                    stream_id = int(str(item_id).strip())
                except Exception:
                    continue
                client.delete_stream(stream_id)
                logger.info(
                    "Docker sync: deleted orphan stream id=%s incoming_port=%s",
                    stream_id,
                    item.get("incoming_port") or item.get("incomingPort"),
                )
                deleted += 1
            logger.info("Deleted %s orphan stream(s) for owner_user_id=%s", deleted, effective_owner_id)

        return created, updated, skipped


class ProxyHostFields:
    """Assemble proxy-host JSON payloads and docker-label YAML fields.

    - "JSON" here refers to the payload sent to NPMplus API.
    - "YML" here refers to docker-compose `labels:` entries.
    """

    BOOL_FIELDS = (
        "allow_websocket_upgrade",
        "block_exploits",
        "caching_enabled",
        "enabled",
        "hsts_enabled",
        "hsts_subdomains",
        "http2_support",
        "ssl_forced",
    )

    @staticmethod
    def _camel_key(snake: str) -> str:
        parts = (snake or "").split("_")
        if not parts:
            return snake
        return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])

    @staticmethod
    def _get_payload_value(payload: Mapping[str, Any], key: str) -> object:
        if key in payload:
            return payload.get(key)
        camel = ProxyHostFields._camel_key(key)
        return payload.get(camel)

    @staticmethod
    def _as_bool_label(value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return "true" if value else "false"
        s = str(value).strip().lower()
        if s in {"1", "true", "yes", "y", "on"}:
            return "true"
        if s in {"0", "false", "no", "n", "off"}:
            return "false"
        return None

    @staticmethod
    def _split_domains(value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        out: list[str] = []
        for item in value:
            s = str(item).strip().lower()
            if s:
                out.append(s)
        return out

    @staticmethod
    def _get_certificate_nice_name(payload: Mapping[str, Any]) -> str | None:
        cert = payload.get("certificate")
        if isinstance(cert, dict):
            name = cert.get("nice_name")
            if name is None:
                return None
            s = str(name).strip()
            return s or None
        if isinstance(cert, str):
            s = cert.strip()
            return s or None
        return None

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

        domains = ProxyHostFields._split_domains(payload.get("domain_names") or payload.get("domainNames"))
        forward_host = ProxyHostFields._get_payload_value(payload, "forward_host")
        forward_port = ProxyHostFields._get_payload_value(payload, "forward_port")
        forward_scheme = ProxyHostFields._get_payload_value(payload, "forward_scheme")

        if not domains:
            raise ValueError("Missing or empty domain_names")
        if forward_host is None or not str(forward_host).strip():
            raise ValueError("Missing forward_host")
        if forward_port is None:
            raise ValueError("Missing forward_port")
        try:
            forward_port_int = int(str(forward_port).strip())
        except Exception as e:
            raise ValueError("Invalid forward_port") from e
        if forward_port_int <= 0 or forward_port_int > 65535:
            raise ValueError("Invalid forward_port")
        if forward_scheme is None or not str(forward_scheme).strip():
            raise ValueError("Missing forward_scheme")

        labels: list[tuple[str, str]] = []
        labels.append((f"{prefix}domain_names", ",".join(domains)))
        labels.append((f"{prefix}forward_host", str(forward_host).strip()))
        labels.append((f"{prefix}forward_port", str(forward_port_int)))
        labels.append((f"{prefix}forward_scheme", str(forward_scheme).strip().lower()))

        # Locations (optional)
        locations = ProxyHostFields._get_locations(payload)
        for idx, loc in enumerate(locations, start=1):
            path = str(loc.get("path") or "").strip()
            loc_forward_host = str(loc.get("forward_host") or loc.get("forwardHost") or "").strip()
            loc_forward_port = loc.get("forward_port") or loc.get("forwardPort")
            loc_forward_scheme = str(
                loc.get("forward_scheme") or loc.get("forwardScheme") or str(forward_scheme)
            ).strip()
            if not path or not loc_forward_host or loc_forward_port is None:
                continue
            try:
                loc_forward_port_int = int(str(loc_forward_port).strip())
            except Exception:
                continue
            if loc_forward_port_int <= 0 or loc_forward_port_int > 65535:
                continue
            labels.append((f"{prefix}loc{idx}_path", path))
            labels.append((f"{prefix}loc{idx}_forward_host", loc_forward_host))
            labels.append((f"{prefix}loc{idx}_forward_port", str(loc_forward_port_int)))
            labels.append((f"{prefix}loc{idx}_forward_scheme", loc_forward_scheme.strip().lower()))

            loc_adv = loc.get("advanced_config") or loc.get("advancedConfig")
            if loc_adv is not None and str(loc_adv).strip():
                labels.append((f"{prefix}loc{idx}_advanced_config", str(loc_adv)))

            loc_type = loc.get("location_type") or loc.get("locationType")
            if loc_type is not None and str(loc_type).strip():
                labels.append((f"{prefix}loc{idx}_location_type", str(loc_type).strip()))

            for loc_bool_field in ("allow_websocket_upgrade", "block_exploits", "caching_enabled"):
                b = ProxyHostFields._as_bool_label(loc.get(loc_bool_field))
                if b is not None:
                    labels.append((f"{prefix}loc{idx}_{loc_bool_field}", b))

        cert_name = ProxyHostFields._get_certificate_nice_name(payload)
        if cert_name:
            labels.append((f"{prefix}certificate", cert_name))

        access_list = AccessListItem.name_from_value(payload.get("access_list") or payload.get("accessList"))
        if access_list:
            labels.append((f"{prefix}access_list", access_list))

        advanced_config = ProxyHostFields._get_payload_value(payload, "advanced_config")
        if advanced_config is not None:
            adv = str(advanced_config)
            if adv.strip():
                labels.append((f"{prefix}advanced_config", adv))

        for bool_field in ProxyHostFields.BOOL_FIELDS:
            b = ProxyHostFields._as_bool_label(ProxyHostFields._get_payload_value(payload, bool_field))
            if b is not None:
                labels.append((f"{prefix}{bool_field}", b))

        return labels

    @staticmethod
    def payload_from_docker_spec(
        spec: DockerProxyHostSpec,
        *,
        client: NPMplusClient,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "domain_names": list(_domain_key(spec.domain_names)),
            "forward_host": spec.forward_host,
            "forward_port": spec.forward_port,
            "forward_scheme": spec.forward_scheme,
        }
        if spec.locations:
            loc_payloads: list[dict[str, Any]] = []
            for loc in spec.locations:
                lp: dict[str, Any] = {
                    "path": loc.path,
                    "forward_host": loc.forward_host,
                    "forward_port": loc.forward_port,
                    "forward_scheme": loc.forward_scheme,
                    "location_type": "",
                }
                if loc.location_type is not None:
                    lp["location_type"] = loc.location_type
                if loc.advanced_config is not None:
                    lp["advanced_config"] = loc.advanced_config
                if loc.allow_websocket_upgrade is not None:
                    lp["allow_websocket_upgrade"] = loc.allow_websocket_upgrade
                if loc.block_exploits is not None:
                    lp["block_exploits"] = loc.block_exploits
                if loc.caching_enabled is not None:
                    lp["caching_enabled"] = loc.caching_enabled
                loc_payloads.append(lp)
            payload["locations"] = loc_payloads

        # bools
        for bool_field in ProxyHostFields.BOOL_FIELDS:
            value = getattr(spec, bool_field, None)
            if value is not None:
                payload[bool_field] = value
        if spec.advanced_config is not None:
            payload["advanced_config"] = spec.advanced_config

        if spec.access_list is not None:
            name = spec.access_list.strip()
            if not name:
                payload["access_list_id"] = 0
            else:
                access_list_id = client.get_access_list_id(name)
                if access_list_id > 0:
                    payload["access_list_id"] = access_list_id

        if spec.certificate is not None:
            cert_name = spec.certificate.strip()
            if not cert_name:
                payload["certificate_id"] = 0
            else:
                certificate_id = client.get_certificate_id(cert_name)
                if certificate_id > 0:
                    payload["certificate_id"] = certificate_id

        return payload


class DeadHostFields:
    BOOL_FIELDS = (
        "enabled",
        "hsts_enabled",
        "hsts_subdomains",
        "http2_support",
        "ssl_forced",
    )

    @staticmethod
    def _camel_key(snake: str) -> str:
        parts = (snake or "").split("_")
        if not parts:
            return snake
        return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])

    @staticmethod
    def _get_payload_value(payload: Mapping[str, Any], key: str) -> object:
        if key in payload:
            return payload.get(key)
        camel = DeadHostFields._camel_key(key)
        return payload.get(camel)

    @staticmethod
    def _as_bool_label(value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return "true" if value else "false"
        s = str(value).strip().lower()
        if s in {"1", "true", "yes", "y", "on"}:
            return "true"
        if s in {"0", "false", "no", "n", "off"}:
            return "false"
        return None

    @staticmethod
    def _split_domains(value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        out: list[str] = []
        for item in value:
            s = str(item).strip().lower()
            if s:
                out.append(s)
        return out

    @staticmethod
    def _get_certificate_nice_name(payload: Mapping[str, Any]) -> str | None:
        cert = payload.get("certificate")
        if isinstance(cert, dict):
            name = cert.get("nice_name")
            if name is None:
                return None
            s = str(name).strip()
            return s or None
        if isinstance(cert, str):
            s = cert.strip()
            return s or None
        return None

    @staticmethod
    def labels_from_dead_host_payload(
        payload: Mapping[str, Any],
        *,
        label_prefix: str,
    ) -> list[tuple[str, str]]:
        prefix = (label_prefix or "").strip() or "npmp.dead."
        if not prefix.endswith((".", "-")):
            prefix += "."

        domains = DeadHostFields._split_domains(payload.get("domain_names") or payload.get("domainNames"))
        if not domains:
            raise ValueError("Missing or empty domain_names")

        labels: list[tuple[str, str]] = []
        labels.append((f"{prefix}domain_names", ",".join(domains)))

        cert_name = DeadHostFields._get_certificate_nice_name(payload)
        if cert_name:
            labels.append((f"{prefix}certificate", cert_name))

        advanced_config = DeadHostFields._get_payload_value(payload, "advanced_config")
        if advanced_config is not None:
            adv = str(advanced_config)
            if adv.strip():
                labels.append((f"{prefix}advanced_config", adv))

        for bool_field in DeadHostFields.BOOL_FIELDS:
            b = DeadHostFields._as_bool_label(DeadHostFields._get_payload_value(payload, bool_field))
            if b is not None:
                labels.append((f"{prefix}{bool_field}", b))

        return labels

    @staticmethod
    def payload_from_docker_spec(
        spec: DockerDeadHostSpec,
        *,
        client: NPMplusClient,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "domain_names": list(_domain_key(spec.domain_names)),
        }

        for bool_field in DeadHostFields.BOOL_FIELDS:
            value = getattr(spec, bool_field, None)
            if value is not None:
                payload[bool_field] = value
        if spec.advanced_config is not None:
            payload["advanced_config"] = spec.advanced_config

        if spec.certificate is not None:
            cert_name = spec.certificate.strip()
            if not cert_name:
                payload["certificate_id"] = 0
            else:
                certificate_id = client.get_certificate_id(cert_name)
                if certificate_id > 0:
                    payload["certificate_id"] = certificate_id

        return payload


class RedirectionHostFields:
    BOOL_FIELDS = (
        "block_exploits",
        "enabled",
        "hsts_enabled",
        "hsts_subdomains",
        "http2_support",
        "preserve_path",
        "ssl_forced",
    )

    @staticmethod
    def _camel_key(snake: str) -> str:
        parts = (snake or "").split("_")
        if not parts:
            return snake
        return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])

    @staticmethod
    def _get_payload_value(payload: Mapping[str, Any], key: str) -> object:
        if key in payload:
            return payload.get(key)
        camel = RedirectionHostFields._camel_key(key)
        return payload.get(camel)

    @staticmethod
    def _as_bool_label(value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return "true" if value else "false"
        s = str(value).strip().lower()
        if s in {"1", "true", "yes", "y", "on"}:
            return "true"
        if s in {"0", "false", "no", "n", "off"}:
            return "false"
        return None

    @staticmethod
    def _split_domains(value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        out: list[str] = []
        for item in value:
            s = str(item).strip().lower()
            if s:
                out.append(s)
        return out

    @staticmethod
    def _get_certificate_nice_name(payload: Mapping[str, Any]) -> str | None:
        cert = payload.get("certificate")
        if isinstance(cert, dict):
            name = cert.get("nice_name")
            if name is None:
                return None
            s = str(name).strip()
            return s or None
        if isinstance(cert, str):
            s = cert.strip()
            return s or None
        return None

    @staticmethod
    def labels_from_redirection_host_payload(
        payload: Mapping[str, Any],
        *,
        label_prefix: str,
    ) -> list[tuple[str, str]]:
        prefix = (label_prefix or "").strip() or "npmp.redirect."
        if not prefix.endswith((".", "-")):
            prefix += "."

        domains = RedirectionHostFields._split_domains(payload.get("domain_names") or payload.get("domainNames"))
        forward_domain_name = RedirectionHostFields._get_payload_value(payload, "forward_domain_name")
        forward_http_code = RedirectionHostFields._get_payload_value(payload, "forward_http_code")
        forward_scheme = RedirectionHostFields._get_payload_value(payload, "forward_scheme")

        if not domains:
            raise ValueError("Missing or empty domain_names")
        if forward_domain_name is None or not str(forward_domain_name).strip():
            raise ValueError("Missing forward_domain_name")
        if forward_http_code is None:
            raise ValueError("Missing forward_http_code")
        if forward_scheme is None or not str(forward_scheme).strip():
            raise ValueError("Missing forward_scheme")

        labels: list[tuple[str, str]] = []
        labels.append((f"{prefix}domain_names", ",".join(domains)))
        labels.append((f"{prefix}forward_domain_name", str(forward_domain_name).strip()))
        labels.append((f"{prefix}forward_http_code", str(int(str(forward_http_code).strip()))))
        labels.append((f"{prefix}forward_scheme", str(forward_scheme).strip().lower()))

        cert_name = RedirectionHostFields._get_certificate_nice_name(payload)
        if cert_name:
            labels.append((f"{prefix}certificate", cert_name))

        advanced_config = RedirectionHostFields._get_payload_value(payload, "advanced_config")
        if advanced_config is not None:
            adv = str(advanced_config)
            if adv.strip():
                labels.append((f"{prefix}advanced_config", adv))

        for bool_field in RedirectionHostFields.BOOL_FIELDS:
            b = RedirectionHostFields._as_bool_label(RedirectionHostFields._get_payload_value(payload, bool_field))
            if b is not None:
                labels.append((f"{prefix}{bool_field}", b))

        return labels

    @staticmethod
    def payload_from_docker_spec(
        spec: DockerRedirectionHostSpec,
        *,
        client: NPMplusClient,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "domain_names": list(_domain_key(spec.domain_names)),
            "forward_domain_name": spec.forward_domain_name,
            "forward_http_code": spec.forward_http_code,
            "forward_scheme": spec.forward_scheme,
        }

        for bool_field in RedirectionHostFields.BOOL_FIELDS:
            value = getattr(spec, bool_field, None)
            if value is not None:
                payload[bool_field] = value
        if spec.advanced_config is not None:
            payload["advanced_config"] = spec.advanced_config

        if spec.certificate is not None:
            cert_name = spec.certificate.strip()
            if not cert_name:
                payload["certificate_id"] = 0
            else:
                certificate_id = client.get_certificate_id(cert_name)
                if certificate_id > 0:
                    payload["certificate_id"] = certificate_id

        return payload


class StreamFields:
    BOOL_FIELDS = (
        "enabled",
        "proxy_protocol_forwarding",
        "tcp_forwarding",
        "udp_forwarding",
    )

    @staticmethod
    def _camel_key(snake: str) -> str:
        parts = (snake or "").split("_")
        if not parts:
            return snake
        return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])

    @staticmethod
    def _get_payload_value(payload: Mapping[str, Any], key: str) -> object:
        if key in payload:
            return payload.get(key)
        camel = StreamFields._camel_key(key)
        return payload.get(camel)

    @staticmethod
    def _as_bool_label(value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return "true" if value else "false"
        s = str(value).strip().lower()
        if s in {"1", "true", "yes", "y", "on"}:
            return "true"
        if s in {"0", "false", "no", "n", "off"}:
            return "false"
        return None

    @staticmethod
    def _get_certificate_nice_name(payload: Mapping[str, Any]) -> str | None:
        cert = payload.get("certificate")
        if isinstance(cert, dict):
            name = cert.get("nice_name")
            if name is None:
                return None
            s = str(name).strip()
            return s or None
        if isinstance(cert, str):
            s = cert.strip()
            return s or None
        return None

    @staticmethod
    def labels_from_stream_payload(
        payload: Mapping[str, Any],
        *,
        label_prefix: str,
    ) -> list[tuple[str, str]]:
        prefix = (label_prefix or "").strip() or "npmp.stream."
        if not prefix.endswith((".", "-")):
            prefix += "."

        incoming_port = StreamFields._get_payload_value(payload, "incoming_port")
        forwarding_host = StreamFields._get_payload_value(payload, "forwarding_host")
        forwarding_port = StreamFields._get_payload_value(payload, "forwarding_port")

        if incoming_port is None:
            raise ValueError("Missing incoming_port")
        if forwarding_host is None or not str(forwarding_host).strip():
            raise ValueError("Missing forwarding_host")
        if forwarding_port is None:
            raise ValueError("Missing forwarding_port")

        try:
            incoming_port_int = int(str(incoming_port).strip())
        except Exception as e:
            raise ValueError("Invalid incoming_port") from e
        if incoming_port_int <= 0 or incoming_port_int > 65535:
            raise ValueError("Invalid incoming_port")

        try:
            forwarding_port_int = int(str(forwarding_port).strip())
        except Exception as e:
            raise ValueError("Invalid forwarding_port") from e
        if forwarding_port_int <= 0 or forwarding_port_int > 65535:
            raise ValueError("Invalid forwarding_port")

        labels: list[tuple[str, str]] = []
        labels.append((f"{prefix}incoming_port", str(incoming_port_int)))
        labels.append((f"{prefix}forwarding_host", str(forwarding_host).strip()))
        labels.append((f"{prefix}forwarding_port", str(forwarding_port_int)))

        cert_name = StreamFields._get_certificate_nice_name(payload)
        if cert_name:
            labels.append((f"{prefix}certificate", cert_name))

        for bool_field in StreamFields.BOOL_FIELDS:
            b = StreamFields._as_bool_label(StreamFields._get_payload_value(payload, bool_field))
            if b is not None:
                labels.append((f"{prefix}{bool_field}", b))

        return labels

    @staticmethod
    def payload_from_docker_spec(
        spec: DockerStreamSpec,
        *,
        client: NPMplusClient,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "incoming_port": spec.incoming_port,
            "forwarding_host": spec.forwarding_host,
            "forwarding_port": spec.forwarding_port,
        }

        for bool_field in StreamFields.BOOL_FIELDS:
            value = getattr(spec, bool_field, None)
            if value is not None:
                payload[bool_field] = value

        if spec.certificate is not None:
            cert_name = spec.certificate.strip()
            if not cert_name:
                payload["certificate_id"] = 0
            else:
                certificate_id = client.get_certificate_id(cert_name)
                if certificate_id > 0:
                    payload["certificate_id"] = certificate_id

        return payload


def _domain_key(domain_names: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted(d.strip().lower() for d in domain_names if str(d).strip()))


def index_proxy_hosts_by_domains(
    items: Mapping[int, dict[str, Any]],
) -> dict[tuple[str, ...], dict[str, Any]]:
    out: dict[tuple[str, ...], dict[str, Any]] = {}
    for item in items.values():
        domains = item.get("domain_names") or item.get("domainNames")
        if not isinstance(domains, list):
            continue
        key = _domain_key([str(d) for d in domains])
        if not key:
            continue
        # If duplicates exist, keep the first.
        out.setdefault(key, item)
    return out


def find_orphan_proxy_hosts(
    *,
    existing_items: Mapping[int, dict[str, Any]],
    managed_domain_keys: set[tuple[str, ...]],
    owner_user_id: int,
) -> list[dict[str, Any]]:
    """Return proxy-host items owned by owner_user_id but not present in managed_domain_keys."""
    orphans: list[dict[str, Any]] = []
    for item in existing_items.values():
        item_owner = item.get("owner_user_id")
        try:
            item_owner_id = int(str(item_owner).strip())
        except Exception:
            continue
        if item_owner_id != owner_user_id:
            continue
        domains = item.get("domain_names") or item.get("domainNames")
        if not isinstance(domains, list):
            continue
        key = _domain_key([str(d) for d in domains])
        if not key:
            continue
        if key in managed_domain_keys:
            continue
        orphans.append(item)
    return orphans


def index_dead_hosts_by_domains(
    items: Mapping[int, dict[str, Any]],
) -> dict[tuple[str, ...], dict[str, Any]]:
    out: dict[tuple[str, ...], dict[str, Any]] = {}
    for item in items.values():
        domains = item.get("domain_names") or item.get("domainNames")
        if not isinstance(domains, list):
            continue
        key = _domain_key([str(d) for d in domains])
        if not key:
            continue
        out.setdefault(key, item)
    return out


def find_orphan_dead_hosts(
    *,
    existing_items: Mapping[int, dict[str, Any]],
    managed_domain_keys: set[tuple[str, ...]],
    owner_user_id: int,
) -> list[dict[str, Any]]:
    """Return dead-host items owned by owner_user_id but not present in managed_domain_keys."""
    orphans: list[dict[str, Any]] = []
    for item in existing_items.values():
        item_owner = item.get("owner_user_id")
        try:
            item_owner_id = int(str(item_owner).strip())
        except Exception:
            continue
        if item_owner_id != owner_user_id:
            continue
        domains = item.get("domain_names") or item.get("domainNames")
        if not isinstance(domains, list):
            continue
        key = _domain_key([str(d) for d in domains])
        if not key:
            continue
        if key in managed_domain_keys:
            continue
        orphans.append(item)
    return orphans


def index_redirection_hosts_by_domains(
    items: Mapping[int, dict[str, Any]],
) -> dict[tuple[str, ...], dict[str, Any]]:
    out: dict[tuple[str, ...], dict[str, Any]] = {}
    for item in items.values():
        domains = item.get("domain_names") or item.get("domainNames")
        if not isinstance(domains, list):
            continue
        key = _domain_key([str(d) for d in domains])
        if not key:
            continue
        out.setdefault(key, item)
    return out


def find_orphan_redirection_hosts(
    *,
    existing_items: Mapping[int, dict[str, Any]],
    managed_domain_keys: set[tuple[str, ...]],
    owner_user_id: int,
) -> list[dict[str, Any]]:
    """Return redirection-host items owned by owner_user_id but not present in managed_domain_keys."""
    orphans: list[dict[str, Any]] = []
    for item in existing_items.values():
        item_owner = item.get("owner_user_id")
        try:
            item_owner_id = int(str(item_owner).strip())
        except Exception:
            continue
        if item_owner_id != owner_user_id:
            continue
        domains = item.get("domain_names") or item.get("domainNames")
        if not isinstance(domains, list):
            continue
        key = _domain_key([str(d) for d in domains])
        if not key:
            continue
        if key in managed_domain_keys:
            continue
        orphans.append(item)
    return orphans


def index_streams_by_port(
    items: Mapping[int, dict[str, Any]],
) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for item in items.values():
        port = item.get("incoming_port") or item.get("incomingPort")
        if port is None:
            continue
        try:
            port_int = int(str(port).strip())
        except Exception:
            continue
        out.setdefault(port_int, item)
    return out


def find_orphan_streams(
    *,
    existing_items: Mapping[int, dict[str, Any]],
    managed_port_keys: set[int],
    owner_user_id: int,
) -> list[dict[str, Any]]:
    """Return stream items owned by owner_user_id but not present in managed_port_keys."""
    orphans: list[dict[str, Any]] = []
    for item in existing_items.values():
        item_owner = item.get("owner_user_id")
        try:
            item_owner_id = int(str(item_owner).strip())
        except Exception:
            continue
        if item_owner_id != owner_user_id:
            continue
        port = item.get("incoming_port") or item.get("incomingPort")
        if port is None:
            continue
        try:
            port_int = int(str(port).strip())
        except Exception:
            continue
        if port_int in managed_port_keys:
            continue
        orphans.append(item)
    return orphans
