from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from .. import utils
from ..configmanager import ConfigManager
from .specs import (
    DockerDeadHostSpec,
    DockerProxyHostSpec,
    DockerRedirectionHostSpec,
    DockerStreamSpec,
)

logger = ConfigManager.get_logger(__name__)


def _parse_grouped_labels(
    docker_labels: dict[str, str],
    base_prefix: str,
) -> dict[str, dict[str, str]]:
    """Group labels by type and index.

    Returns dict keyed by (type, index) -> field_dict.
    Index is empty string for unnumbered labels.
    """
    docker_grouped: dict[str, dict[str, str]] = {}
    prefix = base_prefix.rstrip(".")
    pattern = re.compile(rf"^{re.escape(prefix)}\.(proxy|dead|redirect|stream)(\d*)\.(.+)$")

    for key, value in docker_labels.items():
        m = pattern.match(key)
        if not m:
            continue
        item_type = m.group(1)
        idx = m.group(2)
        field = m.group(3)
        group_key = f"{item_type}{idx}"
        docker_grouped.setdefault(group_key, {})[field] = value

    return docker_grouped


def extract_proxy_host_spec_from_grouped_labels(
    docker_fields: dict[str, str],
) -> DockerProxyHostSpec | None:
    domains_raw = docker_fields.get("domain_names")
    forward_host = docker_fields.get("forward_host")
    forward_port = docker_fields.get("forward_port")
    forward_scheme = docker_fields.get("forward_scheme")

    if not domains_raw or not forward_host or not forward_port or not forward_scheme:
        return None

    try:
        domains = utils.parse_domain_names(domains_raw)
    except Exception:
        return None

    loc_pattern = re.compile(r"^loc(\d+)_(.+)$")
    docker_loc_groups: dict[int, dict[str, str]] = {}
    for k, v in docker_fields.items():
        m = loc_pattern.match(k)
        if not m:
            continue
        try:
            idx = int(m.group(1))
        except Exception:
            continue
        if idx <= 0:
            continue
        docker_loc_groups.setdefault(idx, {})[m.group(2)] = v

    locations: list[DockerProxyHostSpec.CustomLocation] = []
    for idx in sorted(docker_loc_groups.keys()):
        docker_loc_fields = docker_loc_groups[idx]
        path = docker_loc_fields.get("path")
        loc_forward_host = docker_loc_fields.get("forward_host")
        loc_forward_port = docker_loc_fields.get("forward_port")
        loc_forward_scheme = docker_loc_fields.get("forward_scheme") or forward_scheme
        if not path or not loc_forward_host or not loc_forward_port:
            continue
        locations.append(
            DockerProxyHostSpec.CustomLocation(
                path=path,
                forward_host=loc_forward_host,
                forward_port=loc_forward_port,
                forward_scheme=loc_forward_scheme,
                advanced_config=docker_loc_fields.get("advanced_config"),
                allow_websocket_upgrade=docker_loc_fields.get("allow_websocket_upgrade"),
                block_exploits=docker_loc_fields.get("block_exploits"),
                caching_enabled=docker_loc_fields.get("caching_enabled"),
                location_type=docker_loc_fields.get("location_type"),
            )
        )

    return DockerProxyHostSpec(
        domain_names=domains,
        forward_host=forward_host,
        forward_port=forward_port,
        forward_scheme=forward_scheme,
        locations=locations,
        access_list=docker_fields.get("access_list"),
        advanced_config=docker_fields.get("advanced_config"),
        allow_websocket_upgrade=docker_fields.get("allow_websocket_upgrade"),
        block_exploits=docker_fields.get("block_exploits"),
        caching_enabled=docker_fields.get("caching_enabled"),
        certificate=docker_fields.get("certificate"),
        enabled=docker_fields.get("enabled"),
        hsts_enabled=docker_fields.get("hsts_enabled"),
        hsts_subdomains=docker_fields.get("hsts_subdomains"),
        http2_support=docker_fields.get("http2_support"),
        ssl_forced=docker_fields.get("ssl_forced"),
    )


def extract_dead_host_spec_from_grouped_labels(
    docker_fields: dict[str, str],
) -> DockerDeadHostSpec | None:
    domains_raw = docker_fields.get("domain_names")
    if not domains_raw:
        return None

    try:
        domain_names = utils.parse_domain_names(domains_raw)
    except Exception:
        return None

    return DockerDeadHostSpec(
        domain_names=domain_names,
        certificate=docker_fields.get("certificate"),
        enabled=docker_fields.get("enabled"),
        ssl_forced=docker_fields.get("ssl_forced"),
        hsts_enabled=docker_fields.get("hsts_enabled"),
        hsts_subdomains=docker_fields.get("hsts_subdomains"),
        http2_support=docker_fields.get("http2_support"),
        advanced_config=docker_fields.get("advanced_config"),
    )


def extract_redirection_host_spec_from_grouped_labels(
    docker_fields: dict[str, str],
) -> DockerRedirectionHostSpec | None:
    domains_raw = docker_fields.get("domain_names")
    forward_domain_name = docker_fields.get("forward_domain_name")
    forward_http_code = docker_fields.get("forward_http_code")
    forward_scheme = docker_fields.get("forward_scheme")

    if not domains_raw or not forward_domain_name or not forward_http_code or not forward_scheme:
        return None

    try:
        domain_names = utils.parse_domain_names(domains_raw)
    except Exception:
        return None

    return DockerRedirectionHostSpec(
        domain_names=domain_names,
        forward_domain_name=forward_domain_name,
        forward_http_code=forward_http_code,
        forward_scheme=forward_scheme,
        preserve_path=docker_fields.get("preserve_path"),
        certificate=docker_fields.get("certificate"),
        enabled=docker_fields.get("enabled"),
        ssl_forced=docker_fields.get("ssl_forced"),
        block_exploits=docker_fields.get("block_exploits"),
        hsts_enabled=docker_fields.get("hsts_enabled"),
        hsts_subdomains=docker_fields.get("hsts_subdomains"),
        http2_support=docker_fields.get("http2_support"),
        advanced_config=docker_fields.get("advanced_config"),
    )


def extract_stream_spec_from_grouped_labels(
    docker_fields: dict[str, str],
) -> DockerStreamSpec | None:
    incoming_port = docker_fields.get("incoming_port")
    forwarding_host = docker_fields.get("forwarding_host")
    forwarding_port = docker_fields.get("forwarding_port")

    if not incoming_port or not forwarding_host or not forwarding_port:
        return None

    return DockerStreamSpec(
        incoming_port=incoming_port,
        forwarding_host=forwarding_host,
        forwarding_port=forwarding_port,
        tcp_forwarding=docker_fields.get("tcp_forwarding"),
        udp_forwarding=docker_fields.get("udp_forwarding"),
        proxy_protocol_forwarding=docker_fields.get("proxy_protocol_forwarding"),
        certificate=docker_fields.get("certificate"),
        enabled=docker_fields.get("enabled"),
    )


def extract_all_specs_from_labels(
    docker_labels: dict[str, str] | None,
) -> tuple[
    list[DockerProxyHostSpec],
    list[DockerDeadHostSpec],
    list[DockerRedirectionHostSpec],
    list[DockerStreamSpec],
]:
    """Extract all spec types from Docker container labels.

    Uses the label schema: <prefix>.<type>[N].<field>
    """
    docker_labels = docker_labels or {}
    base_prefix = ConfigManager.docker_label_prefix().rstrip(".")

    docker_proxy_specs: list[DockerProxyHostSpec] = []
    docker_dead_specs: list[DockerDeadHostSpec] = []
    docker_redirect_specs: list[DockerRedirectionHostSpec] = []
    docker_stream_specs: list[DockerStreamSpec] = []

    docker_grouped = _parse_grouped_labels(docker_labels, base_prefix + ".")
    for group_key, docker_fields in docker_grouped.items():
        if group_key.startswith("proxy"):
            spec = extract_proxy_host_spec_from_grouped_labels(docker_fields)
            if spec is not None:
                docker_proxy_specs.append(spec)
        elif group_key.startswith("dead"):
            spec = extract_dead_host_spec_from_grouped_labels(docker_fields)
            if spec is not None:
                docker_dead_specs.append(spec)
        elif group_key.startswith("redirect"):
            spec = extract_redirection_host_spec_from_grouped_labels(docker_fields)
            if spec is not None:
                docker_redirect_specs.append(spec)
        elif group_key.startswith("stream"):
            spec = extract_stream_spec_from_grouped_labels(docker_fields)
            if spec is not None:
                docker_stream_specs.append(spec)

    return docker_proxy_specs, docker_dead_specs, docker_redirect_specs, docker_stream_specs


def _get_docker_inspect_items() -> list[dict[str, Any]]:
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


def scan_docker_specs(
    *,
    docker_inspect_items: Sequence[dict[str, Any]] | None = None,
) -> tuple[
    list[DockerProxyHostSpec],
    list[DockerDeadHostSpec],
    list[DockerRedirectionHostSpec],
    list[DockerStreamSpec],
]:
    """Scan all Docker containers and extract all spec types from labels."""

    docker_inspect_items = list(docker_inspect_items) if docker_inspect_items is not None else _get_docker_inspect_items()

    docker_proxy_specs: list[DockerProxyHostSpec] = []
    docker_dead_specs: list[DockerDeadHostSpec] = []
    docker_redirect_specs: list[DockerRedirectionHostSpec] = []
    docker_stream_specs: list[DockerStreamSpec] = []

    for docker_inspect_item in docker_inspect_items:
        docker_labels = (
            ((docker_inspect_item.get("Config") or {}) if isinstance(docker_inspect_item.get("Config"), dict) else {})
            .get("Labels")
            or {}
        )
        if not isinstance(docker_labels, dict):
            docker_labels = {}

        proxy_specs, dead_specs, redirect_specs, stream_specs = extract_all_specs_from_labels(
            {str(k): str(v) for k, v in docker_labels.items() if k is not None and v is not None}
        )
        docker_proxy_specs.extend(proxy_specs)
        docker_dead_specs.extend(dead_specs)
        docker_redirect_specs.extend(redirect_specs)
        docker_stream_specs.extend(stream_specs)

    logger.info(
        "Scan found proxy=%d dead=%d redirect=%d stream=%d",
        len(docker_proxy_specs),
        len(docker_dead_specs),
        len(docker_redirect_specs),
        len(docker_stream_specs),
    )

    return docker_proxy_specs, docker_dead_specs, docker_redirect_specs, docker_stream_specs
