from __future__ import annotations

import logging
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


def _normalize_prefix(value: str | None) -> str:
    s = (value or "").strip()
    if not s:
        return "npmp-"
    return s if s.endswith("-") else s + "-"


_LABEL_PREFIX = _normalize_prefix(os.getenv("NPMP_DOCKER_LABEL_PREFIX"))


@dataclass(frozen=True)
class DockerProxyHostSpec:
    container_id: str
    container_name: str
    domain_names: list[str]
    forward_host: str
    forward_port: int
    forward_scheme: str
    access_list: str | None = None
    advanced_config: str | None = None
    allow_websocket_upgrade: bool | None = None
    block_exploits: bool | None = None
    caching_enabled: bool | None = None
    certificate_domains: list[str] | None = None
    enabled: bool | None = None
    hsts_enabled: bool | None = None
    hsts_subdomains: bool | None = None
    http2_support: bool | None = None
    ssl_forced: bool | None = None


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


def extract_proxy_host_spec_from_labels(
    *,
    labels: Mapping[str, str] | None,
    container_id: str,
    container_name: str,
) -> DockerProxyHostSpec | None:
    labels = labels or {}
    # Only consider containers that opt-in via our label prefix.
    prefixed = {
        k: v
        for k, v in labels.items()
        if isinstance(k, str) and k.startswith(_LABEL_PREFIX)
    }
    if not prefixed:
        return None

    domains_raw = labels.get(f"{_LABEL_PREFIX}domain_names")
    forward_host = labels.get(f"{_LABEL_PREFIX}forward_host")
    forward_port_raw = labels.get(f"{_LABEL_PREFIX}forward_port")
    forward_scheme = labels.get(f"{_LABEL_PREFIX}forward_scheme")

    # Optional fields
    access_list = labels.get(f"{_LABEL_PREFIX}access_list")
    advanced_config = labels.get(f"{_LABEL_PREFIX}advanced_config")
    allow_websocket_upgrade = _parse_bool(
        labels.get(f"{_LABEL_PREFIX}allow_websocket_upgrade")
    )
    block_exploits = _parse_bool(labels.get(f"{_LABEL_PREFIX}block_exploits"))
    caching_enabled = _parse_bool(labels.get(f"{_LABEL_PREFIX}caching_enabled"))
    certificate_raw = labels.get(f"{_LABEL_PREFIX}certificate")
    enabled = _parse_bool(labels.get(f"{_LABEL_PREFIX}enabled"))
    hsts_enabled = _parse_bool(labels.get(f"{_LABEL_PREFIX}hsts_enabled"))
    hsts_subdomains = _parse_bool(labels.get(f"{_LABEL_PREFIX}hsts_subdomains"))
    http2_support = _parse_bool(labels.get(f"{_LABEL_PREFIX}http2_support"))
    ssl_forced = _parse_bool(labels.get(f"{_LABEL_PREFIX}ssl_forced"))

    # These four must be present.
    if (
        not domains_raw
        or not forward_host
        or not forward_port_raw
        or not forward_scheme
    ):
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

    return DockerProxyHostSpec(
        container_id=container_id,
        container_name=(
            container_name.lstrip("/") if container_name else container_id[:12]
        ),
        domain_names=domain_names,
        forward_host=str(forward_host).strip(),
        forward_port=forward_port,
        forward_scheme=str(forward_scheme).strip(),
        access_list=None if access_list is None else str(access_list).strip(),
        advanced_config=None if advanced_config is None else str(advanced_config),
        allow_websocket_upgrade=allow_websocket_upgrade,
        block_exploits=block_exploits,
        caching_enabled=caching_enabled,
        certificate_domains=(
            None
            if certificate_raw is None
            else [d.lower() for d in _split_csv(certificate_raw)]
        ),
        enabled=enabled,
        hsts_enabled=hsts_enabled,
        hsts_subdomains=hsts_subdomains,
        http2_support=http2_support,
        ssl_forced=ssl_forced,
    )


def extract_proxy_host_specs_from_inspect(
    inspect_data: Sequence[Mapping[str, Any]],
) -> list[DockerProxyHostSpec]:
    specs: list[DockerProxyHostSpec] = []
    for item in inspect_data:
        container_id = str(item.get("Id") or "").strip()
        container_name = str(item.get("Name") or "").strip()
        labels = (
            (item.get("Config") or {}) if isinstance(item.get("Config"), dict) else {}
        ).get("Labels") or {}
        if not isinstance(labels, dict):
            labels = {}
        spec = extract_proxy_host_spec_from_labels(
            labels={
                str(k): str(v)
                for k, v in labels.items()
                if k is not None and v is not None
            },
            container_id=container_id,
            container_name=container_name,
        )
        if spec is not None:
            specs.append(spec)
    return specs


def scan_docker_proxy_host_specs() -> list[DockerProxyHostSpec]:
    """Scan all Docker containers and extract proxy-host specs from labels.

    Uses the Python Docker SDK (`docker` module) via `docker.from_env()`.
    Respects the DOCKER_HOST environment variable; if not set, connects to
    the local Docker socket (unix:///var/run/docker.sock on Unix systems).
    """
    try:
        import docker  # type: ignore[import-not-found]
    except Exception as e:
        raise RuntimeError(
            "Python docker module not installed; install 'docker' package"
        ) from e

    try:
        client = docker.from_env()
    except Exception as e:
        raise RuntimeError("Failed to initialize Docker client from environment") from e

    try:
        containers = client.containers.list(all=True)
    except Exception as e:
        raise RuntimeError("Failed to list docker containers") from e

    inspect_items: list[Mapping[str, Any]] = []
    for c in containers:
        try:
            attrs = getattr(c, "attrs", None) or {}
            if isinstance(attrs, dict):
                inspect_items.append(attrs)
        except Exception:
            # Skip containers that cannot be inspected.
            continue

    specs = extract_proxy_host_specs_from_inspect(inspect_items)
    logger.info(
        "Found %s docker container specs with required npmp-* labels", len(specs)
    )
    return specs
