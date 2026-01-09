from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .configmanager import ConfigManager
from .npmplus_api import NPMplusApi

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


class DockerSyncer:
    @staticmethod
    def extract_proxy_host_spec_from_labels(
        *,
        labels: Mapping[str, str] | None,
        container_id: str,
        container_name: str,
    ) -> DockerProxyHostSpec | None:
        """Extract a proxy-host spec from Docker container labels.

        Parses labels with the configured prefix and returns a DockerProxyHostSpec
        if all required fields are present and valid.
        """
        labels = labels or {}
        prefix = ConfigManager.docker_label_prefix()
        # Only consider containers that opt-in via our label prefix.
        prefixed = {k: v for k, v in labels.items() if isinstance(k, str) and k.startswith(prefix)}
        if not prefixed:
            return None

        domains_raw = labels.get(f"{prefix}domain_names")
        forward_host = labels.get(f"{prefix}forward_host")
        forward_port_raw = labels.get(f"{prefix}forward_port")
        forward_scheme = labels.get(f"{prefix}forward_scheme")

        # Optional fields
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

        # Locations: <prefix>locN_path, <prefix>locN_forward_host, <prefix>locN_forward_port, <prefix>locN_forward_scheme
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

        # These four must be present.
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
            certificate_domains=(None if certificate_raw is None else [d.lower() for d in _split_csv(certificate_raw)]),
            enabled=enabled,
            hsts_enabled=hsts_enabled,
            hsts_subdomains=hsts_subdomains,
            http2_support=http2_support,
            ssl_forced=ssl_forced,
        )

    @staticmethod
    def extract_proxy_host_specs_from_inspect(
        inspect_data: Sequence[Mapping[str, Any]],
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

        inspect_items: list[Mapping[str, Any]] = []
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
    def sync_docker_proxy_hosts(
        cls,
        *,
        client: NPMplusApi,
        specs: Sequence[DockerProxyHostSpec],
        disable_orphans: bool = False,
        delete_orphans: bool = False,
        owner_user_id: int | None = None,
    ) -> tuple[int, int, int]:
        """Create/update proxy-hosts from docker label specs.

        If disable_orphans is True, proxy-hosts owned by the current user but not present
        in docker specs will be updated to enabled=false.

        If delete_orphans is True, proxy-hosts owned by the current user but not present
        in docker specs will be deleted.

        Returns (created, updated, skipped).
        """

        def _infer_owner_user_id_from_token() -> int | None:
            # Best-effort: different NPMplus versions may return different shapes.
            try:
                data = client.refresh_token()
                for key in ("user_id", "userId", "id"):
                    if key in data:
                        try:
                            return int(str(data[key]).strip())  # type: ignore[index]
                        except Exception:
                            pass
            except Exception:
                return None
            return None

        def _domain_key_from_payload(payload: Mapping[str, Any]) -> tuple[str, ...] | None:
            domains = payload.get("domain_names") or payload.get("domainNames")
            if not isinstance(domains, list):
                return None
            key = _domain_key([str(d) for d in domains])
            return key or None

        def _camel_key(snake: str) -> str:
            parts = (snake or "").split("_")
            if not parts:
                return snake
            return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])

        def _get_existing_value(item: Mapping[str, Any], key: str) -> object:
            if key in item:
                return item.get(key)
            camel = _camel_key(key)
            return item.get(camel)

        def _normalize_domains(value: object) -> tuple[str, ...] | None:
            if not isinstance(value, list):
                return None
            return _domain_key([str(v) for v in value])

        def _normalize_int(value: object) -> int | None:
            if value is None:
                return None
            try:
                return int(str(value).strip())
            except Exception:
                return None

        def _normalize_bool(value: object) -> bool | None:
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

        def _values_equal(field: str, desired: object, existing: object) -> bool:
            def _normalize_locations(value: object) -> list[tuple[object, ...]]:
                if not isinstance(value, list):
                    return []
                out: list[tuple[object, ...]] = []
                for item in value:
                    if not isinstance(item, dict):
                        continue
                    path = str(item.get("path") or "").strip()
                    forward_host = str(item.get("forward_host") or item.get("forwardHost") or "").strip().lower()
                    forward_scheme = str(item.get("forward_scheme") or item.get("forwardScheme") or "").strip().lower()
                    forward_port = _normalize_int(item.get("forward_port") or item.get("forwardPort"))
                    advanced_config = str(item.get("advanced_config") or item.get("advancedConfig") or "")
                    allow_ws = _normalize_bool(item.get("allow_websocket_upgrade") or item.get("allowWebsocketUpgrade"))
                    block_exploits = _normalize_bool(item.get("block_exploits") or item.get("blockExploits"))
                    caching_enabled = _normalize_bool(item.get("caching_enabled") or item.get("cachingEnabled"))
                    location_type = str(item.get("location_type") or item.get("locationType") or "").strip()
                    if not path:
                        continue
                    out.append(
                        (
                            path,
                            forward_host,
                            forward_port,
                            forward_scheme,
                            advanced_config,
                            allow_ws,
                            block_exploits,
                            caching_enabled,
                            location_type,
                        )
                    )
                out.sort(key=lambda t: str(t[0]))
                return out

            if field == "locations":
                return _normalize_locations(desired) == _normalize_locations(existing)
            if field == "domain_names":
                return _normalize_domains(desired) == _normalize_domains(existing)
            if field in {"forward_port", "access_list_id", "certificate_id"}:
                return _normalize_int(desired) == _normalize_int(existing)
            if field in set(ProxyHostFields.BOOL_FIELDS):
                return _normalize_bool(desired) == _normalize_bool(existing)
            if field in {"forward_scheme", "forward_host"}:
                return str(desired).strip().lower() == str(existing).strip().lower()
            return desired == existing

        existing = client.list_proxy_hosts(expand=[], query=None)
        by_domains = index_proxy_hosts_by_domains(existing)

        access_list_name_to_id: dict[str, int] = {}
        if any(spec.access_list is not None for spec in specs):
            try:
                for item in client.list_access_lists(expand=[], query=None):
                    if not isinstance(item, dict):
                        continue
                    name = item.get("name") or item.get("title")
                    item_id = item.get("id")
                    if name is None or item_id is None:
                        continue
                    try:
                        access_list_name_to_id[str(name).strip().lower()] = int(str(item_id).strip())
                    except Exception:
                        continue
            except Exception as e:
                logger.warning("Failed to list access-lists for docker sync (%s)", str(e))

        cert_domain_key_to_id: dict[tuple[str, ...], int] = {}
        if any(spec.certificate_domains is not None for spec in specs):
            try:
                for item in client.list_certificates(expand=[], query=None):
                    if not isinstance(item, dict):
                        continue
                    item_id = item.get("id")
                    key = _domain_key_from_payload(item)
                    if item_id is None or key is None:
                        continue
                    try:
                        cert_domain_key_to_id[key] = int(str(item_id).strip())
                    except Exception:
                        continue
            except Exception as e:
                logger.warning("Failed to list certificates for docker sync (%s)", str(e))

        created = 0
        updated = 0
        skipped = 0
        disabled = 0
        managed_owner_user_id: int | None = None

        seen_domain_keys: set[tuple[str, ...]] = set()

        for spec in specs:
            key = _domain_key(spec.domain_names)
            if key in seen_domain_keys:
                logger.warning(
                    "Duplicate domain_names in docker specs; skipping container %s",
                    spec.container_name,
                )
                skipped += 1
                continue
            seen_domain_keys.add(key)

            base_payload = ProxyHostFields.payload_from_docker_spec(
                spec,
                access_list_name_to_id=access_list_name_to_id,
                cert_domain_key_to_id=cert_domain_key_to_id,
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
            if spec.certificate_domains is not None:
                cert_key = _domain_key(spec.certificate_domains)
                if cert_key and "certificate_id" not in base_payload:
                    logger.warning(
                        "Docker spec references certificate=%s but no matching certificate found; leaving unset (container=%s)",
                        ",".join(cert_key),
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
                skipped += 1
                continue

            changed_fields: list[str] = []
            if mode == "update":
                assert existing_item is not None
                for field, desired_value in base_payload.items():
                    existing_value = _get_existing_value(existing_item, field)
                    if not _values_equal(field, desired_value, existing_value):
                        changed_fields.append(field)
                if not changed_fields:
                    assert obj_id is not None
                    logger.info(
                        "Docker sync: no changes for proxy-host id=%s domains=%s (container=%s)",
                        obj_id,
                        list(key),
                        spec.container_name,
                    )
                    skipped += 1
                    continue

            if mode == "create":
                result = client.create_proxy_host(base_payload)
                created += 1
                logger.info(
                    "Docker sync: created proxy-host id=%s domains=%s (container=%s)",
                    result.get("id"),
                    list(key),
                    spec.container_name,
                )
            else:
                assert obj_id is not None
                host_id: int = obj_id
                result = client.update_proxy_host(host_id, base_payload)
                updated += 1
                logger.info(
                    "Docker sync: updated proxy-host id=%s domains=%s fields=%s (container=%s)",
                    host_id,
                    list(key),
                    ", ".join(changed_fields),
                    spec.container_name,
                )

            if managed_owner_user_id is None:
                owner_raw = result.get("owner_user_id") or result.get("ownerUserId")
                try:
                    managed_owner_user_id = int(str(owner_raw).strip())
                except Exception:
                    managed_owner_user_id = None

        if disable_orphans:
            effective_owner_id: int | None = owner_user_id
            if effective_owner_id is None:
                effective_owner_id = managed_owner_user_id
            if effective_owner_id is None and specs:
                # If we didn't create/update anything, try to infer from an existing host matched by docker.
                for k in seen_domain_keys:
                    item = by_domains.get(k)
                    if not item:
                        continue
                    owner_raw = item.get("owner_user_id") or item.get("ownerUserId")
                    try:
                        effective_owner_id = int(str(owner_raw).strip())
                        break
                    except Exception:
                        continue
            if effective_owner_id is None:
                effective_owner_id = _infer_owner_user_id_from_token()
            if effective_owner_id is None:
                logger.warning(
                    "disable_orphans requested but could not determine owner_user_id; skipping orphan disable"
                )
                return created, updated, skipped

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
                result = client.update_proxy_host(host_id, {"enabled": False})
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
            effective_owner_id: int | None = owner_user_id
            if effective_owner_id is None:
                effective_owner_id = managed_owner_user_id
            if effective_owner_id is None and specs:
                # If we didn't create/update anything, try to infer from an existing host matched by docker.
                for k in seen_domain_keys:
                    item = by_domains.get(k)
                    if not item:
                        continue
                    owner_raw = item.get("owner_user_id") or item.get("ownerUserId")
                    try:
                        effective_owner_id = int(str(owner_raw).strip())
                        break
                    except Exception:
                        continue
            if effective_owner_id is None:
                effective_owner_id = _infer_owner_user_id_from_token()
            if effective_owner_id is None:
                logger.warning(
                    "delete_orphans requested but could not determine owner_user_id; skipping orphan deletion"
                )
                return created, updated, skipped

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
    def _get_access_list_name(payload: Mapping[str, Any]) -> str | None:
        value = payload.get("access_list") or payload.get("accessList")
        if isinstance(value, str):
            s = value.strip()
            return s or None
        if isinstance(value, Mapping):
            name = value.get("name") or value.get("title")
            if name is None:
                return None
            s = str(name).strip()
            return s or None
        return None

    @staticmethod
    def _get_certificate_domains(payload: Mapping[str, Any]) -> list[str] | None:
        cert = payload.get("certificate")
        if isinstance(cert, Mapping):
            domains = cert.get("domain_names")
            if domains is None:
                domains = cert.get("domainNames")
            out = ProxyHostFields._split_domains(domains)
            return out or None
        return None

    @staticmethod
    def _get_locations(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        locs = payload.get("locations")
        if locs is None:
            return []
        if isinstance(locs, Mapping):
            return [locs]
        if isinstance(locs, list):
            return [x for x in locs if isinstance(x, Mapping)]
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

        cert_domains = ProxyHostFields._get_certificate_domains(payload)
        if cert_domains:
            labels.append((f"{prefix}certificate", ",".join(cert_domains)))

        access_list = ProxyHostFields._get_access_list_name(payload)
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
        access_list_name_to_id: Mapping[str, int],
        cert_domain_key_to_id: Mapping[tuple[str, ...], int],
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

        # relations (resolved by name/domains)
        if spec.access_list is not None:
            name = spec.access_list.strip()
            if not name:
                payload["access_list_id"] = 0
            else:
                access_list_id = access_list_name_to_id.get(name.lower())
                if access_list_id is not None:
                    payload["access_list_id"] = access_list_id

        if spec.certificate_domains is not None:
            cert_key = _domain_key(spec.certificate_domains)
            if not cert_key:
                payload["certificate_id"] = 0
            else:
                cert_id = cert_domain_key_to_id.get(cert_key)
                if cert_id is not None:
                    payload["certificate_id"] = cert_id

        return payload


def _domain_key(domain_names: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted(d.strip().lower() for d in domain_names if str(d).strip()))


def index_proxy_hosts_by_domains(
    items: Sequence[Mapping[str, Any]],
) -> dict[tuple[str, ...], Mapping[str, Any]]:
    out: dict[tuple[str, ...], Mapping[str, Any]] = {}
    for item in items:
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
    existing_items: Sequence[Mapping[str, Any]],
    managed_domain_keys: set[tuple[str, ...]],
    owner_user_id: int,
) -> list[Mapping[str, Any]]:
    """Return proxy-host items owned by owner_user_id but not present in managed_domain_keys."""
    orphans: list[Mapping[str, Any]] = []
    for item in existing_items:
        item_owner = item.get("owner_user_id") or item.get("ownerUserId")
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
