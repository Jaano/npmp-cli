from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .api_client import NPMplusClient
from .docker_scanner import DockerProxyHostSpec
from .yaml_loader import filter_payload_for_write
from .yaml_writer import host_filename, write_yaml_file

logger = logging.getLogger(__name__)


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


def sync_docker_proxy_hosts(
    *,
    client: NPMplusClient,
    specs: Sequence[DockerProxyHostSpec],
    out_dir: Path,
    skip_unchanged: bool,
    disable_orphans: bool = False,
    delete_orphans: bool = False,
    owner_user_id: int | None = None,
) -> tuple[int, int, int]:
    """Create/update proxy-hosts from docker label specs.

    If disable_orphans is True, proxy-hosts owned by the current user but not present in docker specs
    will be updated to enabled=false.

    If delete_orphans is True, proxy-hosts owned by the current user but not present in docker specs
    will be deleted.

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

    def _bool_fields_from_spec(spec: DockerProxyHostSpec) -> dict[str, bool]:
        out: dict[str, bool] = {}
        if spec.allow_websocket_upgrade is not None:
            out["allow_websocket_upgrade"] = spec.allow_websocket_upgrade
        if spec.block_exploits is not None:
            out["block_exploits"] = spec.block_exploits
        if spec.caching_enabled is not None:
            out["caching_enabled"] = spec.caching_enabled
        if spec.enabled is not None:
            out["enabled"] = spec.enabled
        if spec.hsts_enabled is not None:
            out["hsts_enabled"] = spec.hsts_enabled
        if spec.hsts_subdomains is not None:
            out["hsts_subdomains"] = spec.hsts_subdomains
        if spec.http2_support is not None:
            out["http2_support"] = spec.http2_support
        if spec.ssl_forced is not None:
            out["ssl_forced"] = spec.ssl_forced
        return out

    def _domain_key_from_payload(payload: Mapping[str, Any]) -> tuple[str, ...] | None:
        domains = payload.get("domain_names") or payload.get("domainNames")
        if not isinstance(domains, list):
            return None
        key = _domain_key([str(d) for d in domains])
        return key or None

    schema = client.get_schema()
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
                    access_list_name_to_id[str(name).strip().lower()] = int(
                        str(item_id).strip()
                    )
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

        base_payload: dict[str, Any] = {
            "domain_names": list(key),
            "forward_host": spec.forward_host,
            "forward_port": spec.forward_port,
            "forward_scheme": spec.forward_scheme,
        }
        base_payload.update(_bool_fields_from_spec(spec))
        if spec.advanced_config is not None:
            base_payload["advanced_config"] = spec.advanced_config
        if spec.access_list is not None:
            name = spec.access_list.strip()
            if not name:
                base_payload["access_list_id"] = 0
            else:
                access_list_id = access_list_name_to_id.get(name.lower())
                if access_list_id is None:
                    logger.warning(
                        "Docker spec references access_list=%s but no matching access-list found; "
                        "leaving unset (container=%s)",
                        name,
                        spec.container_name,
                    )
                else:
                    base_payload["access_list_id"] = access_list_id
        if spec.certificate_domains is not None:
            cert_key = _domain_key(spec.certificate_domains)
            if not cert_key:
                base_payload["certificate_id"] = 0
            else:
                cert_id = cert_domain_key_to_id.get(cert_key)
                if cert_id is None:
                    logger.warning(
                        "Docker spec references certificate=%s but no matching certificate found; "
                        "leaving unset (container=%s)",
                    )
                else:
                    base_payload["certificate_id"] = cert_id

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

        write_payload = filter_payload_for_write(
            schema, "proxy-hosts", base_payload, mode=mode
        )
        if mode == "create":
            result = client.create_proxy_host(write_payload)
            created += 1
        else:
            assert obj_id is not None
            host_id: int = obj_id
            result = client.update_proxy_host(host_id, write_payload)
            updated += 1

        if managed_owner_user_id is None:
            owner_raw = result.get("owner_user_id") or result.get("ownerUserId")
            try:
                managed_owner_user_id = int(str(owner_raw).strip())
            except Exception:
                managed_owner_user_id = None

        path = out_dir / host_filename("proxy-hosts", dict(result))
        write_yaml_file(path, dict(result), skip_unchanged=skip_unchanged)

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
            payload = dict(item)
            payload["enabled"] = False
            write_payload = filter_payload_for_write(
                schema, "proxy-hosts", payload, mode="update"
            )
            result = client.update_proxy_host(host_id, write_payload)
            disabled += 1
            path = out_dir / host_filename("proxy-hosts", dict(result))
            write_yaml_file(path, dict(result), skip_unchanged=skip_unchanged)

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
            deleted += 1

        logger.info(
            "Deleted %s orphan proxy-host(s) for owner_user_id=%s",
            deleted,
            effective_owner_id,
        )

    return created, updated, skipped
