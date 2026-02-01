from __future__ import annotations

from collections.abc import Sequence

from ..configmanager import ConfigManager
from ..npmplus_client import NPMplusClient
from .specs import (
    DockerProxyHostSpec,
    ProxyHostFields,
    domain_key,
    find_orphan_proxy_hosts,
    index_proxy_hosts_by_domains,
    warn_if_missing_access_list,
    warn_if_missing_certificate,
)

logger = ConfigManager.get_logger(__name__)


def sync_docker_proxy_hosts(
    *,
    client: NPMplusClient,
    docker_specs: Sequence[DockerProxyHostSpec],
    take_ownership: bool = False,
    disable_orphans: bool = False,
    delete_orphans: bool = False,
) -> None:
    """Create/update proxy-hosts from docker label specs."""

    existing = client.list_proxy_hosts()
    by_domains = index_proxy_hosts_by_domains(existing)

    effective_owner_id: int | None = None
    if disable_orphans or delete_orphans:
        try:
            effective_owner_id = client.my_id
        except Exception:
            effective_owner_id = None
    if take_ownership and not client.my_natural_index:
        raise ValueError("--take-ownership requires determining current user (ensure /api/users/me works)")

    seen_domain_keys: set[tuple[str, ...]] = set()
    for docker_spec in docker_specs:
        key = domain_key(docker_spec.domain_names)
        parts = [str(d).strip().lower() for d in (docker_spec.domain_names or [])]
        parts = [p for p in parts if p]
        parts = sorted(set(parts))
        natural_index = ",".join(parts)
        if key in seen_domain_keys:
            logger.warning(
                "Duplicate domain_names in docker specs; skipping proxy-hosts domains=%s",
                natural_index,
            )
            continue
        seen_domain_keys.add(key)

        warn_if_missing_access_list(
            client=client,
            access_list=docker_spec.access_list,
            kind="proxy-hosts",
            natural_index=natural_index,
        )
        warn_if_missing_certificate(
            client=client,
            certificate=docker_spec.certificate,
            kind="proxy-hosts",
            natural_index=natural_index,
        )

        desired = ProxyHostFields.item_from_docker_spec(docker_spec, client=client)

        existing_item = by_domains.get(key)
        existing_id: int | None = existing_item.id if existing_item is not None and existing_item.id > 0 else None

        if existing_item is not None and ProxyHostFields.items_equal(desired, existing_item):
            logger.info(
                "Synced %s %s (skip) id=%s from docker",
                "proxy-hosts",
                natural_index,
                existing_id,
            )
            continue

        if existing_id is not None:
            desired.id = existing_id
        mode, result = desired.save(take_ownership=take_ownership)
        new_id: object = result.get("id")
        try:
            new_id = int(str(new_id).strip())
        except Exception:
            pass
        logger.info(
            "Synced %s %s (%s) id=%s from docker",
            "proxy-hosts",
            natural_index,
            mode,
            new_id,
        )

    if disable_orphans:
        if effective_owner_id is None:
            logger.warning(
                "disable_orphans requested but could not determine authenticated owner_user_id; skipping orphan disable"
            )
        elif not seen_domain_keys:
            logger.warning("disable_orphans requested but no proxy-host specs provided; skipping orphan disable")
        else:
            orphans = find_orphan_proxy_hosts(
                existing_items=existing,
                managed_domain_keys=seen_domain_keys,
                owner_user_id=effective_owner_id,
            )
            for item in orphans:
                host_id = item.id
                if host_id <= 0:
                    logger.warning(
                        "Orphan proxy-host missing id; skipping domains=%s",
                        item.domain_names,
                    )
                    continue
                if item.enabled is False:
                    continue
                client.disable_proxy_host(host_id)
                domains = item.domain_names or []
                natural_index = ",".join(str(d) for d in domains) if domains else f"id={host_id}"
                logger.info("Docker sync: disabled orphan proxy-host (%s)", natural_index)

    if delete_orphans:
        if effective_owner_id is None:
            logger.warning(
                "delete_orphans requested but could not determine authenticated owner_user_id; skipping orphan deletion"
            )
        elif not seen_domain_keys:
            logger.warning("delete_orphans requested but no proxy-host specs provided; skipping orphan deletion")
        else:
            orphans = find_orphan_proxy_hosts(
                existing_items=existing,
                managed_domain_keys=seen_domain_keys,
                owner_user_id=effective_owner_id,
            )
            for item in orphans:
                host_id = item.id
                if host_id <= 0:
                    logger.warning(
                        "Orphan proxy-host missing id; skipping domains=%s",
                        item.domain_names,
                    )
                    continue
                client.delete_proxy_host(host_id)
                logger.info(
                    "Docker sync: deleted orphan proxy-host id=%s domains=%s",
                    host_id,
                    item.domain_names,
                )
