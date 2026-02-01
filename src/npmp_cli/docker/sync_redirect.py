from __future__ import annotations

from collections.abc import Sequence

from ..configmanager import ConfigManager
from ..npmplus_client import NPMplusClient
from .specs import (
    DockerRedirectionHostSpec,
    RedirectionHostFields,
    domain_key,
    find_orphan_redirection_hosts,
    index_redirection_hosts_by_domains,
    warn_if_missing_certificate,
)

logger = ConfigManager.get_logger(__name__)


def sync_docker_redirection_hosts(
    *,
    client: NPMplusClient,
    docker_specs: Sequence[DockerRedirectionHostSpec],
    take_ownership: bool = False,
    disable_orphans: bool = False,
    delete_orphans: bool = False,
) -> None:
    """Create/update redirection-hosts from docker label specs."""

    existing = client.list_redirection_hosts()
    by_domains = index_redirection_hosts_by_domains(existing)

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
        if key in seen_domain_keys:
            natural_index = ",".join(key)
            logger.warning(
                "Duplicate domain_names in docker specs; skipping redirection-hosts domains=%s",
                natural_index,
            )
            continue
        seen_domain_keys.add(key)

        natural_index = ",".join(key)
        warn_if_missing_certificate(
            client=client,
            certificate=docker_spec.certificate,
            kind="redirection-hosts",
            natural_index=natural_index,
        )

        desired = RedirectionHostFields.item_from_docker_spec(docker_spec, client=client)

        existing_item = by_domains.get(key)
        existing_id: int | None = existing_item.id if existing_item is not None and existing_item.id > 0 else None

        if existing_item is not None and RedirectionHostFields.items_equal(desired, existing_item):
            logger.info(
                "Synced %s %s (skip) id=%s from docker",
                "redirection-hosts",
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
            "redirection-hosts",
            natural_index,
            mode,
            new_id,
        )

    if disable_orphans and effective_owner_id is not None:
        if not seen_domain_keys:
            logger.warning(
                "disable_orphans requested but no redirection-host specs provided; skipping orphan disable"
            )
        else:
            orphans = find_orphan_redirection_hosts(
                existing_items=existing,
                managed_domain_keys=seen_domain_keys,
                owner_user_id=effective_owner_id,
            )
            for item in orphans:
                host_id = item.id
                if host_id <= 0:
                    continue
                if item.enabled is False:
                    continue
                client.disable_redirection_host(host_id)
                domains = item.domain_names or []
                natural_index = ",".join(str(d) for d in domains) if domains else f"id={host_id}"
                logger.info("Docker sync: disabled orphan redirection-host (%s)", natural_index)

    if delete_orphans and effective_owner_id is not None:
        if not seen_domain_keys:
            logger.warning(
                "delete_orphans requested but no redirection-host specs provided; skipping orphan deletion"
            )
        else:
            orphans = find_orphan_redirection_hosts(
                existing_items=existing,
                managed_domain_keys=seen_domain_keys,
                owner_user_id=effective_owner_id,
            )
            for item in orphans:
                host_id = item.id
                if host_id <= 0:
                    continue
                client.delete_redirection_host(host_id)
                logger.info(
                    "Docker sync: deleted orphan redirection-host id=%s domains=%s",
                    host_id,
                    item.domain_names,
                )
