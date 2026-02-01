from __future__ import annotations

from collections.abc import Sequence

from ..configmanager import ConfigManager
from ..npmplus_client import NPMplusClient
from .specs import (
    DockerStreamSpec,
    StreamFields,
    find_orphan_streams,
    index_streams_by_port,
    warn_if_missing_certificate,
)

logger = ConfigManager.get_logger(__name__)


def sync_docker_streams(
    *,
    client: NPMplusClient,
    docker_specs: Sequence[DockerStreamSpec],
    take_ownership: bool = False,
    disable_orphans: bool = False,
    delete_orphans: bool = False,
) -> None:
    """Create/update streams from docker label specs."""

    existing = client.list_streams()
    by_port = index_streams_by_port(existing)

    effective_owner_id: int | None = None
    if disable_orphans or delete_orphans:
        try:
            effective_owner_id = client.my_id
        except Exception:
            effective_owner_id = None
    if take_ownership and not client.my_natural_index:
        raise ValueError("--take-ownership requires determining current user (ensure /api/users/me works)")

    seen_port_keys: set[int] = set()
    for docker_spec in docker_specs:
        port_key = int(str(docker_spec.incoming_port).strip())
        if port_key in seen_port_keys:
            logger.warning(
                "Duplicate incoming_port in docker specs; skipping streams incoming_port=%s",
                port_key,
            )
            continue
        seen_port_keys.add(port_key)

        natural_index = str(port_key)
        warn_if_missing_certificate(
            client=client,
            certificate=docker_spec.certificate,
            kind="streams",
            natural_index=natural_index,
        )

        desired = StreamFields.item_from_docker_spec(docker_spec, client=client)

        existing_item = by_port.get(port_key)
        existing_id: int | None = existing_item.id if existing_item is not None and existing_item.id > 0 else None

        if existing_item is not None and StreamFields.items_equal(desired, existing_item):
            logger.info(
                "Synced %s %s (skip) id=%s from docker",
                "streams",
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
            "streams",
            natural_index,
            mode,
            new_id,
        )

    if disable_orphans and effective_owner_id is not None:
        if not seen_port_keys:
            logger.warning("disable_orphans requested but no stream specs provided; skipping orphan disable")
        else:
            orphans = find_orphan_streams(
                existing_items=existing,
                managed_port_keys=seen_port_keys,
                owner_user_id=effective_owner_id,
            )
            for item in orphans:
                stream_id = item.id
                if stream_id <= 0:
                    continue
                if item.enabled is False:
                    continue
                client.disable_stream(stream_id)
                incoming_port = item.incoming_port
                natural_index = str(incoming_port) if incoming_port else f"id={stream_id}"
                logger.info("Docker sync: disabled orphan stream (%s)", natural_index)

    if delete_orphans and effective_owner_id is not None:
        if not seen_port_keys:
            logger.warning("delete_orphans requested but no stream specs provided; skipping orphan deletion")
        else:
            orphans = find_orphan_streams(
                existing_items=existing,
                managed_port_keys=seen_port_keys,
                owner_user_id=effective_owner_id,
            )
            for item in orphans:
                stream_id = item.id
                if stream_id <= 0:
                    continue
                client.delete_stream(stream_id)
                logger.info(
                    "Docker sync: deleted orphan stream id=%s incoming_port=%s",
                    stream_id,
                    item.incoming_port,
                )
