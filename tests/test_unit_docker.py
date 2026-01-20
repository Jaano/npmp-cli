from __future__ import annotations

import pytest

from npmp_cli.dockersyncer import DockerProxyHostSpec, DockerSyncer

pytestmark = pytest.mark.integration


class StubClient:
    def __init__(self) -> None:
        self.deleted_ids: list[int] = []
        self.created_payloads: list[dict[str, object]] = []
        self.updated: list[tuple[int, dict[str, object]]] = []

    def get_current_user(self) -> dict[str, int]:
        return {"id": 1}

    def list_proxy_hosts(self, expand: object, query: object) -> dict[int, dict[str, object]]:  # noqa: ARG002
        return {
            100: {
                "id": 100,
                "domain_names": ["example.invalid"],
                "owner_user_id": 2,
                "forward_host": "old.example",
                "forward_port": 80,
                "forward_scheme": "http",
            }
        }

    def get_proxy_host(self, host_id: int) -> dict[str, object]:
        assert host_id == 100
        return {"id": 100, "owner_user_id": 2}

    def set_proxy_host(
        self, payload: dict[str, object], *, host_id: int | None = None, replace: bool = False
    ) -> tuple[str, dict[str, object]]:
        if replace and host_id is not None:
            self.delete_proxy_host(int(host_id))
            self.created_payloads.append(payload)
            return ("create", {"id": 101, **payload})
        if host_id is None:
            self.created_payloads.append(payload)
            return ("create", {"id": 101, **payload})
        self.updated.append((int(host_id), payload))
        return ("update", {"id": int(host_id), **payload})

    def delete_proxy_host(self, host_id: int) -> None:
        self.deleted_ids.append(host_id)

    def list_access_lists(self, expand: object, query: object) -> list[object]:  # noqa: ARG002
        return []

    def list_certificates(self, expand: object, query: object) -> list[object]:  # noqa: ARG002
        return []

    def access_list_name_to_id_map(self) -> dict[str, int]:
        return {}

    def certificate_name_to_id_map(self) -> dict[str, int]:
        return {}


def test_takeownership_deletes_and_recreates() -> None:
    client = StubClient()

    spec = DockerProxyHostSpec(
        container_id="cid",
        container_name="cname",
        domain_names=["example.invalid"],
        forward_host="new.example",
        forward_port=8080,
        forward_scheme="http",
    )

    created, updated, skipped = DockerSyncer.sync_docker_proxy_hosts(
        client=client,  # type: ignore[arg-type]
        specs=[spec],
        takeownership=True,
    )

    assert (created, updated, skipped) == (1, 0, 0)
    assert client.deleted_ids == [100]
    assert len(client.created_payloads) == 1
    assert client.updated == []
