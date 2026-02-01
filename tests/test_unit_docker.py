from __future__ import annotations

from npmp_cli.docker.specs import DockerProxyHostSpec
from npmp_cli.docker.sync_proxy import sync_docker_proxy_hosts
from tests.test_configuration import StubNPMplusClient


def test_take_ownership_deletes_and_recreates() -> None:
    client = StubNPMplusClient()

    spec = DockerProxyHostSpec(
        domain_names=["example.invalid"],
        forward_host="new.example",
        forward_port=8080,
        forward_scheme="http",
    )

    sync_docker_proxy_hosts(
        client=client,  # type: ignore[arg-type]
        docker_specs=[spec],
        take_ownership=True,
    )

    assert client.deleted_ids == [100]
    assert len(client.created_payloads) == 1
    assert client.updated == []
