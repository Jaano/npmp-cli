from __future__ import annotations

import os

import pytest

from npmp_cli.dockersyncer import DockerSyncer
from npmp_cli.npmplus_client import NPMplusClient

pytestmark = pytest.mark.integration


def test_scan_and_sync(require_docker: bool, npmplus_client: NPMplusClient, unique_suffix: str) -> None:
    try:
        import docker
    except Exception:
        pytest.skip("Python docker module not available")

    prefix = f"npmp-it-{unique_suffix}."
    domain = f"npmp-cli-docker-it-{unique_suffix}.invalid"

    old_prefix = os.getenv("NPMP_DOCKER_LABEL_PREFIX")
    os.environ["NPMP_DOCKER_LABEL_PREFIX"] = prefix

    client = docker.from_env()
    container = None
    created_id: int | None = None
    try:
        labels = {
            f"{prefix}domain_names": domain,
            f"{prefix}forward_host": "example.com",
            f"{prefix}forward_port": "80",
            f"{prefix}forward_scheme": "http",
        }

        try:
            container = client.containers.run(
                "alpine:3.19",
                ["sh", "-c", "sleep 300"],
                detach=True,
                labels=labels,
                name=f"npmp-cli-it-{unique_suffix}",
            )
        except Exception as e:
            pytest.skip(f"Failed to start docker container: {e}")

        specs = DockerSyncer.scan_docker_proxy_host_specs()
        spec = next((s for s in specs if domain in (s.domain_names or [])), None)
        assert spec is not None

        DockerSyncer.sync_docker_proxy_hosts(client=npmplus_client, specs=[spec])

        items = npmplus_client.list_proxy_hosts()
        found = None
        for item in items.values():
            domains = item.get("domain_names") or item.get("domainNames")
            if isinstance(domains, list) and any(str(d).strip().lower() == domain.lower() for d in domains):
                found = item
                break
        assert found is not None
        created_id = int(str(found.get("id")).strip())
    finally:
        if created_id is not None:
            try:
                npmplus_client.delete_proxy_host(created_id)
            except Exception:
                pass
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                pass
        if old_prefix is None:
            os.environ.pop("NPMP_DOCKER_LABEL_PREFIX", None)
        else:
            os.environ["NPMP_DOCKER_LABEL_PREFIX"] = old_prefix
