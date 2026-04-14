from __future__ import annotations

import os

import pytest

from npmp_cli.docker.scanner import scan_docker_specs
from npmp_cli.docker.sync_dead import sync_docker_dead_hosts
from npmp_cli.docker.sync_proxy import sync_docker_proxy_hosts
from npmp_cli.docker.sync_redirect import sync_docker_redirection_hosts
from npmp_cli.docker.sync_stream import sync_docker_streams
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
            f"{prefix}proxy.domain_names": domain,
            f"{prefix}proxy.forward_host": "example.com",
            f"{prefix}proxy.forward_port": "80",
            f"{prefix}proxy.forward_scheme": "http",
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

        proxy_specs, _, _, _ = scan_docker_specs()
        spec = next((s for s in proxy_specs if domain in (s.domain_names or [])), None)
        assert spec is not None

        sync_docker_proxy_hosts(client=npmplus_client, docker_specs=[spec])

        items = npmplus_client.list_proxy_hosts()
        found = None
        for item in items.values():
            if any(str(d).strip().lower() == domain.lower() for d in (item.domain_names or [])):
                found = item
                break
        assert found is not None
        created_id = int(found.id)
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


def test_sync_dead_hosts(require_docker: bool, npmplus_client: NPMplusClient, unique_suffix: str) -> None:
    try:
        import docker
    except Exception:
        pytest.skip("Python docker module not available")

    prefix = f"npmp-it-{unique_suffix}."
    domain = f"npmp-cli-docker-dead-it-{unique_suffix}.invalid"

    old_prefix = os.getenv("NPMP_DOCKER_LABEL_PREFIX")
    os.environ["NPMP_DOCKER_LABEL_PREFIX"] = prefix

    client = docker.from_env()
    container = None
    created_id: int | None = None
    try:
        labels = {
            f"{prefix}dead.domain_names": domain,
        }

        try:
            container = client.containers.run(
                "alpine:3.19",
                ["sh", "-c", "sleep 300"],
                detach=True,
                labels=labels,
                name=f"npmp-cli-dead-it-{unique_suffix}",
            )
        except Exception as e:
            pytest.skip(f"Failed to start docker container: {e}")

        _, dead_specs, _, _ = scan_docker_specs()
        spec = next((s for s in dead_specs if domain in (s.domain_names or [])), None)
        assert spec is not None

        sync_docker_dead_hosts(client=npmplus_client, docker_specs=[spec])

        items = npmplus_client.list_dead_hosts()
        found = next(
            (item for item in items.values() if any(str(d).strip().lower() == domain.lower() for d in (item.domain_names or []))),
            None,
        )
        assert found is not None
        created_id = int(found.id)
    finally:
        if created_id is not None:
            try:
                npmplus_client.delete_dead_host(created_id)
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


def test_sync_redirection_hosts(require_docker: bool, npmplus_client: NPMplusClient, unique_suffix: str) -> None:
    try:
        import docker
    except Exception:
        pytest.skip("Python docker module not available")

    prefix = f"npmp-it-{unique_suffix}."
    domain = f"npmp-cli-docker-redir-it-{unique_suffix}.invalid"

    old_prefix = os.getenv("NPMP_DOCKER_LABEL_PREFIX")
    os.environ["NPMP_DOCKER_LABEL_PREFIX"] = prefix

    client = docker.from_env()
    container = None
    created_id: int | None = None
    try:
        labels = {
            f"{prefix}redirect.domain_names": domain,
            f"{prefix}redirect.forward_domain_name": "example.com",
            f"{prefix}redirect.forward_http_code": "302",
            f"{prefix}redirect.forward_scheme": "http",
        }

        try:
            container = client.containers.run(
                "alpine:3.19",
                ["sh", "-c", "sleep 300"],
                detach=True,
                labels=labels,
                name=f"npmp-cli-redir-it-{unique_suffix}",
            )
        except Exception as e:
            pytest.skip(f"Failed to start docker container: {e}")

        _, _, redirect_specs, _ = scan_docker_specs()
        spec = next((s for s in redirect_specs if domain in (s.domain_names or [])), None)
        assert spec is not None

        sync_docker_redirection_hosts(client=npmplus_client, docker_specs=[spec])

        items = npmplus_client.list_redirection_hosts()
        found = next(
            (item for item in items.values() if any(str(d).strip().lower() == domain.lower() for d in (item.domain_names or []))),
            None,
        )
        assert found is not None
        created_id = int(found.id)
    finally:
        if created_id is not None:
            try:
                npmplus_client.delete_redirection_host(created_id)
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


def test_sync_streams(require_docker: bool, npmplus_client: NPMplusClient, unique_suffix: str) -> None:
    try:
        import docker
    except Exception:
        pytest.skip("Python docker module not available")

    prefix = f"npmp-it-{unique_suffix}."
    incoming_port = 33000 + (hash(unique_suffix) % 1000)

    old_prefix = os.getenv("NPMP_DOCKER_LABEL_PREFIX")
    os.environ["NPMP_DOCKER_LABEL_PREFIX"] = prefix

    client = docker.from_env()
    container = None
    created_id: int | None = None
    try:
        labels = {
            f"{prefix}stream.incoming_port": str(incoming_port),
            f"{prefix}stream.forwarding_host": "example.com",
            f"{prefix}stream.forwarding_port": "80",
            f"{prefix}stream.tcp_forwarding": "true",
        }

        try:
            container = client.containers.run(
                "alpine:3.19",
                ["sh", "-c", "sleep 300"],
                detach=True,
                labels=labels,
                name=f"npmp-cli-stream-it-{unique_suffix}",
            )
        except Exception as e:
            pytest.skip(f"Failed to start docker container: {e}")

        _, _, _, stream_specs = scan_docker_specs()
        spec = next((s for s in stream_specs if str(s.incoming_port) == str(incoming_port)), None)
        assert spec is not None

        sync_docker_streams(client=npmplus_client, docker_specs=[spec])

        items = npmplus_client.list_streams()
        found = next(
            (item for item in items.values() if int(item.incoming_port) == incoming_port),
            None,
        )
        assert found is not None
        created_id = int(found.id)
    finally:
        if created_id is not None:
            try:
                npmplus_client.delete_stream(created_id)
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

