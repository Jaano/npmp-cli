from __future__ import annotations

from npmp_cli.docker_syncer import DockerSyncer


def test_extract_proxy_host_spec_from_labels_requires_all_fields() -> None:
    labels = {
        "npmp.domain_names": "example.com",
        "npmp.forward_host": "app",
        # missing forward_port
        "npmp.forward_scheme": "http",
    }
    assert (
        DockerSyncer.extract_proxy_host_spec_from_labels(
            labels=labels,
            container_id="abc",
            container_name="/c",
        )
        is None
    )


def test_extract_proxy_host_spec_from_labels_parses_values() -> None:
    labels = {
        "npmp.domain_names": "xyz.com, zzx.com ",
        "npmp.forward_host": "my-service",
        "npmp.forward_port": "8080",
        "npmp.forward_scheme": "http",
    }
    spec = DockerSyncer.extract_proxy_host_spec_from_labels(labels=labels, container_id="abc", container_name="/my")
    assert spec is not None
    assert spec.container_name == "my"
    assert spec.domain_names == ["xyz.com", "zzx.com"]
    assert spec.forward_host == "my-service"
    assert spec.forward_port == 8080
    assert spec.forward_scheme == "http"


def test_extract_proxy_host_spec_from_labels_parses_optional_fields() -> None:
    labels = {
        "npmp.domain_names": "xyz.com",
        "npmp.forward_host": "my-service",
        "npmp.forward_port": "8080",
        "npmp.forward_scheme": "http",
        "npmp.access_list": "LAN",
        "npmp.advanced_config": "",
        "npmp.allow_websocket_upgrade": "true",
        "npmp.block_exploits": "false",
        "npmp.caching_enabled": "0",
        "npmp.certificate": "*.example.com,example.com",
        "npmp.enabled": "false",
        "npmp.hsts_enabled": "false",
        "npmp.hsts_subdomains": "false",
        "npmp.http2_support": "true",
        "npmp.ssl_forced": "false",
    }
    spec = DockerSyncer.extract_proxy_host_spec_from_labels(labels=labels, container_id="abc", container_name="/my")
    assert spec is not None
    assert spec.access_list == "LAN"
    assert spec.advanced_config == ""
    assert spec.allow_websocket_upgrade is True
    assert spec.block_exploits is False
    assert spec.caching_enabled is False
    assert spec.certificate_domains == ["*.example.com", "example.com"]
    assert spec.enabled is False
    assert spec.hsts_enabled is False
    assert spec.hsts_subdomains is False
    assert spec.http2_support is True
    assert spec.ssl_forced is False


def test_extract_proxy_host_spec_from_labels_parses_locations() -> None:
    labels = {
        "npmp.domain_names": "xyz.com",
        "npmp.forward_host": "my-service",
        "npmp.forward_port": "8080",
        "npmp.forward_scheme": "http",
        "npmp.loc1_path": "/api",
        "npmp.loc1_forward_host": "api-service",
        "npmp.loc1_forward_port": "9000",
        # forward_scheme omitted on purpose -> should fall back to host scheme
        "npmp.loc2_path": "/grpc",
        "npmp.loc2_forward_host": "grpc-service",
        "npmp.loc2_forward_port": "50051",
        "npmp.loc2_forward_scheme": "grpcs",
        "npmp.loc2_allow_websocket_upgrade": "true",
    }
    spec = DockerSyncer.extract_proxy_host_spec_from_labels(labels=labels, container_id="abc", container_name="/my")
    assert spec is not None
    assert len(spec.locations) == 2
    assert spec.locations[0].path == "/api"
    assert spec.locations[0].forward_host == "api-service"
    assert spec.locations[0].forward_port == 9000
    assert spec.locations[0].forward_scheme == "http"
    assert spec.locations[1].path == "/grpc"
    assert spec.locations[1].forward_scheme == "grpcs"
    assert spec.locations[1].allow_websocket_upgrade is True


def test_extract_proxy_host_specs_from_inspect() -> None:
    inspect = [
        {
            "Id": "abc",
            "Name": "/my",
            "Config": {
                "Labels": {
                    "npmp.domain_names": "a.example",
                    "npmp.forward_host": "a",
                    "npmp.forward_port": "80",
                    "npmp.forward_scheme": "http",
                }
            },
        },
        {
            "Id": "def",
            "Name": "/other",
            "Config": {"Labels": {"something": "else"}},
        },
    ]
    specs = DockerSyncer.extract_proxy_host_specs_from_inspect(inspect)
    assert len(specs) == 1
    assert specs[0].container_id == "abc"
    assert specs[0].domain_names == ["a.example"]
