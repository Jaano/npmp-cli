from __future__ import annotations

from npmp_cli.filemanager import YmlFileManager


def test_proxy_host_json_to_compose_labels_yaml_required_fields() -> None:
    payload = {
        "domain_names": ["Example.COM", "www.example.com"],
        "forward_host": "app",
        "forward_port": 8080,
        "forward_scheme": "http",
        "ssl_forced": True,
    }

    yaml_text = YmlFileManager.proxy_host_json_to_compose_labels_yaml(payload, label_prefix="npmp.")
    assert yaml_text.startswith("labels:\n")
    assert "npmp.domain_names" in yaml_text
    assert 'npmp.domain_names: "example.com,www.example.com"' in yaml_text
    assert 'npmp.forward_host: "app"' in yaml_text
    assert 'npmp.forward_port: "8080"' in yaml_text
    assert 'npmp.forward_scheme: "http"' in yaml_text
    assert 'npmp.ssl_forced: "true"' in yaml_text


def test_proxy_host_json_to_compose_labels_yaml_multiline_advanced_config_uses_block_scalar() -> None:
    payload = {
        "domain_names": ["a.example"],
        "forward_host": "app",
        "forward_port": 80,
        "forward_scheme": "http",
        "advanced_config": "line1\nline2\n",
    }

    yaml_text = YmlFileManager.proxy_host_json_to_compose_labels_yaml(payload, label_prefix="npmp.")
    assert "npmp.advanced_config: |-" in yaml_text
    assert "    line1" in yaml_text
    assert "    line2" in yaml_text


def test_proxy_host_json_to_compose_labels_yaml_emits_locations() -> None:
    payload = {
        "domain_names": ["a.example"],
        "forward_host": "app",
        "forward_port": 80,
        "forward_scheme": "http",
        "locations": [
            {
                "path": "/api",
                "forward_host": "api",
                "forward_port": 9000,
                "allow_websocket_upgrade": True,
            },
            {
                "path": "/grpc",
                "forward_host": "grpc",
                "forward_port": 50051,
                "forward_scheme": "grpcs",
            },
        ],
    }

    yaml_text = YmlFileManager.proxy_host_json_to_compose_labels_yaml(payload, label_prefix="npmp.")
    assert 'npmp.loc1_path: "/api"' in yaml_text
    assert 'npmp.loc1_forward_host: "api"' in yaml_text
    assert 'npmp.loc1_forward_port: "9000"' in yaml_text
    assert 'npmp.loc1_forward_scheme: "http"' in yaml_text
    assert 'npmp.loc1_allow_websocket_upgrade: "true"' in yaml_text
    assert 'npmp.loc2_path: "/grpc"' in yaml_text
    assert 'npmp.loc2_forward_scheme: "grpcs"' in yaml_text
