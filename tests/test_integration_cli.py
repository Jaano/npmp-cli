from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from npmp_cli.cli import app
from npmp_cli.npmplus_client import NPMplusClient
from tests.conftest import find_item_by_domains

pytestmark = pytest.mark.integration


def test_schema_writes_file(npmplus_client: NPMplusClient) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(app, ["schema", "-o", "schema.json"])
        assert result.exit_code == 0, result.output

        p = Path("schema.json")
        assert p.exists()
        payload = json.loads(p.read_text(encoding="utf-8"))
        assert isinstance(payload, dict)
        assert "paths" in payload


def test_load_save_json_to_compose_roundtrip(npmplus_client: NPMplusClient, unique_invalid_domain: str) -> None:
    runner = CliRunner()

    domains = (unique_invalid_domain,)
    created_id: int | None = None

    with runner.isolated_filesystem():
        f = Path("proxy-hosts__it.json")
        f.write_text(
            json.dumps(
                {
                    "domain_names": list(domains),
                    "forward_host": "example.com",
                    "forward_port": 80,
                    "forward_scheme": "http",
                    "enabled": True,
                    "advanced_config": "set $host $http_host;\n",
                },
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            ),
            encoding="utf-8",
        )

        result = runner.invoke(app, ["load", str(f)])
        assert result.exit_code == 0, result.output

        found = find_item_by_domains(npmplus_client.list_proxy_hosts(), domains)
        assert found is not None
        created_id = int(str(found.get("id")).strip())

        out_dir = Path("out")
        result2 = runner.invoke(app, ["save", "--out", str(out_dir)])
        assert result2.exit_code == 0, result2.output

        saved = out_dir / f"proxy-hosts__{created_id}.json"
        assert saved.exists()

        compose_out = Path("labels.yml")
        result3 = runner.invoke(app, ["json-to-compose", str(saved), str(compose_out)])
        assert result3.exit_code == 0, result3.output
        assert compose_out.exists()
        yml = compose_out.read_text(encoding="utf-8")
        assert "services:" in yml
        assert "labels:" in yml
        assert "npmp.domain_names" in yml
        assert "npmp.forward_host" in yml
        assert "set $$host $$http_host;" in yml
        assert "set $host $http_host;" not in yml

        label_keys: list[str] = []
        for line in yml.splitlines():
            s = line.rstrip("\n")
            if not s.startswith("      "):
                continue
            if s.lstrip().startswith("#"):
                continue
            if ":" not in s:
                continue
            key = s.strip().split(":", 1)[0].strip()
            if key:
                label_keys.append(key)

        domain_key_label = next((k for k in label_keys if k.endswith("domain_names")), None)
        assert domain_key_label is not None
        prefix = domain_key_label[: -len("domain_names")]

        preferred_suffix_order = ["enabled", "domain_names", "forward_scheme", "forward_host", "forward_port"]
        seen_positions: list[int] = []
        for suffix in preferred_suffix_order:
            full_key = prefix + suffix
            if full_key in label_keys:
                seen_positions.append(label_keys.index(full_key))
        assert seen_positions == sorted(seen_positions)

    if created_id is not None:
        npmplus_client.delete_proxy_host(created_id)


def test_load_takeownership_does_not_recreate_when_same_owner(
    npmplus_client: NPMplusClient, unique_invalid_domain: str
) -> None:
    runner = CliRunner()

    domains = (unique_invalid_domain,)
    created_id: int | None = None
    updated_id: int | None = None

    with runner.isolated_filesystem():
        f = Path("proxy-hosts__it-takeownership.json")
        f.write_text(
            json.dumps(
                {
                    "domain_names": list(domains),
                    "forward_host": "example.com",
                    "forward_port": 80,
                    "forward_scheme": "http",
                    "enabled": True,
                },
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            ),
            encoding="utf-8",
        )

        r1 = runner.invoke(app, ["load", str(f)])
        assert r1.exit_code == 0, r1.output

        found1 = find_item_by_domains(npmplus_client.list_proxy_hosts(), domains)
        assert found1 is not None
        created_id = int(str(found1.get("id")).strip())

        f.write_text(
            json.dumps(
                {
                    "domain_names": list(domains),
                    "forward_host": "example.org",
                    "forward_port": 80,
                    "forward_scheme": "http",
                    "enabled": True,
                },
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            ),
            encoding="utf-8",
        )

        r2 = runner.invoke(app, ["load", "--takeownership", str(f)])
        assert r2.exit_code == 0, r2.output

        items2 = npmplus_client.list_proxy_hosts()
        found2 = find_item_by_domains(items2, domains)
        assert found2 is not None
        updated_id = int(str(found2.get("id")).strip())
        assert updated_id == created_id

        assert str(found2.get("forward_host") or found2.get("forwardHost") or "").strip() == "example.org"

    if updated_id is not None:
        npmplus_client.delete_proxy_host(updated_id)
