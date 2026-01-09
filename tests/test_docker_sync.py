from __future__ import annotations

from npmp_cli.docker_syncer import find_orphan_proxy_hosts, index_proxy_hosts_by_domains


def test_index_proxy_hosts_by_domains_matches_snake_case() -> None:
    items = [
        {"id": 1, "domain_names": ["B.EXAMPLE", "a.example"]},
        {"id": 2, "domain_names": ["other.example"]},
    ]
    idx = index_proxy_hosts_by_domains(items)
    assert idx[("a.example", "b.example")]["id"] == 1
    assert idx[("other.example",)]["id"] == 2


def test_find_orphan_proxy_hosts_filters_by_owner_and_domains() -> None:
    existing = [
        {"id": 1, "owner_user_id": 10, "domain_names": ["a.example"], "enabled": True},
        {"id": 2, "owner_user_id": 10, "domain_names": ["b.example"], "enabled": True},
        {"id": 3, "owner_user_id": 99, "domain_names": ["c.example"], "enabled": True},
    ]
    managed = {("a.example",)}
    orphans = find_orphan_proxy_hosts(existing_items=existing, managed_domain_keys=managed, owner_user_id=10)
    assert [o["id"] for o in orphans] == [2]
