from __future__ import annotations

import typer

from . import utils
from .cli_common import (
    client_context,
    print_json,
    require_force_if_interactive,
    resolve_proxy_host,
    split_repeatable_csv,
)

proxy_host_app = typer.Typer(no_args_is_help=True)


@proxy_host_app.command("list")
def proxy_host_list(
    json_out: bool = typer.Option(False, "--json", help="Print JSON"),
) -> None:
    with client_context(readonly=True) as client:
        items = list(client.list_proxy_hosts().values())
        items.sort(key=lambda x: int(getattr(x, "id", 0)))
        if json_out:
            print_json([x.to_json() for x in items])
            return
        for x in items:
            domains = ",".join(getattr(x, "domain_names", []))
            forward = f"{getattr(x, 'forward_scheme', '')}://{getattr(x, 'forward_host', '')}:{getattr(x, 'forward_port', '')}"
            print(f"{x.id}\t{int(bool(x.enabled))}\t{domains}\t{forward}")


@proxy_host_app.command("show")
def proxy_host_show(
    identifier: str = typer.Argument(..., help="Host id or domain"),
    json_out: bool = typer.Option(False, "--json", help="Print JSON"),
) -> None:
    with client_context(readonly=True) as client:
        item = resolve_proxy_host(client, identifier)
        if json_out:
            print_json(item.to_json())
            return
        print(f"id\t{item.id}")
        print(f"enabled\t{int(bool(item.enabled))}")
        print(f"domain_names\t{','.join(item.domain_names)}")
        print(f"forward\t{item.forward_scheme}://{item.forward_host}:{item.forward_port}")
        if item.access_list is not None:
            print(f"access_list\t{item.access_list}")
        if item.certificate is not None:
            print(f"certificate\t{item.certificate}")


@proxy_host_app.command("create")
def proxy_host_create(
    domain_names: list[str] = typer.Option(..., "--domain-names", help="Domain names (repeatable or comma-separated)"),
    forward_scheme: str = typer.Option(..., "--forward-scheme"),
    forward_host: str = typer.Option(..., "--forward-host"),
    forward_port: int = typer.Option(..., "--forward-port"),
    access_list: str | None = typer.Option(None, "--access-list", help="Access list name (empty string clears)"),
    certificate: str | None = typer.Option(None, "--certificate", help="Certificate nice_name (empty string clears)"),
    ssl_forced: bool = typer.Option(False, "--ssl-forced/--no-ssl-forced"),
    caching_enabled: bool = typer.Option(False, "--caching-enabled/--no-caching-enabled"),
    block_exploits: bool = typer.Option(False, "--block-exploits/--no-block-exploits"),
    allow_websocket_upgrade: bool = typer.Option(False, "--allow-websocket-upgrade/--no-allow-websocket-upgrade"),
    http2_support: bool = typer.Option(False, "--http2-support/--no-http2-support"),
    hsts_enabled: bool = typer.Option(False, "--hsts-enabled/--no-hsts-enabled"),
    hsts_subdomains: bool = typer.Option(False, "--hsts-subdomains/--no-hsts-subdomains"),
    advanced_config: str = typer.Option("", "--advanced-config"),
    location: list[str] = typer.Option([], "--location", help="Repeatable: path:scheme:host:port"),
    enabled: bool = typer.Option(True, "--enabled/--disabled"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    domains = [d.strip().lower() for d in split_repeatable_csv(domain_names) if d.strip()]
    locations = [utils.parse_location(x) for x in location]
    with client_context(readonly=dry_run) as client:
        key = utils.domain_key(domains)
        natural = ",".join(key) if key else ""
        if client.get_proxy_host_id(natural) > 0:
            raise typer.BadParameter("proxy-host already exists for domain(s); use update")

        from .models import ProxyHostItem

        proxy = ProxyHostItem(
            api=client,
            domain_names=domains,
            forward_scheme=forward_scheme,
            forward_host=forward_host,
            forward_port=forward_port,
            enabled=enabled,
            access_list=access_list,
            certificate=certificate,
            ssl_forced=ssl_forced,
            caching_enabled=caching_enabled,
            block_exploits=block_exploits,
            allow_websocket_upgrade=allow_websocket_upgrade,
            http2_support=http2_support,
            hsts_enabled=hsts_enabled,
            hsts_subdomains=hsts_subdomains,
            advanced_config=advanced_config,
            locations=locations,
        )
        payload = proxy.to_payload()
        if dry_run:
            print_json({"action": "create", "kind": "proxy-host", "payload": payload})
            return
        res = client.create_proxy_host(payload)
        print_json(res)


@proxy_host_app.command("update")
def proxy_host_update(
    identifier: str = typer.Argument(..., help="Host id or domain"),
    domain_names: list[str] | None = typer.Option(None, "--domain-names", help="Domain names (repeatable or comma-separated)"),
    forward_scheme: str | None = typer.Option(None, "--forward-scheme"),
    forward_host: str | None = typer.Option(None, "--forward-host"),
    forward_port: int | None = typer.Option(None, "--forward-port"),
    access_list: str | None = typer.Option(None, "--access-list", help="Access list name (empty string clears)"),
    certificate: str | None = typer.Option(None, "--certificate", help="Certificate nice_name (empty string clears)"),
    ssl_forced: bool | None = typer.Option(None, "--ssl-forced/--no-ssl-forced"),
    caching_enabled: bool | None = typer.Option(None, "--caching-enabled/--no-caching-enabled"),
    block_exploits: bool | None = typer.Option(None, "--block-exploits/--no-block-exploits"),
    allow_websocket_upgrade: bool | None = typer.Option(None, "--allow-websocket-upgrade/--no-allow-websocket-upgrade"),
    http2_support: bool | None = typer.Option(None, "--http2-support/--no-http2-support"),
    hsts_enabled: bool | None = typer.Option(None, "--hsts-enabled/--no-hsts-enabled"),
    hsts_subdomains: bool | None = typer.Option(None, "--hsts-subdomains/--no-hsts-subdomains"),
    advanced_config: str | None = typer.Option(None, "--advanced-config"),
    location: list[str] | None = typer.Option(None, "--location", help="Repeatable: path:scheme:host:port (replaces locations)"),
    enabled: bool | None = typer.Option(None, "--enabled/--disabled"),
    take_ownership: bool = typer.Option(False, "--take-ownership"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    from .models import ProxyHostItem

    with client_context(readonly=dry_run) as client:
        existing = resolve_proxy_host(client, identifier)
        host_id = int(existing.id)

        proxy = ProxyHostItem.from_json(client, existing.to_json())

        if domain_names is not None:
            proxy.domain_names = [d.strip().lower() for d in split_repeatable_csv(domain_names) if d.strip()]
        if forward_scheme is not None:
            proxy.forward_scheme = forward_scheme
        if forward_host is not None:
            proxy.forward_host = forward_host
        if forward_port is not None:
            proxy.forward_port = forward_port
        if access_list is not None:
            proxy.access_list = access_list
        if certificate is not None:
            proxy.certificate = certificate
        if ssl_forced is not None:
            proxy.ssl_forced = ssl_forced
        if caching_enabled is not None:
            proxy.caching_enabled = caching_enabled
        if block_exploits is not None:
            proxy.block_exploits = block_exploits
        if allow_websocket_upgrade is not None:
            proxy.allow_websocket_upgrade = allow_websocket_upgrade
        if http2_support is not None:
            proxy.http2_support = http2_support
        if hsts_enabled is not None:
            proxy.hsts_enabled = hsts_enabled
        if hsts_subdomains is not None:
            proxy.hsts_subdomains = hsts_subdomains
        if advanced_config is not None:
            proxy.advanced_config = advanced_config
        if location is not None:
            proxy.locations = [utils.parse_location(x) for x in location]
        if enabled is not None:
            proxy.enabled = enabled

        payload = proxy.to_payload()

        if dry_run:
            print_json({"action": "update", "kind": "proxy-host", "id": host_id, "payload": payload, "take_ownership": take_ownership})
            return

        if take_ownership and existing.owner_user_id and existing.owner_user_id != client.my_id:
            client.delete_proxy_host(host_id)
            res = client.create_proxy_host(payload)
            print_json({"replaced": True, "result": res})
            return

        res = client.update_proxy_host(host_id, payload)
        print_json(res)


@proxy_host_app.command("delete")
def proxy_host_delete(
    identifier: str = typer.Argument(..., help="Host id or domain"),
    force: bool = typer.Option(False, "--force"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    with client_context(readonly=dry_run) as client:
        item = resolve_proxy_host(client, identifier)
        host_id = int(item.id)
        require_force_if_interactive(force=force, prompt=f"Delete proxy-host {host_id} ({','.join(item.domain_names)})?")
        if dry_run:
            print_json({"action": "delete", "kind": "proxy-host", "id": host_id})
            return
        item.delete()


@proxy_host_app.command("enable")
def proxy_host_enable(identifier: str = typer.Argument(..., help="Host id or domain")) -> None:
    with client_context() as client:
        item = resolve_proxy_host(client, identifier)
        client.enable_proxy_host(int(item.id))


@proxy_host_app.command("disable")
def proxy_host_disable(identifier: str = typer.Argument(..., help="Host id or domain")) -> None:
    with client_context() as client:
        item = resolve_proxy_host(client, identifier)
        client.disable_proxy_host(int(item.id))
