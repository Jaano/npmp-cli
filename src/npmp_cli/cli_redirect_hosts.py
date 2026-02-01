from __future__ import annotations

import typer

from . import utils
from .cli_common import (
    client_context,
    print_json,
    require_force_if_interactive,
    resolve_redirect_host,
    split_repeatable_csv,
)

redirect_host_app = typer.Typer(no_args_is_help=True)


@redirect_host_app.command("list")
def redirect_host_list(json_out: bool = typer.Option(False, "--json", help="Print JSON")) -> None:
    with client_context(readonly=True) as client:
        items = list(client.list_redirection_hosts().values())
        items.sort(key=lambda x: int(getattr(x, "id", 0)))
        if json_out:
            print_json([x.to_json() for x in items])
            return
        for x in items:
            domains = ",".join(getattr(x, "domain_names", []))
            forward = f"{getattr(x, 'forward_scheme', '')}://{getattr(x, 'forward_domain_name', '')} ({getattr(x, 'forward_http_code', '')})"
            print(f"{x.id}\t{int(bool(x.enabled))}\t{domains}\t{forward}")


@redirect_host_app.command("show")
def redirect_host_show(
    identifier: str = typer.Argument(..., help="Host id or domain"),
    json_out: bool = typer.Option(False, "--json", help="Print JSON"),
) -> None:
    with client_context(readonly=True) as client:
        item = resolve_redirect_host(client, identifier)
        if json_out:
            print_json(item.to_json())
            return
        print(f"id\t{item.id}")
        print(f"enabled\t{int(bool(item.enabled))}")
        print(f"domain_names\t{','.join(item.domain_names)}")
        print(f"forward\t{item.forward_scheme}://{item.forward_domain_name} ({item.forward_http_code})")
        print(f"preserve_path\t{int(bool(item.preserve_path))}")
        if item.certificate is not None:
            print(f"certificate\t{item.certificate}")


@redirect_host_app.command("create")
def redirect_host_create(
    domain_names: list[str] = typer.Option(..., "--domain-names", help="Domain names (repeatable or comma-separated)"),
    forward_scheme: str = typer.Option(..., "--forward-scheme"),
    forward_domain_name: str = typer.Option(..., "--forward-domain-name"),
    forward_http_code: int = typer.Option(..., "--forward-http-code"),
    preserve_path: bool = typer.Option(False, "--preserve-path/--no-preserve-path"),
    block_exploits: bool = typer.Option(False, "--block-exploits/--no-block-exploits"),
    certificate: str | None = typer.Option(None, "--certificate", help="Certificate nice_name (empty string clears)"),
    ssl_forced: bool = typer.Option(False, "--ssl-forced/--no-ssl-forced"),
    http2_support: bool = typer.Option(False, "--http2-support/--no-http2-support"),
    hsts_enabled: bool = typer.Option(False, "--hsts-enabled/--no-hsts-enabled"),
    hsts_subdomains: bool = typer.Option(False, "--hsts-subdomains/--no-hsts-subdomains"),
    advanced_config: str = typer.Option("", "--advanced-config"),
    enabled: bool = typer.Option(True, "--enabled/--disabled"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    from .models import RedirectionHostItem

    domains = [d.strip().lower() for d in split_repeatable_csv(domain_names) if d.strip()]
    with client_context(readonly=dry_run) as client:
        key = utils.domain_key(domains)
        natural = ",".join(key) if key else ""
        if client.get_redirection_host_id(natural) > 0:
            raise typer.BadParameter("redirect-host already exists for domain(s); use update")
        item = RedirectionHostItem(
            api=client,
            domain_names=domains,
            forward_scheme=forward_scheme,
            forward_domain_name=forward_domain_name,
            forward_http_code=forward_http_code,
            preserve_path=preserve_path,
            block_exploits=block_exploits,
            certificate=certificate,
            ssl_forced=ssl_forced,
            http2_support=http2_support,
            hsts_enabled=hsts_enabled,
            hsts_subdomains=hsts_subdomains,
            advanced_config=advanced_config,
            enabled=enabled,
        )
        payload = item.to_payload()
        if dry_run:
            print_json({"action": "create", "kind": "redirect-host", "payload": payload})
            return
        res = client.create_redirection_host(payload)
        print_json(res)


@redirect_host_app.command("update")
def redirect_host_update(
    identifier: str = typer.Argument(..., help="Host id or domain"),
    domain_names: list[str] | None = typer.Option(None, "--domain-names", help="Domain names (repeatable or comma-separated)"),
    forward_scheme: str | None = typer.Option(None, "--forward-scheme"),
    forward_domain_name: str | None = typer.Option(None, "--forward-domain-name"),
    forward_http_code: int | None = typer.Option(None, "--forward-http-code"),
    preserve_path: bool | None = typer.Option(None, "--preserve-path/--no-preserve-path"),
    block_exploits: bool | None = typer.Option(None, "--block-exploits/--no-block-exploits"),
    certificate: str | None = typer.Option(None, "--certificate", help="Certificate nice_name (empty string clears)"),
    ssl_forced: bool | None = typer.Option(None, "--ssl-forced/--no-ssl-forced"),
    http2_support: bool | None = typer.Option(None, "--http2-support/--no-http2-support"),
    hsts_enabled: bool | None = typer.Option(None, "--hsts-enabled/--no-hsts-enabled"),
    hsts_subdomains: bool | None = typer.Option(None, "--hsts-subdomains/--no-hsts-subdomains"),
    advanced_config: str | None = typer.Option(None, "--advanced-config"),
    enabled: bool | None = typer.Option(None, "--enabled/--disabled"),
    take_ownership: bool = typer.Option(False, "--take-ownership"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    from .models import RedirectionHostItem

    with client_context(readonly=dry_run) as client:
        existing = resolve_redirect_host(client, identifier)
        host_id = int(existing.id)
        item = RedirectionHostItem.from_json(client, existing.to_json())

        if domain_names is not None:
            item.domain_names = [d.strip().lower() for d in split_repeatable_csv(domain_names) if d.strip()]
        if forward_scheme is not None:
            item.forward_scheme = forward_scheme
        if forward_domain_name is not None:
            item.forward_domain_name = forward_domain_name
        if forward_http_code is not None:
            item.forward_http_code = forward_http_code
        if preserve_path is not None:
            item.preserve_path = preserve_path
        if block_exploits is not None:
            item.block_exploits = block_exploits
        if certificate is not None:
            item.certificate = certificate
        if ssl_forced is not None:
            item.ssl_forced = ssl_forced
        if http2_support is not None:
            item.http2_support = http2_support
        if hsts_enabled is not None:
            item.hsts_enabled = hsts_enabled
        if hsts_subdomains is not None:
            item.hsts_subdomains = hsts_subdomains
        if advanced_config is not None:
            item.advanced_config = advanced_config
        if enabled is not None:
            item.enabled = enabled

        payload = item.to_payload()
        if dry_run:
            print_json({"action": "update", "kind": "redirect-host", "id": host_id, "payload": payload, "take_ownership": take_ownership})
            return

        if take_ownership and existing.owner_user_id and existing.owner_user_id != client.my_id:
            client.delete_redirection_host(host_id)
            res = client.create_redirection_host(payload)
            print_json({"replaced": True, "result": res})
            return

        res = client.update_redirection_host(host_id, payload)
        print_json(res)


@redirect_host_app.command("delete")
def redirect_host_delete(
    identifier: str = typer.Argument(..., help="Host id or domain"),
    force: bool = typer.Option(False, "--force"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    with client_context(readonly=dry_run) as client:
        item = resolve_redirect_host(client, identifier)
        host_id = int(item.id)
        require_force_if_interactive(force=force, prompt=f"Delete redirect-host {host_id} ({','.join(item.domain_names)})?")
        if dry_run:
            print_json({"action": "delete", "kind": "redirect-host", "id": host_id})
            return
        item.delete()


@redirect_host_app.command("enable")
def redirect_host_enable(identifier: str = typer.Argument(..., help="Host id or domain")) -> None:
    with client_context() as client:
        item = resolve_redirect_host(client, identifier)
        client.enable_redirection_host(int(item.id))


@redirect_host_app.command("disable")
def redirect_host_disable(identifier: str = typer.Argument(..., help="Host id or domain")) -> None:
    with client_context() as client:
        item = resolve_redirect_host(client, identifier)
        client.disable_redirection_host(int(item.id))
