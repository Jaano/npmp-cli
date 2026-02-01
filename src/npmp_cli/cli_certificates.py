from __future__ import annotations

import typer

from .cli_common import (
    client_context,
    print_json,
    require_force_if_interactive,
    resolve_certificate,
)

certificate_app = typer.Typer(no_args_is_help=True)


@certificate_app.command("list")
def certificate_list(json_out: bool = typer.Option(False, "--json", help="Print JSON")) -> None:
    with client_context(readonly=True) as client:
        items = list(client.list_certificates().values())
        items.sort(key=lambda x: int(getattr(x, "id", 0)))
        if json_out:
            print_json([x.to_json() for x in items])
            return
        for x in items:
            domains = ",".join(getattr(x, "domain_names", []))
            print(f"{x.id}\t{x.nice_name}\t{domains}\t{getattr(x, 'provider', '')}")


@certificate_app.command("show")
def certificate_show(identifier: str = typer.Argument(..., help="Certificate id or nice_name")) -> None:
    with client_context(readonly=True) as client:
        item = resolve_certificate(client, identifier)
        print(f"id\t{item.id}")
        print(f"nice_name\t{item.nice_name}")
        print(f"provider\t{item.provider}")
        print(f"domain_names\t{','.join(item.domain_names)}")


@certificate_app.command("delete")
def certificate_delete(
    identifier: str = typer.Argument(..., help="Certificate id or nice_name"),
    force: bool = typer.Option(False, "--force"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    with client_context(readonly=dry_run) as client:
        item = resolve_certificate(client, identifier)
        cert_id = int(item.id)
        require_force_if_interactive(force=force, prompt=f"Delete certificate {cert_id} ({item.nice_name})?")
        if dry_run:
            print_json({"action": "delete", "kind": "certificate", "id": cert_id})
            return
        item.delete()
