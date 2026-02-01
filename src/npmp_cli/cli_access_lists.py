from __future__ import annotations

import typer

from . import utils
from .cli_common import (
    client_context,
    print_json,
    require_force_if_interactive,
    resolve_access_list,
)

access_list_app = typer.Typer(no_args_is_help=True)


@access_list_app.command("list")
def access_list_list(json_out: bool = typer.Option(False, "--json", help="Print JSON")) -> None:
    with client_context(readonly=True) as client:
        items = list(client.list_access_lists().values())
        items.sort(key=lambda x: int(getattr(x, "id", 0)))
        if json_out:
            print_json([x.to_json() for x in items])
            return
        for x in items:
            print(f"{x.id}\t{x.name}\t{int(bool(x.satisfy_any))}\t{int(bool(x.pass_auth))}")


@access_list_app.command("show")
def access_list_show(
    identifier: str = typer.Argument(..., help="Access list id or name"),
    json_out: bool = typer.Option(False, "--json", help="Print JSON"),
) -> None:
    with client_context(readonly=True) as client:
        item = resolve_access_list(client, identifier)
        if json_out:
            print_json(item.to_json())
            return
        print(f"id\t{item.id}")
        print(f"name\t{item.name}")
        print(f"satisfy_any\t{int(bool(item.satisfy_any))}")
        print(f"pass_auth\t{int(bool(item.pass_auth))}")
        print(f"clients\t{len(item.clients)}")
        print(f"items\t{len(item.items)}")


@access_list_app.command("create")
def access_list_create(
    name: str = typer.Option(..., "--name"),
    satisfy_any: bool = typer.Option(True, "--satisfy-any/--satisfy-all"),
    pass_auth: bool = typer.Option(False, "--pass-auth/--no-pass-auth"),
    allow: list[str] = typer.Option([], "--allow", help="Repeatable: IP or CIDR"),
    deny: list[str] = typer.Option([], "--deny", help="Repeatable: IP or CIDR"),
    auth_user: list[str] = typer.Option([], "--auth-user", help="Repeatable: USERNAME:PASSWORD"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    from .models import AccessListItem

    with client_context(readonly=dry_run) as client:
        if client.get_access_list_id(name.strip()) > 0:
            raise typer.BadParameter("access-list already exists; use update")

        item = AccessListItem(
            api=client,
            name=name,
            satisfy_any=satisfy_any,
            pass_auth=pass_auth,
            clients=utils.parse_access_list_clients(allow=allow, deny=deny),
            items=utils.parse_access_list_auth_items(auth_user=auth_user),
        )
        payload = item.to_payload()
        if dry_run:
            print_json({"action": "create", "kind": "access-list", "payload": payload})
            return
        res = client.create_access_list(payload)
        print_json(res)


@access_list_app.command("update")
def access_list_update(
    identifier: str = typer.Argument(..., help="Access list id or name"),
    name: str | None = typer.Option(None, "--name"),
    satisfy_any: bool | None = typer.Option(None, "--satisfy-any/--satisfy-all"),
    pass_auth: bool | None = typer.Option(None, "--pass-auth/--no-pass-auth"),
    allow: list[str] | None = typer.Option(None, "--allow", help="Repeatable: IP or CIDR"),
    deny: list[str] | None = typer.Option(None, "--deny", help="Repeatable: IP or CIDR"),
    auth_user: list[str] | None = typer.Option(None, "--auth-user", help="Repeatable: USERNAME:PASSWORD"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    from .models import AccessListItem

    with client_context(readonly=dry_run) as client:
        existing = resolve_access_list(client, identifier)
        list_id = int(existing.id)
        item = AccessListItem.from_json(client, existing.to_json())

        if name is not None:
            item.name = name
        if satisfy_any is not None:
            item.satisfy_any = satisfy_any
        if pass_auth is not None:
            item.pass_auth = pass_auth
        if allow is not None or deny is not None:
            item.clients = utils.parse_access_list_clients(allow=allow or [], deny=deny or [])
        if auth_user is not None:
            item.items = utils.parse_access_list_auth_items(auth_user=auth_user)

        payload = item.to_payload()
        if dry_run:
            print_json({"action": "update", "kind": "access-list", "id": list_id, "payload": payload})
            return
        res = client.update_access_list(list_id, payload)
        print_json(res)


@access_list_app.command("delete")
def access_list_delete(
    identifier: str = typer.Argument(..., help="Access list id or name"),
    force: bool = typer.Option(False, "--force"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    with client_context(readonly=dry_run) as client:
        item = resolve_access_list(client, identifier)
        list_id = int(item.id)
        require_force_if_interactive(force=force, prompt=f"Delete access-list {list_id} ({item.name})?")
        if dry_run:
            print_json({"action": "delete", "kind": "access-list", "id": list_id})
            return
        item.delete()
