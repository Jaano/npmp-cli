from __future__ import annotations

import typer

from .cli_common import (
    client_context,
    print_json,
    require_force_if_interactive,
    resolve_stream,
)

stream_app = typer.Typer(no_args_is_help=True)


@stream_app.command("list")
def stream_list(json_out: bool = typer.Option(False, "--json", help="Print JSON")) -> None:
    with client_context(readonly=True) as client:
        items = list(client.list_streams().values())
        items.sort(key=lambda x: int(getattr(x, "id", 0)))
        if json_out:
            print_json([x.to_json() for x in items])
            return
        for x in items:
            proto = []
            if getattr(x, "tcp_forwarding", False):
                proto.append("tcp")
            if getattr(x, "udp_forwarding", False):
                proto.append("udp")
            p = "+".join(proto) if proto else ""
            forward = f"{getattr(x, 'forwarding_host', '')}:{getattr(x, 'forwarding_port', '')}"
            print(f"{x.id}\t{int(bool(x.enabled))}\t{getattr(x, 'incoming_port', '')}\t{p}\t{forward}")


@stream_app.command("show")
def stream_show(
    identifier: str = typer.Argument(..., help="Stream id or incoming port"),
    json_out: bool = typer.Option(False, "--json", help="Print JSON"),
) -> None:
    with client_context(readonly=True) as client:
        item = resolve_stream(client, identifier)
        if json_out:
            print_json(item.to_json())
            return
        print(f"id\t{item.id}")
        print(f"enabled\t{int(bool(item.enabled))}")
        print(f"incoming_port\t{item.incoming_port}")
        print(f"forward\t{item.forwarding_host}:{item.forwarding_port}")
        print(f"tcp_forwarding\t{int(bool(item.tcp_forwarding))}")
        print(f"udp_forwarding\t{int(bool(item.udp_forwarding))}")
        if item.certificate is not None:
            print(f"certificate\t{item.certificate}")


@stream_app.command("create")
def stream_create(
    incoming_port: int = typer.Option(..., "--incoming-port"),
    forwarding_host: str = typer.Option(..., "--forwarding-host"),
    forwarding_port: int = typer.Option(..., "--forwarding-port"),
    tcp_forwarding: bool = typer.Option(False, "--tcp-forwarding/--no-tcp-forwarding"),
    udp_forwarding: bool = typer.Option(False, "--udp-forwarding/--no-udp-forwarding"),
    proxy_protocol_forwarding: bool = typer.Option(False, "--proxy-protocol-forwarding/--no-proxy-protocol-forwarding"),
    certificate: str | None = typer.Option(None, "--certificate", help="Certificate nice_name (empty string clears)"),
    enabled: bool = typer.Option(True, "--enabled/--disabled"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    from .models import StreamItem

    with client_context(readonly=dry_run) as client:
        natural = str(int(incoming_port))
        if client.get_stream_id(natural) > 0:
            raise typer.BadParameter("stream already exists for incoming_port; use update")

        item = StreamItem(
            api=client,
            incoming_port=incoming_port,
            forwarding_host=forwarding_host,
            forwarding_port=forwarding_port,
        )
        item.tcp_forwarding = tcp_forwarding
        item.udp_forwarding = udp_forwarding
        item.proxy_protocol_forwarding = proxy_protocol_forwarding
        item.certificate = certificate
        item.enabled = enabled

        payload = item.to_payload()
        if dry_run:
            print_json({"action": "create", "kind": "stream", "payload": payload})
            return
        res = client.create_stream(payload)
        print_json(res)


@stream_app.command("update")
def stream_update(
    identifier: str = typer.Argument(..., help="Stream id or incoming port"),
    incoming_port: int | None = typer.Option(None, "--incoming-port"),
    forwarding_host: str | None = typer.Option(None, "--forwarding-host"),
    forwarding_port: int | None = typer.Option(None, "--forwarding-port"),
    tcp_forwarding: bool | None = typer.Option(None, "--tcp-forwarding/--no-tcp-forwarding"),
    udp_forwarding: bool | None = typer.Option(None, "--udp-forwarding/--no-udp-forwarding"),
    proxy_protocol_forwarding: bool | None = typer.Option(None, "--proxy-protocol-forwarding/--no-proxy-protocol-forwarding"),
    certificate: str | None = typer.Option(None, "--certificate", help="Certificate nice_name (empty string clears)"),
    enabled: bool | None = typer.Option(None, "--enabled/--disabled"),
    take_ownership: bool = typer.Option(False, "--take-ownership"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    from .models import StreamItem

    with client_context(readonly=dry_run) as client:
        existing = resolve_stream(client, identifier)
        stream_id = int(existing.id)
        item = StreamItem.from_json(client, existing.to_json())

        if incoming_port is not None:
            item.incoming_port = incoming_port
        if forwarding_host is not None:
            item.forwarding_host = forwarding_host
        if forwarding_port is not None:
            item.forwarding_port = forwarding_port
        if tcp_forwarding is not None:
            item.tcp_forwarding = tcp_forwarding
        if udp_forwarding is not None:
            item.udp_forwarding = udp_forwarding
        if proxy_protocol_forwarding is not None:
            item.proxy_protocol_forwarding = proxy_protocol_forwarding
        if certificate is not None:
            item.certificate = certificate
        if enabled is not None:
            item.enabled = enabled

        payload = item.to_payload()
        if dry_run:
            print_json({"action": "update", "kind": "stream", "id": stream_id, "payload": payload, "take_ownership": take_ownership})
            return

        if take_ownership and existing.owner_user_id and existing.owner_user_id != client.my_id:
            client.delete_stream(stream_id)
            res = client.create_stream(payload)
            print_json({"replaced": True, "result": res})
            return

        res = client.update_stream(stream_id, payload)
        print_json(res)


@stream_app.command("delete")
def stream_delete(
    identifier: str = typer.Argument(..., help="Stream id or incoming port"),
    force: bool = typer.Option(False, "--force"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    with client_context(readonly=dry_run) as client:
        item = resolve_stream(client, identifier)
        stream_id = int(item.id)
        require_force_if_interactive(force=force, prompt=f"Delete stream {stream_id} (incoming_port={item.incoming_port})?")
        if dry_run:
            print_json({"action": "delete", "kind": "stream", "id": stream_id})
            return
        item.delete()


@stream_app.command("enable")
def stream_enable(identifier: str = typer.Argument(..., help="Stream id or incoming port")) -> None:
    with client_context() as client:
        item = resolve_stream(client, identifier)
        client.enable_stream(int(item.id))


@stream_app.command("disable")
def stream_disable(identifier: str = typer.Argument(..., help="Stream id or incoming port")) -> None:
    with client_context() as client:
        item = resolve_stream(client, identifier)
        client.disable_stream(int(item.id))
