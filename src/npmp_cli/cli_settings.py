from __future__ import annotations

import typer

from .cli_common import client_context, print_json

settings_app = typer.Typer(no_args_is_help=True)


@settings_app.command("list")
def settings_list(json_out: bool = typer.Option(False, "--json", help="Print JSON")) -> None:
    with client_context(readonly=True) as client:
        settings = client.list_settings()
        if json_out:
            print_json(settings)
            return
        if isinstance(settings, list):
            for s in settings:
                if not isinstance(s, dict):
                    print(str(s))
                    continue
                sid = str(s.get("id") or s.get("key") or "").strip()
                name = str(s.get("name") or "").strip()
                value = s.get("value")
                print(f"{sid}\t{name}\t{value}")
            return
        if isinstance(settings, dict):
            for k in sorted(settings.keys()):
                print(f"{k}\t{settings.get(k)}")
            return
        print(str(settings))


@settings_app.command("show")
def settings_show(setting_id: str = typer.Argument(..., help="Setting id")) -> None:
    with client_context(readonly=True) as client:
        payload = client.get_setting(setting_id)
        print_json(payload)
