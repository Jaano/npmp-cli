from __future__ import annotations

from typer.testing import CliRunner

from npmp_cli.cli import app


def test_cli_manual_command_groups_exist_via_help() -> None:
    runner = CliRunner()

    commands = [
        ["proxy-host", "list", "--help"],
        ["proxy-host", "show", "--help"],
        ["proxy-host", "create", "--help"],
        ["proxy-host", "update", "--help"],
        ["proxy-host", "delete", "--help"],
        ["proxy-host", "enable", "--help"],
        ["proxy-host", "disable", "--help"],
        ["dead-host", "list", "--help"],
        ["dead-host", "show", "--help"],
        ["dead-host", "create", "--help"],
        ["dead-host", "update", "--help"],
        ["dead-host", "delete", "--help"],
        ["dead-host", "enable", "--help"],
        ["dead-host", "disable", "--help"],
        ["redirect-host", "list", "--help"],
        ["redirect-host", "show", "--help"],
        ["redirect-host", "create", "--help"],
        ["redirect-host", "update", "--help"],
        ["redirect-host", "delete", "--help"],
        ["redirect-host", "enable", "--help"],
        ["redirect-host", "disable", "--help"],
        ["stream", "list", "--help"],
        ["stream", "show", "--help"],
        ["stream", "create", "--help"],
        ["stream", "update", "--help"],
        ["stream", "delete", "--help"],
        ["stream", "enable", "--help"],
        ["stream", "disable", "--help"],
        ["access-list", "list", "--help"],
        ["access-list", "show", "--help"],
        ["access-list", "create", "--help"],
        ["access-list", "update", "--help"],
        ["access-list", "delete", "--help"],
        ["certificate", "list", "--help"],
        ["certificate", "show", "--help"],
        ["certificate", "delete", "--help"],
        ["settings", "list", "--help"],
        ["settings", "show", "--help"],
    ]

    for argv in commands:
        result = runner.invoke(app, argv)
        assert result.exit_code == 0, f"{argv} failed: {result.output}"
