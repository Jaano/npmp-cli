from __future__ import annotations

import glob
import os
from contextlib import contextmanager
from pathlib import Path

import typer

from .configmanager import ConfigManager
from .docker_syncer import DockerSyncer
from .filemanager import JsonFileManager, YmlFileManager
from .npmplus_api import NPMplusApi

logger = ConfigManager.get_logger(__name__)

ConfigManager.load_dotenv_best_effort()

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=True,
    pretty_exceptions_show_locals=False,
    pretty_exceptions_short=True,
)


def _expand_input_files(values: list[str], *, require_suffix: str | None = None) -> list[Path]:
    """Expand CLI positional inputs.

    Supports passing explicit file paths or quoted glob patterns (e.g. 'npmp-config/*.json').
    """
    if not values:
        raise typer.BadParameter("Provide at least one input file")

    expanded: list[Path] = []
    seen: set[Path] = set()
    for raw in values:
        v = (raw or "").strip()
        if not v:
            continue
        v = os.path.expanduser(v)
        matches = glob.glob(v, recursive=True)
        if not matches:
            raise typer.BadParameter(f"No files matched: {raw}")
        for m in matches:
            p = Path(m)
            if not p.exists() or not p.is_file():
                continue
            if require_suffix is not None and p.suffix.lower() != require_suffix.lower():
                continue
            p = p.resolve()
            if p in seen:
                continue
            seen.add(p)
            expanded.append(p)

    if not expanded:
        suffix_msg = "" if require_suffix is None else f" (with {require_suffix} suffix)"
        raise typer.BadParameter(f"No valid files found{suffix_msg} for: {', '.join(values)}")
    return expanded


@contextmanager
def _client_context(
    *,
    identity: str | None,
):
    """Create and authenticate NPMplusApi with consistent behavior across commands.

    All credentials (NPMP_BASE_URL, NPMP_TOKEN or NPMP_IDENTITY + NPMP_SECRET)
    are read from environment only.
    """
    base_url = ConfigManager.base_url()
    if not base_url:
        raise typer.BadParameter("NPMP_BASE_URL is required (set in environment or .env)")
    verify_tls = ConfigManager.verify_tls()
    with NPMplusApi(base_url=base_url, verify_tls=verify_tls) as client:
        token_env = ConfigManager.token()
        if token_env:
            client.set_token_cookie(token_env)
        else:
            secret_env = ConfigManager.secret()
            if identity and secret_env:
                client.login(identity, secret_env)
            else:
                raise typer.BadParameter("Provide NPMP_TOKEN or both --identity and NPMP_SECRET in environment")
        yield client


@app.callback()
def _main(
    log_level: str = typer.Option(
        "INFO",
        "--log-level",
        envvar="NPMP_LOG_LEVEL",
        help="Logging level (DEBUG, INFO, WARNING, ERROR)",
        show_default=True,
    ),
) -> None:
    try:
        ConfigManager.configure_logging(log_level)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None


@app.command("save")
def save(
    identity: str | None = typer.Option(None, "--identity", envvar="NPMP_IDENTITY"),
    out: Path = typer.Option(Path("npmp-config"), "--out"),
    kind: str = typer.Option(
        "all",
        "--kind",
        help="Which NPMplus host type(s) to save",
        case_sensitive=False,
        show_default=True,
    ),
    query: str | None = typer.Option(None, "--query", help="Optional server-side search query"),
) -> None:
    """Save NPMplus “sites” (hosts) as JSON files.

    By default saves all host types: proxy-hosts, redirection-hosts, dead-hosts, streams.
    """

    with _client_context(identity=identity) as client:
        try:
            JsonFileManager(client).save(kind=kind, out=out, query=query)
        except PermissionError as e:
            raise typer.Exit(code=2) from e
        except ValueError as e:
            raise typer.BadParameter(str(e)) from None

        logger.info("Saved to %s", out)


@app.command("schema")
def schema(
    identity: str | None = typer.Option(None, "--identity", envvar="NPMP_IDENTITY"),
) -> None:
    """Fetch and print `/api/schema` (OpenAPI) as JSON."""
    with _client_context(identity=identity) as client:
        import json

        print(json.dumps(client.get_schema(), ensure_ascii=False, sort_keys=True, indent=2))


@app.command("load")
def load(
    files: list[str] = typer.Argument(
        ...,
        help="One or more saved JSON files, or glob patterns (e.g. 'npmp-config/proxy-hosts__*.json')",
    ),
    identity: str | None = typer.Option(None, "--identity", envvar="NPMP_IDENTITY"),
) -> None:
    """Load one or more saved JSON files into NPMplus.

    Accepts explicit file paths or glob patterns. Each file is applied via POST/PUT.
    """
    input_files = _expand_input_files(files, require_suffix=".json")

    with _client_context(identity=identity) as client:
        errors = 0
        for file in input_files:
            try:
                kind_name, resolved_mode, new_id = JsonFileManager(client).load(
                    file=file,
                )
            except ValueError as e:
                errors += 1
                raise typer.BadParameter(str(e)) from None
            except Exception:
                errors += 1
                raise typer.Exit(code=2) from None

            logger.info("Loaded %s (%s) id=%s from %s", kind_name, resolved_mode, new_id, file)

        if errors:
            raise typer.Exit(code=2)


@app.command("sync-docker")
def sync_docker(
    identity: str | None = typer.Option(None, "--identity", envvar="NPMP_IDENTITY"),
    disable_orphans: bool = typer.Option(
        False,
        "--disable-orphans",
        help="Disable (enabled=false) proxy-hosts owned by the current user that are not present in docker specs",
    ),
    delete_orphans: bool = typer.Option(
        False,
        "--delete-orphans",
        help="Delete proxy-hosts owned by the current user that are not present in docker specs",
    ),
    owner_user_id: int | None = typer.Option(
        None,
        "--owner-user-id",
        envvar="NPMP_OWNER_USER_ID",
        help="Override owner_user_id used for --disable-orphans and --delete-orphans (usually inferred automatically)",
    ),
) -> None:
    """Scan all Docker containers for labels with the configured prefix and upsert proxy-hosts."""

    specs = DockerSyncer.scan_docker_proxy_host_specs()
    if not specs and not disable_orphans and not delete_orphans:
        logger.info("No docker containers found with required label prefix")
        return

    with _client_context(identity=identity) as client:
        created, updated, skipped = DockerSyncer.sync_docker_proxy_hosts(
            client=client,
            specs=specs,
            disable_orphans=disable_orphans,
            delete_orphans=delete_orphans,
            owner_user_id=owner_user_id,
        )

    logger.info("Docker sync complete: created=%s updated=%s skipped=%s", created, updated, skipped)


@app.command("json-to-compose")
def json_to_compose(
    paths: list[str] = typer.Argument(
        ...,
        help="One or more saved proxy-host JSON files, or glob patterns (optionally append OUTPUT.yml for a single input)",
    ),
) -> None:
    """Convert saved proxy-host JSON file(s) to docker-compose `labels:` YAML blocks.

    Accepts explicit file paths or glob patterns. For multiple inputs, output is written next to each input.
    """
    output_file: Path | None = None
    inputs = paths
    if len(paths) >= 2 and paths[-1].lower().endswith((".yml", ".yaml")):
        if len(paths) != 2:
            raise typer.BadParameter("OUTPUT.yml can only be used when converting a single input file")
        output_file = Path(paths[-1])
        inputs = [paths[0]]

    input_files = _expand_input_files(inputs, require_suffix=".json")
    if output_file is not None and len(input_files) != 1:
        raise typer.BadParameter("OUTPUT.yml can only be used when converting a single input file")

    for input_file in input_files:
        try:
            out_path = YmlFileManager.write_proxy_host_json_as_compose_labels_yaml(
                input_file,
                output_file,
            )
        except ValueError as e:
            raise typer.BadParameter(str(e)) from None

        logger.info("Wrote %s", out_path)
