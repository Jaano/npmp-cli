from __future__ import annotations

import glob
import os
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import typer

from .configmanager import ConfigManager
from .dockersyncer import DockerSyncer
from .jsonfilemanager import JsonFileManager, write_json_file
from .npmplus_client import NPMplusClient
from .ymlfilemanager import YmlFileManager

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
    expanded.sort(key=lambda p: (0 if "access-lists" in p.name else 1, p.name))
    return expanded


@contextmanager
def _client_context(*, readonly: bool = False) -> Generator[NPMplusClient, None, None]:
    """Create and authenticate NPMplusClient with consistent behavior across commands.

    All credentials (NPMP_BASE_URL, NPMP_TOKEN or NPMP_IDENTITY + NPMP_SECRET)
    are read from environment only.
    """
    base_url = ConfigManager.base_url()
    if not base_url:
        raise typer.BadParameter("NPMP_BASE_URL is required (set in environment or .env)")
    verify_tls = ConfigManager.verify_tls()
    try:
        retry_count = ConfigManager.http_retry_count()
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None

    with NPMplusClient(base_url=base_url, verify_tls=verify_tls, retry_count=retry_count, readonly=readonly) as client:
        token_env = ConfigManager.token()
        if token_env:
            client.set_token_cookie(token_env)
        else:
            identity_env = ConfigManager.identity()
            secret_env = ConfigManager.secret()
            if identity_env and secret_env:
                client.login(identity_env, secret_env)
            else:
                raise typer.BadParameter("Provide NPMP_TOKEN or both NPMP_IDENTITY and NPMP_SECRET in environment")
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
    log_console_stream: str = typer.Option(
        "stderr",
        "--log-console-stream",
        envvar="NPMP_LOG_CONSOLE_STREAM",
        help="Console log stream: stderr or stdout (default: stderr)",
        show_default=True,
    ),
    log_file: str | None = typer.Option(
        None,
        "--log-file",
        envvar="NPMP_LOG_FILE",
        help="Optional log file path. If you pass an existing directory or a path ending with '/', logs to <dir>/npmp-cli.log.",
        show_default=False,
    ),
    log_file_level: str | None = typer.Option(
        None,
        "--log-file-level",
        envvar="NPMP_LOG_FILE_LEVEL",
        help="Logging level for --log-file (defaults to --log-level)",
        show_default=False,
    ),
) -> None:
    try:
        ConfigManager.configure_logging(
            log_level,
            console_stream=log_console_stream,
            log_file=log_file,
            file_level=log_file_level,
        )
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None


@app.command("save")
def save(
    out: Path = typer.Option(Path("npmp-config"), "--out"),
) -> None:
    """Save NPMplus "sites" (hosts) as JSON files.

    Saves all host types: proxy-hosts, redirection-hosts, dead-hosts, streams, access-lists.
    """

    with _client_context() as client:
        try:
            JsonFileManager(client).save(out=out)
        except PermissionError as e:
            raise typer.Exit(code=2) from e
        except ValueError as e:
            raise typer.BadParameter(str(e)) from None

        logger.info("Done")


@app.command("audit-log")
def audit_log(
    out: Path = typer.Option(
        Path("audit.log"),
        "--out",
        "-o",
        help="Output file path (plain text; each record may span multiple lines)",
        show_default=True,
    ),
) -> None:
    """Export NPMplus audit log to a plain text file."""

    from datetime import datetime, timezone

    local_tz = datetime.now().astimezone().tzinfo

    def _format_created_on_local(value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            dt = value
        else:
            s = str(value).strip()
            if not s:
                return None
            try:
                if s.endswith("Z"):
                    s = s[:-1] + "+00:00"
                dt = datetime.fromisoformat(s)
            except Exception:
                return str(value).strip() or None

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt_local = dt.astimezone(local_tz)
        return dt_local.replace(microsecond=0).isoformat()

    def _format_event(ev: dict[str, object]) -> str:
        ts = _format_created_on_local(ev.get("created_on"))
        action = ev.get("action")
        object_type = ev.get("object_type")
        user_ev = ev.get("user")
        user = user_ev.get("nickname") if isinstance(user_ev, dict) else user_ev
        meta = ev.get("meta")
        header_parts: list[str] = []
        if ts is not None and str(ts).strip():
            header_parts.append(str(ts).strip())
        if action is not None and str(action).strip():
            header_parts.append(f"action={str(action).strip()}")
        if object_type is not None and str(object_type).strip():
            header_parts.append(f"type={str(object_type).strip()}")
        if user is not None:
            header_parts.append(f"user={user}")

        header = " ".join(header_parts).rstrip()

        meta_lines: list[str] = []
        if isinstance(meta, dict):
            for k in sorted(meta.keys()):
                meta_lines.append(f"  {k}={meta.get(k)!r}")
        elif meta is not None:
            meta_lines.append(f"  meta={meta!r}")

        if header or meta_lines:
            if meta_lines:
                return (header + "\n" + "\n".join(meta_lines)).rstrip()
            return header

        # Fallback: stable key=value format
        return " ".join(f"{k}={ev.get(k)!r}" for k in sorted(ev.keys()))

    with _client_context(readonly=True) as client:

        def _event_sort_key(ev: dict[str, object]) -> tuple[datetime, int]:
            ts = ev.get("created_on") or ev.get("created_at") or ev.get("createdAt") or ev.get("created")
            dt = datetime.min.replace(tzinfo=timezone.utc)
            if ts is not None:
                s = str(ts).strip()
                if s:
                    try:
                        if s.endswith("Z"):
                            s = s[:-1] + "+00:00"
                        dt = datetime.fromisoformat(s)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                    except Exception:
                        dt = datetime.min.replace(tzinfo=timezone.utc)

            raw_id = ev.get("id")
            try:
                event_id = int(str(raw_id).strip()) if raw_id is not None else -1
            except Exception:
                event_id = -1

            return dt, event_id

        events = [ev for ev in client.list_audit_log() if isinstance(ev, dict)]
        events.sort(key=_event_sort_key)
        out_path = out.expanduser()
        lines = [_format_event(ev) for ev in events]
        out_path.write_text(("\n".join(lines) + ("\n" if lines else "")), encoding="utf-8")
        logger.info("Saved audit log to %s", out_path)


@app.command("schema")
def schema(
    out: str = typer.Option(
        "schema.json",
        "--out",
        "-o",
        help="Output file path for schema JSON. Use '-' for stdout.",
        show_default=True,
    ),
) -> None:
    """Fetch `/api/schema` (OpenAPI) and write it as JSON."""
    with _client_context() as client:
        schema_json = client.get_schema()
        if (out or "").strip() == "-":
            import json

            print(json.dumps(schema_json, ensure_ascii=False, sort_keys=True, indent=2))
            return

        out_path = Path(out).expanduser()
        write_json_file(out_path, schema_json)
        logger.info("Saved schema to %s", out_path)


@app.command("load")
def load(
    files: list[str] = typer.Argument(
        ...,
        help="One or more saved JSON files, or glob patterns (e.g. 'npmp-config/proxy-hosts__*.json')",
    ),
    takeownership: bool = typer.Option(
        False,
        "--takeownership",
        help="If a matching record exists but is owned by a different user, delete it and create a new one owned by the current authenticated user",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview changes without modifying the NPMplus server",
    ),
) -> None:
    """Load one or more saved JSON files into NPMplus.

    Accepts explicit file paths or glob patterns. Each file is applied via POST/PUT.
    """
    input_files = _expand_input_files(files, require_suffix=".json")

    with _client_context(readonly=dry_run) as client:
        errors = 0
        for file in input_files:
            try:
                JsonFileManager(client).load(
                    file=file,
                    takeownership=takeownership,
                )
            except ValueError as e:
                errors += 1
                logger.error("Failed to load %s: %s", file, e)
            except Exception as e:
                errors += 1
                logger.error("Failed to load %s: %s", file, e)

        if errors:
            raise typer.Exit(code=2)


@app.command("sync-docker")
def sync_docker(
    takeownership: bool = typer.Option(
        False,
        "--takeownership",
        help="If a matching item exists but is owned by a different user, delete it and create a new one owned by the current authenticated user",
    ),
    disable_orphans: bool = typer.Option(
        False,
        "--disable-orphans",
        help="Disable (enabled=false) items owned by the current user that are not present in docker specs",
    ),
    delete_orphans: bool = typer.Option(
        False,
        "--delete-orphans",
        help="Delete items owned by the current user that are not present in docker specs",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview changes without modifying the NPMplus server",
    ),
) -> None:
    """Scan Docker containers for labels and sync proxy-hosts, dead-hosts, redirection-hosts, streams."""

    proxy_specs, dead_specs, redirect_specs, stream_specs = DockerSyncer.scan_docker_specs()
    total_specs = len(proxy_specs) + len(dead_specs) + len(redirect_specs) + len(stream_specs)

    if total_specs == 0 and not disable_orphans and not delete_orphans:
        logger.info("No docker containers found with required label prefix")
        return

    with _client_context(readonly=dry_run) as client:
        try:
            if proxy_specs or disable_orphans or delete_orphans:
                DockerSyncer.sync_docker_proxy_hosts(
                    client=client,
                    specs=proxy_specs,
                    takeownership=takeownership,
                    disable_orphans=disable_orphans,
                    delete_orphans=delete_orphans,
                )

            if dead_specs or disable_orphans or delete_orphans:
                DockerSyncer.sync_docker_dead_hosts(
                    client=client,
                    specs=dead_specs,
                    takeownership=takeownership,
                    disable_orphans=disable_orphans,
                    delete_orphans=delete_orphans,
                )

            if redirect_specs or disable_orphans or delete_orphans:
                DockerSyncer.sync_docker_redirection_hosts(
                    client=client,
                    specs=redirect_specs,
                    takeownership=takeownership,
                    disable_orphans=disable_orphans,
                    delete_orphans=delete_orphans,
                )

            if stream_specs or disable_orphans or delete_orphans:
                DockerSyncer.sync_docker_streams(
                    client=client,
                    specs=stream_specs,
                    takeownership=takeownership,
                    disable_orphans=disable_orphans,
                    delete_orphans=delete_orphans,
                )

        except ValueError as e:
            raise typer.BadParameter(str(e)) from None


@app.command("json-to-compose")
def json_to_compose(
    paths: list[str] = typer.Argument(
        ...,
        help="One or more saved JSON files (proxy-hosts, dead-hosts, redirection-hosts, streams), or glob patterns",
    ),
    service_name: str | None = typer.Option(
        None,
        "--service-name",
        help="Docker-compose service key to use (defaults to first domain label, e.g. 'app' from 'app.example.com')",
    ),
) -> None:
    """Convert saved JSON file(s) to docker-compose `labels:` YAML blocks.

    Auto-detects item type from filename pattern (proxy-hosts__*, dead-hosts__*, redirection-hosts__*, streams__*).
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
        name = input_file.name.lower()
        try:
            if "dead-hosts__" in name:
                out_path = YmlFileManager.write_dead_host_json_as_compose_labels_yaml(
                    input_file,
                    output_file,
                    service_name=service_name,
                )
            elif "redirection-hosts__" in name:
                out_path = YmlFileManager.write_redirection_host_json_as_compose_labels_yaml(
                    input_file,
                    output_file,
                    service_name=service_name,
                )
            elif "streams__" in name:
                out_path = YmlFileManager.write_stream_json_as_compose_labels_yaml(
                    input_file,
                    output_file,
                    service_name=service_name,
                )
            else:
                out_path = YmlFileManager.write_proxy_host_json_as_compose_labels_yaml(
                    input_file,
                    output_file,
                    service_name=service_name,
                )
            logger.info("Wrote %s", out_path)
        except ValueError as e:
            logger.warning("Skipping %s: %s", input_file.name, e)
