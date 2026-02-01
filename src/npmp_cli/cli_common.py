from __future__ import annotations

import glob
import os
import shlex
from collections.abc import Callable, Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, TypeVar

import typer

from .configmanager import ConfigManager
from .npmplus_client import NPMplusClient


def load_config_callback(value: str) -> str:
    """Eager callback to load env file before other options are processed."""
    ConfigManager.load_dotenv(value)
    return value


def format_cli_invocation_for_log(ctx: typer.Context) -> str:
    info_name = (ctx.info_name or ctx.command_path or "npmp-cli").strip()
    args = [a for a in (ctx.args or []) if a]

    # Avoid accidentally logging sensitive values if such flags are added later.
    redacted_next = False
    redacted_args: list[str] = []
    for a in args:
        if redacted_next:
            redacted_args.append("<redacted>")
            redacted_next = False
            continue

        lowered = a.lower()
        if lowered in {"--secret", "--password", "--token", "--api-key", "--apikey"}:
            redacted_args.append(a)
            redacted_next = True
            continue
        if any(k in lowered for k in ("secret=", "password=", "token=", "api-key=", "apikey=")):
            key = a.split("=", 1)[0]
            redacted_args.append(f"{key}=<redacted>")
            continue

        redacted_args.append(a)

    parts = [info_name, *redacted_args]
    return shlex.join(parts)


def print_json(value: Any) -> None:
    import json

    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def split_repeatable_csv(values: list[str] | None) -> list[str]:
    if not values:
        return []
    out: list[str] = []
    for raw in values:
        s = str(raw or "").strip()
        if not s:
            continue
        if "," in s:
            out.extend([p.strip() for p in s.split(",") if p.strip()])
        else:
            out.append(s)
    return out


def resolve_int_identifier(identifier: str) -> int | None:
    s = str(identifier or "").strip()
    if not s:
        return None
    if s.isdigit():
        try:
            return int(s)
        except Exception:
            return None
    return None


TItem = TypeVar("TItem")


def find_unique(items: dict[int, TItem], *, predicate: Callable[[TItem], bool], kind: str, identifier: str) -> TItem:
    matches = [item for item in items.values() if predicate(item)]
    if not matches:
        raise typer.BadParameter(f"Unknown {kind}: {identifier}")
    if len(matches) > 1:
        raise typer.BadParameter(f"Ambiguous {kind} identifier (matched {len(matches)}): {identifier}")
    return matches[0]


def require_force_if_interactive(*, force: bool, prompt: str) -> None:
    if force:
        return
    if not typer.confirm(prompt, default=False):
        raise typer.Exit(code=1)


def expand_input_files(values: list[str], *, require_suffix: str | None = None) -> list[Path]:
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
def client_context(*, readonly: bool = False) -> Generator[NPMplusClient, None, None]:
    """Create and authenticate NPMplusClient with consistent behavior across commands."""
    base_url = ConfigManager.base_url()
    if not base_url:
        raise typer.BadParameter("NPMP_BASE_URL is required (set in environment or .env)")
    verify_tls = ConfigManager.verify_tls()
    try:
        retry_count = ConfigManager.http_retry_count()
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None

    with NPMplusClient(base_url=base_url, verify_tls=verify_tls, retry_count=retry_count, readonly=readonly) as client:
        identity_env = ConfigManager.identity()
        secret_env = ConfigManager.secret()
        if identity_env and secret_env:
            client.login(identity_env, secret_env)
        else:
            raise typer.BadParameter("Provide NPMP_IDENTITY and NPMP_SECRET in environment")
        yield client


def resolve_proxy_host(client: NPMplusClient, identifier: str):
    host_id = resolve_int_identifier(identifier)
    items = client.list_proxy_hosts()
    if host_id is not None:
        found = items.get(host_id)
        if found is None:
            raise typer.BadParameter(f"Unknown proxy-host id: {identifier}")
        return found

    needle = str(identifier or "").strip().lower()
    if not needle:
        raise typer.BadParameter("IDENTIFIER is required")

    def _match(item) -> bool:
        domains = [str(d).strip().lower() for d in getattr(item, "domain_names", [])]
        return needle in domains or needle == getattr(item, "natural_index", "").strip().lower()

    return find_unique(items, predicate=_match, kind="proxy-host", identifier=identifier)


def resolve_dead_host(client: NPMplusClient, identifier: str):
    host_id = resolve_int_identifier(identifier)
    items = client.list_dead_hosts()
    if host_id is not None:
        found = items.get(host_id)
        if found is None:
            raise typer.BadParameter(f"Unknown dead-host id: {identifier}")
        return found

    needle = str(identifier or "").strip().lower()
    if not needle:
        raise typer.BadParameter("IDENTIFIER is required")

    def _match(item) -> bool:
        domains = [str(d).strip().lower() for d in getattr(item, "domain_names", [])]
        return needle in domains or needle == getattr(item, "natural_index", "").strip().lower()

    return find_unique(items, predicate=_match, kind="dead-host", identifier=identifier)


def resolve_redirect_host(client: NPMplusClient, identifier: str):
    host_id = resolve_int_identifier(identifier)
    items = client.list_redirection_hosts()
    if host_id is not None:
        found = items.get(host_id)
        if found is None:
            raise typer.BadParameter(f"Unknown redirect-host id: {identifier}")
        return found

    needle = str(identifier or "").strip().lower()
    if not needle:
        raise typer.BadParameter("IDENTIFIER is required")

    def _match(item) -> bool:
        domains = [str(d).strip().lower() for d in getattr(item, "domain_names", [])]
        return needle in domains or needle == getattr(item, "natural_index", "").strip().lower()

    return find_unique(items, predicate=_match, kind="redirect-host", identifier=identifier)


def resolve_stream(client: NPMplusClient, identifier: str):
    stream_id = resolve_int_identifier(identifier)
    items = client.list_streams()
    if stream_id is not None:
        found = items.get(stream_id)
        if found is not None:
            return found

    needle = str(identifier or "").strip()
    if not needle:
        raise typer.BadParameter("IDENTIFIER is required")

    def _match(item) -> bool:
        try:
            incoming_port = int(getattr(item, "incoming_port", 0))
        except Exception:
            incoming_port = 0
        return needle == str(incoming_port)

    return find_unique(items, predicate=_match, kind="stream", identifier=identifier)


def resolve_access_list(client: NPMplusClient, identifier: str):
    list_id = resolve_int_identifier(identifier)
    items = client.list_access_lists()
    if list_id is not None:
        found = items.get(list_id)
        if found is None:
            raise typer.BadParameter(f"Unknown access-list id: {identifier}")
        return found

    needle = str(identifier or "").strip()
    if not needle:
        raise typer.BadParameter("IDENTIFIER is required")

    def _match(item) -> bool:
        return needle == getattr(item, "natural_index", "").strip()

    return find_unique(items, predicate=_match, kind="access-list", identifier=identifier)


def resolve_certificate(client: NPMplusClient, identifier: str):
    cert_id = resolve_int_identifier(identifier)
    items = client.list_certificates()
    if cert_id is not None:
        found = items.get(cert_id)
        if found is None:
            raise typer.BadParameter(f"Unknown certificate id: {identifier}")
        return found

    needle = str(identifier or "").strip()
    if not needle:
        raise typer.BadParameter("IDENTIFIER is required")

    def _match(item) -> bool:
        return needle == getattr(item, "natural_index", "").strip()

    return find_unique(items, predicate=_match, kind="certificate", identifier=identifier)
