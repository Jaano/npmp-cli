from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from pathlib import Path

import typer

try:
    from dotenv import load_dotenv

    env_file = os.getenv("NPMP_ENV_FILE")
    load_dotenv(dotenv_path=env_file or ".env")
except Exception:
    pass

from .api_client import NPMplusAuthError, NPMplusClient, NPMplusError
from .docker_scanner import scan_docker_proxy_host_specs
from .docker_syncer import sync_docker_proxy_hosts
from .yaml_loader import filter_payload_for_write, infer_kind
from .yaml_writer import host_filename, write_yaml_file

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=True,
    pretty_exceptions_show_locals=False,
    pretty_exceptions_short=True,
)


def _configure_logging(level: str) -> None:
    normalized = (level or "INFO").strip().upper()
    try:
        logging_level = getattr(logging, normalized)
        if not isinstance(logging_level, int):
            raise AttributeError
    except Exception:
        raise typer.BadParameter(
            "--log-level must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL"
        ) from None

    logging.basicConfig(
        level=logging_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("httpx").setLevel(max(logging_level, logging.WARNING))
    logging.getLogger("httpcore").setLevel(max(logging_level, logging.WARNING))


def _expand_attempts_for_kind(kind_name: str) -> list[list[str] | None]:
    """Ordered list of expand attempts for a kind.

    NPMplus endpoints are not consistent: some return 500/400 for certain expand values.
    We try to request as much as possible, then fall back.
    """
    k = (kind_name or "").strip().lower()
    if k == "access-lists":
        # Access list rules are exposed under `clients` (allow/deny CIDRs). Some installs
        # may also return `items`, so request both.
        return [["clients", "items"], ["clients"], None]

    # Most "host" resources commonly support these.
    return [
        ["owner", "certificate", "access_list"],
        ["owner", "access_list"],
        ["owner"],
        None,
    ]


def _fetch_with_expand_fallback(method, *, kind_name: str, query: str | None) -> list[dict[str, object]]:  # type: ignore[no-untyped-def]
    attempts = _expand_attempts_for_kind(kind_name)
    logger = logging.getLogger(__name__)
    for i, attempt in enumerate(attempts):
        try:
            return method(expand=attempt, query=query)
        except NPMplusError as e:
            is_last = i == (len(attempts) - 1)
            if is_last:
                logger.warning(
                    "GET %s failed even without expand (%s)", kind_name, str(e)
                )
                raise
            logger.debug(
                "GET %s failed with expand=%s; retrying with less expansion (%s)",
                kind_name,
                attempt,
                str(e),
            )
            continue
    # Should be unreachable (last attempt is None and would either return or raise).
    raise RuntimeError(f"Failed to fetch {kind_name}")


def _coerce_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        s = str(value).strip()
        if not s:
            return None
        return int(s)
    except Exception:
        return None


def _domain_key_from_payload(payload: dict[str, object]) -> tuple[str, ...] | None:
    def _as_domains(value: object) -> list[str] | None:
        if isinstance(value, list):
            parts: list[str] = []
            for v in value:
                s = str(v).strip().lower()
                if s:
                    parts.append(s)
            return parts
        if isinstance(value, str):
            parts = [p.strip().lower() for p in value.split(",")]
            parts = [p for p in parts if p]
            return parts
        return None

    domains = _as_domains(payload.get("domain_names"))
    if domains is None:
        domains = _as_domains(payload.get("domainNames"))
    if not domains:
        return None
    return tuple(sorted(set(domains)))


def _access_list_name_from_payload(payload: dict[str, object]) -> str | None:
    name = payload.get("name") or payload.get("title")
    if name is None:
        return None
    s = str(name).strip()
    return s if s else None


def _incoming_port_from_payload(payload: dict[str, object]) -> int | None:
    return _coerce_int(payload.get("incomingPort") or payload.get("incoming_port"))


def _parse_csv_domains(value: str) -> tuple[str, ...]:
    parts = [p.strip().lower() for p in (value or "").split(",")]
    parts = [p for p in parts if p]
    return tuple(sorted(set(parts)))


def _payload_domain_key(payload: dict[str, object]) -> tuple[str, ...] | None:
    key = _domain_key_from_payload(payload)
    return key


def _resolve_relations_for_load(
    client: NPMplusClient, kind_name: str, payload: dict[str, object]
) -> dict[str, object]:
    """Fill *_id relation fields from natural-key string fields.

    We intentionally do not persist numeric IDs in save files. For load, we resolve:
    - proxy-hosts/redirection-hosts/dead-hosts/streams: access_list -> access_list_id
    - proxy-hosts/redirection-hosts/dead-hosts/streams: certificate -> certificate_id
    """
    k = (kind_name or "").strip().lower()
    if k not in {"proxy-hosts", "redirection-hosts", "dead-hosts", "streams"}:
        return payload

    out: dict[str, object] = dict(payload)

    # access_list name -> access_list_id
    if _coerce_int(out.get("access_list_id") or out.get("accessListId")) is None:
        access_list_name = out.get("access_list") or out.get("accessList")
        if isinstance(access_list_name, str) and access_list_name.strip():
            wanted = access_list_name.strip().lower()
            try:
                for item in client.list_access_lists(expand=[], query=None):
                    if not isinstance(item, dict):
                        continue
                    name = item.get("name") or item.get("title")
                    item_id = item.get("id")
                    if name is None or item_id is None:
                        continue
                    if str(name).strip().lower() == wanted:
                        try:
                            out["access_list_id"] = int(str(item_id).strip())
                        except Exception:
                            pass
                        break
            except Exception:
                pass

    # certificate domains csv -> certificate_id
    if _coerce_int(out.get("certificate_id") or out.get("certificateId")) is None:
        cert_value = out.get("certificate")
        if isinstance(cert_value, str) and cert_value.strip():
            wanted_key = _parse_csv_domains(cert_value)
            if wanted_key:
                try:
                    for item in client.list_certificates(expand=[], query=None):
                        if not isinstance(item, dict):
                            continue
                        item_id = item.get("id")
                        if item_id is None:
                            continue
                        item_key = _payload_domain_key(item)  # type: ignore[arg-type]
                        if item_key is None:
                            continue
                        if tuple(item_key) == wanted_key:
                            try:
                                out["certificate_id"] = int(str(item_id).strip())
                            except Exception:
                                pass
                            break
                except Exception:
                    pass

    return out


def _find_existing_id_by_natural_key(
    client: NPMplusClient, kind_name: str, payload: dict[str, object]
) -> int | None:
    """Return the server object's id matching the payload, or None.

    Matching is by natural key (not numeric id):
    - access-lists: name
    - streams: incomingPort
    - *-hosts: domain_names set
    """
    k = (kind_name or "").strip().lower()
    if k == "access-lists":
        target_name = _access_list_name_from_payload(payload)
        if not target_name:
            return None
        items = client.list_access_lists(expand=[], query=None)
        for item in items:
            if not isinstance(item, dict):
                continue
            name = _access_list_name_from_payload(item)  # type: ignore[arg-type]
            if name and name.strip().lower() == target_name.strip().lower():
                return _coerce_int(item.get("id"))
        return None

    if k == "streams":
        port = _incoming_port_from_payload(payload)
        if port is None:
            return None
        items = client.list_streams(expand=[], query=None)
        for item in items:
            if not isinstance(item, dict):
                continue
            existing_port = _incoming_port_from_payload(item)  # type: ignore[arg-type]
            if existing_port == port:
                return _coerce_int(item.get("id"))
        return None

    if k in {"proxy-hosts", "redirection-hosts", "dead-hosts"}:
        domain_key = _domain_key_from_payload(payload)
        if not domain_key:
            return None
        if k == "proxy-hosts":
            items = client.list_proxy_hosts(expand=[], query=None)
        elif k == "redirection-hosts":
            items = client.list_redirection_hosts(expand=[], query=None)
        else:
            items = client.list_dead_hosts(expand=[], query=None)
        for item in items:
            if not isinstance(item, dict):
                continue
            item_key = _domain_key_from_payload(item)  # type: ignore[arg-type]
            if item_key == domain_key:
                return _coerce_int(item.get("id"))
        return None

    return None


def _minimize_saved_host_payload(
    kind_name: str, item: dict[str, object]
) -> dict[str, object]:
    """Minimize expanded relation payloads for saved host JSON.

    For host resources (proxy/redirection/dead/streams) we keep only natural-key info for:
    - access_list: name (string)
    - owner: nickname (string)
    - certificate: certificate name(s) (comma-separated)

    Access lists are not modified here (they are their own resource).
    """
    k = (kind_name or "").strip().lower()
    if k == "access-lists":
        return dict(item)

    out: dict[str, object] = dict(item)

    # domain_names -> "<domain1>,<domain2>,..." (comma-separated)
    domains = out.get("domain_names")
    if not isinstance(domains, list):
        domains = out.get("domainNames")
    if isinstance(domains, list):
        parts: list[str] = []
        for d in domains:
            dd = str(d).strip()
            if dd:
                parts.append(dd)
        out["domain_names"] = ",".join(sorted(set(parts), key=lambda s: s.lower()))

    # owner -> "nickname"
    owner = out.get("owner")
    if isinstance(owner, dict):
        nickname = owner.get("nickname")
        out["owner"] = "" if nickname is None else str(nickname)

    # access_list -> "name"
    access_list = out.get("access_list")
    if isinstance(access_list, dict):
        name = access_list.get("name") or access_list.get("title")
        out["access_list"] = "" if name is None else str(name)
    access_list_camel = out.get("accessList")
    if isinstance(access_list_camel, dict):
        name = access_list_camel.get("name") or access_list_camel.get("title")
        out["accessList"] = "" if name is None else str(name)

    # certificate -> "<name1>,<name2>,..." derived from the expanded certificate object
    certificate = out.get("certificate")
    if isinstance(certificate, dict):
        cert_domains = certificate.get("domain_names")
        if not isinstance(cert_domains, list):
            cert_domains = certificate.get("domainNames")
        if isinstance(cert_domains, list) and cert_domains:
            parts: list[str] = []
            for d in cert_domains:
                dd = str(d).strip()
                if dd:
                    parts.append(dd)
            # Keep deterministic output regardless of API ordering.
            out["certificate"] = ",".join(sorted(set(parts), key=lambda s: s.lower()))
            return out

        # Fallback to a single certificate display name if no domain list is present.
        nice_name = (
            certificate.get("nice_name")
            or certificate.get("niceName")
            or certificate.get("name")
        )
        out["certificate"] = "" if nice_name is None else str(nice_name)

    return out


@contextmanager
def _client_context(
    *,
    identity: str | None,
):
    """Create and authenticate NPMplusClient with consistent behavior across commands.

    All credentials (NPMP_BASE_URL, NPMP_TOKEN or NPMP_IDENTITY + NPMP_SECRET)
    are read from environment only.
    """
    base_url = os.getenv("NPMP_BASE_URL")
    if not base_url:
        raise typer.BadParameter(
            "NPMP_BASE_URL is required (set in environment or .env)"
        )
    verify_tls_env = os.getenv("NPMP_VERIFY_TLS", "true").lower()
    verify_tls = verify_tls_env not in {"0", "false", "no", "off"}
    with NPMplusClient(base_url=base_url, verify_tls=verify_tls) as client:
        token_env = os.getenv("NPMP_TOKEN")
        if token_env:
            client.set_token_cookie(token_env)
        else:
            secret_env = os.getenv("NPMP_SECRET")
            if identity and secret_env:
                client.login(identity, secret_env)
            else:
                raise typer.BadParameter(
                    "Provide NPMP_TOKEN or both --identity and NPMP_SECRET in environment"
                )
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
    _configure_logging(log_level)


_KIND_TO_METHOD = {
    "proxy-hosts": "list_proxy_hosts",
    "redirection-hosts": "list_redirection_hosts",
    "dead-hosts": "list_dead_hosts",
    "streams": "list_streams",
    "access-lists": "list_access_lists",
}


@app.command("save")
def save(
    identity: str | None = typer.Option(None, "--identity", envvar="NPMP_IDENTITY"),
    out: Path = typer.Option(Path("savings"), "--out"),
    kind: str = typer.Option(
        "all",
        "--kind",
        help="Which NPMplus host type(s) to save",
        case_sensitive=False,
        show_default=True,
    ),
    query: str | None = typer.Option(
        None, "--query", help="Optional server-side search query"
    ),
) -> None:
    """Save NPMplus “sites” (hosts) as YAML files.

    By default saves all host types: proxy-hosts, redirection-hosts, dead-hosts, streams.
    """

    k = kind.lower().strip()
    if k == "all":
        kinds = list(_KIND_TO_METHOD.keys())
    elif k in _KIND_TO_METHOD:
        kinds = [k]
    else:
        raise typer.BadParameter(
            f"Unknown --kind: {kind}. Use one of: all, {', '.join(_KIND_TO_METHOD)}"
        )

    with _client_context(identity=identity) as client:
        wrote = 0
        seen = 0
        for kind_name in kinds:
            method_name = _KIND_TO_METHOD[kind_name]
            method = getattr(client, method_name)
            try:
                items = _fetch_with_expand_fallback(
                    method, kind_name=kind_name, query=query
                )
            except NPMplusAuthError as e:
                raise typer.Exit(code=2) from e

            for item in items:
                seen += 1
                payload = _minimize_saved_host_payload(kind_name, item)
                path = out / host_filename(kind_name, item)
                write_yaml_file(path, payload, skip_unchanged=False)
                wrote += 1

        typer.echo(f"Saved {seen} items ({wrote} written) to {out}")


@app.command("schema")
def schema(
    identity: str | None = typer.Option(None, "--identity", envvar="NPMP_IDENTITY"),
) -> None:
    """Fetch and print `/api/schema` (OpenAPI)."""
    with _client_context(identity=identity) as client:
        import yaml

        print(
            yaml.safe_dump(
                client.get_schema(),
                allow_unicode=True,
                sort_keys=True,
                default_flow_style=False,
            )
        )


@app.command("load")
def load(
    file: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="Path to a single saved YAML file",
    ),
    identity: str | None = typer.Option(None, "--identity", envvar="NPMP_IDENTITY"),
    kind: str | None = typer.Option(None, "--kind", help="Override kind inference"),
) -> None:
    """Load exactly one saved YAML file into NPMplus.

    This command applies a single YAML file (one at a time) via POST/PUT.
    """
    if file.suffix.lower() == ".json":
        raise typer.BadParameter("JSON is not supported. Provide a .yaml file.")

    import yaml

    payload = yaml.safe_load(file.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise typer.BadParameter("YAML file must contain an object")

    # Normalize saved domain_names which may be a comma-separated string.
    # NPMplus write endpoints expect a list.
    if isinstance(payload.get("domain_names"), str):
        payload["domain_names"] = [
            p.strip() for p in str(payload["domain_names"]).split(",") if p.strip()
        ]
    if isinstance(payload.get("domainNames"), str):
        payload["domainNames"] = [
            p.strip() for p in str(payload["domainNames"]).split(",") if p.strip()
        ]

    kind_name = infer_kind(file, payload, kind_override=kind)

    # We intentionally do NOT use the file's numeric `id` to select the target.
    # Instead we find the object's id on this server by natural key.
    resolved_mode = "auto"
    target_id: int | None = None

    with _client_context(identity=identity) as client:
        # Always resolve by natural key.
        if resolved_mode == "auto":
            target_id = _find_existing_id_by_natural_key(client, kind_name, payload)
            if target_id is None:
                resolved_mode = "create"
            else:
                resolved_mode = "update"
        else:
            raise RuntimeError("unreachable")

        payload = _resolve_relations_for_load(client, kind_name, payload)
        schema = client.get_schema()
        write_payload = filter_payload_for_write(
            schema, kind_name, payload, mode=resolved_mode
        )
        try:
            if kind_name == "proxy-hosts":
                if resolved_mode == "create":
                    result = client.create_proxy_host(write_payload)
                else:
                    assert target_id is not None
                    host_id: int = target_id
                    result = client.update_proxy_host(host_id, write_payload)
            elif kind_name == "redirection-hosts":
                if resolved_mode == "create":
                    result = client.create_redirection_host(write_payload)
                else:
                    assert target_id is not None
                    host_id = target_id
                    result = client.update_redirection_host(host_id, write_payload)
            elif kind_name == "dead-hosts":
                if resolved_mode == "create":
                    result = client.create_dead_host(write_payload)
                else:
                    assert target_id is not None
                    host_id = target_id
                    result = client.update_dead_host(host_id, write_payload)
            elif kind_name == "streams":
                if resolved_mode == "create":
                    result = client.create_stream(write_payload)
                else:
                    assert target_id is not None
                    stream_id: int = target_id
                    result = client.update_stream(stream_id, write_payload)
            elif kind_name == "access-lists":
                if resolved_mode == "create":
                    result = client.create_access_list(write_payload)
                else:
                    assert target_id is not None
                    list_id: int = target_id
                    result = client.update_access_list(list_id, write_payload)
            else:
                raise typer.BadParameter(f"Unsupported kind: {kind_name}")
        except Exception as e:
            msg = str(e)
            handled = False
            # Common case when loading a file saved from a different instance:
            # the numeric id doesn't exist on this server.
            if resolved_mode == "update" and "HTTP 404" in msg and "Not Found" in msg:
                # Upsert behavior: if the object doesn't exist on this server, create it.
                create_payload = filter_payload_for_write(
                    schema, kind_name, payload, mode="create"
                )
                try:
                    if kind_name == "proxy-hosts":
                        result = client.create_proxy_host(create_payload)
                    elif kind_name == "redirection-hosts":
                        result = client.create_redirection_host(create_payload)
                    elif kind_name == "dead-hosts":
                        result = client.create_dead_host(create_payload)
                    elif kind_name == "streams":
                        result = client.create_stream(create_payload)
                    elif kind_name == "access-lists":
                        result = client.create_access_list(create_payload)
                    else:
                        raise typer.BadParameter(f"Unsupported kind: {kind_name}")
                    resolved_mode = "create"
                    handled = True
                except Exception as e2:
                    msg2 = str(e2)
                    typer.echo(
                        f"Load failed (update->create fallback): {msg2}", err=True
                    )
                    raise typer.Exit(code=2) from None
            if not handled:
                typer.echo(f"Load failed: {msg}", err=True)
                raise typer.Exit(code=2) from None

        new_id = result.get("id")
        typer.echo(f"Loaded {kind_name} ({resolved_mode}) id={new_id}")


@app.command("sync-docker")
def sync_docker(
    identity: str | None = typer.Option(None, "--identity", envvar="NPMP_IDENTITY"),
    out: Path = typer.Option(Path("savings"), "--out"),
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
    """Scan all Docker containers for npmp-* labels and upsert proxy-hosts."""

    specs = scan_docker_proxy_host_specs()
    if not specs and not disable_orphans and not delete_orphans:
        typer.echo("No docker containers found with required npmp-* labels")
        return

    with _client_context(identity=identity) as client:
        created, updated, skipped = sync_docker_proxy_hosts(
            client=client,
            specs=specs,
            out_dir=out,
            skip_unchanged=False,
            disable_orphans=disable_orphans,
            delete_orphans=delete_orphans,
            owner_user_id=owner_user_id,
        )

    typer.echo(
        f"Docker sync complete: created={created} updated={updated} skipped={skipped}"
    )
