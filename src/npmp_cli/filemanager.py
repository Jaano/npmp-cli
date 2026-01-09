from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .configmanager import ConfigManager
from .docker_syncer import ProxyHostFields
from .npmplus_api import NPMplusApi

logger = ConfigManager.get_logger(__name__)


def host_filename(kind: str, item: Mapping[str, object]) -> str:
    item_id = item.get("id")
    id_part = str(item_id) if item_id is not None else "unknown"
    return f"{kind}__{id_part}.json"


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        Path(tmp_path).replace(path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise


def write_json_file(path: Path, payload: Any) -> None:
    content = (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )
    _atomic_write_text(path, content)


class YmlFileManager:
    @staticmethod
    def write_proxy_host_json_as_compose_labels_yaml(
        input_file: Path,
        output_file: Path | None = None,
        *,
        label_prefix: str | None = None,
    ) -> Path:
        if input_file.suffix.lower() != ".json":
            raise ValueError("Only JSON is supported. Provide a .json file.")

        out_path = output_file or input_file.with_suffix(".yml")

        try:
            payload = json.loads(input_file.read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"Failed to parse JSON: {e}") from None

        if isinstance(payload, list):
            if len(payload) != 1 or not isinstance(payload[0], dict):
                raise ValueError("Expected a single proxy-host JSON object (not a list)")
            payload = payload[0]
        if not isinstance(payload, dict):
            raise ValueError("Expected a JSON object")

        yaml_text = YmlFileManager.proxy_host_json_to_compose_labels_yaml(
            payload,
            label_prefix=label_prefix,
        )
        _atomic_write_text(out_path, yaml_text)
        return out_path

    @staticmethod
    def _normalize_prefix(value: str | None) -> str:
        s = (value or "").strip()
        if not s:
            return "npmp."
        if s.endswith((".", "-")):
            return s
        return s + "."

    @staticmethod
    def _as_bool_label(value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return "true" if value else "false"
        s = str(value).strip().lower()
        if s in {"1", "true", "yes", "y", "on"}:
            return "true"
        if s in {"0", "false", "no", "n", "off"}:
            return "false"
        return None

    @staticmethod
    def _split_domains(value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        out: list[str] = []
        for item in value:
            s = str(item).strip().lower()
            if s:
                out.append(s)
        return out

    @staticmethod
    def _yaml_double_quote(value: str) -> str:
        v = value or ""
        v = v.replace("\\", "\\\\")
        v = v.replace('"', '\\"')
        return f'"{v}"'

    @staticmethod
    def _yaml_block_scalar(value: str, *, indent: str) -> str:
        lines = (value or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
        if lines and lines[-1] == "":
            lines = lines[:-1]
        body = "\n".join(f"{indent}{line}" for line in lines)
        return f"|-\n{body}" if body else "|-"

    @staticmethod
    def _get_access_list_name(payload: Mapping[str, Any]) -> str | None:
        value = payload.get("access_list")
        if isinstance(value, str):
            s = value.strip()
            return s or None
        if isinstance(value, Mapping):
            name = value.get("name") or value.get("title")
            if name is None:
                return None
            s = str(name).strip()
            return s or None
        return None

    @staticmethod
    def _get_certificate_domains(payload: Mapping[str, Any]) -> list[str] | None:
        cert = payload.get("certificate")
        if isinstance(cert, Mapping):
            out = YmlFileManager._split_domains(cert.get("domain_names"))
            return out or None
        return None

    @staticmethod
    def _get_locations(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        locs = payload.get("locations")
        if locs is None:
            return []
        if isinstance(locs, Mapping):
            return [locs]
        if isinstance(locs, list):
            return [x for x in locs if isinstance(x, Mapping)]
        return []

    @staticmethod
    def proxy_host_json_to_compose_labels_yaml(
        payload: Mapping[str, Any],
        *,
        label_prefix: str | None = None,
    ) -> str:
        """Convert a saved NPMplus proxy-host JSON object into a docker-compose `labels:` YAML block."""

        prefix = (
            ConfigManager.docker_label_prefix()
            if label_prefix is None
            else YmlFileManager._normalize_prefix(label_prefix)
        )

        labels = ProxyHostFields.labels_from_proxy_host_payload(payload, label_prefix=prefix)

        label_map = {k: v for k, v in labels}

        lines: list[str] = ["labels:"]

        def _append_commented_placeholder(key: str, value: str) -> None:
            lines.append(f"  # {key}: {YmlFileManager._yaml_double_quote(value)}")

        def _append_commented_block_placeholder(key: str, *, example_lines: list[str]) -> None:
            lines.append(f"  # {key}: |-")
            for line in example_lines:
                lines.append(f"  #   {line}")

        for key, value in labels:
            if "\n" in value or "\r" in value:
                scalar = YmlFileManager._yaml_block_scalar(value, indent="    ")
                lines.append(f"  {key}: {scalar}")
            else:
                lines.append(f"  {key}: {YmlFileManager._yaml_double_quote(value)}")

        optional_keys: list[tuple[str, str]] = [
            (f"{prefix}access_list", "LAN"),
            (f"{prefix}certificate", "*.example.com,example.com"),
            (f"{prefix}allow_websocket_upgrade", "true"),
            (f"{prefix}block_exploits", "true"),
            (f"{prefix}caching_enabled", "true"),
            (f"{prefix}enabled", "true"),
            (f"{prefix}hsts_enabled", "true"),
            (f"{prefix}hsts_subdomains", "false"),
            (f"{prefix}http2_support", "true"),
            (f"{prefix}ssl_forced", "true"),
        ]
        for key, placeholder in optional_keys:
            if key not in label_map:
                _append_commented_placeholder(key, placeholder)

        adv_key = f"{prefix}advanced_config"
        if adv_key not in label_map:
            _append_commented_block_placeholder(
                adv_key,
                example_lines=[
                    "# Example: add custom nginx directives",
                    "location /health { return 200; }",
                ],
            )

        for idx, _loc in enumerate(YmlFileManager._get_locations(payload), start=1):
            if f"{prefix}loc{idx}_path" not in label_map:
                continue
            for key, placeholder in (
                (f"{prefix}loc{idx}_allow_websocket_upgrade", "true"),
                (f"{prefix}loc{idx}_block_exploits", "true"),
                (f"{prefix}loc{idx}_caching_enabled", "true"),
                (f"{prefix}loc{idx}_location_type", ""),
            ):
                if key not in label_map:
                    _append_commented_placeholder(key, placeholder)
            loc_adv_key = f"{prefix}loc{idx}_advanced_config"
            if loc_adv_key not in label_map:
                _append_commented_block_placeholder(
                    loc_adv_key,
                    example_lines=[
                        "# Example location-specific nginx directives",
                        "proxy_set_header X-From-Location loc" + str(idx) + ";",
                    ],
                )

        return "\n".join(lines) + "\n"


KIND_VALUES = {
    "proxy-hosts",
    "redirection-hosts",
    "dead-hosts",
    "streams",
    "access-lists",
}

KIND_TO_METHOD: dict[str, str] = {
    "proxy-hosts": "list_proxy_hosts",
    "redirection-hosts": "list_redirection_hosts",
    "dead-hosts": "list_dead_hosts",
    "streams": "list_streams",
    "access-lists": "list_access_lists",
}


def infer_kind(path, payload: Mapping[str, object]) -> str:  # type: ignore[no-untyped-def]
    parent = path.parent.name.strip().lower()
    if parent in KIND_VALUES:
        return parent

    name = path.name.strip().lower()
    for k in sorted(KIND_VALUES, key=len, reverse=True):
        if name.startswith(k + "__") or name == k + ".json":
            return k

    keys = {str(k).lower() for k in payload.keys()}
    if "satisfy_any" in keys or "pass_auth" in keys or "proxy_host_count" in keys or "clients" in keys:
        return "access-lists"
    if "incomingport" in keys:
        return "streams"
    if "forward_host" in keys or "forward_port" in keys or "forward_scheme" in keys:
        return "proxy-hosts"
    if "redirect_host" in keys or "redirect_code" in keys:
        return "redirection-hosts"
    return "dead-hosts"


def _expand_attempts_for_kind(kind_name: str) -> list[list[str] | None]:
    k = (kind_name or "").strip().lower()
    if k == "access-lists":
        return [["clients", "items"], ["clients"], None]
    return [
        ["owner", "certificate", "access_list"],
        ["owner", "access_list"],
        ["owner"],
        None,
    ]


def _fetch_with_expand_fallback(method, *, kind_name: str, query: str | None) -> list[dict[str, object]]:  # type: ignore[no-untyped-def]
    attempts = _expand_attempts_for_kind(kind_name)
    for i, attempt in enumerate(attempts):
        try:
            return method(expand=attempt, query=query)
        except RuntimeError as e:
            is_last = i == (len(attempts) - 1)
            if is_last:
                logger.warning("GET %s failed even without expand (%s)", kind_name, str(e))
                raise
            logger.debug(
                "GET %s failed with expand=%s; retrying with less expansion (%s)",
                kind_name,
                attempt,
                str(e),
            )
            continue
    raise RuntimeError(f"Failed to fetch {kind_name}")


def _schema_request_properties(schema: Mapping[str, object], path: str, method: str) -> set[str]:
    paths = schema.get("paths")
    if not isinstance(paths, dict):
        return set()
    op = paths.get(path)
    if not isinstance(op, dict):
        return set()
    op_method = op.get(method.lower())
    if not isinstance(op_method, dict):
        return set()
    rb = op_method.get("requestBody")
    if not isinstance(rb, dict):
        return set()
    content = rb.get("content")
    if not isinstance(content, dict):
        return set()
    app_json = content.get("application/json")
    if not isinstance(app_json, dict):
        return set()
    s = app_json.get("schema")
    if not isinstance(s, dict):
        return set()
    props = s.get("properties")
    if not isinstance(props, dict):
        return set()
    return {str(k) for k in props.keys()}


def _schema_array_item_properties(schema: Mapping[str, object], path: str, method: str, prop_name: str) -> set[str]:
    paths = schema.get("paths")
    if not isinstance(paths, dict):
        return set()
    op = paths.get(path)
    if not isinstance(op, dict):
        return set()
    op_method = op.get(method.lower())
    if not isinstance(op_method, dict):
        return set()
    rb = op_method.get("requestBody")
    if not isinstance(rb, dict):
        return set()
    content = rb.get("content")
    if not isinstance(content, dict):
        return set()
    app_json = content.get("application/json")
    if not isinstance(app_json, dict):
        return set()
    s = app_json.get("schema")
    if not isinstance(s, dict):
        return set()
    props = s.get("properties")
    if not isinstance(props, dict):
        return set()
    arr = props.get(prop_name)
    if not isinstance(arr, dict):
        return set()
    items = arr.get("items")
    if not isinstance(items, dict):
        return set()
    item_props = items.get("properties")
    if not isinstance(item_props, dict):
        return set()
    return {str(k) for k in item_props.keys()}


def _filter_payload_for_write(
    schema: Mapping[str, object], kind: str, payload: Mapping[str, object], *, mode: str
) -> dict[str, object]:
    k = kind.strip().lower()
    if k not in KIND_VALUES:
        raise ValueError(f"Unknown kind: {kind}")
    m = mode.strip().lower()
    if m not in {"create", "update"}:
        raise ValueError("mode must be create or update")

    if k == "streams":
        write_path = "/nginx/streams" if m == "create" else "/nginx/streams/{streamID}"
        method = "post" if m == "create" else "put"
    elif k == "access-lists":
        write_path = "/nginx/access-lists" if m == "create" else "/nginx/access-lists/{listID}"
        method = "post" if m == "create" else "put"
    else:
        write_path = f"/nginx/{k}" if m == "create" else f"/nginx/{k}/{{hostID}}"
        method = "post" if m == "create" else "put"

    allowed = _schema_request_properties(schema, write_path, method)
    if not allowed:
        deny = {"id", "created_on", "modified_on"}
        return {str(k): v for k, v in payload.items() if str(k) not in deny}

    out: dict[str, object] = {str(k): v for k, v in payload.items() if str(k) in allowed}

    if k == "access-lists":
        for nested in ("clients", "items"):
            val = out.get(nested)
            if not isinstance(val, list):
                continue
            allowed_nested = _schema_array_item_properties(schema, write_path, method, nested)
            if not allowed_nested:
                continue
            filtered_list: list[object] = []
            for entry in val:
                if not isinstance(entry, dict):
                    continue
                filtered_list.append({str(k): v for k, v in entry.items() if str(k) in allowed_nested})
            out[nested] = filtered_list

    return out


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


def _cert_domains_key(value: object) -> str | None:
    if isinstance(value, list):
        parts = [str(v).strip().lower() for v in value if str(v).strip()]
        if not parts:
            return None
        return ",".join(sorted(set(parts)))
    if isinstance(value, str):
        parts = [p.strip().lower() for p in value.split(",")]
        parts = [p for p in parts if p]
        if not parts:
            return None
        return ",".join(sorted(set(parts)))
    return None


def _cert_key_from_payload(payload: Mapping[str, object]) -> str | None:
    cert = payload.get("certificate")
    if isinstance(cert, dict):
        domains = cert.get("domain_names")
        if domains is None:
            domains = cert.get("domainNames")
        return _cert_domains_key(domains)
    if isinstance(cert, str):
        return _cert_domains_key(cert)
    return None


def _access_list_name_from_any(value: object) -> str | None:
    if isinstance(value, dict):
        name = value.get("name") or value.get("title")
        if name is None:
            return None
        s = str(name).strip()
        return s if s else None
    if isinstance(value, str):
        s = value.strip()
        return s if s else None
    return None


def _synthetic_key(kind_name: str, payload: Mapping[str, object]) -> tuple[str, ...] | None:
    k = (kind_name or "").strip().lower()
    if k == "proxy-hosts":
        fh = payload.get("forward_host") or payload.get("forwardHost")
        fp = payload.get("forward_port") or payload.get("forwardPort")
        fs = payload.get("forward_scheme") or payload.get("forwardScheme")
        parts = ["proxy", str(fs or "").strip().lower(), str(fh or "").strip().lower(), str(fp or "").strip()]
        parts = [p for p in parts if p]
        return tuple(parts) if len(parts) >= 3 else None
    if k == "redirection-hosts":
        rh = payload.get("redirect_host") or payload.get("redirectHost")
        rc = payload.get("redirect_code") or payload.get("redirectCode")
        parts = ["redir", str(rh or "").strip().lower(), str(rc or "").strip()]
        parts = [p for p in parts if p]
        return tuple(parts) if len(parts) >= 2 else None
    return None


def _drop_id_fields_for_load(value: object) -> object:
    deny = {
        "id",
        "owner_user_id",
        "ownerUserId",
        "access_list_id",
        "accessListId",
        "certificate_id",
        "certificateId",
    }
    if isinstance(value, dict):
        out: dict[str, object] = {}
        for k, v in value.items():
            ks = str(k)
            if ks in deny:
                continue
            out[ks] = _drop_id_fields_for_load(v)
        return out
    if isinstance(value, list):
        return [_drop_id_fields_for_load(v) for v in value]
    return value


def _resolve_relation_ids_for_load(client: NPMplusApi, kind_name: str, payload: dict[str, object]) -> dict[str, object]:
    k = (kind_name or "").strip().lower()
    if k not in {"proxy-hosts", "redirection-hosts", "dead-hosts", "streams"}:
        return payload

    out: dict[str, object] = dict(payload)

    access_name = _access_list_name_from_any(out.get("access_list") or out.get("accessList"))
    if access_name:
        wanted = access_name.strip().lower()
        try:
            for item in client.list_access_lists(expand=[], query=None):
                if not isinstance(item, dict):
                    continue
                name = _access_list_name_from_any(item.get("name") or item.get("title"))
                item_id = item.get("id")
                if not name or item_id is None:
                    continue
                if name.strip().lower() == wanted:
                    try:
                        out["access_list_id"] = int(str(item_id).strip())
                    except Exception:
                        pass
                    break
        except Exception:
            pass

    cert_key = _cert_key_from_payload(out)
    if cert_key:
        wanted = cert_key
        try:
            for item in client.list_certificates(expand=[], query=None):
                if not isinstance(item, dict):
                    continue
                item_id = item.get("id")
                if item_id is None:
                    continue
                domains = item.get("domain_names")
                if domains is None:
                    domains = item.get("domainNames")
                item_key = _cert_domains_key(domains)
                if not item_key:
                    continue
                if item_key == wanted:
                    try:
                        out["certificate_id"] = int(str(item_id).strip())
                    except Exception:
                        pass
                    break
        except Exception:
            pass

    return out


def _access_list_name_from_payload(payload: dict[str, object]) -> str | None:
    name = payload.get("name") or payload.get("title")
    if name is None:
        return None
    s = str(name).strip()
    return s if s else None


def _incoming_port_from_payload(payload: dict[str, object]) -> int | None:
    return _coerce_int(payload.get("incomingPort") or payload.get("incoming_port"))


def _find_existing_id_by_natural_key(client: NPMplusApi, kind_name: str, payload: dict[str, object]) -> int | None:
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
        synth_key = None if domain_key else _synthetic_key(k, payload)
        if not domain_key and not synth_key:
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
            if domain_key:
                item_key = _domain_key_from_payload(item)  # type: ignore[arg-type]
                if item_key == domain_key:
                    return _coerce_int(item.get("id"))
            elif synth_key:
                item_synth = _synthetic_key(k, item)  # type: ignore[arg-type]
                if item_synth == synth_key:
                    return _coerce_int(item.get("id"))
        return None

    return None


class JsonFileManager:
    def __init__(self, client: NPMplusApi) -> None:
        self._client = client

    @staticmethod
    def _resolve_save_kinds(kind: str) -> list[str]:
        k = (kind or "").strip().lower()
        if not k:
            raise ValueError("--kind cannot be empty")
        if k == "all":
            return list(KIND_TO_METHOD.keys())
        if k in KIND_TO_METHOD:
            return [k]
        allowed = ", ".join(["all", *sorted(KIND_TO_METHOD.keys())])
        raise ValueError(f"Unknown --kind: {kind}. Use one of: {allowed}")

    def save(self, *, kind: str, out: Path, query: str | None) -> None:
        kinds = JsonFileManager._resolve_save_kinds(kind)
        for kind_name in kinds:
            method_name = KIND_TO_METHOD[kind_name]
            method = getattr(self._client, method_name)
            items = _fetch_with_expand_fallback(method, kind_name=kind_name, query=query)
            for item in items:
                payload: dict[str, Any] = dict(item)
                path = out / host_filename(kind_name, item)
                write_json_file(path, payload)

    def load(
        self,
        *,
        file: Path,
    ) -> tuple[str, str, object]:
        try:
            import json

            payload = json.loads(file.read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"Invalid JSON: {str(e)}") from None
        if not isinstance(payload, dict):
            raise ValueError("JSON file must contain an object")

        kind_name = infer_kind(file, payload)

        def _camel_key(snake: str) -> str:
            parts = (snake or "").split("_")
            if not parts:
                return snake
            return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])

        def _get_existing_value(item: Mapping[str, Any], key: str) -> object:
            if key in item:
                return item.get(key)
            camel = _camel_key(key)
            return item.get(camel)

        def _normalize_domains(value: object) -> tuple[str, ...] | None:
            if not isinstance(value, list):
                return None
            parts = [str(v).strip().lower() for v in value]
            parts = [p for p in parts if p]
            return tuple(sorted(parts))

        def _normalize_int(value: object) -> int | None:
            if value is None:
                return None
            try:
                return int(str(value).strip())
            except Exception:
                return None

        def _normalize_bool(value: object) -> bool | None:
            if value is None:
                return None
            if isinstance(value, bool):
                return value
            v = str(value).strip().lower()
            if v in {"1", "true", "yes", "on"}:
                return True
            if v in {"0", "false", "no", "off"}:
                return False
            return None

        def _values_equal(field: str, desired: object, existing: object) -> bool:
            if field == "domain_names":
                return _normalize_domains(desired) == _normalize_domains(existing)
            if field.endswith("_id") or field in {"forward_port", "incomingPort", "incoming_port"}:
                return _normalize_int(desired) == _normalize_int(existing)
            if field in {
                "enabled",
                "allow_websocket_upgrade",
                "block_exploits",
                "caching_enabled",
                "hsts_enabled",
                "hsts_subdomains",
                "http2_support",
                "ssl_forced",
                "pass_auth",
                "satisfy_any",
            }:
                return _normalize_bool(desired) == _normalize_bool(existing)
            if isinstance(desired, str) or isinstance(existing, str):
                return str(desired).strip() == str(existing).strip()
            return desired == existing

        def _is_additional_props_error(message: str) -> bool:
            m = (message or "").lower()
            return "must not have additional properties" in m or "additional properties" in m

        def _apply(kind_name: str, mode: str, host_id: int | None, body: dict[str, object]) -> Mapping[str, Any]:
            if kind_name == "proxy-hosts":
                if mode == "create":
                    return self._client.create_proxy_host(body)
                assert host_id is not None
                return self._client.update_proxy_host(host_id, body)
            if kind_name == "redirection-hosts":
                if mode == "create":
                    return self._client.create_redirection_host(body)
                assert host_id is not None
                return self._client.update_redirection_host(host_id, body)
            if kind_name == "dead-hosts":
                if mode == "create":
                    return self._client.create_dead_host(body)
                assert host_id is not None
                return self._client.update_dead_host(host_id, body)
            if kind_name == "streams":
                if mode == "create":
                    return self._client.create_stream(body)
                assert host_id is not None
                return self._client.update_stream(host_id, body)
            if kind_name == "access-lists":
                if mode == "create":
                    return self._client.create_access_list(body)
                assert host_id is not None
                return self._client.update_access_list(host_id, body)
            raise ValueError(f"Unsupported kind: {kind_name}")

        target_id = _find_existing_id_by_natural_key(self._client, kind_name, payload)
        resolved_mode = "create" if target_id is None else "update"
        logger.info("Load: %s %s from %s", resolved_mode, kind_name, file)

        write_payload: dict[str, object] = payload
        write_id: int | None = target_id
        original_payload: dict[str, object] = dict(write_payload)
        write_payload = _drop_id_fields_for_load(write_payload)  # type: ignore[assignment]
        assert isinstance(write_payload, dict)
        write_payload = _resolve_relation_ids_for_load(self._client, kind_name, write_payload)

        if kind_name == "proxy-hosts" and "locations" in write_payload:
            locations = write_payload.get("locations")
            if locations is None:
                write_payload["locations"] = []
                logger.info("Load: normalized locations=null to [] (%s)", kind_name)
            elif isinstance(locations, dict):
                write_payload["locations"] = [locations]
                logger.info("Load: normalized locations object to list (%s)", kind_name)
            elif isinstance(locations, list):
                cleaned = [x for x in locations if isinstance(x, dict)]
                if len(cleaned) != len(locations):
                    write_payload["locations"] = cleaned
                    logger.info("Load: removed non-object locations entries (%s)", kind_name)
            else:
                del write_payload["locations"]
                logger.info("Load: removed invalid locations field (%s)", kind_name)

        dropped_keys = sorted(set(original_payload.keys()) - set(write_payload.keys()))
        if dropped_keys:
            logger.info("Load: dropped fields before write (%s): %s", kind_name, ", ".join(dropped_keys))
        modified_keys: list[str] = []
        for k, v in write_payload.items():
            if k in original_payload and not _values_equal(k, v, original_payload.get(k)):
                modified_keys.append(k)
        if modified_keys:
            logger.info(
                "Load: normalized/rewrote fields before write (%s): %s",
                kind_name,
                ", ".join(sorted(modified_keys)),
            )

        if resolved_mode == "update" and write_id is not None:
            try:
                method_name = KIND_TO_METHOD.get(kind_name)
                if method_name:
                    items = getattr(self._client, method_name)(expand=[], query=None)
                    if isinstance(items, list):
                        existing_item = None
                        for item in items:
                            if not isinstance(item, dict):
                                continue
                            if _coerce_int(item.get("id")) == write_id:
                                existing_item = item
                                break
                        if isinstance(existing_item, dict):
                            changed_fields: list[str] = []
                            for field, desired_value in write_payload.items():
                                existing_value = _get_existing_value(existing_item, field)
                                if not _values_equal(field, desired_value, existing_value):
                                    changed_fields.append(field)
                            if changed_fields:
                                logger.info(
                                    "Load: will update %s id=%s fields=%s",
                                    kind_name,
                                    write_id,
                                    ", ".join(sorted(changed_fields)),
                                )
                            else:
                                logger.info("Load: no field changes detected for %s id=%s", kind_name, write_id)
            except Exception:
                # Best-effort diff only; never fail the load due to logging.
                pass
        try:
            result = _apply(kind_name, resolved_mode, write_id, write_payload)
        except Exception as e:
            msg = str(e)
            handled = False
            if "HTTP 400" in msg and _is_additional_props_error(msg):
                try:
                    schema = self._client.get_schema()
                    filtered = _filter_payload_for_write(schema, kind_name, write_payload, mode=resolved_mode)
                    filtered_out = sorted(set(write_payload.keys()) - set(filtered.keys()))
                    if filtered_out:
                        logger.info(
                            "Load: server rejected extra fields; removed (%s): %s",
                            kind_name,
                            ", ".join(filtered_out),
                        )
                    logger.warning("Server rejected extra fields; retrying with schema-filtered payload")
                    result = _apply(kind_name, resolved_mode, write_id, filtered)
                    handled = True
                except Exception as e2:
                    logger.error("Load failed (filtered retry): %s", str(e2))
                    raise RuntimeError(str(e2)) from None

            if resolved_mode == "update" and "HTTP 404" in msg and "Not Found" in msg:
                create_payload = write_payload
                try:
                    result = _apply(kind_name, "create", None, create_payload)
                    resolved_mode = "create"
                    logger.info("Load: update target missing; created %s instead", kind_name)
                    handled = True
                except Exception as e2:
                    msg2 = str(e2)
                    if "HTTP 400" in msg2 and _is_additional_props_error(msg2):
                        try:
                            schema = self._client.get_schema()
                            filtered = _filter_payload_for_write(schema, kind_name, create_payload, mode="create")
                            filtered_out = sorted(set(create_payload.keys()) - set(filtered.keys()))
                            if filtered_out:
                                logger.info(
                                    "Load: server rejected extra fields on create; removed (%s): %s",
                                    kind_name,
                                    ", ".join(filtered_out),
                                )
                            logger.warning("Server rejected extra fields; retrying create with schema-filtered payload")
                            result = _apply(kind_name, "create", None, filtered)
                            resolved_mode = "create"
                            handled = True
                        except Exception as e3:
                            logger.error("Load failed (update->create filtered retry): %s", str(e3))
                            raise RuntimeError(str(e3)) from None
                    else:
                        logger.error("Load failed (update->create fallback): %s", msg2)
                        raise RuntimeError(msg2) from None
            if not handled:
                logger.error("Load failed: %s", msg)
                raise RuntimeError(msg) from None

        new_id = result.get("id")
        return kind_name, resolved_mode, new_id
