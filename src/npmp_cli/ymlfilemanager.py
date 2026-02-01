from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import utils
from .configmanager import ConfigManager
from .docker.specs import DeadHostFields, ProxyHostFields, RedirectionHostFields, StreamFields
from .models import DeadHostItem, ProxyHostItem, RedirectionHostItem, StreamItem

logger = ConfigManager.get_logger(__name__)


_BOOL_LABEL_SUFFIXES: tuple[str, ...] = tuple(
    sorted(
        {
            *ProxyHostItem.BOOL_LABEL_FIELDS,
            *ProxyHostItem.LOCATION_BOOL_LABEL_FIELDS,
            *DeadHostItem.BOOL_LABEL_FIELDS,
            *RedirectionHostItem.BOOL_LABEL_FIELDS,
            *StreamItem.BOOL_LABEL_FIELDS,
        }
    )
)


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


class YmlFileManager:
    @staticmethod
    def _escape_compose_interpolation(value: str) -> str:
        out: list[str] = []
        i = 0
        while i < len(value):
            ch = value[i]
            if ch != "$":
                out.append(ch)
                i += 1
                continue
            if i + 1 < len(value) and value[i + 1] == "$":
                out.append("$$")
                i += 2
                continue
            out.append("$$")
            i += 1
        return "".join(out)

    @staticmethod
    def write_proxy_host_json_as_compose_labels_yaml(
        input_file: Path,
        output_file: Path | None = None,
        *,
        label_prefix: str | None = None,
        service_name: str | None = None,
    ) -> Path:
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
            service_name=service_name,
        )
        _atomic_write_text(out_path, yaml_text)
        return out_path

    @staticmethod
    def write_dead_host_json_as_compose_labels_yaml(
        input_file: Path,
        output_file: Path | None = None,
        *,
        label_prefix: str | None = None,
        service_name: str | None = None,
    ) -> Path:
        out_path = output_file or input_file.with_suffix(".yml")

        try:
            payload = json.loads(input_file.read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"Failed to parse JSON: {e}") from None

        if isinstance(payload, list):
            if len(payload) != 1 or not isinstance(payload[0], dict):
                raise ValueError("Expected a single dead-host JSON object (not a list)")
            payload = payload[0]
        if not isinstance(payload, dict):
            raise ValueError("Expected a JSON object")

        yaml_text = YmlFileManager.dead_host_json_to_compose_labels_yaml(
            payload,
            label_prefix=label_prefix,
            service_name=service_name,
        )
        _atomic_write_text(out_path, yaml_text)
        return out_path

    @staticmethod
    def write_redirection_host_json_as_compose_labels_yaml(
        input_file: Path,
        output_file: Path | None = None,
        *,
        label_prefix: str | None = None,
        service_name: str | None = None,
    ) -> Path:
        out_path = output_file or input_file.with_suffix(".yml")

        try:
            payload = json.loads(input_file.read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"Failed to parse JSON: {e}") from None

        if isinstance(payload, list):
            if len(payload) != 1 or not isinstance(payload[0], dict):
                raise ValueError("Expected a single redirection-host JSON object (not a list)")
            payload = payload[0]
        if not isinstance(payload, dict):
            raise ValueError("Expected a JSON object")

        yaml_text = YmlFileManager.redirection_host_json_to_compose_labels_yaml(
            payload,
            label_prefix=label_prefix,
            service_name=service_name,
        )
        _atomic_write_text(out_path, yaml_text)
        return out_path

    @staticmethod
    def write_stream_json_as_compose_labels_yaml(
        input_file: Path,
        output_file: Path | None = None,
        *,
        label_prefix: str | None = None,
        service_name: str | None = None,
    ) -> Path:
        out_path = output_file or input_file.with_suffix(".yml")

        try:
            payload = json.loads(input_file.read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"Failed to parse JSON: {e}") from None

        if isinstance(payload, list):
            if len(payload) != 1 or not isinstance(payload[0], dict):
                raise ValueError("Expected a single stream JSON object (not a list)")
            payload = payload[0]
        if not isinstance(payload, dict):
            raise ValueError("Expected a JSON object")

        yaml_text = YmlFileManager.stream_json_to_compose_labels_yaml(
            payload,
            label_prefix=label_prefix,
            service_name=service_name,
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
    def _yaml_double_quote(value: str) -> str:
        v = YmlFileManager._escape_compose_interpolation(value or "")
        v = v.replace("\\", "\\\\")
        v = v.replace('"', '\\"')
        return f'"{v}"'

    @staticmethod
    def _yaml_label_scalar(key: str, value: str, *, indent: str) -> str:
        if "\n" in value or "\r" in value:
            return YmlFileManager._yaml_block_scalar(value, indent=indent)

        if any(key.endswith(suffix) for suffix in _BOOL_LABEL_SUFFIXES):
            b = utils.normalize_bool(value)
            if b is not None:
                return "true" if b else "false"

        if key.endswith("forward_port"):
            try:
                return str(int(str(value).strip()))
            except Exception:
                pass

        return YmlFileManager._yaml_double_quote(value)

    @staticmethod
    def _yaml_block_scalar(value: str, *, indent: str) -> str:
        escaped = YmlFileManager._escape_compose_interpolation(value or "")
        lines = escaped.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        if lines and lines[-1] == "":
            lines = lines[:-1]
        body = "\n".join(f"{indent}{line}" for line in lines)
        return f"|-\n{body}" if body else "|-"

    @staticmethod
    def _default_service_name_from_payload(payload: Mapping[str, Any]) -> str:
        domains = payload.get("domain_names") or payload.get("domainNames")
        if isinstance(domains, list) and domains:
            first = str(domains[0] or "").strip().lower()
            if first.startswith("*."):
                first = first[2:]
            if first:
                return (first.split(".", 1)[0] or "service").strip() or "service"
        return "service"

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
        service_name: str | None = None,
    ) -> str:
        prefix = (
            ConfigManager.docker_proxy_label_prefix()
            if label_prefix is None
            else YmlFileManager._normalize_prefix(label_prefix)
        )

        labels = ProxyHostFields.labels_from_proxy_host_payload(payload, label_prefix=prefix)

        preferred_suffix_order = (
            "enabled",
            "domain_names",
            "forward_scheme",
            "forward_host",
            "forward_port",
            "access_list",
            "caching_enabled",
            "block_exploits",
            "allow_websocket_upgrade",
            "certificate",
            "ssl_forced",
            "http2_support",
            "hsts_enabled",
            "hsts_subdomains",
        )
        preferred_keys = [f"{prefix}{suffix}" for suffix in preferred_suffix_order]
        preferred_rank = {k: i for i, k in enumerate(preferred_keys)}

        def _label_sort_key(item: tuple[str, str]) -> tuple[int, int, str]:
            k = item[0]
            rank = preferred_rank.get(k)
            if rank is not None:
                return (0, rank, "")
            return (1, 0, k)

        labels = sorted(labels, key=_label_sort_key)
        label_map = dict(labels)

        svc_name = (service_name or "").strip() or YmlFileManager._default_service_name_from_payload(payload)

        lines: list[str] = [
            "services:",
            f"  {svc_name}:",
            "    labels:",
        ]

        def _append_commented_placeholder(key: str, value: str) -> None:
            scalar = YmlFileManager._yaml_label_scalar(key, value, indent="        ")
            lines.append(f"      # {key}: {scalar}")

        def _append_commented_block_placeholder(key: str, *, example_lines: list[str]) -> None:
            lines.append(f"      # {key}: |-")
            for line in example_lines:
                lines.append(f"      #   {line}")

        for key, value in labels:
            scalar = YmlFileManager._yaml_label_scalar(key, value, indent="        ")
            lines.append(f"      {key}: {scalar}")

        optional_keys: list[tuple[str, str]] = [
            (f"{prefix}enabled", "true"),
            (f"{prefix}access_list", "LAN"),
            (f"{prefix}caching_enabled", "false"),
            (f"{prefix}block_exploits", "false"),
            (f"{prefix}allow_websocket_upgrade", "true"),
            (f"{prefix}certificate", "my-cert"),
            (f"{prefix}ssl_forced", "true"),
            (f"{prefix}http2_support", "true"),
            (f"{prefix}hsts_enabled", "false"),
            (f"{prefix}hsts_subdomains", "false"),
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

    @staticmethod
    def dead_host_json_to_compose_labels_yaml(
        payload: Mapping[str, Any],
        *,
        label_prefix: str | None = None,
        service_name: str | None = None,
    ) -> str:
        prefix = (
            ConfigManager.docker_dead_host_label_prefix()
            if label_prefix is None
            else YmlFileManager._normalize_prefix(label_prefix)
        )

        labels = DeadHostFields.labels_from_dead_host_payload(payload, label_prefix=prefix)

        preferred_suffix_order = (
            "enabled",
            "domain_names",
            "certificate",
            "ssl_forced",
            "http2_support",
            "hsts_enabled",
            "hsts_subdomains",
        )
        preferred_keys = [f"{prefix}{suffix}" for suffix in preferred_suffix_order]
        preferred_rank = {k: i for i, k in enumerate(preferred_keys)}

        def _label_sort_key(item: tuple[str, str]) -> tuple[int, int, str]:
            k = item[0]
            rank = preferred_rank.get(k)
            if rank is not None:
                return (0, rank, "")
            return (1, 0, k)

        labels = sorted(labels, key=_label_sort_key)
        label_map = dict(labels)

        svc_name = (service_name or "").strip() or YmlFileManager._default_service_name_from_payload(payload)

        lines: list[str] = [
            "services:",
            f"  {svc_name}:",
            "    labels:",
        ]

        for key, value in labels:
            scalar = YmlFileManager._yaml_label_scalar(key, value, indent="        ")
            lines.append(f"      {key}: {scalar}")

        optional_keys: list[tuple[str, str]] = [
            (f"{prefix}enabled", "true"),
            (f"{prefix}certificate", "my-cert"),
            (f"{prefix}ssl_forced", "true"),
            (f"{prefix}http2_support", "true"),
            (f"{prefix}hsts_enabled", "false"),
            (f"{prefix}hsts_subdomains", "false"),
        ]

        for key, placeholder in optional_keys:
            if key not in label_map:
                scalar = YmlFileManager._yaml_label_scalar(key, placeholder, indent="        ")
                lines.append(f"      # {key}: {scalar}")

        adv_key = f"{prefix}advanced_config"
        if adv_key not in label_map:
            lines.append(f"      # {adv_key}: |-")
            lines.append("      #   # Example: add custom nginx directives")

        return "\n".join(lines) + "\n"

    @staticmethod
    def redirection_host_json_to_compose_labels_yaml(
        payload: Mapping[str, Any],
        *,
        label_prefix: str | None = None,
        service_name: str | None = None,
    ) -> str:
        prefix = (
            ConfigManager.docker_redirection_host_label_prefix()
            if label_prefix is None
            else YmlFileManager._normalize_prefix(label_prefix)
        )

        labels = RedirectionHostFields.labels_from_redirection_host_payload(payload, label_prefix=prefix)

        preferred_suffix_order = (
            "enabled",
            "domain_names",
            "forward_domain_name",
            "forward_http_code",
            "forward_scheme",
            "preserve_path",
            "certificate",
            "ssl_forced",
            "block_exploits",
            "http2_support",
            "hsts_enabled",
            "hsts_subdomains",
        )
        preferred_keys = [f"{prefix}{suffix}" for suffix in preferred_suffix_order]
        preferred_rank = {k: i for i, k in enumerate(preferred_keys)}

        def _label_sort_key(item: tuple[str, str]) -> tuple[int, int, str]:
            k = item[0]
            rank = preferred_rank.get(k)
            if rank is not None:
                return (0, rank, "")
            return (1, 0, k)

        labels = sorted(labels, key=_label_sort_key)
        label_map = dict(labels)

        svc_name = (service_name or "").strip() or YmlFileManager._default_service_name_from_payload(payload)

        lines: list[str] = [
            "services:",
            f"  {svc_name}:",
            "    labels:",
        ]

        for key, value in labels:
            scalar = YmlFileManager._yaml_label_scalar(key, value, indent="        ")
            lines.append(f"      {key}: {scalar}")

        optional_keys: list[tuple[str, str]] = [
            (f"{prefix}enabled", "true"),
            (f"{prefix}preserve_path", "true"),
            (f"{prefix}certificate", "my-cert"),
            (f"{prefix}ssl_forced", "true"),
            (f"{prefix}block_exploits", "false"),
            (f"{prefix}http2_support", "true"),
            (f"{prefix}hsts_enabled", "false"),
            (f"{prefix}hsts_subdomains", "false"),
        ]

        for key, placeholder in optional_keys:
            if key not in label_map:
                scalar = YmlFileManager._yaml_label_scalar(key, placeholder, indent="        ")
                lines.append(f"      # {key}: {scalar}")

        adv_key = f"{prefix}advanced_config"
        if adv_key not in label_map:
            lines.append(f"      # {adv_key}: |-")
            lines.append("      #   # Example: add custom nginx directives")

        return "\n".join(lines) + "\n"

    @staticmethod
    def stream_json_to_compose_labels_yaml(
        payload: Mapping[str, Any],
        *,
        label_prefix: str | None = None,
        service_name: str | None = None,
    ) -> str:
        prefix = (
            ConfigManager.docker_stream_label_prefix()
            if label_prefix is None
            else YmlFileManager._normalize_prefix(label_prefix)
        )

        labels = StreamFields.labels_from_stream_payload(payload, label_prefix=prefix)

        preferred_suffix_order = (
            "enabled",
            "incoming_port",
            "forwarding_host",
            "forwarding_port",
            "tcp_forwarding",
            "udp_forwarding",
            "proxy_protocol_forwarding",
            "certificate",
        )
        preferred_keys = [f"{prefix}{suffix}" for suffix in preferred_suffix_order]
        preferred_rank = {k: i for i, k in enumerate(preferred_keys)}

        def _label_sort_key(item: tuple[str, str]) -> tuple[int, int, str]:
            k = item[0]
            rank = preferred_rank.get(k)
            if rank is not None:
                return (0, rank, "")
            return (1, 0, k)

        labels = sorted(labels, key=_label_sort_key)
        label_map = dict(labels)

        incoming_port = payload.get("incoming_port") or payload.get("incomingPort")
        svc_name = (service_name or "").strip() or f"stream-{incoming_port}"

        lines: list[str] = [
            "services:",
            f"  {svc_name}:",
            "    labels:",
        ]

        for key, value in labels:
            scalar = YmlFileManager._yaml_label_scalar(key, value, indent="        ")
            lines.append(f"      {key}: {scalar}")

        optional_keys: list[tuple[str, str]] = [
            (f"{prefix}enabled", "true"),
            (f"{prefix}tcp_forwarding", "true"),
            (f"{prefix}udp_forwarding", "false"),
            (f"{prefix}proxy_protocol_forwarding", "false"),
            (f"{prefix}certificate", "my-cert"),
        ]

        for key, placeholder in optional_keys:
            if key not in label_map:
                scalar = YmlFileManager._yaml_label_scalar(key, placeholder, indent="        ")
                lines.append(f"      # {key}: {scalar}")

        return "\n".join(lines) + "\n"
