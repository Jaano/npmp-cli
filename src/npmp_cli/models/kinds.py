from __future__ import annotations

from enum import Enum
from typing import Any


class Kind(str, Enum):
    ACCESS_LISTS = "access-lists"
    CERTIFICATES = "certificates"
    PROXY_HOSTS = "proxy-hosts"
    REDIRECTION_HOSTS = "redirection-hosts"
    DEAD_HOSTS = "dead-hosts"
    STREAMS = "streams"
    USERS = "users"

    @staticmethod
    def infer_json_kind(payload: dict[str, Any]) -> Kind:
        keys = {str(k).lower() for k in payload.keys()}
        if "pass_auth" in keys:
            return Kind.ACCESS_LISTS
        if "incoming_port" in keys:
            return Kind.STREAMS
        if "forward_domain_name" in keys:
            return Kind.REDIRECTION_HOSTS
        if "forward_host" in keys:
            return Kind.PROXY_HOSTS
        return Kind.DEAD_HOSTS
