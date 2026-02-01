"""Docker integration: scan labels and sync NPMplus resources."""

from .scanner import scan_docker_specs
from .specs import (
    DockerDeadHostSpec,
    DockerProxyHostSpec,
    DockerRedirectionHostSpec,
    DockerStreamSpec,
)
from .sync_dead import sync_docker_dead_hosts
from .sync_proxy import sync_docker_proxy_hosts
from .sync_redirect import sync_docker_redirection_hosts
from .sync_stream import sync_docker_streams

__all__ = [
    "DockerDeadHostSpec",
    "DockerProxyHostSpec",
    "DockerRedirectionHostSpec",
    "DockerStreamSpec",
    "scan_docker_specs",
    "sync_docker_dead_hosts",
    "sync_docker_proxy_hosts",
    "sync_docker_redirection_hosts",
    "sync_docker_streams",
]
