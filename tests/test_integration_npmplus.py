from __future__ import annotations

import os

import pytest

from npmp_cli.api_client import NPMplusClient


def _bool_env(name: str, default: bool) -> bool:
	v = os.getenv(name)
	if v is None:
		return default
	return v.strip().lower() in {"1", "true", "yes", "on"}


@pytest.mark.integration
@pytest.mark.skipif(
	not _bool_env("NPMP_RUN_INTEGRATION", False),
	reason="Set NPMP_RUN_INTEGRATION=1 to run integration tests",
)
def test_integration_schema_and_list_hosts() -> None:
	base_url = os.getenv("NPMP_BASE_URL")
	identity = os.getenv("NPMP_IDENTITY")
	secret = os.getenv("NPMP_SECRET")
	token = os.getenv("NPMP_TOKEN")
	verify_tls = _bool_env("NPMP_VERIFY_TLS", False)

	if not base_url:
		pytest.skip("NPMP_BASE_URL not set")

	with NPMplusClient(base_url=base_url, verify_tls=verify_tls) as client:
		if token:
			client.set_token_cookie(token)
		elif identity and secret:
			client.login(identity, secret)
		else:
			pytest.skip("Need either NPMP_TOKEN or both NPMP_IDENTITY and NPMP_SECRET")

		schema = client.get_schema()
		assert isinstance(schema, dict)
		assert "paths" in schema

		# Read-only smoke checks
		proxy_hosts = client.list_proxy_hosts()
		assert isinstance(proxy_hosts, list)

		redirection_hosts = client.list_redirection_hosts()
		assert isinstance(redirection_hosts, list)

		dead_hosts = client.list_dead_hosts()
		assert isinstance(dead_hosts, list)

		streams = client.list_streams()
		assert isinstance(streams, list)
