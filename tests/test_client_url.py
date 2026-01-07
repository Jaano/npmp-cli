import pytest

from npmp_cli.api_client import _normalize_api_base_url


@pytest.mark.parametrize(
	"inp,expected",
	[
		("https://example", "https://example/api"),
		("https://example/", "https://example/api"),
		("https://example/api", "https://example/api"),
		("https://example/api/", "https://example/api"),
	],
)
def test_normalize_api_base_url(inp, expected):
	assert _normalize_api_base_url(inp) == expected
