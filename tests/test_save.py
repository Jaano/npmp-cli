from npmp_cli.yaml_writer import host_filename, sanitize_filename


def test_sanitize_filename_basic():
	assert sanitize_filename("Example.COM") == "example.com"
	assert sanitize_filename(" hello world ") == "hello_world"
	assert sanitize_filename("a/b:c") == "a_b_c"


def test_host_filename_access_lists_uses_name() -> None:
	item = {"id": 12, "name": "Office Only"}
	assert host_filename("access-lists", item) == "access-lists__12.yaml"
