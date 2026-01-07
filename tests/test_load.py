from __future__ import annotations

from pathlib import Path

import pytest

from npmp_cli.yaml_loader import filter_payload_for_write, infer_kind


def test_infer_kind_from_filename() -> None:
	p = Path("proxy-hosts__62.yaml")
	k = infer_kind(p, {"id": 62})
	assert k == "proxy-hosts"


def test_infer_kind_from_folder() -> None:
	p = Path("savings/streams__1.yaml")
	k = infer_kind(p, {"incomingPort": 1234})
	assert k == "streams"


def test_filter_payload_for_write_uses_schema_props() -> None:
	# Minimal schema stub that only allows forward_* and domain_names for create proxy-host
	schema = {
		"paths": {
			"/nginx/proxy-hosts": {
				"post": {
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"properties": {
										"domain_names": {},
										"forward_scheme": {},
										"forward_host": {},
										"forward_port": {},
									}
								}
							}
						}
					}
				}
			}
		}
	}

	payload = {
		"id": 62,
		"created_on": "x",
		"domain_names": ["a.example"],
		"forward_scheme": "http",
		"forward_host": "container",
		"forward_port": 80,
		"meta": {"nginx_online": True},
	}

	filtered = filter_payload_for_write(schema, "proxy-hosts", payload, mode="create")
	assert "id" not in filtered
	assert "created_on" not in filtered
	assert "meta" not in filtered
	assert filtered["domain_names"] == ["a.example"]


def test_infer_kind_access_lists_from_payload_keys() -> None:
	p = Path("savings/access-lists__1.yaml")
	k = infer_kind(p, {"name": "LAN", "clients": [], "pass_auth": False})
	assert k == "access-lists"


def test_filter_payload_for_write_access_lists_uses_listid_paths() -> None:
	schema = {
		"paths": {
			"/nginx/access-lists": {
				"post": {
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"properties": {
										"name": {},
										"pass_auth": {},
										"satisfy_any": {},
										"clients": {
											"items": {
												"properties": {"address": {}, "directive": {}},
												"additionalProperties": False,
											}
										},
										"items": {
											"items": {
												"properties": {"username": {}, "password": {}},
												"additionalProperties": False,
											}
										},
									}
								}
							}
						}
					}
				}
			},
			"/nginx/access-lists/{listID}": {
				"put": {
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"properties": {
										"name": {},
										"pass_auth": {},
										"satisfy_any": {},
										"clients": {
											"items": {
												"properties": {"address": {}, "directive": {}},
												"additionalProperties": False,
											}
										},
										"items": {
											"items": {
												"properties": {"username": {}, "password": {}},
												"additionalProperties": False,
											}
										},
									}
								}
							}
						}
					}
				}
			},
		}
	}

	payload = {
		"id": 1,
		"name": "LAN",
		"clients": [
			{"id": 9, "address": "192.168.0.0/24", "directive": "allow", "created_on": "x"},
			{"address": "10.0.0.0/8", "directive": "deny", "meta": {}},
		],
		"items": [{"username": "u", "password": "p", "id": 123}],
		"created_on": "x",
	}

	filtered = filter_payload_for_write(schema, "access-lists", payload, mode="update")
	assert filtered["name"] == "LAN"
	assert "created_on" not in filtered
	assert filtered["clients"] == [
		{"address": "192.168.0.0/24", "directive": "allow"},
		{"address": "10.0.0.0/8", "directive": "deny"},
	]
	assert filtered["items"] == [{"username": "u", "password": "p"}]


def test_infer_kind_override_validation() -> None:
	with pytest.raises(ValueError):
		infer_kind(Path("x.yaml"), {}, kind_override="nope")
