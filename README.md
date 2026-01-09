# npmp-cli

Small Python toolkit to talk to **NPMplus** ([ZoeyVid/NPMplus](https://github.com/ZoeyVid/NPMplus)).

## Features

- Export NPMplus resources (proxy-hosts, redirection-hosts, dead-hosts, streams, access-lists) to JSON files
- Import JSON configurations back into NPMplus (can be used for migration)
- Save the NPMplus OpenAPI schema
- Sync Docker container labels to NPMplus proxy hosts (this is Caddy Docker Proxy or Traefik style declarative configuration via Docker labels)
- Disable or delete proxy hosts that no longer have corresponding Docker containers (only those owned by specific user)
- Convert saved proxy-host JSON files into docker-compose YAML `labels:` blocks, for easy copy-paste into your container definitions

## Table of Contents

- [Features](#features)
- [Install](#install)
- [Environment Variables](#environment-variables)
- [Command Reference](#command-reference)
  - [Global Options](#global-options)
  - [npmp-cli save](#npmp-cli-save)
  - [npmp-cli schema](#npmp-cli-schema)
  - [npmp-cli load](#npmp-cli-load)
  - [npmp-cli sync-docker](#npmp-cli-sync-docker)
  - [npmp-cli json-to-compose](#npmp-cli-json-to-compose)
- [Sync from Docker Labels](#sync-from-docker-labels)
  - [Required Labels](#required-labels)
  - [Optional Labels](#optional-labels)
  - [Example](#example)
- [Credits](#credits)

## Install

```bash
python -m venv .venv
.venv/bin/python -m pip install -e .
```

For development (tests, linting):

```bash
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest -q
```

## Environment Variables

You can set these environment variables or put them in `.env` at repo root (will be loaded automatically):

| Variable | Description | Default |
| --- | --- | --- |
| `NPMP_BASE_URL` | Base URL to your NPMplus instance | *required* |
| `NPMP_IDENTITY` | NPMplus identity/username for login | |
| `NPMP_SECRET` | NPMplus password for login | |
| `NPMP_TOKEN` | JWT cookie value (alternative to identity+secret) | |
| `NPMP_VERIFY_TLS` | Enable/disable TLS certificate verification | `true` |
| `NPMP_LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) | `INFO` |
| `NPMP_ENV_FILE` | Path to an alternative .env file | `.env` |
| `NPMP_DOCKER_LABEL_PREFIX` | Prefix for docker labels (must end with `.`) | `npmp.` |
| `DOCKER_HOST` | Docker connection URL | local socket |

**Note:** For `NPMP_VERIFY_TLS`, use `false`/`0`/`no`/`off` to disable verification.

## Command Reference

### Global Options

Available for all commands:

```text
--log-level TEXT    Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO)
                    Can also be set via NPMP_LOG_LEVEL environment variable
```

### npmp-cli save

Save NPMplus resources (proxy-hosts, redirection-hosts, dead-hosts, streams, access-lists) as JSON files.

```bash
npmp-cli save [OPTIONS]
```

**Options:**

| Option | Description | Default |
| --- | --- | --- |
| `--identity TEXT` | NPMplus identity/username (env: `NPMP_IDENTITY`) | |
| `--out PATH` | Output directory for saved JSON files | `./npmp-config` |
| `--kind TEXT` | Resource type(s): `all`, `proxy-hosts`, `redirection-hosts`, `dead-hosts`, `streams`, `access-lists` | `all` |
| `--query TEXT` | Optional server-side search query | |

**Example:**

```bash
npmp-cli save --identity bot --out ./backups --kind proxy-hosts
```

### npmp-cli schema

Fetch and print the NPMplus OpenAPI schema from `/api/schema`.

```bash
npmp-cli schema [OPTIONS]
```

**Options:**

| Option | Description |
| --- | --- |
| `--identity TEXT` | NPMplus identity/username (env: `NPMP_IDENTITY`) |

**Example:**

```bash
npmp-cli schema --identity bot > schema.json
```

### npmp-cli load

Load one or more saved JSON files into NPMplus (create or update based on natural key matching).

```bash
npmp-cli load INPUT... [OPTIONS]
```

**Arguments:**

| Argument | Description |
| --- | --- |
| `INPUT...` | One or more JSON files, or glob patterns (e.g. `./npmp-config/proxy-hosts__*.json`) |

**Options:**

| Option | Description |
| --- | --- |
| `--identity TEXT` | NPMplus identity/username (env: `NPMP_IDENTITY`) |

**Example:**

```bash
npmp-cli load ./npmp-config/proxy-hosts__62.json --identity bot
```

Load multiple files (note quotes to prevent your shell expanding differently):

```bash
npmp-cli load './npmp-config/proxy-hosts__*.json' --identity bot
```

### npmp-cli sync-docker

Scan Docker containers for labels with the configured prefix and create/update NPMplus proxy-hosts accordingly.

```bash
npmp-cli sync-docker [OPTIONS]
```

**Options:**

| Option | Description | Default |
| --- | --- | --- |
| `--identity TEXT` | NPMplus identity/username (env: `NPMP_IDENTITY`) | |
| `--disable-orphans` | Set `enabled=false` on orphaned proxy-hosts | `false` |
| `--delete-orphans` | Delete orphaned proxy-hosts permanently | `false` |
| `--owner-user-id INTEGER` | Override owner_user_id for orphan detection (env: `NPMP_OWNER_USER_ID`) | auto-detected |

**Example:**

```bash
npmp-cli sync-docker --identity bot --disable-orphans
```

### npmp-cli json-to-compose

Convert one or more saved proxy-host JSON files into docker-compose `labels:` YAML blocks.

```bash
npmp-cli json-to-compose INPUT.json... [OUTPUT.yml]
```

If `OUTPUT.yml` is not provided, it writes a `.yml` file next to each input (same basename).

Notes:

- `OUTPUT.yml` can only be used when converting a single input file.

Examples:

```bash
npmp-cli json-to-compose ./npmp-config/proxy-hosts__62.json
npmp-cli json-to-compose './npmp-config/proxy-hosts__*.json'
```

## Sync from Docker Labels

Scans all Docker containers and creates/updates NPMplus **proxy hosts** based on container labels.

This is opt-in per container: only containers with labels starting with the prefix (default `npmp.`) are considered (configurable via `NPMP_DOCKER_LABEL_PREFIX`).

### Required Labels

All four must be present:

| Label | Maps to | Description |
| --- | --- | --- |
| `npmp.domain_names` | `domain_names` | Comma-separated domain names |
| `npmp.forward_host` | `forward_host` | Upstream hostname or IP |
| `npmp.forward_port` | `forward_port` | Upstream port (integer: 1-65535) |
| `npmp.forward_scheme` | `forward_scheme` | Protocol: `http`, `https` |

### Optional Labels

All optional; if not set, NPMplus defaults apply:

| Label | Maps to | Type | Description |
| --- | --- | --- | --- |
| `npmp.access_list` | `access_list` | string | Name of access list |
| `npmp.advanced_config` | `advanced_config` | string | Custom nginx config |
| `npmp.allow_websocket_upgrade` | `allow_websocket_upgrade` | boolean | Enable WebSocket upgrades |
| `npmp.block_exploits` | `block_exploits` | boolean | Block common exploits |
| `npmp.caching_enabled` | `caching_enabled` | boolean | Enable caching |
| `npmp.certificate` | `certificate` | string | Comma-separated cert domain names |
| `npmp.enabled` | `enabled` | boolean | Enable/disable proxy host |
| `npmp.hsts_enabled` | `hsts_enabled` | boolean | Enable HSTS |
| `npmp.hsts_subdomains` | `hsts_subdomains` | boolean | Include HSTS subdomains |
| `npmp.http2_support` | `http2_support` | boolean | Enable HTTP/2 |
| `npmp.ssl_forced` | `ssl_forced` | boolean | Force SSL/HTTPS redirect |

**Boolean values:** `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off`

### Location Labels

You can also define per-path locations for a proxy host using numbered labels.

For location *N* (starting at 1):

| Label | Maps to | Description |
| --- | --- | --- |
| `npmp.locN_path` | `locations[N].path` | Location path (e.g. `/api`) |
| `npmp.locN_forward_host` | `locations[N].forward_host` | Upstream hostname/IP |
| `npmp.locN_forward_port` | `locations[N].forward_port` | Upstream port |
| `npmp.locN_forward_scheme` | `locations[N].forward_scheme` | Protocol (defaults to host scheme if omitted) |

Optional per-location fields:

| Label | Maps to |
| --- | --- |
| `npmp.locN_advanced_config` | `locations[N].advanced_config` |
| `npmp.locN_allow_websocket_upgrade` | `locations[N].allow_websocket_upgrade` |
| `npmp.locN_block_exploits` | `locations[N].block_exploits` |
| `npmp.locN_caching_enabled` | `locations[N].caching_enabled` |
| `npmp.locN_location_type` | `locations[N].location_type` |

### Example

docker-compose.yml:

```yaml
services:
  app:
    image: ghcr.io/example/app:latest
    labels:
      npmp.domain_names: "xyz.com,www.xyz.com"
      npmp.forward_host: "appserver.local"
      npmp.forward_port: "8080"
      npmp.forward_scheme: "http"
      npmp.certificate: "*.xyz.com,xyz.com"
      npmp.ssl_forced: "true"
      npmp.http2_support: "true"
      npmp.allow_websocket_upgrade: "true"
```

Run sync:

```bash
npmp-cli sync-docker --identity bot
```

**Notes:**

- Matching is done by `domain_names` (order-insensitive). If a proxy host already exists with the same set of domains, it will be updated; otherwise it will be created.
- `--disable-orphans` proxy-hosts owned by the current user but not present in any docker container spec will be updated to `enabled=false` (useful when containers get decommissioned).
- `--delete-orphans` proxy-hosts owned by the current user but not present in any docker container spec will be deleted permanently.

## Credits

This project is a CLI tool for managing [NPMplus](https://github.com/ZoeyVid/NPMplus), which is itself a fork of [Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager).

Inspirations from:

- Caddy Docker Proxy <https://github.com/lucaslorentz/caddy-docker-proxy>
- Traefik <https://doc.traefik.io/traefik/providers/docker/>

## Stuff

- **Author**: [github.com/Jaano](https://github.com/Jaano)
- **License**: MIT License
