# npmp-cli

Small Python toolkit to talk to **NPMplus** ([ZoeyVid/NPMplus](https://github.com/ZoeyVid/NPMplus)).

## Features

- Export all NPMplus resources (proxy-hosts, redirection-hosts, dead-hosts, streams, access-lists) to YAML files
- Import YAML configurations back into NPMplus
- Save the NPMplus OpenAPI schema
- Sync Docker container labels to NPMplus proxy hosts (this is caddyproxy-style declarative configuration via Docker labels)
- Disable or delete proxy hosts that no longer have corresponding Docker containers

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
- [Sync from Docker Labels](#sync-from-docker-labels)
  - [Required Labels](#required-labels)
  - [Optional Labels](#optional-labels)
  - [Example](#example)
- [Credits](#credits)

## Install

```bash
python -m pip install -e .
```

## Environment Variables

You can set these environment variables or put them in `.env` at repo root (will be loaded automatically):

| Variable | Description | Default |
|----------|-------------|---------|
| `NPMP_BASE_URL` | Base URL to your NPMplus instance | *required* |
| `NPMP_IDENTITY` | NPMplus identity/username for login | |
| `NPMP_SECRET` | NPMplus password for login | |
| `NPMP_TOKEN` | JWT cookie value (alternative to identity+secret) | |
| `NPMP_VERIFY_TLS` | Enable/disable TLS certificate verification | `true` |
| `NPMP_LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) | `INFO` |
| `NPMP_ENV_FILE` | Path to an alternative .env file | `.env` |
| `NPMP_DOCKER_LABEL_PREFIX` | Prefix for docker labels (must end with `-`) | `npmp-` |
| `DOCKER_HOST` | Docker connection URL | local socket |

**Note:** For `NPMP_VERIFY_TLS`, use `false`/`0`/`no`/`off` to disable verification.

## Command Reference

### Global Options

Available for all commands:

```
--log-level TEXT    Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO)
                    Can also be set via NPMP_LOG_LEVEL environment variable
```

### npmp-cli save

Save NPMplus resources (proxy-hosts, redirection-hosts, dead-hosts, streams, access-lists) as YAML files.

```bash
npmp-cli save [OPTIONS]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--identity TEXT` | NPMplus identity/username (env: `NPMP_IDENTITY`) | |
| `--out PATH` | Output directory for saved YAML files | `./savings` |
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
|--------|-------------|
| `--identity TEXT` | NPMplus identity/username (env: `NPMP_IDENTITY`) |

**Example:**

```bash
npmp-cli schema --identity bot > schema.yaml
```

### npmp-cli load

Load a single saved YAML file into NPMplus (create or update based on natural key matching).

```bash
npmp-cli load FILE [OPTIONS]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `FILE` | Path to the YAML file to load (required) |

**Options:**

| Option | Description |
|--------|-------------|
| `--identity TEXT` | NPMplus identity/username (env: `NPMP_IDENTITY`) |
| `--kind TEXT` | Override automatic kind inference (e.g., `proxy-hosts`, `access-lists`) |

**Example:**

```bash
npmp-cli load ./savings/proxy-hosts__62.yaml --identity bot
```

### npmp-cli sync-docker

Scan Docker containers for `npmp-*` labels and create/update NPMplus proxy-hosts accordingly.

```bash
npmp-cli sync-docker [OPTIONS]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--identity TEXT` | NPMplus identity/username (env: `NPMP_IDENTITY`) | |
| `--out PATH` | Directory to save sync results | `./savings` |
| `--disable-orphans` | Set `enabled=false` on orphaned proxy-hosts | `false` |
| `--delete-orphans` | Delete orphaned proxy-hosts permanently | `false` |
| `--owner-user-id INTEGER` | Override owner_user_id for orphan detection (env: `NPMP_OWNER_USER_ID`) | auto-detected |

**Example:**

```bash
npmp-cli sync-docker --identity bot --disable-orphans
```

## Sync from Docker Labels

Scans all Docker containers and creates/updates NPMplus **proxy hosts** based on container labels.

This is opt-in per container: only containers with labels starting with the prefix (default `npmp-`) are considered (configurable via `NPMP_DOCKER_LABEL_PREFIX`).

### Required Labels

All four must be present:

| Label | Maps to | Description |
|-------|---------|-------------|
| `npmp-domain_names` | `domain_names` | Comma-separated domain names |
| `npmp-forward_host` | `forward_host` | Upstream hostname or IP |
| `npmp-forward_port` | `forward_port` | Upstream port (integer: 1-65535) |
| `npmp-forward_scheme` | `forward_scheme` | Protocol: `http`, `https` |

### Optional Labels

All optional; if not set, NPMplus defaults apply:

| Label | Maps to | Type | Description |
|-------|---------|------|-------------|
| `npmp-access_list` | `access_list` | string | Name of access list |
| `npmp-advanced_config` | `advanced_config` | string | Custom nginx config |
| `npmp-allow_websocket_upgrade` | `allow_websocket_upgrade` | boolean | Enable WebSocket upgrades |
| `npmp-block_exploits` | `block_exploits` | boolean | Block common exploits |
| `npmp-caching_enabled` | `caching_enabled` | boolean | Enable caching |
| `npmp-certificate` | `certificate` | string | Comma-separated cert domain names |
| `npmp-enabled` | `enabled` | boolean | Enable/disable proxy host |
| `npmp-hsts_enabled` | `hsts_enabled` | boolean | Enable HSTS |
| `npmp-hsts_subdomains` | `hsts_subdomains` | boolean | Include HSTS subdomains |
| `npmp-http2_support` | `http2_support` | boolean | Enable HTTP/2 |
| `npmp-ssl_forced` | `ssl_forced` | boolean | Force SSL/HTTPS redirect |

**Boolean values:** `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off`

### Example

docker-compose.yml:

```yaml
services:
  app:
    image: ghcr.io/example/app:latest
    labels:
      npmp-domain_names: "xyz.com,www.xyz.com"
      npmp-forward_host: "app"
      npmp-forward_port: "8080"
      npmp-forward_scheme: "http"
      npmp-certificate: "*.xyz.com,xyz.com"
      npmp-ssl_forced: "true"
      npmp-http2_support: "true"
      npmp-allow_websocket_upgrade: "true"
```

Run sync:

```bash
npmp-cli sync-docker --identity bot
```

**Notes:**

- Matching is done by `domain_names` (order-insensitive). If a proxy host already exists with the same set of domains, it will be updated; otherwise it will be created.
- If you add `--disable-orphans`, proxy-hosts owned by the current user but not present in any docker container spec will be updated to `enabled=false` (useful when containers get decommissioned).
- If you add `--delete-orphans`, proxy-hosts owned by the current user but not present in any docker container spec will be deleted permanently.
- Results are also saved under `./savings/` (deterministic YAML).
- Requires access to Docker via the Python `docker` module and a working local Docker connection.

## Credits

This project is a CLI tool for managing [NPMplus](https://github.com/ZoeyVid/NPMplus), which is itself a fork of [Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager).

### This Project (npmp-cli)
- **Author**: github.com/jaano
- **License**: MIT License
- **Purpose**: CLI toolkit for interacting with NPMplus API, saving configurations to YAML, and syncing Docker container labels to create/update proxy hosts automatically.
