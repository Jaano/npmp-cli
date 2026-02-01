# npmp-cli manual

See also:

- [cli-examples.md](cli-examples.md) (copy/paste cookbook)

## What this CLI is

`npmp-cli` is a Python CLI for talking to an NPMplus server (ZoeyVid/NPMplus).

Primary uses:

- Export NPMplus resources to JSON files
- Import JSON configurations back into NPMplus
- Fetch and save the OpenAPI schema
- Sync Docker container labels into NPMplus items
- Convert saved JSON files into `docker-compose` `labels:` blocks

## Install

### Pre-built binaries

Download the latest release for your platform from GitHub Releases.

Typical artifact names:

- `npmp-cli-linux` (Linux x86_64; requires GLIBC 2.35+)
- `npmp-cli-macos-arm` (macOS Apple Silicon)
- `npmp-cli-macos-intel` (macOS Intel)
- `npmp-cli-windows.exe` (Windows)

Sanity check:

```bash
chmod +x npmp-cli
./npmp-cli-linux --help
```

### From source

```bash
python -m venv .venv
.venv/bin/python -m pip install -e .
```

Development install:

```bash
.venv/bin/python -m pip install -e '.[dev]'
```

## Configuration

### Env file loading

By default the CLI loads `.env` (current working directory).

Override with:

- `--config PATH` (CLI option)
- `NPMP_ENV_FILE=PATH` (env var)

### Required environment

You must provide:

- `NPMP_BASE_URL` (example: `https://npm.example.com`)
- `NPMP_IDENTITY` + `NPMP_SECRET`

### Full environment variable reference

| Variable | Meaning | Default |
| --- | --- | --- |
| `NPMP_BASE_URL` | Base URL to your NPMplus instance | required |
| `NPMP_IDENTITY` | NPMplus identity/username for login | required |
| `NPMP_SECRET` | NPMplus password for login | required |
| `NPMP_VERIFY_TLS` | Enable/disable TLS certificate verification | `true` |
| `NPMP_LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) | `INFO` |
| `NPMP_LOG_CONSOLE_STREAM` | Console log stream: `stderr` (default) or `stdout` | `stderr` |
| `NPMP_LOG_FILE` | Optional log file path (existing directory or path ending with `/` logs to `<dir>/npmp-cli.log`) | |
| `NPMP_LOG_FILE_LEVEL` | Logging level for file logging (defaults to `NPMP_LOG_LEVEL`) | |
| `NPMP_HTTP_RETRY_COUNT` | Retry count for transient httpx disconnect/transport errors (total attempts = retries + 1) | `3` |
| `NPMP_ENV_FILE` | Path to an alternative `.env` file | `.env` |
| `NPMP_DOCKER_LABEL_PREFIX` | Prefix for docker labels (must end with `.`) | `npmp.` |
| `DOCKER_HOST` | Docker connection URL | local socket |

### Global CLI options

These options apply to all commands:

- `--config PATH` (loads env file early; default: `.env`)
- `--log-level LEVEL`
- `--log-console-stream stderr|stdout`
- `--log-file PATH_OR_DIR`
- `--log-file-level LEVEL`

## Input file handling

Some commands accept multiple input files.

- You can pass explicit file paths.
- You can pass quoted glob patterns (example: `'npmp-config/*.json'`).
- Globs are expanded by the CLI (not by your shell), so quoting them is recommended.

## Output formats

- `list` subcommands default to a human-readable tab-separated format.
- `list --json` prints JSON.
- `show` subcommands default to a readable top-level view.
- `show --json` prints the full payload.

## Command reference

For copy/paste examples, use [cli-examples.md](cli-examples.md).

### Top-level commands

#### `save`

Export proxy-hosts, redirection-hosts, dead-hosts, streams, and access-lists into JSON files.

- Synopsis: `npmp-cli save [--out DIR]`
- Options:
  - `--out DIR` (default: `npmp-config`)

#### `audit-log`

Export NPMplus audit log to a plain text file (timestamps are normalized to local time).

- Synopsis: `npmp-cli audit-log [--out FILE]`
- Options:
  - `--out, -o FILE` (default: `audit.log`)

#### `schema`

Fetch `/api/schema` (OpenAPI) and write it as JSON.

- Synopsis: `npmp-cli schema [--out FILE|-]`
- Options:
  - `--out, -o FILE` (default: `schema.json`; use `-` for stdout)

#### `load`

Load one or more saved JSON files into NPMplus.

- Synopsis: `npmp-cli load [OPTIONS] INPUT...`
- Inputs:
  - One or more JSON files, or quoted globs (example: `'npmp-config/proxy-hosts__*.json'`)
- Options:
  - `--take-ownership` (delete+create if owned by different user)
  - `--dry-run` (preview; no server changes)

#### `sync-docker`

Scan Docker container labels and sync items to NPMplus.

- Synopsis: `npmp-cli sync-docker [OPTIONS]`
- Options:
  - `--take-ownership` (delete+create if owned by different user)
  - `--disable-orphans` (disable items owned by the authenticated user that are not present in docker specs)
  - `--delete-orphans` (delete items owned by the authenticated user that are not present in docker specs)
  - `--dry-run` (preview; no server changes)

#### `json-to-compose`

Convert saved JSON file(s) into docker-compose `labels:` YAML blocks.

- Synopsis: `npmp-cli json-to-compose [OPTIONS] INPUT.json [OUTPUT.yml]`
- Notes:
  - `OUTPUT.yml` can only be used when converting a single input file.
  - Item type is auto-detected from the filename pattern (`proxy-hosts__*`, `dead-hosts__*`, `redirection-hosts__*`, `streams__*`).
- Options:
  - `--service-name NAME` (defaults to first domain label, e.g. `app` from `app.example.com`)

### Resource command groups

Each group supports `list` and `show` (with `--json` for JSON output). Create/update/delete support `--dry-run`.

#### `proxy-host`

Manage proxy hosts.

- `npmp-cli proxy-host list [--json]`
- `npmp-cli proxy-host show IDENTIFIER [--json]` (identifier is id or domain)
- `npmp-cli proxy-host create [OPTIONS]`
  - Required: `--domain-names`, `--forward-scheme`, `--forward-host`, `--forward-port`
  - Optional fields:
    - `--access-list NAME` (empty string clears)
    - `--certificate NICE_NAME` (empty string clears)
    - `--ssl-forced/--no-ssl-forced`
    - `--caching-enabled/--no-caching-enabled`
    - `--block-exploits/--no-block-exploits`
    - `--allow-websocket-upgrade/--no-allow-websocket-upgrade`
    - `--http2-support/--no-http2-support`
    - `--hsts-enabled/--no-hsts-enabled`
    - `--hsts-subdomains/--no-hsts-subdomains`
    - `--advanced-config TEXT`
    - `--location TEXT` (repeatable; `path:scheme:host:port`)
    - `--enabled/--disabled` (default enabled)
    - `--dry-run`
- `npmp-cli proxy-host update IDENTIFIER [OPTIONS]`
  - Optional fields:
    - `--domain-names`, `--forward-scheme`, `--forward-host`, `--forward-port`
    - Same optional boolean/field switches as `create`
    - `--location TEXT` (repeatable; replaces locations)
    - `--enabled/--disabled`
    - `--take-ownership`
    - `--dry-run`
- `npmp-cli proxy-host delete IDENTIFIER [--force] [--dry-run]`
- `npmp-cli proxy-host enable IDENTIFIER`
- `npmp-cli proxy-host disable IDENTIFIER`

#### `dead-host`

Manage dead (404) hosts.

- `npmp-cli dead-host list [--json]`
- `npmp-cli dead-host show IDENTIFIER [--json]` (identifier is id or domain)
- `npmp-cli dead-host create [OPTIONS]`
  - Required: `--domain-names`
  - Optional: `--certificate`, `--ssl-forced/--no-ssl-forced`, `--http2-support/--no-http2-support`, `--hsts-enabled/--no-hsts-enabled`, `--hsts-subdomains/--no-hsts-subdomains`, `--advanced-config`, `--enabled/--disabled`, `--dry-run`
- `npmp-cli dead-host update IDENTIFIER [OPTIONS]`
  - Optional: same as create + `--take-ownership`
- `npmp-cli dead-host delete IDENTIFIER [--force] [--dry-run]`
- `npmp-cli dead-host enable IDENTIFIER`
- `npmp-cli dead-host disable IDENTIFIER`

#### `redirect-host`

Manage redirection hosts.

- `npmp-cli redirect-host list [--json]`
- `npmp-cli redirect-host show IDENTIFIER [--json]` (identifier is id or domain)
- `npmp-cli redirect-host create [OPTIONS]`
  - Required: `--domain-names`, `--forward-scheme`, `--forward-domain-name`, `--forward-http-code`
  - Optional: `--preserve-path/--no-preserve-path`, `--block-exploits/--no-block-exploits`, `--certificate`, `--ssl-forced/--no-ssl-forced`, `--http2-support/--no-http2-support`, `--hsts-enabled/--no-hsts-enabled`, `--hsts-subdomains/--no-hsts-subdomains`, `--advanced-config`, `--enabled/--disabled`, `--dry-run`
- `npmp-cli redirect-host update IDENTIFIER [OPTIONS]`
  - Optional: same as create + `--take-ownership`
- `npmp-cli redirect-host delete IDENTIFIER [--force] [--dry-run]`
- `npmp-cli redirect-host enable IDENTIFIER`
- `npmp-cli redirect-host disable IDENTIFIER`

#### `stream`

Manage streams.

- `npmp-cli stream list [--json]`
- `npmp-cli stream show IDENTIFIER [--json]` (identifier is id or incoming port)
- `npmp-cli stream create [OPTIONS]`
  - Required: `--incoming-port`, `--forwarding-host`, `--forwarding-port`
  - Optional: `--tcp-forwarding/--no-tcp-forwarding`, `--udp-forwarding/--no-udp-forwarding`, `--proxy-protocol-forwarding/--no-proxy-protocol-forwarding`, `--proxy-ssl/--no-proxy-ssl`, `--certificate`, `--enabled/--disabled`, `--dry-run`
- `npmp-cli stream update IDENTIFIER [OPTIONS]`
  - Optional: same as create + `--take-ownership`
- `npmp-cli stream delete IDENTIFIER [--force] [--dry-run]`
- `npmp-cli stream enable IDENTIFIER`
- `npmp-cli stream disable IDENTIFIER`

#### `access-list`

Manage access lists.

- `npmp-cli access-list list [--json]`
- `npmp-cli access-list show IDENTIFIER [--json]` (identifier is id or name)
- `npmp-cli access-list create [OPTIONS]`
  - Required: `--name`
  - Optional:
    - `--satisfy-any/--satisfy-all` (default satisfy-any)
    - `--pass-auth/--no-pass-auth`
    - `--allow IP_OR_CIDR` (repeatable)
    - `--deny IP_OR_CIDR` (repeatable)
    - `--auth-user USERNAME:PASSWORD` (repeatable)
    - `--dry-run`
- `npmp-cli access-list update IDENTIFIER [OPTIONS]`
  - Optional: same as create
- `npmp-cli access-list delete IDENTIFIER [--force] [--dry-run]`

#### `certificate`

Manage certificates (read-only + delete).

- `npmp-cli certificate list [--json]`
- `npmp-cli certificate show IDENTIFIER` (identifier is id or nice_name)
- `npmp-cli certificate delete IDENTIFIER [--force] [--dry-run]`

#### `settings`

Manage server settings (read-only).

- `npmp-cli settings list [--json]`
- `npmp-cli settings show SETTING_ID`

## Sync from Docker labels

This feature scans Docker containers and creates/updates NPMplus resources (proxy-hosts, dead-hosts, redirection-hosts, streams) based on container labels.

See [cli-examples.md](cli-examples.md) for working examples.

### Label schema

Labels follow this pattern:

- `npmp.<type>[N].<field>`

Where:

- `<type>`: `proxy`, `dead`, `redirect`, `stream`
- `[N]`: optional numeric suffix (1, 2, 3...) for multiple items of same type per container
- `<field>`: field name

The label prefix defaults to `npmp.` and can be changed via `NPMP_DOCKER_LABEL_PREFIX` (must end with `.`).

### Proxy-host labels

| Label | Required | Description |
| --- | --- | --- |
| `npmp.proxy[N].domain_names` | yes | Domain names (comma-separated list) |
| `npmp.proxy[N].forward_scheme` | yes | Scheme |
| `npmp.proxy[N].forward_host` | yes | Forward hostname / IP |
| `npmp.proxy[N].forward_port` | yes | Forward port |
| `npmp.proxy[N].access_list` | no | Access list |
| `npmp.proxy[N].allow_websocket_upgrade` | no | Enable websocket upgrade (true/false) |
| `npmp.proxy[N].block_exploits` | no | Block common exploits (true/false) |
| `npmp.proxy[N].caching_enabled` | no | Cache assets (true/false) |
| `npmp.proxy[N].certificate` | no | TLS certificate (certificate nice_name) |
| `npmp.proxy[N].ssl_forced` | no | Force HTTPS (true/false) |
| `npmp.proxy[N].http2_support` | no | HTTP/3 support (true/false) |
| `npmp.proxy[N].hsts_enabled` | no | HSTS enabled (true/false) |
| `npmp.proxy[N].hsts_subdomains` | no | HSTS sub-domains (true/false) |
| `npmp.proxy[N].loc[N]_path` | no | Custom locations |
| `npmp.proxy[N].loc[N]_forward_scheme` | no | Custom location scheme |
| `npmp.proxy[N].loc[N]_forward_host` | no | Custom location forward hostname / IP |
| `npmp.proxy[N].loc[N]_forward_port` | no | Custom location forward port |
| `npmp.proxy[N].advanced_config` | no | Custom Nginx configuration |
| `npmp.proxy[N].enabled` | no | Enabled (true/false) |

### Dead/404 host labels

| Label | Required | Description |
| --- | --- | --- |
| `npmp.dead[N].domain_names` | yes | Domain names (comma-separated list) |
| `npmp.dead[N].certificate` | no | TLS certificate |
| `npmp.dead[N].ssl_forced` | no | Force HTTPS (true/false) |
| `npmp.dead[N].http2_support` | no | HTTP/3 support (true/false) |
| `npmp.dead[N].hsts_enabled` | no | HSTS enabled (true/false) |
| `npmp.dead[N].hsts_subdomains` | no | HSTS sub-domains (true/false) |
| `npmp.dead[N].advanced_config` | no | Custom Nginx configuration |
| `npmp.dead[N].enabled` | no | Enabled (true/false) |

### Redirection-host labels

| Label | Required | Description |
| --- | --- | --- |
| `npmp.redirect[N].domain_names` | yes | Domain names (comma-separated) |
| `npmp.redirect[N].forward_scheme` | yes | Scheme |
| `npmp.redirect[N].forward_domain_name` | yes | Forward domain |
| `npmp.redirect[N].forward_http_code` | yes | HTTP code (301, 302, ...) |
| `npmp.redirect[N].preserve_path` | no | Preserve path (true/false) |
| `npmp.redirect[N].block_exploits` | no | Block common exploits (true/false) |
| `npmp.redirect[N].certificate` | no | TLS certificate (certificate nice_name) |
| `npmp.redirect[N].ssl_forced` | no | Force HTTPS (true/false) |
| `npmp.redirect[N].http2_support` | no | HTTP/3 support (true/false) |
| `npmp.redirect[N].hsts_enabled` | no | HSTS enabled (true/false) |
| `npmp.redirect[N].hsts_subdomains` | no | HSTS sub-domains (true/false) |
| `npmp.redirect[N].advanced_config` | no | Custom Nginx configuration |
| `npmp.redirect[N].enabled` | no | Enabled (true/false) |

### Stream labels

| Label | Required | Description |
| --- | --- | --- |
| `npmp.stream[N].incoming_port` | yes | Incoming port |
| `npmp.stream[N].forwarding_host` | yes | Forward host |
| `npmp.stream[N].forwarding_port` | yes | Forward port |
| `npmp.stream[N].tcp_forwarding` | no | TCP (true/false) |
| `npmp.stream[N].udp_forwarding` | no | UDP (true/false) |
| `npmp.stream[N].proxy_protocol_forwarding` | no | Proxy protocol forwarding (true/false) |
| `npmp.stream[N].certificate` | no | TLS certificate (certificate nice_name) |
| `npmp.stream[N].enabled` | no | Enabled (true/false) |

## Where to find runnable examples

- [cli-examples.md](cli-examples.md) contains examples for every command and subcommand.
- For CLI built-in help, run `npmp-cli --help` and `npmp-cli COMMAND --help`.
