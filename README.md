# npmp-cli

Small Python toolkit to talk to **NPMplus** ([ZoeyVid/NPMplus](https://github.com/ZoeyVid/NPMplus)).

## Features

- Export NPMplus resources (proxy-hosts, redirection-hosts, dead-hosts, streams, access-lists) to JSON files
- Import JSON configurations back into NPMplus (can be used for migration).
- Users and certificates are not exported/imported, they must be handled manually
- Save the NPMplus OpenAPI schema, for reference
- Sync Docker container labels to NPMplus proxy items (this is Caddy Docker Proxy or Traefik style declarative configuration via Docker labels)
- Optionally disable or delete proxy items that no longer have corresponding Docker containers (only those owned by specific user)
- Convert saved JSON files into docker-compose YAML `labels:` blocks, for easy copy-paste into your container definitions

## Install

```bash
python -m venv .venv
.venv/bin/python -m pip install -e .
```

For development:

```bash
.venv/bin/python -m pip install -e '.[dev]'
```

## Usage

Use `run.sh` to invoke the CLI:

for example:

```bash
./run.sh save --help
./run.sh sync-docker --dry-run
./run.sh json-to-compose npmp-config/proxy-hosts__*.json
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
| `NPMP_LOG_CONSOLE_STREAM` | Console log stream: `stderr` (default) or `stdout` | `stderr` |
| `NPMP_LOG_FILE` | Optional log file path (existing directory or path ending with `/` logs to `<dir>/npmp-cli.log`) | |
| `NPMP_LOG_FILE_LEVEL` | Logging level for file logging (defaults to `NPMP_LOG_LEVEL`) | |
| `NPMP_HTTP_RETRY_COUNT` | Retry count for transient httpx disconnect/transport errors (total attempts = retries + 1) | `3` |
| `NPMP_ENV_FILE` | Path to an alternative .env file | `.env` |
| `NPMP_DOCKER_LABEL_PREFIX` | Prefix for docker labels (must end with `.`) | `npmp.` |
| `DOCKER_HOST` | Docker connection URL | local socket |

## Command Reference

| Command | Description |
| --- | --- |
| `save [--out PATH]` | Export resources to JSON files |
| `load [--takeownership] [--dry-run] INPUT...` | Import JSON configs into NPMplus |
| `schema [--out PATH]` | Save OpenAPI schema |
| `sync-docker [--takeownership] [--disable-orphans] [--delete-orphans] [--dry-run]` | Sync Docker labels to NPMplus |
| `json-to-compose [--service-name TEXT] INPUT.json [OUTPUT.yml]` | Convert JSON to compose labels |

Global options: `--log-level`, `--log-console-stream`, `--log-file`, `--log-file-level`

Examples:

```bash
npmp-cli save --out ./npmp-config
npmp-cli load --takeownership './npmp-config/proxy-hosts__*.json'
npmp-cli sync-docker --takeownership --disable-orphans
npmp-cli json-to-compose ./npmp-config/proxy-hosts__62.json
```

## Sync from Docker Labels

Scans all Docker containers and creates/updates NPMplus resources (proxy-hosts, dead-hosts, redirection-hosts, streams) based on container labels.

Easiest way to migrate NPMplus config to Docker labels is to first export existing config to JSON files via `npmp-cli save`, then convert those JSON files to docker-compose YAML labels blocks via `npmp-cli json-to-compose`, and finally copy-paste the generated labels into your container definitions.

### Label Schema

Labels follow the pattern: `npmp.<type>[N].<field>`

- `<type>`: `proxy`, `dead`, `redirect`, `stream`
- `[N]`: optional numeric suffix (1, 2, 3...) for multiple items of same type per container
- `<field>`: field name

### Proxy-Host Labels

| Label | Required | Description |
| --- | --- | --- |
| `npmp.proxy[N].domain_names` | yes | **Domain Names** (comma-separated list) |
| `npmp.proxy[N].forward_scheme` | yes | **Scheme** |
| `npmp.proxy[N].forward_host` | yes | **Forward Hostname / IP** |
| `npmp.proxy[N].forward_port` | yes | **Forward Port** |
| `npmp.proxy[N].access_list` | no | **Access List** |
| `npmp.proxy[N].allow_websocket_upgrade` | no | **Enable fancyindex/compression** (true/false) |
| `npmp.proxy[N].block_exploits` | no | **Block Common Exploits** (true/false) |
| `npmp.proxy[N].caching_enabled` | no | **Cache Assets** (true/false) |
| `npmp.proxy[N].certificate` | no | **TLS Certificate** (certificate nice_name) |
| `npmp.proxy[N].ssl_forced` | no | **Force HTTPS** (true/false) |
| `npmp.proxy[N].http2_support` | no | **HTTP/3 Support** (true/false) |
| `npmp.proxy[N].hsts_enabled` | no | **HSTS Enabled** (true/false) |
| `npmp.proxy[N].hsts_subdomains` | no | **HSTS Sub-domains** (true/false) |
| `npmp.proxy[N].loc[N]_path` | no | **Custom Locations** |
| `npmp.proxy[N].loc[N]_forward_scheme` | no | **CL Scheme** |
| `npmp.proxy[N].loc[N]_forward_host` | no | **CL Forward Hostname / IP** |
| `npmp.proxy[N].loc[N]_forward_port` | no | **CL Forward Port** |
| `npmp.proxy[N].advanced_config` | no | **Custom Nginx Configuration** |
| `npmp.proxy[N].enabled` | no | **Enabled** (true/false) |

### Dead/404 Host Labels

| Label | Required | Description |
| --- | --- | --- |
| `npmp.dead[N].domain_names` | yes | **Domain Names** (comma-separated list) |
| `npmp.dead[N].certificate` | no | **TLS Certificate** |
| `npmp.dead[N].ssl_forced` | no | **Force HTTPS** (true/false) |
| `npmp.dead[N].http2_support` | no | **HTTP/3 Support** (true/false) |
| `npmp.dead[N].hsts_enabled` | no | **HSTS Enabled** (true/false) |
| `npmp.dead[N].hsts_subdomains` | no | **HSTS Sub-domains** (true/false) |
| `npmp.dead[N].advanced_config` | no | **Custom Nginx Configuration** |
| `npmp.dead[N].enabled` | no | **Enabled** (true/false) |

### Redirection-Host Labels

| Label | Required | Description |
| --- | --- | --- |
| `npmp.redirect[N].domain_names` | yes | **Domain Names** (comma-separated domain names) |
| `npmp.redirect[N].forward_scheme` | yes | **Scheme** |
| `npmp.redirect[N].forward_domain_name` | yes | **Forward Domain** |
| `npmp.redirect[N].forward_http_code` | yes | **HTTP Code** (HTTP redirect code 301, 302 etc) |
| `npmp.redirect[N].preserve_path` | no | **Preserve Path** (true/false) |
| `npmp.redirect[N].block_exploits` | no | **Block Common Exploits** (true/false) |
| `npmp.redirect[N].certificate` | no | **TLS Certificate** (certificate nice_name) |
| `npmp.redirect[N].ssl_forced` | no | **Force HTTPS** (true/false) |
| `npmp.redirect[N].http2_support` | no | **HTTP/3 Support** (true/false) |
| `npmp.redirect[N].hsts_enabled` | no | **HSTS Enabled** (true/false) |
| `npmp.redirect[N].hsts_subdomains` | no | **HSTS Sub-domains** (true/false) |
| `npmp.redirect[N].advanced_config` | no | **Custom Nginx Configuration** |
| `npmp.redirect[N].enabled` | no | **Enabled** (true/false) |

### Stream Labels

| Label | Required | Description |
| --- | --- | --- |
| `npmp.stream[N].incoming_port` | yes | **Incoming Port** |
| `npmp.stream[N].forwarding_host` | yes | **Forward Host** |
| `npmp.stream[N].forwarding_port` | yes | **Forward Port** |
| `npmp.stream[N].tcp_forwarding` | no | **TCP** (true/false) |
| `npmp.stream[N].udp_forwarding` | no | **UDP** (true/false) |
| `npmp.stream[N].proxy_protocol_forwarding` | no | **Proxy Protocol** (true/false) |
| `npmp.stream[N].certificate` | no | **TLS Certificate** (certificate nice_name) |
| `npmp.stream[N].enabled` | no | **Enabled** (true/false) |

### Example

docker-compose.yml:

```yaml
services:
  app:
    image: ghcr.io/example/app:latest
    labels:
      # Proxy host
      npmp.proxy.domain_names: "xyz.com,www.xyz.com"
      npmp.proxy.forward_host: "appserver.local"
      npmp.proxy.forward_port: "8080"
      npmp.proxy.forward_scheme: "http"
      npmp.proxy.certificate: "my-cert"
      npmp.proxy.ssl_forced: "true"
      npmp.proxy.http2_support: "true"
      npmp.proxy.allow_websocket_upgrade: "true"
      # Stream (TCP proxy)
      npmp.stream.incoming_port: "5432"
      npmp.stream.forwarding_host: "db.local"
      npmp.stream.forwarding_port: "5432"
      npmp.stream.tcp_forwarding: "true"
```

**Multiple items of same type** (use numeric suffix):

```yaml
services:
  myapp:
    labels:
      # First proxy-host
      npmp.proxy1.domain_names: "app.example.com"
      npmp.proxy1.forward_host: "localhost"
      npmp.proxy1.forward_port: "8080"
      npmp.proxy1.forward_scheme: "http"
      npmp.proxy1.loc1_path: "/api"
      npmp.proxy1.loc1_forward_host: "api.local"
      npmp.proxy1.loc1_forward_port: "3000"
      npmp.proxy1.loc1_forward_scheme: "http"
      npmp.proxy1.loc2_path: "/static"
      npmp.proxy1.loc2_forward_host: "cdn.local"
      npmp.proxy1.loc2_forward_port: "80"
      npmp.proxy1.loc2_forward_scheme: "http"
      npmp.proxy1.loc3_path: "/static"
      npmp.proxy1.loc3_forward_host: "static.local"
      npmp.proxy1.loc3_forward_port: "8080"
      npmp.proxy1.loc3_forward_scheme: "http"
# Second proxy-host
      npmp.proxy2.domain_names: "api.example.com"
      npmp.proxy2.forward_host: "localhost"
      npmp.proxy2.forward_port: "3000"
      npmp.proxy2.forward_scheme: "http"
     
```

Run sync:

```bash
npmp-cli sync-docker
```

**Notes:**

- Matching is done by `domain_names` (order-insensitive). If a proxy host already exists with the same set of domains, it will be updated; otherwise it will be created.
- `--takeownership` deletes and recreates a matching proxy-host if it is owned by a different user.
- `--disable-orphans` proxy-hosts owned by the current user but not present in any docker container spec will be updated to `enabled=false` (useful when containers get decommissioned).
- `--delete-orphans` proxy-hosts owned by the current user but not present in any docker container spec will be deleted permanently.

## Credits and stuff

This project is a CLI tool for managing [NPMplus](https://github.com/ZoeyVid/NPMplus), which is itself a fork of [Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager).

Inspirations from:

- Caddy Docker Proxy <https://github.com/lucaslorentz/caddy-docker-proxy>
- Traefik <https://doc.traefik.io/traefik/providers/docker/>

- **Author**: [github.com/Jaano](https://github.com/Jaano)
- **License**: MIT License
