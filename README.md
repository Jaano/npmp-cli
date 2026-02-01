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

## Documentation

- [cli-manual.md](cli-manual.md)
- [cli-examples.md](cli-examples.md)

## Install

### Pre-built binaries

Download the latest release for your platform from [GitHub releases](https://github.com/Jaano/npmp-cli/releases/)

### From source

```bash
python -m venv .venv
.venv/bin/python -m pip install -e .
```

## Quick run

```bash
npmp-cli --help
npmp-cli --config .env save
npmp-cli --config .env sync-docker --dry-run
```

## Safeguards (mass writes)

- Dry-run is a hard safety rail: `load --dry-run` and `sync-docker --dry-run` run the client in readonly mode, so `POST`/`PUT`/`DELETE` calls are not executed (they are only logged).
- Destructive actions are opt-in: orphan disabling/deletion never happens unless you pass `--disable-orphans` or `--delete-orphans`.
- Orphan handling is owner-scoped: `--disable-orphans` / `--delete-orphans` only target items owned by the currently authenticated user. If the CLI cannot determine the authenticated user, orphan handling is skipped.
- Cross-owner overwrite is explicit: `--take-ownership` is required to replace items owned by someone else (it does this by deleting and recreating the record under the current user).
- Local exports are written atomically: `save` writes JSON to a temp file and then replaces the destination path to avoid partial/corrupt files.

## Not in scope (what this CLI does not do)

- Does not export/import users or certificates (handle those separately in NPMplus).
- Does not manage global NPMplus settings.
- Does not touch NPMplus server files, database, or Docker volumes directly; it only uses the HTTP API.
- Does not manage the NPMplus deployment lifecycle (install/upgrade/restart) or run server-side scripts.

## Credits and stuff

This project is a CLI tool for managing [NPMplus](https://github.com/ZoeyVid/NPMplus), which is itself a fork of [Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager).

**Author**: [github.com/Jaano](https://github.com/Jaano)

Inspirations from:

- Caddy Docker Proxy <https://github.com/lucaslorentz/caddy-docker-proxy>
- Traefik <https://doc.traefik.io/traefik/providers/docker/>

**License**: [MIT License](LICENSE.txt)
