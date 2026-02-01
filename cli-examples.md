# npmp-cli examples

This file is a copy/paste cookbook for all available `npmp-cli` commands.

## Common setup

### Auth + server

You must provide:

- `NPMP_BASE_URL` (example: `https://npm.example.com`)
- `NPMP_IDENTITY` + `NPMP_SECRET`

Examples:

```bash
export NPMP_BASE_URL="https://npm.example.com"
export NPMP_IDENTITY="bot"
export NPMP_SECRET="changeme"
```

### Config file (.env)

By default the CLI loads `.env`. Override with:

```bash
npmp-cli --config .env.prod save
```

### Logging

Examples:

```bash
npmp-cli --log-level DEBUG save
npmp-cli --log-file ./npmp-cli.log save
npmp-cli --log-file ./logs/ save
```

## Top-level commands

### save

Save all NPMplus items (proxy hosts, redirection hosts, dead hosts, streams, access lists) as JSON files.

```bash
npmp-cli save
npmp-cli save --out npmp-config
npmp-cli --config .env.prod save --out ./backups/npmp-config
```

### audit-log

Export NPMplus audit log to plain text.

```bash
npmp-cli audit-log
npmp-cli audit-log --out ./audit.log
```

### schema

Fetch `/api/schema` (OpenAPI) and write it as JSON.

```bash
npmp-cli schema
npmp-cli schema --out ./schema.json
npmp-cli schema --out -
```

### load

Load one or more saved JSON files into NPMplus.

```bash
npmp-cli load npmp-config/proxy-hosts__125.json
npmp-cli load 'npmp-config/*.json'
npmp-cli load 'npmp-config/*.json' --dry-run
npmp-cli load 'npmp-config/*.json' --take-ownership
```

### sync-docker

Scan Docker container labels and sync items to NPMplus.

```bash
npmp-cli sync-docker
npmp-cli sync-docker --dry-run
npmp-cli sync-docker --take-ownership

# Orphan handling is scoped to the authenticated owner
npmp-cli sync-docker --disable-orphans
npmp-cli sync-docker --delete-orphans
```

### json-to-compose

Convert saved JSON files to docker-compose `labels:` YAML blocks.

```bash
npmp-cli json-to-compose npmp-config/proxy-hosts__125.json
npmp-cli json-to-compose 'npmp-config/proxy-hosts__*.json'
npmp-cli json-to-compose npmp-config/proxy-hosts__125.json --service-name app

# Convert a single input file and write to OUTPUT.yml
npmp-cli json-to-compose npmp-config/proxy-hosts__125.json ./labels.yml
```

## proxy-host

Manage proxy hosts.

### proxy-host list

```bash
npmp-cli proxy-host list
npmp-cli proxy-host list --json
```

### proxy-host show

Default output is a readable top-level view; use `--json` for full payload.

```bash
npmp-cli proxy-host show 125
npmp-cli proxy-host show app.example.com
npmp-cli proxy-host show app.example.com --json
```

### proxy-host create

```bash
npmp-cli proxy-host create \
  --domain-names 'app.example.com,www.app.example.com' \
  --forward-scheme http \
  --forward-host 10.0.0.10 \
  --forward-port 8080

# With certificate + access list
npmp-cli proxy-host create \
  --domain-names 'app.example.com' \
  --forward-scheme http \
  --forward-host 10.0.0.10 \
  --forward-port 8080 \
  --certificate 'LetsEncrypt Wildcard' \
  --access-list 'Office Only'

# Replace locations (path:scheme:host:port)
npmp-cli proxy-host create \
  --domain-names 'app.example.com' \
  --forward-scheme http \
  --forward-host 10.0.0.10 \
  --forward-port 8080 \
  --location '/api:http:10.0.0.11:8081' \
  --location '/static:http:10.0.0.12:8082'

# Preview only
npmp-cli proxy-host create \
  --domain-names 'app.example.com' \
  --forward-scheme http \
  --forward-host 10.0.0.10 \
  --forward-port 8080 \
  --dry-run
```

### proxy-host update

```bash
npmp-cli proxy-host update app.example.com --forward-host 10.0.0.20
npmp-cli proxy-host update 125 --enabled
npmp-cli proxy-host update 125 --disabled

# Take ownership (delete+recreate) if owned by a different user
npmp-cli proxy-host update app.example.com --take-ownership --forward-port 8081

# Replace locations
npmp-cli proxy-host update app.example.com \
  --location '/api:http:10.0.0.11:8081' \
  --location '/static:http:10.0.0.12:8082'

# Preview only
npmp-cli proxy-host update app.example.com --forward-host 10.0.0.20 --dry-run
```

### proxy-host delete

```bash
npmp-cli proxy-host delete 125
npmp-cli proxy-host delete app.example.com
npmp-cli proxy-host delete app.example.com --dry-run

# Ignore missing items
npmp-cli proxy-host delete app.example.com --force
```

### proxy-host enable / disable

```bash
npmp-cli proxy-host enable 125
npmp-cli proxy-host disable app.example.com
```

## dead-host

Manage dead hosts.

### dead-host list

```bash
npmp-cli dead-host list
npmp-cli dead-host list --json
```

### dead-host show

```bash
npmp-cli dead-host show 3
npmp-cli dead-host show dead.example.com
npmp-cli dead-host show dead.example.com --json
```

### dead-host create

```bash
npmp-cli dead-host create --domain-names 'dead.example.com'
npmp-cli dead-host create --domain-names 'dead.example.com' --disabled
npmp-cli dead-host create --domain-names 'dead.example.com' --dry-run
```

### dead-host update

```bash
npmp-cli dead-host update dead.example.com --enabled
npmp-cli dead-host update dead.example.com --disabled
npmp-cli dead-host update 3 --domain-names 'dead.example.com,dead2.example.com'
npmp-cli dead-host update dead.example.com --take-ownership --dry-run
```

### dead-host delete

```bash
npmp-cli dead-host delete 3
npmp-cli dead-host delete dead.example.com --dry-run
npmp-cli dead-host delete dead.example.com --force
```

### dead-host enable / disable

```bash
npmp-cli dead-host enable dead.example.com
npmp-cli dead-host disable 3
```

## redirect-host

Manage redirection hosts.

### redirect-host list

```bash
npmp-cli redirect-host list
npmp-cli redirect-host list --json
```

### redirect-host show

```bash
npmp-cli redirect-host show 7
npmp-cli redirect-host show old.example.com
npmp-cli redirect-host show old.example.com --json
```

### redirect-host create

```bash
npmp-cli redirect-host create \
  --domain-names 'old.example.com' \
  --forward-scheme https \
  --forward-domain-name 'new.example.com' \
  --forward-http-code 301

npmp-cli redirect-host create \
  --domain-names 'old.example.com' \
  --forward-scheme https \
  --forward-domain-name 'new.example.com' \
  --forward-http-code 302 \
  --preserve-path

npmp-cli redirect-host create \
  --domain-names 'old.example.com' \
  --forward-scheme https \
  --forward-domain-name 'new.example.com' \
  --forward-http-code 301 \
  --dry-run
```

### redirect-host update

```bash
npmp-cli redirect-host update old.example.com --forward-http-code 302
npmp-cli redirect-host update 7 --disabled
npmp-cli redirect-host update old.example.com --take-ownership --dry-run
```

### redirect-host delete

```bash
npmp-cli redirect-host delete 7
npmp-cli redirect-host delete old.example.com --dry-run
npmp-cli redirect-host delete old.example.com --force
```

### redirect-host enable / disable

```bash
npmp-cli redirect-host enable old.example.com
npmp-cli redirect-host disable 7
```

## stream

Manage streams.

### stream list

```bash
npmp-cli stream list
npmp-cli stream list --json
```

### stream show

Identifier can be the stream id or incoming port.

```bash
npmp-cli stream show 12
npmp-cli stream show 25565
npmp-cli stream show 25565 --json
```

### stream create

```bash
npmp-cli stream create \
  --incoming-port 25565 \
  --forwarding-host 10.0.0.50 \
  --forwarding-port 25565

npmp-cli stream create \
  --incoming-port 51820 \
  --forwarding-host 10.0.0.60 \
  --forwarding-port 51820 \
  --udp-forwarding

npmp-cli stream create \
  --incoming-port 25565 \
  --forwarding-host 10.0.0.50 \
  --forwarding-port 25565 \
  --dry-run
```

### stream update

```bash
npmp-cli stream update 25565 --forwarding-host 10.0.0.51
npmp-cli stream update 12 --disabled
npmp-cli stream update 25565 --take-ownership --dry-run
```

### stream delete

```bash
npmp-cli stream delete 12
npmp-cli stream delete 25565 --dry-run
npmp-cli stream delete 25565 --force
```

### stream enable / disable

```bash
npmp-cli stream enable 25565
npmp-cli stream disable 12
```

## access-list

Manage access lists.

### access-list list

```bash
npmp-cli access-list list
npmp-cli access-list list --json
```

### access-list show

```bash
npmp-cli access-list show 1
npmp-cli access-list show 'Office Only'
npmp-cli access-list show 'Office Only' --json
```

### access-list create

```bash
npmp-cli access-list create --name 'Office Only' --allow 192.168.1.0/24

# Multiple allow/deny entries
npmp-cli access-list create \
  --name 'Office Only' \
  --allow 192.168.1.0/24 \
  --allow 10.0.0.0/8 \
  --deny 0.0.0.0/0

# Basic auth users (username:password)
npmp-cli access-list create \
  --name 'Admins' \
  --auth-user 'admin:changeme'

# Preview only
npmp-cli access-list create --name 'Office Only' --allow 192.168.1.0/24 --dry-run
```

### access-list update

```bash
npmp-cli access-list update 'Office Only' --allow 192.168.1.0/24
npmp-cli access-list update 1 --name 'Office Only'
npmp-cli access-list update 1 --dry-run
```

### access-list delete

```bash
npmp-cli access-list delete 1
npmp-cli access-list delete 'Office Only' --dry-run
npmp-cli access-list delete 'Office Only' --force
```

## certificate

Manage certificates.

### certificate list

```bash
npmp-cli certificate list
npmp-cli certificate list --json
```

### certificate show

```bash
npmp-cli certificate show 5
npmp-cli certificate show 'LetsEncrypt Wildcard'
```

### certificate delete

```bash
npmp-cli certificate delete 5
npmp-cli certificate delete 'LetsEncrypt Wildcard' --dry-run
npmp-cli certificate delete 'LetsEncrypt Wildcard' --force
```

## settings

Manage server settings.

### settings list

```bash
npmp-cli settings list
npmp-cli settings list --json
```

### settings show

```bash
npmp-cli settings show default-site
npmp-cli settings show backend-log-level
```
