#!/bin/sh
set -eu

ROOT_DIR=$(cd "$(dirname "$0")" && pwd)
VENV_BIN="$ROOT_DIR/.venv/bin"

if [ -x "$ROOT_DIR/npmp-cli" ]; then
	exec "$ROOT_DIR/npmp-cli" "$@"
elif [ -x "$VENV_BIN/python" ]; then
	exec "$VENV_BIN/python" -m npmp_cli "$@"
else
	printf '%s\n' "Error: .venv not found or not usable. Create it with: python -m venv .venv && .venv/bin/python -m pip install -e ." >&2
	exit 2
fi
