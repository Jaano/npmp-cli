#!/bin/sh
set -eu

ROOT_DIR=$(cd "$(dirname "$0")" && pwd)
VENV_BIN="$ROOT_DIR/.venv/bin"

NPMP_CLI=
if [ -x "$VENV_BIN/npmp-cli" ]; then
	NPMP_CLI="$VENV_BIN/npmp-cli"
elif [ -x "$VENV_BIN/python" ]; then
	NPMP_CLI="$VENV_BIN/python -m npmp_cli"
else
	echo "Error: .venv not found or not usable. Create it with: python -m venv .venv && .venv/bin/python -m pip install -e ." >&2
	exit 2
fi

exec $NPMP_CLI "$@"
