#!/bin/sh
set -eu

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
VENV_BIN="$ROOT_DIR/.venv/bin"

export NPMP_RUN_INTEGRATION="1"

echo "Running integration tests (NPMP_ENV_FILE=${NPMP_ENV_FILE:-<unset>}, NPMP_RUN_INTEGRATION=$NPMP_RUN_INTEGRATION)"

if [ -x "$VENV_BIN/python" ]; then
	exec "$VENV_BIN/python" -m pytest -vv -rA --durations=10 -m integration "$@"
fi

if [ -x "$VENV_BIN/pytest" ]; then
	exec "$VENV_BIN/pytest" -vv -rA --durations=10 -m integration "$@"
fi

echo "Error: .venv not found or not usable. Create it with: python -m venv .venv && .venv/bin/python -m pip install -e '.[dev]'" >&2
exit 2
