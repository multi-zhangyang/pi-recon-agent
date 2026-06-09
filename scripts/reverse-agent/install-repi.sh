#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(pwd)}"
BIN_DIR="${2:-/usr/local/bin}"
if [ ! -x "$ROOT/repi" ]; then
  echo "missing executable $ROOT/repi" >&2
  exit 1
fi
mkdir -p "$BIN_DIR"
ln -sfn "$ROOT/repi" "$BIN_DIR/repi"
REPI_INIT_VERBOSE=1 "$ROOT/repi" --offline --help >/dev/null
cat <<MSG
Installed repi launcher:
  $BIN_DIR/repi -> $ROOT/repi

Isolated profile:
  ${REPI_CODING_AGENT_DIR:-${REPI_AGENT_DIR:-$HOME/.repi/agent}}

Normal pi profile:
  $HOME/.pi/agent (not modified by install-repi.sh)

Optional one-way credential/model bootstrap:
  repi --import-pi-auth --offline --list-models

Smoke test:
  repi --offline --help
  repi --offline --list-models
MSG
