#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(pwd)}"
ROOT="$(cd "$ROOT" && pwd)"
BIN_DIR="${2:-/usr/local/bin}"
cat >&2 <<'MSG'
install-recon-pi.sh is deprecated.
REPI no longer takes over the `pi` command. Installing the independent `repi` launcher instead.
MSG
exec "$ROOT/scripts/reverse-agent/install-repi.sh" "$ROOT" "$BIN_DIR"
