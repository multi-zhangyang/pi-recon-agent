#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(pwd)}"
ROOT="$(cd "$ROOT" && pwd)"
BIN_DIR="${2:-/usr/local/bin}"
if [ ! -x "$ROOT/repi" ]; then
  echo "missing executable $ROOT/repi" >&2
  exit 1
fi
mkdir -p "$BIN_DIR"

cleanup_stale_recon_pi() {
  local candidate="$1"
  [ -n "$candidate" ] || return 0
  [ -e "$candidate" ] || [ -L "$candidate" ] || return 0
  [ -e "$ROOT/pi" ] || return 0
  local resolved_candidate resolved_recon
  resolved_candidate="$(readlink -f "$candidate" 2>/dev/null || printf '%s' "$candidate")"
  resolved_recon="$(readlink -f "$ROOT/pi" 2>/dev/null || printf '%s' "$ROOT/pi")"
  if [ "$resolved_candidate" = "$resolved_recon" ]; then
    rm -f "$candidate"
    echo "removed stale REPI pi shim: $candidate"
  fi
}

# Do not install or overwrite `pi`. Only remove stale symlinks created by the old takeover installer.
cleanup_stale_recon_pi "$BIN_DIR/pi"
cleanup_stale_recon_pi "$HOME/.local/bin/pi"
NPM_PREFIX="$(npm prefix -g 2>/dev/null || true)"
if [ -n "$NPM_PREFIX" ]; then
  cleanup_stale_recon_pi "$NPM_PREFIX/bin/pi"
fi

ln -sfn "$ROOT/repi" "$BIN_DIR/repi"
node "$ROOT/scripts/reverse-agent/init-repi-profile.mjs" "$ROOT"
REPI_INIT_VERBOSE=1 "$ROOT/repi" --offline --help >/dev/null 2>&1
cat <<MSG
Installed REPI:
  launcher: $BIN_DIR/repi -> $ROOT/repi
  runtime : ${REPI_CODING_AGENT_DIR:-${REPI_AGENT_DIR:-$HOME/.repi/agent}}
  profile : built-in reverse/pentest kernel initialized

Next commands:
  repi --offline --help
  repi --offline --list-models
  repi --import-pi-auth --offline --list-models
MSG
