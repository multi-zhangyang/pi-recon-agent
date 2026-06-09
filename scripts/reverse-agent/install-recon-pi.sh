#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(pwd)}"
BIN_DIR="${2:-$HOME/.local/bin}"
if [ ! -x "$ROOT/pi" ]; then
  echo "missing executable $ROOT/pi" >&2
  exit 1
fi
mkdir -p "$BIN_DIR"
CURRENT_PI="$(command -v pi || true)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [ -n "$CURRENT_PI" ] && [ "$(readlink -f "$CURRENT_PI" 2>/dev/null || printf '%s' "$CURRENT_PI")" != "$(readlink -f "$ROOT/pi")" ]; then
  BACKUP_NOTE="$BIN_DIR/pi-upstream.$STAMP.path"
  {
    echo "original_command=$CURRENT_PI"
    echo "original_resolved=$(readlink -f "$CURRENT_PI" 2>/dev/null || true)"
    ls -l "$CURRENT_PI" 2>/dev/null || true
  } > "$BACKUP_NOTE"
fi
replace_pi_candidate() {
  local candidate="$1"
  [ -n "$candidate" ] || return 0
  [ -e "$candidate" ] || [ -L "$candidate" ] || return 0
  local resolved_candidate resolved_recon backup_link backup_note
  resolved_candidate="$(readlink -f "$candidate" 2>/dev/null || printf '%s' "$candidate")"
  resolved_recon="$(readlink -f "$ROOT/pi")"
  [ "$resolved_candidate" != "$resolved_recon" ] || return 0
  backup_link="$(dirname "$candidate")/pi-upstream.$STAMP"
  backup_note="$(dirname "$candidate")/pi-upstream.$STAMP.path"
  ln -sfn "$resolved_candidate" "$backup_link"
  {
    echo "original_command=$candidate"
    echo "original_resolved=$resolved_candidate"
    echo "backup_link=$backup_link"
    ls -l "$candidate" 2>/dev/null || true
  } > "$backup_note"
  rm -f "$candidate"
  ln -s "$ROOT/pi" "$candidate"
  echo "$candidate -> $ROOT/pi (upstream backup: $backup_link)"
}

ln -sfn "$ROOT/pi" "$BIN_DIR/pi"
NPM_PREFIX="$(npm prefix -g 2>/dev/null || true)"
if [ -n "$NPM_PREFIX" ]; then
  GLOBAL_UPSTREAM="$NPM_PREFIX/lib/node_modules/@earendil-works/pi-coding-agent"
  if [ -d "$GLOBAL_UPSTREAM" ]; then
    GLOBAL_BACKUP="$NPM_PREFIX/lib/node_modules/@earendil-works/pi-coding-agent.upstream-backup.$STAMP"
    mv "$GLOBAL_UPSTREAM" "$GLOBAL_BACKUP"
    echo "moved upstream global pi package -> $GLOBAL_BACKUP"
  fi
  replace_pi_candidate "$NPM_PREFIX/bin/pi"
  rm -f "$NPM_PREFIX/bin/pi"
  ln -s "$ROOT/pi" "$NPM_PREFIX/bin/pi"
fi
PI_OFFLINE=1 "$BIN_DIR/pi" --offline --help >/dev/null
cat <<MSG
Installed Pi-RECON as primary pi launcher:
  $BIN_DIR/pi -> $ROOT/pi
  ${NPM_PREFIX:+$NPM_PREFIX/bin/pi -> $ROOT/pi}

Runtime profile:
  ${PI_RECON_AGENT_DIR:-${PI_CODING_AGENT_DIR:-${REPI_CODING_AGENT_DIR:-$HOME/.repi/agent}}}

Smoke test:
  pi --offline --help
  pi --offline --list-models

If an upstream pi existed, its path was recorded as:
  ${BACKUP_NOTE:-none}
MSG
