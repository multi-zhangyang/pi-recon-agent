#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(pwd)}"
ROOT="$(cd "$ROOT" && pwd)"
BIN_DIR="${2:-$HOME/.local/bin}"
if [ ! -x "$ROOT/pi" ]; then
  echo "missing executable $ROOT/pi" >&2
  exit 1
fi
mkdir -p "$BIN_DIR"
replace_pi_candidate() {
  local candidate="$1"
  [ -n "$candidate" ] || return 0
  [ -e "$candidate" ] || [ -L "$candidate" ] || return 0
  local resolved_candidate resolved_recon
  resolved_candidate="$(readlink -f "$candidate" 2>/dev/null || printf '%s' "$candidate")"
  resolved_recon="$(readlink -f "$ROOT/pi")"
  [ "$resolved_candidate" != "$resolved_recon" ] || return 0
  rm -f "$candidate"
  ln -s "$ROOT/pi" "$candidate"
  echo "$candidate -> $ROOT/pi (purged previous target: $resolved_candidate)"
}

ln -sfn "$ROOT/pi" "$BIN_DIR/pi"
NPM_PREFIX="$(npm prefix -g 2>/dev/null || true)"
if [ -n "$NPM_PREFIX" ]; then
  GLOBAL_PARENT="$NPM_PREFIX/lib/node_modules/@earendil-works"
  if [ -d "$GLOBAL_PARENT" ]; then
    while IFS= read -r -d '' pkg; do
      rm -rf "$pkg"
      echo "deleted upstream global pi package -> $pkg"
    done < <(find "$GLOBAL_PARENT" -maxdepth 1 -type d -name 'pi-coding-agent*' -print0)
  fi
  replace_pi_candidate "$NPM_PREFIX/bin/pi"
  rm -f "$NPM_PREFIX/bin/pi"
  ln -s "$ROOT/pi" "$NPM_PREFIX/bin/pi"
fi
if [ "${PI_RECON_KEEP_UPSTREAM_PROFILE:-0}" != "1" ] && [ -e "$HOME/.pi" ]; then
  rm -rf "$HOME/.pi"
  echo "deleted upstream/global pi profile -> $HOME/.pi"
fi
PI_OFFLINE=1 "$BIN_DIR/pi" --offline --help >/dev/null 2>&1
cat <<MSG
Installed Pi-RECON as primary pi launcher:
  $BIN_DIR/pi -> $ROOT/pi
  ${NPM_PREFIX:+$NPM_PREFIX/bin/pi -> $ROOT/pi}

Runtime profile:
  ${PI_RECON_AGENT_DIR:-${PI_CODING_AGENT_DIR:-${REPI_CODING_AGENT_DIR:-$HOME/.repi/agent}}}

Hard takeover:
  - upstream @earendil-works/pi-coding-agent global package directories are deleted
  - upstream ~/.pi profile is deleted unless PI_RECON_KEEP_UPSTREAM_PROFILE=1
  - PATH pi and npm-global pi both point at this repository launcher

Smoke test:
  pi --offline --help
  pi --offline --list-models
MSG
