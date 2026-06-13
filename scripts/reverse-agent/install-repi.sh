#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'MSG'
Usage:
  install-repi.sh [ROOT] [BIN_DIR]
  install-repi.sh --root <repo> [--bin-dir <dir>|--user|--system]

Options:
  --root <repo>     REPI source checkout. Default: current directory.
  --bin-dir <dir>   Directory where the repi launcher symlink is written.
  --user            Install launcher into ~/.local/bin.
  --system          Install launcher into /usr/local/bin.
  -h, --help        Show this help.

If no bin directory is provided, the installer uses /usr/local/bin when it is
writable; otherwise it falls back to ~/.local/bin and prints a PATH hint.
MSG
}

ROOT=""
BIN_DIR=""
POSITIONAL=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root)
      ROOT="${2:-}"
      if [ -z "$ROOT" ]; then echo "--root requires a value" >&2; exit 2; fi
      shift 2
      ;;
    --bin-dir)
      BIN_DIR="${2:-}"
      if [ -z "$BIN_DIR" ]; then echo "--bin-dir requires a value" >&2; exit 2; fi
      shift 2
      ;;
    --user)
      BIN_DIR="$HOME/.local/bin"
      shift
      ;;
    --system)
      BIN_DIR="/usr/local/bin"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [ -z "$ROOT" ] && [ "${#POSITIONAL[@]}" -ge 1 ]; then ROOT="${POSITIONAL[0]}"; fi
if [ -z "$BIN_DIR" ] && [ "${#POSITIONAL[@]}" -ge 2 ]; then BIN_DIR="${POSITIONAL[1]}"; fi
ROOT="${ROOT:-$(pwd)}"
ROOT="$(cd "$ROOT" && pwd)"

if [ -z "$BIN_DIR" ]; then
  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    BIN_DIR="/usr/local/bin"
  else
    BIN_DIR="$HOME/.local/bin"
  fi
fi

if [ ! -x "$ROOT/repi" ]; then
  echo "missing executable $ROOT/repi" >&2
  exit 1
fi
mkdir -p "$BIN_DIR"

absolute_path() {
  local path="$1"
  local dir base
  dir="$(cd "$(dirname "$path")" && pwd)"
  base="$(basename "$path")"
  printf '%s/%s' "$dir" "$base"
}

cleanup_stale_recon_pi() {
  local candidate="$1"
  [ -n "$candidate" ] || return 0
  [ -e "$candidate" ] || [ -L "$candidate" ] || return 0
  [ -e "$ROOT/pi" ] || return 0
  local candidate_abs resolved_candidate resolved_recon
  candidate_abs="$(absolute_path "$candidate")"
  [ "$candidate_abs" != "$ROOT/pi" ] || return 0
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

REPI_LINK="$BIN_DIR/repi"
if [ "$(absolute_path "$REPI_LINK")" != "$ROOT/repi" ]; then
  ln -sfn "$ROOT/repi" "$REPI_LINK"
fi
node "$ROOT/scripts/reverse-agent/init-repi-profile.mjs" "$ROOT"
REPI_INIT_VERBOSE=1 "$ROOT/repi" --offline --help >/dev/null 2>&1
PATH_HINT=""
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) PATH_HINT="  PATH hint: export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
cat <<MSG
Installed REPI:
  launcher: $BIN_DIR/repi -> $ROOT/repi
  runtime : ${REPI_CODING_AGENT_DIR:-${REPI_AGENT_DIR:-$HOME/.repi/agent}}
  profile : built-in reverse/pentest kernel initialized
${PATH_HINT}

Next commands:
  repi commands
  repi --offline --help
  repi doctor
  repi model doctor
MSG
