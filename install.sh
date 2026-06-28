#!/usr/bin/env bash
# REPI installer.
#
# One-line (curl|bash) — clones from GitHub, installs deps, wires the launcher:
#   curl -fsSL https://raw.githubusercontent.com/multi-zhangyang/pi-recon-agent/main/install.sh | bash
#   curl -fsSL .../install.sh | bash -s -- --prefix /opt/repi --system
#
# Local refresh — run inside an existing checkout (idempotent, no clone):
#   bash install.sh
#   bash install.sh --skip-npm
#
# Options:
#   --prefix <dir>   Clone/install location for curl|bash mode (default ~/.repi-src).
#   --user           Launcher into ~/.local/bin (default).
#   --system         Launcher into /usr/local/bin (needs sudo).
#   --bin-dir <dir>  Launcher into a custom directory.
#   --branch <name>  Branch/commit to clone (default main).
#   --skip-npm       Do not run npm install (local refresh).
#   -h, --help       Show this help.
set -euo pipefail

REPO="https://github.com/multi-zhangyang/pi-recon-agent.git"
BRANCH="main"
PREFIX=""
BIN_ARGS=()
SKIP_NPM=0

usage() {
  sed -n '2,20p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' || cat <<'MSG'
REPI installer. See https://github.com/multi-zhangyang/pi-recon-agent#install
MSG
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="${2:-}"; [ -n "$PREFIX" ] || { echo "--prefix requires a value" >&2; exit 2; }; shift 2 ;;
    --branch) BRANCH="${2:-}"; [ -n "$BRANCH" ] || { echo "--branch requires a value" >&2; exit 2; }; shift 2 ;;
    --user|--system) BIN_ARGS+=("$1"); shift ;;
    --bin-dir) BIN_ARGS+=("$1" "${2:-}"); [ -n "${2:-}" ] || { echo "--bin-dir requires a value" >&2; exit 2; }; shift 2 ;;
    --skip-npm) SKIP_NPM=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# --- prerequisites --------------------------------------------------------
case "$(uname -s 2>/dev/null || echo unknown)" in
  Linux|Darwin) : ;;
  *) echo "REPI is tested on Linux/macOS. Proceeding, but YMMV." >&2 ;;
esac

if ! command -v git >/dev/null 2>&1; then
  echo "git is required. Install it first:" >&2
  echo "  Debian/Ubuntu: sudo apt-get install -y git" >&2
  echo "  macOS (brew):  brew install git" >&2
  exit 1
fi
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js >= 22.19 is required. Install it first:" >&2
  echo "  https://nodejs.org/  or  https://github.com/nvm-sh/nvm  (nvm install 22)" >&2
  exit 1
fi
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
if [ "$NODE_MAJOR" -lt 22 ] 2>/dev/null; then
  echo "Node.js >= 22.19 required (found $(node -v 2>/dev/null || echo unknown)). Upgrade via nvm: nvm install 22" >&2
  exit 1
fi
if [ "$SKIP_NPM" -eq 0 ] && ! command -v npm >/dev/null 2>&1; then
  echo "npm is required (comes with Node.js)." >&2
  exit 1
fi

# --- resolve ROOT: local refresh vs curl|bash clone -----------------------
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd 2>/dev/null || echo "")"
LOCAL_MODE=0
# A REPI checkout is identified by the `repi` launcher plus the packages/coding-agent
# workspace — robust against the root package.json being named "repi-monorepo".
if [ -n "$SELF_DIR" ] && [ -x "$SELF_DIR/repi" ] && [ -d "$SELF_DIR/packages/coding-agent" ] && [ -f "$SELF_DIR/package.json" ]; then
  ROOT="$SELF_DIR"
  LOCAL_MODE=1
fi

if [ "$LOCAL_MODE" -ne 1 ]; then
  PREFIX="${PREFIX:-$HOME/.repi-src}"
  if [ -d "$PREFIX/.git" ]; then
    echo "==> Updating existing REPI checkout at $PREFIX"
    git -C "$PREFIX" fetch --quiet origin
    git -C "$PREFIX" checkout "$BRANCH" -- 2>/dev/null || git -C "$PREFIX" checkout "$BRANCH"
    git -C "$PREFIX" pull --ff-only --quiet origin "$BRANCH" || git -C "$PREFIX" reset --hard "origin/$BRANCH"
  else
    echo "==> Cloning REPI into $PREFIX"
    mkdir -p "$(dirname "$PREFIX")"
    git clone --quiet --branch "$BRANCH" "$REPO" "$PREFIX"
  fi
  ROOT="$(cd "$PREFIX" && pwd)"
  if [ ! -x "$ROOT/repi" ]; then
    echo "missing executable $ROOT/repi after clone — repo may be corrupt" >&2
    exit 1
  fi
else
  echo "==> Local refresh from $ROOT"
fi

# --- deps -----------------------------------------------------------------
if [ "$SKIP_NPM" -eq 0 ]; then
  echo "==> Installing Node dependencies (this can take a few minutes)"
  (cd "$ROOT" && npm install --ignore-scripts --no-audit --no-fund)
else
  echo "==> Skipping npm install (--skip-npm)"
fi

# --- launcher + runtime profile ------------------------------------------
# No bin flag given: prefer /usr/local/bin when writable (already on PATH for
# root, so `repi` works in the current shell immediately); otherwise fall back
# to ~/.local/bin (install-repi.sh will auto-add it to the user's shell rc).
# Pass --user/--system/--bin-dir through untouched when explicitly given.
if [ "${#BIN_ARGS[@]}" -eq 0 ]; then
  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    BIN_ARGS=("--system")
  else
    BIN_ARGS=("--user")
  fi
fi
bash "$ROOT/scripts/reverse-agent/install-repi.sh" --root "$ROOT" "${BIN_ARGS[@]}"

# --- verify ---------------------------------------------------------------
echo "==> Verifying offline startup"
"$ROOT/repi" --offline --help >/dev/null 2>&1
"$ROOT/repi" --offline --list-models >/dev/null 2>&1

# --- PATH hint ------------------------------------------------------------
BIN_DIR=""
DISPLAY_DIR=""
case " ${BIN_ARGS[*]} " in
  *" --system "*) BIN_DIR="/usr/local/bin"; DISPLAY_DIR="$BIN_DIR" ;;
  *" --bin-dir "*) for i in "${!BIN_ARGS[@]}"; do [ "${BIN_ARGS[$i]}" = "--bin-dir" ] && BIN_DIR="${BIN_ARGS[$((i+1))]}" && break; done; DISPLAY_DIR="$BIN_DIR" ;;
  *) BIN_DIR="$HOME/.local/bin"; DISPLAY_DIR="~/.local/bin" ;;
esac
PATH_HINT=""
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *) PATH_HINT="  export PATH=\"$BIN_DIR:\$PATH\"   # add to your shell profile" ;;
esac

cat <<MSG

REPI install complete.
  source  : $ROOT
  launcher: $DISPLAY_DIR/repi
${PATH_HINT:+$PATH_HINT}

Next:
  repi --offline --help
  repi doctor
  repi model add --provider <id> --api openai-completions --base-url <url> --model <model>
  repi model login --provider <id> --api-key-stdin
  repi model test --provider <id> --model <model>
  repi bootstrap    # (optional) install RE toolchain: gdb/binwalk/pwntools/...
MSG
