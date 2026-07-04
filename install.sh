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
#   --user           Force launcher into ~/.local/bin.
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

print_done_bar() {
  printf '■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ 100%%\n'
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
    echo "INFO: Updating existing REPI checkout at $PREFIX"
    git -C "$PREFIX" fetch --quiet origin
    git -C "$PREFIX" checkout "$BRANCH" -- 2>/dev/null || git -C "$PREFIX" checkout "$BRANCH"
    git -C "$PREFIX" pull --ff-only --quiet origin "$BRANCH" || git -C "$PREFIX" reset --hard "origin/$BRANCH"
    print_done_bar
  else
    echo "INFO: Downloading REPI source into $PREFIX"
    mkdir -p "$(dirname "$PREFIX")"
    git clone --quiet --branch "$BRANCH" "$REPO" "$PREFIX"
    print_done_bar
  fi
  ROOT="$(cd "$PREFIX" && pwd)"
  if [ ! -x "$ROOT/repi" ]; then
    echo "missing executable $ROOT/repi after clone — repo may be corrupt" >&2
    exit 1
  fi
else
  echo "INFO: Refreshing REPI from $ROOT"
  print_done_bar
fi

# --- deps -----------------------------------------------------------------
if [ "$SKIP_NPM" -eq 0 ]; then
  echo "INFO: Installing Node dependencies (this can take a few minutes)"
  (cd "$ROOT" && npm install --ignore-scripts --no-audit --no-fund)
  print_done_bar
else
  echo "INFO: Skipping npm install (--skip-npm)"
fi

# --- launcher + runtime profile ------------------------------------------
# No bin flag given: pick a launcher dir that is ALREADY on $PATH so `repi`
# works immediately when possible. Preference order:
#   1. /usr/local/bin, /usr/local/sbin — standard PATH dirs; use sudo when the
#      user has it so a fresh install does not leave `repi` off PATH.
#   2. the first writable entry on $PATH that is not a system-critical dir.
#   3. ~/.local/bin — install-repi.sh creates shell rc files and adds PATH for
#      future shells, while printing the one-line export for the current shell.
# Explicit --user/--system/--bin-dir are passed through untouched.
path_contains_dir() {
  case ":${PATH:-}:" in *":$1:"*) return 0 ;; *) return 1 ;; esac
}

can_sudo_install() {
  command -v sudo >/dev/null 2>&1 || return 1
  sudo -n true >/dev/null 2>&1 && return 0
  [ -r /dev/tty ] || return 1
  echo "sudo is needed to install the repi launcher into /usr/local/bin" >&2
  sudo -v </dev/tty
}

if [ "${#BIN_ARGS[@]}" -eq 0 ]; then
  chosen=""
  for d in /usr/local/bin /usr/local/sbin; do
    path_contains_dir "$d" || continue
    if { [ -d "$d" ] || mkdir -p "$d" 2>/dev/null; } && [ -w "$d" ]; then
      chosen="$d"
      break
    fi
    if can_sudo_install; then
      chosen="$d"
      break
    fi
  done
  if [ -z "$chosen" ]; then
    IFS=':' read -ra _path_dirs <<<"${PATH:-}"
    for d in "${_path_dirs[@]}"; do
      case "$d" in ""|/bin|/usr/bin|/sbin|/usr/sbin) continue ;; esac
      [ -d "$d" ] && [ -w "$d" ] && chosen="$d" && break
    done
  fi
  if [ -n "$chosen" ]; then
    BIN_ARGS=("--bin-dir" "$chosen")
  else
    BIN_ARGS=("--user")
  fi
fi
REPI_INSTALL_EMBEDDED=1 bash "$ROOT/scripts/reverse-agent/install-repi.sh" --root "$ROOT" "${BIN_ARGS[@]}"

# --- verify ---------------------------------------------------------------
echo "INFO: Verifying offline startup"
"$ROOT/repi" --offline --help >/dev/null 2>&1
"$ROOT/repi" --offline --list-models >/dev/null 2>&1
print_done_bar

# --- PATH hint ------------------------------------------------------------
BIN_DIR=""
DISPLAY_DIR=""
case " ${BIN_ARGS[*]} " in
  *" --system "*) BIN_DIR="/usr/local/bin"; DISPLAY_DIR="$BIN_DIR" ;;
  *" --bin-dir "*) for i in "${!BIN_ARGS[@]}"; do [ "${BIN_ARGS[$i]}" = "--bin-dir" ] && BIN_DIR="${BIN_ARGS[$((i+1))]}" && break; done; DISPLAY_DIR="$BIN_DIR" ;;
  *) BIN_DIR="$HOME/.local/bin"; DISPLAY_DIR="~/.local/bin" ;;
esac
SOURCE_COMMAND=""
PATH_STATUS="Successfully linked repi in $DISPLAY_DIR (already on \$PATH)"
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *)
    RC_LINE="export PATH=\"$BIN_DIR:\$PATH\""
    RC_CONFIGURED_DISPLAY=""
    for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
      [ -f "$rc" ] || continue
      if grep -qF "$RC_LINE" "$rc" 2>/dev/null; then
        RC_CONFIGURED_DISPLAY="${RC_CONFIGURED_DISPLAY}~/${rc##*/} "
      fi
    done
    RC_CONFIGURED_DISPLAY="${RC_CONFIGURED_DISPLAY% }"
    if [ -n "$RC_CONFIGURED_DISPLAY" ]; then
      RC_PRIMARY=""
      case " $RC_CONFIGURED_DISPLAY " in
        *" ~/.bashrc "*) RC_PRIMARY="~/.bashrc"; SOURCE_COMMAND="source ~/.bashrc  # Load new PATH (or open a new terminal)" ;;
        *" ~/.zshrc "*) RC_PRIMARY="~/.zshrc"; SOURCE_COMMAND="source ~/.zshrc   # Load new PATH (or open a new terminal)" ;;
        *" ~/.profile "*) RC_PRIMARY="~/.profile"; SOURCE_COMMAND="source ~/.profile # Load new PATH (or open a new terminal)" ;;
      esac
      RC_PRIMARY="${RC_PRIMARY:-$RC_CONFIGURED_DISPLAY}"
      PATH_STATUS="Successfully added repi to \$PATH in $RC_PRIMARY"
    else
      PATH_STATUS="Installed repi to $DISPLAY_DIR; add it to \$PATH for direct command use"
      SOURCE_COMMAND="export PATH=\"$BIN_DIR:\$PATH\"  # Load repi for this shell"
    fi
    ;;
esac
REPI_VERSION="$(ROOT_PACKAGE_JSON="$ROOT/package.json" node -e 'try { console.log(require(process.env.ROOT_PACKAGE_JSON).version) } catch { console.log("unknown") }' 2>/dev/null || echo unknown)"

cat <<MSG

$PATH_STATUS

REPI $REPI_VERSION installed successfully, to start:

${SOURCE_COMMAND:+$SOURCE_COMMAND
}cd <project>  # Open directory
repi          # Run command

For more information visit https://github.com/multi-zhangyang/pi-recon-agent
MSG
