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

If no bin directory is provided, the installer prefers a launcher directory that
is already on PATH (/usr/local/bin when writable or sudo-able). If it must fall
back to ~/.local/bin, it creates the shell startup file and adds the PATH export
idempotently so future shells can run `repi` directly.
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

if [ ! -x "$ROOT/repi" ]; then
  echo "missing executable $ROOT/repi" >&2
  exit 1
fi

path_contains_dir() {
  local dir="$1"
  case ":${PATH:-}:" in
    *":$dir:"*) return 0 ;;
    *) return 1 ;;
  esac
}

shell_name() {
  basename "${SHELL:-}" 2>/dev/null || true
}

CAN_SUDO="unknown"
can_sudo() {
  case "$CAN_SUDO" in
    yes) return 0 ;;
    no) return 1 ;;
  esac

  if ! command -v sudo >/dev/null 2>&1; then
    CAN_SUDO="no"
    return 1
  fi
  if sudo -n true >/dev/null 2>&1; then
    CAN_SUDO="yes"
    return 0
  fi
  # curl|bash usually has stdin connected to the script pipe. sudo can still
  # prompt on /dev/tty; never let sudo read from the script stream.
  if [ -r /dev/tty ]; then
    echo "sudo is needed to install the repi launcher into /usr/local/bin" >&2
    if sudo -v </dev/tty; then
      CAN_SUDO="yes"
      return 0
    fi
  fi

  CAN_SUDO="no"
  return 1
}

can_prepare_dir_direct() {
  local dir="$1"
  { [ -d "$dir" ] || mkdir -p "$dir" 2>/dev/null; } && [ -w "$dir" ]
}

can_prepare_dir() {
  local dir="$1"
  can_prepare_dir_direct "$dir" || can_sudo
}

first_writable_path_dir() {
  local path_value="${PATH:-}"
  local old_ifs="$IFS"
  local dir
  IFS=':'
  for dir in $path_value; do
    IFS="$old_ifs"
    case "$dir" in
      ""|/bin|/usr/bin|/sbin|/usr/sbin) ;;
      *)
        if [ -d "$dir" ] && [ -w "$dir" ]; then
          printf '%s' "$dir"
          return 0
        fi
        ;;
    esac
    IFS=':'
  done
  IFS="$old_ifs"
  return 1
}

if [ -z "$BIN_DIR" ]; then
  if path_contains_dir /usr/local/bin && can_prepare_dir /usr/local/bin; then
    BIN_DIR="/usr/local/bin"
  elif path_contains_dir /usr/local/sbin && can_prepare_dir /usr/local/sbin; then
    BIN_DIR="/usr/local/sbin"
  else
    BIN_DIR="$(first_writable_path_dir || true)"
    BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
  fi
fi

USE_SUDO=0
if ! mkdir -p "$BIN_DIR" 2>/dev/null; then
  can_sudo || { echo "cannot create launcher directory: $BIN_DIR" >&2; exit 1; }
  sudo mkdir -p "$BIN_DIR"
  USE_SUDO=1
fi
if [ ! -w "$BIN_DIR" ]; then
  can_sudo || { echo "launcher directory is not writable: $BIN_DIR" >&2; exit 1; }
  USE_SUDO=1
fi

remove_path() {
  if [ "$USE_SUDO" -eq 1 ]; then
    sudo rm -f "$1"
  else
    rm -f "$1"
  fi
}

link_path() {
  if [ "$USE_SUDO" -eq 1 ]; then
    sudo ln -sfn "$1" "$2"
  else
    ln -sfn "$1" "$2"
  fi
}

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
    remove_path "$candidate"
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
  link_path "$ROOT/repi" "$REPI_LINK"
fi
node "$ROOT/scripts/reverse-agent/init-repi-profile.mjs" "$ROOT"
REPI_INIT_VERBOSE=1 "$ROOT/repi" --offline --help >/dev/null 2>&1

# If the launcher dir is not on PATH, add it to the user's shell rc files
# idempotently so future shells have `repi` available with no manual export.
# Only do this for user-local dirs (under $HOME) — never rewrite rc for a
# system dir like /usr/local/bin (already on PATH) and never touch rc when
# running with sudo (the rc would be root's, not the invoking user's).
BIN_ON_PATH=0
if path_contains_dir "$BIN_DIR"; then
  BIN_ON_PATH=1
fi

RC_LINE="export PATH=\"$BIN_DIR:\$PATH\""
RC_UPDATED=""
if [ "$BIN_ON_PATH" -ne 1 ] && [ "${SUDO_USER:-}" = "" ] && [ -n "$HOME" ]; then
  case "$BIN_DIR" in
    "$HOME"|"$HOME"/*)
      RC_FILES=("$HOME/.profile")
      current_shell="$(shell_name)"
      if [ -n "${BASH_VERSION:-}" ] || [ "$current_shell" = "bash" ]; then
        RC_FILES=("$HOME/.bashrc" "$HOME/.profile")
      elif [ -n "${ZSH_VERSION:-}" ] || [ "$current_shell" = "zsh" ]; then
        RC_FILES=("$HOME/.zshrc" "$HOME/.profile")
      fi
      for rc in "${RC_FILES[@]}"; do
        # Create the targeted rc files when missing. The previous installer only
        # edited existing files, which left minimal shells with a working
        # ~/.local/bin/repi symlink but no future-shell PATH entry.
        [ -f "$rc" ] || : > "$rc"
        if ! grep -qF "$RC_LINE" "$rc" 2>/dev/null; then
          printf '\n# Added by repi install\n%s\n' "$RC_LINE" >> "$rc"
          RC_UPDATED="${RC_UPDATED}${rc##*/} "
        fi
      done
      ;;
  esac
fi

PATH_HINT=""
PATH_STATUS=""
SOURCE_COMMAND=""
if [ "$BIN_ON_PATH" -ne 1 ]; then
  if [ -n "$RC_UPDATED" ]; then
    RC_UPDATED_DISPLAY=""
    for rc_name in $RC_UPDATED; do
      RC_UPDATED_DISPLAY="${RC_UPDATED_DISPLAY}~/${rc_name#./} "
    done
    RC_UPDATED_DISPLAY="${RC_UPDATED_DISPLAY% }"
    PATH_HINT="  Added PATH export to: $RC_UPDATED_DISPLAY
  Open a new shell, or for this shell run: export PATH=\"$BIN_DIR:\$PATH\""
    PATH_STATUS="Successfully added repi to \$PATH in $RC_UPDATED_DISPLAY"
    case " $RC_UPDATED " in
      *" .bashrc "*) SOURCE_COMMAND="source ~/.bashrc  # Load new PATH (or open a new terminal)" ;;
      *" .zshrc "*) SOURCE_COMMAND="source ~/.zshrc   # Load new PATH (or open a new terminal)" ;;
      *" .profile "*) SOURCE_COMMAND="source ~/.profile # Load new PATH (or open a new terminal)" ;;
    esac
  else
    PATH_HINT="  PATH hint (run in this shell): export PATH=\"$BIN_DIR:\$PATH\""
    PATH_STATUS="Installed repi to $BIN_DIR; add it to \$PATH for direct command use"
    SOURCE_COMMAND="export PATH=\"$BIN_DIR:\$PATH\"  # Load repi for this shell"
  fi
else
  PATH_STATUS="Successfully linked repi in $BIN_DIR (already on \$PATH)"
fi
REPI_VERSION="$(ROOT_PACKAGE_JSON="$ROOT/package.json" node -e 'try { console.log(require(process.env.ROOT_PACKAGE_JSON).version) } catch { console.log("unknown") }' 2>/dev/null || echo unknown)"
if [ "${REPI_INSTALL_EMBEDDED:-0}" = "1" ]; then
  cat <<MSG
REPI launcher ready:
  launcher: $BIN_DIR/repi -> $ROOT/repi
  runtime : ${REPI_CODING_AGENT_DIR:-${REPI_AGENT_DIR:-$HOME/.repi/agent}}
  profile : built-in reverse/pentest kernel initialized
$PATH_HINT
MSG
  exit 0
fi
cat <<MSG
Installed REPI:
  launcher: $BIN_DIR/repi -> $ROOT/repi
  runtime : ${REPI_CODING_AGENT_DIR:-${REPI_AGENT_DIR:-$HOME/.repi/agent}}
  profile : built-in reverse/pentest kernel initialized
$PATH_HINT

$PATH_STATUS

REPI $REPI_VERSION installed successfully, to start:

${SOURCE_COMMAND:+$SOURCE_COMMAND
}cd <project>  # Open target/project directory
repi          # Run command

Useful first checks:

repi doctor
repi model status

For more information visit https://github.com/multi-zhangyang/pi-recon-agent
MSG
