#!/usr/bin/env bash
set -euo pipefail

# Clean old REPI file-profile pollution from upstream Pi's global profile.
# Default is dry-run. Nothing is moved unless --apply is passed; tools/ needs --force-tools.
AGENT_DIR="${PI_AGENT_DIR:-$HOME/.pi/agent}"
DRY_RUN=1
FORCE_TOOLS=0
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP=""
ACTION_COUNT=0
MARKER_RE='REPI|pi-recon|reverse[/-]pentest|reverse-pentest|逆向渗透|re_(context|operator|proof_loop|memory|swarm)|isolated-repi-profile|repi-profile'

usage() {
  cat <<'MSG'
Usage: clean-global-repi-profile.sh [--dry-run] [--apply] [--force-tools] [--agent-dir DIR]

Conservative REPI legacy cleaner for upstream Pi's ~/.pi/agent profile.
Default is --dry-run. With --apply, only files that contain REPI/reverse-pentest
markers are moved to repi-legacy-backup.<timestamp>. The global tools/ directory
is never moved unless --force-tools is also provided.
MSG
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      ;;
    --apply)
      DRY_RUN=0
      ;;
    --force|--force-tools)
      FORCE_TOOLS=1
      ;;
    --agent-dir)
      shift
      if [ "$#" -eq 0 ]; then
        echo "--agent-dir requires a value" >&2
        exit 2
      fi
      AGENT_DIR="$1"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [ ! -d "$AGENT_DIR" ]; then
  echo "global pi agent dir not found: $AGENT_DIR"
  exit 0
fi

ensure_backup() {
  if [ -z "$BACKUP" ]; then
    BACKUP="$AGENT_DIR/repi-legacy-backup.$STAMP"
    if [ "$DRY_RUN" -eq 0 ]; then
      mkdir -p "$BACKUP"
      cat > "$BACKUP/README.txt" <<MSG
REPI legacy global resources were moved here so normal 'pi' and isolated 'repi' do not collide.
Only files with REPI/reverse-pentest markers were moved by default; tools/ required --force-tools.
To restore manually, copy files back into $AGENT_DIR.
Created: $STAMP
MSG
    fi
  fi
}

record_action() {
  ACTION_COUNT=$((ACTION_COUNT + 1))
}

file_has_marker() {
  local src="$1"
  [ -f "$src" ] || return 1
  grep -IEqi "$MARKER_RE" "$src"
}

dir_has_marker() {
  local dir="$1"
  [ -d "$dir" ] || return 1
  while IFS= read -r -d '' file; do
    if file_has_marker "$file"; then
      return 0
    fi
  done < <(find "$dir" -type f -print0 2>/dev/null)
  return 1
}

move_marked_file() {
  local src="$1"
  local rel="$2"
  [ -e "$src" ] || [ -L "$src" ] || return 0
  if ! file_has_marker "$src"; then
    echo "kept unmarked file: $src"
    return 0
  fi
  ensure_backup
  record_action
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] would move $src -> $BACKUP/$rel"
    return 0
  fi
  mkdir -p "$(dirname "$BACKUP/$rel")"
  mv "$src" "$BACKUP/$rel"
  echo "moved $src -> $BACKUP/$rel"
}

move_marked_tree_files() {
  local dir="$1"
  local rel_prefix="$2"
  [ -d "$dir" ] || return 0
  while IFS= read -r -d '' file; do
    if file_has_marker "$file"; then
      local rel="${file#$dir/}"
      move_marked_file "$file" "$rel_prefix/$rel"
    fi
  done < <(find "$dir" -type f -print0 2>/dev/null)
  if [ "$DRY_RUN" -eq 0 ]; then
    find "$dir" -depth -type d -empty -delete 2>/dev/null || true
  fi
}

move_marked_dir_with_force() {
  local dir="$1"
  local rel="$2"
  local label="$3"
  [ -d "$dir" ] || return 0
  if [ "$FORCE_TOOLS" -ne 1 ]; then
    echo "kept $label: $dir (requires --force-tools)"
    return 0
  fi
  if ! dir_has_marker "$dir"; then
    echo "kept $label without REPI marker: $dir"
    return 0
  fi
  ensure_backup
  record_action
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] would move $label $dir -> $BACKUP/$rel"
    return 0
  fi
  mkdir -p "$(dirname "$BACKUP/$rel")"
  mv "$dir" "$BACKUP/$rel"
  echo "moved $label -> $BACKUP/$rel"
}

clean_settings() {
  local settings="$AGENT_DIR/settings.json"
  [ -f "$settings" ] || return 0
  local dry_flag="$DRY_RUN"
  local output
  output="$(node - "$settings" "$dry_flag" <<'NODE'
const fs = require('node:fs');
const path = process.argv[2];
const dryRun = process.argv[3] === '1';
const raw = fs.readFileSync(path, 'utf8');
let settings;
try {
  settings = JSON.parse(raw);
} catch (error) {
  console.log(`kept unparsable settings.json: ${error.message}`);
  process.exit(0);
}
const before = JSON.stringify(settings);
const owned = /reverse-pentest|reverse-pentest-core|reverse-pentest-orchestrator|repi-profile|pi-recon/i;
for (const key of ['extensions', 'skills', 'prompts']) {
  if (Array.isArray(settings[key])) {
    settings[key] = settings[key].filter((value) => !owned.test(String(value)));
    if (settings[key].length === 0) delete settings[key];
  }
}
if (Array.isArray(settings.enabledModels)) {
  const joined = settings.enabledModels.join('\n');
  if (/stale-(anthropic|openai)\/vendor\/private-model/.test(joined)) delete settings.enabledModels;
}
const after = JSON.stringify(settings);
if (before === after) {
  console.log('settings unchanged');
  process.exit(0);
}
if (dryRun) {
  console.log('__REPI_SETTINGS_CHANGED__ would update settings.json owned REPI entries');
  process.exit(0);
}
fs.copyFileSync(path, `${path}.bak.${new Date().toISOString().replace(/[-:.]/g, '').slice(0, 15)}Z`);
fs.writeFileSync(path, `${JSON.stringify(settings, null, 2)}\n`);
console.log('__REPI_SETTINGS_CHANGED__ updated settings.json owned REPI entries');
process.exit(0);
NODE
)"
  echo "$output" | sed 's/__REPI_SETTINGS_CHANGED__ //'
  if printf '%s\n' "$output" | grep -q '__REPI_SETTINGS_CHANGED__'; then
    ensure_backup
    record_action
    if [ "$DRY_RUN" -eq 0 ]; then
      cp "$settings" "$BACKUP/settings.json.after"
      local latest_backup
      latest_backup="$(ls -t "$settings".bak.* 2>/dev/null | head -n 1 || true)"
      if [ -n "$latest_backup" ]; then
        cp "$latest_backup" "$BACKUP/settings.json.before"
      fi
    fi
  fi
}

clean_settings

move_marked_file "$AGENT_DIR/SYSTEM.md" "SYSTEM.md"
move_marked_file "$AGENT_DIR/APPEND_SYSTEM.md" "APPEND_SYSTEM.md"
move_marked_file "$AGENT_DIR/extensions/reverse-pentest-core.ts" "extensions/reverse-pentest-core.ts"

for f in "$AGENT_DIR"/SYSTEM.md.bak.* "$AGENT_DIR"/APPEND_SYSTEM.md.bak.* "$AGENT_DIR"/settings.json.bak.*; do
  [ -e "$f" ] || continue
  move_marked_file "$f" "legacy-backups/$(basename "$f")"
done

move_marked_tree_files "$AGENT_DIR/skills/reverse-pentest-orchestrator" "skills/reverse-pentest-orchestrator"

for name in agentsec audit-agent chain cl cloud decision exploit firmware identity is jsre malware memory mobile native pcap pr pwn reverse webauthz websec wr; do
  move_marked_file "$AGENT_DIR/prompts/$name.md" "prompts/$name.md"
done

for name in recon evidence memory mission reports vendor; do
  move_marked_tree_files "$AGENT_DIR/$name" "$name"
done

# tools/ can contain normal Pi or user custom tools. Move it only with an explicit force flag and marker evidence.
move_marked_dir_with_force "$AGENT_DIR/tools" "tools" "legacy global tools dir"

if [ "$ACTION_COUNT" -eq 0 ]; then
  echo "No REPI-marked global pi profile files matched. Nothing changed."
  exit 0
fi

if [ "$DRY_RUN" -eq 1 ]; then
  echo "DRY-RUN only. Re-run with --apply to move marked files into: $BACKUP"
else
  echo "Cleaned global pi REPI file-profile pollution. Backup: $BACKUP"
fi
