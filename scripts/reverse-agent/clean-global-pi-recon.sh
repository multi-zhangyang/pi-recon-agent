#!/usr/bin/env bash
set -euo pipefail
AGENT_DIR="${PI_AGENT_DIR:-$HOME/.pi/agent}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="$AGENT_DIR/repi-legacy-backup.$STAMP"
mkdir -p "$BACKUP"

if [ ! -d "$AGENT_DIR" ]; then
  echo "global pi agent dir not found: $AGENT_DIR"
  exit 0
fi

if [ -f "$AGENT_DIR/settings.json" ]; then
  cp "$AGENT_DIR/settings.json" "$BACKUP/settings.json"
  node - "$AGENT_DIR/settings.json" <<'NODE'
const fs = require('node:fs');
const path = process.argv[2];
const s = JSON.parse(fs.readFileSync(path, 'utf8'));
const keep = (v) => !String(v).includes('reverse-pentest') && String(v) !== 'prompts';
for (const key of ['extensions', 'skills', 'prompts']) {
  if (Array.isArray(s[key])) {
    s[key] = s[key].filter(keep);
    if (s[key].length === 0) delete s[key];
  }
}
if (Array.isArray(s.enabledModels)) {
  // Keep user model cycling only when it is not the old Pi-RECON broken 2go-only scope.
  const joined = s.enabledModels.join('\n');
  if (/2go-(anthropic|openai)\/moonshot\/kimi-k2\.6/.test(joined)) delete s.enabledModels;
}
fs.writeFileSync(path, `${JSON.stringify(s, null, 2)}\n`);
NODE
fi

move_if_exists() {
  local src="$1"
  local dst="$BACKUP/$2"
  if [ -e "$src" ] || [ -L "$src" ]; then
    mkdir -p "$(dirname "$dst")"
    mv "$src" "$dst"
    echo "moved $src -> $dst"
  fi
}

move_if_contains_recon() {
  local src="$1"
  local dst="$BACKUP/$2"
  if [ -f "$src" ] && grep -Eqi 'Pi-RECON|逆向渗透|reverse/pentest|reverse-pentest' "$src"; then
    mkdir -p "$(dirname "$dst")"
    mv "$src" "$dst"
    echo "moved $src -> $dst"
  fi
}

move_if_exists "$AGENT_DIR/extensions/reverse-pentest-core.ts" "extensions/reverse-pentest-core.ts"
move_if_exists "$AGENT_DIR/skills/reverse-pentest-orchestrator" "skills/reverse-pentest-orchestrator"

for name in agentsec audit-agent chain cl cloud decision exploit firmware identity is jsre malware memory mobile native pcap pr pwn reverse webauthz websec wr; do
  move_if_exists "$AGENT_DIR/prompts/$name.md" "prompts/$name.md"
done

move_if_contains_recon "$AGENT_DIR/SYSTEM.md" "SYSTEM.md"
move_if_contains_recon "$AGENT_DIR/APPEND_SYSTEM.md" "APPEND_SYSTEM.md"

if [ -d "$AGENT_DIR/tools" ]; then
  mkdir -p "$BACKUP/tools"
  mv "$AGENT_DIR/tools" "$BACKUP/tools"
  echo "moved legacy global tools dir -> $BACKUP/tools"
fi

cat > "$BACKUP/README.txt" <<MSG
Pi-RECON legacy global resources were moved here so normal 'pi' and isolated 'repi' do not collide.
To restore manually, copy files back into $AGENT_DIR.
Created: $STAMP
MSG

echo "Cleaned global pi Pi-RECON file-profile pollution. Backup: $BACKUP"
