#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(pwd)}"
AGENT_DIR="${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

if [ ! -d "$ROOT/.pi" ]; then
  echo "missing $ROOT/.pi" >&2
  exit 1
fi

mkdir -p "$AGENT_DIR/extensions" "$AGENT_DIR/skills" "$AGENT_DIR/prompts" "$AGENT_DIR/memory/playbooks" "$AGENT_DIR/mission" "$AGENT_DIR/evidence/runs" "$AGENT_DIR/evidence/maps" "$AGENT_DIR/evidence/browser" "$AGENT_DIR/evidence/web-authz" "$AGENT_DIR/evidence/chains" "$AGENT_DIR/evidence/decisions" "$AGENT_DIR/evidence/exploit-lab" "$AGENT_DIR/evidence/mobile-runtime" "$AGENT_DIR/evidence/native-runtime" "$AGENT_DIR/evidence/graphs" "$AGENT_DIR/evidence/proof-loops" "$AGENT_DIR/evidence/knowledge" "$AGENT_DIR/evidence/harness" "$AGENT_DIR/tools"

for f in SYSTEM.md APPEND_SYSTEM.md; do
  if [ -f "$AGENT_DIR/$f" ]; then
    cp "$AGENT_DIR/$f" "$AGENT_DIR/$f.bak.$STAMP"
  fi
  cp "$ROOT/.pi/$f" "$AGENT_DIR/$f"
done

cp "$ROOT/.pi/extensions/reverse-pentest-core.ts" "$AGENT_DIR/extensions/reverse-pentest-core.ts"
rm -rf "$AGENT_DIR/skills/reverse-pentest-orchestrator"
cp -R "$ROOT/.pi/skills/reverse-pentest-orchestrator" "$AGENT_DIR/skills/reverse-pentest-orchestrator"
cp "$ROOT/.pi/prompts/"*.md "$AGENT_DIR/prompts/"

for f in field-journal.md case-index.md evolution-log.md; do
  if [ ! -f "$AGENT_DIR/memory/$f" ]; then
    cp "$ROOT/.pi/memory/$f" "$AGENT_DIR/memory/$f"
  fi
done
if [ ! -f "$AGENT_DIR/mission/current.json" ]; then
  cp "$ROOT/.pi/mission/current.json" "$AGENT_DIR/mission/current.json"
fi
if [ ! -f "$AGENT_DIR/evidence/ledger.md" ]; then
  cp "$ROOT/.pi/evidence/ledger.md" "$AGENT_DIR/evidence/ledger.md"
fi
cp "$ROOT/.pi/tools/tool-index.md" "$AGENT_DIR/tools/tool-index.md"

if [ -d "$ROOT/node_modules" ]; then
  if [ -L "$AGENT_DIR/node_modules" ] || [ ! -e "$AGENT_DIR/node_modules" ]; then
    ln -sfn "$ROOT/node_modules" "$AGENT_DIR/node_modules"
    echo "Linked profile runtime dependencies: $AGENT_DIR/node_modules -> $ROOT/node_modules"
  else
    echo "Existing non-symlink node_modules kept: $AGENT_DIR/node_modules"
  fi
fi

REVERSE_SKILL_ROOT="$(cd "$ROOT/.." && pwd)/reverse-skill"
if [ -d "$REVERSE_SKILL_ROOT" ]; then
  mkdir -p "$AGENT_DIR/vendor"
  if [ -L "$AGENT_DIR/vendor/reverse-skill" ] || [ ! -e "$AGENT_DIR/vendor/reverse-skill" ]; then
    ln -sfn "$REVERSE_SKILL_ROOT" "$AGENT_DIR/vendor/reverse-skill"
    echo "Linked reverse-skill vendor: $AGENT_DIR/vendor/reverse-skill -> $REVERSE_SKILL_ROOT"
  else
    echo "Existing non-symlink vendor reverse-skill kept: $AGENT_DIR/vendor/reverse-skill"
  fi
fi

node - "$AGENT_DIR/settings.json" <<'NODE'
const fs = require('node:fs');
const path = process.argv[2];
let settings = {};
if (fs.existsSync(path)) {
  fs.copyFileSync(path, `${path}.bak.${new Date().toISOString().replace(/[-:.]/g, '').slice(0, 15)}Z`);
  settings = JSON.parse(fs.readFileSync(path, 'utf8'));
}
const unique = (items) => Array.from(new Set(items));
settings.defaultThinkingLevel = settings.defaultThinkingLevel ?? 'high';
settings.enableSkillCommands = true;
settings.compaction = { enabled: true, reserveTokens: 32768, keepRecentTokens: 36000, ...(settings.compaction ?? {}) };
settings.branchSummary = { reserveTokens: 24576, skipPrompt: true, ...(settings.branchSummary ?? {}) };
settings.extensions = unique([...(settings.extensions ?? []), 'extensions/reverse-pentest-core.ts']);
settings.skills = unique([...(settings.skills ?? []), 'skills/reverse-pentest-orchestrator/SKILL.md']);
settings.prompts = unique([...(settings.prompts ?? []), 'prompts']);
fs.writeFileSync(path, `${JSON.stringify(settings, null, 2)}\n`);
NODE

echo "Installed Pi-RECON profile into $AGENT_DIR"
echo "Run: scripts/reverse-agent/refresh-tool-index.sh \"$ROOT\""
