#!/usr/bin/env node
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

const repoRoot = process.argv[2] || process.cwd();
const agentDir =
	process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const legacyPiAgentDir = process.env.PI_AGENT_IMPORT_DIR || join(homedir(), ".pi", "agent");

const mkdir = (path) => mkdirSync(path, { recursive: true });
const readJson = (path) => {
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch {
		return undefined;
	}
};
const writeJson = (path, value, mode) => {
	mkdir(dirname(path));
	writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
	if (mode !== undefined) chmodSync(path, mode);
};
const copyIfMissing = (from, to, mode) => {
	if (!existsSync(from) || existsSync(to)) return false;
	mkdir(dirname(to));
	copyFileSync(from, to);
	if (mode !== undefined) chmodSync(to, mode);
	return true;
};

mkdir(agentDir);
mkdir(join(agentDir, "sessions"));
mkdir(join(agentDir, "recon", "memory", "playbooks"));
mkdir(join(agentDir, "recon", "mission"));
mkdir(join(agentDir, "recon", "tools"));
for (const sub of [
	"runs",
	"maps",
	"browser",
	"web-authz",
	"chains",
	"decisions",
	"exploit-lab",
	"mobile-runtime",
	"native-runtime",
	"graphs",
	"proof-loops",
	"knowledge",
	"harness",
	"swarms",
	"supervisor",
	"contexts",
	"operators",
	"verifiers",
	"compilers",
	"replayers",
	"autofix",
	"failures",
	"repairs",
	"claim-release",
]) {
	mkdir(join(agentDir, "recon", "evidence", sub));
}

const copiedModels = copyIfMissing(join(legacyPiAgentDir, "models.json"), join(agentDir, "models.json"), 0o600);
const copiedAuth = copyIfMissing(join(legacyPiAgentDir, "auth.json"), join(agentDir, "auth.json"), 0o600);

const settingsPath = join(agentDir, "settings.json");
const settings = readJson(settingsPath) || {};
settings.defaultThinkingLevel = settings.defaultThinkingLevel ?? "high";
settings.enableSkillCommands = true;
settings.quietStartup = settings.quietStartup ?? false;
settings.collapseChangelog = settings.collapseChangelog ?? true;
settings.compaction = { enabled: true, reserveTokens: 32768, keepRecentTokens: 36000, ...(settings.compaction ?? {}) };
settings.branchSummary = { reserveTokens: 24576, skipPrompt: true, ...(settings.branchSummary ?? {}) };
settings.retry = {
	enabled: true,
	maxRetries: 3,
	baseDelayMs: 1500,
	provider: { timeoutMs: 240000, maxRetries: 2, maxRetryDelayMs: 30000, ...(settings.retry?.provider ?? {}) },
	...(settings.retry ?? {}),
};
// repi uses the built-in --recon kernel and wrapper-level --no-extensions/--no-skills/--no-prompt-templates.
// Keep the isolated profile free of file-based reverse extensions/prompts so it cannot collide with normal pi.
for (const key of ["extensions", "skills", "prompts", "enabledModels"]) {
	if (Array.isArray(settings[key]) && settings[key].some((x) => String(x).includes("reverse-pentest") || String(x) === "prompts")) {
		delete settings[key];
	}
}
writeJson(settingsPath, settings, 0o600);

for (const [rel, body] of [
	["recon/memory/field-journal.md", "# Pi-RECON Field Journal\n\n"],
	["recon/memory/case-index.md", "# Pi-RECON Case Index\n\n"],
	["recon/memory/evolution-log.md", "# Pi-RECON Evolution Log\n\n"],
	["recon/evidence/ledger.md", "# Pi-RECON Evidence Ledger\n\n"],
	["recon/tools/tool-index.md", "# Pi-RECON Tool Index\n\n"],
]) {
	const path = join(agentDir, rel);
	if (!existsSync(path)) writeFileSync(path, body, "utf8");
}

const manifestPath = join(agentDir, "recon", "profile.json");
writeJson(manifestPath, {
	name: "repi",
	kind: "isolated-pi-recon-profile",
	repoRoot,
	agentDir,
	legacyPiImported: { models: copiedModels, auth: copiedAuth },
	resources: {
		storage: "recon/",
		settings: "settings.json",
		models: existsSync(join(agentDir, "models.json")) ? "models.json" : null,
		auth: existsSync(join(agentDir, "auth.json")) ? "auth.json" : null,
	},
}, 0o600);

if (process.env.REPI_INIT_VERBOSE === "1") {
	console.error(`[repi:init] agentDir=${agentDir}`);
	if (copiedModels) console.error(`[repi:init] copied models.json from ${legacyPiAgentDir}`);
	if (copiedAuth) console.error(`[repi:init] copied auth.json from ${legacyPiAgentDir}`);
}
