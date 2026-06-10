import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { getAgentDir, getPackageDir } from "../config.ts";

export interface RepiProfileInitResult {
	agentDir: string;
	legacyPiAgentDir: string;
	importLegacyPiProfile: boolean;
	copiedModels: boolean;
	copiedAuth: boolean;
}

function mkdir(path: string): void {
	mkdirSync(path, { recursive: true });
}

function readJson(path: string): Record<string, unknown> | undefined {
	try {
		return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
	} catch {
		return undefined;
	}
}

function writeJson(path: string, value: unknown, mode?: number): void {
	mkdir(dirname(path));
	writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
	if (mode !== undefined) chmodSync(path, mode);
}

function copyIfMissing(from: string, to: string, mode?: number): boolean {
	if (!existsSync(from) || existsSync(to)) return false;
	mkdir(dirname(to));
	copyFileSync(from, to);
	if (mode !== undefined) chmodSync(to, mode);
	return true;
}

function truthyEnv(value: string | undefined): boolean {
	return value === "1" || value?.toLowerCase() === "true" || value?.toLowerCase() === "yes";
}

export function initializeRepiProfile(options: { repoRoot?: string; verbose?: boolean } = {}): RepiProfileInitResult {
	const agentDir = getAgentDir();
	const legacyPiAgentDir = process.env.PI_AGENT_IMPORT_DIR || join(homedir(), ".pi", "agent");
	const importLegacyPiProfile =
		truthyEnv(process.env.REPI_IMPORT_PI_PROFILE) || truthyEnv(process.env.REPI_IMPORT_PI_AUTH);

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

	const copiedModels = importLegacyPiProfile
		? copyIfMissing(join(legacyPiAgentDir, "models.json"), join(agentDir, "models.json"), 0o600)
		: false;
	const copiedAuth = importLegacyPiProfile
		? copyIfMissing(join(legacyPiAgentDir, "auth.json"), join(agentDir, "auth.json"), 0o600)
		: false;

	const settingsPath = join(agentDir, "settings.json");
	const settings = readJson(settingsPath) || {};
	settings.defaultThinkingLevel = settings.defaultThinkingLevel ?? "high";
	settings.enableSkillCommands = true;
	settings.quietStartup = settings.quietStartup ?? false;
	settings.collapseChangelog = settings.collapseChangelog ?? true;
	const existingCompaction = (settings.compaction as Record<string, unknown> | undefined) ?? {};
	const migratedLegacyReserveTokens =
		existingCompaction.triggerPercent === undefined &&
		existingCompaction.warningPercent === undefined &&
		existingCompaction.reserveTokens === 32768
			? 16384
			: existingCompaction.reserveTokens;
	settings.compaction = {
		...existingCompaction,
		enabled: existingCompaction.enabled ?? true,
		triggerPercent: existingCompaction.triggerPercent ?? 85,
		warningPercent: existingCompaction.warningPercent ?? 80,
		reserveTokens: migratedLegacyReserveTokens ?? 16384,
		keepRecentTokens: existingCompaction.keepRecentTokens ?? 36000,
	};
	settings.branchSummary = {
		reserveTokens: 24576,
		skipPrompt: true,
		...((settings.branchSummary as Record<string, unknown> | undefined) ?? {}),
	};
	settings.retry = {
		enabled: true,
		maxRetries: 3,
		baseDelayMs: 1500,
		provider: {
			timeoutMs: 240000,
			maxRetries: 2,
			maxRetryDelayMs: 30000,
			...(((settings.retry as Record<string, unknown> | undefined)?.provider as
				| Record<string, unknown>
				| undefined) ?? {}),
		},
		...((settings.retry as Record<string, unknown> | undefined) ?? {}),
	};

	// REPI uses the built-in --recon kernel and defaults to clean-room startup.
	// Remove stale file-profile resources that old takeover installers placed in settings.
	for (const key of ["extensions", "skills", "prompts", "enabledModels"]) {
		const value = settings[key];
		if (
			Array.isArray(value) &&
			value.some((entry) => String(entry).includes("reverse-pentest") || String(entry) === "prompts")
		) {
			delete settings[key];
		}
	}
	writeJson(settingsPath, settings, 0o600);

	for (const [rel, body] of [
		["recon/memory/field-journal.md", "# REPI Field Journal\n\n"],
		["recon/memory/case-index.md", "# REPI Case Index\n\n"],
		["recon/memory/evolution-log.md", "# REPI Evolution Log\n\n"],
		["recon/evidence/ledger.md", "# REPI Evidence Ledger\n\n"],
		["recon/tools/tool-index.md", "# REPI Tool Index\n\n"],
	] as const) {
		const path = join(agentDir, rel);
		if (!existsSync(path)) writeFileSync(path, body, "utf8");
	}

	const manifestPath = join(agentDir, "recon", "profile.json");
	writeJson(
		manifestPath,
		{
			name: "repi",
			kind: "isolated-repi-profile",
			repoRoot: options.repoRoot ?? process.env.REPI_REPO_ROOT ?? getPackageDir(),
			agentDir,
			legacyPiImported: {
				requested: importLegacyPiProfile,
				source: legacyPiAgentDir,
				models: copiedModels,
				auth: copiedAuth,
			},
			resources: {
				storage: "recon/",
				settings: "settings.json",
				models: existsSync(join(agentDir, "models.json")) ? "models.json" : null,
				auth: existsSync(join(agentDir, "auth.json")) ? "auth.json" : null,
			},
		},
		0o600,
	);

	if (options.verbose || process.env.REPI_INIT_VERBOSE === "1") {
		console.error(`[repi:init] agentDir=${agentDir}`);
		if (!importLegacyPiProfile) console.error("[repi:init] legacy pi import skipped (default isolated mode)");
		if (copiedModels) console.error(`[repi:init] copied models.json from ${legacyPiAgentDir}`);
		if (copiedAuth) console.error(`[repi:init] copied auth.json from ${legacyPiAgentDir}`);
	}

	return { agentDir, legacyPiAgentDir, importLegacyPiProfile, copiedModels, copiedAuth };
}
