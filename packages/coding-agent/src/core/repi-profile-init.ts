import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { getAgentDir, getPackageDir } from "../config.ts";
import { atomicWriteFileSync } from "./tools/atomic-write.ts";

export interface RepiProfileInitResult {
	agentDir: string;
	legacyPiAgentDir: string;
	importLegacyPiProfile: boolean;
	copiedModels: boolean;
	copiedAuth: boolean;
}

function mkdir(path: string): void {
	mkdirSync(path, { recursive: true, mode: 0o700 });
	try {
		chmodSync(path, 0o700);
	} catch {
		// Best-effort on non-POSIX filesystems.
	}
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
	// Foundational opt #265: write atomically (temp+rename, mode-preserved) so a
	// crash mid-write (SIGKILL/OOM/power loss) doesn't truncate settings.json /
	// profile.json — readJson swallows the JSON.parse failure → settings rebuilt
	// from defaults only → user customizations permanently lost. Same class as
	// opt #43 (SettingsManager runtime path); this startup init path bypassed the
	// SettingsManager entirely. The helper preserves an existing target's mode
	// across the replace and unlinks the temp on any failure.
	atomicWriteFileSync(path, `${JSON.stringify(value, null, 2)}\n`, mode ?? 0o600);
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
	// opt #273: do NOT create the global recon/memory/playbooks dir here.
	// initializeRepiProfile runs before the session cwd is known, so a global
	// playbooks dir would orphan (scoped agent uses projects/<cwd>/playbooks via
	// memoryPlaybooksDir()). The scoped playbooks dir is created on demand by
	// ensureRepiStorage when the recon extension inits with the cwd scope set.
	mkdir(join(agentDir, "recon", "memory"));
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
	for (const dir of [
		agentDir,
		join(agentDir, "sessions"),
		join(agentDir, "recon"),
		join(agentDir, "recon", "memory"),
		join(agentDir, "recon", "evidence"),
		join(agentDir, "recon", "mission"),
		join(agentDir, "recon", "tools"),
	]) {
		try {
			chmodSync(dir, 0o700);
		} catch {
			// Best-effort on non-POSIX filesystems.
		}
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
	const existingMemory =
		settings.memory && typeof settings.memory === "object" && !Array.isArray(settings.memory)
			? (settings.memory as Record<string, unknown>)
			: {};
	const migrateMemoryV1 = Number(existingMemory.schemaVersion ?? 0) < 2;
	const legacyAutoDeposit =
		migrateMemoryV1 && existingMemory.autoDeposit === false ? "high-value" : existingMemory.autoDeposit;
	const legacyStartupDigest =
		migrateMemoryV1 && existingMemory.startupDigest === "status" ? "scoped" : existingMemory.startupDigest;
	const legacyScopePolicy =
		migrateMemoryV1 && existingMemory.scopePolicy === "session"
			? "mission+workspace+target"
			: existingMemory.scopePolicy;
	settings.memory = {
		...existingMemory,
		schemaVersion: 2,
		mode: existingMemory.mode ?? "scoped",
		autoRecall: existingMemory.autoRecall ?? true,
		autoInject: existingMemory.autoInject ?? false,
		rawAutoInject: existingMemory.rawAutoInject ?? false,
		autoDeposit: legacyAutoDeposit ?? "high-value",
		startupDigest: legacyStartupDigest ?? "scoped",
		scopePolicy: legacyScopePolicy ?? "mission+workspace+target",
		contextMemoryMode: existingMemory.contextMemoryMode ?? "scoped",
		includeGlobalMemoryInContextPack: existingMemory.includeGlobalMemoryInContextPack ?? false,
		activeRecall: existingMemory.activeRecall ?? false,
		maxInjectedTokens: existingMemory.maxInjectedTokens ?? 1200,
		startupBudgetTokens: existingMemory.startupBudgetTokens ?? 800,
		contextPackBudgetTokens: existingMemory.contextPackBudgetTokens ?? 1200,
		maxStartupItems: existingMemory.maxStartupItems ?? 5,
		minRecallScore: existingMemory.minRecallScore ?? 0.35,
		rawTranscriptRetention: existingMemory.rawTranscriptRetention ?? "external-only",
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

	// REPI uses the built-in --recon kernel and an isolated ~/.repi profile.
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
		// opt #273: the recon/memory/* default .md files are NOT seeded here.
		// initializeRepiProfile runs at cli.ts bootstrap BEFORE the session cwd is
		// known, so it cannot scope them — writing them here seeded the GLOBAL
		// recon/memory root on every startup, orphaning defaults the scoped agent
		// never reads (cross-project pollution). ensureRepiStorage() now seeds the
		// same defaults per-cwd via memoryPath() (scoped) when the recon extension
		// inits. Only non-memory recon infrastructure (evidence ledger, tool index)
		// is seeded here — those are global runtime infra, not project memory.
		["recon/evidence/ledger.md", "# REPI Evidence Ledger\n\n"],
		["recon/tools/tool-index.md", "# REPI Tool Index\n\n"],
	] as const) {
		const path = join(agentDir, rel);
		if (!existsSync(path)) writeFileSync(path, body, "utf8");
		try {
			chmodSync(path, 0o600);
		} catch {
			// Best-effort on non-POSIX filesystems.
		}
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
