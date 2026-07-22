import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { getAgentDir, getPackageDir } from "../config.ts";
import { DEFAULT_COMPACTION_SETTINGS } from "./compaction/compaction.ts";
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
	const content = `${JSON.stringify(value, null, 2)}\n`;
	try {
		if (readFileSync(path, "utf8") === content) {
			chmodSync(path, mode ?? 0o600);
			return;
		}
	} catch {}
	atomicWriteFileSync(path, content, mode ?? 0o600);
}

function copyIfMissing(from: string, to: string, mode?: number): boolean {
	if (!existsSync(from) || existsSync(to)) return false;
	mkdir(dirname(to));
	// A failed direct copy can leave a truncated destination that makes every
	// later startup skip the legacy import via existsSync(to). Publish only a
	// complete JSON file so a failed import leaves the destination retryable.
	atomicWriteFileSync(to, readFileSync(from, "utf8"), mode ?? 0o600);
	return true;
}

function truthyEnv(value: string | undefined): boolean {
	return value === "1" || value?.toLowerCase() === "true" || value?.toLowerCase() === "yes";
}

/**
 * Return only profile roots created by REPI's worker/session isolation code.
 * Evidence can contain user-owned fixtures named settings.json, so do not
 * recursively discover files by name.
 */
function knownIsolatedProfileSettings(agentDir: string): string[] {
	const paths = [join(agentDir, "settings.json")];
	const add = (path: string) => paths.push(path);
	const threadRoot = join(agentDir, "recon", "agent-threads");
	try {
		for (const entry of readdirSync(threadRoot, { withFileTypes: true })) {
			if (entry.isDirectory()) add(join(threadRoot, entry.name, "agent-home", "settings.json"));
		}
	} catch {
		// Missing worker roots are normal.
	}
	const swarmsRoot = join(agentDir, "recon", "evidence", "swarms");
	try {
		for (const entry of readdirSync(swarmsRoot, { withFileTypes: true })) {
			if (!entry.isDirectory()) continue;
			if (/-sessions$/.test(entry.name)) {
				add(join(swarmsRoot, entry.name, ".repi", "agent", "settings.json"));
			}
			if (/-worker-child-session-runtime-child-process$/.test(entry.name)) {
				add(join(swarmsRoot, entry.name, "home", ".repi", "agent", "settings.json"));
			}
		}
	} catch {
		// Missing swarm roots are normal.
	}
	return Array.from(new Set(paths));
}

function removeRetiredMemorySetting(path: string): void {
	const settings = readJson(path);
	if (!settings || Array.isArray(settings) || !Object.hasOwn(settings, "memory")) return;
	delete settings.memory;
	writeJson(path, settings, 0o600);
}

/**
 * Remove state written by the retired persistent-memory/file-profile runtime.
 *
 * This is deliberately a narrow, idempotent migration. Session transcripts,
 * mission state, and ordinary evidence remain intact; only paths that could
 * reintroduce the removed memory/trace/profile prompt surface are removed.
 */
function removeRetiredRuntimeState(agentDir: string): void {
	const remove = (path: string) => {
		try {
			rmSync(path, { recursive: true, force: true });
		} catch {
			// Best effort: a locked stale artifact must not prevent startup.
		}
	};

	for (const path of [
		join(agentDir, "memory"),
		join(agentDir, "SYSTEM.md"),
		join(agentDir, "APPEND_SYSTEM.md"),
		// Retired file-profile resources. Keep the scope exact so a user-owned
		// prompt/skill outside the isolated REPI profile is never touched.
		join(agentDir, "prompts", "memory.md"),
		join(agentDir, "skills", "reverse-pentest-orchestrator"),
		join(agentDir, "recon", "memory"),
		join(agentDir, "recon", "builtin"),
		join(agentDir, "recon", "evidence", "knowledge"),
		join(agentDir, "recon", "evidence", "tool-calls"),
	]) {
		remove(path);
	}

	const archiveDir = join(agentDir, "recon", "archive");
	try {
		for (const entry of readdirSync(join(agentDir, "extensions"), { withFileTypes: true })) {
			if (entry.isDirectory() && /^(?:legacy-tools|legacy-hooks)-/.test(entry.name)) {
				remove(join(agentDir, "extensions", entry.name));
			}
		}
	} catch {
		// Missing extension directory is normal.
	}
	try {
		const runsDir = join(agentDir, "recon", "evidence", "runs");
		for (const entry of readdirSync(runsDir, { withFileTypes: true })) {
			if (/(?:case-memory|knowledge-graph)/i.test(entry.name)) remove(join(runsDir, entry.name));
		}
	} catch {
		// Missing run evidence is normal.
	}

	try {
		for (const entry of readdirSync(archiveDir, { withFileTypes: true })) {
			if (entry.isDirectory() && /^(?:legacy-file-profile|poison-cleanup-runtime)-/.test(entry.name)) {
				remove(join(archiveDir, entry.name));
			}
		}
	} catch {
		// Missing archive directory is the normal fresh-profile case.
	}

	// Worker homes are independent profiles. Clean their retired state too so
	// an old delegated run cannot be reintroduced by a later merge/resume.
	const threadRoot = join(agentDir, "recon", "agent-threads");
	try {
		for (const entry of readdirSync(threadRoot, { withFileTypes: true })) {
			if (!entry.isDirectory()) continue;
			const workerDir = join(threadRoot, entry.name, "agent-home");
			for (const path of [
				join(workerDir, "memory"),
				join(workerDir, "SYSTEM.md"),
				join(workerDir, "APPEND_SYSTEM.md"),
				join(workerDir, "prompts", "memory.md"),
				join(workerDir, "skills", "reverse-pentest-orchestrator"),
				join(workerDir, "recon", "memory"),
				join(workerDir, "recon", "builtin"),
				join(workerDir, "recon", "evidence", "knowledge"),
				join(workerDir, "recon", "evidence", "tool-calls"),
			]) {
				remove(path);
			}
		}
	} catch {
		// Missing or unreadable worker roots are non-fatal.
	}

	for (const settingsPath of knownIsolatedProfileSettings(agentDir)) {
		removeRetiredMemorySetting(settingsPath);
	}
}

export function initializeRepiProfile(options: { repoRoot?: string; verbose?: boolean } = {}): RepiProfileInitResult {
	const agentDir = getAgentDir();
	const legacyPiAgentDir = process.env.PI_AGENT_IMPORT_DIR || join(homedir(), ".pi", "agent");
	const importLegacyPiProfile =
		truthyEnv(process.env.REPI_IMPORT_PI_PROFILE) || truthyEnv(process.env.REPI_IMPORT_PI_AUTH);
	process.env.REPI_CODING_AGENT_DIR ||= agentDir;
	process.env.REPI_CODING_AGENT_SESSION_DIR ||= join(agentDir, "sessions");
	process.env.PI_CODING_AGENT_DIR ||= agentDir;
	process.env.PI_CODING_AGENT_SESSION_DIR ||= process.env.REPI_CODING_AGENT_SESSION_DIR;

	mkdir(agentDir);
	mkdir(join(agentDir, "sessions"));
	mkdir(join(agentDir, "recon"));
	removeRetiredRuntimeState(agentDir);

	const copiedModels = importLegacyPiProfile
		? copyIfMissing(join(legacyPiAgentDir, "models.json"), join(agentDir, "models.json"), 0o600)
		: false;
	const copiedAuth = importLegacyPiProfile
		? copyIfMissing(join(legacyPiAgentDir, "auth.json"), join(agentDir, "auth.json"), 0o600)
		: false;

	const settingsPath = join(agentDir, "settings.json");
	const settings = readJson(settingsPath) || {};
	settings.defaultThinkingLevel = settings.defaultThinkingLevel ?? "medium";
	settings.enableSkillCommands = true;
	settings.quietStartup = settings.quietStartup ?? false;
	settings.collapseChangelog = settings.collapseChangelog ?? true;
	const existingCompaction = (settings.compaction as Record<string, unknown> | undefined) ?? {};
	const migratedLegacyReserveTokens =
		existingCompaction.triggerPercent === undefined &&
		existingCompaction.warningPercent === undefined &&
		existingCompaction.reserveTokens === 32768
			? DEFAULT_COMPACTION_SETTINGS.reserveTokens
			: existingCompaction.reserveTokens;
	settings.compaction = {
		...existingCompaction,
		enabled: existingCompaction.enabled ?? DEFAULT_COMPACTION_SETTINGS.enabled,
		triggerPercent: existingCompaction.triggerPercent ?? DEFAULT_COMPACTION_SETTINGS.triggerPercent,
		warningPercent: existingCompaction.warningPercent ?? DEFAULT_COMPACTION_SETTINGS.warningPercent,
		reserveTokens: migratedLegacyReserveTokens ?? DEFAULT_COMPACTION_SETTINGS.reserveTokens,
		keepRecentTokens: existingCompaction.keepRecentTokens ?? DEFAULT_COMPACTION_SETTINGS.keepRecentTokens,
	};
	// Drop the retired persistence block during migration so old profiles cannot
	// recreate the removed subsystem.
	delete settings.memory;
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
		if (!Array.isArray(value)) continue;
		const filtered = value.filter(
			(entry) => !String(entry).includes("reverse-pentest") && String(entry) !== "prompts",
		);
		if (filtered.length === 0) delete settings[key];
		else if (filtered.length !== value.length) settings[key] = filtered;
	}
	writeJson(settingsPath, settings, 0o600);

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
