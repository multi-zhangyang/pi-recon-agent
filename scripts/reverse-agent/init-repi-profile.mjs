#!/usr/bin/env node
import {
	chmodSync,
	closeSync,
	existsSync,
	mkdirSync,
	openSync,
	readFileSync,
	readdirSync,
	renameSync,
	rmSync,
	statSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";

const repoRoot = process.argv[2] || process.cwd();
const agentDir =
	process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const legacyPiAgentDir = process.env.PI_AGENT_IMPORT_DIR || join(homedir(), ".pi", "agent");
const importLegacyPiProfile =
	process.env.REPI_IMPORT_PI_PROFILE === "1" ||
	process.env.REPI_IMPORT_PI_PROFILE === "true" ||
	process.env.REPI_IMPORT_PI_AUTH === "1" ||
	process.env.REPI_IMPORT_PI_AUTH === "true";

const mkdir = (path) => {
	mkdirSync(path, { recursive: true, mode: 0o700 });
	try {
		chmodSync(path, 0o700);
	} catch {
		// Best-effort on non-POSIX filesystems.
	}
};
const readJson = (path) => {
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch {
		return undefined;
	}
};
const atomicWriteFile = (path, content, mode = 0o600) => {
	mkdir(dirname(path));
	const tempPath = join(
		dirname(path),
		`.${basename(path)}.${process.pid}.${Date.now()}.${randomBytes(4).toString("hex")}.tmp`,
	);
	try {
		const fd = openSync(tempPath, "wx", mode);
		try {
			writeFileSync(fd, content);
		} finally {
			closeSync(fd);
		}
		try {
			chmodSync(tempPath, statSync(path).mode & 0o777);
		} catch {
			chmodSync(tempPath, mode);
		}
		renameSync(tempPath, path);
	} catch (error) {
		try {
			unlinkSync(tempPath);
		} catch {
			// Best-effort: temp may not exist (open failed) or may already be renamed.
		}
		throw error;
	}
};
const writeJson = (path, value, mode) => {
	atomicWriteFile(path, `${JSON.stringify(value, null, 2)}\n`, mode ?? 0o600);
	if (mode !== undefined) chmodSync(path, mode);
};
const copyIfMissing = (from, to, mode) => {
	if (!existsSync(from) || existsSync(to)) return false;
	atomicWriteFile(to, readFileSync(from), mode ?? 0o600);
	if (mode !== undefined) chmodSync(to, mode);
	return true;
};

// Only inspect profile roots created by REPI's worker/session isolation code.
// Evidence can contain arbitrary user fixtures named settings.json, so do not
// recursively discover files by name.
const knownIsolatedProfileSettings = (root) => {
	const paths = [join(root, "settings.json")];
	const add = (path) => paths.push(path);
	const threadRoot = join(root, "recon", "agent-threads");
	try {
		for (const entry of readdirSync(threadRoot, { withFileTypes: true })) {
			if (entry.isDirectory()) add(join(threadRoot, entry.name, "agent-home", "settings.json"));
		}
	} catch {}
	const swarmsRoot = join(root, "recon", "evidence", "swarms");
	try {
		for (const entry of readdirSync(swarmsRoot, { withFileTypes: true })) {
			if (!entry.isDirectory()) continue;
			if (/-sessions$/.test(entry.name)) add(join(swarmsRoot, entry.name, ".repi", "agent", "settings.json"));
			if (/-worker-child-session-runtime-child-process$/.test(entry.name)) {
				add(join(swarmsRoot, entry.name, "home", ".repi", "agent", "settings.json"));
			}
		}
	} catch {}
	return [...new Set(paths)];
};
const removeRetiredMemorySetting = (path) => {
	const settings = readJson(path);
	if (!settings || Array.isArray(settings) || !Object.prototype.hasOwnProperty.call(settings, "memory")) return;
	delete settings.memory;
	writeJson(path, settings, 0o600);
};

// Remove state written by the retired persistent-memory/file-profile runtime.
// Keep session transcripts, mission state, and ordinary evidence intact.
const removeRetiredRuntimeState = (root) => {
	const remove = (path) => {
		try {
			rmSync(path, { recursive: true, force: true });
		} catch {
			// Best effort: stale locked state must not block startup.
		}
	};
	for (const path of [
		join(root, "memory"),
		join(root, "SYSTEM.md"),
		join(root, "APPEND_SYSTEM.md"),
		join(root, "prompts", "memory.md"),
		join(root, "skills", "reverse-pentest-orchestrator"),
		join(root, "recon", "memory"),
		join(root, "recon", "builtin"),
		join(root, "recon", "evidence", "knowledge"),
		join(root, "recon", "evidence", "tool-calls"),
	]) remove(path);
	try {
		for (const entry of readdirSync(join(root, "extensions"), { withFileTypes: true })) {
			if (entry.isDirectory() && /^(?:legacy-tools|legacy-hooks)-/.test(entry.name)) {
				remove(join(root, "extensions", entry.name));
			}
		}
	} catch {}
	try {
		const runsDir = join(root, "recon", "evidence", "runs");
		for (const entry of readdirSync(runsDir, { withFileTypes: true })) {
			if (/(?:case-memory|knowledge-graph)/i.test(entry.name)) remove(join(runsDir, entry.name));
		}
	} catch {}
	const archiveDir = join(root, "recon", "archive");
	try {
		for (const entry of readdirSync(archiveDir, { withFileTypes: true })) {
			if (entry.isDirectory() && /^(?:legacy-file-profile|poison-cleanup-runtime)-/.test(entry.name)) {
				remove(join(archiveDir, entry.name));
			}
		}
	} catch {}
	const threadRoot = join(root, "recon", "agent-threads");
	try {
		for (const entry of readdirSync(threadRoot, { withFileTypes: true })) {
			if (!entry.isDirectory()) continue;
			const worker = join(threadRoot, entry.name, "agent-home");
			for (const path of [
				join(worker, "memory"),
				join(worker, "SYSTEM.md"),
				join(worker, "APPEND_SYSTEM.md"),
				join(worker, "prompts", "memory.md"),
				join(worker, "skills", "reverse-pentest-orchestrator"),
				join(worker, "recon", "memory"),
				join(worker, "recon", "builtin"),
				join(worker, "recon", "evidence", "knowledge"),
				join(worker, "recon", "evidence", "tool-calls"),
			]) remove(path);
		}
	} catch {}
	for (const settingsPath of knownIsolatedProfileSettings(root)) removeRetiredMemorySetting(settingsPath);
};

mkdir(agentDir);
mkdir(join(agentDir, "sessions"));
// Keep install-time bootstrap minimal. Mission/evidence/tool directories are
// created by the first operation that needs them, so a fresh profile has no
// empty artifact tree to carry around.
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
const existingCompaction = settings.compaction ?? {};
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
delete settings["memory"];
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
	if (!Array.isArray(settings[key])) continue;
	const filtered = settings[key].filter((x) => !String(x).includes("reverse-pentest") && String(x) !== "prompts");
	if (filtered.length === 0) delete settings[key];
	else if (filtered.length !== settings[key].length) settings[key] = filtered;
}
writeJson(settingsPath, settings, 0o600);

const manifestPath = join(agentDir, "recon", "profile.json");
writeJson(manifestPath, {
	name: "repi",
	kind: "isolated-repi-profile",
	repoRoot,
	agentDir,
	legacyPiImported: { requested: importLegacyPiProfile, source: legacyPiAgentDir, models: copiedModels, auth: copiedAuth },
	resources: {
		storage: "recon/",
		settings: "settings.json",
		models: existsSync(join(agentDir, "models.json")) ? "models.json" : null,
		auth: existsSync(join(agentDir, "auth.json")) ? "auth.json" : null,
	},
}, 0o600);

if (process.env.REPI_INIT_VERBOSE === "1") {
	console.error(`[repi:init] agentDir=${agentDir}`);
	if (!importLegacyPiProfile) console.error("[repi:init] legacy pi import skipped (default isolated mode)");
	if (copiedModels) console.error(`[repi:init] copied models.json from ${legacyPiAgentDir}`);
	if (copiedAuth) console.error(`[repi:init] copied auth.json from ${legacyPiAgentDir}`);
}
