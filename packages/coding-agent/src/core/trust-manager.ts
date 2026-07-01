import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync } from "node:fs";
import { dirname, join } from "node:path";
import lockfile from "proper-lockfile";
import { CONFIG_DIR_NAME } from "../config.ts";
import { canonicalizePath, resolvePath } from "../utils/paths.ts";
import { atomicWriteFileSync } from "./tools/atomic-write.ts";

export type ProjectTrustDecision = boolean | null;

type TrustFile = Record<string, boolean | null | undefined>;

const CONTEXT_FILE_NAMES = ["AGENTS.md", "AGENTS.MD", "CLAUDE.md", "CLAUDE.MD"];

function normalizeCwd(cwd: string): string {
	return canonicalizePath(resolvePath(cwd));
}

function nearestMarkerDir(cwd: string, markerCheck: (dir: string) => boolean): string | undefined {
	let currentDir = normalizeCwd(cwd);
	while (true) {
		if (markerCheck(currentDir)) {
			return currentDir;
		}
		const parentDir = dirname(currentDir);
		if (parentDir === currentDir) {
			return undefined;
		}
		currentDir = parentDir;
	}
}

function nearestGitRoot(cwd: string): string | undefined {
	return nearestMarkerDir(cwd, (dir) => existsSync(join(dir, ".git")));
}

function nearestProjectContextRoot(cwd: string): string | undefined {
	return nearestMarkerDir(cwd, (dir) => {
		if (existsSync(join(dir, CONFIG_DIR_NAME))) {
			return true;
		}
		if (existsSync(join(dir, ".agents", "skills"))) {
			return true;
		}
		return CONTEXT_FILE_NAMES.some((filename) => existsSync(join(dir, filename)));
	});
}

function trustAliasesForCwd(cwd: string): string[] {
	const aliases = new Set<string>();
	aliases.add(normalizeCwd(cwd));
	if (process.env.PWD) {
		aliases.add(normalizeCwd(process.env.PWD));
	}
	const gitRoot = nearestGitRoot(cwd);
	if (gitRoot) {
		aliases.add(gitRoot);
	}
	const contextRoot = nearestProjectContextRoot(cwd);
	if (contextRoot) {
		aliases.add(contextRoot);
	}
	return Array.from(aliases);
}

function readTrustFile(path: string): TrustFile {
	if (!existsSync(path)) {
		return {};
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(readFileSync(path, "utf-8"));
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return quarantineTrustFile(path, `Failed to read trust store: ${message}`);
	}

	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		return quarantineTrustFile(path, "Invalid trust store: expected an object");
	}

	const data: TrustFile = {};
	for (const [key, value] of Object.entries(parsed)) {
		if (value !== true && value !== false && value !== null) {
			return quarantineTrustFile(
				path,
				`Invalid trust store: value for ${JSON.stringify(key)} must be true, false, or null`,
			);
		}
		data[key] = value;
	}
	return data;
}

function chmodPrivate(path: string, mode: number): void {
	try {
		chmodSync(path, mode);
	} catch {
		// Best-effort on non-POSIX filesystems.
	}
}

function quarantineTrustFile(path: string, reason: string): TrustFile {
	const suffix = new Date().toISOString().replace(/[:.]/g, "-");
	const backupPath = `${path}.bad.${suffix}`;
	try {
		renameSync(path, backupPath);
		console.error(`${reason}; moved to ${backupPath}`);
	} catch {
		console.error(`${reason}; using an empty in-memory trust store for this run`);
	}
	return {};
}

function writeTrustFile(path: string, data: TrustFile): void {
	const sorted: TrustFile = {};
	for (const key of Object.keys(data).sort()) {
		const value = data[key];
		if (value === true || value === false || value === null) {
			sorted[key] = value;
		}
	}
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	chmodPrivate(dirname(path), 0o700);
	// Atomic temp+rename (mode 0o600): a plain writeFileSync truncates then
	// writes, so a crash mid-write leaves a truncated/partial trust.json. The
	// reader self-heals (readTrustFile → quarantineTrustFile renames a bad file
	// aside and returns {}), but that SILENTLY loses every prior trust decision
	// → the user is re-prompted to trust dirs they already approved. temp+rename
	// means a reader sees either the complete prior trust store or the complete
	// new one, so a crash can't destroy decisions. chmodPrivate after the rename
	// still enforces 0o600 (atomicWriteFileSync preserves an existing target's
	// mode, which could be wrong if the file predates 0o600 enforcement).
	atomicWriteFileSync(path, `${JSON.stringify(sorted, null, 2)}\n`, 0o600);
	chmodPrivate(path, 0o600);
}

function acquireTrustLockSync(path: string): () => void {
	const trustDir = dirname(path);
	mkdirSync(trustDir, { recursive: true, mode: 0o700 });
	chmodPrivate(trustDir, 0o700);
	const maxAttempts = 10;
	const delayMs = 20;
	let lastError: unknown;

	for (let attempt = 1; attempt <= maxAttempts; attempt++) {
		try {
			return lockfile.lockSync(trustDir, { realpath: false, lockfilePath: `${path}.lock` });
		} catch (error) {
			const code =
				typeof error === "object" && error !== null && "code" in error
					? String((error as { code?: unknown }).code)
					: undefined;
			if (code !== "ELOCKED" || attempt === maxAttempts) {
				throw error;
			}
			lastError = error;
			const start = Date.now();
			while (Date.now() - start < delayMs) {
				// Sleep synchronously to avoid changing trust store callers to async.
			}
		}
	}

	if (lastError instanceof Error) {
		throw lastError;
	}
	throw new Error("Failed to acquire trust store lock");
}

function withTrustFileLock<T>(path: string, fn: () => T): T {
	const release = acquireTrustLockSync(path);
	try {
		return fn();
	} finally {
		release();
	}
}

export function hasProjectTrustInputs(cwd: string): boolean {
	let currentDir = canonicalizePath(resolvePath(cwd));
	if (existsSync(join(currentDir, CONFIG_DIR_NAME))) {
		return true;
	}

	while (true) {
		for (const filename of CONTEXT_FILE_NAMES) {
			if (existsSync(join(currentDir, filename))) {
				return true;
			}
		}
		if (existsSync(join(currentDir, ".agents", "skills"))) {
			return true;
		}

		const parentDir = dirname(currentDir);
		if (parentDir === currentDir) {
			return false;
		}
		currentDir = parentDir;
	}
}

export class ProjectTrustStore {
	private trustPath: string;

	constructor(agentDir: string) {
		this.trustPath = join(resolvePath(agentDir), "trust.json");
	}

	get(cwd: string): ProjectTrustDecision {
		return withTrustFileLock(this.trustPath, () => {
			const data = readTrustFile(this.trustPath);
			let current = normalizeCwd(cwd);

			while (true) {
				const value = data[current];
				if (value === true || value === false) {
					return value;
				}

				const parent = dirname(current);
				if (parent === current) {
					return null;
				}
				current = parent;
			}
		});
	}

	set(cwd: string, decision: ProjectTrustDecision): void {
		withTrustFileLock(this.trustPath, () => {
			const data = readTrustFile(this.trustPath);
			for (const key of trustAliasesForCwd(cwd)) {
				if (decision === null) {
					delete data[key];
				} else {
					data[key] = decision;
				}
			}
			writeTrustFile(this.trustPath, data);
		});
	}
}
