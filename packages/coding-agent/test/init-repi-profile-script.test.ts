import { spawnSync } from "node:child_process";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const INIT_SCRIPT = fileURLToPath(new URL("../../../scripts/reverse-agent/init-repi-profile.mjs", import.meta.url));

function collectTmp(root: string): string[] {
	const out: string[] = [];
	for (const entry of readdirSync(root, { withFileTypes: true })) {
		const path = join(root, entry.name);
		if (entry.name.endsWith(".tmp")) out.push(path);
		if (entry.isDirectory()) out.push(...collectTmp(path));
	}
	return out;
}

describe("init-repi-profile.mjs install-time profile initialization", () => {
	let tempRoot: string;
	let agentDir: string;
	let repoRoot: string;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-init-script-"));
		agentDir = join(tempRoot, "agent");
		repoRoot = join(tempRoot, "repo");
		mkdirSync(repoRoot, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempRoot, { recursive: true, force: true });
	});

	function runInit() {
		const result = spawnSync(process.execPath, [INIT_SCRIPT, repoRoot], {
			encoding: "utf8",
			env: {
				...process.env,
				REPI_CODING_AGENT_DIR: agentDir,
				REPI_IMPORT_PI_PROFILE: "0",
				REPI_IMPORT_PI_AUTH: "0",
			},
			timeout: 10_000,
		});
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
	}

	it("rewrites settings/profile by temp+rename and leaves no temp files", () => {
		runInit();
		const settingsPath = join(agentDir, "settings.json");
		const profilePath = join(agentDir, "recon", "profile.json");
		const settingsInode = statSync(settingsPath).ino;
		const profileInode = statSync(profilePath).ino;

		runInit();

		const nextSettingsInode = statSync(settingsPath).ino;
		const nextProfileInode = statSync(profilePath).ino;
		if (settingsInode !== 0 && nextSettingsInode !== 0) expect(nextSettingsInode).not.toBe(settingsInode);
		if (profileInode !== 0 && nextProfileInode !== 0) expect(nextProfileInode).not.toBe(profileInode);
		expect(JSON.parse(readFileSync(settingsPath, "utf8")).memory.schemaVersion).toBe(2);
		expect(JSON.parse(readFileSync(profilePath, "utf8")).kind).toBe("isolated-repi-profile");
		expect(statSync(settingsPath).mode & 0o777).toBe(0o600);
		expect(statSync(profilePath).mode & 0o777).toBe(0o600);
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("does not seed legacy global memory files before the cwd-scoped store exists", () => {
		runInit();

		for (const name of [
			"field-journal.md",
			"case-index.md",
			"evolution-log.md",
			"core-memory.md",
			"project-memory.md",
			"procedural-memory.md",
			"events.jsonl",
		]) {
			expect(existsSync(join(agentDir, "recon", "memory", name))).toBe(false);
		}
		expect(existsSync(join(agentDir, "recon", "memory", "playbooks"))).toBe(false);
		expect(existsSync(join(agentDir, "recon", "evidence", "ledger.md"))).toBe(true);
		expect(existsSync(join(agentDir, "recon", "tools", "tool-index.md"))).toBe(true);
	});

	it("copies legacy model/auth files atomically with private permissions", () => {
		const legacyAgentDir = join(tempRoot, "legacy-pi", "agent");
		mkdirSync(legacyAgentDir, { recursive: true });
		writeFileSync(join(legacyAgentDir, "models.json"), '{"providers":{}}\n');
		writeFileSync(join(legacyAgentDir, "auth.json"), '{"secrets":{}}\n');

		const result = spawnSync(process.execPath, [INIT_SCRIPT, repoRoot], {
			encoding: "utf8",
			env: {
				...process.env,
				REPI_CODING_AGENT_DIR: agentDir,
				PI_AGENT_IMPORT_DIR: legacyAgentDir,
				REPI_IMPORT_PI_PROFILE: "1",
			},
			timeout: 10_000,
		});
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);

		for (const name of ["models.json", "auth.json"]) {
			const path = join(agentDir, name);
			expect(readFileSync(path, "utf8")).toContain("{}");
			expect(statSync(path).mode & 0o777).toBe(0o600);
		}
		expect(collectTmp(agentDir)).toEqual([]);
	});
});
