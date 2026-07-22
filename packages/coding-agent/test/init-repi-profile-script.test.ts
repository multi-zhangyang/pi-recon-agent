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
		expect(JSON.parse(readFileSync(settingsPath, "utf8"))).not.toHaveProperty("memory");
		expect(JSON.parse(readFileSync(profilePath, "utf8")).kind).toBe("isolated-repi-profile");
		expect(statSync(settingsPath).mode & 0o777).toBe(0o600);
		expect(statSync(profilePath).mode & 0o777).toBe(0o600);
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("keeps install-time storage minimal", () => {
		runInit();

		expect(existsSync(join(agentDir, "recon", "memory"))).toBe(false);
		expect(existsSync(join(agentDir, "recon", "evidence"))).toBe(false);
		expect(existsSync(join(agentDir, "recon", "tools"))).toBe(false);
	});

	it("migrates retired state without deleting sessions, missions, evidence, or reports", () => {
		const stalePaths = [
			join(agentDir, "memory", "case-index.md"),
			join(agentDir, "SYSTEM.md"),
			join(agentDir, "APPEND_SYSTEM.md"),
			join(agentDir, "prompts", "memory.md"),
			join(agentDir, "skills", "reverse-pentest-orchestrator", "references", "memory-schema.md"),
			join(agentDir, "recon", "memory", "events.jsonl"),
			join(agentDir, "recon", "builtin", "prompts", "memory.md"),
			join(agentDir, "recon", "evidence", "knowledge", "graph.md"),
			join(agentDir, "recon", "evidence", "runs", "old-case-memory-repair.md"),
			join(agentDir, "recon", "evidence", "tool-calls", "trace.jsonl"),
			join(agentDir, "recon", "archive", "legacy-file-profile-old", "extension.ts"),
			join(agentDir, "recon", "agent-threads", "run-1", "agent-home", "recon", "memory", "events.jsonl"),
			join(agentDir, "recon", "agent-threads", "run-1", "agent-home", "prompts", "memory.md"),
		];
		const preservedPaths = [
			join(agentDir, "sessions", "keep.jsonl"),
			join(agentDir, "evidence", "ledger.md"),
			join(agentDir, "mission", "current.json"),
			join(agentDir, "reports", "latest.md"),
			join(agentDir, "recon", "agent-threads", "run-1", "agent-home", "evidence", "ledger.md"),
			join(agentDir, "recon", "agent-threads", "run-1", "agent-home", "mission", "current.json"),
			join(agentDir, "recon", "agent-threads", "run-1", "agent-home", "reports", "latest.md"),
		];
		const isolatedSettings = [
			join(agentDir, "recon", "agent-threads", "run-1", "agent-home", "settings.json"),
			join(agentDir, "recon", "evidence", "swarms", "2020-run-sessions", ".repi", "agent", "settings.json"),
			join(
				agentDir,
				"recon",
				"evidence",
				"swarms",
				"2020-run-worker-child-session-runtime-child-process",
				"home",
				".repi",
				"agent",
				"settings.json",
			),
		];
		const unrelatedEvidenceSettings = join(agentDir, "recon", "evidence", "swarms", "notes", "settings.json");
		for (const path of [...stalePaths, ...preservedPaths]) {
			mkdirSync(join(path, ".."), { recursive: true });
			writeFileSync(path, "stale\n");
		}
		writeFileSync(
			join(agentDir, "settings.json"),
			JSON.stringify({
				memory: { autoInject: true },
				extensions: ["custom-extension.ts", "reverse-pentest-core.ts"],
				skills: ["custom-skill", "reverse-pentest-orchestrator"],
				prompts: ["custom-prompt", "prompts"],
				enabledModels: ["custom/model", "reverse-pentest/model"],
			}),
		);
		for (const path of isolatedSettings) {
			mkdirSync(join(path, ".."), { recursive: true });
			writeFileSync(path, JSON.stringify({ memory: { autoRecall: true }, defaultModel: "keep" }));
		}
		mkdirSync(join(unrelatedEvidenceSettings, ".."), { recursive: true });
		writeFileSync(unrelatedEvidenceSettings, JSON.stringify({ memory: { autoRecall: true } }));

		runInit();

		for (const path of stalePaths) expect(existsSync(path), path).toBe(false);
		for (const path of preservedPaths) expect(existsSync(path), path).toBe(true);
		const settings = JSON.parse(readFileSync(join(agentDir, "settings.json"), "utf8"));
		expect(settings).not.toHaveProperty("memory");
		expect(settings.extensions).toEqual(["custom-extension.ts"]);
		expect(settings.skills).toEqual(["custom-skill"]);
		expect(settings.prompts).toEqual(["custom-prompt"]);
		expect(settings.enabledModels).toEqual(["custom/model"]);
		for (const path of isolatedSettings) {
			const isolated = JSON.parse(readFileSync(path, "utf8"));
			expect(isolated).not.toHaveProperty("memory");
			expect(isolated.defaultModel).toBe("keep");
		}
		expect(JSON.parse(readFileSync(unrelatedEvidenceSettings, "utf8"))).toHaveProperty("memory");
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
