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
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ENV_AGENT_DIR } from "../src/config.ts";
import { initializeRepiProfile } from "../src/core/repi-profile-init.ts";

// Foundational opt #265: repi-profile-init writeJson used bare writeFileSync
// (truncate-then-write) for settings.json + profile.json on EVERY startup. A
// crash mid-write truncated the file → readJson swallows the JSON.parse
// failure → settings rebuilt from defaults only → user customizations
// (retry/compaction/model overrides) permanently lost. Routed through
// atomicWriteFileSync (temp+rename, mode-preserved) — same doctrine as the
// opt #43 SettingsManager runtime path. The inode-change probe distinguishes
// temp+rename (new inode) from truncate-then-write (same inode). Driven via
// the public initializeRepiProfile with REPI_CODING_AGENT_DIR pointed at a
// temp dir (the real startup path, no private export needed).

describe("initializeRepiProfile writes settings.json + profile.json atomically (opt #265)", () => {
	let dir: string;
	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-init-atomic-265-"));
		process.env[ENV_AGENT_DIR] = dir;
	});
	afterEach(() => {
		delete process.env[ENV_AGENT_DIR];
		rmSync(dir, { recursive: true, force: true });
	});

	it("atomically replaces changed settings and skips an unchanged third write", () => {
		initializeRepiProfile({ repoRoot: dir });
		const settingsPath = join(dir, "settings.json");
		expect(existsSync(settingsPath)).toBe(true);
		const ino1 = statSync(settingsPath).ino;

		// Force a migration so the second init has real content to replace.
		writeFileSync(settingsPath, `${JSON.stringify({ compaction: { reserveTokens: 32768 } }, null, 2)}\n`);
		initializeRepiProfile({ repoRoot: dir });
		const ino2 = statSync(settingsPath).ino;

		if (ino1 === 0 || ino2 === 0) {
			console.warn("inode-change probe not supported on this filesystem (ino=0); skipping");
			return;
		}
		// Atomic temp+rename → a NEW inode replaces the old. Truncate-then-write
		// keeps the SAME inode → this assertion pins the fix.
		expect(ino2).not.toBe(ino1);

		// Content is complete + parseable (not torn).
		const parsed = JSON.parse(readFileSync(settingsPath, "utf8")) as Record<string, unknown>;
		expect(parsed.retry).toBeDefined();
		expect(parsed).not.toHaveProperty("memory");

		initializeRepiProfile({ repoRoot: dir });
		expect(statSync(settingsPath).ino).toBe(ino2);
	});

	it("replaces the profile.json inode between writes and leaves no .tmp orphan", () => {
		initializeRepiProfile({ repoRoot: join(dir, "changed-root") });
		const manifestPath = join(dir, "recon", "profile.json");
		expect(existsSync(manifestPath)).toBe(true);
		const ino1 = statSync(manifestPath).ino;

		initializeRepiProfile({ repoRoot: dir });
		const ino2 = statSync(manifestPath).ino;

		if (ino1 === 0 || ino2 === 0) {
			console.warn("inode-change probe not supported on this filesystem (ino=0); skipping");
			return;
		}
		expect(ino2).not.toBe(ino1);

		// No orphaned temp files anywhere under the agent dir.
		function collectTmp(root: string): string[] {
			const out: string[] = [];
			for (const entry of readdirSync(root, { withFileTypes: true })) {
				if (entry.name.endsWith(".tmp")) out.push(join(root, entry.name));
				if (entry.isDirectory()) out.push(...collectTmp(join(root, entry.name)));
			}
			return out;
		}
		expect(collectTmp(dir)).toEqual([]);

		// Both files are mode 0o600 (private).
		expect(statSync(join(dir, "settings.json")).mode & 0o777).toBe(0o600);
		expect(statSync(manifestPath).mode & 0o777).toBe(0o600);
	});

	it("removes only retired memory, trace, and file-profile state", () => {
		const stalePaths = [
			join(dir, "memory", "case-index.md"),
			join(dir, "SYSTEM.md"),
			join(dir, "APPEND_SYSTEM.md"),
			join(dir, "prompts", "memory.md"),
			join(dir, "skills", "reverse-pentest-orchestrator", "references", "memory-schema.md"),
			join(dir, "recon", "memory", "vector-index.json"),
			join(dir, "recon", "builtin", "prompts", "memory.md"),
			join(dir, "recon", "evidence", "knowledge", "graph.md"),
			join(dir, "recon", "evidence", "runs", "old-case-memory-repair.md"),
			join(dir, "recon", "evidence", "tool-calls", "tool-call-trace.jsonl"),
			join(dir, "recon", "archive", "legacy-file-profile-2020", "SYSTEM.md"),
			join(dir, "recon", "archive", "poison-cleanup-runtime-2020", "memory", "events.jsonl"),
			join(dir, "recon", "agent-threads", "run-1", "agent-home", "recon", "memory", "events.jsonl"),
			join(dir, "recon", "agent-threads", "run-1", "agent-home", "prompts", "memory.md"),
			join(dir, "recon", "agent-threads", "run-1", "agent-home", "recon", "evidence", "tool-calls", "trace.jsonl"),
		];
		const preservedPaths = [
			join(dir, "sessions", "session.jsonl"),
			join(dir, "evidence", "ledger.md"),
			join(dir, "mission", "current.json"),
			join(dir, "reports", "latest.md"),
			join(dir, "recon", "mission", "current.json"),
			join(dir, "recon", "evidence", "ledger.md"),
			join(dir, "recon", "archive", "compact-ledger-corrupt-2020", "repair.json"),
			join(dir, "recon", "agent-threads", "run-1", "handoff.md"),
			join(dir, "recon", "agent-threads", "run-1", "agent-home", "evidence", "ledger.md"),
			join(dir, "recon", "agent-threads", "run-1", "agent-home", "mission", "current.json"),
			join(dir, "recon", "agent-threads", "run-1", "agent-home", "reports", "latest.md"),
		];
		const isolatedSettings = [
			join(dir, "recon", "agent-threads", "run-1", "agent-home", "settings.json"),
			join(dir, "recon", "evidence", "swarms", "2020-run-sessions", ".repi", "agent", "settings.json"),
			join(
				dir,
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
		const unrelatedEvidenceSettings = join(dir, "recon", "evidence", "swarms", "notes", "settings.json");
		for (const path of [...stalePaths, ...preservedPaths]) {
			mkdirSync(join(path, ".."), { recursive: true });
			writeFileSync(path, "stale\n");
		}
		writeFileSync(
			join(dir, "settings.json"),
			JSON.stringify({
				memory: { autoRecall: true },
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

		initializeRepiProfile({ repoRoot: dir });

		for (const path of stalePaths) expect(existsSync(path), path).toBe(false);
		for (const path of preservedPaths) expect(existsSync(path), path).toBe(true);
		const settings = JSON.parse(readFileSync(join(dir, "settings.json"), "utf8"));
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
});
