import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// opt #273: memory must be project-scoped (per-cwd), not global, to prevent
// cross-project memory pollution. setMemoryScopeCwd(cwd) routes ALL memory*Path()
// helpers under recon/memory/projects/<encoded-cwd>/; null falls back to the
// legacy global recon/memory root (backwards compatible for CLI tools w/o a cwd).

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

describe("repi memory per-cwd scoping (opt #273)", () => {
	let originalAgentDir: string | undefined;
	let tempAgentDir: string;
	let projectCwd: string;

	beforeEach(() => {
		originalAgentDir = process.env[ENV_AGENT_DIR];
		tempAgentDir = mkdtempSync(join(tmpdir(), "repi-mem-scope-"));
		process.env[ENV_AGENT_DIR] = tempAgentDir;
		projectCwd = mkdtempSync(join(tmpdir(), "repi-proj-"));
	});

	afterEach(async () => {
		if (originalAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = originalAgentDir;
		const { setMemoryScopeCwd } = await import("../src/core/repi/storage.ts");
		setMemoryScopeCwd(null);
	});

	it("encodeCwdForScope mirrors the session-manager getDefaultSessionDirPath encoding", async () => {
		const { encodeCwdForScope } = await import("../src/core/repi/storage.ts");
		const encoded = encodeCwdForScope(projectCwd);
		// Mirrors session-manager.ts:494: `--${resolvedCwd.replace(/^[/\\]/,"").replace(/[/\\:]/g,"-")}--`
		const expected = `--${projectCwd.replace(/^[/\\]/, "").replace(/[/\\:]/g, "-")}--`;
		expect(encoded).toBe(expected);
		expect(encoded.startsWith("--")).toBe(true);
		expect(encoded.endsWith("--")).toBe(true);
		expect(encoded).not.toContain("/");
		expect(encoded).not.toContain("\\");
		expect(encoded).not.toContain(":");
	});

	it("memoryPath lands under projects/<encoded-cwd>/ when scope is set", async () => {
		const { setMemoryScopeCwd, memoryPath, encodeCwdForScope } = await import("../src/core/repi/storage.ts");
		setMemoryScopeCwd(projectCwd);
		const eventsPath = memoryPath("events.jsonl");
		const encoded = encodeCwdForScope(projectCwd);
		expect(eventsPath).toBe(join(tempAgentDir, "recon", "memory", "projects", encoded, "events.jsonl"));
		expect(eventsPath).not.toBe(join(tempAgentDir, "recon", "memory", "events.jsonl"));
		// The global root must NOT be the target — that's the pollution bug.
		expect(eventsPath.includes("projects")).toBe(true);
	});

	it("memoryPlaybooksDir lands under projects/<encoded-cwd>/playbooks when scope is set", async () => {
		const { setMemoryScopeCwd, memoryPlaybooksDir, encodeCwdForScope } = await import("../src/core/repi/storage.ts");
		setMemoryScopeCwd(projectCwd);
		const dir = memoryPlaybooksDir();
		const encoded = encodeCwdForScope(projectCwd);
		expect(dir).toBe(join(tempAgentDir, "recon", "memory", "projects", encoded, "playbooks"));
	});

	it("two different cwds resolve to two different scoped roots (no pollution)", async () => {
		const { setMemoryScopeCwd, memoryPath } = await import("../src/core/repi/storage.ts");
		const projectB = mkdtempSync(join(tmpdir(), "repi-projB-"));
		setMemoryScopeCwd(projectCwd);
		const aPath = memoryPath("events.jsonl");
		setMemoryScopeCwd(projectB);
		const bPath = memoryPath("events.jsonl");
		expect(aPath).not.toBe(bPath);
		expect(aPath).not.toBe(bPath.replace(/repi-projB-[\w-]+/, projectCwd.replace(/^.*\//, "")));
	});

	it("falls back to the legacy global root when scope is null (backwards compat)", async () => {
		const { setMemoryScopeCwd, memoryPath, memoryPlaybooksDir } = await import("../src/core/repi/storage.ts");
		setMemoryScopeCwd(null);
		expect(memoryPath("events.jsonl")).toBe(join(tempAgentDir, "recon", "memory", "events.jsonl"));
		expect(memoryPlaybooksDir()).toBe(join(tempAgentDir, "recon", "memory", "playbooks"));
	});

	it("writing via memoryPath actually lands in the scoped dir on disk", async () => {
		const { setMemoryScopeCwd, memoryPath, encodeCwdForScope } = await import("../src/core/repi/storage.ts");
		setMemoryScopeCwd(projectCwd);
		const eventsPath = memoryPath("events.jsonl");
		mkdirSync(join(eventsPath, ".."), { recursive: true });
		writeFileSync(eventsPath, '{"kind":"test"}\n');
		const encoded = encodeCwdForScope(projectCwd);
		const scopedFile = join(tempAgentDir, "recon", "memory", "projects", encoded, "events.jsonl");
		expect(existsSync(scopedFile)).toBe(true);
		// And the global root file must NOT exist.
		expect(existsSync(join(tempAgentDir, "recon", "memory", "events.jsonl"))).toBe(false);
	});
});
