import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

type FsModule = typeof import("node:fs");
type CopyFileSyncArgs = Parameters<FsModule["copyFileSync"]>;

// A failed copyFileSync can leave a prefix at the destination. The old worker
// provisioning path swallowed that error and launched with the torn file; the
// legacy profile importer also skipped that existing torn file on later starts.
// Simulate that exact failure. The fixed paths do not call copyFileSync: they
// publish complete JSON through atomicWriteFileSync.
vi.mock("node:fs", async (importOriginal) => {
	const actual = await importOriginal<FsModule>();
	return {
		...actual,
		copyFileSync: vi.fn((...args: CopyFileSyncArgs) => {
			const [source, destination] = args;
			if (String(destination).includes("agent-home") || String(destination).includes("profile-target")) {
				const content = actual.readFileSync(source);
				actual.writeFileSync(destination, content.subarray(0, Math.min(3, content.length)));
				const error = new Error("ENOSPC: no space left on device, copyfile") as Error & { code: string };
				error.code = "ENOSPC";
				throw error;
			}
			return actual.copyFileSync(...args);
		}),
	};
});

const { createAgentThreadManager } = await import("../src/core/agent-thread-manager.ts");
const { initializeRepiProfile } = await import("../src/core/repi-profile-init.ts");
const { ENV_AGENT_DIR } = await import("../src/config.ts");

describe("AgentThreadManager worker profile atomic provisioning", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("publishes complete private config files instead of retaining a partial failed copy", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-thread-profile-atomic-"));
		const agentDir = join(tempRoot, "agent");
		const sourceFiles = {
			"models.json": '{"providers":{"fixture":{"apiKey":"secret"}}}\n',
			"settings.json": '{"defaultProvider":"fixture","defaultModel":"model"}\n',
			"auth.json": '{"fixture":{"type":"api_key","key":"secret"}}\n',
		} as const;
		mkdirSync(agentDir, { recursive: true });
		for (const [name, content] of Object.entries(sourceFiles)) {
			writeFileSync(join(agentDir, name), content, { mode: 0o600 });
		}

		const manager = createAgentThreadManager({
			cwd: tempRoot,
			agentDir,
			repiBinPath: join(tempRoot, "missing-repi"),
		});
		const manifest = await manager.spawnThread({ specName: "verifier", task: "profile copy", timeoutMs: 5000 });
		await manager.awaitRun(manifest.runId);

		for (const [name, content] of Object.entries(sourceFiles)) {
			const destination = join(manifest.agentDir, name);
			expect(existsSync(destination), name).toBe(true);
			expect(readFileSync(destination, "utf8"), name).toBe(content);
			expect(statSync(destination).mode & 0o777, name).toBe(0o600);
		}
	});
});

describe("initializeRepiProfile legacy config atomic import", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		delete process.env[ENV_AGENT_DIR];
		delete process.env.PI_AGENT_IMPORT_DIR;
		delete process.env.REPI_IMPORT_PI_PROFILE;
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("imports complete private legacy config files instead of retaining a partial failed copy", () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-profile-import-atomic-"));
		const legacyDir = join(tempRoot, "legacy-agent");
		const targetDir = join(tempRoot, "profile-target");
		const sourceFiles = {
			"models.json": '{"providers":{"legacy":{"apiKey":"secret"}}}\n',
			"auth.json": '{"legacy":{"type":"api_key","key":"secret"}}\n',
		} as const;
		mkdirSync(legacyDir, { recursive: true });
		for (const [name, content] of Object.entries(sourceFiles)) {
			writeFileSync(join(legacyDir, name), content, { mode: 0o600 });
		}
		process.env[ENV_AGENT_DIR] = targetDir;
		process.env.PI_AGENT_IMPORT_DIR = legacyDir;
		process.env.REPI_IMPORT_PI_PROFILE = "1";

		const result = initializeRepiProfile({ repoRoot: tempRoot });

		expect(result.copiedModels).toBe(true);
		expect(result.copiedAuth).toBe(true);
		for (const [name, content] of Object.entries(sourceFiles)) {
			const destination = join(targetDir, name);
			expect(readFileSync(destination, "utf8"), name).toBe(content);
			expect(statSync(destination).mode & 0o777, name).toBe(0o600);
		}
	});
});
