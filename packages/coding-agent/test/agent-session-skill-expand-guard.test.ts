import { mkdirSync, rmSync, type Stats, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #171 — stat-first guard for _expandSkillCommand's readFileSync of the
// skill file. Mock node:fs so we can simulate a pathologically large SKILL.md
// (statSync reports 5 GB, readFileSync throws ERR_FS_FILE_TOO_LARGE) and a
// non-regular skill path, without actually allocating GBs or opening a special
// file. Defaults to real behavior; per-test we override statSync/readFileSync
// for specific paths and delegate everything else to the real module.
vi.mock("node:fs", async () => {
	const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
	return {
		...actual,
		statSync: vi.fn(actual.statSync),
		readFileSync: vi.fn(actual.readFileSync),
	};
});

import * as fs from "node:fs";
import { Agent } from "@pi-recon/repi-agent-core";
import { getModel } from "@pi-recon/repi-ai";
import { AgentSession } from "../src/core/agent-session.ts";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { createExtensionRuntime } from "../src/core/extensions/loader.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import type { ResourceLoader } from "../src/core/resource-loader.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import { createSyntheticSourceInfo } from "../src/core/source-info.ts";
import { stripFrontmatter } from "../src/utils/frontmatter.ts";

const realFs = await vi.importActual<typeof import("node:fs")>("node:fs");

const SKILL_FIXTURE = `---
name: my-skill
description: A small test skill for opt #171 parity.
---

# My Skill

Body text here.
`;

function fakeStats(overrides: Partial<Stats> & { size: number; isFile?: () => boolean }): Stats {
	return {
		size: overrides.size,
		isFile: overrides.isFile ?? (() => true),
		isDirectory: overrides.isDirectory ?? (() => false),
		isBlockDevice: overrides.isBlockDevice ?? (() => false),
		isCharacterDevice: overrides.isCharacterDevice ?? (() => false),
		isFIFO: overrides.isFIFO ?? (() => false),
		isSocket: overrides.isSocket ?? (() => false),
	} as unknown as Stats;
}

describe("AgentSession _expandSkillCommand stat-first guard (opt #171)", () => {
	let tempDir: string;
	let session: AgentSession;
	let capturedErrors: { extensionPath: string; event: string; error: string }[];

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-skill-expand-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		capturedErrors = [];
		// Restore real delegation as the default for each test.
		vi.mocked(fs.statSync).mockImplementation(realFs.statSync);
		vi.mocked(fs.readFileSync).mockImplementation(realFs.readFileSync);
		delete process.env.REPI_READ_TEXT_FILE_MAX_BYTES;
	});

	afterEach(() => {
		if (session) session.dispose();
		if (tempDir && realFs.existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
		vi.mocked(fs.statSync).mockRestore();
		vi.mocked(fs.readFileSync).mockRestore();
		delete process.env.REPI_READ_TEXT_FILE_MAX_BYTES;
	});

	function buildSession(skill: { name: string; filePath: string; baseDir: string }): AgentSession {
		const resourceLoader: ResourceLoader = {
			getExtensions: () => ({ extensions: [], errors: [], runtime: createExtensionRuntime() }),
			getSkills: () => ({
				skills: [
					{
						name: skill.name,
						description: "test skill",
						filePath: skill.filePath,
						baseDir: skill.baseDir,
						sourceInfo: createSyntheticSourceInfo(skill.filePath, { source: "sdk" }),
						disableModelInvocation: false,
					},
				],
				diagnostics: [],
			}),
			getPrompts: () => ({ prompts: [], diagnostics: [] }),
			getThemes: () => ({ themes: [], diagnostics: [] }),
			getAgentsFiles: () => ({ agentsFiles: [] }),
			getSystemPrompt: () => undefined,
			getAppendSystemPrompt: () => [],
			extendResources: () => {},
			reload: async () => {},
		};

		const model = getModel("anthropic", "claude-sonnet-4-5")!;
		const agent = new Agent({
			getApiKey: () => "test-key",
			initialState: { model, systemPrompt: "Test", tools: [] },
			streamFn: () => {
				throw new Error("streamFn should not be called by expandSkillCommand");
			},
		});

		const sessionManager = SessionManager.inMemory();
		const settingsManager = SettingsManager.create(tempDir, tempDir);
		const authStorage = AuthStorage.create(join(tempDir, "auth.json"));
		const modelRegistry = ModelRegistry.create(authStorage, tempDir);

		const s = new AgentSession({
			agent,
			sessionManager,
			settingsManager,
			cwd: tempDir,
			modelRegistry,
			resourceLoader,
		});

		s.extensionRunner.onError((err) => {
			capturedErrors.push({
				extensionPath: err.extensionPath,
				event: err.event,
				error: err.error,
			});
		});
		return s;
	}

	it("small SKILL.md under the cap is byte-identical to the old readFileSync+stripFrontmatter path (parity pin)", () => {
		const skillDir = join(tempDir, "my-skill");
		mkdirSync(skillDir, { recursive: true });
		const skillFile = join(skillDir, "SKILL.md");
		writeFileSync(skillFile, SKILL_FIXTURE);

		session = buildSession({ name: "my-skill", filePath: skillFile, baseDir: skillDir });

		const result = session.expandSkillCommand("/skill:my-skill");

		// Expected = the exact skillBlock the OLD unguarded code would produce.
		const expectedBody = stripFrontmatter(realFs.readFileSync(skillFile, "utf-8")).trim();
		const expected = `<skill name="my-skill" location="${skillFile}">\nReferences are relative to ${skillDir}.\n\n${expectedBody}\n</skill>`;

		expect(result).toBe(expected);
		expect(result).not.toContain("REPI_READ_TEXT_FILE_MAX_BYTES");
		expect(capturedErrors).toEqual([]);
	});

	it("oversized skill file returns a bounded head+tail marker WITHOUT loading the whole file", () => {
		const hugePath = join(tempDir, "huge", "SKILL.md");
		const hugeBase = join(tempDir, "huge");
		const hugeSize = 5 * 1024 * 1024 * 1024; // 5 GB

		// statSync reports a 5 GB regular file; readFileSync throws (simulates
		// the OOM condition without allocating 5 GB).
		vi.mocked(fs.statSync).mockImplementation((p) => {
			if (String(p) === hugePath) return fakeStats({ size: hugeSize });
			return realFs.statSync(p);
		});
		vi.mocked(fs.readFileSync).mockImplementation((p, ...rest) => {
			if (String(p) === hugePath) {
				const err: NodeJS.ErrnoException = new Error(`File "${hugePath}" is too large`);
				err.code = "ERR_FS_FILE_TOO_LARGE";
				throw err;
			}
			return (realFs.readFileSync as unknown as (...a: unknown[]) => string)(p, ...rest);
		});

		session = buildSession({ name: "my-skill", filePath: hugePath, baseDir: hugeBase });

		const result = session.expandSkillCommand("/skill:my-skill");

		// skillBlock is still emitted to the model, but with a marker body.
		expect(result).toContain(`<skill name="my-skill"`);
		expect(result).toContain(hugePath);
		expect(result).toContain("REPI_READ_TEXT_FILE_MAX_BYTES");
		expect(result).toContain("not inlined to avoid OOM");

		// The whole file was NOT loaded: readFileSync must not have been called
		// for the huge path (it would have thrown into the catch → original text).
		const hugeReads = vi.mocked(fs.readFileSync).mock.calls.filter((c) => String(c[0]) === hugePath);
		expect(hugeReads).toHaveLength(0);

		// And it did not fall through to the error/pass-through path.
		expect(result).not.toBe("/skill:my-skill");
		expect(capturedErrors).toEqual([]);
	});

	it("non-regular skill path (a directory) is refused with an actionable hint and passes through", () => {
		const dirPath = join(tempDir, "askill");
		mkdirSync(dirPath, { recursive: true });

		vi.mocked(fs.statSync).mockImplementation((p) => {
			if (String(p) === dirPath) {
				return fakeStats({
					size: 0,
					isFile: () => false,
					isDirectory: () => true,
				});
			}
			return realFs.statSync(p);
		});

		session = buildSession({ name: "my-skill", filePath: dirPath, baseDir: tempDir });

		const result = session.expandSkillCommand("/skill:my-skill");

		// Refused: original text returned unchanged.
		expect(result).toBe("/skill:my-skill");
		// An actionable hint was emitted via the extension runner error path.
		expect(capturedErrors.length).toBe(1);
		expect(capturedErrors[0].extensionPath).toBe(dirPath);
		expect(capturedErrors[0].event).toBe("skill_expansion");
		expect(capturedErrors[0].error).toContain("directory");
		expect(capturedErrors[0].error).toContain("regular SKILL.md");
	});

	it("REPI_READ_TEXT_FILE_MAX_BYTES=0 disables the size guard (reads the file normally)", () => {
		const skillDir = join(tempDir, "my-skill");
		mkdirSync(skillDir, { recursive: true });
		const skillFile = join(skillDir, "SKILL.md");
		writeFileSync(skillFile, SKILL_FIXTURE);

		process.env.REPI_READ_TEXT_FILE_MAX_BYTES = "0";

		// statSync reports a huge size, but cap=0 disables the guard, so the
		// code falls through to readFileSync (real) and reads the small fixture.
		const hugeSize = 5 * 1024 * 1024 * 1024;
		vi.mocked(fs.statSync).mockImplementation((p) => {
			if (String(p) === skillFile) return fakeStats({ size: hugeSize });
			return realFs.statSync(p);
		});

		session = buildSession({ name: "my-skill", filePath: skillFile, baseDir: skillDir });

		const result = session.expandSkillCommand("/skill:my-skill");

		const expectedBody = stripFrontmatter(realFs.readFileSync(skillFile, "utf-8")).trim();
		const expected = `<skill name="my-skill" location="${skillFile}">\nReferences are relative to ${skillDir}.\n\n${expectedBody}\n</skill>`;

		expect(result).toBe(expected);
		expect(result).not.toContain("REPI_READ_TEXT_FILE_MAX_BYTES");
		expect(capturedErrors).toEqual([]);
	});
});
