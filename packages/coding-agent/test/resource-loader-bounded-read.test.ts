import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #169 — bounded-read guard for the readFileSync sites that inline
// user-controlled files INTO THE SYSTEM PROMPT (every ancestor CLAUDE.md /
// AGENTS.md, --system-prompt / --append-system-prompt file args, every enabled
// SKILL.md and prompt template). Mirrors the opt #163 neuter-pin strategy: the
// OOM-prevention behavior is distinguishable via whether readFileSync (the
// unbounded whole-file read) is CALLED. Fixed code stat-first short-circuits
// for over-cap files (streaming head+tail) and rejects non-regular files BEFORE
// readFileSync, so readFileSync is NOT called. Neutered (original
// readFileSync-whole) code always calls readFileSync. This test mocks node:fs
// so the target file REPORTS a 5 GB size via statSync and readFileSync THROWS
// ERR_FS_FILE_TOO_LARGE, and counts readFileSync calls.

const fakeFiles = new Map<string, { buf: Buffer; fakeSize: number }>();
let readFileSyncCalls = 0;

vi.mock("node:fs", async () => {
	const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
	return {
		...actual,
		__repiRegisterFake: (path: string, buf: Buffer, fakeSize: number) => {
			fakeFiles.set(path, { buf, fakeSize });
		},
		statSync: (path: string) => {
			const f = fakeFiles.get(path);
			if (f) {
				// Override size on the REAL Stats object (preserves isFile/
				// isDirectory on the prototype; a plain spread would drop them).
				const real = actual.statSync(path);
				return Object.defineProperty(real, "size", {
					value: f.fakeSize,
					configurable: true,
				}) as ReturnType<typeof actual.statSync>;
			}
			return actual.statSync(path);
		},
		readFileSync: (path: string, encoding?: BufferEncoding) => {
			readFileSyncCalls += 1;
			if (fakeFiles.has(path)) {
				throw Object.assign(new Error("File exceeds maximum allowed size"), { code: "ERR_FS_FILE_TOO_LARGE" });
			}
			return actual.readFileSync(path, encoding ?? "utf8");
		},
	};
});

// Import AFTER vi.mock so the modules see the mocked fs.
const { resolvePromptInput, loadContextFileFromDir } = await import("../src/core/resource-loader.ts");
const { loadSkillFromFile } = await import("../src/core/skills.ts");
const { loadTemplateFromFile } = await import("../src/core/prompt-templates.ts");
const fsMock = (await import("node:fs")) as unknown as typeof import("node:fs") & {
	__repiRegisterFake: (path: string, buf: Buffer, fakeSize: number) => void;
};

describe("readBoundedTextFile guard at system-prompt load sites (opt #169)", () => {
	let dir: string;
	let stderrSpy: ReturnType<typeof vi.spyOn>;
	let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-resource-loader-guard-169-"));
		fakeFiles.clear();
		readFileSyncCalls = 0;
		// Suppress + capture the over-cap stderr notice and caller warnings.
		stderrSpy = vi.spyOn(process.stderr, "write").mockReturnValue(true) as unknown as ReturnType<typeof vi.spyOn>;
		consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined) as unknown as ReturnType<
			typeof vi.spyOn
		>;
	});
	afterEach(() => {
		stderrSpy.mockRestore();
		consoleErrorSpy.mockRestore();
		rmSync(dir, { recursive: true, force: true });
		fakeFiles.clear();
	});

	describe("parity: small files load byte-identical via the fast readFileSync path", () => {
		it("resolvePromptInput returns verbatim content for a small --system-prompt file", () => {
			const file = join(dir, "system.md");
			const body = "# system prompt\n\nrules END-MARKER\n";
			writeFileSync(file, body, "utf8");
			const got = resolvePromptInput(file, "system prompt");
			expect(got).toBe(body);
			expect(got?.endsWith("END-MARKER\n")).toBe(true);
			expect(readFileSyncCalls).toBe(1);
		});

		it("loadContextFileFromDir returns verbatim CLAUDE.md content", () => {
			const body = "# project context\n\nancestor rules END-MARKER\n";
			writeFileSync(join(dir, "CLAUDE.md"), body, "utf8");
			const got = loadContextFileFromDir(dir);
			expect(got).not.toBeNull();
			expect(got?.content).toBe(body);
			expect(got?.content.endsWith("END-MARKER\n")).toBe(true);
			expect(readFileSyncCalls).toBe(1);
		});

		it("loadSkillFromFile parses a small SKILL.md (frontmatter intact)", () => {
			const skillDir = join(dir, "my-skill");
			mkdirSync(skillDir, { recursive: true });
			const file = join(skillDir, "SKILL.md");
			const body = "---\nname: my-skill\ndescription: does a thing END-MARKER\n---\n\nbody\n";
			writeFileSync(file, body, "utf8");
			const result = loadSkillFromFile(file, "path");
			expect(result.skill).not.toBeNull();
			expect(result.skill?.name).toBe("my-skill");
			expect(result.skill?.description).toBe("does a thing END-MARKER");
			expect(readFileSyncCalls).toBe(1);
		});

		it("loadTemplateFromFile returns verbatim body for a small prompt template", () => {
			const file = join(dir, "review.md");
			const body = "---\ndescription: review helper\n---\n\ntemplate body END-MARKER\n";
			writeFileSync(file, body, "utf8");
			const tpl = loadTemplateFromFile(file, {
				path: file,
				source: "local",
				scope: "temporary",
				origin: "top-level",
			});
			expect(tpl).not.toBeNull();
			expect(tpl?.content).toBe("template body END-MARKER");
			expect(readFileSyncCalls).toBe(1);
		});
	});

	describe("oversized file: bounded head+tail marker, NOT loaded whole", () => {
		it("resolvePromptInput inlines bounded head+tail and skips readFileSync (neuter pin)", () => {
			const file = join(dir, "huge.md");
			writeFileSync(file, Buffer.from("HEAD-CONTENT\n", "utf8"));
			fsMock.__repiRegisterFake(file, Buffer.from("HEAD-CONTENT\n", "utf8"), 5_000_000_000);

			const got = resolvePromptInput(file, "system prompt");
			// Fixed: stat > cap -> streaming head+tail with marker, readFileSync NOT called.
			// Neutered (original readFileSync-whole): readFileSync called -> throws
			// ERR_FS_FILE_TOO_LARGE -> caught -> returns the literal input path.
			expect(got).toContain("<truncated:");
			expect(got).toContain("REPI_READ_TEXT_FILE_MAX_BYTES cap");
			expect(got).toContain("HEAD-CONTENT");
			expect(readFileSyncCalls).toBe(0);
			// The over-cap notice fired (NOT a silent truncation).
			expect(stderrSpy).toHaveBeenCalled();
		});

		it("loadContextFileFromDir inlines bounded head+tail for an oversized CLAUDE.md", () => {
			const file = join(dir, "CLAUDE.md");
			writeFileSync(file, Buffer.from("ANCESTOR-HEAD\n", "utf8"));
			fsMock.__repiRegisterFake(file, Buffer.from("ANCESTOR-HEAD\n", "utf8"), 5_000_000_000);

			const got = loadContextFileFromDir(dir);
			expect(got).not.toBeNull();
			expect(got?.content).toContain("<truncated:");
			expect(got?.content).toContain("ANCESTOR-HEAD");
			expect(readFileSyncCalls).toBe(0);
		});
	});

	describe("special file (non-regular): refused with an actionable hint", () => {
		it("resolvePromptInput refuses a directory and surfaces a hint WITHOUT readFileSync", () => {
			const sub = join(dir, "not-a-file");
			mkdirSync(sub, { recursive: true });
			const got = resolvePromptInput(sub, "system prompt");
			// Refused: returns the literal input (existing catch contract).
			expect(got).toBe(sub);
			// readFileSync never reached (stat-first regular-file guard).
			expect(readFileSyncCalls).toBe(0);
			// Actionable hint surfaced via the caller's warning.
			expect(consoleErrorSpy).toHaveBeenCalled();
			const warned = consoleErrorSpy.mock.calls.map((c) => String(c[0])).join(" ");
			expect(warned).toContain("not a regular file");
			expect(warned).toContain("Hint");
		});
	});

	describe("REPI_READ_TEXT_FILE_MAX_BYTES=0 disables the size cap (regular-file check still applies)", () => {
		it("cap=0: an oversized file falls through to readFileSync (guard disabled)", () => {
			vi.stubEnv("REPI_READ_TEXT_FILE_MAX_BYTES", "0");
			try {
				const file = join(dir, "huge-disabled.md");
				writeFileSync(file, Buffer.from("X\n", "utf8"));
				fsMock.__repiRegisterFake(file, Buffer.from("X\n", "utf8"), 5_000_000_000);

				const got = resolvePromptInput(file, "system prompt");
				// Guard disabled -> readFileSync IS called -> throws ERR_FS_FILE_TOO_LARGE
				// -> existing catch returns the literal input path.
				expect(got).toBe(file);
				expect(readFileSyncCalls).toBe(1);
			} finally {
				vi.unstubAllEnvs();
			}
		});

		it("cap=0 still rejects a non-regular file (regular-file check independent of size cap)", () => {
			vi.stubEnv("REPI_READ_TEXT_FILE_MAX_BYTES", "0");
			try {
				const sub = join(dir, "dir-disabled");
				mkdirSync(sub, { recursive: true });
				const got = resolvePromptInput(sub, "system prompt");
				expect(got).toBe(sub);
				expect(readFileSyncCalls).toBe(0);
			} finally {
				vi.unstubAllEnvs();
			}
		});
	});
});
