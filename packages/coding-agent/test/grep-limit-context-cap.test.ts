import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";

// Foundational opt #262: grep limit/context args (bare Type.Number, no upper
// bound) could OOM the agent — limit:1e6 → rg until 1M matches each pushed with
// full lineText; context:1e5 → formatBlock 2*context+1 lines/match. Cap them
// (env-overridable) and truncate lineText on push. Also Math.floor so a
// fractional context can't drop the match line.

vi.mock("../src/core/utils/tools-manager.ts", () => ({
	ensureTool: vi.fn(async () => "/fake/rg"),
}));

vi.mock("child_process", async (importActual) => {
	const actual = await importActual<typeof import("child_process")>();
	return { ...actual, spawn: vi.fn() };
});

const { spawn } = await import("child_process");
const { createGrepToolDefinition } = await import("../src/core/tools/grep.ts");

function makeFakeChild(): EventEmitter & {
	stdout: PassThrough;
	stderr: PassThrough;
	killed: boolean;
	kill: () => boolean;
} {
	const stdout = new PassThrough();
	const stderr = new PassThrough();
	const child = Object.assign(new EventEmitter(), {
		stdout,
		stderr,
		killed: false,
		kill() {
			this.killed = true;
			return true;
		},
	});
	return child as ReturnType<typeof makeFakeChild>;
}

function rgMatchLine(file: string, lineNumber: number, text: string): string {
	return JSON.stringify({ type: "match", data: { path: { text: file }, lines: { text }, line_number: lineNumber } });
}

describe("grep limit/context cap + lineText truncation (opt #262)", () => {
	afterEach(() => {
		vi.mocked(spawn).mockReset();
		delete process.env.REPI_GREP_MAX_LIMIT;
		delete process.env.REPI_GREP_MAX_CONTEXT;
	});

	it("caps the match limit and truncates each stored lineText", async () => {
		process.env.REPI_GREP_MAX_LIMIT = "5";
		const fakeChild = makeFakeChild();
		vi.mocked(spawn).mockReturnValue(fakeChild as never);

		const def = createGrepToolDefinition(process.cwd(), {
			operations: { isDirectory: async () => true, readFile: async () => "", statSize: () => 0 },
		});

		// Request an absurd limit; emit 12 matches each with a 2000-char line.
		const huge = "A".repeat(2000);
		const promise = def.execute(
			"call-cap",
			{ pattern: "A", path: ".", limit: 1_000_000 },
			undefined,
			undefined,
			undefined as never,
		);
		await new Promise<void>((r) => setImmediate(r));

		for (let i = 1; i <= 12; i++) {
			fakeChild.stdout.emit("data", Buffer.from(`${rgMatchLine("file.txt", i, huge)}\n`));
		}
		// Let readline parse + the line listener drain (stops at effectiveLimit=5).
		await new Promise<void>((r) => setTimeout(r, 10));
		fakeChild.emit("close", 0);

		const result = await Promise.race([
			promise,
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("grep promise hung")), 4000)),
		]);

		expect(result).not.toBeInstanceOf(Error);
		const text = (result as { content: { type: string; text: string }[] }).content[0].text;
		// The limit was capped at 5 → matchLimitReached notice names 5.
		expect(text).toMatch(/5 matches limit reached/);
		// Exactly 5 match lines emitted (not 12, not 1_000_000).
		const matchLines = text.split("\n").filter((l) => /file\.txt:\d+:/.test(l));
		expect(matchLines.length).toBe(5);
		// Each emitted line is truncated (the 2000-char line was cut to ~500 +
		// marker, NOT 2000) and the "Some lines truncated" notice fires.
		expect(text).toMatch(/Some lines truncated/);
		for (const line of matchLines) {
			const contentPart = line.replace(/^file\.txt:\d+:\s/, "");
			expect(contentPart.length).toBeLessThan(600);
			expect(line).toMatch(/\[truncated\]/);
		}
	});

	it("caps context and floors a fractional context so the match line is kept", async () => {
		process.env.REPI_GREP_MAX_CONTEXT = "3";
		// A 30-line file; the match lands at line 15.
		const fileLines: string[] = [];
		for (let i = 1; i <= 30; i++) fileLines.push(`line ${i}`);
		const fileContent = fileLines.join("\n");

		const runCtx = async (context: number): Promise<string> => {
			const fakeChild = makeFakeChild();
			vi.mocked(spawn).mockReturnValue(fakeChild as never);
			const def = createGrepToolDefinition(process.cwd(), {
				operations: {
					isDirectory: async () => false,
					readFile: async () => fileContent,
					statSize: () => fileContent.length,
				},
			});
			const promise = def.execute(
				"call-ctx",
				{ pattern: "line 15", path: "file.txt", context },
				undefined,
				undefined,
				undefined as never,
			);
			await new Promise<void>((r) => setImmediate(r));
			fakeChild.stdout.emit("data", Buffer.from(`${rgMatchLine("file.txt", 15, "line 15")}\n`));
			await new Promise<void>((r) => setTimeout(r, 10));
			fakeChild.emit("close", 0);
			const result = await Promise.race([
				promise,
				new Promise<never>((_, reject) => setTimeout(() => reject(new Error("grep promise hung")), 4000)),
			]);
			expect(result).not.toBeInstanceOf(Error);
			return (result as { content: { type: string; text: string }[] }).content[0].text;
		};

		// context:100000 → capped to 3 → block = lines 12..18 (7 lines). Without
		// the cap the block would span 1..30 (30 lines, bounded only by the file).
		const text = await runCtx(100_000);
		const lines = text.split("\n").filter((l) => l.length > 0);
		expect(lines.length).toBe(7);
		// The match line itself is present (file.txt:15:).
		expect(text).toMatch(/file\.txt:15:/);

		// Fractional context: 2.5 → floor to 2 → block = lines 13..17 (5 lines),
		// AND the match line (15) is kept (pre-fix fractional current never === 15).
		const text2 = await runCtx(2.5);
		const lines2 = text2.split("\n").filter((l) => l.length > 0);
		expect(lines2.length).toBe(5);
		expect(text2).toMatch(/file\.txt:15:/);
	});
});
