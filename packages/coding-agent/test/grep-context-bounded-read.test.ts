import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #166 — grep context-line read path (formatBlock → getFileLines) did
// `ops.readFile(filePath)` of the WHOLE file then `.split("\n")` into an
// unbounded array cached in fileCache. With context (-A/-B/-C) it ran for
// EVERY matched file → a pattern inside a multi-GB log/artifact loaded the
// ENTIRE file into memory before slicing the context window → OOM. The fix
// stat-guards each matched file (reusing the SHARED REPI_READ_TEXT_FILE_MAX_BYTES
// knob, default 16 MB, 0 disables): small files keep the fast whole-read+cache
// path (byte-identical to the old behavior); oversized files stream-skip to the
// matched line range and read ONLY the context window via positioned readSync
// (1 MB chunks, same doctrine as opt #158's hashFileSha256) and are NOT cached
// wholesale. This test mocks rg via the injected `operations` (ops) seam — no
// `vi.mock("node:fs")` needed — and proves (1) the oversized streaming path
// produces a byte-identical context window to the fast whole-read path (parity
// pin), and (2) an oversized file is served WITHOUT calling readFile-whole.

vi.mock("../src/core/utils/tools-manager.ts", () => ({
	ensureTool: vi.fn(async () => "/fake/rg"),
}));

vi.mock("child_process", async (importActual) => {
	const actual = await importActual<typeof import("child_process")>();
	return { ...actual, spawn: vi.fn() };
});

const { spawn } = await import("child_process");
const { createGrepToolDefinition, defaultGrepReadLineRange } = await import("../src/core/tools/grep.ts");

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

// Feed rg a single match event for `filePath` at `lineNumber`, then drive a
// successful close so the formatting loop runs.
async function runGrepWithContext(
	operations: Record<string, unknown>,
	filePath: string,
	lineNumber: number,
	context: number,
): Promise<string> {
	const fakeChild = makeFakeChild();
	vi.mocked(spawn).mockReturnValue(fakeChild as never);

	const def = createGrepToolDefinition(process.cwd(), {
		operations: operations as never,
	});

	const promise = def.execute(
		"call-166",
		{ pattern: "MATCH", path: filePath, context },
		undefined,
		undefined,
		undefined as never,
	);

	// Let the async IIFE resume past ensureTool + isDirectory + spawn and attach
	// its readline/child listeners.
	await new Promise<void>((r) => setImmediate(r));

	const matchLine = `${JSON.stringify({
		type: "match",
		data: { path: { text: filePath }, line_number: lineNumber, lines: { text: "MATCH" } },
	})}\n`;
	fakeChild.stdout.emit("data", Buffer.from(matchLine));

	// Let readline parse the line (it emits 'line' on a later tick).
	await new Promise<void>((r) => setTimeout(r, 10));

	// Drive the close handler with a success code so it reaches the formatting
	// loop (matchCount > 0, not aborted, code 0).
	fakeChild.emit("close", 0);

	const result = (await promise) as { content: Array<{ type: string; text: string }> };
	return result.content[0].text;
}

describe("grep context bounded read (opt #166)", () => {
	let tmpDir: string;
	let filePath: string;

	const FILE_CONTENT = "line1 alpha\nline2 beta\nline3 MATCH\nline4 delta\nline5 echo\n";
	const MATCH_LINE = 3;

	beforeEach(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "grep-ctx-166-"));
		filePath = join(tmpDir, "big.log");
		writeFileSync(filePath, FILE_CONTENT, "utf-8");
	});

	afterEach(() => {
		vi.mocked(spawn).mockReset();
		rmSync(tmpDir, { recursive: true, force: true });
	});

	it("oversized streaming path yields a byte-identical context window to the fast whole-read path (parity pin)", async () => {
		// Fast path: statSize reports a small file → whole readFile + cache. This
		// is exactly the OLD behavior, so its output is the parity reference.
		const fastOps = {
			isDirectory: async () => false,
			readFile: async () => FILE_CONTENT,
			statSize: () => FILE_CONTENT.length,
		};

		// Oversized path: statSize lies (5 GB) → stream-skip via the REAL
		// defaultGrepReadLineRange over the same backing file. readFile is unused.
		const oversizedOps = {
			isDirectory: async () => false,
			readFile: async () => {
				throw new Error("fast path should not be used for oversized file");
			},
			statSize: () => 5 * 1024 * 1024 * 1024,
			readLineRange: (p: string, startLine: number, endLine: number) =>
				defaultGrepReadLineRange(p, startLine, endLine),
		};

		const fastOut = await runGrepWithContext(fastOps, filePath, MATCH_LINE, 2);
		const oversizedOut = await runGrepWithContext(oversizedOps, filePath, MATCH_LINE, 2);

		// Both paths must produce the same context window. The fast path is the
		// old behavior; the streaming path must match it byte-for-byte.
		expect(oversizedOut).toBe(fastOut);

		// Sanity: the context window contains the match line and surrounding lines.
		const base = `${filePath.split(/[\\/]/).pop() as string}`;
		expect(fastOut).toContain(`${base}:3: line3 MATCH`);
		expect(fastOut).toContain(`${base}-1- line1 alpha`);
		expect(fastOut).toContain(`${base}-2- line2 beta`);
		expect(fastOut).toContain(`${base}-4- line4 delta`);
		expect(fastOut).toContain(`${base}-5- line5 echo`);
	});

	it("oversized file is served WITHOUT calling readFile-whole (no OOM)", async () => {
		let readFileCalled = false;
		const oversizedOps = {
			isDirectory: async () => false,
			readFile: async () => {
				readFileCalled = true;
				throw Object.assign(new Error("too large"), { code: "ERR_FS_FILE_TOO_LARGE" });
			},
			statSize: () => 5 * 1024 * 1024 * 1024,
			readLineRange: (p: string, startLine: number, endLine: number) =>
				defaultGrepReadLineRange(p, startLine, endLine),
		};

		const out = await runGrepWithContext(oversizedOps, filePath, MATCH_LINE, 2);

		// The whole-file readFile must NOT be called for an oversized file.
		expect(readFileCalled).toBe(false);

		// The matched line + context window is still returned (from the bounded
		// streaming slice, not a whole load).
		const base = `${filePath.split(/[\\/]/).pop() as string}`;
		expect(out).toContain(`${base}:3: line3 MATCH`);
		expect(out).toContain(`${base}-2- line2 beta`);
		expect(out).toContain(`${base}-4- line4 delta`);
	});

	it("REPI_READ_TEXT_FILE_MAX_BYTES=0 disables the guard → fast path is used even for a huge statSize", async () => {
		const previous = process.env.REPI_READ_TEXT_FILE_MAX_BYTES;
		process.env.REPI_READ_TEXT_FILE_MAX_BYTES = "0";
		try {
			let readFileCalled = false;
			// statSize reports 5 GB but the guard is disabled (0) → fast path.
			// readLineRange would throw if reached; assert it is NOT called.
			let readLineRangeCalled = false;
			const disabledOps = {
				isDirectory: async () => false,
				readFile: async () => {
					readFileCalled = true;
					return FILE_CONTENT;
				},
				statSize: () => 5 * 1024 * 1024 * 1024,
				readLineRange: () => {
					readLineRangeCalled = true;
					return { baseLine: 1, lines: [] };
				},
			};

			const out = await runGrepWithContext(disabledOps, filePath, MATCH_LINE, 2);

			expect(readFileCalled).toBe(true);
			expect(readLineRangeCalled).toBe(false);
			const base = `${filePath.split(/[\\/]/).pop() as string}`;
			expect(out).toContain(`${base}:3: line3 MATCH`);
		} finally {
			if (previous === undefined) delete process.env.REPI_READ_TEXT_FILE_MAX_BYTES;
			else process.env.REPI_READ_TEXT_FILE_MAX_BYTES = previous;
		}
	});
});
