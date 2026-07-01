import { mkdtempSync, readFileSync as realReadFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #164 neuter-verify: the streaming lineCount's OOM-prevention behavior is
// NOT output-distinguishable from the original split-based lineCount on small
// files (both return the same count). The DISTINGUISHABLE behavior is that the
// FIXED lineCount streams via positioned readSync and NEVER calls readFileSync,
// so a mocked 5 GB file (statSync reports 5 GB, readFileSync throws
// ERR_FS_FILE_TOO_LARGE, openSync/readSync/closeSync operate on a small real
// backing buffer) yields the TRUE non-whitespace line count without loading
// the file whole. The ORIGINAL lineCount called readText→readTextFile→
// readFileSync, which throws on the mocked huge file → readTextFile's catch
// returns "" → lineCount returns 0. So reverting lineCount to readFileSync+
// split makes `expect(count).toBe(knownCount)` FAIL with `Received: 0`.
//
// The trailing-newline edge-correction (final `if (lineHasNonWs) count++`) is
// pinned by the no-trailing-newline parity case: removing it makes that case
// fail with `Received: expected - 1`.

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
			if (f) return { ...actual.statSync(path), size: f.fakeSize } as ReturnType<typeof actual.statSync>;
			return actual.statSync(path);
		},
		readFileSync: (path: string, encoding?: BufferEncoding) => {
			readFileSyncCalls += 1;
			if (fakeFiles.has(path)) {
				throw Object.assign(new Error("File exceeds maximum allowed size"), { code: "ERR_FS_FILE_TOO_LARGE" });
			}
			return actual.readFileSync(path, encoding ?? "utf8");
		},
		// openSync / readSync / closeSync stay REAL so streaming + bounded-tail
		// operate on the small real backing file.
	};
});

const { lineCount, readTextFile } = await import("../src/core/repi/evidence.ts");
const fsMock = (await import("node:fs")) as unknown as typeof import("node:fs") & {
	__repiRegisterFake: (path: string, buf: Buffer, fakeSize: number) => void;
};

// The OLD split-based lineCount semantics, computed on the full small content
// via the REAL readFileSync (the mock only intercepts paths registered as
// fake; small parity files are NOT registered, so real readFileSync runs).
function oldLineCount(path: string): number {
	const text = realReadFileSync(path, "utf-8");
	if (!text.trim()) return 0;
	return text.split(/\r?\n/).filter((line) => line.trim()).length;
}

describe("evidence lineCount streaming parity + readTextFile stat-first guard (opt #164)", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-evidence-linecount-164-"));
		fakeFiles.clear();
		readFileSyncCalls = 0;
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
		fakeFiles.clear();
		vi.unstubAllEnvs();
	});

	it("small multi-line file WITH trailing newline: streaming count === old split count", () => {
		const file = join(dir, "trailing.md");
		const body = "## record one\n\n- fact: a\n## record two\n- fact: b\n";
		writeFileSync(file, body, "utf8");
		expect(lineCount(file)).toBe(oldLineCount(file));
		expect(lineCount(file)).toBe(4); // 4 non-whitespace lines
	});

	it("small multi-line file WITHOUT trailing newline: final line counted (edge-correction pin)", () => {
		const file = join(dir, "no-trailing.md");
		const body = "line a\n\nline b"; // no final \n; final segment "line b"
		writeFileSync(file, body, "utf8");
		expect(lineCount(file)).toBe(oldLineCount(file));
		expect(lineCount(file)).toBe(2);
		// Neuter pin: removing the final `if (lineHasNonWs) count++` edge-
		// correction would return 1 here (the "line b" segment has no \n).
	});

	it("file with leading/trailing whitespace-only lines + CRLF: streaming count === old count", () => {
		const file = join(dir, "crlf.md");
		const body = "   \r\nkeep\r\n\r\n   \r\nkeep2\r\n";
		writeFileSync(file, body, "utf8");
		expect(lineCount(file)).toBe(oldLineCount(file));
		expect(lineCount(file)).toBe(2);
	});

	it("all-whitespace file returns 0 (matches old `if (!text.trim()) return 0`)", () => {
		const file = join(dir, "ws-only.md");
		writeFileSync(file, "   \n\t\n  \r\n", "utf8");
		expect(lineCount(file)).toBe(oldLineCount(file));
		expect(lineCount(file)).toBe(0);
	});

	it("empty file returns 0", () => {
		const file = join(dir, "empty.md");
		writeFileSync(file, "", "utf8");
		expect(lineCount(file)).toBe(0);
	});

	it("mock 5 GB file: lineCount returns the true count via streaming WITHOUT readFileSync (neuter pin)", () => {
		const file = join(dir, "huge.log");
		// Small real backing buffer with a known non-whitespace line count.
		const buf = Buffer.from("keep1\n\nkeep2\nkeep3\n", "utf8"); // 3 non-ws lines
		writeFileSync(file, buf, "utf8");
		fsMock.__repiRegisterFake(file, buf, 5_000_000_000);
		// Expected count from the backing buffer content (old semantics).
		const expected = buf
			.toString("utf-8")
			.split(/\r?\n/)
			.filter((l) => l.trim()).length;
		expect(expected).toBe(3);

		const got = lineCount(file);
		// Fixed: streams via readSync → true count, readFileSync NOT called.
		expect(got).toBe(3);
		expect(readFileSyncCalls).toBe(0);
		// Neutered (original readFileSync+split): readFileSync throws → caught
		// by readTextFile → "" → lineCount returns 0 → `expect(got).toBe(3)`
		// FAILS with `Received: 0`.
	});

	it("readTextFile: small file under cap returns full content verbatim", () => {
		const file = join(dir, "small.md");
		const body = "# evidence\n\ntail content END-MARKER\n";
		writeFileSync(file, body, "utf8");
		expect(readTextFile(file)).toBe(body);
		expect(readFileSyncCalls).toBe(1);
	});

	it("readTextFile: oversized file returns a bounded TAIL marker without readFileSync", () => {
		// Small cap so a tiny fake-size triggers the guard and the tail overlaps
		// the real backing bytes (start = fakeSize - cap within the real file).
		vi.stubEnv("REPI_READ_TEXT_FILE_MAX_BYTES", "8");
		const file = join(dir, "oversized.log");
		const body = "0123456789ABCDEFGHIJ"; // 20 bytes, no newlines
		const buf = Buffer.from(body, "utf8");
		writeFileSync(file, buf, "utf8");
		fsMock.__repiRegisterFake(file, buf, 20); // fakeSize 20 > cap 8

		const got = readTextFile(file, "FALLBACK");
		// Bounded tail: last 8 bytes of the 20-byte "file", with a marker.
		expect(got.startsWith("[truncated 12 bytes from head, showing last 8 bytes of 20]")).toBe(true);
		expect(got.endsWith(body.slice(12))).toBe(true); // last 8 bytes = "CDEFGHIJ"
		expect(readFileSyncCalls).toBe(0);
		expect(got).not.toBe("FALLBACK");
	});

	it("readTextFile: REPI_READ_TEXT_FILE_MAX_BYTES=0 disables the guard (readFileSync → throws → fallback)", () => {
		vi.stubEnv("REPI_READ_TEXT_FILE_MAX_BYTES", "0");
		const file = join(dir, "huge-disabled.log");
		const buf = Buffer.from("keep1\nkeep2\n", "utf8");
		writeFileSync(file, buf, "utf8");
		fsMock.__repiRegisterFake(file, buf, 5_000_000_000);

		const got = readTextFile(file, "FB");
		expect(got).toBe("FB");
		expect(readFileSyncCalls).toBe(1);
	});
});
