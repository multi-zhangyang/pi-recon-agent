import { mkdtempSync, rmSync, type Stats, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #168: processFileArguments (@file CLI args) had NO upper-bound check —
// readFile(absolutePath) loaded the ENTIRE user-referenced @file into memory
// (image branch) and inlined it into the prompt string (text branch). A multi-GB
// @file OOMs the process AND blows the model's token budget. The fix adds a
// stat-size guard BEFORE readFile, reusing the SHARED REPI_READ_TEXT_FILE_MAX_BYTES
// knob (default 16 MB, 0 disables): text oversize → bounded head+tail read via
// open+read at offsets (never readFile-whole) with a middle-ellipsis marker;
// image oversize → refuse with a resize hint (binary bytes can't be truncated).
//
// Test 1 (small text @file, REAL fixture): pins BYTE-IDENTICAL parity — the
// inlined <file> content is exactly the file content, unchanged by the guard.
//
// Test 2 (small image @file, REAL fixture): the guard does not perturb the
// image branch for a small PNG (handled, pushed to images, readFile used).
//
// Test 3 (oversized text @file, MOCK 5 GB): simulates a 5 GB file where
// readFile THROWS ERR_FS_FILE_TOO_LARGE (exactly what Node does on a real 5 GB
// file) while open+read operate on a small backing buffer. The fixed code takes
// the bounded head+tail path (open+read, readFile NOT called) and returns a
// head+tail slice + marker. The original readFile-whole code hits the throwing
// readFile → catch → exit(1), and readFileCalls.has(file) is TRUE → the
// "readFile NOT called on fake" assertion FAILS (neuter pin, output-
// distinguishable: the mock records the readFile call so we can assert it).
//
// Test 4 (oversized image @file, MOCK 5 GB): the guard refuses the oversized
// image with a resize hint (exit 1) BEFORE readFile — readFile NOT called.
//
// Test 5 (cap=0 disables guard, MOCK 5 GB with throwOnRead:false): with
// REPI_READ_TEXT_FILE_MAX_BYTES=0 the guard is bypassed and readFile is used
// (returns the whole backing content, NO truncation marker) — proving the knob
// disables the guard rather than always-truncate.

const fakeFiles = new Map<string, { buf: Buffer; fakeSize: number; throwOnRead?: boolean }>();
const readFileCalls = new Set<string>();

vi.mock("node:fs/promises", async () => {
	const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
	return {
		...actual,
		__repiRegisterFake: (path: string, buf: Buffer, fakeSize: number, throwOnRead = true) => {
			fakeFiles.set(path, { buf, fakeSize, throwOnRead });
		},
		access: (path: string) => actual.access(path),
		stat: (path: string) => {
			const f = fakeFiles.get(path);
			if (f) return Promise.resolve({ size: f.fakeSize } as unknown as Stats);
			return actual.stat(path);
		},
		readFile: async (path: string, encoding?: BufferEncoding) => {
			const key = String(path);
			readFileCalls.add(key);
			const f = fakeFiles.get(key);
			if (f) {
				if (f.throwOnRead === false) {
					// Simulate "whole file loaded" for the cap=0 disables test.
					return f.buf.toString("utf-8");
				}
				throw Object.assign(new Error("File exceeds maximum allowed size"), { code: "ERR_FS_FILE_TOO_LARGE" });
			}
			return actual.readFile(path, encoding as BufferEncoding);
		},
		open: (path: string, flags?: string) => {
			const f = fakeFiles.get(String(path));
			if (f) {
				return Promise.resolve(makeFakeHandle(f.buf));
			}
			return actual.open(path, flags as never);
		},
	};
});

/** Fake FileHandle for a mocked huge file: reads serve the small backing buffer
 * (head region from `position`, tail region from the backing buffer's end). */
function makeFakeHandle(buf: Buffer) {
	return {
		read: async (
			out: Buffer,
			offset: number,
			length: number,
			position: number | null,
		): Promise<{ bytesRead: number; buffer: Buffer }> => {
			const pos = position ?? 0;
			if (pos < buf.length) {
				const n = Math.min(length, buf.length - pos);
				buf.copy(out, offset, pos, pos + n);
				return { bytesRead: n, buffer: out };
			}
			// Tail read at a huge position: return the last `length` bytes of the
			// backing buffer (simulates the file's tail holding that content).
			const n = Math.min(length, buf.length);
			buf.copy(out, offset, buf.length - n, buf.length);
			return { bytesRead: n, buffer: out };
		},
		close: async (): Promise<void> => {},
	};
}

// Import AFTER vi.mock so the module sees the mocked fs.promises.
const { processFileArguments } = await import("../src/cli/file-processor.ts");
const fsMock = (await import("node:fs/promises")) as unknown as typeof import("node:fs/promises") & {
	__repiRegisterFake: (path: string, buf: Buffer, fakeSize: number, throwOnRead?: boolean) => void;
};

// Small 2x2 red PNG (base64) — real image-magic bytes for the mime sniff.
const TINY_PNG_B64 =
	"iVBORw0KGgoAAAANSUhEUgAAAAIAAAACAQMAAABIeJ9nAAAAIGNIUk0AAHomAACAhAAA+gAAAIDoAAB1MAAA6mAAADqYAAAXcJy6UTwAAAAGUExURf8AAP///0EdNBEAAAABYktHRAH/Ai3eAAAAB3RJTUUH6gEOADM5Ddoh/wAAAAxJREFUCNdjYGBgAAAABAABJzQnCgAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAyNi0wMS0xNFQwMDo1MTo1NyswMDowMOnKzHgAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMjYtMDEtMTRUMDA6NTE6NTcrMDA6MDCYl3TEAAAAKHRFWHRkYXRhOnRpbWVzdGFtcAAyMDI2LTAxLTE0VDAwOjUxOjU3KzAwOjAwz4JVGwAAAABJRU5ErkJggg==";

let dir: string;
let exitSpy: ReturnType<typeof vi.spyOn>;
const exitCalls: number[] = [];

class ExitError extends Error {
	constructor(code: number) {
		super(`process.exit(${code})`);
		this.name = "ExitError";
	}
}

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "repi-atfile-guard-168-"));
	fakeFiles.clear();
	readFileCalls.clear();
	exitCalls.length = 0;
	exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
		const c = Number(code ?? 0);
		exitCalls.push(c);
		throw new ExitError(c);
	}) as never) as unknown as ReturnType<typeof vi.spyOn>;
});

afterEach(() => {
	exitSpy.mockRestore();
	rmSync(dir, { recursive: true, force: true });
	fakeFiles.clear();
	readFileCalls.clear();
});

describe("processFileArguments @file size guard (opt #168)", () => {
	it("small text @file inlines byte-identical content (parity)", async () => {
		const body = "line one\nline two\nFINAL-MARKER\n";
		const file = join(dir, "small.txt");
		writeFileSync(file, body);

		const result = await processFileArguments([file]);

		expect(result.images).toHaveLength(0);
		expect(result.text).toBe(`<file name="${file}">\n${body}\n</file>\n`);
		expect(result.text).toContain("FINAL-MARKER");
		expect(exitCalls).toEqual([]);
	});

	it("small image @file is handled unchanged (guard does not perturb image branch)", async () => {
		const file = join(dir, "small.png");
		writeFileSync(file, Buffer.from(TINY_PNG_B64, "base64"));

		const result = await processFileArguments([file], { autoResizeImages: false });

		expect(result.images).toHaveLength(1);
		expect(result.images[0].mimeType).toBe("image/png");
		expect(result.text).toContain(`<file name="${file}">`);
		expect(exitCalls).toEqual([]);
	});

	it("oversized text @file → bounded head+tail marker, readFile NOT called on fake (5 GB mock)", async () => {
		// Backing buffer: HEAD at the very start, TAIL at the very end, padding
		// between. headLen/tailLen (~22 each at cap=300) slice distinct regions.
		const backing = Buffer.from(`HEAD_START\n${"X".repeat(180)}\nTAIL_END`, "utf-8");
		const file = join(dir, "huge.txt");
		writeFileSync(file, backing);
		fsMock.__repiRegisterFake(file, backing, 5_000_000_000);

		vi.stubEnv("REPI_READ_TEXT_FILE_MAX_BYTES", "300");
		try {
			let result: { text: string; images: unknown[] } | undefined;
			try {
				result = await processFileArguments([file]);
			} catch {
				// Neuter: the unguarded readFile threw ERR_FS_FILE_TOO_LARGE → the
				// text-branch catch fired → process.exit(1) threw ExitError. Swallow
				// so the assertions below run and FAIL (readFile WAS called).
			}
			// FIX: bounded head+tail path taken → readFile NOT called on the fake
			// huge file (open+read at offsets instead). Under the original
			// unguarded code readFile IS called → this assertion FAILS (neuter pin,
			// output-distinguishable via the readFileCalls mock ledger).
			expect(readFileCalls.has(file)).toBe(false);
			expect(result?.text).toContain("HEAD_START");
			expect(result?.text).toContain("TAIL_END");
			expect(result?.text).toContain("elided");
			expect(result?.text).toContain("REPI_READ_TEXT_FILE_MAX_BYTES");
			// Length bounded well under the 5 GB fake size and near the cap.
			expect(result?.text.length ?? 0).toBeLessThan(2000);
			expect(exitCalls).toEqual([]);
		} finally {
			vi.unstubAllEnvs();
		}
	});

	it("oversized image @file → refused with resize hint, readFile NOT called (5 GB mock)", async () => {
		const backing = Buffer.from(TINY_PNG_B64, "base64");
		const file = join(dir, "huge.png");
		writeFileSync(file, backing);
		fsMock.__repiRegisterFake(file, backing, 5_000_000_000);

		vi.stubEnv("REPI_READ_TEXT_FILE_MAX_BYTES", "300");
		try {
			// Guard refuses BEFORE readFile → process.exit(1) throws ExitError
			// (the image branch has no try/catch around readFile, so the throw
			// propagates). readFile is never called on the fake.
			await expect(processFileArguments([file], { autoResizeImages: false })).rejects.toThrow(ExitError);
			expect(exitCalls).toContain(1);
			expect(readFileCalls.has(file)).toBe(false);
		} finally {
			vi.unstubAllEnvs();
		}
	});

	it("cap=0 disables the guard (whole readFile path, no truncation marker)", async () => {
		const backing = Buffer.from(`HEAD_START\n${"X".repeat(180)}\nTAIL_END`, "utf-8");
		const file = join(dir, "huge-cap0.txt");
		writeFileSync(file, backing);
		// throwOnRead=false → readFile returns the whole backing content instead
		// of throwing, simulating "the whole file was loaded" with the guard off.
		fsMock.__repiRegisterFake(file, backing, 5_000_000_000, false);

		vi.stubEnv("REPI_READ_TEXT_FILE_MAX_BYTES", "0");
		try {
			const result = await processFileArguments([file]);

			// Guard bypassed: readFile WAS called and the whole content is inlined
			// with NO truncation marker.
			expect(readFileCalls.has(file)).toBe(true);
			expect(result.text).toContain("HEAD_START");
			expect(result.text).toContain("TAIL_END");
			expect(result.text).not.toContain("elided");
			expect(exitCalls).toEqual([]);
		} finally {
			vi.unstubAllEnvs();
		}
	});
});
