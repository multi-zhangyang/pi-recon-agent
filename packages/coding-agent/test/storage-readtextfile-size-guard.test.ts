import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #163 neuter-verify: the OOM-prevention behavior is NOT output-
// distinguishable via the RETURN value at testable scales. readTextFile's
// existing try/catch already returns `fallback` on ANY readFileSync error
// (including ERR_FS_FILE_TOO_LARGE), so the original un-guarded code would
// ALSO return fallback "" on a mocked huge file — the return value alone can't
// tell fixed from neutered. The DISTINGUISHABLE behavior is that the FIXED
// code stat-first short-circuits and NEVER calls readFileSync when stat>cap,
// while the ORIGINAL code always calls readFileSync (which on a real multi-GB
// file either throws ERR_FS_FILE_TOO_LARGE / a V8 RangeError that MAY be
// caught, or — for sizes between the buffer cap and process RSS — exhausts
// memory and OOM-crashes the agent before the catch can run). To pin that
// deterministically, this test mocks node:fs so the target file REPORTS a 5 GB
// size via statSync and readFileSync THROWS ERR_FS_FILE_TOO_LARGE, and counts
// readFileSync calls. Fixed: stat > cap → warn + return fallback, readFileSync
// NOT called (calls === 0). Neutered (original readFileSync-whole):
// readFileSync IS called (calls === 1) → the `expect(calls).toBe(0)` assertion
// FAILS. This is the honest neuter-pin: the fix's distinguishing act is the
// stat-first skip of the unbounded read, not a different return value.

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
	};
});

const { readTextFile, readTextFileCached } = await import("../src/core/repi/storage.ts");
const fsMock = (await import("node:fs")) as unknown as typeof import("node:fs") & {
	__repiRegisterFake: (path: string, buf: Buffer, fakeSize: number) => void;
};

describe("readTextFile / readTextFileCached stat-first OOM guard (opt #163)", () => {
	let dir: string;
	let stderrSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-readtextfile-guard-163-"));
		fakeFiles.clear();
		readFileSyncCalls = 0;
		// Suppress + capture the over-cap stderr notice so the test output stays clean.
		stderrSpy = vi.spyOn(process.stderr, "write").mockReturnValue(true) as unknown as ReturnType<typeof vi.spyOn>;
	});
	afterEach(() => {
		stderrSpy.mockRestore();
		rmSync(dir, { recursive: true, force: true });
		fakeFiles.clear();
	});

	it("small file under the cap returns full content verbatim via the fast readFileSync path", () => {
		const file = join(dir, "small.md");
		const body = "# playbook\n\ntail content END-MARKER\n";
		writeFileSync(file, body, "utf8");
		const got = readTextFile(file);
		expect(got).toBe(body);
		expect(got.endsWith("END-MARKER\n")).toBe(true);
		expect(readFileSyncCalls).toBe(1);
	});

	it("a 5 GB (simulated) file returns fallback WITHOUT calling readFileSync (neuter pin)", () => {
		const file = join(dir, "huge.jsonl");
		// A small real backing file (so statSync's spread of actual values works)
		// registered as a fake 5 GB file whose readFileSync throws.
		writeFileSync(file, Buffer.from('{"x":1}\n', "utf8"));
		fsMock.__repiRegisterFake(file, Buffer.from('{"x":1}\n', "utf8"), 5_000_000_000);

		const got = readTextFile(file, "FALLBACK");
		// Fixed: stat > cap → warn + return fallback, readFileSync NOT called.
		// Neutered (original): readFileSync called → calls === 1 → assertion FAILS.
		expect(got).toBe("FALLBACK");
		expect(readFileSyncCalls).toBe(0);
		// The over-cap notice fired (NOT a silent drop).
		expect(stderrSpy).toHaveBeenCalled();
	});

	it("readTextFileCached applies the same guard and skips readFileSync on an over-cap file", () => {
		const file = join(dir, "huge-cached.jsonl");
		writeFileSync(file, Buffer.from('{"y":2}\n', "utf8"));
		fsMock.__repiRegisterFake(file, Buffer.from('{"y":2}\n', "utf8"), 5_000_000_000);

		const got = readTextFileCached(file, "FB");
		expect(got).toBe("FB");
		expect(readFileSyncCalls).toBe(0);
	});

	it("readTextFileCached returns full content verbatim for a small file (fast path intact)", () => {
		const file = join(dir, "small-cached.md");
		const body = "core memory note END\n";
		writeFileSync(file, body, "utf8");
		const got = readTextFileCached(file);
		expect(got).toBe(body);
		expect(readFileSyncCalls).toBe(1);
	});

	it("REPI_READ_TEXT_FILE_MAX_BYTES=0 disables the guard (huge file loads via readFileSync, throws→caught→fallback)", () => {
		vi.stubEnv("REPI_READ_TEXT_FILE_MAX_BYTES", "0");
		try {
			const file = join(dir, "huge-disabled.jsonl");
			writeFileSync(file, Buffer.from('{"z":3}\n', "utf8"));
			fsMock.__repiRegisterFake(file, Buffer.from('{"z":3}\n', "utf8"), 5_000_000_000);

			const got = readTextFile(file, "FB");
			// Guard disabled → readFileSync IS called → throws ERR_FS_FILE_TOO_LARGE
			// → existing try/catch returns fallback. This proves the 0-disables knob.
			expect(got).toBe("FB");
			expect(readFileSyncCalls).toBe(1);
		} finally {
			vi.unstubAllEnvs();
		}
	});
});
