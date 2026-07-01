import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #156 neuter-verify: the OOM-prevention behavior is NOT output-
// distinguishable at testable scales — for any file small enough to fit in a
// test, readFileSync-whole-then-slice and tail-read-then-slice return the SAME
// tail. The fix only differs in MEMORY behavior on multi-GB files (where
// readFileSync OOMs / ERR_FS_FILE_TOO_LARGE before the slice runs). To pin THAT
// behavior deterministically, this test mocks node:fs so the target file
// REPORTS a 5 GB size and readFileSync THROWS ERR_FS_FILE_TOO_LARGE (exactly
// what Node does on a real 5 GB file), while openSync/readSync/closeSync
// operate on a small real backing buffer (the file's logical tail). The fixed
// readText takes the tail-read path (stat > cap → readSync, never readFileSync)
// and returns the real tail; the original readFileSync-whole code would hit the
// throwing readFileSync → catch → return "" → the assertion fails.

const fakeFiles = new Map<string, { buf: Buffer; fakeSize: number }>();
const openFds = new Map<number, Buffer>();
let nextFd = 1000;

vi.mock("node:fs", async () => {
	const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
	return {
		...actual,
		// Test-only escape hatch to register a fake huge file.
		__repiRegisterFake: (path: string, buf: Buffer, fakeSize: number) => {
			fakeFiles.set(path, { buf, fakeSize });
		},
		statSync: (path: string) => {
			const f = fakeFiles.get(path);
			if (f) return { ...actual.statSync(path), size: f.fakeSize } as ReturnType<typeof actual.statSync>;
			return actual.statSync(path);
		},
		readFileSync: (path: string, encoding?: BufferEncoding) => {
			if (fakeFiles.has(path)) {
				throw Object.assign(new Error("File exceeds maximum allowed size"), { code: "ERR_FS_FILE_TOO_LARGE" });
			}
			return actual.readFileSync(path, encoding ?? "utf8");
		},
		openSync: (path: string, flags?: string) => {
			const f = fakeFiles.get(path);
			if (f) {
				const fd = nextFd++;
				openFds.set(fd, f.buf);
				return fd;
			}
			return actual.openSync(path, (flags ?? "r") as never);
		},
		readSync: (fd: number, buf: Buffer, offset: number, length: number, _position: number) => {
			const backing = openFds.get(fd);
			if (backing !== undefined) {
				// The fake file reports a huge size; the real content lives in the
				// small backing buffer. Copy the backing buffer's tail into buf.
				const n = Math.min(length, backing.length);
				backing.copy(buf, offset, backing.length - n, backing.length);
				return n;
			}
			return actual.readSync(fd, buf, offset, length, _position);
		},
		closeSync: (fd: number) => {
			if (openFds.has(fd)) {
				openFds.delete(fd);
				return;
			}
			return actual.closeSync(fd);
		},
	};
});

// Import AFTER vi.mock so the module sees the mocked fs.
const { readText } = await import("../src/core/agent-thread-manager.ts");
const fsMock = (await import("node:fs")) as unknown as typeof import("node:fs") & {
	__repiRegisterFake: (path: string, buf: Buffer, fakeSize: number) => void;
};

describe("readText tail-reads a (simulated) 5 GB file without OOM (opt #156 neuter pin)", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-readtext-mock-156-"));
		fakeFiles.clear();
		openFds.clear();
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
		fakeFiles.clear();
		openFds.clear();
	});

	it("returns the real tail when readFileSync would ERR_FS_FILE_TOO_LARGE", () => {
		const file = join(dir, "huge.log");
		const tail = Buffer.from(`${"X".repeat(2000)}END-MARKER`, "utf8");
		// Write a real small file (so openSync/readSync have backing content)...
		writeFileSync(file, tail);
		// ...then register it as a fake 5 GB file whose readFileSync throws.
		fsMock.__repiRegisterFake(file, tail, 5_000_000_000);

		const got = readText(file, 12000);
		// Fixed: stat > cap → tail-read path (readSync) → real tail returned.
		// Original (neutered): readFileSync throws ERR_FS_FILE_TOO_LARGE →
		// catch → "" → endsWith("END-MARKER") FAILS.
		expect(got.endsWith("END-MARKER")).toBe(true);
		expect(got.length).toBeLessThanOrEqual(12000);
	});
});
