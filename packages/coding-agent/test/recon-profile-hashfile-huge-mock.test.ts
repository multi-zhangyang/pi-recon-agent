import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #158 neuter-verify: the OOM-prevention behavior is NOT output-
// distinguishable at testable scales — for any file small enough to fit in a
// test, readFileSync-whole and chunked-readSync give the SAME sha256. The fix
// only differs in MEMORY behavior on files > 1 MB fast-max where readFileSync
// of a multi-GB file would OOM / ERR_FS_FILE_TOO_LARGE before the digest runs.
// To pin THAT behavior deterministically, this test mocks node:fs so the target
// file REPORTS a size > fast-max (3 MB) and readFileSync THROWS
// ERR_FS_FILE_TOO_LARGE (exactly what Node does on a real multi-GB file), while
// openSync/readSync/closeSync operate on a small real backing buffer (the
// file's logical contents, read in 1 MB chunks). The fixed hashFileSha256
// takes the stat>fast-max → chunked readSync path (never readFileSync) and
// returns the real sha256; the original readFileSync-only code would hit the
// throwing readFileSync → uncaught throw → the assertion fails. (A real 5 GB
// fake size would process 5 GB of bytes and time out the test; 3 MB is enough
// to force the chunked path — the only thing this pin needs to prove.)

const fakeFiles = new Map<string, { buf: Buffer; fakeSize: number }>();
const openFds = new Map<number, Buffer>();
let nextFd = 1000;

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
		readSync: (fd: number, buf: Buffer, offset: number, length: number, position: number) => {
			const backing = openFds.get(fd);
			if (backing !== undefined) {
				// The fake file reports a huge size; the real content lives in the
				// small backing buffer. Serve the chunk at `position` by mapping
				// into the backing buffer modulo its length so the loop sees 5 GB
				// of deterministic content. position is within [0, fakeSize).
				let written = 0;
				while (written < length) {
					const backingPos = (position + written) % backing.length;
					const chunk = Math.min(length - written, backing.length - backingPos);
					backing.copy(buf, offset + written, backingPos, backingPos + chunk);
					written += chunk;
				}
				return written;
			}
			return actual.readSync(fd, buf, offset, length, position);
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
const { hashFileSha256 } = await import("../src/core/repi/text.ts");
const fsMock = (await import("node:fs")) as unknown as typeof import("node:fs") & {
	__repiRegisterFake: (path: string, buf: Buffer, fakeSize: number) => void;
};

describe("hashFileSha256 streams a (simulated) 5 GB file without OOM (opt #158 neuter pin)", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-hashfile-mock-158-"));
		fakeFiles.clear();
		openFds.clear();
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
		fakeFiles.clear();
		openFds.clear();
	});

	it("hashes a 3 MB file via chunked readSync when readFileSync would ERR_FS_FILE_TOO_LARGE", () => {
		const file = join(dir, "huge.bin");
		const fakeSize = 3_000_000;
		// Real backing buffer (small) whose contents repeat across the fake size.
		const backing = Buffer.alloc(256 * 1024);
		for (let i = 0; i < backing.length; i++) backing[i] = (i * 7 + 3) & 0xff;
		writeFileSync(file, backing);
		fsMock.__repiRegisterFake(file, backing, fakeSize);

		// Reference hash: fakeSize bytes of the repeating backing buffer. Compute
		// by hashing the backing buffer repeated whole times plus the remainder —
		// the fake readSync serves exactly this.
		const ref = createHash("sha256");
		const fullRepeats = Math.floor(fakeSize / backing.length);
		const remainder = fakeSize - fullRepeats * backing.length;
		for (let i = 0; i < fullRepeats; i++) ref.update(backing);
		ref.update(backing.subarray(0, remainder));
		const expected = ref.digest("hex");

		const got = hashFileSha256(file);
		// Fixed: stat > fast-max → chunked readSync path → real hash.
		// Original (neutered): readFileSync throws ERR_FS_FILE_TOO_LARGE →
		// uncaught throw (no try/catch around the old update(readFileSync)) →
		// the assertion never runs / test fails.
		expect(got).toBe(expected);
	});
});
