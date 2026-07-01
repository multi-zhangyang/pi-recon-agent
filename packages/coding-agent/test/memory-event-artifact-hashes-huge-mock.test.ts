import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #159 neuter-verify: memoryArtifactHashes used to hash artifacts inline
// via createHash("sha256").update(readFileSync(path)).digest("hex"). For any
// file small enough to fit in a test, that and the streaming hashFileSha256
// path give the SAME sha256 — so the OOM fix is not output-distinguishable at
// testable scales. To pin THAT behavior, mock node:fs so the artifact REPORTS
// 3 MB (> hashFileSha256's 1 MB fast-max → forces the chunked path) and
// readFileSync THROWS ERR_FS_FILE_TOO_LARGE, while openSync/readSync/closeSync
// operate on a small real backing buffer (contents repeat via position-modulo).
// Fixed memoryArtifactHashes routes through hashFileSha256 → chunked readSync
// → real sha256, required=true. Neutered (original inline readFileSync) hits
// the throwing readFileSync → catch → sha256=null, required=false → the
// assertion fails. (3 MB not 5 GB so the test processes only 3 MB of bytes and
// stays within the time budget; 3 MB is enough to force the chunked path.)

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

const { memoryArtifactHashes } = await import("../src/core/repi/memory-event.ts");
const fsMock = (await import("node:fs")) as unknown as typeof import("node:fs") & {
	__repiRegisterFake: (path: string, buf: Buffer, fakeSize: number) => void;
};

describe("memoryArtifactHashes streams a (simulated) 3 MB artifact without OOM (opt #159 neuter pin)", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-memartifact-mock-159-"));
		fakeFiles.clear();
		openFds.clear();
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
		fakeFiles.clear();
		openFds.clear();
	});

	it("returns the real sha256 + required=true when readFileSync would ERR_FS_FILE_TOO_LARGE", () => {
		const file = join(dir, "huge.bin");
		const fakeSize = 3_000_000;
		const backing = Buffer.alloc(256 * 1024);
		for (let i = 0; i < backing.length; i++) backing[i] = (i * 13 + 5) & 0xff;
		writeFileSync(file, backing);
		fsMock.__repiRegisterFake(file, backing, fakeSize);

		const ref = createHash("sha256");
		const fullRepeats = Math.floor(fakeSize / backing.length);
		const remainder = fakeSize - fullRepeats * backing.length;
		for (let i = 0; i < fullRepeats; i++) ref.update(backing);
		ref.update(backing.subarray(0, remainder));
		const expected = ref.digest("hex");

		const got = memoryArtifactHashes([file]);
		// Fixed: routes through hashFileSha256 → chunked readSync → real hash.
		// Original (neutered): inline readFileSync throws ERR_FS_FILE_TOO_LARGE
		// → catch → sha256=null, required=false → these assertions fail.
		expect(got).toHaveLength(1);
		expect(got[0].sha256).toBe(expected);
		expect(got[0].required).toBe(true);
	});
});
