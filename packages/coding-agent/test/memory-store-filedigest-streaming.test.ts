import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #165: fileDigest used to readFileSync(path) the WHOLE file into a Buffer AND
// buffer.toString("utf-8") a second full-size copy before sha256'ing. A multi-MB
// memory artifact (evidence capture, large dump) was loaded into memory TWICE just
// to digest it → OOM / ERR_FS_FILE_TOO_LARGE. The fix reuses hashFileSha256
// (streaming positioned-read createHash, byte-identical) for sha256, uses stat.size
// for bytes, and guards the `text` field with the shared REPI_READ_TEXT_FILE_MAX_BYTES
// cap (oversized → bounded tail + marker, never the whole file).
//
// Test 1 (small file): pins BYTE-IDENTICAL parity to the old readFileSync-based
// computation (sha256 of the Buffer, buffer.length, buffer.toString("utf-8")).
//
// Test 2 (huge mock): simulates a 5 GB file where readFileSync throws
// ERR_FS_FILE_TOO_LARGE (exactly what Node does on a real 5 GB file) while
// openSync/readSync/closeSync operate on a small real backing buffer. The fixed
// fileDigest streams the hash (no whole load) and returns the correct digest +
// stat-based bytes + a bounded-tail `text` with a marker. The original
// readFileSync-whole code hits the throwing readFileSync → catch → error sentinel
// {sha256:sha256Text(""),bytes:0,text:""} → every assertion FAILS (neuter pin).

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
		readFileSync: (path: NodeJS.ArrayBufferView | string, encoding?: BufferEncoding) => {
			const key = String(path);
			if (fakeFiles.has(key)) {
				throw Object.assign(new Error("File exceeds maximum allowed size"), { code: "ERR_FS_FILE_TOO_LARGE" });
			}
			return actual.readFileSync(path as string, encoding as BufferEncoding);
		},
		openSync: (path: NodeJS.ArrayBufferView | string, flags?: number | string) => {
			const f = fakeFiles.get(String(path));
			if (f) {
				const fd = nextFd++;
				openFds.set(fd, f.buf);
				return fd;
			}
			return actual.openSync(path as string, (flags ?? "r") as never);
		},
		readSync: (fd: number, buf: Buffer, offset: number, length: number, position: number) => {
			const backing = openFds.get(fd);
			if (backing !== undefined) {
				// Head region [0, backing.length): return backing content from `position`
				// so hashFileSha256 (1 MB chunks from pos 0) hashes the backing bytes and
				// then terminates (next chunk reads past backing → EOF below).
				if (position < backing.length) {
					const n = Math.min(length, backing.length - position);
					backing.copy(buf, offset, position, position + n);
					return n;
				}
				// Tail read (length <= 64 KB, position past the backing head): simulate
				// the file's tail region holding the backing content, so the bounded-tail
				// `text` field is non-empty. Large reads (hashFileSha256 1 MB chunks)
				// fall through to EOF (0) so the hash loop terminates.
				if (length <= 65536 && position >= backing.length) {
					const n = Math.min(length, backing.length);
					backing.copy(buf, offset, backing.length - n, backing.length);
					return n;
				}
				return 0; // EOF
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
const { fileDigest } = await import("../src/core/repi/memory-store.ts");
const fsReal = await vi.importActual<typeof import("node:fs")>("node:fs");
const fsMock = (await import("node:fs")) as unknown as typeof import("node:fs") & {
	__repiRegisterFake: (path: string, buf: Buffer, fakeSize: number) => void;
};

describe("fileDigest streaming + stat-guard (opt #165)", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-filedigest-165-"));
		fakeFiles.clear();
		openFds.clear();
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
		fakeFiles.clear();
		openFds.clear();
	});

	it("small file: digest is byte-identical to the old readFileSync-based computation", () => {
		const path = join(dir, "case-memory.jsonl");
		// Multibyte UTF-8 (é = 2 bytes) pins sha256(buffer) === sha256(string-utf8)
		// and buffer.length === stat.size === Buffer.byteLength(text, "utf-8").
		const line = JSON.stringify({ id: "mem:x", seq: 1, caseSignature: "café-route" });
		const body = `${line}\n`;
		writeFileSync(path, body);

		const got = fileDigest(path);

		// Reference: the OLD readFileSync-whole computation (Buffer-based).
		const buffer = fsReal.readFileSync(path);
		const refSha256 = createHash("sha256").update(buffer).digest("hex");
		const refBytes = buffer.length;
		const refText = buffer.toString("utf-8");

		expect(got.sha256).toBe(refSha256);
		expect(got.bytes).toBe(refBytes);
		expect(got.bytes).toBe(fsReal.statSync(path).size);
		expect(got.text).toBe(refText);
		expect(got.text).toBe(body);
	});

	it("huge mock file: streams the digest without loading the file whole (no OOM)", () => {
		const file = join(dir, "huge-dump.bin");
		// Backing content lives at the head; the mock reports 5 GB + makes readFileSync throw.
		const backing = Buffer.from(`${"Y".repeat(4000)}END-MARKER`, "utf8");
		writeFileSync(file, backing);
		const fakeSize = 5_000_000_000;
		fsMock.__repiRegisterFake(file, backing, fakeSize);

		const got = fileDigest(file);

		// sha256: streamed via hashFileSha256 over the backing bytes (the mock returns
		// EOF past the head) → equals the direct hash of the backing Buffer.
		const refSha256 = createHash("sha256").update(backing).digest("hex");
		expect(got.sha256).toBe(refSha256);
		// bytes: stat-based (no read) → the fake reported size, NOT 0 (error sentinel).
		expect(got.bytes).toBe(fakeSize);
		// text: oversized → bounded tail + marker, NOT the whole file and NOT "" (the
		// error-sentinel text the neutered readFileSync-whole catch returns).
		expect(got.text).toContain("fileDigest:");
		expect(got.text).toContain("REPI_READ_TEXT_FILE_MAX_BYTES");
		expect(got.text.length).toBeLessThanOrEqual(64 * 1024 + 256); // tail + marker
		expect(got.text).toContain("END-MARKER"); // tail body surfaced from the mock
	});

	it("huge mock file: cap=0 disables the text guard → readFileSync-whole is attempted → throws → error sentinel", () => {
		// With REPI_READ_TEXT_FILE_MAX_BYTES=0 the text guard is disabled, so fileDigest
		// calls readFileSync(path, "utf-8") on the fake-huge file → throws → the outer
		// catch returns the error sentinel. This proves the cap is what routes oversized
		// files to the bounded-tail path (and confirms the catch contract is preserved).
		const file = join(dir, "huge-dump-2.bin");
		const backing = Buffer.from("payload", "utf8");
		writeFileSync(file, backing);
		fsMock.__repiRegisterFake(file, backing, 5_000_000_000);
		const prev = process.env.REPI_READ_TEXT_FILE_MAX_BYTES;
		process.env.REPI_READ_TEXT_FILE_MAX_BYTES = "0";
		try {
			const got = fileDigest(file);
			expect(got.sha256).toBe(
				// sha256Text("") — the error sentinel (createHash of the empty string).
				createHash("sha256")
					.update("")
					.digest("hex"),
			);
			expect(got.bytes).toBe(0);
			expect(got.text).toBe("");
		} finally {
			if (prev === undefined) delete process.env.REPI_READ_TEXT_FILE_MAX_BYTES;
			else process.env.REPI_READ_TEXT_FILE_MAX_BYTES = prev;
		}
	});
});
