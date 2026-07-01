import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #160 neuter-verify: migrateSessionsFromAgentRoot used to read each
// legacy ~/.repi/agent/*.jsonl session via readFileSync(file, "utf8") +
// content.split("\n")[0] — loading the ENTIRE transcript into memory and
// splitting into an array of all lines just to read line 0. Legacy transcripts
// can be hundreds of MB → OOM at startup. Now it delegates to readSessionHeader
// (opt #157's bounded line-reader). For any file small enough to fit in a test,
// readFileSync+split and readSessionHeader give the SAME header — so the OOM
// fix is not output-distinguishable at testable scales. To pin it, mock
// node:fs so the legacy session REPORTS a huge size and readFileSync THROWS
// ERR_FS_FILE_TOO_LARGE, while openSync/readSync/closeSync operate on a small
// real backing buffer whose first line is the session header (readSessionHeader
// reads only until the newline). readdirSync/mkdirSync/existsSync/renameSync
// pass through to real fs on the temp agentDir. Fixed → readSessionHeader →
// bounded readSync → header parsed → file renamed into the cwd subdir.
// Neutered (original readFileSync+split) → throwing readFileSync → catch →
// skip → file NOT renamed. (The huge fake size only governs which code path is
// taken; the backing buffer is small so the test stays fast.)

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
				// Serve bytes from the backing buffer starting at `position`
				// (modulo its length) so readSessionHeader's loop sees the
				// header line + newline at position 0.
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

const { migrateSessionsFromAgentRoot } = await import("../src/migrations.ts");
const fsMock = (await import("node:fs")) as unknown as typeof import("node:fs") & {
	__repiRegisterFake: (path: string, buf: Buffer, fakeSize: number) => void;
};

describe("migrateSessionsFromAgentRoot reads only the header of a huge legacy session (opt #160 neuter pin)", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-migrate-sessions-160-"));
		fakeFiles.clear();
		openFds.clear();
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
		fakeFiles.clear();
		openFds.clear();
	});

	it("migrates a (simulated) 500 MB legacy session by reading only its header line", () => {
		const cwd = "/tmp/repi-migrate-160-cwd";
		const header = {
			type: "session",
			id: "legacy-1",
			timestamp: "2026-06-28T00:00:00.000Z",
			cwd,
		};
		// Backing buffer: header JSON + newline + padding. readSessionHeader
		// reads only until the newline.
		const backing = Buffer.from(`${JSON.stringify(header)}\n${"x".repeat(4096)}`, "utf8");
		const file = join(dir, "legacy.jsonl");
		writeFileSync(file, backing);
		fsMock.__repiRegisterFake(file, backing, 500_000_000);

		expect(existsSync(file)).toBe(true);
		migrateSessionsFromAgentRoot(dir);

		// Fixed: readSessionHeader → bounded readSync → header parsed → renamed
		// into the cwd subdir. Original (neutered): readFileSync throws
		// ERR_FS_FILE_TOO_LARGE → catch → skip → file stays at `file`.
		expect(existsSync(file), "legacy file should have been moved out").toBe(false);

		// The file moved into sessions/<encoded-cwd>/.
		const safePath = `--${cwd.replace(/^[/\\]/, "").replace(/[/\\:]/g, "-")}--`;
		const moved = join(dir, "sessions", safePath, "legacy.jsonl");
		expect(existsSync(moved)).toBe(true);

		// Sanity: only the .jsonl was touched; the sessions subdir is the one
		// entry under sessions/.
		const sessionsDir = join(dir, "sessions");
		expect(readdirSync(sessionsDir)).toContain(safePath);
	});
});
