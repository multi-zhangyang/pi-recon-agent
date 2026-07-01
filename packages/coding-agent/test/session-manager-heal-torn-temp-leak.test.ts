import { existsSync, mkdirSync, readdirSync, writeFileSync as realWriteFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type FsModule = typeof import("node:fs");
type WriteFileSyncArgs = Parameters<FsModule["writeFileSync"]>;

// opt #274: healTornTrailingLine wrapped open→write→chmod→rename so that ONLY
// the renameSync step was guarded by an unlink. If writeFileSync threw mid-loop
// (disk full / EIO / EROFS), the inner finally closed the fd and the error
// propagated to the OUTER catch — which swallowed it but never unlinked the
// temp, leaving a `.<basename>.<pid>.<hex>.torn.tmp` file in the session dir
// permanently (repeated heal attempts on a nearly-full disk accumulated them).
// The fix mirrors atomicWriteFileSync's whole-sequence unlink-on-failure: the
// outer catch unlinks the temp too. This test mocks writeFileSync (from "fs",
// the specifier session-manager.ts uses) to throw ENOSPC on the heal's first
// numeric-fd write, then asserts no `.torn.tmp` leaks.

const state = vi.hoisted(() => ({ healThrow: true }));

vi.mock("fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	const realWriteFileSync = actual.writeFileSync;
	return {
		...actual,
		writeFileSync: vi.fn((...args: WriteFileSyncArgs) => {
			// The heal path calls writeFileSync(fd, line) with a NUMERIC fd right
			// after openSync("wx") created the temp. Throw ENOSPC once on the
			// first fd-style call to simulate disk full mid-heal.
			if (typeof args[0] === "number" && state.healThrow) {
				state.healThrow = false;
				const err = new Error("ENOSPC: no space left on device, write") as Error & { code: string };
				err.code = "ENOSPC";
				throw err;
			}
			return (realWriteFileSync as (...a: WriteFileSyncArgs) => void)(...args);
		}),
	};
});

const { loadEntriesFromFile } = await import("../src/core/session-manager.ts");

const HEADER = '{"type":"session","id":"abc","timestamp":"2025-01-01T00:00:00Z","cwd":"/tmp"}\n';
const ENTRY1 =
	'{"type":"message","id":"1","parentId":null,"timestamp":"2025-01-01T00:00:01Z","message":{"role":"user","content":"first","timestamp":1}}\n';

describe("healTornTrailingLine temp leak on write failure (opt #274)", () => {
	let tempDir: string;

	beforeEach(() => {
		state.healThrow = true;
		tempDir = join(tmpdir(), `opt274-heal-leak-${process.pid}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("unlinks the torn-heal temp when the write fails mid-loop (no .torn.tmp leak)", () => {
		const file = join(tempDir, "torn.jsonl");
		// Crash mid-append left a partial final line with no trailing "\n".
		realWriteFileSync(file, `${HEADER}${ENTRY1}{"type":"message","id":"2","par`);

		// The heal attempts to rewrite the parseable entries to a temp; the
		// mocked writeFileSync throws ENOSPC on the first entry write. The outer
		// catch swallows (best-effort heal) so load still returns the 2
		// parseable entries (in-memory skip already made the session usable).
		const entries = loadEntriesFromFile(file);
		expect(entries).toHaveLength(2);
		expect(entries[0]?.type).toBe("session");
		expect(entries[1]?.type).toBe("message");

		// The fix unlinks the temp on the write-failure path. Without the fix the
		// `.torn.tmp` file was left in the session dir permanently.
		const leaked = readdirSync(tempDir).filter((n) => n.endsWith(".torn.tmp"));
		expect(leaked).toEqual([]);
	});

	it("leaves no temp artifact when the heal succeeds (write does not throw)", () => {
		state.healThrow = false; // disable the ENOSPC mock → heal writes succeed
		const file = join(tempDir, "torn2.jsonl");
		realWriteFileSync(file, `${HEADER}${ENTRY1}{"type":"message","id":"9","par`);

		const entries = loadEntriesFromFile(file);
		expect(entries).toHaveLength(2);
		// Successful heal renames the temp into place → no .torn.tmp remains.
		expect(readdirSync(tempDir).filter((n) => n.endsWith(".torn.tmp"))).toEqual([]);
		// The original file was re-truncated (healed).
		expect(existsSync(file)).toBe(true);
	});
});
