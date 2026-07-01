import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

// Mock node:fs so writeFileSync throws once after the fd is opened, simulating
// a disk-full / EIO mid-write. The real openSync/closeSync/statSync/chmodSync/
// renameSync/unlinkSync pass through. atomicWriteFileSync imports writeFileSync
// as a named binding from "node:fs", so the mock intercepts it at the source.

vi.mock("node:fs", async (importActual) => {
	const actual = await importActual<typeof import("node:fs")>();
	return {
		...actual,
		writeFileSync: vi.fn(() => {
			throw Object.assign(new Error("writeFileSync: disk full (simulated)"), { code: "ENOSPC" });
		}),
	};
});

const { atomicWriteFileSync } = await import("../src/core/tools/atomic-write.ts");
const fs = await import("node:fs");

describe("atomicWriteFileSync temp cleanup on write failure (F1)", () => {
	let tempDir: string;

	afterEach(() => {
		if (tempDir) rmSync(tempDir, { recursive: true, force: true });
		tempDir = undefined as unknown as string;
	});

	it("unlinks the temp file when writeFileSync throws mid-write (no .tmp leftover)", () => {
		tempDir = mkdtempSync(join(tmpdir(), "atomic-sync-throw-"));
		const target = join(tempDir, "state.json");

		// Pre-fix: writeFileSync threw, the finally closed the fd, the error
		// propagated out of the function BEFORE the rename catch could run → the
		// temp file was left permanently in the dir. Post-fix: the outer catch
		// unlinks the temp on any failure.
		expect(() => atomicWriteFileSync(target, '{"x":1}\n')).toThrow(/disk full/);

		const leftovers = readdirSync(tempDir).filter((f) => f.endsWith(".tmp"));
		expect(leftovers).toEqual([]);
		// And the target was never created (rename never ran).
		expect(fs.existsSync(target)).toBe(false);
		// Confirm the mock actually fired (guards against a false PASS from the
		// mock not being wired).
		expect(vi.mocked(fs.writeFileSync)).toHaveBeenCalled();
	});
});
