import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

// Mock node:fs so writeFileSync throws on a sentinel path (simulating EACCES /
// ENOSPC mid-write) while delegating to the real implementation otherwise.
// safeWriteLogFile imports mkdirSync/writeFileSync from "node:fs", so the mock
// intercepts them at the source. Cast through `unknown` to satisfy TS2352.

vi.mock("node:fs", async (importActual) => {
	const actual = await importActual<typeof import("node:fs")>();
	return {
		...actual,
		writeFileSync: vi.fn((filePath: string, data: string | NodeJS.ArrayBufferView) => {
			if (typeof filePath === "string" && filePath.includes("eacces-sentinel")) {
				throw Object.assign(new Error("writeFileSync: permission denied (simulated)"), { code: "EACCES" });
			}
			return actual.writeFileSync(filePath, data);
		}),
	};
});

const fs = (await import("node:fs")) as unknown as typeof import("node:fs") & {
	writeFileSync: (filePath: string, data: string | NodeJS.ArrayBufferView) => void;
};
const { safeWriteLogFile } = await import("../../tui/src/safe-log-write.ts");

describe("safeWriteLogFile (opt #172)", () => {
	let tempDir: string;

	afterEach(() => {
		if (tempDir) rmSync(tempDir, { recursive: true, force: true });
		tempDir = undefined as unknown as string;
	});

	it("writes the file with correct content on a writable dir (normal case)", () => {
		tempDir = mkdtempSync(join(tmpdir(), "safe-log-write-normal-"));
		const target = join(tempDir, "sub", "crash.log");
		const data = ["Crash at now", "Terminal width: 80", "", "=== lines ===", "[0] hello"].join("\n");

		expect(() => safeWriteLogFile(target, data)).not.toThrow();

		// Parent dir was created and content matches exactly.
		const written = readFileSync(target, "utf8");
		expect(written).toBe(data);
	});

	it("swallows an EACCES/ENOSPC writeFileSync failure so the caller reaches stop()", () => {
		tempDir = mkdtempSync(join(tmpdir(), "safe-log-write-eacces-"));
		const target = join(tempDir, "eacces-sentinel.log");
		const data = "should never be written";

		// Pre-fix (bare writeFileSync): the EACCES throw escaped the log site,
		// skipping this.stop() and wedging the terminal. Post-fix: the helper
		// wraps the write in try/catch, so a caller running
		// `safeWriteLogFile(...); this.stop()` always reaches stop().
		expect(() => safeWriteLogFile(target, data)).not.toThrow();
		expect(vi.mocked(fs.writeFileSync)).toHaveBeenCalled();
	});
});
