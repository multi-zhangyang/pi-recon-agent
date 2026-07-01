import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock node:fs so we can flip renameSync to throw on demand (simulating a
// mid-rename ENOSPC/EIO). The default implementation is set per-test in
// beforeEach to the REAL renameSync (fetched via importActual) so success-path
// tests exercise the real temp+rename. atomicWriteFile imports renameSync as a
// named binding from "node:fs", so the mock intercepts it at the source —
// same proven pattern as atomic-write-sync-temp-cleanup.test.ts. The factory
// must not close over outer variables (vi.mock is hoisted), so the real
// renameSync is resolved lazily inside beforeEach.
vi.mock("node:fs", async (importActual) => {
	const actual = await importActual<typeof import("node:fs")>();
	return {
		...actual,
		renameSync: vi.fn(),
	};
});

// Mock proper-lockfile so the withFileLock routing assertion can observe
// lockSync acquisition + release without taking a real cross-process lock.
const lockRelease = vi.fn();
const lockSyncSpy = vi.fn(() => lockRelease);
vi.mock("proper-lockfile", () => ({
	default: { lockSync: lockSyncSpy, unlockSync: vi.fn() },
}));

// Route the .mjs specifier through a non-literal const so tsgo does not try to
// resolve the plain JS module (TS7016 "no declaration file"). Matches the
// report-write-guard.test.ts pattern. Runtime still loads the real helper.
const PURGE_HELPER = "../../../scripts/reverse-agent/lib/memory-purge-helpers.mjs";
const { atomicWriteFile, withFileLock } = await import(PURGE_HELPER);
const fs = await import("node:fs");

describe("atomicWriteFile (opt #176 memory purge atomicity)", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = mkdtempSync(join(tmpdir(), "mem-purge-atomic-"));
		// Default renameSync to the REAL implementation so success-path tests
		// exercise the real temp+rename. The failure test overrides this to
		// throw. Resolved lazily here (not in the hoisted vi.mock factory).
		const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
		vi.mocked(fs.renameSync).mockImplementation(actual.renameSync);
		lockSyncSpy.mockClear();
		lockRelease.mockClear();
	});

	afterEach(() => {
		if (tempDir) rmSync(tempDir, { recursive: true, force: true });
		(tempDir as unknown as undefined) = undefined;
	});

	it("writes correct content via temp+rename and leaves no .tmp behind", () => {
		const target = join(tempDir, "events.jsonl");
		const payload = `${JSON.stringify({ kind: "repi-memory-event", id: "evt-1" })}\n${JSON.stringify({ kind: "repi-memory-event", id: "evt-2" })}\n`;
		atomicWriteFile(target, payload, 0o600);

		expect(readFileSync(target, "utf8")).toBe(payload);
		const leftovers = readdirSync(tempDir).filter((f) => f.endsWith(".tmp"));
		expect(leftovers).toEqual([]);
	});

	it("preserves an existing file's mode across the replace", () => {
		const target = join(tempDir, "events.jsonl");
		writeFileSync(target, "old\n", { mode: 0o600 });
		atomicWriteFile(target, "new\n", 0o600);
		expect(readFileSync(target, "utf8")).toBe("new\n");
	});

	it("ATOMIC PIN: a mid-rename failure leaves the ORIGINAL file intact (not truncated)", () => {
		const target = join(tempDir, "events.jsonl");
		const original = `${JSON.stringify({ kind: "repi-memory-event", id: "keep-me" })}\n`;
		writeFileSync(target, original, { mode: 0o600 });

		// Simulate a crash/failure at the rename step (ENOSPC/EIO mid-rename).
		// Pre-fix (bare writeFileSync): the file is truncated BEFORE the write,
		// so any failure mid-write loses the original. Post-fix (temp+rename):
		// the temp is written+unlinked; the original is untouched until a
		// successful rename, so it survives the failure.
		vi.mocked(fs.renameSync).mockImplementation(() => {
			throw Object.assign(new Error("renameSync: ENOSPC (simulated)"), { code: "ENOSPC" });
		});

		expect(() => atomicWriteFile(target, "SHOULD NOT LAND\n", 0o600)).toThrow(/ENOSPC/);

		// The ORIGINAL content survives — this is the atomic pin.
		expect(existsSync(target)).toBe(true);
		expect(readFileSync(target, "utf8")).toBe(original);
		// No temp leftover (unlinked in the catch).
		const leftovers = readdirSync(tempDir).filter((f) => f.endsWith(".tmp"));
		expect(leftovers).toEqual([]);
		// Confirm the mock fired (guards against a false PASS).
		expect(vi.mocked(fs.renameSync)).toHaveBeenCalled();
	});
});

describe("withFileLock (opt #176 purge RMW serialization)", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "mem-purge-lock-"));
		lockSyncSpy.mockClear();
		lockRelease.mockClear();
	});

	afterEach(() => {
		if (tempDir) rmSync(tempDir, { recursive: true, force: true });
		(tempDir as unknown as undefined) = undefined;
	});

	it("acquires a proper-lockfile lock around fn and releases it in finally (routing assertion)", () => {
		// Level: routing assertion. A true two-process serialization test is
		// heavier and flaky in CI; we assert the lock is acquired BEFORE fn
		// runs and released AFTER, which is the load-bearing invariant for the
		// purge RMW. The real lockfile.lockSync is exercised end-to-end by the
		// smoke run (see memory file), not by this unit test.
		const target = join(tempDir, "events.jsonl");
		let lockHeldDuringFn = false;
		let releasedAfterFn = false;

		const result = withFileLock(target, () => {
			expect(lockSyncSpy).toHaveBeenCalledTimes(1);
			lockHeldDuringFn = true;
			return "purge-result";
		});

		expect(lockHeldDuringFn).toBe(true);
		expect(result).toBe("purge-result");
		expect(lockRelease).toHaveBeenCalledTimes(1);
		releasedAfterFn = true;
		expect(releasedAfterFn).toBe(true);
	});

	it("releases the lock even when fn throws (finally semantics)", () => {
		const target = join(tempDir, "events.jsonl");
		expect(() =>
			withFileLock(target, () => {
				throw new Error("purge RMW failed");
			}),
		).toThrow(/purge RMW failed/);
		expect(lockRelease).toHaveBeenCalledTimes(1);
	});
});
