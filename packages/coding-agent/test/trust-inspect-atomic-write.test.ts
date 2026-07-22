// REPI opt #189 — trust-inspect.mjs non-atomic trust write → torn write corrupts trust store.
//
// Root cause: trust-inspect.mjs writeTrust used bare `writeFileSync(trustPath,
// ..., {mode:0o600})` — a truncate-then-write with no temp+rename. The MAIN
// trust write was made atomic in the opt #43 audit, but this separate
// maintenance/repair script mutates the SAME trust file and was not converted.
// A crash/SIGTERM mid-writeFileSync → partially-written trust file → JSON.parse
// throws on next read → agent treats all project-local files as untrusted (or
// errors) until manually repaired. Silent-data-loss / correctness.
//
// Fix: route writeTrust through the shared atomicWriteFile helper (temp+rename
// same-dir, mode 0o600 preserved, unlink-on-error) imported from
// scripts/reverse-agent/lib/atomic-file.mjs. Post-write chmod enforces
// 0o600 even if the existing-mode preservation branch kept a looser mode.
//
// Test type: two layers.
//  (1) ROUTING PIN on trust-inspect.mjs source — the load-bearing change is
//      that the script routes through atomicWriteFile and no longer does a bare
//      writeFileSync(trustPath,...). Revert → the "absent" assertion fails
//      (the bare-write pattern returns) and the import assertion fails.
//  (2) BEHAVIORAL ATOMIC PIN via mock — make renameSync throw (simulating a
//      mid-rename ENOSPC/EIO) and assert the ORIGINAL trust file is untouched.
//      Pre-fix (bare writeFileSync): the file is truncated BEFORE the write, so
//      any failure mid-write loses the original. Post-fix (temp+rename): the
//      temp is written+unlinked; the original is untouched until a successful
//      rename, so it survives the failure. This exercises the EXACT helper
//      trust-inspect now routes through (atomicWriteFile from
//      atomic-file.mjs). Same proven pattern as opt #176/#41/#42/#43.

import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// --- Layer 1: routing pin on the fix site (trust-inspect.mjs source) ---

const source = readFileSync(
	fileURLToPath(new URL("../../../scripts/reverse-agent/trust-inspect.mjs", import.meta.url)),
	"utf-8",
);

describe("trust-inspect.mjs routes writeTrust through atomicWriteFile (opt #189 routing pin)", () => {
	it("imports atomicWriteFile from the lib helper", () => {
		expect(source).toContain('import { atomicWriteFile } from "./lib/atomic-file.mjs"');
	});

	it("the old bare-writeFileSync(trustPath,...) pattern is gone", () => {
		// Revert writeTrust to bare writeFileSync → this assertion fails (the
		// pattern returns).
		expect(source).not.toContain("writeFileSync(trustPath,");
	});

	it("calls atomicWriteFile with mode 0o600", () => {
		expect(source).toContain("atomicWriteFile(trustPath,");
		expect(source).toContain("0o600");
	});
});

// --- Layer 2: behavioral atomic pin on the helper trust-inspect routes through ---

// Mock node:fs so we can flip renameSync to throw on demand (simulating a
// mid-rename ENOSPC/EIO). atomicWriteFile imports renameSync as a named binding
// from "node:fs", so the mock intercepts it at the source.
vi.mock("node:fs", async (importActual) => {
	const actual = await importActual<typeof import("node:fs")>();
	return {
		...actual,
		renameSync: vi.fn(),
	};
});

// Route the .mjs specifier through a non-literal const so tsgo does not try to
// resolve the plain JS module (TS7016 "no declaration file"). Matches the
// report-write-guard.test.ts pattern. Runtime still loads the real helper.
const ATOMIC_FILE_HELPER = "../../../scripts/reverse-agent/lib/atomic-file.mjs";
const { atomicWriteFile } = await import(ATOMIC_FILE_HELPER);
const fs = await import("node:fs");

describe("atomicWriteFile (opt #189 trust-inspect atomicity — the helper trust-inspect routes through)", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = mkdtempSync(join(tmpdir(), "trust-inspect-atomic-"));
		// Default renameSync to the REAL implementation so success-path tests
		// exercise the real temp+rename. Resolved lazily here (not in the hoisted
		// vi.mock factory).
		const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
		vi.mocked(fs.renameSync).mockImplementation(actual.renameSync);
	});

	afterEach(() => {
		if (tempDir) rmSync(tempDir, { recursive: true, force: true });
		(tempDir as unknown as undefined) = undefined;
	});

	it("writes correct trust content via temp+rename and leaves no .tmp behind", () => {
		const target = join(tempDir, "trust.json");
		const payload = `${JSON.stringify({ "/some/path": true }, null, 2)}\n`;
		atomicWriteFile(target, payload, 0o600);

		expect(readFileSync(target, "utf8")).toBe(payload);
		const leftovers = readdirSync(tempDir).filter((f) => f.endsWith(".tmp"));
		expect(leftovers).toEqual([]);
	});

	it("ATOMIC PIN: a mid-rename failure leaves the ORIGINAL trust file intact (not truncated)", () => {
		const target = join(tempDir, "trust.json");
		const original = `${JSON.stringify({ "/keep/me": true }, null, 2)}\n`;
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
