import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cleanupSessionResources } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { registerPersistedTempFile } from "../src/core/tools/output-accumulator.ts";

// opt #153: persisted temp files (truncated bash overflow logs, pasted-image
// temp files) were tracked in a module-level Set drained ONLY by a
// process.on("exit") handler. In a long-running rpc daemon that handles many
// sessions over its lifetime, files accumulated across sessions — leaking in
// the OS tmpdir AND in the in-memory Set until the process exited. Fix:
// registerPersistedTempFile now accepts a sessionId; a session-resource
// cleanup (fired by cleanupSessionResources on newSession/fork/switchSession/
// dispose) unlinks that session's temp files, bounding growth to the live
// session. Files registered WITHOUT a sessionId (remote-bash path) keep the
// legacy exit-only behavior.
//
// Test exercises the real module-level state + the real cleanupSessionResources
// dispatch (the same path agent-session.ts:836 fires on session replacement).

describe("registerPersistedTempFile session-scoped cleanup (opt #153)", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-temp-session-153-"));
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	it("cleanupSessionResources(sessionId) unlinks that session's temp files", () => {
		const sessionId = `test-sess-153-a-${Math.random().toString(36).slice(2)}`;
		const fileA1 = join(dir, "a1.log");
		const fileA2 = join(dir, "a2.log");
		writeFileSync(fileA1, "x");
		writeFileSync(fileA2, "x");
		registerPersistedTempFile(fileA1, sessionId);
		registerPersistedTempFile(fileA2, sessionId);

		expect(existsSync(fileA1)).toBe(true);
		expect(existsSync(fileA2)).toBe(true);

		// Dismiss the session (mirrors agent-session dispose/replacement).
		cleanupSessionResources(sessionId);

		expect(existsSync(fileA1)).toBe(false);
		expect(existsSync(fileA2)).toBe(false);
	});

	it("cleanupSessionResources(sessionA) does NOT touch sessionB's files", () => {
		const sessionA = `test-sess-153-b-${Math.random().toString(36).slice(2)}`;
		const sessionB = `test-sess-153-c-${Math.random().toString(36).slice(2)}`;
		const fileA = join(dir, "a.log");
		const fileB = join(dir, "b.log");
		writeFileSync(fileA, "x");
		writeFileSync(fileB, "x");
		registerPersistedTempFile(fileA, sessionA);
		registerPersistedTempFile(fileB, sessionB);

		cleanupSessionResources(sessionA);

		// A's file unlinked, B's file preserved (B is still live).
		expect(existsSync(fileA)).toBe(false);
		expect(existsSync(fileB)).toBe(true);

		// Cleaning B afterward unlinks B's file (no cross-session residue).
		cleanupSessionResources(sessionB);
		expect(existsSync(fileB)).toBe(false);
	});

	it("files registered WITHOUT a sessionId are NOT unlinked by session cleanup (legacy exit-only)", () => {
		const sessionId = `test-sess-153-d-${Math.random().toString(36).slice(2)}`;
		const legacy = join(dir, "legacy.log");
		writeFileSync(legacy, "x");
		registerPersistedTempFile(legacy); // no sessionId — remote-bash path

		cleanupSessionResources(sessionId);

		// The legacy file survives session cleanup — it's only unlinked at
		// process exit (the remote-bash agent process is typically short-lived).
		expect(existsSync(legacy)).toBe(true);
	});
});
