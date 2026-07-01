import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, describe, expect, test, vi } from "vitest";

// Regression guard for opt #65 — find/grep awaited the fd/rg child via
// child.on("close") with abort the only early escape. On a hung FUSE/NFS mount or
// a D-state process (SIGTERM can't reap it), 'close' never fires → if the user
// doesn't abort, the tool hangs forever and freezes the agent. Fix: a wall
// timeout (REPI_FIND_TIMEOUT_MS / REPI_GREP_TIMEOUT_MS, default 120s) SIGKILLs
// the child (escalating past the abort's SIGTERM — a D-state process ignores
// SIGTERM) and settles. find/grep are result-capped (--max-results / stopChild on
// effectiveLimit) so a legitimate search exits well under the cap; it only fires
// on a genuinely hung process.
//
// The timeout is read lazily at execute time (getGrepTimeoutMs/getFindTimeoutMs),
// so this test stubs the env var right before execute — no resetModules/dynamic
// import needed.

const testHarness = vi.hoisted(() => ({ ensureToolPath: "" }));

// Inject a "hung" rg/fd: a script that ignores SIGTERM (simulates a D-state
// process that SIGTERM can't reap) and never exits. Only SIGKILL (the wall
// timeout's escalation) kills it.
vi.mock("../src/utils/tools-manager.ts", () => ({
	ensureTool: vi.fn(async () => testHarness.ensureToolPath),
}));

import { createFindTool } from "../src/core/tools/find.ts";
// Static imports — the mock above is hoisted and applies to these. The tool
// modules read the timeout env lazily at execute time, so no resetModules.
import { createGrepTool } from "../src/core/tools/grep.ts";

let hungScriptPath: string;

beforeAll(() => {
	const dir = mkdtempSync(join(tmpdir(), "pi-grep-find-hang-"));
	hungScriptPath = join(dir, "hung-tool.mjs");
	// Ignore SIGTERM (so the abort path's SIGTERM is ineffective, proving the
	// SIGKILL escalation is necessary) and never exit voluntarily. The shebang
	// points DIRECTLY at the node binary (not `env node`): `env node` makes the
	// real node a grandchild, so SIGKILL on the direct child only kills `env` and
	// orphans node (which holds the stdout pipe write end → vitest waits for it
	// forever). A direct-node shebang makes the child PID be node itself, so
	// child.kill("SIGKILL") reaps it cleanly. 0o755 so spawn(path) execs it.
	writeFileSync(
		hungScriptPath,
		`#!${process.execPath}\nprocess.on("SIGTERM", () => {});\nprocess.on("SIGHUP", () => {});\nsetInterval(() => {}, 1000);\n`,
	);
	chmodSync(hungScriptPath, 0o755);
	testHarness.ensureToolPath = hungScriptPath;
});

afterEach(() => {
	vi.unstubAllEnvs();
});

function makeSearchDir(): string {
	const dir = mkdtempSync(join(tmpdir(), "pi-grep-find-search-"));
	writeFileSync(join(dir, "a.txt"), "hello world\n");
	return dir;
}

describe("grep tool wall timeout (opt #65)", () => {
	test("a hung rg (SIGTERM-ignoring) is SIGKILLed and rejects after the wall timeout", async () => {
		vi.stubEnv("REPI_GREP_TIMEOUT_MS", "300");
		const grepTool = createGrepTool(process.cwd());
		const searchDir = makeSearchDir();
		const start = Date.now();
		await expect(grepTool.execute("t1", { pattern: "hello", path: searchDir }, undefined)).rejects.toThrow(
			/grep timed out after 300ms/,
		);
		const elapsed = Date.now() - start;
		expect(elapsed).toBeGreaterThanOrEqual(280);
		expect(elapsed).toBeLessThan(5000);
	}, 10000);
});

describe("find tool wall timeout (opt #65)", () => {
	test("a hung fd (SIGTERM-ignoring) is SIGKILLed and rejects after the wall timeout", async () => {
		vi.stubEnv("REPI_FIND_TIMEOUT_MS", "300");
		const findTool = createFindTool(process.cwd());
		const searchDir = makeSearchDir();
		const start = Date.now();
		await expect(findTool.execute("t2", { pattern: "*.txt", path: searchDir }, undefined)).rejects.toThrow(
			/find timed out after 300ms/,
		);
		const elapsed = Date.now() - start;
		expect(elapsed).toBeGreaterThanOrEqual(280);
		expect(elapsed).toBeLessThan(5000);
	}, 10000);
});
