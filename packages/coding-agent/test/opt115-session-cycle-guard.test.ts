import { spawnSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// Derive repo root from this test file's location:
//   <repo>/packages/coding-agent/test/opt115-session-cycle-guard.test.ts
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "../../..");
const TSX = join(REPO_ROOT, "node_modules", ".bin", "tsx");
const SESSION_MANAGER = join(REPO_ROOT, "packages", "coding-agent", "src", "core", "session-manager.ts");

describe("opt #115 — parentId cycle guard in tree walks", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `opt115-cycle-${Date.now()}`);
		mkdirSync(tempDir, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("buildSessionContext throws on a cyclic parentId chain instead of infinite-looping", () => {
		// A cycle (A.parentId=B, B.parentId=A) can arise from bit rot / hand
		// editing of a session JSONL file. The walk `while (current) { current =
		// byId.get(current.parentId) }` has no termination condition on a cycle,
		// so without a visited-set guard it spins the event loop at 100% CPU
		// forever (kill -9 required). Run in a SUBPROCESS with a hard wall-clock
		// timeout: a missing guard infinite-loops and blocks the event loop, so
		// an in-process test would hang the whole suite. The subprocess turns
		// that into a clean timeout kill (SIGTERM, empty stdout) we assert against.
		const script = `
import { buildSessionContext } from ${JSON.stringify(SESSION_MANAGER)};

const A = { id: "A", parentId: "B", type: "message", timestamp: "2025-01-01T00:00:00Z", message: { role: "user", content: "a", timestamp: 1 } };
const B = { id: "B", parentId: "A", type: "message", timestamp: "2025-01-01T00:00:01Z", message: { role: "user", content: "b", timestamp: 2 } };
const byId = new Map([["A", A], ["B", B]]);

try {
	buildSessionContext([A, B], "A", byId);
	process.stdout.write("NO_THROW\\n");
} catch (e) {
	process.stdout.write("THREW:" + (e instanceof Error ? e.message : String(e)) + "\\n");
}
`;
		const scriptPath = join(tempDir, "cycle-probe.ts");
		writeFileSync(scriptPath, script);

		// Strip NODE_OPTIONS: vitest injects its own ESM loader flags here, which
		// conflict with tsx's loader when inherited by the child and break the
		// import (child exits non-zero with an error on stderr, no stdout).
		const childEnv = { ...process.env };
		delete childEnv.NODE_OPTIONS;

		const result = spawnSync(TSX, [scriptPath], {
			encoding: "utf8",
			timeout: 8000,
			env: childEnv,
		});

		// With the guard: throws "cycle detected" -> stdout "THREW:...", no timeout.
		// Without the guard: infinite loop -> timeout kills child -> SIGTERM + empty stdout.
		expect(result.signal).not.toBe("SIGTERM");
		expect(result.stdout, `stdout=${result.stdout!} stderr=${result.stderr!}`).toContain("THREW");
		expect(result.stdout).toContain("cycle");
	}, 20000);
});
