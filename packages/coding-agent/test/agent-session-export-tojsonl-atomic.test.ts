import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { exportSessionToJsonl } from "../src/core/agent-session-presentation-runtime.ts";

// opt #150: AgentSession.exportToJsonl wrote the full session JSONL via
// writeFileSync (truncate-then-write) to the user's target path. A crash /
// SIGKILL / OOM mid-write — or the user Ctrl-C'ing a large export — left a
// truncated .jsonl that looks like valid JSONL up to the cut and is reported
// as a success (the returned path exists). Unlike the session file itself
// (atomic via _rewriteFile, opt #38), exports were an uncovered truncate-
// then-write of a file the user later relies on. Now routed through
// atomicWriteFileSync (temp+rename, 0o644) so readers see complete-old-or-new,
// never torn. The inode-change probe (same doctrine as opts #38/#41/#42/#43)
// distinguishes temp+rename (new inode) from truncate-then-write (same inode).
//
// exportToJsonl is a public method reachable via AgentSession.prototype; it
// only touches this.sessionManager (getSessionId/getCwd/getBranch) + module-
// level helpers (resolvePath/dirname/existsSync/mkdirSync/atomicWriteFileSync),
// so a fake `this` carrying just a stub sessionManager exercises the real
// write path in isolation.

type StubEntry = { id: string; type?: string; [key: string]: unknown };

type Ctx = {
	sessionManager: {
		getSessionId: () => string;
		getCwd: () => string;
		getBranch: () => StubEntry[];
	};
};

function makeCtx(cwd: string, entries: StubEntry[]): Ctx {
	return {
		sessionManager: {
			getSessionId: () => "test-session-150",
			getCwd: () => cwd,
			getBranch: () => entries,
		},
	};
}

describe("AgentSession.exportToJsonl atomic write (opt #150)", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-export-150-"));
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	it("writes atomically — temp+rename replaces the inode between exports", () => {
		const ctx = makeCtx(dir, [
			{ id: "e1", type: "user" },
			{ id: "e2", type: "assistant" },
		]);
		const out = join(dir, "export.jsonl");

		const returned1 = exportSessionToJsonl(ctx.sessionManager as never, out);
		expect(returned1).toBe(out);
		const ino1 = statSync(out).ino;

		exportSessionToJsonl(ctx.sessionManager as never, out);
		const ino2 = statSync(out).ino;

		if (ino1 === 0 || ino2 === 0) {
			console.warn("inode-change probe not supported on this filesystem (ino=0); skipping");
			return;
		}
		// Atomic temp+rename → a NEW inode replaces the old. Truncate-then-write
		// would keep the SAME inode → this assertion pins the fix.
		expect(ino2).not.toBe(ino1);

		// Content is complete and well-formed JSONL (header + 2 entries).
		const lines = readFileSync(out, "utf-8").trim().split("\n");
		expect(lines.length).toBe(3);
		const header = JSON.parse(lines[0]!) as { type: string; id: string };
		expect(header.type).toBe("session");
		expect(JSON.parse(lines[1]!).id).toBe("e1");
		expect(JSON.parse(lines[2]!).id).toBe("e2");
	});

	it("creates the parent dir if missing and leaves no orphaned .tmp", () => {
		const ctx = makeCtx(dir, [{ id: "e1" }]);
		const nested = join(dir, "sub", "deep", "export.jsonl");

		const returned = exportSessionToJsonl(ctx.sessionManager as never, nested);
		expect(returned).toBe(nested);
		expect(existsSync(nested)).toBe(true);

		const tmpFiles = readdirSync(join(dir, "sub", "deep")).filter((e) => e.endsWith(".tmp"));
		expect(tmpFiles).toEqual([]);
	});
});
