import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type FsModule = typeof import("node:fs");
type WriteFileSyncArgs = Parameters<FsModule["writeFileSync"]>;

// Hoisted mutable state shared with the mocked writeFileSync so the mock can
// throw ENOSPC exactly once on the first first-flush write, then delegate to
// the real implementation for the retry. vi.hoisted runs before vi.mock's
// factory is evaluated, so referencing `state` from inside the factory is safe.
const state = vi.hoisted(() => ({ firstFlushThrow: true }));

// The source imports writeFileSync from "fs" (not "node:fs"), so mock that
// specifier. Every other export is passed through unchanged.
vi.mock("fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	const realWriteFileSync = actual.writeFileSync;
	return {
		...actual,
		writeFileSync: vi.fn((...args: WriteFileSyncArgs) => {
			// The first-flush path calls writeFileSync(fd, line) with a NUMERIC
			// file descriptor (openSync("wx") just created the file). The
			// append path uses appendFileSync; _rewriteFile is not exercised
			// here. Throw ENOSPC once on the first fd-style call to simulate
			// disk full mid-loop, right after the file was created.
			if (typeof args[0] === "number" && state.firstFlushThrow) {
				state.firstFlushThrow = false;
				const err = new Error("ENOSPC: no space left on device, write") as Error & { code: string };
				err.code = "ENOSPC";
				throw err;
			}
			return (realWriteFileSync as (...a: WriteFileSyncArgs) => void)(...args);
		}),
	};
});

// Import AFTER vi.mock so the SessionManager picks up the mocked writeFileSync.
const { SessionManager } = await import("../src/core/session-manager.ts");

interface Usage {
	input: number;
	output: number;
	cacheRead: number;
	cacheWrite: number;
	totalTokens: number;
	cost: { input: number; output: number; cacheRead: number; cacheWrite: number; total: number };
}

const usage: Usage = {
	input: 1,
	output: 1,
	cacheRead: 0,
	cacheWrite: 0,
	totalTokens: 2,
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
};

describe("SessionManager first-flush ENOSPC — partial file removed, retry does not brick", () => {
	let tempDir: string;

	beforeEach(() => {
		state.firstFlushThrow = true;
		tempDir = mkdtempSync(join(tmpdir(), "session-firstflush-enospc-"));
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("unlinks the partial file on ENOSPC so the next persist recreates cleanly (no EEXIST)", () => {
		const session = SessionManager.create(tempDir, tempDir);
		const sessionFile = session.getSessionFile();
		expect(sessionFile).toBeDefined();

		// A user message alone does not flush (no assistant yet).
		session.appendMessage({ role: "user", content: "hello", timestamp: 1 });
		expect(existsSync(sessionFile!)).toBe(false);

		// The first assistant message triggers the first-flush path: openSync
		// creates the file, then the mocked writeFileSync throws ENOSPC mid-loop.
		// Previously the partial file was left on disk while flushed stayed false.
		expect(() =>
			session.appendMessage({
				role: "assistant",
				content: [{ type: "text", text: "hi" }],
				api: "anthropic-messages",
				provider: "anthropic",
				model: "test",
				usage,
				stopReason: "stop",
				timestamp: 2,
			}),
		).toThrow(/ENOSPC/);

		// Key behavioral pin: the partial file must have been removed by the
		// error path so the next openSync("wx") does not hit EEXIST.
		expect(existsSync(sessionFile!)).toBe(false);

		// The next append re-enters the !flushed branch. Without the fix this
		// throws EEXIST (file still present) on EVERY subsequent append, bricking
		// persistence. With the fix, openSync("wx") succeeds and all buffered
		// fileEntries (user + assistant + this new user) are written cleanly.
		expect(() => session.appendMessage({ role: "user", content: "again", timestamp: 3 })).not.toThrow();

		// The file now exists and is complete + parseable. It holds the session
		// header entry plus the three buffered messages (user/assistant/user).
		expect(existsSync(sessionFile!)).toBe(true);
		const content = readFileSync(sessionFile!, "utf8");
		const lines = content.trim().split("\n");
		expect(lines.length).toBe(4);
		const parsed: Array<{ type: string; message?: { role: string } }> = [];
		for (const line of lines) {
			expect(() => JSON.parse(line)).not.toThrow();
			parsed.push(JSON.parse(line));
		}
		expect(parsed.some((e) => e.type === "session")).toBe(true);
		const messages = parsed.filter((e) => e.type === "message");
		expect(messages).toHaveLength(3);
		expect(messages[0]?.message?.role).toBe("user");
		expect(messages[1]?.message?.role).toBe("assistant");
		expect(messages[2]?.message?.role).toBe("user");
	});
});
