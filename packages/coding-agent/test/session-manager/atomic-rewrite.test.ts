import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { SessionManager } from "../../src/core/session-manager.ts";

describe("SessionManager._rewriteFile atomicity", () => {
	let tempDir: string;

	it("rewrites the session file atomically: complete + parseable, no temp artifact left behind", () => {
		tempDir = mkdtempSync(join(tmpdir(), "session-atomic-"));
		try {
			const session = SessionManager.create(tempDir, tempDir);
			session.appendMessage({ role: "user", content: "hello", timestamp: 1 });
			session.appendMessage({
				role: "assistant",
				content: [{ type: "text", text: "hi" }],
				api: "anthropic-messages",
				provider: "anthropic",
				model: "test",
				usage: {
					input: 1,
					output: 1,
					cacheRead: 0,
					cacheWrite: 0,
					totalTokens: 2,
					cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
				},
				stopReason: "stop",
				timestamp: 2,
			});

			const sessionFile = session.getSessionFile();
			expect(sessionFile).toBeDefined();
			expect(existsSync(sessionFile!)).toBe(true);
			const messageCountBefore = session.getEntries().filter((e) => e.type === "message").length;
			expect(messageCountBefore).toBe(2);

			// Trigger an atomic rewrite — the same internal the migration, fork, and
			// load-corruption-recovery paths use. Previously this did openSync("w")
			// (truncate-then-write), so a crash mid-write would lose the whole session.
			// temp+rename REPLACES the file's inode; the old truncate-then-write kept
			// the same inode. Asserting the inode changes is what distinguishes the
			// atomic implementation from the unsafe one (both produce a complete file).
			const inodeBefore = statSync(sessionFile!).ino;
			(session as unknown as { _rewriteFile: () => void })._rewriteFile();
			const inodeAfter = statSync(sessionFile!).ino;
			expect(inodeAfter).not.toBe(inodeBefore);

			// No temp file left behind in the session directory.
			const leftovers = readdirSync(dirname(sessionFile!)).filter((f) => f.endsWith(".tmp"));
			expect(leftovers).toEqual([]);

			// The session file is complete and every line is valid JSON (not truncated).
			// Parse the content and confirm both messages survived the rewrite intact.
			const content = readFileSync(sessionFile!, "utf8");
			const lines = content.trim().split("\n");
			expect(lines.length).toBeGreaterThanOrEqual(2);
			const parsed: Array<{ type: string; message?: { role: string } }> = [];
			for (const line of lines) {
				expect(() => JSON.parse(line)).not.toThrow();
				parsed.push(JSON.parse(line));
			}
			const messages = parsed.filter((e) => e.type === "message");
			expect(messages).toHaveLength(messageCountBefore);
			expect(messages[0]?.message?.role).toBe("user");
			expect(messages[1]?.message?.role).toBe("assistant");
		} finally {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("preserves a restrictive session file mode (0o600) across the atomic rewrite", () => {
		tempDir = mkdtempSync(join(tmpdir(), "session-atomic-mode-"));
		try {
			const session = SessionManager.create(tempDir, tempDir);
			session.appendMessage({ role: "user", content: "hello", timestamp: 1 });
			session.appendMessage({
				role: "assistant",
				content: [{ type: "text", text: "hi" }],
				api: "anthropic-messages",
				provider: "anthropic",
				model: "test",
				usage: {
					input: 1,
					output: 1,
					cacheRead: 0,
					cacheWrite: 0,
					totalTokens: 2,
					cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
				},
				stopReason: "stop",
				timestamp: 2,
			});
			const sessionFile = session.getSessionFile()!;
			chmodSync(sessionFile, 0o600);

			(session as unknown as { _rewriteFile: () => void })._rewriteFile();

			const mode = statSync(sessionFile).mode & 0o777;
			expect(mode).toBe(0o600);
		} finally {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});
});
