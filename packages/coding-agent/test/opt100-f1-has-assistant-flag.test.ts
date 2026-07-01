/**
 * opt #100 F1 — session-manager _persist O(n) some() per append → O(1) _hasAssistant flag.
 *
 * Before the fix, every _persist(entry) ran a full fileEntries.some() scan to
 * decide whether an assistant message had been appended. Once the first
 * assistant flushed the file, that scan was redundant but still O(n) per append
 * → O(n^2) over a session. The fix tracks a boolean _hasAssistant flag set in
 * _appendEntry and recomputed in _buildIndex/newSession.
 */
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type SessionEntry, SessionManager } from "../src/core/session-manager.ts";

describe("opt100 F1: _persist O(1) _hasAssistant flag", () => {
	let tempDir: string;
	let sm: SessionManager;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-opt100-f1-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		// persist=true so _persist actually executes its some()/write logic.
		sm = SessionManager.create(tempDir);
	});

	afterEach(() => {
		if (tempDir && existsSync(tempDir)) {
			rmSync(tempDir, { recursive: true });
		}
	});

	function userMsg(text: string) {
		return {
			role: "user" as const,
			content: [{ type: "text" as const, text }],
			timestamp: Date.now(),
		};
	}

	function assistantMsg(text: string) {
		return {
			role: "assistant" as const,
			content: [{ type: "text" as const, text }],
			provider: "anthropic",
			model: "claude-sonnet-4-5",
			api: "anthropic",
			usage: {
				input: 1,
				output: 1,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 2,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			stopReason: "stop" as const,
			timestamp: Date.now(),
		};
	}

	it("flag is false before the first assistant and true after", () => {
		const internal = sm as unknown as { _hasAssistant: boolean; flushed: boolean };

		expect(internal._hasAssistant).toBe(false);
		sm.appendMessage(userMsg("hello"));
		expect(internal._hasAssistant).toBe(false);

		// Before the first assistant, flushed stays false (file deferred).
		expect(internal.flushed).toBe(false);

		sm.appendMessage(assistantMsg("hi there"));
		expect(internal._hasAssistant).toBe(true);
		// First assistant flushes the file (all entries written).
		expect(internal.flushed).toBe(true);
		expect(existsSync(sm.getSessionFile()!)).toBe(true);
	});

	it("does not run an O(n) some() scan per append after the first assistant", () => {
		const internal = sm as unknown as { fileEntries: SessionEntry[]; _hasAssistant: boolean };

		// Replace the some() method on the live fileEntries array instance with a
		// counting wrapper. _persist calls this.fileEntries.some(...), so the
		// instance-level override is invoked and counted.
		let someCalls = 0;
		internal.fileEntries.some = function (
			this: SessionEntry[],
			predicate: (e: SessionEntry, i: number, arr: SessionEntry[]) => boolean,
		): boolean {
			someCalls++;
			return Array.prototype.some.call(this, predicate) as boolean;
		};

		// Seed: one user + first assistant (which flushes the file). The pre-assistant
		// appends legitimately call some() because the flag is still false.
		sm.appendMessage(userMsg("seed"));
		sm.appendMessage(assistantMsg("seed reply"));
		expect(internal._hasAssistant).toBe(true);

		// Reset the counter — every subsequent append should use the O(1) flag and
		// NOT call some().
		someCalls = 0;

		const N = 2000;
		for (let i = 0; i < N; i++) {
			sm.appendMessage(userMsg(`m${i}`));
		}

		// O(1) per append: zero some() scans regardless of N.
		expect(someCalls).toBe(0);
	});

	it("recomputes the flag from disk on load (setSessionFile/_buildIndex)", () => {
		// Build a session with an assistant, then reload it from file.
		sm.appendMessage(userMsg("q"));
		sm.appendMessage(assistantMsg("a"));
		const file = sm.getSessionFile()!;

		const reloaded = SessionManager.open(file);
		const internal = reloaded as unknown as { _hasAssistant: boolean; flushed: boolean };
		expect(internal._hasAssistant).toBe(true);
		expect(internal.flushed).toBe(true);

		// A fresh session with no assistant must report false.
		const fresh = SessionManager.create(tempDir);
		expect((fresh as unknown as { _hasAssistant: boolean })._hasAssistant).toBe(false);
	});
});
