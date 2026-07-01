import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { NodeExecutionEnv } from "../../src/harness/env/nodejs.ts";
import { JsonlSessionStorage } from "../../src/harness/session/jsonl-storage.ts";
import { InMemorySessionStorage } from "../../src/harness/session/memory-storage.ts";
import type { MessageEntry } from "../../src/harness/types.ts";
import { createAssistantMessage, createTempDir, createUserMessage } from "./session-test-utils.ts";

// opt #92 — agent-core session storage hardening (audit F1 + F3).
//
// F1: appendEntry/setLeafId persist via appendFile (non-atomic — opt #38 only
// made the _rewriteFile path atomic), so a crash mid-flush leaves a torn
// TRAILING line (partial JSON, no trailing "\n"). Without read-side tolerance
// ONE torn line made the ENTIRE session unopenable (parseEntryLine throws
// invalid_entry → open rejects → the whole session's history unreachable).
// Worse: without healing, the next appendEntry would concatenate onto the
// partial line → one fused unhealable INTERIOR corrupt line. The fix drops a
// torn LAST line in-memory AND re-truncates the file to the last good line.
//
// F3: getPathToRoot walks parentId upward with no cycle guard; a bit-rotted
// file with A.parentId=B, B.parentId=A spins forever (runs per turn via
// buildContext → getBranch → event-loop-blocking CPU spin). The fix converts a
// cycle into a typed invalid_session error.

const HEADER = (cwd: string) => ({
	type: "session" as const,
	version: 3,
	id: "session-1",
	timestamp: "2026-01-01T00:00:00.000Z",
	cwd,
});

function userEntry(id: string, parentId: string | null, text: string): MessageEntry {
	return {
		type: "message",
		id,
		parentId,
		timestamp: "2026-01-01T00:00:00.000Z",
		message: createUserMessage(text),
	};
}

describe("JsonlSessionStorage torn trailing line tolerance (F1)", () => {
	it("opens a session whose final line is a torn partial write (drops + heals)", async () => {
		const dir = createTempDir();
		const env = new NodeExecutionEnv({ cwd: dir });
		const filePath = join(dir, "session.jsonl");
		const storage = await JsonlSessionStorage.create(env, filePath, { cwd: dir, sessionId: "session-1" });
		await storage.appendEntry(userEntry("u1", null, "one"));
		await storage.appendEntry(userEntry("u2", "u1", "two"));

		// Simulate a crash mid-appendFile: cut the last entry line mid-JSON and drop
		// the trailing newline (the torn-write signature). The file now ends with a
		// partial line that JSON.parse cannot parse.
		const fullLines = readFileSync(filePath, "utf8").split("\n"); // [header, u1, u2, ""]
		const tornU2 = fullLines[2]!.slice(0, Math.max(1, fullLines[2]!.length - 20)); // partial JSON
		const torn = [fullLines[0], fullLines[1], tornU2].join("\n"); // no trailing \n
		writeFileSync(filePath, torn);
		expect(readFileSync(filePath, "utf8").endsWith("\n")).toBe(false);

		// Before the fix: open threw invalid_entry → whole session unopenable.
		const reopened = await JsonlSessionStorage.open(env, filePath);
		const entries = await reopened.getEntries();
		// The torn last line was dropped; the first good entry survives.
		expect(entries.map((entry) => entry.id)).toEqual(["u1"]);

		// The file was healed (re-truncated to the last good line boundary).
		const healed = readFileSync(filePath, "utf8");
		const healedLines = healed.split("\n").filter((line) => line.trim());
		expect(healedLines.map((line) => JSON.parse(line).id)).toEqual(["session-1", "u1"]);
		// Healed file ends with a newline so the next append is clean.
		expect(healed.endsWith("\n")).toBe(true);

		// The next appendEntry round-trips (no fusion onto a partial line).
		await reopened.appendEntry(userEntry("u3", "u1", "three"));
		const reopened2 = await JsonlSessionStorage.open(env, filePath);
		expect((await reopened2.getEntries()).map((entry) => entry.id)).toEqual(["u1", "u3"]);
	});

	it("still rejects an interior corrupt line (genuine corruption, not a torn tail)", async () => {
		const dir = createTempDir();
		const env = new NodeExecutionEnv({ cwd: dir });
		const filePath = join(dir, "session.jsonl");
		// Corrupt line is INTERIOR (a valid entry follows it) → not a torn tail.
		writeFileSync(
			filePath,
			`${JSON.stringify(HEADER(dir))}\nnot json\n${JSON.stringify(userEntry("u1", null, "one"))}\n`,
		);
		await expect(JsonlSessionStorage.open(env, filePath)).rejects.toMatchObject({ code: "invalid_entry" });
	});
});

describe("getPathToRoot cycle guard (F3)", () => {
	it("throws invalid_session on a parentId cycle instead of hanging", async () => {
		// A bit-rotted file with A.parentId=B, B.parentId=A. Without the cycle
		// guard getPathToRoot spins forever (event-loop-blocking). Wrap in a
		// timeout race so a hang fails the test fast.
		const a: MessageEntry = {
			type: "message",
			id: "a",
			parentId: "b",
			timestamp: "2026-01-01T00:00:00.000Z",
			message: createAssistantMessage("a"),
		};
		const b: MessageEntry = { ...a, id: "b", parentId: "a", message: createUserMessage("b") };
		const storage = new InMemorySessionStorage({ entries: [a, b] });

		const result = await Promise.race([
			storage.getPathToRoot("a").then(
				() => "resolved" as const,
				(error: unknown) => error,
			),
			new Promise<"hung">((resolve) => setTimeout(() => resolve("hung"), 2000)),
		]);

		expect(result).not.toBe("hung");
		expect(result).toBeInstanceOf(Error);
		if (result instanceof Error) {
			expect(() => {
				throw result;
			}).toThrow(/Cycle detected/);
		}
	});
});
