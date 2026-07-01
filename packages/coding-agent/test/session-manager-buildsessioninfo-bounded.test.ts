import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildSessionInfo } from "../src/core/session-manager.ts";

// opt #167: buildSessionInfo streamed the session JSONL via readline (good)
// but pushed every user/assistant textContent into allMessages: string[] with
// NO cap, then returned allMessages.join(" ") as allMessagesText — purely for
// the session-picker fuzzy search. buildSessionInfosWithConcurrency
// (concurrency 10) ran this for ALL sessions at once on list/search → the full
// transcript of every session was accumulated in memory → OOM on several long
// sessions. Now allMessagesText is bounded per session (head + recent tail,
// final slice to cap; REPI_SESSION_SEARCH_MAX_CHARS, default 256 KB, 0 =
// disable). A normal session whose total text stays under the cap is
// byte-identical to the uncapped join.

interface MsgEntry {
	type: "message";
	id: string;
	parentId: string | null;
	timestamp: string;
	message: { role: "user" | "assistant"; content: string };
}

function msgLine(id: number, role: "user" | "assistant", text: string): string {
	const entry: MsgEntry = {
		type: "message",
		id: `m${id}`,
		parentId: id === 1 ? null : `m${id - 1}`,
		timestamp: new Date(2026, 0, 1, 0, 0, id).toISOString(),
		message: { role, content: text },
	};
	return JSON.stringify(entry);
}

function headerLine(id: string, cwd = "/tmp"): string {
	return JSON.stringify({
		type: "session",
		version: 3,
		id,
		timestamp: "2026-01-01T00:00:00.000Z",
		cwd,
	});
}

function writeSession(file: string, lines: string[]): void {
	writeFileSync(file, `${lines.join("\n")}\n`);
}

describe("buildSessionInfo bounded allMessagesText (opt #167)", () => {
	let dir: string;
	const prev = process.env.REPI_SESSION_SEARCH_MAX_CHARS;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-sessioninfo-167-"));
		delete process.env.REPI_SESSION_SEARCH_MAX_CHARS;
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
		if (prev === undefined) delete process.env.REPI_SESSION_SEARCH_MAX_CHARS;
		else process.env.REPI_SESSION_SEARCH_MAX_CHARS = prev;
	});

	it("small session: allMessagesText is byte-identical to the uncapped join (parity)", async () => {
		const lines = [
			headerLine("small-1"),
			msgLine(1, "user", "list open ports on the target"),
			msgLine(2, "assistant", "running nmap -sS -p- against 10.0.0.1"),
			msgLine(3, "user", "now scan for udp"),
			msgLine(4, "assistant", "nmap -sU --top-ports 50"),
		];
		const file = join(dir, "small.jsonl");
		writeSession(file, lines);

		const expected = [
			"list open ports on the target",
			"running nmap -sS -p- against 10.0.0.1",
			"now scan for udp",
			"nmap -sU --top-ports 50",
		].join(" ");

		// Default cap (256 KB) — total is far under the cap, capped path runs.
		const info = await buildSessionInfo(file);
		expect(info).not.toBeNull();
		expect(info?.allMessagesText).toBe(expected);
		expect(info?.firstMessage).toBe("list open ports on the target");

		// cap=0 (disabled) — uncapped path, must also be byte-identical.
		process.env.REPI_SESSION_SEARCH_MAX_CHARS = "0";
		const infoUncapped = await buildSessionInfo(file);
		expect(infoUncapped?.allMessagesText).toBe(expected);
	});

	it("large session: allMessagesText length is bounded <= cap and keeps firstMessage", async () => {
		// Use a tiny cap so we can exceed it with a modest fixture.
		process.env.REPI_SESSION_SEARCH_MAX_CHARS = "120";
		const lines = [headerLine("large-1")];
		const texts: string[] = [];
		// first user message (becomes firstMessage / head)
		texts.push("enumerate the target 10.0.0.1 with a full tcp scan");
		lines.push(msgLine(1, "user", texts[0]!));
		// many subsequent messages whose total far exceeds 120 chars
		for (let i = 2; i <= 40; i++) {
			const role = i % 2 === 0 ? "assistant" : "user";
			const t = `msg-${i}-padding-xxxxxxxxxxxx-${i}`;
			texts.push(t);
			lines.push(msgLine(i, role, t));
		}
		const file = join(dir, "large.jsonl");
		writeSession(file, lines);

		const uncappedTotal = texts.join(" ").length;
		expect(uncappedTotal).toBeGreaterThan(120);

		const info = await buildSessionInfo(file);
		expect(info).not.toBeNull();
		// The returned text must be bounded by the cap.
		expect(info!.allMessagesText.length).toBeLessThanOrEqual(120);
		// Representative content: the head (firstMessage) is preserved.
		expect(info!.allMessagesText.startsWith(texts[0]!)).toBe(true);
		expect(info!.firstMessage).toBe(texts[0]!);
		// And it is strictly smaller than the uncapped total.
		expect(info!.allMessagesText.length).toBeLessThan(uncappedTotal);
	});

	it("cap=0 disables the cap: full text returned for an over-cap session", async () => {
		const lines = [headerLine("dis-1")];
		const texts: string[] = [];
		texts.push("first user message here");
		lines.push(msgLine(1, "user", texts[0]!));
		for (let i = 2; i <= 10; i++) {
			const t = `padding-message-${i}-xxxxxxxxxxxx`;
			texts.push(t);
			lines.push(msgLine(i, i % 2 === 0 ? "assistant" : "user", t));
		}
		const file = join(dir, "disable.jsonl");
		writeSession(file, lines);
		const expected = texts.join(" ");
		// Sanity: the fixture really is over the small-cap bound.
		process.env.REPI_SESSION_SEARCH_MAX_CHARS = "50";
		const capped = await buildSessionInfo(file);
		expect(capped!.allMessagesText.length).toBeLessThanOrEqual(50);

		// cap=0 → full uncapped join returned byte-for-byte.
		process.env.REPI_SESSION_SEARCH_MAX_CHARS = "0";
		const info = await buildSessionInfo(file);
		expect(info?.allMessagesText).toBe(expected);
	});

	it("returns null for a non-session file", async () => {
		const file = join(dir, "garbage.jsonl");
		writeFileSync(file, "not json at all\n");
		expect(await buildSessionInfo(file)).toBeNull();
	});
});
