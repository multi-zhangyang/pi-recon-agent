import { afterEach, describe, expect, it, vi } from "vitest";
import { InMemorySessionStorage } from "../../src/harness/session/memory-storage.ts";
import type { ThinkingLevelChangeEntry } from "../../src/harness/types.ts";

// A fixed timestamp inside one ~65.5s uuidv7 window. With the old slice(0, 8)
// the entry-id prefix was only the timestamp's top 32 bits → constant across
// the whole window, so every entry after the first collided and burned the
// 100-retry loop before falling back to a full 36-char id (mixed id lengths).
const FIXED_TS = 0x0123456789ab;

describe("generateEntryId 65s-window collision", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("keeps ids unique and consistently full-length within a fixed timestamp window", async () => {
		vi.spyOn(Date, "now").mockReturnValue(FIXED_TS);
		const storage = new InMemorySessionStorage();
		const ids: string[] = [];
		let parentId: string | null = null;
		for (let i = 0; i < 60; i++) {
			const id = await storage.createEntryId();
			ids.push(id);
			// Register the id (mirrors a real append) so the next generateEntryId
			// sees it — otherwise byId never grows and collisions never reproduce.
			const entry: ThinkingLevelChangeEntry = {
				type: "thinking_level_change",
				id,
				parentId,
				timestamp: "1970-01-01T00:00:00.000Z",
				thinkingLevel: "low",
			};
			await storage.appendEntry(entry);
			parentId = id;
		}

		// All unique.
		expect(new Set(ids).size).toBe(ids.length);
		// All full 36-char uuidv7 — no 8-char prefix mixed in from the first
		// non-colliding call (pre-fix ids[0] was 8 chars, ids[1..] were 36).
		expect(ids.every((id) => id.length === 36)).toBe(true);
	});
});
