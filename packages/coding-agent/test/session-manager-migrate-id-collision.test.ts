/**
 * opt #225 — migrateV1ToV2 records each generated id in the collision set so
 * generateId's 100-retry collision check actually works across the migration.
 *
 * Pre-fix, the local `ids` Set was never added to, so generateId's
 * `if (!byId.has(id)) return id` check was dead — two colliding 8-hex ids
 * would silently share an id, shadowing one entry in byId and corrupting the
 * parent chain (silent context loss, same class as #222/#223).
 *
 * This test forces randomUUID to collide on the first two generations then
 * diverge, and asserts the two migrated entries get DISTINCT ids.
 */
import { describe, expect, it, vi } from "vitest";

const { randomUUIDMock } = vi.hoisted(() => ({ randomUUIDMock: vi.fn() }));

vi.mock("crypto", async (importOriginal) => {
	const actual = await importOriginal<typeof import("crypto")>();
	return { ...actual, randomUUID: randomUUIDMock };
});

import { migrateSessionEntries, parseSessionEntries } from "../src/core/session-manager.ts";

describe("opt #225: migrateV1ToV2 collision set is populated", () => {
	it("migrated entries get distinct ids even when randomUUID collides", () => {
		let call = 0;
		randomUUIDMock.mockImplementation(() => {
			call++;
			// First two generations collide (slice(0,8) === "AAAAAAAA"); third diverges.
			if (call <= 2) return "AAAAAAAA-0000-0000-0000-000000000001";
			return "BBBBBBBB-0000-0000-0000-000000000002";
		});

		const entries = parseSessionEntries(
			'{"type":"session","id":"s1","timestamp":"2025-01-01T00:00:00Z","cwd":"/tmp","version":1}\n' +
				'{"type":"message","timestamp":"2025-01-01T00:00:00Z","message":{"role":"user","content":"a","timestamp":1}}\n' +
				'{"type":"message","timestamp":"2025-01-01T00:00:00Z","message":{"role":"assistant","content":[{"type":"text","text":"b"}],"timestamp":1}}\n',
		);
		migrateSessionEntries(entries);

		// The mock must actually fire — confirms the binding is live.
		expect(randomUUIDMock).toHaveBeenCalled();

		const ids = entries.filter((e) => e.type !== "session").map((e) => (e as { id: string }).id);
		expect(ids).toHaveLength(2);
		// With the fix: entry1="AAAAAAAA", entry2 retries→"BBBBBBBB" (unique).
		// Pre-fix: ids set never populated → entry2="AAAAAAAA" (duplicate).
		expect(new Set(ids).size).toBe(2);
		expect(ids).toContain("AAAAAAAA");
		expect(ids).toContain("BBBBBBBB");
	});
});
