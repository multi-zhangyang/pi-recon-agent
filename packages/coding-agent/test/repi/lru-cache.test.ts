import { describe, expect, it } from "vitest";
import { LruCache } from "../../src/core/repi/lru-cache.ts";

describe("REPI bounded LRU cache", () => {
	it("evicts the least-recently-used entry at the configured bound", () => {
		const cache = new LruCache<string, string>(2);
		cache.set("oldest", "a");
		cache.set("recent", "b");

		// A hit promotes the oldest entry, so "recent" becomes the eviction target.
		expect(cache.get("oldest")).toBe("a");
		cache.set("new", "c");

		expect(cache.size).toBe(2);
		expect(cache.get("recent")).toBeUndefined();
		expect(cache.get("oldest")).toBe("a");
		expect(cache.get("new")).toBe("c");
	});

	it("treats replacement as recent without evicting an extra entry", () => {
		const cache = new LruCache<string, number>(2);
		cache.set("a", 1);
		cache.set("b", 2);
		cache.set("a", 3);
		cache.set("c", 4);

		expect(cache.size).toBe(2);
		expect(cache.get("a")).toBe(3);
		expect(cache.get("b")).toBeUndefined();
		expect(cache.get("c")).toBe(4);
	});
});
