import { describe, expect, it } from "vitest";
import { repiIndexedToolPresent, repiResolvedToolPresent } from "../src/core/repi/tool-presence.ts";

describe("REPI tool presence helpers", () => {
	it("resolves aliases from the persisted tool index", () => {
		const index = new Map<string, { present: boolean; path?: string }>([
			["r2", { present: true, path: "/usr/bin/r2" }],
			["python3", { present: true, path: "/usr/bin/python3" }],
		]);

		expect(repiIndexedToolPresent(index, "radare2")).toBe(true);
		expect(repiIndexedToolPresent(index, "python")).toBe(true);
		expect(repiIndexedToolPresent(index, "frida")).toBeUndefined();
	});

	it("uses host probing only when the index has no explicit answer", () => {
		const index = new Map<string, { present: boolean; path?: string }>([["frida", { present: false }]]);
		const seen: string[] = [];
		const probe = (tool: string) => {
			seen.push(tool);
			return tool === "bash";
		};

		expect(repiResolvedToolPresent(index, "frida", { pathEnv: "/tmp/empty", probe })).toBe(false);
		expect(seen).toEqual([]);
		expect(repiResolvedToolPresent(index, "bash", { pathEnv: "/tmp/empty", probe })).toBe(true);
		expect(seen).toEqual(["bash"]);
	});
});
