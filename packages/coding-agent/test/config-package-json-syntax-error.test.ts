import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Foundational opt #271: config.ts's package.json read only swallowed ENOENT;
// a SyntaxError (corrupt/hand-edited shipped package.json, `code === undefined`)
// was rethrown → crashed startup before VERSION/APP_NAME/CONFIG_DIR_NAME
// initialized. All downstream consumers tolerate missing fields via `??`/`||`
// defaults against `pkg = {}`, so the fix swallows the parse failure and
// degrades to defaults (with a stderr warning) instead of aborting. This test
// mocks readFileSync to throw SyntaxError for the package.json path and asserts
// config.ts loads with default metadata + a warning, no throw.

// Hoisted controller: vi.mock is hoisted to the top of the file and there can
// be only ONE vi.mock("fs") per file, so a state flag switches the thrown error
// per test rather than re-declaring the mock.
const state = vi.hoisted(() => ({ mode: "syntax" as "syntax" | "eacces" }));

vi.mock("fs", async () => {
	const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
	return {
		...actual,
		readFileSync: vi.fn((path: unknown, ...rest: unknown[]) => {
			if (typeof path === "string" && path.endsWith("package.json")) {
				if (state.mode === "syntax") {
					throw new SyntaxError("Unexpected token < in JSON at position 0");
				}
				const eacces = new Error("EACCES") as NodeJS.ErrnoException;
				eacces.code = "EACCES";
				throw eacces;
			}
			return (actual.readFileSync as unknown as (p: unknown, ...r: unknown[]) => unknown)(path, ...rest);
		}),
	};
});

describe("opt #271: config.ts degrades gracefully on a corrupt package.json (SyntaxError)", () => {
	beforeEach(() => {
		vi.resetModules();
		state.mode = "syntax";
	});

	afterEach(() => {
		vi.restoreAllMocks();
		vi.resetModules();
		state.mode = "syntax";
	});

	it("loads with default APP_NAME/VERSION + warns instead of crashing on SyntaxError", async () => {
		state.mode = "syntax";
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		// Importing config.ts runs its top-level package.json read. Pre-fix this
		// rethrew the SyntaxError; post-fix it swallows + warns + uses defaults.
		const config = await import("../src/config.ts");

		// No crash: defaults applied (APP_NAME falls back to "repi", VERSION "0.0.0").
		expect(config.APP_NAME).toBe("repi");
		expect(config.VERSION).toBe("0.0.0");
		expect(config.PACKAGE_NAME).toBe("@pi-recon/repi-coding-agent");

		// The parse failure was surfaced (not silently masked).
		expect(errorSpy).toHaveBeenCalled();
		const logged = errorSpy.mock.calls.map((c) => String(c[0])).join(" ");
		expect(logged).toMatch(/package\.json parse failed/);
	});

	it("still rethrows a non-ENOENT, non-SyntaxError error (e.g. EACCES)", async () => {
		state.mode = "eacces";
		vi.spyOn(console, "error").mockImplementation(() => {});

		// A real environment error (permissions) still surfaces — it is NOT a
		// parse failure and indicates a genuine problem worth failing on.
		await expect(import("../src/config.ts")).rejects.toThrow(/EACCES/);
	});
});
