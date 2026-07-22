import { copyFileSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Regression guard for opt #52: built-in + custom theme loading must not crash when a theme
// file is missing, truncated, or corrupt (broken install / interrupted update / disk error /
// hand-edit). Previously:
//   - getBuiltinThemes used bare `JSON.parse(readFileSync(dark.json/light.json))` → ENOENT/
//     SyntaxError propagated into getAvailableThemesWithPaths (the /themes command) AND into
//     initTheme/setTheme. Their catch fell back to `loadTheme("dark")` — but if dark.json was
//     the corrupt file the fallback threw INSIDE the catch → uncaught → STARTUP CRASH.
//   - getCustomThemeInfos used `existsSync` then bare `readdirSync` → a TOCTOU deletion or
//     EACCES/EIO between the two threw out of getAvailableThemesWithPaths → /themes crash.
// opt #52 wraps both: corrupt built-ins are skipped (omitted from the record), the dark
// fallback chain tries dark → light, and the custom-dir readdirSync is guarded.

// Point getThemesDir/getCustomThemesDir at per-test temp dirs. vi.hoisted gives the mock
// factory a mutable ref it reads at instantiation time (after resetModules re-imports).
const hoisted = vi.hoisted(() => ({ themesDir: "", customThemesDir: "" }));

vi.mock("../src/config.ts", async (importActual) => {
	const actual = await importActual<typeof import("../src/config.ts")>();
	return {
		...actual,
		getThemesDir: () => hoisted.themesDir,
		getCustomThemesDir: () => hoisted.customThemesDir,
	};
});

// Real bundled theme fixtures (valid ThemeJson) we copy into the temp themes dir.
const FIXTURE_DIR = join(__dirname, "..", "src", "modes", "interactive", "theme");
const REAL_DARK = join(FIXTURE_DIR, "dark.json");
const REAL_LIGHT = join(FIXTURE_DIR, "light.json");

async function freshTheme() {
	// Bust the module-level BUILTIN_THEMES cache so each test re-reads the temp dir.
	vi.resetModules();
	return await import("../src/core/presentation/theme-runtime.ts");
}

describe("theme loading corrupt-file guards (opt #52)", () => {
	let tempRoot: string;

	beforeEach(() => {
		tempRoot = join(tmpdir(), `repi-theme-guard-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		hoisted.themesDir = join(tempRoot, "themes");
		hoisted.customThemesDir = join(tempRoot, "custom-themes");
		mkdirSync(hoisted.themesDir, { recursive: true });
	});

	afterEach(() => {
		vi.restoreAllMocks();
		rmSync(tempRoot, { recursive: true, force: true });
	});

	it("lists both built-ins when both theme files are valid", async () => {
		copyFileSync(REAL_DARK, join(hoisted.themesDir, "dark.json"));
		copyFileSync(REAL_LIGHT, join(hoisted.themesDir, "light.json"));
		const theme = await freshTheme();
		const names = theme
			.getAvailableThemesWithPaths()
			.map((t) => t.name)
			.sort();
		expect(names).toEqual(["dark", "light"]);
	});

	it("skips a corrupt dark.json and lists light, without throwing", async () => {
		// Corrupt dark.json (valid JSON missing required structure would also be skipped by
		// the read failure only if unparseable; here we use unparseable to force the catch).
		writeFileSync(join(hoisted.themesDir, "dark.json"), "{ this is not valid json", "utf-8");
		copyFileSync(REAL_LIGHT, join(hoisted.themesDir, "light.json"));
		const theme = await freshTheme();
		let names: string[] = [];
		expect(() => {
			names = theme.getAvailableThemesWithPaths().map((t) => t.name);
		}).not.toThrow();
		expect(names).toContain("light");
		expect(names).not.toContain("dark");
	});

	it("setTheme falls back to light (not crash) when dark.json is corrupt and the requested theme is missing", async () => {
		writeFileSync(join(hoisted.themesDir, "dark.json"), "{ broken", "utf-8");
		copyFileSync(REAL_LIGHT, join(hoisted.themesDir, "light.json"));
		const theme = await freshTheme();

		// Pre-fix: setTheme catch → loadTheme("dark") → getBuiltinThemes throws SyntaxError on
		// the corrupt dark.json → UNCAUGHT → setTheme throws. Post-fix: loadFallbackTheme tries
		// dark (skipped) → light → no throw, success:false with the original "not found" error.
		let result: { success: boolean; error?: string } | undefined;
		expect(() => {
			result = theme.setTheme("does-not-exist");
		}).not.toThrow();
		expect(result?.success).toBe(false);
		expect(result?.error).toContain("Theme not found");
	});

	it("does not throw when the custom themes dir is unreadable (readdirSync throws)", async () => {
		copyFileSync(REAL_DARK, join(hoisted.themesDir, "dark.json"));
		copyFileSync(REAL_LIGHT, join(hoisted.themesDir, "light.json"));
		// Point getCustomThemesDir at a FILE, not a dir: existsSync returns true (it's a file),
		// then readdirSync throws ENOTDIR. Pre-fix (existsSync-then-bare-readdirSync) this
		// propagated out of getAvailableThemesWithPaths → /themes crash. Root bypasses chmod so
		// we can't use EACCES, but ENOTDIR is the same unguarded-readdirSync-throw class.
		writeFileSync(join(tempRoot, "custom-themes-is-a-file"), "not a dir", "utf-8");
		hoisted.customThemesDir = join(tempRoot, "custom-themes-is-a-file");
		const theme = await freshTheme();
		let names: string[] = [];
		expect(() => {
			names = theme.getAvailableThemesWithPaths().map((t) => t.name);
		}).not.toThrow();
		// Built-ins still listed; the unreadable custom dir contributed nothing.
		expect(names).toEqual(["dark", "light"]);
	});

	it("does not throw when the custom themes dir does not exist (ENOENT)", async () => {
		copyFileSync(REAL_DARK, join(hoisted.themesDir, "dark.json"));
		copyFileSync(REAL_LIGHT, join(hoisted.themesDir, "light.json"));
		// customThemesDir was never created.
		const theme = await freshTheme();
		expect(existsSync(hoisted.customThemesDir)).toBe(false);
		let names: string[] = [];
		expect(() => {
			names = theme.getAvailableThemesWithPaths().map((t) => t.name);
		}).not.toThrow();
		expect(names).toEqual(["dark", "light"]);
	});
});
