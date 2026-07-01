import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { migrateModelsJsonConfigValues } from "../src/migrations.ts";

// opt #155: migrateModelsJsonConfigValues parsed the user-supplied
// ~/.repi/models.json with a bare JSON.parse(stripJsonComments(...)) and NO
// try/catch. A syntactically-malformed file (trailing comma, unterminated
// string — anything the regex-based stripJsonComments leaves invalid) made
// JSON.parse throw a SyntaxError. runMigrations (called at startup from
// main.ts) invokes this via migrateExplicitEnvVarConfigValues with no
// surrounding try/catch → the SyntaxError was uncaught → the agent CRASHED at
// startup before any session loaded. The sibling migrateAuthJsonConfigValues
// wraps its whole body in try/catch and model-registry's loadCustomModels
// catches SyntaxError gracefully; this was the lone inconsistency. Fix: wrap
// the body in try/catch → a malformed models.json skips migration (no values
// to migrate) instead of crashing. Mirrors the auth sibling exactly.

describe("migrateModelsJsonConfigValues tolerates a malformed models.json (opt #155)", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-migrate-models-155-"));
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	it("a trailing-comma models.json does NOT crash (returns [] instead of throwing)", () => {
		// Trailing comma after the last provider — valid JS object literal but
		// INVALID JSON; stripJsonComments (a regex stripper) does not fix it.
		writeFileSync(join(dir, "models.json"), '{"providers":{"openai":{"apiKey":"k",},}}');
		// Before the fix: JSON.parse throws SyntaxError here → this call crashes.
		// After the fix: caught → returns [].
		expect(() => migrateModelsJsonConfigValues(dir)).not.toThrow();
		expect(migrateModelsJsonConfigValues(dir)).toEqual([]);
	});

	it("an unterminated-string models.json does NOT crash", () => {
		writeFileSync(join(dir, "models.json"), '{"providers":{"openai":{"apiKey":"unterminated');
		expect(() => migrateModelsJsonConfigValues(dir)).not.toThrow();
		expect(migrateModelsJsonConfigValues(dir)).toEqual([]);
	});

	it("a well-formed models.json with a legacy env-var-name apiKey migrates (regression guard)", () => {
		// isLegacyEnvVarNameConfigValue matches /^[A-Z_][A-Z0-9_]*$/ → an
		// all-caps env-var-name value is migrated to $-prefixed syntax.
		writeFileSync(join(dir, "models.json"), '{"providers":{"openai":{"apiKey":"OPENAI_API_KEY"}}}');
		const migrations = migrateModelsJsonConfigValues(dir);
		// The try/catch must NOT swallow a legitimate migration on a valid file.
		expect(migrations.length).toBeGreaterThanOrEqual(1);
		expect(migrations.some((m) => m.location.includes("apiKey"))).toBe(true);
		expect(migrations.some((m) => m.from === "OPENAI_API_KEY" && m.to === "$OPENAI_API_KEY")).toBe(true);
	});
});
