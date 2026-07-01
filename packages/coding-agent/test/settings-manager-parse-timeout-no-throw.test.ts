/**
 * opt #242 — parseTimeoutSetting returns undefined (not throw) on a malformed
 * value, so the getter's `?? DEFAULT` fallback applies and startup doesn't
 * crash on a hand-edited settings.json.
 *
 * Pre-fix parseTimeoutSetting threw when `value` was present but
 * parseHttpIdleTimeoutMs returned undefined (negative, non-numeric, NaN). The
 * getters are `parseTimeoutSetting(...) ?? DEFAULT_HTTP_IDLE_TIMEOUT_MS`, but
 * the throw fired BEFORE `??` evaluated — so a settings.json with
 * "httpIdleTimeoutMs": -1 crashed startup at
 * configureHttpDispatcher(settingsManager.getHttpIdleTimeoutMs()). The read
 * path must not throw (setters still validate on write).
 *
 * Fix: return undefined on malformed → `?? DEFAULT` applies. The test seeds
 * {httpIdleTimeoutMs: -1} into the global settings file and asserts
 * getHttpIdleTimeoutMs() returns the default. Pre-fix (throw restored) it
 * throws.
 */
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DEFAULT_HTTP_IDLE_TIMEOUT_MS } from "../src/core/http-dispatcher.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";

describe("opt #242: parseTimeoutSetting does not throw on a malformed settings value", () => {
	let tempDir: string;
	let agentDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `opt242-timeout-no-throw-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
	});

	afterEach(() => {
		if (tempDir) rmSync(tempDir, { recursive: true, force: true });
	});

	it("getHttpIdleTimeoutMs returns the default for httpIdleTimeoutMs=-1 (no throw)", () => {
		// Seed a malformed value the setter would reject but loadFromStorage
		// does not validate (JSON.parse-only).
		writeFileSync(join(agentDir, "settings.json"), JSON.stringify({ httpIdleTimeoutMs: -1 }));

		const settings = SettingsManager.create(tempDir, agentDir);

		// Post-fix: returns the default. Pre-fix: throws "Invalid httpIdleTimeoutMs".
		expect(() => settings.getHttpIdleTimeoutMs()).not.toThrow();
		expect(settings.getHttpIdleTimeoutMs()).toBe(DEFAULT_HTTP_IDLE_TIMEOUT_MS);
	});

	it("getWebSocketConnectTimeoutMs returns undefined for a malformed value (no throw)", () => {
		writeFileSync(join(agentDir, "settings.json"), JSON.stringify({ websocketConnectTimeoutMs: "not-a-number" }));

		const settings = SettingsManager.create(tempDir, agentDir);
		expect(() => settings.getWebSocketConnectTimeoutMs()).not.toThrow();
		expect(settings.getWebSocketConnectTimeoutMs()).toBeUndefined();
	});
});
