/**
 * opt #238 — ResourceLoader.reload() leaked eventBus listeners across reloads.
 *
 * reload() (resource-loader.ts) re-ran every extension factory against the SAME
 * persistent `this.eventBus` (created once in the constructor, reused for the
 * loader's lifetime). Each factory's `api.events.on(channel, handler)` added a
 * NEW listener to the underlying EventEmitter; the previous reload's listeners
 * were NEVER removed (no clear, no per-load unsubscribe tracking). After N
 * reloads each event channel had N copies of every handler → events fired N
 * times (duplicate side-effects, e.g. an auto-resume extension queuing N steer
 * messages on one event) AND the old handlers/closures were never collected.
 *
 * Fix: wrap the eventBus so every `on()` registration's unsubscribe is recorded
 * in `eventUnsubs`; drain them (best-effort) before re-loading extensions in
 * reload(). Works for any EventBus (injected or default) — the wrapper only
 * intercepts `on` to track the unsub; emit passes through unchanged.
 *
 * The test injects an EventBus, registers a counting handler via an inline
 * extension factory, reloads TWICE, and emits between reloads. Post-fix: the
 * handler fires ONCE per emit (drain removed the stale listener before the
 * factory re-registered). Pre-fix (drain removed): the handler fires TWICE on
 * the second emit (two accumulated listeners).
 */
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createEventBus } from "../src/core/event-bus.ts";
import { DefaultResourceLoader } from "../src/core/resource-loader.ts";
import type { ExtensionFactory } from "../src/core/sdk.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";

describe("opt #238: ResourceLoader.reload() drains stale eventBus listeners", () => {
	let tempDir: string;
	let agentDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `opt238-eventbus-leak-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
	});

	afterEach(() => {
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("a handler registered via pi.events.on fires once per emit across reloads (no accumulation)", async () => {
		const bus = createEventBus();
		let counter = 0;

		// Inline factory registers a counting listener on every load.
		const factory: ExtensionFactory = (pi) => {
			pi.events.on("opt238", () => {
				counter++;
			});
		};

		const settingsManager = SettingsManager.create(tempDir, agentDir);
		const resourceLoader = new DefaultResourceLoader({
			cwd: tempDir,
			agentDir,
			settingsManager,
			eventBus: bus,
			extensionFactories: [factory],
			noSkills: true,
			noPromptTemplates: true,
			noThemes: true,
		});

		// First load → exactly one listener registered.
		await resourceLoader.reload();
		bus.emit("opt238", null);
		expect(counter).toBe(1);

		// Second reload re-runs the factory. Pre-fix this added a SECOND listener
		// without removing the first → the next emit fires twice. Post-fix the
		// drain removes the stale listener before the factory re-registers → the
		// next emit fires once.
		await resourceLoader.reload();
		bus.emit("opt238", null);
		expect(counter).toBe(2); // post-fix: 1 + 1. pre-fix: 1 + 2 = 3.

		// A third reload confirms the drain is not a one-off (still exactly one
		// listener after reload #3).
		await resourceLoader.reload();
		bus.emit("opt238", null);
		expect(counter).toBe(3); // post-fix: 2 + 1. pre-fix: 3 + 3 = 6.
	}, 15000);
});
