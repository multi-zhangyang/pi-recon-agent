/**
 * opt #231 — the session_compact extension event carries the CORRECT
 * compactionEntry (looked up by the id appendCompaction returns), not the
 * first .find(summary) match over getEntries().
 *
 * Pre-fix, both compaction paths did:
 *   this.sessionManager.appendCompaction(summary, ...); // id DISCARDED
 *   const newEntries = this.sessionManager.getEntries();   // ALL file entries, every branch
 *   const savedCompactionEntry = newEntries.find(e => e.type==="compaction" && e.summary===summary);
 * getEntries() returns every entry across every branch, so a PRIOR compaction on
 * this branch (or a forked sibling) sharing the same summary text (templated /
 * boilerplate summaries) made .find return the WRONG entry — stale id/timestamp/
 * firstKeptEntryId fed to session_compact consumers (e.g. REPI auto-resume).
 *
 * Post-fix, appendCompaction's returned id is captured and getEntry(id) fetches
 * the just-appended entry. The distinguishing assertion: seed a prior compaction
 * with the SAME summary the stubbed compact() will produce, then assert the
 * session_compact payload's compactionEntry.id is the NEW id, not the prior one.
 */
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent } from "@pi-recon/repi-agent-core";
import { getModel } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AgentSession } from "../src/core/agent-session.ts";
import { AuthStorage } from "../src/core/auth-storage.ts";
import {
	createExtensionRuntime,
	type Extension,
	type SessionCompactEvent,
	type SessionEvent,
} from "../src/core/extensions/index.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import { createSyntheticSourceInfo } from "../src/core/source-info.ts";
import { createTestResourceLoader } from "./utilities.ts";

// The summary the stubbed compact() will produce — SAME as the prior compaction
// we seed, to trigger the pre-fix .find(summary) misselection.
const DUP_SUMMARY = "DUP-SUMMARY";
const capturedEvents: SessionEvent[] = [];

vi.mock("../src/core/compaction/index.js", () => ({
	calculateContextTokens: (usage: {
		totalTokens?: number;
		input: number;
		output: number;
		cacheRead: number;
		cacheWrite: number;
	}) => usage.totalTokens ?? usage.input + usage.output + usage.cacheRead + usage.cacheWrite,
	collectEntriesForBranchSummary: () => ({ entries: [], commonAncestorId: null }),
	compact: async () => ({ summary: DUP_SUMMARY, firstKeptEntryId: "new-kept", tokensBefore: 200, details: {} }),
	estimateContextTokens: () => ({ tokens: 99999, usageTokens: 99999, trailingTokens: 0, lastUsageIndex: 0 }),
	estimateCompactionContext: () => ({ beforeTokens: 200, afterTokens: 100 }),
	generateBranchSummary: async () => ({ summary: "", aborted: false, readFiles: [], modifiedFiles: [] }),
	isContextOverflow: () => false,
	prepareCompaction: () => ({
		messagesToSummarize: [{ role: "user", content: [{ type: "text", text: "hello" }] }],
		turnPrefixMessages: [],
	}),
	shouldCompact: () => true,
	stripTrailingErrorAssistants: (messages: Array<{ role: string }>) => messages,
}));

function createCapturingExtension(): Extension {
	const handlers = new Map<string, ((...args: unknown[]) => Promise<unknown>)[]>();
	handlers.set("session_compact", [
		async (...args: unknown[]) => {
			capturedEvents.push(args[0] as SessionEvent);
			return undefined;
		},
	]);
	return {
		path: "test-extension",
		resolvedPath: "/test/test-extension.ts",
		sourceInfo: createSyntheticSourceInfo("<test:test-extension>", { source: "test" }),
		handlers,
		tools: new Map(),
		messageRenderers: new Map(),
		commands: new Map(),
		flags: new Map(),
		shortcuts: new Map(),
	};
}

describe("opt #231: session_compact event carries the correct compactionEntry (by id, not summary)", () => {
	let session: AgentSession;
	let sessionManager: SessionManager;
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-opt231-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		capturedEvents.length = 0;

		const model = getModel("anthropic", "claude-sonnet-4-5")!;
		const agent = new Agent({ initialState: { model, systemPrompt: "Test", tools: [] } });

		sessionManager = SessionManager.inMemory();
		const settingsManager = SettingsManager.create(tempDir, tempDir);
		const authStorage = AuthStorage.create(join(tempDir, "auth.json"));
		authStorage.setRuntimeApiKey("anthropic", "test-key");
		const modelRegistry = ModelRegistry.create(authStorage, tempDir);

		const extensions = [createCapturingExtension()];
		const runtime = createExtensionRuntime();
		const resourceLoader = {
			...createTestResourceLoader(),
			getExtensions: () => ({ extensions, errors: [], runtime }),
		};

		session = new AgentSession({
			agent,
			sessionManager,
			settingsManager,
			cwd: tempDir,
			modelRegistry,
			resourceLoader,
		});
	});

	afterEach(() => {
		session.dispose();
		vi.restoreAllMocks();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("a prior compaction sharing the same summary does not shadow the new entry in the event", async () => {
		// Seed a PRIOR compaction with the same summary the stubbed compact() will
		// produce. Pre-fix .find(summary) returns THIS one (first in file order).
		const priorId = sessionManager.appendCompaction(DUP_SUMMARY, "prior-kept", 100);
		// Seed a user message so prepareCompaction has branch content.
		sessionManager.appendMessage({ role: "user", content: [{ type: "text", text: "hello" }], timestamp: Date.now() });

		await session.compact();

		const compactEvents = capturedEvents.filter((e): e is SessionCompactEvent => e.type === "session_compact");
		expect(compactEvents).toHaveLength(1);
		const firedId = compactEvents[0].compactionEntry.id;

		// Post-fix: getEntry(compactionId) → the NEW entry, distinct from the prior.
		// Pre-fix: .find(summary===DUP_SUMMARY) → the prior entry → firedId === priorId.
		expect(firedId).not.toBe(priorId);
		// And it must be a real compaction entry that actually exists now.
		expect(sessionManager.getEntry(firedId)?.type).toBe("compaction");
		// firstKeptEntryId is the NEW compaction's ("new-kept"), not the prior's.
		expect(compactEvents[0].compactionEntry.firstKeptEntryId).toBe("new-kept");
	}, 15000);
});
