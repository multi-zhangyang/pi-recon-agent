import {
	fauxAssistantMessage,
	completeSimple as globalCompleteSimple,
	streamSimple as globalStreamSimple,
	type Models,
	registerFauxProvider,
} from "@pi-recon/repi-ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AgentHarness } from "../../src/harness/agent-harness.ts";
import { generateBranchSummary } from "../../src/harness/compaction/branch-summarization.ts";
import { type CompactionPreparation, compact, generateSummary } from "../../src/harness/compaction/compaction.ts";
import { NodeExecutionEnv } from "../../src/harness/env/nodejs.ts";
import { InMemorySessionStorage } from "../../src/harness/session/memory-storage.ts";
import { Session } from "../../src/harness/session/session.ts";
import { getOrThrow } from "../../src/harness/types.ts";
import type { AgentMessage } from "../../src/index.ts";

const registrations: Array<{ unregister(): void }> = [];

afterEach(() => {
	for (const registration of registrations.splice(0)) registration.unregister();
});

function createRuntime() {
	const streamSimple = vi.fn(globalStreamSimple);
	const completeSimple = vi.fn(globalCompleteSimple);
	return {
		runtime: { streamSimple, completeSimple } as unknown as Models,
		streamSimple,
		completeSimple,
	};
}

function messageEntry(id: string, parentId: string | null, message: AgentMessage) {
	return {
		type: "message" as const,
		id,
		parentId,
		timestamp: new Date().toISOString(),
		message,
	};
}

describe("AgentHarness Models runtime integration", () => {
	it("uses Models.streamSimple for turns and bypasses the legacy auth callback", async () => {
		const faux = registerFauxProvider();
		registrations.push(faux);
		faux.setResponses([fauxAssistantMessage("runtime response")]);
		const { runtime, streamSimple } = createRuntime();
		const legacyAuth = vi.fn(() => {
			throw new Error("legacy auth path should not run");
		});
		const model = faux.getModel();
		const harness = new AgentHarness({
			env: new NodeExecutionEnv({ cwd: process.cwd() }),
			session: new Session(new InMemorySessionStorage()),
			models: runtime,
			model,
			getApiKeyAndHeaders: legacyAuth,
		});

		const response = await harness.prompt("hello");

		expect(response.content).toEqual([{ type: "text", text: "runtime response" }]);
		expect(streamSimple).toHaveBeenCalledTimes(1);
		expect(legacyAuth).not.toHaveBeenCalled();
	});

	it("keeps harness compaction and branch navigation on the Models runtime", async () => {
		const faux = registerFauxProvider();
		registrations.push(faux);
		faux.setResponses([
			fauxAssistantMessage("## Goal\nHarness compaction"),
			fauxAssistantMessage("## Goal\nHarness branch"),
		]);
		const { runtime, completeSimple } = createRuntime();
		const legacyAuth = vi.fn(() => {
			throw new Error("legacy auth path should not run");
		});
		const session = new Session(new InMemorySessionStorage());
		const firstUserId = await session.appendMessage({
			role: "user",
			content: [{ type: "text", text: "a".repeat(100_000) }],
			timestamp: Date.now(),
		});
		await session.appendMessage(fauxAssistantMessage("old answer"));
		await session.appendMessage({
			role: "user",
			content: [{ type: "text", text: "b".repeat(160_000) }],
			timestamp: Date.now(),
		});
		await session.appendMessage(fauxAssistantMessage("recent answer"));
		const harness = new AgentHarness({
			env: new NodeExecutionEnv({ cwd: process.cwd() }),
			session,
			models: runtime,
			model: faux.getModel(),
			getApiKeyAndHeaders: legacyAuth,
		});

		const compacted = await harness.compact();
		const navigated = await harness.navigateTree(firstUserId, { summarize: true });

		expect(compacted.summary).toContain("Harness compaction");
		expect(navigated.summaryEntry?.summary).toContain("Harness branch");
		expect(completeSimple).toHaveBeenCalledTimes(2);
		expect(legacyAuth).not.toHaveBeenCalled();
	});

	it("uses the model context window when compacting small-window histories", async () => {
		const faux = registerFauxProvider({
			models: [{ id: "small-context", contextWindow: 8192, maxTokens: 2048 }],
		});
		registrations.push(faux);
		faux.setResponses([fauxAssistantMessage("## Goal\nSmall-window compaction")]);
		const { runtime, completeSimple } = createRuntime();
		const session = new Session(new InMemorySessionStorage());
		await session.appendMessage({
			role: "user",
			content: [{ type: "text", text: "u".repeat(8000) }],
			timestamp: Date.now(),
		});
		await session.appendMessage(fauxAssistantMessage("a".repeat(8000)));
		await session.appendMessage({
			role: "user",
			content: [{ type: "text", text: "v".repeat(8000) }],
			timestamp: Date.now(),
		});
		await session.appendMessage(fauxAssistantMessage("b".repeat(8000)));
		const harness = new AgentHarness({
			env: new NodeExecutionEnv({ cwd: process.cwd() }),
			session,
			models: runtime,
			model: faux.getModel("small-context")!,
		});

		const compacted = await harness.compact();

		expect(compacted.summary).toContain("Small-window compaction");
		expect(compacted.summary).not.toContain("No prior history");
		expect(completeSimple).toHaveBeenCalledTimes(1);
		expect((await session.getBranch()).at(-1)?.type).toBe("compaction");
	});

	it("routes compaction and branch summaries through Models.completeSimple", async () => {
		const faux = registerFauxProvider();
		registrations.push(faux);
		const model = faux.getModel();
		const { runtime, completeSimple } = createRuntime();
		faux.setResponses([
			fauxAssistantMessage("## Goal\nCompaction summary"),
			fauxAssistantMessage("## Goal\nBranch summary"),
			fauxAssistantMessage("## Goal\nDirect summary"),
		]);

		const preparation: CompactionPreparation = {
			firstKeptEntryId: "kept",
			messagesToSummarize: [
				{
					role: "user",
					content: [{ type: "text", text: "work to summarize" }],
					timestamp: Date.now(),
				},
			],
			turnPrefixMessages: [],
			isSplitTurn: false,
			tokensBefore: 100,
			fileOps: { read: new Set(), written: new Set(), edited: new Set() },
			settings: { enabled: true, reserveTokens: 2000, keepRecentTokens: 20 },
		};
		const compacted = getOrThrow(await compact(preparation, runtime, model));
		expect(compacted.summary).toContain("Compaction summary");

		const entries = [
			messageEntry("user", null, {
				role: "user",
				content: [{ type: "text", text: "branch work" }],
				timestamp: Date.now(),
			}),
			messageEntry("assistant", "user", fauxAssistantMessage("branch progress")),
		];
		const branch = getOrThrow(
			await generateBranchSummary(entries, {
				models: runtime,
				model,
				signal: new AbortController().signal,
			}),
		);
		expect(branch.summary).toContain("Branch summary");

		const direct = getOrThrow(
			await generateSummary(
				[
					{
						role: "user",
						content: [{ type: "text", text: "direct work" }],
						timestamp: Date.now(),
					},
				],
				runtime,
				model,
				2000,
			),
		);
		expect(direct).toContain("Direct summary");
		expect(completeSimple).toHaveBeenCalledTimes(3);
		for (const call of completeSimple.mock.calls) {
			expect(call[2]).not.toHaveProperty("apiKey");
		}
	});

	it.each([
		["length", fauxAssistantMessage("partial summary", { stopReason: "length" })],
		["no text", fauxAssistantMessage({ type: "thinking", thinking: "reasoning only" })],
	])("fails closed for a branch summary response with %s", async (_label, summaryResponse) => {
		const faux = registerFauxProvider();
		registrations.push(faux);
		faux.setResponses([summaryResponse]);
		const { runtime } = createRuntime();
		const entries = [
			messageEntry("user", null, {
				role: "user",
				content: [{ type: "text", text: "branch work" }],
				timestamp: Date.now(),
			}),
		];

		const result = await generateBranchSummary(entries, {
			models: runtime,
			model: faux.getModel(),
			signal: new AbortController().signal,
		});

		expect(result).toMatchObject({ ok: false, error: { code: "summarization_failed" } });
	});
});
