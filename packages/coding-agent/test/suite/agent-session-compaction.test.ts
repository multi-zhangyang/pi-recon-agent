import {
	type AssistantMessage,
	createAssistantMessageEventStream,
	fauxAssistantMessage,
	fauxToolCall,
	type Model,
} from "@pi-recon/repi-ai";
import { Type } from "typebox";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createReconExtensionFactory } from "../../src/core/recon-profile.ts";
import { createHarness, getMessageText, type Harness } from "./harness.ts";

type SessionWithCompactionInternals = {
	_compactionRuntime: {
		checkCompaction: (assistantMessage: AssistantMessage, skipAbortedCheck?: boolean) => Promise<boolean>;
		runAutoCompaction: (reason: "overflow" | "threshold", willRetry: boolean) => Promise<boolean>;
	};
};

function createUsage(totalTokens: number) {
	return {
		input: totalTokens,
		output: 0,
		cacheRead: 0,
		cacheWrite: 0,
		totalTokens,
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
	};
}

function createAssistant(
	harness: Harness,
	options: {
		text?: string;
		stopReason?: AssistantMessage["stopReason"];
		errorMessage?: string;
		totalTokens?: number;
		timestamp?: number;
	},
): AssistantMessage {
	const model = harness.getModel();
	return {
		...fauxAssistantMessage(options.text ?? "", {
			stopReason: options.stopReason,
			errorMessage: options.errorMessage,
			timestamp: options.timestamp,
		}),
		api: model.api,
		provider: model.provider,
		model: model.id,
		usage: createUsage(options.totalTokens ?? 0),
	};
}

function useSummaryStreamFn(harness: Harness, summary: string): () => number {
	let callCount = 0;
	harness.session.agent.streamFn = (model) => {
		callCount++;
		const stream = createAssistantMessageEventStream();
		queueMicrotask(() => {
			const message: AssistantMessage = {
				...fauxAssistantMessage(summary),
				api: model.api,
				provider: model.provider,
				model: model.id,
				usage: createUsage(10),
			};
			stream.push({ type: "done", reason: "stop", message });
		});
		return stream;
	};
	return () => callCount;
}

function seedCompactableSession(harness: Harness): void {
	const now = Date.now();
	harness.sessionManager.appendMessage({
		role: "user",
		content: [{ type: "text", text: "message to compact" }],
		timestamp: now - 1000,
	});
	harness.sessionManager.appendMessage(
		createAssistant(harness, {
			text: "assistant message to compact ".repeat(200),
			stopReason: "stop",
			totalTokens: 100,
			timestamp: now - 500,
		}),
	);
	harness.sessionManager.appendMessage({
		role: "user",
		content: [{ type: "text", text: "recent request to keep" }],
		timestamp: now,
	});
	harness.session.agent.state.messages = harness.sessionManager.buildSessionContext().messages;
}

describe("AgentSession compaction characterization", () => {
	const harnesses: Harness[] = [];

	afterEach(() => {
		vi.useRealTimers();
		vi.restoreAllMocks();
		while (harnesses.length > 0) {
			harnesses.pop()?.cleanup();
		}
	});

	it("manually compacts using an extension-provided summary", async () => {
		const harness = await createHarness({
			settings: { compaction: { keepRecentTokens: 1 } },
			extensionFactories: [
				(pi) => {
					pi.on("session_before_compact", async (event) => ({
						compaction: {
							summary: "summary from extension",
							firstKeptEntryId: event.preparation.firstKeptEntryId,
							tokensBefore: event.preparation.tokensBefore,
							details: { source: "extension" },
						},
					}));
				},
			],
		});
		harnesses.push(harness);

		seedCompactableSession(harness);

		const result = await harness.session.compact();
		const compactionEntries = harness.sessionManager.getEntries().filter((entry) => entry.type === "compaction");

		expect(result.summary).toBe("summary from extension");
		expect(compactionEntries).toHaveLength(1);
		expect(harness.session.messages[0]?.role).toBe("compactionSummary");
	});

	it("rejects a compaction that would grow the estimated context", async () => {
		const harness = await createHarness({
			settings: { compaction: { keepRecentTokens: 1 } },
			extensionFactories: [
				(pi) => {
					pi.on("session_before_compact", async (event) => ({
						compaction: {
							summary: "oversized summary ".repeat(1_000),
							firstKeptEntryId: event.preparation.firstKeptEntryId,
							tokensBefore: event.preparation.tokensBefore,
						},
					}));
				},
			],
		});
		harnesses.push(harness);
		seedCompactableSession(harness);

		await expect(harness.session.compact()).rejects.toThrow("Compaction did not reduce estimated context");
		expect(harness.sessionManager.getEntries().some((entry) => entry.type === "compaction")).toBe(false);
	});

	it("does not auto-compact generic 400 no-body provider errors", async () => {
		const harness = await createHarness({
			extensionFactories: [createReconExtensionFactory()],
		});
		harnesses.push(harness);
		harness.setResponses([
			fauxAssistantMessage("", {
				stopReason: "error",
				errorMessage: "400 status code (no body)",
			}),
		]);

		await harness.session.prompt("1");

		expect(harness.sessionManager.getEntries().some((entry) => entry.type === "compaction")).toBe(false);
		expect(
			harness.sessionManager
				.getEntries()
				.some((entry) => entry.type === "custom" && entry.customType === "repi-compaction-auto-resume"),
		).toBe(false);
	});

	it("does not auto-compact tiny no-history overflow-like errors", async () => {
		const harness = await createHarness({
			extensionFactories: [createReconExtensionFactory()],
		});
		harnesses.push(harness);
		harness.setResponses([
			fauxAssistantMessage("", {
				stopReason: "error",
				errorMessage: "413 status code (no body)",
			}),
		]);

		await harness.session.prompt("1");

		expect(harness.sessionManager.getEntries().some((entry) => entry.type === "compaction")).toBe(false);
		expect(harness.eventsOfType("compaction_end").at(-1)).toMatchObject({
			reason: "overflow",
			result: undefined,
			aborted: false,
		});
	});

	it("throws when compacting without a model", async () => {
		const harness = await createHarness();
		harnesses.push(harness);
		harness.session.agent.state.model = undefined as unknown as Model<any>;

		await expect(harness.session.compact()).rejects.toThrow("No model selected");
	});

	it("throws when compacting without configured auth", async () => {
		const harness = await createHarness({ withConfiguredAuth: false });
		harnesses.push(harness);

		await expect(harness.session.compact()).rejects.toThrow(`No API key found for ${harness.getModel().provider}.`);
	});

	it("manually compacts with a custom streamFn when registry auth is absent", async () => {
		const harness = await createHarness({
			withConfiguredAuth: false,
			settings: { compaction: { keepRecentTokens: 1 } },
		});
		harnesses.push(harness);
		seedCompactableSession(harness);
		const getStreamCallCount = useSummaryStreamFn(harness, "summary from custom stream");

		const result = await harness.session.compact();

		expect(result.summary).toContain("summary from custom stream");
		expect(getStreamCallCount()).toBe(1);
	});

	it("auto-compacts with a custom streamFn when registry auth is absent", async () => {
		const harness = await createHarness({
			withConfiguredAuth: false,
			settings: { compaction: { keepRecentTokens: 1 } },
		});
		harnesses.push(harness);
		seedCompactableSession(harness);
		const getStreamCallCount = useSummaryStreamFn(harness, "auto summary from custom stream");
		const sessionInternals = harness.session as unknown as SessionWithCompactionInternals;

		await sessionInternals._compactionRuntime.runAutoCompaction("threshold", false);

		const compactionEntries = harness.sessionManager.getEntries().filter((entry) => entry.type === "compaction");
		expect(compactionEntries).toHaveLength(1);
		expect(getStreamCallCount()).toBe(1);
	});

	it("cancels in-progress manual compaction when abortCompaction is called", async () => {
		const harness = await createHarness({
			settings: { compaction: { keepRecentTokens: 1 } },
			extensionFactories: [
				(pi) => {
					pi.on("session_before_compact", async (event) => {
						return await new Promise<{ cancel: true }>((resolve) => {
							event.signal.addEventListener("abort", () => resolve({ cancel: true }), { once: true });
						});
					});
				},
			],
		});
		harnesses.push(harness);

		seedCompactableSession(harness);

		const compactPromise = harness.session.compact();
		await new Promise((resolve) => setTimeout(resolve, 0));
		harness.session.abortCompaction();

		await expect(compactPromise).rejects.toThrow("Compaction cancelled");
	});

	it("resumes after threshold compaction when only agent-level queued messages exist", async () => {
		vi.useFakeTimers();
		const harness = await createHarness({
			settings: { compaction: { keepRecentTokens: 1 } },
			extensionFactories: [
				(pi) => {
					pi.on("session_before_compact", async (event) => ({
						compaction: {
							summary: "auto compacted",
							firstKeptEntryId: event.preparation.firstKeptEntryId,
							tokensBefore: event.preparation.tokensBefore,
							details: {},
						},
					}));
				},
			],
		});
		harnesses.push(harness);
		harness.setResponses([fauxAssistantMessage("one"), fauxAssistantMessage("two")]);
		await harness.session.prompt("first");
		await harness.session.prompt("second");

		harness.session.agent.followUp({
			role: "custom",
			customType: "test",
			content: [{ type: "text", text: "queued custom" }],
			display: false,
			timestamp: Date.now(),
		});

		const sessionInternals = harness.session as unknown as SessionWithCompactionInternals;

		await expect(sessionInternals._compactionRuntime.runAutoCompaction("threshold", false)).resolves.toBe(true);
	});

	it("compacts at turn boundary before the next autonomous tool-loop LLM call", async () => {
		const toolCalls: string[] = [];
		const harness = await createHarness({
			models: [{ id: "faux-1", contextWindow: 10_000 }],
			settings: { compaction: { keepRecentTokens: 1, triggerPercent: 50 } },
			tools: [
				{
					name: "echo",
					label: "Echo",
					description: "Echo a value",
					parameters: Type.Object({ value: Type.String() }),
					execute: async (_toolCallId, params) => {
						const value =
							typeof params === "object" && params !== null && "value" in params ? String(params.value) : "";
						toolCalls.push(value);
						return {
							content: [{ type: "text", text: `echo:${value}` }],
							details: {},
						};
					},
				},
			],
			initialActiveToolNames: ["echo"],
			extensionFactories: [
				(pi) => {
					pi.on("session_before_compact", async (event) => ({
						compaction: {
							summary: "turn boundary compacted",
							firstKeptEntryId: event.preparation.firstKeptEntryId,
							tokensBefore: event.preparation.tokensBefore,
							details: {},
						},
					}));
				},
			],
		});
		harnesses.push(harness);

		const model = harness.getModel();
		const responses: AssistantMessage[] = [
			{
				...fauxAssistantMessage([fauxToolCall("echo", { value: "one" })], {
					stopReason: "toolUse",
					timestamp: Date.now(),
				}),
				api: model.api,
				provider: model.provider,
				model: model.id,
				usage: createUsage(6_000),
			},
			{
				...fauxAssistantMessage("after compact continue", { timestamp: Date.now() + 1 }),
				api: model.api,
				provider: model.provider,
				model: model.id,
				usage: createUsage(10),
			},
		];
		let streamCalls = 0;
		harness.session.agent.streamFn = (requestModel) => {
			const stream = createAssistantMessageEventStream();
			const message = responses[streamCalls++];
			queueMicrotask(() => {
				if (!message) {
					const error = createAssistant(harness, { stopReason: "error", errorMessage: "unexpected stream call" });
					stream.push({ type: "error", reason: "error", error });
					stream.end(error);
					return;
				}
				const finalMessage = { ...message, model: requestModel.id };
				const reason =
					finalMessage.stopReason === "length" || finalMessage.stopReason === "toolUse"
						? finalMessage.stopReason
						: "stop";
				stream.push({ type: "done", reason, message: finalMessage });
				stream.end(finalMessage);
			});
			return stream;
		};
		seedCompactableSession(harness);

		await harness.session.prompt("start autonomous work ".repeat(1_000));

		expect(toolCalls).toEqual(["one"]);
		expect(streamCalls).toBe(2);
		expect(harness.sessionManager.getEntries().some((entry) => entry.type === "compaction")).toBe(true);
		expect(harness.eventsOfType("compaction_start").some((event) => event.reason === "threshold")).toBe(true);
		expect(harness.session.messages.some((message) => getMessageText(message) === "after compact continue")).toBe(
			true,
		);
	});

	it("keeps a turn-boundary tool loop running when threshold compaction has no summarizable history", async () => {
		const toolCalls: string[] = [];
		const harness = await createHarness({
			models: [{ id: "faux-1", contextWindow: 10_000 }],
			settings: { compaction: { keepRecentTokens: 10_000, triggerPercent: 50 } },
			tools: [
				{
					name: "echo",
					label: "Echo",
					description: "Echo a value",
					parameters: Type.Object({ value: Type.String() }),
					execute: async (_toolCallId, params) => {
						const value =
							typeof params === "object" && params !== null && "value" in params ? String(params.value) : "";
						toolCalls.push(value);
						return { content: [{ type: "text", text: `echo:${value}` }], details: {} };
					},
				},
			],
			initialActiveToolNames: ["echo"],
		});
		harnesses.push(harness);

		const model = harness.getModel();
		const responses: AssistantMessage[] = [
			{
				...fauxAssistantMessage([fauxToolCall("echo", { value: "one" })], { stopReason: "toolUse" }),
				api: model.api,
				provider: model.provider,
				model: model.id,
				usage: createUsage(6_000),
			},
			{
				...fauxAssistantMessage("continued after compact no-op"),
				api: model.api,
				provider: model.provider,
				model: model.id,
				usage: createUsage(10),
			},
		];
		let streamCalls = 0;
		harness.session.agent.streamFn = (requestModel) => {
			const stream = createAssistantMessageEventStream();
			const message = responses[streamCalls++];
			queueMicrotask(() => {
				if (!message) {
					const error = createAssistant(harness, { stopReason: "error", errorMessage: "unexpected stream call" });
					stream.push({ type: "error", reason: "error", error });
					stream.end(error);
					return;
				}
				const finalMessage = { ...message, model: requestModel.id };
				stream.push({
					type: "done",
					reason: finalMessage.stopReason === "toolUse" ? "toolUse" : "stop",
					message: finalMessage,
				});
				stream.end(finalMessage);
			});
			return stream;
		};

		await harness.session.prompt("run one tool then finish");

		expect(toolCalls).toEqual(["one"]);
		expect(streamCalls).toBe(2);
		expect(harness.sessionManager.getEntries().some((entry) => entry.type === "compaction")).toBe(false);
		expect(harness.eventsOfType("compaction_start")).toHaveLength(0);
		expect(
			harness.session.messages.some((message) => getMessageText(message) === "continued after compact no-op"),
		).toBe(true);
	});

	it("does not reset maxTurns when threshold compaction has no summarizable history", async () => {
		const toolCalls: string[] = [];
		const harness = await createHarness({
			models: [{ id: "faux-1", contextWindow: 10_000 }],
			settings: { compaction: { keepRecentTokens: 10_000, triggerPercent: 50 } },
			tools: [
				{
					name: "echo",
					label: "Echo",
					description: "Echo a value",
					parameters: Type.Object({ value: Type.String() }),
					execute: async (_toolCallId, params) => {
						const value =
							typeof params === "object" && params !== null && "value" in params ? String(params.value) : "";
						toolCalls.push(value);
						return { content: [{ type: "text", text: `echo:${value}` }], details: {} };
					},
				},
			],
			initialActiveToolNames: ["echo"],
		});
		harnesses.push(harness);
		harness.session.agent.maxTurns = 2;

		const model = harness.getModel();
		const responses: AssistantMessage[] = ["one", "two", "three"].map((value) => ({
			...fauxAssistantMessage([fauxToolCall("echo", { value })], { stopReason: "toolUse" }),
			api: model.api,
			provider: model.provider,
			model: model.id,
			usage: createUsage(6_000),
		}));
		let streamCalls = 0;
		harness.session.agent.streamFn = (requestModel) => {
			const stream = createAssistantMessageEventStream();
			const message = responses[streamCalls++];
			queueMicrotask(() => {
				if (!message) {
					const error = createAssistant(harness, { stopReason: "error", errorMessage: "unexpected stream call" });
					stream.push({ type: "error", reason: "error", error });
					stream.end(error);
					return;
				}
				const finalMessage = { ...message, model: requestModel.id };
				stream.push({ type: "done", reason: "toolUse", message: finalMessage });
				stream.end(finalMessage);
			});
			return stream;
		};

		await harness.session.prompt("respect the turn budget");

		expect(toolCalls).toEqual(["one", "two"]);
		expect(streamCalls).toBe(2);
		expect(harness.sessionManager.getEntries().some((entry) => entry.type === "compaction")).toBe(false);
	});

	it("preserves maxTurns across real turn-boundary compaction continuations", async () => {
		const toolCalls: string[] = [];
		const harness = await createHarness({
			models: [{ id: "faux-1", contextWindow: 10_000 }],
			settings: { compaction: { keepRecentTokens: 1, triggerPercent: 50 } },
			tools: [
				{
					name: "echo",
					label: "Echo",
					description: "Echo a value",
					parameters: Type.Object({ value: Type.String() }),
					execute: async (_toolCallId, params) => {
						const value =
							typeof params === "object" && params !== null && "value" in params ? String(params.value) : "";
						toolCalls.push(value);
						return { content: [{ type: "text", text: `echo:${value}` }], details: {} };
					},
				},
			],
			initialActiveToolNames: ["echo"],
			extensionFactories: [
				(pi) => {
					pi.on("session_before_compact", async (event) => ({
						compaction: {
							summary: "bounded turn compacted",
							firstKeptEntryId: event.preparation.firstKeptEntryId,
							tokensBefore: event.preparation.tokensBefore,
							details: {},
						},
					}));
				},
			],
		});
		harnesses.push(harness);
		harness.session.agent.maxTurns = 2;

		const model = harness.getModel();
		const responses: AssistantMessage[] = ["one", "two"].map((value) => ({
			...fauxAssistantMessage([fauxToolCall("echo", { value })], { stopReason: "toolUse" }),
			api: model.api,
			provider: model.provider,
			model: model.id,
			usage: createUsage(6_000),
		}));
		responses.push({
			...fauxAssistantMessage("third turn must not run"),
			api: model.api,
			provider: model.provider,
			model: model.id,
			usage: createUsage(10),
		});
		let streamCalls = 0;
		harness.session.agent.streamFn = (requestModel) => {
			const stream = createAssistantMessageEventStream();
			const message = responses[streamCalls++];
			queueMicrotask(() => {
				if (!message) {
					const error = createAssistant(harness, { stopReason: "error", errorMessage: "unexpected stream call" });
					stream.push({ type: "error", reason: "error", error });
					stream.end(error);
					return;
				}
				const finalMessage = { ...message, model: requestModel.id };
				stream.push({
					type: "done",
					reason: finalMessage.stopReason === "toolUse" ? "toolUse" : "stop",
					message: finalMessage,
				});
				stream.end(finalMessage);
			});
			return stream;
		};
		seedCompactableSession(harness);

		await harness.session.prompt("compact without resetting the prompt budget");

		expect(toolCalls).toEqual(["one", "two"]);
		expect(streamCalls).toBe(2);
		expect(harness.sessionManager.getEntries().filter((entry) => entry.type === "compaction").length).toBeGreaterThan(
			0,
		);
		expect(harness.session.messages.some((message) => getMessageText(message) === "third turn must not run")).toBe(
			false,
		);
	});

	it("does not retry overflow recovery more than once", async () => {
		const harness = await createHarness();
		harnesses.push(harness);
		const sessionInternals = harness.session as unknown as SessionWithCompactionInternals;
		const overflowMessage = createAssistant(harness, {
			stopReason: "error",
			errorMessage: "prompt is too long",
			timestamp: Date.now(),
		});
		const runAutoCompactionSpy = vi
			.spyOn(sessionInternals._compactionRuntime, "runAutoCompaction")
			.mockResolvedValue(false);
		const compactionErrors: string[] = [];
		harness.session.subscribe((event) => {
			if (event.type === "compaction_end" && event.errorMessage) {
				compactionErrors.push(event.errorMessage);
			}
		});

		await sessionInternals._compactionRuntime.checkCompaction(overflowMessage);
		await sessionInternals._compactionRuntime.checkCompaction({ ...overflowMessage, timestamp: Date.now() + 1 });

		expect(runAutoCompactionSpy).toHaveBeenCalledTimes(1);
		expect(compactionErrors).toContain(
			"Context overflow recovery failed after one compact-and-retry attempt. Try reducing context or switching to a larger-context model.",
		);
	});

	it("ignores stale pre-compaction assistant usage on pre-prompt checks", async () => {
		const harness = await createHarness();
		harnesses.push(harness);
		const sessionInternals = harness.session as unknown as SessionWithCompactionInternals;
		const staleTimestamp = Date.now() - 10_000;
		const staleAssistant = createAssistant(harness, {
			stopReason: "stop",
			totalTokens: 610_000,
			timestamp: staleTimestamp,
		});

		harness.sessionManager.appendMessage({
			role: "user",
			content: [{ type: "text", text: "before compaction" }],
			timestamp: staleTimestamp - 1000,
		});
		harness.sessionManager.appendMessage(staleAssistant);
		const firstKeptEntryId = harness.sessionManager.getEntries()[0]!.id;
		harness.sessionManager.appendCompaction(
			"summary",
			firstKeptEntryId,
			staleAssistant.usage.totalTokens,
			undefined,
			false,
		);
		harness.sessionManager.appendMessage({
			role: "user",
			content: [{ type: "text", text: "after compaction" }],
			timestamp: Date.now(),
		});

		const runAutoCompactionSpy = vi
			.spyOn(sessionInternals._compactionRuntime, "runAutoCompaction")
			.mockResolvedValue(false);

		await sessionInternals._compactionRuntime.checkCompaction(staleAssistant, false);

		expect(runAutoCompactionSpy).not.toHaveBeenCalled();
	});

	it("triggers threshold compaction for error messages using the last successful usage", async () => {
		const harness = await createHarness();
		harnesses.push(harness);
		const sessionInternals = harness.session as unknown as SessionWithCompactionInternals;
		const successfulAssistant = createAssistant(harness, {
			stopReason: "stop",
			totalTokens: 190_000,
			timestamp: Date.now(),
		});
		const errorAssistant = createAssistant(harness, {
			stopReason: "error",
			errorMessage: "529 overloaded",
			timestamp: Date.now() + 1000,
		});
		harness.session.agent.state.messages = [
			{ role: "user", content: [{ type: "text", text: "hello" }], timestamp: Date.now() - 1000 },
			successfulAssistant,
			{ role: "user", content: [{ type: "text", text: "retry" }], timestamp: Date.now() + 500 },
			errorAssistant,
		];

		const runAutoCompactionSpy = vi
			.spyOn(sessionInternals._compactionRuntime, "runAutoCompaction")
			.mockResolvedValue(false);

		await sessionInternals._compactionRuntime.checkCompaction(errorAssistant);

		expect(runAutoCompactionSpy).toHaveBeenCalledWith("threshold", false);
	});

	it("does not trigger threshold compaction for error messages when no prior usage exists", async () => {
		const harness = await createHarness();
		harnesses.push(harness);
		const sessionInternals = harness.session as unknown as SessionWithCompactionInternals;
		const errorAssistant = createAssistant(harness, {
			stopReason: "error",
			errorMessage: "529 overloaded",
			timestamp: Date.now(),
		});
		harness.session.agent.state.messages = [
			{ role: "user", content: [{ type: "text", text: "hello" }], timestamp: Date.now() - 1000 },
			errorAssistant,
		];

		const runAutoCompactionSpy = vi
			.spyOn(sessionInternals._compactionRuntime, "runAutoCompaction")
			.mockResolvedValue(false);

		await sessionInternals._compactionRuntime.checkCompaction(errorAssistant);

		expect(runAutoCompactionSpy).not.toHaveBeenCalled();
	});

	it("does not trigger threshold compaction when only kept pre-compaction usage exists", async () => {
		const harness = await createHarness();
		harnesses.push(harness);
		const sessionInternals = harness.session as unknown as SessionWithCompactionInternals;
		const preCompactionTimestamp = Date.now() - 10_000;
		const keptAssistant = createAssistant(harness, {
			stopReason: "stop",
			totalTokens: 190_000,
			timestamp: preCompactionTimestamp,
		});

		harness.sessionManager.appendMessage({
			role: "user",
			content: [{ type: "text", text: "before compaction" }],
			timestamp: preCompactionTimestamp - 1000,
		});
		harness.sessionManager.appendMessage(keptAssistant);
		const firstKeptEntryId = harness.sessionManager.getEntries()[0]!.id;
		harness.sessionManager.appendCompaction(
			"summary",
			firstKeptEntryId,
			keptAssistant.usage.totalTokens,
			undefined,
			false,
		);

		const errorAssistant = createAssistant(harness, {
			stopReason: "error",
			errorMessage: "529 overloaded",
			timestamp: Date.now(),
		});
		harness.session.agent.state.messages = [
			{ role: "user", content: [{ type: "text", text: "kept user" }], timestamp: preCompactionTimestamp - 1000 },
			keptAssistant,
			{ role: "user", content: [{ type: "text", text: "new prompt" }], timestamp: Date.now() - 500 },
			errorAssistant,
		];

		const runAutoCompactionSpy = vi
			.spyOn(sessionInternals._compactionRuntime, "runAutoCompaction")
			.mockResolvedValue(false);

		await sessionInternals._compactionRuntime.checkCompaction(errorAssistant);

		expect(runAutoCompactionSpy).not.toHaveBeenCalled();
	});

	it("does not trigger threshold compaction below the threshold or when disabled", async () => {
		const belowThresholdHarness = await createHarness({
			settings: { compaction: { enabled: true, reserveTokens: 1000 } },
			models: [{ id: "faux-1", contextWindow: 200_000 }],
		});
		harnesses.push(belowThresholdHarness);
		const disabledHarness = await createHarness({ settings: { compaction: { enabled: false } } });
		harnesses.push(disabledHarness);

		const belowThresholdInternals = belowThresholdHarness.session as unknown as SessionWithCompactionInternals;
		const disabledInternals = disabledHarness.session as unknown as SessionWithCompactionInternals;
		const belowThresholdSpy = vi
			.spyOn(belowThresholdInternals._compactionRuntime, "runAutoCompaction")
			.mockResolvedValue(false);
		const disabledSpy = vi.spyOn(disabledInternals._compactionRuntime, "runAutoCompaction").mockResolvedValue(false);

		await belowThresholdInternals._compactionRuntime.checkCompaction(
			createAssistant(belowThresholdHarness, { stopReason: "stop", totalTokens: 1_000, timestamp: Date.now() }),
		);
		await disabledInternals._compactionRuntime.checkCompaction(
			createAssistant(disabledHarness, { stopReason: "stop", totalTokens: 1_000_000, timestamp: Date.now() }),
		);

		expect(belowThresholdSpy).not.toHaveBeenCalled();
		expect(disabledSpy).not.toHaveBeenCalled();
	});
});
