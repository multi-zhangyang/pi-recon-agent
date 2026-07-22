import { Agent, type AgentMessage, type ThinkingLevel } from "@pi-recon/repi-agent-core";
import { type Api, type Message, type Model, streamSimple } from "@pi-recon/repi-ai";
import type { ExtensionRunner } from "./extensions/index.ts";
import { convertToLlm } from "./messages.ts";
import type { ModelRegistry } from "./model-registry.ts";
import type { ModelRuntime } from "./model-runtime.ts";
import { mergeProviderAttributionHeaders } from "./provider-attribution.ts";
import type { SessionManager } from "./session-manager.ts";
import type { SettingsManager } from "./settings-manager.ts";

export interface SessionAgentRunPolicy {
	maxTurns?: number;
	reserveFinalTurn: boolean;
	lengthContinueMaxTurns?: number;
	streamMaxRetries?: number;
	maxToolResultChars?: number;
	maxConsumedToolResultChars?: number;
	deduplicateReadOnlyToolCalls: boolean;
}

export interface CreateSessionAgentOptions {
	model?: Model<Api>;
	thinkingLevel: ThinkingLevel;
	settingsManager: SettingsManager;
	sessionManager: SessionManager;
	modelRegistry: ModelRegistry;
	modelRuntime?: ModelRuntime;
	extensionRunnerRef: { current?: ExtensionRunner };
	runPolicy: SessionAgentRunPolicy;
}

function convertMessages(settingsManager: SettingsManager, messages: AgentMessage[]): Message[] {
	const converted = convertToLlm(messages);
	if (!settingsManager.getBlockImages()) return converted;

	return converted.map((message) => {
		if (message.role !== "user" && message.role !== "toolResult") return message;
		if (!Array.isArray(message.content) || !message.content.some((content) => content.type === "image")) {
			return message;
		}

		const content = message.content
			.map((item) => (item.type === "image" ? { type: "text" as const, text: "Image reading is disabled." } : item))
			.filter(
				(item, index, items) =>
					!(
						item.type === "text" &&
						item.text === "Image reading is disabled." &&
						index > 0 &&
						items[index - 1].type === "text" &&
						(items[index - 1] as { type: "text"; text: string }).text === "Image reading is disabled."
					),
			);
		return { ...message, content };
	});
}

/** Build the model-facing Agent without loading resources or mutating session history. */
export function createSessionAgent(options: CreateSessionAgentOptions): Agent {
	const {
		model,
		thinkingLevel,
		settingsManager,
		sessionManager,
		modelRegistry,
		modelRuntime,
		extensionRunnerRef,
		runPolicy,
	} = options;

	return new Agent({
		initialState: {
			systemPrompt: "",
			model,
			thinkingLevel,
			tools: [],
		},
		convertToLlm: (messages) => convertMessages(settingsManager, messages),
		streamFn: async (activeModel, context, streamOptions) => {
			const providerRetrySettings = settingsManager.getProviderRetrySettings();
			const httpIdleTimeoutMs = settingsManager.getHttpIdleTimeoutMs();
			const effectiveTimeoutMs = httpIdleTimeoutMs === 0 ? 2147483647 : httpIdleTimeoutMs;
			const timeoutMs = streamOptions?.timeoutMs ?? providerRetrySettings.timeoutMs ?? effectiveTimeoutMs;
			const websocketConnectTimeoutMs =
				streamOptions?.websocketConnectTimeoutMs ?? settingsManager.getWebSocketConnectTimeoutMs();
			if (modelRuntime?.getProvider(activeModel.provider)) {
				const runtimeModel = modelRuntime.getModel(activeModel.provider, activeModel.id) ?? activeModel;
				return modelRuntime.streamSimple(runtimeModel, context, {
					...streamOptions,
					timeoutMs,
					websocketConnectTimeoutMs,
					maxRetries: streamOptions?.maxRetries ?? providerRetrySettings.maxRetries,
					maxRetryDelayMs: streamOptions?.maxRetryDelayMs ?? providerRetrySettings.maxRetryDelayMs,
					transformHeaders: (headers) =>
						mergeProviderAttributionHeaders(runtimeModel, settingsManager, streamOptions?.sessionId, headers) ??
						{},
				});
			}

			const auth = await modelRegistry.getApiKeyAndHeaders(activeModel);
			if (!auth.ok) throw new Error(auth.error);
			return streamSimple(activeModel, context, {
				...streamOptions,
				apiKey: auth.apiKey,
				timeoutMs,
				websocketConnectTimeoutMs,
				maxRetries: streamOptions?.maxRetries ?? providerRetrySettings.maxRetries,
				maxRetryDelayMs: streamOptions?.maxRetryDelayMs ?? providerRetrySettings.maxRetryDelayMs,
				headers: mergeProviderAttributionHeaders(
					activeModel,
					settingsManager,
					streamOptions?.sessionId,
					auth.headers,
					streamOptions?.headers,
				),
			});
		},
		onPayload: async (payload) => {
			const runner = extensionRunnerRef.current;
			return runner?.hasHandlers("before_provider_request") ? runner.emitBeforeProviderRequest(payload) : payload;
		},
		onResponse: async (response) => {
			const runner = extensionRunnerRef.current;
			if (!runner?.hasHandlers("after_provider_response")) return;
			await runner.emit({
				type: "after_provider_response",
				status: response.status,
				headers: response.headers,
			});
		},
		sessionId: sessionManager.getSessionId(),
		transformContext: async (messages) => extensionRunnerRef.current?.emitContext(messages) ?? messages,
		steeringMode: settingsManager.getSteeringMode(),
		followUpMode: settingsManager.getFollowUpMode(),
		transport: settingsManager.getTransport(),
		thinkingBudgets: settingsManager.getThinkingBudgets(),
		maxRetryDelayMs: settingsManager.getProviderRetrySettings().maxRetryDelayMs,
		maxTurns: runPolicy.maxTurns,
		reserveFinalTurn: runPolicy.reserveFinalTurn,
		lengthContinueMaxTurns: runPolicy.lengthContinueMaxTurns,
		streamMaxRetries: runPolicy.streamMaxRetries,
		maxToolResultChars: runPolicy.maxToolResultChars,
		maxConsumedToolResultChars: runPolicy.maxConsumedToolResultChars,
		deduplicateReadOnlyToolCalls: runPolicy.deduplicateReadOnlyToolCalls,
		onRunBudgetExceeded: ({ turns, maxTurns }) => {
			process.stderr.write(`repi: reached max-turns budget (${turns}/${maxTurns}).\n`);
		},
	});
}
