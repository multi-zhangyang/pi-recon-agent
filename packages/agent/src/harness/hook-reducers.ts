import type {
	AgentHarnessStreamOptions,
	AgentHarnessStreamOptionsPatch,
	BeforeAgentStartEvent,
	BeforeAgentStartResult,
	BeforeProviderPayloadEvent,
	BeforeProviderPayloadResult,
	BeforeProviderRequestEvent,
	BeforeProviderRequestResult,
	ContextEvent,
	ContextResult,
	SessionBeforeCompactEvent,
	SessionBeforeCompactResult,
	SessionBeforeTreeEvent,
	SessionBeforeTreeResult,
	ToolCallEvent,
	ToolCallResult,
	ToolResultEvent,
	ToolResultPatch,
} from "./types.ts";

/** Runtime shape shared by hook registrations; public registration remains typed on AgentHarness. */
export type HarnessHookHandler = (event: any, signal?: AbortSignal) => Promise<any> | any;

const MAX_CONTEXT_HOOK_GROWTH_CHARS = 32_000;
const MAX_CONTEXT_HOOK_ADDED_MESSAGES = 32;

function estimateContextValue(value: unknown, seen = new WeakSet<object>(), limit = 100_000_000): number {
	if (typeof value === "string") return Math.min(value.length, limit);
	if (value === null || value === undefined || typeof value === "boolean" || typeof value === "number") return 8;
	if (typeof value !== "object") return 16;
	if (seen.has(value)) return 0;
	seen.add(value);
	let total = 0;
	if (Array.isArray(value)) {
		for (const item of value) {
			total += estimateContextValue(item, seen, Math.max(0, limit - total));
			if (total >= limit) return limit;
		}
		return total;
	}
	for (const [key, item] of Object.entries(value)) {
		if (key === "details" || key === "timestamp" || key === "display") continue;
		total += key.length + estimateContextValue(item, seen, Math.max(0, limit - total));
		if (total >= limit) return limit;
	}
	return total;
}

function estimateContextMessages(messages: ContextEvent["messages"]): number {
	let total = 0;
	for (const message of messages) {
		total += estimateContextValue(message);
		if (total >= 100_000_000) return 100_000_000;
	}
	return total;
}

function abortError(reason: unknown): Error {
	if (reason instanceof Error) return reason;
	const error = new Error(typeof reason === "string" && reason ? reason : "Agent harness hook aborted");
	error.name = "AbortError";
	return error;
}

export function throwIfAborted(signal?: AbortSignal): void {
	if (signal?.aborted) throw abortError(signal.reason);
}

/**
 * Let cancellation end the runner's wait even when an extension hook ignores
 * its signal. The late settlement remains observed by this race, avoiding an
 * unhandled rejection after the run has moved on.
 */
export async function awaitWithAbort<T>(operation: PromiseLike<T>, signal?: AbortSignal): Promise<T> {
	throwIfAborted(signal);
	if (!signal) return await operation;
	return await new Promise<T>((resolve, reject) => {
		let settled = false;
		const finish = (callback: () => void): void => {
			if (settled) return;
			settled = true;
			signal.removeEventListener("abort", onAbort);
			callback();
		};
		const onAbort = () => finish(() => reject(abortError(signal.reason)));
		signal.addEventListener("abort", onAbort, { once: true });
		// Abort can race between the initial check and listener registration.
		if (signal.aborted) {
			onAbort();
			return;
		}
		Promise.resolve(operation).then(
			(value) => finish(() => resolve(value)),
			(error) => finish(() => reject(error)),
		);
	});
}

async function invokeHook<TEvent, TResult>(
	handler: HarnessHookHandler,
	event: TEvent,
	signal?: AbortSignal,
): Promise<TResult> {
	throwIfAborted(signal);
	const result = await awaitWithAbort(
		Promise.resolve().then(() => {
			throwIfAborted(signal);
			return handler(event, signal);
		}),
		signal,
	);
	throwIfAborted(signal);
	return result as TResult;
}

export function cloneHarnessStreamOptions(streamOptions?: AgentHarnessStreamOptions): AgentHarnessStreamOptions {
	return {
		...streamOptions,
		headers: streamOptions?.headers ? { ...streamOptions.headers } : undefined,
		metadata: streamOptions?.metadata ? { ...streamOptions.metadata } : undefined,
	};
}

export function applyHarnessStreamOptionsPatch(
	base: AgentHarnessStreamOptions,
	patch?: AgentHarnessStreamOptionsPatch,
): AgentHarnessStreamOptions {
	const result = cloneHarnessStreamOptions(base);
	if (!patch) return result;

	if (Object.hasOwn(patch, "transport")) result.transport = patch.transport;
	if (Object.hasOwn(patch, "timeoutMs")) result.timeoutMs = patch.timeoutMs;
	if (Object.hasOwn(patch, "maxRetries")) result.maxRetries = patch.maxRetries;
	if (Object.hasOwn(patch, "maxRetryDelayMs")) result.maxRetryDelayMs = patch.maxRetryDelayMs;
	if (Object.hasOwn(patch, "cacheRetention")) result.cacheRetention = patch.cacheRetention;

	if (Object.hasOwn(patch, "headers")) {
		if (patch.headers === undefined) {
			result.headers = undefined;
		} else {
			const headers = { ...(result.headers ?? {}) };
			for (const [key, value] of Object.entries(patch.headers)) {
				if (value === undefined) delete headers[key];
				else headers[key] = value;
			}
			result.headers = Object.keys(headers).length > 0 ? headers : undefined;
		}
	}

	if (Object.hasOwn(patch, "metadata")) {
		if (patch.metadata === undefined) {
			result.metadata = undefined;
		} else {
			const metadata = { ...(result.metadata ?? {}) };
			for (const [key, value] of Object.entries(patch.metadata)) {
				if (value === undefined) delete metadata[key];
				else metadata[key] = value;
			}
			result.metadata = Object.keys(metadata).length > 0 ? metadata : undefined;
		}
	}

	return result;
}

export async function reduceContextHooks(
	handlers: readonly HarnessHookHandler[],
	event: ContextEvent,
	signal?: AbortSignal,
): Promise<ContextResult | undefined> {
	let current = event;
	let changed = false;
	for (const handler of handlers) {
		const previousChars = estimateContextMessages(current.messages);
		const previousCount = current.messages.length;
		const result = await invokeHook<ContextEvent, ContextResult | undefined>(
			handler,
			{ ...current, messages: structuredClone(current.messages) },
			signal,
		);
		if (result?.messages) {
			const candidateChars = estimateContextMessages(result.messages);
			if (
				candidateChars > previousChars + MAX_CONTEXT_HOOK_GROWTH_CHARS ||
				Math.max(0, result.messages.length - previousCount) > MAX_CONTEXT_HOOK_ADDED_MESSAGES
			) {
				continue;
			}
			current = { ...current, messages: result.messages };
			changed = true;
		}
	}
	return changed ? { messages: current.messages } : undefined;
}

export async function reduceBeforeAgentStartHooks(
	handlers: readonly HarnessHookHandler[],
	event: BeforeAgentStartEvent,
	signal?: AbortSignal,
): Promise<BeforeAgentStartResult | undefined> {
	let systemPrompt = event.systemPrompt;
	const messages = [] as NonNullable<BeforeAgentStartResult["messages"]>;
	for (const handler of handlers) {
		const result = await invokeHook<BeforeAgentStartEvent, BeforeAgentStartResult | undefined>(
			handler,
			{ ...event, systemPrompt },
			signal,
		);
		if (result?.messages) messages.push(...result.messages);
		if (result?.systemPrompt !== undefined) systemPrompt = result.systemPrompt;
	}
	return messages.length > 0 || systemPrompt !== event.systemPrompt ? { messages, systemPrompt } : undefined;
}

export async function reduceToolCallHooks(
	handlers: readonly HarnessHookHandler[],
	event: ToolCallEvent,
	signal?: AbortSignal,
): Promise<ToolCallResult | undefined> {
	for (const handler of handlers) {
		const result = await invokeHook<ToolCallEvent, ToolCallResult | undefined>(handler, event, signal);
		if (result?.block === true) return { block: true, reason: result.reason };
	}
	return undefined;
}

export async function reduceToolResultHooks(
	handlers: readonly HarnessHookHandler[],
	event: ToolResultEvent,
	signal?: AbortSignal,
): Promise<ToolResultPatch | undefined> {
	const cloneContent = (content: ToolResultEvent["content"]): ToolResultEvent["content"] =>
		content.map((part) => ({ ...part }));
	// Tool-result hooks are allowed to mutate their event for convenience. Keep
	// that mutation out of the executor's result object and durable transcript.
	let current: ToolResultEvent = { ...event, content: cloneContent(event.content) };
	let changed = false;
	for (const handler of handlers) {
		const result = await invokeHook<ToolResultEvent, ToolResultPatch | undefined>(handler, current, signal);
		if (!result) continue;
		const hasContent = Object.hasOwn(result, "content") && result.content !== undefined;
		const hasDetails = Object.hasOwn(result, "details");
		const hasError = Object.hasOwn(result, "isError") && result.isError !== undefined;
		const hasTerminate = Object.hasOwn(result, "terminate") && result.terminate !== undefined;
		if (!hasContent && !hasDetails && !hasError && !hasTerminate) continue;
		current = {
			...current,
			...(hasContent ? { content: cloneContent(result.content!) } : {}),
			...(hasDetails ? { details: result.details } : {}),
			...(hasError ? { isError: result.isError! } : {}),
			...(hasTerminate ? { terminate: result.terminate } : {}),
		};
		changed = true;
	}
	if (!changed) return undefined;
	return {
		content: current.content,
		details: current.details,
		isError: current.isError,
		...(current.terminate !== undefined ? { terminate: current.terminate } : {}),
	};
}

export async function reduceBeforeProviderRequestHooks(
	handlers: readonly HarnessHookHandler[],
	event: BeforeProviderRequestEvent,
	signal?: AbortSignal,
): Promise<AgentHarnessStreamOptions> {
	let current = { ...event, streamOptions: cloneHarnessStreamOptions(event.streamOptions) };
	for (const handler of handlers) {
		const result = await invokeHook<BeforeProviderRequestEvent, BeforeProviderRequestResult | undefined>(
			handler,
			{ ...current, streamOptions: cloneHarnessStreamOptions(current.streamOptions) },
			signal,
		);
		if (result?.streamOptions) {
			current = {
				...current,
				streamOptions: applyHarnessStreamOptionsPatch(current.streamOptions, result.streamOptions),
			};
		}
	}
	return current.streamOptions;
}

export async function reduceBeforeProviderPayloadHooks(
	handlers: readonly HarnessHookHandler[],
	event: BeforeProviderPayloadEvent,
	signal?: AbortSignal,
): Promise<unknown> {
	let current = event;
	for (const handler of handlers) {
		const result = await invokeHook<BeforeProviderPayloadEvent, BeforeProviderPayloadResult | undefined>(
			handler,
			current,
			signal,
		);
		if (result !== undefined) current = { ...current, payload: result.payload };
	}
	return current.payload;
}

export async function reduceSessionBeforeHooks(
	handlers: readonly HarnessHookHandler[],
	event: SessionBeforeCompactEvent | SessionBeforeTreeEvent,
	signal?: AbortSignal,
): Promise<SessionBeforeCompactResult | SessionBeforeTreeResult | undefined> {
	let last: SessionBeforeCompactResult | SessionBeforeTreeResult | undefined;
	for (const handler of handlers) {
		const result = await invokeHook<
			SessionBeforeCompactEvent | SessionBeforeTreeEvent,
			SessionBeforeCompactResult | SessionBeforeTreeResult | undefined
		>(handler, event, signal);
		if (!result) continue;
		last = result;
		if (result.cancel === true) return result;
	}
	return last;
}
