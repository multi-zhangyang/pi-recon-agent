/**
 * Proxy stream function for apps that route LLM calls through a server.
 * The server manages auth and proxies requests to LLM providers.
 */

// Internal import for JSON parsing utility
import {
	type AssistantMessage,
	type AssistantMessageEvent,
	type Context,
	EventStream,
	type Model,
	parseStreamingJson,
	type SimpleStreamOptions,
	type StopReason,
	type ToolCall,
} from "@pi-recon/repi-ai";

// Create stream class matching ProxyMessageEventStream
class ProxyMessageEventStream extends EventStream<AssistantMessageEvent, AssistantMessage> {
	constructor() {
		super(
			(event) => event.type === "done" || event.type === "error",
			(event) => {
				if (event.type === "done") return event.message;
				if (event.type === "error") return event.error;
				throw new Error("Unexpected event type");
			},
		);
	}
}

/**
 * Proxy event types - server sends these with partial field stripped to reduce bandwidth.
 */
export type ProxyAssistantMessageEvent =
	| { type: "start" }
	| { type: "text_start"; contentIndex: number }
	| { type: "text_delta"; contentIndex: number; delta: string }
	| { type: "text_end"; contentIndex: number; contentSignature?: string }
	| { type: "thinking_start"; contentIndex: number }
	| { type: "thinking_delta"; contentIndex: number; delta: string }
	| { type: "thinking_end"; contentIndex: number; contentSignature?: string }
	| { type: "toolcall_start"; contentIndex: number; id: string; toolName: string }
	| { type: "toolcall_delta"; contentIndex: number; delta: string }
	| { type: "toolcall_end"; contentIndex: number }
	| {
			type: "done";
			reason: Extract<StopReason, "stop" | "length" | "toolUse">;
			usage: AssistantMessage["usage"];
	  }
	| {
			type: "error";
			reason: Extract<StopReason, "aborted" | "error">;
			errorMessage?: string;
			usage: AssistantMessage["usage"];
	  };

type ProxySerializableStreamOptions = Pick<
	SimpleStreamOptions,
	| "temperature"
	| "maxTokens"
	| "reasoning"
	| "cacheRetention"
	| "sessionId"
	| "headers"
	| "metadata"
	| "transport"
	| "thinkingBudgets"
	| "maxRetryDelayMs"
>;

export interface ProxyStreamOptions extends ProxySerializableStreamOptions {
	/** Local abort signal for the proxy request */
	signal?: AbortSignal;
	/** Auth token for the proxy server */
	authToken: string;
	/** Proxy server URL (e.g., "https://genai.example.com") */
	proxyUrl: string;
}

/**
 * Stream function that proxies through a server instead of calling LLM providers directly.
 * The server strips the partial field from delta events to reduce bandwidth.
 * We reconstruct the partial message client-side.
 *
 * Use this as the `streamFn` option when creating an Agent that needs to go through a proxy.
 *
 * @example
 * ```typescript
 * const agent = new Agent({
 *   streamFn: (model, context, options) =>
 *     streamProxy(model, context, {
 *       ...options,
 *       authToken: await getAuthToken(),
 *       proxyUrl: "https://genai.example.com",
 *     }),
 * });
 * ```
 */
function buildProxyRequestOptions(options: ProxyStreamOptions): ProxySerializableStreamOptions {
	return {
		temperature: options.temperature,
		maxTokens: options.maxTokens,
		reasoning: options.reasoning,
		cacheRetention: options.cacheRetention,
		sessionId: options.sessionId,
		headers: options.headers,
		metadata: options.metadata,
		transport: options.transport,
		thinkingBudgets: options.thinkingBudgets,
		maxRetryDelayMs: options.maxRetryDelayMs,
	};
}

export function streamProxy(model: Model<any>, context: Context, options: ProxyStreamOptions): ProxyMessageEventStream {
	const stream = new ProxyMessageEventStream();

	(async () => {
		// Initialize the partial message that we'll build up from events
		const partial: AssistantMessage = {
			role: "assistant",
			stopReason: "stop",
			content: [],
			api: model.api,
			provider: model.provider,
			model: model.id,
			usage: {
				input: 0,
				output: 0,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 0,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			timestamp: Date.now(),
		};

		let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
		let terminated = false;

		const abortHandler = () => {
			if (reader) {
				reader.cancel("Request aborted by user").catch(() => {});
			}
		};

		if (options.signal) {
			options.signal.addEventListener("abort", abortHandler);
		}

		try {
			const response = await fetch(`${options.proxyUrl}/api/stream`, {
				method: "POST",
				headers: {
					Authorization: `Bearer ${options.authToken}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					model,
					context,
					options: buildProxyRequestOptions(options),
				}),
				signal: options.signal,
			});

			if (!response.ok) {
				let errorMessage = `Proxy error: ${response.status} ${response.statusText}`;
				try {
					const errorData = (await response.json()) as { error?: string };
					if (errorData.error) {
						errorMessage = `Proxy error: ${errorData.error}`;
					}
				} catch {
					// Couldn't parse error response
				}
				throw new Error(errorMessage);
			}

			reader = response.body!.getReader();
			const decoder = new TextDecoder();
			let buffer = "";
			// opt #254: extract per-line processing so the trailing buffer flush below
			// can reuse it. Pre-fix the for-loop was inline and the trailing partial
			// line (after the last "\n") was always dropped via lines.pop() — a
			// terminal done/error event sent WITHOUT a trailing newline was lost,
			// leaving `terminated` false and synthesizing a spurious "Proxy stream
			// ended without a done event" error.
			const processLine = (line: string): void => {
				if (!line.startsWith("data: ")) return;
				const data = line.slice(6).trim();
				if (!data) return;
				// opt #55 — guard the JSON.parse: a single malformed `data:` line
				// (truncated JSON, a non-JSON heartbeat/keep-alive payload, an encoding
				// glitch) used to throw SyntaxError here → propagated to the outer catch
				// → synthesized an error event → stream.end() → the ENTIRE proxy
				// response was lost, including all subsequent valid SSE lines and the
				// partial text already buffered (never committed). Now skip just the
				// unparseable line and continue, matching the SSE parser in
				// mcp-manager.ts:parseSseJsonMessages. processProxyEvent's own throws
				// (e.g. "Received text_delta for non-text content") are genuine
				// structural errors that SHOULD terminate the stream — left uncaught.
				let proxyEvent: ProxyAssistantMessageEvent;
				try {
					proxyEvent = JSON.parse(data) as ProxyAssistantMessageEvent;
				} catch {
					return;
				}
				const event = processProxyEvent(proxyEvent, partial);
				if (event) {
					if (event.type === "done" || event.type === "error") {
						terminated = true;
					}
					stream.push(event);
				}
			};

			while (true) {
				const { done, value } = await reader.read();
				if (done) break;

				if (options.signal?.aborted) {
					throw new Error("Request aborted by user");
				}

				buffer += decoder.decode(value, { stream: true });
				const lines = buffer.split("\n");
				buffer = lines.pop() || "";

				for (const line of lines) {
					processLine(line);
				}
			}

			// opt #254: flush the trailing buffer. SSE servers may omit the final
			// newline after the terminal event; pre-fix that line sat in `buffer`
			// (lines.pop()) and was dropped → the done/error event was lost →
			// `terminated` stayed false → a spurious "Proxy stream ended without a
			// done event" error was synthesized, discarding the real terminal event
			// and any partial text it carried. Flush the decoder's trailing bytes
			// and process the remaining line(s).
			buffer += decoder.decode();
			if (buffer) {
				for (const line of buffer.split("\n")) {
					processLine(line);
				}
			}

			if (options.signal?.aborted) {
				throw new Error("Request aborted by user");
			}

			if (!terminated) {
				// The SSE body ended cleanly but the server never sent a done/error
				// terminal event. EventStream.end() with no result argument does NOT
				// resolve finalResultPromise, so a consumer awaiting stream.result()
				// (the agent-loop) would hang forever — partial text already streamed
				// is also never committed (no message_end). Synthesize a terminal
				// error event (matching the catch-block shape) so the stream resolves
				// and the agent-loop's commit path runs.
				const reason = options.signal?.aborted ? "aborted" : "error";
				partial.stopReason = reason;
				partial.errorMessage = "Proxy stream ended without a done event";
				stream.push({ type: "error", reason, error: partial });
			}
			stream.end();
		} catch (error) {
			const errorMessage = error instanceof Error ? error.message : String(error);
			const reason = options.signal?.aborted ? "aborted" : "error";
			partial.stopReason = reason;
			partial.errorMessage = errorMessage;
			stream.push({
				type: "error",
				reason,
				error: partial,
			});
			stream.end();
		} finally {
			// Release the response body reader on every exit path. On a throw
			// before the body was fully consumed (malformed SSE JSON.parse, or
			// processProxyEvent throwing its "non-text content" errors), the
			// ReadableStreamDefaultReader kept holding the response body → undici
			// did not release the keep-alive socket until GC. cancel() is a no-op
			// on an already-done/canceled reader, so this is safe unconditionally.
			await reader?.cancel().catch(() => {});
			if (options.signal) {
				options.signal.removeEventListener("abort", abortHandler);
			}
		}
	})();

	return stream;
}

/**
 * Normalize a server-supplied `usage` object into a well-shaped Usage.
 *
 * The proxy event types declare `usage: AssistantMessage["usage"]`, but at runtime this comes from
 * `JSON.parse(data)` of an SSE line sent by an EXTERNAL proxy server — the type annotation is not
 * enforced at the boundary. A server that omits `usage`, sends a partial object (e.g. only
 * `{input, output}`), or sends wrong-typed fields would otherwise propagate undefined/NaN into the
 * AssistantMessage and downstream into the compaction trigger (`calculateContextTokens(undefined)`
 * → TypeError crash every turn at agent-session.ts:2140) and overflow detector (`input + undefined`
 * → NaN → silent overflow → lost turn). Every direct provider (anthropic/openai-completions/google/
 * bedrock) rebuilds Usage with `?? 0` / `|| 0` and recomputes totalTokens; the proxy was the lone
 * outlier that assigned the raw object verbatim. This mirrors the direct-provider contract.
 */
function normalizeProxyUsage(raw: unknown): AssistantMessage["usage"] {
	const zero = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 };
	if (!raw || typeof raw !== "object") {
		return { ...zero, totalTokens: 0, cost: { ...zero } };
	}
	const r = raw as Record<string, unknown>;
	const input = Number(r.input) || 0;
	const output = Number(r.output) || 0;
	const cacheRead = Number(r.cacheRead) || 0;
	const cacheWrite = Number(r.cacheWrite) || 0;
	const rawTotal = Number(r.totalTokens);
	const totalTokens = Number.isFinite(rawTotal) && rawTotal > 0 ? rawTotal : input + output + cacheRead + cacheWrite;
	const rc = r.cost;
	const cost =
		rc && typeof rc === "object"
			? {
					input: Number((rc as Record<string, unknown>).input) || 0,
					output: Number((rc as Record<string, unknown>).output) || 0,
					cacheRead: Number((rc as Record<string, unknown>).cacheRead) || 0,
					cacheWrite: Number((rc as Record<string, unknown>).cacheWrite) || 0,
					total: Number((rc as Record<string, unknown>).total) || 0,
				}
			: { ...zero };
	return { input, output, cacheRead, cacheWrite, totalTokens, cost };
}

/**
 * Process a proxy event and update the partial message.
 */
function processProxyEvent(
	proxyEvent: ProxyAssistantMessageEvent,
	partial: AssistantMessage,
): AssistantMessageEvent | undefined {
	switch (proxyEvent.type) {
		case "start":
			return { type: "start", partial };

		case "text_start":
			partial.content[proxyEvent.contentIndex] = { type: "text", text: "" };
			return { type: "text_start", contentIndex: proxyEvent.contentIndex, partial };

		case "text_delta": {
			const content = partial.content[proxyEvent.contentIndex];
			if (content?.type === "text") {
				content.text += proxyEvent.delta;
				return {
					type: "text_delta",
					contentIndex: proxyEvent.contentIndex,
					delta: proxyEvent.delta,
					partial,
				};
			}
			throw new Error("Received text_delta for non-text content");
		}

		case "text_end": {
			const content = partial.content[proxyEvent.contentIndex];
			if (content?.type === "text") {
				content.textSignature = proxyEvent.contentSignature;
				return {
					type: "text_end",
					contentIndex: proxyEvent.contentIndex,
					content: content.text,
					partial,
				};
			}
			throw new Error("Received text_end for non-text content");
		}

		case "thinking_start":
			partial.content[proxyEvent.contentIndex] = { type: "thinking", thinking: "" };
			return { type: "thinking_start", contentIndex: proxyEvent.contentIndex, partial };

		case "thinking_delta": {
			const content = partial.content[proxyEvent.contentIndex];
			if (content?.type === "thinking") {
				content.thinking += proxyEvent.delta;
				return {
					type: "thinking_delta",
					contentIndex: proxyEvent.contentIndex,
					delta: proxyEvent.delta,
					partial,
				};
			}
			throw new Error("Received thinking_delta for non-thinking content");
		}

		case "thinking_end": {
			const content = partial.content[proxyEvent.contentIndex];
			if (content?.type === "thinking") {
				content.thinkingSignature = proxyEvent.contentSignature;
				return {
					type: "thinking_end",
					contentIndex: proxyEvent.contentIndex,
					content: content.thinking,
					partial,
				};
			}
			throw new Error("Received thinking_end for non-thinking content");
		}

		case "toolcall_start":
			partial.content[proxyEvent.contentIndex] = {
				type: "toolCall",
				id: proxyEvent.id,
				name: proxyEvent.toolName,
				arguments: {},
				partialJson: "",
			} satisfies ToolCall & { partialJson: string } as ToolCall;
			return { type: "toolcall_start", contentIndex: proxyEvent.contentIndex, partial };

		case "toolcall_delta": {
			const content = partial.content[proxyEvent.contentIndex];
			if (content?.type === "toolCall") {
				(content as any).partialJson += proxyEvent.delta;
				content.arguments = parseStreamingJson((content as any).partialJson) || {};
				partial.content[proxyEvent.contentIndex] = { ...content }; // Trigger reactivity
				return {
					type: "toolcall_delta",
					contentIndex: proxyEvent.contentIndex,
					delta: proxyEvent.delta,
					partial,
				};
			}
			throw new Error("Received toolcall_delta for non-toolCall content");
		}

		case "toolcall_end": {
			const content = partial.content[proxyEvent.contentIndex];
			if (content?.type === "toolCall") {
				delete (content as any).partialJson;
				return {
					type: "toolcall_end",
					contentIndex: proxyEvent.contentIndex,
					toolCall: content,
					partial,
				};
			}
			return undefined;
		}

		case "done":
			partial.stopReason = proxyEvent.reason;
			partial.usage = normalizeProxyUsage(proxyEvent.usage);
			return { type: "done", reason: proxyEvent.reason, message: partial };

		case "error":
			partial.stopReason = proxyEvent.reason;
			partial.errorMessage = proxyEvent.errorMessage;
			partial.usage = normalizeProxyUsage(proxyEvent.usage);
			return { type: "error", reason: proxyEvent.reason, error: partial };

		default: {
			const _exhaustiveCheck: never = proxyEvent;
			console.warn(`Unhandled proxy event type: ${(proxyEvent as any).type}`);
			return undefined;
		}
	}
}
