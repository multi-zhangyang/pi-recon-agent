import type { Readable } from "node:stream";
import { StringDecoder } from "node:string_decoder";

/**
 * Resolve the per-line byte cap for {@link attachJsonlLineReader}.
 *
 * RPC mode stays alive forever (`return new Promise(() => {})` at rpc-mode.ts:873)
 * reading external stdin. `onData` does `buffer += chunk` and flushes only when a
 * `\n` is found — NO length cap. A peer sending a multi-GB blob with no `\n`
 * accumulates the whole thing → silent RSS growth → OOM kill. Same class as the
 * MCP stdio buffer (opt #59) but uncapped and the idle/onError swallow at :51
 * covers stream errors, not buffer growth.
 *
 * The cap is checked against `buffer.length` (UTF-16 code units, same proxy the
 * MCP_STDIO_BUFFER_MAX_CHARS doctrine uses); for ASCII/binary-ish payloads chars
 * ≈ bytes, and multi-byte text has bytes ≥ chars so a char cap is conservative
 * (triggers no later than the byte cap would). 8 MB is well above any legitimate
 * JSONL command (tool results are capped at the context boundary ~256K, opt #15)
 * and a full REPI session line. `REPI_RPC_LINE_MAX_BYTES` env overrides; 0
 * disables (legacy unbounded). opt #184.
 */
export const RPC_LINE_MAX_BYTES = (() => {
	const raw = process.env.REPI_RPC_LINE_MAX_BYTES;
	if (raw === undefined || raw === "") return 8 * 1024 * 1024;
	const n = Number(raw);
	if (!Number.isFinite(n) || n < 0) return 8 * 1024 * 1024;
	if (n === 0) return Number.POSITIVE_INFINITY;
	return Math.floor(n);
})();

/**
 * Serialize a single strict JSONL record.
 *
 * Framing is LF-only. Payload strings may contain other Unicode separators such as
 * U+2028 and U+2029. Clients must split records on `\n` only.
 */
export function serializeJsonLine(value: unknown): string {
	return `${JSON.stringify(value)}\n`;
}

/**
 * Attach an LF-only JSONL reader to a stream.
 *
 * This intentionally does not use Node readline. Readline splits on additional
 * Unicode separators that are valid inside JSON strings and therefore does not
 * implement strict JSONL framing.
 */
export function attachJsonlLineReader(stream: Readable, onLine: (line: string) => void): () => void {
	const decoder = new StringDecoder("utf8");
	let buffer = "";

	const emitLine = (line: string) => {
		onLine(line.endsWith("\r") ? line.slice(0, -1) : line);
	};

	const onData = (chunk: string | Buffer) => {
		buffer += typeof chunk === "string" ? chunk : decoder.write(chunk);

		// opt #184: bound the un-flushed buffer. A peer streaming a multi-GB blob
		// with no `\n` would otherwise accumulate the whole thing → OOM. Reset and
		// emit a synthetic framing-error marker line so the consumer/peer learns
		// the line was dropped rather than silent truncation. The marker is valid
		// JSON; handleInputLine parses it and routes the unknown type through its
		// existing error path (an `error` output to the peer).
		if (RPC_LINE_MAX_BYTES !== Number.POSITIVE_INFINITY && buffer.length > RPC_LINE_MAX_BYTES) {
			const droppedBytes = buffer.length;
			buffer = "";
			emitLine(
				JSON.stringify({
					jsonlFramingError: true,
					reason: "line exceeded REPI_RPC_LINE_MAX_BYTES",
					maxBytes: RPC_LINE_MAX_BYTES === Number.POSITIVE_INFINITY ? null : RPC_LINE_MAX_BYTES,
					droppedBytes,
				}),
			);
			return;
		}

		while (true) {
			const newlineIndex = buffer.indexOf("\n");
			if (newlineIndex === -1) {
				return;
			}

			emitLine(buffer.slice(0, newlineIndex));
			buffer = buffer.slice(newlineIndex + 1);
		}
	};

	const onEnd = () => {
		buffer += decoder.end();
		if (buffer.length > 0) {
			emitLine(buffer);
			buffer = "";
		}
	};

	const onError = () => {
		// A stream-level 'error' (EBADF on a closed stdin pipe in RPC mode, a
		// child stdout that errors, etc.) with no listener throws `Unhandled
		// 'error' event` and crashes the agent. The caller's child "error"
		// handler does NOT cover the stream's own 'error' event. Swallow here;
		// 'end' will still fire and flush any buffered remainder, and the caller
		// owns higher-level error reporting.
	};

	stream.on("data", onData);
	stream.on("end", onEnd);
	stream.on("error", onError);

	return () => {
		stream.off("data", onData);
		stream.off("end", onEnd);
		stream.off("error", onError);
	};
}
