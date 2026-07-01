// Shared helpers for repi-mcp.mjs stdio child hardening (REPI opt #173).
//
// Root cause addressed by these primitives:
//  - stdout buffer accumulated with no byte cap → a verbose/misbehaving MCP
//    server emitting one huge JSON-RPC line (or a tools/call result carrying a
//    base64 image) drove `repi mcp` into OOM before the 10s timeout fired.
//  - finish() sent SIGTERM and resolved immediately, never escalating to
//    SIGKILL and never awaiting exit → a server catching SIGTERM kept its
//    stdio pipes + listeners alive and hung the Node event loop at exit.
//  - writeLine() wrote to child.stdin with no stdin 'error' listener → an
//    EPIPE emitted when the server dies mid-write was an unhandled 'error'
//    event crash.
//
// These are pure-ish utilities extracted so they can be unit-tested directly.

/** Append `chunk` to `buf` and, when `max > 0`, roll the buffer down to its
 *  tail so it never exceeds `max` bytes (well, UTF-16 code units — same as the
 *  surrounding .mjs which uses String.length throughout). `max === 0` disables
 *  the cap (returns the unbounded concatenation). Returns the new buffer. */
export function capStdioBuffer(buf, chunk, max) {
	let next = buf + String(chunk);
	if (max > 0 && next.length > max) next = next.slice(next.length - max);
	return next;
}

/** Send SIGTERM, then arm a SIGKILL-grace timer (`graceMs`) that force-kills
 *  the child if it is still alive. Returns a promise that resolves when the
 *  child fully exits ('close'), so the caller can await tear-down and the
 *  event loop is not kept alive by lingering stdio listeners. If the child is
 *  already gone (no pid / killed), resolves immediately. The grace timer is
 *  unref'd so it cannot itself keep the loop alive. */
export function killWithGrace(child, graceMs) {
	return new Promise((resolve) => {
		if (!child || !child.pid || child.exitCode !== null || child.signalCode) {
			return resolve({ killed: false, exitCode: child ? child.exitCode : null, signalCode: child ? child.signalCode : null });
		}
		let settled = false;
		const grace = setTimeout(() => {
			if (settled) return;
			try { if (child.exitCode === null) child.kill("SIGKILL"); } catch {}
		}, graceMs).unref();
		try { child.kill("SIGTERM"); } catch {}
		child.once("close", () => {
			if (settled) return;
			settled = true;
			clearTimeout(grace);
			resolve({ killed: true, exitCode: child.exitCode, signalCode: child.signalCode });
		});
		// Safety net: if 'close' never fires (shouldn't happen for a real
		// child), resolve after grace + a small epsilon so the caller never
		// hangs. unref'd.
		const net = setTimeout(() => {
			if (settled) return;
			settled = true;
			clearTimeout(grace);
			resolve({ killed: true, exitCode: child.exitCode, signalCode: child.signalCode });
		}, graceMs + 1000).unref();
	});
}

/** Attach an idempotent 'error' swallower on `stdin` (so an EPIPE when the
 *  child dies mid-write does not crash the host as an unhandled 'error'
 *  event) and write `line` as UTF-8. The listener is tagged so it is only
 *  attached once per stream. Returns true if the write was accepted. */
const SWALLOW_TAG = "_repiMcpStdinErrorSwallowed";
export function safeWriteLine(stdin, line) {
	if (!stdin) return false;
	if (!stdin[SWALLOW_TAG]) {
		stdin.on("error", () => {});
		stdin[SWALLOW_TAG] = true;
	}
	try {
		stdin.write(line, "utf8");
		return true;
	} catch {
		return false;
	}
}

/** Best-effort drain of an HTTP Response body so the underlying keep-alive
 *  socket is released back to the pool. Safe on null/locked/consumed/errored
 *  bodies. Mirrors the opt #49 doctrine. */
export async function drainHttpBody(response) {
	try {
		if (response?.body?.cancel) await response.body.cancel();
	} catch {}
}

/** Read an HTTP Response body with a hard byte cap. `Response.text()` buffers
 *  the entire body before returning; a malicious or broken HTTP MCP endpoint
 *  can therefore OOM the REPI CLI before the request timeout fires. This helper
 *  streams chunks, aborts/cancels once the cap is exceeded, and returns decoded
 *  UTF-8 text only when the full body fits within the limit. `maxBytes <= 0`
 *  disables the cap for explicit operator debugging. */
export async function readHttpTextBounded(response, maxBytes, label = "mcp_http_body") {
	if (!response) return "";
	const limit = Number(maxBytes) || 0;
	const fail = () => new Error(`${label}_too_large maxBytes=${limit}`);
	if (!response.body?.getReader) {
		const text = await response.text();
		if (limit > 0 && Buffer.byteLength(text, "utf8") > limit) throw fail();
		return text;
	}
	const reader = response.body.getReader();
	const decoder = new TextDecoder();
	let bytes = 0;
	let text = "";
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			bytes += value?.byteLength ?? Buffer.byteLength(String(value ?? ""), "utf8");
			if (limit > 0 && bytes > limit) {
				try { await reader.cancel(); } catch {}
				throw fail();
			}
			text += decoder.decode(value, { stream: true });
		}
		text += decoder.decode();
		return text;
	} finally {
		try { reader.releaseLock(); } catch {}
	}
}
