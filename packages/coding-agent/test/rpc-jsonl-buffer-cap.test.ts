import { Readable } from "node:stream";
import { describe, expect, test, vi } from "vitest";

// opt #184: attachJsonlLineReader's onData did `buffer += chunk` and flushed only
// on `\n` with NO length cap. RPC mode stays alive forever reading external stdin,
// so a peer sending a multi-GB blob with no `\n` accumulates the whole thing → OOM.
// Fix: REPI_RPC_LINE_MAX_BYTES cap (default 8MB, 0 disables). On overflow, reset
// the buffer and emit a synthetic framing-error marker line so the peer learns the
// line was dropped rather than silent truncation. The cap resolver is a module-level
// IIFE, so the env must be stubbed BEFORE the dynamic import (vitest isolates each
// test file's module registry, so this is the first evaluation of jsonl.ts here).

describe("RPC JSONL line reader buffer cap (opt #184)", () => {
	test("emits a framing-error marker and resets the buffer when a line exceeds REPI_RPC_LINE_MAX_BYTES", async () => {
		vi.resetModules();
		vi.stubEnv("REPI_RPC_LINE_MAX_BYTES", String(1024 * 1024)); // 1 MB
		const { attachJsonlLineReader } = await import("../src/modes/rpc/jsonl.ts");

		const lines: string[] = [];
		// A 2 MB blob with no newline — over the 1 MB cap, would OOM unbounded.
		const blob = "x".repeat(2 * 1024 * 1024);
		const stream = Readable.from([blob, '{"after":1}\n']);

		const done = new Promise<void>((resolve) => {
			stream.on("end", resolve);
		});

		attachJsonlLineReader(stream, (line) => {
			lines.push(line);
		});

		await done;

		// 1. A framing-error marker was emitted (valid JSON with jsonlFramingError).
		const framingError = lines.find((l) => {
			try {
				return (JSON.parse(l) as { jsonlFramingError?: boolean }).jsonlFramingError === true;
			} catch {
				return false;
			}
		});
		expect(framingError).toBeDefined();
		const parsed = JSON.parse(framingError as string) as {
			jsonlFramingError: boolean;
			reason: string;
			maxBytes: number | null;
			droppedBytes: number;
		};
		expect(parsed.reason).toContain("REPI_RPC_LINE_MAX_BYTES");
		expect(parsed.droppedBytes).toBeGreaterThan(1024 * 1024);

		// 2. The buffer was RESET (not accumulated): the subsequent valid line is
		//    emitted cleanly. Under the neuter (no cap) the blob would remain in the
		//    buffer and prefix `{"after":1}` → JSON.parse fails → this assertion fails.
		const afterLine = lines.find((l) => {
			try {
				return (JSON.parse(l) as { after?: number }).after === 1;
			} catch {
				return false;
			}
		});
		expect(afterLine).toBe('{"after":1}');

		// 3. No single emitted line carries the multi-MB blob (no unbounded growth).
		for (const line of lines) {
			expect(line.length).toBeLessThan(1024 * 1024);
		}
		vi.unstubAllEnvs();
	});

	test("0 disables the cap (legacy unbounded behavior)", async () => {
		vi.resetModules();
		vi.stubEnv("REPI_RPC_LINE_MAX_BYTES", "0");
		const { attachJsonlLineReader, RPC_LINE_MAX_BYTES } = await import("../src/modes/rpc/jsonl.ts");
		expect(RPC_LINE_MAX_BYTES).toBe(Number.POSITIVE_INFINITY);

		const lines: string[] = [];
		// 32 KB blob with no newline — under the disabled cap it stays buffered,
		// then the trailing newline flushes it as one (valid) line.
		const blob = `{"big":"${"y".repeat(32 * 1024)}"}\n`;
		const stream = Readable.from([blob]);

		const done = new Promise<void>((resolve) => {
			stream.on("end", resolve);
		});

		attachJsonlLineReader(stream, (line) => {
			lines.push(line);
		});

		await done;
		expect(lines).toHaveLength(1);
		expect((JSON.parse(lines[0]) as { big: string }).big.length).toBe(32 * 1024);
		// No framing-error marker when cap is disabled.
		expect(lines.some((l) => l.includes("jsonlFramingError"))).toBe(false);
		vi.unstubAllEnvs();
	});
});
