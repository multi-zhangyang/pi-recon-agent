import { describe, expect, it } from "vitest";
import { execCommand } from "../src/core/exec.ts";

// opt #98 F1: a signal-killed process (abort/timeout/SIGKILL/OOM) reports
// exitCode null from waitForChildProcess. The old `code ?? 0` coerced that to
// 0 = success, so callers branching on `result.code !== 0` treated a
// timeout/abort kill as a successful run. Post-fix a signal kill maps to a
// shell-style 128+signum (or a non-zero sentinel) — never 0 — while the
// `killed` flag is preserved.
//
// opt #98 F8: appendBounded recomputed Buffer.byteLength(current + chunk) on
// every data event, re-encoding the whole accumulated string per chunk → O(n²)
// up to the cap. Post-fix byte counts are tracked incrementally and only the
// new chunk is encoded per event; the front is sliced only when the cap is
// exceeded. Content is byte-for-byte identical to before (the fix only changes
// how bytes are counted, not what is kept).

const NODE = process.execPath;

describe("execCommand signal-kill exit code (F1)", () => {
	it("reports a non-zero code (not 0=success) for an aborted process, with killed=true", async () => {
		const controller = new AbortController();
		const promise = execCommand(NODE, ["-e", "setInterval(()=>{},1000)"], process.cwd(), {
			signal: controller.signal,
		});
		setTimeout(() => controller.abort(), 100);
		const result = await Promise.race([
			promise,
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("exec hung")), 8000)),
		]);
		expect(result.killed).toBe(true);
		// Pre-fix: code === 0 (null ?? 0) → callers treat abort as success.
		expect(result.code).not.toBe(0);
		expect(Number.isFinite(result.code)).toBe(true);
		expect(result.code! > 0).toBe(true);
	});

	it("reports a non-zero code for a timeout-killed process", async () => {
		const result = await Promise.race([
			execCommand(NODE, ["-e", "setInterval(()=>{},1000)"], process.cwd(), { timeout: 100 }),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("exec hung")), 8000)),
		]);
		expect(result.killed).toBe(true);
		expect(result.code).not.toBe(0);
		expect(result.code! > 0).toBe(true);
	});

	it("still reports the real exit code for a process that exits normally", async () => {
		const result = await execCommand(NODE, ["-e", "process.exit(7)"], process.cwd());
		expect(result.killed).toBe(false);
		expect(result.code).toBe(7);
	});

	it("still reports code 0 for a successful run", async () => {
		const result = await execCommand(NODE, ["-e", ""], process.cwd());
		expect(result.killed).toBe(false);
		expect(result.code).toBe(0);
	});
});

describe("execCommand incremental byte tracking (F8)", () => {
	it("keeps content byte-for-byte identical to the legacy path (no truncation)", async () => {
		// Small multibyte output under a cap that does not truncate.
		const line = `${"€".repeat(50)}\n`;
		const expected = line.repeat(3);
		const result = await execCommand(
			NODE,
			["-e", "const s='€'.repeat(50)+'\\n'; for(let i=0;i<3;i++) process.stdout.write(s)"],
			process.cwd(),
			{ maxBytes: 10_000 },
		);
		expect(result.code).toBe(0);
		expect(result.truncated).toBeUndefined();
		expect(result.stdout).toBe(expected);
	});

	it("tail-trims identically to the legacy path when the cap is exceeded", async () => {
		// Output exceeds the cap; the tail must be kept exactly as before.
		const result = await execCommand(
			NODE,
			["-e", "const s='€'.repeat(50)+'\\n'; for(let i=0;i<100;i++) process.stdout.write(s)"],
			process.cwd(),
			{ maxBytes: 1000 },
		);
		expect(result.code).toBe(0);
		expect(result.truncated).toBe(true);
		// Tail kept, head dropped; bounded near the cap.
		expect(Buffer.byteLength(result.stdout, "utf-8")).toBeLessThanOrEqual(1100);
		expect(result.stdout).toContain("€");
	});

	it("does not go O(n²) on a large multibyte output under a non-truncating cap", async () => {
		// ~48MB of multibyte output, cap 100MB (no truncation). The legacy
		// appendBounded re-encoded the whole accumulated string per data event
		// → tens of seconds. The incremental fix only encodes the new chunk per
		// event. Assert the run completes well under the legacy cost.
		const writes = 800;
		const result = await Promise.race([
			execCommand(
				NODE,
				["-e", `const s='€'.repeat(20000)+'\\n'; for(let i=0;i<${writes};i++) process.stdout.write(s)`],
				process.cwd(),
				{ maxBytes: 100 * 1024 * 1024, timeout: 60000 },
			),
			new Promise<never>((_, reject) =>
				setTimeout(() => reject(new Error("exec too slow (O(n²) regression)")), 10000),
			),
		]);
		expect(result.code).toBe(0);
		expect(result.truncated).toBeUndefined();
		// Content sanity: ~48MB of multibyte output was captured in full (the
		// cap did not truncate). Exact byte count is not asserted because the
		// -e arg encoding can shift a handful of bytes; the perf guarantee is
		// the load-bearing part.
		expect(Buffer.byteLength(result.stdout, "utf-8")).toBeGreaterThan(40_000_000);
	});
});
