import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// agent-thread-manager streams child stdout to <runRoot>/stdout.txt. It used to
// writeFileSync the ENTIRE accumulated buffer on every 'data' chunk — O(N) disk
// I/O per chunk, ~500 full 2MB rewrites for a 2MB stream. Now it appends only
// the new delta (appendFileSync) and does one full rewrite (writeFileSync) only
// when the in-memory buffer crosses its 2MB cap (slice). Prove the append-mostly
// shape: count writeFileSync vs appendFileSync calls on the stdout path. vi.mock
// wraps both (delegating to real) with a vi.hoisted counter filtered by path.
const { stdoutWriteCount, stdoutAppendCount } = vi.hoisted(() => ({
	stdoutWriteCount: { current: 0 },
	stdoutAppendCount: { current: 0 },
}));

vi.mock("node:fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	const wrap = (
		impl: (...args: Parameters<typeof actual.writeFileSync>) => void,
		counter: { current: number },
		pathFilter: string,
	) =>
		vi.fn((...args: Parameters<typeof actual.writeFileSync>) => {
			if (String(args[0]).endsWith(pathFilter)) counter.current++;
			return impl(...args);
		});
	return {
		...actual,
		writeFileSync: wrap(actual.writeFileSync, stdoutWriteCount, "stdout.txt"),
		appendFileSync: wrap(
			actual.appendFileSync as (...a: Parameters<typeof actual.writeFileSync>) => void,
			stdoutAppendCount,
			"stdout.txt",
		),
	};
});

const { createAgentThreadManager } = await import("../src/core/agent-thread-manager.ts");

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}
async function waitFor(predicate: () => boolean, timeoutMs = 10_000): Promise<void> {
	const started = Date.now();
	while (Date.now() - started < timeoutMs) {
		if (predicate()) return;
		await sleep(50);
	}
	throw new Error("timeout waiting for predicate");
}

describe("AgentThreadManager streaming stdout IO", () => {
	let tempRoot: string | undefined;

	beforeEach(() => {
		stdoutWriteCount.current = 0;
		stdoutAppendCount.current = 0;
	});

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("appends per chunk and rewrites only on the 2MB cap slice (regression: was full rewrite per chunk)", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-thread-stream-"));
		const workspace = join(tempRoot, "workspace");
		const { mkdirSync } = await import("node:fs");
		mkdirSync(workspace, { recursive: true });
		// Stream 8MB of 'A' (crosses the 2MB cap 4× → 4 slice rewrites; ~500
		// 16KB 'data' chunks at child-stdio pipe granularity → ~496 appends).
		// Old code: ~500 full writeFileSync rewrites of the growing buffer.
		// New code: ~496 appends + 1 initial empty create + 4 slice rewrites.
		const fakeRepi = join(tempRoot, "fake-repi.sh");
		writeFileSync(fakeRepi, ["#!/usr/bin/env bash", "yes A | tr -d '\\n' | head -c 8388608", ""].join("\n"), "utf8");
		chmodSync(fakeRepi, 0o700);

		const manager = createAgentThreadManager({
			cwd: workspace,
			agentDir: join(tempRoot, "agent"),
			repiBinPath: fakeRepi,
		});
		const manifest = await manager.spawnThread({ specName: "verifier", task: "stream", timeoutMs: 15_000 });
		await waitFor(() => manager.getRun(manifest.runId)?.status === "complete", 20_000);

		// Append dominated. Discriminators chosen to be robust to chunk
		// granularity (Node may deliver 16-128KB 'data' chunks): new code
		// APPENDS (>0, and more appends than full rewrites) and does only a
		// handful of full writeFileSyncs (initial create + ~4 slice rewrites);
		// old code never appended (0 appendFileSync) and did one writeFileSync
		// per chunk (~100+). <50 write + append>write cleanly separates them.
		expect(stdoutAppendCount.current).toBeGreaterThan(0);
		expect(stdoutWriteCount.current).toBeLessThan(50);
		expect(stdoutAppendCount.current).toBeGreaterThan(stdoutWriteCount.current);

		// Disk bounded at ~2x cap (append-only between truncates, truncated to
		// the 2MB tail when it crosses 4MB — never unbounded growth). 8MB
		// streamed → file well under 8MB proves boundedness (the naive
		// append-only fix's failure mode would be an 8MB file).
		const stdoutPath = join(manifest.runRoot, "stdout.txt");
		const stat = await import("node:fs/promises").then((m) => m.stat(stdoutPath));
		expect(stat.size).toBeLessThan(6 * 1024 * 1024);

		// Content contract: the file is all 'A's (uniform stream). The in-memory
		// cap is 2MB; after the final slice the file holds the last 2MB, so ≥ 2MB.
		const content = readFileSync(stdoutPath, "utf8");
		expect(content.length).toBeGreaterThan(0);
		expect(/^[A]*$/.test(content)).toBe(true);
		expect(content.length).toBeGreaterThanOrEqual(2 * 1024 * 1024);
	}, 30_000);
});
