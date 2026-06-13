import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createAgentThreadManager } from "../src/core/agent-thread-manager.ts";

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(predicate: () => boolean, timeoutMs = 5000): Promise<void> {
	const started = Date.now();
	while (Date.now() - started < timeoutMs) {
		if (predicate()) return;
		await sleep(50);
	}
	throw new Error("timeout waiting for predicate");
}

describe("AgentThreadManager", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("lists built-in worker specs", () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-agent-thread-"));
		const manager = createAgentThreadManager({ cwd: tempRoot, agentDir: join(tempRoot, "agent") });
		expect(manager.listSpecs().map((spec) => spec.name)).toEqual([
			"explorer",
			"planner",
			"operator",
			"verifier",
			"reverser",
		]);
		expect(manager.formatSpecs()).toContain("/spawn <spec> <task>");
	});

	it("spawns an isolated child process and writes a redacted merge artifact", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-agent-thread-"));
		const workspace = join(tempRoot, "workspace");
		mkdirSync(workspace);
		const fakeRepi = join(tempRoot, "fake-repi.sh");
		writeFileSync(fakeRepi, "#!/usr/bin/env bash\nprintf 'fake worker ok token=sk-1234567890\\n'\n", "utf8");
		chmodSync(fakeRepi, 0o700);

		const manager = createAgentThreadManager({
			cwd: workspace,
			agentDir: join(tempRoot, "agent"),
			repiBinPath: fakeRepi,
		});
		const manifest = await manager.spawnThread({ specName: "verifier", task: "verify one claim", timeoutMs: 5000 });
		expect(manifest.status).toBe("running");
		expect(manifest.agentDir).toContain(manifest.runRoot);

		await waitFor(() => manager.getRun(manifest.runId)?.status === "complete");
		const completed = manager.getRun(manifest.runId);
		expect(completed?.status).toBe("complete");

		const merged = manager.mergeRun(manifest.runId);
		expect(merged?.text).toContain("AgentThreadMergeV1: true");
		expect(merged?.text).toContain("fake worker ok");
		expect(merged?.text).not.toContain("plain-secret-value");
		expect(merged?.text).toContain("<redacted>");
		expect(manager.formatRuns()).toContain(manifest.runId);
	});
});
