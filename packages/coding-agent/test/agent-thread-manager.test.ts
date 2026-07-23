import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

async function withRepiSubagentEnv<T>(values: Record<string, string>, fn: () => Promise<T>): Promise<T> {
	const names = [
		"REPI_SUBAGENT_MODEL",
		"REPI_SUBAGENT_PROVIDER",
		"REPI_PROVIDER",
		"REPI_MODEL_PROVIDER",
		"REPI_PROVIDER_ID",
	];
	const originals = new Map(names.map((name) => [name, process.env[name]]));
	for (const name of names) delete process.env[name];
	for (const [name, value] of Object.entries(values)) process.env[name] = value;
	try {
		return await fn();
	} finally {
		for (const name of names) {
			const original = originals.get(name);
			if (original === undefined) delete process.env[name];
			else process.env[name] = original;
		}
	}
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
		writeFileSync(
			fakeRepi,
			"#!/usr/bin/env bash\nprintf 'fake worker ok token=synthetic-redaction-value\\n'\n",
			"utf8",
		);
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
		expect(merged?.text).not.toContain("synthetic-redaction-value");
		expect(merged?.text).toContain("<redacted>");
		expect(manager.formatRuns()).toContain(manifest.runId);
	});

	it("passes REPI_SUBAGENT_MODEL as the default child provider/model override", async () => {
		await withRepiSubagentEnv(
			{
				REPI_PROVIDER: "repi-env",
				REPI_SUBAGENT_MODEL: "worker-model",
			},
			async () => {
				tempRoot = mkdtempSync(join(tmpdir(), "repi-agent-thread-"));
				const workspace = join(tempRoot, "workspace");
				mkdirSync(workspace);
				const fakeRepi = join(tempRoot, "fake-repi.sh");
				writeFileSync(fakeRepi, "#!/usr/bin/env bash\nprintf 'args=%s\\n' \"$*\"\n", "utf8");
				chmodSync(fakeRepi, 0o700);

				const manager = createAgentThreadManager({
					cwd: workspace,
					agentDir: join(tempRoot, "agent"),
					repiBinPath: fakeRepi,
				});
				const manifest = await manager.spawnThread({
					specName: "verifier",
					task: "verify env model",
					timeoutMs: 5000,
				});
				expect(manifest.provider).toBe("repi-env");
				expect(manifest.model).toBe("worker-model");

				await waitFor(() => manager.getRun(manifest.runId)?.status === "complete");
				const completed = manager.getRun(manifest.runId);
				expect(completed?.provider).toBe("repi-env");
				expect(completed?.model).toBe("worker-model");
				const stdout = readFileSync(completed!.stdoutPath, "utf8");
				expect(stdout).toContain("--provider repi-env --model worker-model");
			},
		);
	});

	it("blocks project MCP config when inheritance is disabled", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-agent-thread-"));
		const workspace = join(tempRoot, "workspace");
		mkdirSync(join(workspace, ".repi"), { recursive: true });
		writeFileSync(
			join(workspace, ".repi", "mcp.json"),
			JSON.stringify({ mcpServers: { demo: { transport: "stdio", command: "node", args: ["demo.js"] } } }),
			"utf8",
		);
		const fakeRepi = join(tempRoot, "fake-repi.sh");
		writeFileSync(
			fakeRepi,
			[
				"#!/usr/bin/env bash",
				"printf 'mcp_disabled=%s\\n' \"$" + '{REPI_MCP_DISABLED:-unset}"',
				"printf 'allowed_servers=%s\\n' \"$" + '{REPI_MCP_ALLOWED_SERVERS:-unset}"',
				"",
			].join("\n"),
			"utf8",
		);
		chmodSync(fakeRepi, 0o700);

		const manager = createAgentThreadManager({
			cwd: workspace,
			agentDir: join(tempRoot, "agent"),
			repiBinPath: fakeRepi,
		});
		const manifest = await manager.spawnThread({
			specName: "verifier",
			task: "verify mcp isolation",
			timeoutMs: 5000,
			inheritMcp: false,
		});
		await waitFor(() => manager.getRun(manifest.runId)?.status === "complete");
		const merged = manager.mergeRun(manifest.runId);
		expect(merged?.text).toContain("mcp_disabled=1");
		expect(merged?.text).toContain("allowed_servers=unset");
	});
});
