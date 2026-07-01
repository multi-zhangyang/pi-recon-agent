import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createAgentThreadManager } from "../src/core/agent-thread-manager.ts";

// Regression guard for opt #50: listRuns() must not crash when a manifest parses
// (valid JSON, passes the Boolean filter) but omits `createdAt` — from hand-editing,
// an older schema, or external corruption. A bare `b.createdAt.localeCompare(a.createdAt)`
// throws `undefined.localeCompare is not a function`, crashing every listRuns caller
// (getRun → interactive /agent, formatRuns, stopRun, resolveRun). opt #44 guarded only
// resolveRun's getRun consult; this guards the throw at the source.

function makeManifestDir(root: string, runId: string): string {
	const runRoot = join(root, runId);
	mkdirSync(runRoot, { recursive: true });
	return runRoot;
}

function writeManifest(runRoot: string, manifest: Record<string, unknown>): void {
	writeFileSync(join(runRoot, "manifest.json"), JSON.stringify(manifest), "utf8");
}

describe("AgentThreadManager listRuns null-safe sort (opt #50)", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("does not throw when one manifest lacks createdAt and returns both runs", () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-agent-thread-sort-"));
		const agentDir = join(tempRoot, "agent");
		const runsRoot = join(agentDir, "recon", "agent-threads");

		// One complete, valid manifest.
		const validRoot = makeManifestDir(runsRoot, "run-valid-aaaa");
		writeManifest(validRoot, {
			kind: "repi-agent-thread-run",
			schemaVersion: 1,
			runId: "run-valid-aaaa",
			specName: "verifier",
			task: "verify one claim",
			status: "complete",
			createdAt: "2026-06-29T10:00:00.000Z",
			cwd: tempRoot,
			runRoot: validRoot,
			agentDir,
			stdoutPath: join(validRoot, "stdout.log"),
			stderrPath: join(validRoot, "stderr.log"),
			manifestPath: join(validRoot, "manifest.json"),
			tools: [],
		});

		// One manifest that parses but is missing createdAt (corrupt/older schema).
		const corruptRoot = makeManifestDir(runsRoot, "run-corrupt-bbbb");
		writeManifest(corruptRoot, {
			kind: "repi-agent-thread-run",
			schemaVersion: 1,
			runId: "run-corrupt-bbbb",
			specName: "explorer",
			task: "explore",
			status: "stopped",
			// createdAt intentionally omitted
			cwd: tempRoot,
			runRoot: corruptRoot,
			agentDir,
			stdoutPath: join(corruptRoot, "stdout.log"),
			stderrPath: join(corruptRoot, "stderr.log"),
			manifestPath: join(corruptRoot, "manifest.json"),
			tools: [],
		});

		const manager = createAgentThreadManager({ cwd: tempRoot, agentDir });

		// Must not throw.
		let runs: ReturnType<typeof manager.listRuns> = [];
		expect(() => {
			runs = manager.listRuns();
		}).not.toThrow();

		// Both runs are returned despite one missing createdAt.
		expect(runs).toHaveLength(2);
		expect(runs.map((r) => r.runId).sort()).toEqual(["run-corrupt-bbbb", "run-valid-aaaa"]);

		// getRun("latest") returns the most recent (the valid one with createdAt); the
		// corrupt one sorts as empty → earliest, so it never shadows a real latest run.
		expect(manager.getRun("latest")?.runId).toBe("run-valid-aaaa");

		// formatRuns (used by interactive /agent with no args) must not throw either.
		expect(() => manager.formatRuns()).not.toThrow();
	});

	it("does not throw when every manifest lacks createdAt", () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-agent-thread-sort-"));
		const agentDir = join(tempRoot, "agent");
		const runsRoot = join(agentDir, "recon", "agent-threads");

		for (const runId of ["run-a", "run-b", "run-c"]) {
			const runRoot = makeManifestDir(runsRoot, runId);
			writeManifest(runRoot, {
				kind: "repi-agent-thread-run",
				schemaVersion: 1,
				runId,
				specName: "explorer",
				task: "explore",
				status: "complete",
				// createdAt intentionally omitted on every row
				cwd: tempRoot,
				runRoot,
				agentDir,
				stdoutPath: join(runRoot, "stdout.log"),
				stderrPath: join(runRoot, "stderr.log"),
				manifestPath: join(runRoot, "manifest.json"),
				tools: [],
			});
		}

		const manager = createAgentThreadManager({ cwd: tempRoot, agentDir });
		expect(() => manager.listRuns()).not.toThrow();
		expect(manager.listRuns()).toHaveLength(3);
		expect(() => manager.formatRuns()).not.toThrow();
	});
});
