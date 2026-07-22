import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../../..");
const script = join(root, "scripts/reverse-agent/repi-live-taskset.mjs");
const temporaryDirectories: string[] = [];

afterEach(() => {
	for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function runTaskset(options: { invalidTarget?: boolean; providerError?: boolean } = {}) {
	const directory = mkdtempSync(join(tmpdir(), "repi-live-taskset-report-"));
	temporaryDirectories.push(directory);
	const fakeCli = join(directory, "fake-repi.mjs");
	writeFileSync(
		fakeCli,
		`#!/usr/bin/env node
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const adapter = "pwntools-local-verifier-adapter";
const target = ${JSON.stringify(options.invalidTarget ? "/wrong-target" : "/bin/true")};
const artifactDir = join(process.env.REPI_CODING_AGENT_DIR, "recon", "evidence", "toolchain", "runtime-adapters", adapter);
mkdirSync(artifactDir, { recursive: true });
const artifactPath = join(artifactDir, "run.json");
writeFileSync(artifactPath, JSON.stringify({
  kind: "RuntimeAdapterExecutionArtifactV1",
  schemaVersion: 1,
  adapterId: adapter,
  domainId: "pwn",
  bridgeId: "exploit-verifier-runtime",
  target,
  startedAt: new Date(0).toISOString(),
  finishedAt: new Date(1).toISOString(),
  selectedRunner: "native",
  command: "python3 verifier.py",
  exitCode: 0,
  killed: false,
  stdoutSha256: "a".repeat(64),
  stderrSha256: "b".repeat(64),
  parserSignals: [{ ruleId: "parser-pwn", evidenceRank: "runtime_artifact", proofExitSignal: "local exploit replay", matches: ["run=1"] }],
  parserSignalSummary: { matchedRules: 1, totalRules: 1, matchCount: 1, evidenceRanks: ["runtime_artifact"], matchedProofExitSignals: ["local exploit replay"], missingProofExitSignals: [] },
  artifactKinds: ["pwn-local-replay", "runtime-adapter-transcript"],
  ingestTargets: ["evidence-ledger"],
  proofExitSignals: ["local exploit replay"],
  replay: { command: "re_runtime_adapter run " + adapter + " " + target, timeoutMs: 20000 }
}));
const id = "tool-1";
console.log(JSON.stringify({ type: "tool_execution_start", toolCallId: id, toolName: "re_runtime_adapter", args: { action: "run", adapter, target: "/bin/true", timeoutMs: 20000 } }));
console.log(JSON.stringify({ type: "tool_execution_end", toolCallId: id, toolName: "re_runtime_adapter", isError: false, result: { content: [{ type: "text", text: "runtime_adapter_run:\\nRuntimeAdapterExecutionArtifactV1: true\\nartifact: " + artifactPath }] } }));
${
	options.providerError
		? 'console.log(JSON.stringify({ type: "message_end", message: { role: "assistant", stopReason: "error", errorMessage: "provider rejected request", content: [] } }));'
		: ""
}
console.log(JSON.stringify({ type: "message_end", message: { role: "assistant", content: [{ type: "text", text: "REPI_NATIVE_TASK_OK" }] } }));
`,
		{ mode: 0o700 },
	);
	chmodSync(fakeCli, 0o700);
	return spawnSync(process.execPath, [script, root, "--json"], {
		encoding: "utf8",
		env: {
			...process.env,
			REPI_RUN_LIVE_TASKSET: "1",
			REPI_LIVE_TASKSET_CASES: "native-domain-adapter",
			REPI_BIN_PATH: fakeCli,
		},
	});
}

describe("live taskset artifact gates", () => {
	it("accepts a routed tool result backed by a verified runtime artifact", () => {
		const result = runTaskset();
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as { ok: boolean; results: Array<Record<string, unknown>> };
		expect(report.ok).toBe(true);
		expect(report.results[0]).toMatchObject({
			ok: true,
			toolCalls: 1,
			toolResults: 1,
			parserMatches: 1,
			failures: [],
			providerFailures: { ok: true, total: 0, errors: 0, aborted: 0, summaries: [] },
		});
	});

	it("rejects a success phrase when the artifact is bound to another target", () => {
		const result = runTaskset({ invalidTarget: true });
		expect(result.status).toBe(1);
		const report = JSON.parse(result.stdout) as { ok: boolean; results: Array<{ failures: string[] }> };
		expect(report.ok).toBe(false);
		expect(report.results[0]?.failures).toContain("artifact_target");
	});

	it("rejects a success phrase when an assistant turn contains a provider error", () => {
		const result = runTaskset({ providerError: true });
		expect(result.status).toBe(1);
		const report = JSON.parse(result.stdout) as {
			ok: boolean;
			results: Array<{ ok: boolean; providerFailures: Record<string, unknown> }>;
		};
		expect(report.ok).toBe(false);
		expect(report.results[0]).toMatchObject({
			ok: false,
			providerFailures: {
				ok: false,
				total: 1,
				errors: 1,
				aborted: 0,
				summaries: ["provider rejected request"],
			},
		});
	});
});
