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

function runAutoCompactedLongTaskset(options: { unrelatedCompaction?: boolean } = {}) {
	const directory = mkdtempSync(join(tmpdir(), "repi-live-taskset-auto-compact-"));
	temporaryDirectories.push(directory);
	const fakeCli = join(directory, "fake-repi.mjs");
	writeFileSync(
		fakeCli,
		`#!/usr/bin/env node
import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
const args = process.argv.slice(2);
const valueAfter = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
if (valueAfter("--mode") === "rpc") {
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    const line = String(chunk).split(/\\r?\\n/).find(Boolean);
    if (!line) return;
    const request = JSON.parse(line);
    console.log(JSON.stringify({ id: request.id, type: "response", command: "compact", success: false, error: "Already compacted" }));
  });
} else {
  const profileDir = process.env.REPI_CODING_AGENT_DIR;
  const sessionDir = valueAfter("--session-dir");
  const sessionId = valueAfter("--session-id");
  const prompt = args.find((value) => value.includes("benchmark")) || "";
  const nonce = /REPI-[A-Z0-9]+/.exec(prompt)?.[0] || "REPI-MISSING";
  const finalText = prompt.includes("If the original nonce") ? "REPI_LONG_SESSION_OK" : "REPI_TURN_01_OK";
  mkdirSync(sessionDir, { recursive: true });
  const sessionPath = join(sessionDir, "fixture.jsonl");
	  const rows = [];
	  if (!existsSync(sessionPath)) rows.push({ type: "session", id: sessionId });
	  rows.push({ type: "message", message: { role: "user", content: prompt + nonce } });
	  rows.push({ type: "message", message: { role: "assistant", content: [{ type: "text", text: finalText }] } });
	  ${options.unrelatedCompaction ? "" : 'rows.push({ type: "compaction", summary: "automatic compact" });'}
	  appendFileSync(sessionPath, rows.map((row) => JSON.stringify(row)).join("\\n") + "\\n");
	  ${
			options.unrelatedCompaction
				? 'appendFileSync(join(sessionDir, "unrelated.jsonl"), [{ type: "session", id: "unrelated-session" }, { type: "compaction", summary: "unrelated automatic compact" }].map((row) => JSON.stringify(row)).join("\\n") + "\\n");'
				: ""
		}
  const reconDir = join(profileDir, "recon");
  mkdirSync(reconDir, { recursive: true });
  const db = new DatabaseSync(join(reconDir, "state.sqlite3"));
  db.exec("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS repi_state(namespace TEXT); INSERT INTO repi_state(namespace) SELECT 'mission' WHERE NOT EXISTS (SELECT 1 FROM repi_state WHERE namespace = 'mission');");
  db.close();
  console.log(JSON.stringify({ type: "message_end", message: { role: "assistant", content: [{ type: "text", text: finalText }] } }));
  console.log(JSON.stringify({ type: "compaction_end", aborted: false, result: { summary: "automatic compact" } }));
  console.log(JSON.stringify({ type: "agent_end", messages: [] }));
}
`,
		{ mode: 0o700 },
	);
	chmodSync(fakeCli, 0o700);
	return spawnSync(process.execPath, [script, root, "--json"], {
		encoding: "utf8",
		env: {
			...process.env,
			REPI_RUN_LIVE_TASKSET: "1",
			REPI_LIVE_TASKSET_CASES: "long-session-recovery",
			REPI_LIVE_TASKSET_TURNS: "2",
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

	it("accepts idempotent RPC compact results after automatic compaction", () => {
		const result = runAutoCompactedLongTaskset();
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			ok: boolean;
			results: Array<{
				ok: boolean;
				compact: Array<{ ok: boolean; source: string; persistedCompactions: number; rpc?: { error?: string } }>;
				compactions: number;
				recovered: boolean;
			}>;
		};
		expect(report.ok).toBe(true);
		expect(report.results[0]).toMatchObject({
			ok: true,
			compactions: 2,
			recovered: true,
			compact: [
				{
					ok: true,
					source: "automatic",
					persistedCompactions: 1,
					automaticCompactionDelta: 1,
					rpc: { error: "Already compacted" },
				},
				{
					ok: true,
					source: "automatic",
					persistedCompactions: 2,
					automaticCompactionDelta: 1,
					rpc: { error: "Already compacted" },
				},
			],
		});
	});

	it("rejects idempotent RPC errors backed only by another session's compaction", () => {
		const result = runAutoCompactedLongTaskset({ unrelatedCompaction: true });
		expect(result.status).toBe(1);
		const report = JSON.parse(result.stdout) as {
			ok: boolean;
			results: Array<{
				ok: boolean;
				compact: Array<{ ok: boolean; source: string; automaticCompactionDelta: number; rpc?: unknown }>;
				compactions: number;
			}>;
		};
		expect(report.ok).toBe(false);
		expect(report.results[0]).toMatchObject({
			ok: false,
			compactions: 0,
			compact: [
				{ ok: false, source: "rpc", automaticCompactionDelta: 0 },
				{ ok: false, source: "rpc", automaticCompactionDelta: 0 },
			],
		});
	});
});
