#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const writeEvidence = !argv.includes("--no-write");
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_TOOL_TRACE_TMP === "1";
const FIXTURE_PATH = "fixtures/reverse-agent/tool-call-trace-ledger.fixture.json";
const SCHEMA_PATH = "schemas/reverse-agent/tool-call-trace-ledger.schema.json";
const sha256 = (value) => createHash("sha256").update(String(value ?? "")).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

function stableJson(value) {
	return JSON.stringify(value, (_key, item) => {
		if (!item || typeof item !== "object" || Array.isArray(item)) return item;
		return Object.keys(item).sort().reduce((out, key) => { out[key] = item[key]; return out; }, {});
	});
}

function eventHash(event) {
	const { eventHash: _eventHash, ...withoutHash } = event;
	return sha256(stableJson(withoutHash));
}

function hasLiteralSecret(value) {
	return /\bsk-[A-Za-z0-9_-]{8,}\b|\bghp_[A-Za-z0-9_]{16,}\b|\bgithub_pat_[A-Za-z0-9_]{16,}\b|(?:AUTH_TOKEN|API_KEY|PASSWORD|SECRET)=(?!<redacted>)\S+/i.test(String(value ?? ""));
}

function markerCheck(id, path, markers) {
	if (!existsSync(join(root, path))) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readText(path);
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function validateEvents(events) {
	const errors = [];
	let prevHash = "0".repeat(64);
	const calls = new Set();
	for (const [index, event] of events.entries()) {
		if (event.kind !== "ToolCallTraceEventV1") errors.push(`kind:${index}`);
		if (event.schemaVersion !== 1) errors.push(`schema:${index}`);
		if (event.prevHash !== prevHash) errors.push(`prevHash:${index}`);
		if (event.eventHash !== eventHash(event)) errors.push(`eventHash:${index}`);
		prevHash = event.eventHash;
		if (!event.toolCallId) errors.push(`toolCallId:${index}`);
		if (!event.toolName) errors.push(`toolName:${index}`);
		if (!/^[a-f0-9]{64}$/.test(event.inputSha256 ?? "")) errors.push(`inputSha256:${index}`);
		if (event.phase === "result" && !/^[a-f0-9]{64}$/.test(event.outputSha256 ?? "")) errors.push(`outputSha256:${index}`);
		if (hasLiteralSecret(`${event.inputPreviewRedacted}\n${event.outputPreviewRedacted ?? ""}\n${event.commandPreviewRedacted ?? ""}\n${event.replay?.command ?? ""}`)) errors.push(`literalSecret:${index}`);
		if (event.assertions?.secretRedacted !== true) errors.push(`secretRedacted:${index}`);
		if (event.phase === "call") calls.add(event.toolCallId);
		if (event.phase === "result" && !calls.has(event.toolCallId)) errors.push(`resultWithoutCall:${event.toolCallId}`);
		if (event.toolName === "bash" && event.replay?.available !== true) errors.push(`bashReplayMissing:${index}`);
	}
	return { ok: errors.length === 0, errors };
}

function mutateEvents(events, mutate) {
	const clone = JSON.parse(JSON.stringify(events));
	if (mutate === "hashDrift") clone[1].outputPreviewRedacted = "tampered";
	if (mutate === "secretLeak") clone[0].inputPreviewRedacted = "OPENAI_API_KEY=sk-leaked-tooltrace-token";
	if (mutate === "missingCall") clone.splice(0, 1);
	if (mutate === "missingOutputHash") delete clone.find((event) => event.phase === "result").outputSha256;
	if (mutate === "missingReplay") clone.find((event) => event.toolName === "bash").replay.available = false;
	return clone;
}

function negativeCase(events, negative) {
	const validation = validateEvents(mutateEvents(events, negative.mutate));
	const missing = (negative.expectedErrors ?? []).filter((needle) => !validation.errors.some((error) => error.includes(needle)));
	return { id: `negative:${negative.id}`, status: !validation.ok && missing.length === 0 ? "pass" : "fail", evidence: { validation, missing } };
}

function writeProbe(probePath, outPath, tempRoot) {
	const importUrl = pathToFileURL(join(root, "packages/coding-agent/src/core/recon-profile.ts")).href;
	writeFileSync(probePath, `
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createReconExtensionFactory } from ${JSON.stringify(importUrl)};
const tempRoot = ${JSON.stringify(tempRoot)};
const outPath = ${JSON.stringify(outPath)};
const agentDir = join(tempRoot, "agent");
const workspace = join(tempRoot, "workspace");
mkdirSync(agentDir, { recursive: true });
mkdirSync(workspace, { recursive: true });
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_SESSION_ID = "tool-call-trace-ledger-session";
process.chdir(workspace);
const handlers = new Map();
const fakePi = {
  registerCommand() {}, registerTool() {}, appendEntry() {}, getSessionName: () => undefined, setSessionName() {}, sendMessage() {},
  on(name, handler) { handlers.set(name, handler); },
  exec: async () => ({ code: 0, stdout: "tool trace probe", stderr: "", killed: false })
};
createReconExtensionFactory()(fakePi);
await handlers.get("before_agent_start")?.({ prompt: "web security tool trace ledger probe", systemPrompt: "base" }, { hasUI: false, ui: {} });
await handlers.get("tool_call")?.({ type: "tool_call", toolCallId: "call-1", toolName: "bash", input: { command: "OPENAI_API_KEY=sk-tooltrace-secret-123456789 curl -s http://127.0.0.1/probe" } }, { hasUI: false, ui: {} });
await handlers.get("tool_result")?.({ type: "tool_result", toolCallId: "call-1", toolName: "bash", input: { command: "OPENAI_API_KEY=sk-tooltrace-secret-123456789 curl -s http://127.0.0.1/probe" }, content: [{ type: "text", text: "ok token=sk-tooltrace-secret-123456789" }], isError: false, details: { code: 0, stdout: "ok", stderr: "" } }, { hasUI: false, ui: {} });
await handlers.get("tool_call")?.({ type: "tool_call", toolCallId: "call-2", toolName: "re_memory", input: { action: "status" } }, { hasUI: false, ui: {} });
await handlers.get("tool_result")?.({ type: "tool_result", toolCallId: "call-2", toolName: "re_memory", input: { action: "status" }, content: [{ type: "text", text: "memory status ok" }], isError: false, details: { status: "pass" } }, { hasUI: false, ui: {} });
const ledgerPath = join(agentDir, "recon", "evidence", "tool-calls", "tool-call-trace.jsonl");
const reportPath = join(agentDir, "recon", "evidence", "tool-calls", "tool-call-trace-report.json");
const events = existsSync(ledgerPath) ? readFileSync(ledgerPath, "utf8").trim().split(/\\r?\\n/).filter(Boolean).map((line) => JSON.parse(line)) : [];
const report = existsSync(reportPath) ? JSON.parse(readFileSync(reportPath, "utf8")) : null;
writeFileSync(outPath, JSON.stringify({ agentDir, workspace, ledgerPath, reportPath, events, report }, null, 2));
`, "utf8");
}

async function runRuntimeProbe(tempRoot) {
	const probePath = join(tempRoot, "tool-trace-probe.mjs");
	const outPath = join(tempRoot, "tool-trace-result.json");
	writeProbe(probePath, outPath, tempRoot);
	const { spawnSync } = await import("node:child_process");
	const child = spawnSync(process.execPath, [probePath], { cwd: root, env: { ...process.env, REPI_CODING_AGENT_DIR: join(tempRoot, "agent") }, encoding: "utf8", maxBuffer: 10 * 1024 * 1024 });
	const result = existsSync(outPath) ? JSON.parse(readFileSync(outPath, "utf8")) : { events: [], report: null };
	return { child: { code: child.status, stdout: child.stdout, stderr: child.stderr }, ...result };
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "tool-call-trace-ledger", stamp);
	mkdirSync(dir, { recursive: true });
	const path = join(dir, "report.json");
	writeFileSync(path, JSON.stringify(result, null, 2));
	return path;
}

function formatMarkdown(result) {
	const lines = ["# REPI Tool Call Trace Ledger Gate", "", `generated_at: ${result.generatedAt}`, `ok: ${result.ok}`, "", "## Checks"];
	for (const check of result.checks) lines.push(`- ${check.id}: ${check.status}`);
	if (result.evidencePath) lines.push("", `evidence: ${result.evidencePath}`);
	return `${lines.join("\n")}\n`;
}

async function main() {
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-tool-call-trace-ledger-"));
	try {
		const runtime = await runRuntimeProbe(tempRoot);
		const validation = validateEvents(runtime.events ?? []);
		const fixture = readJson(FIXTURE_PATH);
		const checks = [
			{ id: "runtime:tool-call-trace-ledger-written", status: runtime.events?.length >= 4 ? "pass" : "fail", evidence: { eventCount: runtime.events?.length ?? 0, ledgerPath: runtime.ledgerPath, child: runtime.child } },
			{ id: "runtime:tool-call-trace-hash-chain", status: validation.ok ? "pass" : "fail", evidence: validation },
			{ id: "runtime:tool-call-trace-secret-redaction", status: !hasLiteralSecret(JSON.stringify(runtime.events ?? [])) ? "pass" : "fail", evidence: { secretRedactionOk: !hasLiteralSecret(JSON.stringify(runtime.events ?? [])) } },
			{ id: "runtime:tool-call-trace-replay-hints", status: (runtime.events ?? []).some((event) => event.toolName === "bash" && event.replay?.available) ? "pass" : "fail", evidence: { replayEvents: (runtime.events ?? []).filter((event) => event.replay?.available).length } },
			{ id: "runtime:tool-call-trace-report", status: runtime.report?.kind === "ToolCallTraceLedgerV1" && runtime.report?.eventCount >= 4 ? "pass" : "fail", evidence: { report: runtime.report } },
			...((fixture.negativeCases ?? []).map((negative) => negativeCase(runtime.events ?? [], negative))),
			markerCheck("code:tool-call-trace-ledger-types", "packages/coding-agent/src/core/recon-profile.ts", ["type ToolCallTraceEventV1", "type ToolCallTraceLedgerV1", "function appendToolCallTraceFromCall", "function verifyToolCallTraceLedgerV1", "tool_call_observability_runtime"]),
			markerCheck("schema:tool-call-trace-ledger", SCHEMA_PATH, ["ToolCallTraceLedgerV1", "append_only_tool_trace", "secret_redaction_required", "replayable_tool_result_hashes"]),
			markerCheck("fixture:tool-call-trace-ledger", FIXTURE_PATH, ["repi-tool-call-trace-ledger-fixture", "negative:tool-trace-hash-drift", "negative:tool-trace-secret-leak", "negative:tool-trace-missing-replay"]),
			markerCheck("npm:tool-call-trace-ledger", "package.json", ["gate:tool-call-trace-ledger", "tool-call-trace-ledger-gate.mjs"]),
			markerCheck("harness:tool-call-trace-ledger", "scripts/reverse-agent/repi-top-harness.mjs", ["runtime:tool-call-trace-ledger", "child:gate:tool-call-trace-ledger"]),
			markerCheck("autonomy:tool-call-trace-ledger", "scripts/reverse-agent/autonomy-control-plane.mjs", ["tool_call_trace_ledger_gate", "ToolCallTraceLedgerV1", "append-only tool trace"]),
			markerCheck("docs:tool-call-trace-ledger", "README.md", ["ToolCallTraceLedgerV1", "gate:tool-call-trace-ledger"]),
		];
		const result = { kind: "repi-tool-call-trace-ledger-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: checks.every((check) => check.status === "pass"), root, runtime, checks };
		result.evidencePath = writeEvidenceFile(result);
		if (json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
		else process.stdout.write(formatMarkdown(result));
		if (strict && !result.ok) process.exitCode = 1;
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
}

main().catch((error) => { console.error(error); process.exit(1); });
