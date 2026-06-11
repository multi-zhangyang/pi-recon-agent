#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_ARTIFACT_SCOPE_TMP === "1";
const writeEvidence = !argv.includes("--no-write");
const SCHEMA_PATH = "schemas/reverse-agent/artifact-scope-filter.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/artifact-scope-filter.fixture.json";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

function check(id, status, evidence = {}) {
	return { id, status: status ? "pass" : "fail", evidence };
}

function validateFixture(fixture) {
	const required = [
		"ArtifactScopeFilterV1",
		"MemoryScopeIsolationV1",
		"latest_artifact_side_channel_scope_filter",
		"artifact_hash_path_matches_memory_scope",
		"blocked_latest_artifact_quarantined",
		"context_artifact_index_excludes_scope_blocked_artifacts",
		"artifact_scope_filter_report_in_context_pack",
	];
	const gates = new Set(fixture.requiredGates ?? []);
	const scenarioIds = new Set((fixture.scenarios ?? []).map((scenario) => scenario.id));
	return {
		missingGates: required.filter((gate) => !gates.has(gate)),
		missingScenarios: [
			"blocked-latest-artifact-skipped",
			"older-allowed-artifact-selected",
			"artifact-scope-report-embedded-in-context-pack",
		].filter((id) => !scenarioIds.has(id)),
	};
}

function writeProbe(probePath, outPath, tempRoot) {
	const importUrl = pathToFileURL(join(root, "packages/coding-agent/src/core/recon-profile.ts")).href;
	writeFileSync(
		probePath,
		`
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createReconExtensionFactory } from ${JSON.stringify(importUrl)};

const outPath = ${JSON.stringify(outPath)};
const tempRoot = ${JSON.stringify(tempRoot)};
const agentDir = join(tempRoot, "agent");
const workspaceA = join(tempRoot, "workspace-a");
const workspaceB = join(tempRoot, "workspace-b");
const runsDir = join(agentDir, "recon", "evidence", "runs");
mkdirSync(agentDir, { recursive: true });
mkdirSync(workspaceA, { recursive: true });
mkdirSync(workspaceB, { recursive: true });
mkdirSync(runsDir, { recursive: true });
const blockedArtifact = join(runsDir, "2026-06-11-z-blocked-target-a.md");
const allowedArtifact = join(runsDir, "2026-06-11-a-allowed-target-b.md");
writeFileSync(blockedArtifact, ["# blocked latest target-a runtime", "", "curl https://target-a.local/api/blocked-only-command", "blocked-only-command must be quarantined from context latest selection"].join("\\n"));
writeFileSync(allowedArtifact, ["# allowed older target-b runtime", "", "curl https://target-b.local/api/allowed-command", "allowed-command should remain in context artifact index"].join("\\n"));
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_BRANCH_ID = "artifact-scope-main";
const tools = new Map();
const fakePi = { registerCommand() {}, registerTool(tool) { tools.set(tool.name, tool); }, on() {}, appendEntry() {}, getSessionName: () => undefined, setSessionName() {}, sendMessage() {}, exec: async () => ({ code: 0, stdout: "artifact-scope-probe", stderr: "", killed: false }) };
createReconExtensionFactory()(fakePi);
const memory = tools.get("re_memory");
const context = tools.get("re_context");
if (!memory) throw new Error("missing re_memory tool");
if (!context) throw new Error("missing re_context tool");
function text(result) { return result?.content?.[0]?.text ?? ""; }
function parseJsonArtifact(path) {
  const body = readFileSync(path, "utf8");
  const start = body.indexOf("\`\`\`json");
  if (start < 0) throw new Error("missing json block in " + path);
  const contentStart = body.indexOf("\\n", start);
  const end = body.indexOf("\`\`\`", contentStart + 1);
  if (contentStart < 0 || end < 0) throw new Error("unterminated json block in " + path);
  return JSON.parse(body.slice(contentStart + 1, end).trim());
}
async function append(title, options) {
  const body = [
    "target=" + options.target,
    "route=Security general",
    "outcome=success",
    "confidence=0.98",
    "replayVerified=true",
    "playbookCandidate=true",
    "verifierRuleCandidate=true",
    "artifactPath=" + options.artifact,
    "runtime artifact command " + options.command,
    "curl " + options.target + "/api/" + options.command,
    "re_context pack " + options.target,
  ].join(" ");
  const result = await memory.execute("artifact-scope", { action: "append", scene: "web", title, text: body });
  return result.details.event;
}
async function main() {
  process.chdir(workspaceA);
  process.env.REPI_SESSION_ID = "session-a";
  const blockedEvent = await append("blocked-target-a-latest", { target: "https://target-a.local", artifact: blockedArtifact, command: "blocked-only-command" });

  process.chdir(workspaceB);
  process.env.REPI_SESSION_ID = "session-b";
  const allowedEvent = await append("allowed-target-b-older", { target: "https://target-b.local", artifact: allowedArtifact, command: "allowed-command" });

  const contextResult = await context.execute("artifact-scope", { action: "pack", target: "https://target-b.local" });
  const contextPath = contextResult.details.path || /^context_artifact:\s*(.+)$/m.exec(text(contextResult))?.[1]?.trim();
  if (!contextPath) throw new Error("missing context artifact path: " + text(contextResult).slice(0, 500));
  const contextPack = parseJsonArtifact(contextPath);
  const reportPath = contextPack.artifactScopeFilter.reportPath;
  const filterReport = JSON.parse(readFileSync(reportPath, "utf8"));
  const memoryResult = await memory.execute("artifact-scope", { action: "artifact-scope-filter", query: "https://target-b.local" });
  writeFileSync(outPath, JSON.stringify({
    tempRoot,
    agentDir,
    blockedArtifact,
    allowedArtifact,
    blockedEvent,
    allowedEvent,
    contextText: text(contextResult),
    contextPath,
    contextPack,
    filterReport,
    memoryText: text(memoryResult),
    memoryDetails: memoryResult.details,
  }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`,
		"utf8",
	);
}

function runProbe(tempRoot) {
	const probePath = join(tempRoot, "artifact-scope-filter-probe.ts");
	const outPath = join(tempRoot, "probe-result.json");
	writeProbe(probePath, outPath, tempRoot);
	const tsx = join(root, "node_modules", ".bin", "tsx");
	const result = spawnSync(tsx, ["--tsconfig", join(root, "tsconfig.json"), probePath], {
		cwd: root,
		env: { ...process.env, PI_OFFLINE: "1", REPI_OFFLINE: "1" },
		encoding: "utf8",
		maxBuffer: 40 * 1024 * 1024,
	});
	return { ...result, outPath, probePath };
}

function main() {
	const checks = [];
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-artifact-scope-filter-"));
	let probeData;
	try {
		const schema = readJson(SCHEMA_PATH);
		const fixture = readJson(FIXTURE_PATH);
		checks.push(check("schema:parse", schema?.$defs?.ArtifactScopeFilterV1 && schema?.$defs?.ArtifactScopeFilterDecisionV1, { path: SCHEMA_PATH }));
		const fixtureEval = validateFixture(fixture);
		checks.push(check("fixture:artifact-scope-scenarios", fixtureEval.missingGates.length === 0 && fixtureEval.missingScenarios.length === 0, fixtureEval));
		const probe = runProbe(tempRoot);
		checks.push(check("runtime:probe-exit", probe.status === 0, { code: probe.status, signal: probe.signal, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) }));
		if (probe.status === 0 && existsSync(probe.outPath)) {
			probeData = JSON.parse(readFileSync(probe.outPath, "utf8"));
			const embedded = probeData.contextPack.artifactScopeFilter;
			const persisted = probeData.filterReport;
			const contextIndexText = JSON.stringify(probeData.contextPack.artifactIndex ?? []);
			const contextText = `${probeData.contextText}\n${contextIndexText}`;
			const decisions = new Map((persisted?.decisions ?? []).map((row) => [row.path, row]));
			checks.push(check("runtime:artifact-scope-embedded", embedded?.ArtifactScopeFilterV1 === true && embedded?.MemoryScopeIsolationV1 === true && probeData.contextText.includes("artifact_scope_filter"), { embedded }));
			checks.push(check("runtime:blocked-latest-artifact-quarantined", embedded?.quarantinedArtifacts?.includes(probeData.blockedArtifact) && decisions.get(probeData.blockedArtifact)?.blocksArtifactReuse === true, { row: decisions.get(probeData.blockedArtifact), quarantined: embedded?.quarantinedArtifacts }));
			checks.push(check("runtime:context-index-excludes-blocked-latest", !contextIndexText.includes(probeData.blockedArtifact) && !contextText.includes("blocked-only-command"), { artifactIndex: probeData.contextPack.artifactIndex }));
			checks.push(check("runtime:context-index-selects-allowed-older", contextIndexText.includes(probeData.allowedArtifact) && embedded?.allowedArtifacts?.includes(probeData.allowedArtifact), { artifactIndex: probeData.contextPack.artifactIndex }));
			checks.push(check("runtime:report-indexed-in-context", (probeData.contextPack.artifactIndex ?? []).some((artifact) => artifact.kind === "artifact_scope_filter" && artifact.path === embedded.reportPath), { artifactIndex: probeData.contextPack.artifactIndex, reportPath: embedded.reportPath }));
			checks.push(check("runtime:memory-tool-artifact-scope", probeData.memoryText.includes("ArtifactScopeFilterV1=true") && probeData.memoryDetails?.ArtifactScopeFilterV1 === true, { memoryText: probeData.memoryText.slice(0, 1200), memoryDetails: probeData.memoryDetails }));
			checks.push(check("runtime:required-gates", ["ArtifactScopeFilterV1", "MemoryScopeIsolationV1", "latest_artifact_side_channel_scope_filter", "blocked_latest_artifact_quarantined", "context_artifact_index_excludes_scope_blocked_artifacts", "artifact_scope_filter_report_in_context_pack"].every((gate) => embedded?.requiredGates?.includes(gate)), { requiredGates: embedded?.requiredGates }));
		} else {
			for (const id of ["runtime:artifact-scope-embedded", "runtime:blocked-latest-artifact-quarantined", "runtime:context-index-excludes-blocked-latest", "runtime:context-index-selects-allowed-older", "runtime:report-indexed-in-context", "runtime:memory-tool-artifact-scope", "runtime:required-gates"]) checks.push(check(id, false, { error: "probe output missing" }));
		}
		checks.push(check("code:artifact-scope-markers", ["ArtifactScopeFilterV1", "scopedContextArtifactIndex", "latest_artifact_side_channel_scope_filter", "context_artifact_index_excludes_scope_blocked_artifacts", "artifact_scope_filter_report_in_context_pack"].every((marker) => readText("packages/coding-agent/src/core/recon-profile.ts").includes(marker)), { markers: ["ArtifactScopeFilterV1", "scopedContextArtifactIndex"] }));
	} catch (error) {
		checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	const failed = checks.filter((row) => row.status !== "pass");
	const result = { kind: "repi-artifact-scope-filter-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, tempRoot: keepTmp ? tempRoot : undefined, checks };
	if (writeEvidence) {
		const dir = join(root, ".repi-harness", "evidence", "artifact-scope-filter", result.generatedAt.replace(/[:.]/g, "-"));
		mkdirSync(dir, { recursive: true });
		writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
		if (probeData) writeFileSync(join(dir, "probe-result.json"), `${JSON.stringify(probeData, null, 2)}\n`, "utf8");
	}
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Artifact Scope Filter Gate");
		for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
		console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
	}
	if (strict && failed.length) process.exit(1);
}

main();
