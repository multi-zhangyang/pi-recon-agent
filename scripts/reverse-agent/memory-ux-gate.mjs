#!/usr/bin/env node
// repi-memory-ux-gate: MemoryUxDashboardV16 user_visible_memory_status recall_explainability append_only_memory_governance
import { spawnSync } from "node:child_process";
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
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_MEMORY_UX_TMP === "1";
const writeEvidence = !argv.includes("--no-write");
const SCHEMA_PATH = "schemas/reverse-agent/memory-ux-dashboard.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/memory-ux-dashboard.fixture.json";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

function check(id, ok, evidence = {}) {
	return { id, status: ok ? "pass" : "fail", evidence };
}

function markerCheck(id, path, markers) {
	if (!existsSync(join(root, path))) return check(id, false, { path, exists: false });
	const text = readText(path);
	const missing = markers.filter((marker) => !text.includes(marker));
	return check(id, missing.length === 0, { path, missing, sha256: sha256(text).slice(0, 16) });
}

function validateDashboard(report) {
	const errors = [];
	if (report?.kind !== "repi-memory-ux-dashboard") errors.push("kind");
	for (const marker of ["MemoryUxDashboardV16", "user_visible_memory_status", "recall_explainability", "append_only_memory_governance", "lifecycle_governance_commands"]) {
		if (report?.[marker] !== true) errors.push(marker);
	}
	if (!report?.statusReportPath || !report?.statusBoardPath || !report?.governanceLedgerPath) errors.push("paths");
	if (!report?.store || typeof report.store.eventCount !== "number" || typeof report.store.hashChainOk !== "boolean") errors.push("store");
	if (!report?.recall || typeof report.recall.hitCount !== "number" || !Array.isArray(report.recall.whyRows)) errors.push("recall");
	if ((report?.recall?.hitCount ?? 0) > 0 && !report.recall.whyRows.length) errors.push("recall_explainability_requires_why_rows_when_hits_exist");
	if (!Array.isArray(report?.governanceCommands) || !report.governanceCommands.some((cmd) => /re_memory (?:promote|demote|forget)/.test(cmd))) errors.push("lifecycle_governance_commands_required");
	if (!Array.isArray(report?.requiredGates) || !report.requiredGates.includes("MemoryUxDashboardV16")) errors.push("requiredGates");
	return errors;
}

function mutateFixture(sample, negative) {
	const clone = JSON.parse(JSON.stringify(sample));
	if (negative.mutate === "clearWhyRows") clone.recall.whyRows = [];
	if (negative.mutate === "clearGovernanceCommands") clone.governanceCommands = [];
	return clone;
}

function writeProbe(probePath, outPath, tempRoot) {
	const importUrl = pathToFileURL(join(root, "packages/coding-agent/src/core/recon-profile.ts")).href;
	writeFileSync(
		probePath,
		`
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createReconExtensionFactory } from ${JSON.stringify(importUrl)};

const outPath = ${JSON.stringify(outPath)};
const tempRoot = ${JSON.stringify(tempRoot)};
const agentDir = join(tempRoot, "agent");
const workspace = join(tempRoot, "workspace");
const artifact = join(workspace, "authz-proof.txt");
mkdirSync(agentDir, { recursive: true });
mkdirSync(workspace, { recursive: true });
writeFileSync(artifact, "MemoryUxDashboardV16 authz replay proof\\n");
process.chdir(workspace);
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_SESSION_ID = "memory-ux-session";
process.env.REPI_BRANCH_ID = "memory-ux-branch";
const tools = new Map();
const fakePi = { registerCommand() {}, registerTool(tool) { tools.set(tool.name, tool); }, on() {}, appendEntry() {}, getSessionName: () => undefined, setSessionName() {}, sendMessage() {}, exec: async () => ({ code: 0, stdout: "memory-ux", stderr: "", killed: false }) };
createReconExtensionFactory()(fakePi);
const memory = tools.get("re_memory");
if (!memory) throw new Error("missing re_memory tool");
function text(result) { return result?.content?.[0]?.text ?? ""; }
async function main() {
  await memory.execute("memory-ux", { action: "append", scene: "web/authz", title: "authz ownership replay", text: "target=https://ux.local route=web/authz outcome=success confidence=0.95 replayVerified=true playbookCandidate=true verifierRuleCandidate=true artifactPath=" + artifact + " re_operator plan authz; re_verifier matrix" });
  const status = await memory.execute("memory-ux", { action: "status", query: "authz ownership replay", route: "web/authz", target: "https://ux.local" });
  const firstEventId = status.details?.recall?.whyRows?.[0]?.eventId;
  const why = await memory.execute("memory-ux", { action: "why", query: "authz ownership replay", route: "web/authz", target: "https://ux.local" });
  const promote = await memory.execute("memory-ux", { action: "promote", query: firstEventId, text: "verified reuse improved plan during memory UX gate" });
  const forget = await memory.execute("memory-ux", { action: "forget", query: firstEventId, text: "tombstone branch verifies append-only governance" });
  const finalStatus = await memory.execute("memory-ux", { action: "status", query: "authz ownership replay", route: "web/authz", target: "https://ux.local" });
  const report = finalStatus.details;
  writeFileSync(outPath, JSON.stringify({
    agentDir,
    firstEventId,
    statusText: text(status),
    whyText: text(why),
    promoteText: text(promote),
    forgetText: text(forget),
    report,
    statusReportExists: existsSync(report.statusReportPath),
    statusBoardExists: existsSync(report.statusBoardPath),
    governanceLedgerExists: existsSync(report.governanceLedgerPath),
    governanceLedgerTail: existsSync(report.governanceLedgerPath) ? readFileSync(report.governanceLedgerPath, "utf8").slice(-2000) : ""
  }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`,
		"utf8",
	);
}

function runProbe(tempRoot) {
	const probePath = join(tempRoot, "memory-ux-probe.ts");
	const outPath = join(tempRoot, "probe-result.json");
	writeProbe(probePath, outPath, tempRoot);
	const tsx = join(root, "node_modules", ".bin", "tsx");
	const result = spawnSync(tsx, ["--tsconfig", join(root, "tsconfig.json"), probePath], {
		cwd: root,
		env: { ...process.env, PI_OFFLINE: "1", REPI_OFFLINE: "1", REPI_REPO_ROOT: root },
		encoding: "utf8",
		maxBuffer: 60 * 1024 * 1024,
	});
	return { ...result, outPath, probePath };
}

function writeEvidenceFile(data) {
	if (!writeEvidence) return undefined;
	const stamp = new Date().toISOString().replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "memory-ux", stamp);
	mkdirSync(dir, { recursive: true });
	const path = join(dir, "result.json");
	writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`, "utf8");
	return path;
}

function main() {
	const checks = [];
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-memory-ux-"));
	let probeData;
	try {
		const schema = readJson(SCHEMA_PATH);
		const fixture = readJson(FIXTURE_PATH);
		checks.push(check("schema:parse", schema?.$defs?.MemoryUxDashboardV16 && schema?.$defs?.MemoryUxWhyRowV16, { path: SCHEMA_PATH }));
		checks.push(check("fixture:sample-dashboard", validateDashboard(fixture.sample).length === 0, { errors: validateDashboard(fixture.sample) }));
		for (const negative of fixture.negativeScenarios ?? []) {
			const errors = validateDashboard(mutateFixture(fixture.sample, negative));
			checks.push(check(`negative:${negative.id}`, errors.includes(negative.expectError), { errors, expectError: negative.expectError }));
		}
		const probe = runProbe(tempRoot);
		checks.push(check("runtime:probe-exit", probe.status === 0, { code: probe.status, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) }));
		if (probe.status === 0 && existsSync(probe.outPath)) {
			probeData = JSON.parse(readFileSync(probe.outPath, "utf8"));
			const errors = validateDashboard(probeData.report);
			checks.push(check("runtime:memory-ux-dashboard", errors.length === 0, { errors, firstEventId: probeData.firstEventId }));
			checks.push(check("runtime:why-this-memory-visible", /why_this_memory|recall_explainability/i.test(probeData.statusText) && /why_this_memory/i.test(probeData.whyText), { statusText: probeData.statusText.slice(0, 1200), whyText: probeData.whyText.slice(0, 800) }));
			checks.push(check("runtime:append-only-governance", /memory-ux:promote|memory-ux:forget|append_only_memory_governance/i.test(probeData.governanceLedgerTail) && /new_event=mem:/i.test(probeData.promoteText + probeData.forgetText), { governanceLedgerTail: probeData.governanceLedgerTail }));
			checks.push(check("runtime:memory-status-artifacts", probeData.statusReportExists && probeData.statusBoardExists && probeData.governanceLedgerExists, { statusReportExists: probeData.statusReportExists, statusBoardExists: probeData.statusBoardExists, governanceLedgerExists: probeData.governanceLedgerExists }));
			const evidencePath = writeEvidenceFile(probeData);
			if (evidencePath) checks.push(check("evidence:written", true, { path: evidencePath }));
		}
		checks.push(markerCheck("code:memory-ux-source", "packages/coding-agent/src/core/recon-profile.ts", ["MemoryUxDashboardV16", "buildMemoryUxDashboard", "formatMemoryUxDashboard", "memoryStatusReportPath", "recall_explainability", "append_only_memory_governance"]));
		checks.push(markerCheck("profile:memory-ux-mirror", "repi-profile/extensions/reverse-pentest-core.ts", ["MemoryUxDashboardV16", "buildMemoryUxDashboard", "formatMemoryUxDashboard", "memoryStatusReportPath", "recall_explainability", "append_only_memory_governance"]));
		checks.push(markerCheck("docs:memory-ux-readme", "README.md", ["MemoryUxDashboardV16", "re_memory status", "re_memory why", "re_memory promote", "status-board.md"]));
		checks.push(markerCheck("docs:memory-ux-recon", "packages/coding-agent/docs/recon.md", ["MemoryUxDashboardV16", "user_visible_memory_status", "recall_explainability"]));
		checks.push(markerCheck("npm:memory-ux-script", "package.json", ["gate:memory-ux", "memory-ux-gate.mjs"]));
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	const ok = checks.every((item) => item.status === "pass");
	if (json) {
		console.log(JSON.stringify({ ok, checks }, null, 2));
	} else {
		console.log("# REPI Memory UX Gate");
		for (const item of checks) console.log(`- ${item.status.toUpperCase()} ${item.id}`);
		console.log(`summary: ${ok ? "pass" : "fail"} checks=${checks.length}`);
	}
	if (!ok && strict) process.exit(1);
}

main();
