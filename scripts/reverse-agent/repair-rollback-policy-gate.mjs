#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { failureRepairFromGap, validateFailureRepairBatch } from "./failure-repair-ledger.mjs";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const writeEvidence = !argv.includes("--no-write");
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_REPAIR_ROLLBACK_TMP === "1";
const FIXTURE_PATH = "fixtures/reverse-agent/repair-rollback-policy.fixture.json";
const SCHEMA_PATH = "schemas/reverse-agent/repair-rollback-policy.schema.json";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

function markerCheck(id, path, markers) {
	if (!existsSync(join(root, path))) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readText(path);
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function walkFiles(dir, prefix = dir) {
	const rows = [];
	if (!existsSync(dir)) return rows;
	for (const name of readdirSync(dir).sort()) {
		const full = join(dir, name);
		const stat = statSync(full);
		if (stat.isDirectory()) rows.push(...walkFiles(full, prefix));
		else if (stat.isFile()) {
			const bytes = readFileSync(full);
			rows.push({ path: relative(prefix, full), bytes: bytes.length, sha256: sha256(bytes) });
		}
	}
	return rows;
}

function snapshot(dir) {
	const files = walkFiles(dir);
	return { treeSha256: sha256(JSON.stringify(files)), files };
}

function regressionGate(workspace, expectedNeedle) {
	const target = readFileSync(join(workspace, "target.txt"), "utf8");
	return {
		gateId: "gate:repair-regression",
		command: `grep -q ${JSON.stringify(expectedNeedle)} target.txt`,
		status: target.includes(expectedNeedle) ? "pass" : "fail",
		expectedNeedle,
		artifactPath: "target.txt",
		artifactSha256: sha256(target),
	};
}

function validateRepairRollbackPolicyV1(report) {
	const errors = [];
	if (report?.kind !== "RepairRollbackPolicyV1") errors.push("repair_rollback_kind_invalid");
	if (report?.schemaVersion !== 1) errors.push("repair_rollback_schema_version_invalid");
	if (!report?.baseline?.treeSha256) errors.push("baseline_missing");
	if (!report?.baseline?.files?.length) errors.push("baseline_files_missing");
	if (!Array.isArray(report?.allowlist) || report.allowlist.length === 0) errors.push("allowlist_missing");
	const allowed = new Set(report?.allowlist ?? []);
	for (const file of report?.repair?.changedFiles ?? []) if (!allowed.has(file)) errors.push(`allowlist_violation:${file}`);
	if (report?.rollback?.required !== true) errors.push("rollback_required_missing");
	if (report?.rollback?.required && report?.rollback?.restored !== true) errors.push("rollback_not_restored");
	if (report?.rollback?.restoredTreeSha256 && report?.baseline?.treeSha256 && report.rollback.restoredTreeSha256 !== report.baseline.treeSha256)
		errors.push("rollback_tree_hash_mismatch");
	const gateRows = report?.regression?.gates ?? [];
	if (!gateRows.length) errors.push("regression_gate_missing");
	for (const row of gateRows) if (row.status !== "pass") errors.push(`regression_gate_failed:${row.gateId}`);
	if (report?.regression?.after !== "pass") errors.push("regression_after_not_pass");
	if (report?.regression?.restored !== "pass") errors.push("regression_restored_not_pass");
	if (!report?.assertions?.baselineCaptured) errors.push("assertion_baseline_not_captured");
	if (!report?.assertions?.allowlistEnforced) errors.push("assertion_allowlist_not_enforced");
	if (!report?.assertions?.rollbackRestored) errors.push("assertion_rollback_not_restored");
	if (!report?.assertions?.regressionGatesPassed) errors.push("assertion_regression_not_passed");
	if (!report?.assertions?.noUnrelatedFileChanges) errors.push("assertion_unrelated_file_changes");
	if (!report?.assertions?.failureRepairLinked) errors.push("assertion_failure_repair_not_linked");
	if (!report?.failureRepairValidation?.ok) errors.push("failure_repair_not_linked");
	if (!Array.isArray(report?.failureLedgerEvents) || report.failureLedgerEvents.length < 1) errors.push("failure_ledger_missing");
	if (!Array.isArray(report?.repairQueue) || !report.repairQueue.some((repair) => repair.action === "rollback" && repair.rollbackCriteria?.mustRestore?.length))
		errors.push("repair_rollback_queue_missing");
	return { ok: errors.length === 0, errors };
}

function buildRuntimeReport(tempRoot) {
	const workspace = join(tempRoot, "workspace");
	mkdirSync(workspace, { recursive: true });
	const targetPath = join(workspace, "target.txt");
	writeFileSync(targetPath, "BASELINE_OK\n", "utf8");
	const before = snapshot(workspace);
	const beforeGate = regressionGate(workspace, "BASELINE_OK");
	writeFileSync(targetPath, "PATCHED_OK\n", "utf8");
	const after = snapshot(workspace);
	const afterGate = regressionGate(workspace, "PATCHED_OK");
	writeFileSync(targetPath, "BASELINE_OK\n", "utf8");
	const restored = snapshot(workspace);
	const restoredGate = regressionGate(workspace, "BASELINE_OK");
	const changedFiles = before.files
		.filter((row) => after.files.find((afterRow) => afterRow.path === row.path)?.sha256 !== row.sha256)
		.map((row) => row.path);
	const allowlist = ["target.txt"];
	const restoredOk = restored.treeSha256 === before.treeSha256;
	const { failure, repair } = failureRepairFromGap({
		root: workspace,
		source: "re_autofix",
		scope: "repair-rollback-policy:runtime-autofix",
		reason: "state changing repair must keep baseline, allowlist, regression gate and rollback proof",
		category: "runtime_failed",
		failedGates: ["gate:repair-regression"],
		artifacts: ["target.txt"],
		rollbackRequired: true,
		allowlist,
		rollbackCriteria: ["restore baseline tree hash", "no unrelated file changes", "previous passed gates remain passed"],
		commands: ["printf PATCHED_OK > target.txt", "printf BASELINE_OK > target.txt"],
		expectedArtifacts: ["target.txt"],
		regressionGates: ["gate:repair-regression", "gate:repair-rollback-policy"],
		action: "rollback",
		liveAllowed: true,
		providerAllowed: false,
		paused: false,
		verificationCommand: "node scripts/reverse-agent/repair-rollback-policy-gate.mjs . --strict",
	});
	failure.rollback.restored = restoredOk;
	repair.rollbackCriteria.mustRestore = allowlist;
	repair.allowlist = allowlist;
	repair.regressionGates = ["gate:repair-regression", "gate:repair-rollback-policy"];
	const failureRepairValidation = validateFailureRepairBatch({ failureLedgerEvents: [failure], repairQueue: [repair] });
	const report = {
		kind: "RepairRollbackPolicyV1",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		source: "re_autofix",
		workspace,
		baseline: { command: "snapshot(workspace)", treeSha256: before.treeSha256, files: before.files },
		allowlist,
		repair: {
			commands: ["printf PATCHED_OK > target.txt"],
			changedFiles,
			expectedArtifacts: ["target.txt"],
			regressionGates: ["gate:repair-regression", "gate:repair-rollback-policy"],
		},
		rollback: {
			required: true,
			commands: ["printf BASELINE_OK > target.txt"],
			restored: restoredOk,
			restoredTreeSha256: restored.treeSha256,
			criteria: ["restore baseline tree hash", "no unrelated file changes", "previous passed gates remain passed"],
		},
		regression: {
			before: beforeGate.status,
			after: afterGate.status,
			restored: restoredGate.status,
			gates: [afterGate, restoredGate],
		},
		failureLedgerEvents: [failure],
		repairQueue: [repair],
		failureRepairValidation,
		assertions: {
			baselineCaptured: Boolean(before.treeSha256 && before.files.length),
			allowlistEnforced: changedFiles.every((file) => allowlist.includes(file)),
			rollbackRestored: restoredOk,
			regressionGatesPassed: afterGate.status === "pass" && restoredGate.status === "pass",
			noUnrelatedFileChanges: changedFiles.every((file) => allowlist.includes(file)) && restoredOk,
			failureRepairLinked: failureRepairValidation.ok,
		},
	};
	return report;
}

function mutateReport(report, negative) {
	const clone = JSON.parse(JSON.stringify(report));
	if (negative.mutate === "removeBaseline") {
		clone.baseline.treeSha256 = "";
		clone.baseline.files = [];
		clone.assertions.baselineCaptured = false;
	}
	if (negative.mutate === "allowlistViolation") {
		clone.repair.changedFiles.push("secrets.env");
		clone.assertions.allowlistEnforced = false;
		clone.assertions.noUnrelatedFileChanges = false;
	}
	if (negative.mutate === "rollbackNotRestored") {
		clone.rollback.restored = false;
		clone.rollback.restoredTreeSha256 = sha256("wrong-tree");
		clone.assertions.rollbackRestored = false;
	}
	if (negative.mutate === "missingRegressionGate") {
		clone.regression.gates = [];
		clone.regression.after = "fail";
		clone.assertions.regressionGatesPassed = false;
	}
	if (negative.mutate === "failureRepairUnlinked") {
		clone.repairQueue = [];
		clone.failureRepairValidation = { ok: false, failureCount: 1, repairCount: 0 };
		clone.assertions.failureRepairLinked = false;
	}
	return clone;
}

function negativeCase(report, negative) {
	const result = validateRepairRollbackPolicyV1(mutateReport(report, negative));
	const missing = (negative.expectedErrors ?? []).filter((needle) => !result.errors.some((error) => error.includes(needle)));
	return { id: `negative:${negative.id}`, status: !result.ok && missing.length === 0 ? "pass" : "fail", evidence: { validation: result, missing } };
}

function fixtureChecks(report) {
	const checks = [];
	try {
		const fixture = readJson(FIXTURE_PATH);
		const valid = validateRepairRollbackPolicyV1(fixture.valid);
		checks.push({ id: "fixture:repair-rollback-valid", status: valid.ok ? "pass" : "fail", evidence: valid });
		for (const negative of fixture.negativeCases ?? []) checks.push(negativeCase(report, negative));
	} catch (error) {
		checks.push({ id: "fixture:repair-rollback-load", status: "fail", evidence: { error: String(error) } });
	}
	return checks;
}


function writeLiveProbe(probePath, outPath, tempRoot) {
	const importUrl = pathToFileURL(join(root, "packages/coding-agent/src/core/recon-profile.ts")).href;
	writeFileSync(probePath, `
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createReconExtensionFactory } from ${JSON.stringify(importUrl)};
const outPath = ${JSON.stringify(outPath)};
const tempRoot = ${JSON.stringify(tempRoot)};
const agentDir = join(tempRoot, "agent");
const workspace = join(tempRoot, "workspace");
mkdirSync(agentDir, { recursive: true });
mkdirSync(workspace, { recursive: true });
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_SESSION_ID = "repair-rollback-live";
process.env.REPI_BRANCH_ID = "repair-rollback-branch";
process.chdir(workspace);
const tools = new Map();
const fakePi = {
  registerCommand() {},
  registerTool(tool) { tools.set(tool.name, tool); },
  on() {}, appendEntry() {}, getSessionName: () => undefined, setSessionName() {}, sendMessage() {},
  exec: async () => ({ code: 0, stdout: "ok", stderr: "", killed: false })
};
createReconExtensionFactory()(fakePi);
const compilerDir = join(agentDir, "recon", "evidence", "compilers");
mkdirSync(compilerDir, { recursive: true });
const sourcePath = join(workspace, "source.txt");
writeFileSync(sourcePath, "BASELINE_OK\\n", "utf8");
const compiler = {
  timestamp: new Date().toISOString(),
  route: "repair-rollback-live",
  target: "repair-rollback-live",
  mode: "draft",
  operatorFeedback: [],
  statusSummary: { proved: 0, weak: 0, contradicted: 0, missing: 1 },
  outcome: ["gap"],
  keyEvidence: [],
  reproCommands: ["printf replay-ok"],
  contradictions: [],
  gaps: ["compiler gap requires state-changing repair scaffold"],
  nextOperatorQueue: [],
  finalReport: [],
  releaseGateMetadata: [],
  claimGatePolicy: [],
  claimGateResult: [],
  sourceArtifacts: [sourcePath]
};
const compilerPath = join(compilerDir, "9999-repair-rollback-live-draft.md");
writeFileSync(compilerPath, ["# REPI Compiler Artifact", "", "\`\`\`json", JSON.stringify(compiler, null, 2), "\`\`\`", ""].join("\\n"));
const autofix = tools.get("re_autofix");
if (!autofix) throw new Error("missing re_autofix tool");
async function main() {
  const result = await autofix.execute("repair-rollback-live", { action: "plan" });
  const text = result.content?.[0]?.text ?? "";
  const policyPath = /repair_rollback_policy:[\\s\\S]*?- path=([^\\n]+)/.exec(text)?.[1]?.trim();
  const policyWrapper = policyPath && existsSync(policyPath) ? JSON.parse(readFileSync(policyPath, "utf8")) : undefined;
  writeFileSync(outPath, JSON.stringify({ compilerPath, policyPath, policyWrapper, text }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`, "utf8");
}

function runLiveProbe(tempRoot) {
	const probePath = join(tempRoot, "repair-rollback-live-probe.ts");
	const outPath = join(tempRoot, "live-probe-result.json");
	writeLiveProbe(probePath, outPath, tempRoot);
	const tsx = join(root, "node_modules", ".bin", "tsx");
	const result = spawnSync(tsx, ["--tsconfig", join(root, "tsconfig.json"), probePath], { cwd: root, env: { ...process.env, PI_OFFLINE: "1", REPI_OFFLINE: "1", REPI_REPO_ROOT: root }, encoding: "utf8", maxBuffer: 30 * 1024 * 1024 });
	return { ...result, outPath, probePath };
}

function validateLiveProbe(probeData) {
	const wrapper = probeData.policyWrapper;
	const report = wrapper?.report ?? wrapper;
	const validation = validateRepairRollbackPolicyV1(report);
	const errors = [...validation.errors];
	if (!validation.ok) errors.push("live_repair_rollback_validation_failed");
	if (wrapper?.validation?.ok !== true) errors.push("live_embedded_validation_not_pass");
	if (!probeData.policyPath || !probeData.policyPath.endsWith("-repair-rollback-policy.json")) errors.push("live_policy_path_missing");
	if (!String(probeData.text ?? "").includes("repair_rollback_policy:")) errors.push("live_output_missing_policy_section");
	if (!String(probeData.text ?? "").includes("- status=pass")) errors.push("live_output_missing_pass_status");
	if (!report?.repairQueue?.some((repair) => repair.action === "rollback")) errors.push("live_rollback_repair_missing");
	if (!report?.failureLedgerEvents?.length) errors.push("live_failure_ledger_missing");
	if (!report?.assertions?.baselineCaptured || !report?.assertions?.allowlistEnforced || !report?.assertions?.rollbackRestored) errors.push("live_assertions_missing");
	return errors;
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "repair-rollback-policy", stamp);
	mkdirSync(dir, { recursive: true });
	const path = join(dir, "report.json");
	writeFileSync(path, JSON.stringify(result, null, 2));
	return path;
}

function formatMarkdown(result) {
	const lines = ["# REPI Repair Rollback Policy Gate", "", `generated_at: ${result.generatedAt}`, `ok: ${result.ok}`, `workspace: ${result.report.workspace}`, "", "## Checks"];
	for (const check of result.checks) lines.push(`- ${check.id}: ${check.status}`);
	if (result.evidencePath) lines.push("", `evidence: ${result.evidencePath}`);
	return `${lines.join("\n")}\n`;
}

async function main() {
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-repair-rollback-policy-"));
	let report;
	try {
		report = buildRuntimeReport(tempRoot);
		const runtimeValidation = validateRepairRollbackPolicyV1(report);
		const checks = [
			{ id: "runtime:repair-baseline-snapshot", status: report.assertions.baselineCaptured ? "pass" : "fail", evidence: { treeSha256: report.baseline.treeSha256, files: report.baseline.files.length } },
			{ id: "runtime:repair-allowlist-enforced", status: report.assertions.allowlistEnforced ? "pass" : "fail", evidence: { allowlist: report.allowlist, changedFiles: report.repair.changedFiles } },
			{ id: "runtime:repair-rollback-restored", status: report.assertions.rollbackRestored ? "pass" : "fail", evidence: { baseline: report.baseline.treeSha256, restored: report.rollback.restoredTreeSha256 } },
			{ id: "runtime:repair-regression-gates-pass", status: report.assertions.regressionGatesPassed ? "pass" : "fail", evidence: report.regression },
			{ id: "runtime:repair-failure-ledger-linked", status: report.assertions.failureRepairLinked ? "pass" : "fail", evidence: report.failureRepairValidation },
			{ id: "runtime:repair-rollback-policy-validation", status: runtimeValidation.ok ? "pass" : "fail", evidence: runtimeValidation },
			...fixtureChecks(report),
			markerCheck("code:repair-rollback-policy-types", "packages/coding-agent/src/core/recon-profile.ts", ["type RepairRollbackPolicyV1", "function verifyRepairRollbackPolicyV1", "function buildRepairRollbackPolicyFromAutofix", "function writeAutofixRepairRollbackPolicy", "repairRollbackPolicyPath", "runtime:repair-rollback-live-wiring", "repair_rollback_tree_hash_mismatch"]),
			markerCheck("schema:repair-rollback-policy", SCHEMA_PATH, ["RepairRollbackPolicyV1", "baseline_required_before_repair", "allowlist_violation_blocks_repair", "rollback_tree_hash_must_match_baseline"]),
			markerCheck("fixture:repair-rollback-policy", FIXTURE_PATH, ["repi-repair-rollback-policy-fixture", "negative:repair-allowlist-violation", "negative:repair-rollback-not-restored", "negative:repair-missing-regression-gate"]),
			markerCheck("npm:repair-rollback-policy", "package.json", ["gate:repair-rollback-policy", "repair-rollback-policy-gate.mjs"]),
			markerCheck("harness:repair-rollback-policy", "scripts/reverse-agent/repi-top-harness.mjs", ["repair:rollback-policy-hard-eval", "repair:rollback-policy-live-wiring", "child:gate:repair-rollback-policy"]),
			markerCheck("autonomy:repair-rollback-policy", "scripts/reverse-agent/autonomy-control-plane.mjs", ["repair_rollback_policy_gate", "RepairRollbackPolicyV1", "baseline/allowlist/regression/rollback", "runtime:repair-rollback-live-wiring"]),
			markerCheck("docs:repair-rollback-policy", "README.md", ["RepairRollbackPolicyV1", "gate:repair-rollback-policy", "runtime:repair-rollback-live-wiring", "repairRollbackPolicyPath"]),
		];
		const liveProbe = runLiveProbe(tempRoot);
		checks.push({ id: "runtime:repair-rollback-live-probe-exit", status: liveProbe.status === 0 ? "pass" : "fail", evidence: { code: liveProbe.status, stdoutTail: (liveProbe.stdout ?? "").slice(-2000), stderrTail: (liveProbe.stderr ?? "").slice(-4000) } });
		if (liveProbe.status === 0 && existsSync(liveProbe.outPath)) {
			const probeData = JSON.parse(readFileSync(liveProbe.outPath, "utf8"));
			const liveErrors = validateLiveProbe(probeData);
			checks.push({ id: "runtime:repair-rollback-live-wiring", status: liveErrors.length ? "fail" : "pass", evidence: { errors: liveErrors, policyPath: probeData.policyPath, rollbackQueue: probeData.policyWrapper?.report?.repairQueue?.length ?? 0 } });
		} else {
			checks.push({ id: "runtime:repair-rollback-live-wiring", status: "fail", evidence: { error: "probe output missing" } });
		}
		const result = {
			kind: "repi-repair-rollback-policy-gate",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: checks.every((check) => check.status === "pass"),
			root,
			report,
			checks,
		};
		result.evidencePath = writeEvidenceFile(result);
		if (json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
		else process.stdout.write(formatMarkdown(result));
		if (strict && !result.ok) process.exitCode = 1;
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
}

main().catch((error) => {
	console.error(error);
	process.exit(1);
});
