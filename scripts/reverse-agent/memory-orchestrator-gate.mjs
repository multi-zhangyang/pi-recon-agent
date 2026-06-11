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
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_MEMORY_ORCHESTRATOR_TMP === "1";
const writeEvidence = !argv.includes("--no-write");
const SCHEMA_PATH = "schemas/reverse-agent/memory-orchestrator.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/memory-orchestrator.fixture.json";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

function check(id, status, evidence = {}) {
	return { id, status: status ? "pass" : "fail", evidence };
}

function typeOk(value, type) {
	if (Array.isArray(type)) return type.some((item) => typeOk(value, item));
	if (type === "array") return Array.isArray(value);
	if (type === "object") return value !== null && typeof value === "object" && !Array.isArray(value);
	if (type === "integer") return Number.isInteger(value);
	if (type === "number") return typeof value === "number" && Number.isFinite(value);
	if (type === "null") return value === null;
	return typeof value === type;
}

function resolveRef(schema, ref) {
	if (!ref?.startsWith("#/$defs/")) throw new Error(`unsupported ref: ${ref}`);
	return schema.$defs?.[ref.slice("#/$defs/".length)];
}

function validateSchema(value, node, schema, path = "$") {
	if (!node) return [];
	if (node.$ref) return validateSchema(value, resolveRef(schema, node.$ref), schema, path);
	const errors = [];
	if (node.const !== undefined && value !== node.const) errors.push(`${path}: const ${JSON.stringify(node.const)} expected`);
	if (node.enum && !node.enum.includes(value)) errors.push(`${path}: enum ${node.enum.join("|")} expected`);
	if (node.type && !typeOk(value, node.type)) {
		errors.push(`${path}: type ${JSON.stringify(node.type)} expected`);
		return errors;
	}
	if (typeof value === "string") {
		if (node.minLength && value.length < node.minLength) errors.push(`${path}: minLength ${node.minLength}`);
		if (node.pattern && !new RegExp(node.pattern).test(value)) errors.push(`${path}: pattern ${node.pattern}`);
		if (node.format === "date-time" && Number.isNaN(Date.parse(value))) errors.push(`${path}: invalid date-time`);
	}
	if (Array.isArray(value)) {
		if (node.minItems && value.length < node.minItems) errors.push(`${path}: minItems ${node.minItems}`);
		if (node.items) value.forEach((item, index) => errors.push(...validateSchema(item, node.items, schema, `${path}[${index}]`)));
	}
	if (value && typeof value === "object" && !Array.isArray(value)) {
		for (const key of node.required ?? []) if (!(key in value)) errors.push(`${path}.${key}: required`);
		for (const [key, propSchema] of Object.entries(node.properties ?? {})) {
			if (key in value) errors.push(...validateSchema(value[key], propSchema, schema, `${path}.${key}`));
		}
		if (node.additionalProperties === false) {
			const allowed = new Set(Object.keys(node.properties ?? {}));
			for (const key of Object.keys(value)) if (!allowed.has(key)) errors.push(`${path}.${key}: additionalProperty`);
		}
	}
	return errors;
}

function validateFixture(fixture) {
	const required = [
		"MemoryOrchestratorV6",
		"mandatory_memory_control_loop",
		"pre_task_retrieve_before_operator",
		"scope_filter_before_memory_injection",
		"post_tool_writeback_contract",
		"MemorySkillCapsuleV9",
		"skill_capsule_assetization",
		"verified_skill_promotion_gate",
		"operator_skill_injection",
		"MemoryDistillPromotionV10",
		"provider_distill_contract",
		"artifact_to_claim_distillation",
		"verifier_backed_promotion_gate",
		"skill_capsule_promotion_writeback",
		"MemoryQualityLedgerV11",
		"active_memory_policy",
		"quality_score_feedback_loop",
		"usefulness_feedback_writeback",
		"MemoryStrategyCapsuleV13",
		"executable_strategy_capsule",
		"replay_backed_strategy_promotion",
		"strategy_quality_gate",
		"strategy_capsule_operator_injection",
		"MemoryActiveKernelV14",
		"unified_memory_decision_engine",
		"active_recall_scheduler",
		"quality_replay_strategy_fusion",
		"scope_safe_strategy_injection",
		"feedback_driven_promotion",
		"cross_session_compact_ready",
		"MemoryMaturationRuntimeV15",
		"automatic_memory_maturation_pipeline",
		"tool_result_to_strategy_loop",
		"closed_loop_writeback",
		"retention_decay_scheduler",
		"stale_memory_rehearsal_queue",
		"usefulness_backprop_to_maturation",
		"promotion_demotion_replay_backed",
		"cross_session_maturation_ready",
		"failure_success_feedback_closure",
		"pre_compact_memory_snapshot",
		"post_compact_resume_memory_injection",
		"final_supervise_before_claim",
		"memory_orchestrator_report_in_context_pack",
	];
	const gates = new Set(fixture.requiredGates ?? []);
	const phases = new Set(fixture.phases ?? []);
	return {
		missingGates: required.filter((gate) => !gates.has(gate)),
		missingPhases: ["pre-task", "pre-operator", "post-tool", "post-failure", "post-success", "pre-compact", "post-compact", "final"].filter((phase) => !phases.has(phase)),
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
const workspace = join(tempRoot, "workspace");
const artifact = join(tempRoot, "verified-artifact.txt");
mkdirSync(agentDir, { recursive: true });
mkdirSync(workspace, { recursive: true });
writeFileSync(artifact, "verified replay artifact for MemoryOrchestratorV6\\n");
process.chdir(workspace);
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_SESSION_ID = "memory-orchestrator-session";
process.env.REPI_BRANCH_ID = "memory-orchestrator-branch";
const tools = new Map();
const fakePi = { registerCommand() {}, registerTool(tool) { tools.set(tool.name, tool); }, on() {}, appendEntry() {}, getSessionName: () => undefined, setSessionName() {}, sendMessage() {}, exec: async () => ({ code: 0, stdout: "memory-orchestrator-probe", stderr: "", killed: false }) };
createReconExtensionFactory()(fakePi);
const memory = tools.get("re_memory");
const context = tools.get("re_context");
if (!memory) throw new Error("missing re_memory tool");
if (!context) throw new Error("missing re_context tool");
function text(result) { return result?.content?.[0]?.text ?? ""; }
function artifactPath(output, label) {
  const match = new RegExp(label + ": (.+)").exec(output);
  if (!match?.[1]) throw new Error("missing artifact label " + label + " in output\\n" + output.slice(0, 1000));
  return match[1].trim();
}
function parseJsonArtifact(path) {
  const body = readFileSync(path, "utf8");
  const fence = String.fromCharCode(96).repeat(3);
  const start = body.indexOf(fence + "json");
  if (start < 0) throw new Error("missing json block in " + path);
  const contentStart = body.indexOf("\\n", start);
  const end = body.indexOf(fence, contentStart + 1);
  if (contentStart < 0 || end < 0) throw new Error("unterminated json block in " + path);
  return JSON.parse(body.slice(contentStart + 1, end).trim());
}
async function main() {
  await memory.execute("memory-orchestrator", { action: "append", scene: "Web / API security", title: "verified authz replay", text: "target=https://target-b.local route=web outcome=success confidence=0.96 replayVerified=true playbookCandidate=true verifierRuleCandidate=true artifactPath=" + artifact + " re_verifier matrix; re_replayer run; curl https://target-b.local/api/objects/1" });
  await memory.execute("memory-orchestrator", { action: "append", scene: "Web / API security", title: "failed stale path", text: "target=https://target-b.local route=web outcome=failure confidence=0.63 artifactPath=" + artifact + " stale endpoint timeout failure should demote" });
  const preTask = await memory.execute("memory-orchestrator", { action: "orchestrate", phase: "pre-task", query: "authz replay target-b", target: "https://target-b.local", route: "Web / API security" });
  const final = await memory.execute("memory-orchestrator", { action: "final", query: "authz replay target-b", target: "https://target-b.local", route: "Web / API security" });
  const report = final.details;
  const reportPath = report.reportPath;
  const packOutput = text(await context.execute("memory-orchestrator", { action: "pack", target: "https://target-b.local" }));
  const packPath = artifactPath(packOutput, "context_artifact");
  const pack = parseJsonArtifact(packPath);
  writeFileSync(outPath, JSON.stringify({ tempRoot, agentDir, preTaskText: text(preTask), finalText: text(final), reportPath, report, packPath, pack, packHasMemoryOrchestrator: pack.memoryOrchestrator?.MemoryOrchestratorV6 === true }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`,
		"utf8",
	);
}

function runProbe(tempRoot) {
	const probePath = join(tempRoot, "memory-orchestrator-probe.ts");
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
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-memory-orchestrator-"));
	let probeData;
	try {
		const schema = readJson(SCHEMA_PATH);
		const fixture = readJson(FIXTURE_PATH);
		checks.push(check("schema:parse", schema?.$defs?.MemoryOrchestratorReportV6 && schema?.$defs?.MemoryOrchestratorStepV6, { path: SCHEMA_PATH }));
		const fixtureEval = validateFixture(fixture);
		checks.push(check("fixture:mandatory-control-loop", fixtureEval.missingGates.length === 0 && fixtureEval.missingPhases.length === 0, fixtureEval));
		const probe = runProbe(tempRoot);
		checks.push(check("runtime:probe-exit", probe.status === 0, { code: probe.status, signal: probe.signal, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) }));
		if (probe.status === 0 && existsSync(probe.outPath)) {
			probeData = JSON.parse(readFileSync(probe.outPath, "utf8"));
			const schemaErrors = validateSchema(probeData.report, schema.$defs.MemoryOrchestratorReportV6, schema, "$.report");
			const stepIds = new Set((probeData.report.steps ?? []).map((step) => step.id));
			const gates = new Set(probeData.report.requiredGates ?? []);
			checks.push(check("runtime:report-schema", schemaErrors.length === 0, { errors: schemaErrors, reportPath: probeData.reportPath, sha256: sha256(JSON.stringify(probeData.report)).slice(0, 24) }));
			checks.push(check("runtime:pre-task-retrieval-before-operator", stepIds.has("pre_task_retrieve") && gates.has("pre_task_retrieve_before_operator") && /re_memory search-events|retrieval_hits=/i.test(probeData.finalText), { stepIds: Array.from(stepIds), gates: Array.from(gates) }));
			checks.push(check("runtime:scope-filter-before-injection", stepIds.has("scope_filter_before_injection") && gates.has("scope_filter_before_memory_injection"), { stepIds: Array.from(stepIds) }));
			checks.push(check("runtime:post-tool-writeback-contract", stepIds.has("post_tool_writeback_contract") && gates.has("post_tool_writeback_contract") && (probeData.report.steps ?? []).some((step) => step.id === "post_tool_writeback_contract" && /re_memory (?:append|deposit)/i.test(step.command)), { nextCommands: probeData.report.nextCommands, postToolStep: (probeData.report.steps ?? []).find((step) => step.id === "post_tool_writeback_contract") }));
			checks.push(check("runtime:compact-resume-memory-injection", stepIds.has("post_compact_resume_memory_injection") && gates.has("post_compact_resume_memory_injection"), { compactResumeStatus: probeData.report.compactResumeStatus }));
			checks.push(check("runtime:skill-capsule-operator-injection", stepIds.has("skill_capsule_operator_injection") && gates.has("MemorySkillCapsuleV9") && probeData.report.memorySkillCapsuleReportPath && (probeData.report.nextCommands ?? []).some((command) => /re_memory skills/i.test(command)), { skillCapsules: { status: probeData.report.memorySkillCapsuleStatus, count: probeData.report.memorySkillCapsuleCount, report: probeData.report.memorySkillCapsuleReportPath }, stepIds: Array.from(stepIds) }));
			checks.push(check("runtime:distill-promotion-provider-gate", stepIds.has("distill_promotion_provider_gate") && gates.has("MemoryDistillPromotionV10") && probeData.report.memoryDistillPromotionReportPath && (probeData.report.nextCommands ?? []).some((command) => /re_memory distill-promote/i.test(command)), { distillPromotion: { status: probeData.report.memoryDistillPromotionStatus, count: probeData.report.memoryDistillPromotionCandidateCount, report: probeData.report.memoryDistillPromotionReportPath }, stepIds: Array.from(stepIds) }));
			checks.push(check("runtime:memory-quality-feedback-loop", stepIds.has("memory_quality_feedback_loop") && gates.has("MemoryQualityLedgerV11") && probeData.report.memoryQualityReportPath && (probeData.report.nextCommands ?? []).some((command) => /re_memory quality/i.test(command)), { memoryQuality: { status: probeData.report.memoryQualityStatus, rows: probeData.report.memoryQualityRowCount, report: probeData.report.memoryQualityReportPath }, stepIds: Array.from(stepIds) }));
			checks.push(check("runtime:strategy-capsule-operator-injection", stepIds.has("strategy_capsule_operator_injection") && gates.has("MemoryStrategyCapsuleV13") && probeData.report.memoryStrategyReportPath && (probeData.report.nextCommands ?? []).some((command) => /re_memory strategy/i.test(command)), { memoryStrategy: { status: probeData.report.memoryStrategyStatus, count: probeData.report.memoryStrategyCapsuleCount, report: probeData.report.memoryStrategyReportPath }, stepIds: Array.from(stepIds) }));
			checks.push(check("runtime:memory-active-kernel-decision", stepIds.has("active_memory_kernel_decision") && gates.has("MemoryActiveKernelV14") && probeData.report.memoryActiveKernelReportPath && (probeData.report.nextCommands ?? []).some((command) => /re_memory active/i.test(command)), { memoryActiveKernel: { status: probeData.report.memoryActiveKernelStatus, decisions: probeData.report.memoryActiveKernelDecisionCount, inject: probeData.report.memoryActiveKernelInject, avoid: probeData.report.memoryActiveKernelAvoid, report: probeData.report.memoryActiveKernelReportPath }, stepIds: Array.from(stepIds) }));
			checks.push(check("runtime:final-supervise-before-claim", stepIds.has("final_supervise_before_claim") && gates.has("final_supervise_before_claim") && (probeData.report.nextCommands ?? []).some((command) => /re_complete audit/i.test(command)), { nextCommands: probeData.report.nextCommands }));
			checks.push(check("runtime:context-pack-embeds-orchestrator", probeData.packHasMemoryOrchestrator && probeData.pack.memoryOrchestrator?.mandatory_memory_control_loop === true, { packPath: probeData.packPath, memoryOrchestrator: probeData.pack.memoryOrchestrator }));
			checks.push(check("runtime:required-gates", ["MemoryOrchestratorV6", "mandatory_memory_control_loop", "pre_task_retrieve_before_operator", "scope_filter_before_memory_injection", "post_tool_writeback_contract", "failure_success_feedback_closure", "pre_compact_memory_snapshot", "post_compact_resume_memory_injection", "MemorySkillCapsuleV9", "skill_capsule_assetization", "operator_skill_injection", "MemoryDistillPromotionV10", "provider_distill_contract", "artifact_to_claim_distillation", "verifier_backed_promotion_gate", "skill_capsule_promotion_writeback", "MemoryQualityLedgerV11", "active_memory_policy", "quality_score_feedback_loop", "usefulness_feedback_writeback", "MemoryStrategyCapsuleV13", "executable_strategy_capsule", "replay_backed_strategy_promotion", "strategy_quality_gate", "strategy_capsule_operator_injection", "MemoryActiveKernelV14", "unified_memory_decision_engine", "active_recall_scheduler", "quality_replay_strategy_fusion", "scope_safe_strategy_injection", "feedback_driven_promotion", "cross_session_compact_ready", "MemoryMaturationRuntimeV15", "automatic_memory_maturation_pipeline", "tool_result_to_strategy_loop", "closed_loop_writeback", "retention_decay_scheduler", "stale_memory_rehearsal_queue", "usefulness_backprop_to_maturation", "promotion_demotion_replay_backed", "cross_session_maturation_ready", "final_supervise_before_claim", "memory_orchestrator_report_in_context_pack"].every((gate) => gates.has(gate)), { requiredGates: probeData.report.requiredGates }));
		} else {
			for (const id of ["runtime:report-schema", "runtime:pre-task-retrieval-before-operator", "runtime:scope-filter-before-injection", "runtime:post-tool-writeback-contract", "runtime:compact-resume-memory-injection", "runtime:skill-capsule-operator-injection", "runtime:distill-promotion-provider-gate", "runtime:memory-quality-feedback-loop", "runtime:strategy-capsule-operator-injection", "runtime:memory-active-kernel-decision", "runtime:final-supervise-before-claim", "runtime:context-pack-embeds-orchestrator", "runtime:required-gates"]) checks.push(check(id, false, { error: "probe output missing" }));
		}
		checks.push(check("code:orchestrator-markers", ["MemoryOrchestratorV6", "buildMemoryOrchestratorReport", "formatMemoryOrchestrator", "memoryOrchestratorReportPath", "mandatory_memory_control_loop", "pre_task_retrieve_before_operator", "post_compact_resume_memory_injection"].every((marker) => readText("packages/coding-agent/src/core/recon-profile.ts").includes(marker)), { markers: ["MemoryOrchestratorV6", "buildMemoryOrchestratorReport", "formatMemoryOrchestrator"] }));
	} catch (error) {
		checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	const failed = checks.filter((row) => row.status !== "pass");
	const result = { kind: "repi-memory-orchestrator-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, tempRoot: keepTmp ? tempRoot : undefined, checks };
	if (writeEvidence) {
		const dir = join(root, ".repi-harness", "evidence", "memory-orchestrator", result.generatedAt.replace(/[:.]/g, "-"));
		mkdirSync(dir, { recursive: true });
		writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
		if (probeData) writeFileSync(join(dir, "probe-result.json"), `${JSON.stringify(probeData, null, 2)}\n`, "utf8");
	}
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Memory Orchestrator Gate");
		for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
		console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
	}
	if (strict && failed.length) process.exit(1);
}

main();
