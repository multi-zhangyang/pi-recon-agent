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
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_MEMORY_SUPERVISOR_TMP === "1";
const writeEvidence = !argv.includes("--no-write");
const SCHEMA_PATH = "schemas/reverse-agent/memory-supervisor.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/memory-supervisor.fixture.json";
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
	}
	return errors;
}

function validateFixture(fixture) {
	const actions = new Set(fixture.scenarios?.flatMap((scenario) => scenario.decisions?.map((decision) => decision.action) ?? []) ?? []);
	const required = ["promote", "demote", "quarantine", "merge"];
	const requiredGates = new Set(fixture.requiredGates ?? []);
	return {
		actions: Array.from(actions).sort(),
		missingActions: required.filter((action) => !actions.has(action)),
		missingGates: ["MemorySupervisorV1", "quarantine_overrides_promotion", "merge_by_case_signature", "feedback_required_after_injection"].filter((gate) => !requiredGates.has(gate)),
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
mkdirSync(agentDir, { recursive: true });
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_BRANCH_ID = "memory-supervisor-branch";
const tools = new Map();
const fakePi = {
  registerCommand() {},
  registerTool(tool) { tools.set(tool.name, tool); },
  on() {},
  appendEntry() {},
  getSessionName: () => undefined,
  setSessionName() {},
  sendMessage() {},
  exec: async () => ({ code: 0, stdout: "memory-supervisor-probe", stderr: "", killed: false }),
};
createReconExtensionFactory()(fakePi);
const tool = tools.get("re_memory");
if (!tool) throw new Error("missing re_memory tool");
async function main() {
  await tool.execute("memory-supervisor", { action: "append", scene: "web", title: "fixture success", text: "Verified replay evidence. re_verifier matrix; re_replayer run" });
  await tool.execute("memory-supervisor", { action: "append", scene: "web", title: "fixture blocked", text: "blocked timeout failure should be reviewed before reuse" });
  const result = await tool.execute("memory-supervisor", { action: "supervise" });
  const reportPath = result?.details?.supervisorReport;
  const boardPath = result?.details?.lifecycleBoard;
  const report = JSON.parse(readFileSync(reportPath, "utf8"));
  const board = readFileSync(boardPath, "utf8");
  writeFileSync(outPath, JSON.stringify({ tempRoot, agentDir, text: result?.content?.[0]?.text ?? "", details: result?.details, reportPath, boardPath, report, boardHead: board.slice(0, 2000) }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`,
		"utf8",
	);
}

function runProbe(tempRoot) {
	const probePath = join(tempRoot, "memory-supervisor-probe.ts");
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
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-memory-supervisor-"));
	let probeData;
	try {
		const schema = readJson(SCHEMA_PATH);
		const fixture = readJson(FIXTURE_PATH);
		checks.push(check("schema:parse", schema?.$defs?.MemorySupervisorReportV1 && schema?.$defs?.MemorySupervisorDecisionV1, { path: SCHEMA_PATH }));
		const fixtureEval = validateFixture(fixture);
		checks.push(check("fixture:promotion-demotion-quarantine-merge", fixtureEval.missingActions.length === 0 && fixtureEval.missingGates.length === 0, fixtureEval));
		const probe = runProbe(tempRoot);
		checks.push(check("runtime:probe-exit", probe.status === 0, { code: probe.status, signal: probe.signal, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) }));
		if (probe.status === 0 && existsSync(probe.outPath)) {
			probeData = JSON.parse(readFileSync(probe.outPath, "utf8"));
			const schemaErrors = validateSchema(probeData.report, schema.$defs.MemorySupervisorReportV1, schema, "$.report");
			checks.push(check("runtime:report-schema", schemaErrors.length === 0, { errors: schemaErrors, reportPath: probeData.reportPath, sha256: sha256(JSON.stringify(probeData.report)).slice(0, 24) }));
			checks.push(check("runtime:lifecycle-board", existsSync(probeData.boardPath) && /MemorySupervisorV1|memory_supervisor|required_gates/.test(probeData.boardHead), { boardPath: probeData.boardPath, boardHead: probeData.boardHead }));
			checks.push(check("runtime:required-gates", ["MemorySupervisorV1", "store_verify_before_supervision", "sedimentation_before_promotion", "quarantine_overrides_promotion", "merge_by_case_signature", "feedback_required_after_injection"].every((gate) => probeData.report.requiredGates?.includes(gate)), { requiredGates: probeData.report.requiredGates }));
		} else {
			checks.push(check("runtime:report-schema", false, { error: "probe output missing" }));
			checks.push(check("runtime:lifecycle-board", false, { error: "probe output missing" }));
			checks.push(check("runtime:required-gates", false, { error: "probe output missing" }));
		}
		checks.push(check("code:supervisor-markers", ["MemorySupervisorV1", "superviseMemoryLifecycle", "formatMemorySupervisor", "memorySupervisorReportPath", "memoryLifecycleBoardPath", "quarantineOverridesPromotion"].every((marker) => readText("packages/coding-agent/src/core/recon-profile.ts").includes(marker)), { markers: ["MemorySupervisorV1", "superviseMemoryLifecycle", "formatMemorySupervisor"] }));
	} catch (error) {
		checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	const failed = checks.filter((row) => row.status !== "pass");
	const result = { kind: "repi-memory-supervisor-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, tempRoot: keepTmp ? tempRoot : undefined, checks };
	if (writeEvidence) {
		const dir = join(root, ".repi-harness", "evidence", "memory-supervisor", result.generatedAt.replace(/[:.]/g, "-"));
		mkdirSync(dir, { recursive: true });
		writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
		if (probeData) writeFileSync(join(dir, "probe-result.json"), `${JSON.stringify(probeData, null, 2)}\n`, "utf8");
	}
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Memory Supervisor Gate");
		for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
		console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
	}
	if (strict && failed.length) process.exit(1);
}

main();
