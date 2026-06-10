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
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_CONTEXT_RUNTIME_SCHEMA_TMP === "1";
const writeEvidence = !argv.includes("--no-write");
const SCHEMA_PATH = "schemas/reverse-agent/context-resume-contract.schema.json";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

const HASH_OMIT = new Set(["contextSha256", "exactResumeVerification", "resumedFromContextPath"]);

function contextPayload(value) {
	if (Array.isArray(value)) return value.map(contextPayload);
	if (value && typeof value === "object") {
		return Object.fromEntries(
			Object.entries(value)
				.filter(([key]) => !HASH_OMIT.has(key))
				.map(([key, item]) => [key, contextPayload(item)]),
		);
	}
	return value;
}

function contextSha(pack) {
	return sha256(JSON.stringify(contextPayload(pack)));
}

function resolveRef(schema, ref) {
	if (!ref?.startsWith("#/$defs/")) throw new Error(`unsupported ref: ${ref}`);
	const key = ref.slice("#/$defs/".length);
	return schema.$defs?.[key];
}

function typeOk(value, type) {
	if (Array.isArray(type)) return type.some((item) => typeOk(value, item));
	if (type === "array") return Array.isArray(value);
	if (type === "object") return value !== null && typeof value === "object" && !Array.isArray(value);
	if (type === "integer") return Number.isInteger(value);
	if (type === "null") return value === null;
	return typeof value === type;
}

function validateSchema(value, node, schema, path = "$") {
	if (!node) return [];
	if (node.$ref) return validateSchema(value, resolveRef(schema, node.$ref), schema, path);
	if (node.oneOf) {
		const results = node.oneOf.map((candidate) => validateSchema(value, candidate, schema, path));
		return results.some((errors) => errors.length === 0) ? [] : [`${path}: oneOf failed: ${results.map((errors) => errors[0] ?? "unknown").join("; ")}`];
	}
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
	if (typeof value === "number" && node.minimum !== undefined && value < node.minimum) errors.push(`${path}: minimum ${node.minimum}`);
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

function check(id, status, evidence = {}) {
	return { id, status: status ? "pass" : "fail", evidence };
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
process.env.REPI_BRANCH_ID = "runtime-schema-branch";
const tools = new Map();
const handlers = new Map();
const appended = [];
const sentMessages = [];
const fakePi = {
  registerCommand() {},
  registerTool(tool) { tools.set(tool.name, tool); },
  on(event, handler) { handlers.set(event, [...(handlers.get(event) ?? []), handler]); },
  appendEntry(type, details) { appended.push({ type, details }); },
  getSessionName: () => undefined,
  setSessionName() {},
  sendMessage(message, options) { sentMessages.push({ message, options }); },
  exec: async () => ({ code: 0, stdout: "runtime-schema-probe", stderr: "", killed: false }),
};
createReconExtensionFactory()(fakePi);
const tool = (name) => {
  const value = tools.get(name);
  if (!value) throw new Error("missing tool " + name);
  return value;
};
function text(result) { return result?.content?.[0]?.text ?? ""; }
function artifactPath(output, label) {
  const match = new RegExp(label + ": (.+)").exec(output);
  if (!match?.[1]) throw new Error("missing artifact label " + label + " in output\\n" + output.slice(0, 1000));
  return match[1].trim();
}
function parseJsonArtifact(path) {
  const body = readFileSync(path, "utf8");
  const start = body.indexOf("\`\`\`json");
  if (start < 0) throw new Error("missing json block in " + path);
  const contentStart = body.indexOf("\\n", start);
  const end = body.indexOf("\`\`\`", contentStart + 1);
  if (contentStart < 0 || end < 0) throw new Error("unterminated json block in " + path);
  return JSON.parse(body.slice(contentStart + 1, end).trim());
}
const missionTool = tool("re_mission");
const mapTool = tool("re_map");
const memoryTool = tool("re_memory");
const contextTool = tool("re_context");
async function main() {
  await missionTool.execute("runtime-schema", { action: "new", task: "runtime schema gate target-a" });
  await mapTool.execute("runtime-schema", { target: "target-a", depth: 1 });
  await memoryTool.execute("runtime-schema", { action: "verify" });
  await memoryTool.execute("runtime-schema", { action: "sediment" });
  const packOutput = text(await contextTool.execute("runtime-schema", { action: "pack", target: "target-a" }));
  const packPath = artifactPath(packOutput, "context_artifact");
  const pack = parseJsonArtifact(packPath);
  const resumeOutput = text(await contextTool.execute("runtime-schema", { action: "resume", target: "target-a", contextPath: packPath }));
  const resumePath = artifactPath(resumeOutput, "context_artifact");
  const resume = parseJsonArtifact(resumePath);
  writeFileSync(outPath, JSON.stringify({ tempRoot, agentDir, packPath, resumePath, packOutput, resumeOutput, pack, resume, appended, sentMessages }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
`,
		"utf8",
	);
}

function runProbe(tempRoot) {
	const probePath = join(tempRoot, "context-runtime-schema-probe.ts");
	const outPath = join(tempRoot, "probe-result.json");
	writeProbe(probePath, outPath, tempRoot);
	const tsx = join(root, "node_modules", ".bin", "tsx");
	const result = spawnSync(tsx, ["--tsconfig", join(root, "tsconfig.json"), probePath], {
		cwd: root,
		env: { ...process.env, REPI_CONTEXT_RUNTIME_PROBE_OUT: outPath, PI_OFFLINE: "1", REPI_OFFLINE: "1" },
		encoding: "utf8",
		maxBuffer: 40 * 1024 * 1024,
	});
	return { ...result, outPath, probePath };
}

function validateRuntimePack(name, pack, sourcePath, schema) {
	const errors = validateSchema(pack, schema.$defs.ContextPackV2, schema, `$${name}`);
	const resumeErrors = validateSchema(pack.resumeContract, schema.$defs.ResumeContractV2, schema, `$${name}.resumeContract`);
	const hash = contextSha(pack);
	if (pack.contextSha256 !== hash) errors.push(`$${name}.contextSha256 drift expected=${hash} actual=${pack.contextSha256}`);
	if (pack.resumeContract?.contextSha256 !== pack.contextSha256) errors.push(`$${name}.resumeContract.contextSha256 mismatch`);
	if (pack.resumeContract?.contextPath !== pack.contextPath) errors.push(`$${name}.resumeContract.contextPath mismatch`);
	for (const artifact of pack.artifactHashes ?? []) {
		if (!artifact.required) continue;
		if (!existsSync(artifact.path)) errors.push(`$${name}.artifact missing ${artifact.path}`);
		else {
			const current = sha256(readFileSync(artifact.path));
			if (artifact.sha256 && artifact.sha256 !== current) errors.push(`$${name}.artifact hash drift ${artifact.path}`);
		}
	}
	return { name, sourcePath, errors: [...errors, ...resumeErrors], contextSha256: pack.contextSha256, artifactKinds: (pack.artifactIndex ?? []).map((artifact) => artifact.kind) };
}

function main() {
	const checks = [];
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-context-runtime-schema-"));
	let probeData;
	try {
		const schema = readJson(SCHEMA_PATH);
		checks.push(check("schema:parse", schema?.$defs?.ContextPackV2 && schema?.$defs?.ResumeContractV2, { path: SCHEMA_PATH }));
		const probe = runProbe(tempRoot);
		checks.push(check("runtime:probe-exit", probe.status === 0, { code: probe.status, signal: probe.signal, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) }));
		if (probe.status === 0 && existsSync(probe.outPath)) {
			probeData = JSON.parse(readFileSync(probe.outPath, "utf8"));
			const packValidation = validateRuntimePack(".pack", probeData.pack, probeData.packPath, schema);
			const resumeValidation = validateRuntimePack(".resume", probeData.resume, probeData.resumePath, schema);
			checks.push(check("runtime:pack-schema", packValidation.errors.length === 0, packValidation));
			checks.push(check("runtime:resume-schema", resumeValidation.errors.length === 0, resumeValidation));
			checks.push(check("runtime:resume-verification-pass", probeData.resume?.exactResumeVerification?.blocked?.length === 0 && probeData.resume?.resumeQueueStatus === "done" && probeData.resume?.closure?.status === "closed", { exactResumeVerification: probeData.resume?.exactResumeVerification, resumeQueueStatus: probeData.resume?.resumeQueueStatus, closure: probeData.resume?.closure }));
			checks.push(check("runtime:memory-hash-contract", ["memory_events", "memory_case_memory", "memory_store_report", "memory_injection_packet", "memory_sedimentation_report"].every((kind) => (probeData.pack?.artifactIndex ?? []).some((artifact) => artifact.kind === kind)), { artifactKinds: (probeData.pack?.artifactIndex ?? []).map((artifact) => artifact.kind) }));
		} else {
			checks.push(check("runtime:pack-schema", false, { error: "probe output missing" }));
			checks.push(check("runtime:resume-schema", false, { error: "probe output missing" }));
		}
		checks.push(check("code:runtime-schema-markers", ["createdAt", "resumeContract", "memory_store_report", "memory_injection_packet"].every((marker) => readText("packages/coding-agent/src/core/recon-profile.ts").includes(marker)), { markers: ["createdAt", "resumeContract", "memory_store_report", "memory_injection_packet"] }));
	} catch (error) {
		checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	const failed = checks.filter((row) => row.status !== "pass");
	const result = { kind: "repi-context-runtime-schema-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, tempRoot: keepTmp ? tempRoot : undefined, checks };
	if (writeEvidence) {
		const dir = join(root, ".repi-harness", "evidence", "context-runtime-schema", result.generatedAt.replace(/[:.]/g, "-"));
		mkdirSync(dir, { recursive: true });
		writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
		if (probeData) writeFileSync(join(dir, "probe-result.json"), `${JSON.stringify(probeData, null, 2)}\n`, "utf8");
	}
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Context Runtime Schema Gate");
		for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
		console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
	}
	if (strict && failed.length) process.exit(1);
}

main();
