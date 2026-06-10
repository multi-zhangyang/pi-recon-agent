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
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_MEMORY_VECTOR_TMP === "1";
const writeEvidence = !argv.includes("--no-write");
const SCHEMA_PATH = "schemas/reverse-agent/memory-vector.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/memory-vector.fixture.json";
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
	const required = ["MemoryEmbeddingProviderV1", "deterministic_local_hash_embedding", "local_hash_embedding_fallback", "openai_compatible_embedding_contract", "embedding_api_key_env_ref_only", "remote_embedding_requires_explicit_allow", "route_scoped_vector_rerank", "quality_weighted_vector_score", "forbidden_cross_route_vector_leak_blocked"];
	const gates = new Set(fixture.requiredGates ?? []);
	const scenarioIds = new Set((fixture.scenarios ?? []).map((scenario) => scenario.id));
	return {
		missingGates: required.filter((gate) => !gates.has(gate)),
		missingScenarios: ["semantic-authz-rerank", "forbidden-cross-route-vector-leak", "quality-weighted-replay-boost", "provider-contract-env-fallback"].filter((id) => !scenarioIds.has(id)),
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
process.env.REPI_BRANCH_ID = "memory-vector-branch";
const tools = new Map();
const fakePi = { registerCommand() {}, registerTool(tool) { tools.set(tool.name, tool); }, on() {}, appendEntry() {}, getSessionName: () => undefined, setSessionName() {}, sendMessage() {}, exec: async () => ({ code: 0, stdout: "memory-vector-probe", stderr: "", killed: false }) };
createReconExtensionFactory()(fakePi);
const memory = tools.get("re_memory");
if (!memory) throw new Error("missing re_memory tool");
async function main() {
  await memory.execute("memory-vector", { action: "append", scene: "web", title: "authz ownership success", text: "authz ownership object tenant permission principal replay verified command curl /api/objects/123" });
  await memory.execute("memory-vector", { action: "append", scene: "pwn", title: "pwn crash", text: "pwn crash segfault rop libc leak cyclic offset command gdb ./vuln" });
  const vectorResult = await memory.execute("memory-vector", { action: "vector", query: "authz ownership permission principal" });
  const searchResult = await memory.execute("memory-vector", { action: "search-events", query: "ownership permission" });
  const vectorReportPath = vectorResult?.details?.vectorSearchReport;
  const vectorIndexPath = vectorResult?.details?.vectorIndex;
  const vectorReport = JSON.parse(readFileSync(vectorReportPath, "utf8"));
  const vectorIndex = JSON.parse(readFileSync(vectorIndexPath, "utf8"));
  process.env.REPI_MEMORY_EMBEDDING_PROVIDER = "openai-compatible";
  process.env.REPI_MEMORY_EMBEDDING_MODEL = "text-embedding-3-small";
  process.env.REPI_MEMORY_EMBEDDING_API_KEY_ENV = "REPI_MEMORY_EMBEDDING_API_KEY";
  delete process.env.REPI_MEMORY_EMBEDDING_ALLOW_REMOTE;
  const fallbackResult = await memory.execute("memory-vector", { action: "vector", query: "authz ownership provider fallback" });
  const fallbackReport = JSON.parse(readFileSync(fallbackResult?.details?.vectorSearchReport, "utf8"));
  const embeddingResult = await memory.execute("memory-vector", { action: "embedding" });
  writeFileSync(outPath, JSON.stringify({ tempRoot, agentDir, vectorText: vectorResult?.content?.[0]?.text ?? "", searchText: searchResult?.content?.[0]?.text ?? "", fallbackText: fallbackResult?.content?.[0]?.text ?? "", embeddingText: embeddingResult?.content?.[0]?.text ?? "", vectorReportPath, vectorIndexPath, vectorReport, vectorIndex, fallbackReport, embeddingDetails: embeddingResult?.details }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`,
		"utf8",
	);
}

function runProbe(tempRoot) {
	const probePath = join(tempRoot, "memory-vector-probe.ts");
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
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-memory-vector-"));
	let probeData;
	try {
		const schema = readJson(SCHEMA_PATH);
		const fixture = readJson(FIXTURE_PATH);
		checks.push(check("schema:parse", schema?.$defs?.MemoryVectorIndexV1 && schema?.$defs?.MemoryVectorSearchReportV1, { path: SCHEMA_PATH }));
		const fixtureEval = validateFixture(fixture);
		checks.push(check("fixture:vector-rerank-negative", fixtureEval.missingGates.length === 0 && fixtureEval.missingScenarios.length === 0, fixtureEval));
		const probe = runProbe(tempRoot);
		checks.push(check("runtime:probe-exit", probe.status === 0, { code: probe.status, signal: probe.signal, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) }));
		if (probe.status === 0 && existsSync(probe.outPath)) {
			probeData = JSON.parse(readFileSync(probe.outPath, "utf8"));
			const indexErrors = validateSchema(probeData.vectorIndex, schema.$defs.MemoryVectorIndexV1, schema, "$.index");
			const searchErrors = validateSchema(probeData.vectorReport, schema.$defs.MemoryVectorSearchReportV1, schema, "$.search");
			checks.push(check("runtime:index-schema", indexErrors.length === 0, { errors: indexErrors, indexPath: probeData.vectorIndexPath, entries: probeData.vectorIndex?.entries?.length, sha256: sha256(JSON.stringify(probeData.vectorIndex)).slice(0, 24) }));
			checks.push(check("runtime:search-schema", searchErrors.length === 0, { errors: searchErrors, reportPath: probeData.vectorReportPath, hits: probeData.vectorReport?.hits?.length, sha256: sha256(JSON.stringify(probeData.vectorReport)).slice(0, 24) }));
			checks.push(check("runtime:vector-rerank-used", /memory_vector_rerank|MemoryVectorSearchV1/.test(probeData.vectorText) && /memory_vector_rerank/.test(probeData.searchText), { vectorTextHead: probeData.vectorText.slice(0, 800), searchTextHead: probeData.searchText.slice(0, 800) }));
			checks.push(check("runtime:required-gates", ["MemoryVectorSearchV1", "MemoryEmbeddingProviderV1", "vector_index_built_before_search", "route_scoped_vector_rerank", "quality_weighted_vector_score", "forbidden_cross_route_vector_leak_blocked"].every((gate) => probeData.vectorReport.requiredGates?.includes(gate)), { requiredGates: probeData.vectorReport.requiredGates }));
			checks.push(check("runtime:embedding-provider-contract", probeData.vectorReport.embeddingProvider?.MemoryEmbeddingProviderV1 === true && probeData.vectorIndex.embeddingProvider?.backend === "local-hash", { provider: probeData.vectorReport.embeddingProvider }));
			checks.push(check("runtime:openai-compatible-fallback", probeData.fallbackReport.embeddingProvider?.requestedBackend === "openai-compatible" && probeData.fallbackReport.embeddingProvider?.status === "fallback" && /remote_embedding_requires_explicit_allow/.test(probeData.fallbackReport.embeddingProvider?.fallbackReason ?? ""), { provider: probeData.fallbackReport.embeddingProvider, fallbackTextHead: probeData.fallbackText?.slice(0, 600), embeddingTextHead: probeData.embeddingText?.slice(0, 600) }));
		} else {
			checks.push(check("runtime:index-schema", false, { error: "probe output missing" }));
			checks.push(check("runtime:search-schema", false, { error: "probe output missing" }));
			checks.push(check("runtime:vector-rerank-used", false, { error: "probe output missing" }));
			checks.push(check("runtime:required-gates", false, { error: "probe output missing" }));
			checks.push(check("runtime:embedding-provider-contract", false, { error: "probe output missing" }));
			checks.push(check("runtime:openai-compatible-fallback", false, { error: "probe output missing" }));
		}
		checks.push(check("code:vector-markers", ["MemoryVectorIndexV1", "MemoryVectorSearchV1", "buildMemoryVectorIndex", "searchMemoryVectors", "memory_vector_rerank", "repi-local-hash-embedding-v1"].every((marker) => readText("packages/coding-agent/src/core/recon-profile.ts").includes(marker)), { markers: ["MemoryVectorIndexV1", "MemoryVectorSearchV1", "buildMemoryVectorIndex"] }));
	} catch (error) {
		checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	const failed = checks.filter((row) => row.status !== "pass");
	const result = { kind: "repi-memory-vector-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, tempRoot: keepTmp ? tempRoot : undefined, checks };
	if (writeEvidence) {
		const dir = join(root, ".repi-harness", "evidence", "memory-vector", result.generatedAt.replace(/[:.]/g, "-"));
		mkdirSync(dir, { recursive: true });
		writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
		if (probeData) writeFileSync(join(dir, "probe-result.json"), `${JSON.stringify(probeData, null, 2)}\n`, "utf8");
	}
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Memory Vector Gate");
		for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
		console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
	}
	if (strict && failed.length) process.exit(1);
}

main();
