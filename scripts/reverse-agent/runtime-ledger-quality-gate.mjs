#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { buildResult as buildRuntimeClaimLedgerGate } from "./gate-runtime-claim-ledger.mjs";

const REQUIRED_SOURCES = ["agent-dogfood", "re_swarm", "compound-frontier"];
const REQUIRED_EVENT_TYPES = ["artifact_handoff", "claim", "validation", "challenge", "resolution"];
const FIXTURE_PATH = "fixtures/reverse-agent/runtime-ledger-quality.fixture.json";
const SCHEMA_PATH = "schemas/reverse-agent/runtime-ledger-quality.schema.json";

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function safeJson(text, fallback = null) {
	try {
		return JSON.parse(text);
	} catch {
		return fallback;
	}
}

function readText(root, path) {
	return readFileSync(join(root, path), "utf8");
}

function readJson(root, path) {
	return JSON.parse(readText(root, path));
}

function walkFiles(dir, predicate, depth = 2, out = []) {
	if (!existsSync(dir) || depth < 0) return out;
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const path = join(dir, entry.name);
		if (entry.isDirectory()) walkFiles(path, predicate, depth - 1, out);
		else if (entry.isFile() && predicate(path)) out.push(path);
	}
	return out;
}

function latestRuntimeClaimLedgerResult(root) {
	const base = join(root, ".repi-harness", "evidence", "runtime-claim-ledger");
	const candidates = walkFiles(base, (path) => path.endsWith("/result.json"), 2)
		.map((path) => {
			let mtime = 0;
			try { mtime = statSync(path).mtimeMs; } catch {}
			return { path, mtime };
		})
		.sort((a, b) => b.mtime - a.mtime || b.path.localeCompare(a.path));
	return candidates[0]?.path ?? "";
}

function loadOrBuildRuntimeClaimLedgerResult(root, options = {}) {
	if (!options.refresh) {
		const latest = latestRuntimeClaimLedgerResult(root);
		if (latest) {
			const parsed = safeJson(readFileSync(latest, "utf8"), null);
			if (parsed?.runtimeLedgerQuality?.length && parsed?.complete === true) {
				return { source: "latest-runtime-claim-ledger-artifact", path: latest.replace(`${root}/`, ""), result: parsed };
			}
		}
	}
	const built = buildRuntimeClaimLedgerGate(root, { requireAllSources: true, requirePromotion: true, keepTmp: options.keepTmp });
	return { source: "fresh-runtime-claim-ledger-build", path: built.artifactDir ? join(built.artifactDir, "result.json") : "", result: built };
}

function hasLiteralSecret(value) {
	return /\bsk-[A-Za-z0-9_-]{8,}\b|\bghp_[A-Za-z0-9_]{16,}\b|\bgithub_pat_[A-Za-z0-9_]{16,}\b|(?:AUTH_TOKEN|API_KEY|PASSWORD|SECRET)=(?!<redacted>)\S+/i.test(String(value ?? ""));
}

function validateSourceQuality(row, options = {}) {
	const errors = [];
	const label = options.label || row?.source || "source";
	if (!row || typeof row !== "object") return { ok: false, errors: [`${label}:missing-row`] };
	if (!row.source) errors.push(`${label}:source`);
	if (row.status !== "strict_pass") errors.push(`${label}:status`);
	if (row.hashChainOk !== true) errors.push(`${label}:hashChainOk`);
	if (row.runtimeClaimLedgerCaptured !== true) errors.push(`${label}:runtimeClaimLedgerCaptured`);
	if (!Number.isInteger(row.eventCount) || row.eventCount < REQUIRED_EVENT_TYPES.length) errors.push(`${label}:eventCount`);
	if (!/^[a-f0-9]{64}$/.test(String(row.tipHash || ""))) errors.push(`${label}:tipHash`);
	for (const type of REQUIRED_EVENT_TYPES) {
		if (!Number.isInteger(row.eventTypeCounts?.[type]) || row.eventTypeCounts[type] < 1) errors.push(`${label}:eventTypeCounts.${type}`);
	}
	if (!Array.isArray(row.artifactDigests) || row.artifactDigests.length < 1) errors.push(`${label}:artifactDigests`);
	for (const [index, digest] of (row.artifactDigests || []).entries()) {
		if (!digest?.path) errors.push(`${label}:artifactDigests.${index}.path`);
		if (digest?.exists !== true) errors.push(`${label}:artifactDigests.${index}.exists`);
		if (!/^[a-f0-9]{64}$/.test(String(digest?.sha256 || ""))) errors.push(`${label}:artifactDigests.sha256`);
		if (!Number.isFinite(Number(digest?.bytes)) || Number(digest.bytes) <= 0) errors.push(`${label}:artifactDigests.${index}.bytes`);
	}
	if (row.strictValidator?.allowPlatformGapsOk !== true) errors.push(`${label}:strictValidator.allowPlatformGapsOk`);
	if (row.strictValidator?.strictClaimsOk !== true) errors.push(`${label}:strictValidator.strictClaimsOk`);
	if (!row.strictValidator?.allowPlatformGapsStdoutSha256) errors.push(`${label}:strictValidator.allowPlatformGapsStdoutSha256`);
	if (!row.strictValidator?.strictClaimsStdoutSha256) errors.push(`${label}:strictValidator.strictClaimsStdoutSha256`);
	if ((row.strictValidator?.requiredGaps || []).length !== 0) errors.push(`${label}:strictValidator.requiredGaps`);
	if (hasLiteralSecret(JSON.stringify(row))) errors.push(`${label}:literalSecret`);
	return { ok: errors.length === 0, errors };
}

function mutateFixtureRow(row, mutate) {
	const clone = JSON.parse(JSON.stringify(row));
	if (mutate === "deleteEventTypeCount") delete clone.eventTypeCounts.resolution;
	if (mutate === "badTipHash") clone.tipHash = "not-a-tip-hash";
	if (mutate === "missingArtifactSha") delete clone.artifactDigests[0].sha256;
	if (mutate === "strictValidatorFailed") clone.strictValidator.strictClaimsOk = false;
	if (mutate === "hashChainFalse") clone.hashChainOk = false;
	return clone;
}

function negativeCase(fixture, negative) {
	const validation = validateSourceQuality(mutateFixtureRow(fixture.validScenario, negative.mutate), { label: negative.id });
	const missing = (negative.expectedErrors ?? []).filter((needle) => !validation.errors.some((error) => error.includes(needle)));
	return {
		id: negative.id,
		status: !validation.ok && missing.length === 0 ? "pass" : "fail",
		evidence: { validation, missing },
	};
}

function markerCheck(root, id, path, markers) {
	const full = join(root, path);
	if (!existsSync(full)) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readFileSync(full, "utf8");
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function buildQualityReport(root, options = {}) {
	const runtime = loadOrBuildRuntimeClaimLedgerResult(root, options);
	const runtimeResult = runtime.result || {};
	const rows = runtimeResult.runtimeLedgerQuality || [];
	const bySource = Object.fromEntries(rows.map((row) => [row.source, row]));
	const fixture = readJson(root, FIXTURE_PATH);
	const sourceChecks = REQUIRED_SOURCES.map((source) => {
		const validation = validateSourceQuality(bySource[source], { label: source });
		return { id: `runtime-quality:${source}`, status: validation.ok ? "pass" : "fail", evidence: { validation, row: bySource[source] ?? null } };
	});
	const adapterValidation = validateSourceQuality(bySource["adapter-fixture"], { label: "adapter-fixture" });
	const checks = [
		{ id: "runtime-quality:gate-complete", status: runtimeResult.ok === true && runtimeResult.complete === true ? "pass" : "fail", evidence: { ok: runtimeResult.ok, complete: runtimeResult.complete, coverage: runtimeResult.coverage, artifactDir: runtimeResult.artifactDir } },
		{ id: "runtime-quality:required-sources", status: REQUIRED_SOURCES.every((source) => bySource[source]) ? "pass" : "fail", evidence: { required: REQUIRED_SOURCES, actual: Object.keys(bySource) } },
		{ id: "runtime-quality:adapter-fixture", status: adapterValidation.ok ? "pass" : "fail", evidence: { validation: adapterValidation, row: bySource["adapter-fixture"] ?? null } },
		...sourceChecks,
		{ id: "runtime-quality:no-literal-secrets", status: hasLiteralSecret(JSON.stringify(rows)) ? "fail" : "pass", evidence: { scannedRows: rows.length } },
		{ id: "fixture:runtime-ledger-quality-valid", status: validateSourceQuality(fixture.validScenario, { label: fixture.validScenario.id }).ok ? "pass" : "fail", evidence: validateSourceQuality(fixture.validScenario, { label: fixture.validScenario.id }) },
		...((fixture.negativeCases || []).map((negative) => negativeCase(fixture, negative))),
		markerCheck(root, "schema:runtime-ledger-quality", SCHEMA_PATH, ["RuntimeLedgerQualityGateV1", "requireArtifactSha256", "requireStrictValidator", "eventTypeCounts", "artifactDigests"]),
		markerCheck(root, "fixture:runtime-ledger-quality", FIXTURE_PATH, ["repi-runtime-ledger-quality-fixture", "negative:runtime-ledger-missing-event-type-count", "negative:runtime-ledger-strict-validator-failed"]),
		markerCheck(root, "gate:runtime-ledger-quality", "scripts/reverse-agent/runtime-ledger-quality-gate.mjs", ["RuntimeLedgerQualityGateV1", "validateSourceQuality", "runtimeLedgerQuality", "artifactDigests", "strictValidator"]),
		markerCheck(root, "npm:runtime-ledger-quality", "package.json", ["gate:runtime-ledger-quality", "runtime-ledger-quality-gate.mjs"]),
		markerCheck(root, "harness:runtime-ledger-quality", "scripts/reverse-agent/repi-top-harness.mjs", ["claims:runtime-ledger-quality", "child:gate:runtime-ledger-quality"]),
		markerCheck(root, "autonomy:runtime-ledger-quality", "scripts/reverse-agent/autonomy-control-plane.mjs", ["runtime_ledger_quality_gate", "RuntimeLedgerQualityGateV1", "artifact sha256"]),
		markerCheck(root, "docs:runtime-ledger-quality", "README.md", ["RuntimeLedgerQualityGateV1", "gate:runtime-ledger-quality"]),
	];
	return {
		kind: "repi-runtime-ledger-quality-gate",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: checks.every((check) => check.status === "pass"),
		root,
		runtimeSource: runtime.source,
		runtimeResultPath: runtime.path,
		requiredSources: REQUIRED_SOURCES,
		qualityPolicy: {
			requireHashChain: true,
			requireAllEventTypes: true,
			requireTipHash: true,
			requireArtifactSha256: true,
			requireStrictValidator: true,
			requiredEventTypes: REQUIRED_EVENT_TYPES,
		},
		sources: rows,
		checks,
	};
}

function writeEvidence(root, result) {
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const outDir = join(root, ".repi-harness", "evidence", "runtime-ledger-quality", stamp);
	mkdirSync(outDir, { recursive: true });
	const resultPath = join(outDir, "result.json");
	writeFileSync(resultPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
	writeFileSync(join(outDir, "artifact.md"), formatText(result), "utf8");
	return resultPath.replace(`${root}/`, "");
}

function formatText(result) {
	const lines = [
		"# REPI RuntimeLedgerQualityGateV1",
		"",
		`generated_at: ${result.generatedAt}`,
		`ok: ${result.ok}`,
		`runtime_source: ${result.runtimeSource}`,
		`runtime_result: ${result.runtimeResultPath || "none"}`,
		"",
		"## Source quality",
	];
	for (const row of result.sources) lines.push(`- ${row.source}: status=${row.status} events=${row.eventCount} hash_chain=${row.hashChainOk} strict=${row.strictValidator?.strictClaimsOk}`);
	lines.push("", "## Checks");
	for (const check of result.checks) lines.push(`- ${check.id}: ${check.status}`);
	if (result.evidencePath) lines.push("", `evidence: ${result.evidencePath}`);
	return `${lines.join("\n")}\n`;
}

function printHelp() {
	console.log("Usage: node scripts/reverse-agent/runtime-ledger-quality-gate.mjs [root] [--strict] [--json] [--refresh] [--no-write]");
}

function main(argv) {
	if (argv.includes("--help") || argv.includes("-h")) return printHelp();
	const rootArg = argv.find((arg) => !arg.startsWith("-"));
	const root = resolve(rootArg ?? process.cwd());
	const result = buildQualityReport(root, { refresh: argv.includes("--refresh"), keepTmp: argv.includes("--keep-tmp") });
	if (!argv.includes("--no-write")) result.evidencePath = writeEvidence(root, result);
	if (argv.includes("--json")) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
	else process.stdout.write(formatText(result));
	if (argv.includes("--strict") && !result.ok) process.exitCode = 1;
}

export { buildQualityReport, validateSourceQuality };

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main(process.argv.slice(2));
