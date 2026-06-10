#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const writeEvidence = !argv.includes("--no-write");
const FIXTURE_PATH = "fixtures/reverse-agent/memory-swarm-writeback.fixture.json";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

function unique(values, limit = 80) {
	const seen = new Set();
	const out = [];
	for (const value of values) {
		const text = String(value ?? "").trim();
		if (!text) continue;
		const key = text.toLowerCase();
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(text);
		if (out.length >= limit) break;
	}
	return out;
}

function markerCheck(id, file, markers, forbidden = []) {
	const path = join(root, file);
	const text = existsSync(path) ? readFileSync(path, "utf8") : "";
	const missing = markers.filter((marker) => !text.includes(marker));
	const forbiddenHits = forbidden.filter((pattern) => (pattern instanceof RegExp ? pattern.test(text) : text.includes(pattern)));
	return {
		id,
		status: existsSync(path) && missing.length === 0 && forbiddenHits.length === 0 ? "pass" : "fail",
		evidence: { file, sha256: existsSync(path) ? sha256(text).slice(0, 24) : null, missing, forbiddenHits: forbiddenHits.map(String) },
	};
}

function simulateWriteback(swarm) {
	if (swarm.mode !== "run") return { status: "skipped", events: [], errors: ["mode_not_run"] };
	const executionsByWorker = new Map();
	for (const execution of swarm.executions ?? []) {
		executionsByWorker.set(execution.workerId, [...(executionsByWorker.get(execution.workerId) ?? []), execution]);
	}
	const manifestsByWorker = new Map((swarm.subagentRuntimeManifests ?? []).map((manifest) => [manifest.workerId, manifest]));
	const events = [];
	for (const worker of (swarm.workers ?? []).filter((candidate) => executionsByWorker.has(candidate.id))) {
		const executions = executionsByWorker.get(worker.id) ?? [];
		const manifest = manifestsByWorker.get(worker.id);
		const blocked = executions.some((execution) => execution.status === "blocked");
		const artifactPaths = unique([
			swarm.claimLedgerPath,
			swarm.structuredClaimMergePath,
			swarm.subagentRuntimeManifestPath,
			manifest?.runtimeManifestFile,
			manifest?.stdoutPath,
			manifest?.stderrPath,
			...(worker.sourceArtifacts ?? []),
		]);
		events.push({
			id: `mem:${worker.id}`,
			domainTags: ["swarm-worker", "memory-swarm-writeback", "MemoryStoreV5", worker.worker, `worker-status:${worker.status}`, `runtime-status:${manifest?.status ?? "unknown"}`],
			outcome: blocked ? "blocked" : "success",
			artifactPaths,
			lessons: [`SubagentRuntimeManifestV1 stdout=${manifest?.stdoutSha256 ?? "missing"} stderr=${manifest?.stderrSha256 ?? "missing"} toolCallDigest=${manifest?.toolCallDigest ?? "missing"}.`],
			commands: executions.map((execution) => execution.command),
		});
	}
	return { status: events.length ? "pass" : "skipped", events, errors: [] };
}

function run() {
	const checks = [];
	let fixture;
	try {
		fixture = readJson(FIXTURE_PATH);
		const simulated = simulateWriteback(fixture.swarm);
		const expected = fixture.expectations ?? {};
		checks.push({ id: "fixture:parse", status: fixture.kind === "repi-memory-swarm-writeback-fixture" ? "pass" : "fail", evidence: { path: FIXTURE_PATH } });
		checks.push({ id: "fixture:writeback-count", status: simulated.events.length === expected.mustWriteEvents ? "pass" : "fail", evidence: { expected: expected.mustWriteEvents, actual: simulated.events.length } });
		checks.push({ id: "fixture:writeback-tags", status: (expected.mustHaveDomainTags ?? []).every((tag) => simulated.events.every((event) => event.domainTags.includes(tag))) ? "pass" : "fail", evidence: { tags: expected.mustHaveDomainTags, events: simulated.events.map((event) => event.domainTags) } });
		checks.push({ id: "fixture:writeback-outcomes", status: (expected.mustCaptureOutcomes ?? []).every((outcome) => simulated.events.some((event) => event.outcome === outcome)) ? "pass" : "fail", evidence: { outcomes: simulated.events.map((event) => event.outcome) } });
		checks.push({ id: "fixture:artifact-capture", status: simulated.events.every((event) => [fixture.swarm.claimLedgerPath, fixture.swarm.structuredClaimMergePath, fixture.swarm.subagentRuntimeManifestPath].every((path) => event.artifactPaths.includes(path))) && simulated.events.every((event) => event.artifactPaths.some((path) => path.endsWith("runtime-manifest.json")) && event.artifactPaths.some((path) => path.endsWith("stdout.txt")) && event.artifactPaths.some((path) => path.endsWith("stderr.txt"))) ? "pass" : "fail", evidence: { artifactPaths: simulated.events.map((event) => event.artifactPaths) } });
		const skippedModes = (expected.mustSkipModes ?? []).map((mode) => simulateWriteback({ ...fixture.swarm, mode }));
		checks.push({ id: "fixture:skip-non-run-modes", status: skippedModes.every((row) => row.status === "skipped" && row.events.length === 0) ? "pass" : "fail", evidence: { skippedModes } });
	} catch (error) {
		checks.push({ id: "fixture:parse", status: "fail", evidence: { error: String(error) } });
	}

	checks.push(markerCheck("code:swarm-memory-writeback", "packages/coding-agent/src/core/recon-profile.ts", [
		"function appendSwarmWorkerMemoryEvents",
		"appendSwarmWorkerMemoryEvents(swarm)",
		"memoryWritebackEvents",
		"memoryWritebackStatus",
		"memory-swarm-writeback",
		"SubagentRuntimeManifestV1",
		"MemoryStoreV5",
		"appendMemoryEvent({",
		"swarm.mode !== \"run\"",
		"memory_swarm_writeback:",
		"memoryStoreReportPath()",
	]));
	checks.push(markerCheck("test:swarm-memory-writeback", "packages/coding-agent/test/recon-profile.test.ts", ["memory_swarm_writeback:", "memory-swarm-writeback", "store-report.json", "MemoryStoreV5"]));
	checks.push(markerCheck("docs:swarm-memory-readme", "README.md", ["memory-swarm-writeback", "gate:memory-swarm-writeback", "re_swarm run"]));
	checks.push(markerCheck("docs:swarm-memory-reverse-readme", "docs/reverse-agent/README.md", ["memory-swarm-writeback", "gate:memory-swarm-writeback", "SubagentRuntimeManifestV1"]));
	checks.push(markerCheck("docs:swarm-memory-recon", "packages/coding-agent/docs/recon.md", ["memory-swarm-writeback", "gate:memory-swarm-writeback", "MemoryStoreV5"]));
	checks.push(markerCheck("profile:swarm-memory", "repi-profile/SYSTEM.md", ["memory-swarm-writeback", "re_swarm run", "MemoryStoreV5"]));
	checks.push(markerCheck("control:swarm-memory", "scripts/reverse-agent/autonomy-control-plane.mjs", ["runtime_re_swarm_memory_writeback", "memory-swarm-writeback", "gate:memory-swarm-writeback"]));
	checks.push(markerCheck("npm:swarm-memory-script", "package.json", ["gate:memory-swarm-writeback", "memory-swarm-writeback-gate.mjs"]));
	checks.push(markerCheck("top:swarm-memory-gate", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:memory-swarm-writeback", "memory:swarm-writeback-hard-eval", "memory:swarm-writeback-fixture"]));

	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-memory-swarm-writeback-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
	if (writeEvidence) {
		const dir = join(root, ".repi-harness", "evidence", "memory-swarm-writeback", new Date().toISOString().replace(/[:.]/g, "-"));
		mkdirSync(dir, { recursive: true });
		writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
	}
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Memory Swarm Writeback Gate");
		for (const check of checks) console.log(`- ${check.status === "pass" ? "PASS" : "FAIL"} ${check.id}`);
		console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
	}
	if (strict && failed.length) process.exit(1);
}

run();
