#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const AUDIT_VERSION = 1;
const DOGFOOD_EVIDENCE_DIR = join(".pi", "evidence", "remote", "agent-parallel-dogfood");
const FRONTIER_PLAN_ARGS = [
	"bench/recon-remote/frontier-orchestrator/run.mjs",
	"--plan",
	"--json",
	"--strategy=quick",
	"--shards=2",
];
const PROVIDER_ENV_KEYS = [
	"RECON_AGENT_MODEL",
	"ANTHROPIC_MODEL",
	"ANTHROPIC_AUTH_TOKEN",
	"ANTHROPIC_API_KEY",
	"ANTHROPIC_OAUTH_TOKEN",
	"OPENAI_API_KEY",
	"AI_GATEWAY_API_KEY",
	"OPENROUTER_API_KEY",
	"GEMINI_API_KEY",
	"GROQ_API_KEY",
	"OPENCODE_API_KEY",
];

function sha256(value) {
	return createHash("sha256").update(String(value ?? "")).digest("hex");
}

function parseJson(text) {
	try {
		return JSON.parse(text);
	} catch {
		return null;
	}
}

function status(condition, detail = {}) {
	return { status: condition ? "pass" : "fail", ...detail };
}

function fieldMissing(obj, fields) {
	return fields.filter((field) => obj?.[field] === undefined || obj?.[field] === null);
}

function listImmediateDirs(root, relativePath) {
	const full = join(root, relativePath);
	if (!existsSync(full)) return [];
	return readdirSync(full, { withFileTypes: true })
		.filter((entry) => entry.isDirectory())
		.map((entry) => entry.name)
		.sort();
}

function runNode(root, args, { env = {}, unsetEnv = [], timeoutMs = 60000 } = {}) {
	const childEnv = { ...process.env, RECON_REPO_ROOT: root, ...env };
	for (const key of unsetEnv) delete childEnv[key];
	const run = spawnSync(process.execPath, args, {
		cwd: root,
		env: childEnv,
		encoding: "utf8",
		maxBuffer: 20 * 1024 * 1024,
		timeout: timeoutMs,
	});
	return {
		command: `node ${args.join(" ")}`,
		code: run.status,
		signal: run.signal,
		error: run.error?.message || "",
		stdout: run.stdout || "",
		stderr: run.stderr || "",
		stdoutBytes: Buffer.byteLength(run.stdout || ""),
		stderrBytes: Buffer.byteLength(run.stderr || ""),
		stdoutSha256: sha256(run.stdout || "").slice(0, 24),
		stderrSha256: sha256(run.stderr || "").slice(0, 24),
		stderrTail: String(run.stderr || "").slice(-2000),
		json: parseJson(run.stdout || ""),
	};
}

function validateWorkers(workers) {
	const required = ["id", "role", "objective", "commands", "evidenceContract", "mergeKeys", "dependencies", "artifactGlobs", "limits"];
	const rows = Array.isArray(workers)
		? workers.map((worker) => ({
				id: worker.id || "",
				missing: fieldMissing(worker, required),
				commands: Array.isArray(worker.commands) ? worker.commands.length : -1,
				evidenceContract: Array.isArray(worker.evidenceContract) ? worker.evidenceContract.length : -1,
				mergeKeys: Array.isArray(worker.mergeKeys) ? worker.mergeKeys.length : -1,
				artifactGlobs: Array.isArray(worker.artifactGlobs) ? worker.artifactGlobs.length : -1,
				dependenciesOk: Array.isArray(worker.dependencies),
				limitsOk: Boolean(worker.limits && typeof worker.limits === "object"),
			}))
		: [];
	const ok = Array.isArray(workers)
		&& workers.length > 0
		&& rows.every((row) => row.missing.length === 0 && row.commands >= 1 && row.evidenceContract >= 1 && row.mergeKeys >= 1 && row.artifactGlobs >= 1 && row.dependenciesOk && row.limitsOk);
	return status(ok, { workerCount: Array.isArray(workers) ? workers.length : 0, rows });
}

function validateMerge(merge) {
	const missing = fieldMissing(merge, ["strategy", "evidenceOrder", "expectedArtifacts"]);
	const ok = missing.length === 0
		&& merge?.strategy === "frontier-summary"
		&& Array.isArray(merge.evidenceOrder)
		&& merge.evidenceOrder.length > 0
		&& Array.isArray(merge.expectedArtifacts)
		&& merge.expectedArtifacts.length > 0;
	return status(ok, {
		missing,
		strategy: merge?.strategy || "",
		evidenceOrder: merge?.evidenceOrder || [],
		expectedArtifacts: merge?.expectedArtifacts || [],
	});
}

function validateFrontierPlanOutput(plan, run) {
	const legacyFields = [
		"mode",
		"strategy",
		"selectedCases",
		"strict",
		"live",
		"fresh",
		"matrixCommand",
		"requestedShardCount",
		"shardStrategy",
		"shardCount",
		"shards",
		"latestMatrixArtifact",
		"caseNotes",
		"contextPolicy",
	];
	const rootMachineFields = ["planId", "source", "workers", "merge", "parallelPlan"];
	const legacyMissing = fieldMissing(plan, legacyFields);
	const rootMissing = fieldMissing(plan, rootMachineFields);
	const parallelPlan = plan?.parallelPlan;
	const parallelMissing = fieldMissing(parallelPlan, ["planId", "source", "workers", "merge"]);
	const shardRows = Array.isArray(plan?.shards)
		? plan.shards.map((shard) => ({
				id: shard.id || "",
				missing: fieldMissing(shard, ["id", "cases", "lane", "command", "evidenceContract", "mergeKeys", "expectedArtifacts"]),
				caseCount: Array.isArray(shard.cases) ? shard.cases.length : -1,
			}))
		: [];
	const workers = validateWorkers(plan?.workers);
	const parallelWorkers = validateWorkers(parallelPlan?.workers);
	const merge = validateMerge(plan?.merge);
	const parallelMerge = validateMerge(parallelPlan?.merge);
	const mirrorWorkers = JSON.stringify(plan?.workers || null) === JSON.stringify(parallelPlan?.workers || null);
	const mirrorMerge = JSON.stringify(plan?.merge || null) === JSON.stringify(parallelPlan?.merge || null);
	const offlinePlan = plan?.mode === "plan" && plan?.live === false && plan?.strict === false && plan?.fresh === false && !String(plan?.matrixCommand || "").includes("--live");
	const ok = run.code === 0
		&& Boolean(plan)
		&& legacyMissing.length === 0
		&& rootMissing.length === 0
		&& parallelMissing.length === 0
		&& Array.isArray(plan.selectedCases)
		&& plan.selectedCases.length > 0
		&& Array.isArray(plan.shards)
		&& plan.shards.length === plan.shardCount
		&& shardRows.every((row) => row.missing.length === 0 && row.caseCount > 0)
		&& plan.source === "frontier-orchestrator"
		&& parallelPlan?.source === "frontier-orchestrator"
		&& workers.status === "pass"
		&& parallelWorkers.status === "pass"
		&& merge.status === "pass"
		&& parallelMerge.status === "pass"
		&& mirrorWorkers
		&& mirrorMerge
		&& offlinePlan;
	return status(ok, {
		runCode: run.code,
		runSignal: run.signal,
		parseOk: Boolean(plan),
		legacyMissing,
		rootMissing,
		parallelMissing,
		mode: plan?.mode || "",
		source: plan?.source || "",
		strategy: plan?.strategy || "",
		selectedCases: plan?.selectedCases || [],
		requestedShardCount: plan?.requestedShardCount ?? null,
		shardCount: plan?.shardCount ?? null,
		offlinePlan,
		shardRows,
		workers,
		parallelWorkers,
		merge,
		parallelMerge,
		mirrorWorkers,
		mirrorMerge,
		stderrTail: run.stderrTail,
	});
}

function validatePlanOnlyOutput(output, run, plan, beforeDirs, afterDirs) {
	const newDirs = afterDirs.filter((dir) => !beforeDirs.includes(dir));
	const expectedWorkers = plan?.parallelPlan?.workers?.length ?? plan?.workers?.length ?? 0;
	const outputWorkers = validateWorkers(output?.workers || []);
	const noModelNeeded = run.code === 0;
	const previewKindOk = output?.kind === "pi-recon-parallel-plan-preview";
	const modeOk = output?.mode === "plan-only" && output?.planOnly === true;
	const noProviderLaunchClaim = output?.willLaunchProvider === false;
	const sourceOk = output?.source === "frontier-orchestrator";
	const workerCountOk = output?.workerCount === expectedWorkers && outputWorkers.status === "pass";
	const mergeOk = output?.merge?.strategy === "frontier-summary";
	const noEvidenceDirCreated = newDirs.length === 0;
	const ok = Boolean(output)
		&& noModelNeeded
		&& previewKindOk
		&& modeOk
		&& noProviderLaunchClaim
		&& sourceOk
		&& workerCountOk
		&& mergeOk
		&& noEvidenceDirCreated;
	return status(ok, {
		runCode: run.code,
		runSignal: run.signal,
		parseOk: Boolean(output),
		previewKindOk,
		modeOk,
		noProviderLaunchClaim,
		noModelNeeded,
		modelEnvUnset: true,
		source: output?.source || "",
		sourceOk,
		workerCount: output?.workerCount ?? null,
		expectedWorkers,
		workerCountOk,
		outputWorkers,
		mergeStrategy: output?.merge?.strategy || "",
		mergeOk,
		evidenceDir: DOGFOOD_EVIDENCE_DIR,
		beforeDirCount: beforeDirs.length,
		afterDirCount: afterDirs.length,
		newDirs,
		noEvidenceDirCreated,
		stderrTail: run.stderrTail,
	});
}

function formatMarkdown(result) {
	const lines = [
		"# Pi-RECON Parallel Plan Audit",
		"",
		`generated_at: ${result.generatedAt}`,
		`mode: ${result.mode}`,
		`ok: ${result.ok}`,
		"",
		"## Checks",
	];
	for (const [name, check] of Object.entries(result.checks)) {
		lines.push(`- ${name}: ${check.status}`);
	}
	lines.push(
		"",
		"## Frontier plan",
		`- command: \`${result.commands.frontierPlan.command}\``,
		`- code: ${result.commands.frontierPlan.code}`,
		`- source: ${result.checks.frontierPlan.source || "n/a"}`,
		`- selected_cases: ${(result.checks.frontierPlan.selectedCases || []).join(",") || "n/a"}`,
		`- workers: ${result.checks.frontierPlan.workers?.workerCount ?? "n/a"}`,
		`- merge: ${result.checks.frontierPlan.merge?.strategy || "n/a"}`,
		"",
		"## Plan-only runner",
		`- command: \`${result.commands.planOnly.command}\``,
		`- code: ${result.commands.planOnly.code}`,
		`- kind: ${result.planOnlyPreview.kind || "n/a"}`,
		`- worker_count: ${result.planOnlyPreview.workerCount ?? "n/a"}`,
		`- no_model_needed: ${result.checks.planOnlyNoProvider.noModelNeeded}`,
		`- no_new_agent_dogfood_dir: ${result.checks.planOnlyNoEvidenceDir.noEvidenceDirCreated}`,
		"",
		"## Verification",
		`- RECON_AGENT_MODEL/ANTHROPIC_MODEL were removed from the child environment.`,
		`- RECON_AGENT_CMD was set to a nonexistent guard path; plan-only exited before any provider/agent launch.`,
		`- New ${DOGFOOD_EVIDENCE_DIR}/<timestamp> directories: ${result.checks.planOnlyNoEvidenceDir.newDirs.length ? result.checks.planOnlyNoEvidenceDir.newDirs.join(",") : "none"}`,
		"",
	);
	return `${lines.join("\n")}\n`;
}

function buildResult(root) {
	const resolvedRoot = resolve(root);
	const generatedAt = new Date().toISOString();
	const frontierRun = runNode(resolvedRoot, FRONTIER_PLAN_ARGS, { timeoutMs: 60000 });
	const frontierPlan = frontierRun.json;
	const frontierCheck = validateFrontierPlanOutput(frontierPlan, frontierRun);

	const tmpDir = mkdtempSync(join(tmpdir(), "pi-recon-parallel-plan-"));
	const tmpPlanPath = join(tmpDir, "frontier-plan.json");
	let planOnlyRun = {
		command: "not-run",
		code: null,
		signal: null,
		error: "",
		stdout: "",
		stderr: "",
		stdoutBytes: 0,
		stderrBytes: 0,
		stdoutSha256: sha256("").slice(0, 24),
		stderrSha256: sha256("").slice(0, 24),
		stderrTail: "",
		json: null,
	};
	let beforeDirs = listImmediateDirs(resolvedRoot, DOGFOOD_EVIDENCE_DIR);
	let afterDirs = beforeDirs;
	try {
		if (frontierPlan) writeFileSync(tmpPlanPath, `${JSON.stringify(frontierPlan, null, 2)}\n`);
		if (frontierCheck.status === "pass") {
			beforeDirs = listImmediateDirs(resolvedRoot, DOGFOOD_EVIDENCE_DIR);
			planOnlyRun = runNode(
				resolvedRoot,
				["bench/recon-remote/agent-dogfood/parallel-run.mjs", "--plan-json", tmpPlanPath, "--plan-only", "--json"],
				{
					unsetEnv: PROVIDER_ENV_KEYS,
					env: {
						RECON_AGENT_CMD: "/__pi_recon_provider_must_not_launch__",
						RECON_AGENT_PROVIDER: "audit-no-provider-launch",
					},
					timeoutMs: 60000,
				},
			);
			afterDirs = listImmediateDirs(resolvedRoot, DOGFOOD_EVIDENCE_DIR);
		}
	} finally {
		rmSync(tmpDir, { recursive: true, force: true });
	}
	const planOnlyCheck = validatePlanOnlyOutput(planOnlyRun.json, planOnlyRun, frontierPlan, beforeDirs, afterDirs);
	const checks = {
		frontierPlan: frontierCheck,
		reconParallelPlanV1: status(frontierCheck.status === "pass", {
			planId: frontierPlan?.parallelPlan?.planId || frontierPlan?.planId || "",
			source: frontierPlan?.parallelPlan?.source || frontierPlan?.source || "",
			workerCount: frontierPlan?.parallelPlan?.workers?.length ?? frontierPlan?.workers?.length ?? 0,
			mergeStrategy: frontierPlan?.parallelPlan?.merge?.strategy || frontierPlan?.merge?.strategy || "",
		}),
		planOnlyPreviewKind: status(planOnlyCheck.previewKindOk, {
			kind: planOnlyRun.json?.kind || "",
			mode: planOnlyRun.json?.mode || "",
		}),
		planOnlyNoProvider: status(planOnlyCheck.noModelNeeded && planOnlyCheck.noProviderLaunchClaim, {
			noModelNeeded: planOnlyCheck.noModelNeeded,
			noProviderLaunchClaim: planOnlyCheck.noProviderLaunchClaim,
			runCode: planOnlyRun.code,
			modelEnvUnset: true,
			guardAgentCmd: "/__pi_recon_provider_must_not_launch__",
		}),
		planOnlyNoEvidenceDir: status(planOnlyCheck.noEvidenceDirCreated, {
			evidenceDir: DOGFOOD_EVIDENCE_DIR,
			beforeDirCount: beforeDirs.length,
			afterDirCount: afterDirs.length,
			newDirs: planOnlyCheck.newDirs,
			noEvidenceDirCreated: planOnlyCheck.noEvidenceDirCreated,
		}),
		planOnlyOutput: planOnlyCheck,
	};
	const ok = Object.values(checks).every((check) => check.status === "pass");
	return {
		kind: "pi-recon-parallel-plan-audit",
		version: AUDIT_VERSION,
		generatedAt,
		root: resolvedRoot,
		mode: "offline-static-recon-parallel-plan-and-plan-only-validation",
		ok,
		checks,
		commands: {
			frontierPlan: {
				command: frontierRun.command,
				code: frontierRun.code,
				signal: frontierRun.signal,
				stdoutBytes: frontierRun.stdoutBytes,
				stderrBytes: frontierRun.stderrBytes,
				stdoutSha256: frontierRun.stdoutSha256,
				stderrSha256: frontierRun.stderrSha256,
				stderrTail: frontierRun.stderrTail,
			},
			planOnly: {
				command: "env -u RECON_AGENT_MODEL -u ANTHROPIC_MODEL RECON_AGENT_CMD=/__pi_recon_provider_must_not_launch__ node bench/recon-remote/agent-dogfood/parallel-run.mjs --plan-json <tmp-frontier-plan.json> --plan-only --json",
				code: planOnlyRun.code,
				signal: planOnlyRun.signal,
				stdoutBytes: planOnlyRun.stdoutBytes,
				stderrBytes: planOnlyRun.stderrBytes,
				stdoutSha256: planOnlyRun.stdoutSha256,
				stderrSha256: planOnlyRun.stderrSha256,
				stderrTail: planOnlyRun.stderrTail,
			},
		},
		frontierPlan: frontierPlan
			? {
					mode: frontierPlan.mode,
					planId: frontierPlan.planId,
					source: frontierPlan.source,
					strategy: frontierPlan.strategy,
					selectedCases: frontierPlan.selectedCases || [],
					shardCount: frontierPlan.shardCount,
					workerCount: frontierPlan.workers?.length || 0,
					mergeStrategy: frontierPlan.merge?.strategy || "",
					parallelPlanWorkerCount: frontierPlan.parallelPlan?.workers?.length || 0,
				}
			: null,
		planOnlyPreview: planOnlyRun.json
			? {
					kind: planOnlyRun.json.kind,
					mode: planOnlyRun.json.mode,
					willLaunchProvider: planOnlyRun.json.willLaunchProvider,
					source: planOnlyRun.json.source,
					planId: planOnlyRun.json.planId,
					workerCount: planOnlyRun.json.workerCount,
					mergeStrategy: planOnlyRun.json.merge?.strategy || "",
				}
			: {},
	};
}

function printHelp() {
	console.log(`Usage: node scripts/reverse-agent/audit-parallel-plan.mjs [root] [--json] [--strict]\n\nOffline validator for ReconParallelPlanV1 and agent-dogfood plan-only behavior. It runs frontier-orchestrator --plan only, then verifies agent-dogfood --plan-json --plan-only --json with model/provider env removed and checks that no .pi/evidence/remote/agent-parallel-dogfood/<timestamp> directory is created.`);
}

function main(argv) {
	if (argv.includes("--help") || argv.includes("-h")) return printHelp();
	const rootArg = argv.find((arg) => !arg.startsWith("-"));
	const root = resolve(rootArg ?? process.cwd());
	const json = argv.includes("--json");
	const strict = argv.includes("--strict");
	const result = buildResult(root);
	if (json) console.log(JSON.stringify(result, null, 2));
	else process.stdout.write(formatMarkdown(result));
	if (strict && !result.ok) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main(process.argv.slice(2));
