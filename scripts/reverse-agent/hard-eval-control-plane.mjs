#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const DEFAULT_ROOT = process.cwd();

const CONTRACT_VERSION = 1;
const EVIDENCE_ORDER = ["same_window_live", "runtime_artifact", "network", "served_asset", "process_config", "persisted_state"];

const PLATFORM_CLAIM_GATES = [
	{ scope: "bilibili.same_window_artifacts", gate: "same_window_artifacts_exist", required: true, weight: 1 },
	{ scope: "bilibili.wbi_per_page_cid", gate: "bilibili_wbi_per_page_cid", required: true, weight: 3 },
	{ scope: "bilibili.cdn_range_or_body_proof", gate: "bilibili_cdn_range_or_body_proof", required: false, weight: 1 },
	{ scope: "xiaohongshu.xs_signed_trace", gate: "xiaohongshu_xs_signed_trace", required: true, weight: 3 },
	{ scope: "xiaohongshu.target_note_2xx", gate: "xiaohongshu_target_note_2xx", required: false, weight: 2 },
	{ scope: "douyin.abogus_structured_replay", gate: "douyin_abogus_structured_replay", required: true, weight: 3 },
	{ scope: "douyin.cookie_boundary", gate: "douyin_cookie_boundary", required: true, weight: 2 },
	{ scope: "douyin.nowatermark_byte_proof", gate: "douyin_nowatermark_byte_proof", required: false, weight: 1 },
];

const ORCHESTRATION_GATES = [
	"allRolesExited",
	"allRolesModelCalled",
	"allRolesUsedTools",
	"allRolesStructured",
	"allRolesCoverPlatforms",
	"sameWindowCovered",
	"allRolesCiteArtifacts",
	"roleSpecificPassed",
	"parallelOverlap",
	"strongParallelOverlap",
	"synthesizerReconciled",
	"childPidsCaptured",
	"monotonicClockCaptured",
	"toolResultsCaptured",
	"sessionDigestsCaptured",
	"nonMockRuntimeExpected",
];

const TEST_COMMANDS_PAUSED = [
	"node bench/recon-remote/same-window-live/run.mjs --strict",
	"node bench/recon-remote/agent-dogfood/parallel-run.mjs",
	"node bench/recon-remote/compound-frontier/run.mjs --live --strict",
	"node bench/recon-remote/real-platform/run.mjs",
	"node bench/recon-remote/douyin-nowatermark/run.mjs",
];

function sha256Bytes(data) {
	return createHash("sha256").update(data).digest("hex");
}

function readText(path) {
	return readFileSync(path, "utf8");
}

function readJson(path) {
	return JSON.parse(readText(path));
}

function relPath(root, path) {
	return path.startsWith(root) ? path.slice(root.length + 1) : path;
}

function fileMeta(root, path) {
	if (!path || !existsSync(path)) return { path: path ? relPath(root, path) : null, exists: false };
	const bytes = readFileSync(path);
	const stat = statSync(path);
	return {
		path: relPath(root, path),
		exists: true,
		bytes: bytes.length,
		mtime: stat.mtime.toISOString(),
		sha256: sha256Bytes(bytes),
	};
}

function walkFiles(dir, predicate, out = []) {
	if (!existsSync(dir)) return out;
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const path = join(dir, entry.name);
		if (entry.isDirectory()) walkFiles(path, predicate, out);
		else if (!predicate || predicate(path)) out.push(path);
	}
	return out;
}

function latestFile(root, subdir, fileName) {
	const dir = join(root, subdir);
	const files = walkFiles(dir, (path) => path.endsWith(`/${fileName}`)).sort();
	return files.at(-1) ?? null;
}

function gateByName(sameWindow, name) {
	return (sameWindow?.gates ?? []).find((gate) => gate?.name === name) ?? null;
}

function getQueryValue(artifact, query) {
	const gateMatch = /^gates\[name=([^\]]+)\]\.passed$/.exec(query);
	if (gateMatch) return Boolean(gateByName(artifact, gateMatch[1])?.passed);
	return undefined;
}

function appendEvent(events, event) {
	const prevHash = events.at(-1)?.eventHash ?? "0".repeat(64);
	const withoutHash = { seq: events.length + 1, prevHash, ...event };
	const eventHash = sha256Bytes(JSON.stringify(withoutHash));
	events.push({ ...withoutHash, eventHash });
	return events.at(-1);
}

function buildContract(runId) {
	return {
		contractVersion: CONTRACT_VERSION,
		runId,
		evidenceOrder: EVIDENCE_ORDER,
		ledgerPolicy: {
			appendOnly: true,
			prevHash: "required",
			eventHash: "required",
			requiredEventTypes: ["artifact_handoff", "claim", "validation", "challenge", "resolution"],
		},
		conflictPolicy: {
			tableRequired: true,
			evidenceOrder: EVIDENCE_ORDER,
			unresolvedBlocksFinal: true,
		},
		claimGatePolicy: {
			provenRequiresArtifactSha256: true,
			provenRequiresJsonQuery: true,
			finalPassRequiresVerifier: true,
			unresolvedChallengeBlocks: true,
		},
		roles: [
			{
				id: "mapper",
				mustEmit: ["artifact_handoff", "claim"],
				allowedClaimKinds: ["observed", "proven", "gap", "stale", "inferred"],
				forbiddenClaimKinds: ["final_pass_without_validation"],
				handoffTargets: ["verifier", "adversary", "synthesizer"],
				evidenceContract: ["artifact_handoff sha256 is present", "claim evidenceRefs bind artifactId/query/op/value"],
			},
			{
				id: "verifier",
				mustEmit: ["validation"],
				allowedClaimKinds: ["observed", "proven", "gap", "frontier_gap", "stale", "inferred", "final_pass"],
				forbiddenClaimKinds: ["final_pass_without_artifact_validation"],
				mustValidateClaimKinds: ["proven", "final_pass"],
				handoffTargets: ["adversary", "synthesizer"],
				evidenceContract: ["validation result is pass/fail", "checks preserve observed values"],
			},
			{
				id: "adversary",
				mustEmit: ["challenge"],
				allowedClaimKinds: ["gap", "frontier_gap", "stale", "inferred"],
				forbiddenClaimKinds: ["unresolved_final_pass"],
				mustChallengeScopes: ["bilibili", "xiaohongshu", "douyin", "same-window", "orchestration-vs-platform"],
				handoffTargets: ["synthesizer"],
				evidenceContract: ["required gaps receive upheld challenge", "platform/orchestration conflation is challenged"],
			},
			{
				id: "synthesizer",
				mustEmit: ["resolution"],
				allowedClaimKinds: ["observed", "proven", "gap", "frontier_gap", "stale", "inferred", "final_pass"],
				forbiddenClaimKinds: ["platform_success_from_orchestration_only"],
				mustResolve: ["all_required_gaps", "all_conflicts", "orchestration_platform_score_split"],
				handoffTargets: [],
				evidenceContract: ["resolution cites claimIds", "conflict policy preserves required platform gaps"],
			},
		],
	};
}

function claimKind(passed, required) {
	if (passed) return "proven";
	return required ? "gap" : "frontier_gap";
}

function severity(required, gate) {
	return required ? "required" : gate?.severity ?? "frontier";
}

function buildPlatformClaims({ sameWindow, artifactId, events }) {
	const claims = [];
	for (const spec of PLATFORM_CLAIM_GATES) {
		const gate = gateByName(sameWindow, spec.gate);
		const passed = Boolean(gate?.passed);
		const idBase = spec.scope.replace(/[^a-z0-9]+/gi, "_");
		const claimId = `claim:platform:${idBase}`;
		const evidenceRef = { artifactId, query: `gates[name=${spec.gate}].passed`, op: "==", value: true };
		const claim = {
			claimId,
			role: "mapper",
			scope: spec.scope,
			kind: claimKind(passed, spec.required),
			required: spec.required,
			weight: spec.weight,
			statement: passed
				? `${spec.scope} is proven by same-window gate ${spec.gate}`
				: `${spec.scope} is not proven by same-window gate ${spec.gate}`,
			evidenceRefs: [evidenceRef],
			gate: spec.gate,
			severity: severity(spec.required, gate),
			observed: passed,
		};
		claims.push(claim);
		appendEvent(events, { type: "claim", ...claim });
		const observed = getQueryValue(sameWindow, evidenceRef.query);
		appendEvent(events, {
			type: "validation",
			claimId,
			role: "verifier",
			result: observed === evidenceRef.value ? "pass" : "fail",
			checks: [{ ...evidenceRef, observed }],
		});
		if (!passed) {
			appendEvent(events, {
				type: "challenge",
				claimId,
				role: "adversary",
				result: "upheld",
				reason: `same-window gate ${spec.gate} is false; claim must remain ${claim.kind}`,
			});
			appendEvent(events, {
				type: "resolution",
				role: "synthesizer",
				claimIds: [claimId],
				decision: "downgrade",
				winner: claimId,
				dominantTier: "same_window_live",
				reason: "live same-window evidence outranks agent narrative and older hard-score rows",
			});
		}
	}
	return claims;
}

function buildOrchestrationClaims({ agentParallel, artifactId, events }) {
	if (!agentParallel) return [];
	const gates = agentParallel.gates ?? {};
	const claims = [
		{
			claimId: "claim:orchestration:parallel_runtime",
			role: "mapper",
			scope: "orchestration.parallel_runtime",
			kind: ORCHESTRATION_GATES.every((name) => gates[name]) ? "proven" : "gap",
			required: true,
			statement: "parallel agent runtime gates are separated from platform target claims",
			evidenceRefs: ORCHESTRATION_GATES.map((name) => ({ artifactId, query: `gates.${name}`, op: "==", value: true })),
		},
		{
			claimId: "claim:orchestration:model_tool_runtime",
			role: "mapper",
			scope: "orchestration.model_tool_runtime",
			kind: (agentParallel.totals?.modelCalls ?? 0) > 0 && (agentParallel.totals?.toolCalls ?? 0) > 0 ? "proven" : "gap",
			required: true,
			statement: "model/tool runtime happened and is counted separately from platform proof",
			evidenceRefs: [
				{ artifactId, query: "totals.modelCalls", op: ">", value: 0 },
				{ artifactId, query: "totals.toolCalls", op: ">", value: 0 },
			],
		},
	];
	for (const claim of claims) {
		appendEvent(events, { type: "claim", ...claim });
		appendEvent(events, { type: "validation", claimId: claim.claimId, role: "verifier", result: claim.kind === "proven" ? "pass" : "fail", checks: claim.evidenceRefs });
		if (claim.kind !== "proven") {
			appendEvent(events, {
				type: "challenge",
				claimId: claim.claimId,
				role: "adversary",
				result: "upheld",
				reason: `${claim.scope} is not proven; orchestration gaps cannot be promoted by synthesizer narrative`,
			});
			appendEvent(events, {
				type: "resolution",
				role: "synthesizer",
				claimIds: [claim.claimId],
				decision: "downgrade",
				winner: claim.claimId,
				dominantTier: "runtime_artifact",
				reason: "runtime artifact gate values overrule optimistic orchestration summary",
			});
		}
	}
	return claims;
}

function weightedScore(claims, predicate) {
	const selected = claims.filter(predicate);
	const max = selected.reduce((sum, claim) => sum + (claim.weight ?? 1), 0);
	const got = selected.filter((claim) => claim.kind === "proven").reduce((sum, claim) => sum + (claim.weight ?? 1), 0);
	return { score: max ? Math.round((got / max) * 100) : 0, passedWeight: got, maxWeight: max, total: selected.length, passed: selected.filter((claim) => claim.kind === "proven").length };
}

function simplePercent(names, gates) {
	const passed = names.filter((name) => Boolean(gates?.[name])).length;
	return { score: names.length ? Math.round((passed / names.length) * 100) : 0, passed, total: names.length };
}

function failureCategory(claim) {
	if (/xiaohongshu/.test(claim.scope)) return "same_window_xhs_gap";
	if (/douyin/.test(claim.scope)) return "same_window_douyin_gap";
	if (/bilibili/.test(claim.scope)) return "same_window_bilibili_gap";
	return "platform_claim_gap";
}

function repairAction(claim) {
	if (/xiaohongshu/.test(claim.scope)) {
		return {
			action: "recapture-evidence",
			commands: ["node bench/recon-remote/real-platform/run.mjs --platform xiaohongshu"],
			expectedArtifacts: [".pi/evidence/remote/real-platform/xiaohongshu-note/**/result.json"],
			note: "resume only when live testing is allowed; require signed x-s/x-t trace and target structured 2xx claim before promotion",
		};
	}
	if (/douyin/.test(claim.scope)) {
		return {
			action: "recapture-evidence",
			commands: ["node bench/recon-remote/douyin-nowatermark/run.mjs"],
			expectedArtifacts: [".pi/evidence/remote/douyin-nowatermark/**/result.json"],
			note: "resume only when live testing is allowed; require browser-captured structured API replay before promotion",
		};
	}
	return {
		action: "recapture-evidence",
		commands: ["node bench/recon-remote/same-window-live/run.mjs --strict"],
		expectedArtifacts: [".pi/evidence/remote/same-window-live/**/result.json"],
		note: "resume only when live testing is allowed",
	};
}

function buildFailures({ claims, sourceArtifact }) {
	const failures = [];
	const repairs = [];
	const artifactRows = sourceArtifact?.path
		? [
				{
					path: sourceArtifact.path,
					sha256: sourceArtifact.sha256,
					tier: "same_window_live",
					bytes: sourceArtifact.bytes,
				},
			].filter((artifact) => artifact.path && artifact.sha256)
		: [];
	for (const claim of claims.filter((item) => item.kind !== "proven")) {
		const signature = sha256Bytes(`${claim.scope}:${claim.gate}:${claim.kind}`).slice(0, 16);
		const failureId = `fail:hard-eval:${signature}`;
		const repairId = `repair:hard-eval:${signature}`;
		failures.push({
			id: failureId,
			ts: new Date().toISOString(),
			source: "hard-eval-control-plane",
			scope: claim.scope,
			category: failureCategory(claim),
			signature,
			attempt: 0,
			maxAttempts: 0,
			status: "failed",
			failedGates: [claim.gate],
			artifacts: artifactRows,
			artifactHashes: artifactRows.map((artifact) => ({ path: artifact.path, sha256: artifact.sha256 })),
			repairId,
			budget: {
				retryKey: signature,
				remainingAttempts: 0,
				exhaustedAction: "queue-paused-repair",
			},
			rollback: {
				required: false,
				baseline: "offline-existing-evidence-only",
				allowlist: [],
				criteria: [],
				restored: null,
			},
		});
		repairs.push({
			repairId,
			fromFailureId: failureId,
			signature,
			scope: claim.scope,
			paused: true,
			expectedGates: [claim.gate],
			preconditions: { liveAllowed: false, providerAllowed: false, requiredSecrets: [] },
			allowlist: [],
			rollbackCriteria: { baseline: "offline-existing-evidence-only", mustRestore: [], verificationCommand: "" },
			regressionGates: [claim.gate],
			...repairAction(claim),
		});
	}
	return { failures, repairs };
}

function buildResult(root) {
	const sameWindowPath = latestFile(root, ".pi/evidence/remote/same-window-live", "result.json");
	const agentParallelPath = latestFile(root, ".pi/evidence/remote/agent-parallel-dogfood", "result.json");
	const hardScorePath = latestFile(root, ".pi/evidence/remote/hard-score", "scoreboard.json");
	const sameWindow = sameWindowPath ? readJson(sameWindowPath) : null;
	const agentParallel = agentParallelPath ? readJson(agentParallelPath) : null;
	const hardScore = hardScorePath ? readJson(hardScorePath) : null;
	const runId = `hard-eval-control-plane/${new Date().toISOString()}`;
	const contract = buildContract(runId);
	const events = [];
	const artifacts = {
		sameWindow: fileMeta(root, sameWindowPath),
		agentParallel: fileMeta(root, agentParallelPath),
		hardScore: fileMeta(root, hardScorePath),
	};
	for (const [artifactId, meta] of Object.entries(artifacts)) {
		appendEvent(events, { type: "artifact_handoff", artifactId, family: artifactId, tier: artifactId === "sameWindow" ? "same_window_live" : "runtime_artifact", ...meta });
	}
	const platformClaims = buildPlatformClaims({ sameWindow, artifactId: "sameWindow", events });
	const orchestrationClaims = buildOrchestrationClaims({ agentParallel, artifactId: "agentParallel", events });
	const platformRequired = weightedScore(platformClaims, (claim) => claim.required);
	const platformAll = weightedScore(platformClaims, () => true);
	const orchestration = simplePercent(ORCHESTRATION_GATES, agentParallel?.gates ?? {});
	const platformGaps = platformClaims.filter((claim) => claim.kind !== "proven");
	const requiredPlatformGaps = platformGaps.filter((claim) => claim.required);
	const { failures, repairs } = buildFailures({ claims: platformGaps, sourceArtifact: artifacts.sameWindow });
	const antiSelfDelusion = {
		orchestrationScore: orchestration.score,
		platformRequiredScore: platformRequired.score,
		platformAllScore: platformAll.score,
		orchestrationPlatformSplit: true,
		blocksPlatformSuccessSummary: requiredPlatformGaps.length > 0,
		reason: requiredPlatformGaps.length
			? "required live platform gaps exist; orchestration success cannot be reported as platform success"
			: "no required live platform gaps in latest same-window artifact",
	};
	const gate = {
		artifactPathsExist: Object.values(artifacts).every((artifact) => artifact.exists),
		artifactHashesBound: Object.values(artifacts).every((artifact) => artifact.exists && artifact.sha256),
		claimLedgerPresent: events.some((event) => event.type === "claim"),
		requiredPlatformClaimsValidated: requiredPlatformGaps.length === 0,
		orchestrationClaimsValidated: orchestrationClaims.every((claim) => claim.kind === "proven"),
		orchestrationSeparatedFromPlatform: true,
		antiSelfDelusion: antiSelfDelusion.blocksPlatformSuccessSummary ? platformGaps.length > 0 : true,
	};
	const verdict = gate.artifactPathsExist && gate.claimLedgerPresent && gate.orchestrationSeparatedFromPlatform
		? requiredPlatformGaps.length
			? "hard-eval-control-plane-platform-gaps"
			: "hard-eval-control-plane-claims-passed"
		: "hard-eval-control-plane-missing-evidence";
	return {
		kind: "pi-recon-hard-eval-control-plane",
		version: 1,
		generatedAt: new Date().toISOString(),
		root,
		runId,
		mode: "offline-existing-evidence-only",
		verdict,
		contract,
		artifacts,
		scores: {
			orchestration,
			platformRequired,
			platformAll,
		},
		antiSelfDelusion,
		gate,
		claims: {
			platform: platformClaims,
			orchestration: orchestrationClaims,
		},
		ledger: events,
		failures,
		repairQueue: repairs,
		testCommandsPaused: TEST_COMMANDS_PAUSED,
		sourceSummary: {
			sameWindowVerdict: sameWindow?.verdict ?? null,
			frontierGaps: sameWindow?.frontierGaps ?? [],
			agentParallelVerdict: agentParallel?.verdict ?? null,
			hardScoreTopScore: hardScore?.topScore ?? null,
		},
	};
}

function ensureDir(path) {
	mkdirSync(path, { recursive: true });
}

function writeOutputs(root, result) {
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const outDir = join(root, ".pi", "evidence", "hard-eval-control-plane", stamp);
	ensureDir(outDir);
	writeFileSync(join(outDir, "result.json"), `${JSON.stringify(result, null, 2)}\n`);
	writeFileSync(join(outDir, "contract.json"), `${JSON.stringify(result.contract, null, 2)}\n`);
	writeFileSync(join(outDir, "gate.json"), `${JSON.stringify(result.gate, null, 2)}\n`);
	writeFileSync(join(outDir, "ledger.jsonl"), result.ledger.map((event) => JSON.stringify(event)).join("\n") + "\n");
	writeFileSync(join(outDir, "failure-ledger.jsonl"), result.failures.map((event) => JSON.stringify(event)).join("\n") + (result.failures.length ? "\n" : ""));
	writeFileSync(join(outDir, "repair-queue.jsonl"), result.repairQueue.map((event) => JSON.stringify(event)).join("\n") + (result.repairQueue.length ? "\n" : ""));
	writeFileSync(join(outDir, "report.md"), formatMarkdown(result));
	return outDir;
}

function formatMarkdown(result) {
	const lines = [
		"# Pi-RECON Hard Eval Control Plane",
		"",
		`generated_at: ${result.generatedAt}`,
		`mode: ${result.mode}`,
		`verdict: ${result.verdict}`,
		`orchestration_score: ${result.scores.orchestration.score}`,
		`platform_required_score: ${result.scores.platformRequired.score}`,
		`platform_all_score: ${result.scores.platformAll.score}`,
		"",
		"## Outcome",
		"",
		result.antiSelfDelusion.reason,
		"",
		"## Artifact handoff",
		...Object.entries(result.artifacts).map(([id, meta]) => `- ${id}: ${meta.exists ? `${meta.path} sha256=${meta.sha256.slice(0, 16)} bytes=${meta.bytes}` : "missing"}`),
		"",
		"## Platform claims",
		...result.claims.platform.map((claim) => `- ${claim.scope}: ${claim.kind} gate=${claim.gate} required=${claim.required}`),
		"",
		"## Orchestration claims",
		...result.claims.orchestration.map((claim) => `- ${claim.scope}: ${claim.kind}`),
		"",
		"## Failure ledger",
		...(result.failures.length ? result.failures.map((failure) => `- ${failure.id}: ${failure.category} scope=${failure.scope} gates=${failure.failedGates.join(",")}`) : ["- none"]),
		"",
		"## Repair queue",
		...(result.repairQueue.length ? result.repairQueue.map((repair) => `- ${repair.repairId}: paused=${repair.paused} action=${repair.action} scope=${repair.scope}`) : ["- none"]),
		"",
		"## Paused live commands",
		...result.testCommandsPaused.map((command) => `- ${command}`),
		"",
	];
	return `${lines.join("\n")}\n`;
}

function printHelp() {
	console.log(`Usage: node scripts/reverse-agent/hard-eval-control-plane.mjs [root] [--json] [--write] [--strict-claims]\n\nBuilds an offline claim ledger, failure ledger, and split orchestration/platform score from existing remote evidence. It does not contact real sites or call model providers.`);
}

function main(argv) {
	if (argv.includes("--help") || argv.includes("-h")) return printHelp();
	const rootArg = argv.find((arg) => !arg.startsWith("-"));
	const root = resolve(rootArg ?? DEFAULT_ROOT);
	const json = argv.includes("--json");
	const write = argv.includes("--write");
	const strictClaims = argv.includes("--strict-claims");
	const result = buildResult(root);
	if (write) result.artifactDir = relPath(root, writeOutputs(root, result));
	if (json) console.log(JSON.stringify(result, null, 2));
	else process.stdout.write(formatMarkdown(result));
	if (strictClaims && result.verdict !== "hard-eval-control-plane-claims-passed") process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	main(process.argv.slice(2));
}
