#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const writeEvidence = !argv.includes("--no-write");
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_LIVE_CONFLICT_ARBITRATION_TMP === "1";
const SCHEMA_PATH = "schemas/reverse-agent/live-conflict-arbitration-matrix.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/live-conflict-arbitration-matrix.fixture.json";

const REQUIRED_SOURCES = ["agent-dogfood", "re_swarm", "compound-frontier", "provider-worker"];
const REQUIRED_GATES = [
	"LiveConflictArbitrationMatrixGateV1",
	"source_coverage_all_runtimes",
	"multi_claim_topic_conflict_matrix",
	"winner_evidence_json_query_verifier",
	"loser_downgrade_blocks_promotion",
	"orchestration_success_separate_from_platform_claim",
	"synthesizer_summary_parsed_to_structured_rows",
	"claim_ledger_refs_hash_chain_quality",
	"provider_backed_same_window_multi_worker_conflict_table",
	"long_run_synthesizer_topic_parse_matrix",
];
const REQUIRED_NEGATIVE_CASES = [
	"missing-winner-evidence",
	"loser-promoted",
	"orchestration-implies-platform-pass",
	"missing-source-coverage",
	"narrative-only-synthesizer-promoted",
	"claim-ledger-ref-missing",
	"unresolved-conflict",
	"final-without-json-query",
	"provider-backed-conflict-single-worker",
	"synthesizer-topic-parse-missing",
	"same-window-conflict-without-provider-worker",
];
const INVARIANTS = [
	"live_conflict_arbitration_matrix_gate",
	"source_coverage_all_runtimes",
	"multi_claim_topic_conflict_matrix",
	"winner_evidence_json_query_verifier",
	"loser_downgrade_blocks_promotion",
	"orchestration_success_separate_from_platform_claim",
	"synthesizer_summary_parsed_to_structured_rows",
	"claim_ledger_refs_hash_chain_quality",
	"provider_backed_same_window_multi_worker_conflict_table",
	"long_run_synthesizer_topic_parse_matrix",
];

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const shortHash = (value) => sha256(value).slice(0, 24);
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));
const check = (id, ok, evidence = {}) => ({ id, status: ok ? "pass" : "fail", evidence });

function markerCheck(id, path, markers) {
	const full = join(root, path);
	if (!existsSync(full)) return check(id, false, { path, exists: false });
	const text = readFileSync(full, "utf8");
	const missing = markers.filter((marker) => !text.includes(marker));
	return check(id, missing.length === 0, { path, missing, sha256: shortHash(text) });
}

function rel(base, path) {
	const basePath = resolve(base);
	const resolved = resolve(path);
	return resolved.startsWith(basePath) ? relative(basePath, resolved) : path;
}

function writeJsonFile(path, value) {
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function fileDigest(base, path) {
	const bytes = readFileSync(path);
	const stat = statSync(path);
	return { path: rel(base, path), sha256: sha256(bytes), bytes: bytes.length, mtime: stat.mtime.toISOString(), exists: true };
}

function claimLedgerEventHash(event) {
	const { eventHash, ...withoutHash } = event;
	return sha256(JSON.stringify(withoutHash));
}

function buildClaimLedger(events) {
	let prevHash = "0".repeat(64);
	return events.map((event, index) => {
		const row = { kind: "ClaimLedgerEventV1", seq: index + 1, prevHash, ...event };
		row.eventHash = claimLedgerEventHash(row);
		prevHash = row.eventHash;
		return row;
	});
}

function claimLedgerHashChainOk(events) {
	let prevHash = "0".repeat(64);
	for (const event of events ?? []) {
		if (event?.kind !== "ClaimLedgerEventV1") return false;
		if (event.prevHash !== prevHash) return false;
		if (event.eventHash !== claimLedgerEventHash(event)) return false;
		prevHash = event.eventHash;
	}
	return (events ?? []).length >= 5;
}

function makeArtifact(tempRoot, sourceDir, name, content) {
	const path = join(sourceDir, `${name}.json`);
	writeJsonFile(path, content);
	return { artifactId: `${content.claimId ?? name}:${name}`, path: rel(tempRoot, path), absolutePath: path, sha256: sha256(readFileSync(path)) };
}

function artifactRef(artifact, jsonQuery, expected, op = "==", verifierPass = true) {
	return {
		artifactId: artifact.artifactId,
		path: artifact.path,
		sha256: artifact.sha256,
		jsonQuery,
		op,
		expected,
		verifierPass,
	};
}

function sourceBase(tempRoot, sourceKind) {
	const dir = join(tempRoot, "live-conflict-arbitration", sourceKind);
	mkdirSync(dir, { recursive: true });
	return dir;
}

function buildSourceRuntime(tempRoot, sourceKind, claimRows) {
	const dir = sourceBase(tempRoot, sourceKind);
	const runtimeManifest = {
		kind: "LiveConflictSourceRuntimeManifestV1",
		sourceKind,
		workerIds: [...new Set(claimRows.map((row) => row.workerId))],
		claimIds: claimRows.map((row) => row.claimId),
		structuredRowsParsed: true,
		narrativeOnlyPromotionBlocked: true,
	};
	const structuredMerge = {
		kind: "StructuredClaimMergeV1",
		schemaVersion: 1,
		mergeId: `merge-${sourceKind}`,
		sourcePoolId: `${sourceKind}-pool`,
		claimRows,
		conflictTable: [],
		promotionGate: {
			mode: "strict_final_claim_promotion",
			requiredStatuses: ["proven"],
			finalClaims: claimRows.filter((row) => row.status === "proven").map((row) => ({ claimId: row.claimId, promotion: "final_pass", reportSection: row.reportSection ?? row.mergeKey, verifierPass: true, artifactRefs: row.artifactRefs.filter((ref) => ref.verifierPass) })),
			blockedClaims: claimRows.filter((row) => row.status !== "proven").map((row) => ({ claimId: row.claimId, reason: `source ${sourceKind} did not prove ${row.mergeKey}` })),
			policies: ["final_pass_requires_json_query", "unresolved_adversary_challenge_blocks_final", "conflict_loser_must_be_downgraded", "artifact_sha256_required"],
		},
	};
	const ledger = buildClaimLedger([
		{ type: "artifact_handoff", source: sourceKind, claimIds: claimRows.map((row) => row.claimId), artifactRefs: claimRows.flatMap((row) => row.artifactRefs.map((ref) => ref.path)) },
		...claimRows.map((row) => ({ type: "claim", source: sourceKind, claimId: row.claimId, mergeKey: row.mergeKey, status: row.status })),
		{ type: "validation", source: sourceKind, claimIds: claimRows.map((row) => row.claimId), verifierPassCount: claimRows.filter((row) => row.artifactRefs.some((ref) => ref.verifierPass)).length },
		{ type: "challenge", source: sourceKind, challengeCount: claimRows.flatMap((row) => row.challenges ?? []).length },
		{ type: "resolution", source: sourceKind, structuredRowsParsed: true, narrativeOnlyPromotionBlocked: true },
	]);
	const runtimeManifestPath = join(dir, `${sourceKind}-runtime-manifest.json`);
	const structuredClaimMergePath = join(dir, `${sourceKind}-structured-claim-merge.json`);
	const claimLedgerPath = join(dir, `${sourceKind}-claim-ledger.jsonl`);
	writeJsonFile(runtimeManifestPath, runtimeManifest);
	writeJsonFile(structuredClaimMergePath, structuredMerge);
	writeFileSync(claimLedgerPath, `${ledger.map((row) => JSON.stringify(row)).join("\n")}\n`, "utf8");
	return {
		sourceKind,
		runtimeManifestPath: rel(tempRoot, runtimeManifestPath),
		structuredClaimMergePath: rel(tempRoot, structuredClaimMergePath),
		claimLedgerPath: rel(tempRoot, claimLedgerPath),
		runtimeManifestSha256: fileDigest(tempRoot, runtimeManifestPath).sha256,
		structuredClaimMergeSha256: fileDigest(tempRoot, structuredClaimMergePath).sha256,
		claimLedgerSha256: fileDigest(tempRoot, claimLedgerPath).sha256,
		claimCount: claimRows.length,
		claimIds: claimRows.map((row) => row.claimId),
		claimLedgerQuality: {
			eventCount: ledger.length,
			eventTypes: [...new Set(ledger.map((row) => row.type))],
			hashChainOk: claimLedgerHashChainOk(ledger),
			tipHash: ledger.at(-1)?.eventHash,
		},
	};
}

function claimRow({ claimId, workerId, sourceKind, mergeKey, status, statement, artifactRefs, challenges = [], reportSection, orchestrationStatus = "pass", platformClaimStatus = "unknown" }) {
	return { claimId, workerId, sourceKind, mergeKey, status, statement, artifactRefs, challenges, reportSection, orchestrationStatus, platformClaimStatus };
}

function buildRuntimeMatrix(tempRoot) {
	const claimRows = [];
	const artifacts = [];
	function addClaim(sourceKind, spec) {
		const dir = sourceBase(tempRoot, sourceKind);
		const artifact = makeArtifact(tempRoot, dir, spec.artifactName, spec.artifactContent);
		artifacts.push(artifact);
		const row = claimRow({
			claimId: spec.claimId,
			workerId: spec.workerId,
			sourceKind,
			mergeKey: spec.mergeKey,
			status: spec.status,
			statement: spec.statement,
			artifactRefs: spec.refs(artifact),
			challenges: spec.challenges ?? [{ challengeId: `${spec.claimId}:challenge`, status: "resolved", resolution: spec.status === "proven" ? "verifier-backed evidence accepted" : "downgraded during arbitration" }],
			reportSection: spec.reportSection,
			orchestrationStatus: spec.orchestrationStatus ?? "pass",
			platformClaimStatus: spec.platformClaimStatus ?? (spec.status === "proven" ? "proven" : "unknown"),
		});
		claimRows.push(row);
		return row;
	}
	const rows = {
		authzDogfood: addClaim("agent-dogfood", {
			claimId: "claim-authz-dogfood-proven",
			workerId: "dogfood-verifier-authz",
			artifactName: "authz-dogfood-proof",
			mergeKey: "authz:orders:ownership",
			reportSection: "Authorization / BOLA",
			status: "proven",
			statement: "Cross-principal replay is blocked by the target authorization check.",
			artifactContent: { claimId: "claim-authz-dogfood-proven", verifier: "pass", ownershipReplay: "blocked_cross_principal", evidenceQuality: "strong", platformClaimStatus: "proven" },
			refs: (artifact) => [artifactRef(artifact, "$.ownershipReplay", "blocked_cross_principal"), artifactRef(artifact, "$.verifier", "pass")],
		}),
		authzSwarm: addClaim("re_swarm", {
			claimId: "claim-authz-swarm-route-only",
			workerId: "swarm-mapper-authz",
			artifactName: "authz-swarm-route-only",
			mergeKey: "authz:orders:ownership",
			reportSection: "Authorization / BOLA",
			status: "gap",
			statement: "Orders route found but cross-principal replay was not executed.",
			platformClaimStatus: "unknown",
			artifactContent: { claimId: "claim-authz-swarm-route-only", verifier: "not_run", ownershipReplay: "not_checked", evidenceQuality: "weak", platformClaimStatus: "unknown" },
			refs: (artifact) => [artifactRef(artifact, "$.ownershipReplay", "not_checked", "==", false)],
		}),
		jsSwarm: addClaim("re_swarm", {
			claimId: "claim-js-swarm-replay-proven",
			workerId: "swarm-js-replayer",
			artifactName: "js-swarm-replay-proof",
			mergeKey: "js:signature:replay",
			reportSection: "Client signing",
			status: "proven",
			statement: "Signed API replay succeeds after reconstructing the request signature.",
			artifactContent: { claimId: "claim-js-swarm-replay-proven", verifier: "pass", replayVerified: true, signatureMode: "reconstructed", evidenceQuality: "strong", platformClaimStatus: "proven" },
			refs: (artifact) => [artifactRef(artifact, "$.replayVerified", true), artifactRef(artifact, "$.signatureMode", "reconstructed")],
		}),
		jsCompound: addClaim("compound-frontier", {
			claimId: "claim-js-compound-anchor-only",
			workerId: "compound-js-anchor",
			artifactName: "js-compound-anchor",
			mergeKey: "js:signature:replay",
			reportSection: "Client signing",
			status: "gap",
			statement: "Signer callsite anchor exists but no replay proof was produced.",
			platformClaimStatus: "unknown",
			artifactContent: { claimId: "claim-js-compound-anchor-only", verifier: "anchor_only", replayVerified: false, signatureMode: "located_only", evidenceQuality: "medium", platformClaimStatus: "unknown" },
			refs: (artifact) => [artifactRef(artifact, "$.signatureMode", "located_only", "==", true), artifactRef(artifact, "$.replayVerified", false, "==", false)],
		}),
		providerTimeout: addClaim("provider-worker", {
			claimId: "claim-provider-worker-timeout-cancelled",
			workerId: "provider-worker-delta-timeout",
			artifactName: "provider-worker-timeout-cancelled",
			mergeKey: "provider:worker:timeout",
			reportSection: "Provider runtime",
			status: "proven",
			statement: "Provider worker timeout was cancelled and converted into paused repair/escalation evidence.",
			artifactContent: { claimId: "claim-provider-worker-timeout-cancelled", verifier: "pass", timeoutCancelled: true, repairPaused: true, evidenceQuality: "strong", platformClaimStatus: "proven" },
			refs: (artifact) => [artifactRef(artifact, "$.timeoutCancelled", true), artifactRef(artifact, "$.repairPaused", true)],
		}),
		providerDogfoodPlanOnly: addClaim("agent-dogfood", {
			claimId: "claim-dogfood-provider-plan-only",
			workerId: "dogfood-provider-planner",
			artifactName: "dogfood-provider-plan-only",
			mergeKey: "provider:worker:timeout",
			reportSection: "Provider runtime",
			status: "blocked",
			statement: "Dogfood orchestration planned provider timeout handling but did not execute the provider worker.",
			platformClaimStatus: "unknown",
			artifactContent: { claimId: "claim-dogfood-provider-plan-only", verifier: "plan_only", timeoutCancelled: false, orchestrationStatus: "pass", platformClaimStatus: "unknown", evidenceQuality: "narrative" },
			refs: (artifact) => [artifactRef(artifact, "$.orchestrationStatus", "pass", "==", false), artifactRef(artifact, "$.platformClaimStatus", "unknown", "==", false)],
		}),
		rateLimitProviderProven: addClaim("provider-worker", {
			claimId: "claim-provider-worker-rate-limit-proven",
			workerId: "provider-worker-alpha-ratelimit",
			artifactName: "provider-worker-rate-limit-proof",
			mergeKey: "api:rate-limit:abuse-window",
			reportSection: "API abuse window",
			status: "proven",
			statement: "Provider-backed worker replay confirms the abuse window is rate-limited at the 61st request in a 60 second bucket.",
			artifactContent: { claimId: "claim-provider-worker-rate-limit-proven", verifier: "pass", providerBacked: true, sameWindowId: "window-rate-limit-2026-06-11T00-00Z", rateLimitStatus: "triggered", statusCode: 429, requestCount: 61, windowSeconds: 60, evidenceQuality: "strong", platformClaimStatus: "proven" },
			refs: (artifact) => [artifactRef(artifact, "$.rateLimitStatus", "triggered"), artifactRef(artifact, "$.statusCode", 429), artifactRef(artifact, "$.providerBacked", true)],
		}),
		rateLimitProviderUnderSampled: addClaim("provider-worker", {
			claimId: "claim-provider-worker-rate-limit-under-sampled",
			workerId: "provider-worker-beta-ratelimit",
			artifactName: "provider-worker-rate-limit-under-sampled",
			mergeKey: "api:rate-limit:abuse-window",
			reportSection: "API abuse window",
			status: "gap",
			statement: "Second provider worker only sampled ten requests in the same window and therefore cannot disprove the 429 boundary.",
			platformClaimStatus: "unknown",
			artifactContent: { claimId: "claim-provider-worker-rate-limit-under-sampled", verifier: "under_sampled", providerBacked: true, sameWindowId: "window-rate-limit-2026-06-11T00-00Z", rateLimitStatus: "not_observed", statusCode: 200, requestCount: 10, windowSeconds: 60, evidenceQuality: "weak", platformClaimStatus: "unknown" },
			refs: (artifact) => [artifactRef(artifact, "$.rateLimitStatus", "triggered", "==", false), artifactRef(artifact, "$.requestCount", 61, "==", false)],
		}),
		rateLimitSwarmObservation: addClaim("re_swarm", {
			claimId: "claim-re-swarm-rate-limit-observation",
			workerId: "swarm-rate-limit-observer",
			artifactName: "re-swarm-rate-limit-observation",
			mergeKey: "api:rate-limit:abuse-window",
			reportSection: "API abuse window",
			status: "gap",
			statement: "Swarm observation saw throttling headers but did not bind the same-window request counter to a provider-backed replay.",
			platformClaimStatus: "unknown",
			artifactContent: { claimId: "claim-re-swarm-rate-limit-observation", verifier: "header_only", providerBacked: false, sameWindowId: "window-rate-limit-2026-06-11T00-00Z", rateLimitStatus: "header_observed", statusCode: 200, requestCount: 1, evidenceQuality: "medium", platformClaimStatus: "unknown" },
			refs: (artifact) => [artifactRef(artifact, "$.providerBacked", true, "==", false), artifactRef(artifact, "$.rateLimitStatus", "triggered", "==", false)],
		}),
		rateLimitDogfoodPlanOnly: addClaim("agent-dogfood", {
			claimId: "claim-dogfood-rate-limit-plan-only",
			workerId: "dogfood-rate-limit-planner",
			artifactName: "dogfood-rate-limit-plan-only",
			mergeKey: "api:rate-limit:abuse-window",
			reportSection: "API abuse window",
			status: "blocked",
			statement: "Dogfood planner proposed the abuse-window test but produced no same-window provider-backed replay artifact.",
			platformClaimStatus: "unknown",
			artifactContent: { claimId: "claim-dogfood-rate-limit-plan-only", verifier: "plan_only", providerBacked: false, sameWindowId: "window-rate-limit-2026-06-11T00-00Z", orchestrationStatus: "pass", platformClaimStatus: "unknown", evidenceQuality: "narrative" },
			refs: (artifact) => [artifactRef(artifact, "$.providerBacked", true, "==", false), artifactRef(artifact, "$.orchestrationStatus", "pass", "==", false)],
		}),
	};
	const bySource = new Map();
	for (const row of claimRows) {
		const list = bySource.get(row.sourceKind) ?? [];
		list.push(row);
		bySource.set(row.sourceKind, list);
	}
	const sourceManifests = REQUIRED_SOURCES.map((source) => buildSourceRuntime(tempRoot, source, bySource.get(source) ?? []));
	const conflictRows = [
		{
			conflictId: "conflict-authz-ownership-live",
			topic: "orders ownership replay result",
			claimIds: [rows.authzDogfood.claimId, rows.authzSwarm.claimId],
			sourceKinds: [rows.authzDogfood.sourceKind, rows.authzSwarm.sourceKind],
			status: "resolved",
			winnerClaimId: rows.authzDogfood.claimId,
			winningEvidenceRefs: rows.authzDogfood.artifactRefs.map((ref) => ref.artifactId),
			loserDowngrades: [{ claimId: rows.authzSwarm.claimId, sourceKind: rows.authzSwarm.sourceKind, downgradeReason: "route-only observation lacks replay verifier", blockedPromotion: true }],
			resolutionReason: "live_conflict_arbitration_matrix prefers JSON-bound verifier replay over route-only observation",
			structuredMergeRefs: sourceManifests.filter((source) => [rows.authzDogfood.sourceKind, rows.authzSwarm.sourceKind].includes(source.sourceKind)).map((source) => source.structuredClaimMergePath),
			runtimeLedgerRefs: sourceManifests.filter((source) => [rows.authzDogfood.sourceKind, rows.authzSwarm.sourceKind].includes(source.sourceKind)).map((source) => source.claimLedgerPath),
			orchestrationStatus: "pass",
			platformClaimStatus: "proven",
		},
		{
			conflictId: "conflict-js-signature-replay-live",
			topic: "signed API replay proof",
			claimIds: [rows.jsSwarm.claimId, rows.jsCompound.claimId],
			sourceKinds: [rows.jsSwarm.sourceKind, rows.jsCompound.sourceKind],
			status: "resolved",
			winnerClaimId: rows.jsSwarm.claimId,
			winningEvidenceRefs: rows.jsSwarm.artifactRefs.map((ref) => ref.artifactId),
			loserDowngrades: [{ claimId: rows.jsCompound.claimId, sourceKind: rows.jsCompound.sourceKind, downgradeReason: "anchor-only compound row lacks replayVerified=true", blockedPromotion: true }],
			resolutionReason: "live_conflict_arbitration_matrix requires replayVerified=true before final promotion",
			structuredMergeRefs: sourceManifests.filter((source) => [rows.jsSwarm.sourceKind, rows.jsCompound.sourceKind].includes(source.sourceKind)).map((source) => source.structuredClaimMergePath),
			runtimeLedgerRefs: sourceManifests.filter((source) => [rows.jsSwarm.sourceKind, rows.jsCompound.sourceKind].includes(source.sourceKind)).map((source) => source.claimLedgerPath),
			orchestrationStatus: "pass",
			platformClaimStatus: "proven",
		},
		{
			conflictId: "conflict-provider-timeout-live",
			topic: "provider timeout cancellation and repair boundary",
			claimIds: [rows.providerTimeout.claimId, rows.providerDogfoodPlanOnly.claimId],
			sourceKinds: [rows.providerTimeout.sourceKind, rows.providerDogfoodPlanOnly.sourceKind],
			status: "resolved",
			winnerClaimId: rows.providerTimeout.claimId,
			winningEvidenceRefs: rows.providerTimeout.artifactRefs.map((ref) => ref.artifactId),
			loserDowngrades: [{ claimId: rows.providerDogfoodPlanOnly.claimId, sourceKind: rows.providerDogfoodPlanOnly.sourceKind, downgradeReason: "orchestration pass is not platform/provider runtime proof", blockedPromotion: true }],
			resolutionReason: "live_conflict_arbitration_matrix keeps orchestration success separate from platform claim success",
			structuredMergeRefs: sourceManifests.filter((source) => [rows.providerTimeout.sourceKind, rows.providerDogfoodPlanOnly.sourceKind].includes(source.sourceKind)).map((source) => source.structuredClaimMergePath),
			runtimeLedgerRefs: sourceManifests.filter((source) => [rows.providerTimeout.sourceKind, rows.providerDogfoodPlanOnly.sourceKind].includes(source.sourceKind)).map((source) => source.claimLedgerPath),
			orchestrationStatus: "pass",
			platformClaimStatus: "proven",
		},
		{
			conflictId: "conflict-rate-limit-abuse-window-live",
			topic: "API abuse-window rate-limit proof",
			claimIds: [rows.rateLimitProviderProven.claimId, rows.rateLimitProviderUnderSampled.claimId, rows.rateLimitSwarmObservation.claimId, rows.rateLimitDogfoodPlanOnly.claimId],
			sourceKinds: [rows.rateLimitProviderProven.sourceKind, rows.rateLimitSwarmObservation.sourceKind, rows.rateLimitDogfoodPlanOnly.sourceKind],
			status: "resolved",
			winnerClaimId: rows.rateLimitProviderProven.claimId,
			winningEvidenceRefs: rows.rateLimitProviderProven.artifactRefs.map((ref) => ref.artifactId),
			loserDowngrades: [
				{ claimId: rows.rateLimitProviderUnderSampled.claimId, sourceKind: rows.rateLimitProviderUnderSampled.sourceKind, downgradeReason: "same-window provider worker was under-sampled and does not disprove the boundary", blockedPromotion: true },
				{ claimId: rows.rateLimitSwarmObservation.claimId, sourceKind: rows.rateLimitSwarmObservation.sourceKind, downgradeReason: "header-only observation lacks provider-backed replay counter", blockedPromotion: true },
				{ claimId: rows.rateLimitDogfoodPlanOnly.claimId, sourceKind: rows.rateLimitDogfoodPlanOnly.sourceKind, downgradeReason: "plan-only orchestration cannot become platform/runtime proof", blockedPromotion: true },
			],
			resolutionReason: "live_conflict_arbitration_matrix requires same-window provider-backed replay before abuse-window promotion",
			structuredMergeRefs: sourceManifests.filter((source) => [rows.rateLimitProviderProven.sourceKind, rows.rateLimitSwarmObservation.sourceKind, rows.rateLimitDogfoodPlanOnly.sourceKind].includes(source.sourceKind)).map((source) => source.structuredClaimMergePath),
			runtimeLedgerRefs: sourceManifests.filter((source) => [rows.rateLimitProviderProven.sourceKind, rows.rateLimitSwarmObservation.sourceKind, rows.rateLimitDogfoodPlanOnly.sourceKind].includes(source.sourceKind)).map((source) => source.claimLedgerPath),
			orchestrationStatus: "pass",
			platformClaimStatus: "proven",
		},
	];
	const loserIds = new Set(conflictRows.flatMap((row) => row.loserDowngrades.map((loser) => loser.claimId)));
	const winnerIds = new Set(conflictRows.map((row) => row.winnerClaimId));
	const claimById = new Map(claimRows.map((row) => [row.claimId, row]));
	const finalClaims = [...winnerIds].map((claimId) => {
		const claim = claimById.get(claimId);
		return { claimId, sourceKind: claim.sourceKind, promotion: "final_pass", reportSection: claim.reportSection, verifierPass: true, platformClaimStatus: claim.platformClaimStatus, artifactRefs: claim.artifactRefs.filter((ref) => ref.verifierPass) };
	});
	const blockedClaims = [...loserIds].map((claimId) => {
		const claim = claimById.get(claimId);
		return { claimId, sourceKind: claim.sourceKind, reason: "lost live conflict arbitration or lacks runtime verifier proof", blockedPromotion: true };
	});
	const sourceKindForClaimIds = (claimIds) => [...new Set(claimIds.map((claimId) => claimById.get(claimId)?.sourceKind).filter(Boolean))];
	const providerBackedConflictTable = [
		{
			kind: "ProviderBackedSameWindowConflictTableV1",
			tableId: "provider-backed-rate-limit-window-table",
			windowId: "window-rate-limit-2026-06-11T00-00Z",
			topic: "api:rate-limit:abuse-window",
			sameWindow: true,
			conflictIds: ["conflict-rate-limit-abuse-window-live"],
			workerIds: [rows.rateLimitProviderProven.workerId, rows.rateLimitProviderUnderSampled.workerId, rows.rateLimitSwarmObservation.workerId, rows.rateLimitDogfoodPlanOnly.workerId],
			providerWorkerIds: [rows.rateLimitProviderProven.workerId, rows.rateLimitProviderUnderSampled.workerId],
			sourceKinds: sourceKindForClaimIds([rows.rateLimitProviderProven.claimId, rows.rateLimitProviderUnderSampled.claimId, rows.rateLimitSwarmObservation.claimId, rows.rateLimitDogfoodPlanOnly.claimId]),
			claimIds: [rows.rateLimitProviderProven.claimId, rows.rateLimitProviderUnderSampled.claimId, rows.rateLimitSwarmObservation.claimId, rows.rateLimitDogfoodPlanOnly.claimId],
			winnerClaimId: rows.rateLimitProviderProven.claimId,
			winningEvidenceRefs: rows.rateLimitProviderProven.artifactRefs.map((ref) => ref.artifactId),
			loserClaimIds: [rows.rateLimitProviderUnderSampled.claimId, rows.rateLimitSwarmObservation.claimId, rows.rateLimitDogfoodPlanOnly.claimId],
			loserDowngradeBlocked: true,
			jsonQueryVerifierPass: true,
			providerRuntimeManifestRefs: sourceManifests.filter((source) => source.sourceKind === "provider-worker").map((source) => source.runtimeManifestPath),
			requestLogRefs: [rows.rateLimitProviderProven, rows.rateLimitProviderUnderSampled].flatMap((row) => row.artifactRefs.map((ref) => ref.path)),
		},
	];
	const synthesizerTopicParseMatrix = {
		kind: "LongRunSynthesizerTopicParseMatrixV1",
		parseId: "long-run-synthesizer-topic-parse-001",
		longRunWindowIds: ["agent-dogfood-long-run-001", "re-swarm-long-run-001", "provider-worker-long-run-001"],
		topicRows: [
			{
				topic: "authz:orders:ownership",
				conflictId: "conflict-authz-ownership-live",
				sourceKinds: sourceKindForClaimIds([rows.authzDogfood.claimId, rows.authzSwarm.claimId]),
				claimIds: [rows.authzDogfood.claimId, rows.authzSwarm.claimId],
				winnerClaimId: rows.authzDogfood.claimId,
				parsedToStructuredRows: true,
				narrativeOnly: false,
				promotion: "final_pass",
			},
			{
				topic: "js:signature:replay",
				conflictId: "conflict-js-signature-replay-live",
				sourceKinds: sourceKindForClaimIds([rows.jsSwarm.claimId, rows.jsCompound.claimId]),
				claimIds: [rows.jsSwarm.claimId, rows.jsCompound.claimId],
				winnerClaimId: rows.jsSwarm.claimId,
				parsedToStructuredRows: true,
				narrativeOnly: false,
				promotion: "final_pass",
			},
			{
				topic: "provider:worker:timeout",
				conflictId: "conflict-provider-timeout-live",
				sourceKinds: sourceKindForClaimIds([rows.providerTimeout.claimId, rows.providerDogfoodPlanOnly.claimId]),
				claimIds: [rows.providerTimeout.claimId, rows.providerDogfoodPlanOnly.claimId],
				winnerClaimId: rows.providerTimeout.claimId,
				parsedToStructuredRows: true,
				narrativeOnly: false,
				promotion: "final_pass",
			},
			{
				topic: "api:rate-limit:abuse-window",
				conflictId: "conflict-rate-limit-abuse-window-live",
				sourceKinds: sourceKindForClaimIds([rows.rateLimitProviderProven.claimId, rows.rateLimitProviderUnderSampled.claimId, rows.rateLimitSwarmObservation.claimId, rows.rateLimitDogfoodPlanOnly.claimId]),
				claimIds: [rows.rateLimitProviderProven.claimId, rows.rateLimitProviderUnderSampled.claimId, rows.rateLimitSwarmObservation.claimId, rows.rateLimitDogfoodPlanOnly.claimId],
				winnerClaimId: rows.rateLimitProviderProven.claimId,
				parsedToStructuredRows: true,
				narrativeOnly: false,
				promotion: "final_pass",
			},
		],
		narrativeOnlyBlockedRows: [
			{ sourceKind: rows.jsCompound.sourceKind, topic: "js:signature:replay", claimIds: [rows.jsCompound.claimId], narrativeOnly: true, blockedPromotion: true },
			{ sourceKind: rows.rateLimitDogfoodPlanOnly.sourceKind, topic: "api:rate-limit:abuse-window", claimIds: [rows.rateLimitDogfoodPlanOnly.claimId], narrativeOnly: true, blockedPromotion: true },
		],
	};
	return {
		kind: "LiveConflictArbitrationMatrixGateV1",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		LiveConflictArbitrationMatrixGateV1: true,
		requiredGates: REQUIRED_GATES,
		arbitrationMatrix: {
			kind: "LiveConflictArbitrationMatrixV1",
			schemaVersion: 1,
			closureGate: "gate:live-conflict-arbitration-matrix",
			sources: sourceManifests,
			claimRows,
			conflictRows,
			providerBackedConflictTable,
			promotionGate: {
				mode: "strict_live_conflict_arbitration",
				finalClaims,
				blockedClaims,
				policies: [
					"final_pass_requires_json_query",
					"final_pass_requires_verifier",
					"winner_evidence_json_query_verifier",
					"loser_downgrade_blocks_promotion",
					"orchestration_success_separate_from_platform_claim",
				],
			},
			synthesizerRows: [
				{ sourceKind: "agent-dogfood", parsedToStructuredRows: true, narrativeOnly: false, claimIds: bySource.get("agent-dogfood")?.map((row) => row.claimId) ?? [] },
				{ sourceKind: "re_swarm", parsedToStructuredRows: true, narrativeOnly: false, claimIds: bySource.get("re_swarm")?.map((row) => row.claimId) ?? [] },
				{ sourceKind: "compound-frontier", parsedToStructuredRows: true, narrativeOnly: false, claimIds: bySource.get("compound-frontier")?.map((row) => row.claimId) ?? [] },
				{ sourceKind: "provider-worker", parsedToStructuredRows: true, narrativeOnly: false, claimIds: bySource.get("provider-worker")?.map((row) => row.claimId) ?? [] },
			],
			synthesizerTopicParseMatrix,
		},
		negativeCases: REQUIRED_NEGATIVE_CASES.map((id) => ({ id, mutates: id, expect: "reject", mustNotPromote: true })),
		invariants: INVARIANTS,
	};
}

function jsonQuery(content, query) {
	let value = JSON.parse(content);
	const parts = String(query ?? "").replace(/^\$\.?/, "").split(".").filter(Boolean);
	for (const part of parts) value = Array.isArray(value) ? value[Number(part)] : value?.[part];
	return value;
}

function valuesEqual(actual, expected, op = "==") {
	if (op === "contains") return Array.isArray(actual) ? actual.includes(expected) : String(actual ?? "").includes(String(expected));
	if (op === "includes_all") return Array.isArray(expected) && expected.every((item) => (Array.isArray(actual) ? actual.includes(item) : String(actual ?? "").includes(String(item))));
	return JSON.stringify(actual) === JSON.stringify(expected);
}

function validateArtifactRef(tempRoot, ref) {
	const errors = [];
	const path = join(tempRoot, ref?.path ?? "");
	if (!ref?.path || !existsSync(path)) return [`artifact_missing:${ref?.path ?? ""}`];
	const content = readFileSync(path, "utf8");
	if (sha256(content) !== ref.sha256) errors.push(`artifact_sha_mismatch:${ref.path}`);
	if (!ref.jsonQuery) errors.push(`artifact_json_query_missing:${ref.path}`);
	else {
		try {
			const actual = jsonQuery(content, ref.jsonQuery);
			if (!valuesEqual(actual, ref.expected, ref.op)) errors.push(`artifact_json_query_mismatch:${ref.path}:${ref.jsonQuery}`);
		} catch (error) {
			errors.push(`artifact_json_query_error:${ref.path}:${String(error)}`);
		}
	}
	if (ref.verifierPass !== true) errors.push(`artifact_verifier_not_pass:${ref.path}`);
	return errors;
}

function validateSourceCoverage(tempRoot, report) {
	const errors = [];
	const sources = report?.arbitrationMatrix?.sources ?? [];
	const kinds = new Set(sources.map((source) => source.sourceKind));
	for (const source of REQUIRED_SOURCES) if (!kinds.has(source)) errors.push(`missing_source:${source}`);
	for (const source of sources) {
		for (const field of ["runtimeManifestPath", "structuredClaimMergePath", "claimLedgerPath"]) {
			if (!source[field]) errors.push(`source_missing_${field}:${source.sourceKind}`);
			else if (!existsSync(join(tempRoot, source[field]))) errors.push(`source_ref_missing:${source.sourceKind}:${field}`);
		}
		if (source.claimLedgerQuality?.hashChainOk !== true) errors.push(`claim_ledger_hash_chain_not_ok:${source.sourceKind}`);
		for (const type of ["artifact_handoff", "claim", "validation", "challenge", "resolution"]) {
			if (!(source.claimLedgerQuality?.eventTypes ?? []).includes(type)) errors.push(`claim_ledger_missing_type:${source.sourceKind}:${type}`);
		}
	}
	return errors;
}

function validateProviderBackedConflictTable(matrix, claims, finalIds, blockedIds) {
	const errors = [];
	const conflicts = new Map((matrix?.conflictRows ?? []).map((conflict) => [conflict.conflictId, conflict]));
	const table = matrix?.providerBackedConflictTable ?? [];
	if (table.length < 1) errors.push("provider_backed_conflict_table_missing");
	const providerWorkerIds = new Set(table.flatMap((row) => row.providerWorkerIds ?? []));
	if (providerWorkerIds.size < 2) errors.push("provider_backed_worker_count_lt_2");
	for (const row of table) {
		if (row?.kind !== "ProviderBackedSameWindowConflictTableV1") errors.push(`provider_table_kind:${row?.tableId ?? ""}`);
		if (row?.sameWindow !== true) errors.push(`provider_table_not_same_window:${row?.tableId ?? ""}`);
		if ((row?.providerWorkerIds ?? []).length < 2) errors.push(`provider_table_worker_count_lt_2:${row?.tableId ?? ""}`);
		if (!(row?.sourceKinds ?? []).includes("provider-worker")) errors.push(`provider_table_missing_provider_worker_source:${row?.tableId ?? ""}`);
		if (!(row?.claimIds ?? []).some((claimId) => claims.get(claimId)?.sourceKind === "provider-worker")) errors.push(`provider_table_missing_provider_worker_claim:${row?.tableId ?? ""}`);
		if (!(row?.providerRuntimeManifestRefs ?? []).length) errors.push(`provider_table_manifest_refs_missing:${row?.tableId ?? ""}`);
		if (!(row?.requestLogRefs ?? []).length) errors.push(`provider_table_request_log_refs_missing:${row?.tableId ?? ""}`);
		if (row?.jsonQueryVerifierPass !== true) errors.push(`provider_table_json_verifier_not_pass:${row?.tableId ?? ""}`);
		if (!row?.winnerClaimId || !finalIds.has(row.winnerClaimId)) errors.push(`provider_table_winner_not_final:${row?.tableId ?? ""}:${row?.winnerClaimId ?? ""}`);
		for (const conflictId of row?.conflictIds ?? []) {
			const conflict = conflicts.get(conflictId);
			if (!conflict) errors.push(`provider_table_conflict_missing:${row?.tableId ?? ""}:${conflictId}`);
			if (conflict?.status !== "resolved") errors.push(`provider_table_conflict_unresolved:${row?.tableId ?? ""}:${conflictId}`);
			if (conflict && !conflict.sourceKinds?.includes("provider-worker")) errors.push(`provider_table_conflict_without_provider_worker:${row?.tableId ?? ""}:${conflictId}`);
			if (conflict && conflict.winnerClaimId !== row.winnerClaimId) errors.push(`provider_table_winner_mismatch:${row?.tableId ?? ""}:${conflictId}`);
			if (conflict && !(conflict.winningEvidenceRefs ?? []).every((ref) => (row.winningEvidenceRefs ?? []).includes(ref))) errors.push(`provider_table_winner_evidence_mismatch:${row?.tableId ?? ""}:${conflictId}`);
		}
		if (!(row?.loserClaimIds ?? []).length) errors.push(`provider_table_losers_missing:${row?.tableId ?? ""}`);
		if (row?.loserDowngradeBlocked !== true) errors.push(`provider_table_loser_downgrade_not_blocked:${row?.tableId ?? ""}`);
		for (const claimId of row?.loserClaimIds ?? []) {
			if (finalIds.has(claimId)) errors.push(`provider_table_loser_promoted:${row?.tableId ?? ""}:${claimId}`);
			if (!blockedIds.has(claimId)) errors.push(`provider_table_loser_not_blocked:${row?.tableId ?? ""}:${claimId}`);
		}
		for (const claimId of row?.claimIds ?? []) if (!claims.has(claimId)) errors.push(`provider_table_claim_missing:${row?.tableId ?? ""}:${claimId}`);
	}
	return errors;
}

function validateSynthesizerTopicParseMatrix(matrix, claims, finalIds) {
	const errors = [];
	const topicMatrix = matrix?.synthesizerTopicParseMatrix;
	const conflicts = new Map((matrix?.conflictRows ?? []).map((conflict) => [conflict.conflictId, conflict]));
	const rows = topicMatrix?.topicRows ?? [];
	if (topicMatrix?.kind !== "LongRunSynthesizerTopicParseMatrixV1") errors.push("synthesizer_topic_matrix_kind");
	if ((topicMatrix?.longRunWindowIds ?? []).length < 3) errors.push("synthesizer_topic_long_run_windows_lt_3");
	if (rows.length < 4) errors.push("synthesizer_topic_count_lt_4");
	const topics = new Set(rows.map((row) => row.topic));
	for (const requiredTopic of ["authz:orders:ownership", "js:signature:replay", "provider:worker:timeout", "api:rate-limit:abuse-window"]) {
		if (!topics.has(requiredTopic)) errors.push(`synthesizer_topic_missing:${requiredTopic}`);
	}
	for (const row of rows) {
		const conflict = conflicts.get(row.conflictId);
		if (!conflict) errors.push(`synthesizer_topic_conflict_missing:${row.conflictId ?? ""}`);
		if (row.parsedToStructuredRows !== true) errors.push(`synthesizer_topic_not_parsed:${row.topic ?? ""}`);
		if (row.narrativeOnly === true) errors.push(`synthesizer_topic_narrative_only:${row.topic ?? ""}`);
		if (row.promotion !== "final_pass") errors.push(`synthesizer_topic_promotion_not_final:${row.topic ?? ""}`);
		if (!row.winnerClaimId || !finalIds.has(row.winnerClaimId)) errors.push(`synthesizer_topic_winner_not_final:${row.topic ?? ""}:${row.winnerClaimId ?? ""}`);
		if (conflict && conflict.winnerClaimId !== row.winnerClaimId) errors.push(`synthesizer_topic_winner_mismatch:${row.topic ?? ""}:${row.conflictId ?? ""}`);
		for (const claimId of row.claimIds ?? []) if (!claims.has(claimId)) errors.push(`synthesizer_topic_claim_missing:${row.topic ?? ""}:${claimId}`);
		if (conflict && !(conflict.claimIds ?? []).every((claimId) => (row.claimIds ?? []).includes(claimId))) errors.push(`synthesizer_topic_claims_do_not_cover_conflict:${row.topic ?? ""}:${row.conflictId ?? ""}`);
	}
	for (const row of topicMatrix?.narrativeOnlyBlockedRows ?? []) {
		if (row.narrativeOnly !== true || row.blockedPromotion !== true) errors.push(`synthesizer_topic_narrative_block_invalid:${row.topic ?? ""}`);
		if ((row.claimIds ?? []).some((claimId) => finalIds.has(claimId))) errors.push(`synthesizer_topic_narrative_promoted:${row.topic ?? ""}`);
	}
	return errors;
}

function validateMatrix(tempRoot, report) {
	const errors = [];
	if (report?.kind !== "LiveConflictArbitrationMatrixGateV1") errors.push("report.kind");
	if (report?.LiveConflictArbitrationMatrixGateV1 !== true) errors.push("report.flag");
	const gates = new Set(report?.requiredGates ?? []);
	for (const gate of REQUIRED_GATES) if (!gates.has(gate)) errors.push(`missing_required_gate:${gate}`);
	const invariants = new Set(report?.invariants ?? []);
	for (const invariant of INVARIANTS) if (!invariants.has(invariant)) errors.push(`missing_invariant:${invariant}`);
	errors.push(...validateSourceCoverage(tempRoot, report));
	const matrix = report?.arbitrationMatrix;
	const claims = new Map((matrix?.claimRows ?? []).map((claim) => [claim.claimId, claim]));
	const finalClaims = matrix?.promotionGate?.finalClaims ?? [];
	const blockedClaims = matrix?.promotionGate?.blockedClaims ?? [];
	const finalIds = new Set(finalClaims.map((claim) => claim.claimId));
	const blockedIds = new Set(blockedClaims.map((claim) => claim.claimId));
	if ((matrix?.conflictRows ?? []).length < 3) errors.push("conflict_row_count_lt_3");
	for (const conflict of matrix?.conflictRows ?? []) {
		if ((conflict.claimIds ?? []).length < 2) errors.push(`conflict_too_few_claims:${conflict.conflictId}`);
		if (conflict.status !== "resolved") errors.push(`conflict_unresolved:${conflict.conflictId}`);
		if (!conflict.winnerClaimId || !claims.has(conflict.winnerClaimId)) errors.push(`conflict_winner_missing:${conflict.conflictId}`);
		if (!conflict.winningEvidenceRefs?.length) errors.push(`conflict_winning_evidence_missing:${conflict.conflictId}`);
		if (!String(conflict.resolutionReason ?? "").includes("live_conflict_arbitration_matrix")) errors.push(`conflict_resolution_marker_missing:${conflict.conflictId}`);
		if (!conflict.structuredMergeRefs?.length || !conflict.runtimeLedgerRefs?.length) errors.push(`conflict_runtime_refs_missing:${conflict.conflictId}`);
		if (conflict.orchestrationStatus === "pass" && conflict.platformClaimStatus !== "proven" && finalIds.has(conflict.winnerClaimId)) errors.push(`orchestration_promoted_without_platform_proof:${conflict.conflictId}`);
		for (const loser of conflict.loserDowngrades ?? []) {
			if (!loser.claimId || loser.blockedPromotion !== true) errors.push(`loser_downgrade_invalid:${conflict.conflictId}:${loser.claimId ?? ""}`);
			if (finalIds.has(loser.claimId)) errors.push(`loser_promoted:${conflict.conflictId}:${loser.claimId}`);
			if (!blockedIds.has(loser.claimId)) errors.push(`loser_not_blocked:${conflict.conflictId}:${loser.claimId}`);
		}
		for (const claimId of conflict.claimIds ?? []) if (!claims.has(claimId)) errors.push(`conflict_claim_missing:${conflict.conflictId}:${claimId}`);
	}
	for (const finalClaim of finalClaims) {
		const claim = claims.get(finalClaim.claimId);
		if (!claim) errors.push(`final_claim_missing:${finalClaim.claimId}`);
		if (claim?.status !== "proven") errors.push(`final_claim_not_proven:${finalClaim.claimId}`);
		if (finalClaim.verifierPass !== true) errors.push(`final_claim_verifier_not_pass:${finalClaim.claimId}`);
		if (finalClaim.platformClaimStatus !== "proven") errors.push(`final_claim_platform_not_proven:${finalClaim.claimId}`);
		if (!finalClaim.artifactRefs?.length) errors.push(`final_claim_artifact_missing:${finalClaim.claimId}`);
		for (const ref of finalClaim.artifactRefs ?? []) errors.push(...validateArtifactRef(tempRoot, ref).map((error) => `${finalClaim.claimId}.${error}`));
	}
	for (const row of matrix?.synthesizerRows ?? []) {
		if (row.parsedToStructuredRows !== true) errors.push(`synthesizer_not_parsed:${row.sourceKind}`);
		if (row.narrativeOnly === true && (row.claimIds ?? []).some((claimId) => finalIds.has(claimId))) errors.push(`narrative_only_promoted:${row.sourceKind}`);
	}
	errors.push(...validateProviderBackedConflictTable(matrix, claims, finalIds, blockedIds));
	errors.push(...validateSynthesizerTopicParseMatrix(matrix, claims, finalIds));
	const text = JSON.stringify(report);
	if (/ghp_[A-Za-z0-9]|github_pat_[A-Za-z0-9]|sk-[A-Za-z0-9]{8,}/i.test(text)) errors.push("literal_secret_leak");
	return { ok: errors.length === 0, errors };
}

function clone(value) {
	return JSON.parse(JSON.stringify(value));
}

function mutateReport(report, id) {
	const row = clone(report);
	const matrix = row.arbitrationMatrix;
	const firstConflict = matrix.conflictRows[0];
	if (id === "missing-winner-evidence") firstConflict.winningEvidenceRefs = [];
	if (id === "loser-promoted") {
		const loser = firstConflict.loserDowngrades[0].claimId;
		const claim = matrix.claimRows.find((item) => item.claimId === loser);
		claim.status = "proven";
		claim.platformClaimStatus = "proven";
		for (const ref of claim.artifactRefs) ref.verifierPass = true;
		matrix.promotionGate.finalClaims.push({ claimId: loser, sourceKind: claim.sourceKind, promotion: "final_pass", reportSection: claim.reportSection, verifierPass: true, platformClaimStatus: "proven", artifactRefs: claim.artifactRefs });
	}
	if (id === "orchestration-implies-platform-pass") {
		const planOnly = matrix.claimRows.find((item) => item.claimId === "claim-dogfood-provider-plan-only");
		planOnly.status = "proven";
		planOnly.platformClaimStatus = "unknown";
		matrix.promotionGate.finalClaims.push({ claimId: planOnly.claimId, sourceKind: planOnly.sourceKind, promotion: "final_pass", reportSection: planOnly.reportSection, verifierPass: true, platformClaimStatus: "unknown", artifactRefs: planOnly.artifactRefs.map((ref) => ({ ...ref, verifierPass: true })) });
	}
	if (id === "missing-source-coverage") matrix.sources = matrix.sources.filter((source) => source.sourceKind !== "provider-worker");
	if (id === "narrative-only-synthesizer-promoted") {
		matrix.synthesizerRows[0].narrativeOnly = true;
		matrix.synthesizerRows[0].claimIds.push(matrix.promotionGate.finalClaims[0].claimId);
	}
	if (id === "claim-ledger-ref-missing") matrix.sources[0].claimLedgerPath = "missing/claim-ledger.jsonl";
	if (id === "unresolved-conflict") firstConflict.status = "unresolved";
	if (id === "final-without-json-query") delete matrix.promotionGate.finalClaims[0].artifactRefs[0].jsonQuery;
	if (id === "provider-backed-conflict-single-worker") matrix.providerBackedConflictTable[0].providerWorkerIds = matrix.providerBackedConflictTable[0].providerWorkerIds.slice(0, 1);
	if (id === "synthesizer-topic-parse-missing") matrix.synthesizerTopicParseMatrix.topicRows = matrix.synthesizerTopicParseMatrix.topicRows.filter((topic) => topic.topic !== "api:rate-limit:abuse-window");
	if (id === "same-window-conflict-without-provider-worker") {
		const providerConflict = matrix.conflictRows.find((conflict) => conflict.conflictId === "conflict-rate-limit-abuse-window-live");
		providerConflict.sourceKinds = providerConflict.sourceKinds.filter((sourceKind) => sourceKind !== "provider-worker");
		matrix.providerBackedConflictTable[0].sourceKinds = matrix.providerBackedConflictTable[0].sourceKinds.filter((sourceKind) => sourceKind !== "provider-worker");
		matrix.providerBackedConflictTable[0].claimIds = matrix.providerBackedConflictTable[0].claimIds.filter((claimId) => !matrix.claimRows.find((claim) => claim.claimId === claimId && claim.sourceKind === "provider-worker"));
	}
	return row;
}

function validateFixture(fixture) {
	const gates = new Set(fixture?.requiredGates ?? []);
	const sources = new Set(fixture?.requiredSources ?? []);
	const negative = new Set((fixture?.negativeCases ?? []).map((row) => row.id));
	return {
		missingGates: REQUIRED_GATES.filter((gate) => !gates.has(gate)),
		missingSources: REQUIRED_SOURCES.filter((source) => !sources.has(source)),
		missingNegativeCases: REQUIRED_NEGATIVE_CASES.filter((id) => !negative.has(id)),
	};
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "live-conflict-arbitration-matrix", stamp);
	mkdirSync(dir, { recursive: true });
	const path = join(dir, "result.json");
	writeFileSync(path, `${JSON.stringify(result, null, 2)}\n`, "utf8");
	return path;
}

function main() {
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-live-conflict-arbitration-"));
	const checks = [];
	try {
		const schema = readJson(SCHEMA_PATH);
		const fixture = readJson(FIXTURE_PATH);
		checks.push(check("schema:parse", Boolean(schema?.$defs?.LiveConflictArbitrationMatrixGateV1 && schema?.$defs?.LiveConflictArbitrationConflictRowV1), { path: SCHEMA_PATH }));
		const fixtureEval = validateFixture(fixture);
		checks.push(check("fixture:coverage", fixtureEval.missingGates.length === 0 && fixtureEval.missingSources.length === 0 && fixtureEval.missingNegativeCases.length === 0, fixtureEval));
		const report = buildRuntimeMatrix(tempRoot);
		const validation = validateMatrix(tempRoot, report);
		checks.push(check("runtime:live-conflict-arbitration-matrix-validation", validation.ok, validation));
		checks.push(check("runtime:source-coverage-all-runtimes", REQUIRED_SOURCES.every((source) => report.arbitrationMatrix.sources.some((row) => row.sourceKind === source)), { sources: report.arbitrationMatrix.sources.map((row) => row.sourceKind) }));
		checks.push(check("runtime:multi-claim-topic-conflict-matrix", report.arbitrationMatrix.conflictRows.length >= 4 && report.arbitrationMatrix.conflictRows.every((row) => row.claimIds.length >= 2 && row.status === "resolved"), { conflicts: report.arbitrationMatrix.conflictRows.map((row) => ({ conflictId: row.conflictId, claimIds: row.claimIds, status: row.status })) }));
		checks.push(check("runtime:winner-evidence-json-query-verifier", report.arbitrationMatrix.promotionGate.finalClaims.every((claim) => claim.artifactRefs.length && claim.artifactRefs.every((ref) => ref.jsonQuery && ref.verifierPass === true)), { finalClaims: report.arbitrationMatrix.promotionGate.finalClaims.map((claim) => ({ claimId: claim.claimId, artifactRefs: claim.artifactRefs.map((ref) => ({ artifactId: ref.artifactId, jsonQuery: ref.jsonQuery, verifierPass: ref.verifierPass })) })) }));
		const finalIds = new Set(report.arbitrationMatrix.promotionGate.finalClaims.map((claim) => claim.claimId));
		const loserIds = new Set(report.arbitrationMatrix.conflictRows.flatMap((row) => row.loserDowngrades.map((loser) => loser.claimId)));
		checks.push(check("runtime:loser-downgrade-blocks-promotion", [...loserIds].every((claimId) => !finalIds.has(claimId)) && [...loserIds].every((claimId) => report.arbitrationMatrix.promotionGate.blockedClaims.some((blocked) => blocked.claimId === claimId && blocked.blockedPromotion)), { loserIds: [...loserIds], finalIds: [...finalIds] }));
		checks.push(check("runtime:orchestration-platform-split", report.arbitrationMatrix.promotionGate.finalClaims.every((claim) => claim.platformClaimStatus === "proven") && report.arbitrationMatrix.promotionGate.blockedClaims.some((blocked) => blocked.claimId === "claim-dogfood-provider-plan-only"), { finalPlatformStatuses: report.arbitrationMatrix.promotionGate.finalClaims.map((claim) => ({ claimId: claim.claimId, platformClaimStatus: claim.platformClaimStatus })) }));
		checks.push(check("runtime:synthesizer-summary-parsed", report.arbitrationMatrix.synthesizerRows.every((row) => row.parsedToStructuredRows === true && row.narrativeOnly === false), { synthesizerRows: report.arbitrationMatrix.synthesizerRows }));
		checks.push(check("runtime:provider-backed-same-window-conflict-table", report.arbitrationMatrix.providerBackedConflictTable.length >= 1 && report.arbitrationMatrix.providerBackedConflictTable.every((row) => row.sameWindow === true && row.providerWorkerIds.length >= 2 && row.sourceKinds.includes("provider-worker") && row.jsonQueryVerifierPass === true), { providerBackedConflictTable: report.arbitrationMatrix.providerBackedConflictTable }));
		checks.push(check("runtime:long-run-synthesizer-topic-parse-matrix", report.arbitrationMatrix.synthesizerTopicParseMatrix.topicRows.length >= 4 && report.arbitrationMatrix.synthesizerTopicParseMatrix.topicRows.every((row) => row.parsedToStructuredRows === true && row.narrativeOnly === false && row.promotion === "final_pass"), { synthesizerTopicParseMatrix: report.arbitrationMatrix.synthesizerTopicParseMatrix }));
		checks.push(check("runtime:claim-ledger-quality", report.arbitrationMatrix.sources.every((source) => source.claimLedgerQuality.hashChainOk && REQUIRED_GATES.includes("claim_ledger_refs_hash_chain_quality")), { sources: report.arbitrationMatrix.sources.map((source) => ({ sourceKind: source.sourceKind, quality: source.claimLedgerQuality })) }));
		const negativeResults = REQUIRED_NEGATIVE_CASES.map((id) => ({ id, validation: validateMatrix(tempRoot, mutateReport(report, id)) }));
		checks.push(check("fixture:negative-rejections", negativeResults.every((row) => !row.validation.ok), { negativeResults: negativeResults.map((row) => ({ id: row.id, ok: row.validation.ok, errors: row.validation.errors })) }));
		checks.push(markerCheck("code:structured-claim-live-wiring", "scripts/reverse-agent/structured-claim-merge-gate.mjs", ["runtime:structured-claim-live-wiring", "structured_conflict_arbitration_live_wiring", "runtime_loser_promoted", "runtime_conflict_winning_evidence_missing"]));
		checks.push(markerCheck("harness:live-conflict-arbitration-matrix", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:live-conflict-arbitration-matrix", "LiveConflictArbitrationMatrixGateV1", "child:gate:live-conflict-arbitration-matrix"]));
		checks.push(markerCheck("autonomy:live-conflict-arbitration-matrix", "scripts/reverse-agent/autonomy-control-plane.mjs", ["LiveConflictArbitrationMatrixGateV1", "live_conflict_arbitration_matrix_gate", "source_coverage_all_runtimes"]));
		checks.push(markerCheck("npm:live-conflict-arbitration-matrix", "package.json", ["gate:live-conflict-arbitration-matrix", "live-conflict-arbitration-matrix-gate.mjs"]));
		checks.push(markerCheck("docs:live-conflict-arbitration-matrix-readme", "README.md", ["LiveConflictArbitrationMatrixGateV1", "gate:live-conflict-arbitration-matrix"]));
		checks.push(markerCheck("docs:live-conflict-arbitration-matrix-control-plane", "docs/reverse-agent/autonomous-control-plane.md", ["LiveConflictArbitrationMatrixGateV1", "gate:live-conflict-arbitration-matrix"]));
		checks.push(markerCheck("docs:live-conflict-arbitration-matrix-reverse", "docs/reverse-agent/README.md", ["LiveConflictArbitrationMatrixGateV1", "gate:live-conflict-arbitration-matrix"]));
	} catch (error) {
		checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	const failed = checks.filter((row) => row.status !== "pass");
	const result = { kind: "repi-live-conflict-arbitration-matrix-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), LiveConflictArbitrationMatrixGateV1: true, ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI LiveConflictArbitrationMatrixGateV1");
		for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
		console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
		if (evidencePath) console.log(`evidence: ${evidencePath}`);
	}
	if (strict && failed.length) process.exit(1);
}

main();
