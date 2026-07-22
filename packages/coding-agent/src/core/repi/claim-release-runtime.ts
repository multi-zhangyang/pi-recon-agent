import { existsSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { artifactScopeDefaultOptions, artifactTargetMatches } from "./artifact-scope.ts";
import {
	type MissionCheckpointStatus,
	type MissionState,
	missionRequiresParallel,
	readCurrentMission,
} from "./mission.ts";
import type { VerifierArtifact } from "./proof-artifact-runtime.ts";
import { ensureReconStorage } from "./resources.ts";
import {
	currentMissionPath,
	evidenceClaimReleaseDir,
	evidenceLedgerPath,
	readTextFile as readText,
	writePrivateTextFile,
} from "./storage.ts";
import type {
	StrictClaimCheckSnapshot,
	StructuredClaimMergeCheckSnapshot,
	SwarmArtifact,
} from "./swarm-runtime-types.ts";
import { sha256Text } from "./text.ts";

export type RuntimeExecutionProofRow = {
	status?: unknown;
	command?: unknown;
	exit?: unknown;
	stdoutHash?: unknown;
	stdoutSha256?: unknown;
	stdout_sha256?: unknown;
	stderrHash?: unknown;
	stderrSha256?: unknown;
	stderr_sha256?: unknown;
	stdoutHead?: unknown;
	stderrHead?: unknown;
	output?: unknown;
};

export function hasExecutionHash(value: unknown): value is string {
	return typeof value === "string" && value.trim().length >= 8 && !/^n\/a$/i.test(value.trim());
}

export function runtimeCheckpointStatus(
	mode: "plan" | "run" | "bundle",
	executions: readonly RuntimeExecutionProofRow[],
	target?: string,
): MissionCheckpointStatus {
	if (mode !== "run") return "pending";
	const hasTarget = typeof target === "string" && target.trim().length > 0;
	const passed = executions.some((execution) => {
		const status = typeof execution.status === "string" ? execution.status.toLowerCase() : "";
		const command = typeof execution.command === "string" ? execution.command.trim() : "";
		const exit = typeof execution.exit === "number" ? execution.exit : undefined;
		return (
			status === "passed" &&
			command.length > 0 &&
			(hasTarget || command.includes("<target>") === false) &&
			(exit === undefined || exit === 0) &&
			hasExecutionHash(execution.stdoutHash ?? execution.stdoutSha256 ?? execution.stdout_sha256) &&
			hasExecutionHash(execution.stderrHash ?? execution.stderrSha256 ?? execution.stderr_sha256)
		);
	});
	if (passed) return "done";
	if (
		executions.length > 0 &&
		executions.every((execution) => {
			const status = typeof execution.status === "string" ? execution.status.toLowerCase() : "";
			return status === "blocked" || status === "failed";
		})
	) {
		return "blocked";
	}
	return "pending";
}

type ClaimReleaseGap = {
	claimId?: string;
	scope?: string;
	checkpoint?: string;
	kind?: string;
};

type ClaimReleaseMarker = {
	kind?: string;
	schemaVersion?: number;
	generatedAt?: string;
	mode?: string;
	ok?: boolean;
	root?: string;
	markerPath?: string;
	sourceSha256?: string;
	sourceBindings?: {
		missionPath?: string;
		ledgerPath?: string;
		verifierPath?: string | null;
		swarmPath?: string | null;
		missionId?: string | null;
		ledgerPrefixChars?: number;
		ledgerPrefixSha256?: string;
	};
	platformRequiredScore?: number;
	orchestrationScore?: number;
	requiredGaps?: ClaimReleaseGap[];
	checks?: {
		checkAndScores?: {
			status?: string;
			platformRequiredScore?: number;
			orchestrationScore?: number;
			requiredGaps?: ClaimReleaseGap[];
		};
	};
};

type ClaimReleaseSourceSnapshot = {
	source: string;
	bindings: NonNullable<ClaimReleaseMarker["sourceBindings"]>;
};

export type ClaimReleaseRuntimeDependencies = {
	latestVerifierArtifactPath: () => string | undefined;
	parseVerifierArtifact: (path: string) => VerifierArtifact | undefined;
	latestSwarmArtifactPath: () => string | undefined;
	parseSwarmArtifact: (path: string) => SwarmArtifact | undefined;
	structuredClaimMergeCheckFromSwarm: (swarm?: SwarmArtifact) => StructuredClaimMergeCheckSnapshot;
};

export function createClaimReleaseRuntime(dependencies: ClaimReleaseRuntimeDependencies) {
	const {
		latestVerifierArtifactPath,
		parseVerifierArtifact,
		latestSwarmArtifactPath,
		parseSwarmArtifact,
		structuredClaimMergeCheckFromSwarm,
	} = dependencies;

	function latestClaimReleaseMarkerPath(): string | undefined {
		try {
			const candidates: Array<{ path: string; mtimeMs: number }> = [];
			for (const entry of readdirSync(evidenceClaimReleaseDir(), { withFileTypes: true })) {
				const directPath = join(evidenceClaimReleaseDir(), entry.name);
				const markerPath = entry.isDirectory() ? join(directPath, "result.json") : directPath;
				if (!markerPath.endsWith("result.json") || !existsSync(markerPath)) continue;
				candidates.push({ path: markerPath, mtimeMs: statSync(markerPath).mtimeMs });
			}
			return candidates.sort((left, right) => right.mtimeMs - left.mtimeMs || right.path.localeCompare(left.path))[0]
				?.path;
		} catch {
			return undefined;
		}
	}

	function parseClaimReleaseMarker(path: string): ClaimReleaseMarker | undefined {
		try {
			const parsed: unknown = JSON.parse(readText(path));
			if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
			return parsed as ClaimReleaseMarker;
		} catch {
			return undefined;
		}
	}

	function safeStructuredClaimMergeCheck(swarm?: SwarmArtifact): StructuredClaimMergeCheckSnapshot {
		try {
			return structuredClaimMergeCheckFromSwarm(swarm);
		} catch (error) {
			return {
				status: "blocked",
				finalClaimCount: 0,
				blockedClaimCount: 0,
				errors: [`structured_claim_merge_unreadable:${error instanceof Error ? error.message : String(error)}`],
				policies: [],
			};
		}
	}

	function claimReleaseSourceSnapshot(ledgerPrefixChars?: number): ClaimReleaseSourceSnapshot {
		const missionPath = currentMissionPath();
		const ledgerPath = evidenceLedgerPath();
		const verifierPath = latestVerifierArtifactPath() ?? null;
		const mission = readCurrentMission();
		const parallelRequired = missionRequiresParallel(mission);
		const swarmPath = parallelRequired ? (latestSwarmArtifactPath() ?? null) : null;
		const ledger = readText(ledgerPath);
		const prefixChars = Math.max(0, Math.floor(ledgerPrefixChars ?? ledger.length));
		const ledgerPrefix = ledger.slice(0, prefixChars);
		const bindings = {
			missionPath,
			ledgerPath,
			verifierPath,
			swarmPath,
			missionId: mission?.id ?? null,
			ledgerPrefixChars: prefixChars,
			ledgerPrefixSha256: sha256Text(ledgerPrefix),
		};
		const missionIdentity = mission
			? JSON.stringify({
					id: mission.id,
					createdAt: mission.createdAt,
					task: mission.task,
					scope: mission.scope,
					route: mission.route,
				})
			: "missing";
		const source = [
			`mission_path=${missionPath}`,
			`mission_identity=${missionIdentity}`,
			`ledger_path=${ledgerPath}`,
			`ledger_prefix_chars=${prefixChars}`,
			`ledger_prefix_sha256=${bindings.ledgerPrefixSha256}`,
			`verifier_path=${verifierPath ?? "missing"}`,
			verifierPath ? readText(verifierPath) : "",
			`swarm_path=${swarmPath ?? "missing"}`,
			swarmPath ? readText(swarmPath) : "",
		].join("\n\0\n");
		return { source, bindings };
	}

	function artifactMatchesMission(
		mission: MissionState | undefined,
		artifact: { missionId?: string } | undefined,
	): boolean {
		return Boolean(mission && artifact?.missionId === mission.id);
	}

	function releaseArtifactMatchesScope(
		mission: MissionState | undefined,
		artifact: { missionId?: string; target?: string } | undefined,
	): boolean {
		if (!artifactMatchesMission(mission, artifact)) return false;
		const expectedTarget = artifactScopeDefaultOptions().target;
		if (expectedTarget === undefined) return true;
		return Boolean(artifact?.target?.trim() && artifactTargetMatches(expectedTarget, artifact.target));
	}

	function localClaimReleasePreflight(): {
		requiredGaps: ClaimReleaseGap[];
		platformRequiredScore: number;
		orchestrationScore: number;
	} {
		const requiredGaps: ClaimReleaseGap[] = [];
		const mission = readCurrentMission();
		const parallelRequired = missionRequiresParallel(mission);
		if (!mission) requiredGaps.push({ checkpoint: "mission", kind: "mission_missing" });
		const evidence = readText(evidenceLedgerPath()).trim();
		if (!evidence || evidence === "# REPI Evidence Ledger") {
			requiredGaps.push({ checkpoint: "evidence_ledger", kind: "evidence_ledger_empty" });
		} else if (!/(command|verify|path|offset|hash):/i.test(evidence)) {
			requiredGaps.push({ checkpoint: "evidence_ledger", kind: "evidence_metadata_missing" });
		}

		const verifierPath = latestVerifierArtifactPath();
		const candidateVerifier = verifierPath ? parseVerifierArtifact(verifierPath) : undefined;
		const verifier =
			candidateVerifier &&
			releaseArtifactMatchesScope(mission, candidateVerifier) &&
			Array.isArray(candidateVerifier.assertions) &&
			Array.isArray(candidateVerifier.contradictions) &&
			Array.isArray(candidateVerifier.gaps)
				? candidateVerifier
				: undefined;
		if (!verifier || verifier.assertions.length === 0) {
			requiredGaps.push({ checkpoint: "verifier_matrix", kind: "verifier_missing" });
		} else {
			if (verifier.contradictions.length > 0 || verifier.assertions.some((row) => row.status === "contradicted")) {
				requiredGaps.push({ checkpoint: "verifier_matrix", kind: "verifier_contradiction" });
			}
			if (verifier.assertions.some((row) => row.status !== "proved")) {
				requiredGaps.push({ checkpoint: "verifier_matrix", kind: "verifier_not_fully_proved" });
			}
			if (verifier.gaps.length > 0) {
				requiredGaps.push({ checkpoint: "verifier_matrix", kind: "verifier_gaps_unresolved" });
			}
			if (
				verifier.assertions.some(
					(row) =>
						row.status === "proved" &&
						(!Number.isFinite(row.confidence) ||
							row.confidence < 70 ||
							!Array.isArray(row.evidence) ||
							row.evidence.length === 0 ||
							!Array.isArray(row.counterEvidence) ||
							row.counterEvidence.length > 0),
				)
			) {
				requiredGaps.push({ checkpoint: "verifier_matrix", kind: "verifier_proof_binding_invalid" });
			}
			if (
				!Array.isArray(verifier.sourceArtifacts) ||
				verifier.sourceArtifacts.length === 0 ||
				verifier.sourceArtifacts.some((path) => typeof path !== "string" || !existsSync(path))
			) {
				requiredGaps.push({ checkpoint: "verifier_matrix", kind: "verifier_source_artifact_missing" });
			}
		}

		const swarmPath = latestSwarmArtifactPath();
		const candidateSwarm = swarmPath ? parseSwarmArtifact(swarmPath) : undefined;
		const swarm =
			candidateSwarm &&
			releaseArtifactMatchesScope(mission, candidateSwarm) &&
			Array.isArray(candidateSwarm.workers) &&
			Array.isArray(candidateSwarm.planCoverage) &&
			Array.isArray(candidateSwarm.executionAudit) &&
			Array.isArray(candidateSwarm.claimLedger) &&
			Array.isArray(candidateSwarm.releaseCheckMetadata)
				? candidateSwarm
				: undefined;
		if (parallelRequired && !swarm) {
			requiredGaps.push({ checkpoint: "swarm_runtime", kind: "swarm_missing" });
		} else if (parallelRequired && swarm) {
			if (
				!swarm.parallelPlan ||
				!Array.isArray(swarm.parallelPlan.workers) ||
				swarm.parallelPlan.workers.length === 0
			) {
				requiredGaps.push({ checkpoint: "parallel_plan", kind: "parallel_plan_missing" });
			}
			if (
				(swarm.planCoverage ?? []).some((row) =>
					/parallel_plan=missing|status=(?:fail|blocked)|worker_binding=(?!pass(?:$|\s))|\bmissing=[1-9]\d*|\bcoverage_rows=0\b|\bcontract=0\b/i.test(
						row,
					),
				)
			) {
				requiredGaps.push({ checkpoint: "parallel_plan", kind: "plan_coverage_gap" });
			}
			if (
				(swarm.executionAudit ?? []).some((row) =>
					/status=(?:pending_execution|needs_repair|needs_evidence)/i.test(row),
				)
			) {
				requiredGaps.push({ checkpoint: "swarm_runtime", kind: "swarm_execution_gap" });
			}
			const mergeCheck = safeStructuredClaimMergeCheck(swarm);
			if (mergeCheck.status !== "pass" || mergeCheck.finalClaimCount === 0) {
				requiredGaps.push({ checkpoint: "structured_claim_merge", kind: "structured_claim_merge_not_pass" });
			}
		}

		const assertions = verifier?.assertions ?? [];
		const proved = assertions.filter((row) => row.status === "proved").length;
		const platformRequiredScore = assertions.length === 0 ? 0 : Math.round((proved / assertions.length) * 100);
		const orchestrationChecks = parallelRequired
			? [
					Boolean(swarm?.parallelPlan?.workers.length),
					Boolean(swarm && !requiredGaps.some((gap) => gap.checkpoint === "parallel_plan")),
					Boolean(swarm && !requiredGaps.some((gap) => gap.checkpoint === "swarm_runtime")),
					Boolean(swarm && !requiredGaps.some((gap) => gap.checkpoint === "structured_claim_merge")),
				]
			: [true];
		const orchestrationScore = Math.round(
			(orchestrationChecks.filter(Boolean).length / orchestrationChecks.length) * 100,
		);
		return { requiredGaps, platformRequiredScore, orchestrationScore };
	}

	function writeLocalClaimReleaseMarker(): string {
		const timestamp = new Date().toISOString();
		const ledgerKeptChars = readText(evidenceLedgerPath()).length;
		ensureReconStorage();
		const dir = join(evidenceClaimReleaseDir(), `local-runtime-${timestamp.replace(/[:.]/g, "-")}`);
		mkdirSync(dir, { recursive: true });
		const markerPath = join(dir, "result.json");
		const sourceSnapshot = claimReleaseSourceSnapshot(ledgerKeptChars);
		const preflight = localClaimReleasePreflight();
		const ok = preflight.requiredGaps.length === 0;
		const marker: ClaimReleaseMarker = {
			kind: "repi-claim-release-marker",
			schemaVersion: 3,
			generatedAt: timestamp,
			mode: "strict-claims",
			ok,
			root: process.cwd(),
			markerPath,
			sourceSha256: sha256Text(sourceSnapshot.source),
			sourceBindings: sourceSnapshot.bindings,
			platformRequiredScore: preflight.platformRequiredScore,
			orchestrationScore: preflight.orchestrationScore,
			requiredGaps: preflight.requiredGaps,
			checks: {
				checkAndScores: {
					status: ok ? "pass" : "blocked",
					platformRequiredScore: preflight.platformRequiredScore,
					orchestrationScore: preflight.orchestrationScore,
					requiredGaps: preflight.requiredGaps,
				},
			},
		};
		writePrivateTextFile(markerPath, `${JSON.stringify(marker, null, 2)}\n`);
		return markerPath;
	}

	function claimReleaseGapLabel(gap: ClaimReleaseGap): string {
		return [
			gap.claimId ? `claim=${gap.claimId}` : undefined,
			gap.scope ? `scope=${gap.scope}` : undefined,
			gap.checkpoint ? `checkpoint=${gap.checkpoint}` : undefined,
			gap.kind ? `kind=${gap.kind}` : undefined,
		]
			.filter(Boolean)
			.join(" ");
	}

	function validClaimReleaseTimestamp(value: unknown): value is string {
		if (typeof value !== "string" || value.length === 0) return false;
		const parsed = Date.parse(value);
		return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
	}

	function validClaimReleaseScore(value: unknown): value is number {
		return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100;
	}

	function claimReleaseGapRows(value: unknown): { labels: string[]; valid: boolean } {
		if (!Array.isArray(value)) return { labels: [], valid: false };
		let valid = true;
		const labels = value.map((item) => {
			if (!item || typeof item !== "object" || Array.isArray(item)) {
				valid = false;
				return "marker_validation:required_gap_not_object";
			}
			const row = item as Record<string, unknown>;
			const fields = ["claimId", "scope", "checkpoint", "kind"] as const;
			if (
				fields.some(
					(field) =>
						row[field] !== undefined && (typeof row[field] !== "string" || row[field].trim().length === 0),
				)
			) {
				valid = false;
				return "marker_validation:required_gap_field_invalid";
			}
			const gap = item as ClaimReleaseGap;
			const label = claimReleaseGapLabel(gap);
			if (!label) {
				valid = false;
				return "marker_validation:required_gap_empty";
			}
			return label;
		});
		return { labels, valid };
	}

	function strictClaimCheckSnapshot(): StrictClaimCheckSnapshot {
		ensureReconStorage();
		const markerPath = latestClaimReleaseMarkerPath();
		if (!markerPath) {
			return {
				status: "missing",
				requiredGaps: [],
				claimCheckResult: [
					"strict_claim_check.status=missing",
					"strict_claim_check.marker_path=missing",
					"strict_claim_check.final_publish_ready=no",
					`strict_claim_check.next=write ${join(evidenceClaimReleaseDir(), "local-runtime-*/result.json")}`,
				],
			};
		}
		const marker = parseClaimReleaseMarker(markerPath);
		if (!marker) {
			return {
				status: "blocked",
				markerPath,
				requiredGaps: ["marker_parse_error"],
				claimCheckResult: [
					"strict_claim_check.status=blocked",
					`strict_claim_check.marker_path=${markerPath}`,
					"strict_claim_check.parse=fail",
					"strict_claim_check.final_publish_ready=no",
				],
			};
		}
		const checkAndScores = marker.checks?.checkAndScores;
		const topGapRows = claimReleaseGapRows(marker.requiredGaps);
		const nestedGapRows = claimReleaseGapRows(checkAndScores?.requiredGaps);
		const requiredGaps = Array.from(
			new Set([
				...topGapRows.labels.filter((label) => !label.startsWith("marker_validation:")),
				...nestedGapRows.labels.filter((label) => !label.startsWith("marker_validation:")),
			]),
		);
		const markerValidationGaps: string[] = [];
		if (marker.kind !== "repi-claim-release-marker") markerValidationGaps.push("marker_validation:kind_invalid");
		if (marker.schemaVersion !== 3) markerValidationGaps.push("marker_validation:schema_version_invalid");
		if (marker.mode !== "strict-claims") markerValidationGaps.push("marker_validation:mode_invalid");
		if (marker.ok !== true) markerValidationGaps.push("marker_validation:ok_not_true");
		if (!validClaimReleaseTimestamp(marker.generatedAt)) {
			markerValidationGaps.push("marker_validation:generated_at_invalid");
		}
		if (typeof marker.sourceSha256 !== "string" || !/^[a-f0-9]{64}$/i.test(marker.sourceSha256)) {
			markerValidationGaps.push("marker_validation:source_sha256_invalid");
		} else {
			if (!marker.sourceBindings || typeof marker.sourceBindings !== "object") {
				markerValidationGaps.push("marker_validation:source_bindings_missing");
			} else {
				const binding = marker.sourceBindings;
				if (
					typeof binding.ledgerPrefixChars !== "number" ||
					!Number.isSafeInteger(binding.ledgerPrefixChars) ||
					binding.ledgerPrefixChars < 0
				) {
					markerValidationGaps.push("marker_validation:ledger_prefix_chars_invalid");
				}
				if (typeof binding.ledgerPrefixSha256 !== "string" || !/^[a-f0-9]{64}$/i.test(binding.ledgerPrefixSha256)) {
					markerValidationGaps.push("marker_validation:ledger_prefix_sha256_invalid");
				}
				const currentSource = claimReleaseSourceSnapshot(
					Number.isSafeInteger(binding.ledgerPrefixChars) ? binding.ledgerPrefixChars : undefined,
				);
				if (
					binding.missionPath !== currentSource.bindings.missionPath ||
					binding.ledgerPath !== currentSource.bindings.ledgerPath ||
					binding.verifierPath !== currentSource.bindings.verifierPath ||
					binding.swarmPath !== currentSource.bindings.swarmPath ||
					binding.missionId !== currentSource.bindings.missionId ||
					binding.ledgerPrefixChars !== currentSource.bindings.ledgerPrefixChars ||
					binding.ledgerPrefixSha256 !== currentSource.bindings.ledgerPrefixSha256
				) {
					markerValidationGaps.push("marker_validation:source_bindings_mismatch");
				}
				if (marker.sourceSha256.toLowerCase() !== sha256Text(currentSource.source)) {
					markerValidationGaps.push("marker_validation:source_sha256_mismatch");
				}
			}
		}
		if (!checkAndScores || typeof checkAndScores !== "object") {
			markerValidationGaps.push("marker_validation:check_and_scores_missing");
		} else {
			if (checkAndScores.status !== "pass") markerValidationGaps.push("marker_validation:check_status_not_pass");
			const topPlatformScore = marker.platformRequiredScore;
			const nestedPlatformScore = checkAndScores.platformRequiredScore;
			const topOrchestrationScore = marker.orchestrationScore;
			const nestedOrchestrationScore = checkAndScores.orchestrationScore;
			if (!validClaimReleaseScore(topPlatformScore) || !validClaimReleaseScore(nestedPlatformScore)) {
				markerValidationGaps.push("marker_validation:platform_required_score_invalid");
			} else if (topPlatformScore !== nestedPlatformScore) {
				markerValidationGaps.push("marker_validation:platform_required_score_mismatch");
			}
			if (!validClaimReleaseScore(topOrchestrationScore) || !validClaimReleaseScore(nestedOrchestrationScore)) {
				markerValidationGaps.push("marker_validation:orchestration_score_invalid");
			} else if (topOrchestrationScore !== nestedOrchestrationScore) {
				markerValidationGaps.push("marker_validation:orchestration_score_mismatch");
			}
		}
		if (!Array.isArray(marker.requiredGaps) || !topGapRows.valid) {
			markerValidationGaps.push("marker_validation:required_gaps_invalid");
		}
		if (!Array.isArray(checkAndScores?.requiredGaps) || !nestedGapRows.valid) {
			markerValidationGaps.push("marker_validation:nested_required_gaps_invalid");
		}
		if (
			Array.isArray(marker.requiredGaps) &&
			Array.isArray(checkAndScores?.requiredGaps) &&
			JSON.stringify([...topGapRows.labels].sort()) !== JSON.stringify([...nestedGapRows.labels].sort())
		) {
			markerValidationGaps.push("marker_validation:required_gaps_mismatch");
		}
		const allRequiredGaps = Array.from(new Set([...requiredGaps, ...markerValidationGaps]));
		const platformRequiredScore = marker.platformRequiredScore;
		const orchestrationScore = marker.orchestrationScore;
		const status: StrictClaimCheckSnapshot["status"] = allRequiredGaps.length === 0 ? "pass" : "blocked";
		const claimCheckResult = [
			`strict_claim_check.status=${status}`,
			`strict_claim_check.marker_path=${markerPath}`,
			`strict_claim_check.generated_at=${marker.generatedAt ?? "missing"}`,
			`strict_claim_check.mode=${marker.mode ?? "missing"}`,
			`strict_claim_check.ok=${marker.ok === true ? "true" : "false"}`,
			`strict_claim_check.platform_required_score=${platformRequiredScore ?? "missing"}`,
			`strict_claim_check.orchestration_score=${orchestrationScore ?? "missing"}`,
			`strict_claim_check.required_gaps=${allRequiredGaps.length}`,
			`strict_claim_check.final_publish_ready=${status === "pass" ? "yes" : "no"}`,
			...(allRequiredGaps.length
				? allRequiredGaps.slice(0, 12).map((gap) => `strict_claim_check.required_gap=${gap}`)
				: []),
		];
		return {
			status,
			markerPath,
			generatedAt: marker.generatedAt,
			mode: marker.mode,
			requiredGaps: allRequiredGaps,
			platformRequiredScore,
			orchestrationScore,
			claimCheckResult,
		};
	}

	function buildClaimCheckResult(
		releaseCheckMetadata: string[] = [],
		claimCheckPolicy: string[] = [],
		strictCheck: StrictClaimCheckSnapshot = strictClaimCheckSnapshot(),
		additionalBlockers: string[] = [],
	): string[] {
		const policyBlockers = [
			...releaseCheckMetadata.filter((item) =>
				/release_check\.parallel_plan_present=false|release_blocking_gaps=[1-9]|required_platform_gaps=[1-9]|unresolved_frontier_gaps=[1-9]|claim_check_verdict=blocked/i.test(
					item,
				),
			),
			...claimCheckPolicy.filter((item) =>
				/parallel_plan_id=missing|worker_binding=(?!pass(?:$|\s))|plan_contract_gaps=[1-9]/i.test(item),
			),
		];
		const blockers = Array.from(new Set([...policyBlockers, ...additionalBlockers].filter(Boolean)));
		const publishReady = strictCheck.status === "pass" && blockers.length === 0;
		return [
			`claim_check.release_metadata_rows=${releaseCheckMetadata.length}`,
			`claim_check.policy_rows=${claimCheckPolicy.length}`,
			`claim_check.strict_status=${strictCheck.status}`,
			`claim_check.marker_path=${strictCheck.markerPath ?? "missing"}`,
			`claim_check.required_gaps=${strictCheck.requiredGaps.length}`,
			`claim_check.platform_required_score=${strictCheck.platformRequiredScore ?? "missing"}`,
			`claim_check.orchestration_score=${strictCheck.orchestrationScore ?? "missing"}`,
			`claim_check.final_publish_ready=${publishReady ? "yes" : "no"}`,
			...(strictCheck.requiredGaps.length
				? strictCheck.requiredGaps.slice(0, 12).map((gap) => `claim_check.required_gap=${gap}`)
				: []),
			...(blockers.length ? blockers.slice(0, 12).map((blocker) => `claim_check.blocker=${blocker}`) : []),
		];
	}

	function formatStrictClaimCheckSnapshot(snapshot?: StrictClaimCheckSnapshot): string[] {
		if (!snapshot) return ["- strict_claim_check.status=missing"];
		return [
			`- status=${snapshot.status}`,
			`- marker_path=${snapshot.markerPath ?? "missing"}`,
			`- generated_at=${snapshot.generatedAt ?? "missing"}`,
			`- mode=${snapshot.mode ?? "missing"}`,
			`- platform_required_score=${snapshot.platformRequiredScore ?? "missing"}`,
			`- orchestration_score=${snapshot.orchestrationScore ?? "missing"}`,
			`- required_gaps=${snapshot.requiredGaps.length}`,
			...(snapshot.requiredGaps.length
				? snapshot.requiredGaps.slice(0, 12).map((gap) => `- required_gap=${gap}`)
				: []),
		];
	}

	return {
		artifactMatchesMission,
		buildClaimCheckResult,
		formatStrictClaimCheckSnapshot,
		safeStructuredClaimMergeCheck,
		strictClaimCheckSnapshot,
		writeLocalClaimReleaseMarker,
	};
}

export type ClaimReleaseRuntime = ReturnType<typeof createClaimReleaseRuntime>;
