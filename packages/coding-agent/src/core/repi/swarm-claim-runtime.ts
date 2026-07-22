import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { swarmStructuredClaimMergePath } from "./swarm-artifact-paths.ts";
import type {
	StructuredClaimArtifactRefV1,
	StructuredClaimMergeCheckSnapshot,
	StructuredClaimMergeV1,
	StructuredClaimRowV1,
	SwarmArtifact,
	SwarmClaimLedgerEventV1,
	SwarmSupervisorRuntimeDependencies,
	SwarmWorkerExecution,
} from "./swarm-runtime-types.ts";
import { slug, truncateMiddle, uniqueNonEmpty } from "./text.ts";

/** Stable JSON representation used for persisted-artifact integrity checks. */
function canonicalJson(value: unknown): string {
	if (value === undefined) return "undefined";
	if (value === null || typeof value !== "object") return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
	const record = value as Record<string, unknown>;
	return `{${Object.keys(record)
		.sort()
		.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
		.join(",")}}`;
}

export type SwarmClaimRuntimeDependencies = {
	runtimeArtifactHashes: SwarmSupervisorRuntimeDependencies["runtimeArtifactHashes"];
	terminalExecutions(executions: readonly SwarmWorkerExecution[]): SwarmWorkerExecution[];
	executionFailed(execution: SwarmWorkerExecution): boolean;
};

export function claimPromotionEvidenceContract(): string[] {
	return [
		"artifact_sha256_required",
		"final_pass_requires_json_query",
		"final_pass_requires_verifier_pass",
		"unresolved_adversary_challenge_blocks_final",
		"unresolved_conflict_blocks_final",
		"conflict_loser_must_be_downgraded",
	];
}

export function verifyStructuredClaimMergePromotion(merge: StructuredClaimMergeV1): {
	ok: boolean;
	errors: string[];
} {
	const errors: string[] = [];
	if (merge.claimRows.length === 0) errors.push("structured_claim_rows_missing");
	if ((merge.promotionCheck?.finalClaims ?? []).length === 0) errors.push("final_claims_missing");
	const claims = new Map(merge.claimRows.map((claim) => [claim.claimId, claim]));
	const conflictsByClaim = new Map<string, StructuredClaimMergeV1["conflictTable"]>();
	for (const conflict of merge.conflictTable) {
		if (conflict.status !== "resolved") errors.push(`unresolved_conflict:${conflict.conflictId}`);
		if (!conflict.winnerClaimId) errors.push(`missing_conflict_winner:${conflict.conflictId}`);
		if (conflict.winningEvidenceRefs.length === 0) errors.push(`missing_winning_evidence:${conflict.conflictId}`);
		for (const claimId of conflict.claimIds) {
			const rows = conflictsByClaim.get(claimId) ?? [];
			rows.push(conflict);
			conflictsByClaim.set(claimId, rows);
		}
		for (const loser of conflict.claimIds.filter((claimId) => claimId !== conflict.winnerClaimId)) {
			if (!conflict.downgradeLosers.includes(loser)) errors.push(`conflict_loser_not_downgraded:${loser}`);
		}
	}
	for (const claim of merge.claimRows) {
		for (const ref of claim.artifactRefs) {
			if (!/^[a-f0-9]{64}$/i.test(ref.sha256))
				errors.push(`artifact_sha256_required:${claim.claimId}:${ref.artifactId}`);
			if (!ref.jsonQuery) errors.push(`final_pass_requires_json_query:${claim.claimId}:${ref.artifactId}`);
			if (!ref.verifierPass) errors.push(`artifact_verifier_not_passed:${claim.claimId}:${ref.artifactId}`);
			if (!ref.path || !existsSync(ref.path)) {
				errors.push(`artifact_path_missing:${claim.claimId}:${ref.artifactId}`);
			} else if (/^[a-f0-9]{64}$/i.test(ref.sha256)) {
				try {
					const actualSha256 = createHash("sha256").update(readFileSync(ref.path)).digest("hex");
					if (actualSha256 !== ref.sha256.toLowerCase())
						errors.push(`artifact_sha256_mismatch:${claim.claimId}:${ref.artifactId}`);
				} catch {
					errors.push(`artifact_read_error:${claim.claimId}:${ref.artifactId}`);
				}
			}
		}
		for (const challenge of claim.challenges) {
			if (challenge.status !== "resolved")
				errors.push(`unresolved_adversary_challenge_blocks_final:${claim.claimId}`);
		}
	}
	for (const finalClaim of merge.promotionCheck?.finalClaims ?? []) {
		const claim = claims.get(finalClaim.claimId);
		if (!claim) {
			errors.push(`final_claim_missing:${finalClaim.claimId}`);
			continue;
		}
		if (claim.status !== "proven") errors.push(`final_pass_claim_not_proven:${finalClaim.claimId}`);
		if (!finalClaim.verifierPass) errors.push(`final_pass_without_verifier_pass:${finalClaim.claimId}`);
		if (finalClaim.artifactRefs.length === 0) errors.push(`final_pass_artifact_refs_missing:${finalClaim.claimId}`);
		const claimArtifactRefs = new Set(
			claim.artifactRefs.map((ref) => `${ref.artifactId}\0${ref.path}\0${ref.sha256}\0${ref.jsonQuery}`),
		);
		for (const ref of finalClaim.artifactRefs) {
			if (!ref.jsonQuery) errors.push(`final_pass_requires_json_query:${finalClaim.claimId}`);
			if (!/^[a-f0-9]{64}$/i.test(ref.sha256)) errors.push(`final_pass_requires_sha256:${finalClaim.claimId}`);
			if (!ref.verifierPass) errors.push(`final_pass_artifact_not_verified:${finalClaim.claimId}:${ref.artifactId}`);
			const binding = `${ref.artifactId}\0${ref.path}\0${ref.sha256}\0${ref.jsonQuery}`;
			if (!claimArtifactRefs.has(binding))
				errors.push(`final_pass_artifact_not_bound_to_claim:${finalClaim.claimId}:${ref.artifactId}`);
		}
		for (const conflict of conflictsByClaim.get(finalClaim.claimId) ?? []) {
			if (conflict.status !== "resolved") errors.push(`unresolved_conflict_blocks_final:${finalClaim.claimId}`);
			if (conflict.winnerClaimId !== finalClaim.claimId)
				errors.push(`final_pass_lost_conflict:${finalClaim.claimId}`);
		}
	}
	return { ok: errors.length === 0, errors: uniqueNonEmpty(errors, 80) };
}

export function createSwarmClaimRuntime(dependencies: SwarmClaimRuntimeDependencies) {
	const runtimeArtifactHashes = dependencies.runtimeArtifactHashes;
	const terminalSwarmWorkerExecutions = dependencies.terminalExecutions;
	const swarmExecutionFailed = dependencies.executionFailed;

	function swarmClaimLedgerEventHash(event: SwarmClaimLedgerEventV1): string {
		const { eventHash: _eventHash, ...withoutHash } = event;
		return createHash("sha256").update(JSON.stringify(withoutHash)).digest("hex");
	}

	function appendSwarmClaimLedgerEvent(
		events: SwarmClaimLedgerEventV1[],
		event: Omit<SwarmClaimLedgerEventV1, "kind" | "seq" | "prevHash" | "eventHash" | "timestamp" | "source">,
		timestamp: string,
	): SwarmClaimLedgerEventV1 {
		const row: SwarmClaimLedgerEventV1 = {
			kind: "ClaimLedgerEventV1",
			seq: events.length + 1,
			prevHash: events.at(-1)?.eventHash ?? "0".repeat(64),
			eventHash: "",
			timestamp,
			source: "re_swarm",
			...event,
		};
		row.eventHash = swarmClaimLedgerEventHash(row);
		events.push(row);
		return row;
	}

	function swarmClaimLedgerHashChainOk(events: SwarmClaimLedgerEventV1[]): boolean {
		let prevHash = "0".repeat(64);
		for (const event of events) {
			if (event.kind !== "ClaimLedgerEventV1" || event.prevHash !== prevHash) return false;
			if (event.eventHash !== swarmClaimLedgerEventHash(event)) return false;
			prevHash = event.eventHash;
		}
		return events.length > 0;
	}

	function swarmClaimInputArtifacts(swarm: SwarmArtifact): string[] {
		const generatedOutputs = new Set(
			[swarm.claimLedgerPath, swarm.structuredClaimMergePath].filter((path): path is string => Boolean(path)),
		);
		return (Array.isArray(swarm.sourceArtifacts) ? swarm.sourceArtifacts : []).filter(
			(path): path is string => typeof path === "string" && !generatedOutputs.has(path),
		);
	}

	function buildSwarmRuntimeClaimLedger(swarm: SwarmArtifact): SwarmClaimLedgerEventV1[] {
		const events: SwarmClaimLedgerEventV1[] = [];
		const timestamp = swarm.timestamp;
		const planId = swarm.parallelPlan?.planId ?? "missing";
		const scope = swarm.target ?? swarm.missionId ?? swarm.route ?? "re_swarm";
		const inputArtifacts = swarmClaimInputArtifacts(swarm);
		appendSwarmClaimLedgerEvent(
			events,
			{
				type: "artifact_handoff",
				claimId: `${planId}:artifact_handoff`,
				workerId: "re_swarm",
				role: "swarm",
				scope,
				statement: "re_swarm emitted ReconParallelPlanV1-bound worker runtime packets and merge contract.",
				evidenceRefs: [
					swarm.delegationArtifact,
					swarm.subagentRuntimeManifestPath,
					...(swarm.parallelPlan?.merge.expectedArtifacts ?? []),
					...(swarm.subagentRuntimeManifests ?? []).flatMap((manifest) => [
						manifest.runtimeManifestFile,
						manifest.stdoutPath,
						manifest.stderrPath,
					]),
					...inputArtifacts,
				].filter((item): item is string => Boolean(item)),
				artifactHashes: runtimeArtifactHashes([
					swarm.delegationArtifact,
					swarm.subagentRuntimeManifestPath,
					...(swarm.subagentRuntimeManifests ?? []).flatMap((manifest) => [
						manifest.runtimeManifestFile,
						manifest.stdoutPath,
						manifest.stderrPath,
					]),
					...inputArtifacts,
				]),
				metadata: {
					mode: swarm.mode,
					planId,
					workerCount: swarm.workers.length,
					executionCount: swarm.executions.length,
					subagentRuntimeManifestCount: swarm.subagentRuntimeManifestCount,
					subagentRuntimeManifestsCaptured: swarm.subagentRuntimeManifestsCaptured,
					mergeStrategy: swarm.parallelPlan?.merge.strategy ?? "missing",
				},
			},
			timestamp,
		);
		for (const worker of swarm.workers) {
			const executions = swarm.executions.filter((execution) => execution.workerId === worker.id);
			const terminalExecutions = terminalSwarmWorkerExecutions(executions);
			const runtimeManifests = (swarm.subagentRuntimeManifests ?? []).filter(
				(manifest) => manifest.workerId === worker.id,
			);
			const runtimeManifestRefs = runtimeManifests.flatMap((manifest) => [
				manifest.runtimeManifestFile,
				manifest.stdoutPath,
				manifest.stderrPath,
			]);
			const blocked = terminalExecutions.filter(swarmExecutionFailed);
			const historicalBlocked = executions.filter(swarmExecutionFailed);
			const coverageRows = swarm.coverageMatrix.filter((row) => row.includes(`worker=${worker.id}`));
			const missingCoverageRows = coverageRows.filter((row) => /status=missing/i.test(row));
			const auditRows = swarm.executionAudit.filter((row) => row.includes(`worker=${worker.id}`));
			const claimPassed = terminalExecutions.length > 0 && blocked.length === 0 && missingCoverageRows.length === 0;
			const claimId = `${planId}:worker:${slug(worker.id).slice(0, 48)}`;
			appendSwarmClaimLedgerEvent(
				events,
				{
					type: "artifact_handoff",
					claimId,
					workerId: worker.id,
					role: worker.worker,
					scope,
					statement:
						"worker packet handoff binds commands, dependencies, merge keys, and evidence contract before execution.",
					evidenceRefs: [swarm.delegationArtifact, ...worker.sourceArtifacts, ...runtimeManifestRefs].filter(
						(item): item is string => Boolean(item),
					),
					artifactHashes: runtimeArtifactHashes([
						swarm.delegationArtifact,
						...worker.sourceArtifacts,
						...runtimeManifestRefs,
					]),
					metadata: {
						objective: worker.objective,
						commands: worker.commands,
						dependencies: worker.dependencies,
						mergeKeys: worker.mergeKeys,
						evidenceContract: worker.evidenceContract,
						runtimeManifestFiles: runtimeManifests.map((manifest) => manifest.runtimeManifestFile),
					},
				},
				timestamp,
			);
			appendSwarmClaimLedgerEvent(
				events,
				{
					type: "claim",
					claimId,
					workerId: worker.id,
					role: worker.worker,
					scope,
					status: claimPassed ? "proven" : executions.length ? "gap" : "pending",
					statement: claimPassed
						? "worker claim is artifact-backed and coverage-complete for this swarm run."
						: "worker claim is not promotable until runtime execution, coverage, and repair checkpoints close.",
					evidenceRefs: [
						swarm.delegationArtifact,
						...worker.sourceArtifacts,
						...executions.flatMap((execution) => execution.sourceArtifacts),
						...runtimeManifestRefs,
					].filter((item): item is string => Boolean(item)),
					artifactHashes: runtimeArtifactHashes([
						swarm.delegationArtifact,
						...worker.sourceArtifacts,
						...executions.flatMap((execution) => execution.sourceArtifacts),
						...runtimeManifestRefs,
					]),
					metadata: {
						workerStatus: worker.status,
						executions: executions.length,
						terminalExecutions: terminalExecutions.length,
						runtimeManifests: runtimeManifests.length,
						blocked: blocked.length,
						historicalBlocked: historicalBlocked.length,
						recoveredByRetry: historicalBlocked.length > 0 && blocked.length === 0,
						coverageRows: coverageRows.length,
						missingCoverageRows: missingCoverageRows.length,
					},
				},
				timestamp,
			);
			appendSwarmClaimLedgerEvent(
				events,
				{
					type: "validation",
					claimId,
					workerId: worker.id,
					role: "supervisor",
					scope,
					status: claimPassed ? "pass" : "fail",
					statement:
						"runtime coverage validation checks execution status, blocked rows, and evidence-contract coverage.",
					evidenceRefs: [swarm.delegationArtifact, ...worker.sourceArtifacts, ...runtimeManifestRefs].filter(
						(item): item is string => Boolean(item),
					),
					metadata: {
						auditRows,
						coverageRows,
						missingCoverageRows,
						runtimeManifestFiles: runtimeManifests.map((manifest) => manifest.runtimeManifestFile),
						blockedCommands: blocked.map((execution) => execution.command),
					},
				},
				timestamp,
			);
			if (!claimPassed) {
				const reason =
					executions.length === 0
						? "pending_execution"
						: blocked.length
							? "blocked_execution"
							: "missing_evidence_contract";
				appendSwarmClaimLedgerEvent(
					events,
					{
						type: "challenge",
						claimId,
						workerId: worker.id,
						role: "adversary",
						scope,
						status: "blocked",
						challenge: `worker claim challenged: ${reason}`,
						evidenceRefs: [swarm.delegationArtifact, ...worker.sourceArtifacts, ...runtimeManifestRefs].filter(
							(item): item is string => Boolean(item),
						),
						metadata: {
							reason,
							blockedRows: blocked.map((execution) =>
								truncateMiddle(execution.output.replace(/\s+/g, " "), 240),
							),
							missingCoverageRows,
						},
					},
					timestamp,
				);
				appendSwarmClaimLedgerEvent(
					events,
					{
						type: "resolution",
						claimId,
						workerId: worker.id,
						role: "re_swarm",
						scope,
						status: "queued_repair",
						resolution:
							"claim remains downgraded; retryQueue and supervisor repair must close before final promotion.",
						evidenceRefs: [swarm.claimLedgerPath, ...swarm.retryQueue].filter((item): item is string =>
							Boolean(item),
						),
						metadata: {
							retryQueue: swarm.retryQueue.filter((row) => row.includes(`worker=${worker.id}`)),
							next: `re_swarm run ${swarm.target ?? "<target>"} 1 1 && re_supervisor repair ${swarm.target ?? "<target>"}`,
						},
					},
					timestamp,
				);
			} else {
				appendSwarmClaimLedgerEvent(
					events,
					{
						type: "challenge",
						claimId,
						workerId: worker.id,
						role: "adversary",
						scope,
						status: "accepted",
						challenge: "passed worker claim receives adversarial challenge before promotion.",
						evidenceRefs: [swarm.delegationArtifact, ...worker.sourceArtifacts, ...runtimeManifestRefs].filter(
							(item): item is string => Boolean(item),
						),
						metadata: {
							auditRows,
							coverageRows,
							runtimeManifestFiles: runtimeManifests.map((manifest) => manifest.runtimeManifestFile),
						},
					},
					timestamp,
				);
				appendSwarmClaimLedgerEvent(
					events,
					{
						type: "resolution",
						claimId,
						workerId: worker.id,
						role: "supervisor",
						scope,
						status: "accepted",
						resolution:
							"passed worker claim remains eligible for final promotion only after strict claim checkpoint and structured merge.",
						evidenceRefs: [
							swarm.claimLedgerPath,
							...runtimeManifestRefs,
							"check:claim-release",
							"re_supervisor review",
						].filter((item): item is string => Boolean(item)),
						metadata: {
							strictFinalPromotion: "requires StructuredClaimMergeV1 and claim checkpoint pass",
						},
					},
					timestamp,
				);
			}
		}
		for (const collision of swarm.collisionMatrix) {
			const claimId = `${planId}:collision:${createHash("sha256").update(collision).digest("hex").slice(0, 12)}`;
			appendSwarmClaimLedgerEvent(
				events,
				{
					type: "challenge",
					claimId,
					workerId: "collision_matrix",
					role: "adversary",
					scope,
					status: "blocked",
					challenge: `merge conflict requires supervisor arbitration: ${collision}`,
					evidenceRefs: [swarm.delegationArtifact, ...swarm.sourceArtifacts].filter((item): item is string =>
						Boolean(item),
					),
				},
				timestamp,
			);
			appendSwarmClaimLedgerEvent(
				events,
				{
					type: "resolution",
					claimId,
					workerId: "collision_matrix",
					role: "supervisor",
					scope,
					status: "queued_repair",
					resolution:
						"collision is preserved for re_supervisor review; final claim promotion is blocked until conflict is resolved.",
					evidenceRefs: [swarm.claimLedgerPath, "re_supervisor review"].filter((item): item is string =>
						Boolean(item),
					),
				},
				timestamp,
			);
		}
		if (!events.some((event) => event.type === "challenge")) {
			appendSwarmClaimLedgerEvent(
				events,
				{
					type: "challenge",
					claimId: `${planId}:final_promotion_policy`,
					workerId: "re_swarm",
					role: "adversary",
					scope,
					status: "accepted",
					challenge:
						"no unresolved worker challenge in this swarm artifact; retain final-promotion adversary checkpoint.",
					evidenceRefs: [swarm.claimLedgerPath, swarm.delegationArtifact].filter((item): item is string =>
						Boolean(item),
					),
				},
				timestamp,
			);
			appendSwarmClaimLedgerEvent(
				events,
				{
					type: "resolution",
					claimId: `${planId}:final_promotion_policy`,
					workerId: "re_swarm",
					role: "supervisor",
					scope,
					status: "accepted",
					resolution:
						"role claims may only promote after supervisor claimCheckPolicy and strict claim marker pass.",
					evidenceRefs: [swarm.claimLedgerPath, "check:claim-release", "re_supervisor review"].filter(
						(item): item is string => Boolean(item),
					),
				},
				timestamp,
			);
		}
		return events;
	}

	function structuredClaimArtifactRefsFromLedgerEvent(event: SwarmClaimLedgerEventV1): StructuredClaimArtifactRefV1[] {
		return (event.artifactHashes ?? [])
			.filter((artifact) => typeof artifact.sha256 === "string" && artifact.sha256.length >= 32)
			.slice(0, 12)
			.map((artifact, index) => ({
				artifactId: `${event.claimId ?? "claim"}:artifact:${index + 1}`,
				path: artifact.path,
				sha256: artifact.sha256,
				jsonQuery: "$.sha256",
				op: "==" as const,
				expected: artifact.sha256,
				verifierPass: true,
			}));
	}

	function structuredClaimStatusFromLedger(status: SwarmClaimLedgerEventV1["status"]): StructuredClaimRowV1["status"] {
		if (status === "proven") return "proven";
		if (status === "pending") return "pending";
		if (status === "blocked" || status === "fail" || status === "queued_repair") return "gap";
		return "gap";
	}

	function structuredClaimConflictScore(claim: StructuredClaimRowV1): number {
		const statusScore =
			claim.status === "proven" ? 1000 : claim.status === "pending" ? 200 : claim.status === "gap" ? 100 : 0;
		const challengeScore =
			claim.challenges.length && claim.challenges.every((challenge) => challenge.status === "resolved") ? 200 : 0;
		return statusScore + challengeScore + claim.artifactRefs.length * 25 + (claim.statement ? 5 : 0);
	}

	function resolveStructuredClaimConflict(
		collision: string,
		index: number,
		claimRows: StructuredClaimRowV1[],
		swarm: Pick<SwarmArtifact, "claimLedgerPath" | "structuredClaimMergePath">,
	): StructuredClaimMergeV1["conflictTable"][number] {
		const conflictClaims = claimRows.slice(0, 8);
		const winner = [...conflictClaims].sort((left, right) => {
			const delta = structuredClaimConflictScore(right) - structuredClaimConflictScore(left);
			return delta || left.claimId.localeCompare(right.claimId);
		})[0];
		const winningEvidenceRefs = uniqueNonEmpty(
			[
				...(winner?.artifactRefs ?? []).map((ref) => ref.path),
				swarm.claimLedgerPath,
				swarm.structuredClaimMergePath,
			],
			16,
		);
		return {
			conflictId: `collision:${index + 1}:${createHash("sha256").update(collision).digest("hex").slice(0, 12)}`,
			claimIds: conflictClaims.map((claim) => claim.claimId),
			topic: collision,
			status: winner && winningEvidenceRefs.length ? "resolved" : "unresolved",
			winnerClaimId: winner?.claimId,
			winningEvidenceRefs,
			downgradeLosers: conflictClaims
				.filter((claim) => claim.claimId !== winner?.claimId)
				.map((claim) => claim.claimId),
			resolutionReason: winner
				? `structured_conflict_arbitration_live_wiring: winner selected by runtime evidence score=${structuredClaimConflictScore(winner)}; evidence order runtime/memory/network/served/process/persisted; loser claims downgraded until stronger verifier artifacts appear.`
				: "structured_conflict_arbitration_live_wiring: unresolved because no claim rows were available for arbitration.",
		};
	}

	function buildStructuredClaimMergeFromSwarm(swarm: SwarmArtifact): StructuredClaimMergeV1 {
		const claimLedger = swarm.claimLedger ?? [];
		const planId = swarm.parallelPlan?.planId ?? `re_swarm:${swarm.timestamp}`;
		const claimEvents = claimLedger.filter((event) => event.type === "claim" && Boolean(event.claimId));
		const validationByClaim = new Map(
			claimLedger
				.filter((event) => event.type === "validation" && Boolean(event.claimId))
				.map((event) => [event.claimId as string, event]),
		);
		const challengesByClaim = new Map<string, SwarmClaimLedgerEventV1[]>();
		const resolutionsByClaim = new Map<string, SwarmClaimLedgerEventV1[]>();
		for (const event of claimLedger) {
			if (!event.claimId) continue;
			if (event.type === "challenge")
				challengesByClaim.set(event.claimId, [...(challengesByClaim.get(event.claimId) ?? []), event]);
			if (event.type === "resolution")
				resolutionsByClaim.set(event.claimId, [...(resolutionsByClaim.get(event.claimId) ?? []), event]);
		}
		const claimRows: StructuredClaimRowV1[] = claimEvents.map((event) => {
			const validation = validationByClaim.get(event.claimId as string);
			const resolutionRows = resolutionsByClaim.get(event.claimId as string) ?? [];
			const artifactRefs = structuredClaimArtifactRefsFromLedgerEvent(event);
			return {
				claimId: event.claimId as string,
				workerId: event.workerId ?? "re_swarm",
				mergeKey: `${event.scope ?? swarm.target ?? swarm.route ?? "re_swarm"}:${event.workerId ?? "worker"}`,
				status:
					validation?.status === "pass" && event.status === "proven" && artifactRefs.length > 0
						? "proven"
						: structuredClaimStatusFromLedger(event.status),
				statement: event.statement ?? "worker claim missing statement",
				artifactRefs,
				challenges: (challengesByClaim.get(event.claimId as string) ?? []).map((challenge, index) => {
					const resolution = resolutionRows[index] ?? resolutionRows[0];
					const resolved = Boolean(
						resolution && (resolution.status === "accepted" || resolution.status === "pass"),
					);
					return {
						challengeId: `${challenge.claimId}:challenge:${index + 1}`,
						status: resolved ? "resolved" : "open",
						resolution: resolution?.resolution,
					};
				}),
			};
		});
		const provenIds = new Set(claimRows.filter((claim) => claim.status === "proven").map((claim) => claim.claimId));
		const conflictTable: StructuredClaimMergeV1["conflictTable"] = (swarm.collisionMatrix ?? [])
			.filter(() => claimRows.length > 1)
			.map((collision, index) => resolveStructuredClaimConflict(collision, index, claimRows, swarm));
		const conflictLoserIds = new Set(conflictTable.flatMap((conflict) => conflict.downgradeLosers));
		const conflictWinnerIds = new Set(
			conflictTable.map((conflict) => conflict.winnerClaimId).filter((item): item is string => Boolean(item)),
		);
		const finalClaims = claimRows
			.filter(
				(claim) =>
					claim.status === "proven" &&
					claim.artifactRefs.length > 0 &&
					claim.challenges.every((challenge) => challenge.status === "resolved") &&
					!conflictLoserIds.has(claim.claimId) &&
					(conflictTable.length === 0 || conflictWinnerIds.has(claim.claimId)),
			)
			.map((claim) => ({
				claimId: claim.claimId,
				promotion: "final_pass" as const,
				reportSection: `worker:${claim.workerId}`,
				verifierPass: true,
				artifactRefs: claim.artifactRefs,
			}));
		const blockedClaims = claimRows
			.filter(
				(claim) =>
					!provenIds.has(claim.claimId) ||
					claim.challenges.some((challenge) => challenge.status !== "resolved") ||
					claim.artifactRefs.length === 0 ||
					conflictLoserIds.has(claim.claimId),
			)
			.map((claim) => ({
				claimId: claim.claimId,
				reason: conflictLoserIds.has(claim.claimId)
					? "lost_structured_conflict_arbitration"
					: claim.artifactRefs.length === 0
						? "artifact_sha256_required"
						: claim.challenges.some((challenge) => challenge.status !== "resolved")
							? "unresolved_adversary_challenge_blocks_final"
							: `claim_status_${claim.status}`,
			}));
		return {
			kind: "StructuredClaimMergeV1",
			schemaVersion: 1,
			mergeId: `structured-claim-merge:${planId}:${createHash("sha256")
				.update(JSON.stringify(claimLedger.map((event) => event.eventHash)))
				.digest("hex")
				.slice(0, 16)}`,
			sourcePoolId: planId,
			target: swarm.target,
			claimRows,
			conflictTable,
			promotionCheck: {
				mode: "strict_final_claim_promotion",
				requiredStatuses: ["proven"],
				finalClaims,
				blockedClaims,
				policies: claimPromotionEvidenceContract(),
			},
		};
	}

	function structuredClaimMergeCheckFromSwarm(swarm?: SwarmArtifact): StructuredClaimMergeCheckSnapshot {
		if (!swarm || !swarm.claimLedger?.length) {
			return {
				status: "missing",
				finalClaimCount: 0,
				blockedClaimCount: 0,
				errors: ["structured_claim_merge_missing_runtime_claim_ledger"],
				policies: claimPromotionEvidenceContract(),
			};
		}
		/*
		 * Never promote from the serialized merge/ledger fields alone.  A swarm
		 * artifact is persisted JSON and can be edited or partially recovered;
		 * trusting `structuredClaimMerge.promotionCheck.finalClaims` here lets a
		 * caller replace a blocked worker claim with a hand-written `final_pass`
		 * without changing the underlying executions.  Rebuild both values from
		 * the execution-backed swarm state, then treat the serialized copies as
		 * integrity witnesses only.
		 */
		const derivedLedger = buildSwarmRuntimeClaimLedger(swarm);
		const persistedLedger = swarm.claimLedger;
		const ledgerHashesMatch =
			persistedLedger.length === derivedLedger.length &&
			persistedLedger.every((event, index) => event?.eventHash === derivedLedger[index]?.eventHash);
		const derivedSwarm = { ...swarm, claimLedger: derivedLedger };
		const derivedMerge = buildStructuredClaimMergeFromSwarm(derivedSwarm);
		const mergeMatches =
			swarm.structuredClaimMerge === undefined ||
			canonicalJson(swarm.structuredClaimMerge) === canonicalJson(derivedMerge);
		const verification = verifyStructuredClaimMergePromotion(derivedMerge);
		const integrityErrors = [
			...(ledgerHashesMatch ? [] : ["runtime_claim_ledger_serialized_mismatch"]),
			...(mergeMatches ? [] : ["structured_claim_merge_serialized_mismatch"]),
		];
		return {
			status: verification.ok && integrityErrors.length === 0 ? "pass" : "blocked",
			mergePath: swarm.structuredClaimMergePath,
			mergeId: derivedMerge.mergeId,
			finalClaimCount: derivedMerge.promotionCheck?.finalClaims?.length ?? 0,
			blockedClaimCount: derivedMerge.promotionCheck?.blockedClaims?.length ?? 0,
			errors: uniqueNonEmpty([...integrityErrors, ...verification.errors], 80),
			policies: derivedMerge.promotionCheck?.policies ?? claimPromotionEvidenceContract(),
		};
	}

	function refreshSwarmRuntimeClaimLedger(swarm: SwarmArtifact): SwarmArtifact {
		const claimLedger = buildSwarmRuntimeClaimLedger(swarm);
		const runtimeClaimLedgerCaptured =
			swarmClaimLedgerHashChainOk(claimLedger) &&
			(["artifact_handoff", "claim", "validation", "challenge", "resolution"] as const).every((type) =>
				claimLedger.some((event) => event.type === type),
			);
		const structuredClaimMergePath = swarm.structuredClaimMergePath ?? swarmStructuredClaimMergePath(swarm);
		const structuredClaimMerge = buildStructuredClaimMergeFromSwarm({
			...swarm,
			claimLedger,
			structuredClaimMergePath,
		});
		const structuredClaimMergeCheck = structuredClaimMergeCheckFromSwarm({
			...swarm,
			claimLedger,
			structuredClaimMerge,
			structuredClaimMergePath,
		});
		return {
			...swarm,
			claimLedger,
			claimLedgerEventCount: claimLedger.length,
			claimLedgerTipHash: claimLedger.at(-1)?.eventHash,
			runtimeClaimLedgerCaptured,
			structuredClaimMerge,
			structuredClaimMergePath,
			structuredClaimMergeStatus: structuredClaimMergeCheck.status,
			structuredClaimMergeErrors: structuredClaimMergeCheck.errors,
			sourceArtifacts: Array.from(
				new Set(
					[
						...swarmClaimInputArtifacts(swarm),
						swarm.subagentRuntimeManifestPath,
						...(swarm.subagentRuntimeManifests ?? []).flatMap((manifest) => [
							manifest.runtimeManifestFile,
							manifest.stdoutPath,
							manifest.stderrPath,
						]),
					].filter((item): item is string => Boolean(item)),
				),
			).slice(0, 64),
		};
	}

	return {
		buildSwarmRuntimeClaimLedger,
		buildStructuredClaimMergeFromSwarm,
		structuredClaimMergeCheckFromSwarm,
		refreshSwarmRuntimeClaimLedger,
	};
}

export type SwarmClaimRuntime = ReturnType<typeof createSwarmClaimRuntime>;
