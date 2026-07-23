import { createHash } from "node:crypto";
import { join } from "node:path";
import { createAgentThreadManager } from "../agent-thread-manager.ts";
import { normalizeWorkerTask } from "../agent-thread-worker-runtime.ts";
import type { ArtifactScopeFilterOptions } from "./artifact-scope.ts";
import { repiSubagentResultFromManifest } from "./re-subagent-contract.ts";
import { validateRepiSubagentArtifact } from "./repi-subagent-artifact-validation.ts";
import type {
	DelegateArtifact,
	DelegatePacket,
	ReconParallelPlanV1,
	SupervisorArtifact,
	SupervisorBuildOptions,
	SupervisorOutputOptions,
	SupervisorVerdict,
	SupervisorWorkerReview,
	SwarmArtifact,
	SwarmSupervisorRuntimeDependencies,
	SwarmWorkerExecution,
	SwarmWorkerRuntime,
} from "./swarm-runtime-types.ts";
import { envBoolean, parseJsonCodeFence, slug, truncateMiddle } from "./text.ts";

type CommanderCoreDependencies = Pick<
	SwarmSupervisorRuntimeDependencies,
	| "appendEvidence"
	| "buildClaimCheckResult"
	| "buildDelegate"
	| "formatStrictClaimCheckSnapshot"
	| "latestDelegateArtifactPath"
	| "latestScopedMarkdownArtifact"
	| "readCurrentMission"
	| "strictClaimCheckSnapshot"
	| "updateMissionCheckpoint"
	| "writeDelegateArtifact"
>;

export type SwarmCommanderRuntimeDependencies = CommanderCoreDependencies & {
	ensureReconStorage: () => void;
	nowIso: () => string;
	evidenceLedgerPath: () => string;
	evidenceSupervisorsDir: () => string;
	readText: (path: string, fallback?: string) => string;
	writePrivateTextFile: (path: string, text: string) => void;
	latestSwarmArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	latestSwarmRunArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	parseSwarmArtifact: (path: string) => SwarmArtifact | undefined;
	swarmPlanCoverage: (
		swarm: Pick<SwarmArtifact, "workers" | "parallelPlan" | "coverageMatrix" | "collisionMatrix">,
	) => string[];
	terminalSwarmWorkerExecutions: (executions: readonly SwarmWorkerExecution[]) => SwarmWorkerExecution[];
	swarmExecutionFailed: (execution: SwarmWorkerExecution) => boolean;
};

export function createSwarmCommanderRuntime(dependencies: SwarmCommanderRuntimeDependencies) {
	const {
		appendEvidence,
		buildClaimCheckResult,
		buildDelegate,
		ensureReconStorage,
		evidenceLedgerPath,
		evidenceSupervisorsDir,
		formatStrictClaimCheckSnapshot,
		latestDelegateArtifactPath,
		latestScopedMarkdownArtifact,
		latestSwarmArtifactPath,
		latestSwarmRunArtifactPath,
		nowIso,
		parseSwarmArtifact,
		readCurrentMission,
		readText,
		strictClaimCheckSnapshot,
		swarmExecutionFailed,
		swarmPlanCoverage,
		terminalSwarmWorkerExecutions,
		updateMissionCheckpoint,
		writeDelegateArtifact,
		writePrivateTextFile,
	} = dependencies;

	function latestSupervisorArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		return latestScopedMarkdownArtifact("supervisor", evidenceSupervisorsDir(), options);
	}

	function parseSupervisorArtifact(path: string): SupervisorArtifact | undefined {
		return parseJsonCodeFence<SupervisorArtifact>(readText(path));
	}

	function parseDelegateArtifact(path: string): DelegateArtifact | undefined {
		return parseJsonCodeFence<DelegateArtifact>(readText(path));
	}

	function latestOrBuildDelegate(options: { target?: string; task?: string } = {}): {
		delegate: DelegateArtifact;
		path: string;
	} {
		const latest = !options.target && !options.task ? latestDelegateArtifactPath() : undefined;
		if (latest) {
			const delegate = parseDelegateArtifact(latest);
			const missionId = readCurrentMission()?.id;
			if (delegate && missionId && delegate.missionId === missionId) return { delegate, path: latest };
		}
		const delegate = buildDelegate({ target: options.target, task: options.task, mode: "plan" });
		const path = writeDelegateArtifact(delegate);
		return { delegate, path };
	}

	function evidenceHitForPacket(packet: DelegatePacket, ledger: string): boolean {
		const haystack = ledger.toLowerCase();
		const needles = [packet.worker, ...packet.phases, ...packet.evidenceContract]
			.map((item) => item.toLowerCase())
			.filter((item) => item.length > 3);
		return needles.some((needle) => haystack.includes(needle));
	}

	function reviewDelegatePacket(packet: DelegatePacket, ledger: string): SupervisorWorkerReview {
		const rationale: string[] = [];
		const conflicts: string[] = [];
		const evidenceGaps: string[] = [];
		const repairActions: string[] = [];
		let score = 45;
		if (packet.status === "done") {
			score += 30;
			rationale.push("packet status is done");
		}
		if (packet.status === "ready") {
			score += 10;
			rationale.push("packet has ready steps");
		}
		if (packet.status === "blocked") {
			score -= 25;
			conflicts.push("packet is blocked");
			repairActions.push("re_operation next");
		}
		if (packet.steps.length === 0) {
			score -= 20;
			evidenceGaps.push("no operation steps assigned");
		}
		if (packet.sourceArtifacts.length > 0) {
			score += 10;
			rationale.push("source artifacts attached");
		} else {
			score -= 10;
			evidenceGaps.push("no source artifact attached to packet");
			repairActions.push("re_operation plan");
		}
		if (evidenceHitForPacket(packet, ledger)) {
			score += 15;
			rationale.push("evidence ledger contains worker/contract anchors");
		} else {
			score -= 10;
			evidenceGaps.push(`ledger lacks ${packet.worker} evidence-contract anchors`);
		}
		const readySteps = packet.steps.filter((step) => step.status === "ready");
		if (readySteps.length > 0) repairActions.push(...readySteps.slice(0, 3).map((step) => step.command));
		if (packet.recommendedTools.length > 0)
			repairActions.push(`re_bootstrap plan ${packet.recommendedTools.slice(0, 6).join(" ")}`);
		const uniqueCommands = new Set(packet.steps.map((step) => step.command));
		if (uniqueCommands.size < packet.steps.length) conflicts.push("duplicate operation commands inside packet");
		score = Math.max(0, Math.min(100, score));
		const verdict: SupervisorVerdict =
			packet.status === "blocked" ? "blocked" : score >= 80 ? "pass" : score >= 60 ? "watch" : "repair";
		const priority = verdict === "blocked" ? 1 : verdict === "repair" ? 2 : verdict === "watch" ? 3 : 4;
		return {
			packetId: packet.id,
			worker: packet.worker,
			verdict,
			score,
			priority,
			rationale: rationale.length ? rationale : ["packet requires supervisor follow-up"],
			conflicts,
			evidenceGaps,
			repairActions: Array.from(new Set(repairActions)).slice(0, 8),
		};
	}

	function latestSwarmForSupervisor(
		options: { target?: string } = {},
	): { swarm: SwarmArtifact; path: string } | undefined {
		const scope = options.target ? { target: options.target, requestedBy: "supervisor_swarm_run" } : {};
		const path = latestSwarmRunArtifactPath(scope) ?? latestSwarmArtifactPath(scope);
		if (!path) return undefined;
		const swarm = parseSwarmArtifact(path);
		if (!swarm) return undefined;
		const missionId = readCurrentMission()?.id;
		if (!missionId || swarm.missionId !== missionId) return undefined;
		if (options.target && swarm.target && options.target !== swarm.target) return undefined;
		return { swarm, path };
	}

	function reviewSwarmWorkerRuntime(
		worker: SwarmWorkerRuntime,
		swarm: SwarmArtifact,
		ledger: string,
	): SupervisorWorkerReview {
		const executions = swarm.executions.filter((execution) => execution.workerId === worker.id);
		const blocked = terminalSwarmWorkerExecutions(executions).filter(swarmExecutionFailed);
		const rationale: string[] = [];
		const conflicts: string[] = [];
		const evidenceGaps: string[] = [];
		const repairActions: string[] = [];
		let score = 50;
		if (executions.length > 0) {
			score += 15;
			rationale.push(`swarm worker executed ${executions.length} command(s)`);
		} else {
			score -= 15;
			evidenceGaps.push("swarm worker has no runtime execution yet");
			repairActions.push(`re_swarm run ${swarm.target ?? "<target>"} 1 1`);
		}
		if (worker.status === "done") {
			score += 25;
			rationale.push("swarm worker completed without blocked execution");
		}
		if (worker.status === "blocked" || blocked.length > 0) {
			score -= 35;
			conflicts.push(
				...blocked.map((execution) => `${execution.command}: ${truncateMiddle(execution.output, 180)}`),
			);
			repairActions.push(`re_swarm run ${swarm.target ?? "<target>"} 1 1`);
			repairActions.push("re_evidence show");
		}
		if (swarm.workerResults.some((result) => result.includes(worker.id))) {
			score += 10;
			rationale.push("worker_results contains runtime merge row");
		} else {
			score -= 10;
			evidenceGaps.push("worker_results lacks runtime merge row");
		}
		if (swarm.mergeDigest.some((item) => item.includes(worker.id) || item.includes(`worker=${worker.worker}`))) {
			score += 10;
			rationale.push("merge_digest contains worker evidence");
		}
		if (
			swarm.executionAudit.some(
				(item) => item.includes(`worker=${worker.id}`) && /status=(covered|needs_evidence)/i.test(item),
			)
		) {
			score += 10;
			rationale.push("execution_audit contains worker runtime coverage row");
		} else {
			score -= 5;
			evidenceGaps.push("execution_audit lacks worker coverage row");
		}
		const workerCoverageRows = swarm.coverageMatrix.filter((item) => item.includes(`worker=${worker.id}`));
		const missingCoverageRows = workerCoverageRows.filter((item) => /status=missing/i.test(item));
		if (workerCoverageRows.length > 0 && missingCoverageRows.length === 0) {
			score += 10;
			rationale.push("coverage_matrix satisfies worker evidence contract");
		} else if (missingCoverageRows.length > 0) {
			score -= 10;
			evidenceGaps.push(`coverage_matrix missing ${missingCoverageRows.length} contract row(s)`);
		}
		const workerRetries = swarm.retryQueue.filter((item) => item.includes(`worker=${worker.id}`));
		if (workerRetries.length > 0) {
			score -= 10;
			repairActions.push(...workerRetries.slice(0, 3).map((item) => item.replace(/^.*\bnext=/, "")));
		}
		if (
			evidenceHitForPacket(
				{
					id: worker.id,
					worker: worker.worker,
					objective: worker.objective,
					status:
						worker.status === "done" || worker.status === "merged"
							? "done"
							: worker.status === "blocked"
								? "blocked"
								: "ready",
					phases: worker.mergeKeys
						.filter((key) => key.startsWith("phase="))
						.map((key) => key.replace(/^phase=/, "")),
					steps: worker.commands.map((command, index) => ({
						id: `${worker.id}:cmd:${index + 1}`,
						phase: "swarm",
						command,
						status: worker.status === "blocked" ? "blocked" : worker.status === "done" ? "done" : "ready",
						sourceArtifacts: worker.sourceArtifacts,
					})),
					evidenceContract: worker.evidenceContract,
					recommendedTools: worker.recommendedTools,
					handoffPrompt: worker.spawnPrompt,
					sourceArtifacts: worker.sourceArtifacts,
				},
				ledger,
			)
		) {
			score += 10;
			rationale.push("ledger contains swarm worker anchors");
		}
		if (worker.commands.length > 0 && (blocked.length > 0 || executions.length === 0))
			repairActions.push(...worker.commands.slice(0, 2));
		repairActions.push(`re_proof_loop run ${swarm.target ?? "<target>"} 4 2`);
		score = Math.max(0, Math.min(100, score));
		const verdict: SupervisorVerdict =
			worker.status === "blocked" ? "blocked" : score >= 80 ? "pass" : score >= 60 ? "watch" : "repair";
		const priority = verdict === "blocked" ? 1 : verdict === "repair" ? 2 : verdict === "watch" ? 3 : 4;
		return {
			packetId: worker.id,
			worker: worker.worker,
			verdict,
			score,
			priority,
			rationale: rationale.length ? rationale : ["swarm worker requires commander merge follow-up"],
			conflicts,
			evidenceGaps,
			repairActions: Array.from(new Set(repairActions)).slice(0, 10),
		};
	}

	function swarmCommanderMergeQueue(swarm?: SwarmArtifact): string[] {
		if (!swarm) return [];
		const target = swarm.target ?? "<target>";
		return Array.from(
			new Set([
				...(swarm.blocked.length ? [`re_supervisor repair ${target}`, "re_evidence show"] : []),
				...swarm.retryQueue
					.flatMap((item) => item.match(/next=([^&;]+)/i)?.[1]?.trim() ?? [])
					.filter((item) => /^re[-_]/i.test(item)),
				...swarm.blocked.slice(0, 8).map(() => `re_swarm run ${target} 1 1`),
				...(swarm.workerResults.length ? ["re_verifier matrix", `re_proof_loop run ${target} 4 2`] : []),
				...(swarm.mergeDigest.length ? ["re_swarm merge", "re_supervisor review"] : []),
				...(swarm.executions.length ? ["re_evidence show", `re_operator dispatch ${target} 2`] : []),
			]),
		).slice(0, 18);
	}

	function commanderWorkerScoreboard(reviews: SupervisorWorkerReview[]): string[] {
		return reviews
			.slice()
			.sort((left, right) => left.priority - right.priority || left.score - right.score)
			.map((review) => {
				const retryBudget = review.verdict === "blocked" ? 2 : review.verdict === "repair" ? 1 : 0;
				const failureCost = review.verdict === "blocked" ? 2 : review.verdict === "repair" ? 1 : 0;
				const next = review.repairActions[0] ?? "none";
				return `${review.worker} packet=${review.packetId} verdict=${review.verdict} score=${review.score} retry_budget=${retryBudget} failure_cost=${failureCost} next=${next}`;
			})
			.slice(0, 32);
	}

	function buildCommanderMergeBudget(
		reviews: SupervisorWorkerReview[],
		queue: string[],
		swarm?: SwarmArtifact,
	): string[] {
		const blockedWorkers = reviews.filter((review) => review.verdict === "blocked").length;
		const repairWorkers = reviews.filter((review) => review.verdict === "repair").length;
		const watchWorkers = reviews.filter((review) => review.verdict === "watch").length;
		const queueDepth = queue.length;
		const maxDispatch = Math.max(1, Math.min(6, queueDepth ? Math.ceil(queueDepth / 2) : 1));
		const retryLimit = Math.max(1, Math.min(3, blockedWorkers ? 2 : repairWorkers ? 1 : 1));
		const failureBudget = Math.max(
			1,
			Math.min(6, blockedWorkers * 2 + repairWorkers + (swarm?.blocked.length ?? 0) || 1),
		);
		const proofRerun = queue.some((item) => /^re[-_]proof[-_]loop\s+run/i.test(item));
		return [
			`max_dispatch=${maxDispatch}`,
			`retry_limit_per_worker=${retryLimit}`,
			`failure_budget=${failureBudget}`,
			`queue_depth=${queueDepth}`,
			`blocked_workers=${blockedWorkers}`,
			`repair_workers=${repairWorkers}`,
			`watch_workers=${watchWorkers}`,
			`swarm_executions=${swarm?.executions.length ?? 0}`,
			`swarm_blocked=${swarm?.blocked.length ?? 0}`,
			`proof_rerun=${proofRerun ? "yes" : "no"}`,
		];
	}

	function supervisorClaimCheckPolicy(plan?: ReconParallelPlanV1, planCoverage: string[] = []): string[] {
		const workerBinding =
			planCoverage.find((row) => row.startsWith("worker_binding="))?.replace(/^worker_binding=/, "") ?? "missing";
		const missingContractRows = planCoverage.filter((row) => /\bmissing=[1-9]/.test(row));
		return [
			`claim_check_policy.parallel_plan_id=${plan?.planId ?? "missing"}`,
			`claim_check_policy.parallel_plan_source=${plan?.source ?? "missing"}`,
			`claim_check_policy.worker_binding=${workerBinding}`,
			`claim_check_policy.plan_contract_gaps=${missingContractRows.length}`,
			"claim_check_policy.proven_requires_artifact_sha256=true",
			"claim_check_policy.proven_requires_json_query=true",
			"claim_check_policy.final_pass_requires_verifier=true",
			"claim_check_policy.unresolved_challenge_blocks=true",
			"claim_check_policy.orchestration_score_never_implies_platform_success=true",
			"claim_check_policy.final_pass_blocks_on_plan_coverage_gap=true",
		];
	}

	function supervisorPlanCoverage(swarm?: SwarmArtifact): string[] {
		if (!swarm) return ["parallel_plan=missing status=blocked next=re_swarm plan"];
		return swarmPlanCoverage(swarm);
	}

	function buildSupervisor(options: SupervisorBuildOptions = {}): SupervisorArtifact {
		ensureReconStorage();
		const { delegate, path: delegationArtifact } = latestOrBuildDelegate(options);
		const ledger = readText(evidenceLedgerPath());
		const latestSwarm = latestSwarmForSupervisor({ target: options.target ?? delegate.target });
		const swarm = latestSwarm?.swarm;
		const parallelPlan = swarm?.parallelPlan;
		const planCoverage = supervisorPlanCoverage(swarm);
		const releaseCheckMetadata = swarm?.releaseCheckMetadata ?? [];
		const claimCheckPolicy = supervisorClaimCheckPolicy(parallelPlan, planCoverage);
		const strictClaimCheck = strictClaimCheckSnapshot();
		const planCoverageBlocks = [
			...(!parallelPlan ? ["parallel_plan=missing"] : []),
			...(parallelPlan && parallelPlan.workers.length === 0 ? ["parallel_plan_workers=0"] : []),
			...planCoverage.filter((row) =>
				/parallel_plan=missing|status=(?:fail|blocked)|worker_binding=(?!pass(?:$|\s))|\bmissing=[1-9]\d*|\bcoverage_rows=0\b|\bcontract=0\b|orphan_plan_workers=(?!none$)/i.test(
					row,
				),
			),
		];
		const structuredMergeBlocks =
			swarm && swarm.structuredClaimMergeStatus !== "pass"
				? [`structured_claim_merge=${swarm.structuredClaimMergeStatus ?? "missing"}`]
				: [];
		const claimGateBlockers = Array.from(new Set([...planCoverageBlocks, ...structuredMergeBlocks]));
		const claimCheckResult = buildClaimCheckResult(
			releaseCheckMetadata,
			claimCheckPolicy,
			strictClaimCheck,
			claimGateBlockers,
		);
		const claimCheckBlocks = strictClaimCheck.status !== "pass" || claimGateBlockers.length > 0;
		const swarmReviews = swarm?.workers.map((worker) => reviewSwarmWorkerRuntime(worker, swarm, ledger)) ?? [];
		const reviews = [...delegate.packets.map((packet) => reviewDelegatePacket(packet, ledger)), ...swarmReviews];
		const commanderMergeQueue = swarmCommanderMergeQueue(swarm);
		const workerScoreboard = commanderWorkerScoreboard(reviews);
		const commanderMergeBudget = buildCommanderMergeBudget(reviews, commanderMergeQueue, swarm);
		const conflicts = Array.from(
			new Set(
				[
					...delegate.gaps,
					...(swarm?.blocked.map((item) => `swarm blocked: ${item}`) ?? []),
					...(planCoverage.some((row) => /worker_binding=fail|parallel_plan=missing|\bmissing=[1-9]/.test(row))
						? planCoverage.map((row) => `parallel plan coverage: ${row}`)
						: []),
					...(claimGateBlockers.length ? claimGateBlockers.map((row) => `claim gate: ${row}`) : []),
					...(swarm?.mergeDigest.filter((item) => /^collision:/i.test(item)) ?? []),
					...(strictClaimCheck.status !== "pass"
						? claimCheckResult.map((item) => `strict claim check: ${item}`)
						: []),
					...reviews.flatMap((review) => review.conflicts.map((item) => `${review.worker}: ${item}`)),
					delegate.packets.length === 0 ? "no worker packets available" : undefined,
				].filter((item): item is string => Boolean(item)),
			),
		).slice(0, 32);
		const repairQueue = Array.from(
			new Set([
				...reviews
					.filter(
						(review) => review.verdict === "blocked" || review.verdict === "repair" || options.mode === "repair",
					)
					.sort((left, right) => left.priority - right.priority || left.score - right.score)
					.flatMap((review) => review.repairActions.map((action) => `${review.worker}: ${action}`)),
				...commanderMergeQueue.map((action) => `commander: ${action}`),
				...(claimCheckBlocks
					? [
							strictClaimCheck.status === "missing"
								? "claim_check: run re_complete audit to write strict claim release marker"
								: claimGateBlockers.length
									? `claim_check: resolve ${claimGateBlockers.slice(0, 3).join(", ")}`
									: "claim_check: resolve required platform gaps and rerun re_complete audit",
						]
					: []),
			]),
		).slice(0, 24);
		const priorityQueue = reviews
			.slice()
			.sort((left, right) => left.priority - right.priority || left.score - right.score)
			.map((review) => `${review.worker} ${review.verdict} score=${review.score} packet=${review.packetId}`);
		const hasBlocked = reviews.some((review) => review.verdict === "blocked");
		const hasRepair = reviews.some((review) => review.verdict === "repair");
		const hasWatch = reviews.some((review) => review.verdict === "watch");
		const supervisorVerdict: SupervisorVerdict = hasBlocked
			? "blocked"
			: claimCheckBlocks
				? "blocked"
				: hasRepair
					? "repair"
					: hasWatch
						? "watch"
						: "pass";
		const mission = readCurrentMission();
		const checkpoints = mission
			? mission.checkpoints.map(
					(checkpoint) => `${checkpoint.name}:${checkpoint.status}${checkpoint.note ? `:${checkpoint.note}` : ""}`,
				)
			: ["mission:none"];
		const nextActions = Array.from(
			new Set([
				...repairQueue.map((item) => item.replace(/^.+?:\s*/, "")),
				...commanderMergeQueue,
				...(parallelPlan ? [] : ["re_swarm plan"]),
				"re_delegate merge",
				"re_swarm merge",
				"re_operation next",
			]),
		).slice(0, 16);
		return {
			timestamp: nowIso(),
			missionId: delegate.missionId,
			route: delegate.route,
			target: options.target ?? delegate.target,
			mode: options.mode ?? "review",
			delegationArtifact,
			swarmArtifact: latestSwarm?.path,
			supervisorVerdict,
			reviews,
			conflicts,
			repairQueue,
			commanderMergeQueue,
			commanderMergeBudget,
			workerScoreboard,
			priorityQueue,
			checkpoints,
			nextActions,
			parallelPlan,
			planCoverage,
			releaseCheckMetadata,
			claimCheckPolicy,
			strictClaimCheck,
			claimCheckResult,
			sourceArtifacts: Array.from(
				new Set(
					[
						delegationArtifact,
						latestSwarm?.path,
						...delegate.sourceArtifacts,
						...(swarm?.sourceArtifacts ?? []),
					].filter(Boolean) as string[],
				),
			).slice(0, 36),
		};
	}

	function formatSupervisorCompact(supervisor: SupervisorArtifact, path?: string): string {
		const keyReviews = supervisor.reviews
			.slice()
			.sort((left, right) => left.priority - right.priority || left.score - right.score)
			.slice(0, 4)
			.map(
				(review) =>
					`- ${review.worker} [${review.verdict}] score=${review.score} packet=${review.packetId} blocker=${review.conflicts[0] ?? review.evidenceGaps[0] ?? "none"}`,
			);
		const keyBlockers = Array.from(
			new Set([
				...supervisor.conflicts,
				...supervisor.claimCheckResult.filter((row) => /blocker|required_gap|final_publish_ready=no/i.test(row)),
			]),
		).slice(0, 6);
		const nextCommand =
			supervisor.nextActions[0] ?? (supervisor.mode === "repair" ? "re_supervisor review" : "re_supervisor repair");
		return [
			"supervisor_review:",
			path ? `supervisor_artifact: ${path}` : undefined,
			`timestamp: ${supervisor.timestamp}`,
			`mode: ${supervisor.mode}`,
			`supervisor_verdict: ${supervisor.supervisorVerdict}`,
			`mission_id: ${supervisor.missionId ?? "none"}`,
			`route: ${supervisor.route ?? "none"}`,
			`target: ${supervisor.target ?? "<none>"}`,
			`workers: ${supervisor.reviews.length}`,
			`conflicts: ${supervisor.conflicts.length}`,
			`repair_queue_depth: ${supervisor.repairQueue.length}`,
			`strict_claim_status: ${supervisor.strictClaimCheck?.status ?? "missing"}`,
			`strict_claim_gaps: ${supervisor.strictClaimCheck?.requiredGaps.length ?? 0}`,
			"key_reviews:",
			...(keyReviews.length ? keyReviews : ["- none"]),
			"key_blockers:",
			...(keyBlockers.length ? keyBlockers.map((item) => `- ${truncateMiddle(item, 320)}`) : ["- none"]),
			...(supervisor.llmCritique ? ["llm_supervisor_critique:", truncateMiddle(supervisor.llmCritique, 800)] : []),
			`next_supervisor_command: ${nextCommand}`,
			...(path ? [`details: read ${path}`] : []),
		]
			.filter(Boolean)
			.join("\n");
	}

	function formatSupervisor(
		supervisor: SupervisorArtifact,
		path?: string,
		options: { includeDetails?: boolean } = {},
	): string {
		if (!options.includeDetails) return formatSupervisorCompact(supervisor, path);
		return [
			"supervisor_review:",
			path ? `supervisor_artifact: ${path}` : undefined,
			`timestamp: ${supervisor.timestamp}`,
			`mode: ${supervisor.mode}`,
			`supervisor_verdict: ${supervisor.supervisorVerdict}`,
			`mission_id: ${supervisor.missionId ?? "none"}`,
			`route: ${supervisor.route ?? "none"}`,
			`target: ${supervisor.target ?? "<none>"}`,
			`delegation_artifact: ${supervisor.delegationArtifact ?? "none"}`,
			`swarm_artifact: ${supervisor.swarmArtifact ?? "none"}`,
			"worker_reviews:",
			...(supervisor.reviews.length
				? supervisor.reviews.flatMap((review) => [
						`- ${review.worker} [${review.verdict}] score=${review.score} priority=${review.priority} packet=${review.packetId}`,
						`  rationale: ${review.rationale.join(" | ")}`,
						`  conflicts: ${review.conflicts.length ? review.conflicts.join(" | ") : "none"}`,
						`  evidence_gaps: ${review.evidenceGaps.length ? review.evidenceGaps.join(" | ") : "none"}`,
						`  repair_actions: ${review.repairActions.length ? review.repairActions.join(" | ") : "none"}`,
					])
				: ["- none"]),
			"conflict_matrix:",
			...(supervisor.conflicts.length ? supervisor.conflicts.map((item) => `- ${item}`) : ["- none"]),
			"repair_queue:",
			...(supervisor.repairQueue.length ? supervisor.repairQueue.map((item) => `- ${item}`) : ["- none"]),
			"commander_merge_queue:",
			...(supervisor.commanderMergeQueue.length
				? supervisor.commanderMergeQueue.map((item) => `- ${item}`)
				: ["- none"]),
			"commander_merge_budget:",
			...(supervisor.commanderMergeBudget.length
				? supervisor.commanderMergeBudget.map((item) => `- ${item}`)
				: ["- none"]),
			"worker_scoreboard:",
			...(supervisor.workerScoreboard.length ? supervisor.workerScoreboard.map((item) => `- ${item}`) : ["- none"]),
			"priority_queue:",
			...(supervisor.priorityQueue.length ? supervisor.priorityQueue.map((item) => `- ${item}`) : ["- none"]),
			"checkpoints:",
			...(supervisor.checkpoints.length ? supervisor.checkpoints.map((item) => `- ${item}`) : ["- none"]),
			"parallel_plan:",
			...(supervisor.parallelPlan
				? [
						`- plan_id=${supervisor.parallelPlan.planId}`,
						`- source=${supervisor.parallelPlan.source}`,
						`- workers=${supervisor.parallelPlan.workers.length}`,
						`- merge=${supervisor.parallelPlan.merge.strategy}`,
					]
				: ["- none"]),
			"plan_coverage:",
			...(supervisor.planCoverage.length ? supervisor.planCoverage.map((item) => `- ${item}`) : ["- none"]),
			"release_check_metadata:",
			...(supervisor.releaseCheckMetadata.length
				? supervisor.releaseCheckMetadata.map((item) => `- ${item}`)
				: ["- none"]),
			"claim_check_policy:",
			...(supervisor.claimCheckPolicy.length ? supervisor.claimCheckPolicy.map((item) => `- ${item}`) : ["- none"]),
			"strict_claim_check:",
			...formatStrictClaimCheckSnapshot(supervisor.strictClaimCheck),
			"claim_check_result:",
			...(supervisor.claimCheckResult.length ? supervisor.claimCheckResult.map((item) => `- ${item}`) : ["- none"]),
			"operator_next_actions:",
			...(supervisor.nextActions.length ? supervisor.nextActions.map((item) => `- ${item}`) : ["- none"]),
			`next_supervisor_command: ${supervisor.mode === "repair" ? "re_supervisor review" : "re_supervisor repair"}`,
			...(supervisor.llmCritique
				? ["llm_supervisor_critique:", ...supervisor.llmCritique.split("\n").map((line) => `- ${line}`)]
				: []),
			"source_artifacts:",
			...(supervisor.sourceArtifacts.length ? supervisor.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
		]
			.filter(Boolean)
			.join("\n");
	}

	function writeSupervisorArtifact(supervisor: SupervisorArtifact): string {
		ensureReconStorage();
		const path = join(
			evidenceSupervisorsDir(),
			`${supervisor.timestamp.replace(/[:.]/g, "-")}-${slug(supervisor.route ?? "supervisor")}-${supervisor.mode}.md`,
		);
		writePrivateTextFile(
			path,
			[
				"# REPI Supervisor Artifact",
				"",
				formatSupervisor(supervisor, path, { includeDetails: true }),
				"",
				"## Worker reviews",
				"",
				...supervisor.reviews.map(
					(review) =>
						`- ${review.worker} verdict=${review.verdict} score=${review.score} packet=${review.packetId}`,
				),
				"",
				"## JSON",
				"",
				"```json",
				JSON.stringify(supervisor, null, 2),
				"```",
				"",
			].join("\n"),
		);
		appendEvidence({
			kind: "artifact",
			title: `supervisor-${supervisor.mode} ${supervisor.missionId ?? "no-mission"}`,
			fact: `Supervisor verdict ${supervisor.supervisorVerdict} across ${supervisor.reviews.length} worker review(s), ${supervisor.conflicts.length} conflict(s), ${supervisor.repairQueue.length} repair action(s), commander_merge=${supervisor.commanderMergeQueue.length}, commander_budget=${supervisor.commanderMergeBudget.length}, parallel_plan=${supervisor.parallelPlan?.planId ?? "missing"}, release_check_metadata=${supervisor.releaseCheckMetadata.length}, claim_check_policy=${supervisor.claimCheckPolicy.length}, strict_claim_check=${supervisor.strictClaimCheck?.status ?? "missing"}`,
			command: `re_supervisor ${supervisor.mode}`,
			path,
			verify: `cat ${path}`,
			confidence: "delegation/operation supervisor critic",
		});
		updateMissionCheckpoint(
			"supervisor_review_ready",
			supervisor.supervisorVerdict === "pass" ? "done" : "blocked",
			`${path} verdict=${supervisor.supervisorVerdict}`,
		);
		return path;
	}

	function parseSupervisorCritique(mergeText: string): { verdict: string; text: string } {
		const verdictMatch = /supervisor_verdict:\s*([a-z_]+)/i.exec(mergeText);
		const verdict = verdictMatch?.[1]?.toLowerCase() ?? "inconclusive";
		const text = truncateMiddle(mergeText, 8000);
		return { verdict, text };
	}

	async function buildSupervisorLlmCritique(
		supervisor: SupervisorArtifact,
		options: { cwd?: string; target?: string; task?: string; signal?: AbortSignal },
	): Promise<string | undefined> {
		if (!options.cwd || envBoolean("REPI_AGENT_THREAD")) return undefined;
		const timeoutMs = 240000;
		const baseReview = formatSupervisor(supervisor);
		const payload = normalizeWorkerTask(
			[
				"You are the REPI supervisor critic (Reflexion-style adversarial review).",
				"Below is a rule-based supervisor review of specialist worker packets and swarm executions.",
				"Your job is to ADVERSARIALLY critique it: find what the rule score missed.",
				"Identify (a) contradictions or weak evidence that passed as 'done',",
				"(b) worker handoffs that are attempted-as-proved without a real proof-exit (no repro, no counter-evidence check),",
				"(c) the single highest-leverage next action,",
				"(d) any worker whose claim should be re-dispatched to an independent verifier/reverser subagent for falsification.",
				"Default to a stricter verdict than the rule score when evidence is thin.",
				"Output EXACTLY these lines (no prose before/after):",
				"supervisor_verdict: <one of pass|watch|repair|blocked>",
				"critique: <one line, the most important failure the rule score missed>",
				"repair_queue: <comma-separated concrete re_* actions, or none>",
				"redispatch: <spec=verifier|reverser|operator; task=<one short task>> or none",
				"notes: <one line>",
				"",
				"--- rule-based supervisor review ---",
				truncateMiddle(baseReview, 5000),
				...(options.target ? [`target: ${options.target}`] : []),
				...(options.task ? [`task: ${options.task}`] : []),
			].join("\n"),
		);
		const mgr = createAgentThreadManager({ cwd: options.cwd });
		try {
			const started = await mgr.spawnThread({
				specName: "verifier",
				task: payload,
				timeoutMs,
				inheritMcp: false,
				mcpServers: [],
				mcpTools: [],
				signal: options.signal,
				missionId: supervisor.missionId,
			});
			const final = await mgr.awaitRun(started.runId);
			const merge = mgr.mergeRun(started.runId);
			const mergedManifest = merge?.manifest ?? final;
			const resultDetails = repiSubagentResultFromManifest(mergedManifest);
			const validation = await validateRepiSubagentArtifact(resultDetails, {
				missionId: supervisor.missionId,
				spec: "verifier",
				task: payload,
				taskSha256: createHash("sha256").update(payload).digest("hex"),
				requireMcpDisabled: true,
				timeoutMs,
			});
			if (!validation.ok) {
				return `spec=verifier; status=blocked; artifact_validation_failed: ${validation.error}`;
			}
			const mergeText = merge?.text ?? `(no merge output; status=${final.status})`;
			const parsed = parseSupervisorCritique(mergeText);
			return [
				`spec=verifier; runId=${final.runId}; status=${final.status}; supervisor_verdict=${parsed.verdict}`,
				parsed.text,
			].join("\n");
		} catch (error) {
			if (options.signal?.aborted) options.signal.throwIfAborted();
			return `spec=verifier; status=blocked; llm-supervisor: ${truncateMiddle(String((error as Error).message ?? error), 240)}`;
		} finally {
			mgr.dispose("repi_supervisor_critique_complete");
		}
	}

	async function buildSupervisorOutput(
		action: "review" | "show" | "repair" = "review",
		options: SupervisorOutputOptions = {},
	): Promise<string> {
		if (action === "show") {
			const path = latestSupervisorArtifactPath();
			if (!path) return "supervisor_review:\nstatus: missing\nnext: re_supervisor review";
			const supervisor = parseSupervisorArtifact(path);
			return supervisor
				? formatSupervisor(supervisor, path)
				: `supervisor_review:\nstatus: unreadable\nsupervisor_artifact: ${path}\nnext: read ${path}`;
		}
		const supervisor = buildSupervisor({ ...options, mode: action === "repair" ? "repair" : "review" });
		if (options.reasoning === "llm" && !envBoolean("REPI_AGENT_THREAD")) {
			try {
				supervisor.llmCritique = await buildSupervisorLlmCritique(supervisor, {
					cwd: options.cwd,
					target: options.target,
					task: options.task,
					signal: options.signal,
				});
			} catch (error) {
				if (options.signal?.aborted) options.signal.throwIfAborted();
				supervisor.llmCritique = `llm-supervisor: blocked (${truncateMiddle(String((error as Error).message ?? error), 200)})`;
			}
		}
		const path = writeSupervisorArtifact(supervisor);
		return formatSupervisor(supervisor, path);
	}

	return {
		latestSupervisorArtifactPath,
		parseSupervisorArtifact,
		parseDelegateArtifact,
		latestOrBuildDelegate,
		supervisorClaimCheckPolicy,
		supervisorPlanCoverage,
		buildSupervisor,
		formatSupervisor,
		writeSupervisorArtifact,
		parseSupervisorCritique,
		buildSupervisorOutput,
	};
}

export type SwarmCommanderRuntime = ReturnType<typeof createSwarmCommanderRuntime>;
