import { existsSync } from "node:fs";
import { artifactScopeDefaultOptions, artifactTargetMatches } from "./artifact-scope.ts";
import { type MissionState, missionRequiresParallel, readCurrentMission } from "./mission.ts";
import type { CompilerArtifact, ReplayArtifact, VerifierArtifact } from "./proof-artifact-runtime.ts";
import { evidenceLedgerPath, readTextFile } from "./storage.ts";
import type {
	StrictClaimCheckSnapshot,
	StructuredClaimMergeCheckSnapshot,
	SupervisorArtifact,
	SwarmArtifact,
} from "./swarm-runtime-types.ts";

export type CompletionDomainProofExitClosure = {
	domainId?: string;
	status: "passed" | "partial" | "blocked";
	matchedProofExits: string[];
	missingProofExits: string[];
	blockers: string[];
};

export type CompletionAudit<TClosure extends CompletionDomainProofExitClosure = CompletionDomainProofExitClosure> = {
	ready: boolean;
	blockers: string[];
	warnings: string[];
	mission?: MissionState;
	domainProofExitClosure?: TClosure;
};

export type CompletionAuditRuntimeDependencies<TClosure extends CompletionDomainProofExitClosure> = {
	latestSupervisorArtifactPath: () => string | undefined;
	parseSupervisorArtifact: (path: string) => SupervisorArtifact | undefined;
	latestSwarmArtifactPath: () => string | undefined;
	parseSwarmArtifact: (path: string) => SwarmArtifact | undefined;
	latestVerifierArtifactPath: () => string | undefined;
	parseVerifierArtifact: (path: string) => VerifierArtifact | undefined;
	latestCompilerArtifactPath: () => string | undefined;
	parseCompilerArtifact: (path: string) => CompilerArtifact | undefined;
	latestReplayerArtifactPath: () => string | undefined;
	parseReplayArtifact: (path: string) => ReplayArtifact | undefined;
	strictClaimCheckSnapshot: () => StrictClaimCheckSnapshot;
	safeStructuredClaimMergeCheck: (swarm?: SwarmArtifact) => StructuredClaimMergeCheckSnapshot;
	replayClosureBlockers: (replay: ReplayArtifact, compiler: CompilerArtifact, compilerPath?: string) => string[];
	buildDomainProofExitClosure: (mission: MissionState) => TClosure;
	formatDomainProofExitClosure: (closure: TClosure) => string;
	formatMission: (mission: MissionState) => string;
};

function artifactMatchesScope(
	mission: MissionState,
	expectedTarget: string | undefined,
	artifact: { missionId?: string; target?: string } | undefined,
): boolean {
	if (artifact?.missionId !== mission.id) return false;
	if (expectedTarget === undefined) return true;
	return Boolean(artifact.target?.trim() && artifactTargetMatches(expectedTarget, artifact.target));
}

export function createCompletionAuditRuntime<TClosure extends CompletionDomainProofExitClosure>(
	dependencies: CompletionAuditRuntimeDependencies<TClosure>,
) {
	const {
		buildDomainProofExitClosure,
		formatDomainProofExitClosure,
		formatMission,
		latestCompilerArtifactPath,
		latestReplayerArtifactPath,
		latestSupervisorArtifactPath,
		latestSwarmArtifactPath,
		latestVerifierArtifactPath,
		parseCompilerArtifact,
		parseReplayArtifact,
		parseSupervisorArtifact,
		parseSwarmArtifact,
		parseVerifierArtifact,
		replayClosureBlockers,
		safeStructuredClaimMergeCheck,
		strictClaimCheckSnapshot,
	} = dependencies;

	function auditCompletion(): CompletionAudit<TClosure> {
		const mission = readCurrentMission();
		const blockers: string[] = [];
		const warnings: string[] = [];
		if (!mission) {
			blockers.push("no active mission");
			return { ready: false, blockers, warnings };
		}
		const parallelRequired = missionRequiresParallel(mission);
		const expectedTarget = artifactScopeDefaultOptions().target;
		for (const checkpoint of mission.checkpoints) {
			if (checkpoint.status === "pending") blockers.push(`pending check: ${checkpoint.name}`);
			if (checkpoint.status === "blocked")
				blockers.push(`blocked check: ${checkpoint.name}${checkpoint.note ? ` — ${checkpoint.note}` : ""}`);
		}
		const evidence = readTextFile(evidenceLedgerPath()).trim();
		if (!evidence || evidence === "# REPI Evidence Ledger") blockers.push("evidence ledger is empty");
		if (!/(command|verify|path|offset|hash):/i.test(evidence))
			warnings.push("evidence ledger lacks command/path/offset/hash/verify metadata");

		const supervisorPath = parallelRequired ? latestSupervisorArtifactPath() : undefined;
		const candidateSupervisor = supervisorPath ? parseSupervisorArtifact(supervisorPath) : undefined;
		const supervisor =
			parallelRequired &&
			candidateSupervisor &&
			artifactMatchesScope(mission, expectedTarget, candidateSupervisor) &&
			Array.isArray(candidateSupervisor.planCoverage) &&
			Array.isArray(candidateSupervisor.claimCheckPolicy) &&
			Array.isArray(candidateSupervisor.claimCheckResult)
				? candidateSupervisor
				: undefined;
		if (parallelRequired && !supervisor) {
			blockers.push(
				supervisorPath
					? `supervisor artifact is unreadable: ${supervisorPath}`
					: "supervisor review artifact is missing",
			);
		} else if (supervisor) {
			if (supervisor.supervisorVerdict !== "pass") {
				blockers.push(`supervisor verdict blocks final claim: ${supervisor.supervisorVerdict} (${supervisorPath})`);
			}
			for (const row of supervisor.planCoverage
				.filter((item) =>
					/worker_binding=fail|parallel_plan=missing|\bmissing=[1-9]|\bcoverage_rows=0\b|\bcontract=0\b/i.test(
						item,
					),
				)
				.slice(0, 8)) {
				blockers.push(`supervisor plan coverage gap: ${row}`);
			}
			for (const row of supervisor.claimCheckPolicy
				.filter((item) => /worker_binding=(?!pass)|plan_contract_gaps=[1-9]|parallel_plan_id=missing/i.test(item))
				.slice(0, 8)) {
				blockers.push(`supervisor claim checkpoint blocks final claim: ${row}`);
			}
			const supervisorStrict = supervisor.strictClaimCheck ?? strictClaimCheckSnapshot();
			if (supervisorStrict.status !== "pass") {
				blockers.push(
					`supervisor strict claim checkpoint blocks final claim: ${supervisorStrict.status} (${supervisorStrict.markerPath ?? "missing marker"})`,
				);
				for (const gap of supervisorStrict.requiredGaps.slice(0, 8))
					blockers.push(`strict claim required gap: ${gap}`);
			}
			for (const row of supervisor.claimCheckResult
				.filter((item) =>
					/final_publish_ready=no|strict_status=(?:blocked|missing)|required_gaps=[1-9]/i.test(item),
				)
				.slice(0, 8)) {
				blockers.push(`supervisor claim checkpoint result blocks final claim: ${row}`);
			}
		}

		const swarmPath = parallelRequired ? latestSwarmArtifactPath() : undefined;
		const candidateSwarm = swarmPath ? parseSwarmArtifact(swarmPath) : undefined;
		const swarm =
			parallelRequired &&
			candidateSwarm &&
			artifactMatchesScope(mission, expectedTarget, candidateSwarm) &&
			Array.isArray(candidateSwarm.workers) &&
			Array.isArray(candidateSwarm.planCoverage) &&
			Array.isArray(candidateSwarm.executionAudit) &&
			Array.isArray(candidateSwarm.claimLedger) &&
			Array.isArray(candidateSwarm.releaseCheckMetadata)
				? candidateSwarm
				: undefined;
		if (parallelRequired && !swarm) {
			blockers.push(swarmPath ? `swarm artifact is unreadable: ${swarmPath}` : "swarm runtime artifact is missing");
		} else if (swarm) {
			if (
				!swarm.parallelPlan ||
				!Array.isArray(swarm.parallelPlan.workers) ||
				swarm.parallelPlan.workers.length === 0
			)
				blockers.push(`swarm parallel plan is missing or empty: ${swarmPath}`);
			for (const row of swarm.planCoverage
				.filter((item) =>
					/worker_binding=fail|parallel_plan=missing|\bmissing=[1-9]|\bcoverage_rows=0\b|\bcontract=0\b/i.test(
						item,
					),
				)
				.slice(0, 8)) {
				blockers.push(`swarm plan coverage gap: ${row}`);
			}
			for (const row of swarm.executionAudit
				.filter((item) => /status=(?:pending_execution|needs_repair|needs_evidence)/i.test(item))
				.slice(0, 8)) {
				blockers.push(`swarm execution audit gap: ${row}`);
			}
			if (swarm.releaseCheckMetadata.length && !supervisor) {
				blockers.push(`swarm release checkpoint metadata has no supervisor review: ${swarmPath}`);
			}
			for (const row of swarm.releaseCheckMetadata
				.filter((item) =>
					/claim_check_verdict=blocked|release_blocking_gaps=[1-9]|required_platform_gaps=[1-9]|unresolved_frontier_gaps=[1-9]/i.test(
						item,
					),
				)
				.slice(0, 8)) {
				blockers.push(`swarm release checkpoint blocks final claim: ${row}`);
			}
			if (!swarm.runtimeClaimLedgerCaptured)
				blockers.push(`swarm runtime claim ledger is missing or invalid: ${swarmPath}`);
			const structuredClaimMergeCheck = safeStructuredClaimMergeCheck(swarm);
			if (structuredClaimMergeCheck.status !== "pass" || structuredClaimMergeCheck.finalClaimCount === 0) {
				blockers.push(
					`swarm structured claim merge blocks final claim: ${structuredClaimMergeCheck.mergePath ?? swarmPath ?? "missing merge path"}`,
				);
				for (const error of structuredClaimMergeCheck.errors.slice(0, 8))
					blockers.push(`structured claim merge error: ${error}`);
			}
		}
		if (parallelRequired && supervisor && supervisor.swarmArtifact !== swarmPath) {
			blockers.push(
				`supervisor/swarm artifact lineage mismatch: supervisor.swarmArtifact=${supervisor.swarmArtifact ?? "missing"} expected swarm=${swarmPath ?? "missing"}`,
			);
		}

		const strictClaim = strictClaimCheckSnapshot();
		if (strictClaim.status !== "pass") {
			blockers.push(
				`strict claim release marker blocks final claim: ${strictClaim.status} (${strictClaim.markerPath ?? "missing marker"}; run re_complete audit)`,
			);
			for (const gap of strictClaim.requiredGaps.slice(0, 8)) blockers.push(`strict claim release gap: ${gap}`);
		}

		const verifierPath = latestVerifierArtifactPath();
		const candidateVerifier = verifierPath ? parseVerifierArtifact(verifierPath) : undefined;
		const verifier =
			candidateVerifier &&
			artifactMatchesScope(mission, expectedTarget, candidateVerifier) &&
			Array.isArray(candidateVerifier.assertions) &&
			Array.isArray(candidateVerifier.contradictions) &&
			Array.isArray(candidateVerifier.gaps)
				? candidateVerifier
				: undefined;
		if (!verifier) {
			blockers.push(
				verifierPath ? `verifier artifact is unreadable: ${verifierPath}` : "verifier matrix artifact is missing",
			);
		} else {
			if (verifier.assertions.length === 0) blockers.push(`verifier has no assertions: ${verifierPath}`);
			const unresolvedAssertions = verifier.assertions.filter((assertion) => assertion.status !== "proved");
			if (unresolvedAssertions.length > 0)
				blockers.push(`verifier has ${unresolvedAssertions.length} non-proved assertion(s): ${verifierPath}`);
			if (verifier.contradictions.length > 0)
				blockers.push(`verifier has ${verifier.contradictions.length} contradiction(s): ${verifierPath}`);
			if (verifier.gaps.length > 0)
				blockers.push(`verifier has ${verifier.gaps.length} unresolved gap(s): ${verifierPath}`);
		}

		const compilerPath = latestCompilerArtifactPath();
		const candidateCompiler = compilerPath ? parseCompilerArtifact(compilerPath) : undefined;
		const compiler =
			candidateCompiler?.statusSummary &&
			artifactMatchesScope(mission, expectedTarget, candidateCompiler) &&
			typeof candidateCompiler.statusSummary === "object" &&
			Array.isArray(candidateCompiler.claimCheckResult)
				? candidateCompiler
				: undefined;
		if (!compiler) {
			blockers.push(
				compilerPath ? `compiler artifact is unreadable: ${compilerPath}` : "final compiler artifact is missing",
			);
		} else {
			if (compiler.verifierArtifact !== verifierPath) {
				blockers.push(
					`compiler/verifier artifact lineage mismatch: compiler.verifierArtifact=${compiler.verifierArtifact ?? "missing"} expected verifier=${verifierPath ?? "missing"}`,
				);
			}
			if (parallelRequired && compiler.supervisorArtifact !== supervisorPath) {
				blockers.push(
					`compiler/supervisor artifact lineage mismatch: compiler.supervisorArtifact=${compiler.supervisorArtifact ?? "missing"} expected supervisor=${supervisorPath ?? "missing"}`,
				);
			}
			if (compiler.mode !== "final") {
				blockers.push(`latest compiler artifact is not final: ${compilerPath}`);
			} else {
				if (
					compiler.statusSummary.proved === 0 ||
					compiler.statusSummary.weak > 0 ||
					compiler.statusSummary.contradicted > 0 ||
					compiler.statusSummary.missing > 0
				)
					blockers.push(
						`compiler verifier summary is not fully proved: proved=${compiler.statusSummary.proved} weak=${compiler.statusSummary.weak} contradicted=${compiler.statusSummary.contradicted} missing=${compiler.statusSummary.missing} (${compilerPath})`,
					);
				if (parallelRequired && compiler.supervisorVerdict !== "pass")
					blockers.push(
						`compiler supervisor verdict blocks final report: ${compiler.supervisorVerdict ?? "missing"} (${compilerPath})`,
					);
				if (compiler.strictClaimCheck?.status !== "pass") {
					blockers.push(
						`compiler final artifact is not claim-check ready: strict_claim_check=${compiler.strictClaimCheck?.status ?? "missing"} (${compilerPath})`,
					);
				}
				for (const row of compiler.claimCheckResult
					.filter((item) =>
						/final_publish_ready=no|strict_status=(?:blocked|missing)|required_gaps=[1-9]/i.test(item),
					)
					.slice(0, 8)) {
					blockers.push(`compiler claim checkpoint result blocks final report: ${row}`);
				}
				if (
					parallelRequired &&
					(compiler.structuredClaimMergeCheck?.status !== "pass" ||
						(compiler.structuredClaimMergeCheck?.finalClaimCount ?? 0) === 0)
				) {
					blockers.push(
						`compiler structured claim merge blocks final report: ${compiler.structuredClaimMergeCheck?.mergePath ?? "missing merge path"}`,
					);
					for (const error of (compiler.structuredClaimMergeCheck?.errors ?? []).slice(0, 8))
						blockers.push(`compiler structured claim merge error: ${error}`);
				}
				if (!compiler.reportPath || !existsSync(compiler.reportPath))
					blockers.push(`compiler final artifact has no readable release report path: ${compilerPath}`);
			}
		}

		const replayPath = latestReplayerArtifactPath();
		const candidateReplay = replayPath ? parseReplayArtifact(replayPath) : undefined;
		const replay =
			candidateReplay &&
			artifactMatchesScope(mission, expectedTarget, candidateReplay) &&
			Array.isArray(candidateReplay.steps) &&
			Array.isArray(candidateReplay.executions) &&
			Array.isArray(candidateReplay.blocked)
				? candidateReplay
				: undefined;
		if (!replay) {
			blockers.push(
				replayPath ? `replayer artifact is unreadable: ${replayPath}` : "replayer run artifact is missing",
			);
		} else if (!compiler) {
			blockers.push(`replayer cannot bind to a valid final compiler artifact: ${replayPath}`);
		} else {
			for (const blocker of replayClosureBlockers(replay, compiler, compilerPath).slice(0, 20)) {
				blockers.push(`replayer closure blocks final claim: ${blocker} (${replayPath})`);
			}
		}

		const domainProofExitClosure = buildDomainProofExitClosure(mission);
		warnings.push(
			`domain_proof_exit_closure: ${domainProofExitClosure.domainId ?? "unmapped"} status=${domainProofExitClosure.status} matched=${domainProofExitClosure.matchedProofExits.length} missing=${domainProofExitClosure.missingProofExits.length}`,
		);
		if (domainProofExitClosure.status !== "passed") {
			for (const blocker of domainProofExitClosure.blockers.slice(0, 10)) blockers.push(blocker);
		}
		return { ready: blockers.length === 0, blockers, warnings, mission, domainProofExitClosure };
	}

	function formatCompletionAuditFromAudit(audit: CompletionAudit<TClosure>): string {
		return [
			audit.ready ? "completion_status: ready" : "completion_status: blocked",
			audit.mission ? formatMission(audit.mission) : "mission: none",
			audit.domainProofExitClosure
				? formatDomainProofExitClosure(audit.domainProofExitClosure)
				: "domain_proof_exit_closure:\nDomainProofExitClosureV1: false\nstatus: missing",
			"blockers:",
			...(audit.blockers.length ? audit.blockers.map((item) => `- ${item}`) : ["- none"]),
			"warnings:",
			...(audit.warnings.length ? audit.warnings.map((item) => `- ${item}`) : ["- none"]),
			"required_output:",
			"- Outcome / Key Evidence / Verification / Next Step",
			"- evidence block with paths, offsets, hashes, commands, requests, hook points, or state transitions",
			"- reproducible commands or explicit reason why no new command applies",
		].join("\n");
	}

	return {
		auditCompletion,
		formatCompletionAudit: () => formatCompletionAuditFromAudit(auditCompletion()),
		formatCompletionAuditFromAudit,
		runCompletionAudit: auditCompletion,
	};
}
