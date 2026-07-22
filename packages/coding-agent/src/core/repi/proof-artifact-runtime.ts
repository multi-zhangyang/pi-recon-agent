import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { ExtensionAPI } from "../extensions/types.ts";
import type { ArtifactScopeFilterOptions } from "./artifact-scope.ts";
import type { EvidenceRecord } from "./evidence.ts";
import type { MissionCheckpointStatus, MissionState } from "./mission.ts";
import { formatCweTags, formatMitreTag } from "./taxonomy.ts";
import { techniqueById } from "./techniques.ts";
import { compactStoredArtifact, parseJsonCodeFence } from "./text.ts";

/** Status assigned to one verifier assertion. */
export type VerifierStatus = "proved" | "weak" | "contradicted" | "missing";

export type VerifierAssertion = {
	id: string;
	subject: string;
	claim: string;
	status: VerifierStatus;
	confidence: number;
	evidence: string[];
	counterEvidence: string[];
	requiredFollowups: string[];
};

export type VerifierArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	mode: "check" | "matrix";
	operatorArtifact?: string;
	operatorFeedback: string[];
	assertions: VerifierAssertion[];
	contradictions: string[];
	gaps: string[];
	nextActions: string[];
	sourceArtifacts: string[];
};

export type StrictClaimCheckSnapshot = {
	status: "pass" | "blocked" | "missing";
	markerPath?: string;
	generatedAt?: string;
	mode?: string;
	requiredGaps: string[];
	platformRequiredScore?: number;
	orchestrationScore?: number;
	claimCheckResult: string[];
};

export type StructuredClaimMergeCheckSnapshot = {
	status: "pass" | "blocked" | "missing";
	mergePath?: string;
	mergeId?: string;
	finalClaimCount: number;
	blockedClaimCount: number;
	errors: string[];
	policies: string[];
};

export type CompilerArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	mode: "draft" | "final";
	parallelRequired?: boolean;
	verifierArtifact?: string;
	operatorFeedback: string[];
	statusSummary: Record<VerifierStatus, number>;
	outcome: string[];
	keyEvidence: string[];
	reproCommands: string[];
	contradictions: string[];
	gaps: string[];
	nextOperatorQueue: string[];
	finalReport: string[];
	reportPath?: string;
	supervisorArtifact?: string;
	supervisorVerdict?: "pass" | "watch" | "repair" | "blocked";
	releaseCheckMetadata: string[];
	claimCheckPolicy: string[];
	strictClaimCheck?: StrictClaimCheckSnapshot;
	claimCheckResult: string[];
	structuredClaimMergeCheck?: StructuredClaimMergeCheckSnapshot;
	sourceArtifacts: string[];
};

export type ReplayStatus = "ready" | "passed" | "failed" | "blocked" | "skipped";

export type ReplayStep = {
	id: string;
	command: string;
	status: ReplayStatus;
	reason?: string;
	sourceArtifacts: string[];
};

export type ReplayExecution = {
	stepId: string;
	command: string;
	status: ReplayStatus;
	exit: number;
	killed?: boolean;
	stdoutHash: string;
	stderrHash: string;
	stdoutHead: string;
	stderrHead: string;
};

export type ReplayArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	mode: "plan" | "run";
	compilerArtifact?: string;
	compilerSha256?: string;
	operatorFeedback: string[];
	steps: ReplayStep[];
	executions: ReplayExecution[];
	replayMatrix: string[];
	passed: number;
	failed: number;
	blocked: string[];
	nextActions: string[];
	sourceArtifacts: string[];
};

/**
 * A zero-exit process is not proof by itself.  Require either captured output
 * or a concrete existing artifact referenced by the replay command.  This
 * keeps `true`, empty shell wrappers, and other no-op commands from closing
 * `replay_ready` while still allowing outputless checks such as `test -f`.
 */
export function replayExecutionHasProofSignal(execution: ReplayExecution, step: ReplayStep): boolean {
	if ([execution.stdoutHead, execution.stderrHead].some((value) => typeof value === "string" && value.trim())) {
		return true;
	}
	const command = execution.command.trim();
	if (!command) return false;
	const sourceArtifacts = Array.isArray(step.sourceArtifacts) ? step.sourceArtifacts : [];
	return sourceArtifacts.some((path) => {
		if (!path || !existsSync(path)) return false;
		const quotedSingle = `'${path.replace(/'/g, "'\\''")}'`;
		const quotedDouble = JSON.stringify(path);
		return command.includes(path) || command.includes(quotedSingle) || command.includes(quotedDouble);
	});
}

/** Minimal operation shape consumed by the verifier. */
export type ProofOperationExecution = {
	stepId: string;
	command: string;
	status: "ready" | "done" | "blocked" | "skipped";
	output: string;
};

/** Minimal operator shape. Extra host fields are intentionally ignored. */
export type ProofOperatorArtifact = {
	missionId?: string;
	route?: string;
	target?: string;
	executed: ProofOperationExecution[];
	operatorFeedback?: string[];
	sourceArtifacts: string[];
};

export type ProofCompilerClaimCheckInputs = {
	parallelRequired: boolean;
	supervisorPath?: string;
	supervisorVerdict?: "pass" | "watch" | "repair" | "blocked";
	swarmPath?: string;
	releaseCheckMetadata: string[];
	claimCheckPolicy: string[];
	strictClaimCheck: StrictClaimCheckSnapshot;
	claimCheckResult: string[];
	structuredClaimMergeCheck: StructuredClaimMergeCheckSnapshot;
};

export type ProofExecResult = {
	code: number;
	killed?: boolean;
	stdout: string;
	stderr: string;
};

type EvidenceInput = Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number };

export type ProofArtifactRuntimeDependencies<TOperator extends ProofOperatorArtifact = ProofOperatorArtifact> = {
	// Storage boundary.
	ensureReconStorage: () => void;
	readText: (path: string, fallback?: string) => string;
	writePrivateTextFile: (path: string, content: string) => void;
	evidenceVerifiersDir: () => string;
	evidenceCompilersDir: () => string;
	evidenceReplayersDir: () => string;
	evidenceLedgerPath: () => string;
	reportDir: () => string;
	latestScopedMarkdownArtifact: (
		kind: string,
		dir: string,
		options?: ArtifactScopeFilterOptions,
	) => string | undefined;

	// Mission/evidence boundary.
	readCurrentMission: () => MissionState | undefined;
	appendEvidence: (record: EvidenceInput) => unknown;
	updateMissionCheckpoint: (name: string, status: MissionCheckpointStatus, note?: string) => unknown;

	// Operator boundary. The generic keeps host-specific operator fields out of this module.
	latestOrBuildOperator: (options: { target?: string }) => { operator: TOperator; path: string };
	classifyOperatorFeedback: (operator: TOperator, operatorArtifact?: string, target?: string) => string[];
	operatorFeedbackNextCommands: (feedback: string[]) => string[];

	// Supervisor/claim-check boundary. The host can either expose the existing aggregate
	// resolver or replace it with an equivalent implementation.
	latestCompilerClaimCheckInputs: (options: { target?: string }) => ProofCompilerClaimCheckInputs;
	formatStrictClaimCheckSnapshot: (snapshot?: StrictClaimCheckSnapshot) => string[];
	prepareClaimReleaseMarker: () => string;

	// Target/text boundary.
	artifactTargetMatches: (requested?: string, actual?: string) => boolean;
	commandContainsPoison: (command: string) => boolean;
	shellQuote: (value: string) => string;
	slug: (value: string) => string;
	truncateMiddle: (value: string, limit: number) => string;

	// Host execution and runtime-repair hooks.
	exec: (pi: ExtensionAPI, command: string, args: string[], options: { timeout: number }) => Promise<ProofExecResult>;
	appendRuntimeFailureRepairFromReplay: (replay: ReplayArtifact, path: string) => void;
};

function parseJsonBlock<T>(readText: (path: string, fallback?: string) => string, path: string): T | undefined {
	return parseJsonCodeFence<T>(readText(path));
}

export function createProofArtifactRuntime<TOperator extends ProofOperatorArtifact = ProofOperatorArtifact>(
	dependencies: ProofArtifactRuntimeDependencies<TOperator>,
) {
	const {
		ensureReconStorage,
		readText,
		writePrivateTextFile,
		evidenceVerifiersDir,
		evidenceCompilersDir,
		evidenceReplayersDir,
		evidenceLedgerPath,
		reportDir,
		latestScopedMarkdownArtifact,
		readCurrentMission,
		appendEvidence,
		updateMissionCheckpoint,
		latestOrBuildOperator,
		classifyOperatorFeedback,
		operatorFeedbackNextCommands,
		latestCompilerClaimCheckInputs,
		formatStrictClaimCheckSnapshot,
		prepareClaimReleaseMarker,
		artifactTargetMatches,
		commandContainsPoison,
		shellQuote,
		slug,
		truncateMiddle,
		exec,
		appendRuntimeFailureRepairFromReplay,
	} = dependencies;
	const requestedTargetMatches = (requested?: string, actual?: string): boolean =>
		requested === undefined || Boolean(actual?.trim() && artifactTargetMatches(requested, actual));

	function latestVerifierArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		return latestScopedMarkdownArtifact("verifier", evidenceVerifiersDir(), options);
	}

	function verifierInterestingEvidence(output: string, fallback: string): string[] {
		const lines = output
			.split(/\r?\n/)
			.map((line) => line.trim())
			.filter(Boolean)
			.filter((line) =>
				/artifact|path:|verify:|hash:|offset:|mission_id|evidence_|ledger|status:|checkpoint|proof|anchor|exit=|code=|operator_queue|reflection_cycle|context_pack|supervisor_review/i.test(
					line,
				),
			)
			.slice(0, 12);
		return lines.length ? lines.map((line) => truncateMiddle(line, 260)) : [fallback];
	}

	function verifierCounterEvidence(text: string): string[] {
		return text
			.split(/\r?\n/)
			.map((line) => line.trim())
			.filter((line) =>
				/blocked|pending checkpoint|missing|unsupported|unresolved|error|failed|cannot|not found|weak|contradict/i.test(
					line,
				),
			)
			.slice(0, 12)
			.map((line) => truncateMiddle(line, 260));
	}

	function verifierProofSignals(text: string): string[] {
		const signals = new Set<string>();
		for (const line of text.split(/\r?\n/).map((row) => row.trim())) {
			if (!line) continue;
			if (/\b(?:exit(?:_code)?|code)\s*[=:]\s*0\b/i.test(line)) signals.add("zero_exit");
			if (
				/\b(?:sha256|stdout_hash|stderr_hash|stdout_sha256|stderr_sha256|hash)\s*[=:]\s*[a-f0-9]{64}\b/i.test(line)
			)
				signals.add("content_hash");
			if (/\b(?:verify|replay_command|repro_command)\s*:\s*\S+/i.test(line)) signals.add("verification_command");
			if (/\b(?:offset|runtime_anchor|traffic_anchor|proof_anchor)\s*[=:]\s*\S+/i.test(line))
				signals.add("observation_anchor");
			if (/\b(?:artifact|artifact_path|evidence_artifact|path)\s*:\s*\S+/i.test(line))
				signals.add("artifact_reference");
			if (/\b(?:status|verdict)\s*[=:]\s*(?:pass|passed|proved|ready)\b/i.test(line))
				signals.add("positive_verdict");
		}
		return [...signals];
	}

	function checkpointEvidenceBinding(note?: string): { backed: boolean; evidence: string[] } {
		const value = note?.trim();
		if (!value) return { backed: false, evidence: [] };
		const candidates = Array.from(
			new Set(
				[value, ...value.split(/\s+/)]
					.map((item) => item.replace(/^(?:path|artifact)=/i, "").replace(/^[`'"(]+|[`'"),;]+$/g, ""))
					.filter(Boolean),
			),
		);
		const path = candidates.find((candidate) => existsSync(candidate));
		if (path) return { backed: true, evidence: [`path: ${path}`, `verify: test -e ${shellQuote(path)}`] };
		const signals = verifierProofSignals(value);
		return {
			backed: false,
			evidence: [`note: ${truncateMiddle(value, 260)}`, ...signals.map((signal) => `proof_signal: ${signal}`)],
		};
	}

	function verifierStatusFromExecution(execution: ProofOperationExecution): VerifierStatus {
		const counter = verifierCounterEvidence(execution.output);
		if (execution.status === "blocked") return counter.length ? "contradicted" : "missing";
		if (execution.status !== "done") return "missing";
		if (counter.some((line) => /unsupported|unresolved|error|failed|cannot|not found/i.test(line)))
			return "contradicted";
		const signals = verifierProofSignals(execution.output);
		const hasRuntimeResult = signals.includes("zero_exit") && signals.includes("content_hash");
		const hasObservation = signals.includes("artifact_reference") || signals.includes("observation_anchor");
		if (hasRuntimeResult && hasObservation) return "proved";
		return "weak";
	}

	function verifierConfidence(status: VerifierStatus): number {
		switch (status) {
			case "proved":
				return 85;
			case "weak":
				return 55;
			case "missing":
				return 25;
			case "contradicted":
				return 10;
		}
	}

	function executionAssertion(
		execution: ProofOperationExecution,
		index: number,
		operatorPath: string,
	): VerifierAssertion {
		const status = verifierStatusFromExecution(execution);
		const evidence = verifierInterestingEvidence(execution.output, `operator_execution: ${execution.command}`).slice(
			0,
			10,
		);
		const counterEvidence = verifierCounterEvidence(execution.output);
		return {
			id: `exec:${index + 1}:${slug(execution.command).slice(0, 24)}`,
			subject: execution.command,
			claim: `operator step ${execution.stepId} completed with status=${execution.status}`,
			status,
			confidence: verifierConfidence(status),
			evidence: [`operator_artifact: ${operatorPath}`, ...evidence],
			counterEvidence,
			requiredFollowups:
				status === "proved"
					? ["re_verifier matrix"]
					: [
							"re_operator escalate",
							`re_operator dispatch <target> 1 # retry ${execution.stepId}`,
							"re_verifier check",
						],
		};
	}

	function checkAssertions(): VerifierAssertion[] {
		const mission = readCurrentMission();
		if (!mission) {
			return [
				{
					id: "check:no-mission",
					subject: "mission blackboard",
					claim: "active mission exists for verification",
					status: "missing",
					confidence: 15,
					evidence: [],
					counterEvidence: ["no active mission"],
					requiredFollowups: ["re_mission new <task>", "re_operator plan"],
				},
			];
		}
		return mission.checkpoints.map((checkpoint, index) => {
			const binding = checkpointEvidenceBinding(checkpoint.note);
			const status: VerifierStatus =
				checkpoint.status === "blocked"
					? "contradicted"
					: checkpoint.status !== "done"
						? "missing"
						: binding.backed
							? "proved"
							: "weak";
			return {
				id: `check:${index + 1}:${checkpoint.name}`,
				subject: `check:${checkpoint.name}`,
				claim: `mission checkpoint ${checkpoint.name} is ${checkpoint.status}`,
				status,
				confidence: status === "proved" ? 85 : status === "weak" ? 50 : status === "contradicted" ? 20 : 35,
				evidence: binding.evidence,
				counterEvidence:
					status === "proved"
						? []
						: status === "weak"
							? ["checkpoint is marked done but has no inspectable evidence binding"]
							: [`checkpoint status=${checkpoint.status}`],
				requiredFollowups:
					status === "proved"
						? []
						: checkpoint.name === "profile_check_ready"
							? ["re_profile_check full", "re_autofix plan profile_check_ready", "re_verifier matrix"]
							: [`close check with artifact/verify binding: ${checkpoint.name}`, "re_operator escalate"],
			};
		});
	}

	function artifactAssertions(operator: ProofOperatorArtifact): VerifierAssertion[] {
		return operator.sourceArtifacts.slice(0, 24).map((artifact, index) => {
			const present = existsSync(artifact);
			return {
				id: `artifact:${index + 1}:${slug(artifact).slice(0, 24)}`,
				subject: artifact,
				claim: "source artifact exists and can be inspected",
				status: present ? "proved" : "contradicted",
				confidence: present ? 90 : 10,
				evidence: present ? [`path: ${artifact}`, `verify: test -f ${shellQuote(artifact)}`] : [],
				counterEvidence: present ? [] : [`missing artifact: ${artifact}`],
				requiredFollowups: present ? ["re_verifier matrix"] : ["re_evidence show", "re_operator plan"],
			};
		});
	}

	function buildVerifier(options: { target?: string; mode?: "check" | "matrix" } = {}): VerifierArtifact {
		ensureReconStorage();
		const { operator, path: operatorArtifact } = latestOrBuildOperator(options);
		const operatorFeedback = classifyOperatorFeedback(operator, operatorArtifact, options.target);
		const executionAssertions = operator.executed.map((execution, index) =>
			executionAssertion(execution, index, operatorArtifact),
		);
		const assertions = [...executionAssertions, ...checkAssertions(), ...artifactAssertions(operator)];
		if (executionAssertions.length === 0) {
			assertions.unshift({
				id: "exec:none",
				subject: "operator executions",
				claim: "at least one operator dispatch execution exists",
				status: "missing",
				confidence: 20,
				evidence: [`operator_artifact: ${operatorArtifact}`],
				counterEvidence: ["operator.executed is empty"],
				requiredFollowups: ["re_operator dispatch <target> 1", "re_verifier check"],
			});
		}
		const contradictions = assertions
			.filter((assertion) => assertion.status === "contradicted")
			.map((assertion) => `${assertion.id}: ${assertion.counterEvidence.join(" | ") || assertion.claim}`);
		const gaps = assertions
			.filter((assertion) => assertion.status === "missing" || assertion.status === "weak")
			.map((assertion) => `${assertion.id}: ${assertion.claim}`);
		const nextActions = Array.from(
			new Set([
				...operatorFeedbackNextCommands(operatorFeedback),
				...(contradictions.length ? ["re_operator escalate"] : []),
				...(gaps.length ? ["re_operator dispatch <target> 1", "re_verifier check"] : []),
				...(assertions.length > 0 &&
				contradictions.length === 0 &&
				gaps.length === 0 &&
				assertions.every((item) => item.status === "proved")
					? ["re_compiler final"]
					: []),
			]),
		).slice(0, 12);
		return {
			timestamp: new Date().toISOString(),
			missionId: operator.missionId,
			route: operator.route,
			target: options.target ?? operator.target,
			mode: options.mode ?? "check",
			operatorArtifact,
			operatorFeedback,
			assertions,
			contradictions,
			gaps,
			nextActions,
			sourceArtifacts: Array.from(new Set([operatorArtifact, ...operator.sourceArtifacts])).slice(0, 36),
		};
	}

	function formatVerifier(verifier: VerifierArtifact, path?: string): string {
		return [
			"verifier_matrix:",
			path ? `verifier_artifact: ${path}` : undefined,
			`timestamp: ${verifier.timestamp}`,
			`mode: ${verifier.mode}`,
			`mission_id: ${verifier.missionId ?? "none"}`,
			`route: ${verifier.route ?? "none"}`,
			`target: ${verifier.target ?? "<none>"}`,
			`operator_artifact: ${verifier.operatorArtifact ?? "none"}`,
			"operator_feedback:",
			...((verifier.operatorFeedback ?? []).length
				? (verifier.operatorFeedback ?? []).map((item) => `- ${item}`)
				: ["- none"]),
			"assertions:",
			...(verifier.assertions.length
				? verifier.assertions.map(
						(assertion) =>
							`- ${assertion.id} [${assertion.status}] confidence=${assertion.confidence} subject=${assertion.subject} claim=${assertion.claim}`,
					)
				: ["- none"]),
			"evidence_bindings:",
			...(verifier.assertions.length
				? verifier.assertions.flatMap((assertion) =>
						assertion.evidence.length
							? assertion.evidence.slice(0, 4).map((item) => `- ${assertion.id}: ${item}`)
							: [`- ${assertion.id}: none`],
					)
				: ["- none"]),
			"counter_evidence:",
			...(verifier.assertions.some((assertion) => assertion.counterEvidence.length)
				? verifier.assertions.flatMap((assertion) =>
						assertion.counterEvidence.map((item) => `- ${assertion.id}: ${item}`),
					)
				: ["- none"]),
			"contradictions:",
			...(verifier.contradictions.length ? verifier.contradictions.map((item) => `- ${item}`) : ["- none"]),
			"gaps:",
			...(verifier.gaps.length ? verifier.gaps.map((item) => `- ${item}`) : ["- none"]),
			"operator_next_actions:",
			...(verifier.nextActions.length ? verifier.nextActions.map((item) => `- ${item}`) : ["- re_verifier matrix"]),
			`next_verifier_command: ${verifier.mode === "matrix" && verifier.assertions.length > 0 && verifier.gaps.length === 0 && verifier.contradictions.length === 0 && verifier.assertions.every((item) => item.status === "proved") ? "re_compiler final" : "re_verifier matrix"}`,
			"source_artifacts:",
			...(verifier.sourceArtifacts.length ? verifier.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
		]
			.filter(Boolean)
			.join("\n");
	}

	function writeVerifierArtifact(verifier: VerifierArtifact): string {
		ensureReconStorage();
		const path = join(
			evidenceVerifiersDir(),
			`${verifier.timestamp.replace(/[:.]/g, "-")}-${slug(verifier.route ?? "verifier")}-${verifier.mode}.md`,
		);
		writePrivateTextFile(
			path,
			[
				"# REPI Verifier Artifact",
				"",
				formatVerifier(verifier, path),
				"",
				"## JSON",
				"",
				"```json",
				JSON.stringify(verifier, null, 2),
				"```",
				"",
			].join("\n"),
		);
		appendEvidence({
			kind: "artifact",
			title: `verifier-${verifier.mode} ${verifier.missionId ?? "no-mission"}`,
			fact: `Verifier matrix ${verifier.mode}: ${verifier.assertions.length} assertion(s), ${verifier.contradictions.length} contradiction(s), ${verifier.gaps.length} gap(s), operator_feedback=${(verifier.operatorFeedback ?? []).length}`,
			command: `re_verifier ${verifier.mode}`,
			path,
			verify: `cat ${path}`,
			confidence: "operator/evidence assertion verifier",
		});
		updateMissionCheckpoint("verifier_matrix_ready", "done", path);
		return path;
	}

	function verifierTechniqueProofContract(techniqueId?: string): string {
		if (!techniqueId) return "";
		const technique = techniqueById(techniqueId);
		if (!technique) {
			return `technique_proof_contract:\nstatus: unknown technique id '${techniqueId}'\nhint: call re_techniques(format=index) to enumerate ids`;
		}
		const tags = [
			technique.mitre ? technique.mitre.map(formatMitreTag).join(", ") : null,
			technique.cwe ? formatCweTags(technique.cwe) : null,
		]
			.filter(Boolean)
			.join(" | ");
		const counterProbes = technique.pitfalls.map((pitfall, index) => `  ${index + 1}. [falsify] ${pitfall}`);
		return [
			"technique_proof_contract:",
			`id: ${technique.id}`,
			`domain: ${technique.domain}`,
			tags ? `taxonomy: ${tags}` : null,
			`assertion: ${technique.proofExit}`,
			"counter_evidence_probes (each must be actively attempted to refute the claim):",
			...counterProbes,
			`expected_tool_surface: ${technique.tools.join(", ")}`,
			"verifier_rule: mark 'proved' ONLY if the captured observation satisfies the assertion above AND every counter_evidence_probe was attempted and failed to refute it; otherwise mark 'weak'/'contradicted'/'missing'.",
			`source: re_techniques(id=${technique.id})`,
		]
			.filter((line): line is string => line !== null)
			.join("\n");
	}

	function buildVerifierOutput(
		action: "check" | "show" | "matrix" = "check",
		options: { target?: string; techniqueId?: string } = {},
	): string {
		if (action === "show") {
			const path = latestVerifierArtifactPath();
			if (!path) return "verifier_matrix:\nstatus: missing\nnext: re_verifier check";
			return compactStoredArtifact("verifier_matrix", path, readText(path));
		}
		const verifier = buildVerifier({ target: options.target, mode: action === "matrix" ? "matrix" : "check" });
		const path = writeVerifierArtifact(verifier);
		const base = formatVerifier(verifier, path);
		const contract = verifierTechniqueProofContract(options.techniqueId);
		return contract ? `${base}\n\n${contract}` : base;
	}

	function parseVerifierArtifact(path: string): VerifierArtifact | undefined {
		return parseJsonBlock<VerifierArtifact>(readText, path);
	}

	function latestOrBuildVerifier(options: { target?: string } = {}): { verifier: VerifierArtifact; path: string } {
		const latest = latestVerifierArtifactPath(
			options.target ? { target: options.target, requestedBy: "latest_or_build_verifier" } : {},
		);
		if (latest) {
			const verifier = parseVerifierArtifact(latest);
			const missionId = readCurrentMission()?.id;
			if (
				verifier &&
				missionId &&
				verifier.missionId === missionId &&
				requestedTargetMatches(options.target, verifier.target)
			)
				return { verifier, path: latest };
		}
		const verifier = buildVerifier({ target: options.target, mode: "matrix" });
		const path = writeVerifierArtifact(verifier);
		return { verifier, path };
	}

	function compilerStatusSummary(assertions: VerifierAssertion[]): Record<VerifierStatus, number> {
		return assertions.reduce<Record<VerifierStatus, number>>(
			(summary, assertion) => {
				summary[assertion.status] += 1;
				return summary;
			},
			{ proved: 0, weak: 0, contradicted: 0, missing: 0 },
		);
	}

	function compilerKeyEvidence(verifier: VerifierArtifact): string[] {
		const proved = verifier.assertions.filter((assertion) => assertion.status === "proved");
		const lines = proved.flatMap((assertion) => [
			`${assertion.id}: ${assertion.claim}`,
			...assertion.evidence.slice(0, 3).map((item) => `  evidence: ${item}`),
		]);
		const feedbackEvidence = (verifier.operatorFeedback ?? [])
			.filter((row) => /category=(strong_evidence|replay_or_exploit_candidate|worker_retry_progress)/i.test(row))
			.map((row) => `operator_feedback: ${row}`);
		if (lines.length || feedbackEvidence.length)
			return Array.from(new Set([...lines, ...feedbackEvidence])).slice(0, 36);
		return Array.from(
			new Set([
				`verifier_artifact: ${verifier.sourceArtifacts[0] ?? "none"}`,
				...verifier.sourceArtifacts.slice(0, 8).map((artifact) => `source_artifact: ${artifact}`),
			]),
		);
	}

	function compilerReproCommands(verifier: VerifierArtifact, verifierPath: string): string[] {
		const ledgerCommands = Array.from(readText(evidenceLedgerPath()).matchAll(/- command: `([^`]+)`/g))
			.map((match) => match[1]?.replace(/\\`/g, "`").trim())
			.filter((command): command is string => Boolean(command));
		const verifyCommands = verifier.assertions
			.flatMap((assertion) => assertion.evidence)
			.map((item) => /^verify:\s*(.+)$/i.exec(item)?.[1]?.trim())
			.filter((command): command is string => Boolean(command));
		return Array.from(
			new Set([
				...ledgerCommands.slice(-12),
				...verifyCommands.slice(0, 8),
				...operatorFeedbackNextCommands(verifier.operatorFeedback ?? []).slice(0, 6),
				`cat ${shellQuote(verifierPath)}`,
				...verifier.sourceArtifacts
					.slice(0, 5)
					.map((artifact) => `test -f ${shellQuote(artifact)} && cat ${shellQuote(artifact)}`),
			]),
		).slice(0, 24);
	}

	function compilerContradictions(verifier: VerifierArtifact): string[] {
		const contradictionAssertions = verifier.assertions
			.filter((assertion) => assertion.status === "contradicted")
			.map((assertion) => `${assertion.id}: ${assertion.counterEvidence.join(" | ") || assertion.claim}`);
		return Array.from(new Set([...verifier.contradictions, ...contradictionAssertions])).slice(0, 24);
	}

	function compilerGaps(verifier: VerifierArtifact): string[] {
		const gapAssertions = verifier.assertions
			.filter((assertion) => assertion.status === "missing" || assertion.status === "weak")
			.map((assertion) => `${assertion.id} [${assertion.status}]: ${assertion.claim}`);
		const feedbackGaps = (verifier.operatorFeedback ?? [])
			.filter((row) =>
				/category=(unresolved_target|dispatcher_gap|missing_tool_or_dependency|runtime_failure|failure_budget_exhausted|worker_retry_blocked|swarm_retry_queue)/i.test(
					row,
				),
			)
			.map((row) => `operator_feedback: ${row}`);
		return Array.from(new Set([...verifier.gaps, ...gapAssertions, ...feedbackGaps])).slice(0, 36);
	}

	function compilerNextOperatorQueue(verifier: VerifierArtifact): string[] {
		const needsRepair = verifier.assertions.some(
			(assertion) =>
				assertion.status === "missing" || assertion.status === "weak" || assertion.status === "contradicted",
		);
		const repair = verifier.assertions
			.filter((assertion) => assertion.status !== "proved")
			.flatMap((assertion) => assertion.requiredFollowups);
		return Array.from(
			new Set([
				...operatorFeedbackNextCommands(verifier.operatorFeedback ?? []),
				...(needsRepair ? ["re_operator escalate"] : []),
				...repair,
				...verifier.nextActions,
				needsRepair ? "re_verifier check" : "re_compiler final",
			]),
		).slice(0, 18);
	}

	function compilerOutcome(verifier: VerifierArtifact, summary: Record<VerifierStatus, number>): string[] {
		const total = verifier.assertions.length;
		if (summary.contradicted > 0)
			return [
				`status=blocked_by_contradiction proved=${summary.proved}/${total} contradicted=${summary.contradicted}`,
				"claim boundary: contradictions must be repaired before final success claims.",
			];
		if (summary.missing > 0 || summary.weak > 0)
			return [
				`status=partial proved=${summary.proved}/${total} weak=${summary.weak} missing=${summary.missing}`,
				"claim boundary: report only proved assertions and keep weak/missing items in next_operator_queue.",
			];
		return [
			`status=ready proved=${summary.proved}/${total}`,
			"claim boundary: verifier found no weak, missing, or contradicted assertion.",
		];
	}

	function compilerClaimCheckReady(compiler: CompilerArtifact): boolean {
		const summary = compiler.statusSummary;
		const parallelReady =
			compiler.parallelRequired === false ||
			(Boolean(compiler.supervisorArtifact) &&
				compiler.supervisorVerdict === "pass" &&
				compiler.structuredClaimMergeCheck?.status === "pass");
		return (
			compiler.mode === "final" &&
			summary.proved > 0 &&
			summary.weak === 0 &&
			summary.contradicted === 0 &&
			summary.missing === 0 &&
			compiler.strictClaimCheck?.status === "pass" &&
			parallelReady &&
			!compiler.claimCheckResult.some((row) =>
				/claim_check\.final_publish_ready=no|claim_check\.blocker=/i.test(row),
			)
		);
	}

	function compilerPublishBlockers(compiler: CompilerArtifact): string[] {
		const blockers: string[] = [];
		const summary = compiler.statusSummary;
		if (compiler.mode !== "final") blockers.push("compiler_mode_not_final");
		if (summary.proved === 0) blockers.push("verifier_no_proved_assertions");
		if (summary.weak > 0 || summary.contradicted > 0 || summary.missing > 0)
			blockers.push("verifier_assertions_not_all_proved");
		if (compiler.strictClaimCheck?.status !== "pass")
			blockers.push(`strict_claim_check=${compiler.strictClaimCheck?.status ?? "missing"}`);
		if (compiler.parallelRequired !== false) {
			if (!compiler.supervisorArtifact) blockers.push("supervisor_review_missing");
			else if (compiler.supervisorVerdict !== "pass")
				blockers.push(`supervisor_verdict=${compiler.supervisorVerdict ?? "missing"}`);
			if (compiler.structuredClaimMergeCheck?.status !== "pass")
				blockers.push(`structured_claim_merge=${compiler.structuredClaimMergeCheck?.status ?? "missing"}`);
		}
		blockers.push(
			...compiler.claimCheckResult
				.filter((row) => /^claim_check\.blocker=|^claim_check\.final_publish_ready=no$/i.test(row))
				.map((row) => row.replace(/^claim_check\.(?:blocker|final_publish_ready)=/i, "")),
		);
		return Array.from(new Set(blockers));
	}

	function compilerClaimCheckResult(compiler: CompilerArtifact): string[] {
		const ready = compilerClaimCheckReady(compiler);
		const blockers = compilerPublishBlockers(compiler).filter((item) => item !== "compiler_mode_not_final");
		return Array.from(
			new Set([
				...compiler.claimCheckResult.filter((row) => !/^claim_check\.final_publish_ready=/i.test(row)),
				`claim_check.final_publish_ready=${ready ? "yes" : "no"}`,
				...(ready ? [] : blockers.slice(0, 16).map((blocker) => `claim_check.blocker=${blocker}`)),
			]),
		);
	}

	function compilerReportLines(compiler: CompilerArtifact): string[] {
		const bullet = (items: string[]) => (items.length ? items.map((item) => `- ${item}`) : ["- none"]);
		return [
			"# REPI Compiled Report",
			"",
			"## Outcome",
			"",
			...bullet(compiler.outcome),
			"",
			"## Key Evidence",
			"",
			...bullet(compiler.keyEvidence),
			"",
			"## Verification",
			"",
			`- verifier_artifact: ${compiler.verifierArtifact ?? "none"}`,
			`- supervisor_artifact: ${compiler.supervisorArtifact ?? "none"}`,
			`- supervisor_verdict: ${compiler.supervisorVerdict ?? "missing"}`,
			`- status_summary: proved=${compiler.statusSummary.proved} weak=${compiler.statusSummary.weak} contradicted=${compiler.statusSummary.contradicted} missing=${compiler.statusSummary.missing}`,
			`- strict_claim_check: ${compiler.strictClaimCheck?.status ?? "missing"}`,
			`- claim_release_marker: ${compiler.strictClaimCheck?.markerPath ?? "missing"}`,
			`- claim_check_final_publish_ready: ${compilerClaimCheckReady(compiler) ? "yes" : "no"}`,
			"",
			"## Claim Check",
			"",
			"### Release Check Metadata",
			...bullet(compiler.releaseCheckMetadata),
			"",
			"### Supervisor Claim Check Policy",
			...bullet(compiler.claimCheckPolicy),
			"",
			"### Strict Claim Check",
			...formatStrictClaimCheckSnapshot(compiler.strictClaimCheck),
			"",
			"### Claim Check Result",
			...bullet(compiler.claimCheckResult),
			"",
			"### Structured Claim Merge Check",
			`- structured_claim_merge_status: ${compiler.structuredClaimMergeCheck?.status ?? "missing"}`,
			`- structured_claim_merge_path: ${compiler.structuredClaimMergeCheck?.mergePath ?? "missing"}`,
			`- final_claims: ${compiler.structuredClaimMergeCheck?.finalClaimCount ?? 0}`,
			`- blocked_claims: ${compiler.structuredClaimMergeCheck?.blockedClaimCount ?? 0}`,
			...bullet(compiler.structuredClaimMergeCheck?.errors ?? []),
			"",
			"## Operator Feedback",
			"",
			...bullet(compiler.operatorFeedback ?? []),
			"",
			"## Repro Commands",
			"",
			"```bash",
			...(compiler.reproCommands.length ? compiler.reproCommands : ["# no repro commands captured yet"]),
			"```",
			"",
			"## Contradictions",
			"",
			...bullet(compiler.contradictions),
			"",
			"## Gaps",
			"",
			...bullet(compiler.gaps),
			"",
			"## Next Step",
			"",
			...bullet(compiler.nextOperatorQueue),
			"",
		];
	}

	function writeCompiledReport(compiler: CompilerArtifact): string {
		ensureReconStorage();
		if (!compilerClaimCheckReady(compiler)) return "";
		const safeTitle = slug(`${compiler.route ?? "repi"}-${compiler.mode}-compiled-report`).slice(0, 90);
		const path = join(reportDir(), `${compiler.timestamp.replace(/[:.]/g, "-")}-${safeTitle}.md`);
		writePrivateTextFile(path, compiler.finalReport.join("\n"));
		updateMissionCheckpoint("report_or_writeup_ready", "done", `${path} strict_claim_check=pass`);
		return path;
	}

	function buildCompiler(options: { target?: string; mode?: "draft" | "final" } = {}): CompilerArtifact {
		ensureReconStorage();
		const { verifier, path: verifierArtifact } = latestOrBuildVerifier(options);
		let claimCheckInputs = latestCompilerClaimCheckInputs({ target: options.target });
		const verifierReleaseReady =
			verifier.assertions.length > 0 &&
			verifier.assertions.every((assertion) => assertion.status === "proved") &&
			verifier.contradictions.length === 0 &&
			verifier.gaps.length === 0;
		if (verifierReleaseReady && claimCheckInputs.strictClaimCheck.status !== "pass") {
			prepareClaimReleaseMarker();
			claimCheckInputs = latestCompilerClaimCheckInputs({ target: options.target });
		}
		const summary = compilerStatusSummary(verifier.assertions);
		const mode = options.mode ?? "draft";
		const strictBlocksFinal = mode === "final" && claimCheckInputs.strictClaimCheck.status !== "pass";
		const structuredClaimBlocksFinal =
			mode === "final" &&
			claimCheckInputs.parallelRequired &&
			claimCheckInputs.structuredClaimMergeCheck.status === "blocked";
		const compiler: CompilerArtifact = {
			timestamp: new Date().toISOString(),
			missionId: verifier.missionId,
			route: verifier.route,
			target: options.target ?? verifier.target,
			mode,
			parallelRequired: claimCheckInputs.parallelRequired,
			verifierArtifact,
			supervisorArtifact: claimCheckInputs.supervisorPath,
			supervisorVerdict: claimCheckInputs.supervisorVerdict,
			operatorFeedback: verifier.operatorFeedback ?? [],
			statusSummary: summary,
			outcome: [
				...compilerOutcome(verifier, summary),
				...(strictBlocksFinal
					? [
							`status=blocked_by_claim_check strict_claim_check=${claimCheckInputs.strictClaimCheck.status}`,
							"claim boundary: final reports require a passing strict claim release marker from check:claim-release.",
						]
					: []),
				...(structuredClaimBlocksFinal
					? [
							`status=blocked_by_structured_claim_merge structured_claim_merge=${claimCheckInputs.structuredClaimMergeCheck.status}`,
							"claim boundary: final reports require StructuredClaimMergeV1 final promotion to pass artifact/jsonQuery/verifier/challenge/conflict checkpoints.",
						]
					: []),
			],
			keyEvidence: compilerKeyEvidence(verifier),
			reproCommands: compilerReproCommands(verifier, verifierArtifact),
			contradictions: compilerContradictions(verifier),
			gaps: [
				...compilerGaps(verifier),
				...(claimCheckInputs.strictClaimCheck.status !== "pass"
					? [
							`strict claim checkpoint ${claimCheckInputs.strictClaimCheck.status}: ${claimCheckInputs.strictClaimCheck.markerPath ?? "missing marker"}`,
							...claimCheckInputs.strictClaimCheck.requiredGaps.map(
								(gap) => `strict claim required gap: ${gap}`,
							),
						]
					: []),
				...(claimCheckInputs.structuredClaimMergeCheck.status === "blocked"
					? [
							`structured claim merge blocked: ${claimCheckInputs.structuredClaimMergeCheck.mergePath ?? "missing merge path"}`,
							...claimCheckInputs.structuredClaimMergeCheck.errors.map(
								(error) => `structured claim merge error: ${error}`,
							),
						]
					: []),
			],
			nextOperatorQueue: Array.from(
				new Set([
					...(claimCheckInputs.strictClaimCheck.status === "pass"
						? []
						: [
								"re_evidence show",
								"re_operator dispatch <target> 2",
								"re_verifier matrix",
								...(claimCheckInputs.parallelRequired ? ["re_swarm merge", "re_supervisor repair"] : []),
							]),
					...(claimCheckInputs.structuredClaimMergeCheck.status === "blocked"
						? ["re_swarm merge", "re_supervisor repair", "re_verifier matrix", "re_compiler draft"]
						: []),
					...compilerNextOperatorQueue(verifier),
				]),
			).slice(0, 24),
			finalReport: [],
			releaseCheckMetadata: claimCheckInputs.releaseCheckMetadata,
			claimCheckPolicy: claimCheckInputs.claimCheckPolicy,
			strictClaimCheck: claimCheckInputs.strictClaimCheck,
			claimCheckResult: claimCheckInputs.claimCheckResult,
			structuredClaimMergeCheck: claimCheckInputs.structuredClaimMergeCheck,
			sourceArtifacts: Array.from(
				new Set(
					[
						verifierArtifact,
						claimCheckInputs.supervisorPath,
						claimCheckInputs.swarmPath,
						claimCheckInputs.strictClaimCheck.markerPath,
						claimCheckInputs.structuredClaimMergeCheck.mergePath,
						...verifier.sourceArtifacts,
					].filter(Boolean) as string[],
				),
			).slice(0, 56),
		};
		const publishBlockers = compilerPublishBlockers(compiler);
		compiler.claimCheckResult = compilerClaimCheckResult(compiler);
		if (mode === "final" && publishBlockers.length > 0) {
			compiler.outcome.push(
				`status=blocked_by_publish_gate blockers=${publishBlockers.slice(0, 8).join(",")}`,
				"claim boundary: final report publication requires every verifier, supervisor, strict-marker, and structured-merge gate to pass.",
			);
			compiler.gaps.push(...publishBlockers.map((blocker) => `publish gate blocker: ${blocker}`));
		}
		compiler.finalReport = compilerReportLines(compiler);
		if (compiler.mode === "final") {
			if (compilerClaimCheckReady(compiler)) compiler.reportPath = writeCompiledReport(compiler);
			else
				updateMissionCheckpoint(
					"report_or_writeup_ready",
					"blocked",
					`strict_claim_check=${compiler.strictClaimCheck?.status ?? "missing"} marker=${compiler.strictClaimCheck?.markerPath ?? "missing"}`,
				);
		}
		return compiler;
	}

	function formatCompiler(compiler: CompilerArtifact, path?: string): string {
		return [
			"compiler_report:",
			path ? `compiler_artifact: ${path}` : undefined,
			`timestamp: ${compiler.timestamp}`,
			`mode: ${compiler.mode}`,
			`mission_id: ${compiler.missionId ?? "none"}`,
			`route: ${compiler.route ?? "none"}`,
			`target: ${compiler.target ?? "<none>"}`,
			`verifier_artifact: ${compiler.verifierArtifact ?? "none"}`,
			`supervisor_artifact: ${compiler.supervisorArtifact ?? "none"}`,
			`supervisor_verdict: ${compiler.supervisorVerdict ?? "missing"}`,
			`report_path: ${compiler.reportPath ?? "none"}`,
			`status_summary: proved=${compiler.statusSummary.proved} weak=${compiler.statusSummary.weak} contradicted=${compiler.statusSummary.contradicted} missing=${compiler.statusSummary.missing}`,
			"release_check_metadata:",
			...(compiler.releaseCheckMetadata.length
				? compiler.releaseCheckMetadata.map((item) => `- ${item}`)
				: ["- none"]),
			"claim_check_policy:",
			...(compiler.claimCheckPolicy.length ? compiler.claimCheckPolicy.map((item) => `- ${item}`) : ["- none"]),
			"strict_claim_check:",
			...formatStrictClaimCheckSnapshot(compiler.strictClaimCheck),
			"claim_check_result:",
			...(compiler.claimCheckResult.length ? compiler.claimCheckResult.map((item) => `- ${item}`) : ["- none"]),
			"structured_claim_merge_check:",
			`- status=${compiler.structuredClaimMergeCheck?.status ?? "missing"}`,
			`- path=${compiler.structuredClaimMergeCheck?.mergePath ?? "missing"}`,
			`- final_claims=${compiler.structuredClaimMergeCheck?.finalClaimCount ?? 0}`,
			`- blocked_claims=${compiler.structuredClaimMergeCheck?.blockedClaimCount ?? 0}`,
			...(compiler.structuredClaimMergeCheck?.errors.length
				? compiler.structuredClaimMergeCheck.errors.slice(0, 10).map((item) => `- error=${item}`)
				: ["- errors=none"]),
			"operator_feedback:",
			...((compiler.operatorFeedback ?? []).length
				? (compiler.operatorFeedback ?? []).map((item) => `- ${item}`)
				: ["- none"]),
			"outcome:",
			...(compiler.outcome.length ? compiler.outcome.map((item) => `- ${item}`) : ["- none"]),
			"key_evidence_block:",
			...(compiler.keyEvidence.length ? compiler.keyEvidence.map((item) => `- ${item}`) : ["- none"]),
			"repro_commands:",
			...(compiler.reproCommands.length ? compiler.reproCommands.map((item) => `- ${item}`) : ["- none"]),
			"contradictions:",
			...(compiler.contradictions.length ? compiler.contradictions.map((item) => `- ${item}`) : ["- none"]),
			"gaps:",
			...(compiler.gaps.length ? compiler.gaps.map((item) => `- ${item}`) : ["- none"]),
			"next_operator_queue:",
			...(compiler.nextOperatorQueue.length ? compiler.nextOperatorQueue.map((item) => `- ${item}`) : ["- none"]),
			"final_report_scaffold:",
			...compiler.finalReport.slice(0, 80),
			`next_compiler_command: ${compilerClaimCheckReady(compiler) ? "re_complete audit" : compiler.mode === "final" ? "re_compiler draft" : "re_compiler final"}`,
			"source_artifacts:",
			...(compiler.sourceArtifacts.length ? compiler.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
		]
			.filter(Boolean)
			.join("\n");
	}

	function writeCompilerArtifact(compiler: CompilerArtifact): string {
		ensureReconStorage();
		const path = join(
			evidenceCompilersDir(),
			`${compiler.timestamp.replace(/[:.]/g, "-")}-${slug(compiler.route ?? "compiler")}-${compiler.mode}.md`,
		);
		writePrivateTextFile(
			path,
			[
				"# REPI Compiler Artifact",
				"",
				formatCompiler(compiler, path),
				"",
				"## Final report scaffold",
				"",
				compiler.finalReport.join("\n"),
				"",
				"## JSON",
				"",
				"```json",
				JSON.stringify(compiler, null, 2),
				"```",
				"",
			].join("\n"),
		);
		appendEvidence({
			kind: "artifact",
			title: `compiler-${compiler.mode} ${compiler.missionId ?? "no-mission"}`,
			fact: `Compiler ${compiler.mode}: proved=${compiler.statusSummary.proved}, weak=${compiler.statusSummary.weak}, contradicted=${compiler.statusSummary.contradicted}, missing=${compiler.statusSummary.missing}, operator_feedback=${(compiler.operatorFeedback ?? []).length}, strict_claim_check=${compiler.strictClaimCheck?.status ?? "missing"}, claim_check_result=${compiler.claimCheckResult.length}, structured_claim_merge=${compiler.structuredClaimMergeCheck?.status ?? "missing"}`,
			command: `re_compiler ${compiler.mode}`,
			path,
			verify: `cat ${path}`,
			confidence: "verifier-to-report compiler",
		});
		updateMissionCheckpoint("compiler_ready", "done", path);
		if (compiler.mode === "final" && !compiler.reportPath) {
			updateMissionCheckpoint(
				"report_or_writeup_ready",
				"blocked",
				`strict_claim_check=${compiler.strictClaimCheck?.status ?? "missing"} marker=${compiler.strictClaimCheck?.markerPath ?? "missing"}`,
			);
		}
		return path;
	}

	function buildCompilerOutput(
		action: "draft" | "show" | "final" = "draft",
		options: { target?: string } = {},
	): string {
		if (action === "show") {
			const path = latestCompilerArtifactPath();
			if (!path) return "compiler_report:\nstatus: missing\nnext: re_compiler draft";
			return compactStoredArtifact("compiler_report", path, readText(path));
		}
		const compiler = buildCompiler({ target: options.target, mode: action });
		const path = writeCompilerArtifact(compiler);
		return formatCompiler(compiler, path);
	}

	function latestCompilerArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		return latestScopedMarkdownArtifact("compiler", evidenceCompilersDir(), options);
	}

	function parseCompilerArtifact(path: string): CompilerArtifact | undefined {
		return parseJsonBlock<CompilerArtifact>(readText, path);
	}

	function latestOrBuildCompiler(options: { target?: string } = {}): { compiler: CompilerArtifact; path: string } {
		const latest = latestCompilerArtifactPath(
			options.target ? { target: options.target, requestedBy: "latest_or_build_compiler" } : {},
		);
		if (latest) {
			const compiler = parseCompilerArtifact(latest);
			const missionId = readCurrentMission()?.id;
			if (
				compiler &&
				missionId &&
				compiler.missionId === missionId &&
				requestedTargetMatches(options.target, compiler.target)
			)
				return { compiler, path: latest };
		}
		const compiler = buildCompiler({ target: options.target, mode: "draft" });
		const path = writeCompilerArtifact(compiler);
		return { compiler, path };
	}

	function replayCommandConcrete(
		command: string,
		target?: string,
	): { command: string; blocked?: string; status?: ReplayStatus } {
		let normalized = command.trim().replace(/^\//, "");
		if (!normalized) return { command: normalized, blocked: "empty replay command" };
		if (commandContainsPoison(normalized))
			return { command: normalized, blocked: "natural-language/poison target rejected" };
		if (/<target>|<TARGET>|<URL>|<none>/i.test(normalized)) {
			if (!target) return { command: normalized, blocked: "target placeholder is unresolved" };
			normalized = normalized.replace(/<target>|<TARGET>|<URL>|<none>/gi, target);
		}
		if (/^re[-_]/i.test(normalized))
			return {
				command: normalized,
				status: "skipped",
				blocked:
					"delegated_internal_repi_command; replay matrix records the orchestration step without shell-sandbox execution",
			};
		return { command: normalized };
	}

	function replayHash(text: string): string {
		return createHash("sha256").update(text).digest("hex");
	}

	function buildReplayMatrix(replay: ReplayArtifact): string[] {
		const executionByStep = new Map(replay.executions.map((execution) => [execution.stepId, execution]));
		return replay.steps.map((step) => {
			const execution = executionByStep.get(step.id);
			if (!execution) {
				return `${step.id} [${step.status}] exit=NA stdout_sha256=NA stderr_sha256=NA command=${step.command}${step.reason ? ` reason=${step.reason}` : ""}`;
			}
			return `${step.id} [${execution.status}] exit=${execution.exit} stdout_sha256=${execution.stdoutHash} stderr_sha256=${execution.stderrHash} command=${execution.command}`;
		});
	}

	function refreshReplayDerivedFields(replay: ReplayArtifact): ReplayArtifact {
		const passed = replay.executions.filter((execution) => execution.status === "passed").length;
		const failed = replay.executions.filter((execution) => execution.status === "failed").length;
		const blocked = replay.steps
			.filter((step) => step.status === "blocked")
			.map((step) => `${step.id}: ${step.reason ?? "blocked"} :: ${step.command}`);
		const readyCount = replay.steps.filter((step) => step.status === "ready").length;
		const nextActions = Array.from(
			new Set([
				...operatorFeedbackNextCommands(replay.operatorFeedback ?? []),
				...(readyCount ? [`re_replayer run ${replay.target ?? "<target>"} ${Math.min(readyCount, 3)}`] : []),
				...(failed ? ["re_autofix plan", "re_compiler draft", "re_verifier matrix"] : []),
				...(blocked.length ? ["re_autofix plan", "re_operator escalate", "re_compiler draft"] : []),
				...(replay.steps.length > 0 && passed > 0 && readyCount === 0 && failed === 0 && blocked.length === 0
					? ["re_complete audit"]
					: []),
			]),
		).slice(0, 12);
		const replayMatrix = buildReplayMatrix({ ...replay, passed, failed, blocked, nextActions, replayMatrix: [] });
		return { ...replay, passed, failed, blocked, nextActions, replayMatrix };
	}

	function replayStepContractMatches(left: ReplayArtifact, right: ReplayArtifact): boolean {
		return (
			left.steps.length === right.steps.length &&
			left.steps.every(
				(step, index) => step.id === right.steps[index]?.id && step.command === right.steps[index]?.command,
			)
		);
	}

	function resumableReplay(base: ReplayArtifact, target?: string): ReplayArtifact {
		const latest = latestReplayerArtifactPath(
			target ? { target, requestedBy: "replayer_resume" } : { requestedBy: "replayer_resume" },
		);
		const candidate = latest ? parseReplayArtifact(latest) : undefined;
		if (
			!candidate ||
			candidate.missionId !== base.missionId ||
			candidate.compilerArtifact !== base.compilerArtifact ||
			candidate.compilerSha256 !== base.compilerSha256 ||
			candidate.target !== base.target ||
			!Array.isArray(candidate.steps) ||
			!Array.isArray(candidate.executions) ||
			!Array.isArray(candidate.sourceArtifacts) ||
			candidate.steps.some(
				(step) => !step || typeof step.id !== "string" || typeof step.command !== "string" || !step.status,
			) ||
			candidate.executions.some(
				(execution) => !execution || typeof execution.stepId !== "string" || typeof execution.command !== "string",
			) ||
			!replayStepContractMatches(candidate, base)
		) {
			return base;
		}
		return refreshReplayDerivedFields({
			...candidate,
			timestamp: new Date().toISOString(),
			mode: "run",
			sourceArtifacts: Array.from(new Set([...candidate.sourceArtifacts, ...base.sourceArtifacts])).slice(0, 56),
		});
	}

	function replayCheckpointStatus(replay: ReplayArtifact): MissionCheckpointStatus {
		const executable = replay.steps.filter((step) => step.status !== "skipped");
		if (executable.length === 0 || replay.executions.length === 0) return "blocked";
		const stepsById = new Map(replay.steps.map((step) => [step.id, step]));
		const executionIds = new Set(replay.executions.map((execution) => execution.stepId));
		if (
			replay.blocked.length > 0 ||
			executionIds.size !== replay.executions.length ||
			replay.executions.some((execution) => {
				const step = stepsById.get(execution.stepId);
				return (
					!step ||
					step.status === "skipped" ||
					execution.command !== step.command ||
					execution.status !== "passed" ||
					execution.exit !== 0 ||
					execution.killed ||
					!/^([a-f0-9]{64})$/i.test(execution.stdoutHash) ||
					!/^([a-f0-9]{64})$/i.test(execution.stderrHash) ||
					!replayExecutionHasProofSignal(execution, step)
				);
			})
		)
			return "blocked";
		if (executable.some((step) => step.status !== "passed")) return "pending";
		return executable.every((step) => executionIds.has(step.id)) ? "done" : "pending";
	}

	function buildReplayer(options: { target?: string; mode?: "plan" | "run" } = {}): ReplayArtifact {
		ensureReconStorage();
		const { compiler, path: compilerArtifact } = latestOrBuildCompiler(options);
		const target = options.target ?? compiler.target;
		const compilerSources = Array.isArray(compiler.sourceArtifacts) ? compiler.sourceArtifacts : [];
		const seen = new Set<string>();
		const steps: ReplayStep[] = [];
		for (const rawCommand of (Array.isArray(compiler.reproCommands) ? compiler.reproCommands : []).slice(0, 40)) {
			if (typeof rawCommand !== "string") continue;
			const command = rawCommand.trim();
			if (!command || seen.has(command)) continue;
			seen.add(command);
			const concrete = replayCommandConcrete(command, target);
			steps.push({
				id: `replay:${steps.length + 1}:${slug(command).slice(0, 24)}`,
				command: concrete.command,
				status: concrete.status ?? (concrete.blocked ? "blocked" : "ready"),
				reason: concrete.blocked,
				sourceArtifacts: compilerSources,
			});
		}
		if (steps.length === 0) {
			steps.push({
				id: "replay:0:no-commands",
				command: "re_compiler draft",
				status: "blocked",
				reason: "compiler artifact has no repro_commands",
				sourceArtifacts: compilerSources,
			});
		}
		return refreshReplayDerivedFields({
			timestamp: new Date().toISOString(),
			missionId: compiler.missionId,
			route: compiler.route,
			target,
			mode: options.mode ?? "plan",
			compilerArtifact,
			compilerSha256: replayHash(readText(compilerArtifact)),
			operatorFeedback: Array.isArray(compiler.operatorFeedback) ? compiler.operatorFeedback : [],
			steps,
			executions: [],
			replayMatrix: [],
			passed: 0,
			failed: 0,
			blocked: [],
			nextActions: [],
			sourceArtifacts: Array.from(new Set([compilerArtifact, ...compilerSources])).slice(0, 56),
		});
	}

	function formatReplayer(replay: ReplayArtifact, path?: string): string {
		return [
			"replay_matrix:",
			path ? `replay_artifact: ${path}` : undefined,
			`timestamp: ${replay.timestamp}`,
			`mode: ${replay.mode}`,
			`mission_id: ${replay.missionId ?? "none"}`,
			`route: ${replay.route ?? "none"}`,
			`target: ${replay.target ?? "<none>"}`,
			`compiler_artifact: ${replay.compilerArtifact ?? "none"}`,
			`compiler_sha256: ${replay.compilerSha256 ?? "none"}`,
			"operator_feedback:",
			...((replay.operatorFeedback ?? []).length
				? (replay.operatorFeedback ?? []).map((item) => `- ${item}`)
				: ["- none"]),
			`passed: ${replay.passed}`,
			`failed: ${replay.failed}`,
			`blocked_count: ${replay.blocked.length}`,
			"steps:",
			...(replay.steps.length
				? replay.steps.map(
						(step) =>
							`- ${step.id} [${step.status}] command=${step.command}${step.reason ? ` reason=${step.reason}` : ""}`,
					)
				: ["- none"]),
			`executed_steps: ${replay.executions.length}`,
			...(replay.executions.length
				? replay.executions.map(
						(execution) =>
							`- ${execution.stepId} [${execution.status}] exit=${execution.exit} stdout_sha256=${execution.stdoutHash} stderr_sha256=${execution.stderrHash} command=${execution.command}`,
					)
				: []),
			"replay_matrix_rows:",
			...(replay.replayMatrix.length ? replay.replayMatrix.map((item) => `- ${item}`) : ["- none"]),
			"blocked:",
			...(replay.blocked.length ? replay.blocked.map((item) => `- ${item}`) : ["- none"]),
			"next_replay_actions:",
			...(replay.nextActions.length
				? replay.nextActions.map((item) => `- ${item}`)
				: ["- re_replayer run <target> 1"]),
			`next_replay_command: ${replay.steps.some((step) => step.status === "ready") ? `re_replayer run ${replay.target ?? "<target>"} 1` : replay.steps.length > 0 && replay.passed > 0 && replay.failed === 0 && replay.blocked.length === 0 ? "re_complete audit" : "re_autofix plan"}`,
			"source_artifacts:",
			...(replay.sourceArtifacts.length ? replay.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
		]
			.filter(Boolean)
			.join("\n");
	}

	function writeReplayerArtifact(replay: ReplayArtifact): string {
		ensureReconStorage();
		const path = join(
			evidenceReplayersDir(),
			`${replay.timestamp.replace(/[:.]/g, "-")}-${slug(replay.route ?? "replayer")}-${replay.mode}.md`,
		);
		writePrivateTextFile(
			path,
			[
				"# REPI Replayer Artifact",
				"",
				formatReplayer(replay, path),
				"",
				"## JSON",
				"",
				"```json",
				JSON.stringify(replay, null, 2),
				"```",
				"",
			].join("\n"),
		);
		appendEvidence({
			kind: replay.mode === "run" ? "runtime" : "artifact",
			title: `replayer-${replay.mode} ${replay.missionId ?? "no-mission"}`,
			fact: `Replay ${replay.mode}: ${replay.executions.length} executed, passed=${replay.passed}, failed=${replay.failed}, blocked=${replay.blocked.length}, operator_feedback=${(replay.operatorFeedback ?? []).length}`,
			command: `re_replayer ${replay.mode}`,
			path,
			verify: `cat ${path}`,
			confidence: "compiler repro command replay matrix",
		});
		if (replay.mode === "run") updateMissionCheckpoint("replay_ready", replayCheckpointStatus(replay), path);
		appendRuntimeFailureRepairFromReplay(replay, path);
		return path;
	}

	async function runReplayer(
		pi: ExtensionAPI,
		options: { target?: string; maxSteps?: number; timeoutMs?: number } = {},
	): Promise<string> {
		const base = buildReplayer({ target: options.target, mode: "run" });
		let replay = resumableReplay(base, options.target);
		const remaining = [
			...replay.steps.filter((step) => step.status === "ready"),
			...replay.steps.filter((step) => step.status === "failed"),
		];
		const maxSteps = Math.max(1, Math.min(40, Math.floor(options.maxSteps ?? Math.max(1, remaining.length))));
		const timeout = Math.max(1000, Math.min(300000, Math.floor(options.timeoutMs ?? 60000)));
		for (const step of remaining.slice(0, maxSteps)) {
			const result = await exec(pi, "bash", ["-lc", `set -o pipefail\n${step.command}`], { timeout });
			const status: ReplayStatus = result.code === 0 && !result.killed ? "passed" : "failed";
			step.status = status;
			step.reason = status === "failed" ? `exit=${result.code}${result.killed ? " killed=true" : ""}` : undefined;
			replay.executions = replay.executions.filter((execution) => execution.stepId !== step.id);
			replay.executions.push({
				stepId: step.id,
				command: step.command,
				status,
				exit: result.code,
				killed: result.killed,
				stdoutHash: replayHash(result.stdout),
				stderrHash: replayHash(result.stderr),
				stdoutHead: truncateMiddle(result.stdout.trim(), 1200),
				stderrHead: truncateMiddle(result.stderr.trim(), 1200),
			});
		}
		replay = refreshReplayDerivedFields(replay);
		const path = writeReplayerArtifact(replay);
		return formatReplayer(replay, path);
	}

	function buildReplayerOutput(action: "plan" | "show" = "plan", options: { target?: string } = {}): string {
		if (action === "show") {
			const path = latestReplayerArtifactPath();
			if (!path) return "replay_matrix:\nstatus: missing\nnext: re_replayer plan";
			return compactStoredArtifact("replay_matrix", path, readText(path));
		}
		const replay = buildReplayer({ target: options.target, mode: "plan" });
		const path = writeReplayerArtifact(replay);
		return formatReplayer(replay, path);
	}

	function latestReplayerArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		return latestScopedMarkdownArtifact("replayer", evidenceReplayersDir(), options);
	}

	function parseReplayArtifact(path: string): ReplayArtifact | undefined {
		return parseJsonBlock<ReplayArtifact>(readText, path);
	}

	function latestOrBuildReplay(options: { target?: string } = {}): { replay: ReplayArtifact; path: string } {
		const latest = latestReplayerArtifactPath(
			options.target ? { target: options.target, requestedBy: "latest_or_build_replay" } : {},
		);
		if (latest) {
			const replay = parseReplayArtifact(latest);
			const missionId = readCurrentMission()?.id;
			if (
				replay &&
				missionId &&
				replay.missionId === missionId &&
				requestedTargetMatches(options.target, replay.target)
			)
				return { replay, path: latest };
		}
		const replay = buildReplayer({ target: options.target, mode: "plan" });
		const path = writeReplayerArtifact(replay);
		return { replay, path };
	}

	return {
		latestVerifierArtifactPath,
		parseVerifierArtifact,
		latestOrBuildVerifier,
		buildVerifier,
		formatVerifier,
		writeVerifierArtifact,
		buildVerifierOutput,
		verifierTechniqueProofContract,
		latestCompilerArtifactPath,
		parseCompilerArtifact,
		latestOrBuildCompiler,
		buildCompiler,
		formatCompiler,
		writeCompilerArtifact,
		buildCompilerOutput,
		latestReplayerArtifactPath,
		parseReplayArtifact,
		latestOrBuildReplay,
		replayCommandConcrete,
		replayHash,
		buildReplayMatrix,
		refreshReplayDerivedFields,
		buildReplayer,
		formatReplayer,
		writeReplayerArtifact,
		runReplayer,
		buildReplayerOutput,
	} as const;
}

export type ProofArtifactRuntime = ReturnType<typeof createProofArtifactRuntime>;
