import { existsSync, readFileSync } from "node:fs";
import type { MemoryArtifactHash } from "./memory-event.ts";
import { buildMemoryExperienceReport } from "./memory-experience.ts";
import { buildMemorySkillCapsuleReport } from "./memory-skill.ts";
import { writeFileAtomic } from "./memory-store.ts";
import {
	ensureRepiStorage,
	memoryDistillPromotionBookPath,
	memoryDistillPromotionCandidateLedgerPath,
	memoryDistillPromotionReportPath,
} from "./storage.ts";
import { clamp01, sha256Text, truncateMiddle, uniqueNonEmpty } from "./text.ts";

export type MemoryDistillProviderBackendV10 =
	| "local-rule"
	| "mock-provider"
	| "openai-compatible"
	| "anthropic-compatible";
export type MemoryDistillPromotionDecisionV10 = "promote" | "retain" | "quarantine" | "demote";
export type MemoryDistillPromotionSourceV10 = "artifact" | "experience_claim" | "skill_capsule" | "distilled_pattern";

export type MemoryDistillProviderV10 = {
	kind: "repi-memory-distill-provider";
	schemaVersion: 1;
	MemoryDistillPromotionV10: true;
	backend: MemoryDistillProviderBackendV10;
	requestedBackend: MemoryDistillProviderBackendV10;
	model: string;
	status: "active" | "fallback";
	allowRemote: boolean;
	baseUrl?: string;
	endpoint?: string;
	apiKeyEnv?: string;
	timeoutMs: number;
	fallbackReason?: string;
	requiredChecks: string[];
};

export type MemoryDistillCandidateV10 = {
	kind: "repi-memory-distill-candidate";
	schemaVersion: 1;
	id: string;
	ts: string;
	MemoryDistillPromotionV10: true;
	sourceType: MemoryDistillPromotionSourceV10;
	sourceId: string;
	sourceHash: string;
	provider: MemoryDistillProviderV10;
	route: string;
	targetScope: string;
	claim: string;
	lesson: string;
	commands: string[];
	verifierCommands: string[];
	avoidCommands: string[];
	evidenceRefs: MemoryArtifactHash[];
	confidence: number;
	verifierRequired: boolean;
	promotionDecision: MemoryDistillPromotionDecisionV10;
	promotionReason: string;
	providerTraceHash: string;
	entryHash: string;
};

export type MemoryDistillPromotionReportV10 = {
	kind: "repi-memory-distill-promotion-report";
	schemaVersion: 1;
	generatedAt: string;
	MemoryDistillPromotionV10: true;
	provider_distill_contract: true;
	artifact_to_claim_distillation: true;
	verifier_backed_promotion_check: true;
	skill_capsule_promotion_writeback: true;
	reportPath: string;
	candidateLedgerPath: string;
	promotionBookPath: string;
	sourceSkillCapsuleReportPath: string;
	sourceExperienceReportPath: string;
	provider: MemoryDistillProviderV10;
	candidateCount: number;
	promotedCandidateIds: string[];
	retainedCandidateIds: string[];
	quarantinedCandidateIds: string[];
	demotedCandidateIds: string[];
	operatorInjectionCommands: string[];
	verifierCommands: string[];
	avoidCommands: string[];
	status: "pass" | "warn" | "blocked" | "empty";
	recentCandidates: MemoryDistillCandidateV10[];
	requiredChecks: string[];
	policy: {
		MemoryDistillPromotionV10: true;
		providerContractEnvRefOnly: true;
		localFallbackDeterministic: true;
		artifactClaimDistillation: true;
		verifierBackedPromotionCheck: true;
		skillCapsulePromotionWriteback: true;
	};
	nextCommands: string[];
};

export function memoryDistillProviderConfigV10(): MemoryDistillProviderV10 {
	const requestedRaw = String(process.env.REPI_MEMORY_DISTILL_PROVIDER ?? "local-rule")
		.trim()
		.toLowerCase();
	const requested: MemoryDistillProviderBackendV10 =
		requestedRaw === "openai" || requestedRaw === "openai-compatible"
			? "openai-compatible"
			: requestedRaw === "anthropic" || requestedRaw === "anthropic-compatible"
				? "anthropic-compatible"
				: requestedRaw === "mock" || requestedRaw === "mock-provider"
					? "mock-provider"
					: "local-rule";
	const allowRemote = /^(?:1|true|yes)$/i.test(process.env.REPI_MEMORY_DISTILL_ALLOW_REMOTE ?? "");
	const apiKeyEnv =
		process.env.REPI_MEMORY_DISTILL_API_KEY_ENV ??
		(requested === "anthropic-compatible" ? "ANTHROPIC_AUTH_TOKEN" : "OPENAI_API_KEY");
	const needsRemote = requested === "openai-compatible" || requested === "anthropic-compatible";
	const fallbackReason =
		needsRemote && !allowRemote
			? "remote_distill_requires_REPI_MEMORY_DISTILL_ALLOW_REMOTE=1"
			: needsRemote && !process.env.REPI_MEMORY_DISTILL_BASE_URL
				? "distill_base_url_missing"
				: needsRemote && !process.env[apiKeyEnv]
					? "distill_api_key_env_missing"
					: undefined;
	const backend = fallbackReason ? "local-rule" : requested;
	return {
		kind: "repi-memory-distill-provider",
		schemaVersion: 1,
		MemoryDistillPromotionV10: true,
		backend,
		requestedBackend: requested,
		model:
			backend === "local-rule"
				? "repi-local-distill-v10"
				: (process.env.REPI_MEMORY_DISTILL_MODEL ?? "memory-distill-default"),
		status: fallbackReason ? "fallback" : "active",
		allowRemote,
		baseUrl: needsRemote ? process.env.REPI_MEMORY_DISTILL_BASE_URL : undefined,
		endpoint: needsRemote
			? (process.env.REPI_MEMORY_DISTILL_ENDPOINT ??
				(requested === "anthropic-compatible" ? "/v1/messages" : "/v1/chat/completions"))
			: undefined,
		apiKeyEnv: needsRemote ? apiKeyEnv : undefined,
		timeoutMs: Number(process.env.REPI_MEMORY_DISTILL_TIMEOUT_MS) || 8000,
		fallbackReason,
		requiredChecks: [
			"MemoryDistillPromotionV10",
			"provider_distill_contract",
			"distill_api_key_env_ref_only",
			"remote_distill_requires_explicit_allow",
			"local_distill_fallback",
		],
	};
}

export function memoryDistillCandidateHash(candidate: Omit<MemoryDistillCandidateV10, "entryHash">): string {
	return sha256Text(JSON.stringify(candidate));
}

export function memoryDistillCandidateFrom(
	input: Omit<MemoryDistillCandidateV10, "kind" | "schemaVersion" | "entryHash">,
): MemoryDistillCandidateV10 {
	const candidate = { kind: "repi-memory-distill-candidate" as const, schemaVersion: 1 as const, ...input };
	return { ...candidate, entryHash: memoryDistillCandidateHash(candidate) };
}

export function memoryDistillSnippetFromArtifacts(refs: MemoryArtifactHash[], limit = 700): string {
	const snippets: string[] = [];
	for (const ref of refs.slice(0, 3)) {
		if (!ref.path || !existsSync(ref.path)) continue;
		try {
			const body = readFileSync(ref.path, "utf-8");
			snippets.push(`${ref.path}\n${truncateMiddle(body, limit)}`);
		} catch {}
	}
	return snippets.join("\n---\n");
}

export function memoryDistillDecision(input: {
	confidence: number;
	hasEvidence: boolean;
	sourceLifecycle?: string;
	hasVerifier: boolean;
	hasConflict: boolean;
}): { decision: MemoryDistillPromotionDecisionV10; reason: string } {
	if (input.hasConflict || input.sourceLifecycle === "quarantined")
		return { decision: "quarantine", reason: "conflict_or_quarantined_source" };
	if (input.sourceLifecycle === "demoted") return { decision: "demote", reason: "source_lifecycle_demoted" };
	if (input.hasEvidence && (input.hasVerifier || input.confidence >= 0.72))
		return { decision: "promote", reason: "artifact_or_verifier_backed_high_confidence" };
	if (input.confidence >= 0.62) return { decision: "retain", reason: "candidate_confidence_without_verifier_check" };
	return { decision: "demote", reason: "low_confidence_distill_candidate" };
}

export function buildMemoryDistillPromotionReport(
	options: { route?: string; target?: string; write?: boolean } = {},
): MemoryDistillPromotionReportV10 {
	ensureRepiStorage();
	const generatedAt = new Date().toISOString();
	const provider = memoryDistillProviderConfigV10();
	const skillReport = buildMemorySkillCapsuleReport({
		route: options.route,
		target: options.target,
		write: options.write,
	});
	const experience = buildMemoryExperienceReport({
		route: options.route,
		target: options.target,
		write: options.write,
	});
	const candidates: MemoryDistillCandidateV10[] = [];
	for (const capsule of skillReport.recentCapsules) {
		const artifactSnippet = memoryDistillSnippetFromArtifacts(capsule.evidenceRefs, 500);
		const claim = uniqueNonEmpty(
			[capsule.injection.operatorPromptSnippet, artifactSnippet, capsule.preconditions.join(" | ")],
			3,
		).join("\n");
		const confidence = clamp01(
			capsule.score + (capsule.evidenceRefs.some((ref) => ref.sha256) ? 0.06 : 0),
			capsule.score,
		);
		const hasVerifier =
			capsule.verifierCommands.length > 0 ||
			capsule.promotionCheck === "replay_or_verifier" ||
			capsule.promotionCheck === "artifact_sha256";
		const decision = memoryDistillDecision({
			confidence,
			hasEvidence: capsule.evidenceRefs.some((ref) => ref.sha256),
			sourceLifecycle: capsule.lifecycle,
			hasVerifier,
			hasConflict: false,
		});
		candidates.push(
			memoryDistillCandidateFrom({
				id: `mdp:${sha256Text(`skill:${capsule.id}:${capsule.entryHash}`).slice(0, 24)}`,
				ts: generatedAt,
				MemoryDistillPromotionV10: true,
				sourceType: "skill_capsule",
				sourceId: capsule.id,
				sourceHash: capsule.entryHash,
				provider,
				route: capsule.route,
				targetScope: capsule.targetScope,
				claim: truncateMiddle(claim || capsule.id, 900),
				lesson: truncateMiddle(
					capsule.injection.operatorPromptSnippet || capsule.injection.verifierPromptSnippet,
					900,
				),
				commands: uniqueNonEmpty(capsule.operatorCommands, 16),
				verifierCommands: uniqueNonEmpty(capsule.verifierCommands, 16),
				avoidCommands: uniqueNonEmpty(capsule.avoidCommands, 16),
				evidenceRefs: capsule.evidenceRefs,
				confidence: Number(confidence.toFixed(4)),
				verifierRequired: !hasVerifier,
				promotionDecision: decision.decision,
				promotionReason: decision.reason,
				providerTraceHash: sha256Text(`${provider.backend}:${provider.model}:${claim}`).slice(0, 32),
			}),
		);
	}
	for (const claim of experience.recentClaims) {
		const confidence = clamp01(
			claim.confidence + (claim.evidenceRefs.some((ref) => ref.sha256) ? 0.08 : 0),
			claim.confidence,
		);
		const decision = memoryDistillDecision({
			confidence,
			hasEvidence: claim.evidenceRefs.some((ref) => ref.sha256),
			sourceLifecycle: claim.status,
			hasVerifier: claim.claimType === "verifier_rule" || claim.promotionReady,
			hasConflict: claim.contradictionEventIds.length > 0,
		});
		candidates.push(
			memoryDistillCandidateFrom({
				id: `mdp:${sha256Text(`claim:${claim.id}:${claim.entryHash}`).slice(0, 24)}`,
				ts: generatedAt,
				MemoryDistillPromotionV10: true,
				sourceType: "experience_claim",
				sourceId: claim.id,
				sourceHash: claim.entryHash,
				provider,
				route: claim.route,
				targetScope: claim.targetScope,
				claim: truncateMiddle(claim.statement, 900),
				lesson: truncateMiddle(`Distilled claim ${claim.claimType}: ${claim.statement}`, 900),
				commands: claim.commandFingerprint ? [claim.commandFingerprint] : [],
				verifierCommands: claim.claimType === "verifier_rule" ? ["re_verifier matrix", "re_replayer run"] : [],
				avoidCommands: claim.claimType === "failure_signature" ? [claim.statement] : [],
				evidenceRefs: claim.evidenceRefs,
				confidence: Number(confidence.toFixed(4)),
				verifierRequired: !claim.promotionReady,
				promotionDecision: decision.decision,
				promotionReason: decision.reason,
				providerTraceHash: sha256Text(`${provider.backend}:${provider.model}:${claim.statement}`).slice(0, 32),
			}),
		);
	}
	const deduped = Array.from(new Map(candidates.map((candidate) => [candidate.id, candidate])).values()).sort(
		(left, right) => {
			const rank = (decision: MemoryDistillPromotionDecisionV10) =>
				decision === "promote" ? 3 : decision === "retain" ? 2 : decision === "demote" ? 1 : 0;
			return (
				rank(right.promotionDecision) - rank(left.promotionDecision) ||
				right.confidence - left.confidence ||
				left.id.localeCompare(right.id)
			);
		},
	);
	const byDecision = (decision: MemoryDistillPromotionDecisionV10) =>
		deduped.filter((candidate) => candidate.promotionDecision === decision).map((candidate) => candidate.id);
	const injectable = deduped.filter(
		(candidate) => candidate.promotionDecision === "promote" || candidate.promotionDecision === "retain",
	);
	const operatorInjectionCommands = uniqueNonEmpty(
		injectable.flatMap((candidate) => candidate.commands),
		32,
	);
	const verifierCommands = uniqueNonEmpty(
		injectable.flatMap((candidate) => candidate.verifierCommands),
		24,
	);
	const avoidCommands = uniqueNonEmpty(
		deduped.flatMap((candidate) => candidate.avoidCommands),
		24,
	);
	const status: MemoryDistillPromotionReportV10["status"] =
		deduped.length === 0
			? "empty"
			: provider.status === "fallback" && provider.requestedBackend !== "local-rule"
				? "warn"
				: byDecision("promote").length
					? "pass"
					: "warn";
	const report: MemoryDistillPromotionReportV10 = {
		kind: "repi-memory-distill-promotion-report",
		schemaVersion: 1,
		generatedAt,
		MemoryDistillPromotionV10: true,
		provider_distill_contract: true,
		artifact_to_claim_distillation: true,
		verifier_backed_promotion_check: true,
		skill_capsule_promotion_writeback: true,
		reportPath: memoryDistillPromotionReportPath(),
		candidateLedgerPath: memoryDistillPromotionCandidateLedgerPath(),
		promotionBookPath: memoryDistillPromotionBookPath(),
		sourceSkillCapsuleReportPath: skillReport.reportPath,
		sourceExperienceReportPath: experience.reportPath,
		provider,
		candidateCount: deduped.length,
		promotedCandidateIds: byDecision("promote"),
		retainedCandidateIds: byDecision("retain"),
		quarantinedCandidateIds: byDecision("quarantine"),
		demotedCandidateIds: byDecision("demote"),
		operatorInjectionCommands,
		verifierCommands,
		avoidCommands,
		status,
		recentCandidates: deduped.slice(0, 32),
		requiredChecks: [
			"MemoryDistillPromotionV10",
			"provider_distill_contract",
			"artifact_to_claim_distillation",
			"verifier_backed_promotion_check",
			"skill_capsule_promotion_writeback",
			"memory_distill_promotion_in_context_pack",
			"memory_distill_orchestrator_step",
		],
		policy: {
			MemoryDistillPromotionV10: true,
			providerContractEnvRefOnly: true,
			localFallbackDeterministic: true,
			artifactClaimDistillation: true,
			verifierBackedPromotionCheck: true,
			skillCapsulePromotionWriteback: true,
		},
		nextCommands: uniqueNonEmpty(
			[
				"re_memory distill-promote",
				operatorInjectionCommands.length
					? "re_operator plan # consumes MemoryDistillPromotionV10 promoted commands"
					: undefined,
				verifierCommands.length
					? "re_verifier matrix # verifies MemoryDistillPromotionV10 retained/promoted claims"
					: undefined,
				avoidCommands.length
					? "re_autofix plan # avoids MemoryDistillPromotionV10 demoted/quarantined routes"
					: undefined,
				"re_context pack",
			].filter(Boolean) as string[],
			12,
		),
	};
	if (options.write !== false) {
		writeFileAtomic(
			memoryDistillPromotionCandidateLedgerPath(),
			deduped.map((candidate) => JSON.stringify(candidate)).join("\n") + (deduped.length ? "\n" : ""),
		);
		writeFileAtomic(memoryDistillPromotionReportPath(), `${JSON.stringify(report, null, 2)}\n`);
		writeFileAtomic(
			memoryDistillPromotionBookPath(),
			[
				"# REPI Memory Distill Promotion Book",
				"",
				"MemoryDistillPromotionV10: true",
				"provider_distill_contract: true",
				`generated_at: ${report.generatedAt}`,
				`provider: ${provider.backend}/${provider.model} status=${provider.status}`,
				"",
				"## Candidates",
				...(deduped.length
					? deduped
							.slice(0, 160)
							.map(
								(candidate) =>
									`- decision=${candidate.promotionDecision} confidence=${candidate.confidence.toFixed(2)} source=${candidate.sourceType}:${candidate.sourceId} reason=${candidate.promotionReason}`,
							)
					: ["- none"]),
				"",
				"## Operator Injection Commands",
				...(operatorInjectionCommands.length
					? operatorInjectionCommands.map((command) => `- ${command}`)
					: ["- none"]),
				"",
				"## Required Checks",
				...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
				"",
			].join("\n"),
		);
	}
	return report;
}

export function formatMemoryDistillPromotion(report = buildMemoryDistillPromotionReport()): string {
	return [
		"memory_distill_promotion_v10:",
		`MemoryDistillPromotionV10=${report.MemoryDistillPromotionV10}`,
		`provider_distill_contract=${report.provider_distill_contract}`,
		`artifact_to_claim_distillation=${report.artifact_to_claim_distillation}`,
		`verifier_backed_promotion_check=${report.verifier_backed_promotion_check}`,
		`skill_capsule_promotion_writeback=${report.skill_capsule_promotion_writeback}`,
		`provider=${report.provider.backend}/${report.provider.model} status=${report.provider.status}`,
		`status=${report.status}`,
		`candidates=${report.candidateCount}`,
		`promoted=${report.promotedCandidateIds.length}`,
		`retained=${report.retainedCandidateIds.length}`,
		`quarantined=${report.quarantinedCandidateIds.length}`,
		`demoted=${report.demotedCandidateIds.length}`,
		`report=${report.reportPath}`,
		`promotion_book=${report.promotionBookPath}`,
		"operator_injection_commands:",
		...(report.operatorInjectionCommands.length
			? report.operatorInjectionCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"verifier_commands:",
		...(report.verifierCommands.length
			? report.verifierCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"recent_candidates:",
		...(report.recentCandidates.length
			? report.recentCandidates
					.slice(0, 12)
					.map(
						(candidate) =>
							`- ${candidate.promotionDecision} confidence=${candidate.confidence.toFixed(2)} source=${candidate.sourceType}:${candidate.sourceId}`,
					)
			: ["- none"]),
		"next_commands:",
		...report.nextCommands.map((command) => `- ${command}`),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}
