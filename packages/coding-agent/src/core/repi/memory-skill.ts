import { jsonlRecords } from "./jsonl.ts";
import { extractMemoryCommands } from "./memory-command.ts";
import { distillMemoryPatterns } from "./memory-distillation.ts";
import { type MemoryArtifactHash, memoryArtifactHashes } from "./memory-event.ts";
import {
	buildMemoryExperienceReport,
	isMemoryExperienceClaimRowV8,
	type MemoryExperienceClaimStatusV8,
	type MemoryExperienceLessonActionV8,
} from "./memory-experience.ts";
import { memoryTargetScope } from "./memory-scope.ts";
import { readMemoryEvents } from "./memory-search.ts";
import { writeFileAtomic } from "./memory-store.ts";
import {
	ensureRepiStorage,
	memoryDistillationReportPath,
	memoryExperienceClaimsPath,
	memorySkillCapsuleBookPath,
	memorySkillCapsuleLedgerPath,
	memorySkillCapsuleReportPath,
} from "./storage.ts";
import { clamp01, sha256Text, slug, truncateMiddle, uniqueNonEmpty } from "./text.ts";

export type MemorySkillCapsuleTypeV9 =
	| "operator_playbook"
	| "verifier_rule"
	| "avoid_rule"
	| "repair_rule"
	| "worker_routing"
	| "scope_guard";
export type MemorySkillCapsuleLifecycleV9 = "candidate" | "promoted" | "quarantined" | "demoted";
export type MemorySkillCapsulePromotionCheckV9 =
	| "artifact_sha256"
	| "replay_or_verifier"
	| "experience_promotion"
	| "pattern_confidence"
	| "feedback_usefulness"
	| "scope";
export type MemorySkillPatternTypeV9 =
	| "command_template"
	| "failure_pattern"
	| "verifier_rule"
	| "worker_routing_hint"
	| "tool_repair_rule";
export type MemorySkillPatternLifecycleV9 = "candidate" | "promoted" | "quarantined" | "stale" | "contradicted";

export type MemorySkillCapsuleV9 = {
	kind: "repi-memory-skill-capsule";
	schemaVersion: 1;
	id: string;
	ts: string;
	MemorySkillCapsuleV9: true;
	caseSignature: string;
	route: string;
	targetScope: string;
	skillType: MemorySkillCapsuleTypeV9;
	lifecycle: MemorySkillCapsuleLifecycleV9;
	sourceIds: string[];
	sourceHashes: string[];
	preconditions: string[];
	operatorCommands: string[];
	verifierCommands: string[];
	avoidCommands: string[];
	workerRoutingHints: string[];
	evidenceRefs: MemoryArtifactHash[];
	score: number;
	promotionCheck: MemorySkillCapsulePromotionCheckV9;
	usage: {
		reuseCount: number;
		successCount: number;
		failureCount: number;
		lastUsedAt: string;
		usefulnessScore: number;
	};
	injection: {
		operatorPromptSnippet: string;
		verifierPromptSnippet: string;
		workerRoutingHint?: string;
		nextActionCommands: string[];
	};
	entryHash: string;
};

export type MemorySkillCapsuleReportV9 = {
	kind: "repi-memory-skill-capsule-report";
	schemaVersion: 1;
	generatedAt: string;
	MemorySkillCapsuleV9: true;
	skill_capsule_assetization: true;
	verified_skill_promotion_check: true;
	operator_skill_injection: true;
	reportPath: string;
	capsuleLedgerPath: string;
	capsuleBookPath: string;
	sourceExperienceReportPath: string;
	sourceDistillationReportPath: string;
	capsuleCount: number;
	promotedCapsuleIds: string[];
	candidateCapsuleIds: string[];
	quarantinedCapsuleIds: string[];
	demotedCapsuleIds: string[];
	operatorInjectionCommands: string[];
	verifierCommands: string[];
	avoidCommands: string[];
	workerRoutingHints: string[];
	status: "pass" | "warn" | "blocked" | "empty";
	recentCapsules: MemorySkillCapsuleV9[];
	requiredChecks: string[];
	policy: {
		MemorySkillCapsuleV9: true;
		experienceToSkillCapsule: true;
		distilledPatternToSkillCapsule: true;
		verifiedPromotionCheck: true;
		operatorInjectionOnlyPromotedOrCandidate: true;
	};
	nextCommands: string[];
};

export function memorySkillCapsuleHash(capsule: Omit<MemorySkillCapsuleV9, "entryHash">): string {
	return sha256Text(JSON.stringify(capsule));
}

export function memorySkillCapsuleTypeFromLesson(action: MemoryExperienceLessonActionV8): MemorySkillCapsuleTypeV9 {
	if (action === "avoid") return "avoid_rule";
	if (action === "repair") return "repair_rule";
	if (action === "verify") return "verifier_rule";
	if (action === "scope-limit") return "scope_guard";
	return "operator_playbook";
}

export function memorySkillCapsuleTypeFromPattern(patternType: MemorySkillPatternTypeV9): MemorySkillCapsuleTypeV9 {
	if (patternType === "verifier_rule") return "verifier_rule";
	if (patternType === "worker_routing_hint") return "worker_routing";
	if (patternType === "tool_repair_rule") return "repair_rule";
	if (patternType === "failure_pattern") return "avoid_rule";
	return "operator_playbook";
}

export function memorySkillCapsuleLifecycleFromPattern(
	lifecycle: MemorySkillPatternLifecycleV9,
): MemorySkillCapsuleLifecycleV9 {
	if (lifecycle === "promoted") return "promoted";
	if (lifecycle === "quarantined" || lifecycle === "contradicted") return "quarantined";
	if (lifecycle === "stale") return "demoted";
	return "candidate";
}

export function memorySkillCapsuleLifecycleFromClaim(
	status?: MemoryExperienceClaimStatusV8,
): MemorySkillCapsuleLifecycleV9 {
	if (status === "promoted") return "promoted";
	if (status === "quarantined" || status === "conflicted") return "quarantined";
	if (status === "demoted") return "demoted";
	return "candidate";
}

export function memorySkillCapsulePromotionCheck(input: {
	evidenceRefs?: MemoryArtifactHash[];
	lifecycle?: MemorySkillCapsuleLifecycleV9;
	promotionReady?: boolean;
	score?: number;
}): MemorySkillCapsulePromotionCheckV9 {
	if (input.evidenceRefs?.some((artifact) => artifact.sha256)) return "artifact_sha256";
	if (input.promotionReady) return "experience_promotion";
	if (input.lifecycle === "promoted") return "replay_or_verifier";
	if ((input.score ?? 0) >= 0.78) return "feedback_usefulness";
	return "pattern_confidence";
}

export function memorySkillCapsuleFrom(
	input: Omit<MemorySkillCapsuleV9, "kind" | "schemaVersion" | "entryHash">,
): MemorySkillCapsuleV9 {
	const capsule = {
		kind: "repi-memory-skill-capsule" as const,
		schemaVersion: 1 as const,
		...input,
	};
	return { ...capsule, entryHash: memorySkillCapsuleHash(capsule) };
}

export function buildMemorySkillCapsuleReport(
	options: { route?: string; target?: string; write?: boolean } = {},
): MemorySkillCapsuleReportV9 {
	ensureRepiStorage();
	const generatedAt = new Date().toISOString();
	const effectiveRoute =
		options.route && !/(?:security|general|unknown)/i.test(options.route) ? options.route : undefined;
	const experience = buildMemoryExperienceReport({
		route: effectiveRoute,
		target: options.target,
		write: options.write,
	});
	const distillation = distillMemoryPatterns({ route: effectiveRoute, target: options.target, now: generatedAt });
	const claimRows = jsonlRecords(memoryExperienceClaimsPath(), isMemoryExperienceClaimRowV8);
	const claimById = new Map(claimRows.map((claim) => [claim.id, claim]));
	const eventByIdForSkillCapsules = new Map(readMemoryEvents().map((event) => [event.id, event]));
	const capsules: MemorySkillCapsuleV9[] = [];
	for (const lesson of experience.recentLessons) {
		const claim = claimById.get(lesson.claimId) ?? experience.recentClaims.find((row) => row.id === lesson.claimId);
		const skillType = memorySkillCapsuleTypeFromLesson(lesson.action);
		const lifecycle = memorySkillCapsuleLifecycleFromClaim(claim?.status);
		const baseScore = clamp01(
			lesson.confidence +
				(claim?.promotionReady ? 0.08 : 0) +
				Math.min(0.12, lesson.backprop.reuseCount * 0.02) -
				Math.min(0.18, lesson.backprop.failureCount * 0.04),
			lesson.confidence,
		);
		const sourceEventCommands = claim?.eventId ? (eventByIdForSkillCapsules.get(claim.eventId)?.commands ?? []) : [];
		const lessonCommands = uniqueNonEmpty(
			[...lesson.commands, ...sourceEventCommands, ...extractMemoryCommands(lesson.lesson)],
			12,
		);
		const operatorCommands = skillType === "operator_playbook" || skillType === "repair_rule" ? lessonCommands : [];
		const verifierCommands =
			skillType === "verifier_rule"
				? uniqueNonEmpty([...lessonCommands, "re_verifier matrix", "re_replayer run"], 8)
				: [];
		const avoidCommands = skillType === "avoid_rule" ? lessonCommands : [];
		const preconditions = uniqueNonEmpty(
			[
				...(lesson.appliesWhen ?? []),
				claim?.route ? `route=${claim.route}` : undefined,
				claim?.targetScope ? `target_scope=${claim.targetScope}` : undefined,
				claim?.commandFingerprint ? `command_fingerprint=${claim.commandFingerprint}` : undefined,
			],
			12,
		);
		const sourceHashes = uniqueNonEmpty([claim?.entryHash, sha256Text(JSON.stringify(lesson))], 8);
		const evidenceRefs = uniqueNonEmpty(
			lesson.evidenceRefs.map((artifact) => artifact.path),
			24,
		).length
			? lesson.evidenceRefs
			: (claim?.evidenceRefs ?? []);
		const score = Number(baseScore.toFixed(4));
		capsules.push(
			memorySkillCapsuleFrom({
				id: `skill:${slug(claim?.caseSignature ?? lesson.claimId)}:${skillType}:${sha256Text(`${lesson.id}:${sourceHashes.join(":")}`).slice(0, 16)}`,
				ts: generatedAt,
				MemorySkillCapsuleV9: true,
				caseSignature: claim?.caseSignature ?? lesson.claimId,
				route: claim?.route ?? options.route ?? "manual",
				targetScope: claim?.targetScope ?? memoryTargetScope(options.target) ?? "workspace",
				skillType,
				lifecycle,
				sourceIds: uniqueNonEmpty([lesson.id, claim?.id, claim?.eventId], 8),
				sourceHashes,
				preconditions,
				operatorCommands,
				verifierCommands,
				avoidCommands,
				workerRoutingHints: [],
				evidenceRefs,
				score,
				promotionCheck: memorySkillCapsulePromotionCheck({
					evidenceRefs,
					lifecycle,
					promotionReady: claim?.promotionReady,
					score,
				}),
				usage: {
					reuseCount: lesson.backprop.reuseCount,
					successCount: lesson.action === "reuse" ? 1 : 0,
					failureCount: lesson.backprop.failureCount,
					lastUsedAt: lesson.backprop.lastUsefulAt,
					usefulnessScore: score,
				},
				injection: {
					operatorPromptSnippet: truncateMiddle(`Use skill capsule ${skillType}: ${lesson.lesson}`, 360),
					verifierPromptSnippet: verifierCommands.length
						? `Verify skill capsule ${lesson.id} with replay/verifier evidence before final claim.`
						: "No verifier command generated.",
					nextActionCommands: uniqueNonEmpty([...operatorCommands, ...verifierCommands, ...avoidCommands], 12),
				},
			}),
		);
	}
	for (const pattern of distillation.patterns) {
		const skillType = memorySkillCapsuleTypeFromPattern(pattern.patternType);
		const lifecycle = memorySkillCapsuleLifecycleFromPattern(pattern.lifecycle);
		const evidenceRefs = memoryArtifactHashes(pattern.evidenceRefs);
		const score = Number(
			clamp01(pattern.confidence + (lifecycle === "promoted" ? 0.05 : 0), pattern.confidence).toFixed(4),
		);
		const operatorCommands = skillType === "operator_playbook" || skillType === "repair_rule" ? pattern.commands : [];
		const verifierCommands =
			skillType === "verifier_rule"
				? uniqueNonEmpty([...pattern.commands, "re_verifier matrix", "re_replayer run"], 12)
				: [];
		const avoidCommands =
			skillType === "avoid_rule" ? uniqueNonEmpty([...pattern.commands, ...pattern.failurePatterns], 12) : [];
		const workerRoutingHints =
			skillType === "worker_routing" ? uniqueNonEmpty([...pattern.commands, ...pattern.reuseRules], 12) : [];
		capsules.push(
			memorySkillCapsuleFrom({
				id: `skill:${slug(pattern.caseSignature)}:${skillType}:${sha256Text(`${pattern.id}:${pattern.entryHash}`).slice(0, 16)}`,
				ts: generatedAt,
				MemorySkillCapsuleV9: true,
				caseSignature: pattern.caseSignature,
				route: pattern.route,
				targetScope: memoryTargetScope(pattern.target) || memoryTargetScope(options.target) || pattern.route,
				skillType,
				lifecycle,
				sourceIds: uniqueNonEmpty([pattern.id, ...pattern.sourceEventIds], 16),
				sourceHashes: uniqueNonEmpty([pattern.entryHash, ...pattern.sourceHashes], 16),
				preconditions: uniqueNonEmpty(
					[
						`route=${pattern.route}`,
						pattern.target ? `target_scope=${memoryTargetScope(pattern.target)}` : undefined,
						`case=${pattern.caseSignature}`,
						...pattern.reuseRules.slice(0, 4),
					],
					12,
				),
				operatorCommands,
				verifierCommands,
				avoidCommands,
				workerRoutingHints,
				evidenceRefs,
				score,
				promotionCheck: memorySkillCapsulePromotionCheck({ evidenceRefs, lifecycle, score }),
				usage: {
					reuseCount: pattern.sourceEventIds.length,
					successCount: lifecycle === "promoted" ? 1 : 0,
					failureCount: lifecycle === "demoted" || lifecycle === "quarantined" ? 1 : 0,
					lastUsedAt: generatedAt,
					usefulnessScore: score,
				},
				injection: {
					operatorPromptSnippet: truncateMiddle(
						`Use distilled ${pattern.patternType} skill for ${pattern.caseSignature}: ${pattern.summary}`,
						360,
					),
					verifierPromptSnippet: verifierCommands.length
						? `Replay/verifier required for ${pattern.id}: ${pattern.summary}`
						: "No verifier command generated.",
					workerRoutingHint: workerRoutingHints[0],
					nextActionCommands: uniqueNonEmpty(
						[...operatorCommands, ...verifierCommands, ...avoidCommands, ...workerRoutingHints],
						12,
					),
				},
			}),
		);
	}
	const deduped = Array.from(new Map(capsules.map((capsule) => [capsule.id, capsule])).values()).sort(
		(left, right) =>
			Number(right.lifecycle === "promoted") - Number(left.lifecycle === "promoted") ||
			right.score - left.score ||
			left.id.localeCompare(right.id),
	);
	const injectable = deduped.filter(
		(capsule) => capsule.lifecycle === "promoted" || capsule.lifecycle === "candidate",
	);
	const operatorInjectionCommands = uniqueNonEmpty(
		injectable.flatMap((capsule) => capsule.operatorCommands),
		32,
	);
	const verifierCommands = uniqueNonEmpty(
		injectable.flatMap((capsule) => capsule.verifierCommands),
		24,
	);
	const avoidCommands = uniqueNonEmpty(
		deduped.flatMap((capsule) => capsule.avoidCommands),
		24,
	);
	const workerRoutingHints = uniqueNonEmpty(
		injectable.flatMap((capsule) => capsule.workerRoutingHints),
		24,
	);
	const byLifecycle = (lifecycle: MemorySkillCapsuleLifecycleV9) =>
		deduped.filter((capsule) => capsule.lifecycle === lifecycle).map((capsule) => capsule.id);
	const status: MemorySkillCapsuleReportV9["status"] =
		deduped.length === 0
			? "empty"
			: byLifecycle("quarantined").length && !operatorInjectionCommands.length
				? "warn"
				: "pass";
	const report: MemorySkillCapsuleReportV9 = {
		kind: "repi-memory-skill-capsule-report",
		schemaVersion: 1,
		generatedAt,
		MemorySkillCapsuleV9: true,
		skill_capsule_assetization: true,
		verified_skill_promotion_check: true,
		operator_skill_injection: true,
		reportPath: memorySkillCapsuleReportPath(),
		capsuleLedgerPath: memorySkillCapsuleLedgerPath(),
		capsuleBookPath: memorySkillCapsuleBookPath(),
		sourceExperienceReportPath: experience.reportPath,
		sourceDistillationReportPath: memoryDistillationReportPath(),
		capsuleCount: deduped.length,
		promotedCapsuleIds: byLifecycle("promoted"),
		candidateCapsuleIds: byLifecycle("candidate"),
		quarantinedCapsuleIds: byLifecycle("quarantined"),
		demotedCapsuleIds: byLifecycle("demoted"),
		operatorInjectionCommands,
		verifierCommands,
		avoidCommands,
		workerRoutingHints,
		status,
		recentCapsules: deduped.slice(0, 24),
		requiredChecks: [
			"MemorySkillCapsuleV9",
			"skill_capsule_assetization",
			"verified_skill_promotion_check",
			"operator_skill_injection",
			"memory_skill_capsules_in_context_pack",
			"experience_to_skill_capsule",
			"distilled_pattern_to_skill_capsule",
		],
		policy: {
			MemorySkillCapsuleV9: true,
			experienceToSkillCapsule: true,
			distilledPatternToSkillCapsule: true,
			verifiedPromotionCheck: true,
			operatorInjectionOnlyPromotedOrCandidate: true,
		},
		nextCommands: uniqueNonEmpty(
			[
				"re_memory skills",
				operatorInjectionCommands.length
					? "re_operator plan # consumes MemorySkillCapsuleV9 operatorCommands"
					: undefined,
				verifierCommands.length ? "re_verifier matrix # consumes MemorySkillCapsuleV9 verifierCommands" : undefined,
				avoidCommands.length ? "re_autofix plan # consumes MemorySkillCapsuleV9 avoidCommands" : undefined,
				"re_context pack",
			].filter(Boolean) as string[],
			12,
		),
	};
	if (options.write !== false) {
		writeFileAtomic(
			memorySkillCapsuleLedgerPath(),
			deduped.map((capsule) => JSON.stringify(capsule)).join("\n") + (deduped.length ? "\n" : ""),
		);
		writeFileAtomic(memorySkillCapsuleReportPath(), `${JSON.stringify(report, null, 2)}\n`);
		writeFileAtomic(
			memorySkillCapsuleBookPath(),
			[
				"# REPI Memory Skill Capsule Book",
				"",
				"MemorySkillCapsuleV9: true",
				"skill_capsule_assetization: true",
				`generated_at: ${report.generatedAt}`,
				`report: ${report.reportPath}`,
				"",
				"## Capsules",
				...(deduped.length
					? deduped
							.slice(0, 160)
							.map(
								(capsule) =>
									`- id=${capsule.id} lifecycle=${capsule.lifecycle} type=${capsule.skillType} score=${capsule.score.toFixed(2)} route=${capsule.route} checkpoint=${capsule.promotionCheck} next=${capsule.injection.nextActionCommands.slice(0, 3).join(" ; ") || "none"}`,
							)
					: ["- none"]),
				"",
				"## Operator Injection Commands",
				...(operatorInjectionCommands.length
					? operatorInjectionCommands.map((command) => `- ${command}`)
					: ["- none"]),
				"",
				"## Verifier Commands",
				...(verifierCommands.length ? verifierCommands.map((command) => `- ${command}`) : ["- none"]),
				"",
				"## Required Checks",
				...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
				"",
			].join("\n"),
		);
	}
	return report;
}

export function formatMemorySkillCapsules(report = buildMemorySkillCapsuleReport()): string {
	return [
		"memory_skill_capsule_v9:",
		`MemorySkillCapsuleV9=${report.MemorySkillCapsuleV9}`,
		`skill_capsule_assetization=${report.skill_capsule_assetization}`,
		`verified_skill_promotion_check=${report.verified_skill_promotion_check}`,
		`operator_skill_injection=${report.operator_skill_injection}`,
		`status=${report.status}`,
		`capsules=${report.capsuleCount}`,
		`promoted=${report.promotedCapsuleIds.length}`,
		`candidate=${report.candidateCapsuleIds.length}`,
		`quarantined=${report.quarantinedCapsuleIds.length}`,
		`demoted=${report.demotedCapsuleIds.length}`,
		`report=${report.reportPath}`,
		`capsule_book=${report.capsuleBookPath}`,
		"operator_injection_commands:",
		...(report.operatorInjectionCommands.length
			? report.operatorInjectionCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"verifier_commands:",
		...(report.verifierCommands.length
			? report.verifierCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"avoid_commands:",
		...(report.avoidCommands.length
			? report.avoidCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"recent_capsules:",
		...(report.recentCapsules.length
			? report.recentCapsules
					.slice(0, 12)
					.map(
						(capsule) =>
							`- ${capsule.lifecycle} ${capsule.skillType} score=${capsule.score.toFixed(2)} id=${capsule.id}`,
					)
			: ["- none"]),
		"next_commands:",
		...report.nextCommands.map((command) => `- ${command}`),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}
