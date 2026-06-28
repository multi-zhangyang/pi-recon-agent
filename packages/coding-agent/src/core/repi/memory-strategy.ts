import { buildMemoryQualityLedgerReport, type MemoryQualityLedgerReportV11 } from "./memory-quality.ts";
import {
	buildMemoryReplayEvaluatorReport,
	type MemoryReplayEvaluatorReportV12,
	type MemoryReplayEvaluatorRowV12,
} from "./memory-replay.ts";
import { memoryRouteMatches, memoryTargetScope } from "./memory-scope.ts";
import { readMemoryEvents } from "./memory-search.ts";
import { buildMemorySkillCapsuleReport, type MemorySkillCapsuleReportV9 } from "./memory-skill.ts";
import { writeFileAtomic } from "./memory-store.ts";
import {
	ensureRepiStorage,
	memoryQualityReportPath,
	memoryReplayEvaluatorReportPath,
	memorySkillCapsuleReportPath,
	memoryStrategyCapsuleBookPath,
	memoryStrategyCapsuleLedgerPath,
	memoryStrategyCapsuleReportPath,
	readJsonObjectFile,
} from "./storage.ts";
import { sha256Text, slug, truncateMiddle, uniqueNonEmpty } from "./text.ts";

export type MemoryStrategyCapsuleLifecycleV13 = "candidate" | "promoted" | "demoted" | "quarantined";

export type MemoryStrategyCapsuleV13 = {
	kind: "repi-memory-strategy-capsule";
	schemaVersion: 1;
	id: string;
	ts: string;
	MemoryStrategyCapsuleV13: true;
	executable_strategy_capsule: true;
	replay_backed_strategy_promotion: true;
	strategy_quality_check: true;
	caseSignature: string;
	route: string;
	targetScope: string;
	lifecycle: MemoryStrategyCapsuleLifecycleV13;
	triggerConditions: string[];
	objectives: string[];
	recommendedCommands: string[];
	verifierCommands: string[];
	fallbackCommands: string[];
	avoidCommands: string[];
	workerRoutingHints: string[];
	applicabilityBoundary: string[];
	sourceReplayRowIds: string[];
	sourceQualityEventIds: string[];
	sourceSkillCapsuleIds: string[];
	evidenceRefs: string[];
	causalScore: number;
	qualityScore: number;
	confidence: number;
	executionPolicy: {
		preflightChecks: string[];
		evidenceRequirements: string[];
		stopConditions: string[];
		compactResumeHints: string[];
	};
	injection: {
		operatorPromptSnippet: string;
		verifierPromptSnippet: string;
		nextActionCommands: string[];
	};
	entryHash: string;
};

export type MemoryStrategyCapsuleReportV13 = {
	kind: "repi-memory-strategy-capsule-report";
	schemaVersion: 1;
	generatedAt: string;
	MemoryStrategyCapsuleV13: true;
	executable_strategy_capsule: true;
	replay_backed_strategy_promotion: true;
	strategy_quality_check: true;
	reportPath: string;
	capsuleLedgerPath: string;
	strategyBookPath: string;
	sourceReplayReportPath: string;
	sourceQualityReportPath: string;
	sourceSkillCapsuleReportPath: string;
	capsuleCount: number;
	promotedCapsuleIds: string[];
	candidateCapsuleIds: string[];
	demotedCapsuleIds: string[];
	quarantinedCapsuleIds: string[];
	operatorInjectionCommands: string[];
	verifierCommands: string[];
	avoidCommands: string[];
	fallbackCommands: string[];
	workerRoutingHints: string[];
	status: "pass" | "warn" | "blocked" | "empty";
	recentCapsules: MemoryStrategyCapsuleV13[];
	requiredChecks: string[];
	policy: {
		MemoryStrategyCapsuleV13: true;
		replayBackedPromotion: true;
		qualityCheckRequired: true;
		executableCommandsRequired: true;
		verifierAndFallbackRequired: true;
	};
	nextCommands: string[];
};

export function memoryStrategyCapsuleHash(capsule: Omit<MemoryStrategyCapsuleV13, "entryHash">): string {
	return sha256Text(JSON.stringify(capsule));
}

export function memoryStrategyCapsuleFrom(
	input: Omit<MemoryStrategyCapsuleV13, "kind" | "schemaVersion" | "entryHash">,
): MemoryStrategyCapsuleV13 {
	const capsule = {
		kind: "repi-memory-strategy-capsule" as const,
		schemaVersion: 1 as const,
		...input,
	};
	return { ...capsule, entryHash: memoryStrategyCapsuleHash(capsule) };
}

export function memoryStrategyLifecycleForReplay(
	row: MemoryReplayEvaluatorRowV12,
	hasExecutable: boolean,
): MemoryStrategyCapsuleLifecycleV13 {
	if (row.poisonRegressionCount > 0 || row.verdict === "regresses") return "demoted";
	if (row.verdict === "blocked") return "quarantined";
	if (row.verdict === "improves" && row.causalScore >= 62 && hasExecutable) return "promoted";
	return "candidate";
}

export function formatMemoryStrategyCapsules(report: MemoryStrategyCapsuleReportV13): string {
	return [
		"memory_strategy_capsule_v13:",
		`MemoryStrategyCapsuleV13=${report.MemoryStrategyCapsuleV13}`,
		`executable_strategy_capsule=${report.executable_strategy_capsule}`,
		`replay_backed_strategy_promotion=${report.replay_backed_strategy_promotion}`,
		`strategy_quality_check=${report.strategy_quality_check}`,
		`status=${report.status}`,
		`capsules=${report.capsuleCount}`,
		`promoted=${report.promotedCapsuleIds.length}`,
		`candidate=${report.candidateCapsuleIds.length}`,
		`demoted=${report.demotedCapsuleIds.length}`,
		`quarantined=${report.quarantinedCapsuleIds.length}`,
		`report=${report.reportPath}`,
		`ledger=${report.capsuleLedgerPath}`,
		`book=${report.strategyBookPath}`,
		"operator_injection_commands:",
		...(report.operatorInjectionCommands.length
			? report.operatorInjectionCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"verifier_commands:",
		...(report.verifierCommands.length
			? report.verifierCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"recent_strategies:",
		...(report.recentCapsules.length
			? report.recentCapsules
					.slice(0, 12)
					.map(
						(capsule) =>
							`- ${capsule.lifecycle} route=${capsule.route} causal=${capsule.causalScore} quality=${capsule.qualityScore} trigger=${capsule.triggerConditions.join("; ")}`,
					)
			: ["- none"]),
		"next_commands:",
		...report.nextCommands.map((command) => `- ${command}`),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}

export function buildMemoryStrategyCapsuleReport(
	options: {
		route?: string;
		target?: string;
		replay?: MemoryReplayEvaluatorReportV12;
		quality?: MemoryQualityLedgerReportV11;
		skillCapsules?: MemorySkillCapsuleReportV9;
		write?: boolean;
	} = {},
): MemoryStrategyCapsuleReportV13 {
	ensureRepiStorage();
	const generatedAt = new Date().toISOString();
	const quality =
		options.quality ??
		readJsonObjectFile<MemoryQualityLedgerReportV11>(memoryQualityReportPath()) ??
		buildMemoryQualityLedgerReport({ route: options.route, target: options.target, write: false });
	const replay =
		options.replay ??
		readJsonObjectFile<MemoryReplayEvaluatorReportV12>(memoryReplayEvaluatorReportPath()) ??
		buildMemoryReplayEvaluatorReport({ route: options.route, target: options.target, quality, write: false });
	const skillCapsules =
		options.skillCapsules ??
		readJsonObjectFile<MemorySkillCapsuleReportV9>(memorySkillCapsuleReportPath()) ??
		buildMemorySkillCapsuleReport({ route: options.route, target: options.target, write: false });
	const events = readMemoryEvents();
	const eventById = new Map(events.map((event) => [event.id, event]));
	const qualityByEvent = new Map((quality.rows ?? []).map((row) => [row.eventId, row]));
	const skillRows = skillCapsules.recentCapsules ?? [];
	const capsules: MemoryStrategyCapsuleV13[] = [];
	for (const row of replay.rows ?? []) {
		if (options.route && row.route && !memoryRouteMatches(row.route, options.route)) continue;
		if (options.target && row.target && !memoryTargetScope(row.target).includes(memoryTargetScope(options.target)))
			continue;
		const sourceEventIds = uniqueNonEmpty(
			[...row.attributionEventIds, ...row.regressionEventIds, ...row.expectedEventIds],
			24,
		);
		const sourceEvents = sourceEventIds.flatMap((eventId) => {
			const event = eventById.get(eventId);
			return event ? [event] : [];
		});
		const relatedSkills = skillRows.filter(
			(skill) =>
				skill.sourceIds.some((sourceId) => sourceEventIds.includes(sourceId)) ||
				sourceEventIds.some(
					(eventId) =>
						skill.caseSignature.includes(eventId) ||
						skill.sourceHashes.includes(qualityByEvent.get(eventId)?.entryHash ?? ""),
				),
		);
		const recommendedCommands = uniqueNonEmpty(
			[
				...sourceEvents.flatMap((event) => event.commands),
				...relatedSkills.flatMap((skill) => skill.operatorCommands),
				...row.attributionEventIds.flatMap((eventId) => qualityByEvent.get(eventId)?.nextCommands ?? []),
			].filter((command) => !/^re_memory (?:quality|replay|feedback)/i.test(command)),
			18,
		);
		const verifierCommands = uniqueNonEmpty(
			[
				...relatedSkills.flatMap((skill) => skill.verifierCommands),
				"re_verifier matrix",
				"re_replayer run",
				row.attributionEventIds.length
					? "re_memory replay # verify strategy still improves over no-memory control"
					: undefined,
			],
			12,
		);
		const avoidCommands = uniqueNonEmpty(
			[
				...row.regressionEventIds.flatMap((eventId) => eventById.get(eventId)?.commands ?? []),
				...relatedSkills.flatMap((skill) => skill.avoidCommands),
				...quality.avoidCommands,
				...replay.avoidCommands,
			],
			18,
		);
		const fallbackCommands = uniqueNonEmpty(
			[
				"re_memory replay",
				"re_memory quality",
				row.regressionEventIds.length ? "re_memory supervise" : undefined,
				"re_autofix plan",
				"re_context pack",
			],
			10,
		);
		const hasExecutable =
			recommendedCommands.length > 0 || relatedSkills.some((skill) => skill.injection.nextActionCommands.length > 0);
		const lifecycle = memoryStrategyLifecycleForReplay(row, hasExecutable);
		const qualityScores = sourceEventIds
			.map((eventId) => qualityByEvent.get(eventId)?.qualityScore)
			.filter((score): score is number => typeof score === "number");
		const qualityScore = qualityScores.length
			? Number((qualityScores.reduce((sum, score) => sum + score, 0) / qualityScores.length).toFixed(2))
			: 0;
		const confidence = Number(
			Math.max(
				0,
				Math.min(1, (row.causalScore / 100) * 0.62 + (qualityScore / 100) * 0.28 + (hasExecutable ? 0.1 : 0)),
			).toFixed(4),
		);
		const route = row.route ?? sourceEvents[0]?.route ?? options.route ?? "memory-strategy";
		const targetScope = memoryTargetScope(row.target ?? sourceEvents[0]?.target ?? options.target);
		const triggerConditions = uniqueNonEmpty(
			[
				row.query ? `query~=${truncateMiddle(row.query, 120)}` : undefined,
				`route=${route}`,
				targetScope ? `target_scope=${targetScope}` : undefined,
				`causal_score>=${Math.max(0, Math.floor(row.causalScore))}`,
				row.attributionEventIds.length ? `requires_memory_events=${row.attributionEventIds.join(",")}` : undefined,
			],
			12,
		);
		const objectives = uniqueNonEmpty(
			[
				row.verdict === "improves"
					? "reuse replay-proven memory path before broad exploration"
					: "avoid replay-regressed memory path and repair route",
				`reduce_estimated_steps_by=${row.savedStepEstimate}`,
				...sourceEvents.flatMap((event) => event.reuseRules).slice(0, 4),
			],
			10,
		);
		const evidenceRefs = uniqueNonEmpty(
			[
				...row.evidenceRefs,
				...sourceEvents.flatMap((event) => event.artifactHashes.map((artifact) => artifact.path)),
				...relatedSkills.flatMap((skill) => skill.evidenceRefs.map((artifact) => artifact.path)),
			],
			32,
		);
		const nextActionCommands = uniqueNonEmpty(
			[
				...(recommendedCommands.length
					? recommendedCommands
					: [`re_operator plan${row.target ? ` ${row.target}` : ""}`]),
				...verifierCommands.slice(0, 3),
				...fallbackCommands.slice(0, 2),
			],
			16,
		);
		capsules.push(
			memoryStrategyCapsuleFrom({
				id: `strategy:${slug(route)}:${sha256Text(`${row.id}:${sourceEventIds.join(",")}:${row.verdict}`).slice(0, 20)}`,
				ts: generatedAt,
				MemoryStrategyCapsuleV13: true,
				executable_strategy_capsule: true,
				replay_backed_strategy_promotion: true,
				strategy_quality_check: true,
				caseSignature: sourceEvents[0]?.caseSignature ?? row.scenarioId,
				route,
				targetScope: targetScope || "workspace",
				lifecycle,
				triggerConditions,
				objectives,
				recommendedCommands: recommendedCommands.length
					? recommendedCommands
					: [`re_operator plan${row.target ? ` ${row.target}` : ""}`],
				verifierCommands,
				fallbackCommands,
				avoidCommands,
				workerRoutingHints: uniqueNonEmpty(
					[
						...relatedSkills.flatMap((skill) => skill.workerRoutingHints),
						`strategy_route=${route}`,
						`strategy_causal_score=${row.causalScore}`,
					],
					12,
				),
				applicabilityBoundary: uniqueNonEmpty(
					[
						"only inject when MemoryScopeIsolationV1 allows same workspace/target/route",
						targetScope ? `target must match ${targetScope}` : undefined,
						row.regressionEventIds.length
							? `avoid regression events: ${row.regressionEventIds.join(",")}`
							: undefined,
						"rerun re_memory replay after major provider/model/compact changes",
					],
					12,
				),
				sourceReplayRowIds: [row.id],
				sourceQualityEventIds: sourceEventIds,
				sourceSkillCapsuleIds: relatedSkills.map((skill) => skill.id).slice(0, 16),
				evidenceRefs,
				causalScore: row.causalScore,
				qualityScore,
				confidence,
				executionPolicy: {
					preflightChecks: ["re_memory scope", "re_memory replay", "re_context pack"],
					evidenceRequirements: [
						"runtime artifact or replay/verifier evidence before final claim",
						"qualityScore and causalScore must be recorded",
					],
					stopConditions: ["scope_blocked", "poisonRegressionCount>0", "verifier/replay contradicts capsule"],
					compactResumeHints: [
						"include strategy-capsule-report in context pack",
						"resume with same sourceReplayRowIds and sourceQualityEventIds",
					],
				},
				injection: {
					operatorPromptSnippet: truncateMiddle(
						`Use StrategyCapsuleV13 when ${triggerConditions.join("; ")}. Objective: ${objectives.join("; ")}. First commands: ${nextActionCommands.slice(0, 4).join(" && ")}`,
						720,
					),
					verifierPromptSnippet: truncateMiddle(
						`Verify StrategyCapsuleV13 ${row.scenarioId}: causalScore=${row.causalScore}, savedSteps=${row.savedStepEstimate}, evidence=${evidenceRefs.slice(0, 4).join(",")}`,
						520,
					),
					nextActionCommands,
				},
			}),
		);
	}
	const deduped = Array.from(new Map(capsules.map((capsule) => [capsule.id, capsule])).values());
	const byLifecycle = (lifecycle: MemoryStrategyCapsuleLifecycleV13) =>
		deduped.filter((capsule) => capsule.lifecycle === lifecycle);
	const injectable = deduped.filter(
		(capsule) => capsule.lifecycle === "promoted" || capsule.lifecycle === "candidate",
	);
	const operatorInjectionCommands = uniqueNonEmpty(
		injectable.flatMap((capsule) => capsule.recommendedCommands),
		30,
	);
	const verifierCommands = uniqueNonEmpty(
		injectable.flatMap((capsule) => capsule.verifierCommands),
		24,
	);
	const avoidCommands = uniqueNonEmpty(
		deduped.flatMap((capsule) => capsule.avoidCommands),
		24,
	);
	const fallbackCommands = uniqueNonEmpty(
		deduped.flatMap((capsule) => capsule.fallbackCommands),
		16,
	);
	const workerRoutingHints = uniqueNonEmpty(
		injectable.flatMap((capsule) => capsule.workerRoutingHints),
		20,
	);
	const status: MemoryStrategyCapsuleReportV13["status"] =
		deduped.length === 0
			? "empty"
			: byLifecycle("quarantined").length && !operatorInjectionCommands.length
				? "blocked"
				: byLifecycle("demoted").length || byLifecycle("candidate").length
					? "warn"
					: "pass";
	const report: MemoryStrategyCapsuleReportV13 = {
		kind: "repi-memory-strategy-capsule-report",
		schemaVersion: 1,
		generatedAt,
		MemoryStrategyCapsuleV13: true,
		executable_strategy_capsule: true,
		replay_backed_strategy_promotion: true,
		strategy_quality_check: true,
		reportPath: memoryStrategyCapsuleReportPath(),
		capsuleLedgerPath: memoryStrategyCapsuleLedgerPath(),
		strategyBookPath: memoryStrategyCapsuleBookPath(),
		sourceReplayReportPath: replay.reportPath ?? memoryReplayEvaluatorReportPath(),
		sourceQualityReportPath: quality.reportPath ?? memoryQualityReportPath(),
		sourceSkillCapsuleReportPath: skillCapsules.reportPath ?? memorySkillCapsuleReportPath(),
		capsuleCount: deduped.length,
		promotedCapsuleIds: byLifecycle("promoted").map((capsule) => capsule.id),
		candidateCapsuleIds: byLifecycle("candidate").map((capsule) => capsule.id),
		demotedCapsuleIds: byLifecycle("demoted").map((capsule) => capsule.id),
		quarantinedCapsuleIds: byLifecycle("quarantined").map((capsule) => capsule.id),
		operatorInjectionCommands,
		verifierCommands,
		avoidCommands,
		fallbackCommands,
		workerRoutingHints,
		status,
		recentCapsules: deduped.slice(0, 48),
		requiredChecks: [
			"MemoryStrategyCapsuleV13",
			"executable_strategy_capsule",
			"replay_backed_strategy_promotion",
			"strategy_quality_check",
			"strategy_capsule_in_context_pack",
			"strategy_capsule_orchestrator_step",
			"strategy_capsule_operator_injection",
		],
		policy: {
			MemoryStrategyCapsuleV13: true,
			replayBackedPromotion: true,
			qualityCheckRequired: true,
			executableCommandsRequired: true,
			verifierAndFallbackRequired: true,
		},
		nextCommands: uniqueNonEmpty(
			[
				"re_memory strategy",
				operatorInjectionCommands.length
					? "re_operator plan # consumes StrategyCapsuleV13 recommendedCommands"
					: undefined,
				verifierCommands.length ? "re_verifier matrix # verifies StrategyCapsuleV13 before claim" : undefined,
				avoidCommands.length ? "re_autofix plan # avoid/demote regressed strategy capsules" : undefined,
				"re_context pack",
			].filter(Boolean) as string[],
			12,
		),
	};
	if (options.write !== false) {
		writeFileAtomic(
			memoryStrategyCapsuleLedgerPath(),
			deduped.map((capsule) => JSON.stringify(capsule)).join("\n") + (deduped.length ? "\n" : ""),
		);
		writeFileAtomic(memoryStrategyCapsuleReportPath(), `${JSON.stringify(report, null, 2)}\n`);
		writeFileAtomic(
			memoryStrategyCapsuleBookPath(),
			[
				"# REPI Memory Strategy Capsule Book",
				"",
				"MemoryStrategyCapsuleV13: true",
				"executable_strategy_capsule: true",
				"replay_backed_strategy_promotion: true",
				"strategy_quality_check: true",
				`generated_at: ${report.generatedAt}`,
				`status: ${report.status}`,
				"",
				"## Promoted / Candidate Strategies",
				...(injectable.length
					? injectable.map(
							(capsule) =>
								`- ${capsule.lifecycle} causal=${capsule.causalScore} quality=${capsule.qualityScore} trigger=${capsule.triggerConditions.join("; ")} next=${capsule.injection.nextActionCommands.slice(0, 3).join(" && ")}`,
						)
					: ["- none"]),
				"",
				"## Avoid / Demoted Commands",
				...(avoidCommands.length ? avoidCommands.map((command) => `- ${command}`) : ["- none"]),
				"",
				"## Required Checks",
				...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
				"",
			].join("\n"),
		);
	}
	return report;
}
