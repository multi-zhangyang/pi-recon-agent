import { writeFileSync } from "node:fs";
import { type CaseMemoryV1, latestCaseMemoryBySignature } from "./case-memory.ts";
import { type MemoryArtifactHash, type MemoryEventV1, memoryEventHashChainOk } from "./memory-event.ts";
import { latestMemoryQualityByEvent, type MemoryQualityLedgerRowV11 } from "./memory-quality.ts";
import { buildMemoryScopeIsolationReport, memoryRouteMatches, memoryTargetScope } from "./memory-scope.ts";
import {
	memoryCaseTextForSearch,
	memoryHybridQueryTokens,
	memorySearchTokens,
	memoryTextForSearch,
	readMemoryEvents,
} from "./memory-search.ts";
import {
	ensureRepiStorage,
	memoryContradictionLedgerPath,
	memoryDistillationReportPath,
	memoryInjectionPacketPath,
	memoryPatternBookPath,
	memoryQuarantinePath,
	memoryRetrievalReportPath,
	memorySedimentationReportPath,
	memorySemanticIndexPath,
} from "./storage.ts";
import { containsRepiPoison, looksLikeNaturalLanguageTarget } from "./target.ts";
import { sha256Text, truncateMiddle, uniqueNonEmpty } from "./text.ts";

export type MemoryDistilledPatternV1 = {
	kind: "repi-memory-distilled-pattern";
	schemaVersion: 1;
	id: string;
	caseSignature: string;
	route: string;
	target?: string;
	patternType: "command_template" | "failure_pattern" | "verifier_rule" | "worker_routing_hint" | "tool_repair_rule";
	lifecycle: "candidate" | "promoted" | "quarantined" | "stale" | "contradicted";
	confidence: number;
	sourceEventIds: string[];
	sourceHashes: string[];
	commands: string[];
	reuseRules: string[];
	failurePatterns: string[];
	evidenceRefs: string[];
	summary: string;
	quarantinedReason?: string;
	entryHash: string;
};

export type MemoryContaminationFindingV1 = {
	caseSignature: string;
	status: "clean" | "quarantine";
	reasons: string[];
	eventIds: string[];
	routes: string[];
	targets: string[];
	quarantinedReason?: string;
};

export type MemoryDistillationReportV1 = {
	kind: "repi-memory-distillation-report";
	schemaVersion: 1;
	generatedAt: string;
	hashChainOk: boolean;
	patterns: MemoryDistilledPatternV1[];
	quarantine: MemoryContaminationFindingV1[];
	injectionPlan: {
		mandatory_memory_injection_chain: ["retrieve", "rank", "inject", "execute", "verify", "feedback"];
		retrievalReport: string;
		distillationReport: string;
		patternBook: string;
		quarantine: string;
		promotedPatternIds: string[];
	};
};

export type MemorySedimentationAction = "inject" | "retain" | "demote" | "quarantine" | "expire";

export type MemorySemanticIndexEntryV1 = {
	kind: "repi-memory-semantic-index-entry";
	schemaVersion: 1;
	id: string;
	eventId: string;
	caseSignature: string;
	route: string;
	targetScope: string;
	domainTags: string[];
	normalizedTokens: string[];
	commandFingerprints: string[];
	artifactRefs: MemoryArtifactHash[];
	verifierRefs: string[];
	claimRefs: string[];
	grade: number;
	action: MemorySedimentationAction;
	blockers: string[];
	reuseSummary: string;
};

export type MemoryContradictionLedgerEntryV1 = {
	kind: "repi-memory-contradiction-ledger-entry";
	schemaVersion: 1;
	id: string;
	caseSignature: string;
	status: "quarantine" | "contradicted" | "stale" | "clean";
	reasons: string[];
	eventIds: string[];
	routes: string[];
	targets: string[];
	entryHash: string;
};

export type MemoryInjectionPacketV1 = {
	kind: "repi-memory-injection-packet";
	schemaVersion: 1;
	generatedAt: string;
	mandatory_memory_injection_packet: true;
	budget: { maxEntries: number; maxCommands: number; maxTokens: number };
	entries: MemorySemanticIndexEntryV1[];
	commands: string[];
	verifierRules: string[];
	requiredChecks: string[];
	feedbackWriteback: string;
};

export type MemorySedimentationReportV1 = {
	kind: "repi-memory-sedimentation-report";
	schemaVersion: 1;
	generatedAt: string;
	hashChainOk: boolean;
	semanticIndexPath: string;
	contradictionLedgerPath: string;
	injectionPacketPath: string;
	distillationReportPath: string;
	entries: MemorySemanticIndexEntryV1[];
	contradictions: MemoryContradictionLedgerEntryV1[];
	injectionPacket: MemoryInjectionPacketV1;
	policy: {
		MemorySedimentationV1: true;
		promotionRequiresArtifactSha256: true;
		promotionRequiresVerifierOrReplay: true;
		quarantineBlocksInjection: true;
		failureFeedbackDemotes: true;
	};
};

export function memoryPatternHash(pattern: Omit<MemoryDistilledPatternV1, "entryHash">): string {
	return sha256Text(JSON.stringify(pattern));
}

export function memoryPatternFrom(
	input: Omit<MemoryDistilledPatternV1, "kind" | "schemaVersion" | "entryHash">,
): MemoryDistilledPatternV1 {
	const pattern = {
		kind: "repi-memory-distilled-pattern" as const,
		schemaVersion: 1 as const,
		...input,
	};
	return { ...pattern, entryHash: memoryPatternHash(pattern) };
}

export function memoryCommandTemplate(command: string, target?: string): string | undefined {
	let normalized = command.trim();
	if (!normalized) return undefined;
	if (target) normalized = normalized.split(target).join("<target>");
	normalized = normalized.replace(/https?:\/\/[^\s'"`]+/gi, "<target>");
	if (/(?:password|secret|api[_-]?key)\s*=|Bearer\s+(?!<token>)[A-Za-z0-9._-]{12,}/i.test(normalized))
		return undefined;
	return normalized;
}

export function detectMemoryContamination(
	events = readMemoryEvents(),
	options?: { now?: string },
): MemoryContaminationFindingV1[] {
	const now = Date.parse(options?.now ?? new Date().toISOString());
	const byCase = new Map<string, MemoryEventV1[]>();
	for (const event of events) {
		const rows = byCase.get(event.caseSignature) ?? [];
		rows.push(event);
		byCase.set(event.caseSignature, rows);
	}
	const findings: MemoryContaminationFindingV1[] = [];
	for (const [caseSignature, rows] of byCase) {
		const routes = uniqueNonEmpty(
			rows.map((event) => event.route.toLowerCase()),
			12,
		);
		const targets = uniqueNonEmpty(
			rows.map((event) => memoryTargetScope(event.target)),
			16,
		);
		const successes = rows.filter((event) => event.outcome === "success");
		const failures = rows.filter((event) => event.outcome === "failure" || event.outcome === "blocked");
		const highConfidenceFailures = failures.filter((event) => event.quality.confidence >= 0.78);
		const latest = Math.max(...rows.map((event) => Date.parse(event.ts)).filter(Number.isFinite), 0);
		const ageDays = latest > 0 && Number.isFinite(now) ? Math.floor((now - latest) / 86_400_000) : 0;
		const failurePressure = failures.length + rows.reduce((sum, event) => sum + event.quality.failureCount, 0);
		const poisonRows = rows.filter(
			(event) =>
				[event.task, event.target, ...event.commands].some(
					(value) => containsRepiPoison(value) || looksLikeNaturalLanguageTarget(value),
				) ||
				[...event.lessons, ...event.reuseRules, ...event.failurePatterns].some((value) =>
					containsRepiPoison(value),
				),
		);
		const reasons = uniqueNonEmpty(
			[
				poisonRows.length
					? `poison_or_natural_language_target:${poisonRows.map((event) => event.id).join(",")}`
					: undefined,
				routes.length > 1 ? `cross_route_contamination:${routes.join(",")}` : undefined,
				targets.length > 2 ? `cross_target_contamination:${targets.join(",")}` : undefined,
				successes.length > 0 && highConfidenceFailures.length > 0
					? "contradicted_success_failure_high_confidence"
					: undefined,
				ageDays > 180 && successes.length === 0 ? `stale_negative_memory:${ageDays}d` : undefined,
				failurePressure >= Math.max(2, successes.length + 2) ? `failure_pressure:${failurePressure}` : undefined,
			],
			8,
		);
		findings.push({
			caseSignature,
			status: reasons.length ? "quarantine" : "clean",
			reasons,
			eventIds: rows.map((event) => event.id),
			routes,
			targets,
			quarantinedReason: reasons.join("; ") || undefined,
		});
	}
	return findings;
}

export function distillMemoryPatterns(options?: {
	route?: string;
	target?: string;
	now?: string;
}): MemoryDistillationReportV1 {
	ensureRepiStorage();
	const events = readMemoryEvents().filter((event) => {
		if (options?.route && !memoryRouteMatches(event.route, options.route)) return false;
		if (
			options?.target &&
			event.target &&
			!memoryTargetScope(event.target).includes(memoryTargetScope(options.target))
		)
			return false;
		return true;
	});
	const contamination = detectMemoryContamination(events, { now: options?.now });
	const quarantineByCase = new Map(contamination.map((finding) => [finding.caseSignature, finding]));
	const byCase = new Map<string, MemoryEventV1[]>();
	for (const event of events) {
		const rows = byCase.get(event.caseSignature) ?? [];
		rows.push(event);
		byCase.set(event.caseSignature, rows);
	}
	const patterns: MemoryDistilledPatternV1[] = [];
	for (const [caseSignature, rows] of byCase) {
		const finding = quarantineByCase.get(caseSignature);
		if (finding?.status === "quarantine") continue;
		const successes = rows.filter((event) => event.outcome === "success");
		const failures = rows.filter((event) => event.outcome === "failure" || event.outcome === "blocked");
		const best = [...successes].sort(
			(left, right) => right.quality.confidence - left.quality.confidence || right.seq - left.seq,
		)[0];
		const confidence = Math.max(...rows.map((event) => event.quality.confidence), 0);
		const commands = uniqueNonEmpty(
			successes.flatMap((event) => event.commands.map((command) => memoryCommandTemplate(command, event.target))),
			16,
		);
		const evidenceRefs = uniqueNonEmpty(
			rows.flatMap((event) => event.artifactHashes.map((artifact) => artifact.path)),
			40,
		);
		const sourceEventIds = rows.map((event) => event.id);
		const sourceHashes = rows.map((event) => event.entryHash);
		if (best && commands.length > 0 && confidence >= 0.72) {
			patterns.push(
				memoryPatternFrom({
					id: `pattern:${caseSignature}:command_template`,
					caseSignature,
					route: best.route,
					target: best.target,
					patternType: "command_template",
					lifecycle: best.quality.replayVerified ? "promoted" : "candidate",
					confidence,
					sourceEventIds,
					sourceHashes,
					commands,
					reuseRules: uniqueNonEmpty(
						rows.flatMap((event) => event.reuseRules),
						16,
					),
					failurePatterns: uniqueNonEmpty(
						rows.flatMap((event) => event.failurePatterns),
						16,
					),
					evidenceRefs,
					summary: uniqueNonEmpty([best.lessons[0], best.reuseRules[0], best.task], 3).join(" | "),
				}),
			);
		}
		if (successes.some((event) => event.quality.replayVerified || event.promotion.verifierRuleCandidate)) {
			patterns.push(
				memoryPatternFrom({
					id: `pattern:${caseSignature}:verifier_rule`,
					caseSignature,
					route: best?.route ?? rows[0]?.route ?? "manual",
					target: best?.target,
					patternType: "verifier_rule",
					lifecycle: "candidate",
					confidence: Math.min(0.93, confidence),
					sourceEventIds,
					sourceHashes,
					commands: uniqueNonEmpty(["re_verifier matrix", "re_replayer run", ...commands], 12),
					reuseRules: uniqueNonEmpty(
						[
							"Require replay/verifier evidence before promoting this claim.",
							...rows.flatMap((event) => event.reuseRules),
						],
						16,
					),
					failurePatterns: uniqueNonEmpty(
						failures.flatMap((event) => event.failurePatterns),
						16,
					),
					evidenceRefs,
					summary: `Verifier rule distilled from ${successes.length} successful event(s) for ${caseSignature}.`,
				}),
			);
		}
		const workerHints = uniqueNonEmpty(
			rows.map((event) => event.promotion.workerRoutingHint),
			8,
		);
		if (workerHints.length > 0) {
			patterns.push(
				memoryPatternFrom({
					id: `pattern:${caseSignature}:worker_routing_hint`,
					caseSignature,
					route: best?.route ?? rows[0]?.route ?? "manual",
					target: best?.target,
					patternType: "worker_routing_hint",
					lifecycle: confidence >= 0.75 ? "promoted" : "candidate",
					confidence,
					sourceEventIds,
					sourceHashes,
					commands: workerHints.map((hint) => `route worker=${hint}`),
					reuseRules: workerHints.map((hint) => `Prefer ${hint} for matching ${caseSignature} evidence gaps.`),
					failurePatterns: uniqueNonEmpty(
						failures.flatMap((event) => event.failurePatterns),
						16,
					),
					evidenceRefs,
					summary: `Worker routing hint distilled for ${caseSignature}: ${workerHints.join(", ")}`,
				}),
			);
		}
	}
	const report: MemoryDistillationReportV1 = {
		kind: "repi-memory-distillation-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		hashChainOk: memoryEventHashChainOk(readMemoryEvents()),
		patterns,
		quarantine: contamination.filter((finding) => finding.status === "quarantine"),
		injectionPlan: {
			mandatory_memory_injection_chain: ["retrieve", "rank", "inject", "execute", "verify", "feedback"],
			retrievalReport: memoryRetrievalReportPath(),
			distillationReport: memoryDistillationReportPath(),
			patternBook: memoryPatternBookPath(),
			quarantine: memoryQuarantinePath(),
			promotedPatternIds: patterns
				.filter((pattern) => pattern.lifecycle === "promoted")
				.map((pattern) => pattern.id),
		},
	};
	writeFileSync(memoryDistillationReportPath(), `${JSON.stringify(report, null, 2)}\n`, "utf-8");
	writeFileSync(
		memoryQuarantinePath(),
		`${JSON.stringify({ kind: "repi-memory-contamination-quarantine", schemaVersion: 1, findings: report.quarantine }, null, 2)}\n`,
		"utf-8",
	);
	writeFileSync(
		memoryPatternBookPath(),
		[
			"# REPI Memory Pattern Book",
			"",
			"memory_pattern_book:",
			`generated_at: ${report.generatedAt}`,
			`hash_chain_ok: ${report.hashChainOk}`,
			`mandatory_memory_injection_chain: ${report.injectionPlan.mandatory_memory_injection_chain.join(" -> ")}`,
			"patterns:",
			...(patterns.length
				? patterns.map(
						(pattern) =>
							`- id=${pattern.id} lifecycle=${pattern.lifecycle} route=${pattern.route} confidence=${pattern.confidence.toFixed(2)} commands=${pattern.commands.length} summary=${truncateMiddle(pattern.summary, 180)}`,
					)
				: ["- none"]),
			"memory_contamination_quarantine:",
			...(report.quarantine.length
				? report.quarantine.map(
						(finding) =>
							`- case=${finding.caseSignature} reasons=${finding.reasons.join(",")} events=${finding.eventIds.join(",")}`,
					)
				: ["- none"]),
			"",
		].join("\n"),
		"utf-8",
	);
	return report;
}

export function formatMemoryDistillation(report = distillMemoryPatterns()): string {
	return [
		"memory_v3_distillation:",
		`hash_chain_ok=${report.hashChainOk}`,
		`patterns=${report.patterns.length}`,
		`quarantine=${report.quarantine.length}`,
		`distillation_report=${memoryDistillationReportPath()}`,
		`pattern_book=${memoryPatternBookPath()}`,
		`quarantine_path=${memoryQuarantinePath()}`,
		`mandatory_memory_injection_chain=${report.injectionPlan.mandatory_memory_injection_chain.join(" -> ")}`,
		"promoted_patterns:",
		...(report.patterns.filter((pattern) => pattern.lifecycle === "promoted").length
			? report.patterns
					.filter((pattern) => pattern.lifecycle === "promoted")
					.map(
						(pattern) =>
							`- ${pattern.id} route=${pattern.route} confidence=${pattern.confidence.toFixed(2)} commands=${pattern.commands.length}`,
					)
			: ["- none"]),
		"memory_contamination_quarantine:",
		...(report.quarantine.length
			? report.quarantine.map((finding) => `- ${finding.caseSignature} reasons=${finding.reasons.join(",")}`)
			: ["- none"]),
	].join("\n");
}

export function memoryCommandFingerprint(command: string, target?: string): string {
	const template = memoryCommandTemplate(command, target) ?? command.trim();
	return `cmd:${sha256Text(template.toLowerCase()).slice(0, 16)}:${truncateMiddle(template.replace(/\s+/g, " "), 120)}`;
}

export function memoryVerifierRefs(event: MemoryEventV1): string[] {
	const commandRefs = event.commands.filter((command) =>
		/\bre_(?:verifier|replayer|proof_loop|complete)\b|\bnpm\s+run\s+check:|\bpytest\b|\bvitest\b/i.test(command),
	);
	return uniqueNonEmpty(
		[
			...(event.quality.replayVerified ? [`replay_verified:event=${event.id}`] : []),
			...(event.promotion.verifierRuleCandidate ? [`verifier_rule_candidate:event=${event.id}`] : []),
			...commandRefs,
		],
		12,
	);
}

export function memoryClaimRefs(event: MemoryEventV1): string[] {
	return uniqueNonEmpty(
		[...event.lessons, ...event.reuseRules, ...event.failurePatterns]
			.filter((line) =>
				/\b(?:claim|verdict|evidence|artifact|offset|route|authz|primitive|signature|ioc|proof)\b/i.test(line),
			)
			.map((line) => truncateMiddle(line, 180)),
		12,
	);
}

export function memorySedimentationTokens(event: MemoryEventV1, caseRow: CaseMemoryV1 | undefined): string[] {
	const text = [memoryTextForSearch(event), memoryCaseTextForSearch(caseRow)].join("\n");
	return uniqueNonEmpty(
		[...memorySearchTokens(text), ...memoryHybridQueryTokens([...memorySearchTokens(text)].slice(0, 80))],
		96,
	);
}

export function memorySedimentationGrade(params: {
	event: MemoryEventV1;
	caseRow?: CaseMemoryV1;
	finding?: MemoryContaminationFindingV1;
	patterns: MemoryDistilledPatternV1[];
	qualityRow?: MemoryQualityLedgerRowV11;
	now?: string;
}): { grade: number; action: MemorySedimentationAction; blockers: string[] } {
	const { event, caseRow, finding, patterns, qualityRow } = params;
	const now = Date.parse(params.now ?? new Date().toISOString());
	const ageDays = Number.isFinite(now) ? Math.max(0, Math.floor((now - Date.parse(event.ts)) / 86_400_000)) : 0;
	const artifactReady = event.artifactHashes.some(
		(artifact) => typeof artifact.sha256 === "string" && artifact.sha256.length >= 32,
	);
	const verifierReady =
		event.quality.replayVerified || event.promotion.verifierRuleCandidate || memoryVerifierRefs(event).length > 0;
	const successful = event.outcome === "success" || event.outcome === "repair";
	const failed = event.outcome === "failure" || event.outcome === "blocked";
	const patternBoost = patterns.filter(
		(pattern) => pattern.caseSignature === event.caseSignature && pattern.lifecycle !== "quarantined",
	).length;
	let grade = 0;
	grade += event.quality.confidence * 38;
	grade += event.quality.replayVerified ? 18 : 0;
	grade += event.promotion.playbookCandidate ? 6 : 0;
	grade += event.promotion.verifierRuleCandidate ? 7 : 0;
	grade += successful ? 12 : 0;
	grade += artifactReady ? 8 : 0;
	grade += Math.min(10, event.quality.reuseCount * 2 + (caseRow?.quality.reuseCount ?? 0) * 1.5);
	grade += Math.min(8, patternBoost * 2);
	if (qualityRow) {
		grade += Math.max(-22, Math.min(18, (qualityRow.qualityScore - 50) * 0.28));
		if (qualityRow.lifecycleDecision === "promote") grade += 7;
		if (qualityRow.lifecycleDecision === "demote" || qualityRow.lifecycleDecision === "expire") grade -= 14;
		if (qualityRow.lifecycleDecision === "quarantine") grade -= 60;
	}
	grade -= failed ? 18 : 0;
	grade -= Math.min(22, event.quality.failureCount * 5 + (caseRow?.quality.failureCount ?? 0) * 3);
	grade -= Math.min(18, event.quality.decay * 18 + ageDays * 0.03);
	const blockers = uniqueNonEmpty(
		[
			finding?.status === "quarantine" ? `memory_contamination_quarantine:${finding.reasons.join(",")}` : undefined,
			!artifactReady ? "artifact_sha256_missing" : undefined,
			!verifierReady ? "verifier_or_replay_missing" : undefined,
			qualityRow?.lifecycleDecision &&
			qualityRow.lifecycleDecision !== "promote" &&
			qualityRow.lifecycleDecision !== "retain"
				? `memory_quality_${qualityRow.lifecycleDecision}`
				: undefined,
			qualityRow?.forbiddenLeakCount ? `quality_forbidden_leak:${qualityRow.forbiddenLeakCount}` : undefined,
			failed ? `negative_outcome:${event.outcome}` : undefined,
			ageDays > 365 && !successful ? `stale_memory:${ageDays}d` : undefined,
		],
		8,
	);
	const hardQuarantine = Boolean(
		finding?.status === "quarantine" && finding.reasons.some((reason) => !/^failure_pressure:/i.test(reason)),
	);
	let action: MemorySedimentationAction = "retain";
	if (hardQuarantine) action = "quarantine";
	else if (qualityRow?.lifecycleDecision === "quarantine") action = "quarantine";
	else if (qualityRow?.lifecycleDecision === "expire") action = "expire";
	else if (qualityRow?.lifecycleDecision === "demote") action = "demote";
	else if (ageDays > 540 && !successful) action = "expire";
	else if (failed || grade < 34) action = "demote";
	else if (grade >= 70 && successful && artifactReady && verifierReady && !finding?.reasons.length) action = "inject";
	return { grade: Number(Math.max(0, Math.min(100, grade)).toFixed(2)), action, blockers };
}

export function memoryContradictionEntry(finding: MemoryContaminationFindingV1): MemoryContradictionLedgerEntryV1 {
	const status: MemoryContradictionLedgerEntryV1["status"] = finding.reasons.some((reason) =>
		/contradicted/i.test(reason),
	)
		? "contradicted"
		: finding.reasons.some((reason) => /stale/i.test(reason))
			? "stale"
			: finding.status;
	const base = {
		kind: "repi-memory-contradiction-ledger-entry" as const,
		schemaVersion: 1 as const,
		id: `memory-contradiction:${finding.caseSignature}`,
		caseSignature: finding.caseSignature,
		status,
		reasons: finding.reasons,
		eventIds: finding.eventIds,
		routes: finding.routes,
		targets: finding.targets,
	};
	return { ...base, entryHash: sha256Text(JSON.stringify(base)) };
}

export function buildMemorySemanticIndex(options?: {
	route?: string;
	target?: string;
	now?: string;
	maxEntries?: number;
}): MemorySedimentationReportV1 {
	ensureRepiStorage();
	const events = readMemoryEvents().filter((event) => {
		if (options?.route && !memoryRouteMatches(event.route, options.route)) return false;
		if (
			options?.target &&
			event.target &&
			!memoryTargetScope(event.target).includes(memoryTargetScope(options.target))
		)
			return false;
		return true;
	});
	const caseMemory = latestCaseMemoryBySignature();
	const distillation = distillMemoryPatterns({ route: options?.route, target: options?.target, now: options?.now });
	const contamination = detectMemoryContamination(events, { now: options?.now });
	const quarantineByCase = new Map(contamination.map((finding) => [finding.caseSignature, finding]));
	const qualityByEvent = latestMemoryQualityByEvent();
	const scopeIsolation = buildMemoryScopeIsolationReport({ route: options?.route, target: options?.target, events });
	const scopeByEvent = new Map(scopeIsolation.rows.map((row) => [row.eventId, row]));
	const entries = events
		.map((event) => {
			const caseRow = caseMemory.get(event.caseSignature);
			const finding = quarantineByCase.get(event.caseSignature);
			const graded = memorySedimentationGrade({
				event,
				caseRow,
				finding,
				patterns: distillation.patterns,
				qualityRow: qualityByEvent.get(event.id),
				now: options?.now,
			});
			const scopeRow = scopeByEvent.get(event.id);
			const scopeBlocked = scopeRow?.blocksInjection === true;
			const action: MemorySedimentationAction = scopeBlocked ? "quarantine" : graded.action;
			const blockers = uniqueNonEmpty(
				[...graded.blockers, ...(scopeRow?.reasons.map((reason) => `scope_isolation:${reason}`) ?? [])],
				16,
			);
			const verifierRefs = memoryVerifierRefs(event);
			const claimRefs = memoryClaimRefs(event);
			const entry: MemorySemanticIndexEntryV1 = {
				kind: "repi-memory-semantic-index-entry",
				schemaVersion: 1,
				id: `memory-semantic:${event.id}`,
				eventId: event.id,
				caseSignature: event.caseSignature,
				route: event.route,
				targetScope: memoryTargetScope(event.target),
				domainTags: event.domainTags,
				normalizedTokens: memorySedimentationTokens(event, caseRow),
				commandFingerprints: uniqueNonEmpty(
					event.commands.map((command) => memoryCommandFingerprint(command, event.target)),
					20,
				),
				artifactRefs: event.artifactHashes.filter((artifact) => artifact.sha256),
				verifierRefs,
				claimRefs,
				grade: graded.grade,
				action,
				blockers,
				reuseSummary: truncateMiddle(
					caseRow?.summary || uniqueNonEmpty([event.lessons[0], event.reuseRules[0], event.task], 3).join(" | "),
					420,
				),
			};
			return entry;
		})
		.sort((left, right) => right.grade - left.grade || left.eventId.localeCompare(right.eventId));
	const byId = new Map(events.map((event) => [event.id, event]));
	const contradictions = contamination
		.filter((finding) => finding.status === "quarantine" || finding.reasons.length > 0)
		.map(memoryContradictionEntry);
	const injectable = entries.filter((entry) => entry.action === "inject").slice(0, options?.maxEntries ?? 8);
	const commands = uniqueNonEmpty(
		injectable.flatMap((entry) => byId.get(entry.eventId)?.commands ?? []),
		32,
	);
	const verifierRules = uniqueNonEmpty(
		[
			...injectable.flatMap((entry) => entry.verifierRefs),
			...(injectable.length ? ["Verify injected memory with replay/verifier evidence before claim promotion."] : []),
		],
		32,
	);
	const injectionPacket: MemoryInjectionPacketV1 = {
		kind: "repi-memory-injection-packet",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		mandatory_memory_injection_packet: true,
		budget: { maxEntries: options?.maxEntries ?? 8, maxCommands: 32, maxTokens: 3500 },
		entries: injectable,
		commands,
		verifierRules,
		requiredChecks: [
			"artifact_sha256_required",
			"promotion_requires_verifier_or_replay",
			"quarantine_blocks_injection",
			"feedback_writeback_required_after_execution",
			"memory_sedimentation_grade>=70",
		],
		feedbackWriteback:
			"After executing an injected command, append MemoryEventV1 feedback with outcome, artifact sha256 and verifier result.",
	};
	const report: MemorySedimentationReportV1 = {
		kind: "repi-memory-sedimentation-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		hashChainOk: memoryEventHashChainOk(readMemoryEvents()),
		semanticIndexPath: memorySemanticIndexPath(),
		contradictionLedgerPath: memoryContradictionLedgerPath(),
		injectionPacketPath: memoryInjectionPacketPath(),
		distillationReportPath: memoryDistillationReportPath(),
		entries,
		contradictions,
		injectionPacket,
		policy: {
			MemorySedimentationV1: true,
			promotionRequiresArtifactSha256: true,
			promotionRequiresVerifierOrReplay: true,
			quarantineBlocksInjection: true,
			failureFeedbackDemotes: true,
		},
	};
	writeFileSync(
		memorySemanticIndexPath(),
		`${JSON.stringify({ kind: "repi-memory-semantic-index", schemaVersion: 1, generatedAt: report.generatedAt, entries }, null, 2)}\n`,
		"utf-8",
	);
	writeFileSync(
		memoryContradictionLedgerPath(),
		`${contradictions.map((entry) => JSON.stringify(entry)).join("\n")}${contradictions.length ? "\n" : ""}`,
		"utf-8",
	);
	writeFileSync(memoryInjectionPacketPath(), `${JSON.stringify(injectionPacket, null, 2)}\n`, "utf-8");
	writeFileSync(memorySedimentationReportPath(), `${JSON.stringify(report, null, 2)}\n`, "utf-8");
	return report;
}

export function formatMemorySedimentation(report = buildMemorySemanticIndex()): string {
	const counts = report.entries.reduce<Record<string, number>>((acc, entry) => {
		acc[entry.action] = (acc[entry.action] ?? 0) + 1;
		return acc;
	}, {});
	return [
		"memory_v4_sedimentation:",
		`hash_chain_ok=${report.hashChainOk}`,
		`semantic_index=${report.semanticIndexPath}`,
		`contradiction_ledger=${report.contradictionLedgerPath}`,
		`mandatory_memory_injection_packet=${report.injectionPacketPath}`,
		`distillation_report=${report.distillationReportPath}`,
		`memory_sedimentation_grade_policy=artifact_sha256+verifier_or_replay+feedback_decay+quarantine`,
		`counts=inject:${counts.inject ?? 0},retain:${counts.retain ?? 0},demote:${counts.demote ?? 0},quarantine:${counts.quarantine ?? 0},expire:${counts.expire ?? 0}`,
		"injectable_entries:",
		...(report.injectionPacket.entries.length
			? report.injectionPacket.entries.map(
					(entry) =>
						`- event=${entry.eventId} grade=${entry.grade.toFixed(1)} route=${entry.route} case=${entry.caseSignature} artifacts=${entry.artifactRefs.length} verifiers=${entry.verifierRefs.length}`,
				)
			: ["- none"]),
		"contradictions_or_quarantine:",
		...(report.contradictions.length
			? report.contradictions.map(
					(entry) => `- case=${entry.caseSignature} status=${entry.status} reasons=${entry.reasons.join(",")}`,
				)
			: ["- none"]),
		"required_checks:",
		...report.injectionPacket.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}
