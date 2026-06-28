import { writeFileSync } from "node:fs";
import { latestCaseMemoryBySignature } from "./case-memory.ts";
import { memoryEventHashChainOk } from "./memory-event.ts";
import { latestMemoryQualityByEvent } from "./memory-quality.ts";
import { type RepiMemoryRuntimeSettings, repiMemorySettings } from "./memory-runtime.ts";
import { currentMemoryScope, memoryRouteMatches, memoryScopeIsolationRow } from "./memory-scope.ts";
import {
	type MemoryRetrievalHit,
	memoryBlockingGovernanceBySource,
	memoryHybridQueryTokens,
	memoryHybridSignalScore,
	memoryNormalizedRecallScore,
	memoryRecallCardLines,
	memoryRecallQuery,
	memorySearchTokens,
	memoryTextForSearch,
	readMemoryEvents,
} from "./memory-search.ts";
import { formatCoreMemoryPacket, formatMemoryIsolationStatus, formatMemoryRuntimeStatus } from "./memory-ux.ts";
import { searchMemoryVectors } from "./memory-vector.ts";
import {
	caseMemoryPath,
	compactResumeLedgerV2ReportPath,
	compactResumeTransitionLedgerPath,
	ensureRepiStorage,
	memoryActiveInjectionPackPath,
	memoryActiveKernelReportPath,
	memoryActiveStrategyBoardPath,
	memoryDepositionEventBusPath,
	memoryDepositionReportPath,
	memoryDistillPromotionBookPath,
	memoryDistillPromotionReportPath,
	memoryEventsPath,
	memoryExperienceLessonBookPath,
	memoryExperienceReportPath,
	memoryFeedbackClosureReportPath,
	memoryInjectionPacketPath,
	memoryMaturationActionBoardPath,
	memoryMaturationRuntimeReportPath,
	memoryOrchestratorReportPath,
	memoryPath,
	memoryQualityBoardPath,
	memoryQualityReportPath,
	memoryReplayEvaluatorBoardPath,
	memoryReplayEvaluatorReportPath,
	memoryRetrievalReportPath,
	memoryScopeIsolationReportPath,
	memorySedimentationReportPath,
	memorySkillCapsuleBookPath,
	memorySkillCapsuleReportPath,
	memoryStoreReportPath,
	memoryStrategyCapsuleBookPath,
	memoryStrategyCapsuleReportPath,
	memorySupervisorReportPath,
	memoryUsefulnessEvalReportPath,
	memoryVectorSearchReportPath,
	readTextFile as readText,
} from "./storage.ts";
import { sanitizeTargetForCommand } from "./target.ts";
import { truncateMiddle, uniqueNonEmpty } from "./text.ts";

export function searchMemoryEvents(
	query?: string,
	options?: { route?: string; target?: string; limit?: number },
): MemoryRetrievalHit[] {
	ensureRepiStorage();
	const events = readMemoryEvents();
	const caseMemory = latestCaseMemoryBySignature();
	const qualityByEvent = latestMemoryQualityByEvent();
	const governanceBlocked = memoryBlockingGovernanceBySource();
	const vectorReport = searchMemoryVectors(query, options);
	const vectorByEvent = new Map(vectorReport.hits.map((hit) => [hit.eventId, hit]));
	const queryTokens = uniqueNonEmpty((query ?? "").toLowerCase().split(/[^a-z0-9一-鿿]+/), 24).filter(
		(token) => token.length >= 2,
	);
	const semanticTokens = memoryHybridQueryTokens(queryTokens);
	const hits = events.flatMap((event) => {
		const governance = governanceBlocked.get(event.id);
		if (governance) return [];
		if (options?.route && !memoryRouteMatches(event.route, options.route)) return [];
		const haystack = memoryTextForSearch(event);
		const haystackTokens = memorySearchTokens(haystack);
		const reasons: string[] = [];
		let score = 0;
		if (queryTokens.length === 0) {
			score += Math.max(1, Math.min(12, event.seq / 10));
			reasons.push("recent");
		}
		for (const token of queryTokens) {
			if (haystackTokens.has(token)) {
				score += 4;
				reasons.push(`token:${token}`);
			}
		}
		if (options?.route && memoryRouteMatches(event.route, options.route)) {
			score += 6;
			reasons.push("route");
		}
		if (options?.target && event.target?.toLowerCase().includes(options.target.toLowerCase())) {
			score += 6;
			reasons.push("target");
		}
		const ageDays = Math.max(0, Math.floor((Date.now() - Date.parse(event.ts)) / 86_400_000));
		const decay = Math.min(25, ageDays * 0.08 + event.quality.decay * 12 + event.quality.failureCount * 4);
		score += event.quality.confidence * 10 + (event.quality.replayVerified ? 8 : 0) + event.quality.reuseCount * 2;
		score -= decay;
		const caseRow = caseMemory.get(event.caseSignature);
		const qualityRow = qualityByEvent.get(event.id);
		if (qualityRow) {
			const qualityDelta = (qualityRow.qualityScore - 50) / 4;
			score += qualityDelta;
			reasons.push(`memory_quality_ledger:${qualityRow.lifecycleDecision}:${qualityRow.qualityScore.toFixed(1)}`);
			if (qualityRow.lifecycleDecision === "promote") score += 5;
			if (qualityRow.lifecycleDecision === "demote" || qualityRow.lifecycleDecision === "expire") score -= 12;
			if (
				qualityRow.lifecycleDecision === "quarantine" ||
				qualityRow.forbiddenLeakCount > 0 ||
				qualityRow.scopeBlocked
			)
				score -= 40;
		}
		score += memoryHybridSignalScore(event, caseRow, queryTokens, semanticTokens, reasons);
		const vectorHit = vectorByEvent.get(event.id);
		if (vectorHit && vectorHit.score > 0) {
			score += Math.min(18, vectorHit.score / 6);
			reasons.push(...vectorHit.reasons);
		}
		if (caseRow) {
			const caseReuseBoost = Math.min(12, caseRow.quality.reuseCount * 1.5);
			const caseFailurePenalty = Math.min(18, caseRow.quality.failureCount * 3 + caseRow.quality.decay * 10);
			if (caseReuseBoost > 0) {
				score += caseReuseBoost;
				reasons.push("case-memory-feedback:reuse");
			}
			if (caseRow.quality.replayVerified && !event.quality.replayVerified) {
				score += 3;
				reasons.push("case-memory-feedback:verified");
			}
			if (caseFailurePenalty > 0) {
				score -= caseFailurePenalty;
				reasons.push("case-memory-feedback:penalty");
			}
		}
		if (event.outcome === "success") score += 6;
		if (event.outcome === "blocked" || event.outcome === "failure") score -= event.outcome === "failure" ? 10 : 8;
		if (
			score <= 0 ||
			(queryTokens.length > 0 &&
				!reasons.some((reason) =>
					/^(?:token:|memory_semantic_hybrid_reuse:|case-memory-hybrid:|artifact-hybrid:)/.test(reason),
				) &&
				!reasons.some((reason) =>
					/^(?:memory_vector_rerank:|route_scoped_vector|quality_weighted_vector_score)/.test(reason),
				))
		)
			return [];
		return [{ event, score, reasons }];
	});
	const result = hits
		.sort((left, right) => right.score - left.score || right.event.seq - left.event.seq)
		.slice(0, options?.limit ?? 12);
	writeFileSync(
		memoryRetrievalReportPath(),
		`${JSON.stringify(
			{
				kind: "repi-memory-retrieval-report",
				schemaVersion: 1,
				query: query ?? "",
				route: options?.route,
				target: options?.target,
				generatedAt: new Date().toISOString(),
				hashChainOk: memoryEventHashChainOk(events),
				hits: result.map((hit) => ({
					id: hit.event.id,
					score: Number(hit.score.toFixed(2)),
					reasons: hit.reasons,
					caseSignature: hit.event.caseSignature,
					outcome: hit.event.outcome,
					quality: hit.event.quality,
					commands: hit.event.commands.slice(0, 6),
				})),
			},
			null,
			2,
		)}\n`,
		"utf-8",
	);
	return result;
}

export function formatMemoryRetrieval(query?: string, hits = searchMemoryEvents(query)): string {
	return [
		"memory_event_retrieval:",
		`query: ${query ?? ""}`,
		`events_path: ${memoryEventsPath()}`,
		`case_memory_path: ${caseMemoryPath()}`,
		`retrieval_report: ${memoryRetrievalReportPath()}`,
		`vector_report: ${memoryVectorSearchReportPath()}`,
		`hash_chain_ok: ${memoryEventHashChainOk(readMemoryEvents())}`,
		"hits:",
		...(hits.length
			? hits.map(
					(hit) =>
						`- id=${hit.event.id} score=${hit.score.toFixed(1)} outcome=${hit.event.outcome} route=${hit.event.route} case=${hit.event.caseSignature} reasons=${hit.reasons.join(",")} commands=${hit.event.commands.length} lessons=${hit.event.lessons.length}`,
				)
			: ["- none"]),
	].join("\n");
}

export function memoryRecallScopeAllowed(
	hit: MemoryRetrievalHit,
	options: { route?: string; target?: string },
): boolean {
	if (repiMemorySettings().scopePolicy === "global") return true;
	return !memoryScopeIsolationRow(hit.event, currentMemoryScope({ route: options.route, target: options.target }))
		.blocksInjection;
}

export function scopedMemoryRecallHits(
	options: { route?: string; target?: string; query?: string; maxItems?: number; minScore?: number } = {},
): MemoryRetrievalHit[] {
	const settings = repiMemorySettings();
	const query = memoryRecallQuery(options);
	const maxItems = options.maxItems ?? settings.maxStartupItems;
	if (maxItems <= 0 || !query.trim()) return [];
	return searchMemoryEvents(query, {
		route: options.route,
		target: options.target,
		limit: Math.max(maxItems * 4, maxItems),
	})
		.filter((hit) => memoryRecallScopeAllowed(hit, options))
		.filter((hit) => memoryNormalizedRecallScore(hit) >= (options.minScore ?? settings.minRecallScore))
		.slice(0, maxItems);
}

export function formatScopedMemoryRecallPacket(
	options: { route?: string; target?: string; query?: string; budgetTokens?: number; maxItems?: number } = {},
): string {
	const settings = repiMemorySettings();
	const hits = scopedMemoryRecallHits({
		route: options.route,
		target: options.target,
		query: options.query,
		maxItems: options.maxItems ?? settings.maxStartupItems,
		minScore: settings.minRecallScore,
	});
	const packet = [
		formatMemoryRuntimeStatus(settings, options),
		formatCoreMemoryPacket(),
		"memory_recall_packet:",
		"recall_type=scoped_summary_cards",
		`query=${memoryRecallQuery(options) || "none"}`,
		`cards=${hits.length}`,
		"cards_detail:",
		...(hits.length ? hits.flatMap(memoryRecallCardLines) : ["- none"]),
		"recall_contract:",
		"- use cards only as hypotheses or known local workflow hints",
		"- verify against current workspace/runtime before acting",
		"- do not assume previous target state unless scope and evidence match",
	].join("\n");
	return truncateMiddle(packet, (options.budgetTokens ?? settings.startupBudgetTokens) * 4);
}

export function buildScopedMemoryDigest(options: { route?: string; target?: string; query?: string } = {}): string {
	return formatScopedMemoryRecallPacket(options);
}

export function concreteMemoryRecallTarget(target?: string): string | undefined {
	return sanitizeTargetForCommand(target);
}

export function formatDeferredScopedMemoryRecall(
	settings: RepiMemoryRuntimeSettings,
	options: { route?: string; target?: string; reason: string },
): string {
	return [
		formatMemoryIsolationStatus(settings, {
			route: options.route,
			target: concreteMemoryRecallTarget(options.target),
		}),
		"memory_recall_packet:",
		"recall_type=deferred_scoped_summary_cards",
		`deferred_reason=${options.reason}`,
		"cards=0",
		"policy=old task cards are not injected until the current task has a concrete URL/path/package target or the operator explicitly runs re_memory search/active",
	].join("\n");
}

export function buildMemoryDigest(): string {
	ensureRepiStorage();
	const eventCount = readMemoryEvents().length;
	return [
		...(eventCount === 0
			? [
					"<memory_empty_warning>",
					"empty_warning: MemoryStoreV5 has eventCount=0; run re_memory append/post-tool or execute re_lane/re_operator/re_swarm so runtime writeback can seed events.jsonl; optional: re_memory verify && re_memory repair-index",
					"</memory_empty_warning>",
				]
			: []),
		"<memory_events_tail>",
		truncateMiddle(readText(memoryEventsPath()), 2400),
		"</memory_events_tail>",
		"<case_memory_tail>",
		truncateMiddle(readText(caseMemoryPath()), 2400),
		"</case_memory_tail>",
		"<memory_store_v5>",
		truncateMiddle(readText(memoryStoreReportPath()), 1800),
		"</memory_store_v5>",
		"<memory_usefulness_eval>",
		truncateMiddle(readText(memoryUsefulnessEvalReportPath()), 1800),
		"</memory_usefulness_eval>",
		"<memory_feedback_closure>",
		truncateMiddle(readText(memoryFeedbackClosureReportPath()), 1800),
		"</memory_feedback_closure>",
		"<memory_scope_isolation>",
		truncateMiddle(readText(memoryScopeIsolationReportPath()), 1800),
		"</memory_scope_isolation>",
		"<memory_orchestrator_v6>",
		truncateMiddle(readText(memoryOrchestratorReportPath()), 2200),
		"</memory_orchestrator_v6>",
		"<memory_deposition_engine_v7>",
		truncateMiddle(readText(memoryDepositionReportPath()), 2200),
		"</memory_deposition_engine_v7>",
		"<memory_deposition_events_tail>",
		truncateMiddle(readText(memoryDepositionEventBusPath()), 1800),
		"</memory_deposition_events_tail>",
		"<memory_experience_engine_v8>",
		truncateMiddle(readText(memoryExperienceReportPath()), 2200),
		"</memory_experience_engine_v8>",
		"<memory_experience_lesson_book>",
		truncateMiddle(readText(memoryExperienceLessonBookPath()), 1800),
		"</memory_experience_lesson_book>",
		"<memory_skill_capsule_v9>",
		truncateMiddle(readText(memorySkillCapsuleReportPath()), 2200),
		"</memory_skill_capsule_v9>",
		"<memory_skill_capsule_book>",
		truncateMiddle(readText(memorySkillCapsuleBookPath()), 1800),
		"</memory_skill_capsule_book>",
		"<memory_distill_promotion_v10>",
		truncateMiddle(readText(memoryDistillPromotionReportPath()), 2200),
		"</memory_distill_promotion_v10>",
		"<memory_distill_promotion_book>",
		truncateMiddle(readText(memoryDistillPromotionBookPath()), 1800),
		"</memory_distill_promotion_book>",
		"<memory_quality_ledger_v11>",
		truncateMiddle(readText(memoryQualityReportPath()), 2200),
		"</memory_quality_ledger_v11>",
		"<memory_quality_board>",
		truncateMiddle(readText(memoryQualityBoardPath()), 1600),
		"</memory_quality_board>",
		"<memory_replay_evaluator_v12>",
		truncateMiddle(readText(memoryReplayEvaluatorReportPath()), 2200),
		"</memory_replay_evaluator_v12>",
		"<memory_replay_evaluator_board>",
		truncateMiddle(readText(memoryReplayEvaluatorBoardPath()), 1600),
		"</memory_replay_evaluator_board>",
		"<memory_strategy_capsule_v13>",
		truncateMiddle(readText(memoryStrategyCapsuleReportPath()), 2200),
		"</memory_strategy_capsule_v13>",
		"<memory_strategy_capsule_book>",
		truncateMiddle(readText(memoryStrategyCapsuleBookPath()), 1600),
		"</memory_strategy_capsule_book>",
		"<memory_active_kernel_v14>",
		truncateMiddle(readText(memoryActiveKernelReportPath()), 2400),
		"</memory_active_kernel_v14>",
		"<memory_active_injection_pack>",
		truncateMiddle(readText(memoryActiveInjectionPackPath()), 1800),
		"</memory_active_injection_pack>",
		"<memory_active_strategy_board>",
		truncateMiddle(readText(memoryActiveStrategyBoardPath()), 1400),
		"</memory_active_strategy_board>",
		"<memory_maturation_runtime_v15>",
		truncateMiddle(readText(memoryMaturationRuntimeReportPath()), 2200),
		"</memory_maturation_runtime_v15>",
		"<memory_maturation_action_board>",
		truncateMiddle(readText(memoryMaturationActionBoardPath()), 1400),
		"</memory_maturation_action_board>",
		"<compact_resume_ledger_v2>",
		truncateMiddle(readText(compactResumeLedgerV2ReportPath()), 2200),
		"</compact_resume_ledger_v2>",
		"<compact_resume_transitions_tail>",
		truncateMiddle(readText(compactResumeTransitionLedgerPath()), 1800),
		"</compact_resume_transitions_tail>",
		"<memory_vector_search>",
		truncateMiddle(readText(memoryVectorSearchReportPath()), 1800),
		"</memory_vector_search>",
		"<case_index>",
		truncateMiddle(readText(memoryPath("case-index.md")), 2000),
		"</case_index>",
		"<memory_sedimentation>",
		truncateMiddle(readText(memorySedimentationReportPath()), 2400),
		"</memory_sedimentation>",
		"<memory_supervisor>",
		truncateMiddle(readText(memorySupervisorReportPath()), 2400),
		"</memory_supervisor>",
		"<mandatory_memory_injection_packet>",
		truncateMiddle(readText(memoryInjectionPacketPath()), 2200),
		"</mandatory_memory_injection_packet>",
		"<field_journal_tail>",
		truncateMiddle(readText(memoryPath("field-journal.md")), 3600),
		"</field_journal_tail>",
		"<evolution_log_tail>",
		truncateMiddle(readText(memoryPath("evolution-log.md")), 1600),
		"</evolution_log_tail>",
	].join("\n");
}

export function buildStartupMemoryDigest(options: { route?: string; target?: string } = {}): string {
	const settings = repiMemorySettings();
	if (settings.mode === "off" || settings.startupDigest === "off") return "memory_startup: disabled";
	if (settings.rawAutoInject && settings.autoInject && settings.startupDigest === "full") {
		return truncateMiddle(buildMemoryDigest(), settings.maxInjectedTokens * 4);
	}
	if (settings.autoRecall && settings.startupDigest === "scoped") {
		const target = concreteMemoryRecallTarget(options.target);
		if (!target) {
			return formatDeferredScopedMemoryRecall(settings, {
				route: options.route,
				target: options.target,
				reason: "no_concrete_target",
			});
		}
		return formatScopedMemoryRecallPacket({
			route: options.route,
			target,
			budgetTokens: settings.startupBudgetTokens,
			maxItems: settings.maxStartupItems,
		});
	}
	return formatMemoryIsolationStatus(settings, options);
}

export function buildContextMemoryTail(options: { route?: string; target?: string } = {}): string {
	const settings = repiMemorySettings();
	if (settings.includeGlobalMemoryInContextPack || settings.contextMemoryMode === "global") {
		return truncateMiddle(buildMemoryDigest(), settings.contextPackBudgetTokens * 4);
	}
	if (settings.contextMemoryMode === "scoped" && settings.autoRecall) {
		const target = concreteMemoryRecallTarget(options.target);
		if (!target) {
			return formatDeferredScopedMemoryRecall(settings, {
				route: options.route,
				target: options.target,
				reason: "context_pack_no_concrete_target",
			});
		}
		return formatScopedMemoryRecallPacket({
			route: options.route,
			target,
			budgetTokens: settings.contextPackBudgetTokens,
			maxItems: Math.max(settings.maxStartupItems, 6),
		});
	}
	return formatMemoryIsolationStatus(settings, options);
}
