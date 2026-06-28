import type { MemoryEventV1, MemoryOutcome } from "./memory-event.ts";
import { searchMemoryEvents } from "./memory-recall.ts";
import { memorySearchTokens, readMemoryEvents } from "./memory-search.ts";
import { writeFileAtomic } from "./memory-store.ts";
import { ensureRepiStorage, memoryUsefulnessEvalReportPath } from "./storage.ts";
import { truncateMiddle, uniqueNonEmpty } from "./text.ts";

export type MemoryUsefulnessEvalScenarioV1 = {
	id: string;
	query: string;
	route?: string;
	target?: string;
	expectedEventIds: string[];
	forbiddenEventIds: string[];
	topK: number;
	source: "default-from-memory" | "operator" | "fixture";
};

export type MemoryUsefulnessEvalScenarioResultV1 = MemoryUsefulnessEvalScenarioV1 & {
	hits: Array<{ eventId: string; score: number; reasons: string[]; outcome: MemoryOutcome; route: string }>;
	expectedRank?: number;
	hitAt1: boolean;
	hitAtK: boolean;
	reciprocalRank: number;
	forbiddenHitIds: string[];
	status: "pass" | "warn" | "fail";
};

export type MemoryUsefulnessEvalReportV1 = {
	kind: "repi-memory-usefulness-eval";
	schemaVersion: 1;
	generatedAt: string;
	MemoryUsefulnessEvalV1: true;
	scenarioCount: number;
	scenarios: MemoryUsefulnessEvalScenarioResultV1[];
	aggregate: {
		hitAt1: number;
		hitAtK: number;
		mrr: number;
		forbiddenLeakRate: number;
		emptyScenarioRate: number;
		status: "pass" | "warn" | "fail" | "empty";
	};
	requiredChecks: string[];
	reportPath: string;
	recommendations: string[];
};

export function memoryUsefulnessQueryForEvent(event: MemoryEventV1): string {
	const tokens = uniqueNonEmpty(
		[
			...event.domainTags,
			...event.route.split(/\s+/),
			...event.lessons.flatMap((line) => [...memorySearchTokens(line)].slice(0, 8)),
			...event.reuseRules.flatMap((line) => [...memorySearchTokens(line)].slice(0, 8)),
			...event.commands.flatMap((line) => [...memorySearchTokens(line)].slice(0, 6)),
		],
		12,
	).filter((token) => token.length >= 2 && !/^(?:the|and|for|with|when|this|that|route|lane|run)$/i.test(token));
	return tokens.slice(0, 8).join(" ") || event.task || event.route;
}

export function defaultMemoryUsefulnessScenarios(events: MemoryEventV1[]): MemoryUsefulnessEvalScenarioV1[] {
	const recentUseful = [...events]
		.filter(
			(event) =>
				event.outcome !== "failure" &&
				event.outcome !== "blocked" &&
				event.quality.confidence >= 0.5 &&
				(event.lessons.length > 0 || event.reuseRules.length > 0 || event.commands.length > 0),
		)
		.sort(
			(left, right) =>
				Number(right.quality.replayVerified) - Number(left.quality.replayVerified) ||
				right.quality.confidence - left.quality.confidence ||
				right.seq - left.seq,
		)
		.slice(0, 10);
	return recentUseful.map((event, index) => {
		const forbiddenEventIds = events
			.filter(
				(candidate) =>
					candidate.id !== event.id &&
					(candidate.route !== event.route || candidate.outcome === "failure" || candidate.outcome === "blocked"),
			)
			.map((candidate) => candidate.id)
			.slice(0, 24);
		return {
			id: `default-memory-usefulness:${index + 1}:${event.id}`,
			query: memoryUsefulnessQueryForEvent(event),
			route: event.route,
			target: event.target,
			expectedEventIds: [event.id],
			forbiddenEventIds,
			topK: 3,
			source: "default-from-memory",
		};
	});
}

export function evaluateMemoryUsefulness(
	scenarios = defaultMemoryUsefulnessScenarios(readMemoryEvents()),
	options?: { write?: boolean },
): MemoryUsefulnessEvalReportV1 {
	ensureRepiStorage();
	const results: MemoryUsefulnessEvalScenarioResultV1[] = scenarios.map((scenario) => {
		const topK = Math.max(1, Math.min(10, Math.floor(scenario.topK || 3)));
		const hits = searchMemoryEvents(scenario.query, {
			route: scenario.route,
			target: scenario.target,
			limit: Math.max(topK, scenario.forbiddenEventIds.length ? 8 : topK),
		});
		const hitRows = hits.map((hit) => ({
			eventId: hit.event.id,
			score: Number(hit.score.toFixed(2)),
			reasons: hit.reasons,
			outcome: hit.event.outcome,
			route: hit.event.route,
		}));
		const expectedRank = hitRows.findIndex((hit) => scenario.expectedEventIds.includes(hit.eventId)) + 1 || undefined;
		const topIds = hitRows.slice(0, topK).map((hit) => hit.eventId);
		const forbiddenHitIds = topIds.filter((eventId) => scenario.forbiddenEventIds.includes(eventId));
		const hitAt1 = Boolean(expectedRank && expectedRank <= 1);
		const hitAtK = scenario.expectedEventIds.length === 0 ? true : Boolean(expectedRank && expectedRank <= topK);
		const reciprocalRank = expectedRank ? 1 / expectedRank : 0;
		const status = hitAtK && forbiddenHitIds.length === 0 ? "pass" : hitRows.length === 0 ? "warn" : "fail";
		return {
			...scenario,
			topK,
			hits: hitRows,
			expectedRank,
			hitAt1,
			hitAtK,
			reciprocalRank,
			forbiddenHitIds,
			status,
		};
	});
	const scenarioCount = results.length;
	const failCount = results.filter((scenario) => scenario.status === "fail").length;
	const warnCount = results.filter((scenario) => scenario.status === "warn").length;
	const aggregate = {
		hitAt1: scenarioCount
			? Number((results.filter((scenario) => scenario.hitAt1).length / scenarioCount).toFixed(4))
			: 0,
		hitAtK: scenarioCount
			? Number((results.filter((scenario) => scenario.hitAtK).length / scenarioCount).toFixed(4))
			: 0,
		mrr: scenarioCount
			? Number((results.reduce((sum, scenario) => sum + scenario.reciprocalRank, 0) / scenarioCount).toFixed(4))
			: 0,
		forbiddenLeakRate: scenarioCount
			? Number((results.filter((scenario) => scenario.forbiddenHitIds.length > 0).length / scenarioCount).toFixed(4))
			: 0,
		emptyScenarioRate: scenarioCount
			? Number((results.filter((scenario) => scenario.hits.length === 0).length / scenarioCount).toFixed(4))
			: 0,
		status:
			scenarioCount === 0
				? ("empty" as const)
				: failCount > 0 || results.some((scenario) => scenario.forbiddenHitIds.length > 0)
					? ("fail" as const)
					: warnCount > 0 || results.some((scenario) => !scenario.hitAt1)
						? ("warn" as const)
						: ("pass" as const),
	};
	const report: MemoryUsefulnessEvalReportV1 = {
		kind: "repi-memory-usefulness-eval",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		MemoryUsefulnessEvalV1: true,
		scenarioCount,
		scenarios: results,
		aggregate,
		requiredChecks: [
			"hit_at_1_or_warn",
			"hit_at_k_required",
			"forbidden_memory_not_in_top_k",
			"route_scope_blocks_cross_domain_recall",
			"memory_store_verified_before_eval",
		],
		reportPath: memoryUsefulnessEvalReportPath(),
		recommendations:
			aggregate.status === "pass"
				? ["keep re_memory eval in release checkpoints after memory schema changes"]
				: [
						"run re_memory verify and re_memory repair-index before trusting recall",
						"inspect forbiddenHitIds for cross-route or failure-dominant pollution",
						"add verifier/replay evidence or demote stale memories",
					],
	};
	if (options?.write !== false)
		writeFileAtomic(memoryUsefulnessEvalReportPath(), `${JSON.stringify(report, null, 2)}\n`);
	return report;
}

export function formatMemoryUsefulnessEval(report = evaluateMemoryUsefulness()): string {
	return [
		"memory_usefulness_eval:",
		`status=${report.aggregate.status}`,
		`scenarios=${report.scenarioCount}`,
		`hit_at_1=${report.aggregate.hitAt1}`,
		`hit_at_k=${report.aggregate.hitAtK}`,
		`mrr=${report.aggregate.mrr}`,
		`forbidden_leak_rate=${report.aggregate.forbiddenLeakRate}`,
		`report=${report.reportPath}`,
		"scenario_results:",
		...(report.scenarios.length
			? report.scenarios.map(
					(scenario) =>
						`- id=${scenario.id} status=${scenario.status} expected_rank=${scenario.expectedRank ?? "missing"} topK=${scenario.topK} forbidden_hits=${scenario.forbiddenHitIds.join(",") || "none"} query=${truncateMiddle(scenario.query, 140)}`,
				)
			: ["- none"]),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
		"recommendations:",
		...report.recommendations.map((item) => `- ${item}`),
	].join("\n");
}
