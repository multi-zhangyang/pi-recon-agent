import { jsonlRecords } from "./jsonl.ts";
import type { MemoryEventV1 } from "./memory-event.ts";
import { buildMemoryQualityLedgerReport, type MemoryQualityLedgerReportV11 } from "./memory-quality.ts";
import { searchMemoryEvents } from "./memory-recall.ts";
import { memoryRouteMatches, memoryTargetScope } from "./memory-scope.ts";
import { type MemoryRetrievalHit, readMemoryEvents } from "./memory-search.ts";
import { writeFileAtomic } from "./memory-store.ts";
import { type MemoryUsefulnessEvalReportV1, memoryUsefulnessQueryForEvent } from "./memory-usefulness.ts";
import {
	ensureRepiStorage,
	memoryQualityReportPath,
	memoryReplayEvaluatorBoardPath,
	memoryReplayEvaluatorLedgerPath,
	memoryReplayEvaluatorReportPath,
	memoryRetrievalReportPath,
	memoryUsefulnessEvalReportPath,
	memoryVectorSearchReportPath,
	readJsonObjectFile,
	readTextFile as readText,
} from "./storage.ts";
import { sha256Text, uniqueNonEmpty } from "./text.ts";

export type MemoryReplayVerdictV12 = "improves" | "neutral" | "regresses" | "blocked";

export type MemoryReplayScenarioV12 = {
	id: string;
	query: string;
	route?: string;
	target?: string;
	expectedEventIds: string[];
	forbiddenEventIds: string[];
	topK: number;
	source: "default-from-memory" | "usefulness-eval" | "operator" | "fixture";
};

export type MemoryReplayEvaluatorRowV12 = {
	kind: "repi-memory-replay-evaluator-row";
	schemaVersion: 1;
	seq: number;
	id: string;
	ts: string;
	MemoryReplayEvaluatorV12: true;
	memory_ab_replay: true;
	causal_attribution_signal: true;
	scenarioId: string;
	query: string;
	route?: string;
	target?: string;
	expectedEventIds: string[];
	forbiddenEventIds: string[];
	controlHitIds: string[];
	treatmentHitIds: string[];
	attributionEventIds: string[];
	regressionEventIds: string[];
	qualityPromotedEventIds: string[];
	qualityDemotedEventIds: string[];
	controlPlanStepsEstimate: number;
	treatmentPlanStepsEstimate: number;
	savedStepEstimate: number;
	toolCallDeltaEstimate: number;
	successLift: number;
	poisonRegressionCount: number;
	causalScore: number;
	verdict: MemoryReplayVerdictV12;
	evidenceRefs: string[];
	feedbackWritebackCommands: string[];
	prevHash: string;
	entryHash: string;
};

export type MemoryReplayEvaluatorReportV12 = {
	kind: "repi-memory-replay-evaluator-report";
	schemaVersion: 1;
	generatedAt: string;
	MemoryReplayEvaluatorV12: true;
	memory_ab_replay: true;
	causal_attribution_signal: true;
	replay_delta_feedback_writeback: true;
	reportPath: string;
	ledgerPath: string;
	boardPath: string;
	sourceQualityReportPath: string;
	sourceUsefulnessEvalReportPath: string;
	scenarioCount: number;
	rowCount: number;
	improvedScenarioIds: string[];
	neutralScenarioIds: string[];
	regressedScenarioIds: string[];
	blockedScenarioIds: string[];
	attributionEventIds: string[];
	regressionEventIds: string[];
	averageCausalScore: number;
	totalSavedStepEstimate: number;
	operatorInjectionCommands: string[];
	avoidCommands: string[];
	status: "pass" | "warn" | "blocked" | "empty";
	rows: MemoryReplayEvaluatorRowV12[];
	requiredChecks: string[];
	policy: {
		MemoryReplayEvaluatorV12: true;
		memoryAbReplay: true;
		causalAttributionSignal: true;
		replayDeltaFeedbackWriteback: true;
		appendOnlyReplayLedger: true;
		qualityLedgerConsumesReplay: true;
	};
	nextCommands: string[];
};

export function memoryReplayEvaluatorRowHash(row: MemoryReplayEvaluatorRowV12): string {
	const { entryHash: _entryHash, ...withoutHash } = row;
	return sha256Text(JSON.stringify(withoutHash));
}

export function isMemoryReplayEvaluatorRow(value: unknown): value is MemoryReplayEvaluatorRowV12 {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const row = value as MemoryReplayEvaluatorRowV12;
	return (
		row.kind === "repi-memory-replay-evaluator-row" &&
		row.schemaVersion === 1 &&
		row.MemoryReplayEvaluatorV12 === true &&
		row.memory_ab_replay === true &&
		row.causal_attribution_signal === true &&
		Number.isInteger(row.seq) &&
		typeof row.id === "string" &&
		typeof row.ts === "string" &&
		typeof row.scenarioId === "string" &&
		typeof row.query === "string" &&
		Array.isArray(row.expectedEventIds) &&
		Array.isArray(row.treatmentHitIds) &&
		Array.isArray(row.attributionEventIds) &&
		Array.isArray(row.regressionEventIds) &&
		typeof row.causalScore === "number" &&
		typeof row.verdict === "string" &&
		Array.isArray(row.feedbackWritebackCommands) &&
		typeof row.prevHash === "string" &&
		typeof row.entryHash === "string"
	);
}

export function memoryReplayCausalSignals(
	report?: MemoryReplayEvaluatorReportV12,
): Map<string, { lift: number; regressions: number; score: number }> {
	const signals = new Map<string, { lift: number; regressions: number; score: number }>();
	for (const row of report?.rows ?? []) {
		for (const eventId of row.attributionEventIds ?? []) {
			const current = signals.get(eventId) ?? { lift: 0, regressions: 0, score: 0 };
			current.lift += Math.max(0, row.successLift);
			current.score = Math.max(current.score, row.causalScore);
			signals.set(eventId, current);
		}
		for (const eventId of row.regressionEventIds ?? []) {
			const current = signals.get(eventId) ?? { lift: 0, regressions: 0, score: 0 };
			current.regressions += 1;
			current.score = Math.max(current.score, row.causalScore);
			signals.set(eventId, current);
		}
	}
	return signals;
}

export function formatMemoryReplayEvaluator(report: MemoryReplayEvaluatorReportV12): string {
	return [
		"memory_replay_evaluator_v12:",
		`MemoryReplayEvaluatorV12=${report.MemoryReplayEvaluatorV12}`,
		`memory_ab_replay=${report.memory_ab_replay}`,
		`causal_attribution_signal=${report.causal_attribution_signal}`,
		`replay_delta_feedback_writeback=${report.replay_delta_feedback_writeback}`,
		`status=${report.status}`,
		`scenarios=${report.scenarioCount}`,
		`rows=${report.rowCount}`,
		`average_causal_score=${report.averageCausalScore}`,
		`total_saved_step_estimate=${report.totalSavedStepEstimate}`,
		`improved=${report.improvedScenarioIds.length}`,
		`regressed=${report.regressedScenarioIds.length}`,
		`blocked=${report.blockedScenarioIds.length}`,
		`attribution_events=${report.attributionEventIds.length}`,
		`regression_events=${report.regressionEventIds.length}`,
		`report=${report.reportPath}`,
		`ledger=${report.ledgerPath}`,
		`board=${report.boardPath}`,
		"operator_injection_commands:",
		...(report.operatorInjectionCommands.length
			? report.operatorInjectionCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"avoid_commands:",
		...(report.avoidCommands.length
			? report.avoidCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"replay_rows:",
		...(report.rows.length
			? report.rows
					.slice(0, 12)
					.map(
						(row) =>
							`- scenario=${row.scenarioId} verdict=${row.verdict} causal=${row.causalScore} saved_steps=${row.savedStepEstimate} attr=${row.attributionEventIds.join(",") || "none"} regress=${row.regressionEventIds.join(",") || "none"}`,
					)
			: ["- none"]),
		"next_commands:",
		...report.nextCommands.map((command) => `- ${command}`),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}

export function readMemoryReplayEvaluatorRows(): MemoryReplayEvaluatorRowV12[] {
	ensureRepiStorage();
	return jsonlRecords(memoryReplayEvaluatorLedgerPath(), isMemoryReplayEvaluatorRow);
}

// opt F5 — replay evaluator ledger rotation (sibling of #88 deposition bus rotation + #48
// tool-trace ledger rotation + F4 quality ledger rotation). The replay ledger
// (replay-evaluator-ledger.jsonl) is append-only with a contiguous prevHash chain, but it has
// NO genesis-strict verifier (isMemoryReplayEvaluatorRow is structural only; no
// memoryReplayHashChainOk exists) and the seq+prevHash for the next append are derived from
// readMemoryReplayEvaluatorRows() each call (no #73-style chain cache).
// buildMemoryReplayEvaluatorReport({write:true}) appends a fresh row per scenario (up to 24)
// on every orchestration call → the file grows unbounded and never rotates;
// readMemoryReplayEvaluatorRows reads the whole file on every cold read. Readers
// (previousRows.at(-1) for chain continuity only) → HEAD IS DISPOSABLE → rotation-safe (same
// contract as #88). Cap at REPI_REPLAY_LEDGER_MAX_ROWS (default 500, 0=disable); when the
// just-appended batch's last seq exceeds maxRows + REPI_REPLAY_LEDGER_ROTATE_BATCH (default
// 50), rotateReplayLedgerIfNeeded drops the head rows, keeps the last maxRows, RENUMBERS seq
// to 1..kept (seq IS part of entryHash via memoryReplayEvaluatorRowHash, which hashes every
// field except entryHash), recomputes prevHash from "0".repeat(64) and entryHash via the
// row-hash function over the kept tail, and atomically rewrites the ledger (writeFileAtomic
// temp+rename 0o600, matching the existing write path). The batch trigger fires once per
// orchestration call (not per row) so the hot-path write stays a single read-modify-write;
// the O(maxRows) rotation read+rewrite+rehash amortizes to O(maxRows/batch) per call. There
// is no cache for this ledger (readMemoryReplayEvaluatorRows reads directly, and no
// cachedJsonlDerived derived cache wraps it) → no re-warm is needed. Returns the rotated rows
// when it rewrote the file, else null.
function replayLedgerMaxRows(): number {
	const raw = Number(process.env.REPI_REPLAY_LEDGER_MAX_ROWS);
	if (Number.isFinite(raw) && raw >= 0) return Math.floor(raw);
	return 500;
}

function replayLedgerRotateBatch(): number {
	const raw = Number(process.env.REPI_REPLAY_LEDGER_ROTATE_BATCH);
	if (Number.isFinite(raw) && raw >= 0) return Math.floor(raw);
	return 50;
}

function rotateReplayLedgerIfNeeded(): MemoryReplayEvaluatorRowV12[] | null {
	const maxRows = replayLedgerMaxRows();
	if (maxRows <= 0) return null;
	const rows = readMemoryReplayEvaluatorRows();
	if (rows.length <= maxRows) return null;
	const kept = rows.slice(-maxRows);
	if (kept.length === 0) return null;
	let prevHash = "0".repeat(64);
	const rotated: MemoryReplayEvaluatorRowV12[] = [];
	for (let i = 0; i < kept.length; i++) {
		// Renumber seq to 1..kept.length — the next buildMemoryReplayEvaluatorReport call
		// derives seq from readMemoryReplayEvaluatorRows().length, so leaving the original
		// (large) seq values would make the next appended row's seq go backwards. seq is part
		// of the entryHash (memoryReplayEvaluatorRowHash hashes every field except entryHash),
		// so the renumber is correctly reflected in the recomputed hash + genesis-reset chain.
		const { entryHash: _omitHash, ...withoutHash } = kept[i];
		const rebuilt = { ...withoutHash, prevHash, seq: i + 1 };
		const newEntryHash = memoryReplayEvaluatorRowHash({ ...rebuilt, entryHash: "" });
		rotated.push({ ...rebuilt, entryHash: newEntryHash });
		prevHash = newEntryHash;
	}
	const body = `${rotated.map((row) => JSON.stringify(row)).join("\n")}\n`;
	writeFileAtomic(memoryReplayEvaluatorLedgerPath(), body);
	return rotated;
}

export function memoryReplayScenarios(
	events: MemoryEventV1[],
	usefulness?: MemoryUsefulnessEvalReportV1,
	options: { route?: string; target?: string; query?: string } = {},
): MemoryReplayScenarioV12[] {
	const scenarios: MemoryReplayScenarioV12[] = [];
	for (const scenario of usefulness?.scenarios ?? []) {
		if (options.route && scenario.route && !memoryRouteMatches(scenario.route, options.route)) continue;
		if (
			options.target &&
			scenario.target &&
			!memoryTargetScope(scenario.target).includes(memoryTargetScope(options.target))
		)
			continue;
		scenarios.push({
			id: `memory-replay-from-usefulness:${scenario.id}`,
			query: scenario.query,
			route: scenario.route,
			target: scenario.target,
			expectedEventIds: scenario.expectedEventIds,
			forbiddenEventIds: scenario.forbiddenEventIds,
			topK: scenario.topK,
			source: "usefulness-eval",
		});
	}
	if (options.query?.trim()) {
		const usefulIds = events
			.filter((event) => event.outcome !== "failure" && event.outcome !== "blocked")
			.sort((left, right) => right.quality.confidence - left.quality.confidence)
			.map((event) => event.id)
			.slice(0, 6);
		scenarios.push({
			id: `memory-replay-operator:${sha256Text(options.query).slice(0, 16)}`,
			query: options.query,
			route: options.route,
			target: options.target,
			expectedEventIds: usefulIds,
			forbiddenEventIds: events
				.filter((event) => event.outcome === "failure" || event.outcome === "blocked")
				.map((event) => event.id)
				.slice(0, 24),
			topK: 5,
			source: "operator",
		});
	}
	if (!scenarios.length) {
		for (const event of [...events]
			.filter(
				(candidate) =>
					candidate.outcome !== "failure" &&
					candidate.outcome !== "blocked" &&
					candidate.quality.confidence >= 0.5,
			)
			.sort(
				(left, right) =>
					Number(right.quality.replayVerified) - Number(left.quality.replayVerified) ||
					right.quality.confidence - left.quality.confidence ||
					right.seq - left.seq,
			)
			.slice(0, 10)) {
			scenarios.push({
				id: `memory-replay-default:${event.id}`,
				query: memoryUsefulnessQueryForEvent(event),
				route: event.route,
				target: event.target,
				expectedEventIds: [event.id],
				forbiddenEventIds: events
					.filter(
						(candidate) =>
							candidate.id !== event.id &&
							(candidate.route !== event.route ||
								candidate.outcome === "failure" ||
								candidate.outcome === "blocked"),
					)
					.map((candidate) => candidate.id)
					.slice(0, 24),
				topK: 3,
				source: "default-from-memory",
			});
		}
	}
	return scenarios.slice(0, 24);
}

export function buildMemoryReplayEvaluatorReport(
	options: {
		route?: string;
		target?: string;
		query?: string;
		quality?: MemoryQualityLedgerReportV11;
		usefulness?: MemoryUsefulnessEvalReportV1;
		write?: boolean;
	} = {},
): MemoryReplayEvaluatorReportV12 {
	ensureRepiStorage();
	const generatedAt = new Date().toISOString();
	const previousRows = readMemoryReplayEvaluatorRows();
	let prevHash = previousRows.at(-1)?.entryHash ?? "0".repeat(64);
	let seq = previousRows.length;
	const events = readMemoryEvents().filter((event) => {
		if (options.route && !memoryRouteMatches(event.route, options.route)) return false;
		if (
			options.target &&
			event.target &&
			!memoryTargetScope(event.target).includes(memoryTargetScope(options.target))
		)
			return false;
		return true;
	});
	const eventById = new Map(events.map((event) => [event.id, event]));
	const usefulness =
		options.usefulness ?? readJsonObjectFile<MemoryUsefulnessEvalReportV1>(memoryUsefulnessEvalReportPath());
	const quality =
		options.quality ??
		readJsonObjectFile<MemoryQualityLedgerReportV11>(memoryQualityReportPath()) ??
		buildMemoryQualityLedgerReport({ route: options.route, target: options.target, write: false });
	const qualityById = new Map((quality.rows ?? []).map((row) => [row.eventId, row]));
	const qualityPromoted = new Set([
		...(quality.promotedEventIds ?? []),
		...(quality.retainedEventIds ?? []).filter((eventId) => (qualityById.get(eventId)?.qualityScore ?? 0) >= 68),
	]);
	const qualityDemoted = new Set([
		...(quality.demotedEventIds ?? []),
		...(quality.quarantinedEventIds ?? []),
		...(quality.expiredEventIds ?? []),
	]);
	const scenarios = memoryReplayScenarios(events, usefulness, options);
	// opt #99 PERF-9 — memoize searchMemoryEvents by (query, route, target, limit) within a single
	// replay build. The replay evaluator generates up to 24 scenarios; several share the same
	// (query, route, target, limit) tuple. Without the memo each duplicate re-runs the full
	// lexical+vector scoring AND re-calls searchMemoryVectors (a 2nd embedding API call) for the
	// same inputs. The memo result is identical (pure function of inputs) and the retrieval-report
	// file side-effect is idempotent (same query/options → same hits; generatedAt is already
	// non-deterministic). The memo is local to this single build → no cross-build stale risk.
	const retrievalMemo = new Map<string, MemoryRetrievalHit[]>();
	const memoizedRetrieval = (
		query: string,
		route: string | undefined,
		target: string | undefined,
		limit: number,
	): MemoryRetrievalHit[] => {
		const key = `${query}\0${route ?? ""}\0${target ?? ""}\0${limit}`;
		const cached = retrievalMemo.get(key);
		if (cached) return cached;
		const hits = searchMemoryEvents(query, { route, target, limit });
		retrievalMemo.set(key, hits);
		return hits;
	};
	const rows: MemoryReplayEvaluatorRowV12[] = scenarios.map((scenario) => {
		const topK = Math.max(1, Math.min(10, Math.floor(scenario.topK || 3)));
		const treatmentHits = memoizedRetrieval(
			scenario.query,
			scenario.route ?? options.route,
			scenario.target ?? options.target,
			Math.max(topK, scenario.forbiddenEventIds.length ? 8 : topK),
		);
		const treatmentHitIds = treatmentHits.slice(0, Math.max(topK, 8)).map((hit) => hit.event.id);
		const topTreatmentIds = treatmentHitIds.slice(0, topK);
		const expectedHits = topTreatmentIds.filter((eventId) => scenario.expectedEventIds.includes(eventId));
		const qualityRegressionIds = topTreatmentIds.filter((eventId) => qualityDemoted.has(eventId));
		const forbiddenHits = topTreatmentIds.filter((eventId) => scenario.forbiddenEventIds.includes(eventId));
		const regressionEventIds = uniqueNonEmpty([...forbiddenHits, ...qualityRegressionIds], 24);
		const attributionEventIds = uniqueNonEmpty(
			expectedHits.length
				? expectedHits
				: topTreatmentIds
						.filter((eventId) => qualityPromoted.has(eventId) && !regressionEventIds.includes(eventId))
						.slice(0, 2),
			12,
		);
		const controlHitIds: string[] = [];
		const expectedDenominator = Math.max(1, scenario.expectedEventIds.length);
		const successLift = Number(
			(
				(expectedHits.length - controlHitIds.length) / expectedDenominator -
				regressionEventIds.length * 0.35
			).toFixed(4),
		);
		const avgQuality = attributionEventIds.length
			? attributionEventIds.reduce(
					(sum, eventId) =>
						sum + (qualityById.get(eventId)?.qualityScore ?? eventById.get(eventId)?.quality.confidence ?? 0),
					0,
				) / attributionEventIds.length
			: 0;
		const controlPlanStepsEstimate = Math.max(
			4,
			Math.min(14, 8 + Math.ceil(scenario.query.split(/\s+/).filter(Boolean).length / 8)),
		);
		const savedStepEstimateRaw = attributionEventIds.length
			? 1.5 + attributionEventIds.length * 1.25 + avgQuality / 28 - regressionEventIds.length * 2
			: 0;
		const savedStepEstimate = Number(
			Math.max(0, Math.min(controlPlanStepsEstimate - 2, savedStepEstimateRaw)).toFixed(2),
		);
		const treatmentPlanStepsEstimate = Number(Math.max(2, controlPlanStepsEstimate - savedStepEstimate).toFixed(2));
		const toolCallDeltaEstimate = Number((treatmentPlanStepsEstimate - controlPlanStepsEstimate).toFixed(2));
		const poisonRegressionCount = regressionEventIds.length;
		const causalScore = Number(
			Math.max(
				0,
				Math.min(
					100,
					50 +
						successLift * 42 +
						savedStepEstimate * 4 +
						Math.max(0, avgQuality - 65) * 0.16 -
						poisonRegressionCount * 38,
				),
			).toFixed(2),
		);
		const verdict: MemoryReplayVerdictV12 =
			poisonRegressionCount > 0
				? "regresses"
				: attributionEventIds.length && causalScore >= 62
					? "improves"
					: treatmentHitIds.length === 0
						? "blocked"
						: "neutral";
		const feedbackWritebackCommands =
			verdict === "improves"
				? attributionEventIds.map(
						(eventId) =>
							`re_memory append # memory_ab_replay_promote event=${eventId} causal_score=${causalScore}`,
					)
				: verdict === "regresses"
					? regressionEventIds.map(
							(eventId) =>
								`re_memory append # memory_ab_replay_demote event=${eventId} causal_score=${causalScore}`,
						)
					: ["re_memory replay"];
		const base: Omit<MemoryReplayEvaluatorRowV12, "entryHash"> = {
			kind: "repi-memory-replay-evaluator-row",
			schemaVersion: 1,
			seq: ++seq,
			id: `mr:${sha256Text(`${generatedAt}:${scenario.id}:${treatmentHitIds.join(",")}:${verdict}`).slice(0, 24)}`,
			ts: generatedAt,
			MemoryReplayEvaluatorV12: true,
			memory_ab_replay: true,
			causal_attribution_signal: true,
			scenarioId: scenario.id,
			query: scenario.query,
			route: scenario.route ?? options.route,
			target: scenario.target ?? options.target,
			expectedEventIds: scenario.expectedEventIds,
			forbiddenEventIds: scenario.forbiddenEventIds,
			controlHitIds,
			treatmentHitIds,
			attributionEventIds,
			regressionEventIds,
			qualityPromotedEventIds: attributionEventIds.filter((eventId) => qualityPromoted.has(eventId)),
			qualityDemotedEventIds: regressionEventIds.filter((eventId) => qualityDemoted.has(eventId)),
			controlPlanStepsEstimate,
			treatmentPlanStepsEstimate,
			savedStepEstimate,
			toolCallDeltaEstimate,
			successLift,
			poisonRegressionCount,
			causalScore,
			verdict,
			evidenceRefs: uniqueNonEmpty(
				[
					quality.reportPath ?? memoryQualityReportPath(),
					usefulness?.reportPath,
					memoryRetrievalReportPath(),
					memoryVectorSearchReportPath(),
				],
				12,
			),
			feedbackWritebackCommands: uniqueNonEmpty(feedbackWritebackCommands, 12),
			prevHash,
		};
		const row = { ...base, entryHash: "" };
		row.entryHash = memoryReplayEvaluatorRowHash(row);
		prevHash = row.entryHash;
		return row;
	});
	const byVerdict = (verdict: MemoryReplayVerdictV12) =>
		rows
			.filter((row) => row.verdict === verdict)
			.map((row) => row.scenarioId)
			.slice(0, 160);
	const attributionEventIds = uniqueNonEmpty(
		rows.flatMap((row) => row.attributionEventIds),
		160,
	);
	const regressionEventIds = uniqueNonEmpty(
		rows.flatMap((row) => row.regressionEventIds),
		160,
	);
	const averageCausalScore = rows.length
		? Number((rows.reduce((sum, row) => sum + row.causalScore, 0) / rows.length).toFixed(2))
		: 0;
	const totalSavedStepEstimate = Number(rows.reduce((sum, row) => sum + row.savedStepEstimate, 0).toFixed(2));
	const operatorInjectionCommands = uniqueNonEmpty(
		attributionEventIds.flatMap((eventId) => eventById.get(eventId)?.commands ?? []),
		24,
	);
	const avoidCommands = uniqueNonEmpty(
		regressionEventIds.flatMap((eventId) => eventById.get(eventId)?.commands ?? []),
		24,
	);
	const status: MemoryReplayEvaluatorReportV12["status"] =
		rows.length === 0
			? "empty"
			: rows.some((row) => row.verdict === "regresses")
				? "warn"
				: rows.some((row) => row.verdict === "blocked")
					? "blocked"
					: rows.some((row) => row.verdict === "improves")
						? "pass"
						: "warn";
	const report: MemoryReplayEvaluatorReportV12 = {
		kind: "repi-memory-replay-evaluator-report",
		schemaVersion: 1,
		generatedAt,
		MemoryReplayEvaluatorV12: true,
		memory_ab_replay: true,
		causal_attribution_signal: true,
		replay_delta_feedback_writeback: true,
		reportPath: memoryReplayEvaluatorReportPath(),
		ledgerPath: memoryReplayEvaluatorLedgerPath(),
		boardPath: memoryReplayEvaluatorBoardPath(),
		sourceQualityReportPath: quality.reportPath ?? memoryQualityReportPath(),
		sourceUsefulnessEvalReportPath: usefulness?.reportPath ?? memoryUsefulnessEvalReportPath(),
		scenarioCount: scenarios.length,
		rowCount: rows.length,
		improvedScenarioIds: byVerdict("improves"),
		neutralScenarioIds: byVerdict("neutral"),
		regressedScenarioIds: byVerdict("regresses"),
		blockedScenarioIds: byVerdict("blocked"),
		attributionEventIds,
		regressionEventIds,
		averageCausalScore,
		totalSavedStepEstimate,
		operatorInjectionCommands,
		avoidCommands,
		status,
		rows: rows.slice(0, 80),
		requiredChecks: [
			"MemoryReplayEvaluatorV12",
			"memory_ab_replay",
			"causal_attribution_signal",
			"replay_delta_feedback_writeback",
			"append_only_replay_ledger",
			"memory_replay_in_quality_ledger",
			"memory_replay_in_context_pack",
			"memory_replay_orchestrator_step",
		],
		policy: {
			MemoryReplayEvaluatorV12: true,
			memoryAbReplay: true,
			causalAttributionSignal: true,
			replayDeltaFeedbackWriteback: true,
			appendOnlyReplayLedger: true,
			qualityLedgerConsumesReplay: true,
		},
		nextCommands: uniqueNonEmpty(
			[
				"re_memory replay",
				"re_memory quality",
				regressionEventIds.length ? "re_memory supervise" : undefined,
				attributionEventIds.length ? "re_memory skills" : undefined,
				"re_context pack",
			].filter(Boolean) as string[],
			12,
		),
	};
	if (options.write !== false) {
		const before = readText(memoryReplayEvaluatorLedgerPath());
		const body = rows.map((row) => JSON.stringify(row)).join("\n");
		writeFileAtomic(
			memoryReplayEvaluatorLedgerPath(),
			`${before}${before && !before.endsWith("\n") ? "\n" : ""}${body}${body ? "\n" : ""}`,
		);
		writeFileAtomic(memoryReplayEvaluatorReportPath(), `${JSON.stringify(report, null, 2)}\n`);
		writeFileAtomic(
			memoryReplayEvaluatorBoardPath(),
			[
				"# REPI Memory Replay Evaluator Board",
				"",
				"MemoryReplayEvaluatorV12: true",
				"memory_ab_replay: true",
				"causal_attribution_signal: true",
				"replay_delta_feedback_writeback: true",
				`generated_at: ${report.generatedAt}`,
				`status: ${report.status}`,
				`average_causal_score: ${report.averageCausalScore}`,
				`total_saved_step_estimate: ${report.totalSavedStepEstimate}`,
				"",
				"## Improved Scenarios",
				...(report.improvedScenarioIds.length ? report.improvedScenarioIds.map((id) => `- ${id}`) : ["- none"]),
				"",
				"## Regressed / Blocked Scenarios",
				...(uniqueNonEmpty([...report.regressedScenarioIds, ...report.blockedScenarioIds], 120).length
					? uniqueNonEmpty([...report.regressedScenarioIds, ...report.blockedScenarioIds], 120).map(
							(id) => `- ${id}`,
						)
					: ["- none"]),
				"",
				"## Attribution Events",
				...(report.attributionEventIds.length ? report.attributionEventIds.map((id) => `- ${id}`) : ["- none"]),
				"",
				"## Required Checks",
				...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
				"",
			].join("\n"),
		);
		// opt F5 — rotate the replay ledger when it exceeds the row cap. Batched via
		// replayLedgerRotateBatch() so this only fires every `batch` rows past the cap (the
		// last appended row's seq is the new total row count; after a rotation rewrites the
		// ledger to maxRows rows with seq 1..maxRows, the next call's seq starts at maxRows+1,
		// so the trigger re-arms and fires once per batch). The kept tail is re-hashed from
		// genesis → the prevHash chain stays contiguous; previousRows.at(-1) for chain
		// continuity only → the dropped head is disposable.
		const _replayMaxRows = replayLedgerMaxRows();
		const _replayLastSeq = rows.at(-1)?.seq ?? 0;
		if (_replayMaxRows > 0 && _replayLastSeq > _replayMaxRows + replayLedgerRotateBatch()) {
			rotateReplayLedgerIfNeeded();
		}
	}
	return report;
}
