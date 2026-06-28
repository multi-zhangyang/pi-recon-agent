import {
	type ArtifactScopeEvent,
	artifactScopeMatchForSource,
	artifactScopeVerdictPriority,
	knowledgeScopePathKey,
} from "./artifact-scope.ts";
import type {
	MemoryScopeIsolationReportV1,
	MemoryScopeIsolationRowV1,
	RepiMemoryScope,
	RepiScopeVerdict,
} from "./memory-scope.ts";

export type KnowledgeScopeSource = {
	kind: string;
	path: string;
	text: string;
};

export type KnowledgeScopeIsolationSourceV1 = {
	path: string;
	kind: string;
	eventId?: string;
	caseSignature?: string;
	verdict: RepiScopeVerdict;
	reasons: string[];
	blocksKnowledgeReuse: boolean;
};

export type KnowledgeScopeIsolationV1 = {
	kind: "repi-knowledge-scope-isolation";
	schemaVersion: 1;
	MemoryScopeIsolationV1: true;
	scope_filter_by_mission_session_workspace_target: true;
	reportPath: string;
	currentScope: RepiMemoryScope;
	checkedSourceCount: number;
	blockedSourceCount: number;
	warnSourceCount: number;
	allowedSourceCount: number;
	blockedEventIds: string[];
	warnEventIds: string[];
	allowedEventIds: string[];
	quarantinedSourceArtifacts: string[];
	warnSourceArtifacts: string[];
	allowedSourceArtifacts: string[];
	sourceRows: KnowledgeScopeIsolationSourceV1[];
	requiredChecks: string[];
};

export type KnowledgeScopeIsolationBuildOptions = {
	sources: KnowledgeScopeSource[];
	events: ArtifactScopeEvent[];
	memoryScopeReport: MemoryScopeIsolationReportV1;
};

export function knowledgeScopeRowForSource(
	source: KnowledgeScopeSource,
	rows: MemoryScopeIsolationRowV1[],
	byArtifactPath: Map<string, MemoryScopeIsolationRowV1>,
): MemoryScopeIsolationRowV1 | undefined {
	return artifactScopeMatchForSource(source, rows, byArtifactPath).row;
}

export function buildKnowledgeScopeIsolation(options: KnowledgeScopeIsolationBuildOptions): KnowledgeScopeIsolationV1 {
	const rowsByEvent = new Map(options.memoryScopeReport.rows.map((row) => [row.eventId, row]));
	const byArtifactPath = new Map<string, MemoryScopeIsolationRowV1>();
	for (const event of options.events) {
		const row = rowsByEvent.get(event.id);
		if (!row) continue;
		for (const artifact of event.artifactHashes) {
			const key = knowledgeScopePathKey(artifact.path);
			const existing = byArtifactPath.get(key);
			if (!existing || artifactScopeVerdictPriority(row.verdict) > artifactScopeVerdictPriority(existing.verdict)) {
				byArtifactPath.set(key, row);
			}
		}
	}
	const sourceRows = options.sources.map((source): KnowledgeScopeIsolationSourceV1 => {
		const row = knowledgeScopeRowForSource(source, options.memoryScopeReport.rows, byArtifactPath);
		const verdict = row?.verdict ?? "allow";
		const reasons = row?.reasons ?? [];
		return {
			path: source.path,
			kind: source.kind,
			eventId: row?.eventId,
			caseSignature: row?.caseSignature,
			verdict,
			reasons,
			blocksKnowledgeReuse: verdict === "block",
		};
	});
	return {
		kind: "repi-knowledge-scope-isolation",
		schemaVersion: 1,
		MemoryScopeIsolationV1: true,
		scope_filter_by_mission_session_workspace_target: true,
		reportPath: options.memoryScopeReport.scopeIsolationReportPath,
		currentScope: options.memoryScopeReport.currentScope,
		checkedSourceCount: sourceRows.length,
		blockedSourceCount: sourceRows.filter((row) => row.verdict === "block").length,
		warnSourceCount: sourceRows.filter((row) => row.verdict === "warn").length,
		allowedSourceCount: sourceRows.filter((row) => row.verdict === "allow").length,
		blockedEventIds: options.memoryScopeReport.blockedEventIds,
		warnEventIds: options.memoryScopeReport.warnEventIds,
		allowedEventIds: options.memoryScopeReport.allowedEventIds,
		quarantinedSourceArtifacts: sourceRows.filter((row) => row.verdict === "block").map((row) => row.path),
		warnSourceArtifacts: sourceRows.filter((row) => row.verdict === "warn").map((row) => row.path),
		allowedSourceArtifacts: sourceRows.filter((row) => row.verdict === "allow").map((row) => row.path),
		sourceRows,
		requiredChecks: [
			"KnowledgeScopeIsolationV1",
			"MemoryScopeIsolationV1",
			"scope_filter_by_mission_session_workspace_target",
			"knowledge_graph_scope_filter_blocks_quarantined_artifacts",
			"knowledge_graph_command_hints_exclude_scope_blocked_sources",
			"knowledge_scope_isolation_report_in_artifact",
		],
	};
}
