import type { RepiMemoryScope, RepiScopeVerdict } from "./memory-scope.ts";
import { readCurrentMission } from "./mission.ts";
import { sanitizeTargetForCommand } from "./target.ts";

export function artifactScopeDefaultOptions(
	options: ArtifactScopeFilterOptions = {},
): Required<Pick<ArtifactScopeFilterOptions, "requestedBy">> &
	Pick<ArtifactScopeFilterOptions, "route" | "target" | "scanLimit" | "write"> {
	const mission = readCurrentMission();
	return {
		route: options.route ?? mission?.route.domain,
		target: sanitizeTargetForCommand(options.target) ?? artifactScopeInferTarget(mission?.task),
		requestedBy: options.requestedBy ?? "latest_artifact_side_channel",
		scanLimit: options.scanLimit,
		write: options.write,
	};
}

export type ArtifactScopeFilterDecisionV1 = {
	kind: "repi-artifact-scope-filter-decision";
	schemaVersion: 1;
	path: string;
	artifactKind: string;
	requestedBy: string;
	eventId?: string;
	caseSignature?: string;
	verdict: RepiScopeVerdict;
	reasons: string[];
	blocksArtifactReuse: boolean;
	recommendedAction: "allow" | "retain" | "quarantine" | "manual-review";
	matchedBy: "artifact-hash" | "text-reference" | "untracked";
};

export type ArtifactScopeFilterReportV1 = {
	kind: "repi-artifact-scope-filter-report";
	schemaVersion: 1;
	generatedAt: string;
	ArtifactScopeFilterV1: true;
	MemoryScopeIsolationV1: true;
	latest_artifact_side_channel_scope_filter: true;
	reportPath: string;
	requestedBy: string;
	currentScope: RepiMemoryScope;
	checkedArtifactCount: number;
	blockedArtifactCount: number;
	warnArtifactCount: number;
	allowedArtifactCount: number;
	quarantinedArtifacts: string[];
	warnArtifacts: string[];
	allowedArtifacts: string[];
	decisions: ArtifactScopeFilterDecisionV1[];
	requiredChecks: string[];
};

export type ArtifactScopeFilterOptions = {
	route?: string;
	target?: string;
	requestedBy?: string;
	scanLimit?: number;
	write?: boolean;
};

export type ArtifactScopeArtifact = {
	kind: string;
	path: string;
	text?: string;
};

export type ArtifactScopeEvent = {
	id: string;
	artifactHashes: Array<{ path: string }>;
};

export type ArtifactScopeMemoryRow = {
	eventId: string;
	caseSignature: string;
	verdict: RepiScopeVerdict;
	reasons: string[];
	eventScope?: {
		target?: string;
	};
};

export type ArtifactScopeMemoryReport<T extends ArtifactScopeMemoryRow = ArtifactScopeMemoryRow> = {
	currentScope: RepiMemoryScope;
	rows: T[];
};

export type ArtifactScopeReportBuildOptions<T extends ArtifactScopeMemoryRow = ArtifactScopeMemoryRow> = {
	target?: string;
	requestedBy: string;
	reportPath: string;
	artifacts: ArtifactScopeArtifact[];
	events: ArtifactScopeEvent[];
	memoryReport: ArtifactScopeMemoryReport<T>;
	memoryTargetScope: (target: string) => string;
	sanitizeTarget?: (target: string) => string | undefined;
	readText?: (path: string) => string;
	generatedAt?: string;
};

export type ScopedMarkdownArtifactSelectionOptions = {
	kind: string;
	limit: number;
	candidatePaths: string[];
	readText: (path: string) => string;
	truncateText: (text: string, limit: number) => string;
	buildReport: (artifacts: ArtifactScopeArtifact[]) => ArtifactScopeFilterReportV1;
};

export function knowledgeScopePathKey(path: string): string {
	return path.trim().replace(/\\/g, "/").toLowerCase();
}

export function artifactTargetMatches(target: string | undefined, artifactTarget: string | undefined): boolean {
	return !target || !artifactTarget || artifactTarget === target;
}

export function artifactScopeVerdictPriority(verdict: RepiScopeVerdict | undefined): number {
	if (verdict === "block") return 3;
	if (verdict === "warn") return 2;
	if (verdict === "allow") return 1;
	return 0;
}

export function artifactScopeInferTarget(text?: string): string | undefined {
	const value = String(text ?? "");
	const url = value.match(/https?:\/\/[^\s'"`<>)]+/i)?.[0];
	if (url) return url.replace(/[),.;]+$/, "");
	const host = value.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?\b/i)?.[0];
	return host;
}

export function artifactScopeMatchForSource<T extends ArtifactScopeMemoryRow>(
	source: { path: string; text?: string },
	rows: T[],
	byArtifactPath: Map<string, T>,
): { row?: T; matchedBy: ArtifactScopeFilterDecisionV1["matchedBy"] } {
	const direct = byArtifactPath.get(knowledgeScopePathKey(source.path));
	if (direct) return { row: direct, matchedBy: "artifact-hash" };
	const text = `${source.path}\n${source.text ?? ""}`;
	const matches = rows.filter(
		(row) =>
			text.includes(row.eventId) ||
			text.includes(row.caseSignature) ||
			(row.eventScope?.target && text.toLowerCase().includes(row.eventScope.target.toLowerCase())),
	);
	if (!matches.length) return { matchedBy: "untracked" };
	return {
		row:
			matches.find((row) => row.verdict === "block") ?? matches.find((row) => row.verdict === "warn") ?? matches[0],
		matchedBy: "text-reference",
	};
}

export function artifactExplicitTarget(
	source: { path: string; text?: string },
	options: { sanitizeTarget?: (target: string) => string | undefined; readText?: (path: string) => string } = {},
): string | undefined {
	const text = source.text ?? options.readText?.(source.path) ?? "";
	const match = /^(?:target|url):\s*(.+)$/im.exec(text)?.[1]?.trim();
	if (!match || /^<.*>$|none|missing$/i.test(match)) return undefined;
	return options.sanitizeTarget?.(match) ?? match;
}

export function artifactScopeDecisionMap(
	report: ArtifactScopeFilterReportV1,
): Map<string, ArtifactScopeFilterDecisionV1> {
	return new Map(report.decisions.map((decision) => [knowledgeScopePathKey(decision.path), decision]));
}

export function buildArtifactScopeFilterReport<T extends ArtifactScopeMemoryRow>(
	options: ArtifactScopeReportBuildOptions<T>,
): ArtifactScopeFilterReportV1 {
	const rowsByEvent = new Map(options.memoryReport.rows.map((row) => [row.eventId, row]));
	const byArtifactPath = new Map<string, T>();
	for (const event of options.events) {
		const row = rowsByEvent.get(event.id);
		if (!row) continue;
		for (const artifact of event.artifactHashes) {
			const key = knowledgeScopePathKey(artifact.path);
			const existing = byArtifactPath.get(key);
			if (!existing || artifactScopeVerdictPriority(row.verdict) > artifactScopeVerdictPriority(existing.verdict))
				byArtifactPath.set(key, row);
		}
	}
	const decisions = options.artifacts.map((artifact): ArtifactScopeFilterDecisionV1 => {
		const match = artifactScopeMatchForSource(artifact, options.memoryReport.rows, byArtifactPath);
		const row = match.row;
		const explicitTarget = artifactExplicitTarget(artifact, {
			sanitizeTarget: options.sanitizeTarget,
			readText: options.readText,
		});
		const target = options.target;
		const targetMismatch =
			target !== undefined &&
			explicitTarget !== undefined &&
			options.memoryTargetScope(explicitTarget) !== options.memoryTargetScope(target);
		const untrackedTargetScope = Boolean(target && !row && !explicitTarget);
		const verdict = targetMismatch ? "block" : untrackedTargetScope ? "warn" : (row?.verdict ?? "allow");
		const reasons = targetMismatch
			? [`artifact_target_mismatch:${explicitTarget}!=${target}`]
			: untrackedTargetScope
				? [`untracked_artifact_no_memory_scope_binding_for_target:${target}`]
				: (row?.reasons ?? ["untracked_artifact_no_memory_scope_binding"]);
		return {
			kind: "repi-artifact-scope-filter-decision",
			schemaVersion: 1,
			path: artifact.path,
			artifactKind: artifact.kind,
			requestedBy: options.requestedBy,
			eventId: row?.eventId,
			caseSignature: row?.caseSignature,
			verdict,
			reasons,
			blocksArtifactReuse: verdict === "block",
			recommendedAction: verdict === "block" ? "quarantine" : verdict === "warn" ? "manual-review" : "allow",
			matchedBy: match.matchedBy,
		};
	});
	return {
		kind: "repi-artifact-scope-filter-report",
		schemaVersion: 1,
		generatedAt: options.generatedAt ?? new Date().toISOString(),
		ArtifactScopeFilterV1: true,
		MemoryScopeIsolationV1: true,
		latest_artifact_side_channel_scope_filter: true,
		reportPath: options.reportPath,
		requestedBy: options.requestedBy,
		currentScope: options.memoryReport.currentScope,
		checkedArtifactCount: decisions.length,
		blockedArtifactCount: decisions.filter((row) => row.verdict === "block").length,
		warnArtifactCount: decisions.filter((row) => row.verdict === "warn").length,
		allowedArtifactCount: decisions.filter((row) => row.verdict === "allow").length,
		quarantinedArtifacts: decisions.filter((row) => row.verdict === "block").map((row) => row.path),
		warnArtifacts: decisions.filter((row) => row.verdict === "warn").map((row) => row.path),
		allowedArtifacts: decisions.filter((row) => row.verdict === "allow").map((row) => row.path),
		decisions,
		requiredChecks: [
			"ArtifactScopeFilterV1",
			"MemoryScopeIsolationV1",
			"latest_artifact_side_channel_scope_filter",
			"artifact_hash_path_matches_memory_scope",
			"blocked_latest_artifact_quarantined",
			"context_artifact_index_excludes_scope_blocked_artifacts",
			"artifact_scope_filter_report_in_context_pack",
		],
	};
}

export function scopedMarkdownArtifacts(options: ScopedMarkdownArtifactSelectionOptions): string[] {
	const artifacts = options.candidatePaths.map((path) => ({
		kind: options.kind,
		path,
		text: options.truncateText(options.readText(path), 7000),
	}));
	if (artifacts.length === 0) return [];
	const report = options.buildReport(artifacts);
	const decisions = artifactScopeDecisionMap(report);
	return artifacts
		.filter((artifact) => decisions.get(knowledgeScopePathKey(artifact.path))?.blocksArtifactReuse !== true)
		.slice(0, options.limit)
		.map((artifact) => artifact.path);
}

export function latestScopedMarkdownArtifact(
	options: Omit<ScopedMarkdownArtifactSelectionOptions, "limit">,
): string | undefined {
	return scopedMarkdownArtifacts({ ...options, limit: 1 })[0];
}

export function formatArtifactScopeFilter(report: ArtifactScopeFilterReportV1): string {
	return [
		"artifact_scope_filter:",
		`ArtifactScopeFilterV1=${report.ArtifactScopeFilterV1}`,
		`MemoryScopeIsolationV1=${report.MemoryScopeIsolationV1}`,
		`latest_artifact_side_channel_scope_filter=${report.latest_artifact_side_channel_scope_filter}`,
		`requested_by=${report.requestedBy}`,
		`current_target=${report.currentScope.target ?? "none"}`,
		`checked=${report.checkedArtifactCount}`,
		`blocked=${report.blockedArtifactCount}`,
		`warn=${report.warnArtifactCount}`,
		`allowed=${report.allowedArtifactCount}`,
		`report=${report.reportPath}`,
		"quarantined_artifacts:",
		...(report.quarantinedArtifacts.length ? report.quarantinedArtifacts.map((item) => `- ${item}`) : ["- none"]),
		"decisions:",
		...(report.decisions.length
			? report.decisions
					.slice(0, 24)
					.map(
						(row) =>
							`- kind=${row.artifactKind} verdict=${row.verdict} matched_by=${row.matchedBy} action=${row.recommendedAction} path=${row.path} reasons=${row.reasons.join(",") || "none"}`,
					)
			: ["- none"]),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}
