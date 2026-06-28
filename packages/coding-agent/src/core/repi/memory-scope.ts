import type { MemoryEventV1 } from "./memory-event.ts";
import { readMemoryEvents } from "./memory-search.ts";
import { writeFileAtomic } from "./memory-store.ts";
import { type MissionState, readCurrentMission } from "./mission.ts";
import { ensureRepiStorage, memoryScopeIsolationReportPath } from "./storage.ts";

export type RepiScopeVerdict = "allow" | "warn" | "block";

export type RepiMemoryScope = {
	kind: "repi-memory-scope";
	schemaVersion: 1;
	missionId?: string;
	sessionId: string;
	cwd: string;
	workspaceRoot: string;
	branchId: string;
	route?: string;
	target?: string;
};

export type RepiMemoryScopeMission = {
	id?: string;
};

export type MemoryScopeIsolationEvent = {
	id: string;
	caseSignature: string;
	memoryScope?: RepiMemoryScope;
};

export type MemoryScopeIsolationRowV1 = {
	kind: "repi-memory-scope-isolation-row";
	schemaVersion: 1;
	eventId: string;
	caseSignature: string;
	eventScope?: RepiMemoryScope;
	currentScope: RepiMemoryScope;
	verdict: RepiScopeVerdict;
	reasons: string[];
	blocksInjection: boolean;
	recommendedAction: "allow" | "retain" | "quarantine" | "manual-review";
};

export type MemoryScopeIsolationReportV1 = {
	kind: "repi-memory-scope-isolation-report";
	schemaVersion: 1;
	generatedAt: string;
	MemoryScopeIsolationV1: true;
	scopeIsolationReportPath: string;
	eventCount: number;
	currentScope: RepiMemoryScope;
	rows: MemoryScopeIsolationRowV1[];
	blockedEventIds: string[];
	warnEventIds: string[];
	allowedEventIds: string[];
	requiredChecks: string[];
};

export type BuildCurrentMemoryScopeOptions = {
	route?: string;
	target?: string;
	mission?: RepiMemoryScopeMission | null;
	cwd?: string;
	workspaceRoot?: string;
	env?: Record<string, string | undefined>;
};

export type BuildMemoryScopeIsolationReportOptions = {
	events: MemoryScopeIsolationEvent[];
	currentScope: RepiMemoryScope;
	scopeIsolationReportPath: string;
	generatedAt?: string;
};

export function memoryTargetScope(target?: string): string {
	const raw = String(target ?? "").trim();
	if (!raw) return "";
	try {
		return new URL(raw).host.toLowerCase();
	} catch {
		return raw.toLowerCase();
	}
}

export function memoryRouteMatches(eventRoute: string | undefined, route: string | undefined): boolean {
	const left = String(eventRoute ?? "")
		.trim()
		.toLowerCase();
	const right = String(route ?? "")
		.trim()
		.toLowerCase();
	if (!right) return true;
	if (!left) return false;
	return left === right || left.includes(right) || right.includes(left);
}

export function contextSessionId(
	mission?: RepiMemoryScopeMission | null,
	env: Record<string, string | undefined> = process.env,
): string {
	return mission?.id ?? env.REPI_SESSION_ID ?? env.SESSION_ID ?? "manual-session";
}

export function contextBranchId(env: Record<string, string | undefined> = process.env): string {
	return env.REPI_BRANCH_ID ?? env.GIT_BRANCH ?? env.BRANCH_NAME ?? "workspace";
}

export function buildCurrentMemoryScope(options: BuildCurrentMemoryScopeOptions = {}): RepiMemoryScope {
	const cwd = options.cwd ?? process.cwd();
	return {
		kind: "repi-memory-scope",
		schemaVersion: 1,
		missionId: options.mission?.id,
		sessionId: contextSessionId(options.mission, options.env),
		cwd,
		workspaceRoot: options.workspaceRoot ?? cwd,
		branchId: contextBranchId(options.env),
		route: options.route,
		target: options.target,
	};
}

export function currentMemoryScope(options?: {
	route?: string;
	target?: string;
	mission?: MissionState | null;
}): RepiMemoryScope {
	const mission = options?.mission === undefined ? readCurrentMission() : options.mission;
	return buildCurrentMemoryScope({
		route: options?.route,
		target: options?.target,
		mission,
	});
}

export function memoryScopeIsolationRow(
	event: MemoryScopeIsolationEvent,
	currentScope: RepiMemoryScope,
): MemoryScopeIsolationRowV1 {
	const eventScope = event.memoryScope;
	const reasons = [
		!eventScope ? "legacy_memory_scope_missing" : undefined,
		eventScope?.workspaceRoot && eventScope.workspaceRoot !== currentScope.workspaceRoot
			? "cross_workspace_contamination"
			: undefined,
		eventScope?.sessionId && eventScope.sessionId !== currentScope.sessionId
			? "cross_session_contamination"
			: undefined,
		eventScope?.branchId && eventScope.branchId !== currentScope.branchId ? "cross_branch_contamination" : undefined,
		currentScope.target &&
		eventScope?.target &&
		memoryTargetScope(eventScope.target) &&
		memoryTargetScope(currentScope.target) &&
		memoryTargetScope(eventScope.target) !== memoryTargetScope(currentScope.target)
			? "cross_target_contamination"
			: undefined,
		currentScope.route && eventScope?.route && !memoryRouteMatches(eventScope.route, currentScope.route)
			? "cross_route_contamination"
			: undefined,
	].filter((reason): reason is string => Boolean(reason));
	const uniqueReasons = Array.from(new Set(reasons)).slice(0, 12);
	const hardBlock = uniqueReasons.some((reason) => /cross_(?:workspace|target|route)_contamination/.test(reason));
	const verdict: RepiScopeVerdict = hardBlock
		? "block"
		: uniqueReasons.some((reason) =>
					/cross_(?:session|branch)_contamination|legacy_memory_scope_missing/.test(reason),
				)
			? "warn"
			: "allow";
	return {
		kind: "repi-memory-scope-isolation-row",
		schemaVersion: 1,
		eventId: event.id,
		caseSignature: event.caseSignature,
		eventScope,
		currentScope,
		verdict,
		reasons: uniqueReasons,
		blocksInjection: verdict === "block",
		recommendedAction:
			verdict === "block"
				? "quarantine"
				: verdict === "warn"
					? uniqueReasons.includes("legacy_memory_scope_missing")
						? "manual-review"
						: "retain"
					: "allow",
	};
}

export function buildRepiMemoryScopeIsolationReport(
	options: BuildMemoryScopeIsolationReportOptions,
): MemoryScopeIsolationReportV1 {
	const rows = options.events.map((event) => memoryScopeIsolationRow(event, options.currentScope));
	return {
		kind: "repi-memory-scope-isolation-report",
		schemaVersion: 1,
		generatedAt: options.generatedAt ?? new Date().toISOString(),
		MemoryScopeIsolationV1: true,
		scopeIsolationReportPath: options.scopeIsolationReportPath,
		eventCount: options.events.length,
		currentScope: options.currentScope,
		rows,
		blockedEventIds: rows.filter((row) => row.verdict === "block").map((row) => row.eventId),
		warnEventIds: rows.filter((row) => row.verdict === "warn").map((row) => row.eventId),
		allowedEventIds: rows.filter((row) => row.verdict === "allow").map((row) => row.eventId),
		requiredChecks: [
			"MemoryScopeIsolationV1",
			"scope_filter_by_mission_session_workspace_target",
			"cross_session_contamination_negative",
			"cross_workspace_contamination_blocks_injection",
			"cross_target_contamination_blocks_injection",
			"legacy_memory_scope_requires_manual_review",
			"scope_isolation_report_in_context_pack",
		],
	};
}

export function buildMemoryScopeIsolationReport(options?: {
	route?: string;
	target?: string;
	events?: MemoryEventV1[];
	write?: boolean;
}): MemoryScopeIsolationReportV1 {
	ensureRepiStorage();
	const events = options?.events ?? readMemoryEvents();
	const currentScope = currentMemoryScope({ route: options?.route, target: options?.target });
	const report = buildRepiMemoryScopeIsolationReport({
		scopeIsolationReportPath: memoryScopeIsolationReportPath(),
		currentScope,
		events,
	});
	if (options?.write !== false)
		writeFileAtomic(memoryScopeIsolationReportPath(), `${JSON.stringify(report, null, 2)}\n`);
	return report;
}

export function formatMemoryScopeIsolation(report: MemoryScopeIsolationReportV1): string {
	return [
		"memory_scope_isolation:",
		`MemoryScopeIsolationV1=${report.MemoryScopeIsolationV1}`,
		`events=${report.eventCount}`,
		`current_session=${report.currentScope.sessionId}`,
		`current_workspace=${report.currentScope.workspaceRoot}`,
		`current_target=${report.currentScope.target ?? "none"}`,
		`blocked=${report.blockedEventIds.length}`,
		`warn=${report.warnEventIds.length}`,
		`allowed=${report.allowedEventIds.length}`,
		`report=${report.scopeIsolationReportPath}`,
		"blocked_event_ids:",
		...(report.blockedEventIds.length ? report.blockedEventIds.map((id) => `- ${id}`) : ["- none"]),
		"warn_event_ids:",
		...(report.warnEventIds.length ? report.warnEventIds.map((id) => `- ${id}`) : ["- none"]),
		"rows:",
		...(report.rows.length
			? report.rows
					.slice(0, 16)
					.map(
						(row) =>
							`- event=${row.eventId} verdict=${row.verdict} action=${row.recommendedAction} reasons=${row.reasons.join(",") || "none"}`,
					)
			: ["- none"]),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}
