import { jsonlRecords } from "./jsonl.ts";
import { isMemoryArtifactHash, type MemoryArtifactHash, type MemoryOutcome } from "./memory-event.ts";
import { verifyMemoryStore, writeFileAtomic } from "./memory-store.ts";
import {
	ensureRepiStorage,
	memoryDepositionEventBusPath,
	memoryDepositionReportPath,
	memoryEventsPath,
	memoryStoreReportPath,
} from "./storage.ts";
import { sha256Text, truncateMiddle, uniqueNonEmpty } from "./text.ts";

export type MemoryDepositionStageV7 =
	| "tool"
	| "shell"
	| "agent"
	| "swarm-worker"
	| "compact-resume"
	| "claim"
	| "manual"
	| "memory-event";

export type MemoryDepositionStatusV7 = "queued" | "written" | "skipped" | "blocked";

export type MemoryDepositionRuntimeEventV7 = {
	kind: "repi-memory-deposition-runtime-event";
	schemaVersion: 1;
	id: string;
	seq: number;
	ts: string;
	MemoryDepositionEngineV7: true;
	stage: MemoryDepositionStageV7;
	source: string;
	status: MemoryDepositionStatusV7;
	task: string;
	route: string;
	target?: string;
	command?: string;
	stdoutSha256?: string;
	stderrSha256?: string;
	exitCode?: number;
	outcome: MemoryOutcome;
	confidence: number;
	artifactHashes: MemoryArtifactHash[];
	claimIds: string[];
	compactResumeId?: string;
	lessons: string[];
	failurePatterns: string[];
	reuseRules: string[];
	commands: string[];
	memoryEventId?: string;
	caseSignature?: string;
	reason: string;
	prevHash: string;
	entryHash: string;
};

export type MemoryDepositionReportV7 = {
	kind: "repi-memory-deposition-report";
	schemaVersion: 1;
	generatedAt: string;
	MemoryDepositionEngineV7: true;
	runtime_step_event_bus: true;
	post_tool_writeback_autocapture: true;
	depositionReportPath: string;
	depositionEventBusPath: string;
	memoryEventsPath: string;
	storeReportPath: string;
	runtimeEventCount: number;
	memoryWritebackCount: number;
	pendingWritebackCount: number;
	blockedWritebackCount: number;
	skippedWritebackCount: number;
	autoWritebackCoverage: number;
	status: "pass" | "warn" | "blocked" | "empty";
	latestRuntimeEventHash: string;
	storeGrade: "pass" | "repairable" | "blocked";
	recentEvents: MemoryDepositionRuntimeEventV7[];
	pendingEventIds: string[];
	blockedEventIds: string[];
	requiredChecks: string[];
	policy: {
		MemoryDepositionEngineV7: true;
		runtimeStepEventBus: true;
		postToolWritebackAutocapture: true;
		appendOnlyDepositionLedger: true;
		memoryEventHashBinding: true;
		claimCompactResumeBinding: true;
	};
	nextCommands: string[];
};

export type MemoryDepositionRuntimeInputV7 = {
	stage?: MemoryDepositionStageV7;
	source?: string;
	status?: MemoryDepositionStatusV7;
	task?: string;
	route?: string;
	target?: string;
	command?: string;
	stdout?: string;
	stderr?: string;
	stdoutSha256?: string;
	stderrSha256?: string;
	exitCode?: number;
	outcome?: MemoryOutcome;
	confidence?: number;
	artifactPaths?: string[];
	artifacts?: MemoryArtifactHash[];
	claimIds?: string[];
	compactResumeId?: string;
	lessons?: string[];
	failurePatterns?: string[];
	reuseRules?: string[];
	commands?: string[];
	memoryEventId?: string;
	caseSignature?: string;
	reason?: string;
	replayVerified?: boolean;
	playbookCandidate?: boolean;
	verifierRuleCandidate?: boolean;
};

export function isMemoryDepositionRuntimeEvent(value: unknown): value is MemoryDepositionRuntimeEventV7 {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const row = value as MemoryDepositionRuntimeEventV7;
	return (
		row.kind === "repi-memory-deposition-runtime-event" &&
		row.schemaVersion === 1 &&
		row.MemoryDepositionEngineV7 === true &&
		typeof row.id === "string" &&
		Number.isInteger(row.seq) &&
		typeof row.ts === "string" &&
		typeof row.stage === "string" &&
		typeof row.source === "string" &&
		typeof row.status === "string" &&
		typeof row.task === "string" &&
		typeof row.route === "string" &&
		typeof row.outcome === "string" &&
		typeof row.confidence === "number" &&
		Array.isArray(row.artifactHashes) &&
		row.artifactHashes.every(isMemoryArtifactHash) &&
		Array.isArray(row.claimIds) &&
		Array.isArray(row.lessons) &&
		Array.isArray(row.failurePatterns) &&
		Array.isArray(row.reuseRules) &&
		Array.isArray(row.commands) &&
		typeof row.reason === "string" &&
		typeof row.prevHash === "string" &&
		typeof row.entryHash === "string"
	);
}

export function memoryDepositionEventHash(event: MemoryDepositionRuntimeEventV7): string {
	const { entryHash: _entryHash, ...withoutHash } = event;
	return sha256Text(JSON.stringify(withoutHash));
}

export function memoryDepositionHashChainOk(events: MemoryDepositionRuntimeEventV7[]): boolean {
	let prevHash = "0".repeat(64);
	for (const event of events) {
		if (event.prevHash !== prevHash) return false;
		if (event.entryHash !== memoryDepositionEventHash(event)) return false;
		prevHash = event.entryHash;
	}
	return true;
}

export function readMemoryDepositionEvents(): MemoryDepositionRuntimeEventV7[] {
	ensureRepiStorage();
	return jsonlRecords(memoryDepositionEventBusPath(), isMemoryDepositionRuntimeEvent);
}

export function buildMemoryDepositionReport(options: { write?: boolean } = {}): MemoryDepositionReportV7 {
	ensureRepiStorage();
	const events = readMemoryDepositionEvents();
	const store = verifyMemoryStore({ write: options.write });
	const hashChainOk = memoryDepositionHashChainOk(events);
	const memoryWritebackCount = events.filter((event) => event.memoryEventId && event.status === "written").length;
	const pending = events.filter((event) => event.status === "queued" || !event.memoryEventId);
	const blocked = events.filter((event) => event.status === "blocked");
	const skipped = events.filter((event) => event.status === "skipped");
	const autoWritebackCoverage = events.length ? Number((memoryWritebackCount / events.length).toFixed(4)) : 0;
	const status =
		events.length === 0
			? "empty"
			: store.storeGrade === "blocked" || !hashChainOk || blocked.length
				? "blocked"
				: pending.length || skipped.length || autoWritebackCoverage < 0.85
					? "warn"
					: "pass";
	const report: MemoryDepositionReportV7 = {
		kind: "repi-memory-deposition-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		MemoryDepositionEngineV7: true,
		runtime_step_event_bus: true,
		post_tool_writeback_autocapture: true,
		depositionReportPath: memoryDepositionReportPath(),
		depositionEventBusPath: memoryDepositionEventBusPath(),
		memoryEventsPath: memoryEventsPath(),
		storeReportPath: memoryStoreReportPath(),
		runtimeEventCount: events.length,
		memoryWritebackCount,
		pendingWritebackCount: pending.length,
		blockedWritebackCount: blocked.length,
		skippedWritebackCount: skipped.length,
		autoWritebackCoverage,
		status,
		latestRuntimeEventHash: events.at(-1)?.entryHash ?? "0".repeat(64),
		storeGrade: store.storeGrade,
		recentEvents: events.slice(-12),
		pendingEventIds: pending.map((event) => event.id).slice(0, 80),
		blockedEventIds: blocked.map((event) => event.id).slice(0, 80),
		requiredChecks: [
			"MemoryDepositionEngineV7",
			"runtime_step_event_bus",
			"post_tool_writeback_autocapture",
			"append_only_deposition_ledger",
			"memory_event_hash_binding",
			"claim_compact_resume_binding",
			"deposition_report_in_context_pack",
		],
		policy: {
			MemoryDepositionEngineV7: true,
			runtimeStepEventBus: true,
			postToolWritebackAutocapture: true,
			appendOnlyDepositionLedger: true,
			memoryEventHashBinding: true,
			claimCompactResumeBinding: true,
		},
		nextCommands: uniqueNonEmpty(
			[
				status === "blocked" ? "re_memory verify" : undefined,
				pending.length
					? 're_memory deposit status=written artifactPath=<artifact> "runtime result + evidence hash"'
					: undefined,
				"re_memory orchestrate post-tool",
				"re_memory feedback",
				"re_memory supervise",
				"re_context pack",
			].filter(Boolean) as string[],
			12,
		),
	};
	if (options.write !== false) writeFileAtomic(memoryDepositionReportPath(), `${JSON.stringify(report, null, 2)}\n`);
	return report;
}

export function formatMemoryDepositionReport(report = buildMemoryDepositionReport()): string {
	return [
		"memory_deposition_engine_v7:",
		`MemoryDepositionEngineV7=${report.MemoryDepositionEngineV7}`,
		`runtime_step_event_bus=${report.runtime_step_event_bus}`,
		`post_tool_writeback_autocapture=${report.post_tool_writeback_autocapture}`,
		`status=${report.status}`,
		`runtime_events=${report.runtimeEventCount}`,
		`memory_writebacks=${report.memoryWritebackCount}`,
		`pending_writebacks=${report.pendingWritebackCount}`,
		`blocked_writebacks=${report.blockedWritebackCount}`,
		`auto_writeback_coverage=${report.autoWritebackCoverage}`,
		`latest_runtime_event_hash=${report.latestRuntimeEventHash}`,
		`event_bus=${report.depositionEventBusPath}`,
		`report=${report.depositionReportPath}`,
		"recent_events:",
		...(report.recentEvents.length
			? report.recentEvents.map(
					(event) =>
						`- id=${event.id} stage=${event.stage} status=${event.status} outcome=${event.outcome} memory_event=${event.memoryEventId ?? "none"} command=${truncateMiddle(event.command ?? "none", 140)}`,
				)
			: ["- none"]),
		"next_commands:",
		...report.nextCommands.map((command) => `- ${command}`),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}
