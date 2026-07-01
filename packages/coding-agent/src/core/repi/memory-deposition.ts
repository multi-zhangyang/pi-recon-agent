import { statSync } from "node:fs";
import { jsonlRecords } from "./jsonl.ts";
import { isMemoryArtifactHash, type MemoryArtifactHash, type MemoryOutcome } from "./memory-event.ts";
import { type MemoryStoreVerificationV1, verifyMemoryStore, writeFileAtomic } from "./memory-store.ts";
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

// opt #73 — deposition append seq/prevHash cache (read-side analog of opt #67's tool-trace
// prevHash cache). appendMemoryDepositionRuntimeEvent read the WHOLE deposition bus
// (readMemoryDepositionEvents → jsonlRecords, O(file) of a file that grows with every deposit)
// on EVERY append just to compute seq=events.length+1 + prevHash=events.at(-1).entryHash — the
// next append's seq IS the just-appended seq+1 and prevHash IS the just-appended entryHash
// (we are the ONLY append writer, serialized by withMemoryStoreLock). So a path-keyed cache
// makes the per-append read O(1) instead of O(file) (over D deposits → O(D²) read bytes → O(D)).
//
// Safety (mtime+size guard, the #65/#68/#70 pattern — NOT #67's bare trust): the cache entry
// stores the post-append stat (mtimeMs+size). On the next append a stat(2) confirms the file is
// unchanged since our last commit → cache hit. ANY external rewrite (sanitize, ensureRepiStorage
// init, manual deletion) changes mtime+size → cache miss → cold read. This is stricter than #67
// (which invalidates via rotation return value) because the deposition bus has multiple non-append
// writers (sanitize poison-cleanup rewrites the whole bus) with no piggyback invalidation hook.
// The stat guard is a universal invalidation — no enumerated invalidation sites needed. Worst case
// is a false MISS (state unchanged but stat differs — never a false HIT): a cold read, correct but
// slower. A false hit would require an external rewrite producing the exact same mtimeMs+size —
// astronomically unlikely, and the deposition chain is verified by memoryDepositionHashChainOk on
// report builds so a stale row would surface there (not silent). Path-keyed so a changed
// REPI_CODING_AGENT_DIR gets its own entry.
const depositionChainCache = new Map<string, { seq: number; lastHash: string; mtimeMs: number; size: number }>();

function depositionBusStat(path: string): { mtimeMs: number; size: number } | undefined {
	try {
		const st = statSync(path);
		return { mtimeMs: st.mtimeMs, size: st.size };
	} catch {
		return undefined;
	}
}

/** Returns { seq, prevHash } for the next deposition row. Cache hit (stat guard passes) → O(1);
 *  miss → cold read of the bus. The caller MUST commitDepositionChain(row.seq, row.entryHash)
 *  after the append succeeds so the next append hits. */
export function nextDepositionChain(): { seq: number; prevHash: string } {
	const path = memoryDepositionEventBusPath();
	const cached = depositionChainCache.get(path);
	if (cached) {
		const st = depositionBusStat(path);
		if (st && st.mtimeMs === cached.mtimeMs && st.size === cached.size) {
			return { seq: cached.seq + 1, prevHash: cached.lastHash };
		}
	}
	const events = readMemoryDepositionEvents();
	return { seq: events.length + 1, prevHash: events.at(-1)?.entryHash ?? "0".repeat(64) };
}

/** Record the post-append chain state so the next append cache-hits. Stats the file to capture
 *  mtimeMs+size for the guard. If the stat fails (file vanished), drop the entry → next append
 *  cold-reads. */
export function commitDepositionChain(seq: number, lastHash: string): void {
	const path = memoryDepositionEventBusPath();
	const st = depositionBusStat(path);
	if (st) depositionChainCache.set(path, { seq, lastHash, mtimeMs: st.mtimeMs, size: st.size });
	else depositionChainCache.delete(path);
}

/** Drop the cached chain state. Belt-and-suspenders for the stat guard — call after any non-append
 *  rewrite of the bus (sanitize) so the next append doesn't depend on a stat tick landing. */
export function invalidateDepositionChainCache(): void {
	depositionChainCache.delete(memoryDepositionEventBusPath());
}

export function buildMemoryDepositionReport(
	options: { write?: boolean; store?: MemoryStoreVerificationV1 } = {},
): MemoryDepositionReportV7 {
	ensureRepiStorage();
	const events = readMemoryDepositionEvents();
	// opt #99 PERF-1 — reuse the orchestrator's in-hand store verdict instead of re-running
	// verifyMemoryStore (a 2nd full hash-chain walk). The store state is invariant within one
	// orchestration (no deposits happen mid-orchestration) → storeGrade is identical.
	const store = options.store ?? verifyMemoryStore({ write: options.write });
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
