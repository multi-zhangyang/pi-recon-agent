import {
	appendFileSync,
	chmodSync,
	closeSync,
	existsSync,
	mkdirSync,
	openSync,
	readdirSync,
	readFileSync,
	readSync,
	statSync,
} from "node:fs";
import { join } from "node:path";
import { getAgentDir } from "../../config.ts";
import { resolvePath } from "../../utils/paths.ts";
import { atomicWriteFileSync } from "../tools/atomic-write.ts";

export function reconDir(): string {
	return join(getAgentDir(), "recon");
}

// --- Per-project memory scoping (opt #273) -------------------------------------
// Memory was GLOBAL (~/.repi/agent/recon/memory/) while sessions are per-cwd,
// so an agent run in project A distilled/recalled memory that polluted project B.
// Scope the memory tree per-cwd: when a session binds, setMemoryScopeCwd(cwd)
// routes ALL memory*Path() helpers under recon/memory/projects/<encoded-cwd>/.
// When no scope is set (standalone CLI tools / tests without a session), falls
// back to the legacy global recon/memory root — backwards compatible. The
// encoding mirrors getDefaultSessionDirPath (session-manager.ts:491) so a
// project's memory sits alongside its sessions under the same agent dir.
let memoryScopeCwd: string | null = null;

export function setMemoryScopeCwd(cwd: string | null): void {
	memoryScopeCwd = cwd ? resolvePath(cwd) : null;
}

export function getMemoryScopeCwd(): string | null {
	return memoryScopeCwd;
}

export function encodeCwdForScope(cwd: string): string {
	const resolvedCwd = resolvePath(cwd);
	return `--${resolvedCwd.replace(/^[/\\]/, "").replace(/[/\\:]/g, "-")}--`;
}

export function scopedMemoryRoot(): string {
	if (memoryScopeCwd) {
		return join(reconDir(), "memory", "projects", encodeCwdForScope(memoryScopeCwd));
	}
	return join(reconDir(), "memory");
}

export function memoryPath(name: string): string {
	return join(scopedMemoryRoot(), name);
}

export function memoryPlaybooksDir(): string {
	return join(scopedMemoryRoot(), "playbooks");
}

export function memoryPlaybooksArchiveDir(): string {
	return join(memoryPlaybooksDir(), "archive");
}

// --- Claude-Code-style project notes (opt #273 follow-on) ---------------------
// One-file-per-fact memory under the per-cwd scoped root, mirroring Claude
// Code's <project>/memory/ layout: notes/<slug>.md (frontmatter + body) + a
// MEMORY.md index (one line per note). Additive on top of the existing v5/v6
// distill system; scoped per-cwd via scopedMemoryRoot so notes never pollute
// other projects.
export function memoryNotesDir(): string {
	return join(scopedMemoryRoot(), "notes");
}

export function memoryNotesIndexPath(): string {
	return join(scopedMemoryRoot(), "MEMORY.md");
}

export function memoryNotePath(name: string): string {
	return join(memoryNotesDir(), `${name}.md`);
}

export function reconArchiveDir(): string {
	return join(reconDir(), "archive");
}

export function memoryEventsPath(): string {
	return memoryPath("events.jsonl");
}

export function caseMemoryPath(): string {
	return memoryPath("case-memory.jsonl");
}

export function memoryCorePath(): string {
	return memoryPath("core-memory.md");
}

export function memoryProjectPath(): string {
	return memoryPath("project-memory.md");
}

export function memoryProceduralPath(): string {
	return memoryPath("procedural-memory.md");
}

export function memoryRetrievalReportPath(): string {
	return memoryPath("retrieval-report.json");
}

export function memoryDistillationReportPath(): string {
	return memoryPath("distillation-report.json");
}

export function memoryPatternBookPath(): string {
	return memoryPath("pattern-book.md");
}

export function memoryQuarantinePath(): string {
	return memoryPath("quarantine.json");
}

export function memorySemanticIndexPath(): string {
	return memoryPath("semantic-index.json");
}

export function memoryContradictionLedgerPath(): string {
	return memoryPath("contradiction-ledger.jsonl");
}

export function memoryInjectionPacketPath(): string {
	return memoryPath("injection-packet.json");
}

export function memorySedimentationReportPath(): string {
	return memoryPath("sedimentation-report.json");
}

export function memorySupervisorReportPath(): string {
	return memoryPath("supervisor-report.json");
}

export function memoryLifecycleBoardPath(): string {
	return memoryPath("lifecycle-board.md");
}

export function memoryTransactionsDir(): string {
	return memoryPath("transactions");
}

export function memoryStoreLockPath(): string {
	return memoryPath(".store.lock");
}

export function memoryStoreReportPath(): string {
	return memoryPath("store-report.json");
}

export function memoryStoreSnapshotPath(): string {
	return memoryPath("store-snapshot.json");
}

export function memoryUsefulnessEvalReportPath(): string {
	return memoryPath("usefulness-eval.json");
}

export function memoryFeedbackClosureReportPath(): string {
	return memoryPath("feedback-closure-report.json");
}

export function memoryScopeIsolationReportPath(): string {
	return memoryPath("scope-isolation-report.json");
}

export function memoryArtifactScopeFilterReportPath(): string {
	return memoryPath("artifact-scope-filter-report.json");
}

export function memoryOrchestratorReportPath(): string {
	return memoryPath("orchestrator-report.json");
}

export function memoryDepositionEventBusPath(): string {
	return memoryPath("deposition-events.jsonl");
}

export function memoryDepositionReportPath(): string {
	return memoryPath("deposition-report.json");
}

export function memoryExperienceEpisodesPath(): string {
	return memoryPath("experience-episodes.jsonl");
}

export function memoryExperienceClaimsPath(): string {
	return memoryPath("experience-claims.jsonl");
}

export function memoryExperienceLessonBookPath(): string {
	return memoryPath("experience-lesson-book.md");
}

export function memoryExperiencePromotionLedgerPath(): string {
	return memoryPath("experience-promotions.jsonl");
}

export function memoryExperienceReportPath(): string {
	return memoryPath("experience-report.json");
}

export function memorySkillCapsuleLedgerPath(): string {
	return memoryPath("skill-capsules.jsonl");
}

export function memorySkillCapsuleReportPath(): string {
	return memoryPath("skill-capsule-report.json");
}

export function memorySkillCapsuleBookPath(): string {
	return memoryPath("skill-capsule-book.md");
}

export function memoryDistillPromotionCandidateLedgerPath(): string {
	return memoryPath("distill-promotion-candidates.jsonl");
}

export function memoryDistillPromotionReportPath(): string {
	return memoryPath("distill-promotion-report.json");
}

export function memoryDistillPromotionBookPath(): string {
	return memoryPath("distill-promotion-book.md");
}

export function memoryQualityLedgerPath(): string {
	return memoryPath("quality-ledger.jsonl");
}

export function memoryQualityReportPath(): string {
	return memoryPath("quality-report.json");
}

export function memoryQualityBoardPath(): string {
	return memoryPath("quality-board.md");
}

export function memoryReplayEvaluatorLedgerPath(): string {
	return memoryPath("replay-evaluator-ledger.jsonl");
}

export function memoryReplayEvaluatorReportPath(): string {
	return memoryPath("replay-evaluator-report.json");
}

export function memoryReplayEvaluatorBoardPath(): string {
	return memoryPath("replay-evaluator-board.md");
}

export function memoryStrategyCapsuleLedgerPath(): string {
	return memoryPath("strategy-capsules.jsonl");
}

export function memoryStrategyCapsuleReportPath(): string {
	return memoryPath("strategy-capsule-report.json");
}

export function memoryStrategyCapsuleBookPath(): string {
	return memoryPath("strategy-capsule-book.md");
}

export function memoryActiveKernelReportPath(): string {
	return memoryPath("active-kernel-report.json");
}

export function memoryActiveInjectionPackPath(): string {
	return memoryPath("active-injection-pack.json");
}

export function memoryActiveStrategyBoardPath(): string {
	return memoryPath("active-strategy-board.md");
}

export function memoryMaturationRuntimeReportPath(): string {
	return memoryPath("maturation-runtime-report.json");
}

export function memoryMaturationRuntimeLedgerPath(): string {
	return memoryPath("maturation-runtime-ledger.jsonl");
}

export function memoryMaturationActionBoardPath(): string {
	return memoryPath("maturation-action-board.md");
}

export function memoryStatusReportPath(): string {
	return memoryPath("status-report.json");
}

export function memoryStatusBoardPath(): string {
	return memoryPath("status-board.md");
}

export function memoryGovernanceLedgerPath(): string {
	return memoryPath("governance-ledger.jsonl");
}

export function compactResumeTransitionLedgerPath(): string {
	return memoryPath("compaction-resume-transitions.jsonl");
}

export function compactResumeLedgerV2ReportPath(): string {
	return memoryPath("compaction-resume-ledger-v2-report.json");
}

export function memoryVectorIndexPath(): string {
	return memoryPath("vector-index.json");
}

export function memoryVectorSearchReportPath(): string {
	return memoryPath("vector-search-report.json");
}

export function autonomousBudgetLedgerPath(): string {
	return memoryPath("autonomous-budget-ledger.md");
}

export function compactionResumeTelemetryPath(): string {
	return memoryPath("compaction-auto-resume-board.md");
}

export function memoryTransactionPath(id: string): string {
	return join(memoryTransactionsDir(), `${id}.json`);
}

export function missionPath(name: string): string {
	return join(reconDir(), "mission", name);
}

export function currentMissionPath(): string {
	return missionPath("current.json");
}

export function evidenceLedgerPath(): string {
	return join(reconDir(), "evidence", "ledger.md");
}

export function evidenceRunsDir(): string {
	return join(reconDir(), "evidence", "runs");
}

export function evidenceMapsDir(): string {
	return join(reconDir(), "evidence", "maps");
}

export function evidenceBrowserDir(): string {
	return join(reconDir(), "evidence", "browser");
}

export function evidenceWebAuthzDir(): string {
	return join(reconDir(), "evidence", "web-authz");
}

export function evidenceExploitLabDir(): string {
	return join(reconDir(), "evidence", "exploit-lab");
}

export function evidenceMobileRuntimeDir(): string {
	return join(reconDir(), "evidence", "mobile-runtime");
}

export function evidenceNativeRuntimeDir(): string {
	return join(reconDir(), "evidence", "native-runtime");
}

export function evidenceKernelDir(): string {
	return join(reconDir(), "evidence", "kernel");
}

export function evidenceGraphsDir(): string {
	return join(reconDir(), "evidence", "graphs");
}

export function evidenceChainsDir(): string {
	return join(reconDir(), "evidence", "chains");
}

export function evidenceDecisionsDir(): string {
	return join(reconDir(), "evidence", "decisions");
}

export function evidenceCampaignsDir(): string {
	return join(reconDir(), "evidence", "campaigns");
}

export function evidenceOperationsDir(): string {
	return join(reconDir(), "evidence", "operations");
}

export function evidenceDelegationsDir(): string {
	return join(reconDir(), "evidence", "delegations");
}

export function evidenceSwarmsDir(): string {
	return join(reconDir(), "evidence", "swarms");
}

export function evidenceSupervisorsDir(): string {
	return join(reconDir(), "evidence", "supervisor");
}

export function evidenceReflectionsDir(): string {
	return join(reconDir(), "evidence", "reflections");
}

export function evidenceContextsDir(): string {
	return join(reconDir(), "evidence", "contexts");
}

export function evidenceOperatorsDir(): string {
	return join(reconDir(), "evidence", "operators");
}

export function evidenceVerifiersDir(): string {
	return join(reconDir(), "evidence", "verifiers");
}

export function evidenceCompilersDir(): string {
	return join(reconDir(), "evidence", "compilers");
}

export function evidenceReplayersDir(): string {
	return join(reconDir(), "evidence", "replayers");
}

export function evidenceAutofixDir(): string {
	return join(reconDir(), "evidence", "autofix");
}

export function evidenceFailuresDir(): string {
	return join(reconDir(), "evidence", "failures");
}

export function evidenceRepairsDir(): string {
	return join(reconDir(), "evidence", "repairs");
}

export function evidenceClaimReleaseDir(): string {
	return join(reconDir(), "evidence", "claim-release");
}

export function evidenceProofLoopsDir(): string {
	return join(reconDir(), "evidence", "proof-loops");
}

export function evidenceKnowledgeDir(): string {
	return join(reconDir(), "evidence", "knowledge");
}

export function evidenceProfileCheckDir(): string {
	return join(reconDir(), "evidence", "profile-checks");
}

export function evidenceToolCallsDir(): string {
	return join(reconDir(), "evidence", "tool-calls");
}

export function evidenceToolchainDir(): string {
	return join(reconDir(), "evidence", "toolchain");
}

export function toolCallTraceLedgerPath(): string {
	return join(evidenceToolCallsDir(), "tool-call-trace.jsonl");
}

export function toolCallTraceReportPath(): string {
	return join(evidenceToolCallsDir(), "tool-call-trace-report.json");
}

export function runtimeFailureLedgerPath(): string {
	return join(evidenceFailuresDir(), "ledger.jsonl");
}

/**
 * Compact `{signature: count}` summary of the runtime-failure ledger. The
 * ledger itself is an append-only audit log (capped + rotated); this summary is
 * the O(1) source of truth for per-signature attempt counts used by the
 * "exhausted after maxAttempts" decision. Keeping counts here (not by scanning
 * the ledger) lets the ledger be safely rotated without resetting attempt
 * counts — and removes the O(n) per-failure scan of the growing ledger.
 */
export function runtimeFailureSummaryPath(): string {
	return join(evidenceFailuresDir(), "summary.json");
}

export function runtimeRepairQueuePath(): string {
	return join(evidenceRepairsDir(), "queue.jsonl");
}

export function reportDir(): string {
	return join(reconDir(), "reports");
}

export function builtinSkillFilePath(): string {
	return join(reconDir(), "builtin", "reverse-pentest-orchestrator", "SKILL.md");
}

export function builtinPromptFilePath(name: string): string {
	return join(reconDir(), "builtin", "prompts", `${name}.md`);
}

export function toolIndexPath(): string {
	return join(reconDir(), "tools", "tool-index.md");
}

export type RepiBuiltinPromptDefault = {
	name: string;
	description: string;
	argumentHint?: string;
	content: string;
};

export type RepiStorageDefaultsOptions = {
	skillContent?: string;
	prompts?: RepiBuiltinPromptDefault[];
	memoryEmbeddingProvider?: unknown;
};

export function chmodPrivate(path: string, mode: number): void {
	try {
		chmodSync(path, mode);
	} catch {
		// Best-effort on non-POSIX filesystems.
	}
}

export function writePrivateTextFile(path: string, content: string): void {
	// Atomic temp+rename (mode 0o600): this is the SHARED write path for all REPI
	// persisted state — playbooks, missions, evidence, memory transactions, tool
	// index — and appendPrivateTextFile does a read-modify-write through it. A
	// plain writeFileSync truncates then writes, so a crash (SIGKILL/OOM/SIGTERM)
	// mid-write leaves a truncated/partial file; readTextFile swallows the parse
	// failure and returns "" (graceful, no crash) but the playbook/mission/evidence
	// is SILENTLY LOST. temp+rename means a reader sees either the complete prior
	// content or the complete new content. chmodPrivate after the rename still
	// enforces 0o600 (atomicWriteFileSync preserves an existing target's mode).
	atomicWriteFileSync(path, content, 0o600);
	chmodPrivate(path, 0o600);
}

// opt #163 — stat-first OOM guard cap (bytes) for the SHARED readTextFile/
// readTextFileCached read path. The old code did readFileSync(path, "utf-8")
// of the WHOLE file with no size bound; jsonl.ts:79 then raw.split(/\r?\n/)
// built an unbounded array plus rows.push accumulation. These are the shared
// read paths for ALL REPI persisted state (playbooks, missions, evidence notes,
// memory transactions, tool index) and (via readTextFileCached) the events/
// case/quality/governance/claims/replay JSONL ledgers. The chain ledgers are
// rotation-bounded by default (#113, 500 rows), but
// REPI_MEMORY_EVENTS_MAX_ROWS=0 disables rotation and the non-ledger callers
// (playbooks/evidence notes/missions) have NO rotation — a large note or
// unrotated ledger loaded wholly into memory and split into an unbounded array
// → OOM. Files at or above this cap return the caller's fallback (default ""
// → JSON.parse/split yields [] / empty) so the caller degrades gracefully
// instead of OOMing. Override with REPI_READ_TEXT_FILE_MAX_BYTES; 0 disables
// the guard. Consistent with opt #34's REPI_READ_MAX_FILE_BYTES (16 MB).
const DEFAULT_READ_TEXT_FILE_MAX_BYTES = 16 * 1024 * 1024;
function resolveReadTextFileMaxBytes(): number {
	const raw = process.env.REPI_READ_TEXT_FILE_MAX_BYTES;
	if (raw !== undefined && raw.trim() !== "") {
		const parsed = Number(raw);
		if (Number.isFinite(parsed) && parsed >= 0) return Math.floor(parsed);
	}
	return DEFAULT_READ_TEXT_FILE_MAX_BYTES;
}

// Dedup set of paths already flagged as over-cap this session, so the hot
// recall path (readTextFileCached on events.jsonl runs multiple times per tool
// result) does not spam stderr for the same oversized file.
const overCapWarnedPaths = new Set<string>();

function warnOverCap(path: string, size: number, cap: number): void {
	if (overCapWarnedPaths.has(path)) return;
	overCapWarnedPaths.add(path);
	// NOT a silent drop: a truncated ledger/note is observable here. The
	// missing/unreadable case stays silent per the existing catch contract.
	process.stderr.write(
		`repi: readTextFile "${path}" is ${size} bytes > cap ${cap} (REPI_READ_TEXT_FILE_MAX_BYTES); returning fallback, content not loaded\n`,
	);
}

export function readTextFile(path: string, fallback = ""): string {
	try {
		const size = statSync(path).size;
		const cap = resolveReadTextFileMaxBytes();
		if (cap > 0 && size > cap) {
			warnOverCap(path, size, cap);
			return fallback;
		}
		return readFileSync(path, "utf-8");
	} catch {
		return fallback;
	}
}

const textFileCache = new Map<string, { mtimeMs: number; size: number; value: string }>();

/**
 * mtime+size-keyed cache of {@link readTextFile}, for hot-path readers of files
 * that are INVARIANT within a turn (or across many tool results) but read
 * repeatedly. The per-tool-result memory-recall packet header reads the core/
 * project/procedural memory .md notes TWICE each (memoryLineCount for the
 * status line + readMemoryNote for the packet) — 6 readFileSync of invariant
 * files per tool result, plus the same files re-read on every subsequent tool
 * result until the memory system rewrites them. This pays one stat(2) per call
 * and re-reads only when the file's mtime/size change (every REPI write goes
 * through atomic temp+rename, which updates both). Identical return contract to
 * readTextFile: `fallback` (default "") on any missing/unreadable path. The
 * missing/unreadable case is NOT cached, so a not-yet-created file is observed
 * on the next call once it appears. Apply ONLY to readers of infrequently-
 * changing files — hot files (events.jsonl on a deposit tool result, the tool-
 * trace ledger) still pay the stat but get a cache miss + re-read (the stat is
 * cheaper than the read+parse they replace, and the cache hits on the majority
 * of tool results where no deposit happened).
 */
export function readTextFileCached(path: string, fallback = ""): string {
	try {
		const stat = statSync(path);
		const mtimeMs = stat.mtimeMs;
		const size = stat.size;
		// opt #163 — same stat-first OOM guard as readTextFile. readTextFileCached
		// previously statSync'd only for the cache key, not to bound the read; a
		// huge file still paid the unbounded readFileSync + jsonl split. The
		// over-cap case returns fallback and is NOT cached (matching the missing-
		// file doctrine) so a later shrink below the cap is observed on the next
		// call.
		const cap = resolveReadTextFileMaxBytes();
		if (cap > 0 && size > cap) {
			warnOverCap(path, size, cap);
			return fallback;
		}
		const cached = textFileCache.get(path);
		if (cached && cached.mtimeMs === mtimeMs && cached.size === size) {
			return cached.value;
		}
		const value = readFileSync(path, "utf-8");
		textFileCache.set(path, { mtimeMs, size, value });
		return value;
	} catch {
		return fallback;
	}
}

export function appendPrivateTextFile(path: string, text: string): void {
	// True append (O(chunk) write + a 1-byte tail read) instead of read-modify-write
	// (O(file) read + O(file) atomic rewrite on EVERY append). This is the SHARED
	// append path for every REPI append-only artifact — tool-call trace ledger,
	// runtime failure/repair ledgers, evidence ledger, field/case/evolution
	// journals — so the read-modify-write made each append O(current file size):
	// a 500-row tool-trace ledger paid a 500-row read + 500-row atomic rewrite per
	// appended row, 2× per tool call. The bytes appended are IDENTICAL to the old
	// path (callers pre-hash/pre-format the content; this only persists bytes), so
	// hash-chain verification is unaffected — only the write mechanism changed.
	//
	// Newline-separator contract preserved EXACTLY: the old code joined
	// `${current}${current.endsWith("\n") ? "" : "\n"}${text}` where `current` is
	// `readTextFile(path)` → "" on a missing OR empty file. So a separator "\n" is
	// prepended unless the existing content ends with "\n" — INCLUDING the missing
	// / empty case ("" does not end with "\n"), which is the existing leading-blank-
	// line behavior (harmless for JSONL readers that filter(Boolean) and for
	// markdown). We detect "doesn't end with \n" with a 1-byte range read of the
	// last byte (openSync + readSync at offset size-1); a missing or size-0 file
	// gets the separator too, matching the old path.
	let prefix = "\n";
	try {
		const size = statSync(path).size;
		if (size > 0) {
			const fd = openSync(path, "r");
			try {
				const buf = Buffer.alloc(1);
				if (readSync(fd, buf, 0, 1, size - 1) > 0 && buf[0] === 0x0a) prefix = "";
			} finally {
				closeSync(fd);
			}
		}
	} catch {
		// missing/unreadable → keep prefix "\n" (matches old: "" doesn't end with \n).
	}
	// Crash safety: appendFileSync is NOT atomic (a crash mid-append can leave a
	// partial trailing line). Acceptable here — JSONL readers (readToolTraceEvents
	// et al.) skip unparseable lines per-line via try/catch, markdown journals are
	// tolerant, and the load-bearing memory hash-chain ledger does NOT use this
	// path (it has its own atomic writer). If true append fails (e.g. a filesystem
	// without O_APPEND), fall back to the atomic read-modify-write path below,
	// preserving the write + 0o600 contract.
	try {
		appendFileSync(path, `${prefix}${text}`, { encoding: "utf8", mode: 0o600 });
		return;
	} catch {
		// Fall through to the atomic read-modify-write fallback.
	}
	const current = readTextFile(path);
	writePrivateTextFile(path, `${current}${current.endsWith("\n") ? "" : "\n"}${text}`);
}

export function ensureRepiStorage(options: RepiStorageDefaultsOptions = {}): void {
	const dirs = [
		reconDir(),
		memoryPath(""),
		memoryTransactionsDir(),
		memoryPlaybooksDir(),
		memoryPlaybooksArchiveDir(),
		reconArchiveDir(),
		join(reconDir(), "mission"),
		join(reconDir(), "evidence"),
		evidenceRunsDir(),
		evidenceMapsDir(),
		evidenceBrowserDir(),
		evidenceWebAuthzDir(),
		evidenceExploitLabDir(),
		evidenceMobileRuntimeDir(),
		evidenceNativeRuntimeDir(),
		evidenceKernelDir(),
		evidenceGraphsDir(),
		evidenceChainsDir(),
		evidenceDecisionsDir(),
		evidenceCampaignsDir(),
		evidenceOperationsDir(),
		evidenceDelegationsDir(),
		evidenceSwarmsDir(),
		evidenceSupervisorsDir(),
		evidenceReflectionsDir(),
		evidenceContextsDir(),
		evidenceOperatorsDir(),
		evidenceVerifiersDir(),
		evidenceCompilersDir(),
		evidenceReplayersDir(),
		evidenceAutofixDir(),
		evidenceFailuresDir(),
		evidenceRepairsDir(),
		evidenceClaimReleaseDir(),
		evidenceProofLoopsDir(),
		evidenceKnowledgeDir(),
		evidenceProfileCheckDir(),
		evidenceToolCallsDir(),
		evidenceToolchainDir(),
		reportDir(),
		join(reconDir(), "tools"),
		join(reconDir(), "builtin", "reverse-pentest-orchestrator"),
		join(reconDir(), "builtin", "prompts"),
	];
	for (const dir of dirs) {
		mkdirSync(dir, { recursive: true });
		chmodPrivate(dir, 0o700);
	}
	const memoryEmbeddingProvider = options.memoryEmbeddingProvider ?? {
		kind: "repi-memory-embedding-provider",
		schemaVersion: 1,
		backend: "local-hash",
		status: "ready",
	};
	const defaults = new Map<string, string>([
		[memoryPath("field-journal.md"), "# REPI Field Journal\n\n"],
		[memoryPath("case-index.md"), "# REPI Case Index\n\n"],
		[memoryPath("evolution-log.md"), "# REPI Evolution Log\n\n"],
		[
			memoryCorePath(),
			"# REPI Core Memory\n\n固定偏好、项目不变量、长期稳定事实写在这里；保持短小，默认随 scoped memory packet 加载。\n\n",
		],
		[
			memoryProjectPath(),
			"# REPI Project Memory\n\n当前 workspace 的构建、运行、测试、入口、常用命令写在这里；避免写临时任务输出。\n\n",
		],
		[
			memoryProceduralPath(),
			"# REPI Procedural Memory\n\n可复用 workflow / checklist / verified command template 写在这里；不要写未验证猜测。\n\n",
		],
		[memoryEventsPath(), ""],
		[caseMemoryPath(), ""],
		[
			memoryRetrievalReportPath(),
			`${JSON.stringify({ kind: "repi-memory-retrieval-report", schemaVersion: 1, query: "", hits: [] }, null, 2)}\n`,
		],
		[
			memoryDistillationReportPath(),
			`${JSON.stringify({ kind: "repi-memory-distillation-report", schemaVersion: 1, patterns: [], quarantine: [] }, null, 2)}\n`,
		],
		[memoryPatternBookPath(), "# REPI Memory Pattern Book\n\n"],
		[
			memoryQuarantinePath(),
			`${JSON.stringify({ kind: "repi-memory-contamination-quarantine", schemaVersion: 1, findings: [] }, null, 2)}\n`,
		],
		[
			memorySemanticIndexPath(),
			`${JSON.stringify({ kind: "repi-memory-semantic-index", schemaVersion: 1, entries: [] }, null, 2)}\n`,
		],
		[memoryContradictionLedgerPath(), ""],
		[
			memoryInjectionPacketPath(),
			`${JSON.stringify({ kind: "repi-memory-injection-packet", schemaVersion: 1, entries: [], commands: [] }, null, 2)}\n`,
		],
		[
			memorySedimentationReportPath(),
			`${JSON.stringify({ kind: "repi-memory-sedimentation-report", schemaVersion: 1, entries: [], contradictions: [] }, null, 2)}\n`,
		],
		[
			memorySupervisorReportPath(),
			`${JSON.stringify({ kind: "repi-memory-supervisor-report", schemaVersion: 1, MemorySupervisorV1: true, decisions: [] }, null, 2)}\n`,
		],
		[memoryLifecycleBoardPath(), "# REPI Memory Lifecycle Board\n\n"],
		[
			memoryStoreReportPath(),
			`${JSON.stringify({ kind: "repi-memory-store-verification", schemaVersion: 1, MemoryStoreV5: true, eventCount: 0, caseRowCount: 0, errors: [] }, null, 2)}\n`,
		],
		[
			memoryStoreSnapshotPath(),
			`${JSON.stringify({ kind: "repi-memory-store-snapshot", schemaVersion: 1, events: [], caseMemory: [] }, null, 2)}\n`,
		],
		[
			memoryUsefulnessEvalReportPath(),
			`${JSON.stringify({ kind: "repi-memory-usefulness-eval", schemaVersion: 1, MemoryUsefulnessEvalV1: true, scenarioCount: 0, scenarios: [] }, null, 2)}\n`,
		],
		[
			memoryFeedbackClosureReportPath(),
			`${JSON.stringify({ kind: "repi-memory-feedback-closure-report", schemaVersion: 1, MemoryFeedbackClosureV1: true, rows: [] }, null, 2)}\n`,
		],
		[
			memoryScopeIsolationReportPath(),
			`${JSON.stringify({ kind: "repi-memory-scope-isolation-report", schemaVersion: 1, MemoryScopeIsolationV1: true, rows: [] }, null, 2)}\n`,
		],
		[
			memoryArtifactScopeFilterReportPath(),
			`${JSON.stringify({ kind: "repi-artifact-scope-filter-report", schemaVersion: 1, ArtifactScopeFilterV1: true, MemoryScopeIsolationV1: true, decisions: [] }, null, 2)}\n`,
		],
		[
			memoryOrchestratorReportPath(),
			`${JSON.stringify({ kind: "repi-memory-orchestrator-report", schemaVersion: 1, MemoryOrchestratorV6: true, mandatory_memory_control_loop: true, steps: [] }, null, 2)}\n`,
		],
		[memoryDepositionEventBusPath(), ""],
		[
			memoryDepositionReportPath(),
			`${JSON.stringify({ kind: "repi-memory-deposition-report", schemaVersion: 1, MemoryDepositionEngineV7: true, runtime_step_event_bus: true, post_tool_writeback_autocapture: true, runtimeEventCount: 0, memoryWritebackCount: 0, pendingWritebackCount: 0, blockedWritebackCount: 0, skippedWritebackCount: 0, autoWritebackCoverage: 0, status: "empty", recentEvents: [], pendingEventIds: [], blockedEventIds: [] }, null, 2)}\n`,
		],
		[memoryExperienceEpisodesPath(), ""],
		[memoryExperienceClaimsPath(), ""],
		[memoryExperienceLessonBookPath(), "# REPI Memory Experience Lesson Book\n\n"],
		[memoryExperiencePromotionLedgerPath(), ""],
		[
			memoryExperienceReportPath(),
			`${JSON.stringify({ kind: "repi-memory-experience-report", schemaVersion: 1, MemoryExperienceEngineV8: true, episode_model_v8: true, structured_claim_extraction: true, lesson_promotion_check: true, contradiction_resolution: true, usefulness_backprop: true, episodeCount: 0, claimCount: 0, lessonCount: 0, promotionDecisionCount: 0, promotedClaimIds: [], retainedClaimIds: [], demotedClaimIds: [], quarantinedClaimIds: [], conflictedClaimIds: [], operatorInjectionCommands: [], avoidCommands: [], verifyCommands: [], promotionCoverage: 0, status: "empty", recentEpisodes: [], recentClaims: [], recentLessons: [] }, null, 2)}\n`,
		],
		[memorySkillCapsuleLedgerPath(), ""],
		[memorySkillCapsuleBookPath(), "# REPI Memory Skill Capsule Book\n\n"],
		[
			memorySkillCapsuleReportPath(),
			`${JSON.stringify({ kind: "repi-memory-skill-capsule-report", schemaVersion: 1, MemorySkillCapsuleV9: true, skill_capsule_assetization: true, verified_skill_promotion_check: true, operator_skill_injection: true, capsuleCount: 0, promotedCapsuleIds: [], candidateCapsuleIds: [], quarantinedCapsuleIds: [], demotedCapsuleIds: [], operatorInjectionCommands: [], verifierCommands: [], avoidCommands: [], workerRoutingHints: [], status: "empty", recentCapsules: [] }, null, 2)}\n`,
		],
		[memoryDistillPromotionCandidateLedgerPath(), ""],
		[memoryDistillPromotionBookPath(), "# REPI Memory Distill Promotion Book\n\n"],
		[
			memoryDistillPromotionReportPath(),
			`${JSON.stringify({ kind: "repi-memory-distill-promotion-report", schemaVersion: 1, MemoryDistillPromotionV10: true, provider_distill_contract: true, artifact_to_claim_distillation: true, verifier_backed_promotion_check: true, skill_capsule_promotion_writeback: true, candidateCount: 0, promotedCandidateIds: [], retainedCandidateIds: [], quarantinedCandidateIds: [], demotedCandidateIds: [], operatorInjectionCommands: [], verifierCommands: [], avoidCommands: [], status: "empty", recentCandidates: [] }, null, 2)}\n`,
		],
		[memoryQualityLedgerPath(), ""],
		[memoryQualityBoardPath(), "# REPI Memory Quality Board\n\n"],
		[
			memoryQualityReportPath(),
			`${JSON.stringify({ kind: "repi-memory-quality-ledger-report", schemaVersion: 1, MemoryQualityLedgerV11: true, active_memory_policy: true, quality_score_feedback_loop: true, usefulness_feedback_writeback: true, eventCount: 0, rowCount: 0, averageQualityScore: 0, promotedEventIds: [], retainedEventIds: [], demotedEventIds: [], quarantinedEventIds: [], expiredEventIds: [], requiredFeedbackEventIds: [], operatorInjectionCommands: [], avoidCommands: [], status: "empty", rows: [] }, null, 2)}\n`,
		],
		[memoryReplayEvaluatorLedgerPath(), ""],
		[memoryReplayEvaluatorBoardPath(), "# REPI Memory Replay Evaluator Board\n\n"],
		[
			memoryReplayEvaluatorReportPath(),
			`${JSON.stringify({ kind: "repi-memory-replay-evaluator-report", schemaVersion: 1, MemoryReplayEvaluatorV12: true, memory_ab_replay: true, causal_attribution_signal: true, replay_delta_feedback_writeback: true, scenarioCount: 0, rowCount: 0, improvedScenarioIds: [], neutralScenarioIds: [], regressedScenarioIds: [], blockedScenarioIds: [], attributionEventIds: [], regressionEventIds: [], averageCausalScore: 0, totalSavedStepEstimate: 0, operatorInjectionCommands: [], avoidCommands: [], status: "empty", rows: [] }, null, 2)}\n`,
		],
		[memoryStrategyCapsuleLedgerPath(), ""],
		[memoryStrategyCapsuleBookPath(), "# REPI Memory Strategy Capsule Book\n\n"],
		[
			memoryStrategyCapsuleReportPath(),
			`${JSON.stringify({ kind: "repi-memory-strategy-capsule-report", schemaVersion: 1, MemoryStrategyCapsuleV13: true, executable_strategy_capsule: true, replay_backed_strategy_promotion: true, strategy_quality_check: true, capsuleCount: 0, promotedCapsuleIds: [], candidateCapsuleIds: [], demotedCapsuleIds: [], quarantinedCapsuleIds: [], operatorInjectionCommands: [], verifierCommands: [], avoidCommands: [], fallbackCommands: [], workerRoutingHints: [], status: "empty", recentCapsules: [] }, null, 2)}\n`,
		],
		[
			memoryActiveKernelReportPath(),
			`${JSON.stringify({ kind: "repi-memory-active-kernel-report", schemaVersion: 1, MemoryActiveKernelV14: true, unified_memory_decision_engine: true, active_recall_scheduler: true, scope_safe_strategy_injection: true, decisionCount: 0, injectDecisionIds: [], reuseDecisionIds: [], verifyDecisionIds: [], avoidDecisionIds: [], quarantineDecisionIds: [], pendingFeedbackDecisionIds: [], operatorInjectionCommands: [], verifierCommands: [], fallbackCommands: [], avoidCommands: [], status: "empty", decisions: [] }, null, 2)}\n`,
		],
		[
			memoryActiveInjectionPackPath(),
			`${JSON.stringify({ kind: "repi-memory-active-injection-pack", schemaVersion: 1, MemoryActiveKernelV14: true, active_recall_scheduler: true, decisions: [], commands: [], verifierRules: [], fallbackCommands: [], avoidCommands: [] }, null, 2)}\n`,
		],
		[memoryActiveStrategyBoardPath(), "# REPI Memory Active Strategy Board\n\n"],
		[
			memoryMaturationRuntimeReportPath(),
			`${JSON.stringify({ kind: "repi-memory-maturation-runtime-report", schemaVersion: 1, MemoryMaturationRuntimeV15: true, automatic_memory_maturation_pipeline: true, tool_result_to_strategy_loop: true, closed_loop_writeback: true, retention_decay_scheduler: true, stale_memory_rehearsal_queue: true, usefulness_backprop_to_maturation: true, rowCount: 0, promotedEventIds: [], retainedEventIds: [], demotedEventIds: [], quarantinedEventIds: [], pendingFeedbackEventIds: [], replayRequiredEventIds: [], retentionQueueEventIds: [], expiredEventIds: [], operatorCommands: [], feedbackCommands: [], retentionCommands: [], status: "empty", rows: [] }, null, 2)}\n`,
		],
		[memoryMaturationRuntimeLedgerPath(), ""],
		[memoryMaturationActionBoardPath(), "# REPI Memory Maturation Action Board\n\n"],
		[compactResumeTransitionLedgerPath(), ""],
		[
			compactResumeLedgerV2ReportPath(),
			`${JSON.stringify({ kind: "repi-compact-resume-ledger-v2-report", schemaVersion: 1, CompactResumeLedgerV2: true, append_only_transition_ledger: true, idempotent_multi_compact_replay: true, auto_resume_budget_enforced: true, currentState: "queued", transitions: [], invalidTransitions: [] }, null, 2)}\n`,
		],
		[
			memoryVectorIndexPath(),
			`${JSON.stringify({ kind: "repi-memory-vector-index", schemaVersion: 1, MemoryVectorIndexV1: true, embeddingProvider: memoryEmbeddingProvider, entries: [] }, null, 2)}\n`,
		],
		[
			memoryVectorSearchReportPath(),
			`${JSON.stringify({ kind: "repi-memory-vector-search-report", schemaVersion: 1, MemoryVectorSearchV1: true, embeddingProvider: memoryEmbeddingProvider, hits: [] }, null, 2)}\n`,
		],
		[toolCallTraceLedgerPath(), ""],
		[
			toolCallTraceReportPath(),
			`${JSON.stringify({ kind: "ToolCallTraceLedgerV1", schemaVersion: 1, tool_call_observability_runtime: true, append_only_tool_trace: true, replayable_tool_result_hashes: true, secret_redaction_required: true, eventCount: 0, callCount: 0, resultCount: 0, errorCount: 0, hashChainOk: true, secretRedactionOk: true, replayCoverage: 0, events: [] }, null, 2)}\n`,
		],
		[evidenceLedgerPath(), "# REPI Evidence Ledger\n\n"],
		[toolIndexPath(), "# REPI Tool Index\n\n"],
	]);
	for (const [path, content] of defaults) {
		if (!existsSync(path)) writePrivateTextFile(path, content);
		else chmodPrivate(path, 0o600);
	}
	if (options.skillContent !== undefined) {
		const skillFile = builtinSkillFilePath();
		if (!existsSync(skillFile)) {
			writePrivateTextFile(
				skillFile,
				`---\nname: reverse-pentest-orchestrator\ndescription: Built-in REPI orchestrator for reverse engineering, CTF, pwn, web/API pentest, JS signing, mobile, firmware, cloud/container, identity/AD, DFIR, malware analysis, and agent/LLM boundary testing tasks.\n---\n\n${options.skillContent}\n`,
			);
		} else {
			chmodPrivate(skillFile, 0o600);
		}
	}
	for (const prompt of options.prompts ?? []) {
		const promptFile = builtinPromptFilePath(prompt.name);
		if (!existsSync(promptFile)) {
			writePrivateTextFile(
				promptFile,
				`---\ndescription: ${prompt.description}\nargument-hint: "${prompt.argumentHint ?? ""}"\n---\n${prompt.content}\n`,
			);
		} else {
			chmodPrivate(promptFile, 0o600);
		}
	}
}

export function recentMarkdownArtifacts(dir: string, limit: number): string[] {
	try {
		return readdirSync(dir)
			.filter((file) => file.endsWith(".md"))
			.sort()
			.reverse()
			.slice(0, limit)
			.map((file) => join(dir, file));
	} catch {
		return [];
	}
}

export function artifactBasename(path: string): string {
	return path.split(/[/\\]/).pop() ?? path;
}

export function readJsonObjectFile<T>(path: string): T | undefined {
	try {
		return JSON.parse(readFileSync(path, "utf-8")) as T;
	} catch {
		return undefined;
	}
}

const jsonObjectFileCache = new Map<string, { mtimeMs: number; size: number; value: unknown }>();

/**
 * mtime+size-keyed cache of {@link readJsonObjectFile}. The REPI modules bypass
 * {@link SettingsManager}'s in-memory cache and read settings.json raw on every
 * call — {@link repiMemorySettings} alone reads it 3× per tool result (recall +
 * scoped-hits + format-packet), each a readFileSync + JSON.parse of an invariant
 * file. This pays one stat(2) per call instead, and only re-reads + re-parses
 * when the file's mtime/size change (atomic temp+rename writes from
 * SettingsManager update both). Identical return contract: undefined on any
 * missing/unreadable/invalid-JSON path (parse failure is not cached, so a
 * transiently-corrupt file keeps re-reading until fixed).
 */
export function readJsonObjectFileCached<T>(path: string): T | undefined {
	try {
		const stat = statSync(path);
		const mtimeMs = stat.mtimeMs;
		const size = stat.size;
		const cached = jsonObjectFileCache.get(path);
		if (cached && cached.mtimeMs === mtimeMs && cached.size === size) {
			return cached.value as T | undefined;
		}
		const value = JSON.parse(readFileSync(path, "utf-8")) as T;
		jsonObjectFileCache.set(path, { mtimeMs, size, value });
		return value;
	} catch {
		return undefined;
	}
}
