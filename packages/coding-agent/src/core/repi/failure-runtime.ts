import { createHash } from "node:crypto";
import { existsSync, mkdirSync, statSync } from "node:fs";
import { join } from "node:path";
import type { ReplayArtifact } from "./proof-artifact-runtime.ts";
import { verifyRepairRollbackPolicyV1 } from "./provider-worker-runtime.ts";
import { ensureReconStorage } from "./resources.ts";
import {
	appendPrivateTextFile,
	evidenceRepairsDir,
	readTextFile,
	runtimeFailureLedgerPath,
	runtimeFailureSummaryPath,
	runtimeRepairQueuePath,
	writePrivateTextFile,
} from "./storage.ts";
import { hashFileSha256, slug, truncateMiddle, uniqueNonEmpty } from "./text.ts";

export type RuntimeFailureSource = "re_replayer" | "re_autofix" | "re_operator" | "re_proof_loop";
export type RuntimeFailureCategory = "artifact_stale" | "runtime_failed" | "tool_missing" | "contract_gap";
export type RuntimeFailureStatus = "failed" | "repair_queued" | "exhausted" | "blocked" | "rolled_back";
export type RuntimeRepairAction =
	| "rerun"
	| "replace-command"
	| "recapture-evidence"
	| "refresh-context"
	| "escalate"
	| "rollback";

export type FailureRepairEvidenceWriteback = {
	failureLedgerPath: string;
	repairQueuePath: string;
	appendOnly: true;
	mode: "runtime";
};

export type FailureRepairArtifactHash = {
	path: string;
	sha256: string;
	tier: string;
};

export type FailureLedgerEventV1 = {
	id: string;
	ts: string;
	source: RuntimeFailureSource;
	scope: string;
	category: RuntimeFailureCategory;
	signature: string;
	attempt: number;
	maxAttempts: number;
	status: RuntimeFailureStatus;
	failedChecks: string[];
	artifacts: FailureRepairArtifactHash[];
	artifactHashes: Array<{ path: string; sha256: string }>;
	repairId: string;
	budget: { retryKey: string; remainingAttempts: number; exhaustedAction: string };
	retryBudget: { retryKey: string; remainingAttempts: number; exhaustedAction: string };
	evidenceWriteback: FailureRepairEvidenceWriteback;
	blockedConditions: Array<{ reason: string; unblock: string }>;
	rollback: { required: boolean; baseline: string; allowlist: string[]; criteria: string[]; restored: boolean };
};

export type RepairQueueItemV1 = {
	repairId: string;
	fromFailureId: string;
	signature: string;
	scope: string;
	action: RuntimeRepairAction;
	repairAction: RuntimeRepairAction;
	commands: string[];
	expectedArtifacts: string[];
	expectedChecks: string[];
	preconditions: { liveAllowed: boolean; providerAllowed: boolean; requiredSecrets: string[] };
	paused: boolean;
	allowlist: string[];
	rollbackCriteria: { baseline: string; mustRestore: string[]; verificationCommand: string };
	blockedConditions: Array<{ reason: string; unblock: string }>;
	evidenceWriteback: FailureRepairEvidenceWriteback;
	regressionChecks: string[];
};

export type RuntimeFailureRepairInput = {
	source: RuntimeFailureSource;
	scope: string;
	target?: string;
	reason: string;
	category?: RuntimeFailureCategory;
	status?: RuntimeFailureStatus;
	commands?: string[];
	failedChecks: string[];
	sourceArtifacts: string[];
	expectedArtifacts?: string[];
	maxAttempts?: number;
	unblock?: string;
};

type RuntimeAutofixItem = {
	id: string;
	kind: string;
	reason: string;
	command: string;
	status: string;
	sourceArtifacts: string[];
};

export type RuntimeAutofixArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	mode: "plan" | "apply";
	replayArtifact?: string;
	compilerArtifact?: string;
	failures: string[];
	patchQueue: RuntimeAutofixItem[];
	commandSubstitutions: RuntimeAutofixItem[];
	bootstrapQueue: RuntimeAutofixItem[];
	evidenceRecaptureQueue: RuntimeAutofixItem[];
	nextOperatorQueue: string[];
	applied: string[];
	repairRollbackPolicyPath?: string;
	sourceArtifacts: string[];
};

export type RepairRollbackPolicyV1 = {
	kind: "RepairRollbackPolicyV1";
	schemaVersion: 1;
	generatedAt: string;
	source: RuntimeFailureSource | "compound-frontier" | "provider-worker";
	workspace: string;
	baseline: {
		command: string;
		treeSha256: string;
		files: Array<{ path: string; bytes: number; sha256: string }>;
	};
	allowlist: string[];
	repair: {
		commands: string[];
		changedFiles: string[];
		expectedArtifacts: string[];
		regressionChecks: string[];
	};
	rollback: {
		required: true;
		commands: string[];
		restored: boolean;
		restoredTreeSha256: string;
		criteria: string[];
	};
	regression: {
		before: "pass" | "fail" | "skipped";
		after: "pass" | "fail" | "skipped";
		restored: "pass" | "fail" | "skipped";
		checkpoints: Array<{
			checkId: string;
			command: string;
			status: "pass" | "fail" | "skipped";
			artifactPath?: string;
			artifactSha256?: string;
		}>;
	};
	failureLedgerEvents: FailureLedgerEventV1[];
	repairQueue: RepairQueueItemV1[];
	failureRepairValidation: { ok: boolean; failureCount: number; repairCount: number };
	assertions: {
		baselineCaptured: boolean;
		allowlistEnforced: boolean;
		rollbackRestored: boolean;
		regressionChecksPassed: boolean;
		noUnrelatedFileChanges: boolean;
		failureRepairLinked: boolean;
	};
};

type RuntimeOperationExecution = {
	stepId: string;
	command: string;
	status: string;
	output: string;
};

type RuntimeOperationStep = {
	id: string;
	command: string;
	status: string;
	reason?: string;
	sourceArtifacts: string[];
};

export type RuntimeOperatorArtifact = {
	missionId?: string;
	route?: string;
	target?: string;
	mode: string;
	steps: RuntimeOperationStep[];
	executed: RuntimeOperationExecution[];
	operatorFeedback: string[];
	commanderDispatchReport: string[];
	sourceArtifacts: string[];
};

export type RuntimeProofLoopArtifact = {
	missionId?: string;
	route?: string;
	target?: string;
	mode: string;
	verdict: string;
	steps: RuntimeOperationStep[];
	executed: RuntimeOperationExecution[];
	specialistQueue: string[];
	swarmBridge: string[];
	operatorFeedback: string[];
	bridgeArtifacts: string[];
	nextActions: string[];
	sourceArtifacts: string[];
};

export type FailureSignaturePriorityReport = {
	rows: string[];
	commands: string[];
	repairQueue: string[];
	sourceArtifacts: string[];
	exhaustedCount: number;
	repeatedCount: number;
};

export type FailureRuntimeDependencies = {
	artifactTier: (path: string) => string;
	latestAutofixArtifactPath: () => string | undefined;
	latestProofLoopArtifactPath: () => string | undefined;
	latestSupervisorArtifactPath: () => string | undefined;
	operatorFeedbackCategory: (row: string) => string;
	operatorFeedbackFallbackCommands: (row: string, target?: string) => string[];
};

function failureSignature(input: {
	scope: string;
	category: RuntimeFailureCategory;
	command?: string;
	reason?: string;
}): string {
	const normalized = [input.scope, input.category, input.command ?? "", input.reason ?? ""]
		.join("\n")
		.replace(/\b20\d{2}-\d{2}-\d{2}T[0-9:.+-]+Z\b/g, "<timestamp>")
		.replace(/\s+/g, " ")
		.trim();
	return createHash("sha256").update(normalized).digest("hex");
}

function failureLedgerMaxRows(): number {
	const raw = process.env.REPI_FAILURE_LEDGER_MAX_ROWS;
	if (raw === undefined) return 500;
	const value = Math.floor(Number(raw));
	return Number.isFinite(value) && value >= 0 ? value : 500;
}

function repairQueueMaxRows(): number {
	const raw = process.env.REPI_REPAIR_QUEUE_MAX_ROWS;
	if (raw === undefined) return 500;
	const value = Math.floor(Number(raw));
	return Number.isFinite(value) && value >= 0 ? value : 500;
}

const FAILURE_SOURCES = new Set<RuntimeFailureSource>(["re_replayer", "re_autofix", "re_operator", "re_proof_loop"]);
const FAILURE_CATEGORIES = new Set<RuntimeFailureCategory>([
	"artifact_stale",
	"runtime_failed",
	"tool_missing",
	"contract_gap",
]);
const FAILURE_STATUSES = new Set<RuntimeFailureStatus>([
	"failed",
	"repair_queued",
	"exhausted",
	"blocked",
	"rolled_back",
]);
const REPAIR_ACTIONS = new Set<RuntimeRepairAction>([
	"rerun",
	"replace-command",
	"recapture-evidence",
	"refresh-context",
	"escalate",
	"rollback",
]);

function isStringArray(value: unknown): value is string[] {
	return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isBlockedCondition(value: unknown): value is { reason: string; unblock: string } {
	if (typeof value !== "object" || value === null) return false;
	const condition = value as Record<string, unknown>;
	return typeof condition.reason === "string" && typeof condition.unblock === "string";
}

function isArtifactHash(value: unknown): value is { path: string; sha256: string } {
	if (typeof value !== "object" || value === null) return false;
	const artifact = value as Record<string, unknown>;
	return typeof artifact.path === "string" && typeof artifact.sha256 === "string";
}

function isFailureBudget(value: unknown): value is FailureLedgerEventV1["budget"] {
	if (typeof value !== "object" || value === null) return false;
	const budget = value as Record<string, unknown>;
	return (
		typeof budget.retryKey === "string" &&
		typeof budget.remainingAttempts === "number" &&
		Number.isFinite(budget.remainingAttempts) &&
		typeof budget.exhaustedAction === "string"
	);
}

function isEvidenceWriteback(value: unknown): value is FailureRepairEvidenceWriteback {
	if (typeof value !== "object" || value === null) return false;
	const writeback = value as Record<string, unknown>;
	return (
		typeof writeback.failureLedgerPath === "string" &&
		typeof writeback.repairQueuePath === "string" &&
		writeback.appendOnly === true &&
		writeback.mode === "runtime"
	);
}

function isFailureRollback(value: unknown): value is FailureLedgerEventV1["rollback"] {
	if (typeof value !== "object" || value === null) return false;
	const rollback = value as Record<string, unknown>;
	return (
		typeof rollback.required === "boolean" &&
		typeof rollback.baseline === "string" &&
		isStringArray(rollback.allowlist) &&
		isStringArray(rollback.criteria) &&
		typeof rollback.restored === "boolean"
	);
}

function isFailureLedgerEvent(row: unknown): row is FailureLedgerEventV1 {
	if (typeof row !== "object" || row === null) return false;
	const candidate = row as Record<string, unknown>;
	return (
		typeof candidate.id === "string" &&
		candidate.id.length > 0 &&
		typeof candidate.source === "string" &&
		FAILURE_SOURCES.has(candidate.source as RuntimeFailureSource) &&
		typeof candidate.scope === "string" &&
		typeof candidate.category === "string" &&
		FAILURE_CATEGORIES.has(candidate.category as RuntimeFailureCategory) &&
		typeof candidate.signature === "string" &&
		candidate.signature.length > 0 &&
		typeof candidate.ts === "string" &&
		typeof candidate.attempt === "number" &&
		Number.isFinite(candidate.attempt) &&
		typeof candidate.maxAttempts === "number" &&
		Number.isFinite(candidate.maxAttempts) &&
		typeof candidate.status === "string" &&
		FAILURE_STATUSES.has(candidate.status as RuntimeFailureStatus) &&
		isStringArray(candidate.failedChecks) &&
		Array.isArray(candidate.artifacts) &&
		candidate.artifacts.every(
			(artifact) => isArtifactHash(artifact) && typeof (artifact as Record<string, unknown>).tier === "string",
		) &&
		Array.isArray(candidate.artifactHashes) &&
		candidate.artifactHashes.every(isArtifactHash) &&
		typeof candidate.repairId === "string" &&
		isFailureBudget(candidate.budget) &&
		isFailureBudget(candidate.retryBudget) &&
		isEvidenceWriteback(candidate.evidenceWriteback) &&
		Array.isArray(candidate.blockedConditions) &&
		candidate.blockedConditions.every(isBlockedCondition) &&
		isFailureRollback(candidate.rollback)
	);
}

function isRepairQueueItem(row: unknown): row is RepairQueueItemV1 {
	if (typeof row !== "object" || row === null) return false;
	const candidate = row as Record<string, unknown>;
	const preconditions = candidate.preconditions as Record<string, unknown> | undefined;
	const rollbackCriteria = candidate.rollbackCriteria as Record<string, unknown> | undefined;
	return (
		typeof candidate.repairId === "string" &&
		candidate.repairId.length > 0 &&
		typeof candidate.fromFailureId === "string" &&
		typeof candidate.signature === "string" &&
		candidate.signature.length > 0 &&
		typeof candidate.scope === "string" &&
		typeof candidate.action === "string" &&
		REPAIR_ACTIONS.has(candidate.action as RuntimeRepairAction) &&
		typeof candidate.repairAction === "string" &&
		REPAIR_ACTIONS.has(candidate.repairAction as RuntimeRepairAction) &&
		typeof candidate.paused === "boolean" &&
		isStringArray(candidate.commands) &&
		isStringArray(candidate.expectedArtifacts) &&
		isStringArray(candidate.expectedChecks) &&
		typeof preconditions === "object" &&
		preconditions !== null &&
		typeof preconditions.liveAllowed === "boolean" &&
		typeof preconditions.providerAllowed === "boolean" &&
		isStringArray(preconditions.requiredSecrets) &&
		isStringArray(candidate.allowlist) &&
		typeof rollbackCriteria === "object" &&
		rollbackCriteria !== null &&
		typeof rollbackCriteria.baseline === "string" &&
		isStringArray(rollbackCriteria.mustRestore) &&
		typeof rollbackCriteria.verificationCommand === "string" &&
		Array.isArray(candidate.blockedConditions) &&
		candidate.blockedConditions.every(isBlockedCondition) &&
		isEvidenceWriteback(candidate.evidenceWriteback) &&
		isStringArray(candidate.regressionChecks)
	);
}

function parseJsonl<T>(path: string, guard: (row: unknown) => row is T): T[] {
	return readTextFile(path)
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter(Boolean)
		.map((line) => {
			try {
				const row: unknown = JSON.parse(line);
				return guard(row) ? row : undefined;
			} catch {
				return undefined;
			}
		})
		.filter((row): row is T => Boolean(row));
}

export function createFailureRuntime(dependencies: FailureRuntimeDependencies) {
	const {
		artifactTier,
		latestAutofixArtifactPath,
		latestProofLoopArtifactPath,
		latestSupervisorArtifactPath,
		operatorFeedbackCategory,
		operatorFeedbackFallbackCommands,
	} = dependencies;

	function readRuntimeFailureLedgerRows(): FailureLedgerEventV1[] {
		return parseJsonl(runtimeFailureLedgerPath(), isFailureLedgerEvent);
	}

	function readRuntimeRepairQueueRows(): RepairQueueItemV1[] {
		return parseJsonl(runtimeRepairQueuePath(), isRepairQueueItem);
	}

	function rebuildFailureSummary(): Map<string, number> {
		const summary = new Map<string, number>();
		for (const row of readRuntimeFailureLedgerRows()) {
			summary.set(row.signature, (summary.get(row.signature) ?? 0) + 1);
		}
		writePrivateTextFile(runtimeFailureSummaryPath(), JSON.stringify(Object.fromEntries(summary)));
		return summary;
	}

	function readFailureSummary(): Map<string, number> {
		ensureReconStorage();
		const path = runtimeFailureSummaryPath();
		if (existsSync(path)) {
			try {
				const parsed: unknown = JSON.parse(readTextFile(path) || "{}");
				if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
					return rebuildFailureSummary();
				}
				const raw = parsed as Record<string, unknown>;
				const summary = new Map<string, number>();
				for (const [signature, count] of Object.entries(raw)) {
					if (typeof count === "number" && Number.isFinite(count) && count > 0) {
						summary.set(signature, Math.floor(count));
					}
				}
				return summary;
			} catch {
				// Rebuild a missing or corrupt compact summary from the append-only ledger.
			}
		}
		return rebuildFailureSummary();
	}

	function bumpFailureSummary(signatures: string[]): void {
		if (!signatures.length) return;
		const summary = readFailureSummary();
		for (const signature of signatures) summary.set(signature, (summary.get(signature) ?? 0) + 1);
		writePrivateTextFile(runtimeFailureSummaryPath(), JSON.stringify(Object.fromEntries(summary)));
	}

	function rotateFailureLedger(): void {
		const maxRows = failureLedgerMaxRows();
		if (maxRows <= 0) return;
		const rows = readRuntimeFailureLedgerRows();
		if (rows.length <= maxRows) return;
		writePrivateTextFile(
			runtimeFailureLedgerPath(),
			`${rows
				.slice(-maxRows)
				.map((row) => JSON.stringify(row))
				.join("\n")}\n`,
		);
	}

	function rotateRepairQueue(): void {
		const maxRows = repairQueueMaxRows();
		if (maxRows <= 0) return;
		const rows = readRuntimeRepairQueueRows();
		if (rows.length <= maxRows) return;
		writePrivateTextFile(
			runtimeRepairQueuePath(),
			`${rows
				.slice(-maxRows)
				.map((row) => JSON.stringify(row))
				.join("\n")}\n`,
		);
	}

	function runtimeFailureAttempt(signature: string): number {
		return (readFailureSummary().get(signature) ?? 0) + 1;
	}

	function runtimeFailureCategory(reason: string): RuntimeFailureCategory {
		if (
			/command not found|not found|No such file|cannot stat|ModuleNotFoundError|ImportError|missing tool|dependency/i.test(
				reason,
			)
		)
			return "tool_missing";
		if (/artifact missing|no .*artifact|stale|hash drift/i.test(reason)) return "artifact_stale";
		if (
			/blocked|unresolved|placeholder|checkpoint|claim|contract|budget|coverage|supervisor|verifier|compiler/i.test(
				reason,
			)
		)
			return "contract_gap";
		return "runtime_failed";
	}

	function runtimeRepairAction(category: RuntimeFailureCategory, reason: string): RuntimeRepairAction {
		if (category === "tool_missing") return "refresh-context";
		if (category === "artifact_stale" || /unresolved|placeholder|recapture|map/i.test(reason))
			return "recapture-evidence";
		if (/budget|coverage|claim|supervisor|escalat/i.test(reason)) return "escalate";
		if (category === "contract_gap") return "replace-command";
		return "rerun";
	}

	function runtimeFailureCommandTarget(target?: string): string {
		return target?.trim() || "<target>";
	}

	function runtimeArtifactHashes(paths: Array<string | undefined>): FailureRepairArtifactHash[] {
		return Array.from(new Set(paths.filter((path): path is string => Boolean(path))))
			.slice(0, 24)
			.flatMap((path) => {
				try {
					if (!existsSync(path) || !statSync(path).isFile()) return [];
					return [{ path, sha256: hashFileSha256(path), tier: artifactTier(path) }];
				} catch {
					// Artifacts can disappear between discovery and hashing. Failure
					// recording must still succeed when that race occurs.
					return [];
				}
			});
	}

	function failureToRepair(
		failure: FailureLedgerEventV1,
		commands: string[],
		action: RuntimeRepairAction,
		expectedChecks: string[],
		expectedArtifacts: string[],
	): RepairQueueItemV1 {
		const paused = commands.some((command) => /\b(?:live|provider|model|api[_-]?key|secret|token)\b/i.test(command));
		return {
			repairId: failure.repairId,
			fromFailureId: failure.id,
			signature: failure.signature,
			scope: failure.scope,
			action,
			repairAction: action,
			commands: Array.from(new Set(commands)).slice(0, 12),
			expectedArtifacts: Array.from(new Set(expectedArtifacts.filter(Boolean))).slice(0, 24),
			expectedChecks,
			preconditions: { liveAllowed: false, providerAllowed: false, requiredSecrets: [] },
			paused,
			allowlist: failure.rollback.allowlist,
			rollbackCriteria: {
				baseline: failure.rollback.baseline,
				mustRestore: failure.rollback.allowlist,
				verificationCommand: "re_proof_loop run <target> 4 2",
			},
			blockedConditions: failure.blockedConditions,
			evidenceWriteback: failure.evidenceWriteback,
			regressionChecks: Array.from(new Set(["verifier_matrix_ready", ...expectedChecks])).slice(0, 8),
		};
	}

	function buildRuntimeFailureRepair(input: RuntimeFailureRepairInput): {
		failure: FailureLedgerEventV1;
		repair: RepairQueueItemV1;
	} {
		const category = input.category ?? runtimeFailureCategory(input.reason);
		const action = runtimeRepairAction(category, input.reason);
		const signature = failureSignature({
			scope: input.scope,
			category,
			command: input.commands?.[0],
			reason: input.reason,
		});
		const attempt = runtimeFailureAttempt(signature);
		const maxAttempts = Math.max(1, input.maxAttempts ?? 3);
		const exhausted = attempt >= maxAttempts && input.status !== "blocked";
		const status: RuntimeFailureStatus = exhausted ? "exhausted" : (input.status ?? "repair_queued");
		const artifacts = runtimeArtifactHashes(input.sourceArtifacts);
		const artifactHashes = artifacts.map((artifact) => ({ path: artifact.path, sha256: artifact.sha256 }));
		const repairId = `repair:runtime:${signature.slice(0, 16)}`;
		const id = `fail:runtime:${signature.slice(0, 16)}:${attempt}`;
		const exhaustedAction = `re_operator escalate ${runtimeFailureCommandTarget(input.target)}`;
		const budget = {
			retryKey: signature,
			remainingAttempts: Math.max(0, maxAttempts - attempt),
			exhaustedAction,
		};
		const evidenceWriteback: FailureRepairEvidenceWriteback = {
			failureLedgerPath: runtimeFailureLedgerPath(),
			repairQueuePath: runtimeRepairQueuePath(),
			appendOnly: true,
			mode: "runtime",
		};
		const failure: FailureLedgerEventV1 = {
			id,
			ts: new Date().toISOString(),
			source: input.source,
			scope: input.scope,
			category,
			signature,
			attempt,
			maxAttempts,
			status,
			failedChecks: input.failedChecks,
			artifacts,
			artifactHashes,
			repairId,
			budget,
			retryBudget: budget,
			evidenceWriteback,
			blockedConditions: [
				{ reason: input.reason, unblock: input.unblock ?? (input.commands?.[0] || exhaustedAction) },
			],
			rollback: {
				required: false,
				baseline: artifactHashes[0]?.sha256 ?? "none",
				allowlist: input.sourceArtifacts.filter(Boolean).slice(0, 12),
				criteria: input.failedChecks,
				restored: false,
			},
		};
		const commands = Array.from(new Set(input.commands?.filter(Boolean) ?? [exhaustedAction])).slice(0, 12);
		return {
			failure,
			repair: failureToRepair(
				failure,
				commands.length ? commands : [exhaustedAction],
				action,
				input.failedChecks,
				input.expectedArtifacts ?? input.sourceArtifacts.filter(Boolean),
			),
		};
	}

	function appendFailureRepairLedger(params: {
		failures: FailureLedgerEventV1[];
		repairs: RepairQueueItemV1[];
	}): void {
		const failures = params.failures.filter(isFailureLedgerEvent);
		const repairs = params.repairs.filter(isRepairQueueItem);
		if (!failures.length && !repairs.length) return;
		ensureReconStorage();
		if (failures.length) {
			// Migrate before append so a rebuilt summary does not count the new rows twice.
			readFailureSummary();
			appendPrivateTextFile(
				runtimeFailureLedgerPath(),
				`${failures.map((item) => JSON.stringify(item)).join("\n")}\n`,
			);
			bumpFailureSummary(failures.map((failure) => failure.signature));
			rotateFailureLedger();
		}
		if (repairs.length) {
			appendPrivateTextFile(runtimeRepairQueuePath(), `${repairs.map((item) => JSON.stringify(item)).join("\n")}\n`);
			rotateRepairQueue();
		}
	}

	function repairRollbackPolicyPath(source: string, timestamp = new Date().toISOString()): string {
		const dir = join(evidenceRepairsDir(), "rollback-policies");
		mkdirSync(dir, { recursive: true });
		return join(dir, `${timestamp.replace(/[:.]/g, "-")}-${slug(source).slice(0, 80)}-repair-rollback-policy.json`);
	}

	function repairRollbackSnapshot(files: string[]): RepairRollbackPolicyV1["baseline"] {
		const rows = uniqueNonEmpty(files, 64)
			.flatMap((path) => {
				try {
					if (!existsSync(path)) return [];
					const stat = statSync(path);
					if (!stat.isFile()) return [];
					return [{ path, bytes: stat.size, sha256: hashFileSha256(path) }];
				} catch {
					return [];
				}
			})
			.sort((left, right) => left.path.localeCompare(right.path));
		return {
			command: "repairRollbackSnapshot(files)",
			treeSha256: createHash("sha256").update(JSON.stringify(rows)).digest("hex"),
			files: rows,
		};
	}

	function repairRollbackRegressionCheck(
		checkId: string,
		command: string,
		artifactPath?: string,
	): RepairRollbackPolicyV1["regression"]["checkpoints"][number] {
		let artifactSha256: string | undefined;
		if (artifactPath) {
			try {
				if (existsSync(artifactPath) && statSync(artifactPath).isFile()) {
					artifactSha256 = hashFileSha256(artifactPath);
				}
			} catch {
				// A disappearing artifact is missing verification evidence, not a
				// reason to lose the rollback-policy record itself.
			}
		}
		return {
			checkId,
			command,
			status: "skipped",
			...(artifactPath && artifactSha256 ? { artifactPath, artifactSha256 } : {}),
		};
	}

	function buildRepairRollbackPolicyFromAutofix(
		autofix: RuntimeAutofixArtifact,
		autofixArtifactPath: string,
	): RepairRollbackPolicyV1 {
		const reportPath = autofix.repairRollbackPolicyPath ?? repairRollbackPolicyPath("re_autofix", autofix.timestamp);
		const baselinePath = reportPath.replace(/\.json$/i, "-baseline.json");
		const sourceArtifactHashes = runtimeArtifactHashes([
			autofix.replayArtifact,
			autofix.compilerArtifact,
			...autofix.sourceArtifacts,
		]);
		writePrivateTextFile(
			baselinePath,
			`${JSON.stringify(
				{
					kind: "RepairRollbackBaselineSnapshotV1",
					schemaVersion: 1,
					generatedAt: new Date().toISOString(),
					source: "re_autofix",
					target: autofix.target,
					mode: autofix.mode,
					autofixArtifactPath,
					sourceArtifactHashes,
				},
				null,
				2,
			)}\n`,
		);
		const baseline = repairRollbackSnapshot(
			uniqueNonEmpty(
				[baselinePath, autofix.replayArtifact, autofix.compilerArtifact, ...autofix.sourceArtifacts],
				64,
			),
		);
		const stateChangingCommands = uniqueNonEmpty(
			[
				...autofix.patchQueue.map((item) => item.command),
				...(autofix.mode === "apply" ? autofix.applied : []),
				...autofix.nextOperatorQueue.filter((item) =>
					/patch|fix|repair|compiler|operator|apply|rollback/i.test(item),
				),
			],
			16,
		);
		const allowlist = uniqueNonEmpty(
			[
				baselinePath,
				autofixArtifactPath,
				autofix.replayArtifact,
				autofix.compilerArtifact,
				...autofix.sourceArtifacts,
			],
			64,
		);
		const changedFiles = uniqueNonEmpty(
			[autofixArtifactPath, ...autofix.patchQueue.flatMap((item) => item.sourceArtifacts)],
			32,
		).filter((path) => allowlist.includes(path));
		const targetRef = runtimeFailureCommandTarget(autofix.target);
		const { failure, repair } = buildRuntimeFailureRepair({
			source: "re_autofix",
			scope: `${autofix.target ?? autofix.route ?? autofix.missionId ?? "autofix"}:repair-rollback-policy`,
			target: autofix.target,
			reason:
				"state-changing autofix repair is guarded by baseline, allowlist, regression checkpoint, and rollback restore proof",
			category: "contract_gap",
			status: "repair_queued",
			commands: stateChangingCommands.length
				? stateChangingCommands
				: [`re_autofix apply ${targetRef}`, `npm run check`],
			failedChecks: ["autofix_ready", "repair_rollback_policy", "check:repair-rollback-policy"],
			sourceArtifacts: allowlist,
			expectedArtifacts: [autofixArtifactPath, reportPath, baselinePath],
			maxAttempts: 1,
			unblock: `npm run check && re_autofix apply ${targetRef}`,
		});
		failure.rollback = {
			required: true,
			baseline: baseline.treeSha256,
			allowlist,
			criteria: [
				"restore baseline tree hash",
				"no unrelated file changes",
				"repair regression checkpoints stay pass",
			],
			restored: false,
		};
		failure.status = "repair_queued";
		repair.action = "rollback";
		repair.repairAction = "rollback";
		repair.commands = uniqueNonEmpty(
			[
				...stateChangingCommands,
				`printf '%s\\n' 'rollback criteria: restore ${baseline.treeSha256}'`,
				`npm run check`,
			],
			16,
		);
		repair.expectedArtifacts = uniqueNonEmpty([autofixArtifactPath, reportPath, baselinePath], 16);
		repair.expectedChecks = ["autofix_ready", "check:repair-rollback-policy"];
		repair.allowlist = allowlist;
		repair.rollbackCriteria = {
			baseline: baseline.treeSha256,
			mustRestore: allowlist,
			verificationCommand: "npm run check",
		};
		repair.regressionChecks = ["autofix_ready", "check:repair-rollback-policy"];
		const failureRepairValidation = {
			ok:
				failure.repairId === repair.repairId && repair.fromFailureId === failure.id && repair.action === "rollback",
			failureCount: 1,
			repairCount: 1,
		};
		const regressionChecks = [
			repairRollbackRegressionCheck("autofix_ready", "re_autofix plan/apply", autofixArtifactPath),
			repairRollbackRegressionCheck("check:repair-rollback-policy", "npm run check", baselinePath),
		];
		return {
			kind: "RepairRollbackPolicyV1",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			source: "re_autofix",
			workspace: process.cwd(),
			baseline,
			allowlist,
			repair: {
				commands: repair.commands,
				changedFiles: changedFiles.length ? changedFiles : [autofixArtifactPath],
				expectedArtifacts: repair.expectedArtifacts,
				regressionChecks: repair.regressionChecks,
			},
			rollback: {
				required: true,
				commands: [`npm run check`, `re_autofix plan ${targetRef}`],
				restored: false,
				restoredTreeSha256: "not-verified",
				criteria: failure.rollback.criteria,
			},
			regression: {
				before: "skipped",
				after: "skipped",
				restored: "skipped",
				checkpoints: regressionChecks,
			},
			failureLedgerEvents: [failure],
			repairQueue: [repair],
			failureRepairValidation,
			assertions: {
				baselineCaptured: Boolean(baseline.treeSha256 && baseline.files.length),
				allowlistEnforced: (changedFiles.length ? changedFiles : [autofixArtifactPath]).every((path) =>
					allowlist.includes(path),
				),
				rollbackRestored: false,
				regressionChecksPassed: regressionChecks.every((checkpoint) => checkpoint.status === "pass"),
				noUnrelatedFileChanges: false,
				failureRepairLinked: failureRepairValidation.ok,
			},
		};
	}

	function writeAutofixRepairRollbackPolicy(
		autofix: RuntimeAutofixArtifact,
		autofixArtifactPath: string,
	): { path?: string; status: "pass" | "blocked" | "missing"; errors: string[]; report?: RepairRollbackPolicyV1 } {
		if (!autofix.patchQueue.length && autofix.mode !== "apply") {
			return { status: "missing", errors: ["state_changing_repair_not_queued"] };
		}
		const reportPath = autofix.repairRollbackPolicyPath ?? repairRollbackPolicyPath("re_autofix", autofix.timestamp);
		const report = buildRepairRollbackPolicyFromAutofix(
			{ ...autofix, repairRollbackPolicyPath: reportPath },
			autofixArtifactPath,
		);
		const validation = verifyRepairRollbackPolicyV1(report);
		writePrivateTextFile(reportPath, `${JSON.stringify({ report, validation }, null, 2)}\n`);
		appendFailureRepairLedger({ failures: report.failureLedgerEvents, repairs: report.repairQueue });
		return { path: reportPath, status: validation.ok ? "pass" : "blocked", errors: validation.errors, report };
	}

	function targetMatches(values: Array<string | undefined>, target?: string): boolean {
		if (!target) return true;
		const needle = target.toLowerCase();
		return values.filter(Boolean).some((item) => item?.toLowerCase().includes(needle));
	}

	function failurePriority(status: RuntimeFailureStatus): number {
		if (status === "exhausted") return 5;
		if (status === "blocked") return 4;
		if (status === "repair_queued") return 3;
		if (status === "failed") return 2;
		if (status === "rolled_back") return 1;
		return 0;
	}

	function failureSignaturePriorityReport(target?: string): FailureSignaturePriorityReport {
		const failures = readRuntimeFailureLedgerRows().filter((failure) =>
			targetMatches(
				[
					failure.scope,
					...failure.failedChecks,
					...failure.blockedConditions.flatMap((condition) => [condition.reason, condition.unblock]),
					...failure.artifactHashes.map((artifact) => artifact.path),
				],
				target,
			),
		);
		const failureIds = new Set(failures.map((failure) => failure.id));
		const failureSignatures = new Set(failures.map((failure) => failure.signature));
		const repairs = readRuntimeRepairQueueRows().filter(
			(repair) =>
				(!target ||
					targetMatches(
						[
							repair.scope,
							...repair.commands,
							...repair.expectedArtifacts,
							...repair.expectedChecks,
							...repair.blockedConditions.flatMap((condition) => [condition.reason, condition.unblock]),
						],
						target,
					) ||
					failureIds.has(repair.fromFailureId)) &&
				(!failureSignatures.size || failureSignatures.has(repair.signature)),
		);
		const repairBySignature = new Map<string, RepairQueueItemV1>();
		for (const repair of repairs) {
			const existing = repairBySignature.get(repair.signature);
			if (!existing || (existing.paused && !repair.paused) || repair.commands.length > existing.commands.length) {
				repairBySignature.set(repair.signature, repair);
			}
		}
		const grouped = new Map<string, FailureLedgerEventV1[]>();
		for (const failure of failures) {
			grouped.set(failure.signature, [...(grouped.get(failure.signature) ?? []), failure]);
		}
		const latest = [...grouped.values()]
			.map((rows) => rows.sort((left, right) => right.attempt - left.attempt || right.ts.localeCompare(left.ts))[0]!)
			.sort(
				(left, right) =>
					failurePriority(right.status) - failurePriority(left.status) ||
					right.attempt - left.attempt ||
					left.budget.remainingAttempts - right.budget.remainingAttempts ||
					right.ts.localeCompare(left.ts),
			);
		const rows = latest.slice(0, 16).map((failure) => {
			const repair = repairBySignature.get(failure.signature);
			const repeats = grouped.get(failure.signature)?.length ?? 1;
			const readyRepair = repair && !repair.paused && repair.commands.length > 0;
			const next = readyRepair ? repair.commands[0] : failure.budget.exhaustedAction;
			return [
				`failure_signature_priority status=${failure.status}`,
				`attempt=${failure.attempt}/${failure.maxAttempts}`,
				`repeats=${repeats}`,
				`remaining=${failure.budget.remainingAttempts}`,
				`signature=${failure.signature.slice(0, 16)}`,
				`source=${failure.source}`,
				`category=${failure.category}`,
				`repair_action=${readyRepair ? repair.action : "escalate"}`,
				`repair_ready=${readyRepair ? "true" : "false"}`,
				`failed_checks=${failure.failedChecks.join("|") || "none"}`,
				`next=${next}`,
			].join(" ");
		});
		return {
			rows,
			commands: uniqueNonEmpty(
				latest.flatMap((failure) => {
					const repair = repairBySignature.get(failure.signature);
					return repair && !repair.paused && repair.commands.length
						? repair.commands
						: [failure.budget.exhaustedAction];
				}),
				16,
			),
			repairQueue: repairs
				.slice(0, 16)
				.map((repair) =>
					[
						`failure_signature_repair_queue repair_id=${repair.repairId}`,
						`signature=${repair.signature.slice(0, 16)}`,
						`action=${repair.action}`,
						`paused=${repair.paused}`,
						`ready=${!repair.paused && repair.commands.length > 0}`,
						`commands=${repair.commands.join(" && ") || "missing"}`,
						`expected_checks=${repair.expectedChecks.join("|") || "none"}`,
					].join(" "),
				),
			sourceArtifacts: uniqueNonEmpty(
				[
					runtimeFailureLedgerPath(),
					runtimeRepairQueuePath(),
					...latest.flatMap((failure) => failure.artifactHashes.map((artifact) => artifact.path)),
				],
				32,
			),
			exhaustedCount: latest.filter((failure) => failure.status === "exhausted").length,
			repeatedCount: [...grouped.values()].filter((items) => items.length > 1).length,
		};
	}

	function appendRuntimeFailureInputs(inputs: RuntimeFailureRepairInput[]): void {
		const failures: FailureLedgerEventV1[] = [];
		const repairs: RepairQueueItemV1[] = [];
		const seen = new Set<string>();
		for (const input of inputs.slice(0, 32)) {
			const category = input.category ?? runtimeFailureCategory(input.reason);
			const signature = failureSignature({
				scope: input.scope,
				category,
				command: input.commands?.[0],
				reason: input.reason,
			});
			if (seen.has(signature)) continue;
			seen.add(signature);
			const { failure, repair } = buildRuntimeFailureRepair(input);
			failures.push(failure);
			repairs.push(repair);
		}
		appendFailureRepairLedger({ failures, repairs });
	}

	function appendRuntimeFailureRepairFromReplay(replay: ReplayArtifact, path: string): void {
		if (replay.mode !== "run" || (replay.failed === 0 && replay.blocked.length === 0)) return;
		const targetRef = runtimeFailureCommandTarget(replay.target);
		const sourceArtifacts = [path, replay.compilerArtifact, ...replay.sourceArtifacts].filter(Boolean) as string[];
		const inputs: RuntimeFailureRepairInput[] = [];
		for (const execution of replay.executions.filter((item) => item.status === "failed").slice(0, 16)) {
			const reason = `replay failed: ${execution.stepId} exit=${execution.exit} killed=${execution.killed === true} command=${execution.command} stdout_sha256=${execution.stdoutHash} stderr_sha256=${execution.stderrHash} stderr=${truncateMiddle(execution.stderrHead, 260)}`;
			inputs.push({
				source: "re_replayer",
				scope: `${replay.target ?? replay.route ?? replay.missionId ?? "replay"}:${execution.stepId}`,
				target: replay.target,
				reason,
				category: runtimeFailureCategory(reason),
				status: "failed",
				commands: [
					`re_autofix plan ${targetRef}`,
					`re_replayer run ${targetRef} 1`,
					`re_operator escalate ${targetRef}`,
				],
				failedChecks: ["replay_ready", "autofix_ready"],
				sourceArtifacts,
				expectedArtifacts: [path, latestAutofixArtifactPath()].filter(Boolean) as string[],
			});
		}
		for (const blocked of replay.blocked.slice(0, 16)) {
			const command = /::\s*(.+)$/.exec(blocked)?.[1]?.trim();
			inputs.push({
				source: "re_replayer",
				scope: `${replay.target ?? replay.route ?? replay.missionId ?? "replay"}:blocked:${slug(blocked).slice(0, 24)}`,
				target: replay.target,
				reason: `replay blocked: ${blocked}`,
				category: runtimeFailureCategory(blocked),
				status: "blocked",
				commands: [
					`re_autofix plan ${targetRef}`,
					command ? `re_operator plan ${targetRef}` : `re_operator escalate ${targetRef}`,
				],
				failedChecks: ["replay_ready", "operator_queue_ready"],
				sourceArtifacts,
				expectedArtifacts: [path, latestAutofixArtifactPath()].filter(Boolean) as string[],
				unblock: command ?? `re_autofix plan ${targetRef}`,
			});
		}
		appendRuntimeFailureInputs(inputs);
	}

	function appendRuntimeFailureRepairFromAutofix(autofix: RuntimeAutofixArtifact, path: string): void {
		const targetRef = runtimeFailureCommandTarget(autofix.target);
		const sourceArtifacts = [
			path,
			autofix.replayArtifact,
			autofix.compilerArtifact,
			...autofix.sourceArtifacts,
		].filter(Boolean) as string[];
		const allItems = [
			...autofix.patchQueue,
			...autofix.commandSubstitutions,
			...autofix.bootstrapQueue,
			...autofix.evidenceRecaptureQueue,
		];
		const queuedCommands = allItems.map((item) => item.command);
		const inputs: RuntimeFailureRepairInput[] = autofix.failures.slice(0, 16).map((failure) => ({
			source: "re_autofix",
			scope: `${autofix.target ?? autofix.route ?? autofix.missionId ?? "autofix"}:failure:${slug(failure).slice(0, 24)}`,
			target: autofix.target,
			reason: `autofix queued repair for replay/compiler failure: ${failure}`,
			category: runtimeFailureCategory(failure),
			status: "repair_queued",
			commands: queuedCommands.length ? queuedCommands.slice(0, 8) : [`re_operator escalate ${targetRef}`],
			failedChecks: ["autofix_ready", "replay_ready"],
			sourceArtifacts,
			expectedArtifacts: [path, autofix.replayArtifact].filter(Boolean) as string[],
		}));
		for (const item of allItems.filter((entry) => entry.status === "blocked").slice(0, 16)) {
			inputs.push({
				source: "re_autofix",
				scope: `${autofix.target ?? autofix.route ?? autofix.missionId ?? "autofix"}:${item.id}`,
				target: autofix.target,
				reason: `autofix item blocked: ${item.kind} ${item.reason}; command=${item.command}`,
				category: runtimeFailureCategory(`${item.reason} ${item.command}`),
				status: "blocked",
				commands: [item.command, `re_operator escalate ${targetRef}`],
				failedChecks: ["autofix_ready", "operator_queue_ready"],
				sourceArtifacts: [path, ...item.sourceArtifacts, ...sourceArtifacts],
				expectedArtifacts: [path, autofix.replayArtifact].filter(Boolean) as string[],
			});
		}
		appendRuntimeFailureInputs(inputs);
	}

	function appendRuntimeFailureRepairFromOperator(operator: RuntimeOperatorArtifact, path: string): void {
		if (operator.mode !== "dispatch") return;
		const targetRef = runtimeFailureCommandTarget(operator.target);
		const sourceArtifacts = [path, ...operator.sourceArtifacts];
		const inputs: RuntimeFailureRepairInput[] = [];
		for (const execution of operator.executed.filter((item) => item.status === "blocked").slice(0, 16)) {
			inputs.push({
				source: "re_operator",
				scope: `${operator.target ?? operator.route ?? operator.missionId ?? "operator"}:${execution.stepId}`,
				target: operator.target,
				reason: `operator execution blocked: command=${execution.command}; output=${truncateMiddle(execution.output, 360)}`,
				category: runtimeFailureCategory(execution.output),
				status: "blocked",
				commands: [
					`re_autofix plan ${targetRef}`,
					`re_proof_loop run ${targetRef} 4 2`,
					`re_operator escalate ${targetRef}`,
				],
				failedChecks: ["operator_queue_ready", "proof_loop_ready"],
				sourceArtifacts,
				expectedArtifacts: [path, latestProofLoopArtifactPath()].filter(Boolean) as string[],
			});
		}
		for (const step of operator.steps.filter((item) => item.status === "blocked").slice(0, 16)) {
			inputs.push({
				source: "re_operator",
				scope: `${operator.target ?? operator.route ?? operator.missionId ?? "operator"}:${step.id}`,
				target: operator.target,
				reason: `operator step blocked: ${step.reason ?? "blocked"}; command=${step.command}`,
				category: runtimeFailureCategory(`${step.reason ?? ""} ${step.command}`),
				status: "blocked",
				commands: [`re_autofix plan ${targetRef}`, `re_operator escalate ${targetRef}`],
				failedChecks: ["operator_queue_ready"],
				sourceArtifacts: [path, ...step.sourceArtifacts, ...sourceArtifacts],
				expectedArtifacts: [path],
			});
		}
		for (const row of operator.operatorFeedback
			.filter((item) =>
				/(missing_tool_or_dependency|unresolved_target|runtime_failure|dispatcher_gap|failure_budget_exhausted|swarm_retry_queue|worker_retry_blocked)/i.test(
					item,
				),
			)
			.slice(0, 16)) {
			const category = operatorFeedbackCategory(row);
			const commands = operatorFeedbackFallbackCommands(row, operator.target);
			inputs.push({
				source: "re_operator",
				scope: `${operator.target ?? operator.route ?? operator.missionId ?? "operator"}:feedback:${slug(row).slice(0, 24)}`,
				target: operator.target,
				reason: `operator feedback ${category}: ${row}`,
				category: runtimeFailureCategory(row),
				status: /failure_budget_exhausted/i.test(row) ? "exhausted" : "repair_queued",
				commands: commands.length ? commands : [`re_operator escalate ${targetRef}`],
				failedChecks: ["operator_queue_ready", "autofix_ready"],
				sourceArtifacts,
				expectedArtifacts: [path, latestAutofixArtifactPath()].filter(Boolean) as string[],
			});
		}
		for (const report of operator.commanderDispatchReport
			.filter((item) => /failure_budget_exhausted/i.test(item))
			.slice(0, 4)) {
			inputs.push({
				source: "re_operator",
				scope: `${operator.target ?? operator.route ?? operator.missionId ?? "operator"}:failure_budget`,
				target: operator.target,
				reason: report,
				category: "contract_gap",
				status: "exhausted",
				commands: [`re_proof_loop run ${targetRef} 4 2`, `re_operator escalate ${targetRef}`],
				failedChecks: ["operator_queue_ready", "proof_loop_ready"],
				sourceArtifacts,
				expectedArtifacts: [path, latestProofLoopArtifactPath()].filter(Boolean) as string[],
			});
		}
		appendRuntimeFailureInputs(inputs);
	}

	function appendRuntimeFailureRepairFromProofLoop(proof: RuntimeProofLoopArtifact, path: string): void {
		if (
			proof.mode !== "run" ||
			(!["needs_repair", "blocked"].includes(proof.verdict) &&
				!proof.steps.some((step) => step.status === "blocked") &&
				!proof.executed.some((execution) => execution.status === "blocked"))
		)
			return;
		const targetRef = runtimeFailureCommandTarget(proof.target);
		const sourceArtifacts = [path, ...proof.bridgeArtifacts, ...proof.sourceArtifacts].filter(Boolean) as string[];
		const repairCommands = proof.nextActions.length
			? proof.nextActions.slice(0, 10)
			: [`re_autofix plan ${targetRef}`, `re_delegate plan ${targetRef}`, `re_swarm run ${targetRef}`];
		const inputs: RuntimeFailureRepairInput[] = [];
		if (proof.verdict === "needs_repair" || proof.verdict === "blocked") {
			const reason = `proof loop verdict=${proof.verdict}; specialist=${proof.specialistQueue.length}; swarm_bridge=${proof.swarmBridge.length}; operator_feedback=${proof.operatorFeedback.length}`;
			inputs.push({
				source: "re_proof_loop",
				scope: `${proof.target ?? proof.route ?? proof.missionId ?? "proof"}:verdict`,
				target: proof.target,
				reason,
				category: "contract_gap",
				status: proof.verdict === "blocked" ? "blocked" : "repair_queued",
				commands: repairCommands,
				failedChecks: [
					"proof_loop_ready",
					"verifier_matrix_ready",
					"compiler_ready",
					"replay_ready",
					"autofix_ready",
				],
				sourceArtifacts,
				expectedArtifacts: [path, latestSupervisorArtifactPath(), latestAutofixArtifactPath()].filter(
					Boolean,
				) as string[],
			});
		}
		for (const step of proof.steps.filter((item) => item.status === "blocked").slice(0, 16)) {
			inputs.push({
				source: "re_proof_loop",
				scope: `${proof.target ?? proof.route ?? proof.missionId ?? "proof"}:${step.id}`,
				target: proof.target,
				reason: `proof-loop step blocked: ${step.reason ?? "blocked"}; command=${step.command}`,
				category: runtimeFailureCategory(`${step.reason ?? ""} ${step.command}`),
				status: "blocked",
				commands: [step.command, ...repairCommands].slice(0, 8),
				failedChecks: ["proof_loop_ready"],
				sourceArtifacts: [path, ...step.sourceArtifacts, ...sourceArtifacts],
				expectedArtifacts: [path],
			});
		}
		for (const execution of proof.executed.filter((item) => item.status === "blocked").slice(0, 16)) {
			inputs.push({
				source: "re_proof_loop",
				scope: `${proof.target ?? proof.route ?? proof.missionId ?? "proof"}:${execution.stepId}`,
				target: proof.target,
				reason: `proof-loop execution blocked: command=${execution.command}; output=${truncateMiddle(execution.output, 360)}`,
				category: runtimeFailureCategory(execution.output),
				status: "blocked",
				commands: repairCommands,
				failedChecks: ["proof_loop_ready", "operator_queue_ready"],
				sourceArtifacts,
				expectedArtifacts: [path, latestAutofixArtifactPath()].filter(Boolean) as string[],
			});
		}
		appendRuntimeFailureInputs(inputs);
	}

	return {
		appendFailureRepairLedger,
		appendRuntimeFailureRepairFromAutofix,
		appendRuntimeFailureRepairFromOperator,
		appendRuntimeFailureRepairFromProofLoop,
		appendRuntimeFailureRepairFromReplay,
		buildRuntimeFailureRepair,
		failureSignaturePriorityReport,
		buildRepairRollbackPolicyFromAutofix,
		writeAutofixRepairRollbackPolicy,
		readRuntimeFailureLedgerRows,
		readRuntimeRepairQueueRows,
		runtimeArtifactHashes,
		runtimeFailureAttempt,
		runtimeFailureCommandTarget,
	};
}
