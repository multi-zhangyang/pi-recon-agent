import { lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

/**
 * The two swarm implementations deliberately keep their native artifact
 * layouts. This module is the read-only compatibility boundary between them.
 * It returns a small, stable reference instead of making callers understand
 * either layout (or accidentally treating a path as a run id).
 */
export const SWARM_RUN_REF_KIND = "SwarmRunRefV1";
export const SWARM_CATALOG_SCHEMA_VERSION = 1;

const MAX_ARTIFACT_BYTES = 8 * 1024 * 1024;

function defaultAgentDir() {
	return process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
}

function safeStat(path) {
	try {
		return statSync(path);
	} catch {
		return undefined;
	}
}

function safeLstat(path) {
	try {
		return lstatSync(path);
	} catch {
		return undefined;
	}
}

function readJson(path) {
	const stat = safeStat(path);
	if (!stat?.isFile() || stat.size > MAX_ARTIFACT_BYTES) return undefined;
	try {
		const parsed = JSON.parse(readFileSync(path, "utf8"));
		return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : undefined;
	} catch {
		return undefined;
	}
}

function readText(path) {
	const stat = safeStat(path);
	if (!stat?.isFile() || stat.size > MAX_ARTIFACT_BYTES) return undefined;
	try {
		return readFileSync(path, "utf8");
	} catch {
		return undefined;
	}
}

function parseTsArtifact(path) {
	const text = readText(path);
	if (!text) return undefined;
	// TS runtime artifacts are markdown wrappers around one JSON code fence.
	// Restrict the match to a bounded file read and validate the identifying
	// fields so unrelated evidence markdown is never advertised as a swarm.
	const match = /```json\s*\n([\s\S]*?)\n```/i.exec(text);
	if (!match) return undefined;
	try {
		const parsed = JSON.parse(match[1]);
		if (
			!parsed ||
			typeof parsed !== "object" ||
			Array.isArray(parsed) ||
			typeof parsed.timestamp !== "string" ||
			!new Set(["plan", "run", "merge"]).has(parsed.mode) ||
			!Array.isArray(parsed.workers) ||
			!Array.isArray(parsed.executions)
		)
			return undefined;
		return parsed;
	} catch {
		return undefined;
	}
}

function parseDateMs(value) {
	const parsed = Date.parse(String(value ?? ""));
	return Number.isFinite(parsed) ? parsed : undefined;
}

function cliCreatedAtMs(runId, plan, report, merge, stat) {
	// Run ids are generated before execution and therefore remain stable after
	// merge. Prefer that creation timestamp over mutable directory mtime.
	const runIdDate = /^(\d{4}-\d{2}-\d{2}T)(\d{2})-(\d{2})-(\d{2})-(\d{3})Z(?:-|$)/.exec(runId);
	if (runIdDate) {
		const parsed = parseDateMs(`${runIdDate[1]}${runIdDate[2]}:${runIdDate[3]}:${runIdDate[4]}.${runIdDate[5]}Z`);
		if (parsed !== undefined) return parsed;
	}
	return (
		parseDateMs(plan?.generatedAt) ??
		parseDateMs(report?.generatedAt) ??
		parseDateMs(merge?.generatedAt) ??
		stat?.birthtimeMs ??
		stat?.mtimeMs ??
		0
	);
}

function stateForCli(report, plan, merge) {
	// Merge is the final promotion gate. A failed merge must not be hidden by
	// an earlier successful worker report or a plan wrapper left in report.json.
	if (merge) return merge.ok === true ? "complete" : "failed";
	if (report?.kind === "repi-swarm-plan-report" || (!report && plan)) return "planned";
	if (report) return report.ok === true ? "complete" : "failed";
	return "unknown";
}

function retryAttemptForExecution(row) {
	const attempt = Number(row?.retryAttempt ?? 1);
	return Number.isInteger(attempt) && attempt > 0 ? attempt : 1;
}

function latestAttemptExecutions(executions) {
	if (!Array.isArray(executions) || executions.length === 0) return [];
	const latestAttempt = Math.max(...executions.map(retryAttemptForExecution));
	return executions.filter((row) => retryAttemptForExecution(row) === latestAttempt);
}

function latestExecutionsByWorker(swarm) {
	const grouped = new Map();
	for (const row of Array.isArray(swarm.executions) ? swarm.executions : []) {
		const workerId = typeof row?.workerId === "string" && row.workerId ? row.workerId : "unknown";
		grouped.set(workerId, [...(grouped.get(workerId) ?? []), row]);
	}
	return new Map([...grouped].map(([workerId, rows]) => [workerId, latestAttemptExecutions(rows)]));
}

function tsStructuredClaimMergePassed(swarm) {
	const finalClaims = swarm.structuredClaimMerge?.promotionCheck?.finalClaims;
	return swarm.structuredClaimMergeStatus === "pass" && Array.isArray(finalClaims) && finalClaims.length > 0;
}

function stateForTs(swarm) {
	if (swarm.mode === "plan") return "planned";
	// A run is not promotable without the structured merge gate. Fail closed for
	// missing/unknown values as well as an explicit block.
	if (!tsStructuredClaimMergePassed(swarm)) return "failed";

	const latestByWorker = latestExecutionsByWorker(swarm);
	const latestExecutions = [...latestByWorker.values()].flat();
	if (latestExecutions.some((row) => row?.timedOut || row?.status === "blocked" || row?.status === "skipped"))
		return "failed";
	// Worker/blocked fields are derived snapshots and may still describe an
	// earlier failed attempt. Only consult them when no execution exists for the
	// worker, otherwise the latest retry attempt is authoritative.
	if (
		(Array.isArray(swarm.workers) ? swarm.workers : []).some(
			(worker) => worker?.status === "blocked" && !latestByWorker.has(worker?.id),
		)
	)
		return "failed";
	if (latestExecutions.length === 0) {
		return Array.isArray(swarm.blocked) && swarm.blocked.length > 0 ? "failed" : "planned";
	}
	return latestExecutions.every((row) => row?.status === "done") ? "complete" : "planned";
}

function workerRowsForTs(swarm) {
	const executions = Array.isArray(swarm.executions) ? swarm.executions : [];
	return (Array.isArray(swarm.workers) ? swarm.workers : []).map((worker) => {
		const rows = executions.filter((row) => row?.workerId === worker?.id);
		const latestRows = latestAttemptExecutions(rows);
		const blocked = latestRows.some((row) => row?.timedOut || row?.status === "blocked" || row?.status === "skipped");
		const done = latestRows.length > 0 && !blocked && latestRows.every((row) => row?.status === "done");
		return {
			workerId: worker?.id ?? "unknown",
			role: worker?.worker,
			status: done ? "pass" : blocked || (latestRows.length === 0 && worker?.status === "blocked") ? "fail" : latestRows.length ? "running" : "planned",
			exit: latestRows.at(-1)?.exitCode ?? null,
			ms: rows.reduce((sum, row) => sum + (Number.isFinite(row?.elapsedMs) ? row.elapsedMs : 0), 0),
		};
	});
}

function summarizeTsMerge(swarm) {
	const structured = swarm.structuredClaimMerge;
	const finalClaims = structured?.promotionCheck?.finalClaims;
	return {
		ok: tsStructuredClaimMergePassed(swarm),
		promotedClaims: Array.isArray(finalClaims) ? finalClaims.length : 0,
		narrativeOnlyBlocked: false,
		structuredClaimMergeStatus: swarm.structuredClaimMergeStatus ?? "missing",
	};
}

function makeCliRef(root, runId, plan, report, merge, stat) {
	const evidenceRoot = resolve(root);
	const state = stateForCli(report, plan, merge);
	return {
		kind: SWARM_RUN_REF_KIND,
		schemaVersion: SWARM_CATALOG_SCHEMA_VERSION,
		engine: "cli",
		runId,
		path: evidenceRoot,
		evidenceRoot,
		paths: {
			root: evidenceRoot,
			evidenceRoot,
			plan: join(evidenceRoot, "plan.json"),
			report: join(evidenceRoot, "report.json"),
			mergeReport: join(evidenceRoot, "merge-report.json"),
		},
		generatedAt: merge?.generatedAt ?? report?.generatedAt ?? plan?.generatedAt ?? undefined,
		createdAtMs: cliCreatedAtMs(runId, plan, report, merge, stat),
		state,
		status: state,
		ok: state !== "failed" && state !== "unknown",
		target: merge?.target ?? report?.target ?? plan?.target,
		mode:
			report?.kind === "repi-swarm-plan-report" || (!report && plan)
				? "plan"
				: report
					? "run"
					: merge
						? "merge"
						: undefined,
		workerCount: merge?.workerCount ?? report?.workers ?? plan?.workers,
	};
}

function makeTsRef(path, swarm, stat) {
	const artifactPath = resolve(path);
	const evidenceRoot = dirname(artifactPath);
	const runId = basename(artifactPath, ".md");
	const state = stateForTs(swarm);
	const sidecar = (suffix) => artifactPath.replace(/\.md$/i, suffix);
	return {
		kind: SWARM_RUN_REF_KIND,
		schemaVersion: SWARM_CATALOG_SCHEMA_VERSION,
		engine: "ts",
		runId,
		path: artifactPath,
		evidenceRoot,
		paths: {
			root: evidenceRoot,
			evidenceRoot,
			artifact: artifactPath,
			claimLedger: swarm.claimLedgerPath ?? sidecar("-claim-ledger.jsonl"),
			structuredClaimMerge: swarm.structuredClaimMergePath ?? sidecar("-structured-claim-merge.json"),
			subagentRuntimeManifests: swarm.subagentRuntimeManifestPath ?? sidecar("-subagent-runtime-manifests.json"),
		},
		generatedAt: swarm.timestamp,
		createdAtMs: parseDateMs(swarm.timestamp) ?? stat?.birthtimeMs ?? stat?.mtimeMs ?? 0,
		state,
		status: state,
		ok: state !== "failed",
		target: swarm.target,
		mode: swarm.mode,
		workerCount: swarm.workers.length,
		workers: workerRowsForTs(swarm),
		merge: summarizeTsMerge(swarm),
	};
}

function discoverCliRuns(root) {
	const stat = safeStat(root);
	if (!stat?.isDirectory()) return [];
	let names;
	try {
		names = readdirSync(root);
	} catch {
		return [];
	}
	return names
		.map((name) => {
			const evidenceRoot = join(root, name);
				// A run directory is later used as a merge write target. Never follow a
				// catalog child symlink outside the evidence root.
				const childStat = safeLstat(evidenceRoot);
			if (!childStat?.isDirectory()) return undefined;
			const plan = readJson(join(evidenceRoot, "plan.json"));
			const report = readJson(join(evidenceRoot, "report.json"));
			const merge = readJson(join(evidenceRoot, "merge-report.json"));
			const isSwarmArtifact = [plan, report, merge].some((row) =>
				/^repi-(?:swarm|llm-worker-pool)-/.test(String(row?.kind ?? "")),
			);
			if (!isSwarmArtifact) return undefined;
			return makeCliRef(evidenceRoot, name, plan, report, merge, childStat);
		})
		.filter(Boolean);
}

function discoverTsRuns(root) {
	const stat = safeStat(root);
	if (!stat?.isDirectory()) return [];
	let names;
	try {
		names = readdirSync(root);
	} catch {
		return [];
	}
	return names
		.filter((name) => name.toLowerCase().endsWith(".md"))
		.map((name) => {
			const artifactPath = join(root, name);
				const artifactStat = safeLstat(artifactPath);
			if (!artifactStat?.isFile()) return undefined;
			const swarm = parseTsArtifact(artifactPath);
			return swarm ? makeTsRef(artifactPath, swarm, artifactStat) : undefined;
		})
		.filter(Boolean);
}

function compareRuns(left, right) {
	return right.createdAtMs - left.createdAtMs || right.runId.localeCompare(left.runId) || left.engine.localeCompare(right.engine);
}

export function discoverSwarmRuns(options = {}) {
	const agentDir = resolve(options.agentDir ?? defaultAgentDir());
	const roots = {
		cli: resolve(options.cliRoot ?? join(agentDir, "recon", "evidence", "llm-swarms")),
		ts: resolve(options.tsRoot ?? join(agentDir, "recon", "evidence", "swarms")),
	};
	return [...discoverCliRuns(roots.cli), ...discoverTsRuns(roots.ts)].sort(compareRuns);
}

function invalidRef(requested, candidates, error, message, matches = []) {
	return {
		ok: false,
		error,
		message,
		ref: requested,
		matches: matches.map((run) => run.runId),
		candidateRefs: candidates.map((run) => `${run.engine}:${run.runId}`),
	};
}

export function resolveSwarmRunRef(runs, ref = "latest") {
	const requested = typeof ref === "string" && ref.length > 0 ? ref : "latest";
	if (requested.includes("..") || requested.includes("/") || requested.includes("\\"))
		return invalidRef(requested, [], "run-not-found", `run ref '${requested}' did not match any discovered run`);
	if (requested === "latest") {
		const latest = runs[0];
		return latest
			? { ok: true, ref: requested, run: latest }
			: invalidRef(requested, [], "run-not-found", "no swarm runs found");
	}
	const enginePrefix = /^(cli|cli-llm|ts|ts-runtime):(.*)$/.exec(requested);
	const engine = enginePrefix?.[1]?.startsWith("cli") ? "cli" : enginePrefix?.[1]?.startsWith("ts") ? "ts" : undefined;
	const value = enginePrefix?.[2] ?? requested;
	const candidates = runs.filter((run) => (!engine || run.engine === engine) && run.runId === value);
	if (candidates.length === 1) return { ok: true, ref: requested, run: candidates[0] };
	if (candidates.length > 1)
		return invalidRef(requested, candidates, "run-ref-ambiguous", `run ref '${requested}' matches multiple runs`, candidates);
	const partial = runs.filter((run) => (!engine || run.engine === engine) && run.runId.includes(value));
	if (partial.length === 1) return { ok: true, ref: requested, run: partial[0] };
	if (partial.length > 1)
		return invalidRef(requested, partial, "run-ref-ambiguous", `run ref '${requested}' matches multiple runs`, partial);
	return invalidRef(requested, [], "run-not-found", `run ref '${requested}' did not match any discovered run`);
}

export function createSwarmRunCatalog(options = {}) {
	const discover = () => discoverSwarmRuns(options);
	return {
		discover,
		listRuns: discover,
		resolveRunRef(ref = "latest") {
			const runs = discover();
			return resolveSwarmRunRef(runs, ref);
		},
	};
}

export function serializeSwarmRunRef(run) {
	return {
		kind: run.kind,
		schemaVersion: run.schemaVersion,
		engine: run.engine,
		ref: `${run.engine}:${run.runId}`,
		runId: run.runId,
		generatedAt: run.generatedAt,
		createdAtMs: run.createdAtMs,
		state: run.state,
		status: run.status,
		ok: run.ok,
		target: run.target,
		mode: run.mode,
		workerCount: run.workerCount,
		evidenceRoot: run.evidenceRoot,
		artifactPath: run.paths?.artifact,
		paths: run.paths,
		workers: run.workers,
		merge: run.merge,
	};
}
