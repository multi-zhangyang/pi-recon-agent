import type { ChildProcess } from "node:child_process";
import { type Dirent, existsSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { getAgentDir } from "../config.ts";
import type {
	AgentThreadManagerOptions,
	AgentThreadRunManifest,
	AgentThreadStatus,
	SpawnAgentThreadOptions,
} from "./agent-thread-contract.ts";
import { readAgentThreadRunManifest } from "./agent-thread-manifest-runtime.ts";
import { mergeAgentThreadRun } from "./agent-thread-merge-runtime.ts";
import { type AgentThreadSpec, BUILTIN_AGENT_THREAD_SPECS } from "./agent-thread-policy.ts";
import { startAgentThreadProcess } from "./agent-thread-process-runtime.ts";
import {
	abortError,
	agentThreadExecutionLimiter,
	envSubagentModelOverride,
	formatCommandForDisplay,
	isChildProcessRunning,
	isTerminalAgentThreadStatus,
	killWorkerProcessTree,
	linkAbortSignals,
	makeRunId,
	mkdirp,
	nowIso,
	redact,
	resolveRepiBin,
	runtimeAgentThreadMaxRunDirs,
	runtimeAgentThreadStopKillGraceMs,
	sha256,
	writeJson,
} from "./agent-thread-runtime.ts";
import {
	buildWorkerPrompt,
	normalizeWorkerGuidance,
	normalizeWorkerTask,
	prepareWorkerMcp,
	provisionWorkerAgentHome,
} from "./agent-thread-worker-runtime.ts";

export type {
	AgentThreadManagerOptions,
	AgentThreadRunManifest,
	AgentThreadStatus,
	SpawnAgentThreadOptions,
} from "./agent-thread-contract.ts";
export { type AgentThreadSpec, BUILTIN_AGENT_THREAD_SPECS } from "./agent-thread-policy.ts";
export { makeRunId, readText } from "./agent-thread-runtime.ts";

export class AgentThreadManager {
	private cwd: string;
	private agentDir: string;
	private repiBinPath: string;
	private children = new Map<string, ChildProcess>();
	private runPromises = new Map<string, Promise<AgentThreadRunManifest>>();
	private runResolvers = new Map<string, (manifest: AgentThreadRunManifest) => void>();
	// Per-run spawn-timeout timers (the outer SIGTERM timer at line ~545), tracked
	// so dispose() can clear them. The inner 2s SIGKILL escalation is unref'd and
	// self-fires — not tracked.
	private timers = new Map<string, NodeJS.Timeout>();
	// Re-entrancy guard for cooperative dispose().
	private disposed = false;
	private readonly lifecycleAbortController = new AbortController();
	// Synchronous reap hook installed only while this manager has in-flight
	// children, removed once idle — bounds live process listeners to the count of
	// managers with running children (createAgentThreadManager is called per
	// re_subagent/reasoning/challenge run, so a constructor-registered hook would
	// accumulate one listener per spawn).
	private exitHook: (() => void) | undefined;

	constructor(options: AgentThreadManagerOptions) {
		this.cwd = resolve(options.cwd);
		this.agentDir = options.agentDir ?? getAgentDir();
		this.repiBinPath = resolveRepiBin(this.cwd, options.repiBinPath);
	}

	/**
	 * Install the synchronous `process.on("exit")` reap hook if not already
	 * installed for this manager. Idempotent.
	 */
	private ensureExitHook(): void {
		if (this.exitHook) return;
		this.exitHook = () => this.disposeChildren("parent_exit");
		process.on("exit", this.exitHook);
	}

	private removeExitHook(): void {
		if (!this.exitHook) return;
		try {
			process.off("exit", this.exitHook);
		} catch {
			// ignore
		}
		this.exitHook = undefined;
	}

	/**
	 * Synchronously SIGKILL every in-flight child and mark its manifest stopped.
	 * Safe to call from a `process.on("exit")` handler (no async). Without this,
	 * a parent exit while re_subagent/reasoning/challenge runs are in flight
	 * reparents each child to init (PID 1) and it keeps running a full print-mode
	 * agent — continuing to make LLM API calls (cost/quota leak) for up to
	 * REPI_PRINT_TIMEOUT_MS (~11 min) after the user quit. The exit hook covers
	 * graceful shutdown and the uncaughtCrash → process.exit(1) path; a SIGKILL
	 * of the parent is unrecoverable (no handler runs) — those orphans
	 * self-terminate via their own print timeout.
	 */
	private disposeChildren(reason: string): void {
		for (const [runId, child] of this.children) {
			const wasRunning = isChildProcessRunning(child);
			if (wasRunning) killWorkerProcessTree(child, "SIGKILL");
			try {
				const current = this.getRun(runId);
				if (!isTerminalAgentThreadStatus(current?.status)) {
					const status: AgentThreadStatus = wasRunning ? "stopped" : child.exitCode === 0 ? "complete" : "failed";
					this.updateManifest(runId, {
						status,
						endedAt: nowIso(),
						...(child.exitCode !== null ? { exitCode: child.exitCode } : {}),
						...(child.signalCode ? { signal: child.signalCode } : {}),
						...(wasRunning ? { cancelledAt: nowIso(), error: `killed:${reason}` } : {}),
					});
				}
			} catch {
				// updateManifest is internally guarded; belt-and-suspenders.
			}
		}
	}

	/**
	 * Cooperative teardown: kill all in-flight runs, clear tracked timers, unblock
	 * any awaitRun callers, and detach the exit hook. Re-entrancy-guarded. Safe to
	 * call multiple times. Intended for the session/host to invoke on abort or
	 * teardown; the `process.on("exit")` hook calls disposeChildren directly.
	 */
	dispose(reason = "disposed"): void {
		if (this.disposed) return;
		this.disposed = true;
		this.lifecycleAbortController.abort(new Error(`Agent thread manager disposed: ${reason}`));
		this.removeExitHook();
		this.disposeChildren(reason);
		for (const timer of this.timers.values()) {
			try {
				clearTimeout(timer);
			} catch {
				// ignore
			}
		}
		this.timers.clear();
		// Unblock any awaitRun callers with a best-effort manifest so a hung
		// dispose does not leave a caller's awaitRun pending forever.
		for (const runId of [...this.runResolvers.keys()]) {
			try {
				this.resolveRun(runId);
			} catch {
				// resolveRun is guarded; ignore.
			}
		}
	}

	get root(): string {
		return join(this.agentDir, "recon", "agent-threads");
	}

	listSpecs(): AgentThreadSpec[] {
		return Object.freeze([...BUILTIN_AGENT_THREAD_SPECS]) as unknown as AgentThreadSpec[];
	}

	getSpec(name = "explorer"): AgentThreadSpec {
		const normalized = name.trim().toLowerCase();
		const spec = BUILTIN_AGENT_THREAD_SPECS.find((item) => item.name === normalized);
		if (!spec) {
			throw new Error(
				`Unknown agent thread spec: ${name}. Available: ${BUILTIN_AGENT_THREAD_SPECS.map((item) => item.name).join(", ")}`,
			);
		}
		return spec;
	}

	listRuns(): AgentThreadRunManifest[] {
		if (!existsSync(this.root)) return [];
		let entries: Dirent[];
		try {
			entries = readdirSync(this.root, { withFileTypes: true });
		} catch {
			return [];
		}
		return entries
			.filter((entry) => entry.isDirectory())
			.map((entry) => readAgentThreadRunManifest(this.root, entry.name, this.cwd))
			.filter((item): item is AgentThreadRunManifest => Boolean(item))
			.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
	}

	/**
	 * Foundational opt #255: best-effort prune of completed run-dirs so they do
	 * not accumulate unbounded under this.root. Keeps the most-recent
	 * REPI_AGENT_THREAD_MAX_RUN_DIRS completed run-dirs by mtime and rmSync's the
	 * rest. In-flight runs (still in this.children) are NEVER pruned. Called from
	 * the child 'close' finally after a run finalizes. Best-effort: any stat/rm
	 * error is swallowed (an unreadable/dir-we-can't-stat is left alone, never
	 * deleted blindly).
	 */
	private pruneRunsIfNeeded(): void {
		const maxDirs = runtimeAgentThreadMaxRunDirs();
		if (maxDirs <= 0) return;
		let names: string[];
		try {
			names = readdirSync(this.root, { withFileTypes: true })
				.filter((entry) => entry.isDirectory())
				.map((entry) => entry.name);
		} catch {
			return;
		}
		if (names.length <= maxDirs) return;
		const inflight = new Set(this.children.keys());
		const stamped: Array<{ name: string; mtime: number }> = [];
		for (const name of names) {
			if (inflight.has(name)) continue;
			try {
				stamped.push({ name, mtime: statSync(join(this.root, name)).mtimeMs });
			} catch {
				// Can't stat — leave it rather than risk deleting blindly.
			}
		}
		if (stamped.length <= maxDirs) return;
		stamped.sort((a, b) => b.mtime - a.mtime);
		for (const { name } of stamped.slice(maxDirs)) {
			try {
				rmSync(join(this.root, name), { recursive: true, force: true });
			} catch {
				// best-effort
			}
		}
	}

	getRun(id = "latest"): AgentThreadRunManifest | undefined {
		const runs = this.listRuns();
		if (id === "latest") return runs[0];
		const exact = runs.find((run) => run.runId === id);
		if (exact) return exact;
		const matches = runs.filter((run) => run.runId.startsWith(id));
		return matches.length === 1 ? matches[0] : undefined;
	}

	async spawnThread(options: SpawnAgentThreadOptions): Promise<AgentThreadRunManifest> {
		if (this.disposed) throw new Error("Agent thread manager is disposed");
		const linkedAbort = linkAbortSignals([options.signal, this.lifecycleAbortController.signal]);
		let releaseLease: (() => void) | undefined;
		let childForCleanup: ChildProcess | undefined;
		let onRunAbort: (() => void) | undefined;
		let runIdForCleanup: string | undefined;
		let runRootForCleanup: string | undefined;
		let manifestPathForCleanup: string | undefined;
		let timerForCleanup: NodeJS.Timeout | undefined;
		const releaseLeaseOnce = (): void => {
			const release = releaseLease;
			releaseLease = undefined;
			release?.();
		};
		try {
			releaseLease = await agentThreadExecutionLimiter.acquire(linkedAbort.signal);
			if (linkedAbort.signal.aborted) throw abortError(linkedAbort.signal.reason);
			if (options.parentLineageSha256 && !/^[a-f\d]{64}$/i.test(options.parentLineageSha256)) {
				throw new Error("parentLineageSha256 must be a 64-character SHA-256 hex digest");
			}
			const spec = this.getSpec(options.specName ?? "explorer");
			const task = normalizeWorkerTask(options.task);
			const additionalPrompt = normalizeWorkerGuidance(options.additionalPrompt);
			if (!task) throw new Error("Agent thread task must not be empty");
			const runId = makeRunId(spec.name);
			runIdForCleanup = runId;
			const runRoot = join(this.root, runId);
			runRootForCleanup = runRoot;
			const workerAgentDir = join(runRoot, "agent-home");
			mkdirp(runRoot);
			mkdirp(workerAgentDir);

			provisionWorkerAgentHome(this.agentDir, workerAgentDir);

			const cwd = resolve(options.cwd ?? this.cwd);
			const stdoutPath = join(runRoot, "stdout.txt");
			const stderrPath = join(runRoot, "stderr.txt");
			const manifestPath = join(runRoot, "manifest.json");
			manifestPathForCleanup = manifestPath;
			const mcpInheritance = prepareWorkerMcp({
				parentAgentDir: this.agentDir,
				workerAgentDir,
				cwd,
				spec,
				spawn: options,
			});
			const prompt = buildWorkerPrompt(spec, task, additionalPrompt, mcpInheritance);
			const [promptSha256, taskSha256] = await Promise.all([sha256(prompt), sha256(task)]);
			const lineageSha256 = await sha256(
				JSON.stringify({
					schemaVersion: 1,
					runId,
					parentRunId: options.parentRunId ?? null,
					missionId: options.missionId ?? null,
					parentLineageSha256: options.parentLineageSha256 ?? null,
					taskSha256,
					promptSha256,
				}),
			);
			const toolNames = [...new Set([...spec.tools, ...mcpInheritance.runtimeToolNames])];
			const envModel = envSubagentModelOverride();
			const childProvider = options.provider ?? envModel.provider;
			const childModel = options.model ?? envModel.model;
			const timeoutMs = Math.max(1000, options.timeoutMs ?? 10 * 60 * 1000);
			const args = [
				"--approve",
				...(childProvider ? ["--provider", childProvider] : []),
				...(childModel ? ["--model", childModel] : []),
				"--thinking",
				spec.thinkingLevel,
				"--no-session",
				...(toolNames.length > 0 ? ["--tools", toolNames.join(",")] : ["--no-tools"]),
				"-p",
				prompt,
			];

			const manifest: AgentThreadRunManifest = {
				kind: "repi-agent-thread-run",
				schemaVersion: 1,
				runId,
				specName: spec.name,
				task,
				status: "running",
				createdAt: nowIso(),
				startedAt: nowIso(),
				cwd,
				runRoot,
				agentDir: workerAgentDir,
				handoffPath: join(runRoot, "handoff.md"),
				handoffPresent: false,
				handoffRecovered: false,
				stdoutPath,
				stderrPath,
				manifestPath,
				provider: childProvider,
				model: childModel,
				taskSha256,
				parentRunId: options.parentRunId,
				missionId: options.missionId,
				parentLineageSha256: options.parentLineageSha256,
				lineageSha256,
				tools: toolNames,
				timeoutMs,
				maxTurns: spec.maxTurns,
				cancelSignal: "SIGTERM",
				mcpServers: mcpInheritance.serverIds,
				mcpTools: mcpInheritance.allowedTools,
				mcpToolFilterActive: mcpInheritance.toolFilterActive,
				mcpInherited: mcpInheritance.inherited,
				promptSha256,
			};
			writeFileSync(stdoutPath, "", { encoding: "utf8", mode: 0o600 });
			writeFileSync(stderrPath, "", { encoding: "utf8", mode: 0o600 });
			writeJson(manifestPath, manifest);

			// The child boots in print mode (--no-session -p) whose default 210s
			// self-timeout would fire before this manager's spawn timer for any
			// delegation budget > 210s, silently capping re_subagent/reason/challenge
			// timeoutMs at 210s. Lift the child's inner print timeout above the spawn
			// timeout so this manager's timer remains the authoritative kill.
			const childPrintTimeoutMs = timeoutMs + 60_000;
			if (linkedAbort.signal.aborted) throw abortError(linkedAbort.signal.reason);
			this.runPromises.set(
				runId,
				new Promise<AgentThreadRunManifest>((resolve) => {
					this.runResolvers.set(runId, resolve);
				}),
			);
			const processRuntime = startAgentThreadProcess({
				command: this.repiBinPath,
				args,
				cwd,
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: workerAgentDir,
					PI_CODING_AGENT_DIR: workerAgentDir,
					REPI_AGENT_THREAD: "1",
					REPI_SKIP_VERSION_CHECK: "1",
					REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
					PI_SKIP_VERSION_CHECK: "1",
					PI_SKIP_PACKAGE_UPDATE_CHECK: "1",
					REPI_TELEMETRY: "0",
					PI_TELEMETRY: "0",
					REPI_PRINT_TIMEOUT_MS: String(childPrintTimeoutMs),
					REPI_PRINT_MAX_TURNS: String(spec.maxTurns),
					REPI_WORKER_RUN_ROOT: runRoot,
					REPI_WORKER_RUN_ID: runId,
					REPI_WORKER_MISSION_ID: options.missionId ?? "",
					REPI_WORKER_LINEAGE_SHA256: lineageSha256,
					REPI_WORKER_HANDOFF_PATH: join(runRoot, "handoff.md"),
					REPI_WORKER_TOOL_INDEX: join(workerAgentDir, "recon", "tools", "tool-index.md"),
					...(mcpInheritance.serverAllowlistEnv !== undefined
						? { REPI_MCP_ALLOWED_SERVERS: mcpInheritance.serverAllowlistEnv }
						: {}),
					...(mcpInheritance.toolAllowlistEnv !== undefined
						? { REPI_MCP_ALLOWED_TOOLS: mcpInheritance.toolAllowlistEnv }
						: {}),
				},
				runId,
				stdoutPath,
				stderrPath,
				handoffPath: join(runRoot, "handoff.md"),
				timeoutMs,
				missionId: options.missionId,
				lineageSha256,
				isDisposed: () => this.disposed,
				isPending: () => this.runResolvers.has(runId),
				getManifest: () => this.getRun(runId),
				updateManifest: (patch) => this.updateManifest(runId, patch),
				onSettled: () => {
					if (onRunAbort) linkedAbort.signal.removeEventListener("abort", onRunAbort);
					linkedAbort.dispose();
					releaseLeaseOnce();
					this.children.delete(runId);
					this.timers.delete(runId);
					this.resolveRun(runId);
					try {
						this.pruneRunsIfNeeded();
					} catch {
						// Best-effort retention must not block run settlement.
					}
					if (this.children.size === 0 && this.timers.size === 0) this.removeExitHook();
				},
			});
			const child = processRuntime.child;
			childForCleanup = child;
			manifest.pid = child.pid;
			writeJson(manifestPath, manifest);
			this.children.set(runId, child);
			timerForCleanup = processRuntime.timeoutTimer;
			this.timers.set(runId, processRuntime.timeoutTimer);
			this.ensureExitHook();
			onRunAbort = () => {
				if (this.disposed) return;
				try {
					this.stopRun(runId, "parent_aborted");
				} catch {
					if (isChildProcessRunning(child)) killWorkerProcessTree(child, "SIGTERM");
				}
			};
			linkedAbort.signal.addEventListener("abort", onRunAbort, { once: true });
			if (linkedAbort.signal.aborted) onRunAbort();

			return manifest;
		} catch (error) {
			if (onRunAbort) linkedAbort.signal.removeEventListener("abort", onRunAbort);
			linkedAbort.dispose();
			if (timerForCleanup) clearTimeout(timerForCleanup);
			const cleanupChild = childForCleanup;
			const cleanupRunId = runIdForCleanup;
			let releaseOnClose = false;
			if (cleanupChild && isChildProcessRunning(cleanupChild)) {
				releaseOnClose = true;
				if (cleanupRunId) this.children.set(cleanupRunId, cleanupChild);
				this.ensureExitHook();
				cleanupChild.once("close", () => {
					releaseLeaseOnce();
					if (cleanupRunId) {
						this.children.delete(cleanupRunId);
						this.timers.delete(cleanupRunId);
					}
					if (this.children.size === 0 && this.timers.size === 0) this.removeExitHook();
				});
				killWorkerProcessTree(cleanupChild, "SIGKILL");
			}
			if (runIdForCleanup) {
				if (!releaseOnClose) this.children.delete(runIdForCleanup);
				this.timers.delete(runIdForCleanup);
				this.runResolvers.delete(runIdForCleanup);
				this.runPromises.delete(runIdForCleanup);
			}
			if (manifestPathForCleanup && existsSync(manifestPathForCleanup) && runIdForCleanup) {
				const aborted = linkedAbort.signal.aborted;
				this.updateManifest(runIdForCleanup, {
					status: aborted ? "stopped" : "failed",
					endedAt: nowIso(),
					...(aborted ? { cancelledAt: nowIso(), cancelSignal: "SIGTERM" as const } : {}),
					error: error instanceof Error ? redact(error.message) : redact(String(error)),
				});
			} else if (runRootForCleanup) {
				try {
					rmSync(runRootForCleanup, { recursive: true, force: true });
				} catch {
					// best-effort cleanup of admission/provisioning failures
				}
			}
			if (!releaseOnClose) releaseLeaseOnce();
			if (this.children.size === 0 && this.timers.size === 0) this.removeExitHook();
			throw error;
		}
	}

	stopRun(id = "latest", reason = "stopped_by_user"): AgentThreadRunManifest | undefined {
		const run = this.getRun(id);
		if (!run) return undefined;
		const child = this.children.get(run.runId);
		if (child && isChildProcessRunning(child)) {
			killWorkerProcessTree(child, "SIGTERM");
			if (!isTerminalAgentThreadStatus(run.status)) {
				this.updateManifest(run.runId, {
					status: "stopped",
					endedAt: nowIso(),
					cancelledAt: nowIso(),
					cancelSignal: "SIGTERM",
					error: reason,
				});
			}
			setTimeout(() => {
				if (isChildProcessRunning(child)) killWorkerProcessTree(child, "SIGKILL");
			}, runtimeAgentThreadStopKillGraceMs()).unref();
		}
		return this.getRun(run.runId);
	}

	awaitRun(runId: string): Promise<AgentThreadRunManifest> {
		const promise = this.runPromises.get(runId);
		if (!promise) {
			return Promise.reject(new Error(`Unknown agent thread run: ${runId}`));
		}
		return promise;
	}

	private resolveRun(runId: string): void {
		const resolve = this.runResolvers.get(runId);
		if (!resolve) return;
		this.runResolvers.delete(runId);
		this.runPromises.delete(runId);
		// getRun can throw (listRuns → readdirSync on a root whose perms changed,
		// or a .sort over a manifest missing createdAt → undefined.localeCompare).
		// This is called from event-handler callbacks (child "close"/"error") whose
		// throw would become an uncaughtException/unhandledRejection AND leave the
		// run promise unsettled → awaitRun hangs forever. Guard the read so the
		// caller always unblocks with at least a runId-bearing manifest.
		let manifest: AgentThreadRunManifest;
		try {
			manifest = this.getRun(runId) ?? ({ runId } as unknown as AgentThreadRunManifest);
		} catch {
			manifest = { runId } as unknown as AgentThreadRunManifest;
		}
		resolve(manifest);
	}

	mergeRun(id = "latest"): { manifest: AgentThreadRunManifest; text: string } | undefined {
		const manifest = this.getRun(id);
		if (!manifest) return undefined;
		const merged = mergeAgentThreadRun(manifest);
		this.updateManifest(manifest.runId, merged.manifestPatch);
		return { manifest: this.getRun(manifest.runId) ?? manifest, text: merged.text };
	}

	formatSpecs(): string {
		return [
			"Agent thread specs:",
			...this.listSpecs().map(
				(spec) =>
					`- ${spec.name} [tools=${spec.tools.join(",") || "none"}, mcp=${spec.mcp?.inherit ? "inherit" : "off"}, maxTurns=${spec.maxTurns}]: ${spec.description}`,
			),
			"",
			"Usage:",
			"- /spawn <spec> <task>",
			"- /agent [latest|run-id|stop <run-id>]",
			"- /merge [latest|run-id]",
		].join("\n");
	}

	formatRuns(): string {
		const runs = this.listRuns().slice(0, 12);
		if (runs.length === 0) return "Agent threads: none";
		return [
			"Agent threads:",
			...runs.map(
				(run) =>
					`- ${run.runId} [${run.status}] ${run.specName}: ${run.task}\n  root=${run.runRoot}\n  stdout=${run.stdoutPath}`,
			),
		].join("\n");
	}

	formatRun(run: AgentThreadRunManifest): string {
		return [
			`Agent thread: ${run.runId}`,
			`status: ${run.status}`,
			`spec: ${run.specName}`,
			`task: ${run.task}`,
			`pid: ${run.pid ?? "n/a"}`,
			`cwd: ${run.cwd}`,
			`root: ${run.runRoot}`,
			`agent_home: ${run.agentDir}`,
			`stdout: ${run.stdoutPath}`,
			`stderr: ${run.stderrPath}`,
			`merge: ${run.mergePath ?? `run /merge ${run.runId}`}`,
			`handoff: present=${run.handoffPresent === true} lineage=${run.handoffLineageValid === true ? "valid" : "unverified"}`,
			`tools: ${run.tools.join(",") || "none"}`,
			`mcp: ${run.mcpInherited ? `servers=${run.mcpServers?.join(",") || "none"} tools=${run.mcpToolFilterActive ? run.mcpTools?.join(",") || "none" : "all"}` : "off"}`,
			`provider/model: ${run.provider ?? "default"}/${run.model ?? "default"}`,
		].join("\n");
	}

	private updateManifest(runId: string, patch: Partial<AgentThreadRunManifest>): void {
		const manifestPath = join(this.root, runId, "manifest.json");
		if (!existsSync(manifestPath)) return;
		try {
			const current = JSON.parse(readFileSync(manifestPath, "utf8")) as AgentThreadRunManifest;
			let nextPatch = patch;
			if (
				patch.status !== undefined &&
				isTerminalAgentThreadStatus(current.status) &&
				patch.status !== current.status
			) {
				// Terminal status is monotonic. Late timeout/error/close callbacks may
				// still contribute exit codes and hashes, but cannot rewrite the outcome
				// or its established cancellation/error timestamps.
				nextPatch = {
					...patch,
					status: current.status,
					...(current.error !== undefined ? { error: current.error } : {}),
					...(current.endedAt !== undefined ? { endedAt: current.endedAt } : {}),
					...(current.cancelledAt !== undefined ? { cancelledAt: current.cancelledAt } : {}),
					...(current.cancelSignal !== undefined ? { cancelSignal: current.cancelSignal } : {}),
				};
			}
			writeJson(manifestPath, { ...current, ...nextPatch });
		} catch {
			// Ignore broken manifest updates; callers can inspect stdout/stderr paths directly.
		}
	}

	formatSpawned(manifest: AgentThreadRunManifest): string {
		return [
			"Spawned REPI agent thread:",
			`- run_id: ${manifest.runId}`,
			`- spec: ${manifest.specName}`,
			`- status: ${manifest.status}`,
			`- pid: ${manifest.pid ?? "pending"}`,
			`- root: ${manifest.runRoot}`,
			`- stdout: ${manifest.stdoutPath}`,
			`- stderr: ${manifest.stderrPath}`,
			`- command: ${formatCommandForDisplay(this.repiBinPath, ["--no-session", "-p", "<worker-prompt>"])}`,
			"Next: /agent latest or /merge latest",
		].join("\n");
	}
}

export function createAgentThreadManager(options: AgentThreadManagerOptions): AgentThreadManager {
	return new AgentThreadManager(options);
}
