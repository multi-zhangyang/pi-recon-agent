import { createHash } from "node:crypto";
import { normalizeWorkerTask } from "../agent-thread-worker-runtime.ts";
import type { ExtensionAPI, ToolCallEvent, ToolDefinition } from "../extensions/types.ts";
import { repiCapabilityAwareCommand, repiPromptNeedsWriteTools } from "./capabilities.ts";
import { buildEvidenceClaimSummary } from "./evidence.ts";
import { installRepiGoalMode } from "./goal.ts";
import {
	createMission,
	type DelegationGateState,
	type MissionRuntimeStats,
	type MissionState,
	missionOperatorDirective,
	readCurrentMission,
	readCurrentSessionMission,
	updateMissionDirective,
	updateMissionRuntimeStats,
	writeCurrentMission,
} from "./mission.ts";
import {
	type RepiSubagentArtifactValidation,
	validateRepiSubagentArtifact,
} from "./repi-subagent-artifact-validation.ts";
import { ensureReconStorage } from "./resources.ts";
import {
	formatRepiRoute,
	isRepiContinuation,
	isRepiTask,
	type RoutePlan,
	repiTaskRequiresDelegation,
	routeRepiTask,
} from "./routes.ts";
import { runMissionSessionScope } from "./session-scope.ts";
import { extractRepiTaskTarget } from "./target.ts";
import { redactSensitiveText, truncateMiddle } from "./text.ts";

export type ReconStats = {
	calls: number;
	bashCalls: number;
	failures: number;
	lastCommandHash?: string;
	repeatedCommandCount: number;
	lastCommands: string[];
	active: boolean;
	selfReviewDue: boolean;
	selfReviewNotified?: boolean;
	toolingGapObserved: boolean;
	lastRoute?: RoutePlan;
	currentMissionId?: string;
	currentMission?: MissionState;
	sessionFile?: string;
	noSession?: boolean;
	lastInjectedState?: string;
	delegationGate?: DelegationGateState;
};

export type RepiSessionLifecycleOptions = {
	injectRuntimePacket?: boolean;
	materializeResources?: boolean;
};

export type RepiSessionLifecycleDependencies = {
	nextDecisionCommand: (mission: MissionState) => string;
	installCommands: (pi: ExtensionAPI, stats: ReconStats) => void;
	installTools: (pi: ExtensionAPI) => void;
};

function canonicalMissionTarget(target: string | undefined): string | undefined {
	if (!target) return undefined;
	try {
		if (/^https?:\/\//i.test(target)) return new URL(target).host.toLowerCase();
	} catch {
		return target;
	}
	if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?$/i.test(target) || /^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/.test(target)) {
		return target.toLowerCase();
	}
	return target.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/, "");
}

function startsNewRepiMission(activeMission: MissionState | undefined, prompt: string): boolean {
	if (!activeMission || !isRepiTask(prompt) || isRepiContinuation(prompt)) return false;
	if (
		/\b(?:new mission|new task|different target|switch target|start over)\b|新任务|另一个目标|换(?:个|一个)?目标|重新开始|重开任务/i.test(
			prompt,
		)
	) {
		return true;
	}
	const requestedRoute = routeRepiTask(prompt);
	if (requestedRoute.domain !== "Reverse/Pentest general" && requestedRoute.domain !== activeMission.route.domain) {
		return true;
	}
	const currentTarget = canonicalMissionTarget(
		extractRepiTaskTarget(activeMission.operatorDirective ?? "") ?? extractRepiTaskTarget(activeMission.task),
	);
	const requestedTarget = canonicalMissionTarget(extractRepiTaskTarget(prompt));
	return Boolean(currentTarget && requestedTarget && currentTarget !== requestedTarget);
}

/** Recognize an explicit operator action without treating ordinary conversation as a new directive. */
function isOperatorDirectivePrompt(prompt: string): boolean {
	return (
		isRepiTask(prompt) ||
		repiPromptNeedsWriteTools(prompt) ||
		/\b(?:run|execute|inspect|check|analyze|focus|replay|verify|prove|trace|capture|map)\b|(?:执行|检查|分析|聚焦|回放|验证|证明|跟踪|抓取|映射)/i.test(
			prompt,
		)
	);
}

function persistedReconStats(stats: ReconStats): MissionRuntimeStats {
	return {
		calls: stats.calls,
		bashCalls: stats.bashCalls,
		failures: stats.failures,
		lastCommandHash: stats.lastCommandHash,
		repeatedCommandCount: stats.repeatedCommandCount,
		lastCommands: stats.lastCommands.slice(-8),
		selfReviewDue: stats.selfReviewDue,
		lastInjectedState: stats.lastInjectedState,
		delegationGate: stats.delegationGate ? { ...stats.delegationGate } : undefined,
	};
}

function restoreReconStats(stats: ReconStats, saved?: Partial<MissionRuntimeStats>): void {
	if (!saved) return;
	if (Number.isSafeInteger(saved.calls) && Number(saved.calls) >= 0) stats.calls = Number(saved.calls);
	if (Number.isSafeInteger(saved.bashCalls) && Number(saved.bashCalls) >= 0) stats.bashCalls = Number(saved.bashCalls);
	if (Number.isSafeInteger(saved.failures) && Number(saved.failures) >= 0) stats.failures = Number(saved.failures);
	if (typeof saved.lastCommandHash === "string") stats.lastCommandHash = saved.lastCommandHash;
	if (Number.isSafeInteger(saved.repeatedCommandCount) && Number(saved.repeatedCommandCount) >= 0) {
		stats.repeatedCommandCount = Number(saved.repeatedCommandCount);
	}
	if (Array.isArray(saved.lastCommands)) {
		stats.lastCommands = saved.lastCommands
			.filter((command): command is string => typeof command === "string")
			.slice(-8);
	}
	stats.selfReviewDue = saved.selfReviewDue === true;
	if (typeof saved.lastInjectedState === "string") stats.lastInjectedState = saved.lastInjectedState;
	if (saved.delegationGate && typeof saved.delegationGate === "object") {
		stats.delegationGate = { ...saved.delegationGate } as DelegationGateState;
	}
}

function resetReconStats(stats: ReconStats): void {
	stats.calls = 0;
	stats.bashCalls = 0;
	stats.failures = 0;
	stats.lastCommandHash = undefined;
	stats.repeatedCommandCount = 0;
	stats.lastCommands = [];
	stats.selfReviewDue = false;
	stats.selfReviewNotified = false;
	stats.toolingGapObserved = false;
	stats.lastInjectedState = undefined;
	stats.delegationGate = undefined;
}

function delegationSpecForRoute(route: RoutePlan): string {
	if (/Native|Pwn|Firmware|Mobile|Malware|Exploit/.test(route.domain)) {
		return "reverser";
	}
	if (/Web|Crypto|DFIR|Memory|Cloud|Identity|Agent/.test(route.domain)) return "explorer";
	return "planner";
}

function delegationTaskForDirective(directive: string): string {
	return normalizeWorkerTask(
		`Research and verify the unfamiliar REPI technique or domain in this operator directive. Return a structured handoff with commands, artifacts, and unresolved gaps. Operator directive: ${directive}`,
	);
}

function delegationTaskSha256(task: string): string {
	return createHash("sha256").update(normalizeWorkerTask(task)).digest("hex");
}

const DELEGATION_MAX_ATTEMPTS = 2;

function missionRequiresDelegation(route: RoutePlan, directive: string): boolean {
	return repiTaskRequiresDelegation(`${route.domain}\n${directive}`);
}

function createDelegationGate(mission: MissionState, directive: string): DelegationGateState {
	const task = delegationTaskForDirective(directive);
	return {
		status: "required",
		missionId: mission.id,
		directiveRevision: mission.directiveRevision ?? 1,
		reason: "explicit knowledge gap or specialist delegation request",
		spec: delegationSpecForRoute(mission.route),
		task,
		taskSha256: delegationTaskSha256(task),
		attempts: 0,
	};
}

function sameDelegationDirective(gate: DelegationGateState | undefined, mission: MissionState): boolean {
	return Boolean(gate && gate.missionId === mission.id && gate.directiveRevision === (mission.directiveRevision ?? 1));
}

function recoverInterruptedDelegationGate(gate: DelegationGateState | undefined, reason: string): boolean {
	if (!gate || gate.status !== "dispatching") return false;
	gate.toolCallId = undefined;
	gate.lastError = reason;
	gate.status = gate.attempts >= DELEGATION_MAX_ATTEMPTS ? "blocked" : "required";
	return true;
}

function clearDelegationArtifact(gate: DelegationGateState): void {
	gate.toolCallId = undefined;
	gate.runId = undefined;
	gate.handoffSha256 = undefined;
	gate.result = undefined;
}

async function revalidateSatisfiedDelegationGate(gate: DelegationGateState | undefined): Promise<boolean> {
	if (!gate || gate.status !== "satisfied") return true;
	const result = gate.result;
	if (!result) {
		gate.status = gate.attempts >= DELEGATION_MAX_ATTEMPTS ? "blocked" : "required";
		gate.lastError = "restored satisfied gate has no persisted validated artifact";
		clearDelegationArtifact(gate);
		return false;
	}
	const validation = await validateRepiSubagentArtifact(result, {
		missionId: gate.missionId,
		spec: gate.spec,
		task: gate.task,
		taskSha256: gate.taskSha256,
	});
	if (validation.ok) {
		gate.handoffSha256 = validation.result.handoffSha256 ?? undefined;
		return true;
	}
	gate.status = gate.attempts >= DELEGATION_MAX_ATTEMPTS ? "blocked" : "required";
	gate.lastError = `persisted delegation artifact failed revalidation: ${validation.error}`;
	clearDelegationArtifact(gate);
	return false;
}

function structuredDelegationResult(details: unknown): details is {
	kind: "RepiSubagentResultV1";
	schemaVersion: 1;
	status: "complete";
	exitCode: 0;
	runId: string;
	spec: string;
	task: string;
	taskSha256: string;
	missionId: string;
	handoffPresent: true;
	handoffRecovered: false;
	handoffLineageValid: true;
	runRoot: string;
	mergePath: string;
	handoffPath: string;
	handoffBytes: number;
	handoffSha256: string;
	handoffRunId: string;
	handoffMissionId: string;
	handoffLineageSha256: string;
	lineageSha256: string;
} {
	if (!details || typeof details !== "object") return false;
	const value = details as Record<string, unknown>;
	return (
		value.kind === "RepiSubagentResultV1" &&
		value.schemaVersion === 1 &&
		value.status === "complete" &&
		value.exitCode === 0 &&
		typeof value.runId === "string" &&
		typeof value.spec === "string" &&
		typeof value.task === "string" &&
		typeof value.taskSha256 === "string" &&
		typeof value.missionId === "string" &&
		value.handoffPresent === true &&
		value.handoffRecovered === false &&
		value.handoffLineageValid === true &&
		typeof value.runRoot === "string" &&
		typeof value.mergePath === "string" &&
		typeof value.handoffPath === "string" &&
		typeof value.handoffBytes === "number" &&
		value.handoffBytes > 0 &&
		typeof value.handoffSha256 === "string" &&
		/^[a-f0-9]{64}$/i.test(value.handoffSha256) &&
		typeof value.handoffRunId === "string" &&
		typeof value.handoffMissionId === "string" &&
		typeof value.handoffLineageSha256 === "string" &&
		typeof value.lineageSha256 === "string" &&
		value.handoffLineageSha256 === value.lineageSha256
	);
}

async function validateDelegationResult(
	details: unknown,
	gate: DelegationGateState,
): Promise<RepiSubagentArtifactValidation> {
	if (!structuredDelegationResult(details)) {
		return { ok: false, error: "re_subagent returned no complete structured result" };
	}
	return validateRepiSubagentArtifact(details, {
		missionId: gate.missionId,
		spec: gate.spec,
		task: gate.task,
		taskSha256: gate.taskSha256,
	});
}

function gateTerminalText(gate: DelegationGateState): string {
	if (gate.status === "blocked") {
		return `Delegation gate blocked: a real ${gate.spec} subagent handoff could not be validated after ${gate.attempts} attempt(s). ${gate.lastError ?? "No valid structured result was returned."}`;
	}
	return `Delegation gate required before execution. Call re_subagent with the bound ${gate.spec} task and return its real structured handoff; direct conclusions and unrelated tools are blocked.`;
}

function getBashCommand(event: ToolCallEvent): string | undefined {
	if (event.toolName !== "bash") return undefined;
	const input = event.input as { command?: unknown; cmd?: unknown };
	const command = input.command ?? input.cmd;
	return typeof command === "string" ? command.trim() : undefined;
}

/** Prevent a report-only heredoc from consuming another model turn. */
function isReportOnlyBashCommand(command: string): boolean {
	const firstLine = command.split(/\r?\n/, 1)[0]?.trim() ?? "";
	return /^cat\s+<<-?\s*["']?[A-Za-z_][A-Za-z0-9_]*["']?\s*$/.test(firstLine) && !/[|>]/.test(firstLine);
}

function customToolAction(event: ToolCallEvent): { action?: string; target?: string; url?: string } {
	if (
		event.toolName === "bash" ||
		event.toolName === "read" ||
		event.toolName === "edit" ||
		event.toolName === "write"
	) {
		return {};
	}
	const input = event.input as { action?: unknown; target?: unknown; url?: unknown };
	return {
		action: typeof input.action === "string" ? input.action.toLowerCase() : undefined,
		target: typeof input.target === "string" ? input.target : undefined,
		url: typeof input.url === "string" ? input.url : undefined,
	};
}

function missionRequestsControlPlane(task: string): boolean {
	return /tool\s*index|toolchain|capabilit(?:y|ies)\b|available\s+tools|工具索引|工具链|能力矩阵|可用工具/i.test(task);
}

function routedToolGuard(
	event: ToolCallEvent,
	stats: ReconStats,
	mission: MissionState | undefined,
): string | undefined {
	if (!stats.active || !mission || missionRequestsControlPlane(missionOperatorDirective(mission) ?? mission.task))
		return undefined;
	const { action, target, url } = customToolAction(event);
	const explicitTarget = Boolean((target ?? url)?.trim());
	if (event.toolName === "re_mission" && action === "new") {
		return "The harness already created the routed mission for this turn; continue with the domain execution tool instead of creating a second mission.";
	}
	if (event.toolName === "re_capabilities" && action === "status") {
		return "The routed capability profile is already active in the current schema; do not perform a capability status preflight.";
	}
	if (event.toolName === "re_tool_index" && (action === "show" || action === "refresh") && !stats.toolingGapObserved) {
		return "The execution adapter performs its own tool preflight; only inspect the tool index after a concrete missing-runner evidence gap.";
	}
	if (event.toolName === "re_runtime_adapter" && explicitTarget && (action === "show" || action === "plan")) {
		return "A concrete target is present; run the selected runtime adapter directly and use its artifact for verification.";
	}
	if (event.toolName === "re_web_authz_state" && explicitTarget && action === "plan") {
		return "A concrete Web target is present; run the authorization-state probe directly. The run result includes its plan and evidence contract.";
	}
	if (
		event.toolName === "re_live_browser" &&
		explicitTarget &&
		(action === "plan" || action === "run") &&
		!/(?:re_live_browser|cdp|persistent\s+browser|har)/i.test(missionOperatorDirective(mission) ?? mission.task)
	) {
		return "Use re_runtime_adapter run as the single DomainAdapter browser/network execution path; do not duplicate it with re_live_browser for the same routed target.";
	}
	return undefined;
}

function createSessionScopedExtensionApi(pi: ExtensionAPI, getSessionFile: () => string | undefined): ExtensionAPI {
	const scoped = Object.create(pi) as ExtensionAPI;
	scoped.registerTool = ((tool: ToolDefinition) => {
		pi.registerTool({
			...tool,
			execute: (toolCallId, params, signal, onUpdate, ctx) =>
				runMissionSessionScope(getSessionFile(), () => tool.execute(toolCallId, params, signal, onUpdate, ctx)),
		});
	}) as ExtensionAPI["registerTool"];
	scoped.registerCommand = ((name, options) => {
		pi.registerCommand(name, {
			...options,
			handler: (args, ctx) => runMissionSessionScope(getSessionFile(), () => options.handler(args, ctx)),
		});
	}) as ExtensionAPI["registerCommand"];
	return scoped;
}

export function installRepiSessionLifecycle(
	pi: ExtensionAPI,
	dependencies: RepiSessionLifecycleDependencies,
	options: RepiSessionLifecycleOptions = {},
): void {
	ensureReconStorage({ materializeResources: options.materializeResources });
	const stats: ReconStats = {
		calls: 0,
		bashCalls: 0,
		failures: 0,
		repeatedCommandCount: 0,
		lastCommands: [],
		active: false,
		selfReviewDue: false,
		selfReviewNotified: false,
		toolingGapObserved: false,
	};
	let delegationDispatchedSinceAgentEnd = false;
	const persistStats = (): void => {
		if (!stats.active || !stats.currentMissionId) return;
		const current = readCurrentMission();
		if (!current || current.id !== stats.currentMissionId) return;
		stats.currentMission = updateMissionRuntimeStats(persistedReconStats(stats));
	};

	pi.on("session_start", async (_event, ctx) => {
		const sessionFile = ctx.sessionManager?.getSessionFile?.();
		return runMissionSessionScope(sessionFile, async () => {
			// Resolve the legacy workspace mission before selecting the session scope,
			// allowing one migration without sharing pointers across new sessions.
			const legacyMission = runMissionSessionScope(undefined, () => readCurrentSessionMission(ctx));
			ensureReconStorage({ materializeResources: options.materializeResources });
			resetReconStats(stats);
			stats.sessionFile = sessionFile;
			stats.noSession = Boolean(ctx.sessionManager) && !stats.sessionFile;
			let mission = readCurrentSessionMission(ctx);
			if (!mission && legacyMission && sessionFile) mission = writeCurrentMission(legacyMission);
			mission ??= legacyMission;
			stats.active = Boolean(mission);
			stats.lastRoute = mission?.route;
			stats.currentMissionId = mission?.id;
			stats.currentMission = mission;
			restoreReconStats(stats, mission?.runtimeStats);
			if (
				recoverInterruptedDelegationGate(stats.delegationGate, "interrupted delegation recovered at session start")
			) {
				persistStats();
			}
			if (!(await revalidateSatisfiedDelegationGate(stats.delegationGate))) persistStats();
			if (ctx.hasUI) ctx.ui.setStatus("repi", "REPI kernel profile ready");
		});
	});

	pi.on("session_tree", (_event, ctx) => {
		const sessionFile = ctx.sessionManager?.getSessionFile?.();
		return runMissionSessionScope(sessionFile, async () => {
			const noSession = Boolean(ctx.sessionManager) && !sessionFile;
			// A tree jump may land before this mission existed. Persisted branch state
			// must win over the process-local fast path on the next turn.
			const mission = noSession ? undefined : readCurrentSessionMission(ctx);
			resetReconStats(stats);
			stats.active = Boolean(mission);
			stats.lastRoute = mission?.route;
			stats.currentMissionId = mission?.id;
			stats.currentMission = mission;
			stats.sessionFile = sessionFile;
			stats.noSession = noSession;
			restoreReconStats(stats, mission?.runtimeStats);
			if (
				recoverInterruptedDelegationGate(
					stats.delegationGate,
					"interrupted delegation recovered after session tree change",
				)
			) {
				persistStats();
			}
			if (!(await revalidateSatisfiedDelegationGate(stats.delegationGate))) persistStats();
			if (ctx.hasUI)
				ctx.ui.setStatus("repi", mission ? formatRepiRoute(mission.route) : "REPI kernel profile ready");
		});
	});

	pi.on("session_shutdown", () => runMissionSessionScope(stats.sessionFile, () => persistStats()));

	pi.on("before_agent_start", async (event, ctx) => {
		const sessionFile = ctx.sessionManager?.getSessionFile?.();
		return runMissionSessionScope(sessionFile, async () => {
			const noSession = Boolean(ctx.sessionManager) && !sessionFile;
			const currentMission = noSession ? stats.currentMission : readCurrentMission();
			const inProcessMission =
				stats.active &&
				stats.currentMissionId === currentMission?.id &&
				stats.sessionFile === sessionFile &&
				stats.noSession === noSession
					? currentMission
					: undefined;
			const persistedMission = noSession ? undefined : readCurrentSessionMission(ctx);
			const activeMission = inProcessMission ?? persistedMission;
			const startNewMission = startsNewRepiMission(activeMission, event.prompt);
			const carriedMission = startNewMission ? undefined : activeMission;
			const continuation = Boolean(carriedMission) && isRepiContinuation(event.prompt);
			const delegationDirectiveUpdate = Boolean(
				carriedMission && missionRequiresDelegation(carriedMission.route, event.prompt),
			);
			const directiveUpdate =
				Boolean(carriedMission) &&
				!continuation &&
				(isOperatorDirectivePrompt(event.prompt) || delegationDirectiveUpdate);
			if (!carriedMission && !isRepiTask(event.prompt)) return;

			const created = !carriedMission;
			const route = carriedMission?.route ?? routeRepiTask(event.prompt);
			const mission = carriedMission
				? !directiveUpdate
					? carriedMission
					: updateMissionDirective(event.prompt, carriedMission)
				: writeCurrentMission(createMission(event.prompt, route));
			const directive = missionOperatorDirective(mission) ?? mission.task;
			if (startNewMission) resetReconStats(stats);
			stats.active = true;
			stats.lastRoute = route;
			stats.currentMissionId = mission.id;
			stats.currentMission = mission;
			stats.sessionFile = sessionFile;
			stats.noSession = noSession;
			if (process.env.REPI_AGENT_THREAD === "1") {
				stats.delegationGate = undefined;
			} else if (missionRequiresDelegation(route, directive)) {
				if (!sameDelegationDirective(stats.delegationGate, mission)) {
					stats.delegationGate = createDelegationGate(mission, directive);
				}
			} else if (!sameDelegationDirective(stats.delegationGate, mission)) {
				stats.delegationGate = undefined;
			}
			if (created && !noSession) {
				pi.appendEntry("repi-route", {
					timestamp: Date.now(),
					route,
					prompt: redactSensitiveText(event.prompt),
					missionId: mission.id,
				});
				pi.appendEntry("repi-mission", { timestamp: Date.now(), missionId: mission.id, route: mission.route });
			}
			if (!pi.getSessionName()) pi.setSessionName(`REPI: ${route.domain}`);
			if (ctx.hasUI) ctx.ui.setStatus("repi", formatRepiRoute(route));
			if (options.injectRuntimePacket === false) return;
			const lane = mission.lanes.find((candidate) => candidate.status === "in_progress");
			const claims = buildEvidenceClaimSummary({ missionId: mission.id, limit: 60 });
			const fallbackCommand = dependencies.nextDecisionCommand(mission);
			const target =
				extractRepiTaskTarget(event.prompt) ??
				extractRepiTaskTarget(missionOperatorDirective(mission) ?? mission.task);
			const directExecutionRequested =
				created || continuation || (isRepiTask(event.prompt) && Boolean(extractRepiTaskTarget(event.prompt)));
			const directCommand =
				directExecutionRequested && target
					? `re_runtime_adapter run ${JSON.stringify(redactSensitiveText(target))}`
					: fallbackCommand;
			const routedDirectCommand = repiCapabilityAwareCommand(route, directive, directCommand);
			const proposedCommand =
				target && /^re_capabilities\s+activate\b/i.test(routedDirectCommand)
					? fallbackCommand
					: routedDirectCommand;
			const nextCommand = truncateMiddle(proposedCommand.replace(/\s+/g, " "), 180).replace(/\s+/g, " ");
			const selfReviewDue = stats.selfReviewDue;
			const directiveHint = truncateMiddle(directive.replace(/\s+/g, " "), 120).replace(/\s+/g, " ");
			const gate = stats.delegationGate;
			const gatePacket =
				gate && gate.status !== "inactive" && gate.status !== "satisfied"
					? `; delegation_gate=${gate.status}:${gate.spec}:${gate.attempts}`
					: "";
			const packet = `REPI state: mission=${mission.id}; domain=${route.domain}; lane=${lane?.name ?? "triage"}; directive=${directiveHint}; claims=${claims.open.length}/${claims.proved.length}/${claims.contradicted.length}; next=${nextCommand}${continuation ? "; continuation=true" : ""}${selfReviewDue ? "; self_review=due" : ""}${gatePacket}`;
			if (!created && !selfReviewDue && stats.lastInjectedState === packet) return;
			stats.lastInjectedState = packet;
			stats.selfReviewDue = false;
			stats.selfReviewNotified = false;
			persistStats();
			const delegationPrompt =
				gate && (gate.status === "required" || gate.status === "dispatching")
					? `\n\n## REPI delegation gate\n${gateTerminalText(gate)}`
					: "";
			return { systemPrompt: `${event.systemPrompt}\n\n${packet}${delegationPrompt}` };
		});
	});

	pi.on("tool_call", async (event) => {
		return runMissionSessionScope(stats.sessionFile, async () => {
			const mission = stats.noSession ? stats.currentMission : readCurrentMission();
			const gate = stats.delegationGate;
			if (gate?.status === "satisfied" && event.toolName !== "re_subagent") {
				if (!(await revalidateSatisfiedDelegationGate(gate))) {
					persistStats();
					return { block: true, reason: `REPI delegation gate: ${gateTerminalText(gate)}` };
				}
			}
			if (gate && gate.status !== "inactive" && gate.status !== "satisfied" && event.toolName !== "re_subagent") {
				return { block: true, reason: `REPI delegation gate: ${gateTerminalText(gate)}` };
			}
			if (gate && event.toolName === "re_subagent") {
				if (gate.status === "blocked") {
					return { block: true, reason: `REPI delegation gate: ${gateTerminalText(gate)}` };
				}
				if (gate.status === "dispatching") {
					return { block: true, reason: "REPI delegation gate: a subagent dispatch is already in flight." };
				}
				if (gate.status === "required") {
					const input = event.input as Record<string, unknown>;
					input.spec = gate.spec;
					input.task = gate.task;
					delete input.additionalPrompt;
					delete input.timeoutMs;
					input.inheritMcp = false;
					input.mcpServers = [];
					input.mcpTools = [];
					// The gate owns execution reliability. Do not let the model
					// choose a timeout that turns the required real dispatch into
					// an avoidable timeout failure.
					input.timeoutMs = 600000;
					gate.status = "dispatching";
					gate.attempts += 1;
					gate.toolCallId = event.toolCallId;
					gate.lastError = undefined;
					delegationDispatchedSinceAgentEnd = true;
					persistStats();
				}
			}
			const routedGuard = routedToolGuard(event, stats, mission);
			if (routedGuard) return { block: true, reason: `REPI routed execution guard: ${routedGuard}` };
			const command = getBashCommand(event);
			if (!command) return;
			if (isReportOnlyBashCommand(command)) {
				return {
					block: true,
					reason:
						"Report-only shell heredocs are blocked; return the completed report directly in the assistant message.",
				};
			}
			stats.bashCalls += 1;
			const hash = createHash("sha256").update(command).digest("hex");
			stats.repeatedCommandCount = stats.lastCommandHash === hash ? stats.repeatedCommandCount + 1 : 1;
			stats.lastCommandHash = hash;
			stats.lastCommands.push(command);
			stats.lastCommands = stats.lastCommands.slice(-8);
			if (stats.active && stats.repeatedCommandCount >= 3) {
				if (!stats.selfReviewDue) stats.selfReviewNotified = false;
				stats.selfReviewDue = true;
				persistStats();
				return {
					block: true,
					reason:
						"REPI loop guard: same bash command repeated 3 times. Run /re-self-review or change evidence surface/tool/arguments.",
				};
			}
			persistStats();
		});
	});

	pi.on("message_end", async (event, ctx) => {
		const gate = stats.delegationGate;
		if (!gate || (gate.status !== "required" && gate.status !== "blocked")) return;
		if (event.message.role !== "assistant") return;
		const content = (event.message as { content?: unknown[] }).content;
		if (Array.isArray(content) && content.some((block) => (block as { type?: unknown })?.type === "toolCall")) return;
		if (ctx.hasPendingMessages()) return;
		return {
			message: {
				...event.message,
				content: [{ type: "text", text: gateTerminalText(gate) }],
				stopReason: "stop",
			} as typeof event.message,
		};
	});

	pi.on("agent_end", async (_event, ctx) => {
		return runMissionSessionScope(stats.sessionFile, async () => {
			const gate = stats.delegationGate;
			if (!gate || gate.status === "satisfied" || gate.status === "inactive") return;
			const dispatchedSinceLastAgentEnd = delegationDispatchedSinceAgentEnd;
			delegationDispatchedSinceAgentEnd = false;
			if (recoverInterruptedDelegationGate(gate, "delegation turn ended without a valid structured tool result")) {
				persistStats();
			}
			if (gate.status === "required" && !dispatchedSinceLastAgentEnd) {
				gate.attempts += 1;
				gate.lastError = "delegation-required turn ended without calling re_subagent";
				persistStats();
			}
			if (gate.attempts >= DELEGATION_MAX_ATTEMPTS || gate.status === "blocked") {
				if (gate.status !== "blocked") {
					gate.status = "blocked";
					gate.lastError ??= "delegation retry budget exhausted";
					persistStats();
				}
				return;
			}
			if (ctx.hasPendingMessages()) return;
			try {
				await pi.sendUserMessage(
					`继续：delegation gate still required. Call the real re_subagent tool now; do not answer the operator or use another tool until its structured handoff validates.`,
					{ deliverAs: "followUp" },
				);
			} catch (error) {
				gate.status = "blocked";
				gate.lastError = `could not enqueue delegation retry: ${error instanceof Error ? error.message : "unknown error"}`;
				persistStats();
			}
		});
	});

	pi.on("tool_result", async (event, ctx) => {
		const sessionFile = ctx.sessionManager?.getSessionFile?.() ?? stats.sessionFile;
		return runMissionSessionScope(sessionFile, async () => {
			let forceError = false;
			const text = event.content
				.filter((block): block is { type: "text"; text: string } => block.type === "text")
				.map((block) => block.text)
				.join("\n");
			const gate = stats.delegationGate;
			if (
				gate &&
				event.toolName === "re_subagent" &&
				gate.status === "dispatching" &&
				event.toolCallId === gate.toolCallId
			) {
				const validation = await validateDelegationResult(event.details, gate);
				if (!event.isError && validation.ok) {
					gate.status = "satisfied";
					gate.runId = validation.result.runId ?? undefined;
					gate.handoffSha256 = validation.result.handoffSha256 ?? undefined;
					gate.result = validation.result;
					gate.lastError = undefined;
					delegationDispatchedSinceAgentEnd = false;
				} else {
					gate.status = gate.attempts >= DELEGATION_MAX_ATTEMPTS ? "blocked" : "required";
					gate.lastError = validation.ok
						? "re_subagent tool result was marked as an error"
						: `re_subagent artifact validation failed: ${validation.error}`;
					clearDelegationArtifact(gate);
					forceError = true;
				}
				gate.toolCallId = undefined;
				persistStats();
			}
			stats.calls += 1;
			if (event.isError || forceError) stats.failures += 1;
			if (
				/runner_unavailable|command_tools_missing|missing[-_ ](?:runner|tool)|command not found|not recognized/i.test(
					text,
				)
			) {
				stats.toolingGapObserved = true;
			}
			if (stats.active && stats.calls > 0 && stats.calls % 5 === 0) {
				if (!stats.selfReviewDue) stats.selfReviewNotified = false;
				stats.selfReviewDue = true;
				if (!stats.selfReviewNotified) {
					stats.selfReviewNotified = true;
					if (ctx.hasUI) ctx.ui.notify("REPI self-review checkpoint is due", "info");
				}
			}
			if (stats.active && event.toolName === "bash") {
				if (
					/command not found|not recognized|No such file|cannot stat|ModuleNotFoundError|ImportError/i.test(text)
				) {
					stats.toolingGapObserved = true;
					if (!stats.selfReviewDue) stats.selfReviewNotified = false;
					stats.selfReviewDue = true;
				}
			}
			persistStats();
			if (forceError) {
				event.isError = true;
				return { isError: true };
			}
		});
	});

	const scopedPi = createSessionScopedExtensionApi(pi, () => stats.sessionFile);
	dependencies.installCommands(scopedPi, stats);
	dependencies.installTools(scopedPi);
	installRepiGoalMode(pi);
}
