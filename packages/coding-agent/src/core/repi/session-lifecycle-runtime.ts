import { createHash } from "node:crypto";
import type { ExtensionAPI, ToolCallEvent, ToolDefinition } from "../extensions/types.ts";
import { repiCapabilityAwareCommand } from "./capabilities.ts";
import { buildEvidenceClaimSummary } from "./evidence.ts";
import { installRepiGoalMode } from "./goal.ts";
import {
	createMission,
	type MissionRuntimeStats,
	type MissionState,
	readCurrentMission,
	readCurrentSessionMission,
	updateMissionRuntimeStats,
	writeCurrentMission,
} from "./mission.ts";
import { ensureReconStorage } from "./resources.ts";
import { formatRepiRoute, isRepiContinuation, isRepiTask, type RoutePlan, routeRepiTask } from "./routes.ts";
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
	lastRoute?: RoutePlan;
	currentMissionId?: string;
	currentMission?: MissionState;
	sessionFile?: string;
	noSession?: boolean;
	lastInjectedState?: string;
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
	const currentTarget = canonicalMissionTarget(extractRepiTaskTarget(activeMission.task));
	const requestedTarget = canonicalMissionTarget(extractRepiTaskTarget(prompt));
	return Boolean(currentTarget && requestedTarget && currentTarget !== requestedTarget);
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
	stats.lastInjectedState = undefined;
}

function getBashCommand(event: ToolCallEvent): string | undefined {
	if (event.toolName !== "bash") return undefined;
	const input = event.input as { command?: unknown; cmd?: unknown };
	const command = input.command ?? input.cmd;
	return typeof command === "string" ? command.trim() : undefined;
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
	};
	const persistStats = (): void => {
		if (!stats.active || stats.noSession || !stats.currentMissionId) return;
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
			if (ctx.hasUI) ctx.ui.setStatus("repi", "REPI kernel profile ready");
		});
	});

	pi.on("session_tree", (_event, ctx) => {
		const sessionFile = ctx.sessionManager?.getSessionFile?.();
		return runMissionSessionScope(sessionFile, () => {
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
			if (!carriedMission && !isRepiTask(event.prompt)) return;

			const created = !carriedMission;
			const route = carriedMission?.route ?? routeRepiTask(event.prompt);
			const mission =
				carriedMission ??
				(noSession ? createMission(event.prompt, route) : writeCurrentMission(createMission(event.prompt, route)));
			if (startNewMission) resetReconStats(stats);
			stats.active = true;
			stats.lastRoute = route;
			stats.currentMissionId = mission.id;
			stats.currentMission = mission;
			stats.sessionFile = sessionFile;
			stats.noSession = noSession;
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
			const nextCommand = truncateMiddle(
				repiCapabilityAwareCommand(route, mission.task, dependencies.nextDecisionCommand(mission)).replace(
					/\s+/g,
					" ",
				),
				180,
			);
			const selfReviewDue = stats.selfReviewDue;
			const packet = created
				? `REPI state: mission=${mission.id}; domain=${route.domain}; lane=${lane?.name ?? "triage"}; next=${nextCommand}`
				: `REPI state: mission=${mission.id}; lane=${lane?.name ?? "closure"}; claims=${claims.open.length}/${claims.proved.length}/${claims.contradicted.length}; next=${nextCommand}${continuation ? "; continuation=true" : ""}${selfReviewDue ? "; self_review=due" : ""}`;
			if (!created && !selfReviewDue && stats.lastInjectedState === packet) return;
			stats.lastInjectedState = packet;
			stats.selfReviewDue = false;
			stats.selfReviewNotified = false;
			persistStats();
			return { systemPrompt: `${event.systemPrompt}\n\n${packet}` };
		});
	});

	pi.on("tool_call", async (event) => {
		return runMissionSessionScope(stats.sessionFile, async () => {
			const command = getBashCommand(event);
			if (!command) return;
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

	pi.on("tool_result", async (event, ctx) => {
		const sessionFile = ctx.sessionManager?.getSessionFile?.() ?? stats.sessionFile;
		return runMissionSessionScope(sessionFile, async () => {
			stats.calls += 1;
			if (event.isError) stats.failures += 1;
			if (stats.active && stats.calls > 0 && stats.calls % 5 === 0) {
				if (!stats.selfReviewDue) stats.selfReviewNotified = false;
				stats.selfReviewDue = true;
				if (!stats.selfReviewNotified) {
					stats.selfReviewNotified = true;
					if (ctx.hasUI) ctx.ui.notify("REPI self-review checkpoint is due", "info");
				}
			}
			if (stats.active && event.toolName === "bash") {
				const text = event.content
					.filter((block): block is { type: "text"; text: string } => block.type === "text")
					.map((block) => block.text)
					.join("\n");
				if (
					/command not found|not recognized|No such file|cannot stat|ModuleNotFoundError|ImportError/i.test(text)
				) {
					if (!stats.selfReviewDue) stats.selfReviewNotified = false;
					stats.selfReviewDue = true;
				}
			}
			persistStats();
		});
	});

	const scopedPi = createSessionScopedExtensionApi(pi, () => stats.sessionFile);
	dependencies.installCommands(scopedPi, stats);
	dependencies.installTools(scopedPi);
	installRepiGoalMode(pi);
}
