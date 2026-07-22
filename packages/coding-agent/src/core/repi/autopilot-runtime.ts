import { createHash } from "node:crypto";
import { existsSync, mkdirSync, renameSync } from "node:fs";
import { dirname, join } from "node:path";
import type { ExtensionAPI } from "../extensions/types.ts";
import type { MissionLane, MissionState } from "./mission.ts";
import type { AutopilotExecutionStrategy, LaneCommandPack, PassiveMapContext } from "./recon-lane-runtime.ts";
import { REPI_GENERIC_TASK, type RoutePlan } from "./routes.ts";

export type BootstrapPlan = {
	tool: string;
	present: boolean;
	path?: string;
	install?: string;
	verify?: string;
	known: boolean;
};

export type AutopilotOptions = {
	action?: "plan" | "run";
	task?: string;
	target?: string;
	lane?: string;
	mapDepth?: number;
	maxAutoSteps?: number;
	runAuto?: boolean;
	cleanState?: boolean;
	reasoning?: "regex" | "llm";
	dispatch?: "inline" | "specialist";
	cwd?: string;
	signal?: AbortSignal;
};

export type AutoModeDefaults = {
	reasoning: "regex" | "llm";
	dispatch: "inline" | "specialist";
	swarmExecution: "simulated" | "real";
};

export type AutopilotRuntimeDependencies = {
	ensureReconStorage: () => void;
	currentMissionPath: () => string;
	reconArchiveDir: () => string;
	reconDir: () => string;
	artifactBasename: (path: string) => string;
	writePrivateJson: (path: string, value: unknown) => void;
	sanitizeTargetForCommand: (target?: string) => string | undefined;
	truncateMiddle: (text: string, maxLength: number) => string;
	readCurrentMission: () => MissionState | undefined;
	writeCurrentMission: (mission: MissionState) => MissionState;
	createMission: (task: string, route: RoutePlan) => MissionState;
	routeReconTask: (task: string) => RoutePlan;
	activeLane: (mission: MissionState, name?: string) => MissionLane | undefined;
	laneCommandPack: (mission: MissionState, lane: MissionLane, target?: string) => LaneCommandPack;
	latestPassiveMapContext: () => PassiveMapContext | undefined;
	autopilotBootstrapPlan: (route: RoutePlan, pack?: LaneCommandPack, map?: PassiveMapContext) => BootstrapPlan[];
	autopilotExecutionStrategy: (pack: LaneCommandPack, bootstrapPlan: BootstrapPlan[]) => AutopilotExecutionStrategy;
	formatAutopilotBootstrap: (plan: BootstrapPlan[]) => string;
	formatAutopilotExecutionStrategy: (strategy: AutopilotExecutionStrategy) => string;
	formatLaneCommandPack: (pack: LaneCommandPack, mode?: "summary" | "full") => string;
	formatMission: (mission: MissionState) => string;
	runPassiveMap: (pi: ExtensionAPI, options: { target?: string; depth?: number }) => Promise<string>;
	updateMissionCheckpoint: (name: string, status: "pending" | "done" | "blocked", note?: string) => MissionState;
	runLaneCommandPack: (
		pi: ExtensionAPI,
		pack: LaneCommandPack,
		options?: { strategy?: AutopilotExecutionStrategy },
	) => Promise<string>;
	runAutoLaneChain: (
		pi: ExtensionAPI,
		options: {
			lane?: string;
			target?: string;
			maxSteps?: number;
			reasoning?: "regex" | "llm";
			dispatch?: "inline" | "specialist";
			cwd?: string;
			signal?: AbortSignal;
		},
	) => Promise<string>;
	formatCompletionAudit: () => string;
};

export function createAutopilotRuntime(dependencies: AutopilotRuntimeDependencies) {
	const {
		ensureReconStorage,
		currentMissionPath,
		reconArchiveDir,
		reconDir,
		artifactBasename,
		writePrivateJson,
		sanitizeTargetForCommand,
		truncateMiddle,
		readCurrentMission,
		writeCurrentMission,
		createMission,
		routeReconTask,
		activeLane,
		laneCommandPack,
		latestPassiveMapContext,
		autopilotBootstrapPlan,
		autopilotExecutionStrategy,
		formatAutopilotBootstrap,
		formatAutopilotExecutionStrategy,
		formatLaneCommandPack,
		formatMission,
		runPassiveMap,
		updateMissionCheckpoint,
		runLaneCommandPack,
		runAutoLaneChain,
		formatCompletionAudit,
	} = dependencies;

	function archiveReconFileIfExists(path: string, archiveRoot: string, archived: string[]): void {
		try {
			if (!existsSync(path)) return;
			const relative = path.startsWith(reconDir()) ? path.slice(reconDir().length + 1) : artifactBasename(path);
			const target = join(archiveRoot, relative);
			mkdirSync(dirname(target), { recursive: true });
			renameSync(path, target);
			archived.push(`${path} -> ${target}`);
		} catch (error) {
			archived.push(`${path} -> archive_failed:${String(error).slice(0, 180)}`);
		}
	}

	function prepareCleanState(params: { target?: string; task?: string }): string[] {
		ensureReconStorage();
		const timestamp = new Date().toISOString();
		const archiveRoot = join(reconArchiveDir(), `autopilot-clean-state-${timestamp.replace(/[:.]/g, "-")}`);
		mkdirSync(archiveRoot, { recursive: true });
		const archived: string[] = [];
		archiveReconFileIfExists(currentMissionPath(), archiveRoot, archived);
		writePrivateJson(join(archiveRoot, "manifest.json"), {
			kind: "repi-autopilot-clean-state-archive",
			generatedAt: timestamp,
			target: sanitizeTargetForCommand(params.target),
			task: params.task ? truncateMiddle(params.task, 500) : undefined,
			archived,
			policy:
				"archive volatile mission/context/dispatcher state; keep tool-index and immutable evidence available through scoped filters",
		});
		ensureReconStorage();
		return [`archive_root=${archiveRoot}`, ...archived.slice(0, 16)];
	}

	function ensureMission(params: { task?: string; target?: string }): MissionState {
		const current = readCurrentMission();
		const task =
			params.task?.trim() ||
			(current?.task ?? `autopilot ${params.target ? `target ${params.target}` : REPI_GENERIC_TASK}`);
		if (params.task || !current)
			return writeCurrentMission(createMission(task, routeReconTask(`${task} ${params.target ?? ""}`)));
		return current;
	}

	function autoModeDefaults(): AutoModeDefaults {
		return { reasoning: "llm", dispatch: "specialist", swarmExecution: "real" };
	}

	function digest(text: string): string {
		return createHash("sha256").update(text).digest("hex");
	}

	function compactAutopilotStage(label: string, text: string, limit = 520): string {
		const lines = text
			.split(/\r?\n/)
			.map((line) => line.trim())
			.filter(
				(line) =>
					line &&
					/^(?:status:|mode:|execution_strategy:|verdict:|score:|exit:|executed_count:|skipped_count:|fallback_count:|missing_tools:|stdout_bytes:|stderr_bytes:|stdout_sha256:|stderr_sha256:|evidence_artifact:|evidence_ledger:|artifact:|next_lane_hint:|auto_lane_update:|run_auto_summary:|steps_executed:|adaptive_decisions:|stop_reason:|next:|reason:|action:|lane:|target:|mission_id:)/i.test(
						line,
					),
			)
			.slice(0, 14);
		const body = lines.length
			? lines.join("\n")
			: text
					.split(/\r?\n/)
					.map((line) => line.trim())
					.filter(Boolean)
					.slice(0, 3)
					.join("\n");
		return truncateMiddle(
			`${label}: bytes=${Buffer.byteLength(text)} sha256=${digest(text)}\n${body || "empty"}`,
			limit,
		);
	}

	function writeAutopilotArtifact(params: {
		kind: "plan" | "run";
		mission: MissionState;
		target?: string;
		strategy: AutopilotExecutionStrategy;
		stages: string[];
		cleanStateSummary: string[];
	}): string {
		ensureReconStorage();
		const timestamp = new Date().toISOString();
		const path = join(reconDir(), "autopilot", "runs", `${timestamp.replace(/[:.]/g, "-")}-${params.kind}.json`);
		mkdirSync(dirname(path), { recursive: true });
		writePrivateJson(path, {
			kind: `repi-autopilot-${params.kind}-artifact`,
			schemaVersion: 1,
			createdAt: timestamp,
			missionId: params.mission.id,
			task: params.mission.task,
			route: params.mission.route,
			target: params.target,
			executionStrategy: params.strategy,
			cleanState: params.cleanStateSummary,
			stages: params.stages.map((text, index) => ({
				index: index + 1,
				bytes: Buffer.byteLength(text),
				sha256: digest(text),
				text,
			})),
		});
		return path;
	}

	async function runAutopilot(pi: ExtensionAPI, params: AutopilotOptions): Promise<string> {
		params.signal?.throwIfAborted();
		const action = params.action ?? "run";
		const cleanStateSummary = params.cleanState ? prepareCleanState(params) : [];
		const mission = ensureMission(params);
		const lane = activeLane(mission, params.lane);
		if (!lane)
			return [
				"autopilot_result:",
				"status: blocked",
				`mission_id: ${mission.id}`,
				"reason: no active lane",
				`available_lanes: ${mission.lanes.map((item) => `${item.name}:${item.status}`).join(", ") || "none"}`,
				`verify: cat ${currentMissionPath()}`,
			].join("\n");
		const initialPack = laneCommandPack(mission, lane, params.target);
		const initialBootstrap = autopilotBootstrapPlan(mission.route, initialPack, latestPassiveMapContext());
		const initialStrategy = autopilotExecutionStrategy(initialPack, initialBootstrap);
		if (action === "plan") {
			const planStages = [
				"autopilot_plan:",
				`mission_id: ${mission.id}`,
				`lane: ${lane.name}`,
				`target: ${initialPack.target ?? params.target ?? "<TARGET>"}`,
				`clean_state: ${params.cleanState ? "applied" : "off"}`,
				...cleanStateSummary.map((item) => `clean_state_${item}`),
				"stages:",
				"- re_map target/depth -> evidence/maps artifact",
				"- bootstrap plan from route/map/command-pack/tool-index",
				"- re_lane plan/run using latest map artifact",
				"- re_lane run-auto bounded follow-up chain",
				"- re_verifier matrix -> re_compiler draft -> re_replayer run",
				"",
				"## bootstrap",
				formatAutopilotBootstrap(initialBootstrap),
				"",
				"## execution-strategy",
				formatAutopilotExecutionStrategy(initialStrategy),
				"",
				formatLaneCommandPack(initialStrategy.pack, "full"),
			].join("\n");
			const artifactPath = writeAutopilotArtifact({
				kind: "plan",
				mission,
				target: initialStrategy.pack.target ?? params.target,
				strategy: initialStrategy,
				stages: [planStages],
				cleanStateSummary,
			});
			return truncateMiddle(
				[
					"autopilot_plan:",
					`mission_id: ${mission.id}`,
					`lane: ${lane.name}`,
					`target: ${initialStrategy.pack.target ?? params.target ?? "<TARGET>"}`,
					`execution_strategy: ${initialStrategy.mode}`,
					`command_count: ${initialStrategy.pack.commands.length}`,
					`fallback_count: ${initialStrategy.fallbacks.length}`,
					`skipped_count: ${initialStrategy.skipped.length}`,
					`missing_tools: ${initialStrategy.missingTools.join(", ") || "none"}`,
					`artifact: ${artifactPath}`,
					"detail: full bootstrap, strategy, and command pack are in artifact",
				].join("\n"),
				4096,
			);
		}

		const outputs = [`## mission\n${formatMission(mission)}`];
		outputs.push(
			`## map\n${await runPassiveMap(pi, { target: params.target ?? initialPack.target, depth: params.mapDepth })}`,
		);
		const mappedMission = readCurrentMission() ?? mission;
		const mappedLane = activeLane(mappedMission, params.lane) ?? lane;
		updateMissionCheckpoint("repro_commands_ready", "done", `autopilot:${mappedLane.name}`);
		const pack = laneCommandPack(mappedMission, mappedLane, params.target ?? initialPack.target);
		const bootstrap = autopilotBootstrapPlan(mappedMission.route, pack, latestPassiveMapContext());
		const strategy = autopilotExecutionStrategy(pack, bootstrap);
		outputs.push(`## bootstrap\n${formatAutopilotBootstrap(bootstrap)}`);
		outputs.push(`## execution-strategy\n${formatAutopilotExecutionStrategy(strategy)}`);
		outputs.push(`## command-pack\n${formatLaneCommandPack(strategy.pack, "full")}`);
		outputs.push(`## lane-run\n${await runLaneCommandPack(pi, strategy.pack, { strategy })}`);
		if (params.runAuto !== false) {
			const defaults = autoModeDefaults();
			outputs.push(
				`## run-auto\n${await runAutoLaneChain(pi, {
					target: strategy.pack.target ?? params.target,
					maxSteps: params.maxAutoSteps,
					reasoning: params.reasoning ?? defaults.reasoning,
					dispatch: params.dispatch ?? defaults.dispatch,
					cwd: params.cwd,
					signal: params.signal,
				})}`,
			);
		}
		outputs.push(`## completion-audit\n${formatCompletionAudit()}`);
		const artifactPath = writeAutopilotArtifact({
			kind: "run",
			mission: mappedMission,
			target: strategy.pack.target ?? params.target,
			strategy,
			stages: outputs,
			cleanStateSummary,
		});
		return truncateMiddle(
			[
				"autopilot_result:",
				`action: ${action}`,
				`mission_id: ${mappedMission.id}`,
				`lane: ${mappedLane.name}`,
				`target: ${strategy.pack.target ?? params.target ?? "<TARGET>"}`,
				`execution_strategy: ${strategy.mode}`,
				`clean_state: ${params.cleanState ? "applied" : "off"}`,
				...cleanStateSummary.map((item) => `clean_state_${item}`),
				`artifact: ${artifactPath}`,
				`stage_count: ${outputs.length}`,
				"stages:",
				...outputs.map((output, index) => compactAutopilotStage(`stage_${index + 1}`, output)),
				"detail: full map, bootstrap, command pack, lane-run, run-auto, and completion audit are in artifact",
			].join("\n"),
			4096,
		);
	}

	return { autoModeDefaults, runAutopilot };
}

export type AutopilotRuntime = ReturnType<typeof createAutopilotRuntime>;
