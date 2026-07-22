import type { ExtensionAPI } from "../extensions/types.ts";
import type { EvidenceRecord } from "./evidence.ts";
import type { ReLaneSpecialistCommandPackCheckV1 } from "./lane-specialist-pack.ts";
import { formatReLaneSpecialistCommandPackGate } from "./lane-specialist-pack.ts";
import type { MissionCheckpointStatus, MissionLane, MissionLaneStatus, MissionState } from "./mission.ts";
import { createMission, normalizeOperatorCheckpointUpdate, readCurrentMission } from "./mission.ts";
import { REPI_SOURCE } from "./profile.ts";
import type { ProfileCheckMode } from "./profile-check.ts";
import { formatRepiRoute, REPI_GENERIC_TASK, type RoutePlan, routeRepiTask } from "./routes.ts";
import type { RuntimeAdapterExecutionCheckV1 } from "./runtime-adapter.ts";
import { formatRuntimeAdapterExecutionGate } from "./runtime-adapter.ts";
import type { LaneCommand } from "./specialist-command-planner.ts";
import { truncateMiddle } from "./text.ts";
import type { ProfessionalRuntimeBridgesCheckV1 } from "./toolchain-runtime.ts";
import { formatProfessionalRuntimeBridgesGate } from "./toolchain-runtime.ts";

export type ReconCommandStats = {
	lastRoute?: RoutePlan;
	currentMissionId?: string;
	selfReviewDue: boolean;
};

export type ReconCommandLanePack = {
	missionId?: string;
	lane: string;
	route: string;
	target?: string;
	commands: LaneCommand[];
	notes: string[];
};

export type ReconCommandBootstrapPlan = {
	tool: string;
	present: boolean;
	path?: string;
	install?: string;
	verify?: string;
	known: boolean;
};

export type ReconCommandCompletionAudit = {
	ready: boolean;
	blockers: string[];
	warnings: string[];
	mission?: MissionState;
	domainProofExitClosure?: {
		status: string;
		blockers: string[];
		matchedProofExits: string[];
		missingProofExits: string[];
		[key: string]: unknown;
	};
};

type EvidenceInput = Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number };
type TargetOptions = { target?: string };
type TimeoutOptions = TargetOptions & { timeoutMs?: number };
type MobileOptions = TimeoutOptions & { packageName?: string };
type ExploitLabOptions = TimeoutOptions & { runs?: number };
type OperationOptions = TargetOptions & { task?: string };
type LaneRunOptions = { lane?: string; target?: string; maxSteps?: number };
type AutopilotOptions = {
	action?: "plan" | "run";
	target?: string;
	maxAutoSteps?: number;
	cleanState?: boolean;
};
type RuntimeAdapterOptions = { adapter?: string; target?: string; timeoutMs?: number };
type MissionLaneCommandPack = ReconCommandLanePack;
type MissionLaneCommandPackFactory<TPack extends MissionLaneCommandPack> = (
	mission: MissionState,
	lane: MissionLane,
	target?: string,
) => TPack;

export type ReconCommandDependencies<
	TStats extends ReconCommandStats,
	TCompletionAudit = ReconCommandCompletionAudit,
	TPack extends MissionLaneCommandPack = MissionLaneCommandPack,
> = {
	sendSource?: string;
	buildKernelOutput: (action: "build" | "show" | "audit", options: TargetOptions) => string;
	runDecisionCore: (pi: ExtensionAPI, options: TargetOptions & { maxSteps?: number }) => Promise<string>;
	buildDecisionCoreOutput: (action: "plan" | "show" | "tick", options: TargetOptions) => string;
	runLiveBrowser: (pi: ExtensionAPI, options: TimeoutOptions) => Promise<string>;
	buildLiveBrowserOutput: (action: "plan" | "show", options: TimeoutOptions) => string;
	runWebAuthzState: (pi: ExtensionAPI, options: TimeoutOptions) => Promise<string>;
	buildWebAuthzStateOutput: (action: "plan" | "show", options: TimeoutOptions) => string;
	runExploitLab: (pi: ExtensionAPI, options: ExploitLabOptions) => Promise<string>;
	buildExploitLabOutput: (action: "plan" | "show" | "bundle", options: ExploitLabOptions) => string;
	runMobileRuntime: (pi: ExtensionAPI, options: MobileOptions) => Promise<string>;
	buildMobileRuntimeOutput: (action: "plan" | "show", options: MobileOptions) => string;
	runNativeRuntime: (pi: ExtensionAPI, options: TimeoutOptions) => Promise<string>;
	buildNativeRuntimeOutput: (action: "plan" | "show", options: TimeoutOptions) => string;
	refreshToolIndex: (pi: ExtensionAPI) => Promise<string>;
	buildToolDigest: () => string;
	buildToolchainDomainCapabilityOutput: (action: "show" | "refresh", domain?: string) => string;
	buildProfessionalRuntimeBridgesGate: (filter?: string) => ProfessionalRuntimeBridgesCheckV1;
	writeProfessionalRuntimeBridgesArtifact: (report: ProfessionalRuntimeBridgesCheckV1) => string;
	buildRuntimeAdapterExecutionGate: (filter?: string) => RuntimeAdapterExecutionCheckV1;
	writeRuntimeAdapterExecutionArtifact: (report: RuntimeAdapterExecutionCheckV1) => string;
	runRuntimeAdapterExecution: (pi: ExtensionAPI, options: RuntimeAdapterOptions) => Promise<string>;
	buildReLaneSpecialistCommandPackGate: (domain?: string) => ReLaneSpecialistCommandPackCheckV1;
	buildDomainProofExitClosureOutput: (action: "show" | "write", domain?: string) => string;
	writeCurrentMission: (mission: MissionState) => MissionState;
	updateMissionCheckpoint: (name: string, status: MissionCheckpointStatus, note?: string) => MissionState;
	formatMission: (mission: MissionState) => string;
	buildMissionDigest: () => string;
	formatLaneQueue: (mission: MissionState) => string;
	activeLane: (mission: MissionState, name?: string) => MissionLane | undefined;
	updateMissionLane: (params: {
		action: "next" | "done" | "block" | "set" | "add";
		lane?: string;
		status?: MissionLaneStatus;
		objective?: string;
		next?: string[];
		note?: string;
	}) => MissionState;
	laneCommandPack: MissionLaneCommandPackFactory<TPack>;
	formatLaneCommandPack: (pack: TPack) => string;
	runLaneCommandPack: (pi: ExtensionAPI, pack: TPack) => Promise<string>;
	runAutoLaneChain: (pi: ExtensionAPI, options: LaneRunOptions) => Promise<string>;
	runPassiveMap: (pi: ExtensionAPI, options: { target?: string; depth?: number }) => Promise<string>;
	runAutopilot: (pi: ExtensionAPI, options: AutopilotOptions) => Promise<string>;
	appendEvidence: (record: EvidenceInput) => EvidenceRecord;
	buildEvidenceDigest: (query?: string) => string;
	buildAttackGraphOutput: (action: "build" | "show") => string;
	buildExploitChainOutput: (action: "plan" | "show" | "compose", options: TargetOptions) => string;
	buildCampaignOutput: (action: "plan" | "show", options: OperationOptions) => string;
	runOperationQueue: (pi: ExtensionAPI, options: LaneRunOptions) => Promise<string>;
	buildOperationOutput: (action: "plan" | "show" | "next", options: OperationOptions) => string;
	buildDelegateOutput: (action: "plan" | "show" | "merge", options: OperationOptions) => string;
	runSwarm: (
		pi: ExtensionAPI,
		options: LaneRunOptions & { maxWorkers?: number; maxCommands?: number },
	) => Promise<string>;
	buildSwarmOutput: (action: "plan" | "show" | "merge", options: TargetOptions) => string;
	buildSupervisorOutput: (action: "review" | "show" | "repair", options: TargetOptions) => Promise<string>;
	dispatchOperatorQueue: (pi: ExtensionAPI, options: LaneRunOptions) => Promise<string>;
	buildOperatorOutput: (action: "plan" | "show" | "verify" | "escalate", options: TargetOptions) => string;
	buildVerifierOutput: (action: "check" | "show" | "matrix", options: TargetOptions) => string;
	buildCompilerOutput: (action: "draft" | "show" | "final", options: TargetOptions) => string;
	runReplayer: (pi: ExtensionAPI, options: LaneRunOptions) => Promise<string>;
	buildReplayerOutput: (action: "plan" | "show", options: TargetOptions) => string;
	buildAutofixOutput: (action: "plan" | "show" | "apply", options: TargetOptions) => string;
	runProofLoop: (
		pi: ExtensionAPI,
		options: TargetOptions & { maxSteps?: number; replaySteps?: number },
	) => Promise<string>;
	buildProofLoopOutput: (
		action: "plan" | "show" | "run",
		options: TargetOptions & { maxSteps?: number; replaySteps?: number },
	) => string;
	buildProfileCheckOutput: (mode: ProfileCheckMode | "show") => string;
	createBootstrapPlan: (tools: string[]) => ReconCommandBootstrapPlan[];
	installBootstrapTools: (pi: ExtensionAPI, tools: string[]) => Promise<string>;
	formatBootstrapPlan: (plan: ReconCommandBootstrapPlan[]) => string;
	writeReportScaffold: (title?: string) => string;
	formatCompletionAudit: () => string;
	runCompletionAudit: () => TCompletionAudit;
	formatCompletionAuditFromAudit: (audit: TCompletionAudit) => string;
	makeSelfReview: (stats: TStats) => string;
};

export function createReconCommands<
	TStats extends ReconCommandStats,
	TCompletionAudit = ReconCommandCompletionAudit,
	TPack extends MissionLaneCommandPack = MissionLaneCommandPack,
>(dependencies: ReconCommandDependencies<TStats, TCompletionAudit, TPack>) {
	const {
		buildKernelOutput,
		runDecisionCore,
		buildDecisionCoreOutput,
		runLiveBrowser,
		buildLiveBrowserOutput,
		runWebAuthzState,
		buildWebAuthzStateOutput,
		runExploitLab,
		buildExploitLabOutput,
		runMobileRuntime,
		buildMobileRuntimeOutput,
		runNativeRuntime,
		buildNativeRuntimeOutput,
		refreshToolIndex,
		buildToolDigest,
		buildToolchainDomainCapabilityOutput,
		buildProfessionalRuntimeBridgesGate,
		writeProfessionalRuntimeBridgesArtifact,
		buildRuntimeAdapterExecutionGate,
		writeRuntimeAdapterExecutionArtifact,
		runRuntimeAdapterExecution,
		buildReLaneSpecialistCommandPackGate,
		buildDomainProofExitClosureOutput,
		writeCurrentMission,
		updateMissionCheckpoint,
		formatMission,
		buildMissionDigest,
		formatLaneQueue,
		activeLane,
		updateMissionLane,
		laneCommandPack,
		formatLaneCommandPack,
		runLaneCommandPack,
		runAutoLaneChain,
		runPassiveMap,
		runAutopilot,
		appendEvidence,
		buildEvidenceDigest,
		buildAttackGraphOutput,
		buildExploitChainOutput,
		buildCampaignOutput,
		runOperationQueue,
		buildOperationOutput,
		buildDelegateOutput,
		runSwarm,
		buildSwarmOutput,
		buildSupervisorOutput,
		dispatchOperatorQueue,
		buildOperatorOutput,
		buildVerifierOutput,
		buildCompilerOutput,
		runReplayer,
		buildReplayerOutput,
		buildAutofixOutput,
		runProofLoop,
		buildProofLoopOutput,
		buildProfileCheckOutput,
		createBootstrapPlan,
		installBootstrapTools,
		formatBootstrapPlan,
		writeReportScaffold,
		formatCompletionAudit,
		runCompletionAudit,
		formatCompletionAuditFromAudit,
		makeSelfReview,
	} = dependencies;

	function sendDisplayMessage(pi: ExtensionAPI, title: string, body: string): void {
		pi.sendMessage({
			customType: "repi",
			content: `## ${title}\n\n${body}`,
			display: true,
			details: { source: dependencies.sendSource ?? REPI_SOURCE, title },
		});
	}
	const routeReconTask = routeRepiTask;
	const formatRoute = formatRepiRoute;
	const formatProfessionalRuntimeBridgesGateReport = formatProfessionalRuntimeBridgesGate;
	return function installReconCommands(pi: ExtensionAPI, stats: TStats): void {
		pi.registerCommand("re-route", {
			description: "Route a reverse/pentest task with REPI",
			handler: async (args) => {
				const route = routeReconTask(args || REPI_GENERIC_TASK);
				stats.lastRoute = route;
				sendDisplayMessage(
					pi,
					"REPI Route",
					[formatRoute(route), `skill: ${route.skillHint}`, ...route.workflow.map((step) => `- ${step}`)].join(
						"\n",
					),
				);
			},
		});
		pi.registerCommand("re-kernel", {
			description: "Build/show/audit REPI execution kernel directives: /re-kernel [build|show|audit] [target]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "show" || first === "audit" ? (parts.shift() as "show" | "audit") : "build";
				if (first === "build") parts.shift();
				const target = parts.join(" ") || undefined;
				sendDisplayMessage(pi, "REPI Execution Kernel", buildKernelOutput(action, { target }));
			},
		});
		pi.registerCommand("re-decision", {
			description: "Plan/show/tick/run REPI decision core: /re-decision [plan|show|tick|run] [target] [max-steps]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action =
					first === "show" || first === "tick" || first === "run"
						? (parts.shift() as "show" | "tick" | "run")
						: "plan";
				if (first === "plan") parts.shift();
				const last = parts.at(-1);
				const maxSteps = last && /^\d+$/.test(last) ? Number(parts.pop()) : undefined;
				const target = parts.join(" ") || undefined;
				const text =
					action === "run"
						? await runDecisionCore(pi, { target, maxSteps })
						: buildDecisionCoreOutput(action, { target });
				sendDisplayMessage(pi, "REPI Decision Core", text);
			},
		});
		pi.registerCommand("re-live-browser", {
			description:
				"Plan/show/run REPI browser/XHR/WS runtime capture: /re-live-browser [plan|show|run] [url] [timeout-ms]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "show" || first === "run" ? (parts.shift() as "show" | "run") : "plan";
				if (first === "plan") parts.shift();
				const last = parts.at(-1);
				const timeoutMs = last && /^\d+$/.test(last) ? Number(parts.pop()) : undefined;
				const target = parts.join(" ") || undefined;
				const text =
					action === "run"
						? await runLiveBrowser(pi, { target, timeoutMs })
						: buildLiveBrowserOutput(action, { target, timeoutMs });
				sendDisplayMessage(pi, "REPI Live Browser", text);
			},
		});
		pi.registerCommand("re-web-authz-state", {
			description:
				"Plan/show/run REPI Web/API authz state machine capture: /re-web-authz-state [plan|show|run] [url] [timeout-ms]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "show" || first === "run" ? (parts.shift() as "show" | "run") : "plan";
				if (first === "plan") parts.shift();
				const last = parts.at(-1);
				const timeoutMs = last && /^\d+$/.test(last) ? Number(parts.pop()) : undefined;
				const target = parts.join(" ") || undefined;
				const text =
					action === "run"
						? await runWebAuthzState(pi, { target, timeoutMs })
						: buildWebAuthzStateOutput(action, { target, timeoutMs });
				sendDisplayMessage(pi, "REPI Web Authz State", text);
			},
		});

		pi.registerCommand("re-exploit-lab", {
			description:
				"Plan/show/run/bundle REPI exploit reliability lab: /re-exploit-lab [plan|show|run|bundle] [target] [runs] [timeout-ms]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action =
					first === "show" || first === "run" || first === "bundle"
						? (parts.shift() as "show" | "run" | "bundle")
						: "plan";
				if (first === "plan") parts.shift();
				const maybeTimeout = parts.at(-1);
				const timeoutMs = maybeTimeout && /^\d+$/.test(maybeTimeout) ? Number(parts.pop()) : undefined;
				const maybeRuns = parts.at(-1);
				const runs = maybeRuns && /^\d+$/.test(maybeRuns) ? Number(parts.pop()) : undefined;
				const target = parts.join(" ") || undefined;
				const text =
					action === "run"
						? await runExploitLab(pi, { target, runs, timeoutMs })
						: buildExploitLabOutput(action, { target, runs, timeoutMs });
				sendDisplayMessage(pi, "REPI Exploit Lab", text);
			},
		});

		pi.registerCommand("re-mobile-runtime", {
			description:
				"Plan/show/run REPI mobile APK/Android Frida runtime capture: /re-mobile-runtime [plan|show|run] [target] [packageName] [timeout-ms]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "show" || first === "run" ? (parts.shift() as "show" | "run") : "plan";
				if (first === "plan") parts.shift();
				const last = parts.at(-1);
				const timeoutMs = last && /^\d+$/.test(last) ? Number(parts.pop()) : undefined;
				const packageName =
					parts.length > 1 && /^[A-Za-z][\w]*(?:\.[A-Za-z][\w]*){1,}$/.test(parts.at(-1) ?? "")
						? parts.pop()
						: undefined;
				const target = parts.join(" ") || undefined;
				const text =
					action === "run"
						? await runMobileRuntime(pi, { target, packageName, timeoutMs })
						: buildMobileRuntimeOutput(action, { target, packageName, timeoutMs });
				sendDisplayMessage(pi, "REPI Mobile Runtime", text);
			},
		});

		pi.registerCommand("re-native-runtime", {
			description:
				"Plan/show/run REPI native ELF/SO GDB/Pwn runtime capture: /re-native-runtime [plan|show|run] [target] [timeout-ms]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "show" || first === "run" ? (parts.shift() as "show" | "run") : "plan";
				if (first === "plan") parts.shift();
				const last = parts.at(-1);
				const timeoutMs = last && /^\d+$/.test(last) ? Number(parts.pop()) : undefined;
				const target = parts.join(" ") || undefined;
				const text =
					action === "run"
						? await runNativeRuntime(pi, { target, timeoutMs })
						: buildNativeRuntimeOutput(action, { target, timeoutMs });
				sendDisplayMessage(pi, "REPI Native Runtime", text);
			},
		});

		pi.registerCommand("re-tools", {
			description: "Show or refresh REPI tool index: /re-tools [show|refresh]",
			handler: async (args) => {
				const action = args.trim() || "show";
				const text = action === "refresh" ? await refreshToolIndex(pi) : buildToolDigest();
				updateMissionCheckpoint("tool_index_checked", "done", `/re-tools ${action}`);
				sendDisplayMessage(pi, "REPI Tool Index", truncateMiddle(text, 9000));
			},
		});
		pi.registerCommand("re-toolchain", {
			description: "Show REPI domain toolchain capability matrix: /re-toolchain [show|refresh] [domain]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "refresh" ? (parts.shift() as "refresh") : "show";
				if (first === "show") parts.shift();
				if (action === "refresh") await refreshToolIndex(pi);
				const text = buildToolchainDomainCapabilityOutput("show", parts.join(" ") || undefined);
				updateMissionCheckpoint("tool_index_checked", "done", `/re-toolchain ${action}`);
				sendDisplayMessage(pi, "REPI Toolchain Domain Capability", truncateMiddle(text, 16000));
			},
		});
		pi.registerCommand("re-runtime-bridge", {
			description:
				"Show/refresh REPI professional runtime bridges: /re-runtime-bridge [show|refresh] [tool-bridge-runtime|exploit-verifier-runtime|web-cdp-replay|mobile-frida]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "refresh" ? (parts.shift() as "refresh") : "show";
				if (first === "show") parts.shift();
				if (action === "refresh") await refreshToolIndex(pi);
				const report = buildProfessionalRuntimeBridgesGate(parts.join(" ") || undefined);
				const path = writeProfessionalRuntimeBridgesArtifact(report);
				updateMissionCheckpoint("tool_index_checked", "done", "ProfessionalRuntimeBridgesCheckV1");
				sendDisplayMessage(
					pi,
					"REPI Professional Runtime Bridges",
					truncateMiddle(formatProfessionalRuntimeBridgesGateReport(report, path), 22000),
				);
			},
		});

		pi.registerCommand("re-runtime-adapter", {
			description:
				"Show/plan/run REPI runtime adapters: /re-runtime-adapter [show|plan|run|refresh] [adapter-id] [target] [timeout-ms]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action =
					first === "plan" || first === "run" || first === "refresh"
						? (parts.shift() as "plan" | "run" | "refresh")
						: "show";
				if (first === "show") parts.shift();
				const maybeTimeout = parts.at(-1);
				const timeoutMs = maybeTimeout && /^\d+$/.test(maybeTimeout) ? Number(parts.pop()) : undefined;
				const adapter = parts[0]?.includes("adapter") ? parts.shift() : undefined;
				const target = parts.join(" ") || undefined;
				if (action === "refresh") await refreshToolIndex(pi);
				const text =
					action === "run"
						? await runRuntimeAdapterExecution(pi, { adapter, target, timeoutMs })
						: (() => {
								const report = buildRuntimeAdapterExecutionGate(adapter || target);
								const path = writeRuntimeAdapterExecutionArtifact(report);
								return formatRuntimeAdapterExecutionGate(report, path);
							})();
				updateMissionCheckpoint("tool_index_checked", "done", "RuntimeAdapterExecutionCheckV1");
				sendDisplayMessage(pi, "REPI Runtime Adapter Execution", truncateMiddle(text, 24000));
			},
		});

		pi.registerCommand("re-lane-specialist-pack", {
			description: "Show REPI re_lane specialist command-pack closure: /re-lane-specialist-pack [show] [domain]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				if (parts[0] === "show") parts.shift();
				const report = buildReLaneSpecialistCommandPackGate(parts.join(" ") || undefined);
				updateMissionCheckpoint(
					"repro_commands_ready",
					report.readyDomainCount === report.domainCount ? "done" : "blocked",
					"ReLaneSpecialistCommandPackCheckV1",
				);
				sendDisplayMessage(
					pi,
					"REPI Lane Specialist Command Pack",
					truncateMiddle(formatReLaneSpecialistCommandPackGate(report), 20000),
				);
			},
		});

		pi.registerCommand("re-domain-proof-exit", {
			description:
				"Show/write REPI domain proof-exit closure from runtime artifacts: /re-domain-proof-exit [show|write] [domain]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "write" ? (parts.shift() as "write") : "show";
				if (first === "show") parts.shift();
				const domain = parts.join(" ") || undefined;
				const text = buildDomainProofExitClosureOutput(action, domain);
				sendDisplayMessage(pi, "REPI Domain Proof Exit Closure", truncateMiddle(text, 18000));
			},
		});
		pi.registerCommand("re-mission", {
			description: "Show or update REPI mission blackboard: /re-mission [show|new|checkpoint] ...",
			handler: async (args) => {
				const trimmed = args.trim();
				if (trimmed.startsWith("new ")) {
					const task = trimmed.slice("new ".length).trim() || REPI_GENERIC_TASK;
					const mission = writeCurrentMission(createMission(task, routeReconTask(task)));
					stats.currentMissionId = mission.id;
					stats.lastRoute = mission.route;
					sendDisplayMessage(pi, "REPI Mission Created", formatMission(mission));
					return;
				}
				if (trimmed.startsWith("checkpoint ")) {
					const [, checkpoint = "manual_check", status = "done", ...noteParts] = trimmed.split(/\s+/);
					const normalizedStatus = ["pending", "done", "blocked"].includes(status)
						? (status as MissionCheckpointStatus)
						: "done";
					const checkpointUpdate = normalizeOperatorCheckpointUpdate(
						checkpoint,
						normalizedStatus,
						noteParts.join(" "),
					);
					const mission = updateMissionCheckpoint(checkpoint, checkpointUpdate.status, checkpointUpdate.note);
					stats.currentMissionId = mission.id;
					sendDisplayMessage(pi, "REPI Mission Check Updated", formatMission(mission));
					return;
				}
				sendDisplayMessage(pi, "REPI Mission", buildMissionDigest());
			},
		});
		pi.registerCommand("re-lane", {
			description: "Drive REPI mission lanes: /re-lane [show|next|done|block|add|set|plan|run|run-auto] ...",
			handler: async (args) => {
				const trimmed = args.trim();
				const [action = "show", lane, ...rest] = trimmed.split(/\s+/);
				if (action === "show") {
					const mission = readCurrentMission();
					sendDisplayMessage(pi, "REPI Lanes", mission ? formatLaneQueue(mission) : "no active mission");
					return;
				}
				if (action === "run-auto") {
					const laneName = lane && /^\d+$/.test(lane) ? undefined : lane;
					const maxText = laneName ? rest[0] : lane;
					const maxSteps = maxText && /^\d+$/.test(maxText) ? Number(maxText) : undefined;
					const text = await runAutoLaneChain(pi, { lane: laneName, maxSteps });
					sendDisplayMessage(pi, "REPI Lane Auto Runner", text);
					return;
				}
				if (action === "plan" || action === "run") {
					const mission =
						readCurrentMission() ??
						writeCurrentMission(createMission("manual mission", routeReconTask(REPI_GENERIC_TASK)));
					const selectedLane = activeLane(mission, lane);
					if (!selectedLane) {
						sendDisplayMessage(pi, "REPI Lane Command Pack", "no active lane");
						return;
					}
					updateMissionCheckpoint("repro_commands_ready", "done", `lane-command-pack:${selectedLane.name}`);
					const pack = laneCommandPack(mission, selectedLane, rest.join(" ") || undefined);
					const text = action === "run" ? await runLaneCommandPack(pi, pack) : formatLaneCommandPack(pack);
					sendDisplayMessage(pi, "REPI Lane Command Pack", text);
					return;
				}
				if (action === "add") {
					const [name = "manual-lane", objective = "manual objective", nextText = ""] = trimmed
						.slice("add".length)
						.split("::")
						.map((part) => part.trim());
					const mission = updateMissionLane({
						action: "add",
						lane: name,
						objective,
						next: nextText
							? nextText
									.split(",")
									.map((step) => step.trim())
									.filter(Boolean)
							: [],
					});
					sendDisplayMessage(pi, "REPI Lane Added", formatLaneQueue(mission));
					return;
				}
				const mission = updateMissionLane({
					action:
						action === "done" || action === "block" || action === "set" || action === "next" ? action : "next",
					lane,
					status: action === "set" && rest[0] ? (rest[0] as MissionLaneStatus) : undefined,
					note: rest.join(" "),
				});
				sendDisplayMessage(pi, "REPI Lane Updated", formatLaneQueue(mission));
			},
		});
		pi.registerCommand("re-map", {
			description: "Run REPI passive target/workspace mapper: /re-map [target] [depth]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const last = parts.at(-1);
				const depth = last && /^\d+$/.test(last) ? Number(parts.pop()) : undefined;
				const target = parts.join(" ") || undefined;
				const text = await runPassiveMap(pi, { target, depth });
				sendDisplayMessage(pi, "REPI Passive Map", text);
			},
		});
		pi.registerCommand("re-auto", {
			description: "Run REPI bounded autopilot: /re-auto [plan|run] [--clean-state] [target] [max-auto-steps]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const action = parts[0] === "plan" || parts[0] === "run" ? (parts.shift() as "plan" | "run") : "run";
				const last = parts.at(-1);
				const maxAutoSteps = last && /^\d+$/.test(last) ? Number(parts.pop()) : undefined;
				const cleanState = parts.includes("--clean-state") || parts.includes("clean-state");
				for (let index = parts.length - 1; index >= 0; index -= 1) {
					if (parts[index] === "--clean-state" || parts[index] === "clean-state") parts.splice(index, 1);
				}
				const target = parts.join(" ") || undefined;
				const text = await runAutopilot(pi, { action, target, maxAutoSteps, cleanState });
				sendDisplayMessage(pi, "REPI Autopilot", text);
			},
		});
		pi.registerCommand("re-evidence", {
			description: "Show/search/append REPI evidence ledger: /re-evidence [show|search|append] ...",
			handler: async (args) => {
				const trimmed = args.trim();
				if (trimmed.startsWith("append ")) {
					const body = trimmed.slice("append ".length).trim();
					const [titlePart, factPart] = body.split("::", 2);
					const evidence = appendEvidence({
						kind: "note",
						title: titlePart?.trim() || "manual evidence",
						fact: factPart?.trim() || body || "manual evidence",
						confidence: "operator-note",
					});
					sendDisplayMessage(pi, "REPI Evidence Appended", `evidence: ${evidence.timestamp} ${evidence.title}`);
					return;
				}
				if (trimmed.startsWith("search ")) {
					sendDisplayMessage(pi, "REPI Evidence Search", buildEvidenceDigest(trimmed.slice("search ".length)));
					return;
				}
				sendDisplayMessage(pi, "REPI Evidence", buildEvidenceDigest());
			},
		});
		pi.registerCommand("re-graph", {
			description: "Build/show REPI mission attack graph: /re-graph [build|show]",
			handler: async (args) => {
				const action = args.trim() === "show" ? "show" : "build";
				sendDisplayMessage(pi, "REPI Attack Graph", buildAttackGraphOutput(action));
			},
		});
		pi.registerCommand("re-chain", {
			description: "Plan/show/compose REPI exploit chain: /re-chain [plan|show|compose] [target]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "show" || first === "compose" ? (parts.shift() as "show" | "compose") : "plan";
				if (first === "plan") parts.shift();
				const target = parts.join(" ") || undefined;
				sendDisplayMessage(pi, "REPI Exploit Chain", buildExploitChainOutput(action, { target }));
			},
		});
		pi.registerCommand("re-campaign", {
			description: "Build/show REPI reverse/pentest campaign graph: /re-campaign [plan|show] [target]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "show" ? "show" : "plan";
				if (first === "show" || first === "plan") parts.shift();
				const target = parts.join(" ") || undefined;
				sendDisplayMessage(pi, "REPI Campaign Graph", buildCampaignOutput(action, { target }));
			},
		});
		pi.registerCommand("re-operation", {
			description: "Build/show/run REPI operation queue: /re-operation [plan|next|show|run] [target] [max-steps]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action =
					first === "show" || first === "next" || first === "run"
						? (parts.shift() as "show" | "next" | "run")
						: "plan";
				const last = parts.at(-1);
				const maxSteps = last && /^\d+$/.test(last) ? Number(parts.pop()) : undefined;
				const target = parts.join(" ") || undefined;
				const text =
					action === "run"
						? await runOperationQueue(pi, { target, maxSteps })
						: buildOperationOutput(action, { target });
				sendDisplayMessage(pi, "REPI Operation Queue", text);
			},
		});
		pi.registerCommand("re-delegate", {
			description: "Build/show/merge REPI specialist worker packets: /re-delegate [plan|show|merge] [target]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "show" || first === "merge" ? (parts.shift() as "show" | "merge") : "plan";
				const target = parts.join(" ") || undefined;
				sendDisplayMessage(pi, "REPI Delegation Plan", buildDelegateOutput(action, { target }));
			},
		});
		pi.registerCommand("re-swarm", {
			description:
				"Build/show/run/merge REPI multi-specialist swarm runtime packets plus ReconParallelPlanV1/planCoverage/releaseCheckMetadata: /re-swarm [plan|show|run|merge] [target] [max-workers] [max-commands]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action =
					first === "show" || first === "run" || first === "merge"
						? (parts.shift() as "show" | "run" | "merge")
						: "plan";
				const maxCommands = action === "run" && /^\d+$/.test(parts.at(-1) ?? "") ? Number(parts.pop()) : undefined;
				const maxWorkers = action === "run" && /^\d+$/.test(parts.at(-1) ?? "") ? Number(parts.pop()) : undefined;
				const target = parts.join(" ") || undefined;
				const text =
					action === "run"
						? await runSwarm(pi, { target, maxWorkers, maxCommands })
						: buildSwarmOutput(action, { target });
				sendDisplayMessage(pi, "REPI Swarm Plan", text);
			},
		});
		pi.registerCommand("re-supervisor", {
			description:
				"Review/show/repair REPI worker packets with ReconParallelPlanV1, planCoverage, and claimCheckPolicy checkpoints: /re-supervisor [review|show|repair] [target]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "show" || first === "repair" ? (parts.shift() as "show" | "repair") : "review";
				const target = parts.join(" ") || undefined;
				sendDisplayMessage(pi, "REPI Supervisor Review", await buildSupervisorOutput(action, { target }));
			},
		});
		pi.registerCommand("re-operator", {
			description:
				"Plan/dispatch/verify/escalate REPI operator queue: /re-operator [plan|show|dispatch|verify|escalate] [target] [max-steps]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action =
					first === "show" || first === "dispatch" || first === "verify" || first === "escalate"
						? (parts.shift() as "show" | "dispatch" | "verify" | "escalate")
						: "plan";
				if (first === "plan") parts.shift();
				const last = parts.at(-1);
				const maxSteps = last && /^\d+$/.test(last) ? Number(parts.pop()) : undefined;
				const target = parts.join(" ") || undefined;
				const text =
					action === "dispatch"
						? await dispatchOperatorQueue(pi, { target, maxSteps })
						: buildOperatorOutput(action, { target });
				sendDisplayMessage(pi, "REPI Operator Queue", text);
			},
		});
		pi.registerCommand("re-verifier", {
			description: "Check/show/matrix REPI verifier matrix: /re-verifier [check|show|matrix] [target]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "show" || first === "matrix" ? (parts.shift() as "show" | "matrix") : "check";
				if (first === "check") parts.shift();
				const target = parts.join(" ") || undefined;
				sendDisplayMessage(pi, "REPI Verifier Matrix", buildVerifierOutput(action, { target }));
			},
		});
		pi.registerCommand("re-compiler", {
			description: "Draft/show/finalize REPI compiled report: /re-compiler [draft|show|final] [target]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "show" || first === "final" ? (parts.shift() as "show" | "final") : "draft";
				if (first === "draft") parts.shift();
				const target = parts.join(" ") || undefined;
				sendDisplayMessage(pi, "REPI Compiler Report", buildCompilerOutput(action, { target }));
			},
		});
		pi.registerCommand("re-replayer", {
			description: "Plan/show/run REPI replay matrix: /re-replayer [plan|show|run] [target] [max-steps]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "show" || first === "run" ? (parts.shift() as "show" | "run") : "plan";
				if (first === "plan") parts.shift();
				const last = parts.at(-1);
				const maxSteps = last && /^\d+$/.test(last) ? Number(parts.pop()) : undefined;
				const target = parts.join(" ") || undefined;
				const text =
					action === "run" ? await runReplayer(pi, { target, maxSteps }) : buildReplayerOutput(action, { target });
				sendDisplayMessage(pi, "REPI Replay Matrix", text);
			},
		});
		pi.registerCommand("re-autofix", {
			description:
				"Plan/show/queue REPI replay repairs (apply is deferred to operator dispatch): /re-autofix [plan|show|apply] [target]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "show" || first === "apply" ? (parts.shift() as "show" | "apply") : "plan";
				if (first === "plan") parts.shift();
				const target = parts.join(" ") || undefined;
				sendDisplayMessage(pi, "REPI Autofix Plan", buildAutofixOutput(action, { target }));
			},
		});
		pi.registerCommand("re-proof-loop", {
			description:
				"Plan/show/run REPI verifier→compiler→replayer→autofix proof loop with specialist swarm bridge: /re-proof-loop [plan|show|run] [target] [max-steps] [replay-steps]",
			handler: async (args) => {
				const parts = args.trim().split(/\s+/).filter(Boolean);
				const first = parts[0];
				const action = first === "show" || first === "run" ? (parts.shift() as "show" | "run") : "plan";
				if (first === "plan") parts.shift();
				const maybeReplaySteps = parts.at(-1);
				const replaySteps = maybeReplaySteps && /^\d+$/.test(maybeReplaySteps) ? Number(parts.pop()) : undefined;
				const maybeMaxSteps = parts.at(-1);
				const maxSteps = maybeMaxSteps && /^\d+$/.test(maybeMaxSteps) ? Number(parts.pop()) : undefined;
				const target = parts.join(" ") || undefined;
				const text =
					action === "run"
						? await runProofLoop(pi, { target, maxSteps, replaySteps })
						: buildProofLoopOutput(action, { target, maxSteps, replaySteps });
				sendDisplayMessage(pi, "REPI Proof Loop", text);
			},
		});
		pi.registerCommand("re-profile-check", {
			description: "Run/show REPI profile checks: /re-profile-check [quick|full|install|show]",
			handler: async (args) => {
				const action = args.trim().split(/\s+/).filter(Boolean)[0];
				const mode =
					action === "full" || action === "install" || action === "show" || action === "quick" ? action : "quick";
				sendDisplayMessage(pi, "REPI Profile Check", buildProfileCheckOutput(mode));
			},
		});
		pi.registerCommand("re-bootstrap", {
			description: "Plan or install missing REPI tools: /re-bootstrap [plan|install] tool1 tool2 ...",
			handler: async (args) => {
				const [action = "plan", ...tools] = args.trim().split(/\s+/).filter(Boolean);
				const targetTools = tools.length > 0 ? tools : ["checksec", "gdb", "radare2", "binwalk", "nmap", "ffuf"];
				const text =
					action === "install"
						? await installBootstrapTools(pi, targetTools)
						: formatBootstrapPlan(createBootstrapPlan(targetTools));
				sendDisplayMessage(pi, "REPI Bootstrap", text);
			},
		});
		pi.registerCommand("re-complete", {
			description: "Audit REPI completion checkpoints or write a report scaffold: /re-complete [audit|scaffold]",
			handler: async (args) => {
				const action = args.trim() || "audit";
				if (action.startsWith("scaffold")) {
					const title = action.slice("scaffold".length).trim() || undefined;
					const path = writeReportScaffold(title);
					sendDisplayMessage(pi, "REPI Report Scaffold", `${path}\n\n${formatCompletionAudit()}`);
					return;
				}
				const audit = runCompletionAudit();
				sendDisplayMessage(pi, "REPI Completion Audit", formatCompletionAuditFromAudit(audit));
			},
		});
		pi.registerCommand("re-self-review", {
			description: "Run REPI self-review checkpoint",
			handler: async () => {
				stats.selfReviewDue = false;
				sendDisplayMessage(pi, "REPI Self Review", makeSelfReview(stats));
			},
		});
	};
}
