import { join } from "node:path";
import type { ExtensionAPI } from "../extensions/types.ts";
import type { ArtifactScopeFilterOptions } from "./artifact-scope.ts";
import type { EvidenceRecord } from "./evidence.ts";
import type { AttackGraphArtifact } from "./graph.ts";
import {
	type MissionCheckpointStatus,
	type MissionLane,
	type MissionState,
	missionOperatorDirective,
} from "./mission.ts";
import { REPI_GENERIC_TASK, type RoutePlan } from "./routes.ts";
import type { LaneCommand } from "./specialist-command-planner.ts";
import { compactStoredArtifact, parseJsonCodeFence } from "./text.ts";

export type PassiveMapContext = {
	path: string;
	timestamp: string;
	target?: string;
	signals: string[];
	candidates: string[];
};

export type BootstrapPlan = {
	tool: string;
	present: boolean;
	path?: string;
	install?: string;
	verify?: string;
	known: boolean;
};

export type CampaignPhaseStatus = "ready" | "blocked" | "pending" | "done";

export type CampaignPhase = {
	name: string;
	objective: string;
	route: string;
	status: CampaignPhaseStatus;
	requiredEvidence: string[];
	candidateLanes: string[];
	nextActions: string[];
	toolGaps: string[];
	sourceArtifacts: string[];
};

export type CampaignArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	phases: CampaignPhase[];
	pivots: string[];
	gaps: string[];
	toolGaps: string[];
	nextActions: string[];
	nextBootstrapCommand: string;
	sourceArtifacts: string[];
};

export type OperationStepStatus = "ready" | "done" | "blocked" | "skipped";

export type OperationStep = {
	id: string;
	phase: string;
	command: string;
	status: OperationStepStatus;
	reason?: string;
	sourceArtifacts: string[];
};

export type OperationExecution = {
	stepId: string;
	command: string;
	status: OperationStepStatus;
	output: string;
};

export type OperationArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	campaignArtifact?: string;
	mode: "plan" | "run";
	steps: OperationStep[];
	executed: OperationExecution[];
	blocked: string[];
	nextActions: string[];
	sourceArtifacts: string[];
};

export type OperationLaneCommandPack = {
	missionId?: string;
	lane: string;
	route: string;
	target?: string;
	commands: LaneCommand[];
	notes: string[];
};

export type CampaignOptions = { target?: string; task?: string };
export type OperationOptions = CampaignOptions & { mode?: "plan" | "run" };
export type OperationRunOptions = CampaignOptions & { maxSteps?: number };

type TargetTimeoutOptions = { target?: string; timeoutMs?: number };
type MobileRuntimeOptions = TargetTimeoutOptions & { packageName?: string };
type ExploitLabOptions = TargetTimeoutOptions & { runs?: number };
type ReplayerOptions = TargetTimeoutOptions & { maxSteps?: number };
type ProofLoopOptions = TargetTimeoutOptions & { maxSteps?: number; replaySteps?: number };

type AppendEvidence = (
	record: Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number },
) => EvidenceRecord;

export type CampaignOperationRuntimeDependencies = {
	ensureReconStorage: () => void;
	readCurrentMission: () => MissionState | undefined;
	writeCurrentMission: (mission: MissionState) => MissionState;
	createMission: (task: string, route: RoutePlan) => MissionState;
	routeReconTask: (task: string) => RoutePlan;
	latestPassiveMapContext: () => PassiveMapContext | undefined;
	inferTargetFromMap: (map: PassiveMapContext | undefined, mission: MissionState) => string | undefined;
	buildAttackGraph: () => AttackGraphArtifact;
	writeAttackGraphArtifact: (graph: AttackGraphArtifact) => string;
	recommendedToolsForRoute: (route: RoutePlan) => string[];
	createBootstrapPlan: (tools: string[]) => BootstrapPlan[];
	formatBootstrapPlan: (plan: BootstrapPlan[]) => string;
	recentMarkdownArtifacts: (dir: string, limit: number) => string[];
	evidenceRunsDir: () => string;
	evidenceGraphsDir: () => string;
	evidenceCampaignsDir: () => string;
	evidenceOperationsDir: () => string;
	latestScopedMarkdownArtifact: (
		kind: string,
		dir: string,
		options?: ArtifactScopeFilterOptions,
	) => string | undefined;
	readText: (path: string, fallback?: string) => string;
	writePrivateTextFile: (path: string, content: string) => void;
	appendEvidence: AppendEvidence;
	updateMissionCheckpoint: (name: string, status: MissionCheckpointStatus, note?: string) => unknown;
	slug: (value: string) => string;
	truncateMiddle: (value: string, limit: number) => string;

	activeLane: (mission: MissionState, name?: string) => MissionLane | undefined;
	laneCommandPack: (mission: MissionState, lane: MissionLane, target?: string) => OperationLaneCommandPack;
	formatLaneCommandPack: (pack: OperationLaneCommandPack) => string;
	runLaneCommandPack: (pi: ExtensionAPI, pack: OperationLaneCommandPack) => Promise<string>;
	runAutoLaneChain: (
		pi: ExtensionAPI,
		options: { lane?: string; target?: string; maxSteps?: number },
	) => Promise<string>;
	runPassiveMap: (pi: ExtensionAPI, options: { target?: string; depth?: number }) => Promise<string>;

	runDecisionCore: (pi: ExtensionAPI, options: { target?: string; maxSteps?: number }) => Promise<string>;
	buildDecisionCoreOutput: (action: "plan" | "show" | "tick", options: { target?: string }) => string;
	buildKernelOutput: (action: "build" | "show" | "audit", options: { target?: string }) => string;
	runLiveBrowser: (pi: ExtensionAPI, options?: TargetTimeoutOptions) => Promise<string>;
	buildLiveBrowserOutput: (action: "plan" | "show", options: TargetTimeoutOptions) => string;
	runWebAuthzState: (pi: ExtensionAPI, options?: TargetTimeoutOptions) => Promise<string>;
	buildWebAuthzStateOutput: (action: "plan" | "show", options: TargetTimeoutOptions) => string;
	runMobileRuntime: (pi: ExtensionAPI, options?: MobileRuntimeOptions) => Promise<string>;
	buildMobileRuntimeOutput: (action: "plan" | "show", options: MobileRuntimeOptions) => string;
	runNativeRuntime: (pi: ExtensionAPI, options?: TargetTimeoutOptions) => Promise<string>;
	buildNativeRuntimeOutput: (action: "plan" | "show", options: TargetTimeoutOptions) => string;
	runExploitLab: (pi: ExtensionAPI, options?: ExploitLabOptions) => Promise<string>;
	buildExploitLabOutput: (action: "plan" | "show" | "bundle", options: ExploitLabOptions) => string;
	refreshToolIndex: (pi: ExtensionAPI) => Promise<string>;
	buildAttackGraphOutput: (action: "build" | "show") => string;
	buildExploitChainOutput: (action: "plan" | "show" | "compose", options: { target?: string }) => string;
	buildVerifierOutput: (action: "check" | "show" | "matrix", options: { target?: string }) => string;
	buildCompilerOutput: (action: "draft" | "show" | "final", options: { target?: string }) => string;
	runReplayer: (pi: ExtensionAPI, options?: ReplayerOptions) => Promise<string>;
	buildReplayerOutput: (action: "plan" | "show", options: { target?: string }) => string;
	buildAutofixOutput: (action: "plan" | "show" | "apply", options: { target?: string }) => string;
	runProofLoop: (pi: ExtensionAPI, options?: ProofLoopOptions) => Promise<string>;
	buildProofLoopOutput: (action: "plan" | "show" | "run", options: ProofLoopOptions) => string;
	formatCompletionAudit: () => string;
	writeReportScaffold: () => string;
};

function textHasAny(text: string, patterns: RegExp[]): boolean {
	return patterns.some((pattern) => pattern.test(text));
}

function matchingLaneNames(mission: MissionState | undefined, patterns: RegExp[]): string[] {
	if (!mission) return [];
	return mission.lanes
		.filter((lane) =>
			patterns.some((pattern) => pattern.test(`${lane.name}\n${lane.objective}\n${lane.next.join("\n")}`)),
		)
		.map((lane) => lane.name);
}

function phaseDoneFromLanes(mission: MissionState | undefined, lanes: string[]): boolean {
	if (!mission || lanes.length === 0) return false;
	return lanes.every((name) => mission.lanes.find((lane) => lane.name === name)?.status === "done");
}

export function buildCampaignPhases(
	mission: MissionState | undefined,
	map: PassiveMapContext | undefined,
	target: string | undefined,
	toolGaps: string[],
	sourceArtifacts: string[],
): CampaignPhase[] {
	const taskText = [
		missionOperatorDirective(mission),
		mission?.route.domain,
		target,
		map?.target,
		...(map?.signals ?? []),
	].join("\n");
	const targetRef = target ?? map?.target ?? "<target>";
	const makePhase = (
		name: string,
		objective: string,
		route: string,
		relevant: boolean,
		requiredEvidence: string[],
		lanePatterns: RegExp[],
		nextActions: string[],
		phaseToolGaps: string[] = toolGaps,
	): CampaignPhase | undefined => {
		if (!mission && name !== "recon-map") return undefined;
		if (!relevant && name !== "report-audit") return undefined;
		const candidateLanes = matchingLaneNames(mission, lanePatterns);
		const status: CampaignPhaseStatus = !mission
			? "blocked"
			: name === "recon-map" && map
				? "done"
				: phaseDoneFromLanes(mission, candidateLanes)
					? "done"
					: relevant
						? "ready"
						: "pending";
		return {
			name,
			objective,
			route,
			status,
			requiredEvidence,
			candidateLanes,
			nextActions,
			toolGaps: phaseToolGaps.slice(0, 10),
			sourceArtifacts: sourceArtifacts.slice(0, 10),
		};
	};
	return [
		makePhase(
			"recon-map",
			"建立目标/工作区被动地图，确认入口、配置、路由、二进制/样本/云身份与证据面",
			mission?.route.domain ?? "Security routing",
			true,
			["passive map artifact", "tool index", "target fingerprint"],
			[/map|surface|triage|inventory|identity/i],
			[`re_decision_core tick ${targetRef}`, `re_map ${targetRef} 3`, "re_tool_index refresh", "re_graph build"],
		),
		makePhase(
			"web-authz",
			"把 Web/API/GraphQL/WebSocket 的认证、授权、对象所有权和状态转换证明成可 replay 的最小路径",
			"Web / API pentest",
			mission?.route.domain === "Web / API pentest" ||
				textHasAny(taskText, [/\bapi\b|websocket|graphql|jwt|oauth|idor|bola|session|cookie|csrf/i]),
			["browser/XHR/WS capture", "auth matrix", "IDOR/BOLA or authz-state evidence", "replay command"],
			[/surface|state|poc|auth|web|api/i],
			[
				`re_live_browser plan ${targetRef}`,
				`re_web_authz_state plan ${targetRef}`,
				`re_lane plan surface ${targetRef}`,
				`re_lane run surface ${targetRef}`,
				`re_lane plan state ${targetRef}`,
				`re_web_authz_state run ${targetRef} 9000`,
				"re_graph build",
			],
		),
		makePhase(
			"credential-identity",
			"验证 cookie/JWT/API key/ticket/hash/serviceaccount 的可用性、作用域、过期和可转移边界",
			"Identity / credentials",
			mission?.route.domain === "Identity / Windows / AD" ||
				textHasAny(taskText, [
					/credential|凭据|token|jwt|cookie|kerberos|ntlm|ldap|spn|ticket|hash|serviceaccount/i,
				]),
			["credential inventory", "usable credential proof", "principal/scope evidence", "negative control"],
			[/credential|principal|identity|state|metadata/i],
			[
				`re_lane plan credentials ${targetRef}`,
				`re_lane run credentials ${targetRef}`,
				`re_lane plan principals ${targetRef}`,
			],
		),
		makePhase(
			"cloud-container",
			"从运行配置、serviceaccount、metadata、IAM/RBAC 到最小 privilege edge 组织云/容器 pivot",
			"Cloud / container",
			mission?.route.domain === "Cloud / container" ||
				textHasAny(taskText, [
					/cloud|aws|azure|gcp|metadata|k8s|kubernetes|docker|container|rbac|iam|serviceaccount/i,
				]),
			["runtime config", "cloud identity", "metadata probe", "privilege edge"],
			[/identity|runtime-config|metadata|privilege|cloud|container/i],
			[
				`re_lane plan identity ${targetRef}`,
				`re_lane run identity ${targetRef}`,
				`re_lane plan privilege ${targetRef}`,
			],
		),
		makePhase(
			"pwn-exploit",
			"把二进制/服务崩溃面推进到 primitive、leak、payload、稳定性和本地/远程一致性验证",
			"Pwn / exploit",
			mission?.route.domain === "Pwn / exploit" ||
				mission?.route.domain === "Exploit reliability" ||
				textHasAny(taskText, [/pwn|exploit|rop|heap|ret2libc|crash|primitive|autopwn|poc/i]),
			["mitigation fingerprint", "crash/control primitive", "offset/leak", "local verifier or replay matrix"],
			[/mitigation|primitive|exploit|replay|inventory|normalize|flake|bundle/i],
			[
				`re_lane plan primitive ${targetRef}`,
				`re_lane run primitive ${targetRef}`,
				`re_lane plan replay ${targetRef}`,
			],
		),
		makePhase(
			"agentsec-boundary",
			"映射 prompt/tool/memory/RAG/MCP/sub-agent 边界并生成注入 replay harness 与隔离证据",
			"Agent / LLM boundary",
			mission?.route.domain === "Agent / LLM boundary" ||
				textHasAny(taskText, [/agent|llm|prompt injection|tool boundary|memory poisoning|mcp|rag|delegation/i]),
			["prompt surface", "tool schema/exec boundary", "memory poisoning path", "injection replay transcript"],
			[/surface|tool-boundary|memory|injection|delegation/i],
			[
				`re_lane plan surface ${targetRef}`,
				`re_lane run surface ${targetRef}`,
				`re_lane plan injection ${targetRef}`,
			],
		),
		makePhase(
			"firmware-pcap-dfir",
			"串联固件/rootfs、PCAP/DFIR、恶意样本 IOC/config 与 transform chain 的证据链",
			"Firmware / PCAP / DFIR / Malware",
			mission?.route.domain === "Firmware / IoT" ||
				mission?.route.domain === "DFIR / PCAP / stego" ||
				mission?.route.domain === "Malware analysis" ||
				textHasAny(taskText, [/firmware|iot|rootfs|pcap|dfir|forensic|malware|ioc|yara|c2|binwalk|tshark/i]),
			[
				"image/pcap/sample fingerprint",
				"extracted artifact",
				"config/IOC or flow timeline",
				"transform/decode chain",
			],
			[/inventory|extract|filesystem|services|emulate|map|timeline|triage|static-config|behavior|decode/i],
			[`re_lane plan inventory ${targetRef}`, `re_lane run inventory ${targetRef}`, `re_lane plan map ${targetRef}`],
		),
		makePhase(
			"report-audit",
			"收敛 campaign 证据、attack graph、复现命令、风险/影响、失败路线和下一步",
			mission?.route.domain ?? "Security reporting",
			true,
			["attack graph", "campaign artifact", "evidence ledger", "completion audit", "report scaffold"],
			[/report|bundle|writeup/i],
			["re_decision_core tick", "re_graph build", "re_campaign show", "re_complete scaffold"],
			[],
		),
	].filter((phase): phase is CampaignPhase => Boolean(phase));
}

export function campaignPivotCandidates(
	mission: MissionState | undefined,
	phases: CampaignPhase[],
	map: PassiveMapContext | undefined,
): string[] {
	const text = [
		missionOperatorDirective(mission),
		mission?.route.domain,
		map?.signals.join("\n"),
		phases.map((phase) => phase.name).join(" "),
	].join("\n");
	const pivots: string[] = [];
	if (textHasAny(text, [/jwt|cookie|session|oauth|api key|token/i]))
		pivots.push(
			"web-authz → credential-identity: reuse token/cookie/API key only after scope and negative-control proof",
		);
	if (textHasAny(text, [/websocket|ws\b|graphql|api/i]))
		pivots.push(
			"web-authz → replay/state machine: capture request order, WS frames, storage and auth matrix before PoC expansion",
		);
	if (textHasAny(text, [/cloud|k8s|metadata|serviceaccount|iam|rbac/i]))
		pivots.push(
			"credential-identity → cloud-container: test serviceaccount/metadata/IAM/RBAC as a minimal privilege edge",
		);
	if (textHasAny(text, [/pwn|exploit|binary|elf|rop|crash/i]))
		pivots.push("pwn-exploit → exploit reliability: convert primitive into replay matrix and artifact bundle");
	if (textHasAny(text, [/firmware|pcap|malware|ioc|dfir/i]))
		pivots.push(
			"firmware-pcap-dfir → credential-identity: extract secrets/IOCs/flows and verify usability separately",
		);
	if (textHasAny(text, [/agent|prompt|mcp|memory|tool/i]))
		pivots.push(
			"agentsec-boundary → evidence ledger: separate untrusted content injection from trusted tool outputs",
		);
	if (pivots.length === 0) pivots.push("recon-map → active lane: prove one end-to-end path before lateral expansion");
	return Array.from(new Set(pivots)).slice(0, 12);
}

export function campaignEvidenceGaps(
	mission: MissionState | undefined,
	map: PassiveMapContext | undefined,
	graph: AttackGraphArtifact,
	phases: CampaignPhase[],
	recentRunArtifacts: string[] = [],
): string[] {
	const gaps: string[] = [];
	if (!mission) gaps.push("no active mission");
	if (!map) gaps.push("no passive map artifact");
	if (recentRunArtifacts.length === 0) gaps.push("no recent lane run artifact");
	for (const phase of phases) {
		if (phase.status === "ready")
			gaps.push(`phase ready but unproven: ${phase.name} requires ${phase.requiredEvidence.join(", ")}`);
		if (phase.status === "blocked") gaps.push(`phase blocked: ${phase.name}`);
	}
	for (const gap of graph.gaps) gaps.push(`attack_graph: ${gap}`);
	return Array.from(new Set(gaps)).slice(0, 28);
}

export function operationCommandConcrete(command: string, target?: string): { command: string; blocked?: string } {
	const targetText = target?.trim();
	if (/<target>|<TARGET>|<URL>|<none>/i.test(command)) {
		if (!targetText) return { command, blocked: "target placeholder is unresolved" };
		return { command: command.replace(/<target>|<TARGET>|<URL>|<none>/gi, targetText) };
	}
	return { command };
}

export function formatCampaign(campaign: CampaignArtifact, path?: string): string {
	return [
		"campaign_graph:",
		path ? `campaign_artifact: ${path}` : undefined,
		`timestamp: ${campaign.timestamp}`,
		`mission_id: ${campaign.missionId ?? "none"}`,
		`route: ${campaign.route ?? "none"}`,
		`target: ${campaign.target ?? "<none>"}`,
		"phases:",
		...campaign.phases.flatMap((phase) => [
			`- ${phase.name} [${phase.status}] route=${phase.route}`,
			`  objective: ${phase.objective}`,
			`  candidate_lanes: ${phase.candidateLanes.length ? phase.candidateLanes.join(", ") : "none"}`,
			`  required_evidence: ${phase.requiredEvidence.join(", ")}`,
			`  next_actions: ${phase.nextActions.join(" | ")}`,
			`  tool_gaps: ${phase.toolGaps.length ? phase.toolGaps.join(", ") : "none"}`,
		]),
		"pivot_candidates:",
		...(campaign.pivots.length ? campaign.pivots.map((item) => `- ${item}`) : ["- none"]),
		"evidence_gaps:",
		...(campaign.gaps.length ? campaign.gaps.map((item) => `- ${item}`) : ["- none"]),
		"tool_gaps:",
		...(campaign.toolGaps.length ? campaign.toolGaps.map((item) => `- ${item}`) : ["- none"]),
		"operator_next_actions:",
		...(campaign.nextActions.length ? campaign.nextActions.map((item) => `- ${item}`) : ["- none"]),
		`next_bootstrap_command: ${campaign.nextBootstrapCommand}`,
		"source_artifacts:",
		...(campaign.sourceArtifacts.length ? campaign.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
	]
		.filter(Boolean)
		.join("\n");
}

export function formatOperation(
	operation: OperationArtifact,
	path: string | undefined,
	truncateMiddle: (value: string, limit: number) => string,
): string {
	return [
		"operation_queue:",
		path ? `operation_artifact: ${path}` : undefined,
		`timestamp: ${operation.timestamp}`,
		`mode: ${operation.mode}`,
		`mission_id: ${operation.missionId ?? "none"}`,
		`route: ${operation.route ?? "none"}`,
		`target: ${operation.target ?? "<none>"}`,
		`campaign_artifact: ${operation.campaignArtifact ?? "none"}`,
		"phase_runner:",
		"- internal_dispatch: re_kernel | re_decision_core plan/tick/run | re_map | re_live_browser plan/run | re_web_authz_state plan/run | re_tool_index refresh | re_lane plan/run/run-auto | re_graph build | re_chain plan/compose | re_campaign plan/show | re_bootstrap plan | re_verifier/re_compiler/re_replayer/re_autofix/re_proof_loop | re_complete audit/scaffold",
		"steps:",
		...(operation.steps.length
			? operation.steps.map(
					(step) =>
						`- ${step.id} [${step.status}] phase=${step.phase} command=${step.command}${step.reason ? ` reason=${step.reason}` : ""}`,
				)
			: ["- none"]),
		`executed_steps: ${operation.executed.length}`,
		...(operation.executed.length
			? operation.executed.map(
					(item) =>
						`- ${item.stepId} [${item.status}] ${item.command} :: ${truncateMiddle(item.output.replace(/\s+/g, " "), 260)}`,
				)
			: []),
		"blocked:",
		...(operation.blocked.length ? operation.blocked.map((item) => `- ${item}`) : ["- none"]),
		"operator_next_actions:",
		...(operation.nextActions.length ? operation.nextActions.map((item) => `- ${item}`) : ["- none"]),
		`next_operation_command: re_operation run ${operation.target ?? "<target>"} 1`,
		"source_artifacts:",
		...(operation.sourceArtifacts.length ? operation.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
	]
		.filter(Boolean)
		.join("\n");
}

export function createCampaignOperationRuntime(dependencies: CampaignOperationRuntimeDependencies) {
	const {
		ensureReconStorage,
		readCurrentMission,
		writeCurrentMission,
		createMission,
		routeReconTask,
		latestPassiveMapContext,
		inferTargetFromMap,
		buildAttackGraph,
		writeAttackGraphArtifact,
		recommendedToolsForRoute,
		createBootstrapPlan,
		formatBootstrapPlan,
		recentMarkdownArtifacts,
		evidenceRunsDir,
		evidenceGraphsDir,
		evidenceCampaignsDir,
		evidenceOperationsDir,
		latestScopedMarkdownArtifact,
		readText,
		writePrivateTextFile,
		appendEvidence,
		updateMissionCheckpoint,
		slug,
		truncateMiddle,
		activeLane,
		laneCommandPack,
		formatLaneCommandPack,
		runLaneCommandPack,
		runAutoLaneChain,
		runPassiveMap,
		runDecisionCore,
		buildDecisionCoreOutput,
		buildKernelOutput,
		runLiveBrowser,
		buildLiveBrowserOutput,
		runWebAuthzState,
		buildWebAuthzStateOutput,
		runMobileRuntime,
		buildMobileRuntimeOutput,
		runNativeRuntime,
		buildNativeRuntimeOutput,
		runExploitLab,
		buildExploitLabOutput,
		refreshToolIndex,
		buildAttackGraphOutput,
		buildExploitChainOutput,
		buildVerifierOutput,
		buildCompilerOutput,
		runReplayer,
		buildReplayerOutput,
		buildAutofixOutput,
		runProofLoop,
		buildProofLoopOutput,
		formatCompletionAudit,
		writeReportScaffold,
	} = dependencies;

	function latestCampaignArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		return latestScopedMarkdownArtifact("campaign", evidenceCampaignsDir(), options);
	}

	function buildCampaign(options: CampaignOptions = {}): CampaignArtifact {
		ensureReconStorage();
		let mission = readCurrentMission();
		if (!mission && options.task?.trim()) {
			mission = writeCurrentMission(createMission(options.task.trim(), routeReconTask(options.task.trim())));
		}
		const map = latestPassiveMapContext();
		const target = options.target?.trim() || (mission ? inferTargetFromMap(map, mission) : undefined) || map?.target;
		const graph = buildAttackGraph();
		const graphWriteResult = writeAttackGraphArtifact(graph);
		const [graphPath] = graphWriteResult.split(/\r?\n/, 1);
		mission = readCurrentMission() ?? mission;
		const recommended = mission ? recommendedToolsForRoute(mission.route).slice(0, 24) : ["rg", "python3", "curl"];
		const missing = recommended
			.map((tool) => createBootstrapPlan([tool])[0])
			.filter((item): item is BootstrapPlan => Boolean(item) && item.known && !item.present)
			.map((item) => item.tool);
		const sourceArtifacts = Array.from(
			new Set(
				[
					map?.path,
					graphPath,
					...recentMarkdownArtifacts(evidenceRunsDir(), 8),
					...recentMarkdownArtifacts(evidenceGraphsDir(), 2),
				].filter((item): item is string => Boolean(item)),
			),
		).slice(0, 24);
		const phases = buildCampaignPhases(mission, map, target, missing, sourceArtifacts);
		const pivots = campaignPivotCandidates(mission, phases, map);
		const gaps = campaignEvidenceGaps(mission, map, graph, phases, recentMarkdownArtifacts(evidenceRunsDir(), 3));
		const targetRef = target ?? "<target>";
		const nextActions = Array.from(
			new Set(
				[
					!map ? `re_map ${targetRef} 3` : undefined,
					"re_graph build",
					...phases.flatMap((phase) => phase.nextActions).slice(0, 10),
					missing.length ? `re_bootstrap plan ${missing.slice(0, 10).join(" ")}` : undefined,
				].filter((item): item is string => Boolean(item)),
			),
		).slice(0, 16);
		return {
			timestamp: new Date().toISOString(),
			missionId: mission?.id,
			route: mission?.route.domain,
			target,
			phases,
			pivots,
			gaps,
			toolGaps: Array.from(new Set(missing)).slice(0, 16),
			nextActions,
			nextBootstrapCommand: missing.length ? `re_bootstrap plan ${missing.slice(0, 12).join(" ")}` : "none",
			sourceArtifacts,
		};
	}

	function writeCampaignArtifact(campaign: CampaignArtifact): string {
		ensureReconStorage();
		const path = join(
			evidenceCampaignsDir(),
			`${campaign.timestamp.replace(/[:.]/g, "-")}-${slug(campaign.route ?? "campaign")}.md`,
		);
		writePrivateTextFile(
			path,
			[
				"# REPI Campaign Artifact",
				"",
				formatCampaign(campaign, path),
				"",
				"## Phases",
				"",
				...campaign.phases.map(
					(phase) =>
						`- ${phase.name} status=${phase.status} route=${phase.route} lanes=${phase.candidateLanes.join(",") || "none"} evidence=${phase.requiredEvidence.join(";")}`,
				),
				"",
				"## Pivots",
				"",
				...campaign.pivots.map((item) => `- ${item}`),
				"",
				"## JSON",
				"",
				"```json",
				JSON.stringify(campaign, null, 2),
				"```",
				"",
			].join("\n"),
		);
		appendEvidence({
			kind: "artifact",
			title: `campaign-plan ${campaign.missionId ?? "no-mission"}`,
			fact: `Built campaign graph with ${campaign.phases.length} phase(s), ${campaign.pivots.length} pivot(s), ${campaign.gaps.length} evidence gap(s), ${campaign.toolGaps.length} tool gap(s)`,
			command: "re_campaign plan",
			path,
			verify: `cat ${path}`,
			confidence: "mission/map/run/evidence/attack-graph campaign",
		});
		updateMissionCheckpoint("campaign_plan_ready", "done", path);
		return path;
	}

	function buildCampaignOutput(action: "plan" | "show" = "plan", options: CampaignOptions = {}): string {
		if (action === "show") {
			const path = latestCampaignArtifactPath();
			if (!path) return "campaign_graph:\nstatus: missing\nnext: re_campaign plan";
			return compactStoredArtifact("campaign_graph", path, readText(path));
		}
		const campaign = buildCampaign(options);
		const path = writeCampaignArtifact(campaign);
		return formatCampaign(campaign, path);
	}

	function latestOperationArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		return latestScopedMarkdownArtifact("operation", evidenceOperationsDir(), options);
	}

	function parseCampaignArtifact(path: string): CampaignArtifact | undefined {
		return parseJsonCodeFence<CampaignArtifact>(readText(path));
	}

	function latestOrBuildCampaign(options: CampaignOptions = {}): { campaign: CampaignArtifact; path: string } {
		const latest = !options.target && !options.task ? latestCampaignArtifactPath() : undefined;
		if (latest) {
			const campaign = parseCampaignArtifact(latest);
			const missionId = readCurrentMission()?.id;
			// A campaign is mission-scoped state. Reusing an artifact from a
			// previous mission silently carries its phases and target forward.
			if (campaign && missionId && campaign.missionId === missionId) return { campaign, path: latest };
		}
		const campaign = buildCampaign(options);
		const path = writeCampaignArtifact(campaign);
		return { campaign, path };
	}

	function buildOperation(options: OperationOptions = {}): OperationArtifact {
		ensureReconStorage();
		const { campaign, path: campaignArtifact } = latestOrBuildCampaign(options);
		const seen = new Set<string>();
		const steps: OperationStep[] = [];
		const addStep = (phase: CampaignPhase, command: string) => {
			const normalized = command.trim();
			if (!normalized || seen.has(`${phase.name}:${normalized}`)) return;
			seen.add(`${phase.name}:${normalized}`);
			const concrete = operationCommandConcrete(normalized, options.target ?? campaign.target);
			steps.push({
				id: `op:${steps.length + 1}:${slug(phase.name)}`,
				phase: phase.name,
				command: concrete.command,
				status: phase.status === "done" ? "done" : concrete.blocked ? "blocked" : "ready",
				reason: concrete.blocked ?? (phase.status === "done" ? "campaign phase already done" : undefined),
				sourceArtifacts: phase.sourceArtifacts,
			});
		};
		for (const phase of campaign.phases) {
			for (const command of phase.nextActions) addStep(phase, command);
		}
		const blocked = steps
			.filter((step) => step.status === "blocked")
			.map((step) => `${step.id} ${step.command}${step.reason ? ` — ${step.reason}` : ""}`);
		const nextActions = steps
			.filter((step) => step.status === "ready")
			.slice(0, 10)
			.map((step) => `re_operation run ${campaign.target ?? options.target ?? "<target>"} 1 # ${step.id}`);
		return {
			timestamp: new Date().toISOString(),
			missionId: campaign.missionId,
			route: campaign.route,
			target: options.target ?? campaign.target,
			campaignArtifact,
			mode: options.mode ?? "plan",
			steps,
			executed: [],
			blocked,
			nextActions,
			sourceArtifacts: Array.from(new Set([campaignArtifact, ...campaign.sourceArtifacts])).slice(0, 28),
		};
	}

	function writeOperationArtifact(operation: OperationArtifact): string {
		ensureReconStorage();
		const path = join(
			evidenceOperationsDir(),
			`${operation.timestamp.replace(/[:.]/g, "-")}-${slug(operation.route ?? "operation")}-${operation.mode}.md`,
		);
		writePrivateTextFile(
			path,
			[
				"# REPI Operation Artifact",
				"",
				formatOperation(operation, path, truncateMiddle),
				"",
				"## Executed",
				"",
				...(operation.executed.length
					? operation.executed.map((item) => `- ${item.stepId} status=${item.status} command=${item.command}`)
					: ["- none"]),
				"",
				"## JSON",
				"",
				"```json",
				JSON.stringify(operation, null, 2),
				"```",
				"",
			].join("\n"),
		);
		appendEvidence({
			kind: "artifact",
			title: `operation-${operation.mode} ${operation.missionId ?? "no-mission"}`,
			fact: `Built operation queue with ${operation.steps.length} step(s), ${operation.executed.length} executed, ${operation.blocked.length} blocked`,
			command: `re_operation ${operation.mode}`,
			path,
			verify: `cat ${path}`,
			confidence: "campaign/phase-runner operation queue",
		});
		updateMissionCheckpoint("operation_queue_ready", "done", path);
		return path;
	}

	async function executeOperationStep(
		pi: ExtensionAPI,
		step: OperationStep,
		target?: string,
	): Promise<OperationExecution> {
		const command = step.command.trim();
		const done = (output: string): OperationExecution => ({ stepId: step.id, command, status: "done", output });
		const blocked = (output: string): OperationExecution => ({ stepId: step.id, command, status: "blocked", output });
		if (/<target>|<TARGET>|<URL>|<none>/i.test(command)) return blocked("unresolved target placeholder");
		const decisionMatch = /^re[-_]decision[-_]core\s+(plan|tick|run)\b(?:\s+(.+?))?(?:\s+(\d+))?$/i.exec(command);
		if (decisionMatch) {
			const action = decisionMatch[1] as "plan" | "tick" | "run";
			const decisionTarget = decisionMatch[2]?.trim() || target;
			const maxSteps = decisionMatch[3] ? Number(decisionMatch[3]) : 1;
			return done(
				action === "run"
					? await runDecisionCore(pi, { target: decisionTarget, maxSteps })
					: buildDecisionCoreOutput(action, { target: decisionTarget }),
			);
		}
		const laneMatch = /^re_lane\s+(plan|run|run-auto)\s+(\S+)(?:\s+(.+))?$/i.exec(command);
		if (laneMatch) {
			const action = laneMatch[1] as "plan" | "run" | "run-auto";
			const laneName = laneMatch[2];
			const laneTarget = laneMatch[3]?.trim() || target;
			if (action === "run-auto")
				return done(await runAutoLaneChain(pi, { lane: laneName, target: laneTarget, maxSteps: 1 }));
			const mission =
				readCurrentMission() ??
				writeCurrentMission(createMission("manual mission", routeReconTask(REPI_GENERIC_TASK)));
			const lane = activeLane(mission, laneName);
			if (!lane) return blocked(`lane not found: ${laneName}`);
			updateMissionCheckpoint("repro_commands_ready", "done", `operation:${step.id}:${lane.name}`);
			const pack = laneCommandPack(mission, lane, laneTarget);
			if (action === "plan") return done(formatLaneCommandPack(pack));
			return done(await runLaneCommandPack(pi, pack));
		}
		if (/^re_map\b/i.test(command)) {
			const parts = command.split(/\s+/).slice(1);
			const last = parts.at(-1);
			const depth = last && /^\d+$/.test(last) ? Number(parts.pop()) : undefined;
			const mapTarget = parts.join(" ") || target;
			return done(await runPassiveMap(pi, { target: mapTarget, depth }));
		}
		const kernelMatch = /^re[-_]kernel(?:\s+(build|show|audit))?(?:\s+(.+))?$/i.exec(command);
		if (kernelMatch)
			return done(
				buildKernelOutput((kernelMatch[1] as "build" | "show" | "audit") ?? "build", {
					target: kernelMatch[2]?.trim() || target,
				}),
			);
		const liveBrowserMatch = /^re[-_]live[-_]browser\s+(plan|show|run)?(?:\s+(.+?))?(?:\s+(\d+))?$/i.exec(command);
		if (liveBrowserMatch) {
			const action = (liveBrowserMatch[1] as "plan" | "show" | "run") ?? "plan";
			const browserTarget = liveBrowserMatch[2]?.trim() || target;
			const timeoutMs = liveBrowserMatch[3] ? Number(liveBrowserMatch[3]) : undefined;
			return done(
				action === "run"
					? await runLiveBrowser(pi, { target: browserTarget, timeoutMs })
					: buildLiveBrowserOutput(action, { target: browserTarget, timeoutMs }),
			);
		}
		const webAuthzStateMatch = /^re[-_]web[-_]authz[-_]state\s+(plan|show|run)?(?:\s+(.+?))?(?:\s+(\d+))?$/i.exec(
			command,
		);
		if (webAuthzStateMatch) {
			const action = (webAuthzStateMatch[1] as "plan" | "show" | "run") ?? "plan";
			const authzTarget = webAuthzStateMatch[2]?.trim() || target;
			const timeoutMs = webAuthzStateMatch[3] ? Number(webAuthzStateMatch[3]) : undefined;
			return done(
				action === "run"
					? await runWebAuthzState(pi, { target: authzTarget, timeoutMs })
					: buildWebAuthzStateOutput(action, { target: authzTarget, timeoutMs }),
			);
		}
		const mobileRuntimeMatch =
			/^re[-_]mobile[-_]runtime\s+(plan|show|run)?(?:\s+(.+?))?(?:\s+([A-Za-z][\w]*(?:\.[A-Za-z][\w]*){1,}))?(?:\s+(\d+))?$/i.exec(
				command,
			);
		if (mobileRuntimeMatch) {
			const action = (mobileRuntimeMatch[1] as "plan" | "show" | "run") ?? "plan";
			const mobileTarget = mobileRuntimeMatch[2]?.trim() || target;
			const packageName = mobileRuntimeMatch[3]?.trim();
			const timeoutMs = mobileRuntimeMatch[4] ? Number(mobileRuntimeMatch[4]) : undefined;
			return done(
				action === "run"
					? await runMobileRuntime(pi, { target: mobileTarget, packageName, timeoutMs })
					: buildMobileRuntimeOutput(action, { target: mobileTarget, packageName, timeoutMs }),
			);
		}
		const nativeRuntimeMatch = /^re[-_]native[-_]runtime\s+(plan|show|run)?(?:\s+(.+?))?(?:\s+(\d+))?$/i.exec(
			command,
		);
		if (nativeRuntimeMatch) {
			const action = (nativeRuntimeMatch[1] as "plan" | "show" | "run") ?? "plan";
			const nativeTarget = nativeRuntimeMatch[2]?.trim() || target;
			const timeoutMs = nativeRuntimeMatch[3] ? Number(nativeRuntimeMatch[3]) : undefined;
			return done(
				action === "run"
					? await runNativeRuntime(pi, { target: nativeTarget, timeoutMs })
					: buildNativeRuntimeOutput(action, { target: nativeTarget, timeoutMs }),
			);
		}
		const exploitLabMatch =
			/^re[-_]exploit[-_]lab\s+(plan|show|run|bundle)?(?:\s+(.+?))?(?:\s+(\d+))?(?:\s+(\d+))?$/i.exec(command);
		if (exploitLabMatch) {
			const action = (exploitLabMatch[1] as "plan" | "show" | "run" | "bundle") ?? "plan";
			const labTarget = exploitLabMatch[2]?.trim() || target;
			const runs = exploitLabMatch[3] ? Number(exploitLabMatch[3]) : undefined;
			const timeoutMs = exploitLabMatch[4] ? Number(exploitLabMatch[4]) : undefined;
			return done(
				action === "run"
					? await runExploitLab(pi, { target: labTarget, runs, timeoutMs })
					: buildExploitLabOutput(action, { target: labTarget, runs, timeoutMs }),
			);
		}
		if (/^re_tool_index\s+refresh$/i.test(command) || /^re-tools\s+refresh$/i.test(command)) {
			const output = await refreshToolIndex(pi);
			updateMissionCheckpoint("tool_index_checked", "done", command);
			return done(output);
		}
		if (/^re_graph\s+build$/i.test(command)) return done(buildAttackGraphOutput("build"));
		if (/^re[-_](?:exploit[-_])?chain\s+(plan|compose)\b/i.test(command)) {
			const action = /^re[-_](?:exploit[-_])?chain\s+compose\b/i.test(command) ? "compose" : "plan";
			const chainTarget = command.replace(/^re[-_](?:exploit[-_])?chain\s+(?:plan|compose)\b/i, "").trim() || target;
			return done(buildExploitChainOutput(action, { target: chainTarget }));
		}
		if (/^re_campaign\s+show$/i.test(command)) return done(buildCampaignOutput("show"));
		if (/^re_campaign\s+plan\b/i.test(command)) return done(buildCampaignOutput("plan", { target }));
		const verifierMatch = /^re[-_]verifier\s+(check|show|matrix)?(?:\s+(.+))?$/i.exec(command);
		if (verifierMatch)
			return done(
				buildVerifierOutput((verifierMatch[1] as "check" | "show" | "matrix") ?? "check", {
					target: verifierMatch[2]?.trim() || target,
				}),
			);
		const compilerMatch = /^re[-_]compiler\s+(draft|show|final)?(?:\s+(.+))?$/i.exec(command);
		if (compilerMatch)
			return done(
				buildCompilerOutput((compilerMatch[1] as "draft" | "show" | "final") ?? "draft", {
					target: compilerMatch[2]?.trim() || target,
				}),
			);
		const replayerMatch = /^re[-_]replayer\s+(plan|show|run)?(?:\s+(.+?))?(?:\s+(\d+))?$/i.exec(command);
		if (replayerMatch) {
			const action = (replayerMatch[1] as "plan" | "show" | "run") ?? "plan";
			const replayTarget = replayerMatch[2]?.trim() || target;
			const maxSteps = replayerMatch[3] ? Number(replayerMatch[3]) : undefined;
			return done(
				action === "run"
					? await runReplayer(pi, { target: replayTarget, maxSteps })
					: buildReplayerOutput(action as "plan" | "show", { target: replayTarget }),
			);
		}
		const autofixMatch = /^re[-_]autofix\s+(plan|show|apply)?(?:\s+(.+))?$/i.exec(command);
		if (autofixMatch)
			return done(
				buildAutofixOutput((autofixMatch[1] as "plan" | "show" | "apply") ?? "plan", {
					target: autofixMatch[2]?.trim() || target,
				}),
			);
		const proofLoopMatch = /^re[-_]proof[-_]loop\s+(plan|show|run)?(?:\s+(.+?))?(?:\s+(\d+))?(?:\s+(\d+))?$/i.exec(
			command,
		);
		if (proofLoopMatch) {
			const action = (proofLoopMatch[1] as "plan" | "show" | "run") ?? "plan";
			const loopTarget = proofLoopMatch[2]?.trim() || target;
			const maxSteps = proofLoopMatch[3] ? Number(proofLoopMatch[3]) : undefined;
			const replaySteps = proofLoopMatch[4] ? Number(proofLoopMatch[4]) : undefined;
			return done(
				action === "run"
					? await runProofLoop(pi, { target: loopTarget, maxSteps, replaySteps })
					: buildProofLoopOutput(action, { target: loopTarget, maxSteps, replaySteps }),
			);
		}
		if (/^re_bootstrap\s+plan\b/i.test(command)) {
			const tools = command
				.replace(/^re_bootstrap\s+plan\b/i, "")
				.trim()
				.split(/\s+/)
				.filter(Boolean);
			return done(
				formatBootstrapPlan(
					createBootstrapPlan(tools.length ? tools : ["checksec", "gdb", "radare2", "binwalk", "nmap", "ffuf"]),
				),
			);
		}
		if (/^re_complete\s+audit$/i.test(command)) return done(formatCompletionAudit());
		if (/^re_complete\s+scaffold\b/i.test(command))
			return done(`${writeReportScaffold()}\n\n${formatCompletionAudit()}`);
		return blocked(`unsupported operation command: ${command}`);
	}

	async function runOperationQueue(pi: ExtensionAPI, options: OperationRunOptions = {}): Promise<string> {
		const operation = buildOperation({ target: options.target, task: options.task, mode: "run" });
		const maxSteps = Math.max(1, Math.min(10, Math.floor(options.maxSteps ?? 1)));
		for (const step of operation.steps.filter((item) => item.status === "ready").slice(0, maxSteps)) {
			const result = await executeOperationStep(pi, step, operation.target);
			operation.executed.push(result);
			step.status = result.status === "blocked" ? "blocked" : "done";
			step.reason = result.status === "blocked" ? result.output : step.reason;
			if (result.status === "blocked") operation.blocked.push(`${step.id} ${step.command} — ${result.output}`);
		}
		operation.nextActions = operation.steps
			.filter((step) => step.status === "ready")
			.slice(0, 10)
			.map((step) => `re_operation run ${operation.target ?? "<target>"} 1 # ${step.id}`);
		const path = writeOperationArtifact(operation);
		return formatOperation(operation, path, truncateMiddle);
	}

	function buildOperationOutput(action: "plan" | "show" | "next" = "plan", options: CampaignOptions = {}): string {
		if (action === "show") {
			const path = latestOperationArtifactPath();
			if (!path) return "operation_queue:\nstatus: missing\nnext: re_operation plan";
			return compactStoredArtifact("operation_queue", path, readText(path));
		}
		const operation = buildOperation({ ...options, mode: "plan" });
		const path = writeOperationArtifact(operation);
		if (action === "next") {
			const next = operation.steps.find((step) => step.status === "ready");
			return [
				formatOperation(operation, path, truncateMiddle),
				"",
				"next_ready_step:",
				next ? `- ${next.id} ${next.command}` : "- none",
			].join("\n");
		}
		return formatOperation(operation, path, truncateMiddle);
	}

	function parseOperationArtifact(path: string): OperationArtifact | undefined {
		return parseJsonCodeFence<OperationArtifact>(readText(path));
	}

	function latestOrBuildOperation(options: CampaignOptions = {}): { operation: OperationArtifact; path: string } {
		const latest = !options.target && !options.task ? latestOperationArtifactPath() : undefined;
		if (latest) {
			const operation = parseOperationArtifact(latest);
			const missionId = readCurrentMission()?.id;
			if (operation && missionId && operation.missionId === missionId) return { operation, path: latest };
		}
		const operation = buildOperation({ target: options.target, task: options.task, mode: "plan" });
		const path = writeOperationArtifact(operation);
		return { operation, path };
	}

	return {
		latestCampaignArtifactPath,
		buildCampaignPhases,
		campaignPivotCandidates,
		campaignEvidenceGaps,
		buildCampaign,
		formatCampaign,
		writeCampaignArtifact,
		buildCampaignOutput,
		latestOperationArtifactPath,
		parseCampaignArtifact,
		latestOrBuildCampaign,
		operationCommandConcrete,
		buildOperation,
		formatOperation: (operation: OperationArtifact, path?: string) =>
			formatOperation(operation, path, truncateMiddle),
		writeOperationArtifact,
		executeOperationStep,
		runOperationQueue,
		buildOperationOutput,
		parseOperationArtifact,
		latestOrBuildOperation,
	} as const;
}

export type CampaignOperationRuntime = ReturnType<typeof createCampaignOperationRuntime>;
