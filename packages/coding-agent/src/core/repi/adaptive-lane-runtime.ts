import { createHash } from "node:crypto";
import { createAgentThreadManager } from "../agent-thread-manager.ts";
import { normalizeWorkerTask } from "../agent-thread-worker-runtime.ts";
import type { ExtensionAPI } from "../extensions/types.ts";
import type { BootstrapPlan } from "./autopilot-runtime.ts";
import {
	laneSpec,
	type MissionCheckpoint,
	type MissionCheckpointStatus,
	type MissionLane,
	type MissionState,
} from "./mission.ts";
import { repiSubagentResultFromManifest } from "./re-subagent-contract.ts";
import type { LaneCommandPack, LaneCommandPackRun } from "./recon-lane-runtime.ts";
import { validateRepiSubagentArtifact } from "./repi-subagent-artifact-validation.ts";
import type { LaneCommand } from "./specialist-command-planner.ts";
import { readTextFile as readText, toolIndexPath } from "./storage.ts";
import { shellQuote } from "./target.ts";
import { envBoolean, metadataValue, numericMetadataValue, truncateMiddle } from "./text.ts";

export type RunAutoDecision = {
	action: "continue_current" | "continue_next" | "stop";
	reason: string;
	nextLane?: string;
	quality?: number;
	verdict?: string;
};

export type MultiLanePlan = {
	action: "none" | "added" | "reprioritized";
	lane?: string;
	reason: string;
	next: string[];
};

export type ToolBootstrapClosure = {
	text: string;
	decision: RunAutoDecision;
	nextLane?: string;
};

export type RunAutoLaneOptions = {
	lane?: string;
	target?: string;
	maxSteps?: number;
	maxCommandsPerStep?: number;
	reasoning?: "regex" | "llm";
	dispatch?: "inline" | "specialist";
	cwd?: string;
	signal?: AbortSignal;
};

export type AdaptiveLaneRuntimeDependencies = {
	readCurrentMission: () => MissionState | undefined;
	writeCurrentMission: (mission: MissionState) => MissionState;
	activeLane: (mission: MissionState, name?: string) => MissionLane | undefined;
	autoCommandsForLane: (lane: MissionLane, maxCommands: number) => { commands: LaneCommand[]; rawItems: string[] };
	autoLaneCommandPack: (
		mission: MissionState,
		lane: MissionLane,
		commands: LaneCommand[],
		target?: string,
	) => LaneCommandPack;
	runLaneCommandPackWithStatus: (pi: ExtensionAPI, pack: LaneCommandPack) => Promise<LaneCommandPackRun>;
	removeLaneNextItems: (laneName: string, items: string[]) => MissionState | undefined;
	buildTaskTreeSnapshot: (options: { target?: string }) => { text: string };
	createBootstrapPlan: (tools: string[]) => BootstrapPlan[];
	formatBootstrapPlan: (plan: BootstrapPlan[]) => string;
	installBootstrapTools: (pi: ExtensionAPI, tools: string[]) => Promise<string>;
	refreshToolIndex: (pi: ExtensionAPI) => Promise<string>;
};

export function parsePlannerDecision(mergeText: string): RunAutoDecision {
	const actionMatch = mergeText.match(/action:\s*(continue_current|continue_next|stop)/i);
	if (!actionMatch) throw new Error("llm-step-planner: no action in planner output");
	const action = actionMatch[1].toLowerCase() as RunAutoDecision["action"];
	const nextLaneRaw = mergeText.match(/nextLane:\s*([^\n]+)/i)?.[1]?.trim() ?? "";
	const verdict = mergeText.match(/verdict:\s*(strong|partial|weak)/i)?.[1]?.toLowerCase();
	const quality = mergeText.match(/quality:\s*(\d+)/i)?.[1];
	const reason = mergeText.match(/reason:\s*([^\n]+)/i)?.[1]?.trim();
	return {
		action,
		reason: reason || `llm-step-planner action=${action}`,
		nextLane: nextLaneRaw && nextLaneRaw.toLowerCase() !== "none" ? nextLaneRaw : undefined,
		verdict,
		quality: quality ? Number(quality) : undefined,
	};
}

export function createAdaptiveLaneRuntime(dependencies: AdaptiveLaneRuntimeDependencies) {
	const {
		readCurrentMission,
		writeCurrentMission,
		activeLane,
		autoCommandsForLane,
		autoLaneCommandPack,
		runLaneCommandPackWithStatus,
		removeLaneNextItems,
		buildTaskTreeSnapshot,
		createBootstrapPlan,
		installBootstrapTools,
		refreshToolIndex,
	} = dependencies;

	function parseLaneRunDecision(text: string, laneName: string): RunAutoDecision {
		const quality = numericMetadataValue(text, "score");
		const verdict = metadataValue(text, "verdict");
		const strategy = metadataValue(text, "execution_strategy") ?? metadataValue(text, "mode");
		const skipped = numericMetadataValue(text, "skipped_count") ?? 0;
		const fallback = numericMetadataValue(text, "fallback_count") ?? 0;
		const selfHealCount = numericMetadataValue(text, "self_heal_count") ?? 0;
		const hasSelfHeal =
			selfHealCount > 0 ||
			/self_heal_commands:/.test(text) ||
			/^self_heal_labels:\s*(?!none\s*$).+/im.test(text) ||
			/\[auto:heal-/i.test(text);
		const nextLaneHint = metadataValue(text, "next_lane_hint");
		const advanced = /auto_lane_update: .* -> /.test(text);
		const toolBlocked = strategy === "blocked" || /^status:\s*blocked\s*$/im.test(text);
		if (toolBlocked) {
			return { action: "stop", reason: `tool_strategy_${strategy ?? "blocked"}:${laneName}`, quality, verdict };
		}
		if ((verdict === "weak" || (quality !== undefined && quality < 45)) && hasSelfHeal) {
			return {
				action: "continue_current",
				reason: `weak_evidence_self_heal:${laneName}`,
				nextLane: laneName,
				quality,
				verdict,
			};
		}
		if (skipped > 0 && fallback === 0) {
			return { action: "stop", reason: `skipped_without_fallback:${laneName}`, quality, verdict };
		}
		if (advanced || nextLaneHint) {
			return { action: "continue_next", reason: `advance:${nextLaneHint ?? "active"}`, quality, verdict };
		}
		if (verdict === "strong" || (quality !== undefined && quality >= 70)) {
			return { action: "continue_next", reason: `strong_evidence:${laneName}`, quality, verdict };
		}
		if (strategy === "tool-index-missing" && !hasSelfHeal) {
			return { action: "stop", reason: `tool_strategy_tool-index-missing:${laneName}`, quality, verdict };
		}
		if ((verdict === "partial" || (quality !== undefined && quality >= 45)) && hasSelfHeal) {
			return {
				action: "continue_current",
				reason: `partial_evidence_self_heal:${laneName}`,
				nextLane: laneName,
				quality,
				verdict,
			};
		}
		return { action: "stop", reason: `no_adaptive_followup:${laneName}`, quality, verdict };
	}

	function formatRunAutoDecision(decision: RunAutoDecision): string {
		return [
			"adaptive_decision:",
			`action: ${decision.action}`,
			`reason: ${decision.reason}`,
			decision.nextLane ? `next_lane: ${decision.nextLane}` : undefined,
			decision.quality !== undefined ? `quality: ${decision.quality}` : undefined,
			decision.verdict ? `verdict: ${decision.verdict}` : undefined,
		]
			.filter(Boolean)
			.join("\n");
	}

	function compactLaneRunTranscript(text: string, maxLength = 700): string {
		const highSignal = text
			.split(/\r?\n/)
			.map((line) => line.trim())
			.filter(
				(line) =>
					line &&
					/^(?:lane_run:|status:|mode:|execution_strategy:|verdict:|score:|reason:|exit:|executed_count:|skipped_count:|fallback_count:|missing_tools:|self_heal_count:|self_heal_labels:|followup_count:|followup_labels:|next_command:|next_lane_hint:|auto_lane_update:|[a-z0-9_-]*artifact:|evidence_artifact:|parser_signal_summary:|blockers?:|next:)/i.test(
						line,
					),
			)
			.slice(0, 18)
			.map((line) => truncateMiddle(line, 240));
		return truncateMiddle(highSignal.join("\n") || "status: no_compact_signals", maxLength);
	}

	function splitMetadataList(value?: string): string[] {
		if (!value || value === "none") return [];
		return value
			.split(/[, ]+/)
			.map((item) => item.trim())
			.filter((item) => item && item !== "none");
	}

	function adaptiveRepairLaneSpec(params: {
		lane: MissionLane;
		decision: RunAutoDecision;
		text: string;
		target?: string;
	}): { name: string; objective: string; next: string[]; blockCurrent: boolean } {
		const missingTools = splitMetadataList(metadataValue(params.text, "missing_tools"));
		const target = params.target ? shellQuote(params.target) : undefined;
		if (/tool_strategy|skipped_without_fallback/.test(params.decision.reason)) {
			const tools = missingTools.length ? missingTools.slice(0, 12) : ["checksec", "gdb", "r2", "rabin2"];
			return {
				name: "tool-bootstrap",
				objective: "补齐缺失工具或确认可用替代路径，再回到被阻塞 lane",
				blockCurrent: true,
				next: [
					`re_bootstrap plan ${tools.join(" ")}`,
					`[auto:tool-presence-audit] for t in ${tools.map((tool) => shellQuote(tool)).join(" ")}; do printf '%s=' "$t"; command -v "$t" || true; done # evidence: missing tool availability audit`,
					`[auto:tool-index-tail] sed -n '1,220p' ${shellQuote(toolIndexPath())} 2>/dev/null || true # evidence: current tool-index evidence`,
				],
			};
		}
		if (/no_adaptive_followup|weak_evidence|partial_evidence/.test(params.decision.reason)) {
			return {
				name: "evidence-repair",
				objective: "当前 lane 证据质量不足；扩大最小证据面并生成可运行 follow-up",
				blockCurrent: false,
				next: [
					target
						? `[auto:repair-target-baseline] file ${target}; sha256sum ${target}; strings -a -n 5 ${target} | grep -iE 'license|serial|key|valid|invalid|check|verify|flag|pass|fail|strcmp|memcmp|auth|token|sign' | head -220 # evidence: target baseline and high-signal strings`
						: "[auto:repair-target-discovery] pwd; find . -maxdepth 4 -type f | sort | head -260 # evidence: target candidate discovery",
					'[auto:repair-signal-sweep] rg -n "license|serial|key|valid|invalid|check|verify|flag|strcmp|memcmp|auth|session|jwt|sign|crypto|token|secret|admin|debug" . 2>/dev/null | head -260 # evidence: widened high-signal search',
					"[auto:repair-entry-map] find . -maxdepth 4 -type f \\( -name 'package.json' -o -name 'Dockerfile*' -o -name 'docker-compose*.yml' -o -name '*.service' -o -name '*route*' -o -name '*controller*' \\) | sort | head -180 # evidence: entry/config/route candidates",
				],
			};
		}
		return {
			name: "map-refresh",
			objective: "当前自动链没有稳定推进；刷新被动地图并重新选择证据面",
			blockCurrent: false,
			next: [
				"[auto:map-refresh-inventory] pwd; find . -maxdepth 5 -type f | sort | head -300 # evidence: refreshed workspace inventory",
				'[auto:map-refresh-routes] rg -n "route|router|auth|session|jwt|license|serial|flag|verify|sign|crypto|token|secret|admin|debug" . 2>/dev/null | head -260 # evidence: refreshed route/logic anchors',
			],
		};
	}

	function applyAdaptiveMultiLanePlan(params: {
		lane: MissionLane;
		decision: RunAutoDecision;
		text: string;
		target?: string;
	}): MultiLanePlan {
		const mission = readCurrentMission();
		if (!mission) return { action: "none", reason: "no_active_mission", next: [] };
		const spec = adaptiveRepairLaneSpec(params);
		const timestamp = new Date().toISOString();
		const currentIndex = mission.lanes.findIndex((lane) => lane.name === params.lane.name);
		const existingIndex = mission.lanes.findIndex((lane) => lane.name === spec.name);
		const existing = existingIndex >= 0 ? mission.lanes[existingIndex] : undefined;
		const mergedNext = [...(existing?.next ?? [])];
		for (const item of spec.next) if (!mergedNext.includes(item)) mergedNext.push(item);
		const plannerLane: MissionLane = {
			name: spec.name,
			objective: spec.objective,
			next: mergedNext,
			status: "in_progress",
			note: `adaptive_from=${params.lane.name}; reason=${params.decision.reason}`,
			updatedAt: timestamp,
		};
		const withoutExisting = mission.lanes.filter((_, index) => index !== existingIndex);
		const insertAfter = Math.max(
			0,
			currentIndex >= 0 ? currentIndex + (existingIndex >= 0 && existingIndex < currentIndex ? 0 : 1) : 0,
		);
		const nextLanes = [...withoutExisting];
		nextLanes.splice(Math.min(insertAfter, nextLanes.length), 0, plannerLane);
		const lanes = nextLanes.map((lane) => {
			if (lane.name === plannerLane.name) return lane;
			if (lane.name === params.lane.name) {
				return {
					...lane,
					status: spec.blockCurrent ? ("blocked" as const) : ("pending" as const),
					note: truncateMiddle(`adaptive_handoff=${plannerLane.name}; reason=${params.decision.reason}`, 500),
					updatedAt: timestamp,
				};
			}
			if (lane.status === "in_progress") return { ...lane, status: "pending" as const, updatedAt: timestamp };
			return lane;
		});
		writeCurrentMission({ ...mission, lanes });
		return {
			action: existing ? "reprioritized" : "added",
			lane: plannerLane.name,
			reason: params.decision.reason,
			next: spec.next,
		};
	}

	function formatMultiLanePlan(plan: MultiLanePlan): string {
		return [
			"multi_lane_plan:",
			`action: ${plan.action}`,
			plan.lane ? `lane: ${plan.lane}` : undefined,
			`reason: ${plan.reason}`,
			...(plan.next.length ? ["next:", ...plan.next.map((item) => `- ${item}`)] : []),
		]
			.filter(Boolean)
			.join("\n");
	}

	function shouldEscalateAdaptiveDecision(decisions: RunAutoDecision[]): boolean {
		const last = decisions.at(-1);
		if (!last || last.action !== "continue_current") return false;
		const same = decisions.filter((decision) => decision.reason === last.reason);
		if (same.length < 2) return false;
		const previous = same.at(-2);
		if (!previous || last.quality === undefined || previous.quality === undefined) return true;
		return last.quality <= previous.quality + 5;
	}

	function upsertMissionCheckpoint(
		checkpoints: MissionCheckpoint[],
		name: string,
		status: MissionCheckpointStatus,
		note?: string,
	): MissionCheckpoint[] {
		const updatedAt = new Date().toISOString();
		if (checkpoints.some((checkpoint) => checkpoint.name === name)) {
			return checkpoints.map((checkpoint) =>
				checkpoint.name === name ? { ...checkpoint, status, note, updatedAt } : checkpoint,
			);
		}
		return [...checkpoints, { name, status, note, updatedAt }];
	}

	function bootstrapToolsFromLane(lane: MissionLane, text: string): string[] {
		const tools: string[] = [];
		const add = (value?: string) => {
			for (const item of splitMetadataList(value)) {
				const tool = item.replace(/^[`'"]+|[`'",;]+$/g, "").trim();
				if (tool && !/^(re_bootstrap|plan|install|none)$/i.test(tool) && !tools.includes(tool)) tools.push(tool);
			}
		};
		const combined = [lane.note ?? "", lane.next.join("\n"), text].join("\n");
		for (const match of combined.matchAll(/\bre_bootstrap\s+(?:plan|install)\s+([^\n#]+)/g)) add(match[1]);
		add(metadataValue(text, "missing_tools"));
		for (const match of combined.matchAll(/missing_tools:\s*([^\n]+)/g)) add(match[1]);
		return tools.slice(0, 16);
	}

	function markToolBootstrapClosure(params: {
		laneName: string;
		sourceLane?: string;
		tools: string[];
		missing: string[];
		refreshedPath: string;
	}): void {
		const mission = readCurrentMission();
		if (!mission) return;
		const timestamp = new Date().toISOString();
		const installCommand = params.missing.length ? `re_bootstrap install ${params.missing.join(" ")}` : undefined;
		const lanes = mission.lanes.map((lane) => {
			if (lane.name === params.laneName) {
				const next = [...lane.next];
				if (installCommand && !next.includes(installCommand)) next.unshift(installCommand);
				return {
					...lane,
					status: params.missing.length ? ("in_progress" as const) : ("done" as const),
					next,
					note: truncateMiddle(
						[
							params.missing.length ? "bootstrap_incomplete" : "bootstrap_closed",
							`tools=${params.tools.join(",") || "none"}`,
							params.missing.length ? `missing=${params.missing.join(",")}` : "missing=none",
							params.sourceLane ? `resume=${params.sourceLane}` : undefined,
						]
							.filter(Boolean)
							.join("; "),
						500,
					),
					updatedAt: timestamp,
				};
			}
			if (!params.missing.length && params.sourceLane && lane.name === params.sourceLane) {
				return {
					...lane,
					status: "in_progress" as const,
					note: truncateMiddle(
						`bootstrap_resumed_from=${params.laneName}; tools=${params.tools.join(",") || "none"}; tool_index=${params.refreshedPath}`,
						500,
					),
					updatedAt: timestamp,
				};
			}
			if (!params.missing.length && lane.status === "in_progress") {
				return { ...lane, status: "pending" as const, updatedAt: timestamp };
			}
			return lane;
		});
		const checkpoints = upsertMissionCheckpoint(
			mission.checkpoints,
			"tool_index_checked",
			params.missing.length ? "blocked" : "done",
			params.missing.length
				? `missing after bootstrap refresh: ${params.missing.join(", ")}`
				: `bootstrap closure refreshed ${params.refreshedPath}`,
		);
		writeCurrentMission({ ...mission, lanes, checkpoints });
	}

	async function runToolBootstrapClosure(
		pi: ExtensionAPI,
		params: { lane: MissionLane; text: string },
	): Promise<ToolBootstrapClosure | undefined> {
		if (params.lane.name !== "tool-bootstrap") return undefined;
		const sourceLane = /(?:^|;\s*)adaptive_from=([^;]+)/.exec(params.lane.note ?? "")?.[1]?.trim() || undefined;
		const tools = bootstrapToolsFromLane(params.lane, params.text);
		const installRequested = /\bre_bootstrap\s+install\b/.test(params.lane.next.join("\n"));
		const bootstrapExecution = installRequested && tools.length ? await installBootstrapTools(pi, tools) : undefined;
		const refreshed = bootstrapExecution ? readText(toolIndexPath()) : await refreshToolIndex(pi);
		const plan = tools.length ? createBootstrapPlan(tools) : [];
		const missing = plan.filter((item) => item.known && !item.present).map((item) => item.tool);
		markToolBootstrapClosure({
			laneName: params.lane.name,
			sourceLane,
			tools,
			missing,
			refreshedPath: toolIndexPath(),
		});
		const text = [
			"tool_bootstrap_closure:",
			`tools: ${tools.join(", ") || "none"}`,
			`install_requested: ${installRequested ? "true" : "false"}`,
			`refreshed_tool_index: ${toolIndexPath()}`,
			`missing_after_refresh: ${missing.join(", ") || "none"}`,
			sourceLane ? `resumed_lane: ${missing.length ? "none" : sourceLane}` : "resumed_lane: none",
			missing.length
				? `next_bootstrap_command: re_bootstrap install ${missing.join(" ")}`
				: "next_bootstrap_command: none",
			`bootstrap_plan: total=${plan.length} present=${plan.filter((item) => item.present).length} missing=${missing.length}`,
			bootstrapExecution
				? `bootstrap_execution: ${compactLaneRunTranscript(bootstrapExecution, 500)}`
				: "bootstrap_execution: not_requested",
			`refreshed_tool_index_bytes: ${Buffer.byteLength(refreshed, "utf8")}`,
		].join("\n");
		if (!tools.length)
			return { text, decision: { action: "stop", reason: `tool_bootstrap_no_tools:${params.lane.name}` } };
		if (missing.length) {
			return { text, decision: { action: "stop", reason: `tool_bootstrap_incomplete:${missing.join(",")}` } };
		}
		return {
			text,
			decision: {
				action: "continue_next",
				reason: `tool_bootstrap_closed:${sourceLane ?? params.lane.name}`,
				nextLane: sourceLane,
			},
			nextLane: sourceLane,
		};
	}

	async function llmLaneRunDecision(options: {
		cwd: string;
		text: string;
		lane: MissionLane;
		mission?: MissionState;
		target?: string;
		signal?: AbortSignal;
	}): Promise<RunAutoDecision> {
		const snapshot = buildTaskTreeSnapshot({ target: options.target });
		const task = normalizeWorkerTask(
			[
				"You are the REPI step-planner. Given the Pentesting Task Tree snapshot and the last lane-run transcript, decide the next action for the autopilot loop.",
				"Return exactly these lines and nothing else:",
				"action: continue_current | continue_next | stop",
				"nextLane: <lane name or none>",
				"verdict: strong | partial | weak",
				"quality: <integer 0-100>",
				"reason: <one line>",
				"Rules: continue_current = re-run the same lane with adjusted commands; continue_next = advance to a different lane (set nextLane); stop = no productive next step. Prefer stop over repeating a failing lane.",
				"",
				`active_lane: ${options.lane.name}`,
				"",
				"## PTT snapshot",
				snapshot.text,
				"",
				"## last lane-run transcript",
				compactLaneRunTranscript(options.text, 4000),
			].join("\n"),
		);
		const manager = createAgentThreadManager({ cwd: options.cwd });
		const timeoutMs = 180000;
		try {
			const started = await manager.spawnThread({
				specName: "planner",
				task,
				timeoutMs,
				inheritMcp: false,
				mcpServers: [],
				mcpTools: [],
				signal: options.signal,
				missionId: options.mission?.id,
			});
			const final = await manager.awaitRun(started.runId);
			const merge = manager.mergeRun(started.runId);
			const mergedManifest = merge?.manifest ?? final;
			const validation = await validateRepiSubagentArtifact(repiSubagentResultFromManifest(mergedManifest), {
				missionId: options.mission?.id,
				spec: "planner",
				task,
				taskSha256: createHash("sha256").update(task).digest("hex"),
				requireMcpDisabled: true,
				timeoutMs,
			});
			if (!validation.ok) throw new Error(`llm-step-planner artifact validation failed: ${validation.error}`);
			return parsePlannerDecision(merge?.text ?? "");
		} finally {
			manager.dispose("repi_lane_planner_complete");
		}
	}

	async function dispatchLaneSpecialist(options: {
		cwd: string;
		lane: MissionLane;
		mission: MissionState;
		target?: string;
		signal?: AbortSignal;
	}): Promise<{ text: string; decision: RunAutoDecision; spec: string; note: string }> {
		if (envBoolean("REPI_AGENT_THREAD")) {
			throw new Error("RE_LANE_SPECIALIST_RECURSION_BLOCKED: specialist dispatch is forbidden in an agent thread");
		}
		const spec = laneSpec(options.lane, options.mission.route);
		if (!spec) throw new Error(`RE_LANE_SPECIALIST_UNAVAILABLE: no specialist owns lane ${options.lane.name}`);
		const snapshot = buildTaskTreeSnapshot({ target: options.target });
		const task = normalizeWorkerTask(
			[
				`You are the REPI ${spec} specialist. Own this mission lane end to end using your doctrine.`,
				`Lane: ${options.lane.name}`,
				`Objective: ${options.lane.objective}`,
				`Next steps queued: ${options.lane.next.join(", ") || "none"}`,
				options.target ? `Target: ${options.target}` : "",
				"Produce concrete evidence (commands run + output, offsets, artifact refs). Write your handoff to $REPI_WORKER_HANDOFF_PATH as your last action.",
				"Then emit: action, nextLane, and reason for the autopilot loop.",
				"",
				"## PTT snapshot",
				truncateMiddle(snapshot.text, 5000),
			]
				.filter(Boolean)
				.join("\n"),
		);
		const manager = createAgentThreadManager({ cwd: options.cwd });
		const timeoutMs = spec === "reverser" ? 360000 : 240000;
		try {
			const started = await manager.spawnThread({
				specName: spec,
				task,
				timeoutMs,
				inheritMcp: false,
				mcpServers: [],
				mcpTools: [],
				signal: options.signal,
				missionId: options.mission.id,
			});
			const final = await manager.awaitRun(started.runId);
			const merge = manager.mergeRun(started.runId);
			const mergedManifest = merge?.manifest ?? final;
			const validation = await validateRepiSubagentArtifact(repiSubagentResultFromManifest(mergedManifest), {
				missionId: options.mission.id,
				spec,
				task,
				taskSha256: createHash("sha256").update(task).digest("hex"),
				requireMcpDisabled: true,
				timeoutMs,
			});
			if (!validation.ok) {
				throw new Error(`specialist artifact validation failed: ${validation.error}`);
			}
			const text = merge?.text ?? "";
			return {
				text,
				decision: parsePlannerDecision(text),
				spec,
				note: `specialist_dispatch: spec=${spec} status=${validation.manifest.status}`,
			};
		} finally {
			manager.dispose("repi_lane_specialist_complete");
		}
	}

	async function runAutoLaneChain(pi: ExtensionAPI, params: RunAutoLaneOptions): Promise<string> {
		const maxSteps = Math.min(Math.max(Math.floor(params.maxSteps ?? 2), 1), 5);
		const maxCommandsPerStep = Math.min(Math.max(Math.floor(params.maxCommandsPerStep ?? 3), 1), 6);
		const outputs: string[] = [];
		let stopReason = "max_steps_reached";
		let requestedLane = params.lane;
		const decisions: RunAutoDecision[] = [];
		for (let step = 0; step < maxSteps; step++) {
			params.signal?.throwIfAborted();
			const mission = readCurrentMission();
			if (!mission) {
				stopReason = "no_active_mission";
				break;
			}
			const lane = activeLane(mission, requestedLane);
			requestedLane = undefined;
			if (!lane) {
				stopReason = "no_active_lane";
				break;
			}
			if (params.dispatch === "specialist") {
				if (!params.cwd?.trim()) {
					outputs.push(
						`## run-auto step ${step + 1}: ${lane.name} (specialist_dispatch_blocked: cwd is required)`,
					);
					stopReason = "specialist_dispatch_blocked:cwd_required";
					break;
				}
				if (envBoolean("REPI_AGENT_THREAD")) {
					outputs.push(
						`## run-auto step ${step + 1}: ${lane.name} (specialist_dispatch_blocked: recursive worker dispatch)`,
					);
					stopReason = "specialist_dispatch_blocked:recursion";
					break;
				}
				try {
					const specialist = await dispatchLaneSpecialist({
						cwd: params.cwd,
						lane,
						mission,
						target: params.target,
						signal: params.signal,
					});
					let decision = specialist.decision;
					const sections = [
						`## run-auto step ${step + 1}: ${lane.name} (specialist:${specialist.spec})`,
						compactLaneRunTranscript(specialist.text, 900),
						specialist.note,
					];
					const bootstrapClosure = await runToolBootstrapClosure(pi, { lane, text: specialist.text });
					if (bootstrapClosure) {
						decision = bootstrapClosure.decision;
						sections.push(`## tool-bootstrap-closure step ${step + 1}\n${bootstrapClosure.text}`);
					}
					decisions.push(decision);
					sections.push(formatRunAutoDecision(decision));
					outputs.push(sections.join("\n"));
					if (shouldEscalateAdaptiveDecision(decisions)) {
						const plan = applyAdaptiveMultiLanePlan({
							lane,
							decision,
							text: specialist.text,
							target: params.target,
						});
						outputs.push(`## multi-lane-planner step ${step + 1}\n${formatMultiLanePlan(plan)}`);
						stopReason = `multi_lane_plan:${plan.lane ?? "none"}:${decision.reason}`;
						break;
					}
					if (decision.action === "continue_current" || decision.action === "continue_next") {
						requestedLane =
							decision.action === "continue_current" ? (decision.nextLane ?? lane.name) : decision.nextLane;
						stopReason =
							step + 1 >= maxSteps
								? `max_steps_reached_after:${decision.reason}`
								: `adaptive_${decision.action}`;
						continue;
					}
					stopReason = decision.reason;
					break;
				} catch (error) {
					if (params.signal?.aborted) params.signal.throwIfAborted();
					outputs.push(
						`## run-auto step ${step + 1}: ${lane.name} (specialist_dispatch_blocked: ${truncateMiddle(String((error as Error).message ?? error), 160)})`,
					);
					stopReason = "specialist_dispatch_blocked:worker_failure";
					break;
				}
			}
			const { commands, rawItems } = autoCommandsForLane(lane, maxCommandsPerStep);
			if (commands.length === 0) {
				const bootstrapClosure = await runToolBootstrapClosure(pi, { lane, text: "" });
				if (bootstrapClosure) {
					const decision = bootstrapClosure.decision;
					decisions.push(decision);
					outputs.push(
						[
							`## run-auto step ${step + 1}: ${lane.name}`,
							`## tool-bootstrap-closure step ${step + 1}\n${bootstrapClosure.text}`,
							formatRunAutoDecision(decision),
						].join("\n"),
					);
					if (decision.action === "continue_next") {
						requestedLane = decision.nextLane;
						stopReason =
							step + 1 >= maxSteps ? `max_steps_reached_after:${decision.reason}` : "adaptive_continue_next";
						continue;
					}
					stopReason = decision.reason;
					break;
				}
				stopReason = `no_auto_commands:${lane.name}`;
				break;
			}
			const pack = autoLaneCommandPack(mission, lane, commands, params.target);
			const run = await runLaneCommandPackWithStatus(pi, pack);
			const text = run.text;
			if (run.executed) removeLaneNextItems(lane.name, rawItems);
			let decision = parseLaneRunDecision(text, lane.name);
			let llmNote = "";
			let llmBlocked = "";
			if (params.reasoning === "llm") {
				const cwd = params.cwd?.trim();
				if (!cwd) {
					const sections = [
						`## run-auto step ${step + 1}: ${lane.name}`,
						compactLaneRunTranscript(text),
						"llm-step-planner blocked: cwd is required",
					];
					outputs.push(sections.join("\n"));
					stopReason = "llm_step_planner_blocked:cwd_required";
					break;
				}
				if (envBoolean("REPI_AGENT_THREAD")) {
					const sections = [
						`## run-auto step ${step + 1}: ${lane.name}`,
						compactLaneRunTranscript(text),
						"llm-step-planner blocked: recursive worker dispatch",
					];
					outputs.push(sections.join("\n"));
					stopReason = "llm_step_planner_blocked:recursion";
					break;
				}
				try {
					decision = await llmLaneRunDecision({
						cwd,
						text,
						lane,
						mission,
						target: params.target,
						signal: params.signal,
					});
					llmNote = "llm-step-planner: applied";
				} catch (error) {
					if (params.signal?.aborted) params.signal.throwIfAborted();
					llmBlocked = `llm-step-planner blocked: ${truncateMiddle(String((error as Error).message ?? error), 160)}`;
					const sections = [
						`## run-auto step ${step + 1}: ${lane.name}`,
						compactLaneRunTranscript(text),
						llmBlocked,
					];
					outputs.push(sections.join("\n"));
					stopReason = "llm_step_planner_blocked:worker_failure";
					break;
				}
			}
			const sections = [`## run-auto step ${step + 1}: ${lane.name}`, compactLaneRunTranscript(text)];
			if (llmNote) sections.push(llmNote);
			const bootstrapClosure = await runToolBootstrapClosure(pi, { lane, text });
			if (bootstrapClosure) {
				decision = bootstrapClosure.decision;
				sections.push(`## tool-bootstrap-closure step ${step + 1}\n${bootstrapClosure.text}`);
			}
			decisions.push(decision);
			sections.push(formatRunAutoDecision(decision));
			outputs.push(sections.join("\n"));
			if (shouldEscalateAdaptiveDecision(decisions)) {
				const plan = applyAdaptiveMultiLanePlan({ lane, decision, text, target: params.target });
				outputs.push(`## multi-lane-planner step ${step + 1}\n${formatMultiLanePlan(plan)}`);
				stopReason = `multi_lane_plan:${plan.lane ?? "none"}:${decision.reason}`;
				break;
			}
			if (decision.action === "continue_current" || decision.action === "continue_next") {
				requestedLane =
					decision.action === "continue_current" ? (decision.nextLane ?? lane.name) : decision.nextLane;
				stopReason =
					step + 1 >= maxSteps ? `max_steps_reached_after:${decision.reason}` : `adaptive_${decision.action}`;
				continue;
			}
			if (/^tool_bootstrap_/.test(decision.reason)) {
				stopReason = decision.reason;
				break;
			}
			const plan = applyAdaptiveMultiLanePlan({ lane, decision, text, target: params.target });
			outputs.push(`## multi-lane-planner step ${step + 1}\n${formatMultiLanePlan(plan)}`);
			stopReason =
				plan.action === "none" ? decision.reason : `multi_lane_plan:${plan.lane ?? "none"}:${decision.reason}`;
			break;
		}
		return truncateMiddle(
			[
				"run_auto_summary:",
				`max_steps: ${maxSteps}`,
				`steps_executed: ${decisions.length}`,
				`adaptive_decisions: ${decisions.length}`,
				`stop_reason: ${stopReason}`,
				"",
				...outputs,
			].join("\n"),
			4096,
		);
	}

	return { parseLaneRunDecision, runAutoLaneChain };
}

export type AdaptiveLaneRuntime = ReturnType<typeof createAdaptiveLaneRuntime>;
