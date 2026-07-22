import { join } from "node:path";
import type { RunAutoDecision } from "./adaptive-lane-runtime.ts";
import type { ArtifactScopeFilterOptions } from "./artifact-scope.ts";
import { latestScopedMarkdownArtifact } from "./artifact-selection-runtime.ts";
import type { BootstrapPlan } from "./autopilot-runtime.ts";
import { type EvidenceRecord, parseEvidenceRecords } from "./evidence.ts";
import { appendEvidence, buildContextEvidenceTail } from "./evidence-runtime.ts";
import { type AttackGraphArtifact, formatAttackGraph, formatAttackGraphArtifactMarkdown } from "./graph.ts";
import type { MissionLane, MissionState } from "./mission.ts";
import type { DecisionCoreArtifact } from "./operator-orchestration-runtime.ts";
import type { PassiveMapContext } from "./recon-lane-runtime.ts";
import { ensureReconStorage } from "./resources.ts";
import type { RoutePlan } from "./routes.ts";
import {
	evidenceGraphsDir,
	evidenceLedgerPath,
	evidenceRunsDir,
	readTextFile,
	writePrivateTextFile,
} from "./storage.ts";
import { shellQuote } from "./target.ts";
import { slug, truncateMiddle } from "./text.ts";

type EvidenceLedgerTaskRecord = EvidenceRecord & {
	index: number;
	evidenceId: string;
};

type EvidenceSignalRecord = {
	title: string;
	fact?: string;
	confidence?: string;
	verify?: string;
	observation?: string;
	verdict?: string;
	counterexample?: string;
	claimId?: string;
	hypothesis?: string;
	prediction?: string;
};

type DomainProofExitSnapshot = {
	status: string;
	matchedProofExits: string[];
	missingProofExits: string[];
	rows: Array<{ status: string; proofExit: string; expectedEvidence: string[]; nextCommands: string[] }>;
};

export type PentestingTaskTreeSnapshot = {
	text: string;
	gapsCount: number;
	missingProofExits: number;
	lastRunVerdict?: string;
};

export type EvidenceGraphRuntimeDependencies = {
	readCurrentMission: () => MissionState | undefined;
	formatRoute: (route: RoutePlan) => string;
	formatMission: (mission: MissionState) => string;
	activeLane: (mission: MissionState, name?: string) => MissionLane | undefined;
	inferTargetFromMap: (map: PassiveMapContext | undefined, mission: MissionState) => string | undefined;
	parseLaneRunDecision: (text: string, laneName: string) => RunAutoDecision;
	recommendedToolsForRoute: (route: RoutePlan) => string[];
	createBootstrapPlan: (tools: string[]) => BootstrapPlan[];
	buildAttackGraph: () => AttackGraphArtifact;
	buildDecisionCore: (options: { target?: string; mode: "tick" }) => DecisionCoreArtifact;
	buildDomainProofExitClosure: (mission?: MissionState) => DomainProofExitSnapshot;
	updateMissionCheckpoint: (name: string, status: "pending" | "done" | "blocked", note?: string) => unknown;
	formatStoredArtifactSummary: (kind: string, path: string) => string;
};

export function createEvidenceGraphRuntime(dependencies: EvidenceGraphRuntimeDependencies) {
	const {
		readCurrentMission,
		formatRoute,
		formatMission,
		activeLane,
		inferTargetFromMap,
		parseLaneRunDecision,
		recommendedToolsForRoute,
		createBootstrapPlan,
		buildAttackGraph,
		buildDecisionCore,
		buildDomainProofExitClosure,
		updateMissionCheckpoint,
		formatStoredArtifactSummary,
	} = dependencies;

	function latestAttackGraphArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		return latestScopedMarkdownArtifact("attack_graph", evidenceGraphsDir(), options);
	}

	function attackGraphNextActions(mission: MissionState | undefined, map: PassiveMapContext | undefined): string[] {
		if (!mission) return ["re_mission new <task>", "re_map <target> <depth>", "re_graph build"];
		const actions: string[] = [];
		const lane = activeLane(mission);
		if (!map) actions.push("re_map <target> <depth>");
		if (lane) {
			const target = inferTargetFromMap(map, mission) ?? map?.target;
			actions.push(`re_lane plan ${lane.name}${target ? ` ${target}` : ""}`.trim());
			actions.push(`re_lane run ${lane.name}${target ? ` ${target}` : ""}`.trim());
			if (lane.next.some((item) => /^\[auto:/i.test(item))) actions.push(`re_lane run-auto ${lane.name} 2`);
		}
		const missingTools = recommendedToolsForRoute(mission.route)
			.map((tool) => createBootstrapPlan([tool])[0])
			.filter((item): item is BootstrapPlan => Boolean(item) && item.known && !item.present)
			.map((item) => item.tool)
			.slice(0, 10);
		if (missingTools.length > 0) actions.push(`re_bootstrap plan ${missingTools.join(" ")}`);
		return Array.from(new Set(actions)).slice(0, 12);
	}

	function summarizeLatestLaneRun(mission: MissionState | undefined): string {
		const path = latestScopedMarkdownArtifact("run", evidenceRunsDir(), { missionId: mission?.id });
		if (!path) return "last_lane_run: (none yet)";
		const text = readTextFile(path);
		if (!text) return `last_lane_run: (unreadable artifact ${path})`;
		const lane = mission ? (activeLane(mission)?.name ?? "") : "";
		const decision = parseLaneRunDecision(text, lane);
		const head = text.slice(0, 600).replace(/\s+\n/g, "\n").trim();
		return [
			`last_lane_run_artifact: ${path}`,
			`decision: action=${decision.action} quality=${decision.quality ?? "n/a"} verdict=${decision.verdict ?? "n/a"} nextLane=${decision.nextLane ?? "n/a"}`,
			`reason: ${truncateMiddle(decision.reason, 300)}`,
			"transcript_head:",
			truncateMiddle(head, 600),
		].join("\n");
	}

	function evidenceRecordHasCounterSignal(record: EvidenceSignalRecord): boolean {
		if (record.verdict === "contradicted" || record.counterexample) return true;
		return /counter[_ -]?evidence|contradict|refut|negative|no[-_ ]?match|not reproduced|failed|blocked|error|反证|矛盾|失败|未复现/i.test(
			[record.title, record.fact, record.confidence, record.verify, record.observation].filter(Boolean).join("\n"),
		);
	}

	function evidenceRecordHasHypothesisSignal(record: EvidenceSignalRecord): boolean {
		if (record.claimId || record.hypothesis || record.prediction) return true;
		return /hypothesis|claim|candidate|suspect|assumption|assertion|proof|finding|假设|候选|断言|发现/i.test(
			[record.title, record.fact, record.confidence].filter(Boolean).join("\n"),
		);
	}

	function parseEvidenceLedgerTaskRecords(limit = 14): EvidenceLedgerTaskRecord[] {
		const missionId = readCurrentMission()?.id;
		return parseEvidenceRecords(readTextFile(evidenceLedgerPath()))
			.filter((record) => !missionId || record.missionId === missionId)
			.slice(-limit)
			.map((record) => ({
				...record,
				index: record.ledgerIndex,
				evidenceId: `evidence:${record.ledgerIndex}:${slug(record.title)}`,
			}));
	}

	function buildPentestingTaskTreeSnapshot(
		options: { target?: string; focus?: string } = {},
	): PentestingTaskTreeSnapshot {
		const mission = readCurrentMission();
		const graph = buildAttackGraph();
		const decision = buildDecisionCore({ target: options.target, mode: "tick" });
		const closure = buildDomainProofExitClosure(mission);
		const lastRun = summarizeLatestLaneRun(mission);
		const missingRows = closure.rows.filter((row) => row.status === "missing").slice(0, 8);
		const lines: string[] = ["# Pentesting Task Tree (PTT) snapshot"];
		if (options.focus) lines.push(`focus: ${options.focus}`);
		lines.push(
			"",
			"## root objective",
			mission?.task ?? "(no active mission — run re_route / re_kernel first)",
			`route: ${mission ? formatRoute(mission.route) : "(none)"}`,
			"",
			"## lanes (branches)",
			mission ? formatMission(mission) : "(no active mission)",
			"",
			"## attack graph",
			`critical_path: ${graph.criticalPath.length ? graph.criticalPath.join(" -> ") : "(none)"}`,
			`gaps (${graph.gaps.length}):`,
			...graph.gaps.slice(0, 16).map((gap) => `- ${gap}`),
			"next_actions:",
			...graph.nextActions.slice(0, 12).map((action) => `- ${action}`),
			"",
			"## decision core",
			`objective_stack: ${decision.objectiveStack.join(" / ") || "(empty)"}`,
			"decision_rules:",
			...decision.decisionRules.slice(0, 16).map((rule) => `- ${rule}`),
			"operator_queue:",
			...decision.operatorQueue.slice(0, 12).map((queue) => `- ${queue}`),
			"stop_conditions:",
			...decision.stopConditions.slice(0, 8).map((condition) => `- ${condition}`),
			"",
			"## domain proof-exit closure",
			`status: ${closure.status}`,
			`matched: ${closure.matchedProofExits.length ? closure.matchedProofExits.join(", ") : "(none)"}`,
			`missing: ${closure.missingProofExits.length ? closure.missingProofExits.join(", ") : "(none)"}`,
		);
		if (missingRows.length > 0) {
			lines.push("missing_rows:");
			for (const row of missingRows) {
				lines.push(
					`- ${row.proofExit}: expected ${row.expectedEvidence.slice(0, 2).join("; ") || "(unspecified)"} -> ${row.nextCommands.slice(0, 2).join("; ") || "(no command)"}`,
				);
			}
		}
		lines.push(
			"",
			"## evidence ledger tail",
			truncateMiddle(buildContextEvidenceTail({ target: options.target }), 3000),
			"",
			"## last lane-run",
			lastRun,
		);
		return {
			text: lines.join("\n"),
			gapsCount: graph.gaps.length,
			missingProofExits: closure.missingProofExits.length,
			lastRunVerdict: /verdict=([^\s]+)/.exec(lastRun)?.[1],
		};
	}

	function writeAttackGraphArtifact(graph: AttackGraphArtifact): string {
		ensureReconStorage();
		const path = join(
			evidenceGraphsDir(),
			`${graph.timestamp.replace(/[:.]/g, "-")}-${slug(graph.route ?? "security")}.md`,
		);
		writePrivateTextFile(path, formatAttackGraphArtifactMarkdown(graph, { truncate: truncateMiddle }));
		const evidence = appendEvidence({
			kind: "artifact",
			title: `attack-graph ${graph.missionId ?? "no-mission"}`,
			fact: `Built operation graph with ${graph.nodes.length} nodes, ${graph.edges.length} edges, ${graph.gaps.length} gap(s), ${graph.nextActions.length} next action(s)`,
			command: "re_graph build",
			path,
			verify: `cat ${shellQuote(path)}`,
			confidence: "mission/evidence/tool graph",
		});
		updateMissionCheckpoint("attack_graph_ready", "done", path);
		return `${path}\n${evidence.timestamp} ${evidence.title}`;
	}

	function buildAttackGraphOutput(action: "build" | "show" = "build"): string {
		if (action === "show") {
			const path = latestAttackGraphArtifactPath();
			return path
				? formatStoredArtifactSummary("attack_graph", path)
				: "attack_graph:\nstatus: missing\nnext: re_graph build";
		}
		const graph = buildAttackGraph();
		const [path] = writeAttackGraphArtifact(graph).split(/\r?\n/, 1);
		return formatAttackGraph(graph, path);
	}

	return {
		attackGraphNextActions,
		buildAttackGraphOutput,
		buildPentestingTaskTreeSnapshot,
		evidenceRecordHasCounterSignal,
		evidenceRecordHasHypothesisSignal,
		latestAttackGraphArtifactPath,
		parseEvidenceLedgerTaskRecords,
		writeAttackGraphArtifact,
	};
}
