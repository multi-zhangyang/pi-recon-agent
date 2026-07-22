import type { ArtifactScopeFilterOptions } from "./artifact-scope.ts";
import type { AttackGraphArtifact, AttackGraphEdge, AttackGraphNode, AttackGraphTaskTreeNode } from "./graph.ts";
import type {
	RepiProofLoopGraphArtifact,
	RuntimeAdapterExecutionGraphArtifact,
	RuntimeAdapterGraphParserSummary,
	RuntimeAdapterMitigationGraphEvidence,
} from "./graph-artifacts.ts";
import type { MissionState } from "./mission.ts";
import type { SwarmArtifact } from "./swarm-runtime-types.ts";

export type AttackGraphPassiveMapContext = {
	path: string;
	timestamp: string;
	target?: string;
	signals: string[];
	candidates: string[];
};

export type AttackGraphBootstrapPlan = {
	tool: string;
	present: boolean;
	path?: string;
	install?: string;
	verify?: string;
	known: boolean;
};

export type AttackGraphEvidenceLedgerTaskRecord = {
	index: number;
	evidenceId: string;
	timestamp: string;
	priority: number;
	kind: string;
	title: string;
	fact?: string;
	command?: string;
	path?: string;
	hash?: string;
	verify?: string;
	confidence?: string;
	claimId?: string;
	hypothesis?: string;
	prediction?: string;
	observation?: string;
	counterexample?: string;
	verdict?: string;
};

export type AttackGraphRuntimeDependencies = {
	ensureReconStorage: () => void;
	nowIso: () => string;
	readCurrentMission: () => MissionState | undefined;
	latestPassiveMapContext: () => AttackGraphPassiveMapContext | undefined;
	recentRuntimeAdapterExecutionArtifacts: (
		limit?: number,
		options?: ArtifactScopeFilterOptions,
	) => Array<{ path: string; artifact: RuntimeAdapterExecutionGraphArtifact }>;
	recentProofLoopArtifacts: (
		limit?: number,
		options?: ArtifactScopeFilterOptions,
	) => Array<{ path: string; proof: RepiProofLoopGraphArtifact }>;
	recentSwarmArtifactsForGraph: (
		limit?: number,
		options?: ArtifactScopeFilterOptions,
	) => Array<{ path: string; swarm: SwarmArtifact }>;
	artifactBasename: (path: string) => string;
	slug: (value: string) => string;
	recentMarkdownArtifacts: (directory: string, limit: number) => string[];
	evidenceRunsDir: () => string;
	readText: (path: string) => string;
	metadataValue: (text: string, key: string) => string | undefined;
	runtimeAdapterParserSummaryForGraph: (
		artifact: RuntimeAdapterExecutionGraphArtifact,
	) => RuntimeAdapterGraphParserSummary;
	runtimeAdapterMitigationEvidenceForGraph: (
		artifact: RuntimeAdapterExecutionGraphArtifact,
	) => RuntimeAdapterMitigationGraphEvidence | undefined;
	existsSync: (path: string) => boolean;
	truncateMiddle: (text: string, limit: number) => string;
	sha256Text: (text: string) => string;
	evidenceLedgerGraphNodes: (limit?: number, options?: { missionId?: string }) => AttackGraphNode[];
	parseEvidenceLedgerTaskRecords: (limit?: number) => AttackGraphEvidenceLedgerTaskRecord[];
	evidenceRecordHasHypothesisSignal: (record: AttackGraphEvidenceLedgerTaskRecord) => boolean;
	evidenceRecordHasCounterSignal: (record: AttackGraphEvidenceLedgerTaskRecord) => boolean;
	recommendedToolsForRoute: (route: MissionState["route"]) => string[];
	createBootstrapPlan: (tools: string[]) => AttackGraphBootstrapPlan[];
	attackGraphNextActions: (
		mission: MissionState | undefined,
		map: AttackGraphPassiveMapContext | undefined,
	) => string[];
	prioritizeAttackGraphTaskTree: (nodes: AttackGraphTaskTreeNode[], limit?: number) => AttackGraphTaskTreeNode[];
};

export function createAttackGraphRuntime(dependencies: AttackGraphRuntimeDependencies) {
	const {
		ensureReconStorage,
		nowIso,
		readCurrentMission,
		latestPassiveMapContext,
		recentRuntimeAdapterExecutionArtifacts,
		recentProofLoopArtifacts,
		recentSwarmArtifactsForGraph,
		artifactBasename,
		slug,
		recentMarkdownArtifacts,
		evidenceRunsDir,
		readText,
		metadataValue,
		runtimeAdapterParserSummaryForGraph,
		runtimeAdapterMitigationEvidenceForGraph,
		existsSync,
		truncateMiddle,
		sha256Text,
		evidenceLedgerGraphNodes,
		parseEvidenceLedgerTaskRecords,
		evidenceRecordHasHypothesisSignal,
		evidenceRecordHasCounterSignal,
		recommendedToolsForRoute,
		createBootstrapPlan,
		attackGraphNextActions,
		prioritizeAttackGraphTaskTree,
	} = dependencies;

	function buildAttackGraph(): AttackGraphArtifact {
		ensureReconStorage();
		const timestamp = nowIso();
		const mission = readCurrentMission();
		const map = latestPassiveMapContext();
		const scope: ArtifactScopeFilterOptions = {
			missionId: mission?.id,
			route: mission?.route.domain,
			target: map?.target && map.target !== "." ? map.target : undefined,
			requestedBy: "attack_graph",
		};
		const runtimeAdapterArtifacts = recentRuntimeAdapterExecutionArtifacts(8, scope);
		const proofLoopArtifacts = recentProofLoopArtifacts(4, scope);
		const swarmArtifacts = recentSwarmArtifactsForGraph(4, scope);
		const nodes = new Map<string, AttackGraphNode>();
		const edges: AttackGraphEdge[] = [];
		const taskTree: AttackGraphTaskTreeNode[] = [];
		const addNode = (node: AttackGraphNode) => {
			const existing = nodes.get(node.id);
			if (!existing) nodes.set(node.id, node);
			else if (node.id.startsWith("hypothesis:")) nodes.set(node.id, { ...existing, ...node });
		};
		const addEdge = (edge: AttackGraphEdge) => {
			if (!edges.some((item) => item.from === edge.from && item.to === edge.to && item.kind === edge.kind))
				edges.push(edge);
		};
		const addTask = (node: AttackGraphTaskTreeNode) => {
			const existing = taskTree.find((item) => item.id === node.id);
			if (!existing) taskTree.push(node);
			else if (node.id.startsWith("hypothesis:")) Object.assign(existing, node);
		};
		const sourceArtifacts: string[] = [];
		const gaps: string[] = [];
		const criticalPath: string[] = [];
		const runtimeArtifactLineage = runtimeAdapterArtifacts.map(({ path, artifact }) => {
			const artifactBase = artifactBasename(path);
			return {
				path,
				artifact,
				artifactBase,
				adapterId: artifact.adapterId,
				target: artifact.target ?? "",
				artifactId: `artifact:runtime-adapter:${slug(artifact.adapterId)}:${slug(artifactBase)}`,
				commandId: `command:runtime-adapter:${slug(artifact.adapterId)}:${slug(artifactBase)}`,
			};
		});
		const runtimeArtifactsForCommand = (command: string) => {
			if (!/\bre_runtime_adapter\s+run\b/i.test(command)) return [];
			const lowerCommand = command.toLowerCase();
			return runtimeArtifactLineage.filter((lineage) => {
				const adapterMatches = lowerCommand.includes(lineage.adapterId.toLowerCase());
				const targetMatches = lineage.target.length > 0 && lowerCommand.includes(lineage.target.toLowerCase());
				return adapterMatches || targetMatches;
			});
		};

		if (!mission) {
			gaps.push("no active mission");
		} else {
			const missionId = `mission:${mission.id}`;
			addNode({ id: missionId, kind: "mission", label: mission.task, status: "active" });
			addTask({ id: missionId, kind: "mission", label: mission.task, status: "active", note: mission.route.domain });
			addNode({
				id: `route:${slug(mission.route.domain)}`,
				kind: "route",
				label: mission.route.domain,
				note: mission.route.intent,
			});
			addEdge({
				from: `mission:${mission.id}`,
				to: `route:${slug(mission.route.domain)}`,
				kind: "owns",
				label: "route",
			});
			criticalPath.push(`mission:${mission.id}`, `route:${mission.route.domain}`);
			let previousLane: string | undefined;
			for (const lane of mission.lanes) {
				const laneId = `lane:${slug(lane.name)}`;
				addNode({
					id: laneId,
					kind: "lane",
					label: lane.name,
					status: lane.status ?? "pending",
					note: lane.objective,
				});
				addTask({
					id: laneId,
					parentId: missionId,
					kind: "lane",
					label: lane.name,
					status: lane.status ?? "pending",
					evidence: lane.next.slice(0, 4),
					note: lane.objective,
				});
				addEdge({ from: `mission:${mission.id}`, to: laneId, kind: "owns", label: "lane" });
				if (previousLane) addEdge({ from: previousLane, to: laneId, kind: "orders" });
				previousLane = laneId;
				if (lane.status === "blocked") gaps.push(`blocked lane: ${lane.name}${lane.note ? ` — ${lane.note}` : ""}`);
				if ((lane.status === "in_progress" || lane.status === "pending") && criticalPath.length < 6) {
					criticalPath.push(`${lane.status}:${lane.name}`);
				}
			}
			for (const checkpoint of mission.checkpoints) {
				const checkId = `check:${slug(checkpoint.name)}`;
				addNode({
					id: checkId,
					kind: "checkpoint",
					label: checkpoint.name,
					status: checkpoint.status,
					note: checkpoint.note,
				});
				addTask({
					id: checkId,
					parentId: missionId,
					kind: "checkpoint",
					label: checkpoint.name,
					status: checkpoint.status,
					note: checkpoint.note,
				});
				addEdge({
					from: `mission:${mission.id}`,
					to: checkId,
					kind: checkpoint.status === "blocked" ? "blocks" : "updates",
				});
				if (checkpoint.status !== "done")
					gaps.push(
						`${checkpoint.status} check: ${checkpoint.name}${checkpoint.note ? ` — ${checkpoint.note}` : ""}`,
					);
			}
		}

		if (map) {
			sourceArtifacts.push(map.path);
			addNode({
				id: `map:${slug(artifactBasename(map.path))}`,
				kind: "map",
				label: map.target ?? "workspace map",
				status: `${map.signals.length} signals`,
				path: map.path,
				note: map.signals.slice(0, 5).join(" | "),
			});
			addTask({
				id: `map:${slug(artifactBasename(map.path))}`,
				parentId: mission ? `mission:${mission.id}` : undefined,
				kind: "map",
				label: map.target ?? "workspace map",
				status: `${map.signals.length} signals`,
				path: map.path,
				evidence: map.signals.slice(0, 5),
			});
			if (mission)
				addEdge({
					from: `mission:${mission.id}`,
					to: `map:${slug(artifactBasename(map.path))}`,
					kind: "evidences",
				});
		} else {
			gaps.push("no passive map artifact");
		}

		for (const path of recentMarkdownArtifacts(evidenceRunsDir(), 8)) {
			sourceArtifacts.push(path);
			const text = readText(path);
			const lane = metadataValue(text, "lane") ?? artifactBasename(path);
			const verdict = metadataValue(text, "verdict");
			const score = metadataValue(text, "score");
			const runId = `run:${slug(artifactBasename(path))}`;
			addNode({
				id: runId,
				kind: "run",
				label: lane,
				status: verdict ?? "unknown",
				path,
				note: score ? `score=${score}` : undefined,
			});
			const laneId = `lane:${slug(lane)}`;
			addTask({
				id: runId,
				parentId: nodes.has(laneId) ? laneId : mission ? `mission:${mission.id}` : undefined,
				kind: "run",
				label: lane,
				status: verdict ?? "unknown",
				path,
				note: score ? `score=${score}` : undefined,
			});
			if (nodes.has(laneId)) addEdge({ from: laneId, to: runId, kind: "evidences", label: "lane-run" });
			if (verdict === "weak") gaps.push(`weak evidence run: ${path}`);
		}

		for (const { path, artifact } of runtimeAdapterArtifacts) {
			sourceArtifacts.push(path);
			const lineage = runtimeArtifactLineage.find((item) => item.path === path);
			const artifactBase = lineage?.artifactBase ?? artifactBasename(path);
			const adapterId = `tool:runtime-adapter:${slug(artifact.adapterId)}`;
			const artifactId =
				lineage?.artifactId ?? `artifact:runtime-adapter:${slug(artifact.adapterId)}:${slug(artifactBase)}`;
			const commandId =
				lineage?.commandId ?? `command:runtime-adapter:${slug(artifact.adapterId)}:${slug(artifactBase)}`;
			const parserMatchCount = artifact.parserSignals.reduce((sum, signal) => sum + signal.matches.length, 0);
			const parserSummary = runtimeAdapterParserSummaryForGraph(artifact);
			const parserSummaryId = `summary:runtime-adapter:${slug(artifact.adapterId)}:${slug(artifactBase)}`;
			const mitigationEvidence = runtimeAdapterMitigationEvidenceForGraph(artifact);
			const mitigationId = `artifact:binary-mitigation-map:${slug(artifact.adapterId)}:${slug(artifactBase)}`;
			const targetProfile = artifact.targetProfile;
			const targetProfileId = `target:runtime-adapter:${slug(artifact.adapterId)}:${slug(artifactBase)}`;

			addNode({
				id: adapterId,
				kind: "tool",
				label: artifact.adapterId,
				status: `${artifact.selectedRunner}/${artifact.domainId}`,
				note: `runtime-adapter bridge=${artifact.bridgeId} target=${artifact.target ?? "<none>"}`,
			});
			addTask({
				id: adapterId,
				parentId: mission ? `mission:${mission.id}` : undefined,
				kind: "tool",
				label: artifact.adapterId,
				status: `${artifact.selectedRunner}/${artifact.domainId}`,
				note: `runtime-adapter target=${artifact.target ?? "<none>"}`,
			});

			if (targetProfile) {
				addNode({
					id: targetProfileId,
					kind: "target_profile",
					label: truncateMiddle(targetProfile.target || artifact.target || "<none>", 160),
					status: `kinds=${targetProfile.targetKinds.join(",")} exists=${targetProfile.exists}`,
					note: [
						`path=${targetProfile.pathKind ?? "<none>"}`,
						`magic=${targetProfile.magic ?? "<none>"}`,
						`adapters=${targetProfile.adapterIds.join(",") || "<none>"}`,
						`reasons=${targetProfile.reasons.join(" | ") || "<none>"}`,
					].join(" "),
				});
				addTask({
					id: targetProfileId,
					parentId: adapterId,
					kind: "target_profile",
					label: truncateMiddle(targetProfile.target || artifact.target || "<none>", 180),
					status: `kinds=${targetProfile.targetKinds.join(",")} exists=${targetProfile.exists}`,
					evidence: targetProfile.signals
						.slice(0, 8)
						.map(
							(signal) =>
								`rank=${signal.evidenceRank} kind=${signal.targetKind} adapter=${signal.adapterId} reason=${signal.reason}`,
						),
					note: `runtime target profile magic=${targetProfile.magic ?? "<none>"}`,
				});
				addEdge({ from: targetProfileId, to: adapterId, kind: "supports", label: "target-profile-auto-detect" });
			}

			addNode({
				id: artifactId,
				kind: "artifact",
				label: artifactBase,
				status: `exit=${artifact.exitCode ?? "null"} parser_matches=${parserMatchCount}`,
				path,
				note: `stdout_sha256=${artifact.stdoutSha256} stderr_sha256=${artifact.stderrSha256}`,
			});
			addTask({
				id: artifactId,
				parentId: adapterId,
				kind: "artifact",
				label: artifactBase,
				status: `exit=${artifact.exitCode ?? "null"} parser_matches=${parserMatchCount}`,
				path,
				evidence: [
					`artifact_kinds=${artifact.artifactKinds.join(",")}`,
					`proof_exit=${artifact.proofExitSignals.join(" | ")}`,
					`stdout_sha256=${artifact.stdoutSha256}`,
					`stderr_sha256=${artifact.stderrSha256}`,
				],
			});

			addNode({
				id: commandId,
				kind: "command",
				label: truncateMiddle(artifact.command, 160),
				status: artifact.killed ? "killed" : `exit=${artifact.exitCode ?? "null"}`,
				note: `runner=${artifact.selectedRunner}`,
			});
			addTask({
				id: commandId,
				parentId: artifactId,
				kind: "command",
				label: truncateMiddle(artifact.command, 180),
				status: artifact.killed ? "killed" : `exit=${artifact.exitCode ?? "null"}`,
				command: artifact.command,
			});
			addEdge({ from: adapterId, to: commandId, kind: "requires", label: artifact.selectedRunner });
			addEdge({ from: commandId, to: artifactId, kind: "produces", label: "runtime-adapter-json" });
			for (const stream of [
				{ name: "stdout", hash: artifact.stdoutSha256, head: artifact.stdoutHead },
				{ name: "stderr", hash: artifact.stderrSha256, head: artifact.stderrHead },
			] as const) {
				const outputId = `artifact:runtime-output:${slug(artifact.adapterId)}:${slug(artifactBase)}:${stream.name}`;
				const outputHead = truncateMiddle((stream.head ?? "").replace(/\s+/g, " ").trim(), 260);
				addNode({
					id: outputId,
					kind: "artifact",
					label: `${stream.name} sha256=${stream.hash.slice(0, 16)}`,
					status: "runtime-output-hash",
					path,
					note: outputHead || `${stream.name} empty`,
				});
				addTask({
					id: outputId,
					parentId: artifactId,
					kind: "artifact",
					label: `${stream.name} sha256=${stream.hash.slice(0, 16)}`,
					status: "runtime-output-hash",
					path,
					evidence: [
						`${stream.name}_sha256=${stream.hash}`,
						outputHead ? `${stream.name}_head=${outputHead}` : `${stream.name}_empty`,
					],
				});
				addEdge({ from: commandId, to: outputId, kind: "produces", label: stream.name });
				addEdge({ from: outputId, to: artifactId, kind: "evidences", label: `${stream.name}_hash` });
			}
			if (targetProfile)
				addEdge({ from: targetProfileId, to: artifactId, kind: "evidences", label: "target-profile" });

			if (mitigationEvidence) {
				addNode({
					id: mitigationId,
					kind: "artifact",
					label: `binary mitigation map ${artifact.adapterId}`,
					status: mitigationEvidence.status,
					path,
					note: mitigationEvidence.evidence.slice(0, 6).join(" | ") || "binary mitigation proof missing",
				});
				addTask({
					id: mitigationId,
					parentId: artifactId,
					kind: "artifact",
					label: `binary mitigation map ${artifact.adapterId}`,
					status: mitigationEvidence.status,
					path,
					evidence: [
						`kind=${mitigationEvidence.kind}`,
						`matched=${mitigationEvidence.matched}`,
						...mitigationEvidence.evidence.slice(0, 10),
						...mitigationEvidence.missing.map((missing) => `missing_proof=${missing}`),
					],
				});
				addEdge({ from: artifactId, to: mitigationId, kind: "produces", label: "binary-mitigation-map" });
				addEdge({
					from: mitigationId,
					to: parserSummaryId,
					kind: mitigationEvidence.matched ? "supports" : "blocks",
					label: mitigationEvidence.proofExitSignal,
				});
				if (!mitigationEvidence.matched && mitigationEvidence.expected) {
					gaps.push(`runtime adapter missing mitigation map proof: ${artifact.adapterId}`);
				}
			}

			addNode({
				id: parserSummaryId,
				kind: "parser_summary",
				label: `parser_signal_summary ${artifact.adapterId}`,
				status: `matched=${parserSummary.matchedRules}/${parserSummary.totalRules} missing=${parserSummary.missingProofExitSignals.length}`,
				note: `ranks=${parserSummary.evidenceRanks.join(",") || "<none>"} matched_proof=${parserSummary.matchedProofExitSignals.join(" | ") || "<none>"}`,
			});
			addTask({
				id: parserSummaryId,
				parentId: artifactId,
				kind: "parser_summary",
				label: `parser_signal_summary ${artifact.adapterId}`,
				status: `matched=${parserSummary.matchedRules}/${parserSummary.totalRules} missing=${parserSummary.missingProofExitSignals.length}`,
				evidence: [
					`matched=${parserSummary.matchedRules}/${parserSummary.totalRules}`,
					`match_count=${parserSummary.matchCount}`,
					`ranks=${parserSummary.evidenceRanks.join(",") || "<none>"}`,
					`matched_proof=${parserSummary.matchedProofExitSignals.join(" | ") || "<none>"}`,
					`missing_proof=${parserSummary.missingProofExitSignals.join(" | ") || "<none>"}`,
				],
			});
			addEdge({ from: parserSummaryId, to: artifactId, kind: "verifies", label: "parser-signal-summary" });

			if (parserSummary.missingProofExitSignals.length > 0) {
				gaps.push(
					`runtime adapter missing proof: ${artifact.adapterId}: ${parserSummary.missingProofExitSignals.join("; ")}`,
				);
				for (const missingProofExit of parserSummary.missingProofExitSignals.slice(0, 6)) {
					const gapId = `gap:runtime-adapter:${slug(artifact.adapterId)}:${slug(artifactBase)}:${slug(missingProofExit)}`;
					addNode({
						id: gapId,
						kind: "gap",
						label: missingProofExit,
						status: "missing-proof-exit",
						note: `adapter=${artifact.adapterId} parser_signal_summary missing_proof=${missingProofExit}`,
					});
					addTask({
						id: gapId,
						parentId: parserSummaryId,
						kind: "gap",
						label: missingProofExit,
						status: "missing-proof-exit",
						evidence: [`missing_proof=${missingProofExit}`, `adapter=${artifact.adapterId}`, `artifact=${path}`],
					});
					addEdge({ from: gapId, to: parserSummaryId, kind: "blocks", label: "missing-proof-exit" });
				}
			}

			if (mission)
				addEdge({ from: `mission:${mission.id}`, to: adapterId, kind: "requires", label: "runtime-adapter" });
			for (const [index, signal] of artifact.parserSignals.entries()) {
				const signalId = `verify:runtime-adapter:${slug(artifact.adapterId)}:${slug(artifactBase)}:${index + 1}:${slug(signal.ruleId)}`;
				const evidenceRank = signal.evidenceRank ?? "unranked";
				addNode({
					id: signalId,
					kind: "verification",
					label: `${signal.ruleId} => ${signal.proofExitSignal}`,
					status: signal.matches.length
						? `rank=${evidenceRank} matches=${signal.matches.length}`
						: `rank=${evidenceRank} no-match`,
					note: signal.matches.slice(0, 4).join(" | ") || "parser signal did not match runner output",
				});
				addTask({
					id: signalId,
					parentId: artifactId,
					kind: "verification",
					label: `${signal.ruleId} => ${signal.proofExitSignal}`,
					status: signal.matches.length
						? `rank=${evidenceRank} matches=${signal.matches.length}`
						: `rank=${evidenceRank} no-match`,
					evidence: [`rank=${evidenceRank}`, ...signal.matches.slice(0, 6)],
				});
				addEdge({ from: signalId, to: artifactId, kind: "verifies", label: `parser:${evidenceRank}` });
				addEdge({
					from: signalId,
					to: parserSummaryId,
					kind: signal.matches.length ? "supports" : "blocks",
					label: signal.matches.length ? "matched-rule" : "no-match",
				});
			}

			if (artifact.killed || (artifact.exitCode !== null && artifact.exitCode !== 0)) {
				gaps.push(
					`runtime adapter failed: ${artifact.adapterId} exit=${artifact.exitCode ?? "null"} killed=${artifact.killed}`,
				);
			}
			if (parserMatchCount === 0) gaps.push(`runtime adapter parser no-match: ${artifact.adapterId}`);
		}

		for (const { path, proof } of proofLoopArtifacts) {
			sourceArtifacts.push(
				path,
				...proof.sourceArtifacts.filter((artifactPath) => existsSync(artifactPath)).slice(0, 8),
			);
			const proofBase = artifactBasename(path);
			const proofId = `proof-loop:${slug(proofBase)}`;
			addNode({
				id: proofId,
				kind: "verification",
				label: `proof_loop ${proof.mode}`,
				status: `verdict=${proof.verdict} executed=${proof.executed.length}`,
				path,
				note: `target=${proof.target ?? "<none>"} max_steps=${proof.maxSteps} replay_steps=${proof.replaySteps}`,
			});
			addTask({
				id: proofId,
				parentId: proof.missionId ? `mission:${proof.missionId}` : mission ? `mission:${mission.id}` : undefined,
				kind: "verification",
				label: `proof_loop ${proof.mode}`,
				status: `verdict=${proof.verdict} executed=${proof.executed.length}`,
				path,
				evidence: [
					`gap_classifier=${proof.gapClassifier.length}`,
					`quick_path=${proof.quickPath.length}`,
					`quick_plan_phases=${proof.quickPlanPhases.length}`,
					`quick_plan_assertions=${proof.quickPlanAssertions.join(" | ") || "none"}`,
					`runtime_adapter_closure=${proof.runtimeAdapterClosure.length}`,
					`next_actions=${proof.nextActions.length}`,
				],
				note: `target=${proof.target ?? "<none>"}`,
			});
			if (mission) addEdge({ from: `mission:${mission.id}`, to: proofId, kind: "verifies", label: "proof-loop" });

			for (const [index, command] of proof.quickPath.slice(0, 10).entries()) {
				const commandId = `command:proof-loop:${slug(proofBase)}:quick:${index + 1}`;
				addNode({
					id: commandId,
					kind: "command",
					label: truncateMiddle(command, 160),
					status: "quick_path",
					note: "proof-loop quick path",
				});
				addTask({
					id: commandId,
					parentId: proofId,
					kind: "command",
					label: truncateMiddle(command, 180),
					status: "quick_path",
					command,
				});
				addEdge({ from: proofId, to: commandId, kind: "suggests", label: "quick_path" });
			}

			for (const [index, row] of proof.runtimeAdapterClosure.slice(0, 12).entries()) {
				const adapterId = /\badapter=([^\s]+)/.exec(row)?.[1] ?? `adapter-${index + 1}`;
				const status = /\bstatus=([^\s]+)/.exec(row)?.[1] ?? "unknown";
				const commands = /\bcommands=(.*?)(?:\s+evidence=|$)/.exec(row)?.[1]?.trim() ?? "";
				const closureId = `verify:proof-loop-runtime-closure:${slug(proofBase)}:${slug(adapterId)}:${index + 1}`;
				addNode({
					id: closureId,
					kind: "verification",
					label: `runtime_adapter_closure ${adapterId}`,
					status,
					path,
					note: row,
				});
				addTask({
					id: closureId,
					parentId: proofId,
					kind: "verification",
					label: `runtime_adapter_closure ${adapterId}`,
					status,
					command: commands && commands !== "<none>" ? commands : undefined,
					path,
					evidence: [row],
				});
				addEdge({
					from: closureId,
					to: proofId,
					kind: status === "needs_adapter_rerun" ? "blocks" : "verifies",
					label: "runtime-adapter-closure",
				});
			}

			for (const step of proof.steps.slice(0, 18)) {
				const stepId = `command:proof-loop:${slug(proofBase)}:${slug(step.id)}`;
				addNode({
					id: stepId,
					kind: "command",
					label: truncateMiddle(step.command, 160),
					status: `${step.phase}/${step.status}`,
					note: step.reason,
				});
				addTask({
					id: stepId,
					parentId: proofId,
					kind: "command",
					label: truncateMiddle(step.command, 180),
					status: `${step.phase}/${step.status}`,
					command: step.command,
					evidence: step.sourceArtifacts.slice(0, 4),
					note: step.reason,
				});
				addEdge({
					from: stepId,
					to: proofId,
					kind: step.status === "blocked" ? "blocks" : step.status === "done" ? "verifies" : "requires",
					label: `proof-loop:${step.phase}`,
				});
				for (const lineage of runtimeArtifactsForCommand(step.command).slice(0, 4)) {
					const lineageId = `artifact:proof-loop-runtime-lineage:${slug(proofBase)}:${slug(step.id)}:${slug(lineage.artifactBase)}`;
					addNode({
						id: lineageId,
						kind: "artifact",
						label: lineage.artifactBase,
						status: `runtime-adapter-lineage ${lineage.adapterId}`,
						path: lineage.path,
						note: `target=${lineage.target || "<none>"}`,
					});
					addTask({
						id: lineageId,
						parentId: stepId,
						kind: "artifact",
						label: lineage.artifactBase,
						status: `runtime-adapter-lineage ${lineage.adapterId}`,
						path: lineage.path,
						evidence: [
							`adapter=${lineage.adapterId}`,
							`target=${lineage.target || "<none>"}`,
							`runtime_artifact=${lineage.path}`,
						],
					});
					addEdge({ from: stepId, to: lineageId, kind: "produces", label: "runtime-adapter-lineage" });
					addEdge({ from: lineageId, to: lineage.artifactId, kind: "supports", label: "runtime-adapter-json" });
					addEdge({ from: lineage.artifactId, to: proofId, kind: "verifies", label: "runtime-adapter-artifact" });
				}
			}

			for (const execution of proof.executed.slice(0, 12)) {
				const executionId = `run:proof-loop:${slug(proofBase)}:${slug(execution.stepId)}`;
				const outputText = execution.output.replace(/\s+/g, " ");
				const outputHash = sha256Text(execution.output);
				const outputId = `artifact:proof-loop-output:${slug(proofBase)}:${slug(execution.stepId)}`;
				addNode({
					id: executionId,
					kind: "run",
					label: truncateMiddle(execution.command, 160),
					status: execution.status,
					note: truncateMiddle(outputText, 260),
				});
				addTask({
					id: executionId,
					parentId: proofId,
					kind: "run",
					label: truncateMiddle(execution.command, 180),
					status: execution.status,
					command: execution.command,
					evidence: [`output_sha256=${outputHash}`, `output=${truncateMiddle(outputText, 260)}`],
				});
				addNode({
					id: outputId,
					kind: "artifact",
					label: `proof-loop-output sha256=${outputHash.slice(0, 16)}`,
					status: "proof-loop-output-hash",
					path,
					note: truncateMiddle(outputText, 260),
				});
				addTask({
					id: outputId,
					parentId: executionId,
					kind: "artifact",
					label: `proof-loop-output sha256=${outputHash.slice(0, 16)}`,
					status: "proof-loop-output-hash",
					path,
					evidence: [`output_sha256=${outputHash}`],
				});
				addEdge({ from: executionId, to: outputId, kind: "produces", label: "proof-loop-output" });
				addEdge({
					from: outputId,
					to: proofId,
					kind: execution.status === "blocked" ? "blocks" : "verifies",
					label: "executed-output-hash",
				});
				for (const lineage of runtimeArtifactsForCommand(execution.command).slice(0, 4)) {
					const lineageId = `artifact:proof-loop-runtime-execution:${slug(proofBase)}:${slug(execution.stepId)}:${slug(lineage.artifactBase)}`;
					addNode({
						id: lineageId,
						kind: "artifact",
						label: lineage.artifactBase,
						status: `runtime-adapter-lineage ${lineage.adapterId}`,
						path: lineage.path,
						note: `executed=${execution.status} target=${lineage.target || "<none>"}`,
					});
					addTask({
						id: lineageId,
						parentId: executionId,
						kind: "artifact",
						label: lineage.artifactBase,
						status: `runtime-adapter-lineage ${lineage.adapterId}`,
						path: lineage.path,
						evidence: [
							`adapter=${lineage.adapterId}`,
							`target=${lineage.target || "<none>"}`,
							`runtime_artifact=${lineage.path}`,
							`proof_execution=${execution.status}`,
						],
					});
					addEdge({ from: executionId, to: lineageId, kind: "produces", label: "runtime-adapter-lineage" });
					addEdge({ from: lineageId, to: lineage.artifactId, kind: "supports", label: "runtime-adapter-json" });
					addEdge({ from: lineage.artifactId, to: proofId, kind: "verifies", label: "runtime-adapter-artifact" });
				}
			}

			for (const [index, row] of proof.gapClassifier.slice(0, 10).entries()) {
				const gapId = `gap:proof-loop:${slug(proofBase)}:${index + 1}`;
				addNode({
					id: gapId,
					kind: "gap",
					label: truncateMiddle(row, 160),
					status: "proof-loop-gap",
					note: row,
				});
				addTask({
					id: gapId,
					parentId: proofId,
					kind: "gap",
					label: truncateMiddle(row, 180),
					status: "proof-loop-gap",
					evidence: [path],
				});
				addEdge({ from: gapId, to: proofId, kind: "blocks", label: "gap_classifier" });
				gaps.push(`proof loop gap: ${truncateMiddle(row, 180)}`);
			}
			if (proof.verdict !== "ready") gaps.push(`proof loop verdict ${proof.verdict}: ${path}`);
		}

		for (const { path, swarm } of swarmArtifacts) {
			sourceArtifacts.push(
				path,
				...swarm.sourceArtifacts.filter((artifactPath) => existsSync(artifactPath)).slice(0, 8),
				...[swarm.workerRetryHandoffClosurePath, swarm.workerRetryHandoffMergeSummaryPath]
					.filter((artifactPath): artifactPath is string => Boolean(artifactPath && existsSync(artifactPath)))
					.slice(0, 2),
			);
			const swarmBase = artifactBasename(path);
			const swarmId = `swarm:${slug(swarmBase)}`;
			const workerClosures = swarm.workerRetryHandoffMergeSummary?.workerClosures ?? [];
			addNode({
				id: swarmId,
				kind: "verification",
				label: `re_swarm ${swarm.mode}`,
				status: `workers=${swarm.workers.length} closures=${workerClosures.length} retry=${swarm.workerRetryHandoffMergeSummaryStatus ?? "missing"}`,
				path,
				note: `target=${swarm.target ?? "<none>"} retry_queue=${swarm.retryQueue.length} blocked=${swarm.blocked.length}`,
			});
			addTask({
				id: swarmId,
				parentId: swarm.missionId ? `mission:${swarm.missionId}` : mission ? `mission:${mission.id}` : undefined,
				kind: "verification",
				label: `re_swarm ${swarm.mode}`,
				status: `workers=${swarm.workers.length} closures=${workerClosures.length}`,
				path,
				evidence: [
					`retry_handoff_closure=${swarm.workerRetryHandoffClosureStatus ?? "missing"}`,
					`retry_handoff_merge_summary=${swarm.workerRetryHandoffMergeSummaryStatus ?? "missing"}`,
					`retry_budget_visible=${swarm.workerRetryHandoffMergeSummary?.assertions.retryBudgetVisible ? "pass" : "fail"}`,
					`source_artifacts_preserved=${swarm.workerRetryHandoffMergeSummary?.assertions.sourceArtifactsPreserved ? "pass" : "fail"}`,
					`next_actions=${swarm.workerRetryHandoffMergeSummary?.nextActions.length ?? 0}`,
				],
			});
			if (mission)
				addEdge({ from: `mission:${mission.id}`, to: swarmId, kind: "verifies", label: "swarm-worker-closure" });
			for (const [index, closure] of workerClosures.slice(0, 18).entries()) {
				const closureId = `verify:swarm-worker-closure:${slug(swarmBase)}:${slug(closure.workerId)}:${index + 1}`;
				const nextId = `command:swarm-worker-closure:${slug(swarmBase)}:${slug(closure.workerId)}:${index + 1}`;
				const closing =
					closure.closure === "passed" ||
					closure.closure === "handoff_recovered" ||
					closure.closure === "exhausted_escalated";
				addNode({
					id: closureId,
					kind: "verification",
					label: `worker_retry_handoff_closure ${closure.workerId}`,
					status: closure.closure,
					path,
					note: closure.summary,
				});
				addTask({
					id: closureId,
					parentId: swarmId,
					kind: "verification",
					label: `worker_retry_handoff_closure ${closure.workerId}`,
					status: closure.closure,
					command: closure.nextAction,
					path,
					evidence: [
						closure.summary,
						`attempt=${closure.attempt}/${closure.maxAttempts}`,
						`retry_remaining=${closure.retryRemaining}`,
						`timed_out=${closure.timedOut}`,
						`next=${closure.nextAction}`,
						...closure.evidenceRefs.slice(0, 5),
					],
				});
				addNode({
					id: nextId,
					kind: "command",
					label: truncateMiddle(closure.nextAction, 160),
					status: "worker-closure-next",
					note: `worker=${closure.workerId} closure=${closure.closure}`,
				});
				addTask({
					id: nextId,
					parentId: closureId,
					kind: "command",
					label: truncateMiddle(closure.nextAction, 180),
					status: "worker-closure-next",
					command: closure.nextAction,
					evidence: closure.evidenceRefs.slice(0, 4),
				});
				addEdge({
					from: closureId,
					to: swarmId,
					kind: closing ? "verifies" : "blocks",
					label: "worker-retry-handoff-closure",
				});
				addEdge({ from: swarmId, to: nextId, kind: "suggests", label: "worker-closure-next" });
				addEdge({ from: nextId, to: closureId, kind: "supports", label: "closure-action" });
				if (!closing) {
					gaps.push(
						`swarm worker closure ${closure.closure}: worker=${closure.workerId} retry_state=${closure.retryState} next=${closure.nextAction}`,
					);
				}
			}
			for (const error of [
				...(swarm.workerRetryHandoffClosureErrors ?? []),
				...(swarm.workerRetryHandoffMergeSummaryErrors ?? []),
			].slice(0, 10)) {
				gaps.push(`swarm retry handoff error: ${error}`);
			}
		}

		for (const node of evidenceLedgerGraphNodes(14, { missionId: mission?.id })) {
			addNode(node);
			if (mission)
				addEdge({ from: `mission:${mission.id}`, to: node.id, kind: "evidences", label: `P${node.priority}` });
		}
		const openEvidenceHypotheses: string[] = [];
		for (const record of parseEvidenceLedgerTaskRecords()) {
			const parentId = mission ? `mission:${mission.id}` : undefined;
			let commandId: string | undefined;
			let commandOutputId: string | undefined;
			addTask({
				id: record.evidenceId,
				parentId,
				kind: "evidence",
				label: record.title,
				status: record.verdict ?? `${record.kind}/P${record.priority}`,
				path: record.path,
				evidence: [record.hypothesis, record.prediction, record.observation, record.fact, record.confidence]
					.filter((item): item is string => Boolean(item))
					.slice(0, 5),
				note: record.timestamp,
			});
			if (record.command) {
				commandId = `command:${record.index}:${slug(record.command)}`;
				addNode({
					id: commandId,
					kind: "command",
					label: truncateMiddle(record.command, 160),
					status: "recorded",
					note: record.title,
				});
				addTask({
					id: commandId,
					parentId: record.evidenceId,
					kind: "command",
					label: truncateMiddle(record.command, 180),
					status: "recorded",
					command: record.command,
				});
				addEdge({ from: commandId, to: record.evidenceId, kind: "produces", label: "stdout/fact" });
				if (record.fact || record.hash || record.verify) {
					const outputSurface = [record.fact, record.hash, record.verify, record.confidence]
						.filter((item): item is string => Boolean(item))
						.join("\n");
					const outputHash = record.hash ?? sha256Text(outputSurface);
					commandOutputId = `artifact:command-output:${record.index}:${slug(record.title)}`;
					addNode({
						id: commandOutputId,
						kind: "artifact",
						label: `evidence-output sha256=${outputHash.slice(0, 16)}`,
						status: "evidence-output-hash",
						note: truncateMiddle(outputSurface.replace(/\s+/g, " "), 260),
					});
					addTask({
						id: commandOutputId,
						parentId: commandId,
						kind: "artifact",
						label: `evidence-output sha256=${outputHash.slice(0, 16)}`,
						status: "evidence-output-hash",
						evidence: [
							`output_sha256=${outputHash}`,
							record.fact ? `fact=${truncateMiddle(record.fact, 260)}` : undefined,
							record.confidence ? `confidence=${record.confidence}` : undefined,
						].filter((item): item is string => Boolean(item)),
					});
					addEdge({ from: commandId, to: commandOutputId, kind: "produces", label: "evidence-output-hash" });
					addEdge({ from: commandOutputId, to: record.evidenceId, kind: "supports", label: "command-output" });
				}
			}
			if (record.path) {
				const artifactId = `artifact:${record.index}:${slug(artifactBasename(record.path))}`;
				addNode({
					id: artifactId,
					kind: "artifact",
					label: artifactBasename(record.path),
					status: record.hash ? "hashed" : "referenced",
					path: record.path,
					note: record.hash,
				});
				addTask({
					id: artifactId,
					parentId: record.evidenceId,
					kind: "artifact",
					label: artifactBasename(record.path),
					status: record.hash ? "hashed" : "referenced",
					path: record.path,
					note: record.hash,
				});
				addEdge({ from: record.evidenceId, to: artifactId, kind: "produces", label: "artifact" });
				sourceArtifacts.push(record.path);
			}
			const shouldAddHypothesis = Boolean(
				record.hypothesis ||
					record.claimId ||
					(record.fact &&
						(evidenceRecordHasHypothesisSignal(record) ||
							evidenceRecordHasCounterSignal(record) ||
							record.command ||
							record.path)),
			);
			const priorHypotheses = openEvidenceHypotheses.slice(-4);
			if (shouldAddHypothesis) {
				const hypothesisId = record.claimId
					? `hypothesis:${slug(record.claimId)}`
					: `hypothesis:${record.index}:${slug(record.title)}`;
				const hypothesisLabel = record.hypothesis ?? record.fact ?? record.title;
				addNode({
					id: hypothesisId,
					kind: "hypothesis",
					label: truncateMiddle(hypothesisLabel, 160),
					status: record.verdict ?? record.confidence ?? "proposed",
					note: record.prediction ?? record.title,
				});
				addTask({
					id: hypothesisId,
					parentId: record.evidenceId,
					kind: "hypothesis",
					label: truncateMiddle(hypothesisLabel, 180),
					status: record.verdict ?? record.confidence ?? "proposed",
					evidence: [record.prediction, record.observation, record.title].filter((item): item is string =>
						Boolean(item),
					),
				});
				addEdge({
					from: record.evidenceId,
					to: hypothesisId,
					kind: record.verdict === "contradicted" ? "refutes" : "supports",
					label: `${record.verdict ?? "evidence"}/P${record.priority}`,
				});
				if (commandOutputId)
					addEdge({
						from: commandOutputId,
						to: hypothesisId,
						kind: "supports",
						label: "command-output-hypothesis",
					});
				if (record.verify) {
					const verifyId = `verify:${record.index}:${slug(record.verify)}`;
					addNode({
						id: verifyId,
						kind: "verification",
						label: truncateMiddle(record.verify, 160),
						status: record.verdict === "proved" ? "passed" : "required",
						note: record.title,
					});
					addTask({
						id: verifyId,
						parentId: hypothesisId,
						kind: "verification",
						label: truncateMiddle(record.verify, 180),
						status: record.verdict === "proved" ? "passed" : "required",
						command: record.verify,
					});
					addEdge({ from: verifyId, to: hypothesisId, kind: "verifies", label: "verify command" });
				}
				if (record.verdict !== "proved" && record.verdict !== "contradicted") {
					openEvidenceHypotheses.push(hypothesisId);
				}
			}
			if (evidenceRecordHasCounterSignal(record)) {
				const counterId = `counter:${record.index}:${slug(record.title)}`;
				addNode({
					id: counterId,
					kind: "counter_evidence",
					label: truncateMiddle(record.counterexample ?? record.observation ?? record.fact ?? record.title, 160),
					status: "present",
					note: record.confidence,
				});
				addTask({
					id: counterId,
					parentId: record.evidenceId,
					kind: "counter_evidence",
					label: truncateMiddle(record.counterexample ?? record.observation ?? record.fact ?? record.title, 180),
					status: "present",
					evidence: [record.title, record.verify].filter((item): item is string => Boolean(item)),
				});
				const hypothesisId = record.claimId
					? `hypothesis:${slug(record.claimId)}`
					: `hypothesis:${record.index}:${slug(record.title)}`;
				addEdge({ from: counterId, to: hypothesisId, kind: "refutes", label: "counter-evidence" });
				for (const priorHypothesisId of priorHypotheses) {
					addEdge({
						from: counterId,
						to: priorHypothesisId,
						kind: "refutes",
						label: "counter-evidence-prior-hypothesis",
					});
				}
			}
		}

		if (mission) {
			const recommended = recommendedToolsForRoute(mission.route).slice(0, 16);
			const missing = recommended
				.map((tool) => createBootstrapPlan([tool])[0])
				.filter((item): item is AttackGraphBootstrapPlan => Boolean(item) && item.known && !item.present)
				.map((item) => item.tool);
			addNode({
				id: "tool:recommended",
				kind: "tool",
				label: recommended.join(", ") || "none",
				status: missing.length ? `missing:${missing.join(",")}` : "ready",
			});
			addEdge({ from: `mission:${mission.id}`, to: "tool:recommended", kind: "requires", label: "tool-index" });
			if (missing.length > 0) gaps.push(`missing recommended tools: ${missing.join(", ")}`);
		}

		const nextActions = attackGraphNextActions(mission, map);
		for (const [index, action] of nextActions.entries()) {
			const id = `next:${index + 1}`;
			addNode({ id, kind: "next", label: action, status: "queued" });
			addTask({
				id,
				parentId: mission ? `mission:${mission.id}` : undefined,
				kind: "next",
				label: action,
				status: "queued",
				command: action,
			});
			if (mission) addEdge({ from: `mission:${mission.id}`, to: id, kind: "suggests" });
		}

		return {
			timestamp,
			missionId: mission?.id,
			route: mission?.route.domain,
			target:
				map?.target ??
				runtimeAdapterArtifacts.find((item) => item.artifact.target)?.artifact.target ??
				swarmArtifacts.find((item) => item.swarm.target)?.swarm.target,
			nodes: [...nodes.values()],
			edges,
			taskTree: prioritizeAttackGraphTaskTree(taskTree, 160),
			criticalPath: criticalPath.length ? criticalPath : ["no mission route selected"],
			gaps: Array.from(new Set(gaps)).slice(0, 24),
			nextActions,
			sourceArtifacts: Array.from(new Set(sourceArtifacts)).slice(0, 24),
		};
	}

	return { buildAttackGraph };
}

export type AttackGraphRuntime = ReturnType<typeof createAttackGraphRuntime>;
