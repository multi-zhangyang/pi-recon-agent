export type AttackGraphNode = {
	id: string;
	kind:
		| "mission"
		| "route"
		| "lane"
		| "checkpoint"
		| "map"
		| "run"
		| "evidence"
		| "command"
		| "artifact"
		| "hypothesis"
		| "counter_evidence"
		| "verification"
		| "tool"
		| "target_profile"
		| "parser_summary"
		| "gap"
		| "next";
	label: string;
	status?: string;
	priority?: number;
	path?: string;
	note?: string;
};

export type AttackGraphEdge = {
	from: string;
	to: string;
	kind:
		| "owns"
		| "orders"
		| "blocks"
		| "evidences"
		| "requires"
		| "suggests"
		| "updates"
		| "supports"
		| "refutes"
		| "produces"
		| "verifies";
	label?: string;
};

export type AttackGraphTaskTreeNode = {
	id: string;
	parentId?: string;
	kind: AttackGraphNode["kind"];
	label: string;
	status?: string;
	command?: string;
	path?: string;
	evidence?: string[];
	note?: string;
};

export type AttackGraphArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	nodes: AttackGraphNode[];
	edges: AttackGraphEdge[];
	taskTree: AttackGraphTaskTreeNode[];
	criticalPath: string[];
	gaps: string[];
	nextActions: string[];
	sourceArtifacts: string[];
};

export type ExploitChainNodeStatus = "done" | "ready" | "blocked" | "pending";

export type ExploitChainNode = {
	id: string;
	stage: string;
	objective: string;
	status: ExploitChainNodeStatus;
	evidence: string[];
	commands: string[];
	gaps: string[];
	next: string[];
};

export type ExploitChainEdge = {
	from: string;
	to: string;
	kind: "requires" | "proves" | "feeds" | "verifies" | "stabilizes";
	label?: string;
};

export type ExploitChainArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	mode: "plan" | "compose";
	nodes: ExploitChainNode[];
	edges: ExploitChainEdge[];
	proofPath: string[];
	exploitPath: string[];
	evidenceGaps: string[];
	operatorFeedback: string[];
	operatorFeedbackQueue: string[];
	replayCommands: string[];
	operatorQueue: string[];
	nextActions: string[];
	sourceArtifacts: string[];
	confidence: "strong" | "partial" | "scaffold";
};

function taskTreeRetentionScore(node: AttackGraphTaskTreeNode): number {
	const status = node.status ?? "";
	const text = `${node.kind}\n${node.label}\n${status}\n${node.note ?? ""}\n${node.evidence?.join("\n") ?? ""}`;
	let score =
		node.kind === "mission" || node.kind === "route"
			? 1_000
			: node.kind === "gap" || node.kind === "counter_evidence"
				? 950
				: node.kind === "verification" || node.kind === "parser_summary"
					? 850
					: node.kind === "hypothesis"
						? 780
						: node.kind === "artifact"
							? 720
							: node.kind === "evidence"
								? 680
								: node.kind === "command" || node.kind === "run"
									? 620
									: node.kind === "target_profile"
										? 560
										: node.kind === "next"
											? 520
											: 100;
	if (/blocked|missing|failed|failure|killed|no-match|counter|refut|contradict|gap/i.test(text)) score += 240;
	if (/sha256|hash|runtime-output|proof-loop-output|parser_signal_summary|proof_exit|missing_proof/i.test(text))
		score += 160;
	if (/quick_path|re_proof_loop|re_verifier|re_compiler|re_replayer|re_autofix/i.test(text)) score += 90;
	if (node.path) score += 50;
	if (node.command) score += 40;
	if (node.evidence?.length) score += Math.min(80, node.evidence.length * 12);
	if (!node.parentId) score += 30;
	return score;
}

export function prioritizeAttackGraphTaskTree(
	nodes: AttackGraphTaskTreeNode[],
	limit = 160,
): AttackGraphTaskTreeNode[] {
	if (limit <= 0) return [];
	if (nodes.length <= limit) return [...nodes];

	const byId = new Map<string, number>();
	for (const [index, node] of nodes.entries()) {
		if (!byId.has(node.id)) byId.set(node.id, index);
	}

	const selected = new Set<number>();
	const ancestorIndexes = (node: AttackGraphTaskTreeNode): number[] => {
		const chain: number[] = [];
		const seen = new Set<string>();
		let parentId = node.parentId;
		while (parentId && !seen.has(parentId)) {
			seen.add(parentId);
			const parentIndex = byId.get(parentId);
			if (parentIndex === undefined) break;
			chain.push(parentIndex);
			parentId = nodes[parentIndex]?.parentId;
		}
		return chain.reverse();
	};
	const add = (index: number): boolean => {
		if (selected.has(index)) return true;
		if (selected.size >= limit) return false;
		selected.add(index);
		return true;
	};
	const addWithParents = (index: number): void => {
		for (const parentIndex of ancestorIndexes(nodes[index]!)) {
			if (!add(parentIndex)) return;
		}
		add(index);
	};

	const ranked = nodes
		.map((node, index) => ({ index, score: taskTreeRetentionScore(node) }))
		.sort((left, right) => right.score - left.score || left.index - right.index);

	for (const { index } of ranked) {
		if (selected.size >= limit) break;
		addWithParents(index);
	}

	return nodes.filter((_node, index) => selected.has(index));
}

function truncateMiddle(text: string, limit: number): string {
	if (text.length <= limit) return text;
	const head = Math.floor(limit * 0.55);
	const tail = Math.floor(limit * 0.35);
	return `${text.slice(0, head)}\n...<truncated ${text.length - limit} chars>...\n${text.slice(-tail)}`;
}

export function createExploitChainNode(params: {
	id: string;
	stage: string;
	objective: string;
	evidence: string[];
	commands: string[];
	gaps: string[];
	previousDone?: boolean;
	next?: string[];
}): ExploitChainNode {
	const status: ExploitChainNodeStatus =
		params.evidence.length > 0
			? "done"
			: params.previousDone === false
				? "pending"
				: params.commands.length
					? "ready"
					: "blocked";
	return {
		id: params.id,
		stage: params.stage,
		objective: params.objective,
		status,
		evidence: params.evidence.slice(0, 10),
		commands: params.commands.slice(0, 10),
		gaps: params.gaps.slice(0, 10),
		next: (params.next ?? params.commands).slice(0, 10),
	};
}

export function formatAttackGraph(graph: AttackGraphArtifact, path?: string): string {
	return [
		"attack_graph:",
		path ? `graph_artifact: ${path}` : undefined,
		`timestamp: ${graph.timestamp}`,
		`mission_id: ${graph.missionId ?? "none"}`,
		`route: ${graph.route ?? "none"}`,
		`target: ${graph.target ?? "<none>"}`,
		`nodes: ${graph.nodes.length}`,
		`edges: ${graph.edges.length}`,
		`task_tree_nodes: ${graph.taskTree.length}`,
		"critical_path:",
		...graph.criticalPath.map((item) => `- ${item}`),
		"gaps:",
		...(graph.gaps.length ? graph.gaps.map((item) => `- ${item}`) : ["- none"]),
		"operator_next_actions:",
		...(graph.nextActions.length ? graph.nextActions.map((item) => `- ${item}`) : ["- none"]),
		"source_artifacts:",
		...(graph.sourceArtifacts.length ? graph.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
	]
		.filter(Boolean)
		.join("\n");
}

export function formatAttackGraphArtifactMarkdown(
	graph: AttackGraphArtifact,
	options: { truncate?: (text: string, limit: number) => string } = {},
): string {
	const truncate = options.truncate ?? truncateMiddle;
	return [
		"# REPI Attack Graph Artifact",
		"",
		formatAttackGraph(graph),
		"",
		"## Nodes",
		"",
		...graph.nodes.map(
			(node) =>
				`- ${node.id} [${node.kind}] ${node.label}${node.status ? ` status=${node.status}` : ""}${node.path ? ` path=${node.path}` : ""}${node.note ? ` note=${truncate(node.note, 220)}` : ""}`,
		),
		"",
		"## Edges",
		"",
		...graph.edges.map((edge) => `- ${edge.from} --${edge.kind}${edge.label ? `:${edge.label}` : ""}--> ${edge.to}`),
		"",
		"## Task Tree",
		"",
		...graph.taskTree.map(
			(node) =>
				`- ${node.parentId ? `${node.parentId} -> ` : ""}${node.id} [${node.kind}] ${node.label}${node.status ? ` status=${node.status}` : ""}${node.command ? ` command=${truncate(node.command, 180)}` : ""}${node.path ? ` path=${node.path}` : ""}${node.evidence?.length ? ` evidence=${truncate(node.evidence.slice(0, 4).join(" | "), 260)}` : ""}${node.note ? ` note=${truncate(node.note, 220)}` : ""}`,
		),
		"",
		"## JSON",
		"",
		"```json",
		JSON.stringify(graph, null, 2),
		"```",
		"",
	].join("\n");
}

export function formatExploitChain(chain: ExploitChainArtifact, path?: string): string {
	return [
		"exploit_chain:",
		path ? `chain_artifact: ${path}` : undefined,
		`timestamp: ${chain.timestamp}`,
		`mode: ${chain.mode}`,
		`mission_id: ${chain.missionId ?? "none"}`,
		`route: ${chain.route ?? "none"}`,
		`target: ${chain.target ?? "<none>"}`,
		`confidence: ${chain.confidence}`,
		"chain_nodes:",
		...(chain.nodes.length
			? chain.nodes.map(
					(node) =>
						`- ${node.id} [${node.status}] stage=${node.stage} evidence=${node.evidence.length} gaps=${node.gaps.length} objective=${node.objective}`,
				)
			: ["- none"]),
		"chain_edges:",
		...(chain.edges.length
			? chain.edges.map((edge) => `- ${edge.from} -> ${edge.to} [${edge.kind}] ${edge.label ?? ""}`)
			: ["- none"]),
		"proof_path:",
		...(chain.proofPath.length ? chain.proofPath.map((item) => `- ${item}`) : ["- none"]),
		"exploit_path:",
		...(chain.exploitPath.length ? chain.exploitPath.map((item) => `- ${item}`) : ["- none"]),
		"evidence_gaps:",
		...(chain.evidenceGaps.length ? chain.evidenceGaps.map((item) => `- ${item}`) : ["- none"]),
		"operator_feedback:",
		...(chain.operatorFeedback.length ? chain.operatorFeedback.map((item) => `- ${item}`) : ["- none"]),
		"operator_feedback_queue:",
		...(chain.operatorFeedbackQueue.length ? chain.operatorFeedbackQueue.map((item) => `- ${item}`) : ["- none"]),
		"replay_commands:",
		...(chain.replayCommands.length ? chain.replayCommands.map((item) => `- ${item}`) : ["- none"]),
		"operator_queue:",
		...(chain.operatorQueue.length ? chain.operatorQueue.map((item) => `- ${item}`) : ["- none"]),
		"chain_next_actions:",
		...(chain.nextActions.length ? chain.nextActions.map((item) => `- ${item}`) : ["- re_map <target> 2"]),
		`next_chain_command: ${chain.mode === "compose" ? "re_verifier matrix" : `re_chain compose ${chain.target ?? "<target>"}`}`,
		"source_artifacts:",
		...(chain.sourceArtifacts.length ? chain.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
	]
		.filter(Boolean)
		.join("\n");
}

export function formatExploitChainArtifactMarkdown(chain: ExploitChainArtifact): string {
	return [
		"# REPI Exploit Chain Artifact",
		"",
		formatExploitChain(chain),
		"",
		"```json",
		JSON.stringify(chain, null, 2),
		"```",
		"",
	].join("\n");
}
