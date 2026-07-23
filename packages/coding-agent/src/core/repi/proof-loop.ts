import { truncateMiddle, uniqueNonEmpty } from "./text.ts";

export type RepiProofLoopDelegateWorker =
	| "web-authz"
	| "identity"
	| "cloud"
	| "mobile-runtime"
	| "native-runtime"
	| "pwn-exploit"
	| "firmware-dfir"
	| "agentsec"
	| "malware"
	| "reporting"
	| "general";

export type RepiProofLoopGapSource =
	| "failure_signature"
	| "operator_feedback"
	| "verifier"
	| "compiler"
	| "replayer"
	| "autofix"
	| "checkpoint"
	| "attack_graph"
	| "artifact";

export type RepiProofLoopGapItem = {
	source: RepiProofLoopGapSource;
	text: string;
	worker: RepiProofLoopDelegateWorker;
	sourceArtifacts: string[];
};

export type RepiProofLoopGapClass =
	| "missing_artifact"
	| "contradiction"
	| "replay_failure"
	| "tool_or_dependency"
	| "target_or_state"
	| "runtime_adapter_gap"
	| "proof_spine_seed"
	| "weak_evidence"
	| "timeout_or_flake"
	| "unknown";

export type RepiProofLoopGapClassification = {
	klass: RepiProofLoopGapClass;
	priority: number;
	action: string;
};

export type RepiProofLoopQuickPlanPhaseV1 = {
	phase:
		| "attack_graph_refresh"
		| "toolchain_repair"
		| "target_state_refresh"
		| "runtime_adapter_frontload"
		| "proof_spine"
		| "replay_repair"
		| "contradiction_repair"
		| "delegate_unknown"
		| "final_loop";
	reason: string;
	classes: RepiProofLoopGapClass[];
	commands: string[];
	evidenceRefs: string[];
};

export type RepiProofLoopQuickPlanV1 = {
	kind: "ProofLoopQuickPlanV1";
	schemaVersion: 1;
	target: string;
	classOrder: Array<{
		klass: RepiProofLoopGapClass;
		priority: number;
		count: number;
		workers: RepiProofLoopDelegateWorker[];
		sources: RepiProofLoopGapSource[];
	}>;
	phases: RepiProofLoopQuickPlanPhaseV1[];
	commands: string[];
	omittedCommands: string[];
	finalLoopCommand: string;
	assertions: {
		bounded: boolean;
		deduplicated: boolean;
		runtimeAdapterBeforeReplay: boolean;
		autofixApplyBeforeFinalReplay: boolean;
		finalLoopLast: boolean;
	};
};

export type RepiProofLoopRuntimeAdapterClosureRowV1 = {
	kind: "ProofLoopRuntimeAdapterClosureRowV1";
	schemaVersion: 1;
	adapterId: string;
	status: "needs_adapter_rerun" | "proof_spine_ready";
	missingProofSignals: string[];
	matchedProofSignals: string[];
	sourceArtifacts: string[];
	commands: string[];
};

type RepiProofLoopMissionContext = {
	route?: { domain?: string };
	task?: string;
	operatorDirective?: string;
};

export function repiProofLoopWorkerForText(
	text: string,
	mission?: RepiProofLoopMissionContext,
): RepiProofLoopDelegateWorker {
	const haystack = `${mission?.route?.domain ?? ""}\n${mission?.operatorDirective ?? mission?.task ?? ""}\n${text}`;
	if (
		/web-authz|web|api|http|xhr|fetch|websocket|graphql|jwt|cookie|session|idor|bola|authz|csrf|cors/i.test(haystack)
	)
		return "web-authz";
	if (/mobile|android|ios|apk|ipa|frida|objection|smali|jni|objc|swift|emulator/i.test(haystack))
		return "mobile-runtime";
	if (/cloud|container|docker|k8s|kubernetes|metadata|serviceaccount|iam|rbac|privilege/i.test(haystack))
		return "cloud";
	if (/credential|principal|kerberos|ldap|ntlm|ticket|hash|identity|active directory|bloodhound/i.test(haystack))
		return "identity";
	if (/firmware|pcap|dfir|forensic|rootfs|tshark|binwalk|extract|filesystem|emulate|timeline|decode/i.test(haystack))
		return "firmware-dfir";
	if (/agentsec|agent|prompt|tool-boundary|memory|injection|delegation|mcp|rag|sub-agent/i.test(haystack))
		return "agentsec";
	if (/malware|ioc|yara|capa|floss|static-config|behavior|c2/i.test(haystack)) return "malware";
	if (/pwn|exploit|primitive|mitigation|rop|heap|overflow|shellcode|pwntools|crash|leak|gadget/i.test(haystack))
		return "pwn-exploit";
	if (
		/native|elf|pe|macho|binary|gdb|lldb|checksec|r2|radare|ghidra|ida|symbol|breakpoint|loader|libc/i.test(haystack)
	)
		return "native-runtime";
	if (/report|complete|writeup|compiler|final/i.test(haystack)) return "reporting";
	return "general";
}

export function classifyRepiProofLoopGap(item: RepiProofLoopGapItem): RepiProofLoopGapClassification {
	const text = `${item.source} ${item.text}`;
	if (/contradiction|counter[_ -]?evidence|refute|conflict/i.test(text)) {
		return { klass: "contradiction", priority: 1, action: "re_supervisor repair -> re_verifier matrix" };
	}
	if (/proof_spine_seed|runtime adapter proof[- ]exit complete|proof[- ]exit complete/i.test(text)) {
		return {
			klass: "proof_spine_seed",
			priority: 2,
			action: "re_verifier matrix -> re_compiler draft -> re_replayer run",
		};
	}
	if (
		/runtime adapter|re_runtime_adapter|missing-proof-exit|missing proof|parser_signal_summary|parser no-match/i.test(
			text,
		)
	) {
		return {
			klass: "runtime_adapter_gap",
			priority: 1,
			action: "re_runtime_adapter run -> re_verifier matrix -> re_compiler draft -> re_replayer run",
		};
	}
	if (
		/proof_spine_seed|binary mitigation map|native-mitigation|pwn-mitigation|mitigation map matched|runtime proof spine/i.test(
			text,
		)
	) {
		return {
			klass: "proof_spine_seed",
			priority: 2,
			action: "re_verifier matrix -> re_compiler draft -> re_replayer run",
		};
	}
	if (
		/command not found|not recognized|No such file|cannot stat|cannot access|ModuleNotFoundError|ImportError|Cannot find module|ERR_MODULE_NOT_FOUND|permission denied|EACCES|ENOENT|missing tool|dependency|bootstrap/i.test(
			text,
		)
	) {
		return { klass: "tool_or_dependency", priority: 1, action: "re_bootstrap plan -> re_operator dispatch" };
	}
	if (/timeout|timed out|flake|unstable/i.test(text)) {
		return {
			klass: "timeout_or_flake",
			priority: 1,
			action: "re_autofix plan/apply with bounded timeout -> re_replayer run",
		};
	}
	if (/nonzero|exit=|failed:|blocked:|replay.*failed|stderr=/i.test(text)) {
		return { klass: "replay_failure", priority: 2, action: "re_autofix plan/apply -> re_replayer run" };
	}
	if (
		/target mismatch|unresolved target|target placeholder|state|session|cookie|auth|nonce|csrf|token|login|credential/i.test(
			text,
		)
	) {
		return {
			klass: "target_or_state",
			priority: 2,
			action: "re_map -> re_live_browser/re_web_authz_state or re_lane plan",
		};
	}
	if (
		/artifact missing|missing: run|no replay execution|verifier artifact missing|compiler artifact missing|replayer artifact missing/i.test(
			text,
		)
	) {
		return {
			klass: "missing_artifact",
			priority: 2,
			action: "re_verifier matrix -> re_compiler draft -> re_replayer run",
		};
	}
	if (/weak|missing=|weak=|insufficient|low confidence|quality/i.test(text)) {
		return { klass: "weak_evidence", priority: 3, action: "re_operator dispatch -> re_verifier matrix" };
	}
	return { klass: "unknown", priority: 4, action: "re_delegate plan -> re_swarm run -> re_supervisor review" };
}

export function formatRepiProofLoopGapClassifier(
	items: RepiProofLoopGapItem[],
	options: { parallelRequired?: boolean } = {},
): string[] {
	return items
		.map((item, index) => {
			const classified = classifyRepiProofLoopGap(item);
			const action =
				classified.klass === "unknown" && options.parallelRequired !== true
					? "re_operator dispatch -> re_verifier matrix"
					: classified.action;
			return `priority=${classified.priority} class=${classified.klass} worker=${item.worker} source=${item.source} gap=${index + 1} action="${action}" evidence=${item.sourceArtifacts.slice(0, 3).join(" | ") || "none"} :: ${truncateMiddle(item.text, 520)}`;
		})
		.sort((left, right) => {
			const leftPriority = Number(/priority=(\d+)/.exec(left)?.[1] ?? "9");
			const rightPriority = Number(/priority=(\d+)/.exec(right)?.[1] ?? "9");
			return leftPriority - rightPriority || left.localeCompare(right);
		})
		.slice(0, 24);
}

export function repiProofLoopCommandTarget(target?: string): string {
	return target?.trim() ? ` ${target.trim()}` : "";
}

export function repiProofLoopRuntimeAdapterCommands(adapterIds: string[], target?: string): string[] {
	const targetRef = target?.trim();
	if (!targetRef) return [];
	return Array.from(new Set(adapterIds.filter((adapterId) => /^[a-z0-9][a-z0-9-]*-adapter$/i.test(adapterId))))
		.slice(0, 4)
		.map((adapterId) => `re_runtime_adapter run ${adapterId} ${targetRef}`);
}

export function repiProofLoopClassOrderFromItems(
	items: RepiProofLoopGapItem[],
): RepiProofLoopQuickPlanV1["classOrder"] {
	const rows = new Map<
		RepiProofLoopGapClass,
		{
			klass: RepiProofLoopGapClass;
			priority: number;
			count: number;
			workers: Set<RepiProofLoopDelegateWorker>;
			sources: Set<RepiProofLoopGapSource>;
		}
	>();
	for (const item of items) {
		const classified = classifyRepiProofLoopGap(item);
		const row = rows.get(classified.klass) ?? {
			klass: classified.klass,
			priority: classified.priority,
			count: 0,
			workers: new Set<RepiProofLoopDelegateWorker>(),
			sources: new Set<RepiProofLoopGapSource>(),
		};
		row.count += 1;
		row.priority = Math.min(row.priority, classified.priority);
		row.workers.add(item.worker);
		row.sources.add(item.source);
		rows.set(classified.klass, row);
	}
	return Array.from(rows.values())
		.map((row) => ({
			klass: row.klass,
			priority: row.priority,
			count: row.count,
			workers: Array.from(row.workers).sort(),
			sources: Array.from(row.sources).sort(),
		}))
		.sort((left, right) => left.priority - right.priority || left.klass.localeCompare(right.klass));
}

function appendProofSpine(commands: string[], targetRef: string, options: { includeAutofixPlan?: boolean } = {}): void {
	commands.push(`re_verifier matrix ${targetRef}`, `re_compiler draft ${targetRef}`, `re_replayer run ${targetRef} 1`);
	if (options.includeAutofixPlan) commands.push(`re_autofix plan ${targetRef}`);
}

function runtimeAdapterIdsFromGapText(text: string): string[] {
	const ids = new Set<string>();
	const patterns = [
		/\bruntime adapter(?: missing proof| parser no-match| failed| missing mitigation map proof)?:\s*([a-z0-9][a-z0-9-]*-adapter)\b/gi,
		/\badapter=([a-z0-9][a-z0-9-]*-adapter)\b/gi,
		/\b(?:re_runtime_adapter run|adapter:|parser_signal_summary|runtime-adapter-artifact:)\s+([a-z0-9][a-z0-9-]*-adapter)\b/gi,
		/\/runtime-adapters\/([a-z0-9][a-z0-9-]*-adapter)(?:\/|$)/gi,
	];
	for (const pattern of patterns) {
		for (const match of text.matchAll(pattern)) {
			const id = match[1]?.trim();
			if (id) ids.add(id);
		}
	}
	return Array.from(ids);
}

function proofSignalListFromGapText(text: string, field: "missing" | "matched"): string[] {
	const names = field === "missing" ? ["missing_proof"] : ["matched_proof"];
	if (/parser_signal_summary\s+adapter=|runtime adapter proof[- ]exit complete/i.test(text)) {
		names.push(field === "missing" ? "missing" : "matched");
	}
	const values: string[] = [];
	for (const name of names) {
		const pattern = new RegExp(
			`\\b${name}=([^\\n]*?)(?=\\s+(?:matched_proof|matched|missing_proof|missing|rules|artifact|evidence|status)=|$)`,
			"gi",
		);
		for (const match of text.matchAll(pattern)) {
			const value = match[1]?.trim();
			if (!value || value === "<none>") continue;
			values.push(
				...value
					.split(/\s*(?:\||;|,)\s*/)
					.map((item) => item.trim())
					.filter((item) => item.length > 0 && !/^(?:adapter|artifact|matched|missing|rules|status)=/i.test(item)),
			);
		}
	}
	return uniqueNonEmpty(values, 12);
}

export function repiProofLoopRuntimeAdapterClosureRows(
	items: RepiProofLoopGapItem[],
	target?: string,
): RepiProofLoopRuntimeAdapterClosureRowV1[] {
	const rows = new Map<string, RepiProofLoopRuntimeAdapterClosureRowV1>();
	const targetRef = target?.trim() || "<target>";
	for (const item of items) {
		const klass = classifyRepiProofLoopGap(item).klass;
		if (klass !== "runtime_adapter_gap" && klass !== "proof_spine_seed") continue;
		for (const adapterId of runtimeAdapterIdsFromGapText(item.text)) {
			const current =
				rows.get(adapterId) ??
				({
					kind: "ProofLoopRuntimeAdapterClosureRowV1",
					schemaVersion: 1,
					adapterId,
					status: "proof_spine_ready",
					missingProofSignals: [],
					matchedProofSignals: [],
					sourceArtifacts: [],
					commands: [],
				} satisfies RepiProofLoopRuntimeAdapterClosureRowV1);
			if (klass === "runtime_adapter_gap") current.status = "needs_adapter_rerun";
			current.missingProofSignals = uniqueNonEmpty(
				[...current.missingProofSignals, ...proofSignalListFromGapText(item.text, "missing")],
				12,
			);
			current.matchedProofSignals = uniqueNonEmpty(
				[...current.matchedProofSignals, ...proofSignalListFromGapText(item.text, "matched")],
				12,
			);
			current.sourceArtifacts = uniqueNonEmpty([...current.sourceArtifacts, ...item.sourceArtifacts], 12);
			current.commands =
				current.status === "needs_adapter_rerun"
					? repiProofLoopRuntimeAdapterCommands([adapterId], targetRef)
					: [
							`re_verifier matrix ${targetRef}`,
							`re_compiler draft ${targetRef}`,
							`re_replayer run ${targetRef} 1`,
						];
			rows.set(adapterId, current);
		}
	}
	return Array.from(rows.values()).sort((left, right) => left.adapterId.localeCompare(right.adapterId));
}

export function repiProofLoopQuickPlanFromItems(
	items: RepiProofLoopGapItem[],
	target?: string,
): RepiProofLoopQuickPlanV1 {
	const targetRef = target?.trim() || "<target>";
	const classOrder = repiProofLoopClassOrderFromItems(items);
	const classes = new Set(classOrder.map((row) => row.klass));
	const commands: string[] = [];
	const phases: RepiProofLoopQuickPlanPhaseV1[] = [];
	const addPhase = (
		phase: RepiProofLoopQuickPlanPhaseV1["phase"],
		reason: string,
		phaseClasses: RepiProofLoopGapClass[],
		phaseCommands: string[],
	): void => {
		const accepted: string[] = [];
		for (const command of phaseCommands) {
			if (commands.includes(command)) continue;
			commands.push(command);
			accepted.push(command);
		}
		if (!accepted.length) return;
		const evidenceRefs = uniqueNonEmpty(
			items
				.filter((item) => phaseClasses.length === 0 || phaseClasses.includes(classifyRepiProofLoopGap(item).klass))
				.flatMap((item) => item.sourceArtifacts),
			8,
		);
		phases.push({ phase, reason, classes: phaseClasses, commands: accepted, evidenceRefs });
	};
	if (items.some((item) => item.source === "attack_graph")) {
		addPhase("attack_graph_refresh", "refresh task tree before closing attack-graph gaps", [], ["re_graph build"]);
	}
	if (classes.has("tool_or_dependency")) {
		addPhase(
			"toolchain_repair",
			"repair missing tools/dependencies before replaying proof commands",
			["tool_or_dependency"],
			["re_bootstrap plan", `re_operator dispatch ${targetRef} 1`],
		);
	}
	if (classes.has("target_or_state")) {
		addPhase(
			"target_state_refresh",
			"refresh volatile target/session state before proof replay",
			["target_or_state"],
			[`re_map ${targetRef}`, `re_live_browser plan ${targetRef}`, `re_web_authz_state plan ${targetRef}`],
		);
	}
	if (classes.has("runtime_adapter_gap")) {
		const adapterIds = Array.from(new Set(items.flatMap((item) => runtimeAdapterIdsFromGapText(item.text))));
		addPhase(
			"runtime_adapter_frontload",
			"collect live/runtime artifacts before verifier/compiler/replayer consumes stale evidence",
			["runtime_adapter_gap"],
			adapterIds.length === 0
				? [`re_runtime_adapter plan ${targetRef}`]
				: adapterIds.slice(0, 4).map((adapterId) => `re_runtime_adapter run ${adapterId} ${targetRef}`),
		);
		const proofSpine: string[] = [];
		appendProofSpine(proofSpine, targetRef, { includeAutofixPlan: true });
		addPhase(
			"proof_spine",
			"verify, compile, and replay the adapter artifacts once before patching",
			["runtime_adapter_gap"],
			proofSpine,
		);
	}
	if (classes.has("proof_spine_seed")) {
		const proofSpine: string[] = [];
		appendProofSpine(proofSpine, targetRef);
		addPhase(
			"proof_spine",
			"promote attack-graph proof-spine seeds through verifier/compiler/replayer",
			["proof_spine_seed"],
			proofSpine,
		);
	}
	if (classes.has("missing_artifact") || classes.has("weak_evidence") || classes.size === 0) {
		const proofSpine: string[] = [];
		appendProofSpine(proofSpine, targetRef, { includeAutofixPlan: true });
		addPhase(
			"proof_spine",
			"materialize missing/weak proof artifacts through verifier/compiler/replayer",
			["missing_artifact", "weak_evidence"],
			proofSpine,
		);
	}
	if (classes.has("replay_failure") || classes.has("timeout_or_flake")) {
		const replayRepair: string[] = [];
		appendProofSpine(replayRepair, targetRef, { includeAutofixPlan: true });
		replayRepair.push(`re_autofix apply ${targetRef}`, `re_replayer run ${targetRef} 2`);
		addPhase(
			"replay_repair",
			"convert replay/flake failure into autofix and a second deterministic replay",
			["replay_failure", "timeout_or_flake"],
			replayRepair,
		);
	}
	if (classes.has("contradiction")) {
		const contradictionRepair = [`re_supervisor repair ${targetRef}`];
		appendProofSpine(contradictionRepair, targetRef);
		addPhase(
			"contradiction_repair",
			"send counter-evidence through supervisor repair before promotion",
			["contradiction"],
			contradictionRepair,
		);
	}
	if (classes.has("unknown")) {
		addPhase(
			"delegate_unknown",
			"escalate unknown gaps to a bounded swarm and merge handoff evidence",
			["unknown"],
			[`re_delegate plan ${targetRef}`, `re_swarm run ${targetRef} 2 1`, "re_swarm merge"],
		);
	}
	if (
		classes.size > 0 &&
		!classes.has("missing_artifact") &&
		!classes.has("weak_evidence") &&
		!classes.has("contradiction") &&
		!classes.has("runtime_adapter_gap") &&
		!classes.has("replay_failure") &&
		!classes.has("timeout_or_flake")
	) {
		const proofSpine: string[] = [];
		appendProofSpine(proofSpine, targetRef);
		addPhase(
			"proof_spine",
			"close non-proof-spine gaps with verifier/compiler/replayer before final loop",
			[],
			proofSpine,
		);
	}
	const loopCommand = `re_proof_loop run ${targetRef} 4 2`;
	addPhase("final_loop", "rerun the proof loop after repairs to force gap closure or escalation", [], [loopCommand]);
	const unique = Array.from(new Set(commands));
	const boundedCommands = [...unique.filter((command) => command !== loopCommand).slice(0, 13), loopCommand];
	const omittedCommands = unique.filter((command) => !boundedCommands.includes(command));
	const runtimeAdapterIndex = boundedCommands.findIndex((command) => command.startsWith("re_runtime_adapter "));
	const firstReplayIndex = boundedCommands.findIndex((command) => command.startsWith("re_replayer run "));
	const autofixApplyIndex = boundedCommands.findIndex((command) => command.startsWith("re_autofix apply "));
	let finalReplayIndex = -1;
	for (let index = 0; index < boundedCommands.length; index += 1) {
		if (boundedCommands[index]?.startsWith("re_replayer run ")) finalReplayIndex = index;
	}
	return {
		kind: "ProofLoopQuickPlanV1",
		schemaVersion: 1,
		target: targetRef,
		classOrder,
		phases,
		commands: boundedCommands,
		omittedCommands,
		finalLoopCommand: loopCommand,
		assertions: {
			bounded: boundedCommands.length <= 14,
			deduplicated: boundedCommands.length === new Set(boundedCommands).size,
			runtimeAdapterBeforeReplay:
				!classes.has("runtime_adapter_gap") || firstReplayIndex < 0 || runtimeAdapterIndex < firstReplayIndex,
			autofixApplyBeforeFinalReplay:
				!(classes.has("replay_failure") || classes.has("timeout_or_flake")) ||
				(autofixApplyIndex >= 0 && finalReplayIndex > autofixApplyIndex),
			finalLoopLast: boundedCommands.at(-1) === loopCommand,
		},
	};
}

export function repiProofLoopQuickPathFromItems(items: RepiProofLoopGapItem[], target?: string): string[] {
	return repiProofLoopQuickPlanFromItems(items, target).commands;
}

export function repiProofLoopSpecialistQueueFromItems(items: RepiProofLoopGapItem[], target?: string): string[] {
	const suffix = repiProofLoopCommandTarget(target);
	return items
		.map(
			(item, index) =>
				`proof-gap:${index + 1}:${item.worker} source=${item.source} evidence=${item.sourceArtifacts.slice(0, 3).join(" | ") || "none"} :: ${truncateMiddle(item.text, 520)} -> re_delegate plan${suffix}`,
		)
		.slice(0, 24);
}
