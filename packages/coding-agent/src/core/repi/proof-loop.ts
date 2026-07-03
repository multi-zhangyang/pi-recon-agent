import { truncateMiddle } from "./text.ts";

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
	| "compact_resume"
	| "failure_signature"
	| "operator_feedback"
	| "verifier"
	| "compiler"
	| "replayer"
	| "autofix"
	| "checkpoint"
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
	| "weak_evidence"
	| "timeout_or_flake"
	| "compact_resume"
	| "unknown";

export type RepiProofLoopGapClassification = {
	klass: RepiProofLoopGapClass;
	priority: number;
	action: string;
};

type RepiProofLoopMissionContext = {
	route?: { domain?: string };
	task?: string;
};

export function repiProofLoopWorkerForText(
	text: string,
	mission?: RepiProofLoopMissionContext,
): RepiProofLoopDelegateWorker {
	const haystack = `${mission?.route?.domain ?? ""}\n${mission?.task ?? ""}\n${text}`;
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
	if (/compact resume|resume command|proof loop has not been entered/i.test(text)) {
		return {
			klass: "compact_resume",
			priority: 1,
			action: "re_context resume -> re_operator plan -> re_proof_loop run",
		};
	}
	if (/contradiction|counter[_ -]?evidence|refute|conflict/i.test(text)) {
		return { klass: "contradiction", priority: 1, action: "re_supervisor repair -> re_verifier matrix" };
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

export function formatRepiProofLoopGapClassifier(items: RepiProofLoopGapItem[]): string[] {
	return items
		.map((item, index) => {
			const classified = classifyRepiProofLoopGap(item);
			return `priority=${classified.priority} class=${classified.klass} worker=${item.worker} source=${item.source} gap=${index + 1} action="${classified.action}" evidence=${item.sourceArtifacts.slice(0, 3).join(" | ") || "none"} :: ${truncateMiddle(item.text, 520)}`;
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

function appendProofSpine(commands: string[], targetRef: string, options: { includeAutofixPlan?: boolean } = {}): void {
	commands.push(`re_verifier matrix ${targetRef}`, `re_compiler draft ${targetRef}`, `re_replayer run ${targetRef} 1`);
	if (options.includeAutofixPlan) commands.push(`re_autofix plan ${targetRef}`);
}

export function repiProofLoopQuickPathFromItems(items: RepiProofLoopGapItem[], target?: string): string[] {
	const targetRef = target?.trim() || "<target>";
	const classes = new Set(items.map((item) => classifyRepiProofLoopGap(item).klass));
	const commands: string[] = [];
	if (classes.has("compact_resume")) {
		commands.push("re_context resume", `re_operator plan ${targetRef}`);
	}
	if (classes.has("tool_or_dependency")) commands.push("re_bootstrap plan", `re_operator dispatch ${targetRef} 1`);
	if (classes.has("target_or_state")) {
		commands.push(`re_map ${targetRef}`, `re_live_browser plan ${targetRef}`, `re_web_authz_state plan ${targetRef}`);
	}
	if (classes.has("missing_artifact") || classes.has("weak_evidence") || classes.size === 0) {
		appendProofSpine(commands, targetRef, { includeAutofixPlan: true });
	}
	if (classes.has("replay_failure") || classes.has("timeout_or_flake")) {
		commands.push(`re_autofix plan ${targetRef}`, `re_autofix apply ${targetRef}`, `re_replayer run ${targetRef} 1`);
	}
	if (classes.has("contradiction")) {
		commands.push(`re_supervisor repair ${targetRef}`);
		appendProofSpine(commands, targetRef);
	}
	if (classes.has("unknown"))
		commands.push(`re_delegate plan ${targetRef}`, `re_swarm run ${targetRef} 2 1`, "re_swarm merge");
	if (
		classes.size > 0 &&
		!classes.has("missing_artifact") &&
		!classes.has("weak_evidence") &&
		!classes.has("contradiction")
	) {
		appendProofSpine(commands, targetRef);
	}
	const loopCommand = `re_proof_loop run ${targetRef} 4 2`;
	commands.push(loopCommand);
	const unique = Array.from(new Set(commands));
	return [...unique.filter((command) => command !== loopCommand).slice(0, 13), loopCommand];
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
