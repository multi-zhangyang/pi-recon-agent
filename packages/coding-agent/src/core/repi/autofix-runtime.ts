import { join } from "node:path";
import type { ArtifactScopeFilterOptions } from "./artifact-scope.ts";
import type { EvidenceRecord } from "./evidence.ts";
import type { RuntimeAutofixArtifact } from "./failure-runtime.ts";
import type { MissionCheckpointStatus, MissionState } from "./mission.ts";
import type { CompilerArtifact, ReplayArtifact } from "./proof-artifact-runtime.ts";
import { ensureReconStorage } from "./resources.ts";
import { evidenceAutofixDir, writePrivateTextFile } from "./storage.ts";
import { shellQuote } from "./target.ts";
import { slug, truncateMiddle } from "./text.ts";

export type AutofixItemKind = "patch" | "command_substitution" | "bootstrap" | "evidence_recapture" | "operator";

export type AutofixStatus = "queued" | "applied" | "blocked";

export type AutofixItem = {
	id: string;
	kind: AutofixItemKind;
	source: string;
	reason: string;
	command: string;
	status: AutofixStatus;
	sourceArtifacts: string[];
};

export type AutofixArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	mode: "plan" | "apply";
	replayArtifact?: string;
	compilerArtifact?: string;
	operatorFeedback: string[];
	failures: string[];
	patchQueue: AutofixItem[];
	commandSubstitutions: AutofixItem[];
	bootstrapQueue: AutofixItem[];
	evidenceRecaptureQueue: AutofixItem[];
	nextOperatorQueue: string[];
	applied: string[];
	repairRollbackPolicyPath?: string;
	repairRollbackPolicyStatus?: "pass" | "blocked" | "missing";
	repairRollbackPolicyErrors: string[];
	sourceArtifacts: string[];
};

type EvidenceInput = Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number };

export type AutofixRuntimeDependencies = {
	latestScopedMarkdownArtifact: (
		kind: string,
		directory: string,
		options?: ArtifactScopeFilterOptions,
	) => string | undefined;
	latestOrBuildReplay: (options?: { target?: string }) => { replay: ReplayArtifact; path: string };
	latestCompilerArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	parseCompilerArtifact: (path: string) => CompilerArtifact | undefined;
	operatorFeedbackNextCommands: (feedback: string[]) => string[];
	writeAutofixRepairRollbackPolicy: (
		autofix: RuntimeAutofixArtifact,
		autofixArtifactPath: string,
	) => { path?: string; status: "pass" | "blocked" | "missing"; errors: string[] };
	appendRuntimeFailureRepairFromAutofix: (autofix: RuntimeAutofixArtifact, path: string) => void;
	appendEvidence: (record: EvidenceInput) => EvidenceRecord;
	updateMissionCheckpoint: (name: string, status: MissionCheckpointStatus, note?: string) => MissionState | undefined;
	formatStoredArtifactSummary: (kind: string, path: string) => string;
};

export function createAutofixRuntime(dependencies: AutofixRuntimeDependencies) {
	const {
		latestScopedMarkdownArtifact,
		latestOrBuildReplay,
		latestCompilerArtifactPath,
		parseCompilerArtifact,
		operatorFeedbackNextCommands,
		writeAutofixRepairRollbackPolicy,
		appendRuntimeFailureRepairFromAutofix,
		appendEvidence,
		updateMissionCheckpoint,
		formatStoredArtifactSummary,
	} = dependencies;

	function latestAutofixArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		return latestScopedMarkdownArtifact("autofix", evidenceAutofixDir(), options);
	}

	function autofixItem(
		kind: AutofixItemKind,
		source: string,
		reason: string,
		command: string,
		sourceArtifacts: string[],
		index: number,
	): AutofixItem {
		return {
			id: `fix:${kind}:${index + 1}:${slug(source).slice(0, 18)}`,
			kind,
			source: truncateMiddle(source, 360),
			reason: truncateMiddle(reason, 360),
			command,
			status: "queued",
			sourceArtifacts,
		};
	}

	function replayFailureRows(replay: ReplayArtifact): string[] {
		const failed = replay.executions
			.filter((execution) => execution.status === "failed")
			.map(
				(execution) =>
					`${execution.stepId}: exit=${execution.exit} command=${execution.command} stderr=${truncateMiddle(execution.stderrHead, 240)}`,
			);
		return Array.from(new Set([...replay.blocked, ...failed])).slice(0, 40);
	}

	function bootstrapToolFromCommand(command: string): string | undefined {
		const token = command
			.trim()
			.split(/\s+/)[0]
			?.replace(/^['"]|['"]$/g, "");
		if (!token || /^(set|test|cat|printf|sed|grep|rg|awk|bash|sh|python|node)$/i.test(token)) return undefined;
		return token;
	}

	function buildAutofix(options: { target?: string; mode?: "plan" | "apply" } = {}): AutofixArtifact {
		ensureReconStorage();
		const { replay, path: replayArtifact } = latestOrBuildReplay(options);
		const compilerPath = replay.compilerArtifact ?? latestCompilerArtifactPath();
		const compiler = compilerPath ? parseCompilerArtifact(compilerPath) : undefined;
		const sourceArtifacts = Array.from(new Set([replayArtifact, compilerPath, ...replay.sourceArtifacts])).filter(
			(path): path is string => Boolean(path),
		);
		const failures = replayFailureRows(replay);
		const operatorFeedback = replay.operatorFeedback ?? compiler?.operatorFeedback ?? [];
		const patchQueue: AutofixItem[] = [];
		const commandSubstitutions: AutofixItem[] = [];
		const bootstrapQueue: AutofixItem[] = [];
		const evidenceRecaptureQueue: AutofixItem[] = [];
		const nextOperatorQueue: string[] = [];
		let index = 0;
		const add = (
			collection: AutofixItem[],
			kind: AutofixItemKind,
			source: string,
			reason: string,
			command: string,
		) => {
			collection.push(autofixItem(kind, source, reason, command, sourceArtifacts, index++));
		};

		for (const blocked of replay.blocked) {
			const command = /::\s*(.+)$/.exec(blocked)?.[1]?.trim() ?? blocked;
			if (/internal REPI command/i.test(blocked) || /^re[-_]/i.test(command)) {
				const delegatedCommand = command.replace(/^re-/i, "re_");
				const targetRef = options.target ?? replay.target ?? "<target>";
				add(
					commandSubstitutions,
					"command_substitution",
					blocked,
					"internal command captured as shell replay; keep original semantics and delegate outside replay sandbox",
					`re_evidence show && re_operator plan ${targetRef} # delegated_internal_original=${delegatedCommand}`,
				);
				nextOperatorQueue.push(delegatedCommand);
				continue;
			}
			if (/target placeholder|unresolved/i.test(blocked)) {
				add(
					evidenceRecaptureQueue,
					"evidence_recapture",
					blocked,
					"replay command still has unresolved target placeholder",
					`re_map ${options.target ?? replay.target ?? "<target>"} 2 && re_evidence show`,
				);
				nextOperatorQueue.push("re_evidence show");
				continue;
			}
			add(
				commandSubstitutions,
				"command_substitution",
				blocked,
				"blocked replay row needs a safer replay wrapper",
				`printf '%s\\n' ${shellQuote(`blocked replay row: ${truncateMiddle(blocked, 160)}`)}; ${command} || true`,
			);
		}

		for (const execution of replay.executions.filter((item) => item.status === "failed")) {
			const stderr = `${execution.stderrHead}\n${execution.stdoutHead}`;
			const tool = /command not found|not found|No such file|cannot stat|ModuleNotFoundError|ImportError/i.test(
				stderr,
			)
				? bootstrapToolFromCommand(execution.command)
				: undefined;
			if (tool) {
				add(
					bootstrapQueue,
					"bootstrap",
					execution.command,
					"replay failed with missing tool/dependency signal",
					`re_bootstrap plan ${tool}`,
				);
				nextOperatorQueue.push(`re_bootstrap plan ${tool}`);
			}
			add(
				commandSubstitutions,
				"command_substitution",
				execution.command,
				`replay failed exit=${execution.exit}`,
				`timeout 60s bash -lc ${shellQuote(execution.command)} || true`,
			);
			add(
				evidenceRecaptureQueue,
				"evidence_recapture",
				execution.command,
				"replay failure requires fresh evidence capture and verifier refresh",
				`re_replayer run ${options.target ?? replay.target ?? "<target>"} 1 && re_verifier matrix`,
			);
		}

		for (const feedback of operatorFeedback.slice(0, 16)) {
			const next = operatorFeedbackNextCommands([feedback])[0] ?? "re_operator escalate";
			if (/category=missing_tool_or_dependency/i.test(feedback)) {
				add(bootstrapQueue, "bootstrap", feedback, "operator feedback classified missing tool/dependency", next);
				nextOperatorQueue.push(next);
				continue;
			}
			if (/category=unresolved_target/i.test(feedback)) {
				add(
					evidenceRecaptureQueue,
					"evidence_recapture",
					feedback,
					"operator feedback classified unresolved target",
					next,
				);
				nextOperatorQueue.push(next);
				continue;
			}
			if (
				/category=swarm_retry_queue/i.test(feedback) ||
				/category=(worker_retry_blocked|failure_budget_exhausted)/i.test(feedback)
			) {
				add(
					evidenceRecaptureQueue,
					"evidence_recapture",
					feedback,
					"operator feedback requires bounded worker retry",
					next,
				);
				nextOperatorQueue.push(next);
				continue;
			}
			if (/category=(dispatcher_gap|runtime_failure)/i.test(feedback)) {
				add(
					commandSubstitutions,
					"command_substitution",
					feedback,
					"operator feedback requires dispatcher/autofix reroute",
					next,
				);
				nextOperatorQueue.push(next);
				continue;
			}
			if (/category=replay_or_exploit_candidate/i.test(feedback)) {
				nextOperatorQueue.push(next, `re_exploit_lab run ${options.target ?? replay.target ?? "<target>"} 3 60000`);
			}
		}

		for (const gap of [...(compiler?.gaps ?? []), ...(compiler?.contradictions ?? [])].slice(0, 12)) {
			add(
				patchQueue,
				"patch",
				gap,
				"compiler gap/contradiction requires a repair scaffold before final claim",
				`re_operator escalate && re_compiler draft${(options.target ?? replay.target) ? ` ${options.target ?? replay.target}` : ""}`,
			);
		}

		if (failures.length === 0 && patchQueue.length === 0) {
			nextOperatorQueue.push("re_verifier matrix", "re_compiler draft");
		} else {
			nextOperatorQueue.push(
				...patchQueue.map((item) => item.command),
				...commandSubstitutions.map((item) => item.command),
				...bootstrapQueue.map((item) => item.command),
				...evidenceRecaptureQueue.map((item) => item.command),
				...(compiler?.nextOperatorQueue ?? []),
				"re_replayer run",
			);
		}

		const applied: string[] = [];
		if (options.mode === "apply") {
			const deferredReason = "autofix apply is queued; dispatch through re_operator to execute and capture evidence";
			for (const item of [patchQueue, commandSubstitutions, bootstrapQueue, evidenceRecaptureQueue].flat()) {
				item.status = "blocked";
				item.reason = `${item.reason}; ${deferredReason}`;
			}
			nextOperatorQueue.unshift(`re_operator dispatch ${options.target ?? replay.target ?? "<target>"} 1`);
		}
		return {
			timestamp: new Date().toISOString(),
			missionId: replay.missionId ?? compiler?.missionId,
			route: replay.route ?? compiler?.route,
			target: options.target ?? replay.target ?? compiler?.target,
			mode: options.mode ?? "plan",
			replayArtifact,
			compilerArtifact: compilerPath,
			operatorFeedback,
			failures,
			patchQueue,
			commandSubstitutions,
			bootstrapQueue,
			evidenceRecaptureQueue,
			nextOperatorQueue: Array.from(new Set(nextOperatorQueue)).slice(0, 36),
			applied,
			repairRollbackPolicyStatus: "missing",
			repairRollbackPolicyErrors: [],
			sourceArtifacts,
		};
	}

	function formatAutofix(autofix: AutofixArtifact, path?: string): string {
		const formatItems = (items: AutofixItem[]) =>
			items.length
				? items.map((item) => `- ${item.id} [${item.status}] ${item.command} # ${item.reason}`)
				: ["- none"];
		return [
			"autofix_plan:",
			path ? `autofix_artifact: ${path}` : undefined,
			`timestamp: ${autofix.timestamp}`,
			`mode: ${autofix.mode}`,
			`mission_id: ${autofix.missionId ?? "none"}`,
			`route: ${autofix.route ?? "none"}`,
			`target: ${autofix.target ?? "<none>"}`,
			`replay_artifact: ${autofix.replayArtifact ?? "none"}`,
			`compiler_artifact: ${autofix.compilerArtifact ?? "none"}`,
			"operator_feedback:",
			...((autofix.operatorFeedback ?? []).length
				? (autofix.operatorFeedback ?? []).map((item) => `- ${item}`)
				: ["- none"]),
			"failures:",
			...(autofix.failures.length ? autofix.failures.map((item) => `- ${item}`) : ["- none"]),
			"patch_queue:",
			...formatItems(autofix.patchQueue),
			"command_substitutions:",
			...formatItems(autofix.commandSubstitutions),
			"bootstrap_queue:",
			...formatItems(autofix.bootstrapQueue),
			"evidence_recapture_queue:",
			...formatItems(autofix.evidenceRecaptureQueue),
			"next_operator_queue:",
			...(autofix.nextOperatorQueue.length ? autofix.nextOperatorQueue.map((item) => `- ${item}`) : ["- none"]),
			"applied:",
			...(autofix.applied.length ? autofix.applied.map((item) => `- ${item}`) : ["- none"]),
			`execution_status: ${autofix.mode === "apply" ? (autofix.applied.length ? "verified" : "deferred_to_operator") : "plan_only"}`,
			"repair_rollback_policy:",
			`- path=${autofix.repairRollbackPolicyPath ?? "pending"}`,
			`- status=${autofix.repairRollbackPolicyStatus ?? "missing"}`,
			...(autofix.repairRollbackPolicyErrors?.length
				? autofix.repairRollbackPolicyErrors.slice(0, 8).map((error) => `- error=${error}`)
				: ["- errors=none"]),
			`next_autofix_command: ${autofix.mode === "apply" ? `re_operator dispatch ${autofix.target ?? "<target>"} 1` : "re_autofix apply"}`,
			"source_artifacts:",
			...(autofix.sourceArtifacts.length ? autofix.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
		]
			.filter(Boolean)
			.join("\n");
	}

	function writeAutofixArtifact(autofix: AutofixArtifact): string {
		ensureReconStorage();
		const path = join(
			evidenceAutofixDir(),
			`${autofix.timestamp.replace(/[:.]/g, "-")}-${slug(autofix.route ?? "autofix")}-${autofix.mode}.md`,
		);
		const render = () =>
			[
				"# REPI Autofix Artifact",
				"",
				formatAutofix(autofix, path),
				"",
				"## JSON",
				"",
				"```json",
				JSON.stringify(autofix, null, 2),
				"```",
				"",
			].join("\n");
		writePrivateTextFile(path, render());
		const repairRollback = writeAutofixRepairRollbackPolicy(autofix, path);
		autofix.repairRollbackPolicyPath = repairRollback.path;
		autofix.repairRollbackPolicyStatus = repairRollback.status;
		autofix.repairRollbackPolicyErrors = repairRollback.errors;
		writePrivateTextFile(path, render());
		appendEvidence({
			kind: "artifact",
			title: `autofix-${autofix.mode} ${autofix.missionId ?? "no-mission"}`,
			fact: `Autofix ${autofix.mode}: failures=${autofix.failures.length}, patch=${autofix.patchQueue.length}, substitutions=${autofix.commandSubstitutions.length}, bootstrap=${autofix.bootstrapQueue.length}, recapture=${autofix.evidenceRecaptureQueue.length}, operator_feedback=${(autofix.operatorFeedback ?? []).length}`,
			command: `re_autofix ${autofix.mode}`,
			path,
			verify: `cat ${path}`,
			confidence: "replay/compile repair queue",
		});
		updateMissionCheckpoint(
			"autofix_ready",
			autofix.mode === "apply" && autofix.applied.length === 0 ? "blocked" : "done",
			autofix.mode === "apply" && autofix.applied.length === 0
				? "apply is queued only; run re_operator dispatch and verify its runtime artifact"
				: path,
		);
		appendRuntimeFailureRepairFromAutofix(autofix, path);
		return path;
	}

	function buildAutofixOutput(action: "plan" | "show" | "apply" = "plan", options: { target?: string } = {}): string {
		if (action === "show") {
			const path = latestAutofixArtifactPath();
			if (!path) return "autofix_plan:\nstatus: missing\nnext: re_autofix plan";
			return formatStoredArtifactSummary("autofix_plan", path);
		}
		const autofix = buildAutofix({ target: options.target, mode: action === "apply" ? "apply" : "plan" });
		const path = writeAutofixArtifact(autofix);
		return formatAutofix(autofix, path);
	}

	return {
		buildAutofix,
		buildAutofixOutput,
		formatAutofix,
		latestAutofixArtifactPath,
		writeAutofixArtifact,
	};
}
