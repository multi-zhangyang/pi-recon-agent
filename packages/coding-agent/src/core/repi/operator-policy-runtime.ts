import type { OperationExecution, OperationStepStatus } from "./campaign-operation-runtime.ts";
import type { MissionState } from "./mission.ts";
import { shellQuote } from "./target.ts";
import { truncateMiddle } from "./text.ts";

export type OperatorPolicyStep = {
	id: string;
	command: string;
	status: OperationStepStatus;
	reason?: string;
};

export type OperatorPolicyRuntimeDependencies = {
	operatorCommandConcrete: (command: string, target?: string) => { command: string; blocked?: string };
	splitRetryNextCommands: (commands: string) => string[];
};

export function createOperatorPolicyRuntime(dependencies: OperatorPolicyRuntimeDependencies) {
	function concreteRuntimeCommands(commands: string[], target?: string): string[] {
		return commands.flatMap((command) => {
			const concrete = dependencies.operatorCommandConcrete(command, target);
			return !concrete.blocked && /^re[-_]/i.test(concrete.command) ? [concrete.command] : [];
		});
	}

	function isCommanderRuntimeCommand(command: string): boolean {
		return /^re[-_](swarm|supervisor|context|operator|proof[-_]loop|verifier|compiler|replayer|autofix)\b/i.test(
			command.trim().replace(/^\//, ""),
		);
	}

	function commanderBudgetValue(lines: string[] | undefined, key: string, fallback: number): number {
		const line = (lines ?? []).find((item) => item.startsWith(`${key}=`));
		const value = line ? Number(line.replace(/^.+?=/, "")) : Number.NaN;
		return Number.isFinite(value) ? value : fallback;
	}

	function operatorStepPriority(command: string): number {
		if (/^re[-_]mission/i.test(command)) return 1;
		if (/^re[-_]kernel/i.test(command)) return 5;
		if (/^re[-_]tool|^re[-_]bootstrap/i.test(command)) return 10;
		if (/^re[-_]decision[-_]core/i.test(command)) return 12;
		if (/^re[-_]autopilot|^re[-_]auto\b/i.test(command)) return 18;
		if (/^re[-_]map|^re[-_]lane\s+plan/i.test(command)) return 20;
		if (/^re[-_]lane\s+(run|run-auto)|^re[-_]graph/i.test(command)) return 30;
		if (
			/^re[-_]live[-_]browser|^re[-_]web[-_]authz[-_]state|^re[-_]exploit[-_]lab|^re[-_]mobile[-_]runtime|^re[-_]native[-_]runtime/i.test(
				command,
			)
		)
			return 32;
		if (/^re[-_](?:exploit[-_])?chain/i.test(command)) return 35;
		if (/^re[-_]campaign|^re[-_]operation|^re[-_]delegate/i.test(command)) return 40;
		if (/^re[-_]swarm/i.test(command)) return 42;
		if (/^re[-_]supervisor|^re[-_]reflect/i.test(command)) return 50;
		if (/^re[-_]operator/i.test(command)) return 55;
		if (/^re[-_]evidence/i.test(command)) return 60;
		if (/^re[-_]verifier/i.test(command)) return 65;
		if (/^re[-_]compiler/i.test(command)) return 68;
		if (/^re[-_]replayer/i.test(command)) return 69;
		if (/^re[-_]autofix/i.test(command)) return 70;
		if (/^re[-_]proof[-_]loop/i.test(command)) return 75;
		if (/^re[-_]complete/i.test(command)) return 80;
		return 90;
	}

	function operatorFeedbackCategory(row: string): string {
		return /\bcategory=([A-Za-z0-9_-]+)/i.exec(row)?.[1] ?? "unknown";
	}

	function operatorFeedbackPriority(category: string): number {
		if (/missing_tool_or_dependency/i.test(category)) return 5;
		if (/unresolved_target/i.test(category)) return 6;
		if (/runtime_failure|dispatcher_gap/i.test(category)) return 7;
		if (/failure_budget_exhausted/i.test(category)) return 8;
		if (/swarm_retry_queue|worker_retry_blocked/i.test(category)) return 9;
		if (/replay_or_exploit_candidate/i.test(category)) return 11;
		if (/worker_retry_progress/i.test(category)) return 15;
		if (/strong_evidence/i.test(category)) return 18;
		return 25;
	}

	function operatorFeedbackNextCommands(feedback: string[]): string[] {
		return Array.from(
			new Set(
				feedback
					.flatMap((row) => /\bnext=(.+?)(?:\s+evidence=|\s+source=|$)/i.exec(row)?.[1]?.trim() ?? "")
					.flatMap(dependencies.splitRetryNextCommands)
					.filter((command) => /^re[-_]/i.test(command)),
			),
		).slice(0, 16);
	}

	function operatorFeedbackFallbackCommands(row: string, target?: string): string[] {
		const category = operatorFeedbackCategory(row);
		const targetRef = target ?? "<target>";
		const primary = operatorFeedbackNextCommands([row]);
		const fallback = /missing_tool_or_dependency/i.test(category)
			? ["re_tool_index refresh", ...primary]
			: /unresolved_target/i.test(category)
				? [`re_map ${targetRef} 2`, "re_evidence show"]
				: /dispatcher_gap/i.test(category)
					? [...primary, `re_operator escalate ${targetRef}`, "re_evidence show"]
					: /runtime_failure/i.test(category)
						? [...primary, `re_replayer run ${targetRef} 1`, `re_proof_loop run ${targetRef} 4 2`]
						: /failure_budget_exhausted/i.test(category)
							? [`re_proof_loop run ${targetRef} 4 2`, "re_evidence show", `re_operator dispatch ${targetRef} 1`]
							: /swarm_retry_queue|worker_retry_blocked|worker_retry_progress/i.test(category)
								? [...primary, "re_swarm merge", `re_supervisor repair ${targetRef}`, "re_evidence show"]
								: /replay_or_exploit_candidate/i.test(category)
									? [...primary, `re_replayer run ${targetRef} 1`, `re_exploit_lab run ${targetRef} 3 60000`]
									: /strong_evidence/i.test(category)
										? ["re_verifier matrix", "re_compiler draft"]
										: primary;
		return Array.from(
			new Set(concreteRuntimeCommands(fallback.flatMap(dependencies.splitRetryNextCommands), target)),
		).slice(0, 8);
	}

	function operatorFeedbackDispatchPlan(rows: string[], target?: string): string[] {
		return rows
			.map((row) => {
				const category = operatorFeedbackCategory(row);
				const fallback = operatorFeedbackFallbackCommands(row, target);
				const primary = operatorFeedbackNextCommands([row])[0] ?? fallback[0] ?? "re_operator dispatch";
				const concretePrimary = dependencies.operatorCommandConcrete(primary, target);
				return [
					"dispatcher_feedback_priority",
					`category=${category}`,
					`priority=${operatorFeedbackPriority(category)}`,
					`primary=${shellQuote(concretePrimary.blocked ? (fallback[0] ?? "none") : concretePrimary.command)}`,
					`fallback=${shellQuote(fallback.join(" && ") || "none")}`,
					`evidence=${shellQuote(truncateMiddle(row, 220))}`,
				].join(" ");
			})
			.sort((a, b) => {
				const left = Number(/\bpriority=(\d+)/.exec(a)?.[1] ?? 99);
				const right = Number(/\bpriority=(\d+)/.exec(b)?.[1] ?? 99);
				return left - right || a.localeCompare(b);
			})
			.slice(0, 24);
	}

	function operatorFeedbackDispatcherCommands(rows: string[], target?: string): string[] {
		return Array.from(
			new Set(
				concreteRuntimeCommands(
					[
						...operatorFeedbackNextCommands(rows),
						...rows.flatMap((row) => operatorFeedbackFallbackCommands(row, target)),
					],
					target,
				),
			),
		).slice(0, 20);
	}

	function dispatcherFeedbackExecutionStatus(
		command: string,
		executions: OperationExecution[],
	): "passed" | "failed" | "queued" {
		const normalized = command.trim().replace(/^\//, "");
		const execution = executions.find((item) => item.command.trim().replace(/^\//, "") === normalized);
		if (!execution) return "queued";
		return execution.status === "blocked" ? "failed" : "passed";
	}

	function dispatcherFeedbackScore(command: string, status: "passed" | "failed" | "queued", category: string): number {
		const base = status === "passed" ? 82 : status === "failed" ? 25 : 50;
		const categoryBoost = Math.max(0, 20 - operatorFeedbackPriority(category));
		const commandBoost = /^re[-_](?:verifier|compiler)/i.test(command)
			? 3
			: /^re[-_](?:proof[-_]loop|replayer|exploit[-_]lab|autofix|swarm|supervisor)/i.test(command)
				? 6
				: 0;
		return Math.max(0, Math.min(100, base + categoryBoost + commandBoost));
	}

	function dispatcherFeedbackScoreboard(operator: {
		operatorFeedback?: string[];
		executed: OperationExecution[];
		target?: string;
	}): string[] {
		return (operator.operatorFeedback ?? [])
			.flatMap((row) => {
				const category = operatorFeedbackCategory(row);
				const commands = operatorFeedbackFallbackCommands(row, operator.target);
				const candidates = commands.length ? commands : operatorFeedbackDispatcherCommands([row], operator.target);
				return candidates.slice(0, 5).map((command) => {
					const status = dispatcherFeedbackExecutionStatus(command, operator.executed);
					const score = dispatcherFeedbackScore(command, status, category);
					return [
						"dispatcher_score",
						`category=${category}`,
						`status=${status}`,
						`score=${score}`,
						`command=${shellQuote(command)}`,
						`evidence=${shellQuote(truncateMiddle(row, 220))}`,
					].join(" ");
				});
			})
			.filter((row, index, rows) => rows.indexOf(row) === index)
			.sort((a, b) => {
				const leftStatus = /\bstatus=passed\b/.test(a) ? 0 : /\bstatus=queued\b/.test(a) ? 1 : 2;
				const rightStatus = /\bstatus=passed\b/.test(b) ? 0 : /\bstatus=queued\b/.test(b) ? 1 : 2;
				const leftScore = Number(/\bscore=(\d+)/.exec(a)?.[1] ?? 0);
				const rightScore = Number(/\bscore=(\d+)/.exec(b)?.[1] ?? 0);
				return leftStatus - rightStatus || rightScore - leftScore || a.localeCompare(b);
			})
			.slice(0, 40);
	}

	function dispatcherLearningHints(scoreboard: string[], target?: string): string[] {
		const targetRef = target ?? "<target>";
		const hints = scoreboard.map((row) => {
			const status = /\bstatus=([a-z]+)/i.exec(row)?.[1] ?? "queued";
			const score = Number(/\bscore=(\d+)/.exec(row)?.[1] ?? 0);
			const category = /\bcategory=([A-Za-z0-9_-]+)/.exec(row)?.[1] ?? "unknown";
			const command = /\bcommand=(?:'([^']+)'|"([^"]+)"|(\S+))/i.exec(row);
			const commandText = command?.[1] ?? command?.[2] ?? command?.[3] ?? "re_operator dispatch";
			if (status === "passed" && score >= 80)
				return `promote_dispatcher category=${category} score=${score} command=${commandText} -> re_graph build ${targetRef}`;
			if (status === "failed")
				return `demote_dispatcher category=${category} score=${score} command=${commandText} -> re_autofix plan ${targetRef}; re_evidence show`;
			return `retry_dispatcher category=${category} score=${score} command=${commandText} -> re_operator dispatch ${targetRef} 1`;
		});
		return Array.from(new Set(hints)).slice(0, 24);
	}

	function operatorVerificationLines(steps: OperatorPolicyStep[], mission?: MissionState): string[] {
		const checkpointChecks = mission?.checkpoints.map((checkpoint) => `${checkpoint.name}: ${checkpoint.status}`) ?? [
			"mission: missing",
		];
		const ready = steps.filter((step) => step.status === "ready").length;
		const blocked = steps.filter((step) => step.status === "blocked").length;
		return [`operator_steps: ready=${ready} blocked=${blocked} total=${steps.length}`, ...checkpointChecks];
	}

	function operatorEscalationQueue(steps: OperatorPolicyStep[], pendingGates: string[]): string[] {
		const queue = [
			...steps
				.filter((step) => step.status === "blocked")
				.map((step) => `repair blocked ${step.id}: ${step.reason ?? step.command}`),
			...pendingGates.slice(0, 12).map((checkpoint) => `close check: ${checkpoint}`),
		];
		if (pendingGates.includes("tool_index_checked")) queue.push("re_tool_index refresh");
		if (pendingGates.includes("passive_map_done")) queue.push("re_map <target> 2");
		if (pendingGates.includes("supervisor_review_ready")) queue.push("re_supervisor review");
		queue.push("re_operator verify");
		return Array.from(new Set(queue)).slice(0, 24);
	}

	return {
		isCommanderRuntimeCommand,
		commanderBudgetValue,
		operatorStepPriority,
		operatorFeedbackCategory,
		operatorFeedbackNextCommands,
		operatorFeedbackFallbackCommands,
		operatorFeedbackDispatchPlan,
		operatorFeedbackDispatcherCommands,
		dispatcherFeedbackScoreboard,
		dispatcherLearningHints,
		operatorVerificationLines,
		operatorEscalationQueue,
	} as const;
}

export type OperatorPolicyRuntime = ReturnType<typeof createOperatorPolicyRuntime>;
