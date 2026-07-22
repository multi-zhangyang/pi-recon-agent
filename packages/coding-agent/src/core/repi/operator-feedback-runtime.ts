import type { OperationExecution } from "./campaign-operation-runtime.ts";
import { shellQuote } from "./target.ts";
import { truncateMiddle } from "./text.ts";

export type OperatorFeedbackSource = {
	executed: OperationExecution[];
	commanderDispatchReport: string[];
	target?: string;
};

export type OperatorFeedbackRuntimeDependencies = {
	latestSwarmRetryQueue: (target?: string) => { rows: string[]; commands: string[] };
};

export function createOperatorFeedbackRuntime(dependencies: OperatorFeedbackRuntimeDependencies) {
	function bootstrapToolFromCommand(command: string): string | undefined {
		const token = command
			.trim()
			.split(/\s+/)[0]
			?.replace(/^['"]|['"]$/g, "");
		if (!token || /^(set|test|cat|printf|sed|grep|rg|awk|bash|sh|python|node)$/i.test(token)) return undefined;
		return token;
	}

	function operatorFeedbackToolHint(text: string, command: string): string | undefined {
		const commandNotFound =
			/(?:command not found|not found|No such file or directory|cannot stat|ModuleNotFoundError|ImportError)[:\s]+([A-Za-z0-9_.+:-]+)/i.exec(
				text,
			)?.[1];
		const raw = commandNotFound ?? bootstrapToolFromCommand(command);
		if (!raw) return undefined;
		return raw
			.replace(/^['"]|['"]$/g, "")
			.split(/[/:]/)
			.pop();
	}

	function operatorFeedbackRow(params: {
		category: string;
		execution?: OperationExecution;
		command?: string;
		status?: string;
		next: string;
		evidence: string;
		operatorArtifact?: string;
	}): string {
		const command = params.execution?.command ?? params.command ?? "none";
		const status = params.execution?.status ?? params.status ?? "unknown";
		const step = params.execution?.stepId ? ` step=${params.execution.stepId}` : "";
		return [
			`category=${params.category}`,
			`status=${status}`,
			step.trim(),
			`command=${shellQuote(truncateMiddle(command, 180))}`,
			`next=${params.next}`,
			`evidence=${shellQuote(truncateMiddle(params.evidence, 260))}`,
			params.operatorArtifact ? `source=${params.operatorArtifact}` : undefined,
		]
			.filter(Boolean)
			.join(" ");
	}

	function classifyOperatorFeedback(
		operator: OperatorFeedbackSource,
		operatorArtifact?: string,
		target?: string,
	): string[] {
		const rows: string[] = [];
		const targetRef = target ?? operator.target ?? "<target>";
		for (const execution of operator.executed) {
			const text = `${execution.command}\n${execution.output}`;
			const evidence = execution.output.replace(/\s+/g, " ");
			const successfulControlPlaneCommand =
				execution.status === "done" &&
				/^re[-_](?:mission|kernel|decision[-_]core|operator|tool[-_]index)\b/i.test(execution.command);
			const unresolvedTarget =
				/<target>|<TARGET>|<URL>|<none>/i.test(execution.command) ||
				/(?:target placeholder is unresolved|unresolved target|missing required target)/i.test(execution.output);
			if (unresolvedTarget) {
				rows.push(
					operatorFeedbackRow({
						category: "unresolved_target",
						execution,
						next: `re_map ${targetRef === "<target>" ? "." : targetRef} 2`,
						evidence,
						operatorArtifact,
					}),
				);
				continue;
			}
			if (successfulControlPlaneCommand) continue;
			if (/unsupported operation command|internal REPI command/i.test(text)) {
				rows.push(
					operatorFeedbackRow({
						category: "dispatcher_gap",
						execution,
						next: `re_operator escalate ${targetRef}`,
						evidence,
						operatorArtifact,
					}),
				);
				continue;
			}
			if (
				/command not found|No such file|cannot stat|ModuleNotFoundError|ImportError|not found|cannot access/i.test(
					text,
				)
			) {
				const tool = operatorFeedbackToolHint(text, execution.command) ?? "tool";
				rows.push(
					operatorFeedbackRow({
						category: "missing_tool_or_dependency",
						execution,
						next: `re_bootstrap plan ${tool}`,
						evidence,
						operatorArtifact,
					}),
				);
				continue;
			}
			if (/retry_queue|swarm_retry_queue|execution_audit|coverage_matrix|re_swarm run|worker=/i.test(text)) {
				rows.push(
					operatorFeedbackRow({
						category: execution.status === "blocked" ? "worker_retry_blocked" : "worker_retry_progress",
						execution,
						next: `re_swarm run ${targetRef} 1 1`,
						evidence,
						operatorArtifact,
					}),
				);
				continue;
			}
			const explicitRuntimeFailure =
				/\b(?:exit|exit_code|status_code)\s*[=:]\s*[1-9]\d*\b/i.test(execution.output) ||
				/\b(?:killed|timed_out)\s*[=:]\s*true\b/i.test(execution.output) ||
				/\bexecution_status\s*:\s*(?:failed|blocked|error)\b/i.test(execution.output) ||
				/\b(?:runtime|tool|command)_error\s*:/i.test(execution.output);
			if (execution.status === "blocked" || explicitRuntimeFailure) {
				rows.push(
					operatorFeedbackRow({
						category: "runtime_failure",
						execution,
						next: `re_autofix plan ${targetRef}`,
						evidence,
						operatorArtifact,
					}),
				);
				continue;
			}
			if (/stdout_sha256|stderr_sha256|replay_matrix|exploit_lab|PoC|poc|payload|crash|offset|RIP|EIP/i.test(text)) {
				rows.push(
					operatorFeedbackRow({
						category: "replay_or_exploit_candidate",
						execution,
						next: /exploit|poc|payload|crash|offset|RIP|EIP/i.test(text)
							? `re_exploit_lab run ${targetRef} 3 60000`
							: `re_replayer run ${targetRef} 1`,
						evidence,
						operatorArtifact,
					}),
				);
				continue;
			}
			if (/artifact|path:|verify:|hash|anchor|checkpoint|proof|verifier_matrix|compiler_report/i.test(text)) {
				rows.push(
					operatorFeedbackRow({
						category: "strong_evidence",
						execution,
						next: "re_verifier matrix",
						evidence,
						operatorArtifact,
					}),
				);
			}
		}
		for (const line of operator.commanderDispatchReport) {
			if (/failure_budget_exhausted|stop_dispatch=true/i.test(line)) {
				rows.push(
					operatorFeedbackRow({
						category: "failure_budget_exhausted",
						command: "commander_dispatch_report",
						status: "blocked",
						next: `re_proof_loop run ${targetRef} 4 2`,
						evidence: line,
						operatorArtifact,
					}),
				);
			}
		}
		const swarmRetry = dependencies.latestSwarmRetryQueue(target ?? operator.target);
		for (const row of swarmRetry.rows.slice(0, 8)) {
			rows.push(
				operatorFeedbackRow({
					category: "swarm_retry_queue",
					command: "swarm_retry_queue",
					status: "queued",
					next: swarmRetry.commands[0] ?? `re_swarm run ${targetRef} 1 1`,
					evidence: row,
					operatorArtifact,
				}),
			);
		}
		return Array.from(new Set(rows)).slice(0, 40);
	}

	return { classifyOperatorFeedback } as const;
}

export type OperatorFeedbackRuntime = ReturnType<typeof createOperatorFeedbackRuntime>;
