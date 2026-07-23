import type { ExtensionAPI } from "../extensions/types.ts";
import type {
	CampaignOperationRuntime,
	OperationExecution,
	OperationStep,
	OperationStepStatus,
} from "./campaign-operation-runtime.ts";
import type { ExploitMobileRuntime } from "./exploit-mobile-runtime.ts";
import { type MissionCheckpointStatus, type MissionState, normalizeOperatorCheckpointUpdate } from "./mission.ts";
import type { NativeRuntime } from "./native-runtime.ts";
import type { ProofArtifactRuntime } from "./proof-artifact-runtime.ts";
import type { createProofLoopRuntime } from "./proof-loop-runtime.ts";
import { REPI_GENERIC_TASK, type RoutePlan } from "./routes.ts";
import type { SwarmSupervisorRuntime } from "./swarm-supervisor-runtime.ts";
import { commandContainsPoison, sanitizeTargetForCommand } from "./target.ts";

export type OperatorExecutionStep = {
	id: string;
	command: string;
	status: OperationStepStatus;
	reason?: string;
	sourceArtifacts: string[];
};

type ProofLoopRuntime = ReturnType<typeof createProofLoopRuntime>;

export type OperatorExecutionRuntimeDependencies = Pick<
	CampaignOperationRuntime,
	"runOperationQueue" | "buildOperationOutput" | "executeOperationStep"
> &
	Pick<ProofArtifactRuntime, "buildVerifierOutput" | "buildCompilerOutput" | "runReplayer" | "buildReplayerOutput"> &
	Pick<ProofLoopRuntime, "runProofLoop" | "buildProofLoopOutput"> &
	Pick<SwarmSupervisorRuntime, "runSwarm" | "buildSwarmOutput" | "buildSupervisorOutput"> &
	Pick<
		ExploitMobileRuntime,
		"runExploitLab" | "buildExploitLabOutput" | "runMobileRuntime" | "buildMobileRuntimeOutput"
	> &
	Pick<NativeRuntime, "runNativeRuntime" | "buildNativeRuntimeOutput"> & {
		buildAutofixOutput: (action?: "plan" | "show" | "apply", options?: { target?: string }) => string;
		buildDelegateOutput: (action?: "plan" | "show" | "merge", options?: { target?: string; task?: string }) => string;
		runAutopilot: (
			pi: ExtensionAPI,
			options: { action?: "plan" | "run"; target?: string; maxAutoSteps?: number },
		) => Promise<string>;
		buildKernelOutput: (action?: "build" | "show" | "audit", options?: { target?: string }) => string;
		runWebAuthzState: (
			pi: ExtensionAPI,
			options?: { target?: string; url?: string; timeoutMs?: number },
		) => Promise<string>;
		buildWebAuthzStateOutput: (
			action?: "plan" | "show",
			options?: { target?: string; url?: string; timeoutMs?: number },
		) => string;
		updateMissionCheckpoint: (name: string, status: MissionCheckpointStatus, note?: string) => MissionState;
		createMission: (task: string, route: RoutePlan) => MissionState;
		writeCurrentMission: (mission: MissionState) => MissionState;
		routeReconTask: (task: string) => RoutePlan;
		formatMission: (mission: MissionState) => string;
		buildMissionDigest: () => string;
	};

export type OperatorExecutionControl = {
	dispatchOperatorQueue: (
		pi: ExtensionAPI,
		options: { target?: string; maxSteps?: number; cwd?: string },
	) => Promise<string>;
	buildOperatorOutput: (action?: "plan" | "show" | "verify" | "escalate", options?: { target?: string }) => string;
};

export function createOperatorExecutionRuntime(dependencies: OperatorExecutionRuntimeDependencies) {
	function operatorCommandConcrete(command: string, target?: string): { command: string; blocked?: string } {
		const normalized = command.trim().replace(/^\//, "");
		if (commandContainsPoison(normalized))
			return { command: normalized, blocked: "natural-language/poison target rejected" };
		if (/<target>|<TARGET>|<URL>|<none>/i.test(normalized)) {
			const safeTarget = sanitizeTargetForCommand(target);
			if (!safeTarget) return { command: normalized, blocked: "target placeholder is unresolved" };
			return { command: normalized.replace(/<target>|<TARGET>|<URL>|<none>/gi, safeTarget) };
		}
		return { command: normalized };
	}

	function operationStepFromOperator(step: OperatorExecutionStep): OperationStep {
		return {
			id: step.id,
			phase: "operator",
			command: step.command.replace(/^re-/i, "re_"),
			status: step.status,
			reason: step.reason,
			sourceArtifacts: step.sourceArtifacts,
		};
	}

	async function executeOperatorStep(
		pi: ExtensionAPI,
		step: OperatorExecutionStep,
		target: string | undefined,
		control: OperatorExecutionControl,
		cwd?: string,
	): Promise<OperationExecution> {
		const command = step.command.trim().replace(/^\//, "");
		const done = (output: string): OperationExecution => ({ stepId: step.id, command, status: "done", output });
		const blocked = (output: string): OperationExecution => ({ stepId: step.id, command, status: "blocked", output });
		if (step.status === "blocked") return blocked(step.reason ?? "operator step is blocked");

		const missionMatch = /^re[-_]mission(?:\s+(show|new|checkpoint))?(?:\s+(.+))?$/i.exec(command);
		if (missionMatch) {
			const action = (missionMatch[1] as "show" | "new" | "checkpoint" | undefined) ?? "show";
			const rest = missionMatch[2]?.trim();
			if (action === "new") {
				const task = rest || target || REPI_GENERIC_TASK;
				return done(
					dependencies.formatMission(
						dependencies.writeCurrentMission(dependencies.createMission(task, dependencies.routeReconTask(task))),
					),
				);
			}
			if (action === "checkpoint") {
				const [checkpoint = "manual_check", status = "done", ...noteParts] = (rest ?? "")
					.split(/\s+/)
					.filter(Boolean);
				const normalizedStatus = ["pending", "done", "blocked"].includes(status)
					? (status as MissionCheckpointStatus)
					: "done";
				const checkpointUpdate = normalizeOperatorCheckpointUpdate(
					checkpoint,
					normalizedStatus,
					noteParts.join(" "),
				);
				return done(
					dependencies.formatMission(
						dependencies.updateMissionCheckpoint(checkpoint, checkpointUpdate.status, checkpointUpdate.note),
					),
				);
			}
			return done(dependencies.buildMissionDigest());
		}

		const kernelMatch = /^re[-_]kernel(?:\s+(build|show|audit))?(?:\s+(.+))?$/i.exec(command);
		if (kernelMatch)
			return done(
				dependencies.buildKernelOutput((kernelMatch[1] as "build" | "show" | "audit") ?? "build", {
					target: kernelMatch[2]?.trim() || target,
				}),
			);

		const autopilotMatch = /^re[-_](?:autopilot|auto)\s+(plan|run)?(?:\s+(.+?))?(?:\s+(\d+))?$/i.exec(command);
		if (autopilotMatch) {
			const action = (autopilotMatch[1] as "plan" | "run") ?? "run";
			const autoTarget = autopilotMatch[2]?.trim() || target;
			const maxAutoSteps = autopilotMatch[3] ? Number(autopilotMatch[3]) : undefined;
			return done(await dependencies.runAutopilot(pi, { action, target: autoTarget, maxAutoSteps }));
		}

		const supervisorMatch = /^re[-_]supervisor\s+(review|show|repair)?(?:\s+(.+))?$/i.exec(command);
		if (supervisorMatch)
			return done(
				await dependencies.buildSupervisorOutput((supervisorMatch[1] as "review" | "show" | "repair") ?? "review", {
					target: supervisorMatch[2]?.trim() || target,
				}),
			);

		const operationMatch = /^re[-_]operation\s+(plan|next|show|run)?(?:\s+(.+?))?(?:\s+(\d+))?$/i.exec(command);
		if (operationMatch) {
			const action = (operationMatch[1] as "plan" | "next" | "show" | "run") ?? "next";
			const opTarget = operationMatch[2]?.trim() || target;
			const maxSteps = operationMatch[3] ? Number(operationMatch[3]) : 1;
			return done(
				action === "run"
					? await dependencies.runOperationQueue(pi, { target: opTarget, maxSteps })
					: dependencies.buildOperationOutput(action, { target: opTarget }),
			);
		}

		const operatorMatch =
			/^re[-_]operator(?:\s+(plan|show|dispatch|verify|escalate))?(?:\s+(.+?))?(?:\s+(\d+))?$/i.exec(command);
		if (operatorMatch) {
			const action = (operatorMatch[1] as "plan" | "show" | "dispatch" | "verify" | "escalate") ?? "plan";
			const opTarget = operatorMatch[2]?.trim() || target;
			const maxSteps = operatorMatch[3] ? Number(operatorMatch[3]) : 1;
			return done(
				action === "dispatch"
					? await control.dispatchOperatorQueue(pi, { target: opTarget, maxSteps, cwd })
					: control.buildOperatorOutput(action, { target: opTarget }),
			);
		}

		const delegateMatch = /^re[-_]delegate\s+(plan|show|merge)?(?:\s+(.+))?$/i.exec(command);
		if (delegateMatch)
			return done(
				dependencies.buildDelegateOutput((delegateMatch[1] as "plan" | "show" | "merge") ?? "plan", {
					target: delegateMatch[2]?.trim() || target,
				}),
			);

		const swarmMatch = /^re[-_]swarm\s+(plan|show|run|merge)?(?:\s+(.+?))?(?:\s+(\d+))?(?:\s+(\d+))?$/i.exec(command);
		if (swarmMatch) {
			const action = (swarmMatch[1] as "plan" | "show" | "run" | "merge") ?? "plan";
			const swarmTarget = swarmMatch[2]?.trim() || target;
			const maxWorkers = swarmMatch[3] ? Number(swarmMatch[3]) : undefined;
			const maxCommands = swarmMatch[4] ? Number(swarmMatch[4]) : undefined;
			return done(
				action === "run"
					? await dependencies.runSwarm(pi, { target: swarmTarget, maxWorkers, maxCommands, cwd })
					: dependencies.buildSwarmOutput(action, { target: swarmTarget }),
			);
		}

		const verifierMatch = /^re[-_]verifier\s+(check|show|matrix)?(?:\s+(.+))?$/i.exec(command);
		if (verifierMatch)
			return done(
				dependencies.buildVerifierOutput((verifierMatch[1] as "check" | "show" | "matrix") ?? "check", {
					target: verifierMatch[2]?.trim() || target,
				}),
			);

		const compilerMatch = /^re[-_]compiler\s+(draft|show|final)?(?:\s+(.+))?$/i.exec(command);
		if (compilerMatch)
			return done(
				dependencies.buildCompilerOutput((compilerMatch[1] as "draft" | "show" | "final") ?? "draft", {
					target: compilerMatch[2]?.trim() || target,
				}),
			);

		const webAuthzStateMatch = /^re[-_]web[-_]authz[-_]state\s+(plan|show|run)?(?:\s+(.+?))?(?:\s+(\d+))?$/i.exec(
			command,
		);
		if (webAuthzStateMatch) {
			const action = (webAuthzStateMatch[1] as "plan" | "show" | "run") ?? "plan";
			const authzTarget = webAuthzStateMatch[2]?.trim() || target;
			const timeoutMs = webAuthzStateMatch[3] ? Number(webAuthzStateMatch[3]) : undefined;
			return done(
				action === "run"
					? await dependencies.runWebAuthzState(pi, { target: authzTarget, timeoutMs })
					: dependencies.buildWebAuthzStateOutput(action, { target: authzTarget, timeoutMs }),
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
					? await dependencies.runMobileRuntime(pi, { target: mobileTarget, packageName, timeoutMs })
					: dependencies.buildMobileRuntimeOutput(action, { target: mobileTarget, packageName, timeoutMs }),
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
					? await dependencies.runNativeRuntime(pi, { target: nativeTarget, timeoutMs })
					: dependencies.buildNativeRuntimeOutput(action, { target: nativeTarget, timeoutMs }),
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
					? await dependencies.runExploitLab(pi, { target: labTarget, runs, timeoutMs })
					: dependencies.buildExploitLabOutput(action, { target: labTarget, runs, timeoutMs }),
			);
		}

		const replayerMatch = /^re[-_]replayer\s+(plan|show|run)?(?:\s+(.+?))?(?:\s+(\d+))?$/i.exec(command);
		if (replayerMatch) {
			const action = (replayerMatch[1] as "plan" | "show" | "run") ?? "plan";
			const replayTarget = replayerMatch[2]?.trim() || target;
			const maxSteps = replayerMatch[3] ? Number(replayerMatch[3]) : undefined;
			return done(
				action === "run"
					? await dependencies.runReplayer(pi, { target: replayTarget, maxSteps })
					: dependencies.buildReplayerOutput(action, { target: replayTarget }),
			);
		}

		const autofixMatch = /^re[-_]autofix\s+(plan|show|apply)?(?:\s+(.+))?$/i.exec(command);
		if (autofixMatch) {
			const action = (autofixMatch[1] as "plan" | "show" | "apply") ?? "plan";
			const output = dependencies.buildAutofixOutput(action, {
				target: autofixMatch[2]?.trim() || target,
			});
			return action === "apply" && /^execution_status: deferred_to_operator$/m.test(output)
				? blocked(output)
				: done(output);
		}

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
					? await dependencies.runProofLoop(pi, { target: loopTarget, maxSteps, replaySteps })
					: dependencies.buildProofLoopOutput(action, { target: loopTarget, maxSteps, replaySteps }),
			);
		}

		const operationResult = await dependencies.executeOperationStep(pi, operationStepFromOperator(step), target);
		return operationResult.status === "blocked" && /unsupported operation command/.test(operationResult.output)
			? blocked(`unsupported operator command: ${command}`)
			: operationResult;
	}

	return { operatorCommandConcrete, executeOperatorStep } as const;
}

export type OperatorExecutionRuntime = ReturnType<typeof createOperatorExecutionRuntime>;
