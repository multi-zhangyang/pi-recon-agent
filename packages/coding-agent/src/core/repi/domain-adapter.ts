import type {
	RuntimeAdapterExecutionArtifactV1,
	RuntimeAdapterExecutionRowV1,
	RuntimeAdapterParserSignalSummaryV1,
	RuntimeAdapterTargetProfileV1,
} from "./runtime-adapter.ts";
import {
	inspectRuntimeAdapterTarget,
	materializeRuntimeAdapterCommand,
	parseRuntimeAdapterEvidenceLines,
	parseRuntimeAdapterSignals,
	summarizeRuntimeAdapterSignals,
} from "./runtime-adapter.ts";
import { shellQuote } from "./target.ts";

export type DomainAdapterRunner = "native" | "fallback";

export type DomainAdapterPlan = {
	target: string;
	timeoutMs: number;
};

export type DomainAdapterCommandResult = {
	code: number | null;
	killed: boolean;
	stdout: string;
	stderr: string;
};

export type DomainAdapterExecution = {
	adapter: RuntimeAdapterExecutionRowV1;
	targetProfile: RuntimeAdapterTargetProfileV1;
	selectedRunner: DomainAdapterRunner;
	command: string;
	timeoutMs: number;
	startedAt: string;
	finishedAt: string;
	result: DomainAdapterCommandResult;
	parserSignals: RuntimeAdapterExecutionArtifactV1["parserSignals"];
	evidenceLines: string[];
	verification: RuntimeAdapterParserSignalSummaryV1;
};

export type DomainAdapterReplay = {
	adapterId: string;
	target: string;
	command: string;
	timeoutMs: number;
};

export type DomainAdapterExecutionContext = {
	run(command: string, timeoutMs: number): Promise<DomainAdapterCommandResult>;
};

/** The only professional-runtime protocol consumed by REPI orchestration. */
export interface DomainAdapter {
	readonly id: string;
	readonly domainId: string;
	inspect(target: string): RuntimeAdapterTargetProfileV1;
	execute(plan: DomainAdapterPlan, context: DomainAdapterExecutionContext): Promise<DomainAdapterExecution>;
	verify(execution: DomainAdapterExecution): RuntimeAdapterParserSignalSummaryV1;
	replay(execution: DomainAdapterExecution): DomainAdapterReplay;
}

export function createDomainAdapter(spec: RuntimeAdapterExecutionRowV1): DomainAdapter {
	return {
		id: spec.adapterId,
		domainId: spec.domainId,
		inspect: inspectRuntimeAdapterTarget,
		async execute(plan, context) {
			const selectedRunner: DomainAdapterRunner = spec.present ? "native" : "fallback";
			const template = selectedRunner === "native" ? spec.commandTemplate : spec.fallbackCommandTemplate;
			const command = materializeRuntimeAdapterCommand(template, plan.target);
			const targetProfile = inspectRuntimeAdapterTarget(plan.target);
			const startedAt = new Date().toISOString();
			const result = await context.run(command, plan.timeoutMs);
			const finishedAt = new Date().toISOString();
			const parserSignals = parseRuntimeAdapterSignals(spec, `${result.stdout}\n${result.stderr}`);
			const evidenceLines = parseRuntimeAdapterEvidenceLines(spec, `${result.stdout}\n${result.stderr}`);
			return {
				adapter: spec,
				targetProfile,
				selectedRunner,
				command,
				timeoutMs: plan.timeoutMs,
				startedAt,
				finishedAt,
				result,
				parserSignals,
				evidenceLines,
				verification: summarizeRuntimeAdapterSignals(spec, parserSignals),
			};
		},
		verify: (execution) => execution.verification,
		replay: (execution) => ({
			adapterId: spec.adapterId,
			target: execution.targetProfile.target,
			command: `re_runtime_adapter run ${spec.adapterId} ${shellQuote(execution.targetProfile.target)}`,
			timeoutMs: execution.timeoutMs,
		}),
	};
}

export class DomainAdapterRegistry {
	private readonly adapters = new Map<string, DomainAdapter>();

	constructor(adapters: readonly DomainAdapter[]) {
		for (const adapter of adapters) {
			if (this.adapters.has(adapter.id)) throw new Error(`Duplicate DomainAdapter id: ${adapter.id}`);
			this.adapters.set(adapter.id, adapter);
		}
	}

	get(id: string): DomainAdapter | undefined {
		return this.adapters.get(id);
	}

	list(): DomainAdapter[] {
		return [...this.adapters.values()];
	}
}
