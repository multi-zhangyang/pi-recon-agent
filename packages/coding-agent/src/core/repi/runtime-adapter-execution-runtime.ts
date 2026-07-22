import { mkdirSync } from "node:fs";
import { join } from "node:path";
import type { ExtensionAPI } from "../extensions/types.ts";
import { atomicWriteFileSync } from "../tools/atomic-write.ts";
import { commandKnownTools, parseToolIndex } from "./bootstrap-runtime.ts";
import { createDomainAdapter } from "./domain-adapter.ts";
import type { EvidenceRecord } from "./evidence.ts";
import { readCurrentMission } from "./mission.ts";
import { ensureReconStorage } from "./resources.ts";
import {
	buildRuntimeAdapterExecutionGate,
	detectRuntimeAdapterIds,
	formatRuntimeAdapterExecutionArtifact,
	formatRuntimeAdapterExecutionGate,
	materializeRuntimeAdapterCommand,
	type RuntimeAdapterExecutionArtifactV1,
	type RuntimeAdapterExecutionCheckV1,
} from "./runtime-adapter.ts";
import { evidenceToolchainDir, toolIndexPath, writePrivateTextFile } from "./storage.ts";
import { shellQuote } from "./target.ts";
import { sha256Text, truncateMiddle } from "./text.ts";
import { repiResolvedToolPresent } from "./tool-presence.ts";

type AppendEvidence = (
	record: Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number },
) => EvidenceRecord;

export type RuntimeAdapterExecutionDependencies = {
	appendEvidence: AppendEvidence;
};

export function createRuntimeAdapterExecutionRuntime(dependencies: RuntimeAdapterExecutionDependencies) {
	const { appendEvidence } = dependencies;

	function buildExecutionGate(adapterFilter?: string): RuntimeAdapterExecutionCheckV1 {
		ensureReconStorage();
		const index = parseToolIndex();
		return buildRuntimeAdapterExecutionGate(adapterFilter, {
			toolIndexPath: toolIndexPath(),
			isToolPresent: (tool) => repiResolvedToolPresent(index, tool),
		});
	}

	function writeExecutionArtifact(report: RuntimeAdapterExecutionCheckV1): string {
		ensureReconStorage();
		const path = join(
			evidenceToolchainDir(),
			`${report.generatedAt.replace(/[:.]/g, "-")}-runtime-adapter-execution.md`,
		);
		writePrivateTextFile(
			path,
			`${formatRuntimeAdapterExecutionGate(report, path)}\n\n## JSON\n\n\`\`\`json\n${JSON.stringify(report, null, 2)}\n\`\`\`\n`,
		);
		appendEvidence({
			kind: "artifact",
			title: "runtime-adapter-execution",
			fact: `RuntimeAdapterExecutionCheckV1 adapters=${report.adapters.length} runner=${report.closure.allHaveRunnerTemplates} parser=${report.closure.allHaveParserRules} ingest=${report.closure.allHaveIngestTargets}`,
			command: "re_runtime_adapter show",
			path,
			verify: `cat ${path}`,
			confidence: "runtime:adapter-execution adapter_runner_parser_ingest_contract evidence-ledger",
		});
		return path;
	}

	async function runExecution(
		pi: ExtensionAPI,
		options: { adapter?: string; target?: string; timeoutMs?: number },
	): Promise<string> {
		const inferredAdapter = options.adapter ?? detectRuntimeAdapterIds(options.target)[0];
		const report = buildExecutionGate(inferredAdapter ?? options.target);
		const adapter = report.adapters.find((row) => row.adapterId === inferredAdapter) ?? report.adapters[0];
		if (!adapter) return "runtime_adapter_execution:\nstatus: missing\nnext: re_runtime_adapter show";
		if (!options.target?.trim()) {
			return `${formatRuntimeAdapterExecutionGate(report)}\n\nblocked: target_required\nnext: re_runtime_adapter run ${adapter.adapterId} <target>`;
		}
		const selectedRunner = adapter.present ? "native" : adapter.fallbackPresent ? "fallback" : undefined;
		if (!selectedRunner) {
			const missingTools = Array.from(new Set([adapter.tool, adapter.fallbackTool]));
			appendEvidence({
				kind: "runtime",
				title: `runtime-adapter blocked ${adapter.adapterId}`,
				fact: `RuntimeAdapterExecutionCheckV1 adapter=${adapter.adapterId} blocked=runner_unavailable native=${adapter.tool} fallback=${adapter.fallbackTool}`,
				command: `re_runtime_adapter run ${adapter.adapterId} ${options.target}`,
				verify: `re_bootstrap plan ${missingTools.join(" ")}`,
				confidence: "runtime:adapter-execution runner_preflight_blocked_no_synthetic_success",
			});
			return `${formatRuntimeAdapterExecutionGate(report)}\n\nblocked: runner_unavailable adapter=${adapter.adapterId} native=${adapter.tool} fallback=${adapter.fallbackTool}\nevidence: runner_preflight_blocked_no_synthetic_success\nnext: re_bootstrap plan ${missingTools.join(" ")}`;
		}
		const domainAdapter = createDomainAdapter(adapter);
		const selectedTemplate = selectedRunner === "native" ? adapter.commandTemplate : adapter.fallbackCommandTemplate;
		const command = materializeRuntimeAdapterCommand(selectedTemplate, options.target);
		const index = parseToolIndex();
		const missingCommandTools = commandKnownTools(command).filter(
			(tool) => repiResolvedToolPresent(index, tool) === false,
		);
		if (missingCommandTools.length > 0) {
			appendEvidence({
				kind: "runtime",
				title: `runtime-adapter preflight ${adapter.adapterId}`,
				fact: `RuntimeAdapterExecutionCheckV1 adapter=${adapter.adapterId} blocked=command_tools_missing tools=${missingCommandTools.join(",")}`,
				command: `re_runtime_adapter run ${adapter.adapterId} ${options.target}`,
				verify: `re_bootstrap plan ${missingCommandTools.join(" ")}`,
				confidence: "runtime:adapter-execution command_preflight_blocked_no_synthetic_success",
			});
			return `${formatRuntimeAdapterExecutionGate(report)}\n\nblocked: command_tools_missing adapter=${adapter.adapterId} tools=${missingCommandTools.join(",")}\nevidence: command_preflight_blocked_no_synthetic_success\ncommand: ${command}\nnext: re_bootstrap plan ${missingCommandTools.join(" ")}`;
		}
		const timeout = Math.max(
			5000,
			Math.min(options.timeoutMs ?? Number(process.env.REPI_RUNTIME_ADAPTER_TIMEOUT_MS ?? 60000), 600000),
		);
		const execution = await domainAdapter.execute(
			{ target: options.target, timeoutMs: timeout },
			{
				run: async (adapterCommand, timeoutMs) =>
					pi.exec(
						"bash",
						["-lc", `set +e\nexport REPI_ADAPTER_TARGET=${shellQuote(options.target!)}\n${adapterCommand}`],
						{ timeout: timeoutMs },
					),
			},
		);
		const verification = domainAdapter.verify(execution);
		const replay = domainAdapter.replay(execution);
		const result = execution.result;
		const artifact: RuntimeAdapterExecutionArtifactV1 = {
			kind: "RuntimeAdapterExecutionArtifactV1",
			schemaVersion: 1,
			missionId: readCurrentMission()?.id,
			adapterId: adapter.adapterId,
			domainId: adapter.domainId,
			bridgeId: adapter.bridgeId,
			target: options.target,
			targetProfile: execution.targetProfile,
			startedAt: execution.startedAt,
			finishedAt: execution.finishedAt,
			selectedRunner: execution.selectedRunner,
			exitCode: result.code,
			killed: result.killed,
			stdoutSha256: sha256Text(result.stdout),
			stderrSha256: sha256Text(result.stderr),
			parserSignals: execution.parserSignals,
			parserSignalSummary: verification,
			evidenceLines: execution.evidenceLines,
			artifactKinds: adapter.artifactKinds,
			ingestTargets: adapter.ingestTargets,
			proofExitSignals: adapter.proofExitSignals,
			replay: { command: replay.command, timeoutMs: replay.timeoutMs },
			command: execution.command,
		};
		const dir = join(evidenceToolchainDir(), "runtime-adapters", adapter.adapterId);
		mkdirSync(dir, { recursive: true });
		const path = join(dir, `${execution.startedAt.replace(/[:.]/g, "-")}.json`);
		atomicWriteFileSync(
			path,
			`${JSON.stringify({ ...artifact, stdoutHead: truncateMiddle(result.stdout, 8000), stderrHead: truncateMiddle(result.stderr, 4000) }, null, 2)}\n`,
			0o644,
		);
		appendEvidence({
			kind: "runtime",
			title: `runtime-adapter ${adapter.adapterId}`,
			fact: `RuntimeAdapterExecutionCheckV1 adapter=${adapter.adapterId} runner=${selectedRunner} exit=${result.code} parser_matches=${artifact.parserSignals.reduce((sum, row) => sum + row.matches.length, 0)} ingest=evidence-ledger`,
			command: `re_runtime_adapter run ${adapter.adapterId} ${options.target}`,
			path,
			verify: `cat ${path}`,
			confidence:
				"runtime:adapter-execution adapter_runner_parser_ingest_contract runner_output_parser_must_write_artifact",
		});
		return formatRuntimeAdapterExecutionArtifact(artifact, path);
	}

	return {
		buildRuntimeAdapterExecutionGate: buildExecutionGate,
		writeRuntimeAdapterExecutionArtifact: writeExecutionArtifact,
		runRuntimeAdapterExecution: runExecution,
	};
}
