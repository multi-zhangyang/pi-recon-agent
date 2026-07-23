import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { artifactScopeDefaultOptions, artifactTargetMatches } from "./artifact-scope.ts";
import type { RuntimeExecutionProofRow } from "./claim-release-runtime.ts";
import type {
	DomainProofExitClosureStatus,
	DomainProofExitClosureV1,
	DomainProofExitRowV1,
} from "./domain-proof-exit-rules.ts";
import type { EvidenceRecord } from "./evidence.ts";
import { recentRuntimeAdapterExecutionArtifacts } from "./graph-artifacts.ts";
import type { MissionCheckpointStatus, MissionState } from "./mission.ts";
import { ensureReconStorage } from "./resources.ts";
import {
	evidenceBrowserDir,
	evidenceExploitLabDir,
	evidenceMobileRuntimeDir,
	evidenceNativeRuntimeDir,
	evidenceProofLoopsDir,
	evidenceReplayersDir,
	evidenceToolchainDir,
	evidenceVerifiersDir,
	evidenceWebAuthzDir,
	readTextFile,
	recentMarkdownArtifacts,
	writePrivateTextFile,
} from "./storage.ts";
import { sanitizeTargetForCommand } from "./target.ts";
import { interestingLines, parseJsonCodeFence, truncateMiddle, uniqueNonEmpty } from "./text.ts";
import type { ToolchainDomainCapabilityV1 } from "./toolchain-runtime.ts";

type EvidenceInput = Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number };

export type DomainProofExitRuntimeDependencies = {
	readCurrentMission: () => MissionState | undefined;
	buildToolchainDomainCapability: (domainFilter?: string) => ToolchainDomainCapabilityV1;
	toolchainDomainIdForRoute: (routeDomain?: string) => string | undefined;
	proofExitRegexes: (proofExit: string) => RegExp[];
	proofExitExpectedEvidence: (proofExit: string) => string[];
	domainProofExitNextCommands: (domainId: string, proofExit: string, mission?: MissionState) => string[];
	appendEvidence: (record: EvidenceInput) => EvidenceRecord;
	updateMissionCheckpoint: (name: string, status: MissionCheckpointStatus, note?: string) => MissionState | undefined;
};

export function createDomainProofExitRuntime(dependencies: DomainProofExitRuntimeDependencies) {
	const {
		readCurrentMission,
		buildToolchainDomainCapability,
		toolchainDomainIdForRoute,
		proofExitRegexes,
		proofExitExpectedEvidence,
		domainProofExitNextCommands,
		appendEvidence,
		updateMissionCheckpoint,
	} = dependencies;

	function proofArtifactJson(text: string): Record<string, unknown> | undefined {
		const parsed = parseJsonCodeFence<unknown>(text);
		return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: undefined;
	}

	function isRuntimeProofSha256(value: unknown): value is string {
		return typeof value === "string" && /^[a-f0-9]{64}$/i.test(value);
	}

	function successfulExecutionEvidence(value: Record<string, unknown>): string | undefined {
		if (value.mode !== "run") return undefined;
		const target = [value.target, value.url, value.packageName].find(
			(item): item is string => typeof item === "string" && item.trim().length > 0,
		);
		if (!target) return undefined;
		const rawExecutions = Array.isArray(value.executions)
			? value.executions
			: Array.isArray(value.executed)
				? value.executed
				: [];
		const evidence: string[] = [];
		for (const raw of rawExecutions) {
			if (typeof raw !== "object" || raw === null || Array.isArray(raw)) continue;
			const execution = raw as RuntimeExecutionProofRow;
			const status = typeof execution.status === "string" ? execution.status.toLowerCase() : "";
			const command = typeof execution.command === "string" ? execution.command.trim() : "";
			const exit = typeof execution.exit === "number" ? execution.exit : undefined;
			const stdoutHash = execution.stdoutHash ?? execution.stdoutSha256 ?? execution.stdout_sha256;
			const stderrHash = execution.stderrHash ?? execution.stderrSha256 ?? execution.stderr_sha256;
			if (
				!(status === "passed" || status === "done") ||
				!command ||
				(exit !== undefined && exit !== 0) ||
				!isRuntimeProofSha256(stdoutHash) ||
				!isRuntimeProofSha256(stderrHash)
			) {
				continue;
			}
			for (const item of [execution.stdoutHead, execution.stderrHead, execution.output]) {
				if (typeof item === "string" && item.trim()) evidence.push(item.trim());
			}
		}
		if (evidence.length === 0) return undefined;
		for (const key of ["runtimeAnchors", "stabilityAnchors"] as const) {
			const items = value[key];
			if (!Array.isArray(items)) continue;
			for (const item of items) {
				if (typeof item === "string" && item.trim()) evidence.push(item.trim());
			}
		}
		return uniqueNonEmpty(evidence, 120).join("\n");
	}

	function runtimeAdapterProofEvidence(
		entry: ReturnType<typeof recentRuntimeAdapterExecutionArtifacts>[number],
	): string | undefined {
		const { artifact } = entry;
		if (
			artifact.exitCode !== 0 ||
			artifact.killed ||
			!artifact.target?.trim() ||
			!artifact.command.trim() ||
			!isRuntimeProofSha256(artifact.stdoutSha256) ||
			!isRuntimeProofSha256(artifact.stderrSha256)
		) {
			return undefined;
		}
		const evidence = [artifact.stdoutHead ?? "", artifact.stderrHead ?? ""];
		for (const signal of artifact.parserSignals) {
			for (const match of signal.matches ?? []) {
				if (match.trim()) evidence.push(match.trim());
			}
		}
		const concrete = uniqueNonEmpty(evidence, 120);
		return concrete.length > 0 ? concrete.join("\n") : undefined;
	}

	function domainProofExitArtifactCorpus(mission?: MissionState): {
		sources: string[];
		text: string;
		hash: string;
		evidenceByPath: Map<string, string>;
	} {
		ensureReconStorage();
		const expectedTarget = artifactScopeDefaultOptions().target;
		const expectedDomain = toolchainDomainIdForRoute(mission?.route.domain);
		const paths = new Set<string>([
			...recentMarkdownArtifacts(evidenceBrowserDir(), 4),
			...recentMarkdownArtifacts(evidenceWebAuthzDir(), 4),
			...recentMarkdownArtifacts(evidenceNativeRuntimeDir(), 4),
			...recentMarkdownArtifacts(evidenceMobileRuntimeDir(), 4),
			...recentMarkdownArtifacts(evidenceExploitLabDir(), 4),
			...recentMarkdownArtifacts(evidenceReplayersDir(), 4),
			...recentMarkdownArtifacts(evidenceVerifiersDir(), 4),
			...recentMarkdownArtifacts(evidenceProofLoopsDir(), 4),
		]);
		const parts: string[] = [];
		const sources: string[] = [];
		const evidenceByPath = new Map<string, string>();
		for (const path of paths) {
			if (!path || !existsSync(path)) continue;
			const artifact = proofArtifactJson(readTextFile(path));
			if (!artifact || !mission || artifact.missionId !== mission.id) continue;
			const artifactTarget = [artifact.target, artifact.url, artifact.packageName].find(
				(item): item is string => typeof item === "string" && item.trim().length > 0,
			);
			if (
				expectedTarget &&
				artifactTarget &&
				!artifactTargetMatches(expectedTarget, sanitizeTargetForCommand(artifactTarget) ?? artifactTarget)
			)
				continue;
			const evidence = successfulExecutionEvidence(artifact);
			if (!evidence) continue;
			sources.push(path);
			evidenceByPath.set(path, evidence);
			parts.push(`\n--- executed-artifact:${path} ---\n${truncateMiddle(evidence, 16000)}`);
		}
		for (const entry of recentRuntimeAdapterExecutionArtifacts(12, {
			missionId: mission?.id,
			target: expectedTarget,
		})) {
			if (!mission) continue;
			if (expectedDomain && entry.artifact.domainId !== expectedDomain) continue;
			if (
				expectedTarget &&
				(!entry.artifact.target ||
					!artifactTargetMatches(
						expectedTarget,
						sanitizeTargetForCommand(entry.artifact.target) ?? entry.artifact.target,
					))
			)
				continue;
			const evidence = runtimeAdapterProofEvidence(entry);
			if (!evidence) continue;
			sources.push(entry.path);
			evidenceByPath.set(entry.path, evidence);
			parts.push(`\n--- runtime-adapter:${entry.path} ---\n${truncateMiddle(evidence, 16000)}`);
		}
		const corpus = parts.join("\n");
		return {
			sources,
			text: corpus,
			hash: createHash("sha256").update(corpus).digest("hex"),
			evidenceByPath,
		};
	}

	function buildDomainProofExitClosure(
		mission = readCurrentMission(),
		domainFilter?: string,
	): DomainProofExitClosureV1 {
		const routeDomain = mission?.route.domain;
		const requestedCapability = domainFilter
			? buildToolchainDomainCapability(domainFilter.trim()).domains[0]
			: undefined;
		const domainId = requestedCapability?.domainId ?? toolchainDomainIdForRoute(routeDomain);
		const capability =
			requestedCapability ?? (domainId ? buildToolchainDomainCapability(domainId).domains[0] : undefined);
		const corpus = domainProofExitArtifactCorpus(mission);
		if (!mission || !domainId || !capability) {
			return {
				kind: "DomainProofExitClosureV1",
				schemaVersion: 1,
				generatedAt: new Date().toISOString(),
				missionId: mission?.id,
				routeDomain,
				domainId,
				status: "blocked",
				toolchainStatus: capability?.status,
				artifactCorpusHash: corpus.hash,
				artifactSources: corpus.sources,
				rows: [],
				matchedProofExits: [],
				missingProofExits: [],
				blockers: mission
					? ["domain proof-exit route is not mapped to a specialized toolchain domain"]
					: ["no active mission"],
				nextRuntimeCommands: ["re_mission new <task>", "re_route <task>", "re_toolchain_domain show"],
			};
		}
		const rows = capability.proofExit.map<DomainProofExitRowV1>((proofExit) => {
			const regexes = proofExitRegexes(proofExit);
			const matchedLines = uniqueNonEmpty(
				regexes.flatMap((pattern) => interestingLines(corpus.text, pattern, 6)),
				10,
			);
			const matchedArtifacts = corpus.sources.filter((path) => {
				const text = corpus.evidenceByPath.get(path) ?? "";
				return regexes.some((pattern) => pattern.test(text));
			});
			return {
				proofExit,
				status: matchedLines.length || matchedArtifacts.length ? "matched" : "missing",
				matchedArtifacts: matchedArtifacts.slice(0, 8),
				matchedLines: matchedLines.slice(0, 8),
				expectedEvidence: proofExitExpectedEvidence(proofExit),
				nextCommands: domainProofExitNextCommands(domainId, proofExit, mission),
			};
		});
		const missingProofExits = rows.filter((row) => row.status === "missing").map((row) => row.proofExit);
		const matchedProofExits = rows.filter((row) => row.status === "matched").map((row) => row.proofExit);
		const status: DomainProofExitClosureStatus =
			missingProofExits.length === 0
				? "passed"
				: matchedProofExits.length > 0 || corpus.sources.length > 1
					? "partial"
					: "blocked";
		const blockers = [
			...(capability.status === "blocked"
				? [
						`toolchain critical_gap for ${domainId}: ${capability.missingRequired.join(", ") || "requiredAny missing"}`,
					]
				: []),
			...missingProofExits.map((proofExit) => `domain_proof_exit_missing:${domainId}:${proofExit}`),
		];
		return {
			kind: "DomainProofExitClosureV1",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			missionId: mission.id,
			routeDomain,
			domainId,
			status,
			toolchainStatus: capability.status,
			artifactCorpusHash: corpus.hash,
			artifactSources: corpus.sources,
			rows,
			matchedProofExits,
			missingProofExits,
			blockers,
			nextRuntimeCommands: uniqueNonEmpty(
				[
					`re_toolchain_domain show ${domainId}`,
					...rows.filter((row) => row.status === "missing").flatMap((row) => row.nextCommands),
					"re_verifier matrix",
					"re_proof_loop run <target> 4 2",
				],
				14,
			),
		};
	}

	function formatDomainProofExitClosure(report: DomainProofExitClosureV1, path?: string): string {
		return [
			"domain_proof_exit_closure:",
			"DomainProofExitClosureV1: true",
			path ? `artifact: ${path}` : undefined,
			`status: ${report.status}`,
			`domain: ${report.domainId ?? "unmapped"}`,
			`route: ${report.routeDomain ?? "unknown"}`,
			`toolchain_status: ${report.toolchainStatus ?? "unknown"}`,
			`artifact_corpus_sha256: ${report.artifactCorpusHash}`,
			`artifact_sources: ${report.artifactSources.length}`,
			"proof_exit_rows:",
			...(report.rows.length
				? report.rows.flatMap((row) => [
						`- proof_exit: ${row.proofExit}`,
						`  status: ${row.status}`,
						`  matched_artifacts: ${row.matchedArtifacts.join(", ") || "none"}`,
						`  matched_lines: ${row.matchedLines.map((line) => truncateMiddle(line.replace(/\s+/g, " "), 220)).join(" | ") || "none"}`,
						`  expected_evidence: ${row.expectedEvidence.join(" | ")}`,
						`  next: ${row.nextCommands.slice(0, 5).join(" | ")}`,
					])
				: ["- none"]),
			"missing:",
			...(report.missingProofExits.length ? report.missingProofExits.map((item) => `- ${item}`) : ["- none"]),
			"blockers:",
			...(report.blockers.length ? report.blockers.map((item) => `- ${item}`) : ["- none"]),
			"next_runtime_commands:",
			...report.nextRuntimeCommands.map((item) => `- ${item}`),
		]
			.filter(Boolean)
			.join("\n");
	}

	function writeDomainProofExitClosureArtifact(report: DomainProofExitClosureV1): string {
		ensureReconStorage();
		const path = join(
			evidenceToolchainDir(),
			`${report.generatedAt.replace(/[:.]/g, "-")}-${report.domainId ?? "unmapped"}-domain-proof-exit-closure.md`,
		);
		writePrivateTextFile(
			path,
			`${formatDomainProofExitClosure(report)}\n\n## JSON\n\n\`\`\`json\n${JSON.stringify(report, null, 2)}\n\`\`\`\n`,
		);
		appendEvidence({
			kind: "artifact",
			title: "domain-proof-exit-closure",
			fact: `DomainProofExitClosureV1 domain=${report.domainId ?? "unmapped"} status=${report.status} missing=${report.missingProofExits.length}`,
			command: "re_domain_proof_exit show",
			path,
			hash: report.artifactCorpusHash,
			verify: `cat ${path}`,
			confidence: "domain proof-exit closure bound to ToolchainDomainCapabilityV1 and runtime artifacts",
		});
		updateMissionCheckpoint(
			"minimal_path_proven",
			report.status === "passed" ? "done" : report.matchedProofExits.length ? "pending" : "blocked",
			`DomainProofExitClosureV1 ${report.status}`,
		);
		return path;
	}

	function buildDomainProofExitClosureOutput(action: "show" | "write" = "show", domainFilter?: string): string {
		const report = buildDomainProofExitClosure(readCurrentMission(), domainFilter);
		if (action === "write") {
			const path = writeDomainProofExitClosureArtifact(report);
			return formatDomainProofExitClosure(report, path);
		}
		return formatDomainProofExitClosure(report);
	}

	return {
		buildDomainProofExitClosure,
		buildDomainProofExitClosureOutput,
		formatDomainProofExitClosure,
		writeDomainProofExitClosureArtifact,
	};
}
