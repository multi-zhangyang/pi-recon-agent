import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import type {
	RuntimeAdapterExecutionArtifactV1,
	RuntimeAdapterParserRuleV1,
	RuntimeAdapterParserSignalSummaryV1,
} from "./runtime-adapter.ts";
import {
	evidenceProofLoopsDir,
	evidenceToolchainDir,
	readJsonObjectFile,
	readTextFile,
	recentMarkdownArtifacts,
} from "./storage.ts";

export type RuntimeAdapterExecutionGraphArtifact = RuntimeAdapterExecutionArtifactV1 & {
	stdoutHead?: string;
	stderrHead?: string;
};

export type RuntimeAdapterGraphParserSummary = RuntimeAdapterParserSignalSummaryV1;
type RuntimeAdapterGraphEvidenceRank = RuntimeAdapterParserRuleV1["evidenceRank"];

export type RuntimeAdapterMitigationGraphEvidence = {
	kind: "binary-mitigation-map";
	expected: boolean;
	matched: boolean;
	status: "matched" | "declared" | "missing-proof";
	proofExitSignal: "binary mitigation map";
	evidence: string[];
	missing: string[];
};

export type RepiProofLoopGraphStep = {
	id: string;
	phase: string;
	command: string;
	status: "ready" | "done" | "blocked" | "skipped" | string;
	reason?: string;
	sourceArtifacts: string[];
};

export type RepiProofLoopGraphExecution = {
	stepId: string;
	command: string;
	status: "ready" | "done" | "blocked" | "skipped" | string;
	output: string;
};

export type RepiProofLoopGraphArtifact = {
	timestamp?: string;
	missionId?: string;
	route?: string;
	target?: string;
	mode: "plan" | "run";
	maxSteps?: number;
	replaySteps?: number;
	steps: RepiProofLoopGraphStep[];
	executed: RepiProofLoopGraphExecution[];
	verdict?: "ready" | "partial" | "needs_repair" | "blocked" | string;
	gapClassifier: string[];
	quickPath: string[];
	quickPlanPhases: string[];
	quickPlanAssertions: string[];
	runtimeAdapterClosure: string[];
	nextActions: string[];
	sourceArtifacts: string[];
};

function isStringArray(value: unknown): value is string[] {
	return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function stringArray(value: unknown): string[] {
	return isStringArray(value) ? value : [];
}

function normalizeProofLoopStep(value: unknown): RepiProofLoopGraphStep | undefined {
	if (typeof value !== "object" || value === null) return undefined;
	const row = value as Record<string, unknown>;
	if (typeof row.id !== "string" || typeof row.phase !== "string" || typeof row.command !== "string") {
		return undefined;
	}
	return {
		id: row.id,
		phase: row.phase,
		command: row.command,
		status: typeof row.status === "string" ? row.status : "ready",
		reason: typeof row.reason === "string" ? row.reason : undefined,
		sourceArtifacts: stringArray(row.sourceArtifacts),
	};
}

function normalizeProofLoopExecution(value: unknown): RepiProofLoopGraphExecution | undefined {
	if (typeof value !== "object" || value === null) return undefined;
	const row = value as Record<string, unknown>;
	if (typeof row.stepId !== "string" || typeof row.command !== "string") return undefined;
	return {
		stepId: row.stepId,
		command: row.command,
		status: typeof row.status === "string" ? row.status : "blocked",
		output: typeof row.output === "string" ? row.output : "",
	};
}

export function runtimeAdapterParserSummaryForGraph(
	artifact: RuntimeAdapterExecutionGraphArtifact,
): RuntimeAdapterGraphParserSummary {
	if (artifact.parserSignalSummary) return artifact.parserSignalSummary;
	const matchedSignals = artifact.parserSignals.filter(
		(signal) => Array.isArray(signal.matches) && signal.matches.length > 0,
	);
	const matchedProofExitSignals = Array.from(
		new Set(
			matchedSignals.map((signal) => signal.proofExitSignal).filter((signal): signal is string => Boolean(signal)),
		),
	);
	const missingProofExitSignals = artifact.proofExitSignals.filter(
		(signal) => !matchedProofExitSignals.includes(signal),
	);
	const evidenceRanks = Array.from(
		new Set(
			matchedSignals
				.map((signal) => signal.evidenceRank)
				.filter((rank): rank is RuntimeAdapterGraphEvidenceRank => Boolean(rank)),
		),
	);
	return {
		matchedRules: matchedSignals.length,
		totalRules: artifact.parserSignals.length,
		matchCount: matchedSignals.reduce((sum, signal) => sum + signal.matches.length, 0),
		evidenceRanks,
		matchedProofExitSignals,
		missingProofExitSignals,
	};
}

const BINARY_MITIGATION_PROOF_SIGNAL = "binary mitigation map";
const MITIGATION_LINE_PATTERN =
	/\[(?:native|pwn)-mitigation\]|binary[- ]mitigation|GNU_STACK|GNU_RELRO|BIND_NOW|RELRO|NX|PIE|canary|fortify/i;

function uniqueStrings(values: string[]): string[] {
	return Array.from(new Set(values.filter((item) => item.trim().length > 0)));
}

function mitigationStreamLines(artifact: RuntimeAdapterExecutionGraphArtifact): string[] {
	return uniqueStrings(
		[artifact.stdoutHead ?? "", artifact.stderrHead ?? ""]
			.join("\n")
			.split(/\r?\n/)
			.map((line) => line.trim())
			.filter((line) => MITIGATION_LINE_PATTERN.test(line))
			.slice(0, 12),
	);
}

export function runtimeAdapterMitigationEvidenceForGraph(
	artifact: RuntimeAdapterExecutionGraphArtifact,
): RuntimeAdapterMitigationGraphEvidence | undefined {
	const proofSignals = artifact.proofExitSignals ?? [];
	const artifactKinds = artifact.artifactKinds ?? [];
	const expected =
		artifactKinds.includes("binary-mitigation-map") ||
		proofSignals.some((signal) => signal.toLowerCase() === BINARY_MITIGATION_PROOF_SIGNAL);
	const mitigationSignals = artifact.parserSignals.filter(
		(signal) =>
			signal.proofExitSignal.toLowerCase() === BINARY_MITIGATION_PROOF_SIGNAL || /mitigation/i.test(signal.ruleId),
	);
	const matchedParserEvidence = mitigationSignals.flatMap((signal) => signal.matches ?? []);
	const streamEvidence = mitigationStreamLines(artifact);
	const evidence = uniqueStrings([
		...matchedParserEvidence,
		...streamEvidence,
		artifactKinds.includes("binary-mitigation-map") ? "artifact_kind=binary-mitigation-map" : "",
		proofSignals.includes(BINARY_MITIGATION_PROOF_SIGNAL) ? `proof_exit=${BINARY_MITIGATION_PROOF_SIGNAL}` : "",
	]).slice(0, 16);
	const matched = matchedParserEvidence.length > 0 || streamEvidence.length > 0;
	if (!expected && !matched) return undefined;
	const missing = expected && !matched ? [BINARY_MITIGATION_PROOF_SIGNAL] : [];
	return {
		kind: "binary-mitigation-map",
		expected,
		matched,
		status: matched ? "matched" : expected ? "missing-proof" : "declared",
		proofExitSignal: BINARY_MITIGATION_PROOF_SIGNAL,
		evidence,
		missing,
	};
}

export function isRuntimeAdapterExecutionGraphArtifact(row: unknown): row is RuntimeAdapterExecutionGraphArtifact {
	if (typeof row !== "object" || row === null) return false;
	const record = row as Record<string, unknown>;
	return (
		record.kind === "RuntimeAdapterExecutionArtifactV1" &&
		record.schemaVersion === 1 &&
		typeof record.adapterId === "string" &&
		typeof record.domainId === "string" &&
		typeof record.bridgeId === "string" &&
		typeof record.startedAt === "string" &&
		typeof record.finishedAt === "string" &&
		typeof record.command === "string" &&
		typeof record.stdoutSha256 === "string" &&
		typeof record.stderrSha256 === "string" &&
		Array.isArray(record.parserSignals) &&
		Array.isArray(record.artifactKinds) &&
		Array.isArray(record.ingestTargets) &&
		Array.isArray(record.proofExitSignals)
	);
}

export function recentRuntimeAdapterExecutionArtifacts(
	limit = 8,
): Array<{ path: string; artifact: RuntimeAdapterExecutionGraphArtifact }> {
	const root = join(evidenceToolchainDir(), "runtime-adapters");
	try {
		return readdirSync(root, { withFileTypes: true })
			.filter((entry) => entry.isDirectory())
			.flatMap((entry) => {
				const dir = join(root, entry.name);
				return readdirSync(dir, { withFileTypes: true })
					.filter((file) => file.isFile() && file.name.endsWith(".json"))
					.map((file) => {
						const path = join(dir, file.name);
						let mtimeMs = 0;
						try {
							mtimeMs = statSync(path).mtimeMs;
						} catch {
							mtimeMs = 0;
						}
						return { path, mtimeMs };
					});
			})
			.sort((left, right) => right.mtimeMs - left.mtimeMs || right.path.localeCompare(left.path))
			.slice(0, limit)
			.map(({ path }) => {
				const artifact = readJsonObjectFile<unknown>(path);
				return isRuntimeAdapterExecutionGraphArtifact(artifact) ? { path, artifact } : undefined;
			})
			.filter((item): item is { path: string; artifact: RuntimeAdapterExecutionGraphArtifact } => Boolean(item));
	} catch {
		return [];
	}
}

export function parseProofLoopArtifact(path: string): RepiProofLoopGraphArtifact | undefined {
	const match = /```json\s*([\s\S]*?)\s*```/m.exec(readTextFile(path));
	if (!match?.[1]) return undefined;
	try {
		const parsed = JSON.parse(match[1]) as Record<string, unknown>;
		if (!(parsed.mode === "plan" || parsed.mode === "run")) return undefined;
		if (!Array.isArray(parsed.steps) || !Array.isArray(parsed.executed)) return undefined;
		const steps = parsed.steps
			.map(normalizeProofLoopStep)
			.filter((step): step is RepiProofLoopGraphStep => Boolean(step));
		const executed = parsed.executed
			.map(normalizeProofLoopExecution)
			.filter((execution): execution is RepiProofLoopGraphExecution => Boolean(execution));
		return {
			timestamp: typeof parsed.timestamp === "string" ? parsed.timestamp : undefined,
			missionId: typeof parsed.missionId === "string" ? parsed.missionId : undefined,
			route: typeof parsed.route === "string" ? parsed.route : undefined,
			target: typeof parsed.target === "string" ? parsed.target : undefined,
			mode: parsed.mode,
			maxSteps: typeof parsed.maxSteps === "number" ? parsed.maxSteps : undefined,
			replaySteps: typeof parsed.replaySteps === "number" ? parsed.replaySteps : undefined,
			steps,
			executed,
			verdict: typeof parsed.verdict === "string" ? parsed.verdict : undefined,
			gapClassifier: stringArray(parsed.gapClassifier),
			quickPath: stringArray(parsed.quickPath),
			quickPlanPhases: stringArray(parsed.quickPlanPhases),
			quickPlanAssertions: stringArray(parsed.quickPlanAssertions),
			runtimeAdapterClosure: stringArray(parsed.runtimeAdapterClosure),
			nextActions: stringArray(parsed.nextActions),
			sourceArtifacts: stringArray(parsed.sourceArtifacts),
		};
	} catch {
		return undefined;
	}
}

export function recentProofLoopArtifacts(limit = 4): Array<{ path: string; proof: RepiProofLoopGraphArtifact }> {
	return recentMarkdownArtifacts(evidenceProofLoopsDir(), limit)
		.map((path) => {
			const proof = parseProofLoopArtifact(path);
			return proof ? { path, proof } : undefined;
		})
		.filter((item): item is { path: string; proof: RepiProofLoopGraphArtifact } => Boolean(item));
}
