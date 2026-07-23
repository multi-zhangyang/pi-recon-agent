import { existsSync, lstatSync, readFileSync, realpathSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";
import { getAgentDir } from "../../config.ts";
import type { AgentThreadRunManifest } from "../agent-thread-contract.ts";
import { readAgentThreadRunManifest } from "../agent-thread-manifest-runtime.ts";
import { handoffManifestPatchFromSnapshot, readHandoffSnapshot, sha256 } from "../agent-thread-runtime.ts";
import type { RepiSubagentResultV1 } from "./re-subagent-contract.ts";

export interface RepiSubagentArtifactExpectation {
	missionId: string;
	spec: string;
	task: string;
	taskSha256: string;
}

export interface RepiSubagentArtifactValidationSuccess {
	ok: true;
	result: RepiSubagentResultV1;
	manifest: AgentThreadRunManifest;
}

export interface RepiSubagentArtifactValidationFailure {
	ok: false;
	error: string;
}

export type RepiSubagentArtifactValidation =
	| RepiSubagentArtifactValidationSuccess
	| RepiSubagentArtifactValidationFailure;

type UnknownRecord = Record<string, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringField(value: UnknownRecord, name: string): string | undefined {
	const field = value[name];
	return typeof field === "string" && field.length > 0 ? field : undefined;
}

function sameString(value: unknown, expected: string): boolean {
	return typeof value === "string" && value === expected;
}

function sameNullableString(value: unknown, expected: string | undefined): boolean {
	return value === (expected ?? null);
}

function reject(error: string): RepiSubagentArtifactValidationFailure {
	return { ok: false, error };
}

function isSafeRunId(runId: string): boolean {
	return /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(runId) && !runId.includes("..") && runId.length <= 160;
}

function fixedRunPaths(
	agentDir: string,
	runId: string,
): {
	runsRoot: string;
	runRoot: string;
	manifestPath: string;
	handoffPath: string;
	mergePath: string;
} {
	const runsRoot = resolve(agentDir, "recon", "agent-threads");
	const runRoot = join(runsRoot, runId);
	const relativeRunRoot = relative(runsRoot, runRoot);
	if (!relativeRunRoot || relativeRunRoot.startsWith("..") || relativeRunRoot.includes("/../")) {
		throw new Error("run id resolves outside the AgentThread root");
	}
	return {
		runsRoot,
		runRoot,
		manifestPath: join(runRoot, "manifest.json"),
		handoffPath: join(runRoot, "handoff.md"),
		mergePath: join(runRoot, "merge.md"),
	};
}

function manifestMatchesExpectation(
	manifest: AgentThreadRunManifest,
	expected: RepiSubagentArtifactExpectation,
): string | undefined {
	if (manifest.status !== "complete" || manifest.exitCode !== 0) {
		return `manifest is not a successful terminal run (status=${manifest.status}, exitCode=${manifest.exitCode ?? "null"})`;
	}
	if (manifest.error) return "successful manifest unexpectedly contains an error";
	if (manifest.specName !== expected.spec) return "manifest spec does not match the delegation gate";
	if (manifest.task !== expected.task) return "manifest task does not match the delegation gate";
	if (manifest.missionId !== expected.missionId) return "manifest mission does not match the delegation gate";
	if (manifest.taskSha256 !== expected.taskSha256) return "manifest task hash does not match the delegation gate";
	if (!manifest.taskSha256 || !/^[a-f0-9]{64}$/i.test(manifest.taskSha256)) {
		return "manifest task hash is not a SHA-256 digest";
	}
	if (!manifest.lineageSha256 || !/^[a-f0-9]{64}$/i.test(manifest.lineageSha256)) {
		return "manifest lineage hash is missing or invalid";
	}
	if (!manifest.promptSha256 || !/^[a-f0-9]{64}$/i.test(manifest.promptSha256)) {
		return "manifest prompt hash is missing or invalid";
	}
	return undefined;
}

function rawManifestPathsMatch(paths: ReturnType<typeof fixedRunPaths>): string | undefined {
	let raw: unknown;
	try {
		raw = JSON.parse(readFileSync(paths.manifestPath, "utf8"));
	} catch (error) {
		return `raw manifest cannot be read: ${error instanceof Error ? error.message : String(error)}`;
	}
	if (!isRecord(raw) || raw.kind !== "repi-agent-thread-run" || raw.schemaVersion !== 1) {
		return "raw manifest has an unsupported contract";
	}
	for (const [field, expected] of [
		["runRoot", paths.runRoot],
		["manifestPath", paths.manifestPath],
		["handoffPath", paths.handoffPath],
		["mergePath", paths.mergePath],
	] as const) {
		if (raw[field] !== expected) return `raw manifest ${field} is redirected from the fixed run path`;
	}
	return undefined;
}

function realArtifactPathsMatch(paths: ReturnType<typeof fixedRunPaths>): string | undefined {
	try {
		for (const [label, path] of [
			["AgentThread root", paths.runsRoot],
			["run directory", paths.runRoot],
			["manifest.json", paths.manifestPath],
			["handoff.md", paths.handoffPath],
			["merge.md", paths.mergePath],
		] as const) {
			if (lstatSync(path).isSymbolicLink()) return `${label} must not be a symbolic link`;
		}
		const realRunsRoot = realpathSync(paths.runsRoot);
		const realRunRoot = realpathSync(paths.runRoot);
		const relativeRunRoot = relative(realRunsRoot, realRunRoot);
		if (!relativeRunRoot || relativeRunRoot.startsWith("..")) {
			return "real run directory resolves outside the AgentThread root";
		}
		for (const path of [paths.manifestPath, paths.handoffPath, paths.mergePath]) {
			if (realpathSync(path) !== join(realRunRoot, basename(path))) {
				return `${basename(path)} is redirected outside the fixed run directory`;
			}
		}
		return undefined;
	} catch (error) {
		return `fixed artifact path cannot be resolved: ${error instanceof Error ? error.message : String(error)}`;
	}
}

function manifestDetailsMatch(
	details: UnknownRecord,
	manifest: AgentThreadRunManifest,
	paths: ReturnType<typeof fixedRunPaths>,
): string | undefined {
	if (!sameString(details.runId, manifest.runId)) return "details run id does not match manifest";
	if (!sameString(details.spec, manifest.specName)) return "details spec does not match manifest";
	if (!sameString(details.task, manifest.task)) return "details task does not match manifest";
	if (!sameString(details.taskSha256, manifest.taskSha256 ?? "")) return "details task hash does not match manifest";
	if (!sameNullableString(details.missionId, manifest.missionId)) return "details mission does not match manifest";
	if (!sameString(details.runRoot, paths.runRoot)) return "details run root is not the fixed AgentThread root";
	if (!sameString(details.mergePath, paths.mergePath)) return "details merge path is not the fixed run path";
	if (!sameString(details.handoffPath, paths.handoffPath)) return "details handoff path is not the fixed run path";
	if (manifest.mergePath !== paths.mergePath || !existsSync(paths.mergePath))
		return "merge artifact is missing or redirected";
	if (manifest.handoffPath !== paths.handoffPath) return "manifest handoff path is redirected";
	if (
		manifest.handoffPresent !== true ||
		manifest.handoffRecovered === true ||
		manifest.handoffLineageValid !== true
	) {
		return "manifest handoff is absent, recovered, or lineage-invalid";
	}
	if (details.handoffPresent !== true) return "details handoff is not present";
	if (details.handoffRecovered !== false) return "recovered handoff cannot satisfy the delegation gate";
	if (details.handoffLineageValid !== true) return "details handoff lineage is invalid";
	return undefined;
}

function snapshotMatches(
	details: UnknownRecord,
	manifest: AgentThreadRunManifest,
	paths: ReturnType<typeof fixedRunPaths>,
): string | undefined {
	if (!manifest.handoffBytes || !manifest.handoffSha256 || !manifest.handoffRunId || !manifest.handoffMissionId) {
		return "manifest handoff metadata is incomplete";
	}
	if (!manifest.handoffLineageSha256 || manifest.handoffLineageSha256 !== manifest.lineageSha256) {
		return "manifest handoff lineage is not bound to the run lineage";
	}
	if (!/^[a-f0-9]{64}$/i.test(manifest.handoffSha256) || !/^[a-f0-9]{64}$/i.test(manifest.handoffLineageSha256)) {
		return "manifest handoff hash is invalid";
	}
	let snapshot: ReturnType<typeof readHandoffSnapshot>;
	try {
		snapshot = readHandoffSnapshot(paths.handoffPath);
	} catch (error) {
		return `handoff artifact cannot be read: ${error instanceof Error ? error.message : String(error)}`;
	}
	if (snapshot.bytes !== manifest.handoffBytes || snapshot.sha256 !== manifest.handoffSha256) {
		return "handoff bytes or SHA-256 does not match manifest";
	}
	if (details.handoffBytes !== snapshot.bytes || details.handoffSha256 !== snapshot.sha256) {
		return "details handoff bytes or SHA-256 does not match the artifact";
	}
	if (!sameString(details.handoffRunId, manifest.handoffRunId))
		return "details handoff run id does not match manifest";
	if (!sameString(details.handoffMissionId, manifest.handoffMissionId)) {
		return "details handoff mission does not match manifest";
	}
	if (!sameString(details.handoffLineageSha256, manifest.handoffLineageSha256)) {
		return "details handoff lineage does not match manifest";
	}
	if (!sameString(details.lineageSha256, manifest.lineageSha256)) return "details lineage does not match manifest";
	const patch = handoffManifestPatchFromSnapshot(snapshot, {
		runId: manifest.runId,
		missionId: manifest.missionId,
		lineageSha256: manifest.lineageSha256 ?? "",
	});
	if (
		patch.handoffLineageValid !== true ||
		patch.handoffBytes !== manifest.handoffBytes ||
		patch.handoffSha256 !== manifest.handoffSha256 ||
		patch.handoffRunId !== manifest.handoffRunId ||
		patch.handoffMissionId !== manifest.handoffMissionId ||
		patch.handoffLineageSha256 !== manifest.handoffLineageSha256
	) {
		return "handoff header lineage or metadata does not match the manifest";
	}
	return undefined;
}

/**
 * Validate a re_subagent result against the persisted process run and handoff.
 * Details are treated as claims only; the fixed AgentThread directory is authoritative.
 */
export async function validateRepiSubagentArtifact(
	details: unknown,
	expected: RepiSubagentArtifactExpectation,
	options: { agentDir?: string; fallbackCwd?: string } = {},
): Promise<RepiSubagentArtifactValidation> {
	if (!expected.missionId || !expected.spec || !expected.task) {
		return reject("delegation gate expectation is incomplete");
	}
	if (!isRecord(details)) return reject("re_subagent details are not an object");
	if (details.kind !== "RepiSubagentResultV1" || details.schemaVersion !== 1) {
		return reject("re_subagent details have an unsupported result contract");
	}
	if (details.status !== "complete" || details.exitCode !== 0) {
		return reject("re_subagent result is not a successful terminal result");
	}
	if (details.error !== undefined) return reject("successful re_subagent result unexpectedly contains an error");
	const runId = stringField(details, "runId");
	if (!runId || !isSafeRunId(runId)) return reject("re_subagent run id is missing or unsafe");
	if (!sameString(details.spec, expected.spec)) return reject("re_subagent spec does not match the delegation gate");
	if (!sameString(details.task, expected.task)) return reject("re_subagent task does not match the delegation gate");
	if (!sameString(details.missionId, expected.missionId))
		return reject("re_subagent mission does not match the delegation gate");
	if (!sameString(details.taskSha256, expected.taskSha256))
		return reject("re_subagent task hash does not match the delegation gate");
	if (!/^[a-f0-9]{64}$/i.test(expected.taskSha256) || (await sha256(expected.task)) !== expected.taskSha256) {
		return reject("delegation gate task hash is invalid");
	}
	if (details.handoffBytes !== null && typeof details.handoffBytes !== "number")
		return reject("handoff bytes are invalid");
	const agentDir = resolve(options.agentDir ?? getAgentDir());
	let paths: ReturnType<typeof fixedRunPaths>;
	try {
		paths = fixedRunPaths(agentDir, runId);
	} catch (error) {
		return reject(error instanceof Error ? error.message : String(error));
	}
	const manifest = readAgentThreadRunManifest(paths.runsRoot, runId, options.fallbackCwd ?? process.cwd());
	if (!manifest) return reject("persisted AgentThread manifest is missing or invalid");
	const rawPathError = rawManifestPathsMatch(paths);
	if (rawPathError) return reject(rawPathError);
	const realPathError = realArtifactPathsMatch(paths);
	if (realPathError) return reject(realPathError);
	if (manifest.manifestPath !== paths.manifestPath || manifest.runRoot !== paths.runRoot) {
		return reject("manifest paths are redirected from the fixed AgentThread root");
	}
	const manifestError = manifestMatchesExpectation(manifest, expected);
	if (manifestError) return reject(manifestError);
	if ((await sha256(manifest.task)) !== manifest.taskSha256)
		return reject("manifest task hash does not match manifest task");
	const recomputedLineageSha256 = await sha256(
		JSON.stringify({
			schemaVersion: 1,
			runId: manifest.runId,
			parentRunId: manifest.parentRunId ?? null,
			missionId: manifest.missionId ?? null,
			parentLineageSha256: manifest.parentLineageSha256 ?? null,
			taskSha256: manifest.taskSha256,
			promptSha256: manifest.promptSha256,
		}),
	);
	if (manifest.lineageSha256 !== recomputedLineageSha256) {
		return reject("manifest lineage hash does not match the run metadata");
	}
	const detailsError = manifestDetailsMatch(details, manifest, paths);
	if (detailsError) return reject(detailsError);
	const snapshotError = snapshotMatches(details, manifest, paths);
	if (snapshotError) return reject(snapshotError);
	const latest = readAgentThreadRunManifest(paths.runsRoot, runId, options.fallbackCwd ?? process.cwd());
	if (
		!latest ||
		latest.status !== manifest.status ||
		latest.exitCode !== manifest.exitCode ||
		latest.specName !== manifest.specName ||
		latest.task !== manifest.task ||
		latest.taskSha256 !== manifest.taskSha256 ||
		latest.missionId !== manifest.missionId ||
		latest.promptSha256 !== manifest.promptSha256 ||
		latest.handoffBytes !== manifest.handoffBytes ||
		latest.handoffSha256 !== manifest.handoffSha256 ||
		latest.handoffRunId !== manifest.handoffRunId ||
		latest.handoffMissionId !== manifest.handoffMissionId ||
		latest.handoffLineageSha256 !== manifest.handoffLineageSha256 ||
		latest.lineageSha256 !== manifest.lineageSha256 ||
		rawManifestPathsMatch(paths) !== undefined
	) {
		return reject("AgentThread manifest changed during artifact validation");
	}
	const latestSnapshotError = snapshotMatches(details, latest, paths);
	if (latestSnapshotError) {
		return reject(`handoff changed during artifact validation: ${latestSnapshotError}`);
	}
	return { ok: true, result: details as unknown as RepiSubagentResultV1, manifest };
}
