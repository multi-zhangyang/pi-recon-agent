import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { AgentThreadRunManifest } from "./agent-thread-contract.ts";
import { isAgentThreadStatus } from "./agent-thread-runtime.ts";

function stringArray(value: unknown): string[] {
	return Array.isArray(value) && value.every((item) => typeof item === "string") ? value : [];
}

/**
 * Read persisted run metadata while deriving all execution paths from the run
 * directory. A damaged manifest must not redirect merge/log reads or break the
 * interactive listing commands with malformed optional values.
 */
export function readAgentThreadRunManifest(
	runsRoot: string,
	runId: string,
	fallbackCwd: string,
): AgentThreadRunManifest | undefined {
	const runRoot = join(runsRoot, runId);
	const manifestPath = join(runRoot, "manifest.json");
	if (!existsSync(manifestPath)) return undefined;
	try {
		const parsed: unknown = JSON.parse(readFileSync(manifestPath, "utf8"));
		if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return undefined;
		const raw = parsed as Record<string, unknown>;
		const specName = raw.specName;
		const task = raw.task;
		if (
			raw.runId !== runId ||
			typeof specName !== "string" ||
			typeof task !== "string" ||
			!isAgentThreadStatus(raw.status)
		) {
			return undefined;
		}

		const manifest: AgentThreadRunManifest = {
			kind: "repi-agent-thread-run",
			schemaVersion: 1,
			runId,
			specName,
			task,
			status: raw.status,
			createdAt: typeof raw.createdAt === "string" ? raw.createdAt : "",
			cwd: typeof raw.cwd === "string" ? raw.cwd : fallbackCwd,
			runRoot,
			agentDir: join(runRoot, "agent-home"),
			stdoutPath: join(runRoot, "stdout.txt"),
			stderrPath: join(runRoot, "stderr.txt"),
			manifestPath,
			handoffPath: join(runRoot, "handoff.md"),
			...(existsSync(join(runRoot, "merge.md")) ? { mergePath: join(runRoot, "merge.md") } : {}),
			tools: stringArray(raw.tools),
			mcpServers: stringArray(raw.mcpServers),
			mcpTools: stringArray(raw.mcpTools),
		};

		type OptionalStringField =
			| "startedAt"
			| "endedAt"
			| "signal"
			| "handoffSha256"
			| "handoffRunId"
			| "handoffMissionId"
			| "handoffLineageSha256"
			| "provider"
			| "model"
			| "taskSha256"
			| "parentRunId"
			| "missionId"
			| "parentLineageSha256"
			| "lineageSha256"
			| "cancelledAt"
			| "promptSha256"
			| "stdoutSha256"
			| "stderrSha256"
			| "error";
		const copyString = <Key extends OptionalStringField>(key: Key): void => {
			const value = raw[key];
			if (typeof value === "string") manifest[key] = value;
		};
		for (const key of [
			"startedAt",
			"endedAt",
			"signal",
			"handoffSha256",
			"handoffRunId",
			"handoffMissionId",
			"handoffLineageSha256",
			"provider",
			"model",
			"taskSha256",
			"parentRunId",
			"missionId",
			"parentLineageSha256",
			"lineageSha256",
			"cancelledAt",
			"promptSha256",
			"stdoutSha256",
			"stderrSha256",
			"error",
		] as const) {
			copyString(key);
		}

		type OptionalBooleanField =
			| "handoffPresent"
			| "handoffRecovered"
			| "handoffLineageValid"
			| "mcpToolFilterActive"
			| "mcpInherited";
		const copyBoolean = <Key extends OptionalBooleanField>(key: Key): void => {
			const value = raw[key];
			if (typeof value === "boolean") manifest[key] = value;
		};
		for (const key of [
			"handoffPresent",
			"handoffRecovered",
			"handoffLineageValid",
			"mcpToolFilterActive",
			"mcpInherited",
		] as const) {
			copyBoolean(key);
		}

		type OptionalNumberField = "pid" | "handoffBytes" | "timeoutMs" | "maxTurns";
		const copyFiniteNumber = <Key extends OptionalNumberField>(key: Key): void => {
			const value = raw[key];
			if (typeof value === "number" && Number.isFinite(value)) manifest[key] = value;
		};
		for (const key of ["pid", "handoffBytes", "timeoutMs", "maxTurns"] as const) copyFiniteNumber(key);
		if (raw.exitCode === null || (typeof raw.exitCode === "number" && Number.isFinite(raw.exitCode))) {
			manifest.exitCode = raw.exitCode;
		}
		if (raw.cancelSignal === "SIGTERM") manifest.cancelSignal = "SIGTERM";
		return manifest;
	} catch {
		return undefined;
	}
}
