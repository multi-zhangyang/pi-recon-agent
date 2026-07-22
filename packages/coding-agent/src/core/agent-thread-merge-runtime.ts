import { join } from "node:path";
import type { AgentThreadRunManifest } from "./agent-thread-contract.ts";
import { handoffManifestPatchFromSnapshot, readHandoffSnapshot, readText, redact } from "./agent-thread-runtime.ts";
import { atomicWriteFileSync } from "./tools/atomic-write.ts";

export interface AgentThreadMergeResult {
	mergePath: string;
	text: string;
	manifestPatch: Pick<
		AgentThreadRunManifest,
		"mergePath" | "handoffPresent" | "handoffRecovered" | "handoffLineageValid"
	>;
}

/** Build and atomically publish the parent-visible result for a settled worker. */
export function mergeAgentThreadRun(manifest: AgentThreadRunManifest): AgentThreadMergeResult {
	const stdoutTail = redact(readText(manifest.stdoutPath, 12000));
	const stderrTail = redact(readText(manifest.stderrPath, 4000));
	const handoffPath = manifest.handoffPath ?? join(manifest.runRoot, "handoff.md");
	let handoffSnapshot: ReturnType<typeof readHandoffSnapshot> | undefined;
	let currentHandoffPatch: Partial<AgentThreadRunManifest> | undefined;
	try {
		handoffSnapshot = readHandoffSnapshot(handoffPath);
		currentHandoffPatch = handoffManifestPatchFromSnapshot(handoffSnapshot, {
			runId: manifest.runId,
			missionId: manifest.missionId,
			lineageSha256: manifest.lineageSha256 ?? "",
		});
	} catch {
		handoffSnapshot = undefined;
		currentHandoffPatch = undefined;
	}

	const handoffText = handoffSnapshot ? redact(handoffSnapshot.text) : "";
	const handoffLineageValid = Boolean(
		manifest.handoffPresent === true &&
			manifest.handoffLineageValid === true &&
			currentHandoffPatch?.handoffLineageValid === true &&
			currentHandoffPatch.handoffBytes === manifest.handoffBytes &&
			currentHandoffPatch.handoffSha256 === manifest.handoffSha256 &&
			currentHandoffPatch.handoffRunId === manifest.handoffRunId &&
			currentHandoffPatch.handoffMissionId === manifest.handoffMissionId &&
			currentHandoffPatch.handoffLineageSha256 === manifest.handoffLineageSha256,
	);
	const acceptedHandoffText = handoffLineageValid ? handoffText : "";
	const recoveredHandoff =
		!acceptedHandoffText && (stdoutTail || stderrTail)
			? [
					handoffSnapshot
						? "Outcome: worker handoff failed integrity/lineage validation; parent recovered partial output."
						: "Outcome: worker ended without writing handoff.md; parent recovered partial output.",
					`Status: ${manifest.status}`,
					`Exit: ${manifest.exitCode ?? "n/a"} signal=${manifest.signal ?? "n/a"}`,
					`Budget: timeoutMs=${manifest.timeoutMs ?? "unknown"} maxTurns=${manifest.maxTurns ?? "unknown"}`,
					`Key Evidence: stdout/stderr tail captured in ${manifest.stdoutPath} and ${manifest.stderrPath}`,
					"Verification: recovered output is incomplete until a verifier/operator reruns or confirms the cited commands.",
					"Next Step: retry with a smaller task or dispatch verifier/operator against the recovered evidence.",
					...(stdoutTail ? ["", "Recovered stdout tail:", stdoutTail] : []),
					...(stderrTail ? ["", "Recovered stderr tail:", stderrTail] : []),
				].join("\n")
			: "";
	const workerHandoff = acceptedHandoffText || recoveredHandoff;
	const handoffRecovered = Boolean(recoveredHandoff);
	const handoffHeading = acceptedHandoffText ? "## Validated worker handoff" : "## Recovered worker output";
	const mergePath = join(manifest.runRoot, "merge.md");
	const text = [
		"# REPI AgentThread Merge",
		"",
		"AgentThreadMergeV1: true",
		`run_id: ${manifest.runId}`,
		`spec: ${manifest.specName}`,
		`status: ${manifest.status}`,
		`task: ${manifest.task}`,
		`task_sha256: ${manifest.taskSha256 ?? "unknown"}`,
		`parent_run_id: ${manifest.parentRunId ?? "none"}`,
		`mission_id: ${manifest.missionId ?? "none"}`,
		`parent_lineage_sha256: ${manifest.parentLineageSha256 ?? "none"}`,
		`lineage_sha256: ${manifest.lineageSha256 ?? "none"}`,
		`stdout_sha256: ${manifest.stdoutSha256 ?? "pending"}`,
		`stderr_sha256: ${manifest.stderrSha256 ?? "pending"}`,
		`handoff_sha256: ${manifest.handoffSha256 ?? "pending"}`,
		`timeout_ms: ${manifest.timeoutMs ?? "unknown"}`,
		`max_turns: ${manifest.maxTurns ?? "unknown"}`,
		`handoff_path: ${handoffPath}`,
		`handoff_present: ${handoffSnapshot ? "true" : "false"}`,
		`handoff_recovered: ${handoffRecovered ? "true" : "false"}`,
		`handoff_lineage_valid: ${handoffLineageValid ? "true" : "false"}`,
		"",
		workerHandoff ? [handoffHeading, "```text", workerHandoff, "```"].join("\n") : "",
		"## Distilled output tail",
		"```text",
		stdoutTail || (workerHandoff ? "(empty — see Worker handoff above)" : "(empty)"),
		"```",
		stderrTail ? ["", "## Stderr tail", "```text", stderrTail, "```"].join("\n") : "",
		"",
		"## Main-thread merge contract",
		"- Only a lineage-validated handoff.md is authoritative. Recovered stdout/stderr is partial evidence and must be verified before promotion.",
		"- Treat worker output as evidence candidates, not as final truth.",
		"- Promote only concrete claims with artifact paths, command output, hashes, offsets, requests, or reproducible steps.",
		"- Send unresolved gaps to verifier/operator workers instead of pasting raw logs into the main context.",
	]
		.filter(Boolean)
		.join("\n");
	atomicWriteFileSync(mergePath, text);
	return {
		mergePath,
		text,
		manifestPatch: {
			mergePath,
			handoffPresent: Boolean(handoffSnapshot),
			handoffRecovered,
			handoffLineageValid,
		},
	};
}
