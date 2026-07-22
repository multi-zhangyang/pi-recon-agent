import { join } from "node:path";
import { evidenceSwarmsDir } from "./storage.ts";
import type { SwarmArtifact } from "./swarm-runtime-types.ts";
import { slug } from "./text.ts";

type SwarmPathInput = Pick<SwarmArtifact, "artifactId" | "timestamp" | "route" | "mode">;

function artifactToken(artifactId: string): string {
	return artifactId.replace(/[^a-z0-9]/gi, "").slice(0, 24) || "artifact";
}

/** Canonical filenames for swarm artifacts and their derived runtime records. */
export function swarmArtifactPath(swarm: SwarmPathInput): string {
	return join(
		evidenceSwarmsDir(),
		`${swarm.timestamp.replace(/[:.]/g, "-")}-${slug(swarm.route ?? "swarm")}-${swarm.mode}-${artifactToken(swarm.artifactId)}.md`,
	);
}

export function swarmClaimLedgerPath(swarm: SwarmPathInput): string {
	return swarmArtifactPath(swarm).replace(/\.md$/i, "-claim-ledger.jsonl");
}

export function swarmStructuredClaimMergePath(swarm: SwarmPathInput): string {
	return swarmArtifactPath(swarm).replace(/\.md$/i, "-structured-claim-merge.json");
}

export function swarmSubagentRuntimeManifestIndexPath(swarm: SwarmPathInput): string {
	return swarmArtifactPath(swarm).replace(/\.md$/i, "-subagent-runtime-manifests.json");
}

export function swarmWorkerChildSessionRuntimePath(swarm: SwarmPathInput): string {
	return swarmArtifactPath(swarm).replace(/\.md$/i, "-worker-child-session-runtime.json");
}

export function swarmWorkerRetryHandoffClosurePath(swarm: SwarmPathInput): string {
	return swarmArtifactPath(swarm).replace(/\.md$/i, "-worker-retry-handoff-closure.json");
}

export function swarmWorkerRetryHandoffMergeSummaryPath(swarm: SwarmPathInput): string {
	return swarmArtifactPath(swarm).replace(/\.md$/i, "-worker-retry-handoff-merge-summary.json");
}

export function swarmWorkerLeaseSchedulerPath(swarm: SwarmPathInput): string {
	return swarmArtifactPath(swarm).replace(/\.md$/i, "-worker-lease-scheduler.json");
}

export function swarmSubagentSessionRoot(swarm: SwarmPathInput): string {
	return swarmArtifactPath(swarm).replace(/\.md$/i, "-sessions");
}
