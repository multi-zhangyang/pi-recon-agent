import {
	type ArtifactScopeFilterOptions,
	artifactMissionMatches,
	artifactScopeDefaultOptions,
	artifactScopeMissionId,
	artifactTargetMatches,
} from "./artifact-scope.ts";
import {
	evidenceAutofixDir,
	evidenceBrowserDir,
	evidenceCampaignsDir,
	evidenceChainsDir,
	evidenceCompilersDir,
	evidenceDecisionsDir,
	evidenceDelegationsDir,
	evidenceExploitLabDir,
	evidenceGraphsDir,
	evidenceMapsDir,
	evidenceMobileRuntimeDir,
	evidenceNativeRuntimeDir,
	evidenceOperationsDir,
	evidenceOperatorsDir,
	evidenceProfileCheckDir,
	evidenceProofLoopsDir,
	evidenceReplayersDir,
	evidenceRunsDir,
	evidenceSupervisorsDir,
	evidenceSwarmsDir,
	evidenceVerifiersDir,
	evidenceWebAuthzDir,
	readTextFile,
	recentMarkdownArtifacts,
} from "./storage.ts";
import { sanitizeTargetForCommand } from "./target.ts";

let selectionCache: Map<string, string[]> | undefined;

export function scopedMarkdownArtifacts(
	kind: string,
	dir: string,
	limit: number,
	options: ArtifactScopeFilterOptions = {},
): string[] {
	const scope = artifactScopeDefaultOptions(options);
	const scanLimit = Math.max(limit, scope.scanLimit ?? Math.max(8, limit * 4));
	const cacheKey = JSON.stringify([
		kind,
		dir,
		limit,
		scope.missionId ?? "",
		scope.route ?? "",
		scope.target ?? "",
		scope.scanLimit ?? "",
		scanLimit,
	]);
	if (scope.write !== true && selectionCache?.has(cacheKey)) return selectionCache.get(cacheKey) ?? [];
	const selected = recentMarkdownArtifacts(dir, scanLimit)
		.filter((path) => {
			const text = readTextFile(path);
			if (!artifactMissionMatches(scope.missionId, artifactScopeMissionId(text))) return false;
			if (!scope.target) return true;
			const declared = /^(?:target|url):\s*(.+)$/im.exec(text)?.[1]?.trim();
			if (!declared || /^<.*>$|none|missing$/i.test(declared)) return true;
			return artifactTargetMatches(scope.target, sanitizeTargetForCommand(declared) ?? declared);
		})
		.slice(0, limit);
	if (scope.write !== true) selectionCache?.set(cacheKey, selected);
	return selected;
}

export function latestScopedMarkdownArtifact(
	kind: string,
	dir: string,
	options: ArtifactScopeFilterOptions = {},
): string | undefined {
	return scopedMarkdownArtifacts(kind, dir, 1, {
		...options,
		requestedBy: options.requestedBy ?? `latest_artifact:${kind}`,
		write: options.write ?? false,
	})[0];
}

export function withScopedMarkdownArtifactSelectionCache<T>(fn: () => T): T {
	if (selectionCache) return fn();
	selectionCache = new Map<string, string[]>();
	try {
		return fn();
	} finally {
		selectionCache = undefined;
	}
}

export function contextEvidenceRank(kind: string): string {
	if (/browser|web_authz|mobile_runtime|native_runtime|exploit_lab|run|replayer|proof_loop/i.test(kind)) {
		return "runtime_artifact";
	}
	if (/map|harness|decision_core|kernel/i.test(kind)) return "process_config";
	if (/compiler|verifier|supervisor|swarm|delegation|operation|operator|autofix/i.test(kind)) {
		return "persisted_state";
	}
	return "artifact";
}

export function contextArtifactIndex(options: ArtifactScopeFilterOptions = {}): Array<{ kind: string; path: string }> {
	const specs: Array<[string, string]> = [
		["map", evidenceMapsDir()],
		["browser", evidenceBrowserDir()],
		["web_authz", evidenceWebAuthzDir()],
		["exploit_lab", evidenceExploitLabDir()],
		["mobile_runtime", evidenceMobileRuntimeDir()],
		["native_runtime", evidenceNativeRuntimeDir()],
		["run", evidenceRunsDir()],
		["attack_graph", evidenceGraphsDir()],
		["exploit_chain", evidenceChainsDir()],
		["decision_core", evidenceDecisionsDir()],
		["campaign", evidenceCampaignsDir()],
		["operation", evidenceOperationsDir()],
		["delegation", evidenceDelegationsDir()],
		["swarm", evidenceSwarmsDir()],
		["supervisor", evidenceSupervisorsDir()],
		["operator", evidenceOperatorsDir()],
		["verifier", evidenceVerifiersDir()],
		["compiler", evidenceCompilersDir()],
		["replayer", evidenceReplayersDir()],
		["autofix", evidenceAutofixDir()],
		["proof_loop", evidenceProofLoopsDir()],
		["harness", evidenceProfileCheckDir()],
	];
	return specs.flatMap(([kind, dir]) => {
		const path = latestScopedMarkdownArtifact(kind, dir, options);
		return path ? [{ kind, path }] : [];
	});
}
