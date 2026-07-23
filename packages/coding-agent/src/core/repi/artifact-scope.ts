import { missionOperatorDirective, readCurrentMission } from "./mission.ts";
import { sanitizeTargetForCommand } from "./target.ts";
import { metadataValue, parseJsonCodeFence } from "./text.ts";

export type ArtifactScopeFilterOptions = {
	missionId?: string;
	route?: string;
	target?: string;
	requestedBy?: string;
	scanLimit?: number;
	write?: boolean;
};

export function artifactScopeInferTarget(text?: string): string | undefined {
	const value = String(text ?? "");
	const url = value.match(/https?:\/\/[^\s'"`<>)]+/i)?.[0];
	if (url) return url.replace(/[),.;]+$/, "");
	const ip = value.match(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/)?.[0];
	if (ip) return ip;
	return value.match(
		/\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|cn|app|dev|site|co|xyz|info|biz|ai|cloud|edu|gov|me|local|test)(?::\d+)?\b/i,
	)?.[0];
}

export function artifactScopeDefaultOptions(
	options: ArtifactScopeFilterOptions = {},
): Required<Pick<ArtifactScopeFilterOptions, "requestedBy">> &
	Pick<ArtifactScopeFilterOptions, "missionId" | "route" | "target" | "scanLimit" | "write"> {
	const mission = readCurrentMission();
	return {
		missionId: options.missionId ?? mission?.id,
		route: options.route ?? mission?.route.domain,
		target:
			sanitizeTargetForCommand(options.target) ??
			artifactScopeInferTarget(missionOperatorDirective(mission)) ??
			artifactScopeInferTarget(mission?.task),
		requestedBy: options.requestedBy ?? "latest_artifact",
		scanLimit: options.scanLimit,
		write: options.write,
	};
}

export function artifactScopeMissionId(text: string): string | undefined {
	const parsed = parseJsonCodeFence<{ missionId?: unknown }>(text);
	if (typeof parsed?.missionId === "string" && parsed.missionId.trim()) return parsed.missionId.trim();
	const value = metadataValue(text, "mission_id") ?? metadataValue(text, "missionId");
	return value && !/^(?:none|missing|<.*>)$/i.test(value) ? value : undefined;
}

export function artifactMissionMatches(missionId: string | undefined, artifactMissionId: string | undefined): boolean {
	return !missionId || artifactMissionId === missionId;
}

export function artifactTargetMatches(target: string | undefined, artifactTarget: string | undefined): boolean {
	return !target || !artifactTarget || artifactTarget === target;
}
