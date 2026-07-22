import { existsSync } from "node:fs";
import { join } from "node:path";
import type { ArtifactScopeFilterOptions } from "./artifact-scope.ts";
import { latestScopedMarkdownArtifact } from "./artifact-selection-runtime.ts";
import type { CompletionAudit, CompletionDomainProofExitClosure } from "./completion-audit-runtime.ts";
import { appendEvidence, buildEvidenceDigest } from "./evidence-runtime.ts";
import { buildKernelArtifact, formatKernelArtifact, type KernelArtifact } from "./execution-kernel.ts";
import type { MissionState } from "./mission.ts";
import {
	buildProfileCheckArtifact,
	formatProfileCheckArtifact,
	type ProfileCheckArtifact,
	type ProfileCheckMode,
} from "./profile-check.ts";
import { ensureReconStorage } from "./resources.ts";
import {
	builtinSkillFilePath,
	currentMissionPath,
	evidenceKernelDir,
	evidenceLedgerPath,
	evidenceProfileCheckDir,
	reportDir,
	toolIndexPath,
	writePrivateTextFile,
} from "./storage.ts";
import { slug, truncateMiddle } from "./text.ts";

type StrictClaimSnapshot = { status: string };

export type ProfileKernelReportRuntimeDependencies<TClosure extends CompletionDomainProofExitClosure> = {
	readCurrentMission: () => MissionState | undefined;
	updateMissionCheckpoint: (name: string, status: "pending" | "done" | "blocked", note?: string) => unknown;
	formatStoredArtifactSummary: (kind: string, path: string) => string;
	formatMission: (mission: MissionState) => string;
	latestSourceArtifactPaths: () => Array<string | undefined>;
	auditCompletion: () => CompletionAudit<TClosure>;
	formatCompletionAuditFromAudit: (audit: CompletionAudit<TClosure>) => string;
	strictClaimCheckSnapshot: () => StrictClaimSnapshot;
};

export function createProfileKernelReportRuntime<TClosure extends CompletionDomainProofExitClosure>(
	dependencies: ProfileKernelReportRuntimeDependencies<TClosure>,
) {
	const {
		readCurrentMission,
		updateMissionCheckpoint,
		formatStoredArtifactSummary,
		formatMission,
		latestSourceArtifactPaths,
		auditCompletion,
		formatCompletionAuditFromAudit,
		strictClaimCheckSnapshot,
	} = dependencies;

	function latestProfileCheckArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		return latestScopedMarkdownArtifact("profile-check", evidenceProfileCheckDir(), options);
	}

	function writeProfileCheckArtifact(profileCheck: ProfileCheckArtifact): string {
		ensureReconStorage();
		const path = join(
			evidenceProfileCheckDir(),
			`${profileCheck.timestamp.replace(/[:.]/g, "-")}-${profileCheck.mode}.md`,
		);
		writePrivateTextFile(
			path,
			[
				"# REPI Profile Check Artifact",
				"",
				formatProfileCheckArtifact(profileCheck, path),
				"",
				"## JSON",
				"",
				"```json",
				JSON.stringify(profileCheck, null, 2),
				"```",
				"",
			].join("\n"),
		);
		appendEvidence({
			kind: "artifact",
			title: `profile-check-${profileCheck.mode}-${profileCheck.verdict}`,
			fact: `Profile check ${profileCheck.mode}: verdict=${profileCheck.verdict}, checks=${profileCheck.checks.length}, install_readiness=${profileCheck.installReadiness.length}, reverse_capability_guards=${profileCheck.reverseCapabilityGuards.length}, regression_guards=${profileCheck.regressionGuards.length}`,
			command: `re_profile_check ${profileCheck.mode}`,
			path,
			verify: `cat ${path}`,
			confidence: "profile/install/regression check",
		});
		updateMissionCheckpoint("profile_check_ready", profileCheck.verdict === "fail" ? "blocked" : "done", path);
		return path;
	}

	function buildProfileCheckOutput(action: ProfileCheckMode | "show" = "quick"): string {
		if (action === "show") {
			const path = latestProfileCheckArtifactPath();
			return path
				? formatStoredArtifactSummary("profile_check", path)
				: "profile_check:\nstatus: missing\nnext: re_profile_check quick";
		}
		const profileCheck = buildProfileCheckArtifact(action);
		const path = writeProfileCheckArtifact(profileCheck);
		return formatProfileCheckArtifact(profileCheck, path);
	}

	function latestKernelArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		return latestScopedMarkdownArtifact("kernel", evidenceKernelDir(), options);
	}

	function kernelSourceArtifacts(): string[] {
		ensureReconStorage();
		const paths = [
			builtinSkillFilePath(),
			toolIndexPath(),
			currentMissionPath(),
			evidenceLedgerPath(),
			...latestSourceArtifactPaths(),
		].filter((path): path is string => Boolean(path && existsSync(path)));
		return Array.from(new Set(paths));
	}

	function writeKernelArtifact(kernel: KernelArtifact): string {
		ensureReconStorage();
		const path = join(
			evidenceKernelDir(),
			`${kernel.timestamp.replace(/[:.]/g, "-")}-${slug(kernel.route ?? "kernel")}-${kernel.mode}.md`,
		);
		writePrivateTextFile(
			path,
			[
				"# REPI Execution Kernel Artifact",
				"",
				formatKernelArtifact(kernel, path),
				"",
				"## JSON",
				"",
				"```json",
				JSON.stringify(kernel, null, 2),
				"```",
				"",
			].join("\n"),
		);
		appendEvidence({
			kind: "artifact",
			title: `execution-kernel-${kernel.mode} ${kernel.missionId ?? "no-mission"}`,
			fact: `Execution kernel ${kernel.mode}: directives=${kernel.directives.length}, next_actions=${kernel.nextActions.length}`,
			command: `re_kernel ${kernel.mode}`,
			path,
			verify: `cat ${path}`,
			confidence: "profile directive kernel",
		});
		updateMissionCheckpoint("execution_kernel_ready", "done", path);
		return path;
	}

	function buildKernelOutput(action: "build" | "show" | "audit" = "build", options: { target?: string } = {}): string {
		if (action === "show") {
			const path = latestKernelArtifactPath();
			return path
				? formatStoredArtifactSummary("execution_kernel", path)
				: "execution_kernel:\nstatus: missing\nnext: re_kernel build";
		}
		const kernel = buildKernelArtifact({
			target: options.target,
			mode: action === "audit" ? "audit" : "build",
			mission: readCurrentMission(),
			sources: kernelSourceArtifacts(),
		});
		const path = writeKernelArtifact(kernel);
		return formatKernelArtifact(kernel, path);
	}

	function writeReportScaffold(title?: string): string {
		ensureReconStorage();
		const mission = readCurrentMission();
		const audit = auditCompletion();
		const date = new Date().toISOString().replace(/[:.]/g, "-");
		const safeTitle = (title ?? mission?.route.domain ?? "repi-report").replace(/[^a-z0-9._-]+/gi, "-").slice(0, 80);
		const path = join(reportDir(), `${date}-${safeTitle}.md`);
		writePrivateTextFile(
			path,
			[
				"# REPI Report Scaffold",
				"",
				"## Outcome",
				"",
				"## Key Evidence",
				"",
				truncateMiddle(buildEvidenceDigest(), 6000),
				"",
				"## Verification",
				"",
				"## Next Step",
				"",
				"## Mission",
				"",
				mission ? formatMission(mission) : "no mission",
				"",
				"## Completion Audit",
				"",
				formatCompletionAuditFromAudit(audit),
				"",
			].join("\n"),
		);
		const strictClaim = strictClaimCheckSnapshot();
		updateMissionCheckpoint(
			"report_or_writeup_ready",
			audit.ready && strictClaim.status === "pass" ? "done" : "blocked",
			`${path} completion_ready=${audit.ready} strict_claim_check=${strictClaim.status}`,
		);
		return path;
	}

	return {
		buildKernelOutput,
		buildProfileCheckOutput,
		latestKernelArtifactPath,
		latestProfileCheckArtifactPath,
		writeReportScaffold,
	};
}
