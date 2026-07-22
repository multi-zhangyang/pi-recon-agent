import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { writeLocalClaimReleaseMarker } from "../src/core/recon-profile.ts";
import { readCurrentMission } from "../src/core/repi/mission.ts";
import { evidenceClaimReleaseDir, evidenceDelegationsDir } from "../src/core/repi/storage.ts";
import { createRegisteredReconHarness } from "./recon-profile-harness.ts";

type ToolResult = {
	content: Array<{ text: string }>;
	details?: { path?: string };
};

type RegisteredTool = {
	execute: (toolCallId: string, params: Record<string, unknown>) => Promise<ToolResult>;
};

type StrictClaimCheckSnapshot = {
	status: "pass" | "blocked" | "missing";
	requiredGaps: string[];
};

type SupervisorArtifact = {
	supervisorVerdict: "pass" | "watch" | "repair" | "blocked";
	parallelPlan?: unknown;
	planCoverage: string[];
	strictClaimCheck?: StrictClaimCheckSnapshot;
	claimCheckResult: string[];
};

type CompilerArtifact = {
	mode: "draft" | "final";
	reportPath?: string;
	supervisorVerdict?: "pass" | "watch" | "repair" | "blocked";
	statusSummary: {
		proved: number;
		weak: number;
		contradicted: number;
		missing: number;
	};
	claimCheckResult: string[];
};

type ClaimReleaseGap = {
	claimId?: string;
	scope?: string;
	checkpoint?: string;
	kind?: string;
};

type ClaimReleaseMarkerFixture = {
	kind: string;
	generatedAt: string;
	mode: string;
	ok: boolean;
	sourceSha256: string;
	platformRequiredScore: number;
	orchestrationScore: number;
	requiredGaps: ClaimReleaseGap[];
	checks: {
		checkAndScores: {
			status: string;
			platformRequiredScore: number;
			orchestrationScore: number;
			requiredGaps: ClaimReleaseGap[];
		};
	};
};

function rewriteArtifactJson(path: string, mutate: (value: Record<string, unknown>) => void): void {
	const text = readFileSync(path, "utf8");
	const start = text.lastIndexOf("```json");
	const end = start < 0 ? -1 : text.lastIndexOf("\n```", text.length);
	expect(start, `JSON block in ${path}`).toBeGreaterThanOrEqual(0);
	expect(end, `JSON block terminator in ${path}`).toBeGreaterThan(start);
	const value = JSON.parse(text.slice(start + "```json".length, end).trim()) as Record<string, unknown>;
	mutate(value);
	writeFileSync(
		path,
		`${text.slice(0, start)}\`\`\`json\n${JSON.stringify(value, null, 2)}${text.slice(end)}`,
		"utf8",
	);
}

type SwarmGateArtifact = {
	parallelPlan?: { workers: unknown[] };
	planCoverage: string[];
	structuredClaimMergeStatus?: "pass" | "blocked" | "missing";
};

function artifactJson<T>(path: string): T {
	const text = readFileSync(path, "utf8");
	// The compiled report itself can contain a nested ```bash block. Anchor on
	// the final JSON fence and only accept a closing fence on its own line.
	const start = text.lastIndexOf("```json");
	const end = start < 0 ? -1 : text.indexOf("\n```\n", start + "```json".length);
	expect(start, `JSON block in ${path}`).toBeGreaterThanOrEqual(0);
	expect(end, `JSON block terminator in ${path}`).toBeGreaterThan(start);
	return JSON.parse(text.slice(start + "```json".length, end).trim()) as T;
}

function tool<T extends RegisteredTool = RegisteredTool>(
	harness: ReturnType<typeof createRegisteredReconHarness>,
	name: string,
): T {
	const value = harness.tools.get(name) as T | undefined;
	expect(value, `${name} tool registered`).toBeDefined();
	return value!;
}

describe("REPI claim publication gates", () => {
	it("blocks a malformed strict-claim marker instead of treating omitted proof fields as pass", async () => {
		const harness = createRegisteredReconHarness("repi-malformed-claim-marker");
		try {
			const markerDir = join(evidenceClaimReleaseDir(), "malformed-marker");
			mkdirSync(markerDir, { recursive: true });
			writeFileSync(
				join(markerDir, "result.json"),
				`${JSON.stringify({
					kind: "repi-claim-release-marker",
					mode: "strict-claims",
					ok: true,
					requiredGaps: [],
				})}\n`,
				"utf8",
			);

			const result = await tool(harness, "re_supervisor").execute("supervisor-malformed", {
				action: "review",
			});
			const path = result.details?.path;
			expect(path).toBeDefined();
			const artifact = artifactJson<SupervisorArtifact>(path!);

			expect(artifact.strictClaimCheck?.status).toBe("blocked");
			expect(artifact.claimCheckResult).toContain("claim_check.final_publish_ready=no");
		} finally {
			harness.restore();
		}
	});

	it.each([
		{
			name: "non-canonical generatedAt",
			expectedGap: "marker_validation:generated_at_invalid",
			mutate: (marker: ClaimReleaseMarkerFixture) => {
				marker.generatedAt = "2026-07-19T00:00:00Z";
			},
		},
		{
			name: "non-hex sourceSha256",
			expectedGap: "marker_validation:source_sha256_invalid",
			mutate: (marker: ClaimReleaseMarkerFixture) => {
				marker.sourceSha256 = "g".repeat(64);
			},
		},
		{
			name: "failed nested check status",
			expectedGap: "marker_validation:check_status_not_pass",
			mutate: (marker: ClaimReleaseMarkerFixture) => {
				marker.checks.checkAndScores.status = "fail";
			},
		},
		{
			name: "non-finite platform score",
			expectedGap: "marker_validation:platform_required_score_invalid",
			mutate: (marker: ClaimReleaseMarkerFixture) => {
				marker.platformRequiredScore = Number.POSITIVE_INFINITY;
				marker.checks.checkAndScores.platformRequiredScore = Number.POSITIVE_INFINITY;
			},
		},
		{
			name: "out-of-range orchestration score",
			expectedGap: "marker_validation:orchestration_score_invalid",
			mutate: (marker: ClaimReleaseMarkerFixture) => {
				marker.orchestrationScore = 101;
				marker.checks.checkAndScores.orchestrationScore = 101;
			},
		},
		{
			name: "top-level and nested platform score mismatch",
			expectedGap: "marker_validation:platform_required_score_mismatch",
			mutate: (marker: ClaimReleaseMarkerFixture) => {
				marker.platformRequiredScore = 10;
				marker.checks.checkAndScores.platformRequiredScore = 11;
			},
		},
		{
			name: "top-level and nested orchestration score mismatch",
			expectedGap: "marker_validation:orchestration_score_mismatch",
			mutate: (marker: ClaimReleaseMarkerFixture) => {
				marker.orchestrationScore = 90;
				marker.checks.checkAndScores.orchestrationScore = 91;
			},
		},
		{
			name: "top-level and nested required gaps mismatch",
			expectedGap: "marker_validation:required_gaps_mismatch",
			mutate: (marker: ClaimReleaseMarkerFixture) => {
				marker.requiredGaps = [{ claimId: "claim-1", checkpoint: "runtime-proof" }];
				marker.checks.checkAndScores.requiredGaps = [];
			},
		},
	])("blocks a strict-claim marker with $name", async ({ expectedGap, mutate }) => {
		const harness = createRegisteredReconHarness("repi-invalid-claim-marker");
		try {
			await tool(harness, "re_delegate").execute("delegate-invalid-marker", {
				action: "plan",
			});
			const markerPath = writeLocalClaimReleaseMarker();
			const marker = JSON.parse(readFileSync(markerPath, "utf8")) as ClaimReleaseMarkerFixture;
			mutate(marker);
			writeFileSync(markerPath, `${JSON.stringify(marker)}\n`, "utf8");

			const result = await tool(harness, "re_supervisor").execute("supervisor-invalid-marker", {
				action: "review",
			});
			const path = result.details?.path;
			expect(path).toBeDefined();
			const artifact = artifactJson<SupervisorArtifact>(path!);

			expect(artifact.strictClaimCheck?.status).toBe("blocked");
			expect(artifact.strictClaimCheck?.requiredGaps).toContain(expectedGap);
			expect(artifact.claimCheckResult).toContain("claim_check.final_publish_ready=no");
		} finally {
			harness.restore();
		}
	});

	it("does not publish a final compiler report when the persisted supervisor verdict is blocked", async () => {
		const harness = createRegisteredReconHarness("repi-blocked-supervisor-compiler-final");
		try {
			const supervisorResult = await tool(harness, "re_supervisor").execute("supervisor-blocked", {
				action: "review",
			});
			const supervisorPath = supervisorResult.details?.path;
			expect(supervisorPath).toBeDefined();
			const supervisor = artifactJson<SupervisorArtifact>(supervisorPath!);
			expect(supervisor.supervisorVerdict).toBe("blocked");

			await tool(harness, "re_verifier").execute("verifier-before-blocked-compiler", {
				action: "matrix",
			});
			writeLocalClaimReleaseMarker();

			const compilerResult = await tool(harness, "re_compiler").execute("compiler-blocked-supervisor", {
				action: "final",
			});
			const compilerPath = compilerResult.details?.path;
			expect(compilerPath).toBeDefined();
			const compiler = artifactJson<CompilerArtifact>(compilerPath!);

			expect(compiler.supervisorVerdict).toBe("blocked");
			expect(compiler.reportPath).toBeUndefined();
			expect(compiler.claimCheckResult).toContain("claim_check.final_publish_ready=no");
			expect(compiler.claimCheckResult).toContain("claim_check.blocker=supervisor_verdict=blocked");
		} finally {
			harness.restore();
		}
	});

	it("blocks supervisor publication when the parallel plan is missing", async () => {
		const harness = createRegisteredReconHarness("repi-missing-parallel-plan");
		try {
			const result = await tool(harness, "re_supervisor").execute("supervisor-no-plan", {
				action: "review",
			});
			const path = result.details?.path;
			expect(path).toBeDefined();
			const artifact = artifactJson<SupervisorArtifact>(path!);

			expect(artifact.parallelPlan).toBeUndefined();
			expect(artifact.planCoverage).toContain("parallel_plan=missing status=blocked next=re_swarm plan");
			expect(artifact.supervisorVerdict).toBe("blocked");
		} finally {
			harness.restore();
		}
	});

	it("does not publish a final compiler report while verifier assertions are partial", async () => {
		const harness = createRegisteredReconHarness("repi-partial-compiler-final");
		try {
			const result = await tool(harness, "re_compiler").execute("compiler-partial", {
				action: "final",
			});
			const path = result.details?.path;
			expect(path).toBeDefined();
			const artifact = artifactJson<CompilerArtifact>(path!);

			expect(artifact.mode).toBe("final");
			expect(artifact.statusSummary.missing + artifact.statusSummary.weak).toBeGreaterThan(0);
			expect(artifact.reportPath).toBeUndefined();
			expect(artifact.claimCheckResult).toContain("claim_check.final_publish_ready=no");

			const mission = readCurrentMission();
			expect(mission?.checkpoints.find((checkpoint) => checkpoint.name === "report_or_writeup_ready")?.status).toBe(
				"blocked",
			);
		} finally {
			harness.restore();
		}
	});

	it("publishes only after a valid marker and runtime-built parallel plan and structured merge pass", async () => {
		const harness = createRegisteredReconHarness("repi-complete-claim-gates");
		try {
			await tool(harness, "re_mission").execute("mission-complete-gates", {
				action: "new",
				task: "verify runtime proof for ./target",
			});
			const mission = readCurrentMission();
			const proofPath = join(harness.tempDir, "worker-proof.txt");
			writeFileSync(proofPath, "runtime proof\n", "utf8");

			const delegationDir = evidenceDelegationsDir();
			mkdirSync(delegationDir, { recursive: true });
			const delegation = {
				timestamp: new Date().toISOString(),
				missionId: mission?.id,
				route: "Gate fixture",
				target: "./target",
				mode: "plan",
				packets: [
					{
						id: "worker:1:general",
						worker: "general",
						objective: "produce one verified runtime handoff",
						status: "ready",
						phases: ["proof"],
						steps: [
							{
								id: "op:1:proof",
								phase: "proof",
								command: "re_mission show",
								status: "ready",
								sourceArtifacts: [proofPath],
							},
						],
						evidenceContract: ["runtime proof"],
						recommendedTools: [],
						handoffPrompt: [],
						sourceArtifacts: [proofPath],
					},
				],
				mergeQueue: [],
				specialistCoverage: [],
				workerScoreboard: [],
				adaptiveRoutingHints: [],
				workerPromotionQueue: [],
				autonomousBudget: {
					maxTurns: 1,
					maxDispatch: 1,
					maxProofLoops: 1,
					maxWorkerRetries: 0,
					scoreDecay: [],
					demotionRules: [],
					laneDemotions: [],
					workerDemotions: [],
					dispatcherDemotions: [],
					promotionRules: [],
					nextActions: [],
				},
				dispatcherScoreDecay: [],
				repeatedFailureDemotions: [],
				highScorePromotions: [],
				gaps: [],
				nextActions: [],
				sourceArtifacts: [proofPath],
			};
			writeFileSync(
				join(delegationDir, "gate-fixture-plan.md"),
				["# Gate fixture", "", "mode: plan", "", "```json", JSON.stringify(delegation, null, 2), "```", ""].join(
					"\n",
				),
				"utf8",
			);

			const swarmResult = await tool(harness, "re_swarm").execute("swarm-complete-gates", {
				action: "run",
				execution: "simulated",
				maxWorkers: 1,
				maxCommands: 1,
			});
			const swarmPath = swarmResult.details?.path;
			expect(swarmPath).toBeDefined();
			const swarm = artifactJson<SwarmGateArtifact>(swarmPath!);
			expect(swarm.parallelPlan?.workers).toHaveLength(1);
			expect(swarm.planCoverage).toContain("worker_binding=pass");
			expect(swarm.structuredClaimMergeStatus).toBe("pass");
			await tool(harness, "re_evidence").execute("evidence-complete-gates", {
				action: "append",
				kind: "runtime",
				title: "general worker runtime proof",
				fact: "worker=general evidence_contract=runtime proof",
				command: "re_mission show",
				path: proofPath,
				verify: `cat ${proofPath}`,
			});
			const verifierResult = await tool(harness, "re_verifier").execute("verifier-complete-gates", {
				action: "matrix",
				target: "./target",
			});
			expect(verifierResult.details?.path).toBeDefined();
			// This fixture represents the proven end state required for a release
			// marker; a normal matrix with weak/missing rows must remain blocked.
			rewriteArtifactJson(verifierResult.details!.path!, (value) => {
				const assertions = Array.isArray(value.assertions) ? value.assertions : [];
				value.assertions = assertions.map((raw) => {
					const row =
						raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};
					return {
						...row,
						status: "proved",
						confidence: 100,
						evidence: Array.isArray(row.evidence) && row.evidence.length ? row.evidence : ["fixture evidence"],
						counterEvidence: [],
					};
				});
				value.contradictions = [];
				value.gaps = [];
			});
			writeLocalClaimReleaseMarker();

			const supervisorResult = await tool(harness, "re_supervisor").execute("supervisor-complete-gates", {
				action: "review",
			});
			const supervisorPath = supervisorResult.details?.path;
			expect(supervisorPath).toBeDefined();
			const supervisor = artifactJson<SupervisorArtifact>(supervisorPath!);
			expect(supervisor.strictClaimCheck?.status).toBe("pass");
			expect(supervisor.parallelPlan).toBeDefined();
			expect(supervisor.supervisorVerdict).toBe("pass");
			expect(supervisor.claimCheckResult).toContain("claim_check.final_publish_ready=yes");
		} finally {
			harness.restore();
		}
	});
});
