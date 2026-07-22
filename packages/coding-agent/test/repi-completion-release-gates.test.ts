import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { readCurrentMission } from "../src/core/repi/mission.ts";
import {
	evidenceClaimReleaseDir,
	evidenceCompilersDir,
	evidenceSwarmsDir,
	evidenceVerifiersDir,
} from "../src/core/repi/storage.ts";
import {
	type StructuredClaimMergeV1,
	verifyStructuredClaimMergePromotion,
} from "../src/core/repi/swarm-supervisor-runtime.ts";
import { createRegisteredReconHarness } from "./recon-profile-harness.ts";

type ToolResult = {
	content: Array<{ text: string }>;
	details?: Record<string, unknown> & {
		path?: string;
		ready?: boolean;
		blockers?: string[];
	};
};

type RegisteredTool = {
	execute: (toolCallId: string, params: Record<string, unknown>) => Promise<ToolResult>;
};

type SupervisorArtifact = {
	strictClaimCheck?: { status: "pass" | "blocked" | "missing" };
};

type JsonObject = Record<string, unknown>;

function tool(harness: ReturnType<typeof createRegisteredReconHarness>, name: string): RegisteredTool {
	const value = harness.tools.get(name) as RegisteredTool | undefined;
	expect(value, `${name} tool registered`).toBeDefined();
	return value!;
}

function artifactJson<T>(path: string): T {
	const text = readFileSync(path, "utf8");
	const start = text.lastIndexOf("```json");
	const end = start < 0 ? -1 : text.indexOf("\n```\n", start + "```json".length);
	expect(start, `JSON block in ${path}`).toBeGreaterThanOrEqual(0);
	expect(end, `JSON block terminator in ${path}`).toBeGreaterThan(start);
	return JSON.parse(text.slice(start + "```json".length, end).trim()) as T;
}

function claimReleaseMarkerPaths(): string[] {
	const dir = evidenceClaimReleaseDir();
	if (!existsSync(dir)) return [];
	return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		const path = entry.isDirectory() ? join(dir, entry.name, "result.json") : join(dir, entry.name);
		return path.endsWith("result.json") && existsSync(path) ? [path] : [];
	});
}

function structuredMergeFixture(path: string): StructuredClaimMergeV1 {
	const sha256 = createHash("sha256").update(readFileSync(path)).digest("hex");
	const artifactRef = {
		artifactId: "artifact-1",
		path,
		sha256,
		jsonQuery: "$.verified",
		op: "==" as const,
		expected: true,
		verifierPass: true,
	};
	return {
		kind: "StructuredClaimMergeV1",
		schemaVersion: 1,
		mergeId: "merge-1",
		sourcePoolId: "pool-1",
		target: "./target",
		claimRows: [
			{
				claimId: "claim-1",
				workerId: "worker-1",
				mergeKey: "proof",
				status: "proven",
				statement: "runtime proof is verified",
				artifactRefs: [artifactRef],
				challenges: [{ challengeId: "challenge-1", status: "resolved", resolution: "artifact verified" }],
			},
		],
		conflictTable: [],
		promotionCheck: {
			mode: "strict_final_claim_promotion",
			requiredStatuses: ["proven"],
			finalClaims: [
				{
					claimId: "claim-1",
					promotion: "final_pass",
					reportSection: "proof",
					verifierPass: true,
					artifactRefs: [artifactRef],
				},
			],
			blockedClaims: [],
			policies: [],
		},
	};
}

function writeMalformedArtifact(dir: string, name: string): string {
	mkdirSync(dir, { recursive: true });
	const path = join(dir, name);
	writeFileSync(path, '# malformed fixture\n\n```json\n{"broken":\n```\n', "utf8");
	return path;
}

function rewriteArtifactJson(path: string, mutate: (value: JsonObject) => void): void {
	const text = readFileSync(path, "utf8");
	const start = text.lastIndexOf("```json");
	const end = start < 0 ? -1 : text.indexOf("\n```\n", start + "```json".length);
	expect(start, `JSON block in ${path}`).toBeGreaterThanOrEqual(0);
	expect(end, `JSON block terminator in ${path}`).toBeGreaterThan(start);
	const value = JSON.parse(text.slice(start + "```json".length, end).trim()) as JsonObject;
	mutate(value);
	writeFileSync(
		path,
		`${text.slice(0, start)}\`\`\`json\n${JSON.stringify(value, null, 2)}${text.slice(end)}`,
		"utf8",
	);
}

function expectLineageBlocker(blockers: string[], labels: string[]): void {
	const matched = blockers.some((blocker) => {
		const lower = blocker.toLowerCase();
		return labels.every((label) => lower.includes(label)) && /lineage|mismatch|binding/.test(lower);
	});
	expect(matched, `lineage blocker for ${labels.join(" -> ")} in:\n${blockers.join("\n")}`).toBe(true);
}

describe("REPI completion and release fail-closed gates", () => {
	it("does not synthesize a pass marker while mission status and supervisor state are read", async () => {
		const harness = createRegisteredReconHarness("repi-no-implicit-claim-marker");
		try {
			await tool(harness, "re_mission").execute("mission-new", {
				action: "new",
				task: "inspect a release gate",
			});
			await tool(harness, "re_mission").execute("mission-show", { action: "show" });

			const review = await tool(harness, "re_supervisor").execute("supervisor-review", {
				action: "review",
			});
			const supervisorPath = review.details?.path;
			expect(supervisorPath).toBeDefined();
			expect(artifactJson<SupervisorArtifact>(supervisorPath!).strictClaimCheck?.status).toBe("missing");
			expect(claimReleaseMarkerPaths()).toEqual([]);

			await tool(harness, "re_supervisor").execute("supervisor-show", { action: "show" });
			expect(claimReleaseMarkerPaths()).toEqual([]);
		} finally {
			harness.restore();
		}
	});

	it("blocks both the generated marker and completion audit when release artifacts are missing", async () => {
		const harness = createRegisteredReconHarness("repi-missing-release-artifacts");
		try {
			await tool(harness, "re_mission").execute("mission-new", {
				action: "new",
				task: "pentest web API at https://target.local",
			});

			const result = await tool(harness, "re_complete").execute("completion-audit", { action: "audit" });
			const blockers = result.details?.blockers ?? [];
			expect(result.details?.ready).toBe(false);
			expect(result.content[0]?.text).toContain("completion_status: blocked");
			expect(blockers).toEqual(
				expect.arrayContaining(["verifier matrix artifact is missing", "final compiler artifact is missing"]),
			);

			expect(claimReleaseMarkerPaths()).toEqual([]);
		} finally {
			harness.restore();
		}
	});

	it("keeps the report checkpoint blocked when scaffold completion is blocked", async () => {
		const harness = createRegisteredReconHarness("repi-blocked-report-scaffold");
		try {
			await tool(harness, "re_mission").execute("mission-new", {
				action: "new",
				task: "inspect a blocked report scaffold",
			});

			const result = await tool(harness, "re_complete").execute("completion-scaffold", {
				action: "scaffold",
				title: "blocked-report",
			});
			expect(result.content[0]?.text).toContain("completion_status: blocked");
			expect(result.details?.path).toBeDefined();
			expect(readFileSync(result.details!.path!, "utf8")).toContain("completion_status: blocked");
			const checkpoint = readCurrentMission()?.checkpoints.find((item) => item.name === "report_or_writeup_ready");
			expect(checkpoint?.status).toBe("blocked");
			expect(checkpoint?.note).toContain("completion_ready=false");
			expect(claimReleaseMarkerPaths()).toEqual([]);
		} finally {
			harness.restore();
		}
	});

	it("keeps a partial proof loop pending instead of marking it done", async () => {
		const harness = createRegisteredReconHarness("repi-partial-proof-loop-checkpoint");
		try {
			await tool(harness, "re_mission").execute("mission-new", {
				action: "new",
				task: "verify login replay hypothesis",
			});

			const result = await tool(harness, "re_proof_loop").execute("proof-loop-plan", {
				action: "plan",
				target: "https://target.local/app",
				maxSteps: 1,
				replaySteps: 1,
			});
			expect(result.content[0]?.text).toContain("verdict: partial");
			const checkpoint = readCurrentMission()?.checkpoints.find((item) => item.name === "proof_loop_ready");
			expect(checkpoint?.status).toBe("pending");
		} finally {
			harness.restore();
		}
	});

	it.each([
		{ kind: "verifier", dir: evidenceVerifiersDir },
		{ kind: "swarm", dir: evidenceSwarmsDir },
		{ kind: "compiler", dir: evidenceCompilersDir },
	])("blocks a malformed $kind JSON artifact without crashing completion audit", async ({ kind, dir }) => {
		const harness = createRegisteredReconHarness(`repi-malformed-${kind}-completion`);
		try {
			await tool(harness, "re_mission").execute("mission-new", {
				action: "new",
				task: "inspect malformed release artifacts",
			});
			const malformedPath = writeMalformedArtifact(dir(), `${kind}-malformed.md`);

			const result = await tool(harness, "re_complete").execute("completion-audit", { action: "audit" });
			expect(result.details?.ready).toBe(false);
			expect(result.content[0]?.text).toContain("completion_status: blocked");
			if (kind === "verifier") expect(result.details?.blockers).toContain("verifier matrix artifact is missing");
			if (kind === "compiler") expect(result.details?.blockers).toContain("final compiler artifact is missing");
			expect(result.details?.blockers).not.toContain(`${kind} artifact is unreadable: ${malformedPath}`);
		} finally {
			harness.restore();
		}
	});

	it("parses a generated compiler JSON block after an embedded report fence", async () => {
		const harness = createRegisteredReconHarness("repi-compiler-nested-report-fence");
		try {
			await tool(harness, "re_mission").execute("mission-new", {
				action: "new",
				task: "inspect a compiler report parser",
			});
			const compiler = await tool(harness, "re_compiler").execute("compiler-draft", { action: "draft" });
			const compilerPath = compiler.details?.path;
			expect(compilerPath).toBeDefined();
			const compilerText = readFileSync(compilerPath!, "utf8");
			expect(compilerText).toMatch(/```bash[\s\S]*```/);

			const result = await tool(harness, "re_complete").execute("completion-audit", { action: "audit" });
			const blockers = result.details?.blockers ?? [];
			expect(result.details?.ready).toBe(false);
			expect(blockers).toContain(`latest compiler artifact is not final: ${compilerPath}`);
			expect(blockers).not.toContain(`compiler artifact is unreadable: ${compilerPath}`);
		} finally {
			harness.restore();
		}
	});

	it("does not consume release artifacts produced by the previous mission", async () => {
		const harness = createRegisteredReconHarness("repi-cross-mission-release-artifacts");
		try {
			const task = "inspect release artifact lineage";
			await tool(harness, "re_mission").execute("mission-a", { action: "new", task });
			const priorMissionId = readCurrentMission()?.id;
			expect(priorMissionId).toBeDefined();

			await tool(harness, "re_delegate").execute("delegate-a", { action: "plan", task });
			const swarm = await tool(harness, "re_swarm").execute("swarm-a", { action: "plan", task });
			const verifier = await tool(harness, "re_verifier").execute("verifier-a", { action: "matrix" });
			const supervisor = await tool(harness, "re_supervisor").execute("supervisor-a", { action: "review" });
			const compiler = await tool(harness, "re_compiler").execute("compiler-a", { action: "draft" });
			const priorPaths = {
				swarm: swarm.details?.path,
				verifier: verifier.details?.path,
				supervisor: supervisor.details?.path,
				compiler: compiler.details?.path,
			};
			for (const path of Object.values(priorPaths)) expect(path).toBeDefined();

			await tool(harness, "re_mission").execute("mission-b", { action: "new", task });
			const currentMissionId = readCurrentMission()?.id;
			expect(currentMissionId).toBeDefined();
			expect(currentMissionId).not.toBe(priorMissionId);

			const result = await tool(harness, "re_complete").execute("completion-audit", { action: "audit" });
			const blockers = result.details?.blockers ?? [];
			expect(result.details?.ready).toBe(false);
			expect(blockers).toEqual(
				expect.arrayContaining(["verifier matrix artifact is missing", "final compiler artifact is missing"]),
			);
			for (const path of Object.values(priorPaths)) {
				expect(blockers.some((blocker) => blocker.includes(path!))).toBe(false);
			}
		} finally {
			harness.restore();
		}
	});

	it("rebuilds no-target release producers for the current mission", async () => {
		const harness = createRegisteredReconHarness("repi-cross-mission-release-producers");
		const target = "https://target.local/api";
		const pathOf = (result: ToolResult, label: string): string => {
			const path = result.details?.path;
			expect(path, `${label} artifact path`).toBeDefined();
			return path!;
		};
		try {
			await tool(harness, "re_mission").execute("mission-a", { action: "new", task: target });
			const missionAId = readCurrentMission()?.id;
			expect(missionAId).toBeDefined();

			const delegateA = await tool(harness, "re_delegate").execute("delegate-a", {
				action: "plan",
				target,
				task: target,
			});
			const swarmA = await tool(harness, "re_swarm").execute("swarm-a", {
				action: "plan",
				target,
				task: target,
			});
			const operatorA = await tool(harness, "re_operator").execute("operator-a", { action: "plan", target });
			const verifierA = await tool(harness, "re_verifier").execute("verifier-a", { action: "matrix", target });
			const supervisorA = await tool(harness, "re_supervisor").execute("supervisor-a", {
				action: "review",
				target,
				task: target,
			});
			const compilerA = await tool(harness, "re_compiler").execute("compiler-a", { action: "draft", target });
			const missionAPaths = {
				delegate: pathOf(delegateA, "mission A delegate"),
				swarm: pathOf(swarmA, "mission A swarm"),
				operator: pathOf(operatorA, "mission A operator"),
				verifier: pathOf(verifierA, "mission A verifier"),
				supervisor: pathOf(supervisorA, "mission A supervisor"),
				compiler: pathOf(compilerA, "mission A compiler"),
			};
			for (const [kind, path] of Object.entries(missionAPaths)) {
				expect(artifactJson<{ missionId?: string }>(path).missionId, `mission A ${kind} missionId`).toBe(
					missionAId,
				);
			}

			await tool(harness, "re_mission").execute("mission-b", { action: "new", task: target });
			const missionBId = readCurrentMission()?.id;
			expect(missionBId).toBeDefined();
			expect(missionBId).not.toBe(missionAId);

			const swarmB = await tool(harness, "re_swarm").execute("swarm-b", { action: "merge" });
			const verifierB = await tool(harness, "re_verifier").execute("verifier-b", { action: "matrix" });
			const supervisorB = await tool(harness, "re_supervisor").execute("supervisor-b", { action: "review" });
			const compilerB = await tool(harness, "re_compiler").execute("compiler-b", { action: "draft" });
			const missionBPaths = {
				swarm: pathOf(swarmB, "mission B swarm"),
				verifier: pathOf(verifierB, "mission B verifier"),
				supervisor: pathOf(supervisorB, "mission B supervisor"),
				compiler: pathOf(compilerB, "mission B compiler"),
			};
			for (const [kind, path] of Object.entries(missionBPaths)) {
				expect(path, `mission B ${kind} artifact is new`).not.toBe(
					missionAPaths[kind as keyof typeof missionBPaths],
				);
				const artifactMissionId = artifactJson<{ missionId?: string }>(path).missionId;
				expect(artifactMissionId, `mission B ${kind} missionId`).toBe(missionBId);
				expect(artifactMissionId, `mission B ${kind} does not reuse mission A`).not.toBe(missionAId);
			}
		} finally {
			harness.restore();
		}
	});

	it("blocks completion when supervisor and compiler lineage paths do not match current artifacts", async () => {
		const harness = createRegisteredReconHarness("repi-mismatched-release-lineage");
		try {
			const task = "inspect release artifact lineage";
			await tool(harness, "re_mission").execute("mission-new", { action: "new", task });
			await tool(harness, "re_delegate").execute("delegate", { action: "plan", task });
			const swarm = await tool(harness, "re_swarm").execute("swarm", { action: "plan", task });
			const verifier = await tool(harness, "re_verifier").execute("verifier", { action: "matrix" });
			const supervisor = await tool(harness, "re_supervisor").execute("supervisor", { action: "review" });
			const compiler = await tool(harness, "re_compiler").execute("compiler", { action: "final" });
			const swarmPath = swarm.details?.path;
			const verifierPath = verifier.details?.path;
			const supervisorPath = supervisor.details?.path;
			const compilerPath = compiler.details?.path;
			for (const path of [swarmPath, verifierPath, supervisorPath, compilerPath]) expect(path).toBeDefined();

			rewriteArtifactJson(supervisorPath!, (value) => {
				value.swarmArtifact = verifierPath;
			});
			rewriteArtifactJson(compilerPath!, (value) => {
				value.verifierArtifact = supervisorPath;
				value.supervisorArtifact = verifierPath;
				// Keep this fixture focused on lineage: embedded Markdown fences in the
				// rendered report are an independent parser failure mode.
				value.finalReport = [];
			});

			const result = await tool(harness, "re_complete").execute("completion-audit", { action: "audit" });
			const blockers = result.details?.blockers ?? [];
			expect(result.details?.ready).toBe(false);
			expectLineageBlocker(blockers, ["supervisor", "swarm"]);
			expectLineageBlocker(blockers, ["compiler", "verifier"]);
			expectLineageBlocker(blockers, ["compiler", "supervisor"]);
			expect(blockers.join("\n")).toContain(swarmPath!);
			expect(blockers.join("\n")).toContain(supervisorPath!);
			expect(blockers.join("\n")).toContain(verifierPath!);
		} finally {
			harness.restore();
		}
	});

	it("rejects structured final claims with empty artifact refs", () => {
		const tempDir = mkdtempSync(join(tmpdir(), "repi-empty-final-refs-"));
		try {
			const artifactPath = join(tempDir, "proof.json");
			writeFileSync(artifactPath, '{"verified":true}\n', "utf8");
			const merge = structuredMergeFixture(artifactPath);
			expect(verifyStructuredClaimMergePromotion(merge)).toEqual({ ok: true, errors: [] });

			merge.promotionCheck.finalClaims[0]!.artifactRefs = [];
			const verification = verifyStructuredClaimMergePromotion(merge);
			expect(verification.ok).toBe(false);
			expect(verification.errors).toContain("final_pass_artifact_refs_missing:claim-1");
		} finally {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects structured claims after an artifact file hash is tampered", () => {
		const tempDir = mkdtempSync(join(tmpdir(), "repi-tampered-claim-artifact-"));
		try {
			const artifactPath = join(tempDir, "proof.json");
			writeFileSync(artifactPath, '{"verified":true}\n', "utf8");
			const merge = structuredMergeFixture(artifactPath);
			expect(verifyStructuredClaimMergePromotion(merge)).toEqual({ ok: true, errors: [] });

			writeFileSync(artifactPath, '{"verified":false}\n', "utf8");
			const verification = verifyStructuredClaimMergePromotion(merge);
			expect(verification.ok).toBe(false);
			expect(verification.errors).toContain("artifact_sha256_mismatch:claim-1:artifact-1");
		} finally {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});
});
