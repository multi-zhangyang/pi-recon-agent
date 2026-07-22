import { spawnSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const SWARM = fileURLToPath(new URL("../../../scripts/reverse-agent/repi-swarm-llm-run.mjs", import.meta.url));

const FAKE_REPI = `#!/usr/bin/env node
console.log(JSON.stringify({
	workerId: "worker-1",
	role: "mapper",
	claims: [{
		id: "claim-1",
		statement: "ret2win primitive is reachable",
		evidence: ["checksec: NX enabled, no PIE", "poc.py exits 0", "negative control: wrong offset exits 1"],
		confidence: 0.9,
		blockers: []
	}],
	artifacts: ["poc.py"],
	blockers: [],
	nextCommands: ["python3 poc.py"]
}));
`;

function collectTmp(root: string): string[] {
	const out: string[] = [];
	for (const entry of readdirSync(root, { withFileTypes: true })) {
		const path = join(root, entry.name);
		if (entry.name.endsWith(".tmp")) out.push(path);
		if (entry.isDirectory()) out.push(...collectTmp(path));
	}
	return out;
}

describe("repi-swarm-llm-run evidence artifact writes", () => {
	let tempRoot: string;
	let fakeRoot: string;
	let agentDir: string;
	let workspace: string;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-swarm-atomic-"));
		fakeRoot = join(tempRoot, "repo");
		agentDir = join(tempRoot, "agent");
		workspace = join(tempRoot, "workspace");
		mkdirSync(fakeRoot, { recursive: true });
		mkdirSync(agentDir, { recursive: true });
		mkdirSync(workspace, { recursive: true });
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(fakeRepiPath, FAKE_REPI);
		chmodSync(fakeRepiPath, 0o755);
	});

	afterEach(() => {
		rmSync(tempRoot, { recursive: true, force: true });
	});

	it("writes plan/report/worker/merge artifacts atomically with private mode", () => {
		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"run",
				"./vuln",
				"--workers",
				"1",
				"--max-concurrency",
				"1",
				"--cwd",
				workspace,
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			ok: boolean;
			runId: string;
			evidenceRoot: string;
			plan: {
				proofDoctrine: { UniversalProofDoctrineV1: boolean; order: string[] };
				evidencePriorityDoctrine: { EvidencePriorityDoctrineV1: boolean; order: Array<{ class: string }> };
				capabilityMatrixDoctrine: { CapabilityMatrixDoctrineV1: boolean; gates: Array<{ gate: string }> };
				workerPackets: Array<{
					proofKit: { passive: string[]; proofExit: string[]; negativeControls: string[] };
					commandPalette: { passive: string[]; proof: string[]; negative: string[] };
					toolProbeCommand: string;
					techniqueHints: {
						domains: string[];
						techniqueIds: string[];
						universalRules: string[];
						playbook: string[];
						proofContracts: Array<{ id: string; proofExit: string }>;
					};
					agentToolchain: {
						AgentToolchainV1: boolean;
						toolsMode: string;
						enabledTools: string[];
						routeTools: string[];
						callOrder: string[];
					};
				}>;
			};
			workersReport: Array<{
				route: { id: string };
				proofKit: { proofExit: string[] };
				commandPalette: { passive: string[]; proof: string[]; negative: string[] };
				toolProbeCommand: string;
				techniqueHints: {
					domains: string[];
					techniqueIds: string[];
					universalRules: string[];
					playbook: string[];
					proofContracts: Array<{ id: string; proofExit: string }>;
				};
				agentToolchain: {
					AgentToolchainV1: boolean;
					toolsMode: string;
					enabledTools: string[];
					routeTools: string[];
					callOrder: string[];
				};
			}>;
			merge: {
				evidencePriorityDoctrine: { EvidencePriorityDoctrineV1: boolean };
				promotedClaims: Array<{
					qualitySignals: { evidenceCount: number; hasCommand: boolean; strongestEvidenceClass: string };
				}>;
				proofReadyPromotedClaims: unknown[];
				proofPromotionReady: boolean;
				proofChecklists: Array<{
					proofReady: boolean;
					coverage: { passive: boolean; proofExit: boolean; negativeControls: boolean };
					route: { id: string };
					toolProbeCommand: string;
					techniqueHints: {
						domains: string[];
						techniqueIds: string[];
						universalRules: string[];
						playbook: string[];
						proofContracts: Array<{ id: string; proofExit: string }>;
					};
					agentToolchain: {
						AgentToolchainV1: boolean;
						enabledTools: string[];
						routeTools: string[];
					};
				}>;
				mergeVerification: {
					proofReady: boolean;
					finalPromotionReady: boolean;
					stats: {
						verifiedWorkers: number;
						verifiedClaims: number;
						verifiedRoutes: number;
						negativeControlsPassed: number;
					};
					claimLedger: Array<{ claimType: string; verdict: string }>;
					composedPaths: Array<{ claimType: string; verdict: string }>;
				};
			};
		};
		expect(report.ok).toBe(true);
		expect(report.plan.proofDoctrine.UniversalProofDoctrineV1).toBe(true);
		expect(report.plan.proofDoctrine.order.join("\n")).toContain("passive map first");
		expect(report.plan.evidencePriorityDoctrine.EvidencePriorityDoctrineV1).toBe(true);
		expect(report.plan.evidencePriorityDoctrine.order.map((row) => row.class)).toContain("runtime-behavior");
		expect(report.plan.capabilityMatrixDoctrine.CapabilityMatrixDoctrineV1).toBe(true);
		expect(report.plan.capabilityMatrixDoctrine.gates.map((row) => row.gate)).toContain("negative-control");
		expect(report.plan.workerPackets[0].proofKit.passive.length).toBeGreaterThan(0);
		expect(report.plan.workerPackets[0].proofKit.proofExit.length).toBeGreaterThan(0);
		expect(report.plan.workerPackets[0].proofKit.negativeControls.length).toBeGreaterThan(0);
		expect(report.plan.workerPackets[0].commandPalette.passive.length).toBeGreaterThan(0);
		expect(report.plan.workerPackets[0].commandPalette.proof.length).toBeGreaterThan(0);
		expect(report.plan.workerPackets[0].commandPalette.negative.length).toBeGreaterThan(0);
		expect(report.plan.workerPackets[0].toolProbeCommand).toContain("command -v");
		expect(report.plan.workerPackets[0].techniqueHints.domains).toContain("exploit-reliability");
		expect(report.plan.workerPackets[0].techniqueHints.techniqueIds).toContain("reliability-replay-matrix");
		expect(report.plan.workerPackets[0].techniqueHints.universalRules.join("\n")).toContain("map before exploit");
		expect(report.plan.workerPackets[0].techniqueHints.playbook.join("\n")).toContain("One-proof loop");
		expect(report.plan.workerPackets[0].techniqueHints.proofContracts.map((row) => row.id)).toContain(
			"reliability-replay-matrix",
		);
		expect(report.plan.workerPackets[0].agentToolchain.AgentToolchainV1).toBe(true);
		expect(report.plan.workerPackets[0].agentToolchain.toolsMode).toBe("default");
		expect(report.plan.workerPackets[0].agentToolchain.enabledTools).toEqual(
			expect.arrayContaining(["bash", "write", "edit", "re_route", "re_techniques", "re_verifier", "re_replayer"]),
		);
		expect(report.plan.workerPackets[0].agentToolchain.callOrder.join("\n")).toContain("re_techniques");
		expect(report.workersReport[0].route.id).toBe("reverse-pentest-general");
		expect(report.workersReport[0].proofKit.proofExit.length).toBeGreaterThan(0);
		expect(report.workersReport[0].commandPalette.proof.length).toBeGreaterThan(0);
		expect(report.workersReport[0].toolProbeCommand).toContain("tool:");
		expect(report.workersReport[0].techniqueHints.techniqueIds).toContain("reliability-replay-matrix");
		expect(report.workersReport[0].techniqueHints.proofContracts[0].proofExit).toContain("proof");
		expect(report.workersReport[0].agentToolchain.enabledTools).toContain("re_techniques");
		expect(report.merge.promotedClaims.length).toBe(1);
		expect(report.merge.proofReadyPromotedClaims.length).toBe(1);
		expect(report.merge.proofPromotionReady).toBe(true);
		expect(report.merge.evidencePriorityDoctrine.EvidencePriorityDoctrineV1).toBe(true);
		expect(report.merge.promotedClaims[0].qualitySignals.evidenceCount).toBeGreaterThan(0);
		expect(report.merge.promotedClaims[0].qualitySignals.hasCommand).toBe(true);
		expect(report.merge.promotedClaims[0].qualitySignals.strongestEvidenceClass).toBe("runtime-behavior");
		expect(report.merge.proofChecklists[0].route.id).toBe("reverse-pentest-general");
		expect(report.merge.proofChecklists[0].toolProbeCommand).toContain("command -v");
		expect(report.merge.proofChecklists[0].techniqueHints.domains).toContain("exploit-reliability");
		expect(report.merge.proofChecklists[0].techniqueHints.playbook.join("\n")).toContain("Merge discipline");
		expect(report.merge.proofChecklists[0].techniqueHints.proofContracts.length).toBeGreaterThan(0);
		expect(report.merge.proofChecklists[0].agentToolchain.enabledTools).toContain("re_verifier");
		expect(report.merge.proofChecklists[0].coverage).toMatchObject({
			passive: true,
			proofExit: true,
			negativeControls: true,
		});
		expect(report.merge.proofChecklists[0].proofReady).toBe(true);
		expect(report.merge.mergeVerification).toMatchObject({
			proofReady: true,
			finalPromotionReady: true,
			stats: {
				verifiedWorkers: 1,
				verifiedClaims: 1,
				verifiedRoutes: 1,
				negativeControlsPassed: 3,
			},
		});
		expect(report.merge.mergeVerification.claimLedger.map((claim) => claim.claimType)).toEqual(
			expect.arrayContaining([
				"swarm-worker-transcript-hash-proof",
				"swarm-claim-proof-gate-proof",
				"swarm-route-proof-gate-proof",
				"swarm-merge-negative-control-proof",
			]),
		);
		expect(
			report.merge.mergeVerification.composedPaths.some(
				(path) => path.claimType === "swarm-merge-verification-proof-path" && path.verdict === "promoted",
			),
		).toBe(true);

		for (const name of [
			"plan.json",
			"report.json",
			"merge-report.json",
			"merge-verification.json",
			"worker-1.stdout.txt",
			"worker-1.stderr.txt",
		]) {
			const path = join(report.evidenceRoot, name);
			expect(existsSync(path), `${name} exists`).toBe(true);
			expect(statSync(path).mode & 0o777, `${name} is private`).toBe(0o600);
		}
		expect(readFileSync(join(report.evidenceRoot, "worker-1.stdout.txt"), "utf8")).toContain("ret2win primitive");
		expect(JSON.parse(readFileSync(join(report.evidenceRoot, "merge-report.json"), "utf8")).finalPromotionReady).toBe(
			true,
		);
		const persistedVerification = JSON.parse(
			readFileSync(join(report.evidenceRoot, "merge-verification.json"), "utf8"),
		) as {
			proofReady: boolean;
			claimLedger: Array<{ claimType: string }>;
		};
		expect(persistedVerification.proofReady).toBe(true);
		expect(
			persistedVerification.claimLedger.some((claim) => claim.claimType === "swarm-worker-transcript-hash-proof"),
		).toBe(true);
		writeFileSync(
			join(report.evidenceRoot, "worker-1.stdout.txt"),
			`${readFileSync(join(report.evidenceRoot, "worker-1.stdout.txt"), "utf8")}\nmutated transcript\n`,
		);
		const tamperedMerge = spawnSync(process.execPath, [SWARM, fakeRoot, "merge", report.runId, "--json"], {
			encoding: "utf8",
			env: {
				...process.env,
				REPI_CODING_AGENT_DIR: agentDir,
			},
			timeout: 10_000,
		});
		expect(tamperedMerge.status, `${tamperedMerge.stderr}\n${tamperedMerge.stdout}`).toBe(0);
		const tamperedReport = JSON.parse(tamperedMerge.stdout) as {
			mergeVerification: {
				proofReady: boolean;
				promotionReport: { blockers: string[] };
				repairQueue: Array<{ blocker: string }>;
			};
		};
		expect(tamperedReport.mergeVerification.proofReady).toBe(false);
		expect(tamperedReport.mergeVerification.promotionReport.blockers).toContain(
			"missing-swarm-transcript-hash-verification",
		);
		expect(tamperedReport.mergeVerification.repairQueue).toContainEqual(
			expect.objectContaining({ blocker: "missing-swarm-transcript-hash-verification" }),
		);
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("merges structured worker JSON when output exceeds the old tail-only preview", () => {
		const claims = Array.from({ length: 24 }, (_, index) => ({
			id: `claim-${index + 1}`,
			statement: `mapped asset ${index + 1} with replayable evidence anchor`,
			evidence: [
				`curl replay ${index + 1} exited 0 and body hash sha256:${String(index + 1)
					.padStart(2, "0")
					.repeat(32)}`,
				`negative control ${index + 1}: tampered replay rejected HTTP 403`,
			],
			confidence: 0.8,
			blockers: [],
		}));
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(
			fakeRepiPath,
			`#!/usr/bin/env node\nconsole.log(JSON.stringify({workerId:"worker-1",role:"mapper",claims:${JSON.stringify(claims)},blockers:[],nextCommands:["node verify.js"]}, null, 2));\n`,
		);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"run",
				"./large-json-worker",
				"--workers",
				"1",
				"--max-concurrency",
				"1",
				"--cwd",
				workspace,
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			evidenceRoot: string;
			merge: {
				finalPromotionReady: boolean;
				promotedClaims: unknown[];
				proofReadyPromotedClaims: unknown[];
				proofPromotionReady: boolean;
				narrativeOnlyBlocked: boolean;
				proofChecklists: Array<{ missing: string[]; proofReady: boolean }>;
				nextCommands: string[];
			};
		};
		const workerStdout = readFileSync(join(report.evidenceRoot, "worker-1.stdout.txt"), "utf8");
		expect(workerStdout.length).toBeGreaterThan(4000);
		expect(workerStdout.trim().startsWith("{")).toBe(true);
		expect(report.merge.finalPromotionReady).toBe(true);
		expect(report.merge.narrativeOnlyBlocked).toBe(false);
		expect(report.merge.promotedClaims.length).toBe(claims.length);
		expect(report.merge.proofReadyPromotedClaims.length).toBe(claims.length);
		expect(report.merge.proofPromotionReady).toBe(true);
		expect(report.merge.proofChecklists[0].proofReady).toBe(true);
		expect(report.merge.proofChecklists[0].missing).toEqual([]);
	});

	it("harvests bounded worker artifact paths into the swarm evidence directory", () => {
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(
			fakeRepiPath,
			`#!/usr/bin/env node\nconst fs=require("node:fs");\nconst path=require("node:path");\nconst artifact=path.join(process.env.REPI_CODING_AGENT_DIR, "worker-proof.txt");\nfs.writeFileSync(artifact, "signed replay accepted\\n");\nconsole.log(JSON.stringify({workerId:"worker-1",role:"mapper",claims:[{id:"claim-artifact",statement:"artifact was produced",evidence:[artifact,"negative control: missing artifact path rejected"],confidence:0.9,blockers:[]}],artifacts:[artifact],blockers:[],nextCommands:[]}, null, 2));\n`,
		);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"run",
				"./artifact-worker",
				"--workers",
				"1",
				"--max-concurrency",
				"1",
				"--cwd",
				workspace,
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			evidenceRoot: string;
			workersReport: Array<{ harvestedArtifacts: Array<{ artifactPath: string; sha256: string }> }>;
			merge: {
				mergeVerification: {
					artifactVerification: { artifactCount: number; verifiedArtifacts: number };
					claimLedger: Array<{ claimType: string }>;
				};
			};
		};
		const harvested = report.workersReport[0].harvestedArtifacts[0];
		expect(harvested.artifactPath).toContain("worker-1-artifacts");
		expect(existsSync(harvested.artifactPath)).toBe(true);
		expect(statSync(harvested.artifactPath).mode & 0o777).toBe(0o600);
		expect(readFileSync(harvested.artifactPath, "utf8")).toBe("signed replay accepted\n");
		expect(existsSync(join(report.evidenceRoot, "worker-1-artifacts.json"))).toBe(true);
		expect(harvested.sha256).toMatch(/^[a-f0-9]{64}$/);
		expect(report.merge.mergeVerification.artifactVerification).toMatchObject({
			artifactCount: 1,
			verifiedArtifacts: 1,
		});
		expect(
			report.merge.mergeVerification.claimLedger.some(
				(claim) => claim.claimType === "swarm-harvested-artifact-integrity-proof",
			),
		).toBe(true);
	});

	it("extracts structured merge JSON after noisy brace-containing prose", () => {
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(
			fakeRepiPath,
			`#!/usr/bin/env node\nconsole.log("analysis note with braces {not json} before final report");\nconsole.log(JSON.stringify({workerId:"worker-1",role:"mapper",claims:[{id:"claim-json",statement:"structured suffix parsed",evidence:["curl exited 0","negative control: bad token got HTTP 403"],confidence:0.9,blockers:[]}],blockers:[],nextCommands:["curl http://example.test"]}, null, 2));\n`,
		);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"run",
				"./noisy-json-worker",
				"--workers",
				"1",
				"--max-concurrency",
				"1",
				"--cwd",
				workspace,
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			merge: { finalPromotionReady: boolean; promotedClaims: Array<{ claimId: string }>; nextCommands: string[] };
		};
		expect(report.merge.finalPromotionReady).toBe(true);
		expect(report.merge.promotedClaims[0].claimId).toBe("claim-json");
		expect(report.merge.nextCommands).toContain("curl http://example.test");
	});

	it("downgrades claims contradicted by higher-priority counter-evidence", () => {
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(
			fakeRepiPath,
			`#!/usr/bin/env node\nconsole.log(JSON.stringify({workerId:"worker-1",role:"verifier",claims:[{id:"source-only",statement:"README says admin endpoint is open",evidence:["README comment says admin endpoint is open"],confidence:0.95,blockers:[],conflicts:[{claimId:"source-only",evidenceClass:"network-traffic",evidence:"negative control: curl /admin returned HTTP 403 body hash sha256:${"ab".repeat(32)}",reason:"live HTTP replay contradicts README",nextCommand:"curl -i http://example.test/admin"}]},{id:"runtime-proof",statement:"authz check rejects invalid token",evidence:["curl /api with valid token exited 0 HTTP 200 body hash sha256:${"cd".repeat(32)}","negative control: invalid token returned HTTP 403"],confidence:0.9,blockers:[]}],blockers:[],nextCommands:[]}, null, 2));\n`,
		);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"run",
				"./conflict-worker",
				"--workers",
				"1",
				"--max-concurrency",
				"1",
				"--cwd",
				workspace,
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			merge: {
				finalPromotionReady: boolean;
				conflictRows: Array<{ claimId: string; evidenceClass: string; evidencePriorityRank: number }>;
				claimRows: Array<{
					claimId: string;
					status: string;
					qualitySignals: { strongestEvidenceClass: string; evidencePriorityRank: number };
					conflictResolution: { status: string; strongestConflictClass: string; downgraded: boolean };
				}>;
				promotedClaims: Array<{ claimId: string }>;
				nextCommands: string[];
			};
		};
		const sourceClaim = report.merge.claimRows.find((claim) => claim.claimId === "source-only");
		const runtimeClaim = report.merge.claimRows.find((claim) => claim.claimId === "runtime-proof");
		expect(report.merge.finalPromotionReady).toBe(true);
		expect(report.merge.conflictRows[0]).toMatchObject({
			claimId: "source-only",
			evidenceClass: "network-traffic",
		});
		expect(report.merge.conflictRows[0].evidencePriorityRank).toBeGreaterThan(
			sourceClaim?.qualitySignals.evidencePriorityRank ?? 0,
		);
		expect(sourceClaim?.status).toBe("observation");
		expect(sourceClaim?.conflictResolution).toMatchObject({
			status: "downgraded_by_equal_or_stronger_counterevidence",
			strongestConflictClass: "network-traffic",
			downgraded: true,
		});
		expect(runtimeClaim?.status).toBe("promoted");
		expect(runtimeClaim?.qualitySignals.strongestEvidenceClass).toBe("runtime-behavior");
		expect(report.merge.promotedClaims.map((claim) => claim.claimId)).toEqual(["runtime-proof"]);
		expect(report.merge.nextCommands).toContain("curl -i http://example.test/admin");
	});

	it("promotes claims backed by explicit evidenceItems", () => {
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(
			fakeRepiPath,
			`#!/usr/bin/env node\nconsole.log(JSON.stringify({workerId:"worker-1",role:"verifier",claims:[{id:"evidence-item-only",statement:"runtime replay proof is recorded as a structured evidence item",evidence:[],confidence:0.88,blockers:[]}],evidenceItems:[{claimId:"evidence-item-only",class:"runtime-behavior",locator:"curl /api/proof exited 0 HTTP 200 body hash sha256:${"ef".repeat(32)}",summary:"negative control: tampered replay rejected HTTP 403"}],blockers:[],nextCommands:[]}, null, 2));\n`,
		);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"run",
				"./evidence-items-worker",
				"--workers",
				"1",
				"--max-concurrency",
				"1",
				"--cwd",
				workspace,
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			merge: {
				evidenceItemRows: Array<{ claimId: string; evidenceClass: string; evidencePriorityRank: number }>;
				claimRows: Array<{
					claimId: string;
					status: string;
					evidenceItemIds: string[];
					qualitySignals: {
						evidenceItemCount: number;
						strongestEvidenceClass: string;
						hasNegativeControl: boolean;
					};
				}>;
				proofChecklists: Array<{ proofReady: boolean }>;
				promotedClaims: Array<{ claimId: string }>;
			};
		};
		expect(report.merge.evidenceItemRows).toHaveLength(1);
		expect(report.merge.evidenceItemRows[0]).toMatchObject({
			claimId: "evidence-item-only",
			evidenceClass: "runtime-behavior",
		});
		const claim = report.merge.claimRows[0];
		expect(claim.status).toBe("promoted");
		expect(claim.evidenceItemIds).toHaveLength(1);
		expect(claim.qualitySignals.evidenceItemCount).toBe(1);
		expect(claim.qualitySignals.strongestEvidenceClass).toBe("runtime-behavior");
		expect(claim.qualitySignals.hasNegativeControl).toBe(true);
		expect(report.merge.proofChecklists[0].proofReady).toBe(true);
		expect(report.merge.promotedClaims.map((row) => row.claimId)).toEqual(["evidence-item-only"]);
	});

	it("recognizes multilingual and lane-specific evidence signals across reverse domains", () => {
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(
			fakeRepiPath,
			`#!/usr/bin/env node\nconsole.log(JSON.stringify({workerId:"worker-1",role:"solo",claims:[{id:"mobile-cn-proof",statement:"移动端签名重放路径已验证",evidence:["jadx -d /tmp/repi-apk-out app.apk 生成证据文件 sha256:${"9a".repeat(32)}","负控制：错误签名重放被拒绝，未进入授权路径"],confidence:0.9,blockers:[]}],evidenceItems:[{claimId:"mobile-cn-proof",class:"runtime-behavior",locator:"frida -U -f com.example.app -l hook.js",summary:"反证：禁用 hook 后请求失败"}],blockers:[],nextCommands:["jadx -d /tmp/repi-apk-out app.apk"]}, null, 2));\n`,
		);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"run",
				"./app.apk",
				"--route",
				"mobile",
				"--workers",
				"1",
				"--max-concurrency",
				"1",
				"--cwd",
				workspace,
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			merge: {
				finalPromotionReady: boolean;
				routeProofReady: boolean;
				claimRows: Array<{
					claimId: string;
					qualitySignals: {
						hasCommand: boolean;
						hasNegativeControl: boolean;
						strongestEvidenceClass: string;
					};
				}>;
				proofChecklists: Array<{
					proofReady: boolean;
					coverage: { passive: boolean; proofExit: boolean; negativeControls: boolean };
				}>;
			};
		};
		expect(report.merge.finalPromotionReady).toBe(true);
		expect(report.merge.routeProofReady).toBe(true);
		expect(report.merge.claimRows[0].qualitySignals).toMatchObject({
			hasCommand: true,
			hasNegativeControl: true,
			strongestEvidenceClass: "runtime-behavior",
		});
		expect(report.merge.proofChecklists[0]).toMatchObject({
			proofReady: true,
			coverage: { passive: true, proofExit: true, negativeControls: true },
		});
	});

	it("does not let unrelated worker-level proof make a weak claim proof-ready", () => {
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(
			fakeRepiPath,
			`#!/usr/bin/env node\nconsole.log(JSON.stringify({workerId:"worker-1",role:"verifier",claims:[{id:"weak-source-claim",statement:"source comment says admin endpoint is open",evidence:["source comment says the admin endpoint is open"],confidence:0.9,blockers:[]}],evidence:["curl /health exited 0 HTTP 200 body hash sha256:${"ab".repeat(32)}","negative control: invalid token returned HTTP 403"],blockers:[],nextCommands:["curl -i http://example.test/health"]}, null, 2));\n`,
		);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"run",
				"./claim-level-proof",
				"--workers",
				"1",
				"--max-concurrency",
				"1",
				"--cwd",
				workspace,
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(1);
		const report = JSON.parse(result.stdout) as {
			mergeFailureReason: string;
			merge: {
				finalPromotionReady: boolean;
				proofPromotionReady: boolean;
				proofReadyPromotedClaims: unknown[];
				proofChecklists: Array<{ proofReady: boolean }>;
				claimRows: Array<{
					claimId: string;
					status: string;
					proofReady: boolean;
					proofCoverage: { passive: boolean; proofExit: boolean; negativeControls: boolean };
				}>;
			};
		};
		expect(report.merge.proofChecklists[0].proofReady).toBe(true);
		expect(report.merge.claimRows[0]).toMatchObject({
			claimId: "weak-source-claim",
			status: "promoted",
			proofReady: false,
			proofCoverage: { passive: true, proofExit: false, negativeControls: false },
		});
		expect(report.merge.proofReadyPromotedClaims).toEqual([]);
		expect(report.merge.proofPromotionReady).toBe(false);
		expect(report.merge.finalPromotionReady).toBe(false);
		expect(report.mergeFailureReason).toContain("route proof incomplete");
	});

	it("downgrades named technique claims until the technique proof-exit contract is satisfied", () => {
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(
			fakeRepiPath,
			`#!/usr/bin/env node\nconsole.log(JSON.stringify({workerId:"worker-1",role:"verifier",claims:[{id:"ret2libc-weak",techniqueId:"pwn-ret2libc",statement:"pwn-ret2libc works",evidence:["python3 exploit.py exited 0 HTTP 200 body hash sha256:${"45".repeat(32)}","negative control: wrong offset exits 1"],confidence:0.9,blockers:[]}],blockers:[],nextCommands:["python3 exploit.py"]}, null, 2));\n`,
		);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"run",
				"./ret2libc-target",
				"--route",
				"native-pwn",
				"--workers",
				"1",
				"--max-concurrency",
				"1",
				"--cwd",
				workspace,
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(1);
		const report = JSON.parse(result.stdout) as {
			mergeFailureReason: string;
			merge: {
				finalPromotionReady: boolean;
				promotedClaims: unknown[];
				proofReadyPromotedClaims: unknown[];
				techniqueProofChecks: Array<{
					claimId: string;
					techniqueId: string;
					proofReady: boolean;
					missing: string[];
				}>;
				missingTechniqueProofClaims: Array<{ claimId: string; missing: string[] }>;
				claimRows: Array<{
					claimId: string;
					status: string;
					techniqueIds: string[];
					techniqueProofReady: boolean;
					techniqueProofMissing: string[];
				}>;
				nextCommands: string[];
				repairQueue: Array<{
					kind: string;
					priority: number;
					claimId?: string;
					routeId?: string;
					missing: string[];
					command: string;
				}>;
			};
		};
		expect(report.merge.finalPromotionReady).toBe(false);
		expect(report.merge.promotedClaims).toEqual([]);
		expect(report.merge.proofReadyPromotedClaims).toEqual([]);
		expect(report.merge.claimRows[0]).toMatchObject({
			claimId: "ret2libc-weak",
			status: "observation",
			techniqueIds: ["pwn-ret2libc"],
			techniqueProofReady: false,
		});
		expect(report.merge.claimRows[0].techniqueProofMissing).toEqual(
			expect.arrayContaining(["pwn-ret2libc:libc-leak", "pwn-ret2libc:libc-base", "pwn-ret2libc:code-exec"]),
		);
		expect(report.merge.techniqueProofChecks[0]).toMatchObject({
			claimId: "ret2libc-weak",
			techniqueId: "pwn-ret2libc",
			proofReady: false,
		});
		expect(report.merge.missingTechniqueProofClaims[0].claimId).toBe("ret2libc-weak");
		const repairCommand = report.merge.nextCommands.find((command) =>
			command.includes("Close named-technique proof-exit gap for claim ret2libc-weak"),
		);
		expect(repairCommand).toContain("--route 'native-pwn'");
		expect(repairCommand).toContain("pwn-ret2libc");
		expect(repairCommand).toContain("libc-leak");
		expect(report.merge.repairQueue[0]).toMatchObject({
			kind: "named-technique-proof",
			priority: 95,
			claimId: "ret2libc-weak",
			routeId: "native-pwn",
		});
		expect(report.merge.repairQueue[0].missing).toEqual(
			expect.arrayContaining(["pwn-ret2libc:libc-leak", "pwn-ret2libc:libc-base"]),
		);
		expect(report.merge.repairQueue[0].command).toContain("Close named-technique proof-exit gap");
		expect(report.mergeFailureReason).toContain("route proof incomplete");
	});

	it("promotes named technique claims when evidence satisfies proof-exit and controls", () => {
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(
			fakeRepiPath,
			`#!/usr/bin/env node\nconsole.log(JSON.stringify({workerId:"worker-1",role:"verifier",claims:[{id:"ret2libc-proof",techniqueId:"pwn-ret2libc",statement:"pwn-ret2libc proof is complete",evidence:["gdb leak proof: puts@got leak 0x7f00 and computed libc base = 0x7e000 for matching libc sha256:${"56".repeat(32)}","python3 exploit.py exited 0 and system('/bin/sh') interactive shell printed id output","negative control: wrong libc build exits SIGSEGV and wrong offset exits 1"],confidence:0.9,blockers:[]}],blockers:[],nextCommands:["python3 exploit.py"]}, null, 2));\n`,
		);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"run",
				"./ret2libc-target",
				"--route",
				"native-pwn",
				"--workers",
				"1",
				"--max-concurrency",
				"1",
				"--cwd",
				workspace,
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			merge: {
				finalPromotionReady: boolean;
				proofReadyPromotedClaims: Array<{ claimId: string; techniqueProofReady: boolean }>;
				techniqueProofChecks: Array<{ techniqueId: string; proofReady: boolean; missing: string[] }>;
				claimRows: Array<{ claimId: string; status: string; techniqueProofReady: boolean }>;
			};
		};
		expect(report.merge.finalPromotionReady).toBe(true);
		expect(report.merge.claimRows[0]).toMatchObject({
			claimId: "ret2libc-proof",
			status: "promoted",
			techniqueProofReady: true,
		});
		expect(report.merge.proofReadyPromotedClaims[0]).toMatchObject({
			claimId: "ret2libc-proof",
			techniqueProofReady: true,
		});
		expect(report.merge.techniqueProofChecks[0]).toMatchObject({
			techniqueId: "pwn-ret2libc",
			proofReady: true,
			missing: [],
		});
	});

	it("applies cross-worker conflicts globally before promotion", () => {
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(
			fakeRepiPath,
			`#!/usr/bin/env node\nconst prompt = process.argv[process.argv.length - 1] || "";\nif (/worker 2/.test(prompt)) {\n  console.log(JSON.stringify({workerId:"worker-2",role:"verifier",claims:[{id:"runtime-control",statement:"invalid token is rejected",evidence:["curl /api/proof exited 0 HTTP 200 body hash sha256:${"12".repeat(32)}","negative control: invalid token returned HTTP 403"],confidence:0.9,blockers:[]}],conflicts:[{claimId:"source-only",evidenceClass:"network-traffic",evidence:"curl /admin returned HTTP 403 body hash sha256:${"34".repeat(32)}",reason:"live replay contradicts source-only claim"}],blockers:[],nextCommands:[]}, null, 2));\n} else {\n  console.log(JSON.stringify({workerId:"worker-1",role:"mapper",claims:[{id:"source-only",statement:"source comment claims admin is open",evidence:["source comment says /admin is open"],confidence:0.9,blockers:[]}],blockers:[],nextCommands:[]}, null, 2));\n}\n`,
		);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"run",
				"./cross-worker-conflict",
				"--workers",
				"2",
				"--max-concurrency",
				"1",
				"--cwd",
				workspace,
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			merge: {
				claimRows: Array<{
					claimId: string;
					status: string;
					conflictResolution: { downgraded: boolean; strongestConflictClass: string };
				}>;
				promotedClaims: Array<{ claimId: string }>;
				conflictRows: Array<{ claimId: string; workerId: number }>;
			};
		};
		const sourceClaim = report.merge.claimRows.find((claim) => claim.claimId === "source-only");
		expect(report.merge.conflictRows).toEqual([expect.objectContaining({ claimId: "source-only", workerId: 2 })]);
		expect(sourceClaim?.status).toBe("observation");
		expect(sourceClaim?.conflictResolution).toMatchObject({
			downgraded: true,
			strongestConflictClass: "network-traffic",
		});
		expect(report.merge.promotedClaims.map((claim) => claim.claimId)).toEqual(["runtime-control"]);
	});

	it("reports worker execution failure before narrative-only merge failure", () => {
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(fakeRepiPath, "#!/usr/bin/env node\nconsole.error('worker boom');\nprocess.exit(2);\n");
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"run",
				"./failing-worker",
				"--workers",
				"1",
				"--max-concurrency",
				"1",
				"--cwd",
				workspace,
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);

		expect(result.status).toBe(1);
		const report = JSON.parse(result.stdout) as {
			mergeFailureReason: string;
			merge: { failedWorkers: Array<{ status: string }> };
		};
		expect(report.mergeFailureReason).toContain("workers failed");
		expect(report.mergeFailureReason).not.toContain("narrative-only");
		expect(report.merge.failedWorkers[0].status).toBe("fail");
	});

	it("honors --max-concurrency in llm-run mode instead of forcing workers-wide fanout", () => {
		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"llm-run",
				"local-selfcheck",
				"--workers",
				"3",
				"--max-concurrency",
				"1",
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			ok: boolean;
			evidenceRoot: string;
			workers: number;
			maxConcurrency: number;
			workersReport: Array<{
				route: { id: string };
				proofKit: { proofExit: string[] };
				commandPalette: { proof: string[] };
				toolProbeCommand: string;
				techniqueHints: { domains: string[]; techniqueIds: string[] };
			}>;
			plan: {
				maxConcurrency: number;
				workerPackets: Array<{
					route: { id: string };
					proofKit: { proofExit: string[] };
					commandPalette: { proof: string[] };
					toolProbeCommand: string;
					techniqueHints: { domains: string[]; techniqueIds: string[] };
				}>;
			};
		};
		expect(report.ok).toBe(true);
		expect(report.workers).toBe(3);
		expect(report.workersReport).toHaveLength(3);
		expect(report.maxConcurrency).toBe(1);
		expect(report.plan.maxConcurrency).toBe(1);
		expect(report.plan.workerPackets[0].route.id).toBe("reverse-pentest-general");
		expect(report.plan.workerPackets[0].proofKit.proofExit.length).toBeGreaterThan(0);
		expect(report.plan.workerPackets[0].commandPalette.proof.length).toBeGreaterThan(0);
		expect(report.plan.workerPackets[0].toolProbeCommand).toContain("command -v");
		expect(report.plan.workerPackets[0].techniqueHints.techniqueIds).toContain("reliability-replay-matrix");
		expect(report.workersReport[0].route.id).toBe("reverse-pentest-general");
		expect(report.workersReport[0].proofKit.proofExit.length).toBeGreaterThan(0);
		expect(report.workersReport[0].commandPalette.proof.length).toBeGreaterThan(0);
		expect(report.workersReport[0].toolProbeCommand).toContain("python3");
		expect(report.workersReport[0].techniqueHints.domains).toContain("exploit-reliability");
	});

	it("preserves --route all and route placeholders in llm-run mode", () => {
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(
			fakeRepiPath,
			`#!/usr/bin/env node\nconst prompt=process.argv.at(-1)||"";\nconsole.log(JSON.stringify({workerId:"fake",prompt}, null, 2));\n`,
		);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"llm-run",
				"full-spectrum audit",
				"--route",
				"all",
				"--max-concurrency",
				"4",
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			ok: boolean;
			evidenceRoot: string;
			workers: number;
			maxConcurrency: number;
			plan: {
				autoExpandedWorkers: boolean;
				routeCandidates: Array<{ id: string }>;
				workerPackets: Array<{ route: { id: string } }>;
			};
			workersReport: Array<{ route: { id: string }; stdoutTail: string }>;
		};
		const routeIds = [
			"native-pwn",
			"web-api",
			"js-reverse",
			"mobile",
			"pcap-dfir",
			"memory-forensics",
			"firmware-iot",
			"cloud-identity",
			"windows-ad",
			"malware",
			"crypto-stego",
			"agent-boundary",
		];
		expect(report.ok).toBe(true);
		expect(report.workers).toBe(12);
		expect(report.maxConcurrency).toBe(4);
		expect(report.plan.autoExpandedWorkers).toBe(true);
		expect(report.plan.routeCandidates.map((route) => route.id)).toEqual(routeIds);
		expect(report.plan.workerPackets.map((packet) => packet.route.id)).toEqual(routeIds);
		expect(report.workersReport.map((worker) => worker.route.id)).toEqual(routeIds);
		const workerStdout = readFileSync(join(report.evidenceRoot, "worker-1.stdout.txt"), "utf8");
		const workerPrompt = (JSON.parse(workerStdout) as { prompt: string }).prompt;
		expect(workerPrompt).toContain("Route: Native / Pwn");
		expect(workerPrompt).toContain("proofKit=");
		expect(workerPrompt).toContain("Route tool probe command");
		const toolProbeLine = workerPrompt.split("\n").find((line) => line.startsWith("for t in"));
		expect(toolProbeLine).toContain("command -v");
		expect(toolProbeLine).not.toContain("'PY'");
		expect(workerPrompt).toContain("techniqueHints=");
	});

	it("wraps custom llm-run prompts with route context even without placeholders", () => {
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(
			fakeRepiPath,
			`#!/usr/bin/env node\nconst prompt=process.argv.at(-1)||"";\nconsole.log(JSON.stringify({workerId:"fake",prompt}, null, 2));\n`,
		);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"llm-run",
				"https://example.test/api",
				"--route",
				"web-api",
				"--workers",
				"1",
				"--max-concurrency",
				"1",
				"--prompt",
				"Assess this target and return concise evidence.",
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			evidenceRoot: string;
			workersReport: Array<{ route: { id: string } }>;
		};
		expect(report.workersReport[0].route.id).toBe("web-api");
		const workerStdout = readFileSync(join(report.evidenceRoot, "worker-1.stdout.txt"), "utf8");
		expect(workerStdout).toContain("Route: Web / API (web-api)");
		expect(workerStdout).toContain("Operator prompt");
		expect(workerStdout).toContain("Assess this target and return concise evidence.");
		expect(workerStdout).toContain("Route proof kit");
		expect(workerStdout).toContain("Route command palette");
		expect(workerStdout).toContain("Route tool probe command");
		expect(workerStdout).toContain("Route technique hints");
		expect(workerStdout).toContain("Capability matrix doctrine");
		expect(workerStdout).toContain("Evidence priority doctrine");
	});

	it("does not mistake flag values for the swarm target", () => {
		const withTarget = spawnSync(
			process.execPath,
			[SWARM, fakeRoot, "plan", "--workers", "2", "--max-concurrency", "1", "./vuln", "--json"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(withTarget.status, `${withTarget.stderr}\n${withTarget.stdout}`).toBe(0);
		expect(
			(JSON.parse(withTarget.stdout) as { plan: { target: string; maxConcurrency: number } }).plan,
		).toMatchObject({
			target: "./vuln",
			maxConcurrency: 1,
		});

		const defaultTarget = spawnSync(process.execPath, [SWARM, fakeRoot, "plan", "--workers", "2", "--json"], {
			encoding: "utf8",
			env: {
				...process.env,
				REPI_CODING_AGENT_DIR: agentDir,
			},
			timeout: 10_000,
		});
		expect(defaultTarget.status, `${defaultTarget.stderr}\n${defaultTarget.stdout}`).toBe(0);
		expect((JSON.parse(defaultTarget.stdout) as { plan: { target: string } }).plan.target).toBe("local-selfcheck");
	});

	it("keeps latest bound to run creation order after merging an older run", () => {
		const run = (args: string[]) =>
			spawnSync(process.execPath, [SWARM, fakeRoot, ...args, "--json"], {
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			});
		const plan = (target: string) => {
			const result = run(["plan", target, "--workers", "1"]);
			expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
			return JSON.parse(result.stdout) as { plan: { runId: string } };
		};

		const older = plan("older-run");
		const newer = plan("newer-run");
		const beforeMerge = run(["status", "latest"]);
		expect(beforeMerge.status, `${beforeMerge.stderr}\n${beforeMerge.stdout}`).toBe(0);
		expect((JSON.parse(beforeMerge.stdout) as { runId: string }).runId).toBe(newer.plan.runId);

		const merge = run(["merge", older.plan.runId]);
		expect(merge.status, `${merge.stderr}\n${merge.stdout}`).toBe(1);
		expect(statSync(join(agentDir, "recon", "evidence", "llm-swarms", older.plan.runId)).mtimeMs).toBeGreaterThan(
			statSync(join(agentDir, "recon", "evidence", "llm-swarms", newer.plan.runId)).mtimeMs,
		);

		const afterMerge = run(["status", "latest"]);
		expect(afterMerge.status, `${afterMerge.stderr}\n${afterMerge.stdout}`).toBe(0);
		expect((JSON.parse(afterMerge.stdout) as { runId: string }).runId).toBe(newer.plan.runId);
	});

	it("rejects unknown, ambiguous, and traversal refs without mutating any run", () => {
		const run = (args: string[]) =>
			spawnSync(process.execPath, [SWARM, fakeRoot, ...args, "--json"], {
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			});
		const plan = (target: string) => {
			const result = run(["plan", target, "--workers", "1"]);
			expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
			return JSON.parse(result.stdout) as { plan: { runId: string } };
		};
		const older = plan("ref-a");
		const newer = plan("ref-b");
		const runRoot = join(agentDir, "recon", "evidence", "llm-swarms");
		const latestBefore = run(["status", "latest"]);
		expect(latestBefore.status, `${latestBefore.stderr}\n${latestBefore.stdout}`).toBe(0);
		expect((JSON.parse(latestBefore.stdout) as { runId: string }).runId).toBe(newer.plan.runId);
		const snapshot = (runId: string) => {
			const dir = join(runRoot, runId);
			return readdirSync(dir)
				.sort()
				.map((name) => {
					const stat = statSync(join(dir, name));
					return [name, stat.size, stat.mtimeMs];
				});
		};
		const before = [snapshot(older.plan.runId), snapshot(newer.plan.runId)];

		const unknownStatus = run(["status", "definitely-not-a-run"]);
		expect(unknownStatus.status).toBe(1);
		expect(JSON.parse(unknownStatus.stdout)).toMatchObject({ ok: false, error: "run-not-found", matches: [] });
		const unknownMerge = run(["merge", "definitely-not-a-run"]);
		expect(unknownMerge.status).toBe(1);
		expect(JSON.parse(unknownMerge.stdout)).toMatchObject({ ok: false, error: "run-not-found", matches: [] });

		let commonLength = 0;
		while (
			commonLength < older.plan.runId.length &&
			commonLength < newer.plan.runId.length &&
			older.plan.runId[commonLength] === newer.plan.runId[commonLength]
		) {
			commonLength += 1;
		}
		const ambiguousRef = older.plan.runId.slice(0, commonLength);
		expect(ambiguousRef.length).toBeGreaterThan(0);
		expect(ambiguousRef).not.toBe(older.plan.runId);
		const ambiguousStatus = run(["status", ambiguousRef]);
		expect(ambiguousStatus.status).toBe(1);
		expect(JSON.parse(ambiguousStatus.stdout)).toMatchObject({ ok: false, error: "run-ref-ambiguous" });
		const ambiguousMerge = run(["merge", ambiguousRef]);
		expect(ambiguousMerge.status).toBe(1);
		expect(JSON.parse(ambiguousMerge.stdout)).toMatchObject({ ok: false, error: "run-ref-ambiguous" });

		const traversal = run(["status", `../${older.plan.runId}`]);
		expect(traversal.status).toBe(1);
		expect(JSON.parse(traversal.stdout)).toMatchObject({ ok: false, error: "run-not-found" });
		const latestAfter = run(["status", "latest"]);
		expect(latestAfter.status, `${latestAfter.stderr}\n${latestAfter.stdout}`).toBe(0);
		expect((JSON.parse(latestAfter.stdout) as { runId: string }).runId).toBe(newer.plan.runId);
		expect([snapshot(older.plan.runId), snapshot(newer.plan.runId)]).toEqual(before);
	});

	it("catalogs TS runtime artifacts beside CLI runs and refuses cross-engine merge", () => {
		const run = (args: string[]) =>
			spawnSync(process.execPath, [SWARM, fakeRoot, ...args, "--json"], {
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			});
		const cliPlan = run(["plan", "cli-catalog-target", "--workers", "1"]);
		expect(cliPlan.status, `${cliPlan.stderr}\n${cliPlan.stdout}`).toBe(0);
		const cliRunId = (JSON.parse(cliPlan.stdout) as { plan: { runId: string } }).plan.runId;
		const tsRoot = join(agentDir, "recon", "evidence", "swarms");
		mkdirSync(tsRoot, { recursive: true });
		const tsRunId = "2099-01-02T03-04-05-006Z-web-api-run";
		const tsArtifact = {
			timestamp: "2099-01-02T03:04:05.006Z",
			route: "web-api",
			target: "ts-catalog-target",
			mode: "run",
			workers: [{ id: "swarm:1:web-authz", worker: "web-authz", status: "done" }],
			executions: [{ workerId: "swarm:1:web-authz", status: "done", exitCode: 0, elapsedMs: 4 }],
			blocked: [],
			structuredClaimMergeStatus: "pass",
			structuredClaimMerge: { promotionCheck: { finalClaims: [{ claimId: "proof-1" }] } },
		};
		const tsArtifactPath = join(tsRoot, `${tsRunId}.md`);
		writeFileSync(
			tsArtifactPath,
			`# REPI Swarm Artifact\n\n## JSON\n\n\`\`\`json\n${JSON.stringify(tsArtifact, null, 2)}\n\`\`\`\n`,
		);

		const listed = run(["list"]);
		expect(listed.status, `${listed.stderr}\n${listed.stdout}`).toBe(0);
		const listReport = JSON.parse(listed.stdout) as { runs: Array<{ engine: string; runId: string }> };
		expect(listReport.runs).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ engine: "cli", runId: cliRunId }),
				expect.objectContaining({ engine: "ts", runId: tsRunId }),
			]),
		);

		const latest = run(["status", "latest"]);
		expect(latest.status, `${latest.stderr}\n${latest.stdout}`).toBe(0);
		expect(JSON.parse(latest.stdout)).toMatchObject({ engine: "ts", runId: tsRunId, state: "complete", ok: true });

		const resolvedTs = run(["resolve", `ts:${tsRunId}`]);
		expect(resolvedTs.status, `${resolvedTs.stderr}\n${resolvedTs.stdout}`).toBe(0);
		expect(JSON.parse(resolvedTs.stdout)).toMatchObject({ ok: true, run: { engine: "ts", runId: tsRunId } });
		const resolvedCli = run(["resolve", `cli:${cliRunId}`]);
		expect(resolvedCli.status, `${resolvedCli.stderr}\n${resolvedCli.stdout}`).toBe(0);
		expect(JSON.parse(resolvedCli.stdout)).toMatchObject({ ok: true, run: { engine: "cli", runId: cliRunId } });

		const before = readFileSync(tsArtifactPath, "utf8");
		const merge = run(["merge", "latest"]);
		expect(merge.status).toBe(1);
		expect(JSON.parse(merge.stdout)).toMatchObject({
			ok: false,
			error: "cross-engine-merge-unsupported",
			engine: "ts",
			runId: tsRunId,
		});
		expect(readFileSync(tsArtifactPath, "utf8")).toBe(before);
	});

	it("reports a failed merge instead of the earlier successful CLI run", () => {
		const runId = "2026-07-20T04-05-06-007Z-status-merge-failed";
		const evidenceRoot = join(agentDir, "recon", "evidence", "llm-swarms", runId);
		mkdirSync(evidenceRoot, { recursive: true });
		writeFileSync(
			join(evidenceRoot, "plan.json"),
			JSON.stringify({
				kind: "repi-swarm-plan-report",
				generatedAt: "2026-07-20T04:05:06.007Z",
				runId,
				target: "merge-failure-target",
				workers: 1,
			}),
		);
		writeFileSync(
			join(evidenceRoot, "report.json"),
			JSON.stringify({
				kind: "repi-swarm-run-report",
				generatedAt: "2026-07-20T04:05:07.000Z",
				runId,
				target: "merge-failure-target",
				workers: 1,
				workersReport: [{ workerId: 1, role: "worker", status: "pass", exit: 0, ms: 2 }],
				ok: true,
			}),
		);
		writeFileSync(
			join(evidenceRoot, "merge-report.json"),
			JSON.stringify({
				kind: "repi-swarm-merge-report",
				generatedAt: "2026-07-20T04:05:08.000Z",
				runId,
				target: "merge-failure-target",
				workerCount: 1,
				promotedClaims: [],
				ok: false,
			}),
		);

		const status = spawnSync(process.execPath, [SWARM, fakeRoot, "status", `cli:${runId}`, "--json"], {
			encoding: "utf8",
			env: { ...process.env, REPI_CODING_AGENT_DIR: agentDir },
			timeout: 10_000,
		});
		expect(status.status, `${status.stderr}\n${status.stdout}`).toBe(1);
		expect(JSON.parse(status.stdout)).toMatchObject({
			ok: false,
			engine: "cli",
			runId,
			state: "failed",
			merge: { ok: false, promotedClaims: 0 },
		});
	});

	it("does not follow catalog child symlinks outside the swarm roots", () => {
		if (process.platform === "win32") return;
		const run = (args: string[]) =>
			spawnSync(process.execPath, [SWARM, fakeRoot, ...args, "--json"], {
				encoding: "utf8",
				env: { ...process.env, REPI_CODING_AGENT_DIR: agentDir },
				timeout: 10_000,
			});
		const outsideCli = join(agentDir, "outside-cli-run");
		mkdirSync(outsideCli, { recursive: true });
		writeFileSync(
			join(outsideCli, "plan.json"),
			JSON.stringify({ kind: "repi-swarm-plan-report", runId: "linked-cli", target: "outside" }),
		);
		const cliRoot = join(agentDir, "recon", "evidence", "llm-swarms");
		mkdirSync(cliRoot, { recursive: true });
		symlinkSync(outsideCli, join(cliRoot, "linked-cli"), "dir");

		const outsideTs = join(agentDir, "outside-ts.md");
		writeFileSync(
			outsideTs,
			`# REPI Swarm Artifact\n\n## JSON\n\n\`\`\`json\n${JSON.stringify({ timestamp: "2099-01-02T03:04:05.006Z", mode: "plan", workers: [], executions: [] })}\n\`\`\`\n`,
		);
		const tsRoot = join(agentDir, "recon", "evidence", "swarms");
		mkdirSync(tsRoot, { recursive: true });
		symlinkSync(outsideTs, join(tsRoot, "linked-ts.md"), "file");

		const listed = run(["list"]);
		expect(listed.status, `${listed.stderr}\n${listed.stdout}`).toBe(0);
		expect(JSON.parse(listed.stdout).runs).toEqual([]);
		const merge = run(["merge", "linked-cli"]);
		expect(merge.status).toBe(1);
		expect(JSON.parse(merge.stdout)).toMatchObject({ ok: false, error: "run-not-found" });
		expect(existsSync(join(outsideCli, "merge-report.json"))).toBe(false);
	});

	it("supports command-first direct invocation and routes specialist worker contracts", () => {
		const result = spawnSync(
			process.execPath,
			[SWARM, "plan", "pwn ELF ret2libc heap primitive", "--workers=4", "--max-concurrency=2", "--json"],
			{
				cwd: fakeRoot,
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			plan: {
				root: string;
				route: { id: string; domain: string; workflow: string[] };
				proofDoctrine: { claimGate: string };
				workers: number;
				maxConcurrency: number;
				workerPackets: Array<{ role: string; objective: string; evidenceContract: string[]; mergeKeys: string[] }>;
			};
		};
		expect(report.plan.root).toBe(fakeRoot);
		expect(report.plan.proofDoctrine.claimGate).toContain("promoted claim");
		expect(report.plan.route).toMatchObject({ id: "native-pwn", domain: "Native / Pwn" });
		expect(report.plan.route.workflow).toContain("primitive/leak proof");
		expect(report.plan.workers).toBe(4);
		expect(report.plan.maxConcurrency).toBe(2);
		expect(report.plan.workerPackets[0].evidenceContract).toContain("sha256/file/checksec");
		expect(report.plan.workerPackets[2].objective).toContain("crash/leak/write primitive");
		expect(report.plan.workerPackets[3].mergeKeys).toContain("flake");
	});

	it("uses an end-to-end solo contract for one-worker swarm runs unless roles are explicit", () => {
		const solo = spawnSync(
			process.execPath,
			[SWARM, fakeRoot, "plan", "javascript signature reverse", "--workers", "1", "--json"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(solo.status, `${solo.stderr}\n${solo.stdout}`).toBe(0);
		const soloReport = JSON.parse(solo.stdout) as {
			plan: {
				workerPackets: Array<{
					role: string;
					objective: string;
					evidenceContract: string[];
					proofKit: { proofExit: string[]; negativeControls: string[] };
				}>;
			};
		};
		expect(soloReport.plan.workerPackets[0].role).toBe("solo");
		expect(soloReport.plan.workerPackets[0].objective).toContain("完整处理");
		expect(soloReport.plan.workerPackets[0].evidenceContract).toContain("negative control or counter-evidence");
		expect(soloReport.plan.workerPackets[0].proofKit.proofExit.join("\n")).toContain("byte-for-byte");
		expect(soloReport.plan.workerPackets[0].proofKit.negativeControls).toContain("missing signature");

		const explicit = spawnSync(
			process.execPath,
			[SWARM, fakeRoot, "plan", "javascript signature reverse", "--workers", "1", "--roles", "mapper", "--json"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(explicit.status, `${explicit.stderr}\n${explicit.stdout}`).toBe(0);
		expect(
			(JSON.parse(explicit.stdout) as { plan: { workerPackets: Array<{ role: string }> } }).plan.workerPackets[0]
				.role,
		).toBe("mapper");
	});

	it("spreads broad multi-domain tasks across matched route profiles", () => {
		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"plan",
				"pwn ELF plus JWT web API plus APK mobile plus PCAP traffic",
				"--workers",
				"4",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			plan: {
				routeCoverage: { complete: boolean; uncoveredCount: number };
				routeCandidates: Array<{
					id: string;
					proofKit: { passive: string[]; proofExit: string[]; negativeControls: string[] };
				}>;
				workerPackets: Array<{
					route: { id: string; domain: string };
					evidenceContract: string[];
					proofKit: { passive: string[]; proofExit: string[]; negativeControls: string[] };
				}>;
			};
		};
		expect(report.plan.routeCandidates.map((route) => route.id)).toEqual(
			expect.arrayContaining(["native-pwn", "web-api", "mobile", "pcap-dfir"]),
		);
		expect(report.plan.workerPackets.map((packet) => packet.route.id)).toEqual([
			"native-pwn",
			"web-api",
			"mobile",
			"pcap-dfir",
		]);
		expect(report.plan.workerPackets[0].evidenceContract).toContain("sha256/file/checksec");
		expect(report.plan.workerPackets[0].proofKit.proofExit.join("\n")).toContain("cyclic offset");
		expect(report.plan.workerPackets[1].route.domain).toBe("Web / API");
		expect(report.plan.workerPackets[1].proofKit.negativeControls).toContain("anonymous vs authenticated");
		expect(report.plan.routeCoverage).toMatchObject({ complete: true, uncoveredCount: 0 });
	});

	it("auto-expands worker count for broad multi-route tasks when --workers is omitted", () => {
		const result = spawnSync(
			process.execPath,
			[SWARM, fakeRoot, "plan", "pwn ELF plus JWT web API plus APK mobile plus PCAP traffic", "--json"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			plan: {
				workers: number;
				autoExpandedWorkers: boolean;
				routeCandidates: Array<{ id: string }>;
				workerPackets: Array<{ route: { id: string } }>;
			};
		};
		expect(report.plan.autoExpandedWorkers).toBe(true);
		expect(report.plan.workers).toBe(report.plan.routeCandidates.length);
		expect(report.plan.workerPackets.map((packet) => packet.route.id)).toEqual(
			report.plan.routeCandidates.map((route) => route.id),
		);
	});

	it("surfaces uncovered route gaps and repair commands when explicit workers are insufficient", () => {
		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"run",
				"pwn ELF plus JWT web API plus APK mobile plus PCAP traffic",
				"--workers",
				"2",
				"--max-concurrency",
				"1",
				"--provider",
				"kimchi",
				"--model",
				"kimi-k2.7",
				"--cwd",
				workspace,
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(1);
		const report = JSON.parse(result.stdout) as {
			mergeFailureReason: string;
			plan: { routeCoverage: { complete: boolean; uncovered: Array<{ id: string }>; uncoveredCount: number } };
			merge: {
				routeCoverage: { complete: boolean; uncovered: Array<{ id: string }>; uncoveredCount: number };
				nextCommands: string[];
			};
		};
		expect(report.plan.routeCoverage.complete).toBe(false);
		expect(report.mergeFailureReason).toContain("route coverage incomplete");
		expect(report.plan.routeCoverage.uncovered.map((route) => route.id)).toEqual(["mobile", "pcap-dfir"]);
		expect(report.merge.routeCoverage.uncoveredCount).toBe(2);
		expect(report.merge.nextCommands.some((command) => command.includes("--route 'mobile'"))).toBe(true);
		expect(report.merge.nextCommands.some((command) => command.includes("--route 'pcap-dfir'"))).toBe(true);
		const repairCommands = report.merge.nextCommands.filter((command) =>
			command.includes("Cover previously unassigned route"),
		);
		expect(repairCommands.length).toBe(2);
		expect(repairCommands.every((command) => command.includes("--provider 'kimchi'"))).toBe(true);
		expect(repairCommands.every((command) => command.includes("--model 'kimi-k2.7'"))).toBe(true);
		expect(repairCommands.every((command) => command.includes(`--cwd '${workspace}'`))).toBe(true);
	});

	it("requires proof-ready promoted claims for every covered route before full-spectrum promotion", () => {
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(
			fakeRepiPath,
			`#!/usr/bin/env node\nconst prompt=process.argv.at(-1)||"";\nconst routeLine=(prompt.match(/^Route:.*$/m)||[""])[0];\nif (/Frontend \\/ JS reverse/.test(routeLine)) {\n  console.log(JSON.stringify({workerId:"worker-2",role:"reverser",claims:[{id:"js-weak",statement:"signature rebuild is only partially proven",evidence:["node rebuild.js exited 0 body hash sha256:${"56".repeat(32)}"],confidence:0.9,blockers:[]}],blockers:[],nextCommands:["node rebuild.js"]}, null, 2));\n} else {\n  console.log(JSON.stringify({workerId:"worker-1",role:"mapper",claims:[{id:"web-proof",statement:"web authz replay is proven",evidence:["curl /api/object/1 exited 0 HTTP 200 body hash sha256:${"78".repeat(32)}","negative control: anonymous replay returned HTTP 403"],confidence:0.9,blockers:[]}],blockers:[],nextCommands:["curl -i http://example.test/api/object/1"]}, null, 2));\n}\n`,
		);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"run",
				"https://example.test/api uses javascript signature",
				"--route",
				"web-api,js-reverse",
				"--workers",
				"2",
				"--max-concurrency",
				"1",
				"--provider",
				"kimchi",
				"--model",
				"kimi-k2.7",
				"--cwd",
				workspace,
				"--timeout-ms",
				"5000",
				"--no-tools",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(1);
		const report = JSON.parse(result.stdout) as {
			ok: boolean;
			mergeFailureReason: string;
			merge: {
				finalPromotionReady: boolean;
				routeProofReady: boolean;
				proofReadyRouteIds: string[];
				missingProofRoutes: Array<{ id: string }>;
				routeReadinessRows: Array<{
					routeId: string;
					proofReady: boolean;
					promotedClaimIds: string[];
					proofReadyPromotedClaimIds: string[];
					missing: string[];
				}>;
				nextCommands: string[];
			};
		};
		expect(report.ok).toBe(false);
		expect(report.merge.finalPromotionReady).toBe(false);
		expect(report.merge.routeProofReady).toBe(false);
		expect(report.merge.proofReadyRouteIds).toEqual(["web-api"]);
		expect(report.merge.missingProofRoutes.map((route) => route.id)).toEqual(["js-reverse"]);
		expect(report.mergeFailureReason).toContain("route proof incomplete");
		const jsRoute = report.merge.routeReadinessRows.find((row) => row.routeId === "js-reverse");
		expect(jsRoute).toMatchObject({
			proofReady: false,
			promotedClaimIds: ["js-weak"],
			proofReadyPromotedClaimIds: [],
		});
		expect(jsRoute?.missing).toContain("proof-ready promoted claim");
		const repairCommand = report.merge.nextCommands.find((command) =>
			command.includes("Close route-level proof gap for Frontend / JS reverse"),
		);
		expect(repairCommand).toContain("--route 'js-reverse'");
		expect(repairCommand).toContain("--provider 'kimchi'");
		expect(repairCommand).toContain("--model 'kimi-k2.7'");
		expect(repairCommand).toContain(`--cwd '${workspace}'`);
		expect(repairCommand).toContain("--no-tools");
	});

	it("turns cross-route worker handoffs into provider-preserving repair commands", () => {
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(
			fakeRepiPath,
			`#!/usr/bin/env node\nconsole.log(JSON.stringify({workerId:"worker-1",role:"mapper",claims:[{id:"claim-handoff",statement:"fallback map found a JWT API edge",evidence:["curl http://example.test/api exited 200","negative control: invalid JWT returned HTTP 403"],confidence:0.9,blockers:[]}],handoffs:[{route:"web-api",reason:"JWT endpoint and object id require authz matrix",evidence:"/api/user/42 accepted bearer token",nextCommand:"curl -kisS http://example.test/api/user/42"}],blockers:[],nextCommands:[]}, null, 2));\n`,
		);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"run",
				"./handoff",
				"--workers",
				"1",
				"--max-concurrency",
				"1",
				"--provider",
				"kimchi",
				"--model",
				"kimi-k2.7",
				"--cwd",
				workspace,
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			merge: {
				routeHandoffs: Array<{ route: { id: string }; reason: string; nextCommand: string }>;
				nextCommands: string[];
			};
		};
		expect(report.merge.routeHandoffs[0].route.id).toBe("web-api");
		expect(report.merge.routeHandoffs[0].reason).toContain("authz matrix");
		expect(report.merge.nextCommands).toContain("curl -kisS http://example.test/api/user/42");
		const handoffCommand = report.merge.nextCommands.find((command) =>
			command.includes("Follow cross-route handoff"),
		);
		expect(handoffCommand).toContain("--route 'web-api'");
		expect(handoffCommand).toContain("--provider 'kimchi'");
		expect(handoffCommand).toContain("--model 'kimi-k2.7'");
		expect(handoffCommand).toContain(`--cwd '${workspace}'`);
		expect(handoffCommand).toContain("Use this proof kit");
	});

	it("supports explicit route forcing for focused repair runs", () => {
		const result = spawnSync(
			process.execPath,
			[SWARM, fakeRoot, "plan", "broad target text", "--route", "mobile,pcap-dfir", "--workers", "2", "--json"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			plan: {
				routeCandidates: Array<{ id: string }>;
				workerPackets: Array<{ route: { id: string } }>;
				routeCoverage: { complete: boolean };
			};
		};
		expect(report.plan.routeCandidates.map((route) => route.id)).toEqual(["mobile", "pcap-dfir"]);
		expect(report.plan.workerPackets.map((packet) => packet.route.id)).toEqual(["mobile", "pcap-dfir"]);
		expect(report.plan.routeCoverage.complete).toBe(true);
	});

	it("supports --route all as a full-spectrum capability entrypoint", () => {
		const result = spawnSync(
			process.execPath,
			[SWARM, fakeRoot, "plan", "full-spectrum audit", "--route", "all", "--json"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			plan: {
				workers: number;
				autoExpandedWorkers: boolean;
				routeCandidates: Array<{ id: string }>;
				workerPackets: Array<{ route: { id: string } }>;
				routeCoverage: { complete: boolean; uncoveredCount: number };
			};
		};
		expect(report.plan.autoExpandedWorkers).toBe(true);
		expect(report.plan.routeCandidates).toHaveLength(12);
		expect(report.plan.workers).toBe(12);
		expect(report.plan.workerPackets.map((packet) => packet.route.id)).toEqual(
			report.plan.routeCandidates.map((route) => route.id),
		);
		expect(report.plan.routeCoverage).toMatchObject({ complete: true, uncoveredCount: 0 });
	});

	it("attaches proof kits across the full reverse/pentest route catalog", () => {
		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"plan",
				"pwn ELF web API javascript webpack APK PCAP memory dump firmware AWS Active Directory malware crypto prompt injection",
				"--workers",
				"12",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			plan: {
				routeCandidates: Array<{
					id: string;
					proofKit: { passive: string[]; proofExit: string[]; negativeControls: string[] };
					commandPalette: { passive: string[]; proof: string[]; negative: string[] };
					toolProbeCommand: string;
					techniqueHints: {
						domains: string[];
						techniqueIds: string[];
						proofContracts: Array<{
							id: string;
							requiredGates: string[];
							negativeGates: string[];
							source: string;
						}>;
					};
					agentToolchain: { enabledTools: string[]; routeTools: string[] };
				}>;
				workerPackets: Array<{
					route: { id: string };
					proofKit: { passive: string[]; proofExit: string[]; negativeControls: string[] };
					commandPalette: { passive: string[]; proof: string[]; negative: string[] };
					toolProbeCommand: string;
					techniqueHints: {
						domains: string[];
						techniqueIds: string[];
						proofContracts: Array<{
							id: string;
							requiredGates: string[];
							negativeGates: string[];
							source: string;
						}>;
					};
					agentToolchain: { enabledTools: string[]; routeTools: string[] };
				}>;
			};
		};
		const routeIds = report.plan.routeCandidates.map((route) => route.id);
		expect(routeIds).toEqual(
			expect.arrayContaining([
				"native-pwn",
				"web-api",
				"js-reverse",
				"mobile",
				"pcap-dfir",
				"memory-forensics",
				"firmware-iot",
				"cloud-identity",
				"windows-ad",
				"malware",
				"crypto-stego",
				"agent-boundary",
			]),
		);
		for (const route of report.plan.routeCandidates) {
			expect(route.proofKit.passive.length, `${route.id} passive`).toBeGreaterThan(0);
			expect(route.proofKit.proofExit.length, `${route.id} proofExit`).toBeGreaterThan(0);
			expect(route.proofKit.negativeControls.length, `${route.id} negativeControls`).toBeGreaterThan(0);
			expect(route.commandPalette.passive.length, `${route.id} passive commands`).toBeGreaterThan(0);
			expect(route.commandPalette.proof.length, `${route.id} proof commands`).toBeGreaterThan(0);
			expect(route.commandPalette.negative.length, `${route.id} negative commands`).toBeGreaterThan(0);
			expect(route.toolProbeCommand, `${route.id} tool probe`).toContain("command -v");
			expect(route.techniqueHints.domains.length, `${route.id} technique domains`).toBeGreaterThan(0);
			expect(route.techniqueHints.techniqueIds.length, `${route.id} technique ids`).toBeGreaterThan(0);
			expect(
				route.techniqueHints.proofContracts.map((contract) => contract.id),
				`${route.id} proof contract ids`,
			).toEqual(route.techniqueHints.techniqueIds);
			for (const contract of route.techniqueHints.proofContracts) {
				expect(contract.source, `${route.id} ${contract.id} local contract`).toBe("swarm-local-contract");
				expect(contract.requiredGates.length, `${route.id} ${contract.id} required gates`).toBeGreaterThan(0);
				expect(contract.negativeGates.length, `${route.id} ${contract.id} negative gates`).toBeGreaterThan(0);
			}
			expect(route.agentToolchain.enabledTools, `${route.id} enabled agent tools`).toEqual(
				expect.arrayContaining(["re_route", "re_techniques", "re_verifier"]),
			);
			expect(route.agentToolchain.routeTools.length, `${route.id} route agent tools`).toBeGreaterThan(0);
		}
		for (const packet of report.plan.workerPackets) {
			expect(packet.commandPalette.passive.length, `${packet.route.id} worker passive commands`).toBeGreaterThan(0);
			expect(packet.commandPalette.proof.length, `${packet.route.id} worker proof commands`).toBeGreaterThan(0);
			expect(packet.commandPalette.negative.length, `${packet.route.id} worker negative commands`).toBeGreaterThan(
				0,
			);
			expect(packet.toolProbeCommand, `${packet.route.id} worker tool probe`).toContain("tool:");
			expect(packet.techniqueHints.domains.length, `${packet.route.id} worker technique domains`).toBeGreaterThan(0);
			expect(packet.techniqueHints.techniqueIds.length, `${packet.route.id} worker technique ids`).toBeGreaterThan(
				0,
			);
			expect(
				packet.techniqueHints.proofContracts.map((contract) => contract.id),
				`${packet.route.id} worker proof contract ids`,
			).toEqual(packet.techniqueHints.techniqueIds);
			expect(
				packet.techniqueHints.proofContracts.every(
					(contract) =>
						contract.source === "swarm-local-contract" &&
						contract.requiredGates.length > 0 &&
						contract.negativeGates.length > 0,
				),
				`${packet.route.id} worker local proof contracts`,
			).toBe(true);
			expect(packet.agentToolchain.enabledTools, `${packet.route.id} worker enabled agent tools`).toContain(
				"re_techniques",
			);
			expect(packet.agentToolchain.routeTools.length, `${packet.route.id} worker route tools`).toBeGreaterThan(0);
		}
		expect(new Set(report.plan.workerPackets.map((packet) => packet.route.id)).size).toBeGreaterThanOrEqual(10);
	});

	it("redacts secret-like swarm targets from plan packets and prompts", () => {
		const jwt = "eyJaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc";
		const result = spawnSync(
			process.execPath,
			[SWARM, fakeRoot, "plan", `--target=${jwt}`, "--workers", "1", "--json"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const serialized = JSON.stringify(JSON.parse(result.stdout));
		expect(serialized).not.toContain(jwt);
		expect(serialized).toContain("<redacted:jwt>");
	});

	it("reports worker profile preparation failures as structured worker failures", () => {
		mkdirSync(join(agentDir, "models.json"));

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"llm-run",
				"local-selfcheck",
				"--workers",
				"1",
				"--max-concurrency",
				"1",
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);

		expect(result.status).toBe(1);
		expect(result.stderr).not.toContain("Error:");
		const report = JSON.parse(result.stdout) as {
			ok: boolean;
			workersReport: Array<{ status: string; stderrTail: string }>;
		};
		expect(report.ok).toBe(false);
		expect(report.workersReport).toHaveLength(1);
		expect(report.workersReport[0].status).toBe("fail");
		expect(report.workersReport[0].stderrTail).toMatch(/EISDIR|illegal operation on a directory/i);
	});
});
