import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseProofLoopArtifact, runtimeAdapterParserSummaryForGraph } from "../src/core/repi/graph-artifacts.ts";

describe("REPI graph artifact readers", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-graph-artifacts-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("parses proof-loop markdown artifacts without importing the full recon profile", () => {
		const path = join(tempDir, "proof.md");
		writeFileSync(
			path,
			[
				"# proof",
				"",
				"```json",
				JSON.stringify({
					mode: "plan",
					missionId: "m1",
					target: "https://target.local/app",
					maxSteps: 4,
					replaySteps: 2,
					verdict: "partial",
					steps: [
						{
							id: "runtime-adapter-1",
							phase: "runtime-adapter",
							command: "re_runtime_adapter run web-cdp-network-adapter https://target.local/app",
							status: "ready",
							reason: "source=target_auto_detection",
							sourceArtifacts: ["/tmp/a.json"],
						},
					],
					executed: [{ stepId: "runtime-adapter-1", command: "cmd", status: "blocked", output: "nonce missing" }],
					gapClassifier: ["priority=1 class=runtime_adapter_gap"],
					quickPath: ["re_graph build"],
					quickPlanPhases: ["phase=1:attack_graph_refresh commands=re_graph build"],
					quickPlanAssertions: ["bounded=pass"],
					nextActions: ["re_proof_loop run https://target.local/app 4 2"],
					sourceArtifacts: ["/tmp/proof.md"],
				}),
				"```",
			].join("\n"),
			"utf-8",
		);

		const parsed = parseProofLoopArtifact(path);
		expect(parsed?.mode).toBe("plan");
		expect(parsed?.steps[0]?.phase).toBe("runtime-adapter");
		expect(parsed?.executed[0]?.output).toBe("nonce missing");
		expect(parsed?.gapClassifier[0]).toContain("runtime_adapter_gap");
		expect(parsed?.quickPlanPhases[0]).toContain("attack_graph_refresh");
		expect(parsed?.quickPlanAssertions[0]).toBe("bounded=pass");
	});

	it("summarizes runtime-adapter parser matches and missing proof exits", () => {
		const summary = runtimeAdapterParserSummaryForGraph({
			kind: "RuntimeAdapterExecutionArtifactV1",
			schemaVersion: 1,
			adapterId: "web-cdp-network-adapter",
			domainId: "web-api",
			bridgeId: "web-cdp",
			startedAt: new Date(0).toISOString(),
			finishedAt: new Date(0).toISOString(),
			selectedRunner: "fallback",
			command: "re_runtime_adapter run web-cdp-network-adapter https://target.local/app",
			exitCode: 0,
			killed: false,
			stdoutSha256: "a".repeat(64),
			stderrSha256: "b".repeat(64),
			artifactKinds: ["runtime-adapter-transcript"],
			ingestTargets: ["evidence-ledger"],
			proofExitSignals: ["request order proof", "crypto request fields"],
			parserSignals: [
				{
					ruleId: "parser-request-order",
					evidenceRank: "network",
					proofExitSignal: "request order proof",
					matches: ["GET /api/orders"],
				},
				{
					ruleId: "parser-crypto-field",
					evidenceRank: "network",
					proofExitSignal: "crypto request fields",
					matches: [],
				},
			],
		});

		expect(summary.matchedRules).toBe(1);
		expect(summary.matchCount).toBe(1);
		expect(summary.matchedProofExitSignals).toEqual(["request order proof"]);
		expect(summary.missingProofExitSignals).toEqual(["crypto request fields"]);
	});
});
