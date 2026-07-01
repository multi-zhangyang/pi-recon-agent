import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

let tempDir: string;
let agentDir: string;
let prevAgentDir: string | undefined;

beforeEach(() => {
	tempDir = join(tmpdir(), `repi-opt99-thread-${Date.now()}-${Math.random().toString(36).slice(2)}`);
	agentDir = join(tempDir, "agent");
	mkdirSync(agentDir, { recursive: true });
	prevAgentDir = process.env[ENV_AGENT_DIR];
	process.env[ENV_AGENT_DIR] = agentDir;
});

afterEach(() => {
	if (prevAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
	else process.env[ENV_AGENT_DIR] = prevAgentDir;
	vi.restoreAllMocks();
	rmSync(tempDir, { recursive: true, force: true });
});

describe("opt #99 threading dedup — sub-builder param reuse", () => {
	it("PERF-1: buildMemoryDepositionReport reuses a passed store verdict (no re-verify)", async () => {
		const storeMod = await import("../../src/core/repi/memory-store.ts");
		const depositionMod = await import("../../src/core/repi/memory-deposition.ts");
		const store = storeMod.verifyMemoryStore();
		// Spy AFTER building the store so we can detect if deposition re-calls verifyMemoryStore
		const spy = vi.spyOn(storeMod, "verifyMemoryStore");
		const report = depositionMod.buildMemoryDepositionReport({ write: false, store });
		expect(report.storeGrade).toBe(store.storeGrade);
		// verifyMemoryStore should NOT be called when store is passed
		expect(spy).not.toHaveBeenCalled();
	});

	it("PERF-1: superviseMemoryLifecycle reuses a passed store verdict", async () => {
		const storeMod = await import("../../src/core/repi/memory-store.ts");
		const supervisorMod = await import("../../src/core/repi/memory-supervisor.ts");
		const store = storeMod.verifyMemoryStore();
		const spy = vi.spyOn(storeMod, "verifyMemoryStore");
		const report = supervisorMod.superviseMemoryLifecycle({ store });
		expect(report.storeGrade).toBe(store.storeGrade);
		expect(spy).not.toHaveBeenCalled();
	});

	it("PERF-4: buildMemoryDistillPromotionReport reuses passed skill + experience (identical output)", async () => {
		const skillMod = await import("../../src/core/repi/memory-skill.ts");
		const expMod = await import("../../src/core/repi/memory-experience.ts");
		const distillMod = await import("../../src/core/repi/memory-distill.ts");
		const skill = skillMod.buildMemorySkillCapsuleReport({ write: false });
		const experience = expMod.buildMemoryExperienceReport({ write: false });
		// Build with pre-built reports
		const withParams = distillMod.buildMemoryDistillPromotionReport({
			write: false,
			skill,
			experience,
		});
		// Build without (internal builds)
		const withoutParams = distillMod.buildMemoryDistillPromotionReport({ write: false });
		// The candidate count and status should match (same inputs → same output)
		expect(withParams.candidateCount).toBe(withoutParams.candidateCount);
		expect(withParams.status).toBe(withoutParams.status);
	});

	it("PERF-4: buildMemorySkillCapsuleReport reuses a passed experience report", async () => {
		const skillMod = await import("../../src/core/repi/memory-skill.ts");
		const expMod = await import("../../src/core/repi/memory-experience.ts");
		const experience = expMod.buildMemoryExperienceReport({ write: false });
		// Spy on buildMemoryExperienceReport AFTER building the experience
		const spy = vi.spyOn(expMod, "buildMemoryExperienceReport");
		const report = skillMod.buildMemorySkillCapsuleReport({ write: false, experience });
		expect(report.capsuleCount).toBe(experience.lessonCount > 0 ? report.capsuleCount : 0);
		// buildMemoryExperienceReport should NOT be called when experience is passed
		expect(spy).not.toHaveBeenCalled();
	});

	it("PERF-9: replay evaluator memoizes searchMemoryEvents (fewer calls than scenarios)", async () => {
		const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");
		// Seed events with IDENTICAL route/lessons/commands so memoryUsefulnessQueryForEvent
		// produces the same query for each → the default scenarios share the same
		// (query, route, target, limit) memo key → the memo collapses them to 1 searchMemoryEvents call.
		// Include a failure event on a different route to make forbiddenEventIds non-empty (limit=8).
		appendMemoryEventTransaction({
			source: "manual",
			task: "failure event different route",
			route: "web",
			outcome: "failure",
			lessons: ["failed web scan"],
			commands: ["nikto -h http://10.0.0.1"],
		});
		for (let i = 0; i < 4; i++) {
			appendMemoryEventTransaction({
				source: "manual",
				task: `replay memo test ${i}`,
				route: "pentest",
				outcome: "success",
				lessons: ["use nmap for port scan"],
				commands: ["nmap -sV 10.0.0.1"],
			});
		}
		const recallMod = await import("../../src/core/repi/memory-recall.ts");
		const replayMod = await import("../../src/core/repi/memory-replay.ts");
		const spy = vi.spyOn(recallMod, "searchMemoryEvents");
		const report = replayMod.buildMemoryReplayEvaluatorReport({
			write: false,
			route: "pentest",
			target: "10.0.0.1",
		});
		const callCount = spy.mock.calls.length;
		// The memo should call searchMemoryEvents strictly FEWER times than the scenario count
		// (all 4 default scenarios share the same query → 1 call instead of 4).
		expect(report.scenarioCount).toBeGreaterThan(0);
		expect(callCount).toBeLessThan(report.scenarioCount);
	});

	it("PERF-5: searchMemoryEvents reuses a passed vectorReport (no re-search)", async () => {
		const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");
		appendMemoryEventTransaction({
			source: "manual",
			task: "vector reuse test",
			route: "pentest",
			outcome: "success",
			lessons: ["use nmap"],
			commands: ["nmap 10.0.0.1"],
		});
		const recallMod = await import("../../src/core/repi/memory-recall.ts");
		const vectorMod = await import("../../src/core/repi/memory-vector.ts");
		// Build the vector report once
		const vectorReport = vectorMod.searchMemoryVectors("nmap", { route: "pentest", limit: 8 });
		// Spy on searchMemoryVectors AFTER building the report
		const spy = vi.spyOn(vectorMod, "searchMemoryVectors");
		// searchMemoryEvents with vectorReport should NOT call searchMemoryVectors
		const hits = recallMod.searchMemoryEvents("nmap", { route: "pentest", limit: 8, vectorReport });
		expect(hits.length).toBeGreaterThan(0);
		expect(spy).not.toHaveBeenCalled();
	});

	it("PERF-3: buildMemorySemanticIndex reuses a passed scope report (no rebuild)", async () => {
		const scopeMod = await import("../../src/core/repi/memory-scope.ts");
		const distillationMod = await import("../../src/core/repi/memory-distillation.ts");
		const scope = scopeMod.buildMemoryScopeIsolationReport({ write: false });
		const spy = vi.spyOn(scopeMod, "buildMemoryScopeIsolationReport");
		// buildMemorySemanticIndex with scope should NOT call buildMemoryScopeIsolationReport
		distillationMod.buildMemorySemanticIndex({ maxEntries: 4, scope });
		expect(spy).not.toHaveBeenCalled();
	});

	it("PERF-3: buildMemoryQualityLedgerReport reuses a passed scope report (no rebuild)", async () => {
		const scopeMod = await import("../../src/core/repi/memory-scope.ts");
		const qualityMod = await import("../../src/core/repi/memory-quality.ts");
		const scope = scopeMod.buildMemoryScopeIsolationReport({ write: false });
		const spy = vi.spyOn(scopeMod, "buildMemoryScopeIsolationReport");
		qualityMod.buildMemoryQualityLedgerReport({ write: false, scope });
		expect(spy).not.toHaveBeenCalled();
	});
});
