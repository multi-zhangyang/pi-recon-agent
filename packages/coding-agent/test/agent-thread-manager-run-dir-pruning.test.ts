/**
 * opt #255 — AgentThreadManager run-dirs were never pruned (LEAK HIGH).
 *
 * spawnThread creates a fresh `<root>/<runId>/` dir per run (stdout.txt,
 * stderr.txt, manifest.json, agent-home/) and nothing ever removed them — every
 * re_subagent/reasoning/challenge run leaked a dir forever, growing disk
 * unbounded and slowing listRuns (readdirSync + JSON.parse per run). After a
 * run finalizes the close handler now calls pruneRunsIfNeeded(), keeping the
 * most-recent REPI_AGENT_THREAD_MAX_RUN_DIRS (default 50, 0=disable) completed
 * run-dirs by mtime and best-effort rmSync'ing the rest. In-flight runs are
 * never pruned.
 */
import { existsSync, mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AgentThreadManager } from "../src/core/agent-thread-manager.ts";

describe("AgentThreadManager run-dir pruning (opt #255)", () => {
	let tempRoot: string;
	let manager: AgentThreadManager;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "pi-thread-prune-"));
		// Small cap so the test only needs a handful of dirs.
		process.env.REPI_AGENT_THREAD_MAX_RUN_DIRS = "3";
		manager = new AgentThreadManager({ cwd: tempRoot, agentDir: tempRoot });
	});

	afterEach(() => {
		delete process.env.REPI_AGENT_THREAD_MAX_RUN_DIRS;
		if (tempRoot && existsSync(tempRoot)) rmSync(tempRoot, { recursive: true, force: true });
	});

	it("keeps the most-recent N completed run-dirs by mtime and removes the rest", () => {
		const root = manager.root;
		mkdirSync(root, { recursive: true });
		// 6 completed run-dirs, mtimes increasing: run-0 oldest … run-5 newest.
		const baseTime = 1_700_000_000;
		for (let i = 0; i < 6; i++) {
			const dir = join(root, `run-${i}`);
			mkdirSync(dir, { recursive: true });
			writeFileSync(join(dir, "manifest.json"), JSON.stringify({ runId: `run-${i}`, createdAt: "" }));
			utimesSync(dir, baseTime + i, baseTime + i);
		}
		expect(existsSync(join(root, "run-0"))).toBe(true);

		(manager as unknown as { pruneRunsIfNeeded: () => void }).pruneRunsIfNeeded();

		// Newest 3 (run-3, run-4, run-5) survive; oldest 3 pruned.
		expect(existsSync(join(root, "run-0"))).toBe(false);
		expect(existsSync(join(root, "run-1"))).toBe(false);
		expect(existsSync(join(root, "run-2"))).toBe(false);
		expect(existsSync(join(root, "run-3"))).toBe(true);
		expect(existsSync(join(root, "run-4"))).toBe(true);
		expect(existsSync(join(root, "run-5"))).toBe(true);
	});

	it("does not prune when REPI_AGENT_THREAD_MAX_RUN_DIRS=0 (disabled)", () => {
		process.env.REPI_AGENT_THREAD_MAX_RUN_DIRS = "0";
		const root = manager.root;
		mkdirSync(root, { recursive: true });
		for (let i = 0; i < 6; i++) {
			const dir = join(root, `run-${i}`);
			mkdirSync(dir, { recursive: true });
			writeFileSync(join(dir, "manifest.json"), "{}");
		}

		(manager as unknown as { pruneRunsIfNeeded: () => void }).pruneRunsIfNeeded();

		// All 6 remain — 0 disables pruning entirely.
		for (let i = 0; i < 6; i++) {
			expect(existsSync(join(root, `run-${i}`))).toBe(true);
		}
	});

	it("does not prune in-flight run-dirs (still in this.children)", () => {
		const root = manager.root;
		mkdirSync(root, { recursive: true });
		const baseTime = 1_700_000_000;
		for (let i = 0; i < 6; i++) {
			const dir = join(root, `run-${i}`);
			mkdirSync(dir, { recursive: true });
			writeFileSync(join(dir, "manifest.json"), JSON.stringify({ runId: `run-${i}` }));
			utimesSync(dir, baseTime + i, baseTime + i);
		}
		// Pretend run-0 (the OLDEST, normally first to be pruned) is in-flight.
		// this.children is Map<runId, ChildProcess>; a truthy placeholder stands in.
		const children = (manager as unknown as { children: Map<string, unknown> }).children;
		children.set("run-0", {} as unknown);

		(manager as unknown as { pruneRunsIfNeeded: () => void }).pruneRunsIfNeeded();

		// run-0 is preserved despite being oldest (in-flight exclusion); the
		// next-oldest (run-1) is pruned instead.
		expect(existsSync(join(root, "run-0"))).toBe(true);
		expect(existsSync(join(root, "run-1"))).toBe(false);
		expect(existsSync(join(root, "run-5"))).toBe(true);
	});
});
