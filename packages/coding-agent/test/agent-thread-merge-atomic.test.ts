/**
 * opt #229 — mergeRun writes merge.md atomically (temp+rename), not
 * truncate-then-write, so a crash mid-write can't truncate the merge artifact
 * and lose the main-thread merge contract + distilled output tail.
 *
 * Regression pattern (same as opts #38/#41/#42/#43): a truncate-then-write
 * rewrites the file in place → the inode is unchanged across the rewrite. A
 * temp+rename atomic write replaces the directory entry → the inode changes.
 * Pre-create merge.md, snapshot its inode, call mergeRun, and assert the inode
 * changed (and the content is the new merge text, not the pre-existing stub).
 */
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createAgentThreadManager } from "../src/core/agent-thread-manager.ts";

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(predicate: () => boolean, timeoutMs = 5000): Promise<void> {
	const started = Date.now();
	while (Date.now() - started < timeoutMs) {
		if (predicate()) return;
		await sleep(50);
	}
	throw new Error("timeout waiting for predicate");
}

describe("opt #229: mergeRun writes merge.md atomically", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("merge.md is replaced (inode changes), not truncated in place", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-agent-thread-"));
		const workspace = join(tempRoot, "workspace");
		mkdirSync(workspace);
		const fakeRepi = join(tempRoot, "fake-repi.sh");
		writeFileSync(fakeRepi, "#!/usr/bin/env bash\nprintf 'worker output ok\\n'\n", "utf8");
		chmodSync(fakeRepi, 0o700);

		const manager = createAgentThreadManager({
			cwd: workspace,
			agentDir: join(tempRoot, "agent"),
			repiBinPath: fakeRepi,
		});
		const manifest = await manager.spawnThread({ specName: "verifier", task: "x", timeoutMs: 5000 });
		await waitFor(() => manager.getRun(manifest.runId)?.status === "complete");

		// Pre-create merge.md (a stale/torn artifact from a prior partial write)
		// and snapshot its inode. A truncate-then-write keeps this inode; a
		// temp+rename atomic write replaces it.
		const mergePath = join(manifest.runRoot, "merge.md");
		writeFileSync(mergePath, "STALE TORN CONTENT", { encoding: "utf8", mode: 0o600 });
		const inodeBefore = statSync(mergePath).ino;

		const merged = manager.mergeRun(manifest.runId);
		expect(merged).toBeDefined();

		const inodeAfter = statSync(mergePath).ino;
		// Inode changed → the file was replaced (temp+rename), not truncated in place.
		expect(inodeAfter).not.toBe(inodeBefore);
		// Content is the new merge artifact, not the stale stub.
		const content = readFileSync(mergePath, "utf8");
		expect(content).toContain("AgentThreadMergeV1: true");
		expect(content).not.toContain("STALE TORN CONTENT");
	});
});
