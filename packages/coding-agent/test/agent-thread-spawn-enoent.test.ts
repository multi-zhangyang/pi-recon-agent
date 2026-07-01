/**
 * opt #228 — a spawn-ENOENT 'error' (which fires BEFORE 'close') must NOT
 * resolve awaitRun early with a partial manifest.
 *
 * Pre-fix, child.on("error") unconditionally wrote status:"failed" AND called
 * resolveRun(runId) the instant 'error' fired. On a spawn failure (ENOENT),
 * Node fires 'error' THEN 'close'. The early resolveRun snapshotted the
 * manifest BEFORE 'close' wrote exitCode/signal/stdoutSha256/stderrSha256, so
 * awaitRun callers got status:"failed" but exitCode:undefined,
 * stdoutSha256:undefined — a partial manifest for a failed run.
 *
 * Post-fix, the 'error' handler only records the failure while the run is still
 * pending (runResolvers still has the runId) and lets 'close's finally resolve
 * the promise with the FULL manifest (exitCode + sha256 of the empty streams).
 */
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createAgentThreadManager } from "../src/core/agent-thread-manager.ts";

describe("opt #228: spawn ENOENT resolves awaitRun with the FULL manifest", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("a spawn-ENOENT 'error' (before 'close') does not resolve awaitRun early with a partial manifest", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-agent-thread-"));
		const workspace = join(tempRoot, "workspace");
		mkdirSync(workspace);
		const manager = createAgentThreadManager({
			cwd: workspace,
			agentDir: join(tempRoot, "agent"),
			// Non-existent explicit bin path: resolveRepiBin passes it through
			// unchanged → spawn hits ENOENT → 'error' fires before 'close'.
			repiBinPath: join(tempRoot, "does-not-exist-repi-bin"),
		});
		const manifest = await manager.spawnThread({ specName: "verifier", task: "x", timeoutMs: 5000 });
		const resolved = await manager.awaitRun(manifest.runId);

		// The run is failed (ENOENT), but 'close' finalized the manifest.
		expect(resolved.status).toBe("failed");
		// exitCode is set by 'close' (on Linux, the libuv ENOENT errno -2). The
		// invariant is it is NOT undefined — the pre-fix early resolve left it
		// undefined because 'close' never wrote before the snapshot.
		expect(resolved.exitCode).not.toBe(undefined);
		expect(typeof resolved.exitCode).toBe("number");
		// sha256 of the (empty) captured streams — 64 hex chars. Pre-fix these were
		// undefined because 'close' never got to write them before the snapshot.
		expect(resolved.stdoutSha256).toMatch(/^[0-9a-f]{64}$/);
		expect(resolved.stderrSha256).toMatch(/^[0-9a-f]{64}$/);
	});
});
