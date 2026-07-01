import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { NodeExecutionEnv } from "../../src/harness/env/nodejs.ts";

// opt #154: NodeExecutionEnv tracked its temp dirs in a MODULE-level
// `createdTempDirs` Set shared across ALL env instances. `cleanup()` iterated
// and cleared that shared set → one env's cleanup would `rm` ANOTHER live env's
// temp dir out from under it (and drop it from the exit-reap set). That made
// `cleanup()` unsafe to call while any other env was active — which is why no
// runtime caller wired it, so dirs accumulated across env instances until
// process exit. Fix: per-instance `instanceTempDirs` Set; `cleanup()` iterates
// only this env's dirs (and drops them from the shared exit safety-net set).
// The module-level set stays as the process-exit reaper for envs never cleaned.
//
// This is the agent-package harness surface (external consumers / harness
// services construct one env per session/skill-run); the coding-agent runtime
// uses exec.ts directly, so the leak is latent for agent-package consumers.

describe("NodeExecutionEnv.cleanup isolates per-instance temp dirs (opt #154)", () => {
	let workdir: string;

	beforeEach(() => {
		workdir = mkdtempSync(join(tmpdir(), "repi-env-iso-154-"));
	});
	afterEach(() => {
		rmSync(workdir, { recursive: true, force: true });
	});

	it("env A's cleanup does NOT remove env B's temp dir", async () => {
		const envA = new NodeExecutionEnv({ cwd: workdir });
		const envB = new NodeExecutionEnv({ cwd: workdir });

		const dirA = await envA.createTempDir("repi-iso-a-");
		const dirB = await envB.createTempDir("repi-iso-b-");
		expect(dirA.ok).toBe(true);
		expect(dirB.ok).toBe(true);
		if (!dirA.ok || !dirB.ok) return; // narrow for TS

		expect(existsSync(dirA.value)).toBe(true);
		expect(existsSync(dirB.value)).toBe(true);

		await envA.cleanup();

		// A's dir reaped by A's cleanup; B's dir untouched (B is still live).
		expect(existsSync(dirA.value)).toBe(false);
		expect(existsSync(dirB.value)).toBe(true);

		// B's own cleanup then reaps B's dir — proving B still owns it.
		await envB.cleanup();
		expect(existsSync(dirB.value)).toBe(false);
	});

	it("cleanup is idempotent and safe when no temp dirs were created", async () => {
		const env = new NodeExecutionEnv({ cwd: workdir });
		// No temp dirs created — cleanup must not throw and must resolve.
		await expect(env.cleanup()).resolves.toBeUndefined();
	});
});
