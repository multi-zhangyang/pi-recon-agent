import { describe, expect, it } from "vitest";
import { NodeExecutionEnv } from "../../src/harness/env/nodejs.ts";
import { createTempDir } from "./session-test-utils.ts";

// Finding A: exec's close handler did `exitCode: code ?? 0`. When the child is terminated by an
// EXTERNAL signal (OOM killer, external kill), Node fires close with code===null and a non-null
// signal. None of the three early-return guards tripped (not our timeout/abort), so `?? 0`
// collapsed the signal death into exitCode:0 and reported a killed command as successful. The fix
// captures the signal and surfaces a spawn_error instead.

describe("NodeExecutionEnv.exec external-signal death", () => {
	it("reports an error when the child is killed by an external signal (not masked as exit 0)", async () => {
		const root = createTempDir();
		const env = new NodeExecutionEnv({ cwd: root });
		// `kill -KILL $$` sends SIGKILL to the shell process itself. The shell exits via signal
		// (code===null, signal==="SIGKILL"), NOT via our timeout/abort (no timeout is set, so the
		// timedOut/aborted guards don't trip). With the bug this resolves to ok({ exitCode: 0 });
		// with the fix it resolves to err(spawn_error).
		const result = await env.exec("kill -KILL $$");
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.code).toBe("spawn_error");
			expect(result.error.message).toContain("SIGKILL");
		}
	}, 15000);

	it("still reports exit 0 for a normal successful command (baseline preserved)", async () => {
		const root = createTempDir();
		const env = new NodeExecutionEnv({ cwd: root });
		const result = await env.exec("true");
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value.exitCode).toBe(0);
	}, 15000);

	it("still reports the non-zero exit code for a normal failing command (baseline preserved)", async () => {
		const root = createTempDir();
		const env = new NodeExecutionEnv({ cwd: root });
		const result = await env.exec("false");
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value.exitCode).not.toBe(0);
	}, 15000);
});
