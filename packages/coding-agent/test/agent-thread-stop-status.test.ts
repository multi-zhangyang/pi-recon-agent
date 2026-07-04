import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createAgentThreadManager } from "../src/core/agent-thread-manager.ts";

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

describe("F1: stopRun 'stopped' status preserved by close handler", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("records 'stopped' (not 'failed') when a run is explicitly stopped", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-agent-thread-f1-"));
		const workspace = join(tempRoot, "workspace");
		mkdirSync(workspace);
		// A child that stays alive until killed: a bash `sleep 30` with a shebang
		// and exec bit (matches the proven harness pattern). SIGTERM'd bash exits
		// with exitCode null → without preserving "stopped" the close handler would
		// rewrite it to "failed".
		const wrapper = join(tempRoot, "wrapper.sh");
		writeFileSync(wrapper, "#!/usr/bin/env bash\nexec sleep 30\n", "utf8");
		chmodSync(wrapper, 0o700);

		const manager = createAgentThreadManager({
			cwd: workspace,
			agentDir: join(tempRoot, "agent"),
			repiBinPath: wrapper,
		});

		const manifest = await manager.spawnThread({
			specName: "verifier",
			task: "stay alive until stopped",
			timeoutMs: 30000,
		});
		expect(manifest.status).toBe("running");
		// Give the child a moment to boot so stopRun sees exitCode === null.
		await sleep(150);

		const stopped = manager.stopRun(manifest.runId);
		expect(stopped?.status).toBe("stopped");

		await manager.awaitRun(manifest.runId);
		const final = manager.getRun(manifest.runId);
		expect(final?.status).toBe("stopped");
		expect(final?.cancelledAt).toBeTruthy();
		expect(final?.cancelSignal).toBe("SIGTERM");
		expect(final?.error).toBe("stopped_by_user");
	});

	it("escalates stopped runs to SIGKILL when the worker ignores SIGTERM", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-agent-thread-stop-escalate-"));
		const workspace = join(tempRoot, "workspace");
		mkdirSync(workspace);
		const wrapper = join(tempRoot, "ignore-term.sh");
		writeFileSync(wrapper, "#!/usr/bin/env bash\ntrap '' TERM\nwhile true; do sleep 1; done\n", "utf8");
		chmodSync(wrapper, 0o700);
		const oldGrace = process.env.REPI_AGENT_THREAD_STOP_KILL_GRACE_MS;
		process.env.REPI_AGENT_THREAD_STOP_KILL_GRACE_MS = "100";
		try {
			const manager = createAgentThreadManager({
				cwd: workspace,
				agentDir: join(tempRoot, "agent"),
				repiBinPath: wrapper,
			});
			const manifest = await manager.spawnThread({
				specName: "verifier",
				task: "ignore sigterm until explicit stop escalation",
				timeoutMs: 30000,
			});
			await sleep(150);
			const stopped = manager.stopRun(manifest.runId);
			expect(stopped?.status).toBe("stopped");
			expect(stopped?.cancelledAt).toBeTruthy();
			const settled = await manager.awaitRun(manifest.runId);
			expect(settled.status).toBe("stopped");
			expect(settled.cancelSignal).toBe("SIGTERM");
			expect(settled.signal).toBe("SIGKILL");
			expect(settled.error).toBe("stopped_by_user");
		} finally {
			if (oldGrace === undefined) delete process.env.REPI_AGENT_THREAD_STOP_KILL_GRACE_MS;
			else process.env.REPI_AGENT_THREAD_STOP_KILL_GRACE_MS = oldGrace;
		}
	});
});
