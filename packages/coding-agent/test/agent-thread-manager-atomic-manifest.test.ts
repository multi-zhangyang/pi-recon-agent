import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createAgentThreadManager } from "../src/core/agent-thread-manager.ts";
import { atomicWriteFileSync } from "../src/core/tools/atomic-write.ts";

async function sleep(ms: number): Promise<void> {
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

describe("atomicWriteFileSync", () => {
	let tempDir: string;

	it("replaces the file atomically: inode changes, no temp leftover, content complete, mode preserved", () => {
		tempDir = mkdtempSync(join(tmpdir(), "atomic-sync-"));
		const target = join(tempDir, "manifest.json");
		atomicWriteFileSync(target, `{"status":"running"}\n`);
		const inodeBefore = statSync(target).ino;
		const modeBefore = statSync(target).mode & 0o777;

		// A re-write must REPLACE the inode (temp+rename). The old truncate-then-
		// write (writeFileSync) kept the SAME inode — that's the distinguishing
		// assertion (both produce a complete, parseable, mode-preserved file).
		atomicWriteFileSync(target, `{"status":"complete","endedAt":"2026-06-28T00:00:00Z"}\n`);
		const inodeAfter = statSync(target).ino;
		expect(inodeAfter).not.toBe(inodeBefore);

		// No temp file left behind in the target's directory.
		const leftovers = readdirSync(dirname(target)).filter((f) => f.endsWith(".tmp"));
		expect(leftovers).toEqual([]);

		// Content complete + parseable (not truncated).
		const parsed = JSON.parse(readFileSync(target, "utf8"));
		expect(parsed.status).toBe("complete");
		expect(parsed.endedAt).toBe("2026-06-28T00:00:00Z");

		// Mode preserved across the atomic replace.
		expect(statSync(target).mode & 0o777).toBe(modeBefore);
	});

	it("creates a new file with mode 0o600 by default", () => {
		tempDir = mkdtempSync(join(tmpdir(), "atomic-sync-mode-"));
		const target = join(tempDir, "fresh.json");
		atomicWriteFileSync(target, `{"x":1}\n`);
		expect(statSync(target).mode & 0o777).toBe(0o600);
	});

	it("preserves a non-default existing mode (0o644) across rewrites", () => {
		tempDir = mkdtempSync(join(tmpdir(), "atomic-sync-mode-preserve-"));
		const target = join(tempDir, "custom.json");
		atomicWriteFileSync(target, `{"a":1}\n`);
		chmodSync(target, 0o644);
		atomicWriteFileSync(target, `{"a":2}\n`);
		expect(statSync(target).mode & 0o777).toBe(0o644);
		expect(JSON.parse(readFileSync(target, "utf8")).a).toBe(2);
	});

	afterEach(() => {
		if (tempDir) rmSync(tempDir, { recursive: true, force: true });
		tempDir = undefined as unknown as string;
	});
});

describe("AgentThreadManager manifest atomicity", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("writes the run manifest atomically (0o600, no .tmp leftover, status correct across updates)", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-agent-thread-atomic-"));
		const workspace = join(tempRoot, "workspace");
		mkdirSync(workspace);
		const fakeRepi = join(tempRoot, "fake-repi.sh");
		writeFileSync(fakeRepi, "#!/usr/bin/env bash\nprintf 'worker ok\\n'\n", "utf8");
		chmodSync(fakeRepi, 0o700);

		const manager = createAgentThreadManager({
			cwd: workspace,
			agentDir: join(tempRoot, "agent"),
			repiBinPath: fakeRepi,
		});
		const manifest = await manager.spawnThread({ specName: "verifier", task: "verify", timeoutMs: 5000 });
		const manifestPath = join(manifest.runRoot, "manifest.json");

		// The manifest is created by writeJson → atomicWriteFileSync: 0o600.
		expect(existsSync(manifestPath)).toBe(true);
		expect(statSync(manifestPath).mode & 0o777).toBe(0o600);

		await waitFor(() => manager.getRun(manifest.runId)?.status === "complete");

		// After the close handler's updateManifest rewrites it (read-modify-write
		// via writeJson → atomicWriteFileSync): mode still 0o600, no stray temp,
		// and the manifest is complete + parseable with the final status.
		expect(statSync(manifestPath).mode & 0o777).toBe(0o600);
		const leftovers = readdirSync(manifest.runRoot).filter((f) => f.endsWith(".tmp"));
		expect(leftovers).toEqual([]);
		const parsed = JSON.parse(readFileSync(manifestPath, "utf8"));
		expect(parsed.status).toBe("complete");
		expect(parsed.runId).toBe(manifest.runId);
	});

	it("records worker budgets and recovers partial stdout/stderr into merge when timeout loses handoff", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-agent-thread-timeout-recover-"));
		const workspace = join(tempRoot, "workspace");
		mkdirSync(workspace);
		const fakeRepi = join(tempRoot, "fake-repi.sh");
		writeFileSync(
			fakeRepi,
			[
				"#!/usr/bin/env bash",
				"printf 'partial stdout before timeout max_turns=%s\\n' \"$REPI_PRINT_MAX_TURNS\"",
				"printf 'partial stderr before timeout\\n' >&2",
				"sleep 30",
			].join("\n"),
			"utf8",
		);
		chmodSync(fakeRepi, 0o700);

		const manager = createAgentThreadManager({
			cwd: workspace,
			agentDir: join(tempRoot, "agent"),
			repiBinPath: fakeRepi,
		});
		const manifest = await manager.spawnThread({
			specName: "verifier",
			task: "verify timeout recovery",
			timeoutMs: 1000,
		});
		const final = await manager.awaitRun(manifest.runId);
		expect(final.status).toBe("timeout");
		expect(final.timeoutMs).toBe(1000);
		expect(final.maxTurns).toBeGreaterThan(0);
		expect(final.cancelSignal).toBe("SIGTERM");
		expect(final.cancelledAt).toBeDefined();
		expect(final.handoffPresent).toBe(false);

		const merge = manager.mergeRun(manifest.runId);
		expect(merge?.text).toContain("handoff_present: false");
		expect(merge?.text).toContain("handoff_recovered: true");
		expect(merge?.text).toContain("Outcome: worker ended without writing handoff.md");
		expect(merge?.text).toContain("partial stdout before timeout max_turns=");
		expect(merge?.text).toContain("partial stderr before timeout");
		const mergedManifest = manager.getRun(manifest.runId);
		expect(mergedManifest?.handoffRecovered).toBe(true);
		expect(mergedManifest?.mergePath).toBeDefined();
	});

	it("close handler resolves the run (does not reject/hang) when getRun throws mid-finalize", async () => {
		// The child "close" handler is an async EventEmitter callback: the emitter
		// drops its returned promise, so a rejection becomes an unhandledRejection
		// (process crash) AND resolveRun never runs → awaitRun hangs forever. The
		// one real throw source in the handler is the getRun consult for the
		// timeout-status override: getRun → listRuns → .sort((a,b) =>
		// b.createdAt.localeCompare(a.createdAt)); a manifest that parses but is
		// MISSING createdAt makes .sort throw `undefined.localeCompare`. Corrupt the
		// manifest to that shape mid-run and assert awaitRun still resolves.
		tempRoot = mkdtempSync(join(tmpdir(), "repi-agent-thread-closeguard-"));
		const workspace = join(tempRoot, "workspace");
		mkdirSync(workspace);
		// Sleep so the manifest can be corrupted before the child exits and "close"
		// fires (otherwise the race is non-deterministic).
		const fakeRepi = join(tempRoot, "fake-repi.sh");
		writeFileSync(fakeRepi, "#!/usr/bin/env bash\nsleep 0.3\nexit 0\n", "utf8");
		chmodSync(fakeRepi, 0o700);

		const manager = createAgentThreadManager({
			cwd: workspace,
			agentDir: join(tempRoot, "agent"),
			repiBinPath: fakeRepi,
		});
		const manifest = await manager.spawnThread({ specName: "verifier", task: "verify", timeoutMs: 5000 });
		const manifestPath = join(manifest.runRoot, "manifest.json");

		// Force listRuns' .sort to throw: it needs ≥2 entries (spec: arrays of
		// length ≤1 never invoke the comparator), AND both must lack createdAt so
		// that whichever is `b` in (a,b) => b.createdAt.localeCompare(a.createdAt)
		// hits `undefined.localeCompare` regardless of argument order. Pre-create a
		// sibling run dir with a createdAt-less manifest, and corrupt the active
		// run's manifest to also lack createdAt.
		const siblingRoot = join(dirname(manifest.runRoot), "zz-sibling-no-created");
		mkdirSync(siblingRoot, { recursive: true });
		writeFileSync(join(siblingRoot, "manifest.json"), JSON.stringify({ runId: "sibling", status: "failed" }), "utf8");
		writeFileSync(manifestPath, JSON.stringify({ runId: manifest.runId, status: "timeout" }), "utf8");

		// Race awaitRun against a hang. Pre-fix: getRun throws in the async close
		// handler → it rejects → resolveRun never called → awaitRun never settles →
		// the sleep(3000) branch rejects this test (or the unhandledRejection fails
		// the run first). Post-fix: the getRun consult is guarded, finalize proceeds,
		// and resolveRun unblocks the caller.
		const result = await Promise.race([
			manager.awaitRun(manifest.runId),
			sleep(3000).then(() => {
				throw new Error("awaitRun hung — close handler did not resolve the run");
			}),
		]);
		expect(result.runId).toBe(manifest.runId);
	});

	it("dispose() kills in-flight children, marks manifests stopped, unblocks awaitRun, and detaches the exit hook", async () => {
		// Without dispose() + the exit hook, a parent exit while a re_subagent/
		// reasoning/challenge run is in flight reparents the child to init (PID 1)
		// and it keeps running a full print-mode agent — continuing to make LLM API
		// calls (cost/quota leak) for up to REPI_PRINT_TIMEOUT_MS after the user
		// quit. dispose() must SIGKILL in-flight children, record status=stopped,
		// unblock any awaitRun caller, and detach the process exit hook so per-call
		// managers don't accumulate listeners.
		tempRoot = mkdtempSync(join(tmpdir(), "repi-agent-thread-dispose-"));
		const workspace = join(tempRoot, "workspace");
		mkdirSync(workspace);
		// `exec sleep 30` replaces the shell with sleep, so manifest.pid is the
		// killable leaf process (not a bash wrapper that would orphan a sleep
		// grandchild). Long sleep = a child that stays in flight until dispose()
		// kills it.
		const fakeRepi = join(tempRoot, "fake-repi.sh");
		writeFileSync(fakeRepi, "#!/usr/bin/env bash\nexec sleep 30\n", "utf8");
		chmodSync(fakeRepi, 0o700);

		const exitBaseline = process.listenerCount("exit");
		const manager = createAgentThreadManager({
			cwd: workspace,
			agentDir: join(tempRoot, "agent"),
			repiBinPath: fakeRepi,
		});
		const manifest = await manager.spawnThread({ specName: "verifier", task: "verify", timeoutMs: 60000 });

		// Child is in flight: manifest running, and the exit-reap hook is installed
		// (one more process "exit" listener than baseline).
		await waitFor(() => manager.getRun(manifest.runId)?.status === "running");
		expect(process.listenerCount("exit")).toBe(exitBaseline + 1);
		// The child process is alive (signal-0 probe does not throw).
		expect(manifest.pid).toBeGreaterThan(0);
		expect(() => process.kill(manifest.pid!, 0)).not.toThrow();

		// Capture the awaitRun promise BEFORE dispose: dispose() resolves all
		// pending resolvers (deleting them from the run-promises map), so a later
		// awaitRun would see "Unknown agent thread run".
		const runPromise = manager.awaitRun(manifest.runId);

		manager.dispose("test");

		// awaitRun must resolve (not hang) — dispose resolves all pending resolvers.
		const result = await Promise.race([
			runPromise,
			sleep(3000).then(() => {
				throw new Error("awaitRun hung after dispose()");
			}),
		]);
		expect(result.runId).toBe(manifest.runId);

		// THE load-bearing assertion: dispose() actually SIGKILLed the in-flight
		// child. A signal-0 probe must now throw ESRCH (process gone). With the kill
		// neutered, the `sleep 30` stays alive and this waitFor times out → fail.
		await waitFor(() => {
			try {
				process.kill(manifest.pid!, 0);
				return false; // still alive
			} catch {
				return true; // gone (ESRCH) — killed
			}
		}, 3000);

		// dispose() recorded status=stopped; the late-firing "close" handler must
		// NOT overwrite it (the disposed guard skips the code-derived finalize).
		await waitFor(() => manager.getRun(manifest.runId)?.status === "stopped", 3000);
		expect(manager.getRun(manifest.runId)?.status).toBe("stopped");

		// The "close" handler fired (SIGKILL landed) and ran idle cleanup that
		// detaches the exit hook → back to baseline.
		await waitFor(() => process.listenerCount("exit") === exitBaseline, 3000);
		expect(process.listenerCount("exit")).toBe(exitBaseline);

		// Idempotent: a second dispose() is a no-op (no throw, hook stays detached).
		expect(() => manager.dispose("test2")).not.toThrow();
		expect(process.listenerCount("exit")).toBe(exitBaseline);
	});
});
