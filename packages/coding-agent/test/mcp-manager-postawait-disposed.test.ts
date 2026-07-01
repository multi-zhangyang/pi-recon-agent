/**
 * Foundational opt #250 — getPooledClient post-await `_disposed` re-check.
 *
 * closeAll() sets `_disposed` synchronously then SIGKILLs inflight children +
 * clears clientPool. If closeAll ran DURING `await createPromise`, a newly-
 * resolved client was neither in `_inflightChildPids` (its pid was removed in
 * the createPromise resolution handler before closeAll's reap reached it) NOR in
 * `clientPool` yet → closeAll missed it → the child leaked (detached+unref'd,
 * kept making LLM calls) AND a live client was returned to a caller whose
 * manager was already torn down. Fix: re-check `_disposed` after the await; if
 * true, close the orphan and reject non-retryably.
 *
 * Deterministic test: override `createInitializedClient` per-instance with a
 * controllable promise, kick off getPooledClient, run closeAll() while the
 * create is pending, then resolve the create. Post-fix: rejects /dispos/ and the
 * orphan client.close() was called. Pre-fix: returns the live client (leak) and
 * close is NOT called.
 */
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";

describe("McpManager getPooledClient post-await disposed re-check (opt #250)", () => {
	let tempRoot: string | undefined;
	let manager: ReturnType<typeof createMcpManager> | undefined;

	afterEach(async () => {
		if (manager) {
			await manager.closeAll();
			manager = undefined;
		}
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("closes the orphan and rejects when closeAll ran during the create await", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-postawait-"));
		const agentDir = join(tempRoot, "agent");
		mkdirSync(agentDir, { recursive: true });
		manager = createMcpManager({ cwd: tempRoot, agentDir });

		const closeSpy = vi.fn(() => undefined);
		const mockClient = { close: closeSpy, isClosed: false, childPid: undefined };
		const mockPooled = {
			key: `${tempRoot}:test-src:fake`,
			fingerprint: "fp-test",
			client: mockClient,
			init: {},
		};

		// Controllable create promise — simulates an initialize handshake that
		// resolves successfully, but only after we run closeAll() below.
		let resolveCreate!: (value: typeof mockPooled) => void;
		const createPromise = new Promise<typeof mockPooled>((resolve) => {
			resolveCreate = resolve;
		});
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(manager as any).createInitializedClient = vi.fn(() => createPromise);

		const entry = {
			id: "fake",
			sourcePath: "test-src",
			config: { transport: "stdio", command: "true" },
		};

		// Kick off getPooledClient (private). It awaits the create promise.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const pooledPromise = (manager as any).getPooledClient(entry, undefined, false);

		// Let microtasks settle so getPooledClient reaches `await createPromise`.
		await Promise.resolve();
		await Promise.resolve();

		// Run closeAll() WHILE the create is still pending → _disposed = true.
		await manager.closeAll();

		// Now the create resolves successfully (the race: pid already removed from
		// the inflight map before closeAll's reap, so the child survived closeAll).
		resolveCreate(mockPooled);

		// Post-fix: rejects /dispos/ and the orphan client was closed (no leak).
		await expect(pooledPromise).rejects.toThrow(/dispos/i);
		expect(closeSpy).toHaveBeenCalledTimes(1);
	});
});
