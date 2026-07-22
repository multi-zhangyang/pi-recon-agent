import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";

// opt #127 — schedulePooledClientClose fire-and-forgets the pooled client close
// (both the pool===false path and the idle-timer path). A rejected close promise
// was dropped via `void` with no .catch → unhandled rejection → process crash
// (no global unhandledRejection handler). Fix: wrap both with .catch(()=>undefined)
// mirroring agent-session's closeAll guard. These tests force a rejection and
// assert NO unhandledRejection escapes.

describe("McpManager schedulePooledClientClose swallows close rejection (opt #127)", () => {
	let tempRoot: string | undefined;
	let unhandled: unknown[] = [];
	let handler: (reason: unknown) => void;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-close-catch-"));
		unhandled = [];
		handler = (reason: unknown) => {
			unhandled.push(reason);
		};
		process.on("unhandledRejection", handler);
	});

	afterEach(() => {
		process.off("unhandledRejection", handler);
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("idle-timer path: a rejecting closePooledClient does not surface an unhandled rejection", async () => {
		const root = tempRoot!;
		const manager = createMcpManager({ cwd: root, agentDir: join(root, "agent") });
		const internals = manager as unknown as {
			clientPool: Map<string, { key: string; client: { close: () => Promise<void> }; idleTimer?: NodeJS.Timeout }>;
			schedulePooledClientClose: (entry: unknown, pooled: unknown) => void;
			closePooledClient: (key: string) => Promise<void>;
		};

		// Real closePooledClient awaits pooled.client.close(); make it reject so the
		// whole closePooledClient promise rejects. pre-fix the idle-timer `void`
		// dropped that rejection → unhandled.
		const pooled = { key: "k", client: { close: () => Promise.reject(new Error("close boom")) } };
		internals.clientPool.set("k", pooled);

		internals.schedulePooledClientClose({ id: "s", config: { poolIdleMs: 0 }, sourcePath: "x" }, pooled);

		// idleMs=0 → timer fires next tick; let the rejection + catch settle.
		await new Promise((r) => setTimeout(r, 20));
		await new Promise((r) => setTimeout(r, 20));

		expect(unhandled).toHaveLength(0);
	});

	it("pool===false path: a rejecting client.close() does not surface an unhandled rejection", async () => {
		const root = tempRoot!;
		const manager = createMcpManager({ cwd: root, agentDir: join(root, "agent") });
		const internals = manager as unknown as {
			schedulePooledClientClose: (entry: unknown, pooled: unknown) => void;
		};

		const pooled = {
			key: "k",
			client: {
				close: () => Promise.reject(new Error("close boom")),
			},
		};

		internals.schedulePooledClientClose({ id: "s", config: { pool: false }, sourcePath: "x" }, pooled);

		// Let the Promise.resolve(...).catch settle.
		await new Promise((r) => setTimeout(r, 10));
		await new Promise((r) => setTimeout(r, 10));

		expect(unhandled).toHaveLength(0);
	});

	it("closeAll waits for every client before reporting aggregated close failures", async () => {
		const root = tempRoot!;
		const manager = createMcpManager({ cwd: root, agentDir: join(root, "agent") });
		const internals = manager as unknown as {
			clientPool: Map<string, { key: string; client: { close: () => Promise<void> }; idleTimer?: NodeJS.Timeout }>;
			_exitReapHook?: () => void;
		};
		let releaseSlowClose!: () => void;
		let slowCloseStarted = false;
		const slowClose = new Promise<void>((resolve) => {
			releaseSlowClose = resolve;
		});

		internals.clientPool.set("failing", {
			key: "failing",
			client: { close: () => Promise.reject(new Error("close boom")) },
		});
		internals.clientPool.set("slow", {
			key: "slow",
			client: {
				close: async () => {
					slowCloseStarted = true;
					await slowClose;
				},
			},
		});

		let outcome: "resolved" | "rejected" | undefined;
		const closing = manager.closeAll().then(
			() => {
				outcome = "resolved";
			},
			() => {
				outcome = "rejected";
			},
		);
		await new Promise((resolve) => setTimeout(resolve, 0));
		const outcomeBeforeSlowClose = outcome;
		releaseSlowClose();
		await closing;

		expect(slowCloseStarted).toBe(true);
		expect(outcomeBeforeSlowClose).toBeUndefined();
		expect(outcome).toBe("rejected");
		expect(internals.clientPool.size).toBe(0);
		expect(internals._exitReapHook).toBeUndefined();
	});
});
