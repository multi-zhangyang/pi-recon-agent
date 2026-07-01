import { EventEmitter } from "node:events";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DefaultPackageManager } from "../src/core/package-manager.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import * as childProcessUtil from "../src/utils/child-process.ts";

/**
 * Mock child that ignores SIGTERM (stays alive) but dies on SIGKILL. The
 * SIGTERM path schedules a delayed close after 2s — longer than the 1s SIGKILL
 * escalation window — so a neutered (SIGKILL-less) variant still settles the
 * promise (and the test fails on the "no SIGKILL" assertion, not by hanging).
 * Emits both "exit" and "close" so it works for runCommand ("exit") and
 * runCommandCapture ("close") alike.
 */
class HungChild extends EventEmitter {
	stdout = new PassThrough();
	stderr = new PassThrough();
	pid = 12345;
	exitCode: number | null = null;
	killSignals: string[] = [];

	kill(signal: NodeJS.Signals = "SIGTERM"): boolean {
		this.killSignals.push(signal);
		if (signal === "SIGKILL") {
			this.exitCode = null;
			setImmediate(() => {
				this.emit("exit", null, "SIGKILL");
				this.emit("close", null, "SIGKILL");
			});
		} else {
			setTimeout(() => {
				this.emit("exit", null, signal);
				this.emit("close", null, signal);
			}, 2000).unref();
		}
		return true;
	}
}

/** Mock child that exits 0 immediately (for env-propagation / success-path tests). */
class ExitingChild extends EventEmitter {
	stdout = new PassThrough();
	stderr = new PassThrough();
	pid = 54321;
	exitCode: number | null = null;
	capturedEnv: Record<string, string> | undefined;

	constructor(env?: Record<string, string>) {
		super();
		this.capturedEnv = env;
		setImmediate(() => {
			this.exitCode = 0;
			this.emit("exit", 0, null);
			this.emit("close", 0, null);
		});
	}
	kill(): boolean {
		return true;
	}
}

interface PackageManagerInternals {
	spawnCommand(command: string, args: string[], options?: { cwd?: string; env?: Record<string, string> }): unknown;
	spawnCaptureCommand(
		command: string,
		args: string[],
		options?: { cwd?: string; env?: Record<string, string> },
	): unknown;
	runCommand(
		command: string,
		args: string[],
		options?: { cwd?: string; timeoutMs?: number; env?: Record<string, string> },
	): Promise<void>;
	runCommandCapture(
		command: string,
		args: string[],
		options?: { cwd?: string; timeoutMs?: number; env?: Record<string, string> },
	): Promise<string>;
	runNpmCommand(args: string[], options?: { cwd?: string; timeoutMs?: number }): Promise<void>;
	installGit(source: unknown, scope: "user" | "project" | "temporary"): Promise<void>;
	parseSource(source: string): { type: string; repo: string; ref?: string };
}

describe("DefaultPackageManager lifecycle (FIX 4/5)", () => {
	let tempDir: string;
	let agentDir: string;
	let packageManager: DefaultPackageManager;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pm-life-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		const settingsManager = SettingsManager.inMemory();
		packageManager = new DefaultPackageManager({ cwd: tempDir, agentDir, settingsManager });
	});

	afterEach(() => {
		vi.restoreAllMocks();
		rmSync(tempDir, { recursive: true, force: true });
	});

	describe("FIX 4 — runCommandCapture timeout SIGTERM→SIGKILL escalation", () => {
		it("escalates from SIGTERM to SIGKILL on a hung child and rejects with timeout", async () => {
			const internals = packageManager as unknown as PackageManagerInternals;
			const child = new HungChild();
			const spawnSpy = vi.spyOn(internals, "spawnCaptureCommand").mockReturnValue(child);

			const promise = internals.runCommandCapture("git", ["clone", "x"], { timeoutMs: 50 });

			await expect(promise).rejects.toThrow(/timed out after 50ms/);
			expect(spawnSpy).toHaveBeenCalledTimes(1);
			expect(child.killSignals).toContain("SIGTERM");
			expect(child.killSignals).toContain("SIGKILL");
			// SIGKILL must come AFTER SIGTERM.
			expect(child.killSignals.indexOf("SIGKILL")).toBeGreaterThan(child.killSignals.indexOf("SIGTERM"));
		});
	});

	describe("FIX 5 — runCommand timeout + env propagation", () => {
		it("escalates from SIGTERM to SIGKILL on a hung child and rejects with timeout", async () => {
			const internals = packageManager as unknown as PackageManagerInternals;
			const child = new HungChild();
			vi.spyOn(internals, "spawnCommand").mockReturnValue(child);

			const promise = internals.runCommand("git", ["clone", "x"], { timeoutMs: 50 });

			await expect(promise).rejects.toThrow(/timed out after 50ms/);
			expect(child.killSignals).toContain("SIGTERM");
			expect(child.killSignals).toContain("SIGKILL");
			expect(child.killSignals.indexOf("SIGKILL")).toBeGreaterThan(child.killSignals.indexOf("SIGTERM"));
		});

		it("propagates env (GIT_TERMINAL_PROMPT=0) through spawnCommand into the real spawnProcess env", async () => {
			const internals = packageManager as unknown as PackageManagerInternals;
			let capturedEnv: NodeJS.ProcessEnv | undefined;
			const spawnSpy = vi.spyOn(childProcessUtil, "spawnProcess").mockImplementation((_command, _args, options) => {
				capturedEnv = options?.env;
				return new ExitingChild() as unknown as import("node:child_process").ChildProcess;
			});

			await internals.runCommand("git", ["clone", "x"], {
				env: { GIT_TERMINAL_PROMPT: "0" },
				timeoutMs: 1000,
			});

			expect(spawnSpy).toHaveBeenCalledTimes(1);
			expect(capturedEnv).toBeDefined();
			expect(capturedEnv!.GIT_TERMINAL_PROMPT).toBe("0");
		});

		it("installGit passes GIT_TERMINAL_PROMPT=0 and a generous timeoutMs to runCommand", async () => {
			const internals = packageManager as unknown as PackageManagerInternals;
			const parsed = internals.parseSource("git:github.com/user/repo");
			expect(parsed.type).toBe("git");

			const calls: Array<{ command: string; args: string[]; options: any }> = [];
			vi.spyOn(internals, "runCommand").mockImplementation((command, args, options) => {
				calls.push({ command, args, options });
				return Promise.resolve();
			});
			// No target dir exists yet, no package.json → clone path only.
			await internals.installGit(parsed, "temporary");

			const cloneCall = calls.find((c) => c.args[0] === "clone");
			expect(cloneCall).toBeDefined();
			expect(cloneCall!.options.env).toBeDefined();
			expect(cloneCall!.options.env.GIT_TERMINAL_PROMPT).toBe("0");
			expect(cloneCall!.options.timeoutMs).toBeTypeOf("number");
			expect(cloneCall!.options.timeoutMs).toBeGreaterThan(60_000); // generous
		});
	});
});
