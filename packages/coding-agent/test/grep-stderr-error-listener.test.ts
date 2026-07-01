import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";

// Mock ensureTool so no real rg lookup/download happens, and mock spawn so the
// grep tool drives a fake child whose stderr we control. The fake child's
// stderr is a real PassThrough; emitting 'error' on it with no listener would
// throw `Unhandled 'error' event` asynchronously (separate call stack, like a
// real libuv stream error) → uncaughtException → crash.

vi.mock("../src/core/utils/tools-manager.ts", () => ({
	ensureTool: vi.fn(async () => "/fake/rg"),
}));

vi.mock("child_process", async (importActual) => {
	const actual = await importActual<typeof import("child_process")>();
	return { ...actual, spawn: vi.fn() };
});

const { spawn } = await import("child_process");
const { createGrepToolDefinition } = await import("../src/core/tools/grep.ts");

function makeFakeChild(): EventEmitter & {
	stdout: PassThrough;
	stderr: PassThrough;
	killed: boolean;
	kill: () => boolean;
} {
	const stdout = new PassThrough();
	const stderr = new PassThrough();
	const child = Object.assign(new EventEmitter(), {
		stdout,
		stderr,
		killed: false,
		kill() {
			this.killed = true;
			return true;
		},
	});
	return child as ReturnType<typeof makeFakeChild>;
}

describe("grep tool stderr 'error' listener (F2)", () => {
	afterEach(() => {
		vi.mocked(spawn).mockReset();
	});

	it("does not crash when child.stderr emits 'error' (EIO) and still rejects via close", async () => {
		const fakeChild = makeFakeChild();
		vi.mocked(spawn).mockReturnValue(fakeChild as never);

		// Custom ops so the tool never touches the real filesystem for
		// isDirectory/readFile; the only thing that matters is the spawned child.
		const def = createGrepToolDefinition(process.cwd(), {
			operations: { isDirectory: async () => true, readFile: async () => "" },
		});

		const promise = def.execute("call-f2", { pattern: "x", path: "." }, undefined, undefined, undefined as never);

		// Let the async IIFE resume past ensureTool + isDirectory + spawn and
		// attach its stream/child listeners (all microtask work runs before the
		// setImmediate macrotask resolves).
		await new Promise<void>((r) => setImmediate(r));

		// Deterministic guard assertion: child.stderr MUST have an 'error'
		// listener. Pre-fix (no stderr error listener) this is 0 → FAIL here,
		// before the emit below can throw an Unhandled 'error' event.
		expect(fakeChild.stderr.listenerCount("error")).toBeGreaterThanOrEqual(1);

		// Emit a stream-level 'error' on stderr — with the guard it is swallowed
		// (no uncaughtException); without the guard this throws Unhandled 'error'
		// event in a separate call stack → crash.
		fakeChild.stderr.emit("error", new Error("EIO on stderr"));
		// Drive a real failure path so the tool settles (rejects via close).
		fakeChild.emit("close", 2);

		// Race against a hang: if the close path is broken the promise never
		// settles.
		const result = await Promise.race([
			promise.catch((e) => e),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("grep promise hung")), 4000)),
		]);

		expect(result).toBeInstanceOf(Error);
		expect(String((result as Error).message)).toMatch(/ripgrep exited with code 2/);
	});
});
