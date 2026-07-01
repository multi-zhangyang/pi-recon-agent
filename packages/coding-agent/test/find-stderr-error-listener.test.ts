import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";

// Mock ensureTool so no real fd lookup/download happens, and mock spawn so the
// find tool drives a fake child whose stderr we control. Emitting 'error' on
// the piped stderr with no listener would throw `Unhandled 'error' event`
// asynchronously → uncaughtException → crash.

vi.mock("../src/core/utils/tools-manager.ts", () => ({
	ensureTool: vi.fn(async () => "/fake/fd"),
}));

vi.mock("child_process", async (importActual) => {
	const actual = await importActual<typeof import("child_process")>();
	return { ...actual, spawn: vi.fn() };
});

const { spawn } = await import("child_process");
const { createFindToolDefinition } = await import("../src/core/tools/find.ts");

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

describe("find tool stderr 'error' listener (F3)", () => {
	afterEach(() => {
		vi.mocked(spawn).mockReset();
	});

	it("does not crash when child.stderr emits 'error' (EIO) and still rejects via close", async () => {
		const fakeChild = makeFakeChild();
		vi.mocked(spawn).mockReturnValue(fakeChild as never);

		// Pass a real cwd so resolveToCwd yields a real path; no custom glob op is
		// provided, so the tool falls into the fd branch and calls spawn (mocked).
		const def = createFindToolDefinition(process.cwd());

		const promise = def.execute("call-f3", { pattern: "*.ts", path: "." }, undefined, undefined, undefined as never);

		// Let the async IIFE resume past ensureTool + spawn and attach its
		// stream/child listeners (microtask work runs before the setImmediate
		// macrotask resolves).
		await new Promise<void>((r) => setImmediate(r));

		// Deterministic guard assertion: child.stderr MUST have an 'error'
		// listener. Pre-fix (no stderr error listener) this is 0 → FAIL here.
		expect(fakeChild.stderr.listenerCount("error")).toBeGreaterThanOrEqual(1);

		// Emit a stream-level 'error' on stderr — with the guard it is swallowed;
		// without the guard this throws Unhandled 'error' event → crash.
		fakeChild.stderr.emit("error", new Error("EIO on stderr"));
		// Drive a real failure path so the tool settles (rejects via close with a
		// non-zero fd exit).
		fakeChild.emit("close", 2);

		const result = await Promise.race([
			promise.catch((e) => e),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("find promise hung")), 4000)),
		]);

		expect(result).toBeInstanceOf(Error);
		expect(String((result as Error).message)).toMatch(/fd exited with code 2/);
	});
});
