import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";

// opt #128 — the fd child `close` handler is a (sync) EventEmitter callback.
// The body was NOT wrapped in try/catch and ran unguarded: lines.join, the
// relativization loop (path.relative / toPosixPath), JSON.stringify (error
// path), and truncateHead. If anything in the handler threw, two things
// happened: (1) the sync throw propagated out of the emitter's 'close' emit
// → uncaughtException (there is NO global uncaughtException handler) →
// process crash; (2) settle() was never reached → the outer `new Promise`
// (the tool's execute return) never settled → `await find` in the agent loop
// hung forever (the turn froze). Fix: wrap the handler body in try/catch;
// catch calls the idempotent `settle(() => reject(err as Error))`. Mirrors
// opt #121 (grep close-handler throw).
//
// This test forces a throw inside the close handler by mocking truncateHead
// to throw on the success path (code 0, non-empty output). Pre-fix the
// throw escapes the emit (the test's fakeChild.emit("close", 0) re-throws
// synchronously) and the promise never settles; post-fix the catch settles
// the promise with the rejection.

vi.mock("../src/core/utils/tools-manager.ts", () => ({
	ensureTool: vi.fn(async () => "/fake/fd"),
}));

vi.mock("../src/core/tools/truncate.ts", async (importActual) => {
	const actual = await importActual<typeof import("../src/core/tools/truncate.ts")>();
	return {
		...actual,
		truncateHead: vi.fn(() => {
			throw new TypeError("boom from truncateHead");
		}),
	};
});

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

describe("find tool close handler settles on an internal throw (opt #128)", () => {
	afterEach(() => {
		vi.mocked(spawn).mockReset();
	});

	it("rejects (instead of hanging / crashing) when the formatting path throws", async () => {
		const fakeChild = makeFakeChild();
		vi.mocked(spawn).mockReturnValue(fakeChild as never);

		// Real cwd so resolveToCwd yields a real path; no custom glob op → the
		// tool falls into the fd branch and calls spawn (mocked).
		const def = createFindToolDefinition(process.cwd());

		const promise = def.execute("call-128", { pattern: "*.ts", path: "." }, undefined, undefined, undefined as never);

		await vi.waitFor(() => expect(fakeChild.listenerCount("close")).toBeGreaterThan(0));

		// Feed one stdout line so `output` is non-empty and the close handler
		// reaches the success path (code 0 → relativization → truncateHead).
		fakeChild.stdout.emit("data", Buffer.from("some/file.ts\n"));

		// Let readline parse the line (it emits 'line' on a later tick).
		await new Promise<void>((r) => setTimeout(r, 10));

		// Drive the close handler with a success code. Pre-fix the mocked
		// truncateHead throws synchronously inside the 'close' listener and the
		// throw escapes fakeChild.emit("close", 0) → this call re-throws and the
		// test fails with the TypeError (the bug: uncaughtException + hang).
		// Post-fix the try/catch swallows it and settle() rejects the promise.
		fakeChild.emit("close", 0);

		const result = await promise.catch((e) => e);

		expect(result).toBeInstanceOf(Error);
		// The throw is the mocked truncateHead TypeError, propagated via the catch.
		expect(String((result as Error).message)).toMatch(/boom from truncateHead/);
	});
});
