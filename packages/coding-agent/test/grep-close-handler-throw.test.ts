import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";

// opt #121 — the ripgrep child `close` handler is an `async` EventEmitter
// callback whose returned promise is dropped by the emitter. The body was NOT
// wrapped in try/catch and contained an un-guarded `await formatBlock(...)`
// (and un-guarded `match.lineText.replace(...)`). If anything in the handler
// threw, two things happened: (1) `settle()` was never reached → the outer
// `new Promise` (the tool's execute return) never settled → `await grep` in
// the agent loop hung forever (the turn froze); (2) the dropped rejected
// promise became `unhandledRejection` → process crash. Fix: wrap the handler
// body in try/catch; catch calls the idempotent `settle(() => reject(err))`.
//
// This test forces a throw inside the close handler by feeding a match whose
// `lines.text` is a NUMBER → `match.lineText.replace(...)` throws TypeError in
// the formatting loop. Pre-fix the promise hangs (race loses to the 4s
// suite timeout) and the dropped promise surfaces as unhandledRejection;
// post-fix the catch settles the promise with the rejection.

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

describe("grep tool close handler settles on an internal throw (opt #121)", () => {
	afterEach(() => {
		vi.mocked(spawn).mockReset();
	});

	it("rejects (instead of hanging) when the formatting loop throws", async () => {
		const fakeChild = makeFakeChild();
		vi.mocked(spawn).mockReturnValue(fakeChild as never);

		const def = createGrepToolDefinition(process.cwd(), {
			operations: { isDirectory: async () => true, readFile: async () => "" },
		});

		const promise = def.execute("call-121", { pattern: "x", path: "." }, undefined, undefined, undefined as never);

		await vi.waitFor(() => expect(fakeChild.listenerCount("close")).toBeGreaterThan(0), {
			timeout: 5_000,
			interval: 20,
		});

		// A match whose lines.text is a NUMBER → `match.lineText.replace(...)`
		// throws TypeError in the close handler's formatting loop.
		const matchLine = `${JSON.stringify({
			type: "match",
			data: { path: { text: "foo.txt" }, line_number: 1, lines: { text: 123 } },
		})}\n`;
		fakeChild.stdout.emit("data", Buffer.from(matchLine));

		// Let readline parse the line (it emits 'line' on a later tick).
		await new Promise<void>((r) => setTimeout(r, 10));

		// Drive the close handler with a success code so it reaches the
		// formatting loop (matchCount > 0, not aborted, code 0).
		fakeChild.emit("close", 0);

		const result = await promise.catch((e) => e);

		expect(result).toBeInstanceOf(Error);
		// The throw is the Number.replace TypeError, propagated via the catch.
		expect(String((result as Error).message)).toMatch(/replace is not a function/i);
	});
});
