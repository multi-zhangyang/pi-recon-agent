import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";

// output-guard holds a module-level `stdioErrorGuardInstalled` idempotency flag,
// so each test that exercises installStdioErrorGuard must import a FRESH module
// instance (vi.resetModules + dynamic import) — otherwise the second test sees
// the guard already installed and the no-op branch runs.
async function freshGuard() {
	vi.resetModules();
	return (await import("../../src/core/output-guard.ts")) as typeof import("../../src/core/output-guard.ts");
}

describe("output-guard stdio error guard", () => {
	describe("isDeadStdioError", () => {
		it("treats EIO/EPIPE/ENOTCONN as a dead downstream pipe", async () => {
			const { isDeadStdioError } = await freshGuard();
			for (const code of ["EIO", "EPIPE", "ENOTCONN"] as const) {
				expect(isDeadStdioError(Object.assign(new Error("pipe gone"), { code }))).toBe(true);
			}
		});

		it("treats other codes, missing code, and non-errors as non-fatal", async () => {
			const { isDeadStdioError } = await freshGuard();
			expect(isDeadStdioError(Object.assign(new Error("boom"), { code: "EUNKNOWN" }))).toBe(false);
			expect(isDeadStdioError(new Error("no code"))).toBe(false);
			expect(isDeadStdioError(null)).toBe(false);
			expect(isDeadStdioError(undefined)).toBe(false);
			expect(isDeadStdioError("string")).toBe(false);
			expect(isDeadStdioError({})).toBe(false);
		});
	});

	describe("installStdioErrorGuard", () => {
		it("exits cleanly (code 1) when stdout emits a dead-pipe error, swallows non-pipe errors", async () => {
			const { installStdioErrorGuard } = await freshGuard();
			const stdout = new EventEmitter();
			const stderr = new EventEmitter();
			const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
			try {
				installStdioErrorGuard({ stdout, stderr });

				// Dead-pipe error on stdout → clean exit(1), NOT an unhandled-'error' crash.
				expect(() =>
					stdout.emit("error", Object.assign(new Error("write EPIPE"), { code: "EPIPE" })),
				).not.toThrow();
				expect(exitSpy).toHaveBeenCalledTimes(1);
				expect(exitSpy).toHaveBeenCalledWith(1);

				// Non-pipe error on stderr → swallowed, no exit, no throw.
				expect(() =>
					stderr.emit("error", Object.assign(new Error("unexpected"), { code: "EUNKNOWN" })),
				).not.toThrow();
				expect(exitSpy).toHaveBeenCalledTimes(1); // still just the one EPIPE exit
			} finally {
				exitSpy.mockRestore();
			}
		});

		it("is idempotent — a second call attaches no additional listeners", async () => {
			const { installStdioErrorGuard } = await freshGuard();
			const stdout = new EventEmitter();
			const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
			try {
				installStdioErrorGuard({ stdout, stderr: null });
				const listenersBefore = stdout.listenerCount("error");
				expect(listenersBefore).toBe(1);

				installStdioErrorGuard({ stdout, stderr: null }); // no-op
				expect(stdout.listenerCount("error")).toBe(listenersBefore);

				// One emit → exactly one exit call (no double-handling from a phantom
				// second listener).
				stdout.emit("error", Object.assign(new Error("EIO"), { code: "EIO" }));
				expect(exitSpy).toHaveBeenCalledTimes(1);
			} finally {
				exitSpy.mockRestore();
			}
		});
	});
});
