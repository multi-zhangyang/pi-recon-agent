import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #177: unit-test safeWriteReport without spawning the one-shot scripts.
// The helper accepts an injectable onWriteError so the test records failures
// instead of letting the default handler call process.exit(1).
const HELPER = "../../../scripts/reverse-agent/lib/report-write-helpers.mjs";

describe("report-write-helpers (opt #177)", () => {
	let tmp: string;

	beforeEach(() => {
		tmp = mkdtempSync(join(tmpdir(), "rwh-"));
	});

	afterEach(() => {
		rmSync(tmp, { recursive: true, force: true });
	});

	it("safeWriteReport writes the file with correct content on a writable dest and does not call onWriteError", async () => {
		const { safeWriteReport } = await import(HELPER);
		const onWriteError = vi.fn();
		const dest = join(tmp, "out", "report.json");
		const ok = safeWriteReport(dest, "hello-report\n", { onWriteError });
		expect(ok).toBe(true);
		expect(readFileSync(dest, "utf8")).toBe("hello-report\n");
		expect(onWriteError).not.toHaveBeenCalled();
	});

	it("safeWriteReport routes a write failure through onWriteError and does NOT throw uncaught (ENOSPC/EACCES-class failure)", async () => {
		const { safeWriteReport } = await import(HELPER);
		// Use a regular file as the parent dir so mkdirSync throws ENOTDIR —
		// a real, root-independent write-path failure (chmod 0o555 would not
		// stop root, but a non-directory parent fails for everyone).
		const blocker = join(tmp, "blocker");
		writeFileSync(blocker, "x");
		const dest = join(blocker, "report.json");
		const onWriteError = vi.fn();
		// If the helper is neutered to bare writeFileSync (no try/catch), this
		// line throws uncaught and the test fails with the raw ENOTDIR error.
		const ok = safeWriteReport(dest, "data\n", { onWriteError });
		expect(ok).toBe(false);
		expect(onWriteError).toHaveBeenCalledTimes(1);
		const [message, ctx] = onWriteError.mock.calls[0];
		expect(message).toContain("Error writing report to");
		expect(message).toContain(dest);
		expect(ctx.path).toBe(dest);
		expect(ctx.error).toBeInstanceOf(Error);
	});

	it("safeWriteReport with fallbackToStdout salvages the data to stdout AND calls onWriteError on a write failure", async () => {
		const { safeWriteReport } = await import(HELPER);
		const blocker = join(tmp, "blocker");
		writeFileSync(blocker, "x");
		const dest = join(blocker, "report.json");
		const onWriteError = vi.fn();
		const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
		try {
			// Neutered helper throws at mkdirSync before reaching any stdout
			// salvage -> writeSpy never sees the payload and the test fails.
			const ok = safeWriteReport(dest, "salvage-payload\n", { onWriteError, fallbackToStdout: true });
			expect(ok).toBe(false);
			const written = writeSpy.mock.calls.map((call) => String(call[0])).join("");
			expect(written).toContain("salvage-payload");
			expect(onWriteError).toHaveBeenCalledTimes(1);
			expect(String(onWriteError.mock.calls[0][0])).toContain("Error writing report to");
		} finally {
			writeSpy.mockRestore();
		}
	});

	it("defaultReportWriteError is the documented stderr + non-zero exit handler", async () => {
		const { defaultReportWriteError } = await import(HELPER);
		// The default handler must emit a stderr diagnostic and exit non-zero.
		// Spy on both so the vitest process is not torn down. defaultReportWriteError
		// routes through console.error, so spy there.
		const errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
		const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
			throw new Error("process.exit called");
		}) as never);
		try {
			expect(() => defaultReportWriteError("Error writing report to /x: boom")).toThrow("process.exit called");
			expect(errSpy).toHaveBeenCalledWith("Error writing report to /x: boom");
			expect(exitSpy).toHaveBeenCalledWith(1);
		} finally {
			errSpy.mockRestore();
			exitSpy.mockRestore();
		}
	});
});
