import { access } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { NodeExecutionEnv } from "../../src/harness/env/nodejs.ts";
import { createTempDir } from "./session-test-utils.ts";

// Finding C: appendFile / createTempDir / createTempFile dropped the abortSignal declared on the
// ExecutionEnv interface and passed by shell-output.ts. An already-aborted signal should short-
// circuit each via the abortResult pre-check (mirroring writeFile) and return a FileError with
// code "aborted" — instead of performing the I/O and returning ok.

describe("NodeExecutionEnv abort-signal honoring (appendFile/createTempDir/createTempFile)", () => {
	it("appendFile returns aborted when the signal is already aborted", async () => {
		const root = createTempDir();
		const env = new NodeExecutionEnv({ cwd: root });
		const target = join(root, "abort-append.txt");
		const ac = new AbortController();
		ac.abort();
		const result = await env.appendFile(target, "x", ac.signal);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.error.code).toBe("aborted");
		// The file must NOT have been created/written despite the abort.
		await expect(access(target)).rejects.toThrow();
	});

	it("createTempFile returns aborted when the signal is already aborted", async () => {
		const root = createTempDir();
		const env = new NodeExecutionEnv({ cwd: root });
		const ac = new AbortController();
		ac.abort();
		const result = await env.createTempFile({ abortSignal: ac.signal });
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.error.code).toBe("aborted");
	});

	it("createTempDir returns aborted when the signal is already aborted", async () => {
		const root = createTempDir();
		const env = new NodeExecutionEnv({ cwd: root });
		const ac = new AbortController();
		ac.abort();
		const result = await env.createTempDir("tmp-", ac.signal);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.error.code).toBe("aborted");
	});

	it("appendFile still succeeds when no signal is provided (baseline preserved)", async () => {
		const root = createTempDir();
		const env = new NodeExecutionEnv({ cwd: root });
		const target = "baseline-append.txt";
		const result = await env.appendFile(target, "hello");
		expect(result.ok).toBe(true);
		const text = await env.readTextFile(target);
		expect(text.ok && text.value).toBe("hello");
	});
});
