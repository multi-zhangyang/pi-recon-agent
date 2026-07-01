import { describe, expect, it } from "vitest";
import { execCommand } from "../src/core/exec.ts";

// execCommand's waitForChildProcess rejects on a child 'error' (ENOENT when the
// binary doesn't exist). Pre-fix the catch discarded _err and resolved with
// empty stdout/stderr + code 1 — the caller couldn't distinguish "command not
// found" from "ran and returned 1 with no output". Post-fix the empty-stderr
// case surfaces the spawn-failure reason.

describe("execCommand surfaces spawn ENOENT (F4)", () => {
	it("resolves with code 1 and an ENOENT-bearing stderr for a missing binary", async () => {
		const result = await execCommand("nonexistent-binary-xyz", [], process.cwd(), { timeout: 5000 });

		expect(result.code).toBe(1);
		// Pre-fix this was "" — the actionable reason was lost.
		expect(result.stderr).not.toBe("");
		expect(result.stderr).toMatch(/ENOENT/);
		expect(result.stderr).toContain("nonexistent-binary-xyz");
	});

	it("keeps the existing stderr content when the command ran and produced stderr (default-preserving)", async () => {
		// A real command that exits 1 and writes to stderr: the spawn-failure
		// fallback must NOT overwrite real stderr content.
		const node = process.execPath;
		const result = await execCommand(
			node,
			["-e", "process.stderr.write('real stderr msg\\n'); process.exit(1)"],
			process.cwd(),
		);

		expect(result.code).toBe(1);
		expect(result.stderr).toContain("real stderr msg");
		// The ENOENT fallback must not have been appended.
		expect(result.stderr).not.toMatch(/ENOENT/);
	});
});
