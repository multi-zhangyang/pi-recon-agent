import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// opt #181: repi-bootstrap.mjs + repi-uninstall.mjs confirmation prompts used
// `spawnSync("head", ["-1"], { stdio: ["inherit","pipe","inherit"] })` with NO
// timeout. If stdin is open but never delivers data (CI with a non-closing
// pipe, container with stdin open but no TTY input), head -1 blocks forever →
// spawnSync blocks the whole Node process → indefinite hang. The shared
// promptYesNo helper wraps the spawnSync with a bounded timeout so a stalled
// stdin resolves with timedOut:true instead of hanging.
//
// The helper is an .mjs with no .d.ts — import via a non-literal const path to
// avoid TS7016 (see report-write-guard.test.ts for the same pattern). The
// behavioral pin spawns a child node process whose stdin is a pipe that NEVER
// writes and NEVER closes; with the timeout in place the child resolves with
// timedOut:true within ~600ms. Neuter-pin: remove the `timeout` option from
// the helper's spawnSync → head -1 blocks forever → the child never exits →
// vitest fails on test timeout.

const HELPER_URL = new URL("../../../scripts/reverse-agent/lib/confirm-prompt-helpers.mjs", import.meta.url).href;

describe("confirm-prompt-helpers (opt #181)", () => {
	let tmp: string;

	beforeEach(() => {
		tmp = mkdtempSync(join(tmpdir(), "cph-"));
	});

	afterEach(() => {
		rmSync(tmp, { recursive: true, force: true });
	});

	it("promptYesNo resolves with timedOut:true when stdin stalls (never writes, never closes) — behavioral pin", async () => {
		// Runner script imports the helper, calls promptYesNo with a 500ms timeout,
		// and writes the JSON result to stdout. The child's stdin is a pipe we
		// never write to and never close → head -1 blocks → spawnSync timeout
		// kills it after 500ms → timedOut:true. With the neutered helper (no
		// timeout), head -1 blocks forever and the child never exits.
		const runner = join(tmp, "runner.mjs");
		writeFileSync(
			runner,
			`import { promptYesNo } from ${JSON.stringify(HELPER_URL)};\n` +
				'const r = promptYesNo("", { timeoutMs: 500 });\n' +
				"process.stdout.write(JSON.stringify(r));\n" +
				"process.exit(0);\n",
		);

		const child = spawn("node", [runner], {
			stdio: ["pipe", "pipe", "pipe"],
		});
		// Intentionally NEVER write to child.stdin and NEVER close it.
		let out = "";
		child.stdout.on("data", (d: Buffer) => {
			out += d.toString();
		});

		const exitCode = await new Promise<number>((resolve, reject) => {
			const timer = setTimeout(() => {
				child.kill("SIGKILL");
				reject(new Error("child did not exit within 5s — promptYesNo hung (neutered?)"));
			}, 5000);
			child.on("exit", (code) => {
				clearTimeout(timer);
				resolve(code ?? -1);
			});
		});

		expect(exitCode).toBe(0);
		const result = JSON.parse(out);
		expect(result.timedOut).toBe(true);
		// spawnSync sets r.error to an ETIMEDOUT Error (with r.signal === "SIGTERM")
		// when its timeout kills the child — that is the expected, non-null error
		// path on a timeout. The helper surfaces it; the caller checks timedOut.
		expect(result.error).not.toBeNull();
		expect(result.error.code).toBe("ETIMEDOUT");
	});
});
