import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { execCommand } from "../src/core/exec.ts";

// execCommand is the shared primitive behind `pi.exec` (extensions/re_* tools).
// Foundational guards: (1) the SIGTERM→SIGKILL escalation timer must be cleared
// + unref'd so a process that dies promptly under SIGTERM does not keep the Node
// event loop alive for 5s after every aborted exec; (2) a per-stream byte cap
// tail-trims stdout/stderr so a runaway command cannot OOM the agent. opt #50
// made the cap opt-in (explicit maxBytes). opt #55 closes the gap that every
// recon `pi.exec` caller passed only `{ timeout }` (no maxBytes) → all ran the
// UNBOUNDED path → a runaway recon command (objdump -d, strings, find /) could
// OOM the agent. The cap now falls back to an env-driven DEFAULT (8MB, 0 =
// disable) when maxBytes is unset, while explicit maxBytes>0 still wins and
// explicit 0 still disables (the JSON-caller contract).

const NODE = process.execPath;
const ENV_MAX_BYTES = "REPI_EXEC_MAX_BYTES";

describe("execCommand", () => {
	let previous: string | undefined;

	beforeEach(() => {
		previous = process.env[ENV_MAX_BYTES];
	});

	afterEach(() => {
		if (previous === undefined) delete process.env[ENV_MAX_BYTES];
		else process.env[ENV_MAX_BYTES] = previous;
	});

	it("returns full output unchanged when output is under the default cap (maxBytes unset)", async () => {
		// Env unset → 8MB default. 50 short lines (~200 bytes) is well under it,
		// so the output passes through untruncated and `truncated` is undefined.
		delete process.env[ENV_MAX_BYTES];
		const result = await execCommand(
			NODE,
			["-e", "for(let i=0;i<50;i++) process.stdout.write('L'+i+'\\n')"],
			process.cwd(),
		);
		expect(result.code).toBe(0);
		expect(result.truncated).toBeUndefined();
		expect(result.stdout).toContain("L0");
		expect(result.stdout).toContain("L49");
	});

	it("tail-trims stdout and sets truncated when output exceeds an explicit maxBytes", async () => {
		// ~10KB of numbered lines; cap at 1000 bytes → tail kept, head dropped.
		const result = await execCommand(
			NODE,
			["-e", "for(let i=0;i<2000;i++) process.stdout.write('L'+i+'\\n')"],
			process.cwd(),
			{ maxBytes: 1000 },
		);
		expect(result.code).toBe(0);
		expect(result.truncated).toBe(true);
		// Tail kept: the last line survives, the first does not.
		expect(result.stdout).toContain("L1999");
		expect(result.stdout).not.toContain("L0\n");
		// Bounded to roughly the cap (allow small slack for the final chunk).
		expect(Buffer.byteLength(result.stdout, "utf-8")).toBeLessThanOrEqual(1100);
	});

	it("does not truncate when output is under an explicit maxBytes", async () => {
		const result = await execCommand(
			NODE,
			["-e", "for(let i=0;i<10;i++) process.stdout.write('L'+i+'\\n')"],
			process.cwd(),
			{ maxBytes: 100_000 },
		);
		expect(result.truncated).toBeUndefined();
		expect(result.stdout).toContain("L0");
		expect(result.stdout).toContain("L9");
	});

	it("applies the REPI_EXEC_MAX_BYTES default cap when maxBytes is unset (the recon pi.exec path)", async () => {
		// Simulate the recon callers: only `{ timeout }` passed, no maxBytes. With
		// the env default set small, runaway output is tail-capped exactly as if
		// the caller had opted in — closing the OOM gap for every pi.exec caller.
		process.env[ENV_MAX_BYTES] = "1000";
		const result = await execCommand(
			NODE,
			["-e", "for(let i=0;i<2000;i++) process.stdout.write('L'+i+'\\n')"],
			process.cwd(),
			{ timeout: 10000 },
		);
		expect(result.code).toBe(0);
		expect(result.truncated).toBe(true);
		expect(result.stdout).toContain("L1999");
		expect(result.stdout).not.toContain("L0\n");
		expect(Buffer.byteLength(result.stdout, "utf-8")).toBeLessThanOrEqual(1100);
	});

	it("explicit maxBytes:0 disables the cap even when REPI_EXEC_MAX_BYTES is set (JSON-caller contract)", async () => {
		// A structured-output caller passes maxBytes:0 so its JSON is never
		// tail-truncated. This must win over the env default even when the env
		// default is set small enough that the output would otherwise be capped.
		process.env[ENV_MAX_BYTES] = "1000";
		const result = await execCommand(
			NODE,
			["-e", "for(let i=0;i<2000;i++) process.stdout.write('L'+i+'\\n')"],
			process.cwd(),
			{ maxBytes: 0 },
		);
		expect(result.code).toBe(0);
		expect(result.truncated).toBeUndefined();
		// Unbounded: both head and tail survive.
		expect(result.stdout).toContain("L0");
		expect(result.stdout).toContain("L1999");
	});

	it("resolves promptly when an aborted process dies under SIGTERM (no 5s hang)", async () => {
		// A long-running process aborted via signal. The old SIGKILL escalation
		// timer was unref'd+uncleared, so the PROMISE never hung — but the process
		// could not exit for 5s after. This asserts the promise still resolves
		// quickly (the kill+resolve path works and clearTimers runs on resolve).
		const controller = new AbortController();
		const promise = execCommand(NODE, ["-e", "setInterval(()=>{},1000)"], process.cwd(), {
			signal: controller.signal,
		});
		setTimeout(() => controller.abort(), 100);
		const result = await Promise.race([
			promise,
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("exec hung")), 4000)),
		]);
		expect(result.killed).toBe(true);
	});
});
