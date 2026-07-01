import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { RpcClient } from "../src/modes/rpc/rpc-client.ts";

const tempDirs: string[] = [];

function writeChildScript(contents: string): string {
	const dir = mkdtempSync(join(tmpdir(), "pi-rpc-client-exit-"));
	tempDirs.push(dir);
	const path = join(dir, "child.mjs");
	writeFileSync(path, contents);
	return path;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) {
		rmSync(dir, { recursive: true, force: true });
	}
});

describe("RpcClient child process failures", () => {
	test("rejects an in-flight request when the child process exits", async () => {
		const client = new RpcClient({
			cliPath: writeChildScript(`
process.stdin.once("data", () => {
	process.exit(43);
});
process.stdin.resume();
`),
		});

		await client.start();

		await expect(client.getCommands()).rejects.toThrow(/Agent process exited \(code=43 signal=null\)/);
	});

	test("tail-caps accumulated stderr so a verbose child cannot grow it unbounded", async () => {
		// The RPC agent process is long-lived and `this.stderr` is embedded in
		// every error message; without a cap a chatty child grows it unbounded.
		// Emit ~75KB of stderr (> 64KB cap) using few long lines (less output
		// flood via the parent's stderr echo), then exit on stdin so we control
		// timing. The kept stderr must be the tail (last line present, first
		// absent) and bounded.
		const client = new RpcClient({
			cliPath: writeChildScript(`
for (let i = 0; i < 150; i++) process.stderr.write("L" + i + "-" + "x".repeat(490) + "\\n");
process.stdin.once("data", () => process.exit(0));
process.stdin.resume();
`),
		});
		await client.start();
		await expect(client.getCommands()).rejects.toThrow(/Agent process exited/);
		// The 'exit' event fires before stdio is fully drained on the parent side;
		// poll until the last line has landed, then assert the cap held.
		for (let i = 0; i < 50; i++) {
			if (client.getStderr().includes("L149-")) break;
			await new Promise<void>((resolve) => setTimeout(resolve, 20));
		}
		const stderr = client.getStderr();
		expect(stderr.length).toBeLessThanOrEqual(70_000);
		expect(stderr).toContain("L149-");
		expect(stderr).not.toContain("L0-");
	});
});
