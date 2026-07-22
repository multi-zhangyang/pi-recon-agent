import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { RpcClient } from "../src/modes/rpc/rpc-client.ts";

const tempDirs: string[] = [];
const clients: RpcClient[] = [];

function createRpcChild(getStateBody: string): string {
	const dir = mkdtempSync(join(tmpdir(), "repi-rpc-idle-"));
	tempDirs.push(dir);
	const path = join(dir, "child.mjs");
	writeFileSync(
		path,
		`import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
 const command = JSON.parse(line);
 if (command.type !== "get_state") return;
 ${getStateBody}
});
`,
	);
	return path;
}

afterEach(async () => {
	await Promise.all(clients.splice(0).map((client) => client.stop()));
	for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("RpcClient.waitForIdle", () => {
	test("resolves from the state snapshot when the session is already idle", async () => {
		const client = new RpcClient({
			cliPath: createRpcChild(
				"console.log(JSON.stringify({ id: command.id, type: 'response', command: 'get_state', success: true, data: { isStreaming: false } }));",
			),
		});
		clients.push(client);
		await client.start();

		await expect(client.waitForIdle(1000)).resolves.toBeUndefined();
	});

	test("does not miss settlement emitted while the state snapshot is in flight", async () => {
		const client = new RpcClient({
			cliPath: createRpcChild(`
console.log(JSON.stringify({ type: "agent_settled" }));
setTimeout(() => console.log(JSON.stringify({ id: command.id, type: "response", command: "get_state", success: true, data: { isStreaming: true } })), 10);
`),
		});
		clients.push(client);
		await client.start();

		const idle = client.waitForIdle(1000);
		let externalListenerSawSettlement = false;
		client.onEvent((event) => {
			if (event.type === "agent_settled") externalListenerSawSettlement = true;
		});

		await expect(idle).resolves.toBeUndefined();
		expect(externalListenerSawSettlement).toBe(true);
	});
});
