import { Buffer } from "node:buffer";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

type RegisteredTool = {
	execute: (toolCallId: string, params: Record<string, unknown>) => Promise<{ content: Array<{ text: string }> }>;
};

describe.skipIf(process.env.REPI_RUN_RECON_E2E !== "1")("REPI inline profile integration", () => {
	let tempDir: string;
	let agentDir: string;
	let targetPath: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-e2e-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		targetPath = join(tempDir, "license-check");
		mkdirSync(agentDir, { recursive: true });
		writeFileSync(targetPath, "ELF fixture\nstrcmp\n", "utf-8");
		previousAgentDir = process.env[ENV_AGENT_DIR];
		process.env[ENV_AGENT_DIR] = agentDir;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("runs mission -> passive map -> evidence -> completion with a bounded prompt", async () => {
		const commands = new Set<string>();
		const tools = new Map<string, RegisteredTool>();
		const handlers = new Map<
			string,
			Array<(event: Record<string, unknown>, ctx: Record<string, unknown>) => unknown>
		>();
		const execCalls: Array<{ command: string; args: string[] }> = [];
		const fakePi = {
			registerCommand(name: string) {
				commands.add(name);
			},
			registerTool(tool: RegisteredTool & { name: string }) {
				tools.set(tool.name, tool);
			},
			on(event: string, handler: (event: Record<string, unknown>, ctx: Record<string, unknown>) => unknown) {
				handlers.set(event, [...(handlers.get(event) ?? []), handler]);
			},
			appendEntry() {},
			getSessionName: () => undefined,
			setSessionName() {},
			sendMessage() {},
			exec: async (command: string, args: string[]) => {
				execCalls.push({ command, args });
				return { code: 0, stdout: "ELF 64-bit\nstrcmp\n", stderr: "", killed: false };
			},
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);

		for (const name of ["re_mission", "re_map", "re_complete"]) expect(tools.has(name)).toBe(true);

		const mission = await tools.get("re_mission")!.execute("mission", {
			action: "new",
			task: `reverse the ELF license check at ${targetPath}`,
		});
		expect(mission.content[0]?.text).toContain("mission_id:");
		const missionPath = join(agentDir, "recon", "mission", "current.json");
		expect(readFileSync(missionPath, "utf-8")).toContain("Native reverse");

		const passiveMap = await tools.get("re_map")!.execute("map", { target: targetPath, depth: 2 });
		expect(passiveMap.content[0]?.text).toContain("passive_map_result:");
		expect(passiveMap.content[0]?.text).toContain("map_artifact:");
		expect(execCalls.length).toBeGreaterThan(0);
		const artifactPath = /map_artifact: (.+)/.exec(passiveMap.content[0]?.text ?? "")?.[1]?.trim();
		expect(artifactPath).toBeDefined();
		expect(existsSync(artifactPath!)).toBe(true);
		expect(readFileSync(artifactPath!, "utf-8")).toContain("REPI Passive Map Artifact");
		expect(readFileSync(join(agentDir, "recon", "evidence", "ledger.md"), "utf-8")).toContain("passive-map");

		const completion = await tools.get("re_complete")!.execute("complete", { action: "audit" });
		expect(completion.content[0]?.text).toContain("completion_status:");

		const beforeAgentStart = handlers.get("before_agent_start")?.[0];
		expect(beforeAgentStart).toBeDefined();
		const injected = (await beforeAgentStart!(
			{
				type: "before_agent_start",
				prompt: `analyze the ELF at ${targetPath}`,
				systemPrompt: "base-system",
				systemPromptOptions: {},
			},
			{ hasUI: false },
		)) as { systemPrompt?: string } | undefined;
		expect(injected?.systemPrompt).toContain("## REPI route");
		expect(injected?.systemPrompt).toContain("domain: Native reverse");
		expect(injected?.systemPrompt).toContain("first_probe:");
		expect(Buffer.byteLength(injected?.systemPrompt ?? "", "utf8")).toBeLessThan(768);
		expect(existsSync(join(agentDir, "recon", "memory"))).toBe(false);
	}, 120_000);
});
