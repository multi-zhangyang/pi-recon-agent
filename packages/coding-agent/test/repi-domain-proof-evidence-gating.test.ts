import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";
import { readCurrentMission } from "../src/core/repi/mission.ts";

type RegisteredTool = {
	name: string;
	execute: (
		toolCallId: string,
		params: Record<string, unknown>,
	) => Promise<{
		content: Array<{ text: string }>;
		details?: Record<string, unknown>;
	}>;
};

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

describe("REPI domain proof exits require executed evidence", () => {
	let tempDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "repi-proof-evidence-gating-"));
		mkdirSync(join(tempDir, "agent"), { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		process.env[ENV_AGENT_DIR] = join(tempDir, "agent");
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		rmSync(tempDir, { recursive: true, force: true });
	});

	function registerTools(stdout = ""): Map<string, RegisteredTool> {
		const tools = new Map<string, RegisteredTool>();
		const fakePi = {
			registerCommand() {},
			registerTool(tool: RegisteredTool) {
				tools.set(tool.name, tool);
			},
			on() {},
			appendEntry() {},
			getSessionName: () => undefined,
			setSessionName() {},
			sendMessage() {},
			exec: async () => ({ code: 0, stdout, stderr: "", killed: false }),
		} as unknown as ExtensionAPI;
		createReconExtensionFactory()(fakePi);
		return tools;
	}

	it("does not treat a plan artifact as native proof", async () => {
		const tools = registerTools();
		await tools.get("re_mission")!.execute("m-1", {
			action: "new",
			task: "analyze ./target.elf native reverse license check",
		});
		await tools.get("re_native_runtime")!.execute("n-1", { action: "plan", target: "./target.elf" });

		const proof = await tools.get("re_domain_proof_exit")!.execute("p-1", { action: "show" });
		expect(proof.content[0]?.text).toContain("domain: rev-native");
		expect(proof.content[0]?.text).toContain("status: blocked");
		expect(proof.content[0]?.text).toContain("symbol/import map");
		expect(proof.content[0]?.text).toContain("domain_proof_exit_missing:rev-native");
		expect(readCurrentMission()?.checkpoints.find((item) => item.name === "native_runtime_ready")?.status).toBe(
			"pending",
		);
	});

	it("accepts native proof only after a passed run has hashes and output", async () => {
		const stdout = [
			"[native-symbol] symbol/import map readelf imports",
			"[native-compare] strcmp comparison sink",
			"[native-trace] gdb runtime trace",
			"[native-patch] patch/replay proof branch condition",
		].join("\n");
		const tools = registerTools(stdout);
		await tools.get("re_mission")!.execute("m-1", {
			action: "new",
			task: "analyze ./target.elf native reverse license check",
		});
		await tools.get("re_native_runtime")!.execute("n-1", { action: "run", target: "./target.elf" });

		const proof = await tools.get("re_domain_proof_exit")!.execute("p-1", { action: "show" });
		expect(proof.content[0]?.text).toContain("domain: rev-native");
		expect(proof.content[0]?.text).toContain("status: passed");
		expect(proof.content[0]?.text).toContain("missing:\n- none");
		expect(readCurrentMission()?.checkpoints.find((item) => item.name === "native_runtime_ready")?.status).toBe(
			"done",
		);
	});

	it("maps Agent/LLM boundary routes to agent-security and keeps proof exits blocking", async () => {
		const tools = registerTools();
		await tools.get("re_mission")!.execute("m-1", {
			action: "new",
			task: "audit prompt injection and MCP tool-call boundary",
		});
		const proof = await tools.get("re_domain_proof_exit")!.execute("p-1", { action: "show" });
		expect(proof.content[0]?.text).toContain("domain: agent-security");
		expect(proof.content[0]?.text).toContain("status: blocked");
		expect(proof.content[0]?.text).toContain("prompt surface map");
		expect(proof.content[0]?.text).toContain("injection replay proof");
		const audit = await tools.get("re_complete")!.execute("c-1", { action: "audit" });
		expect(audit.content[0]?.text).toContain("domain_proof_exit_closure: agent-security status=blocked");
	});
});
