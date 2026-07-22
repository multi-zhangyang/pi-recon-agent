import { Buffer } from "node:buffer";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Context, fauxAssistantMessage } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";
import { createRepiCapabilityActivationFactory } from "../src/core/repi/capabilities.ts";
import {
	createReconResourceLoaderOptions,
	RECON_APPEND_SYSTEM_PROMPT,
	RECON_SYSTEM_PROMPT,
} from "../src/core/repi/resources.ts";
import { DefaultResourceLoader } from "../src/core/resource-loader.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import { resolveRepiPromptComposition } from "../src/main.ts";
import { createHarness, type Harness } from "./suite/harness.ts";

vi.setConfig({ testTimeout: 120_000 });

type ContextBudget = {
	toolNames: string[];
	toolCount: number;
	systemPromptBytes: number;
	systemPromptTokens: number;
	toolSchemaBytes: number;
	fixedContextBytes: number;
	systemPrompt: string;
};

type FocusedRoute = "core" | "web" | "native" | "crypto" | "forensics" | "agent";

const ROUTE_PROMPTS: Record<FocusedRoute, string> = {
	core: "inspect the current repository and report the next concrete step",
	web: "audit https://example.test/api/orders for IDOR authorization bypass",
	native: "reverse the ELF binary ./license-check and trace its validation branch",
	crypto: "factor an RSA modulus with a lattice relation using Sage and verify the recovered plaintext",
	forensics: "analyze capture.pcap with tshark and recover the protocol timeline",
	agent: "audit prompt injection across an LLM agent MCP tool boundary",
};

const EXPECTED_TOOLS: Record<FocusedRoute, string[]> = {
	core: ["read", "bash", "re_capabilities", "goal_complete"],
	web: ["re_live_browser", "re_web_authz_state", "re_exploit_lab", "re_runtime_adapter"],
	native: ["re_native_runtime", "re_exploit_lab", "re_runtime_adapter", "re_lane_specialist_pack"],
	crypto: ["re_exploit_lab", "re_runtime_adapter", "re_lane_specialist_pack", "re_toolchain_domain"],
	forensics: ["re_runtime_adapter", "re_runtime_bridge", "re_lane_specialist_pack", "re_toolchain_domain"],
	agent: ["re_runtime_adapter", "re_runtime_bridge", "re_reason"],
};

const EXCLUDED_TOOLS: Record<FocusedRoute, string[]> = {
	core: ["re_live_browser", "re_native_runtime", "re_swarm", "re_proof_loop"],
	web: ["re_native_runtime", "re_mobile_runtime", "re_swarm", "re_proof_loop"],
	native: ["re_live_browser", "re_mobile_runtime", "re_swarm", "re_proof_loop"],
	crypto: ["re_live_browser", "re_native_runtime", "re_runtime_bridge", "re_swarm", "re_proof_loop"],
	forensics: ["re_live_browser", "re_native_runtime", "re_exploit_lab", "re_swarm", "re_proof_loop"],
	agent: ["re_live_browser", "re_native_runtime", "re_toolchain_domain", "re_swarm", "re_proof_loop"],
};

function measureContext(context: Context): ContextBudget {
	const tools = context.tools ?? [];
	const systemPrompt = context.systemPrompt ?? "";
	const systemPromptBytes = Buffer.byteLength(systemPrompt, "utf8");
	const toolSchemaBytes = Buffer.byteLength(JSON.stringify(tools), "utf8");
	return {
		toolNames: tools.map((tool) => tool.name),
		toolCount: tools.length,
		systemPromptBytes,
		systemPromptTokens: Math.ceil(systemPrompt.length / 4),
		toolSchemaBytes,
		fixedContextBytes: systemPromptBytes + toolSchemaBytes,
		systemPrompt,
	};
}

async function captureNextContext(harness: Harness, prompt: string): Promise<ContextBudget> {
	let budget: ContextBudget | undefined;
	harness.setResponses([
		(context) => {
			budget = measureContext(context);
			return fauxAssistantMessage("done");
		},
	]);
	await harness.session.prompt(prompt);
	if (!budget) throw new Error(`faux provider did not receive context for: ${prompt}`);
	return budget;
}

async function createRealRepiHarness(runtimeDir: string, label: string): Promise<Harness> {
	const caseDir = join(runtimeDir, label);
	const agentDir = join(caseDir, "agent");
	const workspaceDir = join(caseDir, "workspace");
	mkdirSync(workspaceDir, { recursive: true });
	process.env.REPI_CODING_AGENT_DIR = agentDir;
	const settingsManager = SettingsManager.create(workspaceDir, agentDir);
	const resourceLoader = new DefaultResourceLoader({
		cwd: workspaceDir,
		agentDir,
		settingsManager,
		noContextFiles: true,
		systemPrompt: RECON_SYSTEM_PROMPT,
		appendSystemPrompt: [RECON_APPEND_SYSTEM_PROMPT],
		extensionFactories: [
			createReconExtensionFactory(),
			createRepiCapabilityActivationFactory({ preserveExplicitToolSelection: label === "full" }),
		],
		...createReconResourceLoaderOptions(),
	});
	await resourceLoader.reload();
	const harness = await createHarness({ resourceLoader });
	await harness.session.bindExtensions({});
	return harness;
}

async function captureFocusedRoute(runtimeDir: string, route: FocusedRoute): Promise<ContextBudget> {
	const harness = await createRealRepiHarness(runtimeDir, route);
	try {
		return await captureNextContext(harness, ROUTE_PROMPTS[route]);
	} finally {
		harness.cleanup();
	}
}

async function captureFullSurface(runtimeDir: string): Promise<ContextBudget> {
	const harness = await createRealRepiHarness(runtimeDir, "full");
	try {
		return await captureNextContext(harness, "audit https://example.test/full-surface capability baseline");
	} finally {
		harness.cleanup();
	}
}

describe("REPI provider context budget", () => {
	let runtimeDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		runtimeDir = join(tmpdir(), `repi-context-budget-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(runtimeDir, { recursive: true });
		previousAgentDir = process.env.REPI_CODING_AGENT_DIR;
		process.env.REPI_CODING_AGENT_DIR = join(runtimeDir, "agent");
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env.REPI_CODING_AGENT_DIR;
		else process.env.REPI_CODING_AGENT_DIR = previousAgentDir;
		if (existsSync(runtimeDir)) rmSync(runtimeDir, { recursive: true, force: true });
	});

	it("keeps real routed provider contexts materially below the full registered surface", async () => {
		const focused = {} as Record<FocusedRoute, ContextBudget>;
		for (const route of Object.keys(ROUTE_PROMPTS) as FocusedRoute[]) {
			focused[route] = await captureFocusedRoute(runtimeDir, route);
		}
		const fullBudget = await captureFullSurface(runtimeDir);

		console.table(
			Object.entries({ ...focused, full: fullBudget }).map(([route, budget]) => ({
				route,
				tools: budget.toolCount,
				systemPromptBytes: budget.systemPromptBytes,
				systemPromptTokens: budget.systemPromptTokens,
				toolSchemaBytes: budget.toolSchemaBytes,
				fixedContextBytes: budget.fixedContextBytes,
			})),
		);

		for (const route of Object.keys(focused) as FocusedRoute[]) {
			const budget = focused[route];
			for (const toolName of EXPECTED_TOOLS[route])
				expect(budget.toolNames, `${route} missing ${toolName}`).toContain(toolName);
			for (const toolName of EXCLUDED_TOOLS[route])
				expect(budget.toolNames, `${route} leaked ${toolName}`).not.toContain(toolName);

			expect(budget.toolCount, `${route} tool count`).toBeLessThan(fullBudget.toolCount * 0.6);
			expect(budget.toolSchemaBytes, `${route} schema budget`).toBeLessThan(fullBudget.toolSchemaBytes * 0.6);
			expect(budget.fixedContextBytes, `${route} fixed context budget`).toBeLessThan(
				fullBudget.fixedContextBytes * 0.75,
			);
			expect(budget.systemPromptBytes, `${route} system prompt absolute budget`).toBeLessThan(4 * 1024);
			expect(budget.systemPromptTokens, `${route} estimated system prompt token budget`).toBeLessThan(700);
			expect(budget.toolSchemaBytes, `${route} schema absolute budget`).toBeLessThan(12 * 1024);
			expect(budget.fixedContextBytes, `${route} fixed context absolute budget`).toBeLessThan(16 * 1024);
			if (route === "core") expect(budget.systemPrompt).not.toContain("## REPI capability");
			else expect(budget.systemPrompt).toContain("## REPI capability");
		}

		expect(focused.core.toolSchemaBytes).toBeLessThan(fullBudget.toolSchemaBytes * 0.4);
		expect(focused.core.fixedContextBytes).toBeLessThan(fullBudget.fixedContextBytes * 0.6);
		expect(focused.core.toolSchemaBytes).toBeLessThan(7 * 1024);
		expect(focused.core.fixedContextBytes).toBeLessThan(10 * 1024);
		expect(fullBudget.toolSchemaBytes).toBeLessThan(48 * 1024);
		expect(fullBudget.fixedContextBytes).toBeLessThan(64 * 1024);
		expect(fullBudget.toolNames).toEqual(
			expect.arrayContaining(["re_live_browser", "re_native_runtime", "re_swarm"]),
		);
	});

	it("keeps an explicit custom prompt free of REPI additions for a security task", async () => {
		const caseDir = join(runtimeDir, "custom-override");
		const agentDir = join(caseDir, "agent");
		const workspaceDir = join(caseDir, "workspace");
		mkdirSync(workspaceDir, { recursive: true });
		const composition = resolveRepiPromptComposition({
			recon: true,
			systemPrompt: "CUSTOM_ONLY",
			appendSystemPrompt: ["USER_APPEND"],
		});
		const settingsManager = SettingsManager.create(workspaceDir, agentDir);
		const resourceLoader = new DefaultResourceLoader({
			cwd: workspaceDir,
			agentDir,
			settingsManager,
			noContextFiles: true,
			systemPrompt: composition.systemPrompt,
			appendSystemPrompt: composition.appendSystemPrompt,
			extensionFactories: [
				createReconExtensionFactory({ injectRuntimePacket: composition.injectPromptPackets }),
				createRepiCapabilityActivationFactory({
					preserveExplicitToolSelection: true,
					injectPromptPacket: composition.injectPromptPackets,
				}),
			],
			...createReconResourceLoaderOptions({ includeBuiltinSkill: composition.injectPromptPackets }),
		});
		await resourceLoader.reload();
		const harness = await createHarness({ resourceLoader, initialActiveToolNames: [], allowedToolNames: [] });
		await harness.session.bindExtensions({});
		try {
			const context = await captureNextContext(harness, "audit https://example.test/api for IDOR");
			expect(context.toolNames).toEqual([]);
			expect(context.systemPrompt).toContain("CUSTOM_ONLY\n\nUSER_APPEND");
			expect(context.systemPrompt).not.toContain("REPI execution kernel");
			expect(context.systemPrompt).not.toContain("## REPI route");
			expect(context.systemPrompt).not.toContain("## REPI capability");
			expect(context.systemPrompt).not.toContain("reverse-pentest-orchestrator");
			expect(context.systemPromptTokens).toBeLessThan(64);
		} finally {
			harness.cleanup();
		}
	});

	it("does not accumulate runtime packets across long continuation dialogs", async () => {
		const harness = await createRealRepiHarness(runtimeDir, "long-dialog");
		try {
			const turns = [
				await captureNextContext(harness, ROUTE_PROMPTS.web),
				await captureNextContext(harness, "继续"),
				await captureNextContext(harness, "继续"),
				await captureNextContext(harness, "继续"),
			];
			const count = (text: string, marker: string): number => text.split(marker).length - 1;

			for (const turn of turns) {
				expect(count(turn.systemPrompt, "REPI state:")).toBeLessThanOrEqual(1);
				expect(count(turn.systemPrompt, "## REPI capability")).toBeLessThanOrEqual(1);
				expect(turn.systemPromptBytes).toBeLessThan(4 * 1024);
			}
			expect(turns[2].systemPrompt).not.toContain("REPI state:");
			expect(turns[3].systemPrompt).not.toContain("REPI state:");
			expect(turns[2].systemPromptBytes).toBe(turns[3].systemPromptBytes);
			expect(turns[3].systemPrompt).not.toMatch(/memory|retrieval|dispatcher|worker dump/i);
		} finally {
			harness.cleanup();
		}
	});
});
