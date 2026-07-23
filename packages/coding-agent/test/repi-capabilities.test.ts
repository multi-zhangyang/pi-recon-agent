import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Context, fauxAssistantMessage, fauxToolCall, getModel } from "@pi-recon/repi-ai";
import { Type } from "typebox";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import {
	createRepiCapabilityActivationFactory,
	isRepiReadOnlyTask,
	REPI_CAPABILITY_PROFILE_NAMES,
	REPI_CAPABILITY_TOOLS,
	REPI_CORE_TOOL_NAMES,
	REPI_DELEGATION_TOOL_NAMES,
	REPI_ROUTE_CONTRACT_TOOL_NAMES,
	repiCapabilityProfilesForRoute,
	repiPromptNeedsWriteTools,
	selectRepiCapabilityTools,
} from "../src/core/repi/capabilities.ts";
import { REPI_TOOL_NAMES } from "../src/core/repi/profile.ts";
import { isRepiTask, repiTaskRequiresDelegation, routeRepiTask } from "../src/core/repi/routes.ts";
import { DefaultResourceLoader } from "../src/core/resource-loader.ts";
import { createAgentSession } from "../src/core/sdk.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import { createHarness } from "./suite/harness.ts";

const CONDITIONAL_TOOLS = ["goal_complete", "third_party_tool"];

function registerTestTools(pi: ExtensionAPI): void {
	for (const name of [...REPI_TOOL_NAMES, ...CONDITIONAL_TOOLS]) {
		pi.registerTool({
			name,
			label: name,
			description: `${name} test tool`,
			parameters: Type.Object({}),
			async execute() {
				return { content: [{ type: "text" as const, text: name }], details: {} };
			},
		});
	}
}

describe("REPI progressive capability activation", () => {
	let tempDir: string;
	let agentDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-capabilities-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
	});

	afterEach(() => {
		if (existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("keeps all tools registered while exposing only the focused core by default", async () => {
		const settingsManager = SettingsManager.create(tempDir, agentDir);
		const resourceLoader = new DefaultResourceLoader({
			cwd: tempDir,
			agentDir,
			settingsManager,
			extensionFactories: [registerTestTools, createRepiCapabilityActivationFactory()],
		});
		await resourceLoader.reload();
		const { session } = await createAgentSession({
			cwd: tempDir,
			agentDir,
			model: getModel("anthropic", "claude-sonnet-4-5")!,
			settingsManager,
			sessionManager: SessionManager.inMemory(tempDir),
			resourceLoader,
		});

		await session.bindExtensions({});

		const registered = session.getAllTools().map((tool) => tool.name);
		const active = session.getActiveToolNames();
		expect(registered).toContain("re_swarm");
		expect(active).toContain("re_capabilities");
		expect(active).not.toContain("grep");
		expect(active).not.toContain("find");
		expect(active).not.toContain("ls");
		expect(active).toContain("goal_complete");
		expect(active).toContain("third_party_tool");
		expect(active).not.toContain("edit");
		expect(active).not.toContain("write");
		expect(active).not.toContain("re_route");
		expect(active).not.toContain("re_techniques");
		expect(active).not.toContain("re_subagent");
		expect(active).not.toContain("re_swarm");
		expect(active.length).toBeLessThan(registered.length / 2);

		session.dispose();
	});

	it("preserves an explicit SDK/CLI tool allowlist", async () => {
		const settingsManager = SettingsManager.create(tempDir, agentDir);
		const resourceLoader = new DefaultResourceLoader({
			cwd: tempDir,
			agentDir,
			settingsManager,
			extensionFactories: [
				registerTestTools,
				createRepiCapabilityActivationFactory({ preserveExplicitToolSelection: true }),
			],
		});
		await resourceLoader.reload();
		const { session } = await createAgentSession({
			cwd: tempDir,
			agentDir,
			model: getModel("anthropic", "claude-sonnet-4-5")!,
			settingsManager,
			sessionManager: SessionManager.inMemory(tempDir),
			resourceLoader,
			tools: ["read", "edit", "write", "re_swarm"],
		});

		await session.bindExtensions({});

		expect(session.getActiveToolNames()).toEqual(["read", "edit", "write", "re_swarm"]);
		session.dispose();
	});

	it("keeps progressive activation when a CLI denylist excludes one tool", async () => {
		const harness = await createHarness({
			excludedToolNames: ["re_swarm"],
			extensionFactories: [registerTestTools, createRepiCapabilityActivationFactory()],
		});
		await harness.session.bindExtensions({});

		const registered = harness.session.getAllTools().map((tool) => tool.name);
		expect(registered).not.toContain("re_swarm");
		expect(harness.session.getActiveToolNames()).not.toContain("re_subagent");
		expect(harness.session.getActiveToolNames().length).toBeLessThan(registered.length / 2);

		let providerTools: string[] = [];
		harness.setResponses([
			(context) => {
				providerTools = context.tools?.map((tool) => tool.name) ?? [];
				return fauxAssistantMessage("done");
			},
		]);
		await harness.session.prompt("audit https://example.test/api authorization");

		expect(providerTools).toContain("re_web_authz_state");
		expect(providerTools).not.toContain("re_swarm");
		expect(providerTools.length).toBeLessThan(20);
		harness.cleanup();
	});

	it("exposes re_subagent without the orchestration profile for an explicit knowledge gap", async () => {
		const harness = await createHarness({
			extensionFactories: [registerTestTools, createRepiCapabilityActivationFactory()],
		});
		await harness.session.bindExtensions({});

		const turns: string[][] = [];
		harness.setResponses([
			(context) => {
				turns.push(context.tools?.map((tool) => tool.name) ?? []);
				return fauxAssistantMessage("researched");
			},
			(context) => {
				turns.push(context.tools?.map((tool) => tool.name) ?? []);
				return fauxAssistantMessage("known path");
			},
			(context) => {
				turns.push(context.tools?.map((tool) => tool.name) ?? []);
				return fauxAssistantMessage("ordinary path");
			},
		]);

		await harness.session.prompt(
			"Reverse ./mystery.elf; I do not know how to analyze its VM bytecode and need to research it",
		);
		await harness.session.prompt("Reverse ./known.elf with Ghidra and trace the comparison");
		await harness.session.prompt("summarize this ordinary source tree");

		expect(turns[0]).toEqual(expect.arrayContaining(["re_subagent", "re_exploit_lab", "re_runtime_adapter"]));
		expect(turns[0]).not.toContain("re_delegate");
		expect(turns[0]).not.toContain("re_swarm");
		expect(turns[0]).not.toContain("re_supervisor");
		expect(turns[1]).not.toContain("re_subagent");
		expect(turns[2]).not.toContain("re_subagent");
		harness.cleanup();
	});

	it("recognizes explicit English and Chinese read-only task signals", () => {
		expect(isRepiReadOnlyTask("Perform a read-only source audit")).toBe(true);
		expect(isRepiReadOnlyTask("Inspect this repository; do not modify any files")).toBe(true);
		expect(isRepiReadOnlyTask("对当前仓库做只读审计，不要修改任何文件")).toBe(true);
		expect(isRepiReadOnlyTask("Fix the failing test and update its fixture")).toBe(false);
		expect(repiPromptNeedsWriteTools("summarize this ordinary source tree")).toBe(false);
		expect(repiPromptNeedsWriteTools("audit the repository and report findings")).toBe(false);
		expect(repiPromptNeedsWriteTools("Fix the failing test and update its fixture")).toBe(true);
		expect(repiPromptNeedsWriteTools("Fix the failing test, but do not modify any files")).toBe(false);
		expect(repiPromptNeedsWriteTools("Build a todo app with local persistence")).toBe(true);
		expect(repiPromptNeedsWriteTools("Add dark mode")).toBe(true);
		expect(repiPromptNeedsWriteTools("Create a TypeScript CLI that prints hello")).toBe(true);
		expect(repiPromptNeedsWriteTools("你现在对这个项目进行重构")).toBe(true);
		expect(repiPromptNeedsWriteTools("audit DELETE /users endpoint for IDOR")).toBe(false);
		expect(repiPromptNeedsWriteTools("analyze the change management API")).toBe(false);
	});

	it("maps task routes to one focused domain without preloading proof", () => {
		expect(REPI_CAPABILITY_PROFILE_NAMES).not.toContain("all");
		expect(isRepiTask("audit https://example.test/orders")).toBe(true);
		expect(isRepiTask("recover an RSA private key from nonce reuse")).toBe(true);
		expect(isRepiTask("summarize this ordinary source tree")).toBe(false);
		expect(routeRepiTask("recover an RSA private key from nonce reuse and a lattice relation").domain).toBe(
			"Crypto / stego",
		);
		expect(routeRepiTask("trace crypto.subtle signing in this JavaScript bundle").domain).toBe("Frontend JS reverse");
		expect(
			routeRepiTask(
				"Run a generic Web black-box review of https://example.test/ with browser evidence and principal boundaries",
			).domain,
		).toBe("Web / API pentest");
		expect(routeRepiTask("inspect the principal boundary in an iOS IPA").domain).toBe("Mobile / iOS");
		expect(repiCapabilityProfilesForRoute(routeRepiTask("audit https://example.test/api auth"))).toEqual(["web"]);
		expect(repiCapabilityProfilesForRoute(routeRepiTask("reverse ./target.elf and build a ROP chain"))).toEqual([
			"native",
		]);
		expect(repiCapabilityProfilesForRoute(routeRepiTask("analyze app.apk with Frida"))).toEqual(["mobile"]);
		const cryptoCtfTask = "solve this RSA nonce challenge";
		expect(repiCapabilityProfilesForRoute(routeRepiTask(cryptoCtfTask), cryptoCtfTask)).toEqual(["crypto"]);
		expect(
			repiCapabilityProfilesForRoute(
				routeRepiTask("CTF challenge"),
				"CTF challenge with a JWT API, RSA oracle, and PCAP",
			),
		).toEqual(["web", "crypto", "forensics"]);
		expect(repiCapabilityProfilesForRoute(routeRepiTask("inspect an unknown artifact"))).toEqual([]);
	});

	it("requires delegation only for explicit REPI knowledge gaps", () => {
		const required = [
			"Reverse ./mystery.elf; I do not know how to analyze its VM bytecode",
			"Reverse ./mystery.elf; I do not know this VM format; do not research it",
			"Need to research an unfamiliar Kerberos delegation technique before testing AD",
			"对这个 APK 里的陌生协议先查资料再逆向",
			"这个 ELF 我不懂怎么分析",
			"Native reverse\n这个协议我不熟悉",
			"Native reverse\n这个我不会，派发子代理查",
			"Delegate a specialist to inspect the suspicious PCAP flow",
		];
		for (const task of required) expect(repiTaskRequiresDelegation(task), task).toBe(true);

		const ordinary = [
			"summarize this ordinary source tree; I do not know this framework",
			"inspect an unknown artifact",
			"research the API authorization flow",
			"Reverse ./known.elf locally; do not research or delegate",
		];
		for (const task of ordinary) expect(repiTaskRequiresDelegation(task), task).toBe(false);
	});

	it("adds only re_subagent for a knowledge-gap route", () => {
		const selected = selectRepiCapabilityTools({
			availableToolNames: [
				...REPI_CORE_TOOL_NAMES,
				"re_exploit_lab",
				"re_runtime_adapter",
				"re_lane_specialist_pack",
				"re_subagent",
				"re_delegate",
				"re_swarm",
				"re_supervisor",
			],
			activeToolNames: [...REPI_CORE_TOOL_NAMES],
			profiles: ["native"],
			requiredToolNames: REPI_DELEGATION_TOOL_NAMES,
		});

		expect(selected).toEqual(
			expect.arrayContaining([
				...REPI_CORE_TOOL_NAMES,
				"re_exploit_lab",
				"re_runtime_adapter",
				"re_lane_specialist_pack",
				"re_subagent",
			]),
		);
		expect(selected).not.toContain("re_delegate");
		expect(selected).not.toContain("re_swarm");
		expect(selected).not.toContain("re_supervisor");
	});

	it("activates route profiles without dropping initially active third-party tools", () => {
		const available = [
			"read",
			"grep",
			"re_capabilities",
			"re_route",
			"re_live_browser",
			"re_web_authz_state",
			"re_native_runtime",
			"re_verifier",
			"third_party_tool",
		];
		const selected = selectRepiCapabilityTools({
			availableToolNames: available,
			activeToolNames: ["read", "re_live_browser", "re_native_runtime", "third_party_tool"],
			profiles: ["web", "proof"],
		});

		expect(selected).toEqual(["read", "third_party_tool", "re_capabilities", "re_web_authz_state", "re_verifier"]);
	});

	it("gives every routed professional profile an execution and verification contract", () => {
		const available = [...REPI_TOOL_NAMES, "read", "bash", "re_capabilities", "goal_complete"];
		const routeCases = [
			["audit https://example.test/api auth", "re_runtime_adapter"],
			["reverse ./target.elf and trace the comparison", "re_runtime_adapter"],
			["analyze app.apk with Frida", "re_runtime_adapter"],
			["recover an RSA key from nonce reuse", "re_runtime_adapter"],
			["analyze capture.pcap with tshark", "re_runtime_adapter"],
			["audit prompt injection across an LLM tool boundary", "re_runtime_adapter"],
		] as const;

		for (const [prompt, domainExecutor] of routeCases) {
			const profiles = repiCapabilityProfilesForRoute(routeRepiTask(prompt), prompt);
			const selected = selectRepiCapabilityTools({
				availableToolNames: available,
				activeToolNames: [],
				profiles,
			});
			expect(selected, prompt).toEqual(expect.arrayContaining([...REPI_ROUTE_CONTRACT_TOOL_NAMES, domainExecutor]));
			expect(selected, prompt).not.toContain("re_route");
			expect(selected, prompt).not.toContain("re_mission");
			expect(selected, prompt).not.toContain("re_tool_index");
			expect(selected, prompt).not.toContain("re_swarm");
		}
	});

	it("keeps every registered REPI tool reachable through a public capability profile", () => {
		const reachable = new Set([...REPI_CORE_TOOL_NAMES, ...Object.values(REPI_CAPABILITY_TOOLS).flat()]);
		expect(REPI_TOOL_NAMES.filter((name) => !reachable.has(name))).toEqual([]);
		expect(REPI_CAPABILITY_TOOLS.orchestration).toContain("re_subagent");
	});

	it("keeps write tools out of an all-profile activation unless the task allows mutation", () => {
		const available = ["read", "edit", "write", "re_capabilities", "re_swarm"];
		const readOnly = selectRepiCapabilityTools({
			availableToolNames: available,
			activeToolNames: available,
			profiles: ["all"],
		});
		const readWrite = selectRepiCapabilityTools({
			availableToolNames: available,
			activeToolNames: readOnly,
			profiles: ["all"],
			allowWriteTools: true,
		});

		expect(readOnly).toEqual(["read", "re_capabilities", "re_swarm"]);
		expect(readWrite).toEqual(["read", "re_capabilities", "re_swarm", "edit", "write"]);
	});

	it("preserves a third-party tool activated after session start", async () => {
		const harness = await createHarness({
			initialActiveToolNames: ["read"],
			extensionFactories: [registerTestTools, createRepiCapabilityActivationFactory()],
		});
		await harness.session.bindExtensions({});
		harness.session.setActiveToolsByName([...harness.session.getActiveToolNames(), "third_party_tool"]);

		let providerTools: string[] = [];
		harness.setResponses([
			(context) => {
				providerTools = context.tools?.map((tool) => tool.name) ?? [];
				return fauxAssistantMessage("done");
			},
		]);
		await harness.session.prompt("audit https://example.test/api authorization");

		expect(providerTools).toContain("third_party_tool");
		expect(providerTools).toContain("re_web_authz_state");
		harness.cleanup();
	});

	it("keeps the focused route for an elliptical continue follow-up", async () => {
		const harness = await createHarness({
			extensionFactories: [registerTestTools, createRepiCapabilityActivationFactory()],
		});
		await harness.session.bindExtensions({});
		const turns: string[][] = [];
		harness.setResponses([
			(context) => {
				turns.push(context.tools?.map((tool) => tool.name) ?? []);
				return fauxAssistantMessage("mapped");
			},
			(context) => {
				turns.push(context.tools?.map((tool) => tool.name) ?? []);
				return fauxAssistantMessage("continued");
			},
		]);

		await harness.session.prompt("audit https://example.test/api authorization");
		await harness.session.prompt("继续");

		expect(turns).toHaveLength(2);
		expect(turns[0]).toContain("re_web_authz_state");
		expect(turns[1]).toContain("re_web_authz_state");
		harness.cleanup();
	});

	it("keeps ordinary coding write tools across an elliptical continue follow-up", async () => {
		const harness = await createHarness({
			extensionFactories: [registerTestTools, createRepiCapabilityActivationFactory()],
		});
		await harness.session.bindExtensions({});
		const turns: string[][] = [];
		harness.setResponses([
			(context) => {
				turns.push(context.tools?.map((tool) => tool.name) ?? []);
				return fauxAssistantMessage("implemented");
			},
			(context) => {
				turns.push(context.tools?.map((tool) => tool.name) ?? []);
				return fauxAssistantMessage("continued");
			},
		]);

		await harness.session.prompt("Refactor the project implementation and update its tests");
		await harness.session.prompt("继续");

		expect(turns).toHaveLength(2);
		expect(turns[0]).toContain("edit");
		expect(turns[0]).toContain("write");
		expect(turns[1]).toContain("edit");
		expect(turns[1]).toContain("write");
		harness.cleanup();
	});

	it("rejects the retired all profile without exposing write or orchestration tools", async () => {
		const harness = await createHarness({
			extensionFactories: [registerTestTools, createRepiCapabilityActivationFactory()],
		});
		await harness.session.bindExtensions({});

		let firstTurnTools: string[] = [];
		let secondTurnTools: string[] = [];
		harness.setResponses([
			(context) => {
				firstTurnTools = context.tools?.map((tool) => tool.name) ?? [];
				return fauxAssistantMessage(
					fauxToolCall("re_capabilities", { action: "activate", profile: "all", mode: "replace" }),
					{ stopReason: "toolUse" },
				);
			},
			(context) => {
				secondTurnTools = context.tools?.map((tool) => tool.name) ?? [];
				return fauxAssistantMessage("done");
			},
		]);

		await harness.session.prompt("Perform a read-only audit of https://example.test/api; do not modify files");

		expect(firstTurnTools).toContain("re_web_authz_state");
		expect(firstTurnTools).not.toContain("edit");
		expect(firstTurnTools).not.toContain("write");
		expect(secondTurnTools).not.toContain("re_swarm");
		expect(secondTurnTools).not.toContain("edit");
		expect(secondTurnTools).not.toContain("write");
		harness.cleanup();
	});

	it("restores edit and write for tasks which permit workspace changes", async () => {
		const harness = await createHarness({
			extensionFactories: [registerTestTools, createRepiCapabilityActivationFactory()],
		});
		await harness.session.bindExtensions({});

		let providerTools: string[] = [];
		harness.setResponses([
			(context) => {
				providerTools = context.tools?.map((tool) => tool.name) ?? [];
				return fauxAssistantMessage("done");
			},
		]);
		await harness.session.prompt("Fix the API authorization handler and update its tests");

		expect(providerTools).toContain("re_web_authz_state");
		expect(providerTools).toContain("edit");
		expect(providerTools).toContain("write");
		harness.cleanup();
	});

	it("does not carry write tools from a mutation task into a new read-only task", async () => {
		const harness = await createHarness({
			extensionFactories: [registerTestTools, createRepiCapabilityActivationFactory()],
		});
		await harness.session.bindExtensions({});

		const turns: string[][] = [];
		harness.setResponses([
			(context) => {
				turns.push(context.tools?.map((tool) => tool.name) ?? []);
				return fauxAssistantMessage("fixed");
			},
			(context) => {
				turns.push(context.tools?.map((tool) => tool.name) ?? []);
				return fauxAssistantMessage("audited");
			},
		]);

		await harness.session.prompt("Fix the API authorization handler and update its tests");
		await harness.session.prompt("Perform a read-only audit of https://example.test/api; do not modify files");

		expect(turns[0]).toEqual(expect.arrayContaining(["edit", "write"]));
		expect(turns[1]).not.toContain("edit");
		expect(turns[1]).not.toContain("write");
		harness.cleanup();
	});

	it("injects capability metadata only for security tasks and supports custom-prompt suppression", async () => {
		const ordinaryHarness = await createHarness({
			extensionFactories: [registerTestTools, createRepiCapabilityActivationFactory()],
		});
		await ordinaryHarness.session.bindExtensions({});
		let ordinarySystemPrompt = "";
		ordinaryHarness.setResponses([
			(context) => {
				ordinarySystemPrompt = context.systemPrompt ?? "";
				return fauxAssistantMessage("done");
			},
		]);
		await ordinaryHarness.session.prompt("summarize this ordinary source tree");
		expect(ordinarySystemPrompt).not.toContain("## REPI capability");
		ordinaryHarness.cleanup();

		const customHarness = await createHarness({
			extensionFactories: [registerTestTools, createRepiCapabilityActivationFactory({ injectPromptPacket: false })],
		});
		await customHarness.session.bindExtensions({});
		let customSystemPrompt = "";
		let customToolNames: string[] = [];
		customHarness.setResponses([
			(context) => {
				customSystemPrompt = context.systemPrompt ?? "";
				customToolNames = context.tools?.map((tool) => tool.name) ?? [];
				return fauxAssistantMessage("done");
			},
		]);
		await customHarness.session.prompt("audit https://example.test/api authorization");
		expect(customSystemPrompt).not.toContain("## REPI capability");
		expect(customToolNames).toContain("re_web_authz_state");
		customHarness.cleanup();
	});

	it("makes a capability activated by a tool available on the next provider turn", async () => {
		const harness = await createHarness({
			extensionFactories: [
				registerTestTools,
				(pi) => {
					pi.on("before_agent_start", (event) => ({
						systemPrompt: `${event.systemPrompt}\n\nREPI_RUNTIME_PACKET`,
					}));
				},
				createRepiCapabilityActivationFactory(),
			],
		});
		await harness.session.bindExtensions({});

		let firstTurnTools: NonNullable<Context["tools"]> = [];
		let secondTurnTools: NonNullable<Context["tools"]> = [];
		let firstTurnSystemPrompt = "";
		let secondTurnSystemPrompt = "";
		harness.setResponses([
			(context) => {
				firstTurnTools = context.tools ?? [];
				firstTurnSystemPrompt = context.systemPrompt ?? "";
				return fauxAssistantMessage(
					fauxToolCall("re_capabilities", { action: "activate", profile: "orchestration" }),
					{ stopReason: "toolUse" },
				);
			},
			(context) => {
				secondTurnTools = context.tools ?? [];
				secondTurnSystemPrompt = context.systemPrompt ?? "";
				return fauxAssistantMessage("done");
			},
		]);

		await harness.session.prompt("audit https://example.test/api authorization");

		const firstTurnToolNames = firstTurnTools.map((tool) => tool.name);
		const secondTurnToolNames = secondTurnTools.map((tool) => tool.name);
		expect(firstTurnToolNames).toContain("re_web_authz_state");
		expect(firstTurnToolNames).not.toContain("re_swarm");
		expect(secondTurnToolNames).toContain("re_swarm");
		expect(secondTurnToolNames).toContain("re_web_authz_state");
		expect(secondTurnTools.slice(0, firstTurnTools.length)).toEqual(firstTurnTools);
		const capabilityPacketMarker = "\n\n## REPI capability";
		const firstStablePrefix = firstTurnSystemPrompt.slice(0, firstTurnSystemPrompt.indexOf(capabilityPacketMarker));
		const secondStablePrefix = secondTurnSystemPrompt.slice(
			0,
			secondTurnSystemPrompt.indexOf(capabilityPacketMarker),
		);
		expect(firstStablePrefix.length).toBeGreaterThan(100);
		expect(secondStablePrefix).toBe(firstStablePrefix);
		expect(secondTurnSystemPrompt).toContain("REPI_RUNTIME_PACKET");
		expect(secondTurnSystemPrompt).toContain("## REPI capability");
		expect(secondTurnSystemPrompt).not.toContain("initial_active_repi_tools");
		harness.cleanup();
	});

	it("keeps an explicit capability across continuation turns but clears it for a new task", async () => {
		const harness = await createHarness({
			extensionFactories: [registerTestTools, createRepiCapabilityActivationFactory()],
		});
		await harness.session.bindExtensions({});

		const providerTurns: string[][] = [];
		harness.setResponses([
			(context) => {
				providerTurns.push(context.tools?.map((tool) => tool.name) ?? []);
				return fauxAssistantMessage(
					fauxToolCall("re_capabilities", { action: "activate", profile: "orchestration" }),
					{ stopReason: "toolUse" },
				);
			},
			(context) => {
				providerTurns.push(context.tools?.map((tool) => tool.name) ?? []);
				return fauxAssistantMessage("activated");
			},
			(context) => {
				providerTurns.push(context.tools?.map((tool) => tool.name) ?? []);
				return fauxAssistantMessage("continued");
			},
			(context) => {
				providerTurns.push(context.tools?.map((tool) => tool.name) ?? []);
				return fauxAssistantMessage("new task");
			},
		]);

		await harness.session.prompt("audit https://example.test/api authorization");
		await harness.session.prompt("继续");
		await harness.session.prompt("reverse ./target.elf and trace the comparison");

		expect(providerTurns).toHaveLength(4);
		expect(providerTurns[0]).not.toContain("re_swarm");
		expect(providerTurns[1]).toContain("re_swarm");
		expect(providerTurns[2]).toContain("re_swarm");
		expect(providerTurns[3]).toContain("re_runtime_adapter");
		expect(providerTurns[3]).not.toContain("re_swarm");
		harness.cleanup();
	});
});
