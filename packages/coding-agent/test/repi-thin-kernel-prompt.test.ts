import { Buffer } from "node:buffer";
import { estimateTokens } from "@pi-recon/repi-agent-core";
import { describe, expect, it } from "vitest";
import {
	REPI_CAPABILITY_TOOLS,
	REPI_CORE_TOOL_NAMES,
	repiCapabilityProfilesForRoute,
} from "../src/core/repi/capabilities.ts";
import { REPI_TOOL_NAMES } from "../src/core/repi/profile.ts";
import {
	createReconResourceLoaderOptions,
	RECON_APPEND_SYSTEM_PROMPT,
	RECON_SKILL_CONTENT,
	RECON_SYSTEM_PROMPT,
} from "../src/core/repi/resources.ts";
import { routeRepiTask } from "../src/core/repi/routes.ts";
import { resolveRepiPromptComposition } from "../src/main.ts";
import { createRegisteredReconHarness } from "./recon-profile-harness.ts";

const KNOWN_REPI_TOOL_NAMES = new Set<string>([...REPI_TOOL_NAMES, "re_capabilities"]);
const CORE_REPI_TOOL_NAMES = new Set<string>(REPI_CORE_TOOL_NAMES);

function repiToolReferences(text: string): string[] {
	return [...new Set(text.match(/\bre_[a-z0-9_]+\b/g) ?? [])].filter((name) => KNOWN_REPI_TOOL_NAMES.has(name)).sort();
}

function activeToolsForPrompt(prompt: string): Set<string> {
	const route = routeRepiTask(prompt);
	const active = new Set<string>(REPI_CORE_TOOL_NAMES);
	for (const profile of repiCapabilityProfilesForRoute(route)) {
		if (profile === "all") continue;
		for (const name of REPI_CAPABILITY_TOOLS[profile]) active.add(name);
	}
	return active;
}

describe("REPI thin-kernel prompt surface", () => {
	it("keeps the always-resident contract below its byte and token budgets", () => {
		const prompt = [RECON_SYSTEM_PROMPT, RECON_APPEND_SYSTEM_PROMPT].join("\n\n");
		const deferredReferences = repiToolReferences(prompt).filter((name) => !CORE_REPI_TOOL_NAMES.has(name));

		expect(Buffer.byteLength(prompt, "utf8")).toBeLessThan(1536);
		expect(estimateTokens({ role: "user", content: prompt, timestamp: 0 })).toBeLessThan(350);
		expect(deferredReferences).toEqual([]);
		expect(prompt).not.toContain("models.json");
		expect(prompt).not.toContain("MemoryPolicy");
	});

	it("keeps the on-demand orchestrator skill below 4KB", () => {
		expect(Buffer.byteLength(RECON_SKILL_CONTENT, "utf8")).toBeLessThan(4 * 1024);
		expect(estimateTokens({ role: "user", content: RECON_SKILL_CONTENT, timestamp: 0 })).toBeLessThan(1024);
		expect(RECON_SKILL_CONTENT).not.toContain("REPI self-configuration support");
		expect(RECON_SKILL_CONTENT).not.toContain("re_decision_core");
	});

	it("lets an explicit custom system prompt replace every REPI prompt segment", () => {
		const composition = resolveRepiPromptComposition({
			recon: true,
			systemPrompt: "CUSTOM_ONLY",
			appendSystemPrompt: ["USER_APPEND"],
		});

		expect(composition).toEqual({
			systemPrompt: "CUSTOM_ONLY",
			appendSystemPrompt: ["USER_APPEND"],
			injectPromptPackets: false,
		});
		expect(composition.appendSystemPrompt).not.toContain(RECON_APPEND_SYSTEM_PROMPT);
		expect(createReconResourceLoaderOptions({ includeBuiltinSkill: false }).skillsOverride).toBeUndefined();
	});

	it("keeps security route packets below 512 bytes and free of disk summaries", async () => {
		const harness = createRegisteredReconHarness("repi-thin-runtime-packet");
		try {
			const beforeAgentStart = harness.handlers.get("before_agent_start")?.[0] as
				| ((
						event: Record<string, unknown>,
						ctx: Record<string, unknown>,
				  ) => Promise<{ systemPrompt?: string } | undefined>)
				| undefined;
			expect(beforeAgentStart).toBeDefined();

			for (const prompt of [
				"audit https://example.test/api for IDOR",
				`audit https://example.test/long-input for IDOR ${"测".repeat(5000)}`,
				"reverse the ELF binary ./license-check",
				"analyze capture.pcap and recover the protocol flow",
				"audit prompt injection across an LLM agent MCP boundary",
			]) {
				const injected = await beforeAgentStart!(
					{ type: "before_agent_start", prompt, systemPrompt: "BASE", systemPromptOptions: {} },
					{ hasUI: false },
				);
				const packet = injected?.systemPrompt?.slice("BASE\n\n".length) ?? "";
				const active = activeToolsForPrompt(prompt);
				const inactiveReferences = repiToolReferences(packet).filter((name) => !active.has(name));

				expect(Buffer.byteLength(packet, "utf8")).toBeLessThan(512);
				expect(packet).toMatch(/^REPI state: /);
				expect(packet.split("\n")).toHaveLength(1);
				expect(packet).not.toContain("Mission blackboard:");
				expect(packet).not.toContain("Evidence ledger tail:");
				expect(packet).not.toContain("active_tools=");
				expect(inactiveReferences).toEqual([]);
			}

			const ordinary = await beforeAgentStart!(
				{
					type: "before_agent_start",
					prompt: "summarize this ordinary source tree",
					systemPrompt: "BASE",
					systemPromptOptions: {},
				},
				{ hasUI: false },
			);
			expect(ordinary).toBeUndefined();

			const continued = await beforeAgentStart!(
				{ type: "before_agent_start", prompt: "继续", systemPrompt: "BASE", systemPromptOptions: {} },
				{ hasUI: false },
			);
			expect(continued?.systemPrompt).toContain("REPI state: ");
			expect(continued?.systemPrompt).toContain("continuation=true");
			const repeatedContinuation = await beforeAgentStart!(
				{ type: "before_agent_start", prompt: "继续", systemPrompt: "BASE", systemPromptOptions: {} },
				{ hasUI: false },
			);
			expect(repeatedContinuation).toBeUndefined();
		} finally {
			harness.restore();
		}
	});
});
