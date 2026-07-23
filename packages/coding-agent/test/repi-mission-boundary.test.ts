import { describe, expect, it } from "vitest";
import { readCurrentMission } from "../src/core/repi/mission.ts";
import { createRegisteredReconHarness } from "./recon-profile-harness.ts";

type BeforeAgentStart = (
	event: Record<string, unknown>,
	ctx: Record<string, unknown>,
) => Promise<{ systemPrompt?: string } | undefined>;

describe("REPI sticky mission boundary", () => {
	it("keeps follow-ups sticky but starts a new mission for a different explicit target", async () => {
		const harness = createRegisteredReconHarness("repi-mission-boundary");
		try {
			const beforeAgentStart = harness.handlers.get("before_agent_start")?.[0] as BeforeAgentStart | undefined;
			expect(beforeAgentStart).toBeDefined();
			const send = (prompt: string) =>
				beforeAgentStart!(
					{ type: "before_agent_start", prompt, systemPrompt: "BASE", systemPromptOptions: {} },
					{ hasUI: false },
				);

			await send("reverse ./alpha.elf");
			const firstId = readCurrentMission()?.id;
			expect(firstId).toBeDefined();

			await send("inspect the imports and comparison path");
			expect(readCurrentMission()?.id).toBe(firstId);
			const continuation = await send("继续");
			expect(readCurrentMission()?.id).toBe(firstId);
			expect(continuation?.systemPrompt).toContain("continuation=true");

			const switched = await send("reverse ./beta.elf");
			const secondId = readCurrentMission()?.id;
			expect(secondId).toBeDefined();
			expect(secondId).not.toBe(firstId);
			expect(switched?.systemPrompt).toContain(`mission=${secondId}`);
			expect(readCurrentMission()?.task).toBe("reverse ./beta.elf");
		} finally {
			harness.restore();
		}
	});

	it("keeps different paths on the same web origin in one mission", async () => {
		const harness = createRegisteredReconHarness("repi-web-mission-boundary");
		try {
			const beforeAgentStart = harness.handlers.get("before_agent_start")?.[0] as BeforeAgentStart;
			const send = (prompt: string) =>
				beforeAgentStart(
					{ type: "before_agent_start", prompt, systemPrompt: "BASE", systemPromptOptions: {} },
					{ hasUI: false },
				);
			await send("audit https://example.test/api for IDOR");
			const missionId = readCurrentMission()?.id;
			await send("check auth on https://example.test/admin");
			expect(readCurrentMission()?.id).toBe(missionId);
		} finally {
			harness.restore();
		}
	});

	it("persists the latest explicit operator directive without replacing the mission", async () => {
		const harness = createRegisteredReconHarness("repi-active-directive");
		try {
			const beforeAgentStart = harness.handlers.get("before_agent_start")?.[0] as BeforeAgentStart;
			const send = (prompt: string) =>
				beforeAgentStart(
					{ type: "before_agent_start", prompt, systemPrompt: "BASE", systemPromptOptions: {} },
					{ hasUI: false },
				);
			await send("audit https://example.test/api for IDOR");
			const missionId = readCurrentMission()?.id;
			const revision = readCurrentMission()?.directiveRevision;
			const packet = await send("只检查对象归属，不扩展扫描");
			const mission = readCurrentMission();
			expect(mission?.id).toBe(missionId);
			expect(mission?.operatorDirective).toBe("只检查对象归属，不扩展扫描");
			expect(mission?.directiveRevision).toBeGreaterThan(revision ?? 0);
			expect(packet?.systemPrompt).toContain("directive=只检查对象归属，不扩展扫描");
			await send("继续");
			expect(readCurrentMission()?.operatorDirective).toBe("只检查对象归属，不扩展扫描");
		} finally {
			harness.restore();
		}
	});

	it("does not promote ordinary conversation into an operator directive", async () => {
		const harness = createRegisteredReconHarness("repi-ordinary-conversation");
		try {
			const beforeAgentStart = harness.handlers.get("before_agent_start")?.[0] as BeforeAgentStart;
			const send = (prompt: string) =>
				beforeAgentStart(
					{ type: "before_agent_start", prompt, systemPrompt: "BASE", systemPromptOptions: {} },
					{ hasUI: false },
				);
			await send("reverse ./alpha.elf");
			const directive = readCurrentMission()?.operatorDirective;
			await send("I only have a question about the status");
			expect(readCurrentMission()?.operatorDirective).toBe(directive);
		} finally {
			harness.restore();
		}
	});
});
