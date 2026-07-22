import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createAgentThreadManager } from "../src/core/agent-thread-manager.ts";
import { BUILTIN_AGENT_THREAD_SPECS } from "../src/core/agent-thread-policy.ts";
import {
	buildWorkerPrompt,
	normalizeWorkerGuidance,
	normalizeWorkerTask,
} from "../src/core/agent-thread-worker-runtime.ts";

describe("worker prompt input boundaries", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("redacts and bounds task and additional guidance independently", () => {
		const task = normalizeWorkerTask(`  API_KEY=super-secret-token ${"x".repeat(20_000)}  `);
		const guidance = normalizeWorkerGuidance(`Bearer abcdefghijklmnop ${"y".repeat(10_000)}`);

		expect(task.length).toBeLessThanOrEqual(12_000);
		expect(guidance?.length).toBeLessThanOrEqual(8_000);
		expect(task).not.toContain("super-secret-token");
		expect(guidance).not.toContain("abcdefghijklmnop");
		expect(task).toContain("<redacted>");
		expect(guidance).toContain("<redacted>");
	});

	it("places untrusted data in single, explicit prompt boundaries", () => {
		const verifier = BUILTIN_AGENT_THREAD_SPECS.find((spec) => spec.name === "verifier");
		expect(verifier).toBeDefined();
		const prompt = buildWorkerPrompt(
			verifier!,
			`task token=secret-value ${"a".repeat(20_000)}`,
			`guidance API_KEY=another-secret ${"b".repeat(10_000)}`,
		);

		expect(prompt.match(/<worker_task>/g)).toHaveLength(1);
		expect(prompt.match(/<\/worker_task>/g)).toHaveLength(1);
		expect(prompt.match(/<worker_additional_guidance>/g)).toHaveLength(1);
		expect(prompt.match(/<\/worker_additional_guidance>/g)).toHaveLength(1);
		expect(prompt).toContain("untrusted task data");
		expect(prompt).not.toContain("secret-value");
		expect(prompt).not.toContain("another-secret");
	});

	it("rejects whitespace-only tasks before creating a child", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-worker-boundary-"));
		const manager = createAgentThreadManager({ cwd: tempRoot, agentDir: join(tempRoot, "agent") });
		await expect(manager.spawnThread({ specName: "verifier", task: " \n\t " })).rejects.toThrow(
			"Agent thread task must not be empty",
		);
		manager.dispose();
	});
});
