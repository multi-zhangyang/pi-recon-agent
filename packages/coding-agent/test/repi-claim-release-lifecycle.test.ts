import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createRegisteredReconHarness, type RegisteredReconHarness } from "./recon-profile-harness.ts";

type RuntimeTool = {
	execute: (
		id: string,
		params: Record<string, unknown>,
	) => Promise<{
		details?: { path?: string };
	}>;
};

function tool(harness: RegisteredReconHarness, name: string): RuntimeTool {
	const value = harness.tools.get(name) as RuntimeTool | undefined;
	if (!value) throw new Error(`missing tool: ${name}`);
	return value;
}

function artifactJson(path: string): Record<string, any> {
	const source = readFileSync(path, "utf8");
	const start = source.lastIndexOf("```json");
	const end = start < 0 ? -1 : source.indexOf("\n```\n", start + "```json".length);
	if (start < 0 || end <= start) throw new Error(`missing JSON block: ${path}`);
	return JSON.parse(source.slice(start + "```json".length, end).trim()) as Record<string, any>;
}

function rewriteArtifactJson(path: string, value: Record<string, any>): void {
	const source = readFileSync(path, "utf8");
	const start = source.lastIndexOf("```json");
	const end = start < 0 ? -1 : source.indexOf("\n```\n", start + "```json".length);
	if (start < 0 || end <= start) throw new Error(`missing JSON block: ${path}`);
	writeFileSync(path, `${source.slice(0, start)}\`\`\`json\n${JSON.stringify(value, null, 2)}${source.slice(end)}`);
}

describe("REPI claim-release lifecycle", () => {
	it("prepares an append-safe marker during final compilation", async () => {
		const harness = createRegisteredReconHarness("repi-claim-release-lifecycle");
		try {
			const beforeAgentStart = harness.handlers.get("before_agent_start")?.[0] as
				| ((event: Record<string, unknown>, ctx: Record<string, unknown>) => Promise<unknown>)
				| undefined;
			expect(beforeAgentStart).toBeDefined();
			await beforeAgentStart!(
				{
					type: "before_agent_start",
					prompt: "reverse ./target.elf",
					systemPrompt: "BASE",
					systemPromptOptions: {},
				},
				{ hasUI: false },
			);

			const verifierResult = await tool(harness, "re_verifier").execute("verifier", {
				action: "matrix",
				target: "./target.elf",
			});
			const verifierPath = verifierResult.details?.path;
			expect(verifierPath).toBeDefined();
			const verifier = artifactJson(verifierPath!);
			verifier.assertions = (verifier.assertions as Array<Record<string, unknown>>).map((assertion) => ({
				...assertion,
				status: "proved",
				confidence: 100,
				evidence:
					Array.isArray(assertion.evidence) && assertion.evidence.length > 0
						? assertion.evidence
						: ["fixture proof"],
				counterEvidence: [],
			}));
			verifier.contradictions = [];
			verifier.gaps = [];
			rewriteArtifactJson(verifierPath!, verifier);

			const firstResult = await tool(harness, "re_compiler").execute("compiler-1", {
				action: "final",
				target: "./target.elf",
			});
			const first = artifactJson(firstResult.details!.path!);
			expect(first.strictClaimCheck?.requiredGaps).toEqual([]);
			expect(first.strictClaimCheck?.status).toBe("pass");
			expect(first.reportPath).toEqual(expect.any(String));

			const secondResult = await tool(harness, "re_compiler").execute("compiler-2", {
				action: "final",
				target: "./target.elf",
			});
			const second = artifactJson(secondResult.details!.path!);
			expect(second.strictClaimCheck?.status).toBe("pass");
			expect(second.reportPath).toEqual(expect.any(String));
			expect(second.nextOperatorQueue).not.toContain("re_complete audit # writes local claim-release marker");
		} finally {
			harness.restore();
		}
	});
});
