import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

type ContextCompactAudit = {
	ok: boolean;
	summary: { categories: number; passed: number; failed: number; markers: number };
	categories: Array<{
		id: string;
		status: "pass" | "fail";
		checks: Array<{ file: string; exists: boolean; markers: number; missing: string[]; status: "pass" | "fail" }>;
	}>;
};

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const auditScript = join(repoRoot, "scripts/reverse-agent/context-compact-audit.mjs");

function runAudit(): ContextCompactAudit {
	return JSON.parse(
		execFileSync("node", [auditScript, repoRoot, "--json"], { encoding: "utf-8" }),
	) as ContextCompactAudit;
}

describe("REPI context compact audit harness", () => {
	it("keeps context, compact, evidence summary, budget, and continuation markers wired", () => {
		const audit = runAudit();
		const categoryIds = audit.categories.map((category) => category.id);

		expect(audit.ok).toBe(true);
		expect(audit.summary.failed).toBe(0);
		expect(audit.summary.markers).toBeGreaterThan(80);
		expect(categoryIds).toEqual(
			expect.arrayContaining([
				"context_pack",
				"owned_compaction_provider",
				"resume_contract_continuation",
				"evidence_summarization",
				"budget_continuation",
				"runtime_tests",
				"docs_contract",
			]),
		);
		expect(audit.categories.flatMap((category) => category.checks.flatMap((check) => check.missing))).toEqual([]);
	});
});
