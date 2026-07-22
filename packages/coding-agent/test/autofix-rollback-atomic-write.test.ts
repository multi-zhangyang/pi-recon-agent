import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// Routing pin for opt #203. `buildRepairRollbackPolicyFromAutofix` (baseline
// snapshot) and `writeAutofixRepairRollbackPolicy` (policy report) in
// failure-runtime.ts used bare non-atomic `writeFileSync` — a crash (SIGKILL/OOM)
// mid-write left truncated JSON that readers silently skip, losing the
// rollback baseline / policy. The fix routes both through `writePrivateTextFile`
// (atomic temp+rename 0o600, the same helper the surrounding autofix state
// writes use: marker ~4180, repair queue ~4596).
//
// A behavioral pin is infeasible here: the two functions are not exported and
// are deeply coupled (artifact-hash reads, ledger appends, runtime-path
// resolution), so isolating them would require exporting + an extensive mock
// surface. We assert the wiring is present in the source instead.
// Neuter-pin: revert either call to `writeFileSync(..., "utf-8")` → the
// corresponding `writePrivateTextFile(...)` assertion fails AND the
// `writeFileSync(baselinePath` / `writeFileSync(reportPath` "absent" assertion
// fails.
describe("autofix repair-rollback writes are atomic (opt #203 routing pin)", () => {
	const src = readFileSync(resolve(import.meta.dirname, "../src/core/repi/failure-runtime.ts"), "utf8");

	it("writes the rollback baseline snapshot via writePrivateTextFile (not writeFileSync)", () => {
		expect(src).toMatch(/writePrivateTextFile\(\s*baselinePath,/);
		// The bare writeFileSync call at this site must be gone.
		expect(src).not.toMatch(/writeFileSync\(\s*baselinePath,/);
	});

	it("writes the rollback policy report via writePrivateTextFile (not writeFileSync)", () => {
		// Asserted as two substrings to keep the literal free of "${" (biome
		// noTemplateCurlyInString). Together they pin the exact call site.
		expect(src).toContain("writePrivateTextFile(reportPath, ");
		expect(src).toContain("JSON.stringify({ report, validation }, null, 2)");
		expect(src).not.toContain("writeFileSync(reportPath, ");
	});
});
