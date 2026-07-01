import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// Routing pin for opt #208. Six remaining bare non-atomic `writeFileSync` sites
// in recon-profile.ts truncated-then-wrote: a crash (SIGKILL/OOM) or ENOSPC
// mid-write left a truncated artifact that a later reader loaded as partial
// with no signal — silently losing worker captured output, a compiled report,
// the tool-call-trace report, an archive manifest, a runtime-adapter artifact,
// or an archived copy. The fix routes each through the atomic helpers already
// used by the surrounding code: `atomicWriteFileSync(..., 0o644)` (temp+rename,
// matching the runtime-manifest/transcript atomic writes at 18053/18178/18366)
// for the worker stdout/stderr + archive manifest + runtime-adapter artifact +
// archive copy; `writePrivateTextFile(...)` (temp+rename 0o600, matching the
// autofix-report #203 and the tool-trace ledger #48) for the compiled report
// + tool-call-trace report.
//
// A behavioral pin is infeasible: these functions are not exported and are
// deeply coupled (worker execution aggregation, compiler artifact build,
// ledger append + incremental cache, archive tree, evidence append). We assert
// the wiring is present in the source instead. Neuter-pin: revert any call to
// `writeFileSync(..., "utf-8")` → the corresponding "present" assertion fails
// AND the matching bare-`writeFileSync(...)` "absent" assertion fails.

function countOccurrences(haystack: string, needle: string): number {
	let count = 0;
	let i = 0;
	for (;;) {
		const next = haystack.indexOf(needle, i);
		if (next === -1) break;
		count++;
		i = next + needle.length;
	}
	return count;
}

describe("recon-profile remaining writes are atomic (opt #208 routing pin)", () => {
	const src = readFileSync(resolve(import.meta.dirname, "../src/core/recon-profile.ts"), "utf8");

	it("writes worker stdout/stderr via atomicWriteFileSync at BOTH sites (not writeFileSync)", () => {
		// Two call sites: the swarm-execution aggregation (~17985) and the
		// bounded re_swarm batch runner (~18304).
		expect(countOccurrences(src, "atomicWriteFileSync(stdoutPath, stdout, 0o644)")).toBe(2);
		expect(countOccurrences(src, "atomicWriteFileSync(stderrPath, stderr, 0o644)")).toBe(2);
		// The bare writeFileSync calls at these sites must be gone.
		expect(src).not.toContain("writeFileSync(stdoutPath, stdout");
		expect(src).not.toContain("writeFileSync(stderrPath, stderr");
	});

	it("writes the compiled report via writePrivateTextFile (not writeFileSync)", () => {
		expect(src).toContain('writePrivateTextFile(path, compiler.finalReport.join("\\n"))');
		expect(src).not.toContain("writeFileSync(path, compiler.finalReport");
	});

	it("writes the tool-call-trace report via writePrivateTextFile at BOTH sites (not writeFileSync)", () => {
		// Incremental build (~29650) + full build (~29947).
		expect(countOccurrences(src, "writePrivateTextFile(toolCallTraceReportPath()")).toBe(2);
		expect(src).not.toContain("writeFileSync(toolCallTraceReportPath()");
	});

	it("writes the archive manifest via atomicWriteFileSync (not writeFileSync)", () => {
		// Asserted as two substrings; together they pin the exact call site
		// (atomicWriteFileSync( + join(archiveRoot, "manifest.json")).
		expect(src).toContain('atomicWriteFileSync(\n\t\tjoin(archiveRoot, "manifest.json")');
		expect(src).not.toContain('writeFileSync(\n\t\tjoin(archiveRoot, "manifest.json")');
	});

	it("writes the runtime-adapter artifact via atomicWriteFileSync (not writeFileSync)", () => {
		// Asserted as two substrings to keep the literal free of "${" (biome
		// noTemplateCurlyInString). Together they pin the exact call site.
		expect(src).toContain("atomicWriteFileSync(path, ");
		expect(src).toContain("stdoutHead: truncateMiddle(result.stdout, 8000)");
		// The bare writeFileSync at this site must be gone (the runtime-adapter
		// artifact write). Distinguished from other writeFileSync(path, ...)
		// sites by the adjacent stdoutHead marker.
		const idx = src.indexOf("stdoutHead: truncateMiddle(result.stdout, 8000)");
		expect(idx).toBeGreaterThan(-1);
		// Walk back to the start of the statement containing this marker and
		// confirm it opens with atomicWriteFileSync, not writeFileSync.
		const lineStart = src.lastIndexOf("\n", idx) + 1;
		const statementHead = src.slice(lineStart, idx).trimStart();
		expect(statementHead.startsWith("atomicWriteFileSync(")).toBe(true);
		expect(statementHead.startsWith("writeFileSync(")).toBe(false);
	});

	it("writes the archived copy via atomicWriteFileSync (not writeFileSync)", () => {
		expect(src).toContain("atomicWriteFileSync(archived, text, 0o644)");
		expect(src).not.toContain('writeFileSync(archived, text, "utf-8")');
	});
});
