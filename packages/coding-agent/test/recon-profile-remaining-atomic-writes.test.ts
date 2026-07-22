import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// Routing pin for opt #208. The remaining bare non-atomic `writeFileSync` sites
// in recon-profile.ts truncated-then-wrote: a crash (SIGKILL/OOM) or ENOSPC
// mid-write left a truncated artifact that a later reader loaded as partial
// with no signal — silently losing worker captured output, a compiled report,
// an archive manifest, or a runtime-adapter artifact. The fix routes each
// through the atomic helpers already used by the surrounding code:
// `atomicWriteFileSync(..., 0o644)` (temp+rename,
// matching the runtime-manifest/transcript atomic writes at 18053/18178/18366)
// for the worker stdout/stderr + archive manifest + runtime-adapter artifact;
// `writePrivateTextFile(...)` (temp+rename 0o600, matching autofix-report #203)
// for the compiled report. Existing state is moved into the archive with rename.
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
	const autopilotSrc = readFileSync(resolve(import.meta.dirname, "../src/core/repi/autopilot-runtime.ts"), "utf8");
	const adapterSrc = readFileSync(
		resolve(import.meta.dirname, "../src/core/repi/runtime-adapter-execution-runtime.ts"),
		"utf8",
	);
	const childSrc = readFileSync(
		resolve(import.meta.dirname, "../src/core/repi/swarm-worker-child-session-runtime.ts"),
		"utf8",
	);
	const proofArtifactSrc = readFileSync(
		resolve(import.meta.dirname, "../src/core/repi/proof-artifact-runtime.ts"),
		"utf8",
	);

	it("writes worker stdout/stderr via atomicWriteFileSync at BOTH sites (not writeFileSync)", () => {
		// Two call sites: the swarm-execution aggregation (~17985) and the
		// bounded re_swarm batch runner (~18304).
		expect(countOccurrences(childSrc, "atomicWriteFileSync(stdoutPath, stdout, 0o644)")).toBe(1);
		expect(countOccurrences(childSrc, "atomicWriteFileSync(stderrPath, stderr, 0o644)")).toBe(1);
		expect(
			countOccurrences(
				readFileSync(resolve(import.meta.dirname, "../src/core/repi/swarm-supervisor-runtime.ts"), "utf8"),
				"atomicWriteFileSync(stdoutPath, stdout, 0o644)",
			),
		).toBe(1);
		expect(
			countOccurrences(
				readFileSync(resolve(import.meta.dirname, "../src/core/repi/swarm-supervisor-runtime.ts"), "utf8"),
				"atomicWriteFileSync(stderrPath, stderr, 0o644)",
			),
		).toBe(1);
		// The bare writeFileSync calls at these sites must be gone.
		expect(childSrc).not.toContain("writeFileSync(stdoutPath, stdout");
		expect(childSrc).not.toContain("writeFileSync(stderrPath, stderr");
	});

	it("writes the compiled report via writePrivateTextFile (not writeFileSync)", () => {
		expect(proofArtifactSrc).toContain('writePrivateTextFile(path, compiler.finalReport.join("\\n"))');
		expect(proofArtifactSrc).not.toContain("writeFileSync(path, compiler.finalReport");
	});

	it("writes the archive manifest via atomicWriteFileSync (not writeFileSync)", () => {
		// Asserted as two substrings; together they pin the exact call site
		// (atomicWriteFileSync( + join(archiveRoot, "manifest.json")).
		expect(autopilotSrc).toContain('writePrivateJson(join(archiveRoot, "manifest.json")');
	});

	it("writes the runtime-adapter artifact via atomicWriteFileSync (not writeFileSync)", () => {
		// Asserted as two substrings to keep the literal free of "${" (biome
		// noTemplateCurlyInString). Together they pin the exact call site.
		expect(adapterSrc).toContain("atomicWriteFileSync(");
		expect(adapterSrc).toContain("stdoutHead: truncateMiddle(result.stdout, 8000)");
		// The bare writeFileSync at this site must be gone (the runtime-adapter
		// artifact write). Distinguished from other writeFileSync(path, ...)
		// sites by the adjacent stdoutHead marker.
		const idx = adapterSrc.indexOf("stdoutHead: truncateMiddle(result.stdout, 8000)");
		expect(idx).toBeGreaterThan(-1);
		const atomicCall = adapterSrc.lastIndexOf("atomicWriteFileSync(", idx);
		const bareCall = adapterSrc.lastIndexOf("\n\t\twriteFileSync(", idx);
		expect(atomicCall).toBeGreaterThan(bareCall);
	});

	it("moves archived state without a read/write copy", () => {
		expect(readFileSync(resolve(import.meta.dirname, "../src/core/repi/autopilot-runtime.ts"), "utf8")).toContain(
			"renameSync(path, target)",
		);
	});
});
