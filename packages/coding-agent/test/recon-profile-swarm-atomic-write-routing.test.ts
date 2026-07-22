import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// opt #162: 8 swarm-runtime state writes (runtimeManifest,
// child-session transcript, worker runtime pool bridge, worker lease scheduler,
// claim ledger, structured claim merge, subagent runtime manifest index, and
// the swarm artifact itself) used bare writeFileSync (truncate-then-write). A
// torn write left truncated JSON/JSONL that the swarm verifier re-reads with no
// error → silent corruption. They now route through atomicWriteFileSync (the
// #41 helper, temp+rename, 0o644) — same doctrine as #43/#103/#161.
//
// A behavioral inode-change probe (like #161) is infeasible here at proportionate
// cost: writeSwarmArtifact calls ensureReconStorage() (provisions skill/prompts
// into the agent dir) and needs a many-field SwarmArtifact fixture, and the
// sibling manifest writers are module-private. The atomic BEHAVIOR is already
// pinned at the helper (opt #41). This test pins the ROUTING — that the import
// is present and each old bare-writeFileSync pattern at the converted sites is
// gone. Revert any site → its "absent" assertion fails (the old pattern returns).

const source = readFileSync(
	fileURLToPath(new URL("../src/core/repi/swarm-supervisor-runtime.ts", import.meta.url)),
	"utf-8",
);

describe("swarm runtime state writes route through atomicWriteFileSync (opt #162 routing pin)", () => {
	it("imports atomicWriteFileSync (the routing target)", () => {
		expect(source).toContain('import { atomicWriteFileSync } from "../tools/atomic-write.ts"');
	});

	it("the old bare-writeFileSync patterns at the converted sites are gone", () => {
		// Each pattern is unique to the converted call site. Reverting a site
		// brings its pattern back → the corresponding assertion fails.
		expect(source).not.toContain("writeFileSync(runtimeManifestFile,");
		expect(source).not.toContain("writeFileSync(transcriptPath,");
		expect(source).not.toContain("writeFileSync(swarm.claimLedgerPath,");
		expect(source).not.toContain("writeFileSync(swarm.structuredClaimMergePath,");
		expect(source).not.toContain("writeFileSync(swarm.subagentRuntimeManifestPath,");
		// Pool bridge + lease scheduler manifests (unique JSON shapes).
		expect(source).not.toContain("writeFileSync(path, `${JSON.stringify({ batch,");
		expect(source).not.toContain("writeFileSync(path, `${JSON.stringify({ scheduler,");
	});
});
