import { describe, expect, it } from "vitest";
import {
	type AttackGraphArtifact,
	type AttackGraphTaskTreeNode,
	formatAttackGraphArtifactMarkdown,
	prioritizeAttackGraphTaskTree,
} from "../src/core/repi/graph.ts";

function taskNode(index: number, overrides: Partial<AttackGraphTaskTreeNode> = {}): AttackGraphTaskTreeNode {
	return {
		id: `node-${index}`,
		parentId: "mission:1",
		kind: "command",
		label: `low-value command ${index}`,
		status: "recorded",
		command: `echo ${index}`,
		...overrides,
	};
}

describe("REPI attack graph task-tree prioritization", () => {
	it("keeps late proof/counter-evidence/gap nodes instead of truncating by insertion order", () => {
		const nodes: AttackGraphTaskTreeNode[] = [
			{ id: "mission:1", kind: "mission", label: "mission" },
			...Array.from({ length: 220 }, (_value, index) => taskNode(index)),
			taskNode(221, {
				id: "artifact:runtime-output",
				kind: "artifact",
				label: "stdout sha256=abc",
				status: "runtime-output-hash",
				path: "/tmp/runtime.json",
				evidence: ["stdout_sha256=abc"],
			}),
			taskNode(222, {
				id: "verify:parser",
				parentId: "artifact:runtime-output",
				kind: "verification",
				label: "parser-dns-transaction => dns timeline",
				status: "rank=network matches=2",
				evidence: ["[dns-query] qname=api.target.local"],
			}),
			taskNode(223, {
				id: "counter:stale-claim",
				kind: "counter_evidence",
				label: "counter evidence refutes stale replay",
				status: "present",
			}),
			taskNode(224, {
				id: "gap:missing-proof",
				parentId: "verify:parser",
				kind: "gap",
				label: "tls sni proof",
				status: "missing-proof-exit",
				evidence: ["missing_proof=tls sni proof"],
			}),
		];

		const prioritized = prioritizeAttackGraphTaskTree(nodes, 40);
		const ids = prioritized.map((node) => node.id);

		expect(prioritized).toHaveLength(40);
		expect(ids).toContain("mission:1");
		expect(ids).toContain("artifact:runtime-output");
		expect(ids).toContain("verify:parser");
		expect(ids).toContain("counter:stale-claim");
		expect(ids).toContain("gap:missing-proof");
		expect(ids).not.toContain("node-219");
		expect(ids.indexOf("artifact:runtime-output")).toBeLessThan(ids.indexOf("verify:parser"));
		expect(ids.indexOf("verify:parser")).toBeLessThan(ids.indexOf("gap:missing-proof"));
	});

	it("formats prioritized task trees with traceable command/output/artifact links", () => {
		const graph: AttackGraphArtifact = {
			timestamp: new Date(0).toISOString(),
			nodes: [],
			edges: [],
			taskTree: prioritizeAttackGraphTaskTree(
				[
					{ id: "mission:1", kind: "mission", label: "mission" },
					...Array.from({ length: 24 }, (_value, index) => taskNode(index)),
					{
						id: "run:proof",
						parentId: "mission:1",
						kind: "run",
						label: "re_replayer run target",
						status: "blocked",
						command: "re_replayer run target 1",
						evidence: ["output_sha256=abc"],
					},
					{
						id: "artifact:proof-output",
						parentId: "run:proof",
						kind: "artifact",
						label: "proof-loop-output sha256=abc",
						status: "proof-loop-output-hash",
						path: "/tmp/proof.md",
					},
				],
				10,
			),
			criticalPath: [],
			gaps: [],
			nextActions: [],
			sourceArtifacts: [],
		};

		const markdown = formatAttackGraphArtifactMarkdown(graph);
		expect(markdown).toContain("run:proof [run]");
		expect(markdown).toContain("command=re_replayer run target 1");
		expect(markdown).toContain("evidence=output_sha256=abc");
		expect(markdown).toContain("artifact:proof-output [artifact]");
		expect(markdown).toContain("proof-loop-output-hash");
	});
});
