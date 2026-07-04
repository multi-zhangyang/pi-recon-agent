import { describe, expect, it } from "vitest";
import {
	classifyRepiProofLoopGap,
	formatRepiProofLoopGapClassifier,
	type RepiProofLoopGapItem,
	repiProofLoopCommandTarget,
	repiProofLoopQuickPathFromItems,
	repiProofLoopSpecialistQueueFromItems,
	repiProofLoopWorkerForText,
} from "../src/core/repi/proof-loop.ts";

function gap(text: string, overrides: Partial<RepiProofLoopGapItem> = {}): RepiProofLoopGapItem {
	return {
		source: "artifact",
		text,
		worker: "general",
		sourceArtifacts: [],
		...overrides,
	};
}

describe("REPI proof-loop pure planner", () => {
	it("routes gap text to specialist workers without loading the full recon profile", () => {
		expect(repiProofLoopWorkerForText("XHR GraphQL JWT cookie replay failed")).toBe("web-authz");
		expect(repiProofLoopWorkerForText("APK frida hook pinning TrustManager")).toBe("mobile-runtime");
		expect(repiProofLoopWorkerForText("SIGSEGV rip overflow rop leak libc")).toBe("pwn-exploit");
		expect(repiProofLoopWorkerForText("pcap rootfs binwalk tshark timeline")).toBe("firmware-dfir");
		expect(repiProofLoopWorkerForText("final report compiler writeup")).toBe("reporting");
	});

	it("classifies proof gaps into executable repair lanes", () => {
		expect(classifyRepiProofLoopGap(gap("verifier artifact missing: run re_verifier matrix")).klass).toBe(
			"missing_artifact",
		);
		expect(classifyRepiProofLoopGap(gap("counter_evidence refutes the replay claim")).klass).toBe("contradiction");
		expect(classifyRepiProofLoopGap(gap("command not found: gdb")).klass).toBe("tool_or_dependency");
		expect(classifyRepiProofLoopGap(gap("failed: replay exit=1 stderr=nonce mismatch")).klass).toBe("replay_failure");
		expect(
			classifyRepiProofLoopGap(
				gap("attack_graph gap: runtime adapter missing proof: web-cdp-network-adapter: CDP network capture", {
					source: "attack_graph",
				}),
			).klass,
		).toBe("runtime_adapter_gap");
		expect(classifyRepiProofLoopGap(gap("weak=2 missing=1 low confidence transcript")).klass).toBe("weak_evidence");
	});

	it("builds a bounded verifier→compiler→replayer→autofix quick path", () => {
		const commands = repiProofLoopQuickPathFromItems(
			[
				gap("compiler artifact missing: run re_compiler draft before proof-loop completion"),
				gap("failed: replay exit=1 stderr=nonce mismatch", { source: "replayer" }),
			],
			"target.bin",
		);
		expect(commands).toEqual([
			"re_verifier matrix target.bin",
			"re_compiler draft target.bin",
			"re_replayer run target.bin 1",
			"re_autofix plan target.bin",
			"re_autofix apply target.bin",
			"re_replayer run target.bin 2",
			"re_proof_loop run target.bin 4 2",
		]);
	});

	it("turns attack-graph runtime adapter proof gaps into an executable adapter→proof spine", () => {
		const commands = repiProofLoopQuickPathFromItems(
			[
				gap("attack_graph gap: runtime adapter missing proof: web-cdp-network-adapter: request order proof", {
					source: "attack_graph",
					worker: "web-authz",
				}),
			],
			"https://target.local/app",
		);
		expect(commands).toEqual([
			"re_graph build",
			"re_runtime_adapter run web-cdp-network-adapter https://target.local/app",
			"re_verifier matrix https://target.local/app",
			"re_compiler draft https://target.local/app",
			"re_replayer run https://target.local/app 1",
			"re_autofix plan https://target.local/app",
			"re_proof_loop run https://target.local/app 4 2",
		]);
	});

	it("formats sorted classifier and delegate queue rows with target-safe suffixes", () => {
		const rows = formatRepiProofLoopGapClassifier([
			gap("some ambiguous low-signal item"),
			gap("counter_evidence says signed replay is false", { worker: "reporting", sourceArtifacts: ["/tmp/a"] }),
		]);
		expect(rows[0]).toContain("priority=1 class=contradiction");
		expect(rows[1]).toContain("priority=4 class=unknown");
		expect(repiProofLoopCommandTarget("  ./vuln  ")).toBe(" ./vuln");
		expect(
			repiProofLoopSpecialistQueueFromItems([gap("artifact missing", { worker: "native-runtime" })], "./vuln")[0],
		).toContain("proof-gap:1:native-runtime");
		expect(
			repiProofLoopSpecialistQueueFromItems([gap("artifact missing", { worker: "native-runtime" })], "./vuln")[0],
		).toContain("re_delegate plan ./vuln");
	});
});
