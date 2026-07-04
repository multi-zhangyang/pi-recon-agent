import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_BRANCH_ID = "REPI_BRANCH_ID";

describe("REPI kernel profile specialist runtime planning", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousBranchId: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-profile-specialist-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		previousBranchId = process.env[ENV_BRANCH_ID];
		process.env[ENV_AGENT_DIR] = agentDir;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) {
			delete process.env[ENV_AGENT_DIR];
		} else {
			process.env[ENV_AGENT_DIR] = previousAgentDir;
		}
		if (previousBranchId === undefined) {
			delete process.env[ENV_BRANCH_ID];
		} else {
			process.env[ENV_BRANCH_ID] = previousBranchId;
		}
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("plans specialist runtime command packs for top reverse and pentest lanes", async () => {
		const tools = new Map<string, unknown>();
		const fakePi = {
			registerCommand() {},
			registerTool(tool: { name: string }) {
				tools.set(tool.name, tool);
			},
			on() {},
			appendEntry() {},
			getSessionName: () => undefined,
			setSessionName() {},
			sendMessage() {},
			exec: async () => ({ code: 0, stdout: "", stderr: "", killed: false }),
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);

		const missionTool = tools.get("re_mission") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const laneTool = tools.get("re_lane") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const planFor = async (task: string, lane: string, target: string) => {
			await missionTool.execute("tool-call-id", { action: "new", task });
			const result = await laneTool.execute("tool-call-id", { action: "plan", lane, target });
			return result.content[0]?.text ?? "";
		};

		const webPlan = await planFor("Web API JWT auth websocket replay", "surface", "https://target.local/app");
		expect(webPlan).toContain("route: Web / API pentest");
		expect(webPlan).toContain("specialist_runtime_planner: browser/XHR/WS");
		expect(webPlan).toContain("browser-xhr-ws-capture-scaffold");
		expect(webPlan).toContain("localStorage");
		expect(webPlan).toContain("websocket");
		expect(webPlan).toContain("browser-xhr-ws-auth-diff-scaffold");
		expect(webPlan).toContain("browser-cdp-artifact-scaffold");
		expect(webPlan).toContain("browser-replay-evaluator-scaffold");
		expect(webPlan).toContain("browser-route-graph-scaffold");
		expect(webPlan).toContain("browser-auth-matrix-scaffold");
		expect(webPlan).toContain("browser-idor-bola-probe-scaffold");
		expect(webPlan).toContain("browser-authz-state-machine-scaffold");
		expect(webPlan).toContain("browser-authz-sequence-replay-scaffold");
		expect(webPlan).toContain("browser-authz-object-ownership-scaffold");
		expect(webPlan).toContain("browser-authz-state-rollback-scaffold");
		expect(webPlan).toContain("web-api-authz-static-scaffold");
		expect(webPlan).toContain("web-api-schema-diff-scaffold");
		expect(webPlan).toContain("web-api-state-source-scaffold");
		expect(webPlan).toContain("/tmp/repi-browser-artifact.json");

		const webScanPlan = await planFor("nuclei ffuf katana web 漏洞扫描", "scope", "https://target.local");
		expect(webScanPlan).toContain("route: Web pentest scanning");
		expect(webScanPlan).toContain("specialist_runtime_planner: web vulnerability scanner/triage");
		expect(webScanPlan).toContain("web-scan-scope-baseline");
		expect(webScanPlan).toContain("web-scan-crawl-corpus-scaffold");
		expect(webScanPlan).toContain("web-scan-content-discovery-scaffold");
		expect(webScanPlan).toContain("web-scan-template-scan-scaffold");
		expect(webScanPlan).toContain("web-scan-manual-replay-verifier");

		const jsPlan = await planFor("JS 签名 sign 参数 crypto.subtle fetch", "observe", "https://target.local/app.js");
		expect(jsPlan).toContain("route: Frontend JS reverse");
		expect(jsPlan).toContain("JS signing rebuild");
		expect(jsPlan).toContain("js-signing-rebuild-browser-hooks");
		expect(jsPlan).toContain("crypto.subtle");
		expect(jsPlan).toContain("XMLHttpRequest");
		expect(jsPlan).toContain("js-signing-rebuild-node-scaffold");
		expect(jsPlan).toContain("js-signing-observation-normalizer");
		expect(jsPlan).toContain("js-signing-first-divergence-scaffold");
		expect(jsPlan).toContain("js-signing-replay-harness-scaffold");

		const nativePlan = await planFor("ELF native reverse license patch symbolic fuzz", "control-flow", "./license");
		expect(nativePlan).toContain("route: Native reverse");
		expect(nativePlan).toContain("specialist_runtime_planner: native deep reverse/pwn");
		expect(nativePlan).toContain("native-deep-symbol-map-scaffold");
		expect(nativePlan).toContain("native-deep-decompiler-project-scaffold");
		expect(nativePlan).toContain("native-deep-compare-trace-scaffold");
		expect(nativePlan).toContain("native-deep-patch-hypothesis-scaffold");
		expect(nativePlan).toContain("native-deep-symbolic-fuzz-scaffold");
		expect(nativePlan).toContain("/tmp/repi-native-symbolic-fuzz.py");

		const pwnPlan = await planFor("pwn ret2libc heap exploit", "primitive", "./vuln");
		expect(pwnPlan).toContain("route: Pwn / exploit");
		expect(pwnPlan).toContain("pwn primitive");
		expect(pwnPlan).toContain("native-deep-symbol-map-scaffold");
		expect(pwnPlan).toContain("pwn-primitive-cyclic-crash");
		expect(pwnPlan).toContain("pwn-primitive-offset-analyzer");
		expect(pwnPlan).toContain("pwn-primitive-rop-libc-scaffold");
		expect(pwnPlan).toContain("pwn-primitive-local-verifier");
		expect(pwnPlan).toContain("pwn-advanced-heap-tcache-scaffold");
		expect(pwnPlan).toContain("pwn-advanced-format-string-scaffold");
		expect(pwnPlan).toContain("pwn-advanced-srop-ret2dlresolve-scaffold");
		expect(pwnPlan).toContain("pwn-advanced-one-gadget-constraints");
		expect(pwnPlan).toContain("pwn-advanced-seccomp-sandbox-scaffold");
		expect(pwnPlan).toContain("ROPgadget");
		expect(pwnPlan).toContain("pwntools");

		const exploitPlan = await planFor("autopwn exploit reliability poc replay matrix", "replay", "./exploit.py");
		expect(exploitPlan).toContain("route: Exploit reliability");
		expect(exploitPlan).toContain("specialist_runtime_planner: exploit reliability/autopwn");
		expect(exploitPlan).toContain("exploit-poc-normalizer-scaffold");
		expect(exploitPlan).toContain("exploit-replay-matrix-scaffold");
		expect(exploitPlan).toContain("exploit-environment-pin-scaffold");
		expect(exploitPlan).toContain("exploit-flake-triage-scaffold");
		expect(exploitPlan).toContain("exploit-artifact-bundle-scaffold");

		const pcapPlan = await planFor("分析 pcap 流量", "map", "capture.pcapng");
		expect(pcapPlan).toContain("PCAP/DFIR flow");
		expect(pcapPlan).toContain("pcap-flow-conversations");
		expect(pcapPlan).toContain("pcap-flow-stream-rank");
		expect(pcapPlan).toContain("pcap-flow-secret-timeline");
		expect(pcapPlan).toContain("tshark -r");
		expect(pcapPlan).toContain("conv,tcp");
		expect(pcapPlan).toContain("export-objects http");
		expect(pcapPlan).toContain("pcap-flow-transform-chain");

		const memoryPlan = await planFor("volatility vmem memory dump 内存取证", "image-info", "mem.vmem");
		expect(memoryPlan).toContain("route: Memory forensics");
		expect(memoryPlan).toContain("specialist_runtime_planner: memory forensics");
		expect(memoryPlan).toContain("memory-forensics-image-info-scaffold");
		expect(memoryPlan).toContain("memory-forensics-process-network-scaffold");
		expect(memoryPlan).toContain("memory-forensics-credential-artifact-scaffold");
		expect(memoryPlan).toContain("memory-forensics-timeline-carve-scaffold");

		const firmwarePlan = await planFor("OpenWrt firmware binwalk squashfs rootfs mips", "inventory", "router.bin");
		expect(firmwarePlan).toContain("route: Firmware / IoT");
		expect(firmwarePlan).toContain("specialist_runtime_planner: Firmware/IoT rootfs");
		expect(firmwarePlan).toContain("firmware-static-fingerprint-scaffold");
		expect(firmwarePlan).toContain("firmware-extract-rootfs-scaffold");
		expect(firmwarePlan).toContain("firmware-filesystem-config-secret-scaffold");
		expect(firmwarePlan).toContain("firmware-service-surface-scaffold");
		expect(firmwarePlan).toContain("firmware-emulation-scaffold");

		const agentSecPlan = await planFor("LLM agent prompt injection MCP tool call memory poisoning", "surface", ".");
		expect(agentSecPlan).toContain("route: Agent / LLM boundary");
		expect(agentSecPlan).toContain("specialist_runtime_planner: agent prompt/tool boundary");
		expect(agentSecPlan).toContain("agent-prompt-surface-map");
		expect(agentSecPlan).toContain("agent-tool-boundary-scaffold");
		expect(agentSecPlan).toContain("agent-memory-poisoning-scaffold");
		expect(agentSecPlan).toContain("agent-injection-replay-harness");
		expect(agentSecPlan).toContain("agent-delegation-trace-scaffold");

		const malwarePlan = await planFor("malware sample yara capa floss c2 ioc config", "triage", "./sample.bin");
		expect(malwarePlan).toContain("route: Malware analysis");
		expect(malwarePlan).toContain("specialist_runtime_planner: malware config/IOC");
		expect(malwarePlan).toContain("malware-static-triage-scaffold");
		expect(malwarePlan).toContain("malware-yara-capa-floss-scaffold");
		expect(malwarePlan).toContain("malware-ioc-config-scaffold");
		expect(malwarePlan).toContain("malware-behavior-trace-scaffold");

		const cloudPlan = await planFor("K8s cloud metadata serviceaccount privilege", "identity", ".");
		expect(cloudPlan).toContain("route: Cloud / container");
		expect(cloudPlan).toContain("specialist_runtime_planner: Cloud/K8s identity");
		expect(cloudPlan).toContain("cloud-identity-config-map");
		expect(cloudPlan).toContain("cloud-runtime-config-scaffold");
		expect(cloudPlan).toContain("cloud-metadata-probe-scaffold");
		expect(cloudPlan).toContain("cloud-privilege-edge-scaffold");

		const adPlan = await planFor("AD kerberos ldap certipy bloodhound credential graph", "principals", "10.0.0.5");
		expect(adPlan).toContain("route: Identity / Windows / AD");
		expect(adPlan).toContain("specialist_runtime_planner: Identity/AD graph");
		expect(adPlan).toContain("identity-ad-principal-enum-scaffold");
		expect(adPlan).toContain("identity-ad-credential-usability-scaffold");
		expect(adPlan).toContain("identity-ad-graph-scaffold");

		const iosPlan = await planFor("iOS IPA Keychain NSURLSession TLS pinning Frida", "ipa-inventory", "app.ipa");
		expect(iosPlan).toContain("route: Mobile / iOS");
		expect(iosPlan).toContain("specialist_runtime_planner: iOS IPA/mobile runtime");
		expect(iosPlan).toContain("ios-ipa-inventory-scaffold");
		expect(iosPlan).toContain("ios-macho-class-map-scaffold");
		expect(iosPlan).toContain("ios-frida-objection-hook-scaffold");
		expect(iosPlan).toContain("ios-network-replay-scaffold");

		const fridaPlan = await planFor("Android APK frida bypass", "runtime-proof", "./app.apk");
		expect(fridaPlan).toContain("Frida/GDB trace");
		expect(fridaPlan).toContain("frida-gdb-trace-hook-template");
		expect(fridaPlan).toContain("Java.perform");
		expect(fridaPlan).toContain("Module.findExportByName");
	});
});
