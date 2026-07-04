import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_BRANCH_ID = "REPI_BRANCH_ID";

vi.setConfig({ testTimeout: 60_000 });

describe("REPI kernel profile runtime/proof/swarm flows", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousBranchId: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-profile-flow-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

	it("auto-detects runtime adapters from target shape and runs the selected real runner", async () => {
		const tools = new Map<string, unknown>();
		const execCalls: Array<{ command: string; args: string[] }> = [];
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
			exec: async (command: string, args: string[]) => {
				execCalls.push({ command, args });
				if (args.join("\n").includes("[adapter-rootfs-target]")) {
					return {
						code: 0,
						stdout:
							"[adapter-rootfs-target] target=/tmp/rootfs\n/etc/passwd\n/etc/init.d/httpd\nroot:x:0:0:root:/root:/bin/sh\nconfig password=admin\n",
						stderr: "",
						killed: false,
					};
				}
				if (
					args.join("\n").includes("adapter-web-cdp-network-runner") ||
					args.join("\n").includes("repi-web-adapter-body")
				) {
					return {
						code: 0,
						stdout:
							"[http-response] status=200 url=https://target.local/app content_type=text/html bytes=128 sha256=abc\n[route-candidate] fetch('/api/orders?nonce=123')\n[crypto-request-field] nonce=123 signature=abc\n",
						stderr: "",
						killed: false,
					};
				}
				return {
					code: 0,
					stdout: "TCP Conversations <-> frames bytes\nGET /login HTTP/1.1\npassword=demo\n",
					stderr: "",
					killed: false,
				};
			},
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);
		const runtimeAdapterTool = tools.get("re_runtime_adapter") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const graphTool = tools.get("re_graph") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};

		const webPlan = await runtimeAdapterTool.execute("tool-call-id", {
			action: "plan",
			target: "https://target.local/app",
		});
		expect(webPlan.content[0]?.text).toContain("adapter:web-cdp-network-adapter");

		const pcapPlan = await runtimeAdapterTool.execute("tool-call-id", { action: "plan", target: "capture.pcap" });
		expect(pcapPlan.content[0]?.text).toContain("adapter:tshark-pcap-flow-adapter");

		const firmwarePlan = await runtimeAdapterTool.execute("tool-call-id", {
			action: "plan",
			target: "router.squashfs",
		});
		expect(firmwarePlan.content[0]?.text).toContain("adapter:binwalk-firmware-extract-adapter");

		const rootfsDir = join(agentDir, "rootfs");
		mkdirSync(join(rootfsDir, "etc", "init.d"), { recursive: true });
		mkdirSync(join(rootfsDir, "bin"), { recursive: true });
		writeFileSync(join(rootfsDir, "etc", "passwd"), "root:x:0:0:root:/root:/bin/sh\n", "utf-8");
		writeFileSync(join(rootfsDir, "etc", "init.d", "httpd"), "#!/bin/sh\nhttpd -p 80\n", "utf-8");
		writeFileSync(join(rootfsDir, "bin", "busybox"), "busybox\n", "utf-8");
		const rootfsPlan = await runtimeAdapterTool.execute("tool-call-id", {
			action: "plan",
			target: rootfsDir,
		});
		expect(rootfsPlan.content[0]?.text).toContain("adapter:firmware-rootfs-service-map-adapter");

		const gdbPlan = await runtimeAdapterTool.execute("tool-call-id", {
			action: "plan",
			target: "SIGSEGV crash in ./vuln",
		});
		expect(gdbPlan.content[0]?.text).toContain("adapter:gdb-native-trace-adapter");

		const pcapRun = await runtimeAdapterTool.execute("tool-call-id", { action: "run", target: "capture.pcap" });
		expect(execCalls[0]?.args.join("\n")).toContain("REPI_ADAPTER_TARGET");
		expect(execCalls[0]?.args.join("\n")).toMatch(/(?:strings -a 'capture\.pcap'|tshark -r 'capture\.pcap')/);
		expect(pcapRun.content[0]?.text).toContain("adapter: tshark-pcap-flow-adapter");
		expect(pcapRun.content[0]?.text).toContain("parser-tshark-conversation");

		const rootfsRun = await runtimeAdapterTool.execute("tool-call-id", { action: "run", target: rootfsDir });
		expect(execCalls[1]?.args.join("\n")).toContain("[adapter-rootfs-target]");
		expect(execCalls[1]?.args.join("\n")).toContain("find");
		expect(rootfsRun.content[0]?.text).toContain("adapter: firmware-rootfs-service-map-adapter");
		expect(rootfsRun.content[0]?.text).toContain("parser-rootfs-passwd");
		expect(rootfsRun.content[0]?.text).toContain("rootfs service map");

		const webRun = await runtimeAdapterTool.execute("tool-call-id", {
			action: "run",
			target: "https://target.local/app",
		});
		expect(webRun.content[0]?.text).toContain("adapter: web-cdp-network-adapter");
		expect(webRun.content[0]?.text).toContain("parser_signal_summary:");
		expect(webRun.content[0]?.text).toContain("request order proof");

		const graph = await graphTool.execute("tool-call-id", { action: "build" });
		const graphPath = /graph_artifact: (.+)/.exec(graph.content[0]?.text ?? "")?.[1]?.trim();
		expect(graphPath).toBeDefined();
		const graphText = readFileSync(graphPath!, "utf-8");
		expect(graphText).toContain("tool:runtime-adapter:tshark-pcap-flow-adapter");
		expect(graphText).toContain("tool:runtime-adapter:firmware-rootfs-service-map-adapter");
		expect(graphText).toContain("[target_profile]");
		expect(graphText).toContain("[parser_summary]");
		expect(graphText).toContain("parser_signal_summary");
		expect(graphText).toContain("runtime target profile");
		expect(graphText).toContain("request order proof");
		expect(graphText).toContain("--blocks:missing-proof-exit");
		expect(graphText).toContain("[command]");
		expect(graphText).toContain("runtime-adapter-json");
		expect(graphText).toContain("runtime-output-hash");
		expect(graphText).toContain("stdout_hash");
		expect(graphText).toContain("parser-tshark-conversation");
		expect(graphText).toContain("parser-rootfs-passwd");
		expect(graphText).toContain("--verifies:parser:");
	});

	it("blocks runtime adapter runs when no real native or fallback runner is available", async () => {
		const tools = new Map<string, unknown>();
		const execCalls: Array<{ command: string; args: string[] }> = [];
		const previousPath = process.env.PATH;
		const emptyPath = join(tempDir, "empty-path");
		mkdirSync(emptyPath, { recursive: true });
		process.env.PATH = emptyPath;
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
			exec: async (command: string, args: string[]) => {
				execCalls.push({ command, args });
				return { code: 0, stdout: "synthetic should not run", stderr: "", killed: false };
			},
		} as unknown as ExtensionAPI;

		try {
			createReconExtensionFactory()(fakePi);
			const runtimeAdapterTool = tools.get("re_runtime_adapter") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			const run = await runtimeAdapterTool.execute("tool-call-id", {
				action: "run",
				adapter: "frida-mobile-hook-adapter",
				target: "com.example.app",
			});
			expect(run.content[0]?.text).toContain("blocked: runner_unavailable");
			expect(run.content[0]?.text).toContain("runner_preflight_blocked_no_synthetic_success");
			expect(run.content[0]?.text).toContain("next: re_bootstrap plan frida bash");
			expect(execCalls).toHaveLength(0);
		} finally {
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
		}
	});

	it("builds an evidence task tree linking commands, artifacts, hypotheses, and counter-evidence", async () => {
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
		const evidenceTool = tools.get("re_evidence") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const graphTool = tools.get("re_graph") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};

		await missionTool.execute("tool-call-id", { action: "new", task: "verify login replay hypothesis" });
		const replayArtifact = join(agentDir, "recon", "evidence", "login-replay.txt");
		writeFileSync(replayArtifact, "HTTP/1.1 200 replay accepted\n", "utf-8");
		await evidenceTool.execute("tool-call-id", {
			action: "append",
			kind: "runtime",
			title: "login replay claim",
			fact: "hypothesis: signed login replay candidate accepted with nonce reuse",
			command: "curl -i -H 'X-Signature: demo' https://target.local/api/login",
			path: replayArtifact,
			hash: "sha256:demo",
			verify: "curl -i -H 'X-Signature: demo' https://target.local/api/login",
			confidence: "candidate hypothesis",
		});
		await evidenceTool.execute("tool-call-id", {
			action: "append",
			kind: "runtime",
			title: "anonymous negative control",
			fact: "counter_evidence: anonymous replay failed with 401, signed replay must bind Authorization",
			command: "curl -i https://target.local/api/login",
			verify: "curl -i https://target.local/api/login",
			confidence: "counter-evidence",
		});

		const graph = await graphTool.execute("tool-call-id", { action: "build" });
		expect(graph.content[0]?.text).toContain("task_tree_nodes:");
		const graphPath = /graph_artifact: (.+)/.exec(graph.content[0]?.text ?? "")?.[1]?.trim();
		expect(graphPath).toBeDefined();
		const graphText = readFileSync(graphPath!, "utf-8");
		expect(graphText).toContain("## Task Tree");
		expect(graphText).toContain("[command]");
		expect(graphText).toContain("[artifact]");
		expect(graphText).toContain("[hypothesis]");
		expect(graphText).toContain("[counter_evidence]");
		expect(graphText).toContain("--produces");
		expect(graphText).toContain("--supports");
		expect(graphText).toContain("--refutes");
	});

	it("wires proof-loop gaps into a quick verifier/replayer/autofix path", async () => {
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
		const proofLoopTool = tools.get("re_proof_loop") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const runtimeAdapterTool = tools.get("re_runtime_adapter") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const graphTool = tools.get("re_graph") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		await runtimeAdapterTool.execute("tool-call-id", {
			action: "run",
			target: "https://target.local/app",
		});
		await graphTool.execute("tool-call-id", { action: "build" });
		const proof = await proofLoopTool.execute("tool-call-id", {
			action: "plan",
			target: "https://target.local/app",
		});
		expect(proof.content[0]?.text).toContain("gap_classifier:");
		expect(proof.content[0]?.text).toContain("source=attack_graph");
		expect(proof.content[0]?.text).toContain("class=runtime_adapter_gap");
		expect(proof.content[0]?.text).toContain("class=missing_artifact");
		expect(proof.content[0]?.text).toContain("quick_path:");
		expect(proof.content[0]?.text).toContain(
			"re_runtime_adapter run web-cdp-network-adapter https://target.local/app",
		);
		expect(proof.content[0]?.text).toContain("re_verifier matrix https://target.local/app");
		expect(proof.content[0]?.text).toContain("re_replayer run https://target.local/app 1");
		expect(proof.content[0]?.text).toContain("re_autofix plan https://target.local/app");
		expect(proof.content[0]?.text).toContain("source=attack_graph_gap");

		const proofRun = await proofLoopTool.execute("tool-call-id", {
			action: "run",
			target: "https://target.local/app",
			maxSteps: 1,
			replaySteps: 1,
		});
		expect(proofRun.content[0]?.text).toContain("proof_loop:");
		expect(proofRun.content[0]?.text).toContain("executed_steps: 1");

		const graph = await graphTool.execute("tool-call-id", { action: "build" });
		const graphPath = /graph_artifact: (.+)/.exec(graph.content[0]?.text ?? "")?.[1]?.trim();
		expect(graphPath).toBeDefined();
		const graphText = readFileSync(graphPath!, "utf-8");
		expect(graphText).toContain("proof_loop plan");
		expect(graphText).toContain("quick_path");
		expect(graphText).toContain("proof-loop-gap");
		expect(graphText).toContain("proof-loop-output-hash");
		expect(graphText).toContain("output_sha256");
		expect(graphText).toContain("re_runtime_adapter run web-cdp-network-adapter https://target.local/app");
	});

	it("propagates swarm worker timeout budgets into runtime manifests", async () => {
		const tools = new Map<string, unknown>();
		const previousTimeout = process.env.REPI_SWARM_WORKER_TIMEOUT_MS;
		process.env.REPI_SWARM_WORKER_TIMEOUT_MS = "12345";
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
			exec: async () => ({ code: 0, stdout: "ok\n", stderr: "", killed: false }),
		} as unknown as ExtensionAPI;

		try {
			createReconExtensionFactory()(fakePi);
			const swarmTool = tools.get("re_swarm") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			const swarm = await swarmTool.execute("tool-call-id", {
				action: "run",
				target: "https://target.local/api/login",
				maxWorkers: 1,
				maxCommands: 1,
			});
			expect(swarm.content[0]?.text).toContain("subagent_runtime_manifests:");
			expect(swarm.content[0]?.text).toContain("timeoutMs=12345");
			expect(swarm.content[0]?.text).toContain("worker_child_session_runtime:");
			expect(swarm.content[0]?.text).toContain("pool_bridge=pass");
			expect(swarm.content[0]?.text).toContain("worker_retry_handoff_closure:");
			expect(swarm.content[0]?.text).toContain("- status=pass");
			expect(swarm.content[0]?.text).toContain("retry_attempts_bounded=pass");
		} finally {
			if (previousTimeout === undefined) delete process.env.REPI_SWARM_WORKER_TIMEOUT_MS;
			else process.env.REPI_SWARM_WORKER_TIMEOUT_MS = previousTimeout;
		}
	});

	it("retries blocked swarm workers with attempt metadata", async () => {
		const tools = new Map<string, unknown>();
		const previousRetryLimit = process.env.REPI_SWARM_RETRY_LIMIT;
		process.env.REPI_SWARM_RETRY_LIMIT = "1";
		const delegationDir = join(agentDir, "recon", "evidence", "delegations");
		mkdirSync(delegationDir, { recursive: true });
		const fixturePath = join(delegationDir, "9999-12-31T23-59-59-retry-fixture-plan.md");
		const fixtureDelegate = {
			timestamp: "9999-12-31T23:59:59.000Z",
			route: "Retry fixture",
			mode: "plan",
			packets: [
				{
					id: "worker:retry:general",
					worker: "general",
					objective: "exercise blocked-command retry metadata",
					status: "ready",
					phases: ["retry"],
					steps: [
						{
							id: "op:retry:1",
							phase: "retry",
							command: "definitely_missing_repi_retry_fixture_command",
							status: "ready",
							sourceArtifacts: [],
						},
						{
							id: "op:retry:2",
							phase: "retry",
							command: "printf retry-ok",
							status: "ready",
							sourceArtifacts: [],
						},
					],
					evidenceContract: ["command output"],
					recommendedTools: [],
					handoffPrompt: [],
					sourceArtifacts: [],
				},
			],
			mergeQueue: [],
			specialistCoverage: [],
			workerScoreboard: [],
			adaptiveRoutingHints: [],
			workerPromotionQueue: [],
			autonomousBudget: {
				maxTurns: 3,
				maxDispatch: 1,
				maxProofLoops: 1,
				maxWorkerRetries: 1,
				scoreDecay: [],
				historicalScoreDecay: [],
				demotionRules: [],
				laneDemotions: [],
				workerDemotions: [],
				dispatcherDemotions: [],
				promotionRules: [],
				playbookPromotions: [],
				ledgerRows: [],
				nextActions: [],
			},
			dispatcherScoreDecay: [],
			repeatedFailureDemotions: [],
			highScorePromotions: [],
			gaps: [],
			nextActions: [],
			sourceArtifacts: [],
		};
		writeFileSync(
			fixturePath,
			["# Retry fixture", "", "```json", JSON.stringify(fixtureDelegate, null, 2), "```", ""].join("\n"),
		);
		let execCalls = 0;
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
			exec: async () => {
				execCalls += 1;
				return execCalls === 1
					? { code: 127, stdout: "", stderr: "command not found\n", killed: false }
					: { code: 0, stdout: "retry-ok\n", stderr: "", killed: false };
			},
		} as unknown as ExtensionAPI;

		try {
			createReconExtensionFactory()(fakePi);
			const swarmTool = tools.get("re_swarm") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			const swarm = await swarmTool.execute("tool-call-id", {
				action: "run",
				maxWorkers: 1,
				maxCommands: 1,
			});
			expect(swarm.content[0]?.text).toContain("retry_execution:");
			expect(swarm.content[0]?.text).toContain("attempt=2/");
			expect(swarm.content[0]?.text).toContain("retryRemaining=");
			expect(swarm.content[0]?.text).toContain("retries=1");
			expect(swarm.content[0]?.text).toContain("worker_retry_handoff_closure:");
			expect(swarm.content[0]?.text).toContain("attempt=2/3");
			expect(swarm.content[0]?.text).toContain("failed_workers_closed=pass");
		} finally {
			if (previousRetryLimit === undefined) delete process.env.REPI_SWARM_RETRY_LIMIT;
			else process.env.REPI_SWARM_RETRY_LIMIT = previousRetryLimit;
		}
	});
});
