import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";
import { readCurrentMission } from "../src/core/repi/mission.ts";
import { toolIndexPath, writePrivateTextFile } from "../src/core/repi/storage.ts";

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_BRANCH_ID = "REPI_BRANCH_ID";

vi.setConfig({ testTimeout: 60_000 });

describe("REPI kernel profile runtime adapter and evidence graph flows", () => {
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
				if (args.join("\n").includes("emitRouteMap('fetch'") || args.join("\n").includes("repi-web-adapter-body")) {
					return {
						code: 0,
						stdout:
							"[http-response] status=200 url=https://target.local/app content_type=text/html bytes=128 sha256=abc\n[route-candidate] fetch('/api/orders?nonce=123')\n[web-signed-field] source=playwright-request field_sha256=abc field=nonce=123&signature=abc\n",
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
		expect(execCalls[0]?.args.join("\n")).toMatch(/(?:python3 - 'capture\.pcap'|tshark -r 'capture\.pcap')/);
		expect(pcapRun.content[0]?.text).toContain("adapter: tshark-pcap-flow-adapter");
		expect(pcapRun.content[0]?.text).toContain("parser-tshark-conversation");

		const rootfsRun = await runtimeAdapterTool.execute("tool-call-id", { action: "run", target: rootfsDir });
		expect(execCalls[1]?.args.join("\n")).toContain("[adapter-rootfs-target]");
		expect(execCalls[1]?.args.join("\n")).toContain("find");
		expect(rootfsRun.content[0]?.text).toContain("adapter: firmware-rootfs-service-map-adapter");
		expect(rootfsRun.content[0]?.text).toContain("parser-rootfs-passwd");
		expect(rootfsRun.content[0]?.text).toContain("rootfs service map");

		writePrivateTextFile(
			toolIndexPath(),
			[
				"| Tool | Present | Path | Version |",
				"|---|---:|---|---|",
				"| node | yes | /usr/bin/node | test |",
				"| curl | yes | /usr/bin/curl | test |",
				"| playwright | no |  |  |",
				"",
			].join("\n"),
		);

		const webRun = await runtimeAdapterTool.execute("tool-call-id", {
			action: "run",
			target: "https://target.local/app",
		});
		expect(webRun.content[0]?.text).toContain("adapter: web-cdp-network-adapter");
		expect(webRun.content[0]?.text).toContain("parser_signal_summary:");
		expect(webRun.content[0]?.text).toContain("request order proof");
		expect(webRun.content[0]?.text).toContain("evidence:");
		expect(webRun.content[0]?.text).toContain("[http-response] status=200");
		expect(webRun.content[0]?.text).toContain(
			"replay: timeout_ms=60000 command=re_runtime_adapter run web-cdp-network-adapter 'https://target.local/app'",
		);
		expect(webRun.content[0]?.text).not.toContain("adapter-web-cdp-network-runner");

		const nativeAdapterDir = join(
			agentDir,
			"recon",
			"evidence",
			"toolchain",
			"runtime-adapters",
			"gdb-native-trace-adapter",
		);
		mkdirSync(nativeAdapterDir, { recursive: true });
		writeFileSync(
			join(nativeAdapterDir, "2026-01-01T00-00-00-000Z.json"),
			`${JSON.stringify(
				{
					kind: "RuntimeAdapterExecutionArtifactV1",
					schemaVersion: 1,
					missionId: readCurrentMission()?.id,
					adapterId: "gdb-native-trace-adapter",
					domainId: "rev-native",
					bridgeId: "tool-bridge-runtime",
					target: "./vuln",
					startedAt: new Date(0).toISOString(),
					finishedAt: new Date(0).toISOString(),
					selectedRunner: "fallback",
					command: "re_runtime_adapter run gdb-native-trace-adapter ./vuln",
					exitCode: 0,
					killed: false,
					stdoutSha256: "a".repeat(64),
					stderrSha256: "b".repeat(64),
					stdoutHead: "[native-mitigation] pie=yes nx=enabled relro=partial canary=no fortify=no type=DYN\n",
					stderrHead: "",
					parserSignals: [
						{
							ruleId: "parser-native-mitigation-map",
							evidenceRank: "runtime_artifact",
							proofExitSignal: "binary mitigation map",
							matches: ["[native-mitigation]", "PIE", "RELRO"],
						},
					],
					parserSignalSummary: {
						matchedRules: 1,
						totalRules: 1,
						matchCount: 3,
						evidenceRanks: ["runtime_artifact"],
						matchedProofExitSignals: ["binary mitigation map"],
						missingProofExitSignals: [],
					},
					artifactKinds: ["native-symbol-map", "binary-mitigation-map", "runtime-adapter-transcript"],
					ingestTargets: ["evidence-ledger"],
					proofExitSignals: ["binary mitigation map"],
				},
				null,
				2,
			)}\n`,
			"utf-8",
		);

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
		expect(graphText).toContain("artifact:binary-mitigation-map:gdb-native-trace-adapter");
		expect(graphText).toContain("binary mitigation map gdb-native-trace-adapter");
		expect(graphText).toContain("pie=yes nx=enabled");
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
		mkdirSync(join(agentDir, "recon", "evidence"), { recursive: true });
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
		expect(graphText).toContain("evidence-output-hash");
		expect(graphText).toContain("evidence-output sha256=");
		expect(graphText).toContain("[hypothesis]");
		expect(graphText).toContain("[counter_evidence]");
		expect(graphText).toContain("--produces");
		expect(graphText).toContain("--supports");
		expect(graphText).toContain("--supports:command-output-hypothesis");
		expect(graphText).toContain("--refutes");
		expect(graphText).toContain("--refutes:counter-evidence-prior-hypothesis");
	});

	it("deduplicates self-review checkpoint notifications while the review is pending", async () => {
		const handlers = new Map<string, Array<(event: any, ctx: any) => Promise<any>>>();
		const notify = vi.fn();
		const appendEntry = vi.fn();
		const fakePi = {
			registerCommand() {},
			registerTool() {},
			on(event: string, handler: (event: any, ctx: any) => Promise<any>) {
				const list = handlers.get(event) ?? [];
				list.push(handler);
				handlers.set(event, list);
			},
			appendEntry,
			getSessionName: () => undefined,
			setSessionName() {},
			sendMessage() {},
			exec: async () => ({ code: 0, stdout: "", stderr: "", killed: false }),
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);
		const beforeAgentStart = handlers.get("before_agent_start")?.[0];
		const toolResult = handlers.get("tool_result")?.[0];
		expect(beforeAgentStart).toBeDefined();
		expect(toolResult).toBeDefined();

		await beforeAgentStart!(
			{
				type: "before_agent_start",
				prompt: "目标：只读审计当前 REPI harness 的逆向渗透运行问题",
				systemPrompt: "base",
				systemPromptOptions: {},
			},
			{
				hasUI: true,
				ui: { notify, setStatus: vi.fn() },
				sessionManager: { getSessionFile: () => undefined },
			},
		);

		const ctx = { hasUI: true, ui: { notify, setStatus: vi.fn() } };
		for (let index = 0; index < 10; index += 1) {
			await toolResult!(
				{
					type: "tool_result",
					toolName: "bash",
					toolCallId: `tool-${index}`,
					input: {},
					content: [{ type: "text", text: "ok" }],
					isError: false,
					details: undefined,
				},
				ctx,
			);
		}

		expect(notify).toHaveBeenCalledTimes(1);
		expect(notify).toHaveBeenCalledWith("REPI self-review checkpoint is due", "info");
		const selfReviewEntries = appendEntry.mock.calls.filter(([kind]) => kind === "repi-self-review-due");
		expect(selfReviewEntries).toEqual([]);
	});
});
