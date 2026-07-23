import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_BRANCH_ID = "REPI_BRANCH_ID";
const ENV_PRODUCT = "REPI_PRODUCT";

describe("REPI kernel profile domain runtime captures", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousBranchId: string | undefined;
	let previousProduct: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-profile-domain-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		previousBranchId = process.env[ENV_BRANCH_ID];
		previousProduct = process.env[ENV_PRODUCT];
		process.env[ENV_AGENT_DIR] = agentDir;
		process.env[ENV_PRODUCT] = "1";
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
		if (previousProduct === undefined) {
			delete process.env[ENV_PRODUCT];
		} else {
			process.env[ENV_PRODUCT] = previousProduct;
		}
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("runs the exploit lab and records stability anchors", async () => {
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
				return {
					code: 0,
					stdout: [
						"[exploit-lab-env] python=3.12 platform=Linux cwd=/tmp timeout_s=7 runs=3",
						"[exploit-lab-inventory] target=./exploit.py exists=true bytes=128 sha256=abc executable=true suffix=.py",
						"[exploit-lab-replay] run=1 exit=0 duration=0.11 stdout_sha256=aaa stderr_sha256=bbb stdout_len=20 stderr_len=0 ok=true",
						"[exploit-lab-replay] run=2 exit=0 duration=0.12 stdout_sha256=aaa stderr_sha256=bbb stdout_len=20 stderr_len=0 ok=true",
						"[exploit-lab-summary] runs=3 ok=3 success_rate=1.000 stable=true unique_exits=1 unique_stdout_hashes=1",
						"[exploit-lab-flake] failures=0 timeout_or_nonzero=0 stable=true retry_budget=0",
						"[exploit-lab-bundle] manifest=/tmp/repi-exploit-lab-manifest.json artifacts=1 target=./exploit.py cmd_sha256=def",
					].join("\n"),
					stderr: "",
					killed: false,
				};
			},
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);

		const missionTool = tools.get("re_mission") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		await missionTool.execute("tool-call-id", { action: "new", task: "autopwn exploit reliability" });

		const exploitLabTool = tools.get("re_exploit_lab") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const result = await exploitLabTool.execute("tool-call-id", {
			action: "run",
			target: "./exploit.py",
			runs: 3,
			timeoutMs: 7000,
		});

		expect(execCalls).toHaveLength(1);
		expect(execCalls[0]?.args.join("\n")).toContain("repi-exploit-lab-runner.py");
		const resultText = result.content[0]?.text ?? "";
		expect(resultText).toContain("exploit_lab:");
		expect(resultText).toContain("mode: run");
		expect(resultText).toContain("executions:");
		expect(resultText).toContain("stdout_sha256=");
		expect(resultText).toContain("Exploit Lab PoC inventory anchors");
		expect(resultText).toContain("Exploit Lab replay matrix anchors");
		expect(resultText).toContain("Exploit Lab flake triage anchors");
		expect(resultText).toContain("Exploit Lab artifact bundle anchors");
		expect(resultText).not.toContain("lab_commands:");
		expect(resultText.length).toBeLessThanOrEqual(4096);
		const artifactPath = /exploit_lab_artifact: (.+)/.exec(resultText)?.[1]?.trim();
		expect(artifactPath).toBeDefined();
		expect(existsSync(artifactPath!)).toBe(true);
		const artifactText = readFileSync(artifactPath!, "utf-8");
		expect(artifactText).toContain("REPI Exploit Lab Artifact");
		expect(artifactText).toContain("lab_commands:");
		expect(artifactText).toContain("repi-exploit-lab-runner.py");
		const missionAfterLab = JSON.parse(readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8")) as {
			checkpoints: Array<{ name: string; status: string }>;
		};
		expect(missionAfterLab.checkpoints.find((gate) => gate.name === "exploit_lab_ready")?.status).toBe("done");
	});

	it("runs the mobile runtime capture and records Frida/ADB anchors", async () => {
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
				return {
					code: 0,
					stdout: [
						"[mobile-env] adb=/usr/bin/adb frida=/usr/bin/frida frida_ps=/usr/bin/frida-ps jadx=/usr/bin/jadx apktool=/usr/bin/apktool gdb=/usr/bin/gdb",
						"[mobile-apk] target=./app.apk bytes=123 sha256=abc file=Android package",
						"[mobile-device] emulator-5554 device product=sdk",
						"[mobile-process] pidof com.demo.app 1234",
						"[mobile-frida-process] 1234 com.demo.app",
						"[mobile-frida-hook-template] /tmp/repi-mobile-frida-hooks.js hooks=Java.crypto,String.equals,Debug.isDebuggerConnected,native.strcmp,memcmp",
						"[mobile-hook-line] Java.perform",
						"[mobile-crypto-hook] Cipher.doFinal in=aa",
						"[mobile-native-hook] strcmp ret=0x0",
						"[mobile-anti-debug-check] isDebuggerConnected",
					].join("\n"),
					stderr: "",
					killed: false,
				};
			},
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);

		const missionTool = tools.get("re_mission") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		await missionTool.execute("tool-call-id", { action: "new", task: "Android APK Frida anti-debug crypto" });

		const mobileRuntimeTool = tools.get("re_mobile_runtime") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const result = await mobileRuntimeTool.execute("tool-call-id", {
			action: "run",
			target: "./app.apk",
			packageName: "com.demo.app",
			timeoutMs: 9000,
		});

		expect(execCalls).toHaveLength(1);
		expect(execCalls[0]?.args.join("\n")).toContain("repi-mobile-frida-hooks.js");
		const resultText = result.content[0]?.text ?? "";
		expect(resultText).toContain("mobile_runtime:");
		expect(resultText).toContain("mode: run");
		expect(resultText).toContain("executions:");
		expect(resultText).toContain("stdout_sha256=");
		expect(resultText).toContain("mobile APK inventory anchors");
		expect(resultText).toContain("mobile device anchors");
		expect(resultText).toContain("mobile process map anchors");
		expect(resultText).toContain("mobile Frida hook template anchors");
		expect(resultText).toContain("mobile Java crypto/compare hook anchors");
		expect(resultText).toContain("mobile native compare hook anchors");
		expect(resultText).toContain("mobile anti-debug/root check anchors");
		expect(resultText).not.toContain("capture_script:");
		expect(resultText.length).toBeLessThanOrEqual(4096);
		const artifactPath = /mobile_runtime_artifact: (.+)/.exec(resultText)?.[1]?.trim();
		expect(artifactPath).toBeDefined();
		expect(existsSync(artifactPath!)).toBe(true);
		const artifactText = readFileSync(artifactPath!, "utf-8");
		expect(artifactText).toContain("REPI Mobile Runtime Artifact");
		expect(artifactText).toContain("capture_script:");
		expect(artifactText).toContain("repi-mobile-frida-hooks.js");
		const missionAfterMobile = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as {
			checkpoints: Array<{ name: string; status: string }>;
		};
		expect(missionAfterMobile.checkpoints.find((gate) => gate.name === "mobile_runtime_ready")?.status).toBe("done");
	});

	it("runs the web authz state capture and records principal/object anchors", async () => {
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
				return {
					code: 0,
					stdout: [
						"[web-authz-env] node=/usr/bin/node curl=/usr/bin/curl jq=/usr/bin/jq python3=/usr/bin/python3 timeout=9s",
						"[web-authz-script] /tmp/repi-web-authz-state.mjs artifact=/tmp/repi-web-authz-state.json principals=anon,A,B",
						"[web-authz-run] [web-authz-state] principal=anon route=/api/users/123 method=GET status=401 bytes=20 hash=aaa",
						"[web-authz-run] [web-authz-state] principal=A route=/api/users/123 method=GET status=200 bytes=120 hash=bbb",
						"[web-authz-run] [web-authz-state] principal=B route=/api/users/123 method=GET status=200 bytes=118 hash=ccc",
						"[web-authz-run] [web-authz-matrix] route=/api/users/123 principals=anon,A,B states=3 same_status=false unique_bodies=3 vector=anon:401:aaa,A:200:bbb,B:200:ccc",
						"[web-authz-run] [web-authz-object] route=/api/users/123 owner=A principal_a_status=200 principal_b_status=200 same_body_ab=false alt_status=200 potential_bola=true",
						"[web-authz-run] [web-authz-sequence] principal=A steps=2 statuses=200,200 hashes=bbb,ddd",
						"[web-authz-run] [web-authz-rollback] status=skipped reason=set_REPI_AUTHZ_MUTATE=1_and_REPI_MUTATION_URL",
						"[web-authz-run] [web-authz-artifact] /tmp/repi-web-authz-state.json",
					].join("\n"),
					stderr: "",
					killed: false,
				};
			},
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);

		const missionTool = tools.get("re_mission") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		await missionTool.execute("tool-call-id", { action: "new", task: "Web API JWT IDOR BOLA authz state" });

		const webAuthzTool = tools.get("re_web_authz_state") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const result = await webAuthzTool.execute("tool-call-id", {
			action: "run",
			target: "https://target.local/api/users/123",
			timeoutMs: 9000,
		});

		expect(execCalls).toHaveLength(1);
		expect(execCalls[0]?.args.join("\n")).toContain("REPI_ADAPTER_TARGET");
		expect(execCalls[0]?.args.join("\n")).toContain("emitAuthorizationState");
		expect(result.content[0]?.text).toContain("web_authz_state:");
		expect(result.content[0]?.text).toContain("mode: run");
		expect(result.content[0]?.text).toContain("executions:");
		expect(result.content[0]?.text).toContain("stdout_sha256=");
		expect(result.content[0]?.text).toContain("web authz principal state anchors");
		expect(result.content[0]?.text).toContain("web authz matrix anchors");
		expect(result.content[0]?.text).toContain("web authz object ownership anchors");
		expect(result.content[0]?.text).toContain("web authz sequence replay anchors");
		expect(result.content[0]?.text).toContain("web authz rollback anchors");
		expect(result.content[0]?.text).toContain("web authz artifact anchors");
		const artifactPath = /web_authz_artifact: (.+)/.exec(result.content[0]?.text ?? "")?.[1]?.trim();
		expect(artifactPath).toBeDefined();
		expect(existsSync(artifactPath!)).toBe(true);
		expect(readFileSync(artifactPath!, "utf-8")).toContain("REPI Web Authz State Artifact");
		const missionAfterWebAuthz = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as {
			checkpoints: Array<{ name: string; status: string }>;
		};
		expect(missionAfterWebAuthz.checkpoints.find((gate) => gate.name === "web_authz_ready")?.status).toBe("done");
	});

	it("runs the native runtime capture and records GDB/pwn anchors", async () => {
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
				return {
					code: 0,
					stdout: [
						"[native-env] file=/usr/bin/file readelf=/usr/bin/readelf objdump=/usr/bin/objdump gdb=/usr/bin/gdb checksec=/usr/bin/checksec ldd=/usr/bin/ldd strings=/usr/bin/strings ROPgadget=/usr/bin/ROPgadget ropper=/usr/bin/ropper patchelf=/usr/bin/patchelf",
						"[native-binary] target=./vuln bytes=123 sha256=abc mode=755 file=ELF 64-bit LSB executable",
						"[native-checksec] Canary found NX enabled PIE enabled",
						"[native-readelf-header] Type: EXEC (Executable file)",
						"[native-readelf-program] GNU_STACK RW",
						"[native-ldd] libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6",
						"[native-symbol] strcmp",
						"[native-string] license",
						"[native-gdb-script] /tmp/repi-native-gdb.gdb breakpoints=main,strcmp,strncmp,memcmp,strstr",
						"[native-gdb] Program received signal SIGSEGV",
						"[native-gdb] RIP 0x6161616b RSP 0x7fffffffe000",
						'[native-lief] format=FORMATS.ELF entry=0x401000 imports=["strcmp"]',
						'[native-pwntools] arch=amd64 entry=0x401000 bits=64 checksec={"NX": true}',
					].join("\n"),
					stderr: "",
					killed: false,
				};
			},
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);

		const missionTool = tools.get("re_mission") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		await missionTool.execute("tool-call-id", { action: "new", task: "pwn ELF ret2libc crash primitive" });

		const nativeRuntimeTool = tools.get("re_native_runtime") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const result = await nativeRuntimeTool.execute("tool-call-id", {
			action: "run",
			target: "./vuln",
			timeoutMs: 9000,
		});

		expect(execCalls).toHaveLength(1);
		expect(execCalls[0]?.args.join("\n")).toContain("REPI_ADAPTER_TARGET");
		expect(execCalls[0]?.args.join("\n")).toContain("gdb -q");
		const resultText = result.content[0]?.text ?? "";
		expect(resultText).toContain("native_runtime:");
		expect(resultText).toContain("mode: run");
		expect(resultText).toContain("executions:");
		expect(resultText).toContain("stdout_sha256=");
		expect(resultText).toContain("native binary inventory anchors");
		expect(resultText).toContain("native mitigation/header anchors");
		expect(resultText).toContain("native loader/libc anchors");
		expect(resultText).toContain("native symbol/string anchors");
		expect(resultText).toContain("native GDB trace anchors");
		expect(resultText).toContain("native crash/register anchors");
		expect(resultText).toContain("native analyzer anchors");
		expect(resultText).not.toContain("capture_script:");
		expect(resultText.length).toBeLessThanOrEqual(4096);
		const artifactPath = /native_runtime_artifact: (.+)/.exec(resultText)?.[1]?.trim();
		expect(artifactPath).toBeDefined();
		expect(existsSync(artifactPath!)).toBe(true);
		const artifactText = readFileSync(artifactPath!, "utf-8");
		expect(artifactText).toContain("REPI Native Runtime Artifact");
		expect(artifactText).toContain("capture_script:");
		expect(artifactText).toContain("repi-native-gdb.gdb");
		const missionAfterNative = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as {
			checkpoints: Array<{ name: string; status: string }>;
		};
		expect(missionAfterNative.checkpoints.find((gate) => gate.name === "native_runtime_ready")?.status).toBe("done");
	});

	it("keeps supervisor queues in the artifact instead of the provider result", async () => {
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
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);

		const missionTool = tools.get("re_mission") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		await missionTool.execute("tool-call-id", { action: "new", task: "review worker evidence and claim gates" });

		const supervisorTool = tools.get("re_supervisor") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const result = await supervisorTool.execute("tool-call-id", { action: "review" });
		const resultText = result.content[0]?.text ?? "";

		expect(resultText).toContain("supervisor_review:");
		expect(resultText).toContain("supervisor_verdict:");
		expect(resultText).toContain("key_blockers:");
		expect(resultText).toContain("next_supervisor_command:");
		expect(resultText).not.toContain("worker_scoreboard:");
		expect(resultText).not.toContain("priority_queue:");
		expect(resultText.length).toBeLessThanOrEqual(4096);
		const artifactPath = /supervisor_artifact: (.+)/.exec(resultText)?.[1]?.trim();
		expect(artifactPath).toBeDefined();
		const artifactText = readFileSync(artifactPath!, "utf-8");
		expect(artifactText).toContain("worker_scoreboard:");
		expect(artifactText).toContain("priority_queue:");
		expect(artifactText).toContain("claim_check_policy:");
	});
});
