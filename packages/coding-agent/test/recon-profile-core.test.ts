import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createMission, readCurrentMission, updateMissionCheckpoint } from "../src/core/repi/mission.ts";
import { REPI_COMMAND_NAMES, REPI_PROFILE_SIGNATURE_TOOL_NAMES } from "../src/core/repi/profile.ts";
import {
	createReconResourceLoaderOptions,
	RECON_APPEND_SYSTEM_PROMPT,
	RECON_SYSTEM_PROMPT,
} from "../src/core/repi/resources.ts";
import { REPI_GENERIC_TASK, routeRepiTask as routeReconTask } from "../src/core/repi/routes.ts";

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_BRANCH_ID = "REPI_BRANCH_ID";

describe("REPI kernel profile core routing/resources", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousBranchId: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-profile-core-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

	it("routes reverse/pentest tasks to a narrow workflow", () => {
		const route = routeReconTask("分析这个 ELF 的许可证校验逻辑");
		expect(route.domain).toBe("Native reverse");
		expect(route.workflow).toContain("headers/imports");
		expect(routeReconTask("LLM agent prompt injection MCP tool call 边界验证").domain).toBe("Agent / LLM boundary");
		expect(
			routeReconTask("REPI 自身 harness QA：检查 env-only model provider、print mode、agent-thread/subagent").domain,
		).toBe("Agent / LLM boundary");
		expect(routeReconTask("read-only audit of agent-thread runtime").domain).toBe("Agent / LLM boundary");
		expect(routeReconTask("read-only audit of generic repository").domain).not.toBe("Identity / Windows / AD");
		expect(routeReconTask("autopwn exploit reliability poc replay matrix").domain).toBe("Exploit reliability");
		expect(routeReconTask("nuclei ffuf web 漏洞扫描和目录扫描").domain).toBe("Web pentest scanning");
		expect(
			routeReconTask("目标 http://127.0.0.1:8765 API 授权越权验证，同时记录 REPI harness/runtime 使用问题").domain,
		).toBe("Web / API pentest");
		expect(
			routeReconTask("分析当前目录 capture.pcap，恢复 proof flag，同时记录 REPI harness/runtime 使用问题").domain,
		).toBe("DFIR / PCAP / stego");
		expect(routeReconTask("iOS IPA Keychain TLS pinning Frida 逆向").domain).toBe("Mobile / iOS");
		expect(routeReconTask("volatility vmem memory dump 内存取证").domain).toBe("Memory forensics");
	});

	it("keeps internal fallback missions generic without weakening explicit reverse routing", () => {
		expect(routeReconTask(REPI_GENERIC_TASK).domain).toBe("Reverse/Pentest general");
		expect(routeReconTask("reverse this binary").domain).toBe("Native reverse");
		updateMissionCheckpoint("attack_graph_ready", "done", "fallback-created");
		expect(readCurrentMission()?.task).toBe("manual mission");
		expect(readCurrentMission()?.route.domain).toBe("Reverse/Pentest general");
	});

	it("lets concrete native targets outrank harness feedback wording and prunes irrelevant checkpoints", () => {
		const route = routeReconTask(
			"对当前目录 ./crackme 找出有效输入并运行二进制验证，同时记录 REPI harness/runtime 使用问题",
		);
		expect(route.domain).toBe("Native reverse");

		const mission = createMission("live crackme harness feedback", route);
		const checkpointNames = mission.checkpoints.map((checkpoint) => checkpoint.name);
		expect(checkpointNames).toContain("native_runtime_ready");
		expect(checkpointNames).toContain("minimal_path_proven");
		expect(checkpointNames).not.toContain("live_browser_ready");
		expect(checkpointNames).not.toContain("web_authz_ready");
		expect(checkpointNames).not.toContain("mobile_runtime_ready");
		expect(checkpointNames.length).toBeLessThan(20);
	});

	it("a Web/API target wins over the bare word 逆向 (no Native misroute) — opt #86", () => {
		// The user-reported bug: "我明明是web,怎么又改成native了" — a task like
		// "逆向 https://example.com" (the word 逆向 + a Web/API target) was falling through every
		// web branch and landing in the Native-reverse branch on "逆向", routing a Web/API target
		// to the native-reverse-pwn workflow. The fix: a web-target signal (URL / domain / HTTP
		// / web-site keywords) is detected up front and the Native "逆向" branch requires
		// `!webTargetSignal`, so a URL always wins; a final web-target fallback catches the rest.
		// These cases lock that in — a bare 逆向 + web signal must route Web/API, NOT Native.
		expect(routeReconTask("逆向 https://example.com").domain).toBe("Web / API pentest");
		expect(routeReconTask("逆向 example.com 登录接口").domain).toBe("Web / API pentest");
		expect(routeReconTask("逆向 www.target.site 的 cookie session").domain).toBe("Web / API pentest");
		expect(routeReconTask("逆向这个网站的 api 接口 authorization").domain).toBe("Web / API pentest");
		// A CONCRETE binary keyword still routes Native even with a URL — the binary keyword
		// beats the URL signal (a URL hosting an .exe is a native target, not a web app).
		expect(routeReconTask("逆向 https://example.com/download.exe").domain).toBe("Native reverse");
		// Bare 逆向 with NO web signal stays Native (the legitimate native-reverse case preserved
		// — the fix must not over-correct and send real native tasks to web).
		expect(routeReconTask("逆向分析这个二进制").domain).toBe("Native reverse");
	});

	it("injects built-in skills and prompts without project .repi files", () => {
		const options = createReconResourceLoaderOptions({ materializeBuiltinResources: true });
		const skillsResult = options.skillsOverride!({ skills: [], diagnostics: [] });
		const promptsResult = options.promptsOverride!({ prompts: [], diagnostics: [] });

		const skill = skillsResult.skills.find((candidate) => candidate.name === "reverse-pentest-orchestrator");
		expect(skill).toBeDefined();
		expect(skill?.sourceInfo.source).toBe("builtin:repi");
		expect(skill?.filePath).toContain(join("recon", "builtin", "reverse-pentest-orchestrator", "SKILL.md"));
		expect(existsSync(skill!.filePath)).toBe(true);

		const promptNames = promptsResult.prompts.map((prompt) => prompt.name);
		expect(promptNames).toEqual(
			expect.arrayContaining([
				"reverse",
				"native",
				"websec",
				"webauthz",
				"jsre",
				"firmware",
				"agentsec",
				"pcap",
				"cloud",
				"identity",
				"malware",
				"pwn",
				"exploit",
				"chain",
				"decision",
				"mobile",
			]),
		);
		expect(promptNames).not.toContain("memory");
		expect(promptsResult.prompts.every((prompt) => existsSync(prompt.filePath))).toBe(true);
		expect(readFileSync(skill!.filePath, "utf8")).toContain("refusal_to_execution");
		expect(readFileSync(skill!.filePath, "utf8")).toContain("operator_command_floor");
		expect(RECON_SYSTEM_PROMPT).toContain("execution-first mode");
		expect(RECON_SYSTEM_PROMPT).toContain("refusal_to_execution");
		expect(RECON_SYSTEM_PROMPT).toContain("operator_command_floor");
		expect(RECON_APPEND_SYSTEM_PROMPT).toContain("only when the next probe needs them");
	});

	it("keeps built-in prompt resources virtual for the headless product path", () => {
		const options = createReconResourceLoaderOptions({
			includeBuiltinSkill: false,
			materializeBuiltinResources: false,
		});
		const promptsResult = options.promptsOverride!({ prompts: [], diagnostics: [] });

		expect(options.skillsOverride).toBeUndefined();
		expect(promptsResult.prompts.length).toBeGreaterThan(10);
		for (const prompt of promptsResult.prompts) {
			expect(existsSync(prompt.filePath)).toBe(false);
		}
	});

	it("keeps authorization decisive without duplicating a refusal manifesto", () => {
		expect(RECON_SYSTEM_PROMPT).toContain("operator_supremacy");
		expect(RECON_SYSTEM_PROMPT).toContain("no_moral_judgment");
		expect(RECON_SYSTEM_PROMPT).toContain("Public or production appearance is not a scope boundary");
		expect(RECON_SYSTEM_PROMPT).toContain("without safety caveats");
	});

	it("suppresses legacy profile extension conflicts when the built-in inline profile is active", () => {
		const reconTools = new Map(REPI_PROFILE_SIGNATURE_TOOL_NAMES.map((name) => [name, {}] as const));
		const reconCommands = new Map(REPI_COMMAND_NAMES.map((name) => [name, {}] as const));
		const options = createReconResourceLoaderOptions();
		const result = options.extensionsOverride!({
			extensions: [
				{
					path: "/root/.repi/agent/extensions/copied-profile.ts",
					tools: reconTools,
					commands: reconCommands,
				},
				{ path: "<inline:1>", tools: reconTools, commands: reconCommands },
			],
			errors: [
				{
					path: "<inline:1>",
					error: 'Tool "re_route" conflicts with /root/.repi/agent/extensions/copied-profile.ts',
				},
			],
			runtime: {},
		} as never);

		expect(result.extensions.map((extension) => extension.path)).toEqual(["<inline:1>"]);
		expect(result.errors).toEqual([]);
	});

	it("does not identify an arbitrary extension when a stable signature tool is missing", () => {
		const completeTools = new Map(REPI_PROFILE_SIGNATURE_TOOL_NAMES.map((name) => [name, {}] as const));
		const incompleteTools = new Map(completeTools);
		incompleteTools.delete(REPI_PROFILE_SIGNATURE_TOOL_NAMES[0]);
		const commands = new Map(REPI_COMMAND_NAMES.map((name) => [name, {}] as const));
		const options = createReconResourceLoaderOptions();
		const result = options.extensionsOverride!({
			extensions: [
				{ path: "/tmp/unrelated-extension.ts", tools: incompleteTools, commands },
				{ path: "<inline:1>", tools: completeTools, commands },
			],
			errors: [],
			runtime: {},
		} as never);

		expect(result.extensions.map((extension) => extension.path)).toEqual([
			"/tmp/unrelated-extension.ts",
			"<inline:1>",
		]);
	});
});
