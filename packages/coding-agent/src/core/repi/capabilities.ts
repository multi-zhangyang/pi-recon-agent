import { Type } from "typebox";
import type { ExtensionAPI } from "../extensions/types.ts";
import { missionOperatorDirective, readCurrentSessionMission } from "./mission.ts";
import { REPI_TOOL_NAMES } from "./profile.ts";
import { isRepiContinuation, isRepiTask, type RoutePlan, routeRepiTask } from "./routes.ts";
import { runMissionSessionScope } from "./session-scope.ts";

export const REPI_CAPABILITY_PROFILE_NAMES = [
	"workflow",
	"web",
	"native",
	"mobile",
	"crypto",
	"forensics",
	"identity",
	"agent",
	"proof",
	"orchestration",
] as const;

// `all` remains a defensive runtime value for old RPC callers, but is not a
// product capability name and is intentionally absent from the model schema.
export type RepiCapabilityProfile = (typeof REPI_CAPABILITY_PROFILE_NAMES)[number] | "all";

/** Tools exposed for every automatically managed REPI turn. */
export const REPI_CORE_TOOL_NAMES = ["read", "bash", "re_capabilities", "goal_complete"] as const;

/** Runtime adapters write scoped evidence directly; routed turns need no control-plane preflight tools. */
export const REPI_ROUTED_FOUNDATION_TOOL_NAMES = [] as const;

/** Proof gates are opt-in after execution; they do not belong in the first routed turn. */
export const REPI_ROUTED_VERIFICATION_TOOL_NAMES = [] as const;

export const REPI_ROUTE_CONTRACT_TOOL_NAMES = [
	...REPI_ROUTED_FOUNDATION_TOOL_NAMES,
	...REPI_ROUTED_VERIFICATION_TOOL_NAMES,
] as const;

/** Built-in tools which require an explicit read/write task signal. */
export const REPI_WRITE_TOOL_NAMES = ["edit", "write"] as const;

export const REPI_CAPABILITY_TOOLS: Record<Exclude<RepiCapabilityProfile, "all">, readonly string[]> = {
	workflow: [
		...REPI_ROUTE_CONTRACT_TOOL_NAMES,
		"re_capabilities",
		"re_route",
		"re_mission",
		"re_map",
		"re_lane",
		"re_techniques",
		"re_evidence",
		"re_tool_index",
		"re_live_browser",
		"re_native_runtime",
		"re_mobile_runtime",
		"re_kernel",
		"re_decision_core",
		"re_autopilot",
		"re_graph",
		"re_operator",
		"re_bootstrap",
	],
	web: [...REPI_ROUTE_CONTRACT_TOOL_NAMES, "re_web_authz_state", "re_runtime_adapter"],
	native: [...REPI_ROUTE_CONTRACT_TOOL_NAMES, "re_exploit_lab", "re_runtime_adapter", "re_lane_specialist_pack"],
	mobile: [...REPI_ROUTE_CONTRACT_TOOL_NAMES, "re_runtime_adapter", "re_lane_specialist_pack"],
	crypto: [
		...REPI_ROUTE_CONTRACT_TOOL_NAMES,
		"re_exploit_lab",
		"re_runtime_adapter",
		"re_lane_specialist_pack",
		"re_toolchain_domain",
	],
	forensics: [
		...REPI_ROUTE_CONTRACT_TOOL_NAMES,
		"re_runtime_adapter",
		"re_runtime_bridge",
		"re_lane_specialist_pack",
		"re_toolchain_domain",
	],
	identity: [
		...REPI_ROUTE_CONTRACT_TOOL_NAMES,
		"re_runtime_adapter",
		"re_runtime_bridge",
		"re_lane_specialist_pack",
		"re_toolchain_domain",
	],
	agent: [...REPI_ROUTE_CONTRACT_TOOL_NAMES, "re_runtime_adapter", "re_runtime_bridge", "re_reason"],
	proof: [
		...REPI_ROUTE_CONTRACT_TOOL_NAMES,
		"re_verifier",
		"re_domain_proof_exit",
		"re_compiler",
		"re_replayer",
		"re_autofix",
		"re_proof_loop",
		"re_challenge",
		"re_complete",
	],
	orchestration: [
		...REPI_ROUTE_CONTRACT_TOOL_NAMES,
		"re_kernel",
		"re_decision_core",
		"re_autopilot",
		"re_graph",
		"re_exploit_chain",
		"re_campaign",
		"re_operation",
		"re_delegate",
		"re_subagent",
		"re_swarm",
		"re_supervisor",
		"re_operator",
		"re_compiler",
		"re_replayer",
		"re_autofix",
		"re_proof_loop",
		"re_profile_check",
		"re_toolchain_domain",
		"re_runtime_bridge",
		"re_runtime_adapter",
		"re_lane_specialist_pack",
	],
};

const MANAGED_REPI_TOOL_NAMES = new Set<string>([
	...REPI_TOOL_NAMES,
	"read",
	"bash",
	"grep",
	"find",
	"ls",
	...REPI_WRITE_TOOL_NAMES,
	"re_capabilities",
]);
const REPI_WRITE_TOOL_SET = new Set<string>(REPI_WRITE_TOOL_NAMES);

const READ_ONLY_TASK_PATTERNS = [
	/\bread[- ]?only\b|\breadonly\b/i,
	/(?:do not|don't|never|without|no)\s+(?:modify|write|edit|change|alter|mutat)/i,
	/(?:只读|只读模式|不要|禁止|不得)\s*(?:修改|写入|编辑|改动|变更)/i,
] as const;

/** Return true when a prompt explicitly forbids workspace mutations. */
export function isRepiReadOnlyTask(prompt: string): boolean {
	return READ_ONLY_TASK_PATTERNS.some((pattern) => pattern.test(prompt));
}

const DIRECT_WRITE_ACTION_PATTERN = /\b(?:edit|write|fix|implement|refactor|create|add|generate|build|rewrite)\b/i;
const AMBIGUOUS_WRITE_ACTION_PATTERN = /\b(?:modify|change|remove|delete|update|patch)\b/i;
const WORKSPACE_TARGET_PATTERN =
	/\b(?:file|files|code|source|repository|repo|project|workspace|test|tests|fixture|implementation|handler|module|function|script|config|configuration|report|document|docs|patch)\b/i;
const CHINESE_DIRECT_MUTATION_PATTERN = /(?:修复|实现|重构|创建|新增|开发|搭建|编写|写入|生成|做一个|做个)/i;
const CHINESE_WORKSPACE_MUTATION_PATTERN =
	/(?:修改|改动|修复|实现|重构|创建|新增|删除|更新|补丁|生成|编写|写入)[^\n。！？]{0,32}(?:文件|代码|项目|仓库|测试|配置|脚本|函数|模块|处理器|报告|文档)/i;
const EXPLICIT_MUTATION_COMMAND_PATTERN =
	/\b(?:apply|commit|save)\s+(?:the\s+)?(?:patch|change|edit|write)|--(?:write|edit|apply)\b/i;

/** Expose edit/write only when the operator actually asks for a mutation. */
export function repiPromptNeedsWriteTools(prompt: string): boolean {
	if (isRepiReadOnlyTask(prompt)) return false;
	if (
		EXPLICIT_MUTATION_COMMAND_PATTERN.test(prompt) ||
		DIRECT_WRITE_ACTION_PATTERN.test(prompt) ||
		CHINESE_DIRECT_MUTATION_PATTERN.test(prompt) ||
		CHINESE_WORKSPACE_MUTATION_PATTERN.test(prompt)
	)
		return true;
	if (!AMBIGUOUS_WRITE_ACTION_PATTERN.test(prompt) || !WORKSPACE_TARGET_PATTERN.test(prompt)) return false;
	// HTTP/API verbs are not workspace mutations by themselves. Require a
	// concrete file/code target so `audit DELETE /users` does not expose writes.
	if (
		/\b(?:delete|remove|update|patch|change)\b[\s\S]{0,48}\b(?:endpoint|api|route|request|response|resource|user|record)\b/i.test(
			prompt,
		) &&
		!/\b(?:file|code|repository|repo|test|fixture|handler|module|function|script|config|project)\b/i.test(prompt)
	)
		return false;
	return true;
}

const capabilityProfileSchema = Type.Union([
	Type.Literal("workflow"),
	Type.Literal("web"),
	Type.Literal("native"),
	Type.Literal("mobile"),
	Type.Literal("crypto"),
	Type.Literal("forensics"),
	Type.Literal("identity"),
	Type.Literal("agent"),
	Type.Literal("proof"),
	Type.Literal("orchestration"),
]);

function repiCapabilityProfilesForCtfTask(task: string): RepiCapabilityProfile[] {
	const profiles = new Set<RepiCapabilityProfile>();
	if (/https?:\/\/|\bweb\b|\bapi\b|graphql|jwt|oauth|ssrf|idor|bola|xss|sqli|ssti|csrf|http/i.test(task)) {
		profiles.add("web");
	}
	if (/\bpwn\b|\brop\b|ret2libc|\bheap\b|tcache|fmtstr|srop|elf|binary|crackme|pwntools|栈|堆|二进制/i.test(task)) {
		profiles.add("native");
	}
	if (/\bcrypto\b|rsa|aes|ecb|cbc|gcm|nonce|padding oracle|lattice|sage|z3|hashcat|xor|stego|隐写|密码/i.test(task)) {
		profiles.add("crypto");
	}
	if (/pcap|pcapng|dfir|forensic|wireshark|tshark|volatility|memory dump|流量|取证|内存镜像/i.test(task)) {
		profiles.add("forensics");
	}
	if (/apk|android|ios|ipa|frida|jadx|apktool|smali/i.test(task)) profiles.add("mobile");
	if (profiles.size === 0) profiles.add("workflow");
	return [...profiles];
}

export function repiCapabilityProfilesForRoute(route: RoutePlan, task = ""): RepiCapabilityProfile[] {
	switch (route.domain) {
		case "Web / API pentest":
		case "Web pentest scanning":
		case "Frontend JS reverse":
			return ["web"];
		case "Native reverse":
		case "Pwn / exploit":
		case "Exploit reliability":
			return ["native"];
		case "Crypto / stego":
			return ["crypto"];
		case "CTF / sandbox":
			return repiCapabilityProfilesForCtfTask(task);
		case "Mobile / Android":
		case "Mobile / iOS":
			return ["mobile"];
		case "DFIR / PCAP / stego":
		case "Memory forensics":
		case "Firmware / IoT":
		case "Malware analysis":
			return ["forensics"];
		case "Cloud / container":
		case "Identity / Windows / AD":
			return ["identity"];
		case "Agent / LLM boundary":
			return ["agent"];
		default:
			return [];
	}
}

/** Return an executable next step without exposing a tool outside the active route profile. */
export function repiCapabilityAwareCommand(route: RoutePlan, task: string, command: string): string {
	const toolName = command.trim().match(/^\/?(re_[a-z0-9_]+)\b/i)?.[1];
	if (!toolName) return command;
	const activeProfiles = repiCapabilityProfilesForRoute(route, task);
	const activeTools = new Set<string>(REPI_CORE_TOOL_NAMES);
	for (const profile of activeProfiles) {
		if (profile === "all") continue;
		for (const name of REPI_CAPABILITY_TOOLS[profile]) activeTools.add(name);
	}
	if (activeTools.has(toolName)) return command;
	const requiredProfile = REPI_CAPABILITY_PROFILE_NAMES.find((profile) =>
		REPI_CAPABILITY_TOOLS[profile].includes(toolName),
	);
	return requiredProfile ? `re_capabilities activate ${requiredProfile}` : command;
}

export function selectRepiCapabilityTools(options: {
	availableToolNames: readonly string[];
	activeToolNames: readonly string[];
	profiles: readonly RepiCapabilityProfile[];
	/** Whether automatically managed edit/write tools may be exposed. */
	allowWriteTools?: boolean;
}): string[] {
	const available = new Set(options.availableToolNames);
	const allowWriteTools = options.allowWriteTools === true;
	const desiredManagedTools = new Set<string>([
		...REPI_CORE_TOOL_NAMES,
		...(allowWriteTools ? REPI_WRITE_TOOL_NAMES : []),
	]);
	for (const profile of options.profiles) {
		if (profile === "all") {
			for (const name of options.availableToolNames) {
				if (MANAGED_REPI_TOOL_NAMES.has(name) && (allowWriteTools || !REPI_WRITE_TOOL_SET.has(name))) {
					desiredManagedTools.add(name);
				}
			}
			continue;
		}
		for (const name of REPI_CAPABILITY_TOOLS[profile]) desiredManagedTools.add(name);
	}

	// Retain the provider-visible order of every still-valid tool. Additive
	// activation can then append schemas without invalidating the existing cache
	// prefix, including third-party tools activated after session startup.
	const selected = new Set<string>();
	for (const name of options.activeToolNames) {
		if (!available.has(name)) continue;
		if (!MANAGED_REPI_TOOL_NAMES.has(name) || desiredManagedTools.has(name)) selected.add(name);
	}

	for (const name of REPI_CORE_TOOL_NAMES) {
		if (available.has(name)) selected.add(name);
	}
	if (allowWriteTools) {
		for (const name of REPI_WRITE_TOOL_NAMES) {
			if (available.has(name)) selected.add(name);
		}
	}

	for (const profile of options.profiles) {
		if (profile === "all") {
			for (const name of options.availableToolNames) {
				if (MANAGED_REPI_TOOL_NAMES.has(name) && (allowWriteTools || !REPI_WRITE_TOOL_SET.has(name))) {
					selected.add(name);
				}
			}
			continue;
		}
		for (const name of REPI_CAPABILITY_TOOLS[profile]) {
			if (available.has(name)) selected.add(name);
		}
	}

	return [...selected];
}

export interface RepiCapabilityActivationOptions {
	preserveExplicitToolSelection?: boolean;
	injectPromptPacket?: boolean;
}

export function createRepiCapabilityActivationFactory(options: RepiCapabilityActivationOptions = {}) {
	return function repiCapabilityActivation(pi: ExtensionAPI): void {
		let activeProfiles: RepiCapabilityProfile[] = [];
		let routedProfiles: RepiCapabilityProfile[] = [];
		let explicitProfiles: RepiCapabilityProfile[] | undefined;
		let activeMissionId: string | undefined;
		let allowWriteTools = false;
		let carriedTask: string | undefined;
		let carriedRoute: RoutePlan | undefined;

		const applyProfiles = (profiles: readonly RepiCapabilityProfile[]): string[] => {
			activeProfiles = [...new Set(profiles)];
			const selected = selectRepiCapabilityTools({
				availableToolNames: pi.getAllTools().map((tool) => tool.name),
				activeToolNames: pi.getActiveTools(),
				profiles: activeProfiles,
				allowWriteTools,
			});
			const current = pi.getActiveTools();
			if (selected.length !== current.length || selected.some((name, index) => name !== current[index])) {
				pi.setActiveTools(selected);
			}
			return selected;
		};

		const resetRuntime = (): void => {
			activeMissionId = undefined;
			routedProfiles = [];
			explicitProfiles = undefined;
			allowWriteTools = false;
			carriedTask = undefined;
			carriedRoute = undefined;
			applyProfiles([]);
		};

		const appendCapabilityPacket = (systemPrompt: string): string => {
			return [
				systemPrompt,
				"",
				"## REPI capability",
				`profile: ${activeProfiles.join(",") || "core"}`,
				"Activate another profile only when the next probe requires it.",
			].join("\n");
		};

		pi.registerTool({
			name: "re_capabilities",
			label: "REPI Capabilities",
			description:
				"Inspect or activate a focused REPI capability profile. Use this progressive-disclosure entry when the current route needs tools that are not active.",
			promptSnippet:
				"Inspect or activate focused REPI capability profiles instead of loading every REPI tool schema.",
			promptGuidelines: [
				"Use status to inspect the current focused tool surface.",
				"Activation is additive by default. Use mode=replace only when the prior route is no longer relevant.",
				"Activate only the capability needed for the current route; combine focused profiles or use orchestration only for genuinely cross-domain work.",
			],
			parameters: Type.Object({
				action: Type.Union([Type.Literal("status"), Type.Literal("activate"), Type.Literal("reset")]),
				profile: Type.Optional(capabilityProfileSchema),
				mode: Type.Optional(Type.Union([Type.Literal("add"), Type.Literal("replace")])),
			}),
			async execute(_toolCallId, params) {
				let selected = pi.getActiveTools();
				if (params.action === "reset") {
					explicitProfiles = undefined;
					selected = applyProfiles(routedProfiles);
				} else if (params.action === "activate") {
					if (!params.profile) {
						return {
							content: [{ type: "text" as const, text: "re_capabilities activate requires `profile`." }],
							details: { error: true, action: params.action } as Record<string, unknown>,
						};
					}
					explicitProfiles =
						params.mode === "replace" ? [params.profile] : [...new Set([...activeProfiles, params.profile])];
					selected = applyProfiles(explicitProfiles);
				}
				const availableCount = pi.getAllTools().length;
				return {
					content: [
						{
							type: "text" as const,
							text: [
								`re_capabilities: profiles=${activeProfiles.join(",") || "core"}`,
								`active_tools=${selected.length}/${availableCount}`,
								`tools=${selected.join(",")}`,
							].join("\n"),
						},
					],
					details: {
						action: params.action,
						profiles: activeProfiles,
						activeToolNames: selected,
						availableCount,
					} as Record<string, unknown>,
				};
			},
		});

		pi.on("session_start", () => {
			if (options.preserveExplicitToolSelection) return;
			resetRuntime();
		});

		pi.on("session_tree", () => {
			if (options.preserveExplicitToolSelection) return;
			// A tree navigation can move to a branch without the mission that
			// populated this process-local cache. Re-resolve from that branch on
			// the next turn instead of carrying the old route across branches.
			resetRuntime();
		});

		pi.on("before_agent_start", (event, ctx) => {
			const sessionFile = ctx.sessionManager?.getSessionFile?.();
			return runMissionSessionScope(sessionFile, () => {
				if (options.preserveExplicitToolSelection) return;
				const mission = readCurrentSessionMission(ctx);
				const routedPrompt = isRepiTask(event.prompt);
				const continuation = isRepiContinuation(event.prompt);
				if (mission?.id !== activeMissionId) {
					activeMissionId = mission?.id;
					explicitProfiles = undefined;
					allowWriteTools = false;
					carriedTask = undefined;
					carriedRoute = undefined;
				} else if (!mission && routedPrompt && !continuation && carriedTask && carriedTask !== event.prompt) {
					// Capability-only SDK callers may not install the mission runtime.
					// Treat a new routed prompt as a task boundary in that mode.
					explicitProfiles = undefined;
					allowWriteTools = false;
				}
				if (mission) {
					carriedTask = missionOperatorDirective(mission);
					carriedRoute = mission.route;
				} else if (routedPrompt) {
					carriedTask = event.prompt;
					carriedRoute = routeRepiTask(event.prompt);
				}

				const task = missionOperatorDirective(mission) ?? carriedTask;
				const route = mission?.route ?? carriedRoute;
				if (!task || !route) {
					routedProfiles = [];
					allowWriteTools = continuation
						? allowWriteTools || repiPromptNeedsWriteTools(event.prompt)
						: repiPromptNeedsWriteTools(event.prompt);
					applyProfiles(explicitProfiles ?? routedProfiles);
					return;
				}

				allowWriteTools =
					allowWriteTools || repiPromptNeedsWriteTools(event.prompt) || repiPromptNeedsWriteTools(task);
				const promptRoute = routedPrompt && !continuation ? routeRepiTask(event.prompt) : undefined;
				const effectiveRoute =
					promptRoute && promptRoute.domain !== "Reverse/Pentest general" ? promptRoute : route;
				routedProfiles = repiCapabilityProfilesForRoute(effectiveRoute, promptRoute ? event.prompt : task);
				const selected = applyProfiles(explicitProfiles ?? routedProfiles);
				// The mission runtime already chose the routed profile. Keep capability
				// activation available to standalone SDK/RPC users, but do not expose a
				// redundant control-plane tool to the routed provider turn.
				if (mission && !explicitProfiles && selected.includes("re_capabilities")) {
					pi.setActiveTools(selected.filter((name) => name !== "re_capabilities"));
				}
				// The mission delta already carries ongoing state. Emit this static hint
				// only on the cold routed prompt, never on sticky/continuation turns.
				if (options.injectPromptPacket === false || mission || !routedPrompt) return;
				return { systemPrompt: appendCapabilityPacket(event.systemPrompt) };
			});
		});
	};
}
