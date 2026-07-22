import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import lockfile from "proper-lockfile";
import { REPI_GENERIC_TASK, type RoutePlan, routeRepiTask } from "./routes.ts";
import {
	currentMissionPath,
	ensureRepiStorage,
	missionStorageScope,
	readJsonObjectFileCached,
	readTextFile,
	writePrivateTextFile,
} from "./storage.ts";
import { redactSensitiveText, sha256Text } from "./text.ts";

export type MissionCheckpointStatus = "pending" | "done" | "blocked";
export type MissionLaneStatus = "pending" | "in_progress" | "done" | "blocked";

export type MissionCheckpoint = {
	name: string;
	status: MissionCheckpointStatus;
	note?: string;
	updatedAt?: string;
};

export type MissionLane = {
	name: string;
	objective: string;
	next: string[];
	status?: MissionLaneStatus;
	note?: string;
	updatedAt?: string;
};

export type MissionRuntimeStats = {
	calls: number;
	bashCalls: number;
	failures: number;
	lastCommandHash?: string;
	repeatedCommandCount: number;
	lastCommands: string[];
	selfReviewDue: boolean;
	lastInjectedState?: string;
};

export type MissionState = {
	id: string;
	createdAt: string;
	updatedAt: string;
	task: string;
	/** Stable workspace scope; prevents a stale mission crossing cwd boundaries. */
	scope?: string;
	route: RoutePlan;
	lanes: MissionLane[];
	checkpoints: MissionCheckpoint[];
	runtimeStats?: MissionRuntimeStats;
};

/** Parallel orchestration is opt-in through mission checkpoints. */
export function missionRequiresParallel(mission: MissionState | undefined): boolean {
	return Boolean(
		mission?.checkpoints.some((checkpoint) =>
			/^(?:delegation_packets_ready|swarm_plan_ready|supervisor_review_ready)$/.test(checkpoint.name),
		),
	);
}

export function missionLanesForRoute(route: RoutePlan): MissionLane[] {
	if (route.domain === "Pwn / exploit") {
		return [
			{
				name: "mitigations",
				objective: "确认保护、加载器、libc 和崩溃面",
				next: ["file/checksec/ldd", "记录 PIE/NX/RELRO/Canary", "确认远程 libc 假设"],
			},
			{
				name: "primitive",
				objective: "证明可控字节、崩溃、leak 或任意读写原语",
				next: ["最小输入触发", "gdb/pwndbg 断点", "记录寄存器/堆状态"],
			},
			{
				name: "exploit",
				objective: "构造稳定 payload 并验证本地/远程一致性",
				next: ["pwntools 脚本", "leak->base->gadget", "重复运行稳定性"],
			},
			{
				name: "report",
				objective: "沉淀偏移、命令、脚本和失败路线",
				next: ["证据块", "复现命令", "evidence ledger"],
			},
		];
	}
	if (route.domain === "Web / API pentest") {
		return [
			{
				name: "surface",
				objective: "映射 routes/auth/session/middleware/workers/storage",
				next: ["被动读代码和配置", "确认真实运行入口", "记录请求顺序"],
			},
			{
				name: "state",
				objective: "证明认证、授权或状态转换边界",
				next: ["最小 replay", "cookie/token/session diff", "状态变化证据"],
			},
			{ name: "poc", objective: "产出可复现 PoC", next: ["curl/httpie 脚本", "前后状态对照", "边界条件"] },
			{
				name: "report",
				objective: "整理影响、证据和修复/下一步",
				next: ["证据块", "验证步骤", "operator next step"],
			},
		];
	}
	if (route.domain === "Web pentest scanning") {
		return [
			{
				name: "scope",
				objective: "确认目标 URL、主机、协议、指纹、robots/sitemap/OpenAPI/GraphQL 和扫描边界",
				next: ["curl/httpx baseline", "robots/sitemap", "WAF/header/tech fingerprint"],
			},
			{
				name: "crawl",
				objective: "构建 bounded route corpus、参数字典、静态资源和登录/未登录差异",
				next: ["katana/wayback fallback", "ffuf/gobuster small wordlist", "parameter candidates"],
			},
			{
				name: "template-scan",
				objective: "用 nuclei/nikto/dalfox/sqlmap 等工具产出候选发现队列，而不是直接声称漏洞成立",
				next: ["nuclei low-rate", "scanner JSONL", "triage severity/source"],
			},
			{
				name: "verify",
				objective: "对每个候选发现做 curl/HTTP replay、状态码/body hash/前后对照和误报裁剪",
				next: ["manual replay", "before/after hash", "false-positive notes"],
			},
			{
				name: "report",
				objective: "输出 finding queue、复现命令、证据 artifact 和后续深挖 lane",
				next: ["finding table", "replay verifier", "operator queue"],
			},
		];
	}
	if (route.domain === "Frontend JS reverse") {
		return [
			{
				name: "observe",
				objective: "捕获请求、initiator、参数和运行时差异",
				next: ["XHR/fetch/WS 观察", "sourcemap/webpack chunk", "hook args/return"],
			},
			{
				name: "rebuild",
				objective: "在 Node/浏览器外复现签名或加密链",
				next: ["抽取最小函数", "补环境", "first divergence patch"],
			},
			{
				name: "verify",
				objective: "用真实请求验证本地生成结果",
				next: ["replay", "对比字段", "记录时间戳/nonce 依赖"],
			},
			{ name: "report", objective: "写出复现脚本和关键断点", next: ["脚本", "证据块", "evidence ledger"] },
		];
	}
	if (route.domain === "Crypto / stego") {
		return [
			{
				name: "inventory",
				objective: "盘点密文/文件/参数/编码/大整数/metadata 与可能的 oracle 面",
				next: ["hash/format", "hex/base64/int/PEM 参数", "IV/nonce/key/signature 字段"],
			},
			{
				name: "transform",
				objective: "复原编码、压缩、异或、分组模式、隐写提取等 transform chain",
				next: ["base64/hex/gzip/zlib", "exiftool/zsteg/binwalk", "candidate plaintext scoring"],
			},
			{
				name: "solver",
				objective: "建立约束/数学/密码攻击 solver，并输出可复用脚本",
				next: ["Z3/Sage/PyCryptodome", "parameter derivation", "solve.py"],
			},
			{
				name: "verify",
				objective: "用 known-answer 或 replay 验证结果，不把猜测当结论",
				next: ["known-answer assert", "transform replay", "artifact hash"],
			},
			{
				name: "report",
				objective: "沉淀参数、脚本、验证命令和失败分支",
				next: ["solver script", "proof-exit", "evidence ledger"],
			},
		];
	}
	if (route.domain === "Malware analysis") {
		return [
			{
				name: "triage",
				objective: "确认样本格式、hash、packer/section/imports、基础 IOC 和执行约束",
				next: ["file/hash/magic", "strings/imports/sections", "packer/entropy"],
			},
			{
				name: "static-config",
				objective: "提取静态配置、C2、mutex、路径、注册表、User-Agent、YARA/capa/FLOSS 线索",
				next: ["IOC regex", "yara/capa/floss", "config hints"],
			},
			{
				name: "behavior",
				objective: "用受控 trace 证明文件/进程/网络/反调试行为",
				next: ["strace/ltrace", "network/process syscall", "anti-debug/sandbox"],
			},
			{
				name: "decode",
				objective: "复原配置或 payload transform chain",
				next: ["decode script", "keys/offsets", "IOC normalization"],
			},
			{
				name: "report",
				objective: "沉淀 hash、IOCs、行为链、配置和复现命令",
				next: ["IOC table", "YARA/config evidence", "evidence ledger"],
			},
		];
	}

	if (route.domain === "Firmware / IoT") {
		return [
			{
				name: "inventory",
				objective: "确认固件封装、hash、架构、压缩/文件系统和候选 rootfs",
				next: ["file/hash/binwalk", "magic/entropy", "architecture/rootfs hints"],
			},
			{
				name: "extract",
				objective: "提取 rootfs、kernel、web 资源、配置层和嵌入 payload",
				next: ["binwalk/unblob", "squashfs/ubifs/cpio", "artifact inventory"],
			},
			{
				name: "filesystem",
				objective: "映射账号、密钥、配置、NVRAM、Web/API/CGI 和启动脚本",
				next: ["passwd/shadow/keys", "nvram/config", "www/cgi/init"],
			},
			{
				name: "services",
				objective: "枚举暴露服务、默认凭据、管理端点和本地攻击面",
				next: ["httpd/dropbear/telnetd", "cgi endpoints", "credential reuse"],
			},
			{
				name: "emulate",
				objective: "构造 QEMU/chroot/用户态复现脚手架并绑定可验证服务路径",
				next: ["arch/qemu-user", "chroot/env", "service smoke"],
			},
			{
				name: "report",
				objective: "沉淀固件图谱、rootfs 路径、凭据/端点/服务和复现命令",
				next: ["evidence graph", "IOC/config table", "evidence ledger"],
			},
		];
	}
	if (route.domain === "Exploit reliability") {
		return [
			{
				name: "inventory",
				objective: "枚举 PoC、payload、replay 脚本、环境假设和目标绑定",
				next: ["PoC candidates", "target/env pins", "input/output contract"],
			},
			{
				name: "normalize",
				objective: "把一次性 PoC 规范化为可参数化、可记录、可回放的 runner",
				next: ["argument contract", "timeout/output hash", "artifact paths"],
			},
			{
				name: "replay",
				objective: "多轮执行 replay matrix，量化成功率、耗时、输出漂移和失败类型",
				next: ["N-run matrix", "success rate", "stdout/stderr hashes"],
			},
			{
				name: "flake-triage",
				objective: "定位 ASLR、race、timeout、IO、网络、libc/loader 环境差异导致的不稳定",
				next: ["failure buckets", "env diff", "retry/backoff"],
			},
			{
				name: "bundle",
				objective: "打包可复现 exploit artifact、环境 pin、运行矩阵和验证摘要",
				next: ["manifest", "runbook", "evidence graph"],
			},
			{
				name: "report",
				objective: "输出稳定性结论、复现命令、失败边界和下一步强化计划",
				next: ["replay stats", "known flakes", "operator command"],
			},
		];
	}
	if (route.domain === "Agent / LLM boundary") {
		return [
			{
				name: "surface",
				objective: "映射 system/developer/user/tool/session-context/RAG/MCP 输入边界和不可信内容入口",
				next: ["prompt/resource inventory", "tool schema map", "untrusted content flow"],
			},
			{
				name: "tool-boundary",
				objective: "证明工具调用、shell/API 参数、schema 校验、审批和输出回灌边界",
				next: ["registerTool/exec map", "argument validation", "tool output trust boundary"],
			},
			{
				name: "retrieval-boundary",
				objective: "确认外部 RAG/检索、日志和不可信资源的投毒/污染路径",
				next: ["resource inventory", "retrieval filters", "poison payload replay"],
			},
			{
				name: "injection",
				objective: "构造间接 prompt injection / tool injection replay harness 并记录最小复现",
				next: ["payload corpus", "replay transcript", "boundary decision proof"],
			},
			{
				name: "delegation",
				objective: "追踪 MCP/resource/sub-agent/delegation 链路和权限漂移边",
				next: ["MCP resources", "sub-agent handoff", "capability drift"],
			},
			{
				name: "report",
				objective: "沉淀 agent 边界图、可复现注入链和工具调用证据",
				next: ["boundary graph", "replay command", "evidence block"],
			},
		];
	}
	if (route.domain === "Memory forensics") {
		return [
			{
				name: "image-info",
				objective: "确认内存镜像格式、hash、OS/profile 候选和 volatility 可用插件",
				next: ["file/sha256", "volatility3 windows.info/linux.banners/mac.banners", "profile fallback"],
			},
			{
				name: "process-network",
				objective: "枚举进程树、命令行、DLL/module、句柄、连接和可疑注入/隐藏进程",
				next: ["pslist/pstree/cmdline", "netscan/sockets", "malfind/dlllist/handles"],
			},
			{
				name: "credential-artifacts",
				objective: "定位凭据、token、浏览器/LSASS/registry/artifact 与可验证来源",
				next: ["hashdump/lsadump fallback", "strings/yara", "registry/browser artifacts"],
			},
			{
				name: "timeline-carve",
				objective: "建立事件时间线、filescan/dumpfiles/carving 和 IOC 证据链",
				next: ["timeliner/mftscan", "filescan/dumpfiles", "IOC/YARA"],
			},
			{
				name: "report",
				objective: "沉淀 profile、插件输出、artifact hash、IOC/timeline 和复现命令",
				next: ["evidence table", "timeline", "forensics proof-exit"],
			},
		];
	}
	if (route.domain === "DFIR / PCAP / stego") {
		return [
			{
				name: "artifact-inventory",
				objective: "确认取证文件类型、hash、pcap/image/stego 候选和解析工具",
				next: ["file/sha256", "capinfos/exiftool", "strings/binwalk"],
			},
			{
				name: "timeline-flow",
				objective: "建立流量会话、DNS/TLS/HTTP、时间线和可疑凭据/对象索引",
				next: ["tshark conversations", "stream ranking", "secret timeline"],
			},
			{
				name: "extract-decode",
				objective: "提取 HTTP object/carve 文件并还原编码、压缩、隐写 transform chain",
				next: ["export objects", "foremost/binwalk", "base64/hex/gzip/zlib/zsteg"],
			},
			{
				name: "verify",
				objective: "验证恢复 artifact 的 hash、可读内容、flag/IOC 来源和复现命令",
				next: ["artifact hash", "decode script", "source packet/frame"],
			},
			{
				name: "report",
				objective: "整理 timeline、artifact、transform 和证据块",
				next: ["flow table", "decode chain", "evidence ledger"],
			},
		];
	}
	if (route.domain === "Mobile / iOS") {
		return [
			{
				name: "ipa-inventory",
				objective: "确认 IPA/Payload/App、Info.plist、Entitlements、Mach-O、Frameworks 和 URL schemes",
				next: ["unzip/list", "plist decode", "codesign/entitlements"],
			},
			{
				name: "static-class-map",
				objective: "定位 Objective-C/Swift 类、selector、Keychain、Crypto、NSURLSession 和 jailbreak/root 检测",
				next: ["otool/nm/strings", "class-dump fallback", "selector grep"],
			},
			{
				name: "runtime-hooks",
				objective:
					"生成 Frida/objection hook，捕获 keychain、CommonCrypto/CryptoKit、NSURLSession、签名函数和反调试",
				next: ["frida-ps/objection", "ObjC hooks", "native Interceptor"],
			},
			{
				name: "network-replay",
				objective: "复现移动端签名/请求链和证书绑定/代理/会话差异",
				next: ["request fields", "signature diff", "TLS pinning evidence"],
			},
			{
				name: "report",
				objective: "沉淀 IPA 结构、hook 点、请求重放、bypass 证据和复现命令",
				next: ["hook script", "replay verifier", "evidence ledger"],
			},
		];
	}
	if (route.domain === "Native reverse" || route.domain === "Mobile / Android") {
		return [
			{ name: "triage", objective: "确认格式、架构、入口、保护、导入、manifest", next: route.workflow.slice(0, 3) },
			{
				name: "control-flow",
				objective: "定位关键函数、字符串引用、校验/解密分支",
				next: ["xrefs", "call graph", "伪代码/反汇编对照"],
			},
			{
				name: "runtime-proof",
				objective: "动态 trace/hook/patch 证明一个最小路径",
				next: ["断点/hook", "输入输出对照", "脚本化 decode"],
			},
			{
				name: "report",
				objective: "沉淀地址、偏移、脚本和复现命令",
				next: ["证据 ledger", "复现命令", "operator next step"],
			},
		];
	}
	if (route.domain === "Cloud / container") {
		return [
			{
				name: "identity",
				objective: "映射云凭据、K8s serviceaccount、运行时身份和当前 principal",
				next: ["env/config/profile", "serviceaccount token", "cloud sts/account"],
			},
			{
				name: "runtime-config",
				objective: "确认容器/K8s/IaC/云 CLI 的真实运行配置和命名空间边界",
				next: ["docker/kubectl context", "manifests/IaC", "namespace/RBAC"],
			},
			{
				name: "metadata",
				objective: "验证 metadata/instance identity 路径和 token 可用性",
				next: ["IMDS/GCP/Azure metadata", "token audience", "egress proof"],
			},
			{
				name: "privilege",
				objective: "证明最小权限边或可达资源边界",
				next: ["whoami/list scope", "RBAC/IAM edge", "least replay"],
			},
			{
				name: "report",
				objective: "整理身份链、资源边和复现命令",
				next: ["attack graph", "evidence ledger", "operator next step"],
			},
		];
	}
	if (route.domain === "Identity / Windows / AD") {
		return [
			{
				name: "principals",
				objective: "枚举域、DC、用户、组、SPN、证书服务和可用协议面",
				next: ["LDAP/Kerberos/SMB baseline", "SPN/user/group", "ADCS"],
			},
			{
				name: "credentials",
				objective: "验证凭据/ticket/hash 的可用性和约束",
				next: ["nxc/impacket check", "Kerberos ticket", "NTLM/hash path"],
			},
			{
				name: "graph",
				objective: "构建权限图，定位可证明的最小 privilege edge",
				next: ["BloodHound/Certipy output", "edge ranking", "path proof"],
			},
			{
				name: "pivot-proof",
				objective: "证明一个最小横向/提权/访问路径",
				next: ["single command proof", "event/evidence", "rollback note"],
			},
			{
				name: "report",
				objective: "沉淀凭据可用性、图边、复现命令和证据",
				next: ["attack graph", "evidence block", "operator next step"],
			},
		];
	}
	return [
		{ name: "map", objective: "被动映射入口、配置、资产和证据面", next: route.workflow.slice(0, 2) },
		{ name: "prove", objective: "证明一条最小端到端路径", next: route.workflow.slice(2, 4) },
		{ name: "expand", objective: "只在最小路径成立后横向扩展", next: ["换证据面", "补工具链", "验证边界"] },
		{ name: "report", objective: "输出证据块、复现命令和下一步", next: ["report", "diagram", "evidence ledger"] },
	];
}

export function initializeMissionLanes(lanes: MissionLane[]): MissionLane[] {
	const timestamp = new Date().toISOString();
	return lanes.map((lane, index) => ({
		...lane,
		status: index === 0 ? "in_progress" : "pending",
		updatedAt: timestamp,
	}));
}

const MISSION_CHECKPOINTS_FULL: MissionCheckpoint[] = [
	{ name: "route_selected", status: "done", note: "REPI route created" },
	{ name: "execution_kernel_ready", status: "pending" },
	{ name: "decision_core_ready", status: "pending" },
	{ name: "tool_index_checked", status: "pending" },
	{ name: "passive_map_done", status: "pending" },
	{ name: "live_browser_ready", status: "pending" },
	{ name: "web_authz_ready", status: "pending" },
	{ name: "exploit_lab_ready", status: "pending" },
	{ name: "mobile_runtime_ready", status: "pending" },
	{ name: "native_runtime_ready", status: "pending" },
	{ name: "minimal_path_proven", status: "pending" },
	{ name: "evidence_ledger_updated", status: "pending" },
	{ name: "repro_commands_ready", status: "pending" },
	{ name: "attack_graph_ready", status: "pending" },
	{ name: "exploit_chain_ready", status: "pending" },
	{ name: "campaign_plan_ready", status: "pending" },
	{ name: "operation_queue_ready", status: "pending" },
	{ name: "delegation_packets_ready", status: "pending" },
	{ name: "swarm_plan_ready", status: "pending" },
	{ name: "supervisor_review_ready", status: "pending" },
	{ name: "operator_queue_ready", status: "pending" },
	{ name: "verifier_matrix_ready", status: "pending" },
	{ name: "compiler_ready", status: "pending" },
	{ name: "replay_ready", status: "pending" },
	{ name: "autofix_ready", status: "pending" },
	{ name: "proof_loop_ready", status: "pending" },
	{ name: "report_or_writeup_ready", status: "pending" },
];
const MISSION_CHECKPOINTS_CORE = [
	"route_selected",
	"execution_kernel_ready",
	"decision_core_ready",
	"tool_index_checked",
	"passive_map_done",
	"minimal_path_proven",
	"evidence_ledger_updated",
	"repro_commands_ready",
	"report_or_writeup_ready",
];

/** Checkpoints that must be closed by a runtime artifact, never by a model/operator note. */
export const RUNTIME_OWNED_MISSION_CHECKPOINTS: ReadonlySet<string> = new Set([
	"minimal_path_proven",
	"verifier_matrix_ready",
	"compiler_ready",
	"replay_ready",
	"proof_loop_ready",
	"report_or_writeup_ready",
]);

export function normalizeOperatorCheckpointUpdate(
	name: string,
	status: MissionCheckpointStatus,
	note?: string,
): { status: MissionCheckpointStatus; note: string | undefined } {
	if (status !== "done" || !RUNTIME_OWNED_MISSION_CHECKPOINTS.has(name)) return { status, note };
	return {
		status: "blocked",
		note: `operator checkpoint rejected: ${name} is runtime-owned; close it through its evidence artifact and completion audit`,
	};
}

const MISSION_CHECKPOINTS_BY_DOMAIN: Record<string, string[]> = {
	"Native reverse": [
		"native_runtime_ready",
		"verifier_matrix_ready",
		"compiler_ready",
		"replay_ready",
		"proof_loop_ready",
	],
	"Pwn / exploit": [
		"native_runtime_ready",
		"exploit_lab_ready",
		"exploit_chain_ready",
		"verifier_matrix_ready",
		"compiler_ready",
		"replay_ready",
		"proof_loop_ready",
	],
	"Exploit reliability": [
		"exploit_lab_ready",
		"exploit_chain_ready",
		"verifier_matrix_ready",
		"replay_ready",
		"proof_loop_ready",
	],
	"Web / API pentest": [
		"live_browser_ready",
		"web_authz_ready",
		"attack_graph_ready",
		"operation_queue_ready",
		"verifier_matrix_ready",
		"compiler_ready",
		"replay_ready",
	],
	"Web pentest scanning": [
		"live_browser_ready",
		"web_authz_ready",
		"attack_graph_ready",
		"operation_queue_ready",
		"verifier_matrix_ready",
		"compiler_ready",
		"replay_ready",
	],
	"Frontend JS reverse": [
		"live_browser_ready",
		"web_authz_ready",
		"attack_graph_ready",
		"verifier_matrix_ready",
		"compiler_ready",
		"replay_ready",
	],
	"Mobile / Android": [
		"mobile_runtime_ready",
		"native_runtime_ready",
		"verifier_matrix_ready",
		"compiler_ready",
		"replay_ready",
	],
	"Mobile / iOS": [
		"mobile_runtime_ready",
		"native_runtime_ready",
		"verifier_matrix_ready",
		"compiler_ready",
		"replay_ready",
	],
	"Agent / LLM boundary": [
		"delegation_packets_ready",
		"swarm_plan_ready",
		"supervisor_review_ready",
		"operator_queue_ready",
		"verifier_matrix_ready",
		"compiler_ready",
		"proof_loop_ready",
	],
	"CTF / sandbox": [
		"native_runtime_ready",
		"exploit_lab_ready",
		"verifier_matrix_ready",
		"compiler_ready",
		"replay_ready",
	],
	"Crypto / stego": ["verifier_matrix_ready", "compiler_ready", "replay_ready", "proof_loop_ready"],
	"Malware analysis": [
		"native_runtime_ready",
		"attack_graph_ready",
		"verifier_matrix_ready",
		"compiler_ready",
		"replay_ready",
	],
	"Firmware / IoT": [
		"native_runtime_ready",
		"attack_graph_ready",
		"operation_queue_ready",
		"verifier_matrix_ready",
		"compiler_ready",
	],
	"Memory forensics": ["attack_graph_ready", "verifier_matrix_ready", "compiler_ready", "replay_ready"],
	"DFIR / PCAP / stego": ["attack_graph_ready", "verifier_matrix_ready", "compiler_ready", "replay_ready"],
	"Cloud / container": [
		"attack_graph_ready",
		"operation_queue_ready",
		"verifier_matrix_ready",
		"compiler_ready",
		"replay_ready",
	],
	"Identity / Windows / AD": [
		"attack_graph_ready",
		"operation_queue_ready",
		"verifier_matrix_ready",
		"compiler_ready",
		"replay_ready",
	],
	"Reverse/Pentest general": [
		"attack_graph_ready",
		"operation_queue_ready",
		"operator_queue_ready",
		"verifier_matrix_ready",
		"compiler_ready",
		"replay_ready",
		"proof_loop_ready",
	],
};

export function defaultMissionCheckpoints(route?: RoutePlan): MissionCheckpoint[] {
	if (!route) return MISSION_CHECKPOINTS_FULL.map((checkpoint) => ({ ...checkpoint }));
	const wanted = new Set([...MISSION_CHECKPOINTS_CORE, ...(MISSION_CHECKPOINTS_BY_DOMAIN[route.domain] ?? [])]);
	return MISSION_CHECKPOINTS_FULL.filter((checkpoint) => wanted.has(checkpoint.name)).map((checkpoint) => ({
		...checkpoint,
	}));
}

export function createMission(task: string, route: RoutePlan): MissionState {
	const timestamp = new Date().toISOString();
	const safeTask = redactSensitiveText(task);
	const id = createHash("sha256").update(`${timestamp}\n${route.domain}\n${safeTask}`).digest("hex").slice(0, 12);
	return {
		id,
		createdAt: timestamp,
		updatedAt: timestamp,
		task: safeTask,
		scope: missionScope(),
		route,
		lanes: initializeMissionLanes(missionLanesForRoute(route)),
		checkpoints: defaultMissionCheckpoints(route),
	};
}

function missionScope(): string {
	return `cwd:${sha256Text(missionStorageScope()).slice(0, 16)}`;
}

export function normalizeMission(mission: MissionState): MissionState {
	let sawActive = false;
	const timestamp = new Date().toISOString();
	const inheritedTimestamp = mission.updatedAt || mission.createdAt || timestamp;
	const lanes = mission.lanes.map((lane, index) => {
		let status = lane.status ?? (index === 0 ? "in_progress" : "pending");
		let updatedAt = lane.updatedAt ?? inheritedTimestamp;
		if (status === "in_progress") {
			if (sawActive) {
				status = "pending";
				updatedAt = timestamp;
			} else sawActive = true;
		}
		return { ...lane, status, updatedAt };
	});
	if (!sawActive) {
		const firstPending = lanes.findIndex((lane) => lane.status === "pending");
		if (firstPending >= 0)
			lanes[firstPending] = { ...lanes[firstPending], status: "in_progress", updatedAt: timestamp };
	}
	return { ...mission, task: redactSensitiveText(mission.task), scope: missionScope(), lanes };
}

function parseMission(text: string | undefined): MissionState | undefined {
	if (!text?.trim()) return undefined;
	try {
		return JSON.parse(text) as MissionState;
	} catch {
		return undefined;
	}
}

function normalizeStoredMission(mission: MissionState | undefined): MissionState | undefined {
	if (isInactiveMission(mission)) return undefined;
	if (
		!mission ||
		mission.scope !== missionScope() ||
		!Array.isArray(mission.lanes) ||
		!Array.isArray(mission.checkpoints)
	)
		return undefined;
	try {
		return normalizeMission(mission);
	} catch {
		return undefined;
	}
}

function isInactiveMission(mission: MissionState | undefined): boolean {
	const status = (mission as (MissionState & { status?: unknown }) | undefined)?.status;
	return status === "closed" || status === "empty";
}

function acquireMissionLock(path: string): () => void {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	let lastError: unknown;
	for (let attempt = 0; attempt < 10; attempt++) {
		try {
			return lockfile.lockSync(path, { realpath: false, stale: 30_000 });
		} catch (error) {
			const code =
				typeof error === "object" && error !== null && "code" in error
					? String((error as { code?: unknown }).code)
					: undefined;
			if (code !== "ELOCKED" || attempt === 9) throw error;
			lastError = error;
			const waitUntil = Date.now() + 20;
			while (Date.now() < waitUntil) {
				// Mission writes are synchronous and the lock is held only around one small JSON write.
			}
		}
	}
	throw lastError instanceof Error ? lastError : new Error("Failed to acquire mission lock");
}

function itemTimestamp(item: { updatedAt?: string }): number {
	const parsed = Date.parse(item.updatedAt ?? "");
	return Number.isFinite(parsed) ? parsed : 0;
}

function mergeMissionItems<T extends { name: string; updatedAt?: string }>(current: T[], candidate: T[]): T[] {
	const remaining = new Map(current.map((item) => [item.name, item]));
	const merged = candidate.map((item) => {
		const existing = remaining.get(item.name);
		remaining.delete(item.name);
		return existing && itemTimestamp(existing) > itemTimestamp(item) ? existing : item;
	});
	return [...merged, ...remaining.values()];
}

function mergeConcurrentMission(current: MissionState | undefined, candidate: MissionState): MissionState {
	const normalizedCurrent = normalizeStoredMission(current);
	if (!normalizedCurrent || normalizedCurrent.id !== candidate.id) return candidate;
	return normalizeMission({
		...candidate,
		createdAt: normalizedCurrent.createdAt,
		lanes: mergeMissionItems(normalizedCurrent.lanes, candidate.lanes),
		checkpoints: mergeMissionItems(normalizedCurrent.checkpoints, candidate.checkpoints),
	});
}

function withMissionLock(mutate: (current: MissionState | undefined) => MissionState): MissionState {
	ensureRepiStorage();
	const path = currentMissionPath();
	const release = acquireMissionLock(path);
	try {
		const current = parseMission(readTextFile(path, ""));
		const mission = mutate(current);
		const next = normalizeMission({ ...mission, updatedAt: new Date().toISOString() });
		writePrivateTextFile(path, `${JSON.stringify(next, null, 2)}\n`);
		return next;
	} finally {
		release();
	}
}

export function writeCurrentMission(mission: MissionState): MissionState {
	return withMissionLock((current) => mergeConcurrentMission(current, normalizeMission(mission)));
}

export function updateMissionCheckpoint(name: string, status: MissionCheckpointStatus, note?: string): MissionState {
	return withMissionLock((current) => {
		if (isInactiveMission(current)) return current as MissionState;
		const mission =
			normalizeStoredMission(current) ?? createMission("manual mission", routeRepiTask(REPI_GENERIC_TASK));
		const updatedAt = new Date().toISOString();
		const checkpoints = mission.checkpoints.some((checkpoint) => checkpoint.name === name)
			? mission.checkpoints.map((checkpoint) =>
					checkpoint.name === name ? { ...checkpoint, status, note, updatedAt } : checkpoint,
				)
			: [...mission.checkpoints, { name, status, note, updatedAt }];
		return { ...mission, checkpoints };
	});
}

export function updateMissionRuntimeStats(runtimeStats: MissionRuntimeStats): MissionState {
	return withMissionLock((current) => {
		if (isInactiveMission(current)) return current as MissionState;
		const mission =
			normalizeStoredMission(current) ?? createMission("manual mission", routeRepiTask(REPI_GENERIC_TASK));
		return {
			...mission,
			runtimeStats: {
				...runtimeStats,
				lastCommands: runtimeStats.lastCommands.slice(-8),
			},
		};
	});
}

export function readCurrentMission(): MissionState | undefined {
	ensureRepiStorage();
	// The mission changes only through mission operations, whose atomic rename
	// invalidates this mtime+size cache. normalizeMission returns a fresh copy, so
	// callers cannot mutate the cached object.
	const raw = readJsonObjectFileCached<MissionState>(currentMissionPath());
	if (!raw) return undefined;
	const lifecycle = raw as MissionState & { status?: unknown };
	if (lifecycle.status === "closed" || lifecycle.status === "empty") return undefined;
	if (raw.scope !== missionScope()) return undefined;
	try {
		return normalizeMission(raw);
	} catch {
		return undefined;
	}
}

type MissionSessionContext = {
	sessionManager?: {
		getBranch?: () => readonly unknown[];
		getEntries?: () => readonly unknown[];
	};
};

/** Return the workspace mission only when the current session actually owns it. */
export function readCurrentSessionMission(ctx: MissionSessionContext): MissionState | undefined {
	const mission = readCurrentMission();
	if (!mission || !ctx.sessionManager) return undefined;
	const entries = ctx.sessionManager.getBranch?.() ?? ctx.sessionManager.getEntries?.() ?? [];
	for (let index = entries.length - 1; index >= 0; index--) {
		const entry = entries[index] as { type?: string; customType?: string; data?: unknown };
		if (entry.type !== "custom") continue;
		if (entry.customType !== "repi-mission" && entry.customType !== "repi-route") continue;
		const data = entry.data as { missionId?: unknown } | undefined;
		if (typeof data?.missionId === "string") return data.missionId === mission.id ? mission : undefined;
	}
	return undefined;
}

/**
 * Map a mission lane to a builtin specialist spec for opt-in specialist
 * dispatch. Returns undefined when no specialist clearly owns the lane (the
 * caller then falls back to the inline autopilot path). Matching is keyword
 * based over lane.name + lane.objective + route.domain so it stays generic
 * across all routes — no per-route special-casing.
 */
export function laneSpec(
	lane: MissionLane,
	route: RoutePlan,
): "explorer" | "reverser" | "operator" | "verifier" | undefined {
	const hay = `${lane.name} ${lane.objective} ${route.domain}`.toLowerCase();
	const has = (needle: string): boolean => hay.includes(needle);
	if (has("verif") || has("proof") || has("report") || has("audit") || has("supervisor") || has("qa")) {
		return "verifier";
	}
	if (
		has("revers") ||
		has("pwn") ||
		has("firmware") ||
		has("malware") ||
		has("memory") ||
		has("dfir") ||
		has("pcap") ||
		has("crypto") ||
		has("native") ||
		has("mobile") ||
		has("exploit") ||
		has("primitive") ||
		has("mitigation") ||
		has("disasm") ||
		has("decompil")
	) {
		return "reverser";
	}
	if (
		has("map") ||
		has("surface") ||
		has("recon") ||
		has("passive") ||
		has("identity") ||
		has("web") ||
		has("cloud") ||
		has("enum") ||
		has("inventory") ||
		has("discover")
	) {
		return "explorer";
	}
	if (has("run") || has("execute") || has("command") || has("operate") || has("launch")) {
		return "operator";
	}
	return undefined;
}
