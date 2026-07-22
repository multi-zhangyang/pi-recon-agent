#!/usr/bin/env node
import { createHash } from "node:crypto";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	readFileSync,
	readdirSync,
	statSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { atomicWriteFile } from "./lib/atomic-file.mjs";

const commandNames = new Set([
	"new",
	"start",
	"init",
	"plan",
	"status",
	"show",
	"doctor",
	"next",
	"pack",
	"context",
	"resume",
	"close",
	"done",
	"complete",
	"reset",
	"clear",
	"help",
]);
const argv = process.argv.slice(2);
const rootArg =
	argv[0] && !argv[0].startsWith("-") && !commandNames.has(argv[0].toLowerCase()) ? argv.shift() : undefined;
const root = resolve(rootArg ?? process.cwd());
const command = argv[0] && (!argv[0].startsWith("-") || ["--help", "-h"].includes(argv[0])) ? argv.shift().toLowerCase() : "status";
const json = argv.some((arg) => arg === "--json");
const agentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const missionDir = join(agentDir, "recon", "mission");
const evidenceDir = join(agentDir, "recon", "evidence");
const contextDir = join(evidenceDir, "contexts");
const configuredMissionScope = process.env.REPI_MISSION_SCOPE?.trim();
const sessionMissionScope = process.env.REPI_MISSION_SESSION_SCOPE?.trim();
const workspaceMissionScope = configuredMissionScope || process.cwd();
const effectiveMissionScope = sessionMissionScope
	? `${workspaceMissionScope}\nsession:${sessionMissionScope}`
	: workspaceMissionScope;
const missionStorageScope = sessionMissionScope
	? effectiveMissionScope
	: configuredMissionScope;
const missionPath = missionStorageScope
	? join(missionDir, `current-${createHash("sha256").update(missionStorageScope).digest("hex").slice(0, 16)}.json`)
	: join(missionDir, "current.json");
const historyPath = join(missionDir, "history.jsonl");
const operatorCwd = resolve(process.env.REPI_OPERATOR_CWD || process.env.PWD || process.cwd());

const ROUTES = [
	{
		id: "ctf-sandbox",
		domain: "CTF / sandbox",
		prompt: "ctf",
		match: /\b(ctf|challenge|flag|sandbox|靶场|题目)\b/i,
		workflow: ["artifact/route inventory", "dominant evidence selection", "minimal solve path", "clean replay", "writeup"],
		tools: ["rg", "file/strings", "python", "gdb/lldb", "curl", "re_verifier"],
		evidence: ["challenge assets", "transform or exploit chain", "solver/replay script", "flag source", "clean-room verification"],
	},
	{
		id: "exploit-reliability",
		domain: "Exploit reliability",
		prompt: "exploit-reliability",
		match: /\b(autopwn|auto[-_ ]?pwn|exploit reliability|reliable exploit|stable exploit|poc replay|replay matrix|payload stability|flake triage|one[-_ ]?click exploit)\b|利用链.*稳定|稳定.*poc|复现矩阵|一键.*利用/i,
		workflow: ["PoC inventory", "environment pinning", "replay matrix", "flake triage", "artifact bundle"],
		tools: ["python/pwntools", "timeout", "sha256sum", "docker", "jq", "re_exploit_lab"],
		evidence: ["target/env pins", "N-run replay stats", "stdout/stderr hashes", "failure buckets", "stable runner"],
	},
	{
		id: "agent-boundary",
		domain: "Agent / LLM boundary",
		prompt: "agent-boundary",
		match: /\b(prompt injection|indirect prompt|tool injection|function call|tool-call|mcp|model context protocol|rag|retrieval|memory poisoning|jailbreak)\b|agent\s*安全|llm\s*安全|记忆投毒|工具滥用|越狱/i,
		workflow: ["prompt/tool surface", "session/context/RAG boundary", "injection replay", "tool-call trace", "delegation proof"],
		tools: ["rg", "jq", "re_mission", "re_evidence", "re_verifier"],
		evidence: ["untrusted content flow", "tool schema boundary", "replay transcript", "context source hit/miss", "capability drift edge"],
	},
	{
		id: "web-scan",
		domain: "Web pentest scanning",
		prompt: "webscan",
		match: /\b(vuln(?:erability)? scan|web scan|nuclei|ffuf|gobuster|feroxbuster|nikto|dalfox|sqlmap|crawl|waf)\b|漏洞扫描|目录扫描|指纹|资产发现|爬虫/i,
		workflow: ["scope baseline", "crawl/route corpus", "template scan queue", "manual replay verification", "finding report"],
		tools: ["curl/httpx", "katana", "ffuf/gobuster", "nuclei/nikto/dalfox/sqlmap", "jq"],
		evidence: ["baseline headers", "route corpus", "scanner JSONL", "manual replay diff", "finding queue"],
	},
	{
		id: "web-api",
		domain: "Web / API",
		prompt: "websec",
		match: /\b(web|http|https|api|graphql|rest|route|endpoint|auth|session|jwt|cookie|oauth|idor|bola|cors|csrf|ssrf|xss|sql|sqli|ssti|rce)\b|接口|登录|鉴权|授权|越权|渗透/i,
		workflow: ["route inventory", "auth/session baseline", "request replay", "state/authorization proof", "verifier/replayer"],
		tools: ["curl/httpie", "browser/CDP", "mitmproxy/burp", "jq", "re_web_authz_state", "re_live_browser"],
		evidence: ["routes", "requests/responses", "principal matrix", "object ownership", "replay commands"],
	},
	{
		id: "js-reverse",
		domain: "Frontend / JS reverse",
		prompt: "jsre",
		match: /\b(js|javascript|webpack|vite|sign|signature|crypto\.subtle|wasm|bundle|xhr|fetch|websocket|anti-debug)\b/i,
		workflow: ["asset inventory", "beautify/deobfuscate", "signing path trace", "first divergence", "replayer"],
		tools: ["node", "playwright/CDP", "esbuild", "jq", "re_live_browser"],
		evidence: ["served assets", "signing function anchors", "request diff", "replay script", "verification matrix"],
	},
	{
		id: "native-pwn",
		domain: "Native / Pwn",
		prompt: "native",
		match: /\b(binary|elf|pe|macho|so|exe|pwn|rop|heap|tcache|format-string|shellcode|crash|core|gdb|lldb|libc|ret2|srop)\b/i,
		workflow: ["file/mitigation map", "imports/strings/xrefs", "crash or trace primitive", "exploit hypothesis", "local replay"],
		tools: ["file/readelf/checksec", "r2/ghidra", "gdb/lldb", "pwntools", "re_native_runtime"],
		evidence: ["hash/arch/mitigations", "crash registers", "offset/leak source", "controlled bytes", "replay PoC"],
	},
	{
		id: "mobile-ios",
		domain: "Mobile / iOS",
		prompt: "ios",
		match: /\b(ipa|ios|objective-c|objc|swift|mach-o|class-dump|otool|codesign|entitlements|keychain|jailbreak)\b|越狱/i,
		workflow: ["IPA inventory", "Info.plist/entitlements", "Mach-O/class map", "Frida/objection hooks", "network/keychain replay"],
		tools: ["unzip/plutil", "otool/nm", "codesign", "frida", "objection", "re_mobile_runtime"],
		evidence: ["IPA/hash", "plist/entitlement anchors", "selector/class map", "hook scripts", "replay commands"],
	},
	{
		id: "mobile",
		domain: "Mobile reverse",
		prompt: "mobile",
		match: /\b(apk|ipa|android|ios|jadx|apktool|frida|objection|keystore|keychain|pinning|root|emulator|magisk)\b/i,
		workflow: ["package inventory", "manifest/permission map", "static hooks", "runtime trace", "bypass/replay proof"],
		tools: ["jadx/apktool", "frida", "adb", "objection", "re_mobile_runtime"],
		evidence: ["package/hash", "manifest anchors", "hook scripts", "runtime trace", "replay commands"],
	},
	{
		id: "memory-forensics",
		domain: "Memory forensics",
		prompt: "memfor",
		match: /\b(memory dump|memdump|vmem|mem\.raw|hiberfil|pagefile|volatility|lsass dump|crash dump)\b|内存取证|内存镜像|内存转储/i,
		workflow: ["image/profile", "process/network map", "credential/artifact hunt", "timeline/carve", "report"],
		tools: ["volatility3", "file/sha256sum", "strings", "yara", "python"],
		evidence: ["image hash/profile", "process tree", "network/session rows", "dumped artifact hashes", "timeline"],
	},
	{
		id: "pcap-dfir",
		domain: "PCAP / DFIR",
		prompt: "pcap",
		match: /\b(pcap|traffic|wireshark|tshark|forensic|dfir|memory dump|volatility|timeline|ioc)\b/i,
		workflow: ["artifact fingerprint", "stream/session ranking", "transform chain", "secret/ioc timeline", "report"],
		tools: ["tshark", "tcpdump", "volatility", "strings", "python"],
		evidence: ["hash/magic", "flow table", "stream extracts", "decoded payloads", "timeline"],
	},
	{
		id: "firmware-iot",
		domain: "Firmware / IoT",
		prompt: "firmware",
		match: /\b(firmware|iot|router|rootfs|squashfs|ubi|uimage|binwalk|unblob|busybox|nvram|cgi)\b/i,
		workflow: ["image fingerprint", "extract rootfs", "service/config map", "emulation smoke", "web/API proof"],
		tools: ["binwalk/unblob", "unsquashfs", "qemu", "grep", "re_web_authz_state"],
		evidence: ["image hash", "rootfs path", "service list", "credentials/config anchors", "emulation/replay"],
	},
	{
		id: "cloud-identity",
		domain: "Cloud / Identity",
		prompt: "cloud",
		match: /\b(cloud|aws|gcp|azure|k8s|kubernetes|iam|sts|role|serviceaccount|metadata|rbac|terraform|docker)\b/i,
		workflow: ["credential/config map", "runtime identity", "permission graph", "metadata probe", "least proof"],
		tools: ["aws/gcloud/az/kubectl", "jq", "docker", "terraform", "re_graph"],
		evidence: ["identity anchors", "RBAC/IAM edges", "metadata status", "privilege path", "replay commands"],
	},
	{
		id: "windows-ad",
		domain: "Identity / Windows / AD",
		prompt: "ad",
		match: /\b(ad|active directory|kerberos|ntlm|ldap|spn|smb|winrm|lsass|mimikatz|bloodhound|certipy|impacket|netexec|nxc|domain controller)\b|域控|内网|横向|提权|凭据/i,
		workflow: ["principal map", "credential usability", "privilege graph", "pivot proof", "evidence report"],
		tools: ["ldapsearch/impacket", "netexec/nxc", "bloodhound-python", "certipy", "jq"],
		evidence: ["principal/group/SPN rows", "credential check output", "graph edge", "single-command proof", "event/log anchors"],
	},
	{
		id: "malware",
		domain: "Malware / sample analysis",
		prompt: "malware",
		match: /\b(malware|sample|yara|capa|floss|packer|upx|ioc|c2|mutex|persistence|sandbox)\b/i,
		workflow: ["static triage", "rule/capability scan", "config/ioc extraction", "behavior trace", "report"],
		tools: ["file/strings", "yara/capa/floss", "strace/ltrace", "python", "clamscan"],
		evidence: ["hash/magic", "rule hits", "config/IOC anchors", "behavior trace", "replay commands"],
	},
	{
		id: "crypto-stego",
		domain: "Crypto / Stego",
		prompt: "reverse",
		match: /\b(crypto|cipher|rsa|aes|xor|hash|padding|oracle|stego|image|exif|metadata|zsteg|png|jpg|jpeg|wav|flac|enc|nonce|salt|lattice|sage|z3)\b/i,
		workflow: ["artifact inventory", "parameter extraction", "transform chain", "oracle/test vector", "solve verifier"],
		tools: ["python", "openssl", "sage", "exiftool", "zsteg/binwalk"],
		evidence: ["params", "known plaintext/test vectors", "transform script", "decoded artifact", "verification"],
	},
];

function usage() {
	return `Usage:
  repi mission new <task> [--target <target>] [--domain <domain>] [--json]
  repi mission plan [task] [--target <target>] [--domain <domain>] [--json]
  repi mission status [--json]
  repi mission next [--json]
  repi mission pack [--output <path>] [--json]
  repi mission close [--summary <text>] [--json]
  repi mission reset [--yes] [--json]

Mission Control is the task-level control plane. It creates a scoped mission,
selects the reverse/pentest lane, writes an evidence contract, generates the
next operator commands, and emits a compact resume pack for the current task.
`;
}

const valueFlags = new Set(["--target", "--domain", "--summary", "--output", "-o"]);

function argValue(...flags) {
	for (let index = 0; index < argv.length; index++) {
		const arg = argv[index];
		for (const flag of flags) {
			if (arg === flag) {
				const next = argv[index + 1];
				return next && !next.startsWith("--") ? next : "";
			}
			if (arg.startsWith(`${flag}=`)) return arg.slice(flag.length + 1);
		}
	}
	return undefined;
}

function hasFlag(flag) {
	return argv.some((arg) => arg === flag || arg.startsWith(`${flag}=`));
}

function positionalText() {
	const parts = [];
	for (let index = 0; index < argv.length; index++) {
		const arg = argv[index];
		if (arg === "--") {
			parts.push(...argv.slice(index + 1));
			break;
		}
		if (arg.startsWith("--")) {
			const flag = arg.includes("=") ? arg.slice(0, arg.indexOf("=")) : arg;
			if (!arg.includes("=") && valueFlags.has(flag)) index++;
			continue;
		}
		if (arg.startsWith("-") && valueFlags.has(arg)) {
			index++;
			continue;
		}
		parts.push(arg);
	}
	return parts.join(" ").trim();
}

function writePrivate(path, text) {
	// Mission state/context artifacts are resume-critical. Write them via a
	// same-directory temp+rename so ENOSPC/EACCES/crash cannot leave a
	// truncated current.json/context pack that loses the active evidence plan.
	try {
		mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
		atomicWriteFile(path, text, 0o600);
	} catch (error) {
		throw new Error(`Error writing mission artifact to ${path}: ${error instanceof Error ? error.message : String(error)}`);
	}
	try {
		chmodSync(path, 0o600);
	} catch {
		// Best effort.
	}
}

function appendPrivate(path, text) {
	const old = existsSync(path) ? readFileSync(path, "utf8") : "";
	writePrivate(path, `${old}${text}`);
}

function readJson(path) {
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch {
		return undefined;
	}
}

function sha(value) {
	return createHash("sha256").update(String(value)).digest("hex").slice(0, 16);
}

function redact(value) {
	return String(value ?? "")
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\b(?:A3T|AKIA|ASIA)[A-Z0-9]{16}\b/g, "<redacted:aws-access-key>")
		.replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "<redacted:jwt>")
		.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "<redacted:private-key>")
		.replace(/(?:AUTH_TOKEN|API_KEY|PASSWORD|SECRET|TOKEN|ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|CLIENT_SECRET)=\S+/gi, (match) => `${match.split("=")[0]}=<redacted>`);
}

function slugify(value) {
	return String(value || "mission")
		.toLowerCase()
		.replace(/[^a-z0-9\u4e00-\u9fa5]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(0, 42) || "mission";
}

function nowStamp() {
	return new Date().toISOString();
}

function compactTime() {
	return new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
}

function selectRoute(task, explicitDomain, explicitTarget) {
	const text = `${task || ""} ${explicitTarget || ""} ${explicitDomain || ""}`;
	if (explicitDomain) {
		const normalizedDomain = explicitDomain.toLowerCase();
		const byDomain = ROUTES.find(
			(route) =>
				route.id.toLowerCase() === normalizedDomain ||
				route.prompt.toLowerCase() === normalizedDomain ||
				route.domain.toLowerCase().includes(normalizedDomain),
		);
		if (byDomain) return byDomain;
	}
	return ROUTES.find((route) => route.match.test(text)) ?? {
		id: "reverse-pentest-general",
		domain: "Reverse/Pentest general",
		prompt: "reverse",
		workflow: ["passive map", "choose one minimal proof path", "execute bounded verification", "compile evidence", "record reusable lesson only if high-value"],
		tools: ["rg", "file/strings", "curl", "python", "re_verifier", "re_compiler"],
		evidence: ["target inventory", "runtime or artifact anchors", "verification command", "claim matrix", "next step"],
	};
}

function shellQuote(value) {
	const text = String(value || ".");
	return `'${text.replace(/'/g, "'\\''")}'`;
}

function lanesForRoute(route) {
	const lanesByRoute = {
		"web-api": [
			{ id: "surface", objective: "映射 routes/auth/session/middleware/workers/storage", exit: "有真实入口、请求顺序和状态存储 anchor" },
			{ id: "authz-state", objective: "建立多身份 principal/object/state 矩阵", exit: "有 token/cookie/session diff 与对象归属证据" },
			{ id: "replay", objective: "构造最小 HTTP replay 证明授权/状态边界", exit: "curl/httpie 命令可复现，含前后状态对照" },
			{ id: "report", objective: "裁剪误报并输出修复/下一步", exit: "Outcome → Evidence → Verification → Next Step 完整" },
		],
		"web-scan": [
			{ id: "scope", objective: "确认 URL、协议、WAF、robots/sitemap/OpenAPI/GraphQL 和扫描边界", exit: "baseline header/body hash 已记录" },
			{ id: "crawl", objective: "构建 bounded route corpus、参数字典、静态资源和登录/未登录差异", exit: "有去重 route/param corpus" },
			{ id: "template-scan", objective: "生成候选发现队列，不直接把扫描命中当漏洞", exit: "scanner JSONL/表格可复查" },
			{ id: "manual-verify", objective: "对每个候选做 replay、body hash、前后状态和误报裁剪", exit: "每个 claim 都有 replay 证据或降级理由" },
		],
		"js-reverse": [
			{ id: "observe", objective: "捕获 XHR/fetch/WS、initiator、参数、nonce/timestamp 和运行时差异", exit: "请求样本和调用栈 anchor 完整" },
			{ id: "trace", objective: "定位签名/加密函数、hook args/return 和 first divergence", exit: "有函数 anchor 与输入输出样本" },
			{ id: "rebuild", objective: "在 Node/浏览器外复现签名或加密链", exit: "本地脚本生成字段可比对" },
			{ id: "verify", objective: "用真实请求验证本地生成结果", exit: "replay 成功或记录明确阻塞差异" },
		],
		"native-pwn": [
			{ id: "mitigations", objective: "确认格式、架构、保护、loader/libc 和崩溃面", exit: "file/checksec/ldd/hash 证据齐全" },
			{ id: "primitive", objective: "证明可控字节、crash、leak 或任意读写原语", exit: "寄存器/堆状态/offset/leak source 可复现" },
			{ id: "exploit", objective: "构造 payload 并验证本地/远程一致性", exit: "pwntools/replay 脚本与稳定性矩阵" },
			{ id: "verify", objective: "反证 ASLR/libc/timeout/IO 差异", exit: "失败桶和边界条件明确" },
		],
		"exploit-reliability": [
			{ id: "inventory", objective: "枚举 PoC、payload、runner、环境假设和目标绑定", exit: "manifest 列出输入/输出/环境 pin" },
			{ id: "normalize", objective: "把一次性 PoC 规范化为可参数化 runner", exit: "参数、超时、日志和 artifact 路径稳定" },
			{ id: "replay-matrix", objective: "多轮执行量化成功率、耗时、输出漂移和失败类型", exit: "N-run stats 与 stdout/stderr hash" },
			{ id: "bundle", objective: "打包稳定 exploit artifact 和 runbook", exit: "一条命令可复现结论" },
		],
		mobile: [
			{ id: "package", objective: "确认 APK/IPA、manifest/plist、权限、证书和 native split", exit: "包 hash 与入口组件 anchor" },
			{ id: "static-hooks", objective: "定位 Java/Kotlin/ObjC/Swift/native 调用链、crypto、pinning、root 检测", exit: "hook 点和代码 anchor" },
			{ id: "runtime-trace", objective: "用 Frida/objection/adb 捕获关键输入输出", exit: "hook 脚本和 trace 可复现" },
			{ id: "network-replay", objective: "复现移动端签名/请求链和证书绑定差异", exit: "replay 命令与请求差异矩阵" },
		],
		"mobile-ios": [
			{ id: "ipa-inventory", objective: "确认 IPA/Payload/App、Info.plist、Entitlements、Mach-O、Frameworks 和 URL schemes", exit: "包结构与 entitlement anchor" },
			{ id: "class-map", objective: "定位 ObjC/Swift selector、Keychain、Crypto、NSURLSession 和 jailbreak 检测", exit: "class/selector/native 符号 map" },
			{ id: "runtime-hooks", objective: "生成 Frida hook 捕获 keychain、crypto、network 和反调试", exit: "hook 脚本和 trace 输出" },
			{ id: "replay", objective: "复现签名/请求链和 TLS pinning/代理差异", exit: "请求重放或明确阻塞证据" },
		],
		"pcap-dfir": [
			{ id: "artifact", objective: "确认 pcap/取证文件 hash、magic、时间范围和解析工具", exit: "capinfos/file/sha256 anchor" },
			{ id: "flow", objective: "排序会话、DNS/TLS/HTTP、凭据/对象和可疑流", exit: "flow table 与 stream ranking" },
			{ id: "extract-decode", objective: "提取对象并还原编码、压缩、隐写 transform chain", exit: "artifact hash 与 decode 脚本" },
			{ id: "timeline", objective: "编译 IOC/secret/timeline 并验证来源包", exit: "packet/frame/stream 来源可追溯" },
		],
		"memory-forensics": [
			{ id: "image-info", objective: "确认镜像格式、hash、OS/profile 和 volatility 插件", exit: "profile 选择有证据" },
			{ id: "process-network", objective: "枚举进程树、命令行、模块、句柄、连接和隐藏/注入迹象", exit: "可疑对象有插件输出 anchor" },
			{ id: "credential-artifacts", objective: "定位凭据、token、浏览器/registry/artifact 并验证来源", exit: "dumped artifact hash 与来源 plugin" },
			{ id: "timeline-carve", objective: "建立 timeline、filescan/dumpfiles/carving 和 IOC 链", exit: "timeline 与恢复文件可复查" },
		],
		"firmware-iot": [
			{ id: "image", objective: "确认固件封装、hash、架构、压缩/文件系统和候选 rootfs", exit: "image hash/magic/entropy/rootfs anchor" },
			{ id: "extract", objective: "提取 rootfs、kernel、web 资源、配置层和嵌入 payload", exit: "可复现提取命令和路径" },
			{ id: "surface", objective: "映射账号、密钥、NVRAM、init、服务、Web/API/CGI", exit: "服务/端点/配置证据表" },
			{ id: "emulate", objective: "构造 QEMU/chroot/用户态复现脚手架", exit: "服务 smoke 或明确阻塞原因" },
		],
		"cloud-identity": [
			{ id: "identity", objective: "映射云凭据、K8s serviceaccount、运行时身份和当前 principal", exit: "whoami/token audience/RBAC anchor" },
			{ id: "runtime-config", objective: "确认容器/K8s/IaC/云 CLI 的真实运行配置和命名空间边界", exit: "context/namespace/IaC path" },
			{ id: "metadata", objective: "验证 metadata/instance identity 路径和 token 可用性", exit: "metadata status 与 token scope" },
			{ id: "privilege", objective: "证明最小权限边或可达资源边界", exit: "single-command least proof" },
		],
		"windows-ad": [
			{ id: "principals", objective: "枚举域、DC、用户、组、SPN、证书服务和协议面", exit: "principal/group/SPN rows" },
			{ id: "credentials", objective: "验证凭据/ticket/hash 的可用性和约束", exit: "单命令认证结果" },
			{ id: "graph", objective: "构建权限图并定位最小 privilege edge", exit: "edge/path 有来源证据" },
			{ id: "pivot-proof", objective: "证明一个最小横向/提权/访问路径", exit: "命令、输出和回滚/边界说明" },
		],
		malware: [
			{ id: "triage", objective: "确认样本格式、hash、packer/sections/imports 和执行约束", exit: "hash/magic/import/entropy anchor" },
			{ id: "static-config", objective: "提取 C2、mutex、路径、注册表、UA、YARA/capa/FLOSS 线索", exit: "IOC/config table" },
			{ id: "behavior", objective: "受控 trace 证明文件/进程/网络/反调试行为", exit: "trace 输出和行为证据" },
			{ id: "decode", objective: "复原配置或 payload transform chain", exit: "decode 脚本和已验证输出" },
		],
		"crypto-stego": [
			{ id: "inventory", objective: "盘点密文/文件/参数/编码/大整数/metadata/oracle 面", exit: "参数和格式 evidence table" },
			{ id: "transform", objective: "复原编码、压缩、异或、分组模式、隐写提取 chain", exit: "transform 脚本和中间 hash" },
			{ id: "solver", objective: "建立约束/数学/密码攻击 solver", exit: "solve.py/Sage/Z3 可复现" },
			{ id: "verify", objective: "用 known-answer 或 replay 验证结果", exit: "assert/known-answer/recovered artifact hash" },
		],
		"agent-boundary": [
			{ id: "surface", objective: "映射 system/developer/user/tool/session-context/RAG/MCP 不可信入口", exit: "boundary graph 与资源清单" },
			{ id: "tool-boundary", objective: "证明工具调用、shell/API 参数、schema 校验和输出回灌边界", exit: "tool schema + trace 证据" },
			{ id: "injection-replay", objective: "构造间接 prompt/tool injection replay harness", exit: "最小复现 transcript" },
			{ id: "delegation", objective: "追踪 MCP/resource/sub-agent/delegation 权限漂移边", exit: "capability drift 证据" },
		],
		"ctf-sandbox": [
			{ id: "map", objective: "盘点题目文件、服务、格式、入口和可控输入", exit: "路径/hash/端口/入口证据" },
			{ id: "dominant-path", objective: "选择最短解题链路：逆向、pwn、web、crypto、forensics 或混合", exit: "主证据面和假设明确" },
			{ id: "solve", objective: "执行 solver/exploit/decode 并绑定 flag 来源", exit: "solver 脚本、输出和来源 anchor" },
			{ id: "verify", objective: "clean replay 验证，去除偶然状态", exit: "从干净状态一条命令复现" },
		],
	};
	return (
		lanesByRoute[route.id] ?? [
			{ id: "map", objective: "被动映射入口、配置、资产和证据面", exit: "有 hash/path/route/runtime anchor" },
			{ id: "prove", objective: "证明一条最小端到端路径", exit: "有命令、输出摘要、可复现路径" },
			{ id: "verify", objective: "反证检查与报告编译", exit: "verifier matrix 无阻塞矛盾" },
		]
	);
}

function starterCommandsForRoute(route, target) {
	const q = shellQuote(redact(target || "."));
	const generic = [`file ${q} 2>/dev/null || true`, `find ${q} -maxdepth 2 -type f 2>/dev/null | head -100 || true`];
	const commandsByRoute = {
		"web-api": [`curl -skI ${q}`, `curl -sk ${q} | head -c 4096`, `repi engage ${q} --json`],
		"web-scan": [`curl -skI ${q}`, `command -v httpx >/dev/null && httpx -silent -title -tech-detect -u ${q} || true`, `repi engage ${q} --json`],
		"js-reverse": [`curl -sk ${q} | head -c 8192`, `rg -n "fetch|xhr|websocket|sign|encrypt|crypto|subtle" ${q} 2>/dev/null || true`, `repi engage ${q} --json`],
		"native-pwn": [`file ${q}`, `checksec --file=${q} 2>/dev/null || true`, `strings -a ${q} | head -200`],
		"exploit-reliability": [`python3 -m py_compile ${q} 2>/dev/null || true`, `timeout 20s ${q} 2>&1 | tee /tmp/repi-poc-smoke.log`, `sha256sum ${q} 2>/dev/null || true`],
		mobile: [`file ${q}`, `jadx -d jadx-out ${q} 2>/dev/null || true`, `apktool d -f ${q} -o apktool-out 2>/dev/null || true`],
		"mobile-ios": [`unzip -l ${q} | head -100`, `plutil -p Payload/*.app/Info.plist 2>/dev/null || true`, `otool -L Payload/*.app/* 2>/dev/null | head -100 || true`],
		"pcap-dfir": [`file ${q}`, `capinfos ${q} 2>/dev/null || true`, `tshark -r ${q} -q -z conv,tcp 2>/dev/null | head -120 || true`],
		"memory-forensics": [`file ${q}`, `vol -f ${q} windows.info 2>/dev/null || vol -f ${q} linux.banners 2>/dev/null || true`, `strings -a ${q} | head -200`],
		"firmware-iot": [`file ${q}`, `binwalk ${q} 2>/dev/null | head -120 || true`, `strings -a ${q} | head -200`],
		"cloud-identity": [`env | grep -Ei 'AWS|AZURE|GOOGLE|KUBERNETES|TOKEN|ROLE' | sed -E 's/=.*/=<redacted>/'`, `kubectl config current-context 2>/dev/null || true`, `aws sts get-caller-identity 2>/dev/null || true`],
		"windows-ad": [`nxc smb ${q} --shares 2>/dev/null || true`, `ldapsearch -x -H ldap://${q} -s base 2>/dev/null || true`, `certipy find -target ${q} 2>/dev/null || true`],
		malware: [`sha256sum ${q}`, `file ${q}`, `strings -a ${q} | head -300`],
		"crypto-stego": [`file ${q}`, `xxd -l 256 ${q} 2>/dev/null || true`, `exiftool ${q} 2>/dev/null | head -120 || true`],
		"agent-boundary": [`rg -n "system|developer|tool|function|session|transcript|context|mcp|rag|retrieval|prompt" ${q} 2>/dev/null || true`, `find ${q} -maxdepth 3 -type f | head -200`, `repi mission pack`],
		"ctf-sandbox": [`file ${q} 2>/dev/null || true`, `find ${q} -maxdepth 3 -type f -print 2>/dev/null | head -200`, `rg -n "flag|ctf|key|secret|password|token" ${q} 2>/dev/null || true`],
	};
	return commandsByRoute[route.id] ?? generic;
}

function buildPlan(task, options = {}) {
	const rawTarget = options.target || argValue("--target") || task;
	const target = redact(rawTarget);
	const route = selectRoute(task, options.domain, rawTarget);
	const coreDomainById = {
		"ctf-sandbox": "CTF / sandbox",
		"exploit-reliability": "Exploit reliability",
		"agent-boundary": "Agent / LLM boundary",
		"memory-forensics": "Memory forensics",
		"pcap-dfir": "DFIR / PCAP / stego",
		"mobile-ios": "Mobile / iOS",
		mobile: "Mobile / Android",
		"js-reverse": "Frontend JS reverse",
		"web-scan": "Web pentest scanning",
		"web-api": "Web / API pentest",
		"crypto-stego": "Crypto / stego",
		"firmware-iot": "Firmware / IoT",
		"cloud-identity": "Cloud / container",
		"windows-ad": "Identity / Windows / AD",
		malware: "Malware analysis",
		"native-pwn": "Pwn / exploit",
	};
	const coreDomain = coreDomainById[route.id] || "Reverse/Pentest general";
	const basePrompt = `Mission: ${task}\nTarget: ${target}\nRoute: ${route.domain}\nExecute passive map first, prove one end-to-end path, bind claims to evidence, and stop narrative-only drift.`;
	const starterCommands = starterCommandsForRoute(route, target);
	return {
		route: {
			id: route.id,
			domain: coreDomain,
			legacyDomain: route.domain,
			prompt: route.prompt,
			intent: route.workflow[0] || "execute routed reverse/pentest workflow",
			toolchain: route.tools.join(" + "),
			skillHint: route.prompt,
			workflow: route.workflow,
			recommendedTools: route.tools,
		},
		lanes: lanesForRoute(route),
		evidenceContract: {
			required: route.evidence,
			forbidden: ["raw secrets", "cross-task context leakage", "narrative-only exploitability claim"],
			outputOrder: "Outcome → Key Evidence → Verification → Next Step",
		},
		starterCommands,
		nextActions: [
			"repi health",
			...starterCommands.slice(0, 3),
			`repi -p ${JSON.stringify(basePrompt)}`,
			`repi swarm plan ${JSON.stringify(target)} --workers 5`,
			"repi mission pack",
		],
		operatorPrompt: basePrompt,
	};
}

function newMission(task, options = {}) {
	const cleanTask = redact(task || "").trim();
	if (!cleanTask) throw new Error("No mission task provided. Usage: repi mission new <task>");
	const createdAt = nowStamp();
	const plan = buildPlan(cleanTask, options);
	const id = `${compactTime()}-${slugify(cleanTask)}-${sha(`${createdAt}:${cleanTask}`)}`;
	const lanes = plan.lanes.map((lane, index) => ({
		...lane,
		name: lane.id,
		next: [lane.exit],
		status: index === 0 ? "in_progress" : "pending",
		updatedAt: createdAt,
	}));
	const checkpoints = [
		{ name: "route_resolved", status: "done", note: plan.route.domain, updatedAt: createdAt },
		{ name: "passive_map_done", status: "pending", updatedAt: createdAt },
		{ name: "evidence_ledger_updated", status: "pending", updatedAt: createdAt },
		{ name: "completion_audit_ready", status: "pending", updatedAt: createdAt },
	];
	return {
		kind: "repi-mission",
		schemaVersion: 1,
		id,
		status: "active",
		createdAt,
		updatedAt: createdAt,
		workspace: operatorCwd,
		root,
		scope: `cwd:${sha(effectiveMissionScope).slice(0, 16)}`,
		task: cleanTask,
		target: redact(options.target || argValue("--target") || cleanTask),
		route: plan.route,
		lanes,
		checkpoints,
		evidenceContract: plan.evidenceContract,
		starterCommands: plan.starterCommands,
		nextActions: plan.nextActions,
		artifacts: {
			missionPath,
			historyPath,
			contextDir,
			evidenceLedger: join(evidenceDir, "ledger.md"),
		},
		notes: ["Mission state contains only the current task. Close it explicitly with repi mission close."],
	};
}

function saveMission(mission) {
	const normalized = { ...mission, updatedAt: nowStamp() };
	writePrivate(missionPath, `${JSON.stringify(normalized, null, 2)}\n`);
	appendPrivate(historyPath, `${JSON.stringify({ ts: nowStamp(), event: "mission_write", id: normalized.id, status: normalized.status, task: normalized.task, target: normalized.target, route: normalized.route?.id })}\n`);
	return normalized;
}

function loadMission() {
	return readJson(missionPath);
}

function isMissionRecord(value) {
	if (!value || typeof value !== "object" || typeof value.task !== "string") return false;
	if (value.kind === "repi-mission" && value.schemaVersion === 1) return true;
	return (
		typeof value.id === "string" &&
		typeof value.scope === "string" &&
		value.route &&
		Array.isArray(value.lanes) &&
		Array.isArray(value.checkpoints)
	);
}

function isActiveMission(value) {
	return isMissionRecord(value) && value.status !== "closed" && value.status !== "empty";
}

function evidenceTail(maxLines = 60) {
	const path = join(evidenceDir, "ledger.md");
	try {
		const lines = readFileSync(path, "utf8").split(/\r?\n/).filter(Boolean);
		return lines.slice(-maxLines);
	} catch {
		return [];
	}
}

function latestArtifacts(maxItems = 16) {
	const rows = [];
	function walk(dir, depth = 0) {
		if (depth > 3 || !existsSync(dir)) return;
		let entries = [];
		try {
			entries = readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}
		for (const entry of entries) {
			const path = join(dir, entry.name);
			if (entry.isDirectory()) walk(path, depth + 1);
			else if (entry.isFile()) {
				try {
					const stat = statSync(path);
					rows.push({ path, bytes: stat.size, mtimeMs: stat.mtimeMs });
				} catch {
					// Ignore transient artifacts.
				}
			}
		}
	}
	walk(evidenceDir);
	return rows
		.sort((a, b) => b.mtimeMs - a.mtimeMs)
		.slice(0, maxItems)
		.map((row) => ({ path: row.path.replace(`${agentDir}/`, "~/.repi/agent/"), bytes: row.bytes, mtime: new Date(row.mtimeMs).toISOString() }));
}

function buildContextPack(mission) {
	const active = isActiveMission(mission) ? mission : undefined;
	const generatedAt = nowStamp();
	const pack = {
		kind: "repi-mission-context-pack",
		schemaVersion: 1,
		generatedAt,
		mission: active
			? {
					id: active.id,
					status: active.status,
					task: active.task,
					target: active.target,
					route: active.route,
					lanes: active.lanes,
					evidenceContract: active.evidenceContract,
					starterCommands: active.starterCommands ?? [],
				}
			: null,
		evidenceTail: evidenceTail(),
		latestArtifacts: latestArtifacts(),
		nextActions: active?.nextActions ?? ["repi mission new <task>", "repi health", "repi model doctor"],
		resumeBrief: active
			? `Continue mission ${active.id}: ${active.task}. Route=${active.route?.domain}. Next=${(active.nextActions ?? [])[0] ?? "map target"}.`
			: "No active mission. Start with repi mission new <task>.",
		contextPolicy: {
			currentMissionOnly: true,
			reason: "只把当前 mission 的紧凑状态作为恢复上下文。",
		},
	};
	return pack;
}

function writeContextPack(pack, output) {
	const outPath = output || join(contextDir, `mission-context-${compactTime()}.json`);
	writePrivate(outPath, `${JSON.stringify(pack, null, 2)}\n`);
	const mdPath = outPath.endsWith(".json") ? outPath.replace(/\.json$/, ".md") : `${outPath}.md`;
	const mission = pack.mission;
	const artifactLines = pack.latestArtifacts.map((row) => `- ${row.path} (${row.bytes} bytes, ${row.mtime})`).join("\n") || "- <none>";
	const evidenceLines = pack.evidenceTail.slice(-20).map((line) => `> ${line}`).join("\n") || "> <none>";
	writePrivate(
		mdPath,
		[
			"# REPI Mission Context Pack",
			"",
			`generatedAt: ${pack.generatedAt}`,
			`mission: ${mission?.id ?? "<none>"}`,
			`status: ${mission?.status ?? "none"}`,
			`route: ${mission?.route?.domain ?? "none"}`,
			"",
			"## Resume brief",
			"",
			pack.resumeBrief,
			"",
			"## Next actions",
			"",
			...(pack.nextActions ?? []).map((action) => `- \`${action}\``),
			"",
			"## Starter commands",
			"",
			...(mission?.starterCommands ?? []).map((action) => `- \`${action}\``),
			"",
			"## Latest artifacts",
			"",
			artifactLines,
			"",
			"## Evidence tail",
			"",
			evidenceLines,
			"",
		].join("\n"),
	);
	return { jsonPath: outPath, markdownPath: mdPath };
}

function reportHuman(report) {
	switch (report.kind) {
		case "repi-mission-report":
			console.log(`REPI Mission ${report.action}`);
			console.log(`status: ${report.mission?.status ?? "none"}`);
			if (report.mission) {
				console.log(`id: ${report.mission.id}`);
				console.log(`task: ${report.mission.task}`);
				console.log(`target: ${report.mission.target}`);
				console.log(`route: ${report.mission.route?.domain}`);
				console.log(`workspace: ${report.mission.workspace}`);
				console.log("next:");
				for (const action of report.mission.nextActions ?? []) console.log(`  - ${action}`);
			} else {
				console.log("next:");
				for (const action of report.nextActions ?? []) console.log(`  - ${action}`);
			}
			if (report.output) {
				console.log(`contextPack: ${report.output.jsonPath}`);
				console.log(`contextMarkdown: ${report.output.markdownPath}`);
			}
			if (report.message) console.log(report.message);
			break;
		case "repi-mission-plan":
			console.log("REPI Mission Plan");
			console.log(`task: ${report.task}`);
			console.log(`target: ${report.target}`);
			console.log(`route: ${report.plan.route.domain}`);
			console.log("workflow:");
			for (const step of report.plan.route.workflow) console.log(`  - ${step}`);
			console.log("evidence:");
			for (const step of report.plan.evidenceContract.required) console.log(`  - ${step}`);
			if (report.plan.starterCommands?.length) {
				console.log("starter:");
				for (const action of report.plan.starterCommands) console.log(`  - ${action}`);
			}
			console.log("next:");
			for (const action of report.plan.nextActions) console.log(`  - ${action}`);
			break;
		default:
			console.log(JSON.stringify(report, null, 2));
	}
}

function finish(report, exitCode = 0) {
	if (json) console.log(JSON.stringify(report, null, 2));
	else reportHuman(report);
	process.exit(exitCode);
}

try {
	if (["help", "--help", "-h"].includes(command)) {
		console.log(usage());
		process.exit(0);
	}

	if (["new", "start", "init"].includes(command)) {
		const task = positionalText();
		const mission = saveMission(newMission(task, { target: argValue("--target"), domain: argValue("--domain") }));
		finish({ kind: "repi-mission-report", schemaVersion: 1, action: "new", root, agentDir, missionPath, mission });
	}

	if (command === "plan") {
		const current = loadMission();
		const task = positionalText() || current?.task || argValue("--target") || "";
		if (!task) throw new Error("No task to plan. Use: repi mission plan <task> or repi mission new <task>");
		const target = argValue("--target") || current?.target || task;
		const plan = buildPlan(task, { target, domain: argValue("--domain") });
		finish({ kind: "repi-mission-plan", schemaVersion: 1, root, agentDir, task: redact(task), target: redact(target), plan });
	}

	if (["status", "show", "doctor"].includes(command)) {
		const mission = loadMission();
		const ok = isActiveMission(mission);
		finish({
			kind: "repi-mission-report",
			schemaVersion: 1,
			action: "status",
			root,
			agentDir,
			missionPath,
			ok,
			mission: ok ? mission : null,
			nextActions: ok ? mission.nextActions : ["repi mission new <task>", "repi health", "repi model doctor"],
			message: ok ? undefined : `No active mission at ${missionPath}`,
		});
	}

	if (command === "next") {
		const mission = loadMission();
		const ok = isActiveMission(mission);
		finish({
			kind: "repi-mission-report",
			schemaVersion: 1,
			action: "next",
			root,
			agentDir,
			missionPath,
			ok,
			mission: ok ? mission : null,
			nextActions: ok ? mission.nextActions : ["repi mission new <task>", "repi health"],
			message: ok ? undefined : "No active mission; create one first.",
		});
	}

	if (["pack", "context", "resume"].includes(command)) {
		const mission = loadMission();
		const pack = buildContextPack(mission);
		const output = writeContextPack(pack, argValue("--output", "-o"));
		finish({
			kind: "repi-mission-report",
			schemaVersion: 1,
			action: "pack",
			root,
			agentDir,
			missionPath,
			ok: true,
			mission: isMissionRecord(mission) ? mission : null,
			contextPack: pack,
			output,
		});
	}

	if (["close", "done", "complete"].includes(command)) {
		const mission = loadMission();
		if (!isActiveMission(mission)) throw new Error("No active mission to close.");
		const summary = redact(argValue("--summary") || positionalText() || "");
		const closed = saveMission({
			...mission,
			status: "closed",
			closedAt: nowStamp(),
			summary,
			nextActions: ["repi mission new <next-task>", "repi health"],
		});
		finish({ kind: "repi-mission-report", schemaVersion: 1, action: "close", root, agentDir, missionPath, ok: true, mission: closed, message: "Mission closed." });
	}

	if (["reset", "clear"].includes(command)) {
		if (!hasFlag("--yes")) throw new Error("reset requires --yes");
		const current = loadMission();
		if (isMissionRecord(current)) {
			appendPrivate(historyPath, `${JSON.stringify({ ts: nowStamp(), event: "mission_reset", id: current.id, status: current.status })}\n`);
		}
		writePrivate(missionPath, `${JSON.stringify({ kind: "repi-mission", schemaVersion: 1, status: "empty", updatedAt: nowStamp(), task: null }, null, 2)}\n`);
		finish({ kind: "repi-mission-report", schemaVersion: 1, action: "reset", root, agentDir, missionPath, ok: true, mission: null, nextActions: ["repi mission new <task>"] });
	}

	throw new Error(`Unknown repi mission command: ${command}`);
} catch (error) {
	const message = error instanceof Error ? error.message : String(error);
	if (json) {
		console.log(JSON.stringify({ kind: "repi-mission-report", schemaVersion: 1, action: command, root, agentDir, missionPath, ok: false, error: message }, null, 2));
	} else {
		console.error(`REPI Mission error: ${message}`);
		console.error("Run: repi mission --help");
	}
	process.exit(2);
}
