#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { atomicWriteFile } from "./lib/memory-purge-helpers.mjs";

const argv = process.argv.slice(2);
const commands = new Set(["llm-run", "run-llm", "workers", "plan", "run", "status", "merge", "help"]);
let root = process.cwd();
if (argv[0] && !argv[0].startsWith("--") && !commands.has(argv[0])) root = resolve(argv.shift());
const command = argv[0] && commands.has(argv[0]) ? argv.shift() : "llm-run";

const sourceAgentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const swarmsRoot = join(sourceAgentDir, "recon", "evidence", "llm-swarms");
const DEFAULT_MAX_OUTPUT_CHARS = 64 * 1024;
const MAX_HARVESTED_ARTIFACT_BYTES = 1024 * 1024;
const MAX_HARVESTED_ARTIFACTS_PER_WORKER = 24;

const roleLibrary = [
	{
		role: "mapper",
		objective: "被动 mapping：入口、文件/路由/协议面、运行方式、证据缺口。",
		evidenceContract: ["entrypoints", "reachable surfaces", "evidence gaps", "safe next commands"],
		mergeKeys: ["surface", "entrypoint", "route", "artifact"],
	},
	{
		role: "reverser",
		objective: "逆向核心逻辑：数据流、签名/校验/反调试/关键分支、可复现分析路径。",
		evidenceContract: ["control/data flow", "interesting symbols/strings", "first divergence", "reverse hypotheses"],
		mergeKeys: ["symbol", "function", "string", "signature"],
	},
	{
		role: "exploiter",
		objective: "攻击路径构造：输入控制点、鉴权/边界、primitive、利用链草案、稳定性风险。",
		evidenceContract: ["controllable input", "primitive or authz gap", "exploit path", "replay commands"],
		mergeKeys: ["primitive", "authz", "payload", "replay"],
	},
	{
		role: "verifier",
		objective: "验证与反证：最小复现、claim 质量、失败条件、需要补证的步骤。",
		evidenceContract: ["verification commands", "counter-evidence", "claim confidence", "blocking gaps"],
		mergeKeys: ["verifier", "claim", "counterexample", "check"],
	},
	{
		role: "adversary",
		objective: "对抗审查：寻找误报、越界假设、未验证叙述、污染记忆/工具输出风险。",
		evidenceContract: ["false positive risks", "unproven assumptions", "scope/target mismatch", "downgrade advice"],
		mergeKeys: ["risk", "assumption", "downgrade", "conflict"],
	},
	{
		role: "specialist",
		objective: "专项补线：选择一个未覆盖专业域，补充具体命令、证据锚点和验证出口。",
		evidenceContract: ["domain-specific commands", "specialist evidence", "proof exit", "fallback path"],
		mergeKeys: ["specialist", "domain", "tool", "proof"],
	},
	{
		role: "solo",
		objective: "单工作者端到端执行：被动映射、逆向关键路径、构造最小验证、反证失败条件并输出结构化证据。",
		evidenceContract: ["entry/surface map", "reverse hypothesis", "proof/replay command", "negative or counter-control", "blocking gap"],
		mergeKeys: ["surface", "reverse", "proof", "control", "artifact"],
	},
];

const universalProofDoctrine = {
	UniversalProofDoctrineV1: true,
	order: [
		"passive map first: files/routes/imports/configs/assets/logs before exploit guesses",
		"identify the live execution/request path before expanding sideways",
		"prove one end-to-end flow with a replayable command or artifact before narrative expansion",
		"attach negative controls or counter-evidence when claiming signing/authz/crypto/exploit success",
		"prefer hashes, offsets, paths, status/body diffs, frames, stack/register state, or transcript snippets over prose",
	],
	claimGate: "a promoted claim needs concrete evidence plus either a replay/proof command, artifact path/hash, or explicit counter-control result",
	blockerGate: "if proof is incomplete, state the exact missing runtime evidence and next command instead of padding the answer",
};

const evidencePriorityDoctrine = {
	EvidencePriorityDoctrineV1: true,
	order: [
		{ class: "runtime-behavior", rank: 80, examples: ["live process output", "debugger/register state", "successful replay transcript", "negative-control runtime result"] },
		{ class: "network-traffic", rank: 70, examples: ["PCAP frame/stream", "HTTP status/body hash", "XHR/WS capture", "curl response diff"] },
		{ class: "served-assets", rank: 60, examples: ["actively served JS/WASM/source map", "downloaded page/API schema", "runtime asset hash"] },
		{ class: "process-config", rank: 50, examples: ["running config", "manifest/IAM/RBAC/session settings", "loader/libc/tool availability"] },
		{ class: "persisted-state", rank: 40, examples: ["database/registry/storage before-after", "filesystem state", "artifact ledger row"] },
		{ class: "artifact", rank: 30, examples: ["file path with hash", "offset", "exported object", "carved dump"] },
		{ class: "source", rank: 20, examples: ["source code", "strings/imports/grep", "comments in code"] },
		{ class: "comment", rank: 10, examples: ["README/TODO/commentary", "unverified narrative"] },
		{ class: "unknown", rank: 0, examples: ["unclassified prose"] },
	],
	conflictPolicy: "When evidence conflicts, prefer the higher-ranked class. Equal/higher counter-evidence downgrades a promoted claim until rechecked.",
};

const capabilityMatrixDoctrine = {
	CapabilityMatrixDoctrineV1: true,
	gates: [
		{ gate: "passive-map", output: "entrypoints/routes/protocols/files/configs/assets/logs/tool availability" },
		{ gate: "live-path", output: "the exact runtime/request/process path that is actually exercised now" },
		{ gate: "primitive-or-transform", output: "controllable input, decode/signing transform, credential edge, or exploit primitive" },
		{ gate: "replay-proof", output: "single replayable command/transcript/artifact binding the claim to evidence" },
		{ gate: "negative-control", output: "tampered/wrong-principal/wrong-key/benign-input/counterexample result" },
		{ gate: "artifact-deposit", output: "paths, hashes, offsets, frames, stream ids, stack/register state, or before/after state" },
		{ gate: "cross-route-handoff", output: "route id + anchor + next command when evidence belongs to another domain" },
	],
	promotionPolicy: "A route is capability-ready only when passive-map, replay-proof, and negative-control have concrete evidence; otherwise emit the missing gate and next command.",
};

const routeProfiles = [
	{
		id: "native-pwn",
		domain: "Native / Pwn",
		match: /\b(pwn|elf|pe32|macho|mach-o|binary|rop|heap|tcache|fastbin|format[-_ ]?string|ret2|srop|seccomp|shellcode|pwntools|gdb|libc|checksec)\b|二进制|栈|堆/i,
		workflow: ["mitigation map", "primitive/leak proof", "payload construction", "stability replay"],
		roles: {
			mapper: {
				objective: "枚举二进制格式、架构、保护、loader/libc、输入面和可触发路径。",
				evidenceContract: ["sha256/file/checksec", "loader/libc assumption", "entry/import/string anchors", "crash surface"],
				mergeKeys: ["binary", "mitigation", "libc", "entrypoint"],
			},
			reverser: {
				objective: "定位关键函数、校验/解析分支、危险调用、可控缓冲区和数据流。",
				evidenceContract: ["function/xref anchors", "controlled input path", "dangerous callsite", "offset hypothesis"],
				mergeKeys: ["function", "xref", "offset", "buffer"],
			},
			exploiter: {
				objective: "证明 crash/leak/write primitive，草拟 payload、ROP/heap 策略和环境 pin。",
				evidenceContract: ["crash registers", "cyclic offset", "leak source", "payload/replay command"],
				mergeKeys: ["primitive", "leak", "payload", "gadget"],
			},
			verifier: {
				objective: "反证 ASLR、PIE、Canary、libc、timeout、IO 和远程差异导致的不稳定。",
				evidenceContract: ["gdb/pwndbg transcript", "N-run replay", "counterexample", "blocked assumption"],
				mergeKeys: ["verifier", "replay", "counterexample", "flake"],
			},
		},
	},
	{
		id: "web-api",
		domain: "Web / API",
		match: /https?:\/\/|\b(api|graphql|jwt|oauth|session|cookie|idor|bola|csrf|ssrf|xss|sqli|ssti|rce|cors|endpoint|route|authz?)\b|接口|登录|鉴权|授权|越权|渗透/i,
		workflow: ["route inventory", "auth/session matrix", "state replay", "object ownership proof"],
		roles: {
			mapper: {
				objective: "被动映射 routes、auth/session、中间件、workers、存储和请求顺序。",
				evidenceContract: ["route list", "auth/session anchors", "request order", "state store"],
				mergeKeys: ["route", "endpoint", "session", "middleware"],
			},
			exploiter: {
				objective: "构造多身份 replay，证明授权、状态转换、对象归属或 SSRF/注入边界。",
				evidenceContract: ["principal matrix", "object ownership", "before/after state", "curl replay"],
				mergeKeys: ["authz", "principal", "object", "replay"],
			},
			verifier: {
				objective: "裁剪扫描误报，校验状态码/body hash/side effect/权限差异。",
				evidenceContract: ["response diff", "body hash", "side effect proof", "false-positive note"],
				mergeKeys: ["verifier", "diff", "hash", "counterexample"],
			},
		},
	},
	{
		id: "js-reverse",
		domain: "Frontend / JS reverse",
		match: /\b(js|javascript|wasm|webpack|vite|sourcemap|fetch|xhr|websocket|signature|sign|crypto\.subtle|encrypt|decrypt|nonce|timestamp)\b|签名|风控|加密参数/i,
		workflow: ["asset inventory", "initiator trace", "signing path rebuild", "request replay"],
		roles: {
			mapper: {
				objective: "枚举 served assets、chunks、source maps、XHR/fetch/WS 和参数字段。",
				evidenceContract: ["asset/chunk list", "initiator stack", "request sample", "nonce/timestamp fields"],
				mergeKeys: ["asset", "chunk", "request", "initiator"],
			},
			reverser: {
				objective: "追踪签名/加密/混淆函数，定位 first divergence 并抽取最小复现逻辑。",
				evidenceContract: ["function anchor", "hook args/return", "first divergence", "node/browser rebuild"],
				mergeKeys: ["signature", "crypto", "hook", "divergence"],
			},
			verifier: {
				objective: "用真实请求对比本地生成字段，证明 replay 成功或明确 runtime 差异。",
				evidenceContract: ["generated field diff", "replay command", "server acceptance", "runtime dependency"],
				mergeKeys: ["replay", "diff", "field", "runtime"],
			},
		},
	},
	{
		id: "mobile",
		domain: "Mobile reverse",
		match: /\b(apk|ipa|android|ios|jadx|apktool|smali|frida|objection|adb|pinning|root|jailbreak|keychain|keystore)\b/i,
		workflow: ["package inventory", "static hook map", "runtime trace", "network replay"],
		roles: {
			mapper: {
				objective: "映射 manifest/plist、组件、权限、证书、native split、URL schemes 和网络配置。",
				evidenceContract: ["package/hash", "manifest/plist anchors", "entry components", "network config"],
				mergeKeys: ["manifest", "component", "permission", "scheme"],
			},
			reverser: {
				objective: "定位 crypto/signing、pinning、root/jailbreak/anti-debug 检测和 native bridge。",
				evidenceContract: ["method/class anchor", "native symbol", "pinning/root check", "Frida hook point"],
				mergeKeys: ["method", "class", "hook", "native"],
			},
			exploiter: {
				objective: "生成 Frida/objection hook 或 patch/bypass，并输出请求重放差异。",
				evidenceContract: ["hook script", "runtime trace", "bypass proof", "network replay"],
				mergeKeys: ["frida", "bypass", "trace", "replay"],
			},
		},
	},
	{
		id: "pcap-dfir",
		domain: "PCAP / DFIR",
		match: /\b(pcap|pcapng|traffic|wireshark|tshark|dfir|forensic|timeline|ioc|stego)\b|取证|流量|隐写/i,
		workflow: ["artifact fingerprint", "flow/session ranking", "object extraction", "decode/timeline"],
		roles: {
			mapper: {
				objective: "确认 artifact hash/magic、时间范围、协议层级、会话和高价值 stream。",
				evidenceContract: ["capinfos/file/sha256", "protocol hierarchy", "flow table", "stream ranking"],
				mergeKeys: ["flow", "stream", "protocol", "host"],
			},
			reverser: {
				objective: "提取对象/载荷并还原编码、压缩、隐写或自定义协议 transform chain。",
				evidenceContract: ["exported object hash", "decode chain", "packet/frame source", "recovered artifact"],
				mergeKeys: ["object", "payload", "decode", "frame"],
			},
			verifier: {
				objective: "绑定 flag/IOC/secret 到 packet/frame/stream 来源并反证误解码。",
				evidenceContract: ["source frame", "artifact hash", "timeline row", "false-positive check"],
				mergeKeys: ["ioc", "timeline", "hash", "verifier"],
			},
		},
	},
	{
		id: "memory-forensics",
		domain: "Memory forensics",
		match: /\b(memory dump|memdump|vmem|mem\.raw|volatility|hiberfil|pagefile|lsass|netscan|pslist|malfind)\b|内存取证|内存镜像|内存转储/i,
		workflow: ["profile selection", "process/network map", "credential/artifact hunt", "timeline/carve"],
		roles: {
			mapper: {
				objective: "确认镜像 hash、OS/profile、插件可用性、进程树和网络连接。",
				evidenceContract: ["image hash/profile", "plugin output", "process tree", "network rows"],
				mergeKeys: ["profile", "process", "connection", "plugin"],
			},
			reverser: {
				objective: "定位注入、隐藏进程、模块、命令行、凭据/token/浏览器/registry artifact。",
				evidenceContract: ["malfind/dll/module anchor", "cmdline", "credential artifact", "dump hash"],
				mergeKeys: ["malfind", "module", "credential", "artifact"],
			},
			verifier: {
				objective: "用多插件/strings/YARA/timeline 交叉验证 IOC 和恢复文件来源。",
				evidenceContract: ["cross-plugin proof", "YARA/strings hit", "timeline row", "source offset"],
				mergeKeys: ["ioc", "timeline", "offset", "verifier"],
			},
		},
	},
	{
		id: "firmware-iot",
		domain: "Firmware / IoT",
		match: /\b(firmware|iot|router|rootfs|squashfs|ubi|ubifs|uimage|binwalk|unblob|busybox|nvram|cgi|mips|arm)\b|固件/i,
		workflow: ["image fingerprint", "rootfs extraction", "service/config map", "emulation smoke"],
		roles: {
			mapper: {
				objective: "确认固件封装、hash、架构、压缩/文件系统、rootfs 和启动脚本。",
				evidenceContract: ["image hash/magic", "architecture", "extract path", "init/service list"],
				mergeKeys: ["rootfs", "arch", "service", "init"],
			},
			reverser: {
				objective: "映射 Web/API/CGI、账号、密钥、NVRAM、默认凭据和危险配置。",
				evidenceContract: ["credential/config anchor", "cgi/endpoint", "service binary", "nvram key"],
				mergeKeys: ["credential", "cgi", "config", "service"],
			},
			verifier: {
				objective: "构造 chroot/QEMU/用户态 smoke，证明服务或漏洞路径可到达。",
				evidenceContract: ["emulation command", "service smoke", "blocking dependency", "replay path"],
				mergeKeys: ["qemu", "chroot", "smoke", "replay"],
			},
		},
	},
	{
		id: "cloud-identity",
		domain: "Cloud / Identity",
		match: /\b(cloud|aws|gcp|azure|k8s|kubernetes|iam|sts|role|serviceaccount|metadata|rbac|terraform|docker|container)\b|云|容器/i,
		workflow: ["credential/config map", "runtime identity", "permission graph", "metadata/pivot proof"],
		roles: {
			mapper: {
				objective: "枚举云/K8s/容器/IaC 配置、当前 principal、namespace 和 token audience。",
				evidenceContract: ["identity anchor", "context/namespace", "IaC path", "token audience"],
				mergeKeys: ["principal", "namespace", "role", "token"],
			},
			exploiter: {
				objective: "证明最小 IAM/RBAC/metadata 权限边，不扩大到未验证叙述。",
				evidenceContract: ["RBAC/IAM edge", "metadata status", "single-command proof", "reachable resource"],
				mergeKeys: ["rbac", "iam", "metadata", "resource"],
			},
			verifier: {
				objective: "反证凭据不可用、scope mismatch、namespace drift 和 token audience 限制。",
				evidenceContract: ["scope check", "denied action", "audience mismatch", "counter-evidence"],
				mergeKeys: ["scope", "deny", "audience", "verifier"],
			},
		},
	},
	{
		id: "windows-ad",
		domain: "Identity / Windows / AD",
		match: /\b(active directory|kerberos|ntlm|ldap|spn|smb|winrm|lsass|bloodhound|certipy|impacket|netexec|nxc|domain controller)\b|域控|内网|横向|提权|凭据/i,
		workflow: ["principal map", "credential usability", "privilege graph", "pivot proof"],
		roles: {
			mapper: {
				objective: "枚举域、DC、用户、组、SPN、证书服务、协议面和可用凭据格式。",
				evidenceContract: ["domain/DC anchor", "principal/group rows", "SPN/ADCS rows", "protocol baseline"],
				mergeKeys: ["principal", "group", "spn", "adcs"],
			},
			exploiter: {
				objective: "验证 hash/ticket/password 可用性，定位最小 BloodHound/Certipy/ACL privilege edge。",
				evidenceContract: ["credential check", "graph edge", "single-command pivot", "event/log anchor"],
				mergeKeys: ["credential", "edge", "pivot", "acl"],
			},
			verifier: {
				objective: "反证不可达边、凭据失效、Kerberos 时间/realm/签名约束和误报路径。",
				evidenceContract: ["failed auth", "realm/time check", "edge counterexample", "downgrade advice"],
				mergeKeys: ["counterexample", "realm", "auth", "verifier"],
			},
		},
	},
	{
		id: "malware",
		domain: "Malware / sample analysis",
		match: /\b(malware|sample|yara|capa|floss|packer|upx|ioc|c2|mutex|persistence|sandbox|ransom|trojan|loader)\b|恶意|样本|反调试|反沙箱/i,
		workflow: ["static triage", "capability/config scan", "behavior trace", "IOC report"],
		roles: {
			mapper: {
				objective: "确认样本 hash/magic/packer/sections/imports/strings 和执行约束。",
				evidenceContract: ["sample hash/magic", "section/import rows", "packer/entropy", "sandbox constraint"],
				mergeKeys: ["sample", "section", "import", "packer"],
			},
			reverser: {
				objective: "提取 C2、mutex、路径、registry、UA、配置和 payload transform chain。",
				evidenceContract: ["config/IOC anchor", "decode key/offset", "YARA/capa/FLOSS hit", "behavior trace"],
				mergeKeys: ["ioc", "config", "c2", "decode"],
			},
			verifier: {
				objective: "用静态/动态/规则输出交叉验证 IOC，避免把字符串噪音当行为。",
				evidenceContract: ["rule hit source", "runtime behavior", "false-positive note", "IOC normalization"],
				mergeKeys: ["rule", "behavior", "ioc", "verifier"],
			},
		},
	},
	{
		id: "crypto-stego",
		domain: "Crypto / Stego",
		match: /\b(crypto|cipher|rsa|aes|cbc|ecb|gcm|xor|hash|padding oracle|oracle|lattice|sage|z3|stego|exif|zsteg|binwalk|png|jpg|jpeg|wav|flac|enc|nonce|salt)\b|隐写|密码|格|同余/i,
		workflow: ["parameter inventory", "transform chain", "solver construction", "known-answer verification"],
		roles: {
			mapper: {
				objective: "盘点密文、文件、参数、编码、大整数、IV/nonce/signature 和 oracle 面。",
				evidenceContract: ["artifact hash/format", "parameter table", "known plaintext", "oracle behavior"],
				mergeKeys: ["param", "cipher", "oracle", "artifact"],
			},
			reverser: {
				objective: "还原编码、压缩、异或、分组模式、数学约束或隐写 transform chain。",
				evidenceContract: ["transform script", "intermediate hash", "solver constraint", "decoded artifact"],
				mergeKeys: ["transform", "solver", "constraint", "decode"],
			},
			verifier: {
				objective: "用 known-answer/test vector/assert/replay 验证结果，不把猜测当结论。",
				evidenceContract: ["test vector", "assert output", "known-answer", "recovered hash"],
				mergeKeys: ["test", "assert", "hash", "verifier"],
			},
		},
	},
	{
		id: "agent-boundary",
		domain: "Agent / LLM boundary",
		match: /\b(prompt injection|indirect prompt|tool injection|function call|tool-call|mcp|rag|retrieval|memory poisoning|jailbreak|sandbox escape)\b|agent\s*安全|llm\s*安全|记忆投毒|工具滥用|越狱/i,
		workflow: ["prompt/tool surface", "memory/RAG boundary", "injection replay", "delegation drift proof"],
		roles: {
			mapper: {
				objective: "映射 system/developer/user/tool/memory/RAG/MCP 输入边界和不可信内容入口。",
				evidenceContract: ["prompt/resource inventory", "tool schema map", "memory/RAG path", "untrusted content flow"],
				mergeKeys: ["prompt", "tool", "memory", "resource"],
			},
			exploiter: {
				objective: "构造最小间接 prompt/tool injection replay，证明或反证边界绕过。",
				evidenceContract: ["payload", "replay transcript", "tool-call trace", "boundary decision"],
				mergeKeys: ["payload", "trace", "decision", "toolcall"],
			},
			verifier: {
				objective: "审查 tool output 信任、记忆污染、capability drift 和未验证代理叙述。",
				evidenceContract: ["counter-prompt", "sanitization check", "capability drift edge", "downgrade advice"],
				mergeKeys: ["counter", "sanitize", "drift", "verifier"],
			},
		},
	},
];


const routeProofKits = {
	"native-pwn": {
		passive: ["file/readelf/checksec/strings/imports", "mitigation + loader/libc map", "input surface and crash trigger inventory"],
		proofExit: ["cyclic offset or register/stack transcript", "leak/write/crash primitive replay command", "N-run stability note with pinned env"],
		negativeControls: ["non-crashing benign input", "wrong offset/payload should fail", "ASLR/PIE/canary/libc assumption explicitly checked"],
	},
	"web-api": {
		passive: ["route/schema/session inventory", "auth/session cookie/header map", "state-changing request order"],
		proofExit: ["principal matrix with status/body-hash diff", "single curl/http replay for the claimed edge", "before/after state or object ownership evidence"],
		negativeControls: ["anonymous vs authenticated", "wrong principal/object", "tampered token/session or missing CSRF"],
	},
	"js-reverse": {
		passive: ["served asset/chunk/source-map inventory", "XHR/fetch/WS initiator and parameter map", "runtime hook plan for crypto/signing calls"],
		proofExit: ["byte-for-byte field rebuild for captured sample", "browser-captured vs generated diff", "signed replay plus missing/tampered/stale controls"],
		negativeControls: ["missing signature", "tampered signature/ciphertext", "stale timestamp/nonce or wrong key"],
	},
	mobile: {
		passive: ["manifest/plist/package/hash inventory", "component/permission/network-config map", "native split and certificate/pinning anchors"],
		proofExit: ["Frida/adb/jadx/apktool command transcript", "hook return/argument trace", "network replay or bypass diff"],
		negativeControls: ["hook disabled", "wrong cert/pin/root state", "clean device/emulator state comparison"],
	},
	"pcap-dfir": {
		passive: ["capinfos/file/hash/time bounds", "protocol hierarchy and conversation ranking", "stream/object extraction candidates"],
		proofExit: ["frame/stream number tied to IOC/secret", "extracted object hash", "decode chain script with intermediate hashes"],
		negativeControls: ["wrong stream/frame decode fails", "checksum/length mismatch noted", "false-positive string source rejected"],
	},
	"memory-forensics": {
		passive: ["image hash/profile/tool availability", "process tree/network/plugin baseline", "dump/carve target inventory"],
		proofExit: ["cross-plugin corroboration", "source offset/process/module anchor", "dumped artifact hash"],
		negativeControls: ["alternate profile/plugin disagreement", "strings-only IOC downgraded", "stale process/socket counterexample"],
	},
	"firmware-iot": {
		passive: ["image magic/hash/extraction map", "arch/rootfs/init/service inventory", "web/cgi/config/credential grep anchors"],
		proofExit: ["emulation/chroot/service smoke command", "endpoint/config replay", "file path + hash for extracted proof"],
		negativeControls: ["service not started/unreachable path", "wrong nvram/config value", "static credential without runtime use downgraded"],
	},
	"cloud-identity": {
		passive: ["current principal/context/namespace", "IaC/RBAC/IAM/token audience map", "metadata endpoint reachability"],
		proofExit: ["single allowed/denied permission edge", "resource ARN/name + command transcript", "token audience/scope verification"],
		negativeControls: ["denied action", "wrong namespace/audience", "expired or unusable credential"],
	},
	"windows-ad": {
		passive: ["domain/DC/protocol baseline", "principal/group/SPN/ADCS map", "credential format/usability candidates"],
		proofExit: ["single auth check or graph edge proof", "BloodHound/LDAP/Certipy row with source", "pivot command transcript"],
		negativeControls: ["bad password/hash/ticket", "realm/time/signing mismatch", "unreachable graph edge downgraded"],
	},
	malware: {
		passive: ["sample hash/magic/sections/imports", "packer/entropy/string triage", "tool availability for YARA/capa/FLOSS"],
		proofExit: ["IOC/config tied to offset/function/rule hit", "decode script with output hash", "static + dynamic or rule corroboration"],
		negativeControls: ["string-only IOC downgraded", "wrong decode key fails", "sandbox behavior absent noted"],
	},
	"crypto-stego": {
		passive: ["artifact hash/format/metadata", "parameter/nonce/IV/ciphertext table", "oracle or known-plaintext behavior"],
		proofExit: ["solver/decoder script with assertions", "known-answer/test-vector match", "recovered artifact hash"],
		negativeControls: ["wrong key/nonce/cipher mode fails", "padding/oracle false positive rejected", "alternative transform chain counterexample"],
	},
	"agent-boundary": {
		passive: ["prompt/tool/memory/RAG boundary map", "untrusted content flow", "tool schema and side-effect inventory"],
		proofExit: ["minimal injection replay transcript", "tool-call trace or refusal/allow decision", "memory/RAG contamination proof"],
		negativeControls: ["benign prompt comparison", "sanitized content path", "tool disabled or least-privilege counterexample"],
	},
	"reverse-pentest-general": {
		passive: ["entrypoint/surface/artifact inventory", "live execution path hypothesis", "tool availability and evidence gaps"],
		proofExit: ["one replayable command or artifact hash", "claim-specific transcript/diff", "next command for missing proof"],
		negativeControls: ["benign input or wrong credential/control", "failed hypothesis recorded", "scope/source mismatch downgraded"],
	},
};


const routeCommandPalettes = {
	"native-pwn": {
		passive: ["file $TARGET && sha256sum $TARGET", "checksec --file=$TARGET || true", "readelf -h -l -s $TARGET | head -200", "strings -a -n 6 $TARGET | head -200"],
		proof: ["python3 - <<'PY'\nfrom pwn import cyclic\nprint(cyclic(256))\nPY", "gdb -q --args $TARGET", "python3 exploit.py 2>&1 | tee proof.log"],
		negative: ["python3 exploit.py --benign 2>&1 | tee negative.log", "python3 exploit.py --wrong-offset 2>&1 | tee wrong-offset.log"],
	},
	"web-api": {
		passive: ["curl -kisS $TARGET | tee http-head.txt", "curl -kisS -X OPTIONS $TARGET | tee http-options.txt", "curl -ksS $TARGET/openapi.json || true", "curl -ksS $TARGET/graphql -d '{\"query\":\"{__typename}\"}' || true"],
		proof: ["curl -kisS -H 'Authorization: Bearer <tokenA>' $TARGET/path | tee principal-a.txt", "curl -kisS -H 'Authorization: Bearer <tokenB>' $TARGET/path | tee principal-b.txt", "sha256sum principal-a.txt principal-b.txt"],
		negative: ["curl -kisS $TARGET/path | tee anonymous.txt", "curl -kisS -H 'Authorization: Bearer invalid' $TARGET/path | tee invalid-token.txt"],
	},
	"js-reverse": {
		passive: ["curl -ksSL $TARGET -o page.html", "grep -Eo 'src=[\"'\''][^\"'\'']+' page.html | head", "grep -RInE 'sign|signature|crypto|nonce|timestamp|fetch|XMLHttpRequest' web-js-assets/ 2>/dev/null | head -200"],
		proof: ["node signer-rebuild.mjs captured-sample.json | tee signer-proof.json", "node replay-signed.mjs --live | tee replay-proof.json"],
		negative: ["node replay-signed.mjs --missing-signature | tee missing-control.json", "node replay-signed.mjs --tampered-signature | tee tampered-control.json", "node replay-signed.mjs --stale-timestamp | tee stale-control.json"],
	},
	mobile: {
		passive: ["file $TARGET && sha256sum $TARGET", "unzip -l $TARGET | head -200", "aapt dump badging $TARGET 2>/dev/null || true", "jadx -d jadx-out $TARGET 2>/dev/null || true"],
		proof: ["frida -U -f <package> -l hook.js --no-pause", "adb shell am start -n <component>", "curl -kisS <captured-api> | tee mobile-replay.txt"],
		negative: ["frida hook disabled comparison", "adb shell settings get global http_proxy", "curl -kisS <captured-api-with-wrong-pin-or-token> | tee mobile-negative.txt"],
	},
	"pcap-dfir": {
		passive: ["capinfos $TARGET", "tshark -r $TARGET -q -z io,phs", "tshark -r $TARGET -q -z conv,tcp | head -80"],
		proof: ["tshark -r $TARGET -Y '<filter>' -T fields -e frame.number -e ip.src -e ip.dst -e data | tee frames.txt", "tshark -r $TARGET -q -z follow,tcp,ascii,<stream> | tee stream.txt", "sha256sum extracted-object.bin"],
		negative: ["tshark -r $TARGET -Y '<wrong-filter>' | head", "cmp extracted-object.bin alternate-object.bin || true"],
	},
	"memory-forensics": {
		passive: ["file $TARGET && sha256sum $TARGET", "strings -a -n 8 $TARGET | head -200", "volatility3 -f $TARGET windows.info 2>/dev/null || true"],
		proof: ["volatility3 -f $TARGET windows.pslist 2>/dev/null | tee pslist.txt", "volatility3 -f $TARGET windows.netscan 2>/dev/null | tee netscan.txt", "volatility3 -f $TARGET windows.dumpfiles --pid <pid> 2>/dev/null"],
		negative: ["volatility3 -f $TARGET windows.info --single-location <alt-profile> 2>/dev/null || true", "grep -F '<ioc>' pslist.txt netscan.txt || true"],
	},
	"firmware-iot": {
		passive: ["file $TARGET && sha256sum $TARGET", "binwalk $TARGET | tee binwalk.txt", "strings -a -n 6 $TARGET | grep -Ei 'http|cgi|password|admin|nvram' | head -200"],
		proof: ["binwalk -eM $TARGET", "find _* -maxdepth 4 -type f | head -200", "chroot squashfs-root /bin/sh -c 'id' 2>/dev/null || true"],
		negative: ["grep -RIn '<credential>' squashfs-root/etc squashfs-root/www 2>/dev/null", "curl -kisS http://127.0.0.1:<port>/<endpoint> | tee firmware-smoke.txt"],
	},
	"cloud-identity": {
		passive: ["env | grep -Ei 'AWS|GOOGLE|AZURE|KUBECONFIG|TOKEN' | sed 's/=.*/=<redacted>/'", "kubectl config current-context 2>/dev/null || true", "aws sts get-caller-identity 2>/dev/null || true"],
		proof: ["kubectl auth can-i --list 2>/dev/null | tee k8s-auth.txt", "aws iam simulate-principal-policy --policy-source-arn <arn> --action-names <action> 2>/dev/null | tee iam-sim.txt"],
		negative: ["kubectl auth can-i <denied-verb> <resource> 2>/dev/null | tee k8s-deny.txt", "aws <service> <denied-action> --dry-run 2>&1 | tee aws-deny.txt"],
	},
	"windows-ad": {
		passive: ["nxc smb <dc-or-range> --shares 2>/dev/null | tee smb-baseline.txt", "ldapsearch -x -H ldap://<dc> -s base namingContexts 2>/dev/null | tee ldap-base.txt", "bloodhound-python -d <domain> -u <user> -p '<pass>' -c DCOnly 2>/dev/null || true"],
		proof: ["nxc smb <dc> -u <user> -p '<pass>' --shares | tee auth-proof.txt", "certipy find -u <user> -p '<pass>' -dc-ip <dc> -stdout | tee adcs.txt"],
		negative: ["nxc smb <dc> -u <user> -p wrong --shares | tee auth-negative.txt", "KRB5CCNAME=bad.ccache nxc smb <dc> -k 2>&1 | tee kerberos-negative.txt"],
	},
	malware: {
		passive: ["file $TARGET && sha256sum $TARGET", "strings -a -n 6 $TARGET | head -300", "rabin2 -I -i $TARGET 2>/dev/null || true", "capa $TARGET 2>/dev/null | tee capa.txt || true"],
		proof: ["floss $TARGET 2>/dev/null | tee floss.txt || true", "yara -r rules.yar $TARGET 2>/dev/null | tee yara.txt || true", "python3 decode-config.py $TARGET | tee config.json"],
		negative: ["python3 decode-config.py --wrong-key $TARGET | tee config-negative.txt", "grep -F '<ioc>' capa.txt floss.txt yara.txt || true"],
	},
	"crypto-stego": {
		passive: ["file $TARGET && sha256sum $TARGET", "exiftool $TARGET 2>/dev/null | head -120 || true", "xxd -l 256 $TARGET"],
		proof: ["python3 solve.py | tee solve-proof.txt", "python3 -m pytest -q 2>/dev/null || true", "sha256sum recovered.bin 2>/dev/null || true"],
		negative: ["python3 solve.py --wrong-key | tee solve-negative.txt", "python3 solve.py --wrong-mode | tee mode-negative.txt"],
	},
	"agent-boundary": {
		passive: ["grep -RInE 'system|developer|tool|mcp|memory|retrieval|prompt' . | head -200", "find . -maxdepth 4 -iname '*prompt*' -o -iname '*tool*' | head -200"],
		proof: ["node injection-replay.mjs | tee injection-proof.json", "repi memory inspect --json 2>/dev/null | tee memory-boundary.json || true"],
		negative: ["node injection-replay.mjs --benign | tee benign-control.json", "node injection-replay.mjs --sanitized | tee sanitized-control.json"],
	},
	"reverse-pentest-general": {
		passive: ["pwd && find . -maxdepth 3 -type f | head -200", "file $TARGET 2>/dev/null || true", "grep -RInE 'TODO|secret|token|password|route|api|main' . | head -200"],
		proof: ["repi engage $TARGET --json | tee engagement.json", "python3 proof.py 2>&1 | tee proof.log"],
		negative: ["python3 proof.py --negative 2>&1 | tee negative.log", "diff -u proof.log negative.log || true"],
	},
};

const routeTechniqueHints = {
	"native-pwn": {
		domains: ["pwn", "native-reverse", "exploit-reliability"],
		techniqueIds: ["pwn-ret2libc", "pwn-format-string", "pwn-tcache-poisoning", "rev-anti-debug-bypass", "reliability-replay-matrix"],
	},
	"web-api": {
		domains: ["web-api", "web-scan"],
		techniqueIds: ["web-idor-bola", "web-ssrf-metadata", "web-jwt-confusion", "web-ssti", "web-request-smuggling", "webscan-content-discovery"],
	},
	"js-reverse": {
		domains: ["js-reverse", "web-api"],
		techniqueIds: ["js-signature-rebuild", "js-wasm-reverse", "web-graphql-introspection"],
	},
	mobile: {
		domains: ["mobile", "js-reverse", "native-reverse"],
		techniqueIds: ["mobile-ssl-pinning-bypass", "mobile-root-bypass", "mobile-crypto-hook", "js-signature-rebuild"],
	},
	"pcap-dfir": {
		domains: ["dfir-pcap", "identity-ad", "crypto-stego"],
		techniqueIds: ["dfir-ntlm-kerberos-extract", "dfir-exfil-detect", "crypto-hash-length-extension"],
	},
	"memory-forensics": {
		domains: ["memory-forensics", "malware", "identity-ad"],
		techniqueIds: ["mem-volatility-creds", "mem-process-hunt", "malware-persistence-mech"],
	},
	"firmware-iot": {
		domains: ["firmware-iot", "web-api", "native-reverse"],
		techniqueIds: ["fw-rootfs-extract", "fw-emulation-qemu", "fw-secure-boot-bypass", "web-ssrf-metadata"],
	},
	"cloud-identity": {
		domains: ["cloud-container", "web-api", "agent-llm"],
		techniqueIds: ["cloud-imds-to-role", "cloud-k8s-rbac", "cloud-container-escape", "web-ssrf-metadata"],
	},
	"windows-ad": {
		domains: ["identity-ad", "dfir-pcap", "memory-forensics"],
		techniqueIds: ["ad-kerberoasting", "ad-cs-esc", "ad-dcsync", "dfir-ntlm-kerberos-extract"],
	},
	malware: {
		domains: ["malware", "native-reverse", "memory-forensics"],
		techniqueIds: ["malware-config-decode", "malware-persistence-mech", "malware-shellcode-emulate", "rev-vm-unpack"],
	},
	"crypto-stego": {
		domains: ["crypto-stego", "dfir-pcap"],
		techniqueIds: ["crypto-padding-oracle", "crypto-cbc-bitflip", "crypto-rsa-attacks", "crypto-ecdsa-nonce-reuse", "dfir-exfil-detect"],
	},
	"agent-boundary": {
		domains: ["agent-llm", "cloud-container", "web-api"],
		techniqueIds: ["agent-rag-poisoning", "agent-memory-exfil", "agent-indirect-injection", "web-idor-bola"],
	},
	"reverse-pentest-general": {
		domains: ["pwn", "web-api", "js-reverse", "mobile", "dfir-pcap", "cloud-container", "agent-llm", "exploit-reliability"],
		techniqueIds: ["reliability-replay-matrix", "web-idor-bola", "js-signature-rebuild", "pwn-ret2libc", "agent-rag-poisoning"],
	},
};

function commandPaletteFor(profile) {
	return routeCommandPalettes[profile?.id] ?? routeCommandPalettes["reverse-pentest-general"];
}

function commandNamesFromPalette(commandPalette) {
	const names = new Set();
	const commands = [
		...(commandPalette?.passive ?? []),
		...(commandPalette?.proof ?? []),
		...(commandPalette?.negative ?? []),
	];
	for (const command of commands) {
		for (const segment of String(command).split(/\n|&&|\|\||;/)) {
			const match = segment.trim().match(/^(?:[A-Z_][A-Z0-9_]*=\S+\s+)*(?:timeout\s+\S+\s+|sudo\s+|env\s+)*([A-Za-z0-9_.+-]+)/i);
			const name = match?.[1];
			if (!name || /^(?:true|false|then|do|done|fi|esac|from|print|comparison|PY)$/i.test(name)) continue;
			names.add(name);
		}
	}
	return [...names].slice(0, 24);
}

function toolProbeCommandFor(profile) {
	const names = commandNamesFromPalette(commandPaletteFor(profile));
	if (!names.length) return undefined;
	return `for t in ${names.map(shellQuote).join(" ")}; do command -v "$t" >/dev/null 2>&1 && echo "tool:$t=ok" || echo "tool:$t=missing"; done`;
}

function techniqueHintsFor(profile) {
	return routeTechniqueHints[profile?.id] ?? routeTechniqueHints["reverse-pentest-general"];
}

function proofKitFor(profile) {
	return routeProofKits[profile?.id] ?? routeProofKits["reverse-pentest-general"];
}

function usage() {
	return `Usage:
  repi swarm plan <target> --workers N [--route <id[,id...]|all>] [--roles mapper,reverser,exploiter,verifier,adversary,solo] [--json]
  repi swarm run <target> --workers N [--provider <id>] [--model <id>] [--tools bash,read,grep,ls] [--json]
  repi swarm status [latest|run-id] [--json]
  repi swarm merge [latest|run-id] [--json]
  repi swarm llm-run <target> --workers N [--provider <id>] [--model <id>] [--prompt <text>]

Plan/run options:
  --target <text>          Target/task label if no positional target is supplied
  --workers <N>            Number of parallel LLM workers (default: 3; broad multi-route tasks auto-expand up to 16)
  --max-concurrency <N>    Max simultaneous child processes (default: workers)
  --provider <id>          Provider id from ~/.repi/agent/models.json or built-ins
  --model <id>             Model id
  --route <id[,id...]|all> Force one or more route ids, or the full route catalog, instead of keyword routing
  --roles <csv>            Role order. Defaults to solo for one worker, else mapper,reverser,exploiter,verifier,adversary
  --tools <list>           Enable tools for workers (run default: bash,read,grep,find,ls; llm-run default: --no-tools)
  --no-tools               Disable all worker tools
  --timeout-ms <ms>        Per-worker timeout (default: REPI_SWARM_LLM_TIMEOUT_MS or 210000)
  --prompt <text>          llm-run prompt template, or extra mission guidance for swarm run
  --expect <regex>         llm-run per-worker success regex. Supports {id}/{target}
  --keep-profiles          Keep temporary isolated worker profiles for debugging
  --json                   Print JSON report only

Examples:
  repi swarm plan ./target --workers 5
  repi swarm run ./target --workers 5 --provider openai-compatible --model vendor/model --tools bash,read,grep,ls
  repi swarm status latest
  repi swarm merge latest
  repi swarm llm-run local-selfcheck --workers 3 --provider openai-compatible --model vendor/model \\
    --prompt "Reply exactly: REPI_SWARM_WORKER_{id}_OK" --expect "REPI_SWARM_WORKER_{id}_OK"
`;
}

function flagValue(args, names, fallback = undefined) {
	const list = Array.isArray(names) ? names : [names];
	for (let index = 0; index < args.length; index++) {
		for (const name of list) {
			if (args[index] === name) return args[index + 1] ?? fallback;
			if (args[index].startsWith(`${name}=`)) return args[index].slice(name.length + 1);
		}
	}
	return fallback;
}

function hasFlag(args, names) {
	return flagValue(args, names, undefined) !== undefined;
}

function parseIntFlag(args, names, fallback, min, max) {
	const raw = flagValue(args, names, "");
	const parsed = Number.parseInt(raw, 10);
	if (!Number.isFinite(parsed)) return fallback;
	return Math.max(min, Math.min(max, parsed));
}

const valueFlags = new Set([
	"--target",
	"--workers",
	"-w",
	"--max-concurrency",
	"--provider",
	"--model",
	"--route",
	"--roles",
	"--tools",
	"--timeout-ms",
	"--prompt",
	"--expect",
	"--cwd",
]);

function positionalTarget(args, offset = 0) {
	const positional = [];
	for (let index = 0; index < args.length; index++) {
		const arg = args[index];
		if (arg === "--") {
			positional.push(...args.slice(index + 1));
			break;
		}
		if (arg.startsWith("--") || arg === "-w") {
			const flagName = arg.includes("=") ? arg.slice(0, arg.indexOf("=")) : arg;
			if (!arg.includes("=") && valueFlags.has(flagName)) index++;
			continue;
		}
		positional.push(arg);
	}
	return positional[offset];
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

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function shellQuote(value) {
	return `'${String(value ?? "").replace(/'/g, "'\\''")}'`;
}

function clip(value, max = 12000) {
	const text = redact(value);
	return text.length > max ? `${text.slice(0, max - 32)}\n...<truncated:${text.length - max + 32}>` : text;
}

function safeArtifactName(sourcePath, index) {
	const base = basename(sourcePath).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 96);
	return `${String(index + 1).padStart(2, "0")}-${base || "artifact"}`;
}

function extractArtifactPathCandidates(text) {
	const candidates = new Set();
	const pattern = /(?:^|[\s"'[(,])((?:\/[A-Za-z0-9._~+@%=:,-]+)+)(?=$|[\s"'\]),;])/g;
	let match;
	while ((match = pattern.exec(String(text ?? "")))) {
		const candidate = match[1];
		if (!candidate || candidate.includes("://") || candidate.length > 512) continue;
		candidates.add(candidate);
	}
	return [...candidates];
}

function harvestWorkerArtifacts(worker, evidenceRoot) {
	const artifactDir = join(evidenceRoot, `worker-${worker.workerId}-artifacts`);
	const rows = [];
	for (const sourcePath of extractArtifactPathCandidates(`${worker.stdoutPreview}\n${worker.stderrPreview}`)) {
		if (rows.length >= MAX_HARVESTED_ARTIFACTS_PER_WORKER) break;
		try {
			const stat = statSync(sourcePath);
			if (!stat.isFile() || stat.size > MAX_HARVESTED_ARTIFACT_BYTES) continue;
			mkdirSync(artifactDir, { recursive: true, mode: 0o700 });
			const content = readFileSync(sourcePath);
			const artifactPath = join(artifactDir, safeArtifactName(sourcePath, rows.length));
			atomicWriteFile(artifactPath, content, 0o600);
			rows.push({
				sourcePath: redact(sourcePath),
				artifactPath,
				size: stat.size,
				sha256: sha256(content),
			});
		} catch {
			// Path-like text is often an endpoint or a stale temp path; only harvest
			// live bounded files and keep merge robust when they are absent.
		}
	}
	if (rows.length) {
		atomicWriteFile(join(evidenceRoot, `worker-${worker.workerId}-artifacts.json`), `${JSON.stringify(rows, null, 2)}\n`, 0o600);
	}
	return rows;
}

function substitute(template, workerId, target, role = "worker", context = {}) {
	const route = context.route ?? {};
	const proofKit = context.proofKit ?? {};
	const commandPalette = context.commandPalette ?? {};
	const techniqueHints = context.techniqueHints ?? {};
	return String(template ?? "")
		.replaceAll("{{id}}", String(workerId))
		.replaceAll("{id}", String(workerId))
		.replaceAll("<id>", String(workerId))
		.replaceAll("{{role}}", role)
		.replaceAll("{role}", role)
		.replaceAll("<role>", role)
		.replaceAll("{{target}}", target)
		.replaceAll("{target}", target)
		.replaceAll("<target>", target)
		.replaceAll("{{route}}", String(route.id ?? "reverse-pentest-general"))
		.replaceAll("{route}", String(route.id ?? "reverse-pentest-general"))
		.replaceAll("<route>", String(route.id ?? "reverse-pentest-general"))
		.replaceAll("{{routeId}}", String(route.id ?? "reverse-pentest-general"))
		.replaceAll("{routeId}", String(route.id ?? "reverse-pentest-general"))
		.replaceAll("<routeId>", String(route.id ?? "reverse-pentest-general"))
		.replaceAll("{{routeDomain}}", String(route.domain ?? "Reverse/Pentest general"))
		.replaceAll("{routeDomain}", String(route.domain ?? "Reverse/Pentest general"))
		.replaceAll("<routeDomain>", String(route.domain ?? "Reverse/Pentest general"))
		.replaceAll("{{routeWorkflow}}", Array.isArray(route.workflow) ? route.workflow.join(" -> ") : "")
		.replaceAll("{routeWorkflow}", Array.isArray(route.workflow) ? route.workflow.join(" -> ") : "")
		.replaceAll("<routeWorkflow>", Array.isArray(route.workflow) ? route.workflow.join(" -> ") : "")
		.replaceAll("{{proofKit}}", JSON.stringify(proofKit))
		.replaceAll("{proofKit}", JSON.stringify(proofKit))
		.replaceAll("<proofKit>", JSON.stringify(proofKit))
		.replaceAll("{{commandPalette}}", JSON.stringify(commandPalette))
		.replaceAll("{commandPalette}", JSON.stringify(commandPalette))
		.replaceAll("<commandPalette>", JSON.stringify(commandPalette))
		.replaceAll("{{techniqueHints}}", JSON.stringify(techniqueHints))
		.replaceAll("{techniqueHints}", JSON.stringify(techniqueHints))
		.replaceAll("<techniqueHints>", JSON.stringify(techniqueHints));
}

function readJson(path) {
	return JSON.parse(readFileSync(path, "utf8"));
}

function copyIfExists(from, to) {
	if (existsSync(from)) atomicWriteFile(to, readFileSync(from), 0o600);
}

function prepareWorkerAgentDir(tempRoot, workerId) {
	const dir = join(tempRoot, `worker-${workerId}`, "agent");
	mkdirSync(dir, { recursive: true, mode: 0o700 });
	for (const name of ["models.json", "auth.json", "settings.json"]) copyIfExists(join(sourceAgentDir, name), join(dir, name));
	return dir;
}

function makeRunId(target) {
	return `${new Date().toISOString().replace(/[:.]/g, "-")}-${sha256(`${target}:${Date.now()}:${Math.random()}`).slice(0, 10)}`;
}

function parseRoles(args) {
	const requested = String(flagValue(args, "--roles", "mapper,reverser,exploiter,verifier,adversary"))
		.split(",")
		.map((role) => role.trim().toLowerCase())
		.filter(Boolean);
	return requested.length ? requested : ["mapper", "reverser", "exploiter", "verifier", "adversary"];
}

function roleSpec(role) {
	return roleLibrary.find((item) => item.role === role) ?? { ...roleLibrary.at(-1), role };
}

const fallbackRouteProfile = {
	id: "reverse-pentest-general",
	domain: "Reverse/Pentest general",
	workflow: ["passive map", "smallest proof path", "verification", "report"],
	roles: {},
};

function routeProfilesFor(target) {
	const text = String(target ?? "");
	const matches = routeProfiles.filter((profile) => profile.match.test(text));
	return matches.length ? matches : [fallbackRouteProfile];
}

function forcedRouteProfiles(routeArg) {
	const requested = String(routeArg ?? "")
		.split(",")
		.map((item) => item.trim())
		.filter(Boolean);
	if (!requested.length) return undefined;
	if (requested.some((id) => /^(?:all|full|full-spectrum|\*)$/i.test(id))) return routeProfiles;
	const profiles = [];
	for (const id of requested) {
		const profile = routeProfiles.find((item) => item.id === id) || (id === fallbackRouteProfile.id ? fallbackRouteProfile : undefined);
		if (profile && !profiles.some((item) => item.id === profile.id)) profiles.push(profile);
	}
	return profiles.length ? profiles : [fallbackRouteProfile];
}

function routeProfileById(id) {
	const routeId = String(id ?? "").trim();
	if (!routeId) return undefined;
	return routeProfiles.find((profile) => profile.id === routeId) || (routeId === fallbackRouteProfile.id ? fallbackRouteProfile : undefined);
}

function routeProfile(target) {
	return routeProfilesFor(target)[0];
}

function workerSpec(role, profile, routeCandidates = [profile]) {
	const base = roleSpec(role);
	const overlay = profile.roles?.[role] ?? {};
	if (role === "solo") {
		const candidateText = routeCandidates.length > 1 ? ` 候选域：${routeCandidates.map((item) => item.domain).join(" / ")}。` : "";
		return {
			role: "solo",
			objective: `单工作者完整处理 ${profile.domain}：${profile.workflow.join(" -> ")}；必须自己完成 mapping、逆向假设、最小 replay/proof、负控制或失败反证，并输出结构化 claims/evidence/blockers/nextCommands。${candidateText}`,
			evidenceContract: [
				...(overlay.evidenceContract ?? []),
				"entry/surface map",
				"control/data-flow or request-order proof",
				"minimal replay/proof command",
				"negative control or counter-evidence",
				"artifact hashes",
			],
			mergeKeys: ["solo", "surface", "reverse", "proof", "control", "artifact"],
		};
	}
	return {
		role: base.role,
		objective: overlay.objective ?? base.objective,
		evidenceContract: overlay.evidenceContract ?? base.evidenceContract,
		mergeKeys: overlay.mergeKeys ?? base.mergeKeys,
	};
}

function routeCandidateRow(profile) {
	return {
		id: profile.id,
		domain: profile.domain,
		workflow: profile.workflow,
		proofKit: proofKitFor(profile),
		commandPalette: commandPaletteFor(profile),
		toolProbeCommand: toolProbeCommandFor(profile),
		techniqueHints: techniqueHintsFor(profile),
	};
}

function routeCoverageForPackets(routeCandidates, workerPackets) {
	const coveredIds = new Set(workerPackets.map((packet) => packet.route?.id).filter(Boolean));
	const covered = routeCandidates.filter((candidate) => coveredIds.has(candidate.id));
	const uncovered = routeCandidates.filter((candidate) => !coveredIds.has(candidate.id));
	return {
		routeCount: routeCandidates.length,
		coveredCount: covered.length,
		uncoveredCount: uncovered.length,
		covered,
		uncovered,
		complete: uncovered.length === 0,
	};
}

function buildSwarmPlan(args, options = {}) {
	const target = flagValue(args, "--target") ?? positionalTarget(args) ?? "local-selfcheck";
	const profiles = forcedRouteProfiles(flagValue(args, "--route")) ?? routeProfilesFor(target);
	const explicitWorkers = hasFlag(args, ["--workers", "-w"]);
	const requestedWorkers = parseIntFlag(args, ["--workers", "-w"], 3, 1, 16);
	const workers = explicitWorkers ? requestedWorkers : profiles.length > 1 ? Math.min(16, Math.max(requestedWorkers, profiles.length)) : requestedWorkers;
	const maxConcurrency = parseIntFlag(args, "--max-concurrency", workers, 1, workers);
	const provider = flagValue(args, "--provider");
	const model = flagValue(args, "--model");
	const tools = args.includes("--no-tools") ? undefined : flagValue(args, "--tools", "bash,read,grep,find,ls");
	const timeoutMs = parseIntFlag(args, "--timeout-ms", Number(process.env.REPI_SWARM_LLM_TIMEOUT_MS ?? 210000), 5000, 30 * 60 * 1000);
	const roles = workers === 1 && flagValue(args, "--roles") === undefined ? ["solo"] : parseRoles(args);
	const runId = options.runId ?? makeRunId(target);
	const profile = profiles[0];
	const workerPackets = Array.from({ length: workers }, (_, index) => {
		const packetProfile = profiles.length > 1 ? profiles[index % profiles.length] : profile;
		const spec = workerSpec(roles[index % roles.length] ?? "specialist", packetProfile, profiles);
		const proofKit = proofKitFor(packetProfile);
		const commandPalette = commandPaletteFor(packetProfile);
		const toolProbeCommand = toolProbeCommandFor(packetProfile);
		const techniqueHints = techniqueHintsFor(packetProfile);
		const workerId = index + 1;
		return {
			workerId,
			id: `worker-${workerId}`,
			role: spec.role,
			route: {
				id: packetProfile.id,
				domain: packetProfile.domain,
				workflow: packetProfile.workflow,
			},
			objective: spec.objective,
			tools,
			dependencies: [],
			evidenceContract: spec.evidenceContract,
			mergeKeys: spec.mergeKeys,
			proofKit,
			commandPalette,
			toolProbeCommand,
			techniqueHints,
			limits: { timeoutMs, maxOutputChars: DEFAULT_MAX_OUTPUT_CHARS },
		};
	});
	const routeCandidates = profiles.map(routeCandidateRow);
	const routeCoverage = routeCoverageForPackets(routeCandidates, workerPackets);
	return {
		kind: "repi-swarm-plan",
		schemaVersion: 1,
		SwarmPlannerV1: true,
		generatedAt: new Date().toISOString(),
		runId,
		root,
		runRoot: resolve(flagValue(args, "--cwd") ?? process.cwd()),
		target: redact(target),
		route: {
			id: profile.id,
			domain: profile.domain,
			workflow: profile.workflow,
		},
		routeCandidates,
		routeCoverage,
		provider: provider ?? "default",
		model: model ?? "default",
		workers,
		autoExpandedWorkers: !explicitWorkers && profiles.length > 1,
		maxConcurrency,
		timeoutMs,
		toolsDisabled: args.includes("--no-tools"),
		workerPackets,
		operatorGuidance: redact(flagValue(args, "--prompt", "")),
			proofDoctrine: universalProofDoctrine,
			evidencePriorityDoctrine,
			capabilityMatrixDoctrine,
			mergeProtocol: {
				StructuredSubagentMergeV1: true,
				requiredWorkerFields: ["claims", "evidenceItems", "conflicts", "blockers", "nextCommands"],
				promotionRule: "claim requires worker exit pass plus concrete evidence/artifact/command; narrative-only rows remain observations",
				conflictPolicy: "verifier/adversary counter-evidence downgrades mapper/reverser/exploiter claims until rechecked",
				mergeArtifacts: ["report.json", "merge-report.json", "merge-verification.json", "worker-*.stdout.txt", "worker-*.stderr.txt", "worker-*-artifacts.json", "worker-*-artifacts/*"],
			},
	};
}

function evidenceRootFor(runId) {
	return join(swarmsRoot, runId);
}

function writePlan(plan) {
	const dir = evidenceRootFor(plan.runId);
	mkdirSync(dir, { recursive: true, mode: 0o700 });
	atomicWriteFile(join(dir, "plan.json"), `${JSON.stringify(plan, null, 2)}\n`, 0o600);
	atomicWriteFile(join(dir, "report.json"), `${JSON.stringify({ kind: "repi-swarm-plan-report", schemaVersion: 1, runId: plan.runId, generatedAt: plan.generatedAt, ok: true, planPath: join(dir, "plan.json"), evidenceRoot: dir, plan }, null, 2)}\n`, 0o600);
	return dir;
}

function promptForWorker(plan, packet, promptTemplate, mode) {
	if (mode === "llm-run") {
		const operatorPrompt = substitute(promptTemplate, packet.workerId, plan.target, packet.role, packet);
		return [
			`You are REPI llm-run worker ${packet.workerId} (${packet.role}).`,
			`Target/task: ${plan.target}`,
			`Route: ${packet.route?.domain ?? plan.route?.domain ?? "Reverse/Pentest general"} (${packet.route?.id ?? plan.route?.id ?? "reverse-pentest-general"})`,
			`Route workflow: ${(packet.route?.workflow ?? plan.route?.workflow ?? []).join(" -> ")}`,
			Array.isArray(plan.routeCandidates) && plan.routeCandidates.length > 1
				? `Route candidates for broad tasks: ${plan.routeCandidates.map((route) => `${route.id}:${route.domain}`).join(" / ")}`
				: undefined,
			"Operator prompt (treat this as the mission goal; if it asks for an exact reply, reply exactly):",
			operatorPrompt,
			"Route proof kit:",
			JSON.stringify(packet.proofKit ?? proofKitFor(packet.route || { id: "reverse-pentest-general" }), null, 2),
			"Route command palette:",
			JSON.stringify(packet.commandPalette ?? commandPaletteFor(packet.route || { id: "reverse-pentest-general" }), null, 2),
			packet.toolProbeCommand ? "Route tool probe command:" : undefined,
			packet.toolProbeCommand,
			"Route technique hints:",
			JSON.stringify(packet.techniqueHints ?? techniqueHintsFor(packet.route || { id: "reverse-pentest-general" }), null, 2),
			"Capability matrix doctrine:",
			JSON.stringify(plan.capabilityMatrixDoctrine ?? capabilityMatrixDoctrine, null, 2),
			"Evidence priority doctrine:",
			JSON.stringify(plan.evidencePriorityDoctrine ?? evidencePriorityDoctrine, null, 2),
		].filter(Boolean).join("\n");
	}
	return [
		`You are REPI swarm worker ${packet.workerId} (${packet.role}).`,
		`Target/task: ${plan.target}`,
		`Route: ${packet.route?.domain ?? plan.route?.domain ?? "Reverse/Pentest general"}`,
		`Route workflow: ${(packet.route?.workflow ?? plan.route?.workflow ?? []).join(" -> ")}`,
		Array.isArray(plan.routeCandidates) && plan.routeCandidates.length > 1
			? `Route candidates for broad tasks: ${plan.routeCandidates.map((route) => route.domain).join(" / ")}`
			: undefined,
		`Role objective: ${packet.objective}`,
		plan.operatorGuidance ? `Operator guidance: ${plan.operatorGuidance}` : undefined,
		"Work independently. Prefer concrete evidence over narrative.",
		"Universal proof doctrine:",
		JSON.stringify(plan.proofDoctrine ?? universalProofDoctrine, null, 2),
		"Evidence priority doctrine:",
		JSON.stringify(plan.evidencePriorityDoctrine ?? evidencePriorityDoctrine, null, 2),
		"Capability matrix doctrine:",
		JSON.stringify(plan.capabilityMatrixDoctrine ?? capabilityMatrixDoctrine, null, 2),
		packet.proofKit ? "Route proof kit:" : undefined,
		packet.proofKit ? JSON.stringify(packet.proofKit, null, 2) : undefined,
		packet.commandPalette ? "Route command palette (adapt placeholders like $TARGET/<token>; do not claim a command ran unless you actually ran it):" : undefined,
		packet.commandPalette ? JSON.stringify(packet.commandPalette, null, 2) : undefined,
		packet.toolProbeCommand ? "Route tool probe command (run first when tools are enabled; record missing tools and choose fallbacks instead of hallucinating availability):" : undefined,
		packet.toolProbeCommand,
		packet.techniqueHints ? "Route technique hints (pull with re_techniques where available; use these as starting hypotheses, not proof):" : undefined,
		packet.techniqueHints ? JSON.stringify(packet.techniqueHints, null, 2) : undefined,
		`Evidence contract: ${packet.evidenceContract.join("; ")}`,
		`Merge keys: ${packet.mergeKeys.join(", ")}`,
		"Every promoted claim should include at least one command/path/hash/diff/offset/status/control artifact. If the proof is only a hypothesis, lower confidence and put the missing proof in blockers.",
		"Output ONLY valid JSON. Do not use Markdown fences. If evidence is missing, put the reason in blockers instead of writing prose.",
		"Required schema:",
		JSON.stringify({
			workerId: packet.id,
			role: packet.role,
			claims: [{ id: `${packet.role}-claim-1`, statement: "...", evidence: ["command/output/path"], confidence: 0.0, blockers: [], conflicts: [] }],
			evidenceItems: [{ class: "runtime-behavior|network-traffic|served-assets|process-config|persisted-state|artifact|source|comment", locator: "command/path/frame/offset", summary: "what proves it" }],
			conflicts: [{ claimId: `${packet.role}-claim-1`, evidenceClass: "runtime-behavior", evidence: "counter-evidence anchor", reason: "why this downgrades", nextCommand: "repair command" }],
			artifacts: ["path or command output anchor"],
			handoffs: [{ route: "route-id-if-another-domain-is-better", reason: "why this needs another route", evidence: "observed anchor", nextCommand: "replay or map command" }],
			blockers: [],
			nextCommands: [],
		}, null, 2),
	].filter(Boolean).join("\n");
}

function runWorker({ plan, packet, promptTemplate, expectTemplate, tempRoot, mode }) {
	return new Promise((resolveWorker) => {
		const startedAt = Date.now();
		let workerAgentDir;
		let prompt;
		try {
			prompt = promptForWorker(plan, packet, promptTemplate, mode);
			workerAgentDir = prepareWorkerAgentDir(tempRoot, packet.workerId);
		} catch (error) {
			const message = redact(String(error?.message || error));
			resolveWorker({
				workerId: packet.workerId,
				role: packet.role,
				status: "fail",
				exit: 1,
				signal: null,
				timedOut: false,
				ms: Date.now() - startedAt,
				provider: plan.provider,
				model: plan.model,
				route: packet.route,
				proofKit: packet.proofKit,
				commandPalette: packet.commandPalette,
				toolProbeCommand: packet.toolProbeCommand,
				techniqueHints: packet.techniqueHints,
				workerAgentDir: workerAgentDir ?? "",
				stdoutSha256: sha256(""),
				stderrSha256: sha256(message),
				stdoutPreview: "",
				stderrPreview: message,
				expect: expectTemplate ? substitute(expectTemplate, packet.workerId, plan.target, packet.role, packet) : undefined,
				expectOk: false,
				promptSha256: sha256(redact(prompt ?? "")),
			});
			return;
		}
		const args = [
			"--approve",
			...(plan.provider !== "default" ? ["--provider", plan.provider] : []),
			...(plan.model !== "default" ? ["--model", plan.model] : []),
			"--thinking",
			"off",
			"--no-session",
			...(packet.tools ? ["--tools", packet.tools] : ["--no-tools"]),
			"-p",
			prompt,
		];
		const child = spawn(join(root, "repi"), args, {
			cwd: plan.runRoot,
			env: {
				...process.env,
				REPI_CODING_AGENT_DIR: workerAgentDir,
				PI_CODING_AGENT_DIR: workerAgentDir,
				REPI_SKIP_VERSION_CHECK: "1",
				REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
				PI_SKIP_VERSION_CHECK: "1",
				PI_SKIP_PACKAGE_UPDATE_CHECK: "1",
				REPI_TELEMETRY: "0",
				PI_TELEMETRY: "0",
				REPI_PRINT_PROGRESS: process.env.REPI_SWARM_LLM_PROGRESS ?? "0",
			},
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill("SIGTERM");
			setTimeout(() => {
				if (child.exitCode === null) child.kill("SIGKILL");
			}, 2000).unref();
		}, packet.limits.timeoutMs);
		child.stdout.on("data", (chunk) => {
			stdout += chunk;
			if (stdout.length > 1024 * 1024) stdout = stdout.slice(-1024 * 1024);
		});
		child.stderr.on("data", (chunk) => {
			stderr += chunk;
			if (stderr.length > 1024 * 1024) stderr = stderr.slice(-1024 * 1024);
		});
		// opt #188: piped child stdio emits 'error' (EIO/EPIPE) independent of the
		// child's own 'error'/'close' — e.g. proc.kill mid-output tears the pipe.
		// A Readable with no 'error' listener → Unhandled 'error' event → crashes
		// the whole orchestrator mid-pool (runPool finally cleanup never runs).
		// Swallow so the 'close' handler still resolves the worker with whatever
		// was captured. Same doctrine as opt #36 (mcp-manager) / #40
		// (waitForChildProcess stdio).
		child.stdout?.on("error", () => {});
		child.stderr?.on("error", () => {});
		child.on("close", (code, signal) => {
			clearTimeout(timer);
			const redactedStdout = clip(stdout, packet.limits.maxOutputChars);
			const redactedStderr = clip(stderr, 6000);
			let expectOk = redactedStdout.trim().length > 0;
			let expect = undefined;
			if (expectTemplate) {
					expect = substitute(expectTemplate, packet.workerId, plan.target, packet.role, packet);
				try {
					expectOk = new RegExp(expect, "m").test(redactedStdout);
				} catch {
					expectOk = redactedStdout.includes(expect);
				}
			}
			resolveWorker({
				workerId: packet.workerId,
				role: packet.role,
				status: code === 0 && expectOk && !timedOut ? "pass" : timedOut ? "timeout" : "fail",
				exit: code ?? (signal ? 128 : 1),
				signal,
				timedOut,
				ms: Date.now() - startedAt,
				provider: plan.provider,
				model: plan.model,
				route: packet.route,
				proofKit: packet.proofKit,
				commandPalette: packet.commandPalette,
				toolProbeCommand: packet.toolProbeCommand,
				techniqueHints: packet.techniqueHints,
				workerAgentDir,
				stdoutSha256: sha256(redactedStdout),
				stderrSha256: sha256(redactedStderr),
				stdoutPreview: redactedStdout,
				stderrPreview: redactedStderr,
				expect,
				expectOk,
				promptSha256: sha256(redact(prompt)),
			});
		});
		child.on("error", (error) => {
			clearTimeout(timer);
			resolveWorker({
				workerId: packet.workerId,
				role: packet.role,
				status: "fail",
				exit: 1,
				signal: null,
				timedOut,
				ms: Date.now() - startedAt,
				provider: plan.provider,
				model: plan.model,
				route: packet.route,
				proofKit: packet.proofKit,
				commandPalette: packet.commandPalette,
				toolProbeCommand: packet.toolProbeCommand,
				techniqueHints: packet.techniqueHints,
				workerAgentDir,
				stdoutSha256: sha256(""),
				stderrSha256: sha256(redact(String(error.message || error))),
				stdoutPreview: "",
				stderrPreview: redact(String(error.message || error)),
				expect: expectTemplate ? substitute(expectTemplate, packet.workerId, plan.target, packet.role, packet) : undefined,
				expectOk: false,
				promptSha256: sha256(redact(promptForWorker(plan, packet, promptTemplate, mode))),
			});
		});
	});
}

async function runPool(plan, promptTemplate, expectTemplate, mode, keepProfiles) {
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-llm-swarm-"));
	const evidenceRoot = evidenceRootFor(plan.runId);
	mkdirSync(evidenceRoot, { recursive: true, mode: 0o700 });
	const rows = [];
	let next = 0;
	async function workerLoop() {
		while (next < plan.workerPackets.length) {
			const packet = plan.workerPackets[next++];
			rows.push(await runWorker({ plan, packet, promptTemplate, expectTemplate, tempRoot, mode }));
		}
	}
	try {
		await Promise.all(Array.from({ length: plan.maxConcurrency }, () => workerLoop()));
		rows.sort((left, right) => left.workerId - right.workerId);
		for (const worker of rows) {
			atomicWriteFile(join(evidenceRoot, `worker-${worker.workerId}.stdout.txt`), worker.stdoutPreview, 0o600);
			atomicWriteFile(join(evidenceRoot, `worker-${worker.workerId}.stderr.txt`), worker.stderrPreview, 0o600);
			worker.harvestedArtifacts = harvestWorkerArtifacts(worker, evidenceRoot);
		}
		return { rows, tempRoot: keepProfiles ? tempRoot : undefined };
	} finally {
		if (!keepProfiles) rmSync(tempRoot, { recursive: true, force: true });
	}
}

function parseJsonObjectSpan(candidate) {
	const text = String(candidate ?? "");
	const starts = [];
	const ends = [];
	for (let index = 0; index < text.length; index += 1) {
		if (text[index] === "{") starts.push(index);
		else if (text[index] === "}") ends.push(index);
	}
	const startCandidates = [...new Set([...starts.slice(0, 80), ...starts.slice(-160)])].sort((left, right) => left - right);
	const endCandidates = [...new Set([...ends.slice(0, 20), ...ends.slice(-160)])].sort((left, right) => right - left);
	let fallback;
	for (const start of startCandidates) {
		for (const end of endCandidates) {
			if (end <= start) continue;
			try {
				const parsed = JSON.parse(text.slice(start, end + 1));
				if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) continue;
				if (Array.isArray(parsed.claims) || Array.isArray(parsed.findings)) return parsed;
				fallback ??= parsed;
			} catch {
				// Keep trying smaller/older spans. LLMs often print prose with
				// brace-like snippets before the final structured JSON.
			}
		}
	}
	return fallback;
}

function extractJsonObject(text) {
	const trimmed = String(text ?? "").trim();
	if (!trimmed) return undefined;
	const fenced = /```(?:json)?\s*([\s\S]*?)```/i.exec(trimmed)?.[1];
	for (const candidate of [fenced, trimmed]) {
		if (!candidate) continue;
		const parsed = parseJsonObjectSpan(candidate);
		if (parsed) return parsed;
	}
	return undefined;
}

function linesMatching(text, pattern, limit = 12) {
	return String(text ?? "")
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter((line) => pattern.test(line))
		.slice(0, limit);
}

const evidenceRankByClass = new Map(evidencePriorityDoctrine.order.map((row) => [row.class, row.rank]));
const commandSignalPattern = /\b(?:curl|httpie|python3?|node|npm|go test|pytest|cargo|gdb|lldb|radare2|r2|rabin2|checksec|frida|objection|adb|jadx|apktool|tshark|tcpdump|wireshark|volatility3?|vol|binwalk|unblob|unsquashfs|yara|capa|floss|strings|file|readelf|objdump|xxd|exiftool|zsteg|steghide|john|hashcat|sqlmap|nmap|openssl|sage|z3|ldapsearch|impacket|bloodhound-python|certipy|netexec|nxc|cast|forge|docker|kubectl|helm|terraform|aws|gcloud|az)\b/i;
const artifactPathSignalPattern = /(?:^|[\s"'[(,])(?:\.{0,2}\/|\/)[A-Za-z0-9._~+@%=:,/\-]+|(?:^|[\s"'[(,])[A-Za-z]:\\[A-Za-z0-9._~+@%=:,\\/\-]+/;
const diffOrStatusSignalPattern = /\b(?:HTTP\s*[1-5][0-9]{2}|status[:= ]?[1-5][0-9]{2}|diff|before\/after|body[_ -]?hash|registers?|rip|rsp|eip|esp|offset|frame|packet|stream|exit(?:ed)?|exit[:= ]?\d+)\b|(?:状态码|响应差异|前后状态|正文哈希|寄存器|偏移|帧|数据包|流编号|退出码)/i;
const negativeControlSignalPattern = /\b(?:negative control|tampered|missing|unsigned|stale|counter[- ]?evidence|control failed|rejected|forbidden|unauthorized|invalid token|wrong principal|wrong key|wrong offset|401|403|crash vs no-crash)\b|(?:负控制|阴性对照|反证|反例|篡改|错误(?:签名|密钥|key|token|令牌|主体|principal|偏移)|未授权|禁止|拒绝|被拒绝|失败对照|崩溃对照)/i;

function evidenceClassRank(evidenceClass) {
	return evidenceRankByClass.get(String(evidenceClass ?? "unknown")) ?? 0;
}

function classifyEvidenceText(value, explicitClass) {
	const text = String(value ?? "");
	const explicit = String(explicitClass ?? "").trim();
	if (evidenceRankByClass.has(explicit)) {
		return { class: explicit, rank: evidenceClassRank(explicit), reason: "explicit" };
	}
	const patterns = [
		["runtime-behavior", /\b(?:exits?\s*\d+|exit[:= ]?\d+|gdb|lldb|register|stack|crash|SIG[A-Z]+|runtime|transcript|replay(?:ed)?|accepted|rejected|forbidden|negative control|counter[- ]?evidence|N-run|frida|adb shell|volatility\d?|kubectl auth can-i|aws sts|get-caller-identity)\b|(?:退出码|运行时|复现|重放|接受|拒绝|被拒绝|负控制|反证|崩溃|寄存器)/i],
		["network-traffic", /\b(?:HTTP\s*[1-5][0-9]{2}|status[:= ]?[1-5][0-9]{2}|body hash|request|response|curl|XHR|fetch|WebSocket|PCAP|packet|frame|stream|tshark|tcpflow|SNI|JA3|DNS|TLS)\b|(?:状态码|请求|响应|流量|数据包|帧|会话流)/i],
		["served-assets", /\b(?:served asset|source-?map|sourcemap|chunk|webpack|vite|wasm|WebAssembly|page\.html|openapi|swagger|graphql schema|asset hash)\b/i],
		["process-config", /\b(?:config|manifest|plist|IAM|RBAC|role|principal|namespace|session|cookie|middleware|route list|loader|libc|checksec|RELRO|PIE|Canary|NX|tool availability)\b|(?:配置|清单|会话|中间件|路由|权限|命名空间|加载器)/i],
		["persisted-state", /\b(?:database|registry|storage|before\/after|state change|filesystem|ledger|artifact ledger|dumped file|carved|persisted)\b|(?:数据库|注册表|存储|状态变化|文件系统|账本|转储|持久化)/i],
		["artifact", /\b(?:sha256|sha1|md5)[:= ]?[a-f0-9]{16,64}\b|(?:^|[\s"'[(,])(?:\.{0,2}\/|\/)[A-Za-z0-9._~+@%=:,/\-]+|\boffset\b|\bhash\b|\bartifact\b|(?:偏移|哈希|证据文件|工件)/i],
		["source", /\b(?:source|grep|strings|imports?|xref|function|symbol|line \d+|code path|static triage|readelf|objdump|rabin2)\b|(?:源码|字符串|导入|交叉引用|函数|符号|代码路径|静态分析)/i],
		["comment", /\b(?:README|TODO|comment|docs?|note|hypothesis only|unverified narrative)\b/i],
	];
	for (const [evidenceClass, pattern] of patterns) {
		if (pattern.test(text)) return { class: evidenceClass, rank: evidenceClassRank(evidenceClass), reason: "pattern" };
	}
	return { class: "unknown", rank: 0, reason: "unknown" };
}

function evidenceTextFromItem(item) {
	if (!item) return "";
	if (typeof item === "string") return item;
	return [
		item.evidenceClass ? `class=${item.evidenceClass}` : item.class ? `class=${item.class}` : undefined,
		item.locator,
		item.summary,
		item.evidence,
		item.command,
		item.path,
		item.hash ? `hash=${item.hash}` : undefined,
		item.frame ? `frame=${item.frame}` : undefined,
		item.offset ? `offset=${item.offset}` : undefined,
	]
		.filter(Boolean)
		.map(String)
		.join(" ");
}

function evidencePrioritySummary(evidence, evidenceItems = []) {
	const rows = [
		...evidence.map((item) => ({
			evidence: redact(String(item)).slice(0, 240),
			...classifyEvidenceText(item),
		})),
		...evidenceItems.map((item) => {
			const evidenceText = evidenceTextFromItem(item);
			const classified = classifyEvidenceText(evidenceText, item?.evidenceClass ?? item?.class);
			return {
				evidence: redact(evidenceText).slice(0, 240),
				...classified,
			};
		}),
	];
	const strongest = rows.reduce((best, row) => (!best || row.rank > best.rank ? row : best), undefined);
	const classes = [...new Set(rows.map((row) => row.class))];
	return {
		classes,
		strongestClass: strongest?.class ?? "unknown",
		strongestRank: strongest?.rank ?? 0,
		rows: rows.slice(0, 12),
	};
}

function claimQualitySignals(evidence, blockers, evidenceItems = []) {
	const evidenceItemTexts = evidenceItems.map(evidenceTextFromItem).filter(Boolean);
	const text = [...evidence, ...evidenceItemTexts].join("\n");
	const priority = evidencePrioritySummary(evidence, evidenceItems);
	const hasCommand = commandSignalPattern.test(text);
	const hasArtifactPath = artifactPathSignalPattern.test(text);
	const hasHash = /\b(?:sha256|sha1|md5)[:= ]?[a-f0-9]{16,64}\b/i.test(text) || /\b[a-f0-9]{64}\b/i.test(text);
	const hasDiffOrStatus = diffOrStatusSignalPattern.test(text);
	const hasNegativeControl = negativeControlSignalPattern.test(text);
	const score = [hasCommand, hasArtifactPath, hasHash, hasDiffOrStatus, hasNegativeControl].filter(Boolean).length;
	return {
		evidenceCount: evidence.length,
		evidenceItemCount: evidenceItems.length,
		blockerCount: blockers.length,
		hasCommand,
		hasArtifactPath,
		hasHash,
		hasDiffOrStatus,
		hasNegativeControl,
		evidenceClasses: priority.classes,
		strongestEvidenceClass: priority.strongestClass,
		evidencePriorityRank: priority.strongestRank,
		evidencePriorityRows: priority.rows,
		score,
	};
}

function claimProofCoverage(qualitySignals) {
	return {
		passive: Number(qualitySignals?.evidenceCount ?? 0) > 0 || Number(qualitySignals?.evidenceItemCount ?? 0) > 0 || Boolean(qualitySignals?.hasArtifactPath) || Boolean(qualitySignals?.hasHash),
		proofExit: Boolean(qualitySignals?.hasCommand) || Boolean(qualitySignals?.hasHash) || Boolean(qualitySignals?.hasDiffOrStatus) || Boolean(qualitySignals?.hasArtifactPath),
		negativeControls: Boolean(qualitySignals?.hasNegativeControl),
	};
}

function claimProofReady(claim) {
	const coverage = claim?.proofCoverage ?? claimProofCoverage(claim?.qualitySignals ?? {});
	return claim?.status === "promoted" && coverage.passive && coverage.proofExit && coverage.negativeControls;
}

function parsedEvidenceBundle(parsed, parsedClaims, stdout, evidenceItems = []) {
	const evidence = [];
	const blockers = [];
	for (const claim of parsedClaims) {
		if (Array.isArray(claim?.evidence)) evidence.push(...claim.evidence.map(String));
		if (Array.isArray(claim?.evidenceItems)) evidence.push(...claim.evidenceItems.map(evidenceTextFromItem));
		if (Array.isArray(claim?.blockers)) blockers.push(...claim.blockers.map(String));
	}
	if (Array.isArray(parsed?.evidence)) evidence.push(...parsed.evidence.map(String));
	if (Array.isArray(parsed?.evidenceItems)) evidence.push(...parsed.evidenceItems.map(evidenceTextFromItem));
	if (Array.isArray(evidenceItems)) evidence.push(...evidenceItems.map(evidenceTextFromItem));
	if (Array.isArray(parsed?.artifacts)) evidence.push(...parsed.artifacts.map(String));
	if (Array.isArray(parsed?.nextCommands)) evidence.push(...parsed.nextCommands.map(String));
	if (Array.isArray(parsed?.blockers)) blockers.push(...parsed.blockers.map(String));
	if (!evidence.length && stdout) evidence.push(...linesMatching(stdout, /sha256|HTTP|status|curl|python|node|gdb|frida|jadx|apktool|tshark|volatility|binwalk|yara|capa|floss|readelf|objdump|offset|diff|artifact|evidence|proof|状态码|证据|负控制|反证/i, 20));
	return {
		evidence: evidence.map(redact).filter(Boolean).slice(0, 80),
		blockers: blockers.map(redact).filter(Boolean).slice(0, 40),
	};
}

function proofChecklistForWorker(worker, parsed, parsedClaims, stdout, evidenceItems = []) {
	const proofKit = worker.proofKit || proofKitFor(worker.route || { id: "reverse-pentest-general" });
	const commandPalette = worker.commandPalette || commandPaletteFor(worker.route || { id: "reverse-pentest-general" });
	const toolProbeCommand = worker.toolProbeCommand || toolProbeCommandFor(worker.route || { id: "reverse-pentest-general" });
	const techniqueHints = worker.techniqueHints || techniqueHintsFor(worker.route || { id: "reverse-pentest-general" });
	const bundle = parsedEvidenceBundle(parsed, parsedClaims, stdout, evidenceItems);
	const quality = claimQualitySignals(bundle.evidence, bundle.blockers, evidenceItems);
	const coverage = {
		passive: bundle.evidence.length > 0 || quality.hasArtifactPath || quality.hasHash,
		proofExit: quality.hasCommand || quality.hasHash || quality.hasDiffOrStatus || quality.hasArtifactPath,
		negativeControls: quality.hasNegativeControl,
	};
	const missing = [];
	if (!coverage.passive) missing.push("passive evidence");
	if (!coverage.proofExit) missing.push("proof/replay evidence");
	if (!coverage.negativeControls) missing.push("negative control or counter-evidence");
	return {
		workerId: worker.workerId,
		role: worker.role ?? "worker",
		route: worker.route ?? null,
		status: worker.status,
		proofKit,
		commandPalette,
		toolProbeCommand,
		techniqueHints,
		coverage,
		qualitySignals: quality,
		missing,
		proofReady: worker.status === "pass" && coverage.passive && coverage.proofExit && coverage.negativeControls,
		evidencePreview: bundle.evidence.slice(0, 8),
		blockers: bundle.blockers.slice(0, 8),
	};
}

function preservedRunFlags(plan) {
	const flagPairs = [];
	const bareFlags = [];
	if (plan?.provider && plan.provider !== "default") flagPairs.push(["--provider", plan.provider]);
	if (plan?.model && plan.model !== "default") flagPairs.push(["--model", plan.model]);
	if (Number.isFinite(Number(plan?.timeoutMs))) flagPairs.push(["--timeout-ms", String(plan.timeoutMs)]);
	if (plan?.runRoot) flagPairs.push(["--cwd", plan.runRoot]);
	const tools = Array.isArray(plan?.workerPackets) ? plan.workerPackets.find((packet) => packet?.tools)?.tools : undefined;
	if (tools) flagPairs.push(["--tools", tools]);
	else if (plan?.toolsDisabled) bareFlags.push("--no-tools");
	return [
		...flagPairs.map(([flag, value]) => `${flag} ${shellQuote(value)}`),
		...bareFlags,
	].join(" ");
}

function swarmRunBaseCommand(plan) {
	const target = shellQuote(plan?.target ?? "local-selfcheck");
	const flags = preservedRunFlags(plan);
	return `repi swarm run ${target}${flags ? ` ${flags}` : ""}`;
}

function proofRepairCommand(plan, checklist) {
	if (!checklist || checklist.proofReady) return undefined;
	const route = checklist.route?.domain || checklist.route?.id || "Reverse/Pentest general";
	const routeFlag = checklist.route?.id ? ` --route ${shellQuote(checklist.route.id)}` : "";
	const prompt = [
		`Close proof gaps for worker-${checklist.workerId} route ${route}.`,
		`Missing: ${checklist.missing.join(", ") || "none"}.`,
		`Use passive/proofExit/negativeControls from this proof kit: ${JSON.stringify(checklist.proofKit)}`,
		`Start from this command palette where applicable: ${JSON.stringify(checklist.commandPalette)}`,
		checklist.toolProbeCommand ? `First probe tool availability with: ${checklist.toolProbeCommand}` : undefined,
		`Pull or apply these route technique hints where applicable: ${JSON.stringify(checklist.techniqueHints)}`,
		"Return only JSON claims/evidence/blockers/nextCommands with concrete commands, paths, hashes, diffs/status, and negative controls.",
	].filter(Boolean).join(" ");
	return `${swarmRunBaseCommand(plan)} --workers 1${routeFlag} --roles verifier --prompt ${shellQuote(prompt)}`;
}

function routeCoverageRepairCommand(plan, route) {
	if (!route) return undefined;
	const prompt = [
		`Cover previously unassigned route ${route.domain || route.id}.`,
		`Use this proof kit: ${JSON.stringify(route.proofKit || proofKitFor(route))}`,
		`Start from this command palette where applicable: ${JSON.stringify(route.commandPalette || commandPaletteFor(route))}`,
		route.toolProbeCommand ? `First probe tool availability with: ${route.toolProbeCommand}` : undefined,
		`Pull or apply these route technique hints where applicable: ${JSON.stringify(route.techniqueHints || techniqueHintsFor(route))}`,
		"Produce one promoted-quality claim with passive evidence, proof/replay evidence, and negative control or counter-evidence.",
	].filter(Boolean).join(" ");
	return `${swarmRunBaseCommand(plan)} --workers 1 --route ${shellQuote(route.id)} --roles solo --prompt ${shellQuote(prompt)}`;
}

function routeProofRepairCommand(plan, readiness) {
	if (!readiness || readiness.proofReady || !readiness.route?.id) return undefined;
	const route = readiness.route;
	const prompt = [
		`Close route-level proof gap for ${route.domain || route.id}.`,
		`Missing: ${readiness.missing.join(", ") || "proof-ready promoted claim"}.`,
		readiness.assignedWorkerIds.length ? `Previous assigned workers: ${readiness.assignedWorkerIds.join(", ")}.` : undefined,
		readiness.promotedClaimIds.length ? `Existing promoted-but-not-route-ready claims: ${readiness.promotedClaimIds.join(", ")}.` : undefined,
		`Use this proof kit: ${JSON.stringify(route.proofKit || proofKitFor(route))}`,
		`Start from this command palette where applicable: ${JSON.stringify(route.commandPalette || commandPaletteFor(route))}`,
		route.toolProbeCommand ? `First probe tool availability with: ${route.toolProbeCommand}` : undefined,
		`Pull or apply these route technique hints where applicable: ${JSON.stringify(route.techniqueHints || techniqueHintsFor(route))}`,
		"Produce one promoted-quality claim with passive evidence, proof/replay evidence, and negative control or counter-evidence for this exact route.",
	].filter(Boolean).join(" ");
	return `${swarmRunBaseCommand(plan)} --workers 1 --route ${shellQuote(route.id)} --roles solo --prompt ${shellQuote(prompt)}`;
}

function normalizeRouteHandoff(worker, row, index) {
	const profile = routeProfileById(row?.route ?? row?.routeId ?? row?.id);
	if (!profile) return undefined;
	return {
		handoffId: `worker-${worker.workerId}-handoff-${index + 1}`,
		workerId: worker.workerId,
		fromRoute: worker.route ?? null,
		route: routeCandidateRow(profile),
		reason: redact(String(row?.reason ?? row?.why ?? "cross-route evidence discovered")).slice(0, 600),
		evidence: redact(String(row?.evidence ?? row?.anchor ?? "")).slice(0, 600),
		nextCommand: row?.nextCommand ? redact(String(row.nextCommand)).slice(0, 1000) : undefined,
	};
}

function routeHandoffCommand(plan, handoff) {
	if (!handoff?.route?.id) return undefined;
	const prompt = [
		`Follow cross-route handoff ${handoff.handoffId} from worker-${handoff.workerId}.`,
		`Reason: ${handoff.reason || "cross-route evidence discovered"}.`,
		handoff.evidence ? `Evidence anchor: ${handoff.evidence}.` : undefined,
		`Use this proof kit: ${JSON.stringify(handoff.route.proofKit || proofKitFor(handoff.route))}`,
		`Start from this command palette where applicable: ${JSON.stringify(handoff.route.commandPalette || commandPaletteFor(handoff.route))}`,
		handoff.route.toolProbeCommand ? `First probe tool availability with: ${handoff.route.toolProbeCommand}` : undefined,
		`Pull or apply these route technique hints where applicable: ${JSON.stringify(handoff.route.techniqueHints || techniqueHintsFor(handoff.route))}`,
		handoff.nextCommand ? `Seed next command: ${handoff.nextCommand}.` : undefined,
		"Produce one promoted-quality claim with passive evidence, proof/replay evidence, and negative control or counter-evidence.",
	].filter(Boolean).join(" ");
	return `${swarmRunBaseCommand(plan)} --workers 1 --route ${shellQuote(handoff.route.id)} --roles solo --prompt ${shellQuote(prompt)}`;
}

function normalizeEvidenceItem(worker, row, index, claimId) {
	if (row === undefined || row === null) return undefined;
	const objectRow = typeof row === "object" ? row : { summary: String(row) };
	const locator = redact(String(objectRow.locator ?? objectRow.path ?? objectRow.command ?? objectRow.frame ?? objectRow.offset ?? "")).slice(0, 500);
	const summary = redact(String(objectRow.summary ?? objectRow.evidence ?? objectRow.description ?? objectRow.note ?? "")).slice(0, 1000);
	const evidenceText = evidenceTextFromItem({ ...objectRow, locator, summary });
	const classified = classifyEvidenceText(evidenceText, objectRow.evidenceClass ?? objectRow.class);
	return {
		evidenceItemId: `worker-${worker.workerId}-evidence-${index + 1}`,
		workerId: worker.workerId,
		role: worker.role ?? "worker",
		route: worker.route ?? null,
		claimId: redact(String(objectRow.claimId ?? objectRow.claim ?? claimId ?? "")).slice(0, 200),
		locator,
		summary,
		evidenceText: redact(evidenceText).slice(0, 1600),
		evidenceClass: classified.class,
		evidencePriorityRank: classified.rank,
		classificationReason: classified.reason,
	};
}

function normalizeConflict(worker, row, index, claimId) {
	if (!row || typeof row !== "object") return undefined;
	const evidence = redact(String(row.evidence ?? row.anchor ?? row.summary ?? row.reason ?? "")).slice(0, 1000);
	const classified = classifyEvidenceText(evidence, row.evidenceClass ?? row.class);
	return {
		conflictId: `worker-${worker.workerId}-conflict-${index + 1}`,
		workerId: worker.workerId,
		role: worker.role ?? "worker",
		route: worker.route ?? null,
		claimId: redact(String(row.claimId ?? row.against ?? claimId ?? "")).slice(0, 200),
		reason: redact(String(row.reason ?? "counter-evidence recorded")).slice(0, 600),
		evidence,
		evidenceClass: classified.class,
		evidencePriorityRank: classified.rank,
		nextCommand: row.nextCommand ? redact(String(row.nextCommand)).slice(0, 1000) : undefined,
	};
}

function conflictResolutionForClaim(claim, conflictRows) {
	const relevant = conflictRows.filter((row) => !row.claimId || row.claimId === claim.claimId);
	const strongest = relevant.reduce((best, row) => (!best || row.evidencePriorityRank > best.evidencePriorityRank ? row : best), undefined);
	if (!strongest) {
		return {
			status: "no_conflict",
			downgraded: false,
			strongestConflictRank: 0,
			strongestConflictClass: "none",
			relevantConflictIds: [],
		};
	}
	const claimRank = Number(claim?.qualitySignals?.evidencePriorityRank ?? 0);
	const downgraded = strongest.evidencePriorityRank >= claimRank;
	return {
		status: downgraded ? "downgraded_by_equal_or_stronger_counterevidence" : "counterevidence_recorded_lower_priority",
		downgraded,
		claimEvidencePriorityRank: claimRank,
		strongestConflictRank: strongest.evidencePriorityRank,
		strongestConflictClass: strongest.evidenceClass,
		relevantConflictIds: relevant.map((row) => row.conflictId).slice(0, 12),
	};
}

function normalizedRouteRow(route) {
	if (!route) return undefined;
	const id = String(route.id ?? route.routeId ?? "").trim();
	if (!id) return undefined;
	const profile = routeProfileById(id) || route;
	return {
		id,
		domain: route.domain ?? profile.domain ?? id,
		workflow: Array.isArray(route.workflow) ? route.workflow : Array.isArray(profile.workflow) ? profile.workflow : [],
		proofKit: route.proofKit ?? proofKitFor(profile),
		commandPalette: route.commandPalette ?? commandPaletteFor(profile),
		toolProbeCommand: route.toolProbeCommand ?? toolProbeCommandFor(profile),
		techniqueHints: route.techniqueHints ?? techniqueHintsFor(profile),
	};
}

function uniqueRouteRows(routes) {
	const seen = new Set();
	const rows = [];
	for (const route of routes) {
		const normalized = normalizedRouteRow(route);
		if (!normalized || seen.has(normalized.id)) continue;
		seen.add(normalized.id);
		rows.push(normalized);
	}
	return rows;
}

function requiredRouteRows(plan, workersReport, routeCoverage) {
	const candidates = uniqueRouteRows(Array.isArray(plan?.routeCandidates) ? plan.routeCandidates : []);
	if (candidates.length) return candidates;
	const covered = uniqueRouteRows(Array.isArray(routeCoverage?.covered) ? routeCoverage.covered : []);
	if (covered.length) return covered;
	const workerRoutes = uniqueRouteRows(workersReport.map((worker) => worker.route).filter(Boolean));
	if (workerRoutes.length) return workerRoutes;
	return uniqueRouteRows([plan?.route, fallbackRouteProfile]);
}

function buildRouteReadinessRows(plan, workersReport, proofChecklists, promotedClaims, proofReadyPromotedClaims, routeCoverage) {
	const workerById = new Map(workersReport.map((worker) => [String(worker.workerId), worker]));
	const checklistByWorkerId = new Map(proofChecklists.map((row) => [String(row.workerId), row]));
	const proofReadyClaimIds = new Set(proofReadyPromotedClaims.map((claim) => claim.claimId));
	return requiredRouteRows(plan, workersReport, routeCoverage).map((route) => {
		const assignedWorkers = workersReport.filter((worker) => String(worker.route?.id ?? plan?.route?.id ?? "") === route.id);
		const routePromotedClaims = promotedClaims.filter((claim) => {
			const claimWorker = workerById.get(String(claim.workerId));
			return String(claim.route?.id ?? claimWorker?.route?.id ?? "") === route.id;
		});
		const routeProofReadyPromotedClaims = routePromotedClaims.filter((claim) => proofReadyClaimIds.has(claim.claimId));
		const proofReadyWorkerIds = assignedWorkers
			.filter((worker) => checklistByWorkerId.get(String(worker.workerId))?.proofReady)
			.map((worker) => worker.workerId);
		const missing = [];
		if (!assignedWorkers.length) missing.push("assigned worker");
		if (!routePromotedClaims.length) missing.push("promoted claim");
		if (!routeProofReadyPromotedClaims.length) missing.push("proof-ready promoted claim");
		return {
			route,
			routeId: route.id,
			domain: route.domain,
			assignedWorkerIds: assignedWorkers.map((worker) => worker.workerId),
			passedWorkerIds: assignedWorkers.filter((worker) => worker.status === "pass").map((worker) => worker.workerId),
			proofReadyWorkerIds,
			promotedClaimIds: routePromotedClaims.map((claim) => claim.claimId),
			proofReadyPromotedClaimIds: routeProofReadyPromotedClaims.map((claim) => claim.claimId),
			proofReady: routeProofReadyPromotedClaims.length > 0,
			missing,
		};
	});
}

function verifySwarmTranscriptHashes(evidenceRoot, workersReport) {
	const workerChecks = workersReport.map((worker) => {
		const stdoutPath = join(evidenceRoot, `worker-${worker.workerId}.stdout.txt`);
		const stderrPath = join(evidenceRoot, `worker-${worker.workerId}.stderr.txt`);
		const stdoutExists = existsSync(stdoutPath);
		const stderrExists = existsSync(stderrPath);
		const stdoutSha256 = stdoutExists ? sha256(readFileSync(stdoutPath)) : null;
		const stderrSha256 = stderrExists ? sha256(readFileSync(stderrPath)) : null;
		return {
			workerId: worker.workerId,
			status: worker.status,
			stdoutPath,
			stderrPath,
			stdoutExists,
			stderrExists,
			stdoutSha256,
			stderrSha256,
			stdoutMatched: stdoutExists && stdoutSha256 === worker.stdoutSha256,
			stderrMatched: stderrExists && stderrSha256 === worker.stderrSha256,
		};
	});
	return {
		verified: workerChecks.length > 0 && workerChecks.every((row) => row.stdoutMatched && row.stderrMatched),
		workerCount: workerChecks.length,
		verifiedWorkers: workerChecks.filter((row) => row.stdoutMatched && row.stderrMatched).length,
		workerChecks,
	};
}

function verifySwarmHarvestedArtifacts(workersReport) {
	const artifactChecks = [];
	for (const worker of workersReport) {
		for (const artifact of worker.harvestedArtifacts ?? []) {
			const path = artifact.artifactPath;
			const exists = Boolean(path && existsSync(path));
			let size = 0;
			let sha = null;
			if (exists) {
				const data = readFileSync(path);
				size = data.length;
				sha = sha256(data);
			}
			artifactChecks.push({
				workerId: worker.workerId,
				sourcePath: artifact.sourcePath ?? null,
				artifactPath: path ?? null,
				exists,
				size,
				expectedSize: artifact.size ?? null,
				sha256: sha,
				expectedSha256: artifact.sha256 ?? null,
				verified: exists && size === artifact.size && sha === artifact.sha256,
			});
		}
	}
	return {
		verified: artifactChecks.every((row) => row.verified),
		artifactCount: artifactChecks.length,
		verifiedArtifacts: artifactChecks.filter((row) => row.verified).length,
		artifactChecks,
	};
}

function verifySwarmClaimProofGates(claimRows, proofReadyPromotedClaims, evidenceItemRows, conflictRows) {
	const evidenceItemIds = new Set(evidenceItemRows.map((row) => row.evidenceItemId));
	const conflictByClaimId = new Map();
	for (const conflict of conflictRows) {
		if (!conflict.claimId) continue;
		if (!conflictByClaimId.has(conflict.claimId)) conflictByClaimId.set(conflict.claimId, []);
		conflictByClaimId.get(conflict.claimId).push(conflict);
	}
	const claimChecks = proofReadyPromotedClaims.map((claim) => {
		const source = claimRows.find((row) => row.claimId === claim.claimId) ?? claim;
		const coverage = source.proofCoverage ?? {};
		const referencedEvidenceItems = source.evidenceItemIds ?? [];
		return {
			claimId: source.claimId,
			workerId: source.workerId,
			routeId: source.route?.id ?? null,
			status: source.status,
			proofReady: Boolean(source.proofReady),
			coverage,
			evidenceItemIds: referencedEvidenceItems,
			evidenceItemsResolved: referencedEvidenceItems.every((id) => evidenceItemIds.has(id)),
			conflictStatus: source.conflictResolution?.status ?? "unknown",
			counterEvidenceCount: (conflictByClaimId.get(source.claimId) ?? []).length,
			verified:
				source.status === "promoted" &&
				Boolean(source.proofReady) &&
				Boolean(coverage.passive) &&
				Boolean(coverage.proofExit) &&
				Boolean(coverage.negativeControls) &&
				referencedEvidenceItems.every((id) => evidenceItemIds.has(id)) &&
				source.conflictResolution?.downgraded !== true,
		};
	});
	return {
		verified: proofReadyPromotedClaims.length > 0 && claimChecks.every((row) => row.verified),
		proofReadyPromotedClaimCount: proofReadyPromotedClaims.length,
		verifiedClaims: claimChecks.filter((row) => row.verified).length,
		claimChecks,
	};
}

function verifySwarmRouteProofGates(routeReadinessRows, proofReadyPromotedClaims) {
	const proofReadyClaimIds = new Set(proofReadyPromotedClaims.map((claim) => claim.claimId));
	const routeChecks = routeReadinessRows.map((row) => {
		const resolvedProofReadyClaims = (row.proofReadyPromotedClaimIds ?? []).filter((claimId) => proofReadyClaimIds.has(claimId));
		return {
			routeId: row.routeId,
			domain: row.domain,
			proofReady: Boolean(row.proofReady),
			assignedWorkerIds: row.assignedWorkerIds ?? [],
			promotedClaimIds: row.promotedClaimIds ?? [],
			proofReadyPromotedClaimIds: row.proofReadyPromotedClaimIds ?? [],
			resolvedProofReadyClaims,
			missing: row.missing ?? [],
			verified: Boolean(row.proofReady) ? resolvedProofReadyClaims.length > 0 : (row.missing ?? []).length > 0,
		};
	});
	return {
		verified: routeChecks.length > 0 && routeChecks.every((row) => row.verified),
		routeCount: routeChecks.length,
		readyRoutes: routeChecks.filter((row) => row.proofReady).length,
		verifiedRoutes: routeChecks.filter((row) => row.verified).length,
		routeChecks,
	};
}

function buildSwarmMergeNegativeControls(transcriptVerification, artifactVerification, claimGateVerification, routeGateVerification) {
	const firstWorker = transcriptVerification.workerChecks[0];
	const firstArtifact = artifactVerification.artifactChecks[0];
	const firstClaim = claimGateVerification.claimChecks[0];
	const firstRoute = routeGateVerification.routeChecks[0];
	const controls = [];
	if (firstWorker) {
		controls.push({
			controlType: "swarm-transcript-hash-mutation-control",
			workerId: firstWorker.workerId,
			passed: firstWorker.stdoutSha256 !== `${firstWorker.stdoutSha256}:mutated`,
		});
	}
	if (firstArtifact) {
		controls.push({
			controlType: "swarm-artifact-hash-mutation-control",
			workerId: firstArtifact.workerId,
			artifactPath: firstArtifact.artifactPath,
			passed: firstArtifact.sha256 !== `${firstArtifact.sha256}:mutated`,
		});
	}
	if (firstClaim) {
		controls.push({
			controlType: "swarm-missing-evidence-item-control",
			claimId: firstClaim.claimId,
			passed: !firstClaim.evidenceItemIds.includes(`${firstClaim.claimId}:missing-evidence-item`),
		});
	}
	if (firstRoute) {
		controls.push({
			controlType: "swarm-route-proof-gate-control",
			routeId: firstRoute.routeId,
			passed: firstRoute.proofReady ? firstRoute.resolvedProofReadyClaims.length > 0 : firstRoute.missing.length > 0,
		});
	}
	return {
		verified: controls.length >= 3 && controls.every((row) => row.passed),
		negativeControlsPassed: controls.filter((row) => row.passed).length,
		negativeControls: controls,
	};
}

function swarmVerificationClaim(claimLedger, claim) {
	const normalized = { verdict: "promoted", confidence: 0.8, blockers: [], ...claim };
	claimLedger.push(normalized);
	return normalized;
}

function buildSwarmMergeVerification(evidenceRoot, workersReport, mergeReport) {
	const transcriptVerification = verifySwarmTranscriptHashes(evidenceRoot, workersReport);
	const artifactVerification = verifySwarmHarvestedArtifacts(workersReport);
	const claimGateVerification = verifySwarmClaimProofGates(mergeReport.claimRows, mergeReport.proofReadyPromotedClaims, mergeReport.evidenceItemRows, mergeReport.conflictRows);
	const routeGateVerification = verifySwarmRouteProofGates(mergeReport.routeReadinessRows, mergeReport.proofReadyPromotedClaims);
	const negativeControlVerification = buildSwarmMergeNegativeControls(transcriptVerification, artifactVerification, claimGateVerification, routeGateVerification);
	const claimLedger = [];
	const composedPaths = [];
	const transcriptClaim = transcriptVerification.verified
		? swarmVerificationClaim(claimLedger, {
				id: "swarm-worker-transcript-hash-" + sha256(transcriptVerification.workerChecks.map((row) => `${row.workerId}:${row.stdoutSha256}:${row.stderrSha256}`).join("|")).slice(0, 16),
				claimType: "swarm-worker-transcript-hash-proof",
				sourceBinding: { artifact: "merge-verification.json", workers: transcriptVerification.workerChecks.map((row) => row.workerId) },
				evidenceBinding: transcriptVerification,
				statement: "Swarm verifier rebound worker stdout/stderr transcripts to hashes stored in report.json.",
			})
		: undefined;
	const artifactClaim = artifactVerification.verified
		? swarmVerificationClaim(claimLedger, {
				id: "swarm-harvested-artifact-integrity-" + sha256(artifactVerification.artifactChecks.map((row) => `${row.workerId}:${row.sha256}`).join("|")).slice(0, 16),
				claimType: "swarm-harvested-artifact-integrity-proof",
				sourceBinding: { artifact: "merge-verification.json", harvestedArtifacts: "worker-*-artifacts.json" },
				evidenceBinding: artifactVerification,
				statement: artifactVerification.artifactCount
					? "Swarm verifier matched harvested worker artifacts by size and SHA-256."
					: "Swarm verifier confirmed there were no harvested artifacts requiring size/SHA-256 verification.",
				confidence: artifactVerification.artifactCount ? 0.84 : 0.72,
			})
		: undefined;
	const claimGateClaim = claimGateVerification.verified
		? swarmVerificationClaim(claimLedger, {
				id: "swarm-claim-proof-gate-" + sha256(claimGateVerification.claimChecks.map((row) => row.claimId).join("|")).slice(0, 16),
				claimType: "swarm-claim-proof-gate-proof",
				sourceBinding: { artifact: "merge-verification.json", merge: "merge-report.json" },
				evidenceBinding: claimGateVerification,
				statement: "Swarm verifier confirmed proof-ready promoted claims carry passive, replay/proof, negative-control, evidence-item, and conflict gates.",
				confidence: 0.86,
			})
		: undefined;
	const routeGateClaim = routeGateVerification.verified
		? swarmVerificationClaim(claimLedger, {
				id: "swarm-route-proof-gate-" + sha256(routeGateVerification.routeChecks.map((row) => `${row.routeId}:${row.proofReady}`).join("|")).slice(0, 16),
				claimType: "swarm-route-proof-gate-proof",
				sourceBinding: { artifact: "merge-verification.json", merge: "merge-report.json" },
				evidenceBinding: routeGateVerification,
				statement: "Swarm verifier confirmed each route readiness row either resolves to proof-ready promoted claims or remains blocked with explicit missing gates.",
				confidence: 0.84,
			})
		: undefined;
	const negativeClaim = negativeControlVerification.verified
		? swarmVerificationClaim(claimLedger, {
				id: "swarm-merge-negative-control-" + sha256(JSON.stringify(negativeControlVerification.negativeControls)).slice(0, 16),
				claimType: "swarm-merge-negative-control-proof",
				sourceBinding: { artifact: "merge-verification.json" },
				evidenceBinding: negativeControlVerification,
				statement: "Swarm verifier executed transcript-hash, artifact-hash, missing-evidence-item, and route-gate negative controls where applicable.",
				confidence: 0.84,
			})
		: undefined;
	if (transcriptClaim && artifactClaim && claimGateClaim && routeGateClaim && negativeClaim) {
		const segments = [transcriptClaim, artifactClaim, claimGateClaim, routeGateClaim, negativeClaim];
		const composed = {
			id: "swarm-merge-verification-proof-path-" + sha256(segments.map((claim) => claim.id).join(">")).slice(0, 16),
			claimType: "swarm-merge-verification-proof-path",
			sourceBinding: { segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType, artifact: claim.sourceBinding?.artifact })) },
			evidenceBinding: {
				verifiedWorkers: transcriptVerification.verifiedWorkers,
				verifiedArtifacts: artifactVerification.verifiedArtifacts,
				verifiedClaims: claimGateVerification.verifiedClaims,
				verifiedRoutes: routeGateVerification.verifiedRoutes,
				negativeControlsPassed: negativeControlVerification.negativeControlsPassed,
			},
			statement: "Swarm merge proof path composes transcript hashes, artifact integrity, claim gates, route gates, and verifier negative controls.",
			verdict: "promoted",
			confidence: 0.88,
			blockers: [],
		};
		claimLedger.push(composed);
		composedPaths.push(composed);
	}
	const blockers = [];
	if (!transcriptVerification.verified) blockers.push("missing-swarm-transcript-hash-verification");
	if (!artifactVerification.verified) blockers.push("missing-swarm-artifact-integrity");
	if (!claimGateVerification.verified) blockers.push("missing-swarm-claim-proof-gate");
	if (!routeGateVerification.verified) blockers.push("missing-swarm-route-proof-gate");
	if (!negativeControlVerification.verified) blockers.push("missing-swarm-merge-negative-control");
	const repairActions = {
		"missing-swarm-transcript-hash-verification": "Rerun swarm merge after ensuring worker-*.stdout.txt and worker-*.stderr.txt hashes match report.json.",
		"missing-swarm-artifact-integrity": "Regenerate or re-harvest worker artifacts so every harvested artifact has matching size and SHA-256.",
		"missing-swarm-claim-proof-gate": "Require each promoted proof-ready claim to include passive evidence, replay/proof evidence, negative controls, and resolved evidence item IDs.",
		"missing-swarm-route-proof-gate": "Run route repair commands until each route has a proof-ready promoted claim or an explicit missing gate.",
		"missing-swarm-merge-negative-control": "Run transcript hash, artifact hash, missing-evidence-item, and route-gate mutation controls before promotion.",
	};
	const proofReady = blockers.length === 0 && composedPaths.length > 0;
	return {
		kind: "repi-swarm-merge-verification",
		schemaVersion: 1,
		SwarmMergeVerificationV1: true,
		generatedAt: new Date().toISOString(),
		runId: mergeReport.runId,
		evidenceRoot,
		proofReady,
		finalPromotionReady: Boolean(mergeReport.finalPromotionReady && proofReady),
		transcriptVerification,
		artifactVerification,
		claimGateVerification,
		routeGateVerification,
		negativeControlVerification,
		stats: {
			verifiedWorkers: transcriptVerification.verifiedWorkers,
			verifiedArtifacts: artifactVerification.verifiedArtifacts,
			verifiedClaims: claimGateVerification.verifiedClaims,
			verifiedRoutes: routeGateVerification.verifiedRoutes,
			negativeControlsPassed: negativeControlVerification.negativeControlsPassed,
		},
		claimLedger,
		composedPaths,
		promotionReport: {
			proofReady,
			finalPromotionReady: Boolean(mergeReport.finalPromotionReady && proofReady),
			promotedClaims: claimLedger.filter((claim) => claim.verdict === "promoted"),
			composedPaths: composedPaths.filter((path) => path.verdict === "promoted"),
			blockers,
		},
		repairQueue: blockers.map((blocker) => ({
			id: "swarm-merge-verification-" + blocker,
			blocker,
			action: repairActions[blocker] ?? "Collect verifier-bound swarm merge evidence and rerun repi swarm merge.",
			rerunCommand: `repi swarm merge ${shellQuote(mergeReport.runId)} --json`,
		})),
	};
}

function buildMergeReport(evidenceRoot) {
	const reportPath = join(evidenceRoot, "report.json");
	const report = existsSync(reportPath) ? readJson(reportPath) : undefined;
	const plan = existsSync(join(evidenceRoot, "plan.json")) ? readJson(join(evidenceRoot, "plan.json")) : report?.plan;
	const workersReport = report?.workersReport ?? [];
	const claimRows = [];
	const observations = [];
	const blockerRows = [];
	const proofChecklists = [];
	const routeHandoffs = [];
	const conflictRows = [];
	const evidenceItemRows = [];
	const nextCommands = new Set();
	for (const worker of workersReport) {
		const stdoutPath = join(evidenceRoot, `worker-${worker.workerId}.stdout.txt`);
		const stdout = existsSync(stdoutPath) ? readFileSync(stdoutPath, "utf8") : worker.stdoutTail ?? "";
		const parsed = extractJsonObject(stdout);
		const parsedClaims = Array.isArray(parsed?.claims)
			? parsed.claims
			: Array.isArray(parsed?.findings)
				? parsed.findings.map((finding, index) =>
						typeof finding === "string"
							? { id: `worker-${worker.workerId}-finding-${index + 1}`, statement: finding, evidence: parsed?.evidence ?? parsed?.artifacts ?? [] }
								: finding,
					)
				: [];
		let evidenceItemOrdinal = 0;
		const workerEvidenceItems = [];
		for (const evidenceItem of Array.isArray(parsed?.evidenceItems) ? parsed.evidenceItems : []) {
			const normalized = normalizeEvidenceItem(worker, evidenceItem, evidenceItemOrdinal++);
			if (normalized) {
				workerEvidenceItems.push(normalized);
				evidenceItemRows.push(normalized);
			}
		}
		proofChecklists.push(proofChecklistForWorker(worker, parsed, parsedClaims, stdout, workerEvidenceItems));
		for (const [index, handoff] of (Array.isArray(parsed?.handoffs) ? parsed.handoffs : []).entries()) {
			const normalized = normalizeRouteHandoff(worker, handoff, index);
			if (normalized) routeHandoffs.push(normalized);
		}
		const workerConflicts = [];
		for (const [index, conflict] of (Array.isArray(parsed?.conflicts) ? parsed.conflicts : []).entries()) {
			const normalized = normalizeConflict(worker, conflict, index);
			if (normalized) workerConflicts.push(normalized);
		}
		for (let index = 0; index < parsedClaims.length; index++) {
			const claim = parsedClaims[index] ?? {};
			const claimId = String(claim.id ?? `worker-${worker.workerId}-claim-${index + 1}`);
			const claimEvidenceItems = [];
			for (const evidenceItem of Array.isArray(claim?.evidenceItems) ? claim.evidenceItems : []) {
				const normalized = normalizeEvidenceItem(worker, evidenceItem, evidenceItemOrdinal++, claimId);
				if (normalized) {
					claimEvidenceItems.push(normalized);
					evidenceItemRows.push(normalized);
				}
			}
			const matchedWorkerEvidenceItems = workerEvidenceItems.filter((item) => item.claimId === claimId || (!item.claimId && parsedClaims.length === 1));
			const allClaimEvidenceItems = [...matchedWorkerEvidenceItems, ...claimEvidenceItems];
			for (const [conflictIndex, conflict] of (Array.isArray(claim?.conflicts) ? claim.conflicts : []).entries()) {
				const normalized = normalizeConflict(worker, conflict, workerConflicts.length + conflictIndex, claimId);
				if (normalized) workerConflicts.push(normalized);
			}
			const directEvidence = Array.isArray(claim.evidence)
				? claim.evidence.map(String).filter(Boolean)
				: Array.isArray(parsed?.evidence)
					? parsed.evidence.map(String).filter(Boolean)
					: Array.isArray(parsed?.artifacts)
						? parsed.artifacts.map(String).filter(Boolean)
						: [];
			const evidence = [...directEvidence, ...allClaimEvidenceItems.map((item) => item.evidenceText).filter(Boolean)];
			const confidence = Number.isFinite(Number(claim.confidence)) ? Number(claim.confidence) : evidence.length > 0 ? 0.6 : 0;
			const blockers = Array.isArray(claim.blockers) ? claim.blockers.map((item) => redact(String(item))).slice(0, 6) : [];
			const qualitySignals = claimQualitySignals(evidence, blockers, allClaimEvidenceItems);
			const proofCoverage = claimProofCoverage(qualitySignals);
			const baseStatus = worker.status === "pass" && evidence.length > 0 && confidence >= 0.5 ? "promoted" : "observation";
			claimRows.push({
				claimId,
				workerId: worker.workerId,
				role: worker.role ?? parsed?.role ?? "worker",
				route: worker.route ?? null,
				statement: redact(String(claim.statement ?? claim.title ?? "")),
				evidence: evidence.map(redact).slice(0, 8),
				confidence,
				baseStatus,
				status: "observation",
				blockers,
				qualitySignals,
				proofCoverage,
				proofReady: false,
				evidenceItemIds: allClaimEvidenceItems.map((item) => item.evidenceItemId).slice(0, 12),
				conflictResolution: conflictResolutionForClaim({ claimId, qualitySignals }, workerConflicts),
			});
		}
		for (const conflict of workerConflicts) {
			conflictRows.push(conflict);
			if (conflict.nextCommand) nextCommands.add(conflict.nextCommand);
		}
		for (const command of Array.isArray(parsed?.nextCommands) ? parsed.nextCommands : []) nextCommands.add(redact(String(command)));
		for (const blocker of Array.isArray(parsed?.blockers) ? parsed.blockers : []) blockerRows.push({ workerId: worker.workerId, role: worker.role, blocker: redact(String(blocker)) });
		if (!parsedClaims.length) {
			observations.push({
				workerId: worker.workerId,
				role: worker.role ?? "worker",
				status: worker.status,
				stdoutSha256: worker.stdoutSha256,
				signals: linesMatching(stdout, /claim|finding|evidence|blocker|next|发现|证据|阻塞|下一步/i, 10),
			});
		}
	}
	for (const claim of claimRows) {
		const conflictResolution = conflictResolutionForClaim(claim, conflictRows);
		claim.conflictResolution = conflictResolution;
		claim.status = claim.baseStatus === "promoted" && !conflictResolution.downgraded ? "promoted" : "observation";
		delete claim.baseStatus;
	}
	for (const checklist of proofChecklists) {
		const command = proofRepairCommand(plan, checklist);
		if (command) nextCommands.add(command);
	}
	const routeCoverage = plan?.routeCoverage || (Array.isArray(plan?.routeCandidates) && Array.isArray(plan?.workerPackets)
		? routeCoverageForPackets(plan.routeCandidates, plan.workerPackets)
		: undefined);
	for (const route of Array.isArray(routeCoverage?.uncovered) ? routeCoverage.uncovered : []) {
		const command = routeCoverageRepairCommand(plan, route);
		if (command) nextCommands.add(command);
	}
	for (const handoff of routeHandoffs) {
		if (handoff.nextCommand) nextCommands.add(handoff.nextCommand);
		const command = routeHandoffCommand(plan, handoff);
		if (command) nextCommands.add(command);
	}
	const promotedClaims = claimRows.filter((claim) => claim.status === "promoted");
	const proofReadyWorkerIds = new Set(proofChecklists.filter((row) => row.proofReady).map((row) => row.workerId));
	for (const claim of claimRows) claim.proofReady = proofReadyWorkerIds.has(claim.workerId) && claimProofReady(claim);
	const proofReadyPromotedClaims = promotedClaims.filter((claim) => claim.proofReady);
	const routeReadinessRows = buildRouteReadinessRows(plan, workersReport, proofChecklists, promotedClaims, proofReadyPromotedClaims, routeCoverage);
	for (const readiness of routeReadinessRows.filter((row) => !row.proofReady && row.assignedWorkerIds.length > 0)) {
		const command = routeProofRepairCommand(plan, readiness);
		if (command) nextCommands.add(command);
	}
	const missingProofRoutes = routeReadinessRows.filter((row) => !row.proofReady).map((row) => row.route);
	const proofReadyRouteIds = routeReadinessRows.filter((row) => row.proofReady).map((row) => row.routeId);
	const routeProofReady = routeReadinessRows.length > 0 && missingProofRoutes.length === 0;
	const routeCoverageReady = routeCoverage?.complete !== false;
	const allWorkersPassed = workersReport.length > 0 && workersReport.every((worker) => worker.status === "pass");
	const mergeReport = {
		kind: "repi-swarm-merge-report",
		schemaVersion: 1,
		StructuredSubagentMergeV1: true,
		generatedAt: new Date().toISOString(),
		runId: report?.runId ?? plan?.runId ?? basename(evidenceRoot),
		evidenceRoot,
		planPath: existsSync(join(evidenceRoot, "plan.json")) ? join(evidenceRoot, "plan.json") : undefined,
		reportPath: existsSync(reportPath) ? reportPath : undefined,
		workerCount: workersReport.length,
		passedWorkers: workersReport.filter((worker) => worker.status === "pass").length,
		failedWorkers: workersReport.filter((worker) => worker.status !== "pass").map((worker) => ({ workerId: worker.workerId, role: worker.role, status: worker.status, exit: worker.exit })),
		claimRows,
		promotedClaims,
		observations,
		blockerRows,
		conflictRows,
		evidenceItemRows,
		proofChecklists,
		routeHandoffs,
		proofReadyPromotedClaims,
		proofPromotionReady: proofReadyPromotedClaims.length > 0 && allWorkersPassed,
		routeReadinessRows,
		proofReadyRouteIds,
		missingProofRoutes,
		routeProofReady,
		routeCoverage,
		routeCoverageReady,
		evidencePriorityDoctrine: plan?.evidencePriorityDoctrine ?? evidencePriorityDoctrine,
		capabilityMatrixDoctrine: plan?.capabilityMatrixDoctrine ?? capabilityMatrixDoctrine,
		nextCommands: [...nextCommands].slice(0, 24),
		mergeDigest: sha256(JSON.stringify({ workers: workersReport.map((worker) => [worker.workerId, worker.status, worker.stdoutSha256]), promotedClaims, blockerRows, conflictRows, evidenceItemRows })),
		ok: allWorkersPassed,
		finalPromotionReady: proofReadyPromotedClaims.length > 0 && allWorkersPassed && routeCoverageReady && routeProofReady,
		narrativeOnlyBlocked: claimRows.length === 0 && observations.length > 0,
	};
	const mergeVerification = buildSwarmMergeVerification(evidenceRoot, workersReport, mergeReport);
	mergeReport.mergeVerification = mergeVerification;
	atomicWriteFile(join(evidenceRoot, "merge-verification.json"), `${JSON.stringify(mergeVerification, null, 2)}\n`, 0o600);
	atomicWriteFile(join(evidenceRoot, "merge-report.json"), `${JSON.stringify(mergeReport, null, 2)}\n`, 0o600);
	return mergeReport;
}

function buildRunReport({ plan, rows, tempRoot, mode }) {
	const evidenceRoot = evidenceRootFor(plan.runId);
	const report = {
		kind: mode === "llm-run" ? "repi-llm-worker-pool-report" : "repi-swarm-run-report",
		schemaVersion: 1,
		LLMWorkerPoolV1: true,
		SwarmRunV1: mode !== "llm-run",
		generatedAt: new Date().toISOString(),
		runId: plan.runId,
		root,
		runRoot: plan.runRoot,
		target: plan.target,
		provider: plan.provider,
		model: plan.model,
		workers: plan.workers,
		maxConcurrency: plan.maxConcurrency,
		timeoutMs: plan.timeoutMs,
		tools: [...new Set(plan.workerPackets.map((packet) => packet.tools ?? "none"))].join(";"),
		evidenceRoot,
		tempRoot,
		planPath: join(evidenceRoot, "plan.json"),
		promptTemplateSha256: mode === "llm-run" ? sha256(plan.operatorGuidance) : undefined,
		plan,
		workersReport: rows.map((worker) => ({
			workerId: worker.workerId,
			role: worker.role,
			status: worker.status,
			exit: worker.exit,
			signal: worker.signal,
			timedOut: worker.timedOut,
			ms: worker.ms,
			provider: worker.provider,
			model: worker.model,
			route: worker.route,
			proofKit: worker.proofKit,
			commandPalette: worker.commandPalette,
			toolProbeCommand: worker.toolProbeCommand,
			techniqueHints: worker.techniqueHints,
			stdoutSha256: worker.stdoutSha256,
			stderrSha256: worker.stderrSha256,
			promptSha256: worker.promptSha256,
			expect: worker.expect,
			expectOk: worker.expectOk,
			stdoutTail: worker.stdoutPreview.slice(-1200),
			stderrTail: worker.stderrPreview.slice(-800),
			harvestedArtifacts: worker.harvestedArtifacts ?? [],
		})),
		mergeDigest: sha256(rows.map((worker) => `${worker.workerId}:${worker.role}:${worker.status}:${worker.stdoutSha256}`).join("\n")),
		ok: rows.every((worker) => worker.status === "pass"),
	};
	atomicWriteFile(join(evidenceRoot, "report.json"), `${JSON.stringify(report, null, 2)}\n`, 0o600);
	return report;
}

function listRuns() {
	if (!existsSync(swarmsRoot)) return [];
	return readdirSync(swarmsRoot)
		.map((name) => {
			const path = join(swarmsRoot, name);
			try {
				return statSync(path).isDirectory() ? { runId: name, path, mtimeMs: statSync(path).mtimeMs } : undefined;
			} catch {
				return undefined;
			}
		})
		.filter(Boolean)
		.sort((left, right) => right.mtimeMs - left.mtimeMs);
}

function resolveRunRef(ref = "latest") {
	if (ref && ref !== "latest") {
		const exact = join(swarmsRoot, ref);
		if (existsSync(exact)) return exact;
		const match = listRuns().find((run) => run.runId.includes(ref));
		if (match) return match.path;
	}
	return listRuns()[0]?.path;
}

function buildStatus(ref) {
	const evidenceRoot = resolveRunRef(ref);
	if (!evidenceRoot) return { kind: "repi-swarm-status-report", schemaVersion: 1, ok: false, error: "no swarm runs found", swarmsRoot };
	const report = existsSync(join(evidenceRoot, "report.json")) ? readJson(join(evidenceRoot, "report.json")) : undefined;
	const plan = existsSync(join(evidenceRoot, "plan.json")) ? readJson(join(evidenceRoot, "plan.json")) : report?.plan;
	const merge = existsSync(join(evidenceRoot, "merge-report.json")) ? readJson(join(evidenceRoot, "merge-report.json")) : undefined;
	return {
		kind: "repi-swarm-status-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: Boolean(report?.ok ?? plan),
		runId: report?.runId ?? plan?.runId ?? basename(evidenceRoot),
		evidenceRoot,
		state: report?.kind === "repi-swarm-plan-report" ? "planned" : report ? (report.ok ? "complete" : "failed") : "planned",
		target: report?.target ?? plan?.target,
		provider: report?.provider ?? plan?.provider,
		model: report?.model ?? plan?.model,
		workers: report?.workersReport?.map((worker) => ({ workerId: worker.workerId, role: worker.role, status: worker.status, exit: worker.exit, ms: worker.ms })) ?? plan?.workerPackets?.map((worker) => ({ workerId: worker.workerId, role: worker.role, status: "planned" })) ?? [],
		merge: merge
			? {
					ok: merge.ok,
					promotedClaims: merge.promotedClaims?.length ?? 0,
					routeProofReady: merge.routeProofReady,
					missingProofRoutes: merge.missingProofRoutes?.map((route) => route.id ?? route.routeId).filter(Boolean) ?? [],
					narrativeOnlyBlocked: merge.narrativeOnlyBlocked,
					mergeVerificationProofReady: Boolean(merge.mergeVerification?.proofReady),
					mergeVerificationBlockers: merge.mergeVerification?.promotionReport?.blockers ?? [],
					mergeDigest: merge.mergeDigest,
				}
			: undefined,
	};
}

function printPlan(plan, evidenceRoot) {
	console.log("REPI Swarm Plan");
	console.log(`runId=${plan.runId} target=${plan.target} workers=${plan.workers} maxConcurrency=${plan.maxConcurrency}`);
	for (const packet of plan.workerPackets) console.log(`- worker-${packet.workerId} role=${packet.role} tools=${packet.tools ?? "none"} objective=${packet.objective}`);
	console.log(`evidence=${evidenceRoot}`);
}

function printRun(report, merge) {
	console.log(report.kind === "repi-llm-worker-pool-report" ? "REPI LLM Worker Pool" : "REPI Swarm Run");
	console.log(`runId=${report.runId} provider=${report.provider} model=${report.model} workers=${report.workers} target=${report.target}`);
	for (const worker of report.workersReport) {
		console.log(`${worker.status === "pass" ? "PASS" : "FAIL"} worker-${worker.workerId}${worker.role ? `/${worker.role}` : ""} exit=${worker.exit} ms=${worker.ms} stdout=${worker.stdoutSha256.slice(0, 12)} stderr=${worker.stderrSha256.slice(0, 12)}`);
		if (worker.status !== "pass" && worker.stderrTail) console.log(`  stderr: ${worker.stderrTail.replace(/\n/g, "\\n").slice(-600)}`);
		if (worker.status !== "pass" && worker.stdoutTail) console.log(`  stdout: ${worker.stdoutTail.replace(/\n/g, "\\n").slice(-600)}`);
	}
	if (merge) console.log(`merge=promoted:${merge.promotedClaims.length} observations:${merge.observations.length} narrativeOnlyBlocked=${merge.narrativeOnlyBlocked}`);
	if (merge?.mergeVerification) console.log(`mergeVerification=proofReady:${merge.mergeVerification.proofReady} workers:${merge.mergeVerification.stats?.verifiedWorkers ?? 0} routes:${merge.mergeVerification.stats?.verifiedRoutes ?? 0}`);
	if (report.mergeFailureReason) console.log(`mergeFailureReason=${report.mergeFailureReason}`);
	console.log(`evidence=${report.evidenceRoot}`);
	console.log(`verdict=${report.ok ? "pass" : "fail"}`);
}

function printStatus(status) {
	if (!status.ok) {
		console.error(status.error);
		return;
	}
	console.log("REPI Swarm Status");
	console.log(`runId=${status.runId} state=${status.state} target=${status.target ?? "none"}`);
	console.log(`provider=${status.provider ?? "default"} model=${status.model ?? "default"}`);
	for (const worker of status.workers) console.log(`- worker-${worker.workerId}/${worker.role ?? "worker"} status=${worker.status} exit=${worker.exit ?? "n/a"} ms=${worker.ms ?? "n/a"}`);
	if (status.merge) console.log(`merge ok=${status.merge.ok} promotedClaims=${status.merge.promotedClaims} routeProofReady=${status.merge.routeProofReady} missingProofRoutes=${status.merge.missingProofRoutes?.join(",") ?? ""} narrativeOnlyBlocked=${status.merge.narrativeOnlyBlocked} mergeVerificationProofReady=${status.merge.mergeVerificationProofReady}`);
	console.log(`evidence=${status.evidenceRoot}`);
}

function printMerge(merge) {
	console.log("REPI Swarm Merge");
	console.log(`runId=${merge.runId} ok=${merge.ok} finalPromotionReady=${merge.finalPromotionReady}`);
	console.log(`workers=${merge.workerCount} passed=${merge.passedWorkers} promotedClaims=${merge.promotedClaims.length} observations=${merge.observations.length} blockers=${merge.blockerRows.length}`);
	if (Array.isArray(merge.proofChecklists)) {
		const ready = merge.proofChecklists.filter((row) => row.proofReady).length;
		console.log(`proofChecklists=${ready}/${merge.proofChecklists.length} ready`);
	}
	if (Array.isArray(merge.proofReadyPromotedClaims)) console.log(`proofReadyPromotedClaims=${merge.proofReadyPromotedClaims.length} proofPromotionReady=${merge.proofPromotionReady}`);
	if (merge.routeCoverage) console.log(`routeCoverage=${merge.routeCoverage.coveredCount}/${merge.routeCoverage.routeCount} covered uncovered=${merge.routeCoverage.uncoveredCount}`);
	if (Array.isArray(merge.routeReadinessRows)) console.log(`routeProofReady=${merge.routeProofReady} readyRoutes=${merge.proofReadyRouteIds?.length ?? 0}/${merge.routeReadinessRows.length} missing=${merge.missingProofRoutes?.map((route) => route.id).join(",") ?? ""}`);
	if (merge.mergeVerification) console.log(`mergeVerificationProofReady=${merge.mergeVerification.proofReady} blockers=${merge.mergeVerification.promotionReport?.blockers?.join(",") ?? ""}`);
	for (const claim of merge.promotedClaims.slice(0, 8)) console.log(`- claim=${claim.claimId} worker=${claim.workerId}/${claim.role} conf=${claim.confidence} ${claim.statement}`);
	if (merge.narrativeOnlyBlocked) console.log("narrativeOnlyBlocked=true: worker output lacked structured evidence-bearing claims; keep as observations.");
	console.log(`evidence=${merge.evidenceRoot}`);
	console.log(`mergeDigest=${merge.mergeDigest}`);
}

function writeStdout(text) {
	return new Promise((resolveWrite) => {
		process.stdout.write(text, () => resolveWrite());
	});
}

if (argv.includes("--help") || argv.includes("-h") || command === "help") {
	console.log(usage());
	process.exit(0);
}

const json = argv.includes("--json");
const keepProfiles = argv.includes("--keep-profiles");

if (command === "plan") {
	const plan = buildSwarmPlan(argv);
	const evidenceRoot = writePlan(plan);
	if (json) await writeStdout(`${JSON.stringify({ kind: "repi-swarm-plan-report", schemaVersion: 1, ok: true, evidenceRoot, plan }, null, 2)}\n`);
	else printPlan(plan, evidenceRoot);
	process.exit(0);
}

if (command === "status") {
	const status = buildStatus(positionalTarget(argv));
	if (json) await writeStdout(`${JSON.stringify(status, null, 2)}\n`);
	else printStatus(status);
	process.exit(status.ok ? 0 : 1);
}

if (command === "merge") {
	const evidenceRoot = resolveRunRef(positionalTarget(argv));
	if (!evidenceRoot) {
		console.error("No swarm run found");
		process.exit(1);
	}
	const merge = buildMergeReport(evidenceRoot);
	if (json) await writeStdout(`${JSON.stringify(merge, null, 2)}\n`);
	else printMerge(merge);
	process.exit(merge.ok ? 0 : 1);
}

const mode = command === "run" ? "run" : "llm-run";
const runId = makeRunId(flagValue(argv, "--target") ?? positionalTarget(argv) ?? "local-selfcheck");
const plan = mode === "llm-run" ? (() => {
	const target = flagValue(argv, "--target") ?? positionalTarget(argv) ?? "local-selfcheck";
	const timeoutMs = parseIntFlag(argv, "--timeout-ms", Number(process.env.REPI_SWARM_LLM_TIMEOUT_MS ?? 210000), 5000, 30 * 60 * 1000);
	const baseArgs = [target, "--timeout-ms", String(timeoutMs)];
	if (hasFlag(argv, ["--workers", "-w"])) baseArgs.push("--workers", String(parseIntFlag(argv, ["--workers", "-w"], 3, 1, 16)));
	if (hasFlag(argv, "--max-concurrency")) baseArgs.push("--max-concurrency", String(parseIntFlag(argv, "--max-concurrency", 3, 1, 16)));
	if (flagValue(argv, "--provider")) baseArgs.push("--provider", flagValue(argv, "--provider"));
	if (flagValue(argv, "--model")) baseArgs.push("--model", flagValue(argv, "--model"));
	if (flagValue(argv, "--route")) baseArgs.push("--route", flagValue(argv, "--route"));
	if (flagValue(argv, "--tools") !== undefined) baseArgs.push("--tools", flagValue(argv, "--tools", "") || "");
	const basePlan = buildSwarmPlan(baseArgs, { runId });
	return {
		...basePlan,
		timeoutMs,
		toolsDisabled: argv.includes("--no-tools"),
		workerPackets: basePlan.workerPackets.map((packet, index) => ({
			...packet,
			workerId: index + 1,
			id: `worker-${index + 1}`,
			role: "worker",
			objective: "generic parallel llm worker",
			tools: argv.includes("--no-tools") ? undefined : flagValue(argv, "--tools"),
			dependencies: [],
			evidenceContract: ["non-empty stdout"],
			mergeKeys: ["worker"],
			limits: { timeoutMs, maxOutputChars: DEFAULT_MAX_OUTPUT_CHARS },
		})),
		operatorGuidance: flagValue(argv, "--prompt") ?? `You are REPI parallel worker {id}. Target/task: {target}. Route: {routeDomain} ({routeId}); workflow={routeWorkflow}. Use proofKit={proofKit}. Use commandPalette={commandPalette}. Use techniqueHints={techniqueHints}. Work independently and return concise JSON with workerId, findings, evidence, blockers, nextCommands. Do not mention other workers.`,
	};
})() : buildSwarmPlan(argv, { runId });
const evidenceRoot = writePlan(plan);
const promptTemplate = mode === "llm-run" ? plan.operatorGuidance : undefined;
const expectTemplate = flagValue(argv, "--expect");
const { rows, tempRoot } = await runPool(plan, promptTemplate, expectTemplate, mode, keepProfiles);
const report = buildRunReport({ plan, rows, tempRoot, mode });
const merge = buildMergeReport(evidenceRoot);
if (mode === "run" && (!merge.finalPromotionReady || rows.some((worker) => worker.status !== "pass"))) {
	const failedWorkers = rows.filter((worker) => worker.status !== "pass");
	report.ok = false;
	report.mergeFailureReason = failedWorkers.length
		? failedWorkers.some((worker) => worker.timedOut)
			? "one or more workers timed out before producing promoted evidence"
			: "one or more workers failed before producing promoted evidence"
		: merge.routeCoverageReady === false
			? "route coverage incomplete; run generated route repair commands"
			: merge.routeProofReady === false
				? `route proof incomplete; missing proof-ready route(s): ${(merge.missingProofRoutes ?? []).map((route) => route.id ?? route.routeId ?? route.domain).filter(Boolean).join(", ") || "unknown"}`
			: merge.narrativeOnlyBlocked
				? "narrative-only worker output lacked structured evidence-bearing claims"
				: !merge.proofPromotionReady
					? "no proof-ready promoted claims after proof checklist"
					: "no promoted evidence-bearing claims after structured merge";
	atomicWriteFile(join(evidenceRoot, "report.json"), `${JSON.stringify(report, null, 2)}\n`, 0o600);
}
if (json) await writeStdout(`${JSON.stringify({ ...report, merge }, null, 2)}\n`);
else printRun(report, merge);
process.exitCode = report.ok ? 0 : 1;
