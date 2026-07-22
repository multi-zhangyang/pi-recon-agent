export const routeAgentToolchains = {
	"native-pwn": ["re_kernel", "re_native_runtime", "re_exploit_chain", "re_exploit_lab", "re_toolchain_domain"],
	"web-api": ["re_web_authz_state", "re_live_browser", "re_runtime_adapter", "re_runtime_bridge", "re_operation"],
	"js-reverse": ["re_live_browser", "re_runtime_adapter", "re_runtime_bridge", "re_exploit_lab"],
	mobile: ["re_mobile_runtime", "re_runtime_adapter", "re_runtime_bridge", "re_toolchain_domain"],
	"pcap-dfir": ["re_evidence", "re_proof_loop", "re_toolchain_domain", "re_runtime_bridge"],
	"memory-forensics": ["re_evidence", "re_proof_loop", "re_toolchain_domain"],
	"firmware-iot": ["re_toolchain_domain", "re_native_runtime", "re_web_authz_state", "re_runtime_bridge"],
	"cloud-identity": ["re_graph", "re_evidence", "re_operation", "re_runtime_bridge"],
	"windows-ad": ["re_graph", "re_evidence", "re_operation", "re_runtime_bridge"],
	malware: ["re_toolchain_domain", "re_native_runtime", "re_evidence", "re_runtime_bridge"],
	"crypto-stego": ["re_proof_loop", "re_exploit_lab", "re_evidence"],
	"agent-boundary": ["re_runtime_adapter", "re_runtime_bridge", "re_proof_loop", "re_evidence", "re_graph"],
	"reverse-pentest-general": ["re_campaign", "re_swarm", "re_supervisor", "re_operation", "re_autopilot"],
};
export const roleLibrary = [
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

export const universalProofDoctrine = {
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

export const evidencePriorityDoctrine = {
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

export const capabilityMatrixDoctrine = {
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

export const routeProfiles = [
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
		workflow: ["prompt/tool surface", "session/context/RAG boundary", "injection replay", "delegation drift proof"],
		roles: {
			mapper: {
				objective: "映射 system/developer/user/tool/session-context/RAG/MCP 输入边界和不可信内容入口。",
				evidenceContract: ["prompt/resource inventory", "tool schema map", "session/context/RAG path", "untrusted content flow"],
				mergeKeys: ["prompt", "tool", "context", "resource"],
			},
			exploiter: {
				objective: "构造最小间接 prompt/tool injection replay，证明或反证边界绕过。",
				evidenceContract: ["payload", "replay transcript", "tool-call trace", "boundary decision"],
				mergeKeys: ["payload", "trace", "decision", "toolcall"],
			},
			verifier: {
				objective: "审查 tool output 信任、session/context 污染、capability drift 和未验证代理叙述。",
				evidenceContract: ["counter-prompt", "sanitization check", "capability drift edge", "downgrade advice"],
				mergeKeys: ["counter", "sanitize", "drift", "verifier"],
			},
		},
	},
];


export const routeProofKits = {
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
		passive: ["prompt/tool/session-context/RAG boundary map", "untrusted content flow", "tool schema and side-effect inventory"],
		proofExit: ["minimal injection replay transcript", "tool-call trace or refusal/allow decision", "session-context/RAG contamination proof"],
		negativeControls: ["benign prompt comparison", "sanitized content path", "tool disabled or least-privilege counterexample"],
	},
	"reverse-pentest-general": {
		passive: ["entrypoint/surface/artifact inventory", "live execution path hypothesis", "tool availability and evidence gaps"],
		proofExit: ["one replayable command or artifact hash", "claim-specific transcript/diff", "next command for missing proof"],
		negativeControls: ["benign input or wrong credential/control", "failed hypothesis recorded", "scope/source mismatch downgraded"],
	},
};


export const routeCommandPalettes = {
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
		passive: ["grep -RInE 'system|developer|tool|session|transcript|context|mcp|retrieval|prompt' . | head -200", "find . -maxdepth 4 -iname '*prompt*' -o -iname '*tool*' | head -200"],
		proof: ["node injection-replay.mjs | tee injection-proof.json"],
		negative: ["node injection-replay.mjs --benign | tee benign-control.json", "node injection-replay.mjs --sanitized | tee sanitized-control.json"],
	},
	"reverse-pentest-general": {
		passive: ["pwd && find . -maxdepth 3 -type f | head -200", "file $TARGET 2>/dev/null || true", "grep -RInE 'TODO|secret|token|password|route|api|main' . | head -200"],
		proof: ["repi engage $TARGET --json | tee engagement.json", "python3 proof.py 2>&1 | tee proof.log"],
		negative: ["python3 proof.py --negative 2>&1 | tee negative.log", "diff -u proof.log negative.log || true"],
	},
};

export const routeTechniqueHints = {
	"native-pwn": {
		domains: ["pwn", "native-reverse", "exploit-reliability"],
		techniqueIds: [
			"pwn-ret2libc",
			"pwn-format-string",
			"pwn-tcache-poisoning",
			"pwn-house-of-botcake",
			"pwn-srop",
			"pwn-ret2dlresolve",
			"rev-anti-debug-bypass",
			"rev-deobfuscate-ollvm",
			"reliability-replay-matrix",
		],
	},
	"web-api": {
		domains: ["web-api", "web-scan"],
		techniqueIds: [
			"web-idor-bola",
			"web-ssrf-metadata",
			"web-jwt-confusion",
			"web-ssti",
			"web-request-smuggling",
			"web-prototype-pollution",
			"web-deserialization-gadget",
			"webscan-content-discovery",
			"webscan-vhost-stack",
		],
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
		techniqueIds: ["dfir-ntlm-kerberos-extract", "dfir-credential-pcap", "dfir-exfil-detect", "crypto-hash-length-extension"],
	},
	"memory-forensics": {
		domains: ["memory-forensics", "malware", "identity-ad"],
		techniqueIds: ["mem-volatility-creds", "mem-process-hunt", "malware-persistence-mech"],
	},
	"firmware-iot": {
		domains: ["firmware-iot", "web-api", "native-reverse"],
		techniqueIds: ["fw-rootfs-extract", "fw-emulation-qemu", "fw-uart-uboot", "fw-secure-boot-bypass", "web-ssrf-metadata"],
	},
	"cloud-identity": {
		domains: ["cloud-container", "web-api", "agent-llm"],
		techniqueIds: ["cloud-imds-to-role", "cloud-k8s-rbac", "cloud-container-escape", "web-ssrf-metadata"],
	},
	"windows-ad": {
		domains: ["identity-ad", "dfir-pcap", "memory-forensics"],
		techniqueIds: ["ad-kerberoasting", "ad-asrep-roasting", "ad-cs-esc", "ad-dcsync", "dfir-ntlm-kerberos-extract"],
	},
	malware: {
		domains: ["malware", "native-reverse", "memory-forensics"],
		techniqueIds: ["malware-config-decode", "malware-unpack-sandbox", "malware-persistence-mech", "malware-shellcode-emulate", "rev-vm-unpack"],
	},
	"crypto-stego": {
		domains: ["crypto-stego", "dfir-pcap"],
		techniqueIds: ["crypto-padding-oracle", "crypto-cbc-bitflip", "crypto-rsa-attacks", "crypto-ecdsa-nonce-reuse", "dfir-exfil-detect"],
	},
	"agent-boundary": {
		domains: ["agent-llm", "cloud-container", "web-api"],
		techniqueIds: ["agent-rag-poisoning", "agent-context-exfil", "agent-indirect-injection", "agent-tool-misuse", "web-idor-bola"],
	},
	"reverse-pentest-general": {
		domains: ["pwn", "web-api", "js-reverse", "mobile", "dfir-pcap", "cloud-container", "agent-llm", "exploit-reliability"],
		techniqueIds: ["reliability-replay-matrix", "web-idor-bola", "js-signature-rebuild", "pwn-ret2libc", "agent-rag-poisoning"],
	},
};

export const techniqueProofContracts = {
	"pwn-ret2libc": {
		proofExit:
			"leak a libc symbol, compute the matching libc base, call system('/bin/sh') or an equivalent shell/flag path, and show a wrong-libc/wrong-offset/alignment control.",
		requiredSignals: [
			{ gate: "libc-leak", any: ["leak", "leaked", "puts@got", "got leak", "libc symbol", "泄漏"] },
			{ gate: "libc-base", any: ["libc base", "base =", "computed base", "matching libc", "libc-database"] },
			{ gate: "code-exec", any: ["system", "/bin/sh", "shell", "cat flag", "id output", "interactive"] },
		],
		negativeControls: [
			{ gate: "ret2libc-control", any: ["wrong libc", "wrong offset", "alignment", "movaps", "negative control", "负控制", "反证"] },
		],
	},
	"pwn-format-string": {
		proofExit: "prove printf-family format-string control, compute the stack offset, land an arbitrary %n/%hn write, and show a wrong-offset/control-flow negative.",
		requiredSignals: [
			{ gate: "format-control", any: ["%p", "%n", "printf", "format string", "格式化字符串"] },
			{ gate: "offset", any: ["offset", "stack offset", "argument offset", "偏移"] },
			{ gate: "write", any: ["arbitrary write", "target changed", "%hn", "%hhn", "got overwrite"] },
		],
		negativeControls: [{ gate: "fmt-control", any: ["wrong offset", "negative control", "no overwrite", "负控制"] }],
	},
	"pwn-tcache-poisoning": {
		proofExit: "prove UAF/double-free into tcache, recover safe-linking state when needed, return an allocation at the forged target, and verify a wrong fd/heap-base control fails.",
		requiredSignals: [
			{ gate: "heap-primitive", any: ["uaf", "double-free", "tcache", "heap"] },
			{ gate: "target-allocation", any: ["forged fd", "allocation returns", "safe-linking", "heap base", "arbitrary write"] },
		],
		negativeControls: [{ gate: "heap-control", any: ["wrong fd", "wrong heap", "wrong key", "negative control", "负控制"] }],
	},
	"pwn-house-of-botcake": {
		proofExit: "prove the unsorted/tcache overlap, poison the overlapped tcache entry into a forged target allocation, and show wrong free-order or safe-linking controls fail.",
		requiredSignals: [
			{ gate: "heap-version", any: ["glibc", "tcache", "unsorted", "heap"] },
			{ gate: "overlap-proof", any: ["overlap", "house of botcake", "double-free", "vis_heap_chunks"] },
			{ gate: "target-allocation", any: ["forged fd", "allocation returns", "arbitrary write", "safe-linking"] },
		],
		negativeControls: [{ gate: "botcake-control", any: ["wrong free order", "wrong count", "wrong heap", "negative control"] }],
	},
	"pwn-srop": {
		proofExit: "prove control reaches a sigreturn frame, verify the syscall/register frame state, execute the intended syscall path, and show wrong-frame/selector controls fail.",
		requiredSignals: [
			{ gate: "syscall-gadget", any: ["syscall", "sigreturn", "srop", "rax=15"] },
			{ gate: "frame-state", any: ["sigreturnframe", "register", "rip", "rdi", "frame"] },
			{ gate: "syscall-effect", any: ["execve", "/bin/sh", "shell", "id output", "cat flag"] },
		],
		negativeControls: [{ gate: "srop-control", any: ["wrong frame", "wrong selector", "wrong rax", "negative control"] }],
	},
	"pwn-ret2dlresolve": {
		proofExit: "prove a fake relocation/symbol/string table is resolved by the dynamic linker, execute the resolved call, and show wrong-symbol/reloc controls fail.",
		requiredSignals: [
			{ gate: "dynamic-linker", any: ["ret2dlresolve", "plt0", "dynamic linker", "reloc", "symtab"] },
			{ gate: "fake-structures", any: ["fake reloc", "fake symbol", "strtab", "rel.plt", "resolver"] },
			{ gate: "resolved-call", any: ["system", "/bin/sh", "shell", "resolved", "id output"] },
		],
		negativeControls: [{ gate: "dlresolve-control", any: ["wrong symbol", "wrong reloc", "alignment", "negative control"] }],
	},
	"web-idor-bola": {
		proofExit: "prove account/principal A can access account/principal B's object with status/body/state diff, and show anonymous/wrong-principal controls fail.",
		requiredSignals: [
			{ gate: "two-principal", any: ["account a", "principal a", "user a", "token a", "用户a"] },
			{ gate: "victim-object", any: ["account b", "principal b", "user b", "victim", "owner", "object ownership", "用户b"] },
			{ gate: "response-diff", any: ["http 200", "body hash", "status", "before/after", "state diff"] },
		],
		negativeControls: [{ gate: "authz-control", any: ["wrong principal", "anonymous", "invalid token", "http 403", "401", "负控制"] }],
	},
	"web-jwt-confusion": {
		proofExit: "forge an accepted JWT using the confusion path, replay a protected endpoint, and show tampered/wrong-key/original-baseline controls.",
		requiredSignals: [
			{ gate: "jwks-or-key", any: ["jwks", "public key", "pem", "rs256", "hs256"] },
			{ gate: "forged-token", any: ["forged token", "alg", "jwt accepted", "bearer"] },
			{ gate: "protected-replay", any: ["protected endpoint", "http 200", "privileged", "admin"] },
		],
		negativeControls: [{ gate: "jwt-control", any: ["tampered token", "wrong key", "invalid token", "http 403", "negative control"] }],
	},
	"web-ssrf-metadata": {
		proofExit: "prove the server fetches cloud metadata via the SSRF sink and verify returned credentials/identity with a denied or wrong-target control.",
		requiredSignals: [
			{ gate: "metadata-fetch", any: ["169.254.169.254", "metadata", "imds", "metadata-flavor", "x-aws-ec2"] },
			{ gate: "credential-or-identity", any: ["sts get-caller-identity", "accesskeyid", "token", "service account", "identity"] },
		],
		negativeControls: [{ gate: "ssrf-control", any: ["blocked", "wrong host", "denied", "negative control", "负控制"] }],
	},
	"web-prototype-pollution": {
		proofExit: "prove attacker-controlled keys pollute a prototype, trigger a reachable application gadget, and show clean-object/frozen/tampered controls fail.",
		requiredSignals: [
			{ gate: "pollution-sink", any: ["prototype pollution", "__proto__", "constructor.prototype", "merge", "lodash"] },
			{ gate: "polluted-property", any: ["polluted", "property", "prototype", "object"] },
			{ gate: "gadget-effect", any: ["gadget", "rce", "xss", "auth bypass", "state diff", "http 200"] },
		],
		negativeControls: [{ gate: "prototype-control", any: ["clean object", "frozen", "sanitized", "tampered", "negative control"] }],
	},
	"web-deserialization-gadget": {
		proofExit: "prove an untrusted deserialization sink reaches a gadget chain with runtime effect, and show benign/signed/wrong-class controls fail.",
		requiredSignals: [
			{ gate: "deserialize-sink", any: ["deserialize", "unserialize", "pickle", "ysoserial", "objectinputstream"] },
			{ gate: "gadget-chain", any: ["gadget", "chain", "payload", "class", "method"] },
			{ gate: "runtime-effect", any: ["rce", "id output", "file written", "http 200", "callback"] },
		],
		negativeControls: [{ gate: "deser-control", any: ["benign object", "wrong class", "invalid signature", "negative control"] }],
	},
	"js-signature-rebuild": {
		proofExit: "capture runtime signer inputs/outputs, rebuild the field byte-for-byte for a frozen sample, replay successfully, and show missing/tampered/stale controls fail.",
		requiredSignals: [
			{ gate: "runtime-capture", any: ["hook", "crypto", "signer", "captured", "initiator"] },
			{ gate: "byte-match", any: ["byte-for-byte", "field diff", "generated field", "matches captured"] },
			{ gate: "signed-replay", any: ["signed replay", "server acceptance", "http 200", "accepted"] },
		],
		negativeControls: [{ gate: "sign-control", any: ["missing signature", "tampered signature", "stale timestamp", "wrong key", "负控制"] }],
	},
	"mobile-ssl-pinning-bypass": {
		proofExit: "show pinned traffic is decrypted through MITM with the hook enabled and fails or remains opaque with the hook disabled/wrong cert.",
		requiredSignals: [
			{ gate: "hook", any: ["frida", "certificatepinner", "trustmanager", "ssl_verify", "hook"] },
			{ gate: "traffic", any: ["mitm", "burp", "mitmproxy", "request", "response"] },
		],
		negativeControls: [{ gate: "pin-control", any: ["hook disabled", "wrong cert", "pin", "negative control"] }],
	},
	"crypto-padding-oracle": {
		proofExit: "demonstrate distinguishable padding oracle behavior, decrypt/forge with assertions, and show wrong padding/mode controls fail.",
		requiredSignals: [
			{ gate: "oracle", any: ["padding oracle", "padding accepted", "padding rejected", "pkcs"] },
			{ gate: "decrypt-or-forge", any: ["recovered plaintext", "forged ciphertext", "decrypt", "assert"] },
		],
		negativeControls: [{ gate: "oracle-control", any: ["wrong padding", "wrong mode", "tampered", "negative control"] }],
	},
	"agent-indirect-injection": {
		proofExit: "produce a minimal injection replay transcript with tool-call/session-context/RAG boundary evidence and benign/sanitized controls.",
		requiredSignals: [
			{ gate: "payload", any: ["injection", "payload", "prompt", "untrusted"] },
			{ gate: "boundary-trace", any: ["tool-call", "session", "transcript", "context", "rag", "trace", "decision"] },
		],
		negativeControls: [{ gate: "agent-control", any: ["benign", "sanitized", "tool disabled", "negative control"] }],
	},
	"rev-anti-debug-bypass": {
		proofExit: "locate the anti-debug check, bypass it with a patch or hook, prove the target runs under instrumentation, and show unpatched/hook-disabled controls still fail.",
		requiredSignals: [
			{ gate: "anti-debug-anchor", any: ["anti-debug", "ptrace", "isdebuggerpresent", "sysctl", "frida-detect", "debugger check"] },
			{ gate: "bypass-effect", any: ["bypass", "patched", "hooked", "debugger attached", "continues", "no exit"] },
			{ gate: "runtime-proof", any: ["gdb", "lldb", "frida", "runtime", "transcript", "exited 0"] },
		],
		negativeControls: [{ gate: "anti-debug-control", any: ["hook disabled", "unpatched", "wrong patch", "still exits", "negative control"] }],
	},
	"rev-deobfuscate-ollvm": {
		proofExit: "identify OLLVM-style flattening/opaque predicates, recover a simpler control flow or patch, prove semantic equivalence on samples, and show wrong-patch controls diverge.",
		requiredSignals: [
			{ gate: "ollvm-pattern", any: ["ollvm", "control-flow flattening", "opaque predicate", "dispatcher", "flattened"] },
			{ gate: "deobfuscation", any: ["deobfuscate", "unflatten", "patch", "cfg", "basic block"] },
			{ gate: "semantic-check", any: ["same output", "sample", "trace", "equivalent", "assert"] },
		],
		negativeControls: [{ gate: "ollvm-control", any: ["wrong patch", "wrong input", "diverge", "negative control"] }],
	},
	"web-ssti": {
		proofExit: "prove a live template injection sink with rendered expression or command output, then show escaped/literal/wrong-template controls fail.",
		requiredSignals: [
			{ gate: "template-sink", any: ["ssti", "{{", "${", "<%", "template"] },
			{ gate: "rendered-execution", any: ["7*7", "49", "id output", "rce", "rendered"] },
			{ gate: "http-replay", any: ["curl", "http 200", "status", "response", "body hash"] },
		],
		negativeControls: [{ gate: "ssti-control", any: ["escaped", "blocked", "literal", "wrong payload", "negative control"] }],
	},
	"web-request-smuggling": {
		proofExit: "prove CL.TE/TE.CL parser desync with paired requests, differential front/back-end behavior, and a normalized or wrong-length control.",
		requiredSignals: [
			{ gate: "desync-craft", any: ["cl.te", "te.cl", "content-length", "transfer-encoding", "smuggling"] },
			{ gate: "parser-differential", any: ["front-end", "back-end", "queue", "desync", "timeout", "poisoned"] },
			{ gate: "paired-replay", any: ["two requests", "paired replay", "http 200", "status diff", "body hash"] },
		],
		negativeControls: [{ gate: "smuggle-control", any: ["normalized", "single parser", "wrong length", "negative control"] }],
	},
	"webscan-content-discovery": {
		proofExit: "prove a discovered path is live with status/body/hash evidence and compare it to a random-path or 404 baseline control.",
		requiredSignals: [
			{ gate: "discovery-run", any: ["ffuf", "feroxbuster", "dirsearch", "gobuster", "content discovery", "wordlist"] },
			{ gate: "live-path", any: ["http 200", "status", "body hash", "content-length", "found path"] },
		],
		negativeControls: [{ gate: "discovery-control", any: ["404", "random path", "baseline", "negative control"] }],
	},
	"webscan-vhost-stack": {
		proofExit: "prove a virtual-host or stack-specific surface via Host/SNI differential responses, and show random-host/default-vhost controls collapse.",
		requiredSignals: [
			{ gate: "vhost-scan", any: ["vhost", "virtual host", "host header", "sni", "ffuf"] },
			{ gate: "differential-response", any: ["status", "body hash", "content-length", "title", "http 200"] },
			{ gate: "stack-fingerprint", any: ["server", "tech stack", "framework", "header", "asset"] },
		],
		negativeControls: [{ gate: "vhost-control", any: ["random host", "default vhost", "baseline", "negative control"] }],
	},
	"js-wasm-reverse": {
		proofExit: "extract and decompile the served WASM, map imports/exports to the runtime call, rebuild the target transform, and show wrong-input controls diverge.",
		requiredSignals: [
			{ gate: "wasm-artifact", any: ["wasm", "webassembly", ".wasm", "served asset"] },
			{ gate: "decompile-map", any: ["wasm2wat", "wasm-decompile", "exports", "imports", "function"] },
			{ gate: "runtime-rebuild", any: ["hook", "rebuild", "result", "byte-for-byte", "matches"] },
		],
		negativeControls: [{ gate: "wasm-control", any: ["wrong input", "tampered", "mismatch", "negative control"] }],
	},
	"web-graphql-introspection": {
		proofExit: "prove the GraphQL schema/operation is reachable, replay a concrete query or mutation, and show disabled/wrong-field/unauthorized controls fail.",
		requiredSignals: [
			{ gate: "introspection", any: ["graphql", "__schema", "introspection", "__typename"] },
			{ gate: "schema-edge", any: ["type", "mutation", "query", "field"] },
			{ gate: "operation-replay", any: ["replay", "http 200", "response", "curl"] },
		],
		negativeControls: [{ gate: "graphql-control", any: ["disabled", "wrong field", "unauthorized", "negative control"] }],
	},
	"mobile-root-bypass": {
		proofExit: "identify the root/jailbreak detection path, hook or patch it, prove the app continues the protected flow, and show hook-disabled controls detect root.",
		requiredSignals: [
			{ gate: "root-check", any: ["root check", "jailbreak", "su", "magisk", "isdevicerooted"] },
			{ gate: "bypass-hook", any: ["frida", "hook", "patch", "bypass"] },
			{ gate: "protected-flow", any: ["app continues", "request succeeds", "runtime", "http 200"] },
		],
		negativeControls: [{ gate: "root-control", any: ["hook disabled", "unpatched", "root detected", "negative control"] }],
	},
	"mobile-crypto-hook": {
		proofExit: "hook the mobile crypto/signing API, capture inputs/outputs, rebuild or decrypt one sample, and show wrong-key/tampered controls fail.",
		requiredSignals: [
			{ gate: "crypto-api", any: ["keystore", "keychain", "cipher", "mac", "crypto"] },
			{ gate: "runtime-capture", any: ["frida", "hook", "args", "return", "captured"] },
			{ gate: "rebuild-or-decrypt", any: ["rebuild", "decrypt", "signature", "byte-for-byte", "matches"] },
		],
		negativeControls: [{ gate: "mobile-crypto-control", any: ["wrong key", "hook disabled", "tampered", "negative control"] }],
	},
	"dfir-ntlm-kerberos-extract": {
		proofExit: "bind NTLM/Kerberos credential material to a packet/frame/stream, export a verifier-accepted hash/ticket, and show wrong-mode/checksum controls fail.",
		requiredSignals: [
			{ gate: "credential-material", any: ["ntlm", "kerberos", "as-rep", "tgs", "hash", "ticket"] },
			{ gate: "packet-binding", any: ["frame", "packet", "stream", "pcap", "tshark"] },
			{ gate: "verifier-tool", any: ["john", "hashcat", "krb5tgs", "principal", "checksum"] },
		],
		negativeControls: [{ gate: "kerb-control", any: ["wrong hash mode", "checksum fail", "wrong realm", "negative control"] }],
	},
	"dfir-credential-pcap": {
		proofExit: "extract credential material from a PCAP with packet/stream provenance, validate the credential format or replay boundary, and show wrong-stream/checksum controls fail.",
		requiredSignals: [
			{ gate: "credential-protocol", any: ["credential", "password", "basic auth", "ntlm", "kerberos", "ftp", "smtp"] },
			{ gate: "stream-provenance", any: ["pcap", "frame", "packet", "stream", "tshark"] },
			{ gate: "format-validation", any: ["hash", "ticket", "decoded", "base64", "principal"] },
		],
		negativeControls: [{ gate: "pcap-credential-control", any: ["wrong stream", "checksum fail", "truncated", "negative control"] }],
	},
	"dfir-exfil-detect": {
		proofExit: "prove exfiltration by binding bytes/objects to flows and timeline, export hashes or stream IDs, and compare with benign/wrong-stream controls.",
		requiredSignals: [
			{ gate: "exfil-flow", any: ["exfil", "upload", "dns tunnel", "http post", "bytes"] },
			{ gate: "flow-binding", any: ["frame", "stream", "host", "timeline", "pcap"] },
			{ gate: "object-proof", any: ["size", "hash", "sha256", "extracted object", "artifact"] },
		],
		negativeControls: [{ gate: "exfil-control", any: ["benign baseline", "wrong stream", "control", "negative control"] }],
	},
	"crypto-hash-length-extension": {
		proofExit: "prove a secret-prefix MAC accepts a length-extension forgery with glue padding and show wrong-length/tampered MAC controls fail.",
		requiredSignals: [
			{ gate: "mac-family", any: ["length extension", "sha1", "md5", "secret-prefix", "mac"] },
			{ gate: "glue-padding", any: ["hashpumpy", "padding", "glue padding", "append"] },
			{ gate: "accepted-forgery", any: ["forged mac", "accepted", "http 200", "valid"] },
		],
		negativeControls: [{ gate: "length-extension-control", any: ["wrong length", "tampered", "invalid mac", "negative control"] }],
	},
	"mem-volatility-creds": {
		proofExit: "extract credentials from a memory image with profile/layer evidence, bind them to process/offset context, and show wrong-profile/offset controls fail.",
		requiredSignals: [
			{ gate: "memory-tool", any: ["volatility", "memdump", "windows.pslist", "linux.psaux", "profile"] },
			{ gate: "credential-artifact", any: ["hashdump", "lsadump", "cmdline", "env", "credential"] },
			{ gate: "offset-binding", any: ["offset", "pid", "process", "dump"] },
		],
		negativeControls: [{ gate: "memory-control", any: ["wrong profile", "wrong offset", "false positive", "negative control"] }],
	},
	"mem-process-hunt": {
		proofExit: "identify suspicious process/VAD/network evidence in memory, dump or hash the artifact, and show benign/wrong-PID controls do not match.",
		requiredSignals: [
			{ gate: "process-enum", any: ["process", "pslist", "pstree", "malfind", "netscan"] },
			{ gate: "suspicious-anchor", any: ["pid", "ppid", "cmdline", "vad", "yara"] },
			{ gate: "artifact-binding", any: ["timeline", "dump", "hash", "sha256"] },
		],
		negativeControls: [{ gate: "process-control", any: ["benign process", "wrong pid", "negative control"] }],
	},
	"malware-persistence-mech": {
		proofExit: "bind a persistence mechanism to runtime or artifact evidence, record the launched payload path/hash, and show clean/disabled controls do not persist.",
		requiredSignals: [
			{ gate: "persistence-key", any: ["run key", "service", "scheduled task", "launchagent", "cron", "persistence"] },
			{ gate: "autorun-location", any: ["registry", "plist", "systemd", "autorun", "startup"] },
			{ gate: "payload-binding", any: ["path", "hash", "ioc", "timeline", "sha256"] },
		],
		negativeControls: [{ gate: "persistence-control", any: ["clean baseline", "disabled", "not launched", "negative control"] }],
	},
	"fw-rootfs-extract": {
		proofExit: "extract the firmware filesystem with tool/version evidence, bind recovered files to hashes, and show corrupt/wrong-format controls fail.",
		requiredSignals: [
			{ gate: "extract-tool", any: ["binwalk", "unblob", "unsquashfs", "rootfs", "squashfs"] },
			{ gate: "filesystem-proof", any: ["/etc/passwd", "init", "busybox", "filesystem", "rootfs"] },
			{ gate: "artifact-hash", any: ["sha256", "file", "extracted", "hash"] },
		],
		negativeControls: [{ gate: "firmware-extract-control", any: ["failed extract", "wrong endian", "corrupt", "negative control"] }],
	},
	"fw-emulation-qemu": {
		proofExit: "boot or chroot the firmware service under emulation, prove a live interaction, and show wrong-arch/no-service controls fail.",
		requiredSignals: [
			{ gate: "emulation", any: ["qemu", "chroot", "emulation", "firmadyne", "qiling"] },
			{ gate: "service-live", any: ["service", "http", "boot", "init", "network"] },
			{ gate: "runtime-interaction", any: ["curl", "status", "shell", "runtime", "http 200"] },
		],
		negativeControls: [{ gate: "emulation-control", any: ["wrong arch", "no network", "service down", "negative control"] }],
	},
	"fw-uart-uboot": {
		proofExit: "prove UART/bootloader access with pinout/baud evidence, interrupt or authenticate to a shell/env path, and show wrong-baud/locked-console controls fail.",
		requiredSignals: [
			{ gate: "uart-interface", any: ["uart", "serial", "baud", "pinout", "logic analyzer"] },
			{ gate: "bootloader-access", any: ["u-boot", "bootloader", "interrupt", "printenv", "console"] },
			{ gate: "interactive-proof", any: ["shell", "env", "bootargs", "id output", "transcript"] },
		],
		negativeControls: [{ gate: "uart-control", any: ["wrong baud", "locked console", "no echo", "negative control"] }],
	},
	"fw-secure-boot-bypass": {
		proofExit: "prove a signed/verified boot boundary can be bypassed or downgraded with serial/boot evidence, and show tampered/wrong-key controls reject.",
		requiredSignals: [
			{ gate: "verified-boot", any: ["u-boot", "secure boot", "signature", "rsa", "verified boot"] },
			{ gate: "bypass-path", any: ["bypass", "patch", "rollback", "key", "downgrade"] },
			{ gate: "boot-proof", any: ["boots", "accepted image", "serial log", "runtime"] },
		],
		negativeControls: [{ gate: "secure-boot-control", any: ["tampered image rejected", "wrong key", "signature fail", "negative control"] }],
	},
	"cloud-imds-to-role": {
		proofExit: "retrieve metadata credentials, prove their role/identity with a cloud STS/API call, and show blocked/wrong-hop controls fail.",
		requiredSignals: [
			{ gate: "imds-fetch", any: ["169.254.169.254", "imds", "metadata"] },
			{ gate: "role-credentials", any: ["role", "credentials", "accesskeyid", "token"] },
			{ gate: "identity-proof", any: ["sts get-caller-identity", "caller identity", "arn"] },
		],
		negativeControls: [{ gate: "imds-control", any: ["imds blocked", "wrong hop", "no token", "negative control"] }],
	},
	"cloud-k8s-rbac": {
		proofExit: "prove Kubernetes RBAC reachability with token/namespace binding, can-i/API replay, and denied wrong-namespace or no-token controls.",
		requiredSignals: [
			{ gate: "k8s-token", any: ["kubernetes", "serviceaccount", "rbac", "token"] },
			{ gate: "permission-replay", any: ["kubectl auth can-i", "rolebinding", "clusterrole", "allowed"] },
			{ gate: "resource-proof", any: ["namespace", "list secrets", "pods", "http 200"] },
		],
		negativeControls: [{ gate: "k8s-control", any: ["denied", "wrong namespace", "no token", "negative control"] }],
	},
	"cloud-container-escape": {
		proofExit: "prove a container-to-host boundary break with mount/socket/capability evidence, host-level proof, and unprivileged/read-only controls.",
		requiredSignals: [
			{ gate: "container-context", any: ["container", "docker", "kubernetes", "cgroup", "mount"] },
			{ gate: "escape-primitive", any: ["host path", "privileged", "socket", "cap_sys_admin", "/var/run/docker.sock"] },
			{ gate: "host-proof", any: ["host proof", "nsenter", "hostname", "id output", "host filesystem"] },
		],
		negativeControls: [{ gate: "container-control", any: ["unprivileged", "read-only", "wrong mount", "negative control"] }],
	},
	"ad-kerberoasting": {
		proofExit: "request roastable TGS material for an SPN, verify/crack or validate the hash format, and show wrong-realm/hash-mode controls fail.",
		requiredSignals: [
			{ gate: "spn-enum", any: ["spn", "kerberoast", "tgs", "impacket", "getuserspns"] },
			{ gate: "hash-material", any: ["hashcat", "john", "$krb5tgs", "hash"] },
			{ gate: "account-binding", any: ["cracked", "service account", "ticket", "principal"] },
		],
		negativeControls: [{ gate: "kerberoast-control", any: ["wrong realm", "wrong hash mode", "preauth fail", "negative control"] }],
	},
	"ad-asrep-roasting": {
		proofExit: "prove a principal lacks Kerberos pre-auth, export a valid AS-REP roast hash, validate/crack it, and show preauth-enabled/wrong-realm controls fail.",
		requiredSignals: [
			{ gate: "no-preauth", any: ["asrep", "as-rep", "preauth not required", "getnpusers", "no preauth"] },
			{ gate: "hash-material", any: ["$krb5asrep", "hashcat", "john", "hash"] },
			{ gate: "principal-binding", any: ["principal", "user", "realm", "cracked"] },
		],
		negativeControls: [{ gate: "asrep-control", any: ["preauth enabled", "wrong realm", "wrong hash mode", "negative control"] }],
	},
	"ad-cs-esc": {
		proofExit: "prove a concrete AD CS ESC path from template conditions to certificate authentication, with denied/wrong-EKU controls.",
		requiredSignals: [
			{ gate: "adcs-path", any: ["ad cs", "certipy", "certificate template", "esc"] },
			{ gate: "template-condition", any: ["enrollee supplies subject", "client auth", "template", "eku"] },
			{ gate: "cert-auth", any: ["pfx", "cert", "authenticate", "ldap", "nt hash"] },
		],
		negativeControls: [{ gate: "adcs-control", any: ["disabled template", "wrong eku", "denied", "negative control"] }],
	},
	"ad-dcsync": {
		proofExit: "prove DCSync replication rights and retrieve directory secret material, with no-rights/wrong-principal controls denied.",
		requiredSignals: [
			{ gate: "dcsync-call", any: ["dcsync", "drsuapi", "secretsdump", "replication"] },
			{ gate: "replication-rights", any: ["replicating directory changes", "getchanges", "ntds"] },
			{ gate: "secret-material", any: ["hash", "krbtgt", "administrator", "ntlm"] },
		],
		negativeControls: [{ gate: "dcsync-control", any: ["no rights", "access denied", "wrong principal", "negative control"] }],
	},
	"malware-config-decode": {
		proofExit: "decode malware configuration with key/algorithm evidence, bind IOCs to the sample hash, and show wrong-key/checksum controls fail.",
		requiredSignals: [
			{ gate: "config-anchor", any: ["config", "c2", "mutex", "campaign", "floss", "capa"] },
			{ gate: "decode-chain", any: ["decode", "xor", "rc4", "base64", "decrypt"] },
			{ gate: "ioc-binding", any: ["extracted", "ioc", "sha256", "sample hash"] },
		],
		negativeControls: [{ gate: "config-control", any: ["wrong key", "bad checksum", "benign sample", "negative control"] }],
	},
	"malware-unpack-sandbox": {
		proofExit: "unpack or sandbox a protected sample to a dumped payload/OEP with behavior or IOC proof, and show packed-baseline/wrong-sample controls differ.",
		requiredSignals: [
			{ gate: "packing-signal", any: ["packed", "packer", "sandbox", "unpack", "entropy"] },
			{ gate: "dump-or-oep", any: ["dump", "oep", "memory dump", "unmapped", "payload"] },
			{ gate: "behavior-proof", any: ["ioc", "network", "file written", "registry", "sha256"] },
		],
		negativeControls: [{ gate: "malware-unpack-control", any: ["packed baseline", "wrong sample", "no behavior", "negative control"] }],
	},
	"malware-shellcode-emulate": {
		proofExit: "emulate shellcode from a pinned entry/architecture, record API/syscall or memory effects, and show wrong-arch/bad-entry controls diverge.",
		requiredSignals: [
			{ gate: "shellcode-input", any: ["shellcode", "unicorn", "speakeasy", "scdbg", "emulate"] },
			{ gate: "runtime-effects", any: ["api call", "syscall", "memory map", "trace"] },
			{ gate: "payload-output", any: ["decoded payload", "network", "ioc", "artifact"] },
		],
		negativeControls: [{ gate: "shellcode-control", any: ["wrong arch", "bad entry", "no api", "negative control"] }],
	},
	"rev-vm-unpack": {
		proofExit: "unpack or devirtualize a protected sample to an OEP/dump with recovered imports/strings, and show packed/wrong-OEP controls differ.",
		requiredSignals: [
			{ gate: "packer-family", any: ["packer", "vmprotect", "themida", "upx", "virtualized", "unpack"] },
			{ gate: "unpack-anchor", any: ["oep", "dump", "deobfuscate", "trace"] },
			{ gate: "recovered-program", any: ["imports", "strings", "payload", "rebuilt"] },
		],
		negativeControls: [{ gate: "unpack-control", any: ["packed baseline", "wrong oep", "dump won't run", "negative control"] }],
	},
	"crypto-cbc-bitflip": {
		proofExit: "prove CBC malleability by deriving a byte/block flip, replaying an accepted forged plaintext, and showing wrong-block/padding controls fail.",
		requiredSignals: [
			{ gate: "cbc-context", any: ["cbc", "bitflip", "iv", "block"] },
			{ gate: "flip-derivation", any: ["flip", "xor", "admin=true", "plaintext diff"] },
			{ gate: "accepted-forgery", any: ["accepted", "forged", "http 200", "valid"] },
		],
		negativeControls: [{ gate: "cbc-control", any: ["wrong block", "bad padding", "tampered", "negative control"] }],
	},
	"crypto-rsa-attacks": {
		proofExit: "prove the RSA weakness parameters, recover plaintext or key material, and show wrong-factor/exponent/padding controls fail.",
		requiredSignals: [
			{ gate: "rsa-params", any: ["rsa", "modulus", "e=", " n=", "ciphertext"] },
			{ gate: "attack-path", any: ["wiener", "common modulus", "broadcast", "factor", "small e"] },
			{ gate: "recovery", any: ["plaintext", "private key", "decrypt", "flag"] },
		],
		negativeControls: [{ gate: "rsa-control", any: ["wrong factor", "wrong exponent", "padding fail", "negative control"] }],
	},
	"crypto-ecdsa-nonce-reuse": {
		proofExit: "prove ECDSA nonce reuse from signatures, recover k/private-key material, verify a signature, and show different-r/wrong-curve controls fail.",
		requiredSignals: [
			{ gate: "ecdsa-sigs", any: ["ecdsa", "nonce", "r=", "s=", "curve"] },
			{ gate: "reuse-proof", any: ["same r", "reused nonce", "k recovery"] },
			{ gate: "key-verification", any: ["private key", "sign", "verify", "valid signature"] },
		],
		negativeControls: [{ gate: "ecdsa-control", any: ["different r", "wrong curve", "invalid signature", "negative control"] }],
	},
	"agent-rag-poisoning": {
		proofExit: "prove poisoned retrieval changes the agent decision with source-bound RAG traces, and show clean-corpus/sanitized/doc-removed controls fail.",
		requiredSignals: [
			{ gate: "poison-source", any: ["rag", "retrieval", "poison", "document", "embedding"] },
			{ gate: "retrieval-trace", any: ["retrieved", "source id", "context", "rank"] },
			{ gate: "decision-effect", any: ["answer changed", "tool-call", "decision", "trace"] },
		],
		negativeControls: [{ gate: "rag-control", any: ["clean corpus", "sanitized", "doc removed", "negative control"] }],
	},
	"agent-context-exfil": {
		proofExit: "prove a session transcript/context/tool-result boundary leak with read/tool-call trace evidence and show redaction/permission/tool-disabled controls block it.",
		requiredSignals: [
			{ gate: "context-target", any: ["session", "transcript", "context", "tool result", "exfil", "secret"] },
			{ gate: "boundary-trace", any: ["tool-call", "trace", "read context", "transcript"] },
			{ gate: "leak-proof", any: ["leaked", "output", "boundary", "transcript"] },
		],
		negativeControls: [{ gate: "context-control", any: ["permission denied", "redacted", "tool disabled", "clean session", "negative control"] }],
	},
	"agent-tool-misuse": {
		proofExit: "prove an agent can be induced into an unintended tool call or argument boundary crossing with trace evidence, and show policy/tool-disabled/sanitized controls block it.",
		requiredSignals: [
			{ gate: "tool-boundary", any: ["tool-call", "function call", "argument", "boundary", "capability"] },
			{ gate: "misuse-trigger", any: ["misuse", "unexpected", "unsafe", "payload", "untrusted"] },
			{ gate: "trace-proof", any: ["trace", "decision", "transcript", "called tool"] },
		],
		negativeControls: [{ gate: "tool-misuse-control", any: ["policy blocked", "tool disabled", "sanitized", "negative control"] }],
	},
	"reliability-replay-matrix": {
		proofExit: "run the same proof multiple times with pinned environment plus at least one wrong-input/control replay.",
		requiredSignals: [
			{ gate: "n-run", any: ["3/3", "n-run", "multiple runs", "replay matrix", "stable"] },
			{ gate: "pinned-env", any: ["pinned", "timeout", "env", "sha256", "libc", "version"] },
		],
		negativeControls: [{ gate: "replay-control", any: ["wrong input", "wrong token", "wrong offset", "negative control", "负控制"] }],
	},
};

export const universalTechniqueRules = [
	"map before exploit: inventory files/routes/imports/configs/assets/logs and tool availability before claiming a primitive",
	"bind to live path: identify the runtime/request/process path actually exercised now before expanding sideways",
	"prove one flow: produce one replayable command/transcript/artifact with hash/status/offset/state diff before adding breadth",
	"attach controls: every auth/signature/crypto/exploit claim needs a benign/wrong-principal/wrong-key/tampered counter-control",
	"record repair gates: if proof is missing, emit the exact blocker and next command instead of narrative padding",
];

export const routeDeepTechniquePlaybooks = {
	"native-pwn": [
		"Mitigation triage: file/readelf/checksec → NX/PIE/RELRO/canary/libc/loader map; pin architecture and run environment.",
		"Input contract: enumerate argv/stdin/env/files/sockets; collect empty/short/cyclic/format-string runs and hash transcripts.",
		"Primitive proof: bind crash/leak/write to register/stack bytes, cyclic offset, core/gdb transcript, and a non-crashing baseline.",
		"Exploit shaping: ret2plt/ret2libc/SROP/ROP/heap/tcache strategy only after leak/offset control is proven; record gadget/libc assumptions.",
		"Reliability gate: N-run replay with wrong offset/payload negative controls before promoting payload readiness.",
	],
	"web-api": [
		"Route inventory: crawl links, JS endpoints, OpenAPI/GraphQL, robots/sitemap, and OPTIONS; classify auth/session/state-changing routes.",
		"Principal matrix: replay anonymous/low/high/wrong-principal with status, body SHA-256, response length, and cookie/header deltas.",
		"Object authz: mutate numeric/UUID/path/query IDs; require ownership/source object proof plus tampered object negative controls.",
		"High-impact probes: SSRF/open redirect/CORS/JWT/schema/upload/admin claims stay leads until paired with replay hashes and controls.",
		"State proof: before/after state or audit/log/object diff is required for destructive/business-impact claims.",
	],
	"js-reverse": [
		"Asset chain: collect served chunks/source maps/WASM with hashes; map fetch/XHR/WS initiators and signature parameters.",
		"Runtime hooks: capture crypto.subtle/createHmac/md5/sha/canonicalization/timestamp/nonce order before rebuilding signers.",
		"Canonical rebuild: freeze timestamp/nonce/input sample, rebuild byte-for-byte, and diff browser-captured vs generated fields.",
		"Control matrix: captured-signed must pass while missing/tampered/stale/wrong-key variants fail with response hashes.",
		"WASM/native bridge: export/import/table/string scans remain leads until a harness calls the exact transform with known-answer tests.",
	],
	mobile: [
		"Archive map: verify APK/IPA hash, manifest/plist/entitlements, DEX/native libs, network config, exported components, and pinning anchors.",
		"Static-to-runtime bridge: bind JADX/class/method findings to Frida hooks, adb intents, logcat, or captured network requests.",
		"Pinning/root/signature bypass: prove hook effect with enabled/disabled comparison and wrong cert/root-state controls.",
		"Crypto/signing: hook parameters and return values around MessageDigest/Mac/Cipher/SecTrust/NSURLSession before replaying APIs.",
		"Impact gate: exported component, deep link, or storage claim needs command transcript plus clean-device negative control.",
	],
	"pcap-dfir": [
		"Capture identity: verify capinfos/file/SHA-256/time bounds; rank conversations by bytes, protocol, and anomalies.",
		"Reassembly: tie credentials/IOCs/exfil to frame numbers, stream IDs, payload hashes, and parser command output.",
		"Object carving: verify HTTP/files/archive entries by offset/size/SHA-256; avoid strings-only promotion.",
		"Protocol pivots: DNS tunnel/TLS SNI/JA3/NTLM/Kerberos/basic/bearer/cookie claims need field extraction and false-positive controls.",
		"Decode chain: every transform step records input/output hashes and a wrong-stream/wrong-key negative control.",
	],
	"memory-forensics": [
		"Image identity: hash/profile/tool availability first; cross-check volatility plugins before trusting one parser.",
		"Process/network correlation: bind PID, command line, socket/endpoint, module/path, and timestamp offsets within a correlation window.",
		"Credential context: tie credential bytes to process/module/network/file offsets; downgrade raw strings until context-bound.",
		"Dump proof: dumped files/modules/process memory need path, size, SHA-256, and extraction command.",
		"Counter-evidence: alternate profile/plugin disagreement or stale process/socket evidence blocks promotion.",
	],
	"firmware-iot": [
		"Container map: parse magic/binwalk/signature/partition offsets and verify rootfs carve by offset/size/hash.",
		"Rootfs triage: enumerate init/service/web/cgi/config/credential paths with file hashes and architecture.",
		"Runtime bridge: emulate/chroot/qemu or service smoke; static creds/endpoints remain leads until runtime reachable.",
		"Config/NVRAM controls: test wrong/default/missing config values and record service behavior.",
		"Exploit path: CGI/auth bypass/command injection claims need request replay plus process/file-state evidence.",
	],
	"cloud-identity": [
		"Principal truth: record current identity, token audience/scope/expiry, namespace, workload, and deployment source.",
		"Trust chain: connect CI OIDC/IaC/IAM/RBAC/container/service account edges to runtime principal and exposed resource.",
		"Permission oracle: pair allowed action with denied action using kubectl auth can-i, IAM simulation, STS, or cloud audit evidence.",
		"Metadata/container pivots: IMDS/K8s token/container socket leads need exact request/response hashes and wrong-audience controls.",
		"Least-privilege delta: promote only resource-specific ARN/name/namespace proof, not broad policy prose.",
	],
	"windows-ad": [
		"Domain map: DC, realm, LDAP base, SMB signing, time skew, SPNs, groups, ACLs, ADCS templates, and trust paths first.",
		"Credential usability: prove password/hash/ticket with one auth command and bad credential/time/realm negative control.",
		"Graph proof: BloodHound/LDAP edge chains must resolve owned source → relationship edges → high-value target with file/hash anchors.",
		"Attack primitives: Kerberoast/ASREP/ADCS/DCSync/RBCD claims require command transcript and privilege boundary evidence.",
		"Operational gate: do not promote graph-only reachability without auth/session/tool output confirming the edge is usable.",
	],
	malware: [
		"Sample identity: hash/magic/sections/imports/entropy/packer signals before behavior claims.",
		"Config extraction: bind IOC/config field to offset/function/rule hit and verify decoder output hash.",
		"Behavior chain: static capability + dynamic/sandbox/emulation/log corroboration before persistence/C2 claims.",
		"Unpack/deobfuscate: record layer hashes and fail controls for wrong key/offset/decoder branch.",
		"IOC hygiene: strings-only hits stay observations until offset, context, and negative-control evidence exists.",
	],
	"crypto-stego": [
		"Parameter table: enumerate artifact hash/format/metadata, cipher mode, key/IV/nonce/salt, block sizes, and encodings.",
		"Transform chain: script every decode/decrypt/decompress/carve step with input/output SHA-256 and assertions.",
		"Oracle/KAT proof: known-answer/test vector/padding-oracle timing or error behavior is required before cryptanalytic claims.",
		"Stego structure: verify chunks/trailing data/audio slices/bit planes by exact offsets and false-positive controls.",
		"Wrong path controls: wrong key/nonce/mode/offset/stream must fail or produce a mismatched hash.",
	],
	"agent-boundary": [
		"Boundary map: enumerate system/developer/user/tool/session-context/RAG/MCP resources and untrusted input flows.",
		"Replay harness: minimal indirect/direct injection payloads must produce request/response/tool-call/transcript traces.",
		"Tool side effects: claims need tool invocation, arguments, authorization context, and side-effect or refusal proof.",
		"Session-context/RAG controls: poisoned vs sanitized retrieval and benign prompt comparisons are required.",
		"Capability drift: downgrade any agent narrative that lacks transcript, tool trace, or policy-bound decision evidence.",
	],
	"reverse-pentest-general": [
		"Route split: classify target into native/web/js/mobile/pcap/memory/firmware/cloud/AD/malware/crypto/agent routes before deep work.",
		"One-proof loop: pick the highest-confidence route, build a minimal replay/verifier, run controls, then expand sideways.",
		"Evidence ledger: every promoted claim carries command/path/hash/status/offset/state diff and a repair command for blockers.",
		"Cross-route handoff: when evidence belongs elsewhere, emit route id, anchor, and next command instead of forcing a weak claim.",
		"Merge discipline: final promotion requires route coverage, proof-ready promoted claim, verifier artifact, and negative controls.",
	],
};
