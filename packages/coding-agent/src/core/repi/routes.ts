export type RoutePlan = {
	domain: string;
	intent: string;
	toolchain: string;
	skillHint: string;
	workflow: string[];
};

export const REPI_TASK_PATTERNS = [
	/apk|android|ios|ipa|frida|objection|jadx|apktool|smali/i,
	/ida|radare2|\br2\b|ghidra|binary|二进制|逆向|反编译|反汇编|elf|pe\b|dll|so\b|wasm|vmprotect|upx/i,
	/\bctf\b|\bpwn\b|\brop\b|ret2libc|\bheap\b|tcache|fastbin|format[-_ ]?string|fmtstr|srop|sigreturn|ret2dlresolve|dlresolve|one_gadget|seccomp|seccomp[-_ ]?bpf|syscall filter|pwntools|漏洞利用|\bexploit\b/i,
	/js\s*逆向|签名|加密参数|风控|webpack|sourcemap|hook|xhr|fetch|websocket/i,
	/web\s*渗透|api\s*安全|graphql|jwt|oauth|ssrf|idor|bola|xss|sqli|ssti|csrf|rce|waf|burp|漏洞扫描|目录扫描|nuclei|ffuf|gobuster|sqlmap|dalfox/i,
	/firmware|固件|iot|binwalk|squashfs|uboot|uart|jtag|mips|arm/i,
	/pcap|流量|取证|dfir|forensic|stego|隐写|wireshark|tshark|memory dump|memdump|vmem|volatility|内存取证|内存镜像/i,
	/cloud|aws|azure|gcp|metadata|k8s|kubernetes|docker|container|容器|云/i,
	/ad\b|active directory|kerberos|ntlm|ldap|windows|lsass|mimikatz|bloodhound|certipy|域控|内网|横向|提权|凭据/i,
	/malware|恶意|样本|yara|sigma|ioc|c2|沙箱|反调试|反沙箱/i,
	/prompt injection|agent\s*安全|llm\s*安全|越狱|记忆投毒|工具滥用/i,
] as const;

export function isRepiTask(text: string): boolean {
	return REPI_TASK_PATTERNS.some((pattern) => pattern.test(text));
}

export function routeRepiTask(text: string): RoutePlan {
	const lower = text.toLowerCase();
	const jsSpecific =
		/(?:\bjs\b|jsre|javascript|frontend|js\s*逆向|签名|加密参数|webpack|sourcemap|风控|crypto|subtle|\bsign\b|signature|nonce|timestamp|encrypt|decrypt)/.test(
			lower,
		) ||
		(/(?:xhr|fetch|websocket)/.test(lower) &&
			!/(?:api|graphql|jwt|oauth|auth|session|csrf|ssrf|idor|bola|xss|sqli|ssti|rce|web\s*api|web\s*渗透)/.test(
				lower,
			));
	const agentBoundarySpecific =
		/prompt injection|system prompt|developer message|tool injection|tool-call|tool call|function call|mcp|model context protocol|agent\s*安全|llm\s*安全|rag|retrieval|memory poisoning|记忆投毒|工具滥用|越狱|jailbreak|indirect prompt|untrusted content/.test(
			lower,
		);
	const exploitReliabilitySpecific =
		/autopwn|auto[-_ ]?pwn|exploit reliability|reliable exploit|stable exploit|poc replay|replay matrix|payload stability|crash flake|flake triage|one[-_ ]?click exploit|利用链.*稳定|稳定.*poc|复现矩阵|回放.*验证|一键.*利用/.test(
			lower,
		);
	if (exploitReliabilitySpecific) {
		return plan(
			"Exploit reliability",
			"turn a working PoC into repeatable, environment-pinned, evidence-backed exploitation",
			"PoC inventory + replay matrix + flake triage + artifact bundle",
			"exploit-reliability",
			["PoC inventory", "normalization", "replay matrix", "flake triage", "artifact bundle/report"],
		);
	}
	if (agentBoundarySpecific) {
		return plan(
			"Agent / LLM boundary",
			"prove prompt, memory, tool-call, and delegation boundary failures",
			"prompt/resource map + tool schema/audit + injection replay harness",
			"agent-boundary",
			[
				"prompt/tool surface",
				"memory/retrieval boundary",
				"injection replay",
				"delegation/tool-call trace",
				"report",
			],
		);
	}
	if (/ctf|靶场|challenge|flag|sandbox/.test(lower)) {
		return plan("CTF / sandbox", "prove minimal challenge path", "passive map + runtime proof", "ctf-sandbox", [
			"map entry surface",
			"identify dominant evidence",
			"prove one flow",
			"verify clean replay",
		]);
	}
	if (/ios|ipa|objective-c|objc|swift|mach-o|mach_o|class-dump|otool|codesign|keychain|jailbreak|越狱/.test(lower)) {
		return plan(
			"Mobile / iOS",
			"reverse IPA/iOS logic, entitlement/keychain/network signing, or runtime checks",
			"ipa/unzip/plist/otool/nm/class-dump + Frida/objection",
			"mobile-ios-reverse",
			[
				"IPA inventory",
				"Info.plist/entitlements",
				"Mach-O/class map",
				"Frida/objection hooks",
				"network/keychain replay",
			],
		);
	}
	if (/apk|android|jadx|apktool|smali|frida|objection/.test(lower)) {
		return plan(
			"Mobile / Android",
			"reverse app logic or bypass runtime checks",
			"jadx/apktool/adb/frida",
			"mobile-reverse",
			["manifest map", "Java/Kotlin call chain", "native split", "Frida hook", "evidence replay"],
		);
	}
	if (jsSpecific) {
		return plan(
			"Frontend JS reverse",
			"recover signing/encryption chain",
			"browser/CDP/hook + Node rebuild",
			"js-reverse",
			["observe requests", "capture initiator", "hook args/returns", "local rebuild", "first-divergence patch"],
		);
	}
	if (
		/(?:\bcrypto\b|cryptography|rsa|aes|cbc|ecb|gcm|nonce|iv\b|padding oracle|oracle|lattice|sage|z3|hashcat|john|xor|base64|base32|hex|modulus|exponent|elliptic|ecdsa|stego|隐写|密码题|格|同余|椭圆曲线)/.test(
			lower,
		)
	) {
		return plan(
			"Crypto / stego",
			"recover parameters, transform chain, oracle behavior, or solver path",
			"python/openssl/Z3/Sage/hashcat + known-answer replay",
			"crypto-stego",
			[
				"artifact/parameter inventory",
				"transform chain",
				"oracle/constraint model",
				"solver script",
				"known-answer replay",
			],
		);
	}
	if (
		/漏洞扫描|目录扫描|指纹|资产发现|vuln(?:erability)? scan|web scan|nuclei|ffuf|gobuster|feroxbuster|nikto|dalfox|sqlmap|waf|crawl|爬虫/.test(
			lower,
		)
	) {
		return plan(
			"Web pentest scanning",
			"turn broad web exposure into a bounded finding queue with manual replay proof",
			"httpx/katana/ffuf/nuclei/nikto/dalfox/sqlmap + curl verifier",
			"web-pentest-scan",
			["scope baseline", "crawl/route corpus", "template scan", "manual replay verifier", "finding queue/report"],
		);
	}
	if (/api|graphql|jwt|oauth|ssrf|idor|bola|xss|sqli|ssti|csrf|rce|web|burp|waf|渗透/.test(lower)) {
		return plan(
			"Web / API pentest",
			"prove request/auth/state vulnerability path",
			"routes/auth/session + replay",
			"web-runtime",
			["route map", "auth/session boundary", "minimal replay", "state mutation", "PoC verification"],
		);
	}
	if (
		/\bpwn\b|\brop\b|ret2libc|\bheap\b|tcache|fastbin|format[-_ ]?string|fmtstr|srop|sigreturn|ret2dlresolve|dlresolve|one_gadget|seccomp|seccomp[-_ ]?bpf|syscall filter|pwntools|栈|堆/.test(
			lower,
		)
	) {
		return plan(
			"Pwn / exploit",
			"turn primitive into reliable exploit",
			"checksec/gdb/pwntools/libc/gadgets",
			"pwn-chain",
			["mitigation map", "primitive proof", "leak source", "payload build", "remote stability"],
		);
	}
	if (/malware|恶意|样本|yara|sigma|ioc|c2|beacon|implant|loader|ransom|trojan|backdoor|反调试|反沙箱/.test(lower)) {
		return plan(
			"Malware analysis",
			"recover sample behavior, config, and IOCs",
			"file/strings/imports + yara/capa/floss + sandbox trace",
			"malware-analysis",
			["sample triage", "static IOC/config hints", "behavior trace", "config decode", "IOC report"],
		);
	}
	if (
		/firmware|固件|\biot\b|router|openwrt|squashfs|uboot|u-boot|uart|jtag|mips|\barm(?:el|hf|64)?\b|ubi\b|ubifs|trx\b|uimage|initramfs|rootfs/.test(
			lower,
		)
	) {
		return plan(
			"Firmware / IoT",
			"recover firmware filesystem, secrets, services, and emulation path",
			"binwalk/unblob/unsquashfs + config grep + qemu/chroot scaffold",
			"firmware-iot",
			["image inventory", "extract rootfs", "config/secret map", "service attack surface", "emulation/report"],
		);
	}
	if (/elf|pe\b|dll|so\b|binary|二进制|逆向|反编译|反汇编|ida|radare2|ghidra|wasm/.test(lower)) {
		return plan(
			"Native reverse",
			"understand compiled/native target",
			"file/checksec/strings/imports + r2/Ghidra/trace",
			"reverse-engineering",
			["headers/imports", "strings and xrefs", "entry/control flow", "dynamic trace", "scripted decode"],
		);
	}
	if (
		/memory dump|memdump|mem\.raw|\.vmem|hiberfil|pagefile|volatility|内存取证|内存镜像|内存转储|lsass dump|crash dump/.test(
			lower,
		)
	) {
		return plan(
			"Memory forensics",
			"recover process, network, credential, malware, and timeline evidence from memory images",
			"volatility3/file/strings/yara + timeline/carving",
			"memory-forensics",
			["image profile", "process/network map", "credential/artifact hunt", "timeline/carve", "verification/report"],
		);
	}
	if (/pcap|取证|dfir|forensic|stego|隐写|wireshark|tshark|内存转储/.test(lower)) {
		return plan(
			"DFIR / PCAP / stego",
			"recover artifact or timeline",
			"tshark/volatility/exiftool + transform chain",
			"forensic",
			["artifact inventory", "timeline/flow map", "extract payload", "decode transform", "verify recovered data"],
		);
	}
	if (/cloud|metadata|k8s|kubernetes|docker|container|aws|azure|gcp|容器|云/.test(lower)) {
		return plan(
			"Cloud / container",
			"trace identity/runtime privilege boundary",
			"cloud CLI + container config",
			"agent-cloud",
			["identity map", "runtime config", "metadata path", "privilege edge", "pivot proof"],
		);
	}
	if (/ad\b|kerberos|ntlm|ldap|lsass|mimikatz|bloodhound|certipy|域控|内网|横向|凭据|提权/.test(lower)) {
		return plan(
			"Identity / Windows / AD",
			"validate credential or privilege path",
			"ticket/token/SPN/SID + Impacket/NetExec",
			"identity-windows",
			["principal map", "credential usability", "privilege graph", "pivot command", "event/evidence record"],
		);
	}
	return plan(
		"Reverse/Pentest general",
		"route unknown reverse/pentest task",
		"passive map + one minimal proof",
		"reverse-pentest-orchestrator",
		["classify artifact", "inspect evidence", "choose smallest proof", "verify", "record"],
	);
}

export function formatRepiRoute(plan: RoutePlan): string {
	return `路由: ${plan.domain} / ${plan.intent} / ${plan.toolchain}`;
}

function plan(domain: string, intent: string, toolchain: string, skillHint: string, workflow: string[]): RoutePlan {
	return { domain, intent, toolchain, skillHint, workflow };
}
