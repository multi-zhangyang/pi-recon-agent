export type RoutePlan = {
	domain: string;
	intent: string;
	toolchain: string;
	skillHint: string;
	workflow: string[];
};

export const REPI_GENERIC_TASK = "general REPI investigation";

export const REPI_TASK_PATTERNS = [
	/\b(?:apk|android|ios|ipa|frida|objection|jadx|apktool|smali)\b|\.(?:apk|ipa)\b/i,
	/ida|radare2|\br2\b|ghidra|gdb|lldb|checksec|readelf|objdump|crackme|revers(?:e|ing)(?:\s+engineering)?|binary|二进制|逆向|反编译|反汇编|\b(?:elf|pe|dll)\b|\.so\b|wasm|vmprotect|upx/i,
	/\bctf\b|\bpwn\b|\brop\b|ret2libc|\bheap\b|tcache|fastbin|format[-_ ]?string|fmtstr|srop|sigreturn|ret2dlresolve|dlresolve|one_gadget|seccomp|seccomp[-_ ]?bpf|syscall filter|pwntools|漏洞利用|\bexploit\b/i,
	/js\s*逆向|签名|加密参数|风控|webpack|sourcemap|hook|xhr|fetch|websocket/i,
	/web\s*渗透|api\s*安全|漏洞扫描|目录扫描|\b(?:graphql|jwt|oauth|ssrf|idor|bola|xss|sqli|ssti|csrf|rce|waf|burp|nuclei|ffuf|gobuster|sqlmap|dalfox)\b/i,
	/firmware|固件|iot|binwalk|squashfs|uboot|uart|jtag|mips|arm/i,
	/pcap|流量|取证|dfir|forensic|stego|隐写|wireshark|tshark|memory dump|memdump|vmem|volatility|内存取证|内存镜像/i,
	/cloud|aws|azure|gcp|metadata|k8s|kubernetes|docker|container|容器|云/i,
	/\bad\b|active directory|kerberos|ntlm|ldap|windows|lsass|mimikatz|bloodhound|certipy|域控|内网|横向|提权|凭据/i,
	/malware|恶意|样本|yara|sigma|ioc|c2|沙箱|反调试|反沙箱/i,
	/prompt injection|agent\s*安全|llm\s*安全|越狱|记忆投毒|工具滥用/i,
] as const;

export function isRepiTask(text: string): boolean {
	return (
		REPI_TASK_PATTERNS.some((pattern) => pattern.test(text)) ||
		routeRepiTask(text).domain !== "Reverse/Pentest general"
	);
}

/** Elliptical follow-up which should inherit the active routed task. */
export function isRepiContinuation(text: string): boolean {
	return /^(?:continue(?:\s+(?:working|execution|the task))?|go on|keep going|proceed|next(?: step)?|resume|继续(?:执行|处理|做|工作)?|接着(?:做|处理|执行)?|往下|下一步|再查(?:一下)?|继续跑|继续检查|继续修复)(?:[\s,，.!！。:：].*)?$/i.test(
		text.trim(),
	);
}

export function routeRepiTask(text: string): RoutePlan {
	const lower = text.toLowerCase();
	// Web-target signal: a URL / web-site / HTTP-API reference makes this a Web task,
	// NOT a Native reverse task — even when the word "逆向" appears. Without this, a
	// bare "逆向 https://example.com" (URL but no explicit web/api/渗透 keyword) fell
	// through every web branch and landed in the Native branch (line ~186) on "逆向",
	// routing a Web/API target to the native-reverse-pwn workflow. The web-target
	// signal is checked BEFORE the Native "逆向" fallback so a URL always wins.
	const webTargetSignal =
		/https?:\/\/|www\.|\.(?:com|net|org|io|cn|app|dev|site|co|xyz|info|biz)\b|网站|站点|网页|接口|endpoint|\bhttp\b|登录|cookie|session|bearer|authorization|请求|响应|header|x-forwarded|user-agent/i.test(
			lower,
		);
	const explicitJsRuntimeSignal =
		/\b(?:js|jsre|javascript|frontend)\b|js\s*逆向|webpack|sourcemap|风控|crypto\.subtle|前端\s*(?:js|javascript)|前端.*(?:签名|加密)/.test(
			lower,
		);
	const jsSpecific =
		explicitJsRuntimeSignal ||
		(webTargetSignal && /签名|加密参数|\bsign\b|signature|nonce|timestamp|encrypt|decrypt/.test(lower)) ||
		(/(?:xhr|fetch|websocket)/.test(lower) &&
			!/(?:api|graphql|jwt|oauth|auth|session|csrf|ssrf|idor|bola|xss|sqli|ssti|rce|web\s*api|web\s*渗透)/.test(
				lower,
			));
	// Concrete local/native target signals must outrank meta words like "harness"
	// or "runtime". A live run against `./crackme` asked REPI to also record
	// harness feedback; the earlier agent-boundary branch matched "harness" first
	// and routed the native binary as an LLM-boundary audit. Keep pure REPI QA
	// tasks on the Agent lane, but let concrete ELF/binary/crackme wording win.
	const nativeConcreteSignal =
		/\b(?:elf|pe|dll)\b|\.so\b|binary|二进制|反编译|反汇编|ida|radare2|\br2\b|ghidra|gdb|lldb|checksec|readelf|objdump|wasm|\.exe\b|executable|compiled|\bcrackme\b|keygen|license[-_ ]?check|许可证校验/i.test(
			lower,
		);
	// A user-facing bare reverse/reversing request is a real native route signal. Internal
	// fallback missions should call routeRepiTask with explicit generic wording instead.
	const nativeReverseWord = /逆向|revers(?:e|ing)(?:[-_ ]?engineer(?:ing)?)?/i.test(lower);
	const nativeRouteSignal = nativeConcreteSignal || (nativeReverseWord && !webTargetSignal);
	const memoryForensicsSignal =
		/memory dump|memdump|mem\.raw|\.vmem|hiberfil|pagefile|volatility|内存取证|内存镜像|内存转储|lsass dump|crash dump/.test(
			lower,
		);
	const pcapDfirSignal = /\b(?:pcap|pcapng|tshark|wireshark|capinfos|dfir|forensic)\b|流量|取证/i.test(lower);
	const nonAgentConcreteTargetSignal =
		nativeRouteSignal ||
		webTargetSignal ||
		/\b(?:pcap|pcapng|tshark|wireshark|capinfos|dfir|forensic|firmware|rootfs|squashfs|apk|ipa|android|ios|frida|jadx|apktool|malware|yara|sigma|volatility|memdump|vmem|kerberos|ntlm|ldap|bloodhound|certipy|kubernetes|docker|metadata|aws|azure|gcp|crypto|stego)\b|流量|取证|固件|内存镜像|恶意样本|域控|云|容器|隐写/i.test(
			lower,
		);
	const agentBoundarySpecific =
		/prompt injection|system prompt|developer message|tool injection|tool-call|tool call|function call|mcp|model context protocol|agent\s*安全|llm\s*安全|(?:agent|llm)[\s/_-]*(?:security|boundary|audit)|rag|retrieval|memory poisoning|记忆投毒|工具滥用|越狱|jailbreak|indirect prompt|untrusted content|repi\s*(?:自身|self|harness|qa)|harness\s*qa|agent[-_ ]?thread|sub[-_ ]?agent|agent\s*(?:harness|runtime|orchestration|boundary)|env[-_ ]?only|model provider|print mode/.test(
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
	if (agentBoundarySpecific && !nonAgentConcreteTargetSignal) {
		return plan(
			"Agent / LLM boundary",
			"prove prompt, session-context, tool-call, and delegation boundary failures",
			"prompt/resource map + tool schema/audit + injection replay harness",
			"agent-boundary",
			[
				"prompt/tool surface",
				"session-context/retrieval boundary",
				"injection replay",
				"delegation/tool-call trace",
				"report",
			],
		);
	}
	if (memoryForensicsSignal) {
		return plan(
			"Memory forensics",
			"recover process, network, credential, malware, and timeline evidence from memory images",
			"volatility3/file/strings/yara + timeline/carving",
			"memory-forensics",
			["image profile", "process/network map", "credential/artifact hunt", "timeline/carve", "verification/report"],
		);
	}
	if (pcapDfirSignal) {
		return plan(
			"DFIR / PCAP / stego",
			"recover artifact or timeline",
			"tshark/volatility/exiftool + transform chain",
			"forensic",
			["artifact inventory", "timeline/flow map", "extract payload", "decode transform", "verify recovered data"],
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
	if (
		/\b(?:ios|ipa|objective-c|objc|swift|mach-o|mach_o|class-dump|otool|codesign|keychain|jailbreak)\b|\.ipa\b|越狱/.test(
			lower,
		)
	) {
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
	if (/\b(?:apk|android|jadx|apktool|smali|frida|objection)\b|\.apk\b/.test(lower)) {
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
		/(?:\bcrypto\b|cryptography|cryptanalysis|cipher(?:text)?|encrypt|decrypt|digital signature|rsa|aes|cbc|ecb|gcm|nonce|iv\b|padding oracle|oracle|lattice|sage|z3|hashcat|john|xor|base64|base32|hex|modulus|exponent|elliptic|ecdsa|stego|隐写|密码|签名算法|格|同余|椭圆曲线)/.test(
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
	if (/\b(?:api|graphql|jwt|oauth|ssrf|idor|bola|xss|sqli|ssti|csrf|rce|web|burp|waf)\b|渗透/.test(lower)) {
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
	// Native reverse: a CONCRETE binary keyword always wins (elf/pe/dll/binary/ida/...).
	// The bare word "逆向"/reverse alone routes Native ONLY when there is NO web-target
	// signal — otherwise "逆向 https://example.com" (a Web/API target) would land here on
	// "逆向" instead of the web-authz workflow. .exe/.dll etc. are concrete binaries, so a
	// URL hosting a binary still routes Native (the binary keyword beats the URL signal).
	if (nativeRouteSignal) {
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
	if (/\bad\b|kerberos|ntlm|ldap|lsass|mimikatz|bloodhound|certipy|域控|内网|横向|凭据|提权/.test(lower)) {
		return plan(
			"Identity / Windows / AD",
			"validate credential or privilege path",
			"ticket/token/SPN/SID + Impacket/NetExec",
			"identity-windows",
			["principal map", "credential usability", "privilege graph", "pivot command", "event/evidence record"],
		);
	}
	// Web-target fallback: a URL / web-site / HTTP-API reference that matched no more-
	// specific domain (mobile/firmware/malware/pwn/crypto/pcap/cloud/AD/native) is a Web/API
	// pentest task — route it to the web-authz workflow, never the generic orchestrator.
	// This is the fix for "逆向 <web target>" being misrouted to Native.
	if (webTargetSignal) {
		return plan(
			"Web / API pentest",
			"prove request/auth/state vulnerability path",
			"routes/auth/session + replay",
			"web-runtime",
			["route map", "auth/session boundary", "minimal replay", "state mutation", "PoC verification"],
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
