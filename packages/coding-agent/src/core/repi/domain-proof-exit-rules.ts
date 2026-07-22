import type { MissionState } from "./mission.ts";
import { escapeRegExp } from "./target.ts";
import type { ToolchainDomainStatus } from "./toolchain-runtime.ts";

export type DomainProofExitClosureStatus = "passed" | "partial" | "blocked";

export type DomainProofExitRowV1 = {
	proofExit: string;
	status: "matched" | "missing";
	matchedArtifacts: string[];
	matchedLines: string[];
	expectedEvidence: string[];
	nextCommands: string[];
};

export type DomainProofExitClosureV1 = {
	kind: "DomainProofExitClosureV1";
	schemaVersion: 1;
	generatedAt: string;
	missionId?: string;
	routeDomain?: string;
	domainId?: string;
	status: DomainProofExitClosureStatus;
	toolchainStatus?: ToolchainDomainStatus;
	artifactCorpusHash: string;
	artifactSources: string[];
	rows: DomainProofExitRowV1[];
	matchedProofExits: string[];
	missingProofExits: string[];
	blockers: string[];
	nextRuntimeCommands: string[];
};

export type DomainProofExitRulesDependencies = {
	activeLane: (mission: MissionState) => { name: string } | undefined;
	readCurrentMission: () => MissionState | undefined;
};

export function createDomainProofExitRules(dependencies: DomainProofExitRulesDependencies) {
	const { activeLane, readCurrentMission } = dependencies;

	function toolchainDomainIdForRoute(routeDomain?: string): string | undefined {
		if (!routeDomain) return undefined;
		if (/Web \/ API/i.test(routeDomain)) return "web-api";
		if (/Web pentest scanning/i.test(routeDomain)) return "web-scan";
		if (/Frontend JS/i.test(routeDomain)) return "frontend-js";
		if (/Pwn \/ exploit/i.test(routeDomain)) return "pwn";
		if (/Native reverse/i.test(routeDomain)) return "rev-native";
		if (/Mobile \/ Android/i.test(routeDomain)) return "mobile";
		if (/Mobile \/ iOS/i.test(routeDomain)) return "mobile-ios";
		if (/DFIR|PCAP/i.test(routeDomain)) return "pcap-dfir";
		if (/Memory forensics/i.test(routeDomain)) return "memory-forensics";
		if (/Firmware \/ IoT/i.test(routeDomain)) return "firmware-iot";
		if (/Crypto \/ stego/i.test(routeDomain)) return "crypto";
		if (/Cloud|Identity \/ Windows \/ AD/i.test(routeDomain)) return "cloud-identity";
		if (/Exploit reliability/i.test(routeDomain)) return "exploit-reliability";
		if (/Malware analysis/i.test(routeDomain)) return "malware-analysis";
		if (/Agent \/ LLM (?:boundary|security)/i.test(routeDomain)) return "agent-security";
		if (/CTF|sandbox/i.test(routeDomain)) return "rev-native";
		return undefined;
	}

	function proofExitExpectedEvidence(proofExit: string): string[] {
		const normalized = proofExit.toLowerCase();
		const rows: string[] = [];
		const add = (...items: string[]) => rows.push(...items);
		if (/offset|symbol|import|manifest|flow|filesystem|token|parameter|multi-run|prompt/.test(normalized))
			add("path/hash-bound artifact", "tool stdout/stderr or parsed JSON row");
		if (/leak|credential|token|config|oracle|secret/.test(normalized))
			add("source line, request, trace, or carved object that exposes the value class without relying on a guess");
		if (
			/runtime|hook|trace|follow-stream|conversation|state|ownership|rollback|verifier|replay|known-answer|solver|patch|graph|delegation/.test(
				normalized,
			)
		)
			add("runtime/replay/verifier command with exit/status/hash and artifact path");
		if (/controllable|object ownership|privilege edge|state rollback|signed replay|first divergence/.test(normalized))
			add("before/after or principal A/B divergence evidence");
		if (rows.length === 0) add("concrete command output", "artifact path", "verification command");
		return Array.from(new Set(rows));
	}

	function proofExitRegexes(proofExit: string): RegExp[] {
		const text = proofExit.toLowerCase();
		const regexes: RegExp[] = [];
		const add = (...items: RegExp[]) => regexes.push(...items);
		if (/principal matrix/.test(text))
			add(/\[auth-matrix\]|principal matrix|principal_[ab]|COOKIE_A|AUTH_A|auth_matrix/i);
		if (/object ownership/.test(text))
			add(/\[authz-ownership\]|object ownership|owner[_ -]?(principal|hash)|potential_bola|IDOR|BOLA/i);
		if (/state rollback/.test(text))
			add(/\[authz-rollback\]|state rollback|restored=(?:true|false)|rollback_hash|before=.*after=/i);
		if (/signed replay divergence/.test(text))
			add(
				/signed replay divergence|\[js-replay-harness\]|\[replay-eval\]|signature_key|replay_match|first-divergence/i,
			);
		if (/scope baseline/.test(text)) add(/\[web-scan-scope\]|\[web-scan-header\]|\[web-scan-httpx\]|scope baseline/i);
		if (/crawl corpus/.test(text)) add(/\[web-scan-crawl\]|\[web-scan-corpus\]|crawl corpus|katana|sitemap|robots/i);
		if (/scanner finding queue/.test(text))
			add(
				/\[web-finding-queue\]|\[web-scan-nuclei\]|\[web-scan-nikto\]|\[web-scan-dalfox\]|nuclei_jsonl|scanner finding/i,
			);
		if (/manual replay verifier/.test(text))
			add(/\[web-scan-verifier\]|manual replay verifier|body_sha256|status_meta=/i);
		if (/observed normalizer/.test(text))
			add(/\[js-signing-normalized\]|observed normalizer|artifact=.*js-observed|normalized artifact/i);
		if (/first divergence/.test(text))
			add(/\[js-first-divergence\]|first[- ]divergence|candidate_signature|expected_signature|suspect=/i);
		if (/signed replay harness/.test(text))
			add(/\[js-replay-harness\]|signed replay harness|REPI_REPLAY_URL|signature_key|status=\d{3}/i);
		if (/symbol\/import map|symbol\/import|string map/.test(text))
			add(/\[native-symbol\]|\[native-import\]|\[native-section\]|symbol\/import map|rabin2|readelf/i);
		if (/comparison sink|compare/.test(text))
			add(/\[native-compare\]|strcmp|strncmp|memcmp|comparison sink|compare trace/i);
		if (/runtime trace/.test(text)) add(/\[native-.*trace\]|strace|ltrace|gdb|runtime trace|info registers|syscall/i);
		if (/patch\/replay proof|patch/.test(text))
			add(/\[native-patch\]|patch hypothesis|replay proof|branch condition|candidate jump/i);
		if (/offset/.test(text)) add(/cyclic|offset|pattern offset|saved rip|saved eip|RIP|EIP|rsp|stack offset/i);
		if (/leak source/.test(text)) add(/leak source|libc base|canary|GOT|PLT|puts@|printf@|address leak|leaked/i);
		if (/controllable bytes/.test(text))
			add(/controllable bytes|cyclic|AAAA|payload|overwrite|SIGSEGV|crash|register/i);
		if (/local verifier/.test(text))
			add(/local verifier|verification=pass|exploit success|replay_matrix|exit:?\s*0|success rate/i);
		if (/manifest\/package map/.test(text))
			add(/manifest|package=|aapt|AndroidManifest|apk.*package|manifest\/package/i);
		if (/java\/native hook/.test(text))
			add(/\[repi-frida\]|Frida|Java\.perform|doFinal|MessageDigest|native hook|Interceptor\.attach/i);
		if (/anti-debug/.test(text))
			add(/anti-debug|anti_debug|ptrace|isDebuggerConnected|Debug\.isDebugger|frida|root check/i);
		if (/runtime anchors/.test(text)) add(/runtime anchors|\[frida|\[native|adb devices|hook return|runtime hook/i);
		if (/ipa inventory/.test(text))
			add(/\[ios-ipa\]|\[ios-plist\]|\[ios-binary\]|Info\.plist|CFBundleIdentifier|IPA inventory/i);
		if (/mach-o\/class map/.test(text))
			add(/\[ios-macho\]|\[ios-otool\]|\[ios-symbol\]|\[ios-class\]|\[ios-string\]|Mach-O|class-dump/i);
		if (/frida\/objection hook/.test(text))
			add(
				/\[ios-frida\]|\[ios-hook\]|\[ios-native-hook\]|\[ios-frida-hook-template\]|\[ios-objection\]|objection hook/i,
			);
		if (/network\/keychain replay/.test(text))
			add(/\[ios-network-replay\]|\[ios-network-anchor\]|SecItem|keychain|NSURLSession|signature|pinning/i);
		if (/flow conversation/.test(text))
			add(/flow conversation|tcp\.stream|conversation|capinfos|tshark.*conv|\[pcap-flow\]/i);
		if (/follow-stream/.test(text))
			add(/follow-stream|tcp\.stream eq|tshark.*-z follow|stream ranking|\[pcap-stream\]/i);
		if (/carved object/.test(text))
			add(/carved object|foremost|extracted artifact|HTTP object|export objects|\[pcap-extract\]/i);
		if (/timeline evidence/.test(text))
			add(/timeline evidence|credential timeline|\[pcap-secret\]|frame\.time|timestamp/i);
		if (/image profile/.test(text))
			add(
				/\[mem-image\]|\[mem-vol-info\]|volatility3.*(?:windows\.info|linux\.banners|mac\.banners)|sample_sha256|image profile/i,
			);
		if (/process\/network map/.test(text))
			add(/\[mem-process\]|\[mem-vol\].*(?:pslist|pstree|cmdline|netscan|sockstat|netstat)|process\/network/i);
		if (/credential\/artifact proof/.test(text))
			add(
				/\[mem-credential\]|\[mem-vol-credential\]|hashdump|lsadump|Authorization|Cookie|AWS_ACCESS_KEY|credential\/artifact/i,
			);
		if (/timeline\/carve evidence/.test(text))
			add(
				/\[mem-timeline\]|\[mem-vol-timeline\]|\[mem-carve\]|malfind|filescan|dumpfiles|timeliner|timeline\/carve/i,
			);
		if (/filesystem extraction/.test(text))
			add(/filesystem extraction|rootfs|squashfs|unsquashfs|binwalk|unblob|\[firmware-extract\]/i);
		if (/service map/.test(text))
			add(/service map|inetd|dropbear|httpd|telnetd|listening|cgi-bin|\[firmware-service\]/i);
		if (/credential\/config proof/.test(text))
			add(/credential\/config proof|passwd|shadow|config secret|nvram|password|private key|\[firmware-config\]/i);
		if (/emulation notes/.test(text)) add(/emulation notes|qemu|chroot|firmware-emulation|qemu-mips|qemu-arm/i);
		if (/parameter derivation/.test(text))
			add(/parameter derivation|modulus|exponent|iv=|nonce=|oracle|Z3|Sage|lattice|\[crypto-param\]/i);
		if (/solver script/.test(text))
			add(/solver script|solve\.py|z3|sage|known answer|assert .*==|\[crypto-solver\]/i);
		if (/known-answer test/.test(text))
			add(/known-answer|known answer|KAT|assert .*==|test vector|verification=pass/i);
		if (/transform replay/.test(text))
			add(/transform replay|decode chain|base64|xor|openssl|pipeline|\[crypto-transform\]/i);
		if (/token source/.test(text))
			add(/token source|serviceaccount|AWS_ACCESS_KEY_ID|metadata|IMDS|credential_process|k8s-serviceaccount/i);
		if (/credential usability/.test(text))
			add(/credential usability|sts get-caller-identity|can-i|nxc|ldapsearch|klist|valid credential/i);
		if (/privilege edge/.test(text))
			add(/privilege edge|rbac|iam|ClusterRoleBinding|GenericAll|WriteDacl|AdminTo|can-i/i);
		if (/graph\/path evidence/.test(text))
			add(/graph\/path evidence|BloodHound|ad-graph-edge|attack_graph|path proof|edge=/i);
		if (/multi-run success rate/.test(text))
			add(/multi-run success rate|success rate|replay matrix|runs=\d+|passed=\d+|failed=\d+/i);
		if (/stdout\/stderr hash/.test(text)) add(/stdout_sha256|stderr_sha256|stdout\/stderr hash|body_hash|sha256/i);
		if (/environment pin/.test(text))
			add(/environment pin|ldd|Dockerfile|uname|libc|node --version|python.*version/i);
		if (/bundle manifest/.test(text)) add(/bundle manifest|manifest\.json|artifact bundle|bundle_path|tar\.gz/i);
		if (/ioc\/config/.test(text)) add(/IOC|malware-ioc|config extractor|C2|mutex|YARA|capa|FLOSS/i);
		if (/behavior trace/.test(text)) add(/malware-behavior|strace|execve|connect|openat|anti-debug|syscall/i);
		if (/prompt surface/.test(text)) add(/prompt surface|agent-prompt|systemPrompt|developer|prompt injection/i);
		if (/tool boundary/.test(text))
			add(/tool boundary|agent-tool|registerTool|tool schema|function_call|ToolCallTraceLedgerV1/i);
		if (/memory poisoning/.test(text))
			add(/memory poisoning|agent-memory|RAG|retrieval|injection-packet|quarantine|poison/i);
		if (/injection replay/.test(text))
			add(/injection replay|agent-injection|prompt injection|replay harness|untrusted content|boundary decision/i);
		if (/static triage/.test(text)) add(/malware-static|entropy|sha256|format_hint|static triage/i);
		if (/rule\/capability/.test(text))
			add(/malware-yara|malware-capa|malware-floss|YARA|capa|rule\/capability|capability signal/i);
		if (regexes.length === 0) {
			const words = proofExit
				.split(/[^A-Za-z0-9_@.-]+/)
				.filter((word) => word.length >= 4)
				.map(escapeRegExp);
			if (words.length) regexes.push(new RegExp(words.join(".*"), "i"));
		}
		return regexes;
	}

	function domainProofExitNextCommands(domainId: string, proofExit: string, mission?: MissionState): string[] {
		const currentMission = mission ?? readCurrentMission();
		const active = currentMission ? activeLane(currentMission) : undefined;
		const lane = active?.name ?? (domainId === "pwn" ? "primitive" : domainId === "web-api" ? "state" : "prove");
		const target = mission?.task && !/^reverse\/pentest task$/i.test(mission.task) ? mission.task : "<target>";
		const suffix = target ? ` ${target}` : "";
		const commands = new Set<string>([
			`re_toolchain_domain show ${domainId}`,
			`re_lane plan ${lane}${suffix}`,
			`re_lane run ${lane}${suffix}`,
			"re_verifier matrix",
			"re_proof_loop run <target> 4 2",
		]);
		if (domainId === "web-api") {
			commands.add(`re_live_browser run${suffix}`);
			commands.add(`re_web_authz_state run${suffix}`);
		}
		if (domainId === "web-scan") {
			commands.add(`re_lane plan scope${suffix}`);
			commands.add(`re_lane run scope${suffix}`);
			commands.add(`re_lane plan verify${suffix}`);
		}
		if (domainId === "frontend-js") {
			commands.add(`re_lane plan rebuild${suffix}`);
			commands.add("node /tmp/repi-js-normalize.mjs && node /tmp/repi-js-first-divergence.mjs");
		}
		if (domainId === "pwn" || domainId === "rev-native") {
			commands.add(`re_native_runtime run${suffix}`);
			commands.add(`re_exploit_lab run${suffix} 3`);
		}
		if (domainId === "mobile") commands.add(`re_mobile_runtime run${suffix}`);
		if (domainId === "mobile-ios") {
			commands.add(`re_lane plan ipa-inventory${suffix}`);
			commands.add(`re_mobile_runtime run${suffix}`);
		}
		if (domainId === "exploit-reliability") commands.add(`re_exploit_lab run${suffix} 5`);
		if (domainId === "pcap-dfir") commands.add(`re_lane plan extract${suffix}`);
		if (domainId === "memory-forensics") commands.add(`re_lane plan process-network${suffix}`);
		if (domainId === "firmware-iot") commands.add(`re_lane plan extract${suffix}`);
		if (domainId === "crypto") commands.add(`re_lane plan solver${suffix}`);
		if (domainId === "cloud-identity") commands.add(`re_lane plan privilege${suffix}`);
		if (domainId === "malware-analysis") commands.add(`re_lane plan behavior${suffix}`);
		if (domainId === "agent-security") commands.add(`re_lane plan injection${suffix}`);
		if (/tool|missing|bootstrap/i.test(proofExit)) commands.add("re_bootstrap plan <missing-tool>");
		return Array.from(commands).slice(0, 8);
	}

	return {
		domainProofExitNextCommands,
		proofExitExpectedEvidence,
		proofExitRegexes,
		toolchainDomainIdForRoute,
	};
}
