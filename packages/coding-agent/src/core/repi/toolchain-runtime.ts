/**
 * Pure toolchain capability and professional runtime bridge contracts.
 *
 * Discovery, storage, and evidence writes intentionally stay in recon-profile;
 * this module only evaluates injected runtime facts and formats reports.
 */

export type ToolchainDomainStatus = "ready" | "degraded" | "blocked";

export type ToolchainDomainSpec = {
	id: string;
	label: string;
	requiredAny: string[];
	preferred: string[];
	fallbacks: string[];
	playbookMarkers: string[];
	commandScaffolds: string[];
	proofExit: string[];
};

export type ToolchainDomainCapabilityRowV1 = {
	domainId: string;
	label: string;
	status: ToolchainDomainStatus;
	requiredAny: string[];
	preferred: string[];
	fallbacks: string[];
	presentRequired: string[];
	presentPreferred: string[];
	presentFallbacks: string[];
	missingRequired: string[];
	missingPreferred: string[];
	fallback_available: boolean;
	critical_gap: boolean;
	playbookMarkersFound: string[];
	playbookMarkersMissing: string[];
	commandScaffoldsFound: string[];
	commandScaffoldsMissing: string[];
	proofExit: string[];
	recommendedInstallHints: string[];
	nextRuntimeCommands: string[];
};

export type ToolchainDomainCapabilityV1 = {
	kind: "ToolchainDomainCapabilityV1";
	schemaVersion: 1;
	generatedAt: string;
	runtime: "runtime:toolchain-doctor";
	discoveryMode: "tool-index";
	toolIndexPath: string;
	domains: ToolchainDomainCapabilityRowV1[];
	coverage: {
		domainCount: number;
		readyCount: number;
		degradedCount: number;
		blockedCount: number;
		readyOrDegradedCount: number;
		fallbackDomainCount: number;
	};
	toolchainClosure: {
		allDomainsHaveFallback: boolean;
		allDomainsHavePlaybookMarkers: boolean;
		allDomainsHaveCommandScaffolds: boolean;
		noCriticalGap: boolean;
	};
	nextActions: string[];
};

export type ProfessionalRuntimeBridgeStatus = "runtime-ready" | "blocked";

export type ProfessionalRuntimeBridgeSpec = {
	id: string;
	title: string;
	domains: string[];
	preferredTools: string[];
	fallbackTools: string[];
	commandTemplates: string[];
	artifactPlan: string[];
	envRefs: string[];
	proofExit: string[];
};

export type ProfessionalRuntimeBridgeRowV1 = {
	bridgeId: string;
	title: string;
	status: ProfessionalRuntimeBridgeStatus;
	domains: string[];
	preferredTools: string[];
	fallbackTools: string[];
	presentPreferred: string[];
	presentFallbacks: string[];
	missingPreferred: string[];
	fallback_available: boolean;
	commandTemplates: string[];
	artifactPlan: string[];
	artifactPlanOk: boolean;
	envRefs: string[];
	envRefOnly: boolean;
	proofExit: string[];
	proofExitFound: string[];
	proofExitMissing: string[];
	executableTemplateCount: number;
	narrativeOnly: boolean;
	nextRuntimeCommands: string[];
};

export type ProfessionalRuntimeBridgesCheckV1 = {
	kind: "ProfessionalRuntimeBridgesCheckV1";
	schemaVersion: 1;
	generatedAt: string;
	ProfessionalRuntimeBridgesCheckV1: true;
	runtime: "runtime:professional-runtime-bridges";
	toolIndexPath: string;
	requiredChecks: string[];
	bridges: ProfessionalRuntimeBridgeRowV1[];
	closure: {
		allBridgeSpecsPresent: boolean;
		allFallbacksAvailable: boolean;
		allHaveExecutableTemplates: boolean;
		allHaveArtifactPlans: boolean;
		allHaveProofExitMappings: boolean;
		allEnvRefsSecretFree: boolean;
	};
	nextRuntimeCommands: string[];
	invariants: string[];
};

export type ToolchainDomainCapabilityBuildOptions = {
	domainFilter?: string;
	generatedAt: string;
	toolIndexPath: string;
	sourceCorpus: string;
	toolPresent: (tool: string) => boolean;
	bootstrapHint: (tool: string) => string;
};

export type ProfessionalRuntimeBridgesBuildOptions = {
	bridgeFilter?: string;
	generatedAt: string;
	toolIndexPath: string;
	sourceCorpus: string;
	toolPresent: (tool: string) => boolean;
};

export const TOOLCHAIN_DOMAIN_CAPABILITY_MATRIX: ToolchainDomainSpec[] = [
	{
		id: "web-api",
		label: "Web/API auth, route, IDOR/BOLA, XHR/WS",
		requiredAny: ["curl", "python3", "node"],
		preferred: ["httpx", "ffuf", "nuclei", "katana", "jq", "playwright", "mitmproxy"],
		fallbacks: ["curl", "python3", "node", "rg"],
		playbookMarkers: ["route", "auth/session", "IDOR/BOLA", "JS signing", "XHR/WS"],
		commandScaffolds: ["re_live_browser", "re_web_authz_state", "re_map", "re_lane", "re_operator"],
		proofExit: ["principal matrix", "object ownership", "state rollback", "signed replay divergence"],
	},
	{
		id: "web-scan",
		label: "Web pentest scanning: scope, crawl, templates, manual replay",
		requiredAny: ["curl", "python3"],
		preferred: ["httpx", "katana", "ffuf", "feroxbuster", "gobuster", "nuclei", "nikto", "dalfox", "sqlmap"],
		fallbacks: ["curl", "python3", "node", "rg"],
		playbookMarkers: ["web scanner scope", "web scanner crawl", "web scanner template", "web scanner manual replay"],
		commandScaffolds: ["re_lane", "re_replayer", "re_verifier", "re_proof_loop"],
		proofExit: ["scope baseline", "crawl corpus", "scanner finding queue", "manual replay verifier"],
	},
	{
		id: "frontend-js",
		label: "Frontend bundle, signer rebuild, anti-bot divergence",
		requiredAny: ["node", "curl", "rg"],
		preferred: ["playwright", "jq", "mitmproxy", "python3"],
		fallbacks: ["node", "curl", "rg", "python3"],
		playbookMarkers: ["fetch/XMLHttpRequest", "WebSocket", "crypto.subtle", "first-divergence", "signed replay"],
		commandScaffolds: ["re_live_browser", "re_lane", "re_replayer", "re_proof_loop"],
		proofExit: ["observed normalizer", "first divergence", "signed replay harness"],
	},
	{
		id: "rev-native",
		label: "Native reverse: headers/imports/strings/control-flow/runtime trace",
		requiredAny: ["file", "strings", "readelf", "objdump"],
		preferred: ["r2", "rabin2", "radare2", "ghidra", "angr", "strace", "ltrace"],
		fallbacks: ["file", "strings", "readelf", "objdump", "python3"],
		playbookMarkers: ["entrypoint", "imports", "strings", "control-flow", "patch"],
		commandScaffolds: ["re_native_runtime", "re_lane", "re_graph", "re_verifier"],
		proofExit: ["symbol/import map", "comparison sink", "runtime trace", "patch/replay proof"],
	},
	{
		id: "pwn",
		label: "Pwn primitive: mitigations, crash, leak, ROP/libc, heap/tcache, fmtstr, SROP/ret2dlresolve, one_gadget, seccomp verifier",
		requiredAny: ["file", "readelf", "gdb", "python3"],
		preferred: ["checksec", "pwn", "ROPgadget", "ropper", "one_gadget", "seccomp-tools", "patchelf"],
		fallbacks: ["readelf", "objdump", "gdb", "python3", "strace"],
		playbookMarkers: [
			"mitigations",
			"cyclic",
			"leak",
			"primitive",
			"ROP/libc",
			"heap/tcache",
			"format-string",
			"SROP/ret2dlresolve",
			"one_gadget constraint",
			"seccomp/sandbox",
		],
		commandScaffolds: ["re_native_runtime", "re_exploit_lab", "re_replayer", "re_proof_loop"],
		proofExit: [
			"offset",
			"leak source",
			"controllable bytes",
			"local verifier",
			"heap/tcache bin state",
			"format-string leak/write",
			"SROP syscall surface",
			"ret2dlresolve payload scaffold",
			"one_gadget constraint review",
			"seccomp/sandbox syscall filter",
		],
	},
	{
		id: "mobile",
		label: "Android/APK: manifest, jadx/apktool, ADB/Frida hooks",
		requiredAny: ["unzip", "strings"],
		preferred: ["jadx", "apktool", "adb", "frida", "frida-ps", "objection", "aapt", "r2"],
		fallbacks: ["unzip", "strings", "readelf", "python3"],
		playbookMarkers: ["APK", "manifest", "smali", "Frida", "Java crypto", "native compare"],
		commandScaffolds: ["re_mobile_runtime", "re_lane", "re_verifier", "re_graph"],
		proofExit: ["manifest/package map", "Java/native hook", "anti-debug evidence", "runtime anchors"],
	},
	{
		id: "mobile-ios",
		label: "iOS/IPA: Info.plist, entitlements, Mach-O/classes, Frida/objection hooks",
		requiredAny: ["unzip", "strings", "file"],
		preferred: ["plutil", "otool", "nm", "codesign", "class-dump", "frida", "frida-ps", "objection"],
		fallbacks: ["unzip", "strings", "python3", "file"],
		playbookMarkers: ["iOS IPA", "Info.plist", "Mach-O/class", "iOS Frida", "keychain"],
		commandScaffolds: ["re_mobile_runtime", "re_lane", "re_replayer", "re_verifier"],
		proofExit: ["IPA inventory", "Mach-O/class map", "Frida/objection hook", "network/keychain replay"],
	},
	{
		id: "pcap-dfir",
		label: "PCAP/DFIR: flow rank, stream follow, objects, secret timeline",
		requiredAny: ["file", "strings"],
		preferred: ["tshark", "capinfos", "tcpdump", "zeek", "foremost", "exiftool"],
		fallbacks: ["strings", "file", "python3", "binwalk", "foremost"],
		playbookMarkers: ["tcp.stream", "HTTP object", "DNS/TLS", "credential timeline", "transform-chain"],
		commandScaffolds: ["re_lane", "re_graph", "re_verifier", "re_replayer"],
		proofExit: ["flow conversation", "follow-stream", "carved object", "timeline evidence"],
	},
	{
		id: "memory-forensics",
		label: "Memory forensics: image profile, process/network, credentials, timeline/carve",
		requiredAny: ["file", "strings", "python3"],
		preferred: ["volatility3", "yara", "foremost"],
		fallbacks: ["file", "strings", "python3", "yara"],
		playbookMarkers: [
			"memory forensics image",
			"memory forensics process",
			"memory forensics credential",
			"memory forensics timeline",
		],
		commandScaffolds: ["re_lane", "re_graph", "re_verifier", "re_replayer"],
		proofExit: ["image profile", "process/network map", "credential/artifact proof", "timeline/carve evidence"],
	},
	{
		id: "firmware-iot",
		label: "Firmware/IoT: image fingerprint, rootfs, configs, service surface, emulation",
		requiredAny: ["file", "strings"],
		preferred: ["binwalk", "unblob", "unsquashfs", "7z", "qemu-system-x86_64", "qemu-arm", "qemu-mips"],
		fallbacks: ["file", "strings", "binwalk", "python3"],
		playbookMarkers: ["rootfs", "squashfs", "config secret", "service surface", "emulation"],
		commandScaffolds: ["re_lane", "re_campaign", "re_operation", "re_graph"],
		proofExit: ["filesystem extraction", "service map", "credential/config proof", "emulation notes"],
	},
	{
		id: "crypto",
		label: "Crypto/stego: transform chain, oracle, solver, parameter recovery",
		requiredAny: ["python3"],
		preferred: ["sage", "z3", "openssl", "hashcat", "john", "zsteg"],
		fallbacks: ["python3", "openssl", "jq"],
		playbookMarkers: ["oracle", "params", "modulus", "lattice", "Z3/Sage", "transform chain"],
		commandScaffolds: ["re_lane", "re_replayer", "re_verifier", "re_proof_loop"],
		proofExit: ["parameter derivation", "solver script", "known-answer test", "transform replay"],
	},
	{
		id: "cloud-identity",
		label: "Cloud/K8s/AD identity: config, credential usability, graph edge proof",
		requiredAny: ["python3", "curl", "jq"],
		preferred: ["kubectl", "aws", "az", "gcloud", "ldapsearch", "nxc", "certipy", "bloodhound-python"],
		fallbacks: ["python3", "curl", "jq", "rg"],
		playbookMarkers: ["Cloud/K8s", "metadata", "privilege edge", "credential usability", "AD graph"],
		commandScaffolds: ["re_lane", "re_campaign", "re_operation", "re_supervisor"],
		proofExit: ["token source", "credential usability", "privilege edge", "graph/path evidence"],
	},
	{
		id: "agent-security",
		label: "Agent/LLM boundary: prompt/tool/memory/delegation replay",
		requiredAny: ["rg", "python3", "node"],
		preferred: ["jq", "mitmproxy", "playwright"],
		fallbacks: ["rg", "python3", "node", "grep"],
		playbookMarkers: [
			"Agent prompt surface anchors",
			"Agent tool boundary anchors",
			"Agent memory poisoning anchors",
			"Agent injection replay anchors",
		],
		commandScaffolds: ["re_lane", "re_replayer", "re_verifier", "re_proof_loop"],
		proofExit: ["prompt surface map", "tool boundary proof", "memory poisoning proof", "injection replay proof"],
	},
	{
		id: "malware-analysis",
		label: "Malware analysis: static triage, rule/capability, IOC/config, behavior trace",
		requiredAny: ["file", "strings", "python3"],
		preferred: ["yara", "capa", "floss", "rabin2", "strace", "upx", "clamscan"],
		fallbacks: ["file", "strings", "python3", "readelf"],
		playbookMarkers: [
			"Malware static triage anchors",
			"Malware rule/capability anchors",
			"Malware IOC/config anchors",
			"Malware behavior trace anchors",
		],
		commandScaffolds: ["re_lane", "re_graph", "re_verifier", "re_replayer"],
		proofExit: ["static triage proof", "rule/capability signal", "IOC/config proof", "behavior trace"],
	},
	{
		id: "exploit-reliability",
		label: "Exploit/PoC reliability: replay matrix, env pin, flake triage, bundle",
		requiredAny: ["python3", "bash", "node"],
		preferred: ["docker", "gdb", "jq", "curl", "patchelf"],
		fallbacks: ["python3", "bash", "node", "sh"],
		playbookMarkers: ["PoC inventory", "replay matrix", "environment pin", "flake triage", "artifact bundle"],
		commandScaffolds: ["re_exploit_lab", "re_replayer", "re_autofix", "re_complete"],
		proofExit: ["multi-run success rate", "stdout/stderr hash", "environment pin", "bundle manifest"],
	},
];

export const PROFESSIONAL_RUNTIME_BRIDGE_MATRIX: ProfessionalRuntimeBridgeSpec[] = [
	{
		id: "tool-bridge-runtime",
		title: "真实工具链桥接总控",
		domains: ["rev-native", "pwn", "web-cdp", "mobile-frida", "pcap-dfir", "firmware-iot"],
		preferredTools: [
			"ghidra",
			"r2",
			"rabin2",
			"angr",
			"gdb",
			"gef",
			"pwndbg",
			"checksec",
			"ROPgadget",
			"one_gadget",
			"seccomp-tools",
			"tshark",
			"volatility3",
			"binwalk",
			"qemu-arm",
			"frida",
			"adb",
			"jadx",
		],
		fallbackTools: ["file", "strings", "readelf", "objdump", "python3", "node", "curl", "unzip"],
		commandTemplates: [
			"bridge-rev-ghidra-r2-angr: re_runtime_bridge show tool-bridge-runtime && re_native_runtime plan <target>",
			"bridge-pwn-pwntools-checksec-rop: re_toolchain_domain show pwn && re_exploit_lab run <target> 5",
			"bridge-web-cdp-http-replay: re_runtime_bridge show web-cdp-replay && re_live_browser run <url>",
			"bridge-mobile-frida-adb-jadx: re_runtime_bridge show mobile-frida && re_mobile_runtime run <apk-or-package>",
			"bridge-dfir-tshark-volatility: re_lane plan pcap-dfir <artifact> && re_verifier matrix",
			"bridge-firmware-binwalk-qemu: re_lane plan firmware-iot <image> && re_proof_loop run <image>",
		],
		artifactPlan: [
			".repi/evidence/toolchain/<timestamp>-professional-runtime-bridges.md",
			".repi/evidence/runs/<mission>/tool-output-hashes.json",
		],
		envRefs: [
			"REPI_TOOLBRIDGE_TIMEOUT_MS",
			"REPI_TOOLBRIDGE_WORKDIR",
			"REPI_ANDROID_SERIAL",
			"REPI_FRIDA_DEVICE",
			"REPI_BROWSER_CDP_URL",
		],
		proofExit: [
			"tool presence discovery",
			"fallback command generation",
			"artifact path plan",
			"proof-exit mapping",
			"no narrative-only bridge",
		],
	},
	{
		id: "exploit-verifier-runtime",
		title: "自动利用验证闭环",
		domains: ["pwn", "web-api", "frontend-js", "mobile-frida"],
		preferredTools: ["gdb", "pwntools", "checksec", "ROPgadget", "one_gadget", "curl", "playwright", "frida"],
		fallbackTools: ["python3", "node", "bash", "sh", "curl"],
		commandTemplates: [
			"verifier-pwn-crash-offset-primitive-exploit: re_exploit_lab run <target> 5 && re_verifier matrix",
			"verifier-web-replay-diff: re_replayer run <captured-request> 3 && re_domain_proof_exit write web-api",
			"verifier-js-signing-replay: re_live_browser run <url> && re_replayer run <signed-request> 3",
			"verifier-mobile-hook-output: re_mobile_runtime run <package> && re_verifier check",
			"verifier-regression-bundle: re_proof_loop run <target> 4 2 && re_verifier matrix",
		],
		artifactPlan: [
			".repi/evidence/runs/<mission>/exploit-verifier-matrix.json",
			".repi/evidence/runs/<mission>/stdout-stderr-hashes.json",
			".repi/evidence/reports/<mission>-replay-verifier.md",
		],
		envRefs: [
			"REPI_EXPLOIT_VERIFY_RUNS",
			"REPI_EXPLOIT_VERIFY_TIMEOUT_MS",
			"REPI_REPLAY_BASE_URL",
			"REPI_FRIDA_DEVICE",
		],
		proofExit: [
			"crash-to-offset proof",
			"primitive control evidence",
			"multi-run verifier",
			"stdout/stderr hash",
			"state rollback proof",
		],
	},
	{
		id: "web-cdp-replay",
		title: "Web/CDP replay harness",
		domains: ["web-api", "frontend-js", "web-scan"],
		preferredTools: ["playwright", "mitmproxy", "httpx", "ffuf", "nuclei", "jq"],
		fallbackTools: ["curl", "node", "python3", "rg"],
		commandTemplates: [
			"cdp-network-capture: re_runtime_bridge show web-cdp-replay && re_live_browser run <url>",
			"cdp-xhr-ws-route-extraction: re_lane plan frontend-js <url> && re_graph build",
			"cdp-cookie-session-isolation: re_web_authz_state run <url> 45000",
			"cdp-signed-request-replay: re_replayer run <request-artifact> 3",
			"cdp-authz-request-order-proof: re_domain_proof_exit write web-api",
			"cdp-blocked-mutation-operator-command: re_operator plan <target>",
		],
		artifactPlan: [
			".repi/evidence/browser/<mission>/cdp-network.har",
			".repi/evidence/browser/<mission>/xhr-ws-routes.json",
			".repi/evidence/browser/<mission>/signed-replay-diff.json",
			".repi/evidence/browser/<mission>/request-order-proof.md",
		],
		envRefs: ["REPI_BROWSER_CDP_URL", "REPI_BROWSER_PROFILE_DIR", "REPI_REPLAY_BASE_URL", "REPI_SESSION_COOKIE_REF"],
		proofExit: [
			"CDP network capture",
			"XHR/WS route extraction",
			"cookie/session isolation",
			"signed request replay",
			"authz replay matrix",
			"request order proof",
		],
	},
	{
		id: "mobile-frida",
		title: "Frida/Mobile 动态分析桥接",
		domains: ["mobile", "mobile-ios", "rev-native"],
		preferredTools: [
			"frida",
			"frida-ps",
			"objection",
			"adb",
			"jadx",
			"apktool",
			"aapt",
			"class-dump",
			"otool",
			"codesign",
			"ios-deploy",
		],
		fallbackTools: ["unzip", "strings", "file", "python3", "node"],
		commandTemplates: [
			"mobile-apk-ipa-static-triage: re_runtime_bridge show mobile-frida && re_mobile_runtime plan <apk-or-ipa>",
			"mobile-frida-java-hook-template: frida -U -f <package> -l hooks/java-crypto.js --no-pause",
			"mobile-frida-objc-swift-hook-template: frida -U -f <bundle> -l hooks/objc-keychain.js --no-pause",
			"mobile-keystore-keychain-certpin-anchors: re_verifier check <mobile-artifact>",
			"mobile-runtime-attach-env-check: REPI_FRIDA_DEVICE=<device> re_mobile_runtime run <package>",
			"mobile-hook-output-artifact-contract: re_domain_proof_exit write mobile",
		],
		artifactPlan: [
			".repi/evidence/mobile/<mission>/static-triage.json",
			".repi/evidence/mobile/<mission>/frida-hook-output.jsonl",
			".repi/evidence/mobile/<mission>/cert-pinning-anchors.md",
			".repi/evidence/mobile/<mission>/runtime-attach-manifest.json",
		],
		envRefs: ["REPI_FRIDA_DEVICE", "REPI_ANDROID_SERIAL", "REPI_IOS_BUNDLE_ID", "REPI_MOBILE_RUNTIME_TIMEOUT_MS"],
		proofExit: [
			"APK/IPA static triage",
			"Java/ObjC/Swift method anchors",
			"keystore/keychain/cert pinning anchors",
			"runtime attach env checkpoint",
			"hook output artifact contract",
		],
	},
];

function runtimeBridgeSecretLike(value: string): boolean {
	return /(sk-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9_]{10,}|github_pat_[A-Za-z0-9_]{10,}|AKIA[0-9A-Z]{12,}|-----BEGIN [A-Z ]+PRIVATE KEY-----)/.test(
		value,
	);
}

export function buildProfessionalRuntimeBridgesGate(
	options: ProfessionalRuntimeBridgesBuildOptions,
): ProfessionalRuntimeBridgesCheckV1 {
	const specs = options.bridgeFilter
		? PROFESSIONAL_RUNTIME_BRIDGE_MATRIX.filter(
				(bridge) => bridge.id === options.bridgeFilter || bridge.id.includes(options.bridgeFilter!),
			)
		: PROFESSIONAL_RUNTIME_BRIDGE_MATRIX;
	const bridges = specs.map<ProfessionalRuntimeBridgeRowV1>((bridge) => {
		const presentPreferred = bridge.preferredTools.filter((tool) => options.toolPresent(tool));
		const presentFallbacks = bridge.fallbackTools.filter((tool) => options.toolPresent(tool));
		const missingPreferred = bridge.preferredTools.filter((tool) => !options.toolPresent(tool));
		const proofExitFound = bridge.proofExit.filter((marker) => options.sourceCorpus.includes(marker));
		const artifactPlanOk =
			bridge.artifactPlan.length >= 3 &&
			bridge.artifactPlan.every((path) => path.startsWith(".repi/evidence") || path.startsWith(".repi/recon"));
		const envRefOnly = bridge.envRefs.every((ref) => /^[A-Z][A-Z0-9_]+$/.test(ref) && !runtimeBridgeSecretLike(ref));
		const executableTemplateCount = bridge.commandTemplates.filter((template) =>
			/\bre_[a-z0-9_]+\b|\bcurl\b|\bfrida\b|\bgdb\b|\bpython3\b|\bnode\b/.test(template),
		).length;
		return {
			bridgeId: bridge.id,
			title: bridge.title,
			status: presentFallbacks.length > 0 ? "runtime-ready" : "blocked",
			domains: bridge.domains,
			preferredTools: bridge.preferredTools,
			fallbackTools: bridge.fallbackTools,
			presentPreferred,
			presentFallbacks,
			missingPreferred,
			fallback_available: presentFallbacks.length > 0,
			commandTemplates: bridge.commandTemplates,
			artifactPlan: bridge.artifactPlan,
			artifactPlanOk,
			envRefs: bridge.envRefs,
			envRefOnly,
			proofExit: bridge.proofExit,
			proofExitFound,
			proofExitMissing: bridge.proofExit.filter((marker) => !proofExitFound.includes(marker)),
			executableTemplateCount,
			narrativeOnly: executableTemplateCount === 0,
			nextRuntimeCommands: [
				"re_runtime_bridge refresh",
				`re_runtime_bridge show ${bridge.id}`,
				bridge.id === "web-cdp-replay" ? "re_live_browser run <url>" : undefined,
				bridge.id === "mobile-frida" ? "re_mobile_runtime run <package>" : undefined,
				bridge.id === "exploit-verifier-runtime" ? "re_exploit_lab run <target> 5" : undefined,
				"re_domain_proof_exit write <domain>",
			].filter((item): item is string => Boolean(item)),
		};
	});
	return {
		kind: "ProfessionalRuntimeBridgesCheckV1",
		schemaVersion: 1,
		generatedAt: options.generatedAt,
		ProfessionalRuntimeBridgesCheckV1: true,
		runtime: "runtime:professional-runtime-bridges",
		toolIndexPath: options.toolIndexPath,
		requiredChecks: [
			"professional_runtime_bridge_check",
			"runtime_execution_bridge_matrix",
			"real_toolchain_bridge_contract",
			"exploit_verifier_runtime_contract",
			"web_cdp_replay_contract",
			"mobile_frida_dynamic_bridge_contract",
			"artifact_backed_tool_execution_plan",
			"env_ref_secret_boundary",
		],
		bridges,
		closure: {
			allBridgeSpecsPresent:
				bridges.length === PROFESSIONAL_RUNTIME_BRIDGE_MATRIX.length || Boolean(options.bridgeFilter),
			allFallbacksAvailable: bridges.every((bridge) => bridge.fallback_available),
			allHaveExecutableTemplates: bridges.every(
				(bridge) => !bridge.narrativeOnly && bridge.executableTemplateCount >= 3,
			),
			allHaveArtifactPlans: bridges.every((bridge) => bridge.artifactPlanOk),
			allHaveProofExitMappings: bridges.every(
				(bridge) => bridge.proofExit.length >= 5 && bridge.proofExitMissing.length === 0,
			),
			allEnvRefsSecretFree: bridges.every((bridge) => bridge.envRefOnly),
		},
		nextRuntimeCommands: [
			"re_runtime_bridge show",
			"re_runtime_bridge refresh",
			"re_runtime_bridge show web-cdp-replay",
			"re_runtime_bridge show mobile-frida",
			"re_exploit_lab run <target> 5",
			"re_live_browser run <url>",
			"re_mobile_runtime run <package>",
		],
		invariants: [
			"professional_runtime_bridge_check",
			"runtime_execution_bridge_matrix",
			"real_toolchain_bridge_contract",
			"exploit_verifier_runtime_contract",
			"web_cdp_replay_contract",
			"mobile_frida_dynamic_bridge_contract",
			"artifact_backed_tool_execution_plan",
			"env_ref_secret_boundary",
			"narrative_only_bridge_rejected",
		],
	};
}

export function formatProfessionalRuntimeBridgesGate(report: ProfessionalRuntimeBridgesCheckV1, path?: string): string {
	return [
		"professional_runtime_bridges:",
		"ProfessionalRuntimeBridgesCheckV1: true",
		"runtime: runtime:professional-runtime-bridges",
		path ? `artifact: ${path}` : undefined,
		`tool_index: ${report.toolIndexPath}`,
		`closure: specs=${report.closure.allBridgeSpecsPresent} fallback=${report.closure.allFallbacksAvailable} executable=${report.closure.allHaveExecutableTemplates} artifact=${report.closure.allHaveArtifactPlans} proof=${report.closure.allHaveProofExitMappings} env_ref=${report.closure.allEnvRefsSecretFree}`,
		"bridges:",
		...report.bridges.flatMap((bridge) => [
			`- bridge:${bridge.bridgeId} status=${bridge.status} fallback_available=${bridge.fallback_available}`,
			`  domains: ${bridge.domains.join(", ")}`,
			`  preferred_present: ${bridge.presentPreferred.join(", ") || "none"}`,
			`  fallback_present: ${bridge.presentFallbacks.join(", ") || "none"}`,
			`  command_templates: ${bridge.commandTemplates.join(" | ")}`,
			`  artifact_plan: ${bridge.artifactPlan.join(" | ")}`,
			`  env_refs: ${bridge.envRefs.join(", ")}`,
			`  proof_exit: ${bridge.proofExit.join("; ")}`,
			`  next: ${bridge.nextRuntimeCommands.join(" | ")}`,
		]),
		"next_runtime_commands:",
		...report.nextRuntimeCommands.map((item) => `- ${item}`),
		"invariants:",
		...report.invariants.map((item) => `- ${item}`),
	]
		.filter(Boolean)
		.join("\n");
}

export function buildToolchainDomainCapability(
	options: ToolchainDomainCapabilityBuildOptions,
): ToolchainDomainCapabilityV1 {
	const specs = options.domainFilter
		? TOOLCHAIN_DOMAIN_CAPABILITY_MATRIX.filter(
				(domain) => domain.id === options.domainFilter || domain.id.includes(options.domainFilter!),
			)
		: TOOLCHAIN_DOMAIN_CAPABILITY_MATRIX;
	const domains = specs.map<ToolchainDomainCapabilityRowV1>((domain) => {
		const presentRequired = domain.requiredAny.filter((tool) => options.toolPresent(tool));
		const presentPreferred = domain.preferred.filter((tool) => options.toolPresent(tool));
		const presentFallbacks = domain.fallbacks.filter((tool) => options.toolPresent(tool));
		const missingRequired = domain.requiredAny.filter((tool) => !options.toolPresent(tool));
		const missingPreferred = domain.preferred.filter((tool) => !options.toolPresent(tool));
		const status: ToolchainDomainStatus =
			presentRequired.length > 0 ? "ready" : presentFallbacks.length > 0 ? "degraded" : "blocked";
		const playbookMarkersFound = domain.playbookMarkers.filter((marker) => options.sourceCorpus.includes(marker));
		const commandScaffoldsFound = domain.commandScaffolds.filter((marker) => options.sourceCorpus.includes(marker));
		const recommendedInstallHints = Array.from(new Set([...missingRequired, ...missingPreferred.slice(0, 5)])).map(
			options.bootstrapHint,
		);
		return {
			domainId: domain.id,
			label: domain.label,
			status,
			requiredAny: domain.requiredAny,
			preferred: domain.preferred,
			fallbacks: domain.fallbacks,
			presentRequired,
			presentPreferred,
			presentFallbacks,
			missingRequired,
			missingPreferred,
			fallback_available: presentFallbacks.length > 0 || status === "ready",
			critical_gap: status === "blocked",
			playbookMarkersFound,
			playbookMarkersMissing: domain.playbookMarkers.filter((marker) => !playbookMarkersFound.includes(marker)),
			commandScaffoldsFound,
			commandScaffoldsMissing: domain.commandScaffolds.filter((marker) => !commandScaffoldsFound.includes(marker)),
			proofExit: domain.proofExit,
			recommendedInstallHints,
			nextRuntimeCommands: [
				"re_tool_index refresh",
				`re_toolchain_domain show ${domain.id}`,
				`re_lane plan ${domain.id} <target>`,
				...domain.commandScaffolds.map((scaffold) => `${scaffold} plan <target>`),
			].slice(0, 10),
		};
	});
	const readyCount = domains.filter((domain) => domain.status === "ready").length;
	const degradedCount = domains.filter((domain) => domain.status === "degraded").length;
	const blockedCount = domains.filter((domain) => domain.status === "blocked").length;
	return {
		kind: "ToolchainDomainCapabilityV1",
		schemaVersion: 1,
		generatedAt: options.generatedAt,
		runtime: "runtime:toolchain-doctor",
		discoveryMode: "tool-index",
		toolIndexPath: options.toolIndexPath,
		domains,
		coverage: {
			domainCount: domains.length,
			readyCount,
			degradedCount,
			blockedCount,
			readyOrDegradedCount: readyCount + degradedCount,
			fallbackDomainCount: domains.filter((domain) => domain.fallback_available).length,
		},
		toolchainClosure: {
			allDomainsHaveFallback: domains.every((domain) => domain.fallback_available || domain.status === "ready"),
			allDomainsHavePlaybookMarkers: domains.every((domain) => domain.playbookMarkersMissing.length === 0),
			allDomainsHaveCommandScaffolds: domains.every((domain) => domain.commandScaffoldsMissing.length === 0),
			noCriticalGap: blockedCount === 0,
		},
		nextActions: [
			"re_toolchain_domain refresh",
			"re_tool_index refresh",
			"re_bootstrap plan <missing-tool>",
			"re_lane plan <domain> <target>",
			"re_proof_loop run <target>",
		],
	};
}

export function formatToolchainDomainCapability(report: ToolchainDomainCapabilityV1, path?: string): string {
	return [
		"toolchain_domain_capability:",
		"ToolchainDomainCapabilityV1: true",
		"runtime: runtime:toolchain-doctor",
		path ? `artifact: ${path}` : undefined,
		`tool_index: ${report.toolIndexPath}`,
		`coverage: domains=${report.coverage.domainCount} ready=${report.coverage.readyCount} degraded=${report.coverage.degradedCount} blocked=${report.coverage.blockedCount}`,
		`closure: fallback=${report.toolchainClosure.allDomainsHaveFallback} playbook=${report.toolchainClosure.allDomainsHavePlaybookMarkers} commands=${report.toolchainClosure.allDomainsHaveCommandScaffolds} noCriticalGap=${report.toolchainClosure.noCriticalGap}`,
		"domains:",
		...report.domains.flatMap((domain) => [
			`- domain:${domain.domainId} status=${domain.status} fallback_available=${domain.fallback_available} critical_gap=${domain.critical_gap}`,
			`  label: ${domain.label}`,
			`  required_present: ${domain.presentRequired.join(", ") || "none"}`,
			`  preferred_present: ${domain.presentPreferred.join(", ") || "none"}`,
			`  fallback_present: ${domain.presentFallbacks.join(", ") || "none"}`,
			`  missing_required: ${domain.missingRequired.join(", ") || "none"}`,
			`  proof_exit: ${domain.proofExit.join("; ")}`,
			`  command_scaffolds: ${domain.commandScaffoldsFound.join(", ") || "none"}`,
			`  next: ${domain.nextRuntimeCommands.slice(0, 4).join(" | ")}`,
		]),
		"next_actions:",
		...report.nextActions.map((item) => `- ${item}`),
	]
		.filter(Boolean)
		.join("\n");
}
