/** Pure specialist lane command-pack matrix and report formatter. */

export type ReLaneSpecialistDomainPackV1 = {
	domainId: string;
	routeMatchers: string[];
	laneSeeds: string[];
	commandPackMarkers: string[];
	analyzerAnchors: string[];
	selfHealCommands: string[];
	proofExitBridge: string[];
};

export type ReLaneSpecialistCommandPackCheckV1 = {
	kind: "ReLaneSpecialistCommandPackCheckV1";
	schemaVersion: 1;
	generatedAt: string;
	runtime: "runtime:re_lane-specialist-command-pack";
	domainCount: number;
	readyDomainCount: number;
	rows: Array<ReLaneSpecialistDomainPackV1 & { status: "ready" | "blocked"; gaps: string[] }>;
	closure: {
		allDomainsHaveRouteMatchers: boolean;
		allDomainsHaveLaneSeeds: boolean;
		allDomainsHaveCommandPacks: boolean;
		allDomainsHaveAnalyzerAnchors: boolean;
		allDomainsHaveSelfHeal: boolean;
		allDomainsHaveProofExitBridge: boolean;
	};
	nextRuntimeCommands: string[];
};

// Toolchain domain marker expansion: domain:agent-security domain:malware-analysis.
// ReLaneSpecialistCommandPackCheckV1 closure markers:
// route_to_domain_lane_seed_matrix -> domain_lane_command_pack_markers -> specialist_evidence_analyzer_anchor_matrix -> self_heal_command_fallback_matrix -> proof_exit_bridge_matrix.
const RE_LANE_SPECIALIST_COMMAND_PACK_MATRIX: ReLaneSpecialistDomainPackV1[] = [
	{
		domainId: "web-api",
		routeMatchers: ["Web / API pentest", "auth/session", "IDOR/BOLA", "XHR/WS"],
		laneSeeds: ["surface", "state", "authz", "replay"],
		commandPackMarkers: ["re_live_browser run", "re_web_authz_state run", "curl -i", "route-auth-map"],
		analyzerAnchors: [
			"browser/XHR/WS runtime anchors",
			"browser route graph anchors",
			"browser auth matrix anchors",
			"browser authz object ownership anchors",
		],
		selfHealCommands: ["re_lane plan state <target>", "re_web_authz_state plan <target>", "re_operator plan"],
		proofExitBridge: ["principal matrix", "object ownership", "state rollback", "signed replay divergence"],
	},
	{
		domainId: "web-scan",
		routeMatchers: ["Web pentest scanning", "nuclei", "ffuf", "content discovery"],
		laneSeeds: ["scope", "crawl", "template", "verify"],
		commandPackMarkers: [
			"web scanner scope",
			"web scanner crawl",
			"web scanner template",
			"web scanner manual replay",
		],
		analyzerAnchors: [
			"web scanner scope anchors",
			"web scanner crawl corpus anchors",
			"web scanner finding queue anchors",
			"manual replay verifier anchors",
		],
		selfHealCommands: ["re_lane plan scope <target>", "re_replayer run", "re_verifier matrix"],
		proofExitBridge: ["scope baseline", "crawl corpus", "scanner finding queue", "manual replay verifier"],
	},
	{
		domainId: "frontend-js",
		routeMatchers: ["Frontend JS reverse", "crypto.subtle", "sign", "WebSocket"],
		laneSeeds: ["observe", "rebuild", "divergence", "replay"],
		commandPackMarkers: ["js-network-surface", "source-map-search", "js signing rebuild", "js first-divergence"],
		analyzerAnchors: [
			"JS signing rebuild anchors",
			"crypto.subtle operation anchors",
			"JS signing normalized artifact anchors",
			"JS first-divergence anchors",
		],
		selfHealCommands: ["re_lane plan rebuild <target>", "re_live_browser run <target>", "re_replayer run"],
		proofExitBridge: ["observed normalizer", "first divergence", "signed replay harness"],
	},
	{
		domainId: "rev-native",
		routeMatchers: ["Native reverse", "ELF", "Mach-O", "headers/imports"],
		laneSeeds: ["triage", "control", "runtime", "patch"],
		commandPackMarkers: ["headers-imports", "strings-interesting", "r2-xrefs", "objdump-control"],
		analyzerAnchors: [
			"Native deep symbol/import/string anchors",
			"Native decompiler/control-flow anchors",
			"Native compare trace anchors",
			"Native patch hypothesis anchors",
		],
		selfHealCommands: ["re_native_runtime plan <target>", "re_lane plan control <target>", "re_verifier matrix"],
		proofExitBridge: ["symbol/import map", "comparison sink", "runtime trace", "patch/replay proof"],
	},
	{
		domainId: "pwn",
		routeMatchers: ["Pwn / exploit", "mitigations", "crash", "ROP/libc"],
		laneSeeds: ["triage", "primitive", "leak", "verify"],
		commandPackMarkers: ["pwn-mitigations", "crash-seed", "cyclic", "ROP/libc"],
		analyzerAnchors: [
			"pwn primitive crash/control anchors",
			"pwn cyclic offset anchors",
			"pwn gadget anchors",
			"pwn ROP/libc chain anchors",
		],
		selfHealCommands: [
			"re_native_runtime run <target>",
			"re_exploit_lab run <target> 3",
			"re_proof_loop run <target> 4 2",
		],
		proofExitBridge: ["offset", "leak source", "controllable bytes", "local verifier"],
	},
	{
		domainId: "mobile",
		routeMatchers: ["Mobile / Android", "APK", "Frida", "jadx"],
		laneSeeds: ["manifest", "control", "runtime", "hook"],
		commandPackMarkers: ["apk-manifest", "jadx-keyword-map", "frida-hook-scaffold", "native-lib-map"],
		analyzerAnchors: [
			"mobile APK manifest anchors",
			"Frida/GDB trace anchors",
			"Java crypto hooks",
			"native compare hooks",
		],
		selfHealCommands: ["re_mobile_runtime plan <target>", "re_lane plan control <target>", "re_verifier matrix"],
		proofExitBridge: ["manifest/package map", "Java/native hook", "anti-debug evidence", "runtime anchors"],
	},
	{
		domainId: "mobile-ios",
		routeMatchers: ["Mobile / iOS", "iOS IPA", "Info.plist", "Keychain"],
		laneSeeds: ["ipa-inventory", "macho", "hook", "network"],
		commandPackMarkers: [
			"ios-ipa-inventory-scaffold",
			"ios-macho-class-map",
			"ios-frida-hook-template",
			"ios-network-keychain-replay",
		],
		analyzerAnchors: [
			"iOS IPA anchors",
			"Mach-O/class map anchors",
			"iOS Frida/objection hook anchors",
			"keychain/network replay anchors",
		],
		selfHealCommands: ["re_lane plan ipa-inventory <target>", "re_mobile_runtime run <target>", "re_replayer run"],
		proofExitBridge: ["IPA inventory", "Mach-O/class map", "Frida/objection hook", "network/keychain replay"],
	},
	{
		domainId: "pcap-dfir",
		routeMatchers: ["DFIR / PCAP / stego", "tcp.stream", "flow conversation", "carved object"],
		laneSeeds: ["flow", "stream", "extract", "timeline"],
		commandPackMarkers: ["pcap-flow", "pcap-stream", "pcap-extract", "pcap-secret"],
		analyzerAnchors: [
			"PCAP/DFIR traffic flow anchors",
			"PCAP stream ranking anchors",
			"PCAP extracted artifact anchors",
			"PCAP secret timeline anchors",
		],
		selfHealCommands: ["re_lane plan extract <target>", "re_graph build", "re_verifier matrix"],
		proofExitBridge: ["flow conversation", "follow-stream", "carved object", "timeline evidence"],
	},
	{
		domainId: "memory-forensics",
		routeMatchers: ["Memory forensics", "volatility", "vmem", "process/network"],
		laneSeeds: ["image", "process-network", "credential", "timeline"],
		commandPackMarkers: [
			"memory-image-profile-scaffold",
			"memory-process-network-scaffold",
			"memory-credential-artifact-scaffold",
			"memory-timeline-carve-scaffold",
		],
		analyzerAnchors: [
			"memory forensics image anchors",
			"memory forensics process/network anchors",
			"memory forensics credential/artifact anchors",
			"memory forensics timeline/carve anchors",
		],
		selfHealCommands: ["re_lane plan process-network <target>", "re_replayer run", "re_verifier matrix"],
		proofExitBridge: ["image profile", "process/network map", "credential/artifact proof", "timeline/carve evidence"],
	},
	{
		domainId: "firmware-iot",
		routeMatchers: ["Firmware / IoT", "rootfs", "squashfs", "emulation"],
		laneSeeds: ["extract", "service", "config", "emulate"],
		commandPackMarkers: [
			"firmware-image-fingerprint",
			"firmware-extraction-rootfs",
			"firmware-service-surface",
			"firmware-config-secret",
		],
		analyzerAnchors: [
			"Firmware image metadata anchors",
			"Firmware extraction/rootfs anchors",
			"Firmware config/secret anchors",
			"Firmware emulation/runtime anchors",
		],
		selfHealCommands: ["re_lane plan extract <target>", "re_campaign plan <target>", "re_operation plan <target>"],
		proofExitBridge: ["filesystem extraction", "service map", "credential/config proof", "emulation notes"],
	},
	{
		domainId: "crypto",
		routeMatchers: ["Crypto / stego", "oracle", "lattice", "transform chain"],
		laneSeeds: ["params", "solver", "kat", "transform"],
		commandPackMarkers: [
			"crypto-param-oracle-scaffold",
			"crypto-solver-scaffold",
			"known-answer test",
			"crypto-stego-extraction-scaffold",
		],
		analyzerAnchors: [
			"Crypto transform chain anchors",
			"crypto parameter derivation anchors",
			"solver script anchors",
			"known-answer test anchors",
		],
		selfHealCommands: ["re_lane plan solver <target>", "re_replayer run", "re_proof_loop run <target>"],
		proofExitBridge: ["parameter derivation", "solver script", "known-answer test", "transform replay"],
	},
	{
		domainId: "cloud-identity",
		routeMatchers: ["Cloud / container", "Identity / Windows / AD", "K8s", "AD graph"],
		laneSeeds: ["config", "metadata", "privilege", "graph"],
		commandPackMarkers: [
			"cloud-identity-config-map",
			"cloud-metadata-probe-scaffold",
			"cloud-privilege-edge-scaffold",
			"identity-ad-graph-scaffold",
		],
		analyzerAnchors: [
			"Cloud identity anchors",
			"Cloud metadata probe anchors",
			"Cloud privilege edge anchors",
			"Identity/AD graph edge anchors",
		],
		selfHealCommands: ["re_lane plan privilege <target>", "re_campaign plan <target>", "re_supervisor review"],
		proofExitBridge: ["token source", "credential usability", "privilege edge", "graph/path evidence"],
	},
	{
		domainId: "agent-security",
		routeMatchers: ["Agent / LLM boundary", "agent-security", "prompt injection", "tool boundary"],
		laneSeeds: ["surface", "boundary", "poison", "injection"],
		commandPackMarkers: [
			"agent-prompt-surface-map",
			"agent-tool-boundary-scaffold",
			"agent-memory-poisoning-scaffold",
			"agent-injection-replay-harness",
		],
		analyzerAnchors: [
			"Agent prompt surface anchors",
			"Agent tool boundary anchors",
			"Agent memory poisoning anchors",
			"Agent injection replay anchors",
		],
		selfHealCommands: ["re_lane plan injection", "re_replayer run", "re_verifier matrix"],
		proofExitBridge: [
			"prompt surface map",
			"tool boundary proof",
			"memory poisoning proof",
			"injection replay proof",
		],
	},
	{
		domainId: "malware-analysis",
		routeMatchers: ["Malware analysis", "malware-analysis", "IOC", "behavior trace"],
		laneSeeds: ["static", "rules", "ioc", "behavior"],
		commandPackMarkers: [
			"malware-static-triage-scaffold",
			"malware-yara-capa-floss-scaffold",
			"malware-ioc-config-scaffold",
			"malware-behavior-trace-scaffold",
		],
		analyzerAnchors: [
			"Malware static triage anchors",
			"Malware rule/capability anchors",
			"Malware IOC/config anchors",
			"Malware behavior trace anchors",
		],
		selfHealCommands: ["re_lane plan behavior", "re_graph build", "re_verifier matrix"],
		proofExitBridge: ["static triage proof", "rule/capability signal", "IOC/config proof", "behavior trace"],
	},
	{
		domainId: "exploit-reliability",
		routeMatchers: ["Exploit reliability", "PoC", "replay matrix", "flake triage"],
		laneSeeds: ["inventory", "matrix", "pin", "bundle"],
		commandPackMarkers: [
			"exploit-poc-inventory",
			"poc-replay-matrix",
			"exploit-environment-pin",
			"exploit-artifact-bundle",
		],
		analyzerAnchors: [
			"Exploit PoC inventory anchors",
			"PoC replay matrix anchors",
			"Exploit environment pin anchors",
			"Exploit artifact bundle anchors",
		],
		selfHealCommands: ["re_exploit_lab run <target> 5", "re_autofix plan", "re_verifier matrix"],
		proofExitBridge: ["multi-run success rate", "stdout/stderr hash", "environment pin", "bundle manifest"],
	},
];

export function buildReLaneSpecialistCommandPackGate(domainFilter?: string): ReLaneSpecialistCommandPackCheckV1 {
	const selected = domainFilter
		? RE_LANE_SPECIALIST_COMMAND_PACK_MATRIX.filter(
				(row) => row.domainId === domainFilter || row.domainId.includes(domainFilter),
			)
		: RE_LANE_SPECIALIST_COMMAND_PACK_MATRIX;
	const rows = selected.map((row) => {
		const gaps = [
			row.routeMatchers.length ? undefined : "route_matchers_missing",
			row.laneSeeds.length ? undefined : "lane_seeds_missing",
			row.commandPackMarkers.length >= 3 ? undefined : "command_pack_markers_missing",
			row.analyzerAnchors.length >= 3 ? undefined : "analyzer_anchors_missing",
			row.selfHealCommands.length >= 2 ? undefined : "self_heal_commands_missing",
			row.proofExitBridge.length >= 3 ? undefined : "proof_exit_bridge_missing",
		].filter((item): item is string => Boolean(item));
		return { ...row, status: gaps.length ? ("blocked" as const) : ("ready" as const), gaps };
	});
	return {
		kind: "ReLaneSpecialistCommandPackCheckV1",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		runtime: "runtime:re_lane-specialist-command-pack",
		domainCount: rows.length,
		readyDomainCount: rows.filter((row) => row.status === "ready").length,
		rows,
		closure: {
			allDomainsHaveRouteMatchers: rows.every((row) => row.routeMatchers.length > 0),
			allDomainsHaveLaneSeeds: rows.every((row) => row.laneSeeds.length > 0),
			allDomainsHaveCommandPacks: rows.every((row) => row.commandPackMarkers.length >= 3),
			allDomainsHaveAnalyzerAnchors: rows.every((row) => row.analyzerAnchors.length >= 3),
			allDomainsHaveSelfHeal: rows.every((row) => row.selfHealCommands.length >= 2),
			allDomainsHaveProofExitBridge: rows.every((row) => row.proofExitBridge.length >= 3),
		},
		nextRuntimeCommands: [
			"re_lane_specialist_pack show",
			"re_lane plan <domain-lane> <target>",
			"re_lane run <domain-lane> <target>",
			"re_domain_proof_exit show <domain>",
		],
	};
}

export function formatReLaneSpecialistCommandPackGate(report: ReLaneSpecialistCommandPackCheckV1): string {
	return [
		"relane_specialist_command_pack:",
		"ReLaneSpecialistCommandPackCheckV1: true",
		`runtime: ${report.runtime}`,
		`coverage: domains=${report.domainCount} ready=${report.readyDomainCount}`,
		`closure: route=${report.closure.allDomainsHaveRouteMatchers} lanes=${report.closure.allDomainsHaveLaneSeeds} command_pack=${report.closure.allDomainsHaveCommandPacks} analyzer=${report.closure.allDomainsHaveAnalyzerAnchors} self_heal=${report.closure.allDomainsHaveSelfHeal} proof_exit=${report.closure.allDomainsHaveProofExitBridge}`,
		"domains:",
		...report.rows.flatMap((row) => [
			`- domain:${row.domainId} status=${row.status} lane_seeds=${row.laneSeeds.join(",")}`,
			`  route_matchers: ${row.routeMatchers.join(" | ")}`,
			`  command_pack_markers: ${row.commandPackMarkers.join(" | ")}`,
			`  analyzer_anchors: ${row.analyzerAnchors.join(" | ")}`,
			`  self_heal_commands: ${row.selfHealCommands.join(" | ")}`,
			`  proof_exit_bridge: ${row.proofExitBridge.join(" | ")}`,
			`  gaps: ${row.gaps.join(", ") || "none"}`,
		]),
		"next_runtime_commands:",
		...report.nextRuntimeCommands.map((item) => `- ${item}`),
	].join("\n");
}
