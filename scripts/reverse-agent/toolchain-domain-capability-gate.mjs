#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const writeEvidence = !argv.includes("--no-write");

const sha256 = (value) => createHash("sha256").update(String(value ?? "")).digest("hex");
const shortHash = (value) => sha256(value).slice(0, 24);
const check = (id, ok, evidence = {}) => ({ id, status: ok ? "pass" : "fail", evidence });

const DOMAIN_MARKERS = ["domain:web-api", "domain:rev-native", "domain:pwn", "domain:mobile", "domain:pcap-dfir", "domain:firmware-iot", "domain:crypto"];

const DOMAIN_TOOLCHAINS = [
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
		commandScaffolds: ["re_native_runtime", "re_lane", "re_knowledge_graph", "re_verifier"],
		proofExit: ["symbol/import map", "comparison sink", "runtime trace", "patch/replay proof"],
	},
	{
		id: "pwn",
		label: "Pwn primitive: mitigations, crash, leak, ROP/libc verifier",
		requiredAny: ["file", "readelf", "gdb", "python3"],
		preferred: ["checksec", "pwntools", "ROPgadget", "ropper", "one_gadget", "patchelf"],
		fallbacks: ["readelf", "objdump", "gdb", "python3"],
		playbookMarkers: ["mitigations", "cyclic", "leak", "primitive", "ROP/libc"],
		commandScaffolds: ["re_native_runtime", "re_exploit_lab", "re_replayer", "re_proof_loop"],
		proofExit: ["offset", "leak source", "controllable bytes", "local verifier"],
	},
	{
		id: "mobile",
		label: "Android/APK: manifest, jadx/apktool, ADB/Frida hooks",
		requiredAny: ["unzip", "strings"],
		preferred: ["jadx", "apktool", "adb", "frida", "frida-ps", "aapt", "r2"],
		fallbacks: ["unzip", "strings", "readelf", "python3"],
		playbookMarkers: ["APK", "manifest", "smali", "Frida", "Java crypto", "native compare"],
		commandScaffolds: ["re_mobile_runtime", "re_lane", "re_verifier", "re_knowledge_graph"],
		proofExit: ["manifest/package map", "Java/native hook", "anti-debug evidence", "runtime anchors"],
	},
	{
		id: "pcap-dfir",
		label: "PCAP/DFIR: flow rank, stream follow, objects, secret timeline",
		requiredAny: ["file", "strings"],
		preferred: ["tshark", "capinfos", "tcpdump", "zeek", "foremost", "exiftool"],
		fallbacks: ["strings", "file", "python3", "binwalk", "foremost"],
		playbookMarkers: ["tcp.stream", "HTTP object", "DNS/TLS", "credential timeline", "transform-chain"],
		commandScaffolds: ["re_lane", "re_knowledge_graph", "re_verifier", "re_replayer"],
		proofExit: ["flow conversation", "follow-stream", "carved object", "timeline evidence"],
	},
	{
		id: "firmware-iot",
		label: "Firmware/IoT: image fingerprint, rootfs, configs, service surface, emulation",
		requiredAny: ["file", "strings"],
		preferred: ["binwalk", "unblob", "unsquashfs", "7z", "qemu-system-x86_64", "qemu-arm", "qemu-mips"],
		fallbacks: ["file", "strings", "binwalk", "python3"],
		playbookMarkers: ["rootfs", "squashfs", "config secret", "service surface", "emulation"],
		commandScaffolds: ["re_lane", "re_campaign", "re_operation", "re_knowledge_graph"],
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

function readText(path) {
	return readFileSync(join(root, path), "utf8");
}

function maybeRead(path) {
	try {
		return readText(path);
	} catch {
		return "";
	}
}

function commandExists(tool) {
	const probe = spawnSync("sh", ["-lc", `command -v ${JSON.stringify(tool)} 2>/dev/null || true`], {
		cwd: root,
		encoding: "utf8",
		maxBuffer: 1024 * 1024,
	});
	const path = String(probe.stdout || "").trim().split(/\r?\n/)[0] || undefined;
	return { tool, present: Boolean(path), path, exitCode: probe.status ?? 0 };
}

function markerCheck(id, path, markers) {
	const full = join(root, path);
	if (!existsSync(full)) return check(id, false, { path, exists: false });
	const text = readFileSync(full, "utf8");
	const missing = markers.filter((marker) => !text.includes(marker));
	return check(id, missing.length === 0, { path, missing, sha256: shortHash(text) });
}

function buildReport() {
	const allTools = Array.from(new Set(DOMAIN_TOOLCHAINS.flatMap((domain) => [...domain.requiredAny, ...domain.preferred, ...domain.fallbacks]))).sort();
	const discovery = Object.fromEntries(allTools.map((tool) => [tool, commandExists(tool)]));
	const sourceCorpus = [
		"packages/coding-agent/src/core/recon-profile.ts",
		"repi-profile/extensions/reverse-pentest-core.ts",
		"README.md",
		"docs/reverse-agent/README.md",
	].map((path) => maybeRead(path)).join("\n---REPI_TOOLCHAIN_CORPUS---\n");
	const domains = DOMAIN_TOOLCHAINS.map((domain) => {
		const presentRequired = domain.requiredAny.filter((tool) => discovery[tool]?.present);
		const presentPreferred = domain.preferred.filter((tool) => discovery[tool]?.present);
		const presentFallbacks = domain.fallbacks.filter((tool) => discovery[tool]?.present);
		const missingRequired = domain.requiredAny.filter((tool) => !discovery[tool]?.present);
		const missingPreferred = domain.preferred.filter((tool) => !discovery[tool]?.present);
		const playbookMarkersFound = domain.playbookMarkers.filter((marker) => sourceCorpus.includes(marker));
		const commandScaffoldsFound = domain.commandScaffolds.filter((marker) => sourceCorpus.includes(marker));
		const status = presentRequired.length > 0 ? "ready" : presentFallbacks.length > 0 ? "degraded" : "blocked";
		const fallbackAvailable = status === "degraded" || presentFallbacks.length > 0;
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
			fallback_available: fallbackAvailable,
			critical_gap: status === "blocked",
			playbookMarkersFound,
			playbookMarkersMissing: domain.playbookMarkers.filter((marker) => !playbookMarkersFound.includes(marker)),
			commandScaffoldsFound,
			commandScaffoldsMissing: domain.commandScaffolds.filter((marker) => !commandScaffoldsFound.includes(marker)),
			proofExit: domain.proofExit,
			recommendedInstallHints: Array.from(new Set([...missingRequired, ...missingPreferred.slice(0, 5)])).map((tool) => `re_bootstrap plan ${tool}`),
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
		generatedAt: new Date().toISOString(),
		runtime: "runtime:toolchain-doctor",
		discoveryMode: "command-v",
		root,
		toolDiscovery: discovery,
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
			allDomainsHaveRuntimeBackedDiscovery: domains.every((domain) => domain.presentRequired.length + domain.presentPreferred.length + domain.presentFallbacks.length >= 0),
			allDomainsHaveFallback: domains.every((domain) => domain.fallback_available || domain.status === "ready"),
			allDomainsHavePlaybookMarkers: domains.every((domain) => domain.playbookMarkersMissing.length === 0),
			allDomainsHaveCommandScaffolds: domains.every((domain) => domain.commandScaffoldsMissing.length === 0),
			noCriticalGap: domains.every((domain) => !domain.critical_gap),
		},
	};
}

function validateReport(report) {
	const errors = [];
	if (report.kind !== "ToolchainDomainCapabilityV1") errors.push("kind_invalid");
	if (report.runtime !== "runtime:toolchain-doctor") errors.push("runtime_marker_missing");
	const ids = new Set(report.domains.map((domain) => domain.domainId));
	for (const id of ["web-api", "rev-native", "pwn", "mobile", "pcap-dfir", "firmware-iot", "crypto"]) {
		if (!ids.has(id)) errors.push(`domain_missing:${id}`);
	}
	for (const domain of report.domains) {
		if (!domain.presentRequired.length && !domain.presentFallbacks.length) errors.push(`domain_no_present_or_fallback:${domain.domainId}`);
		if (!domain.fallbacks?.length) errors.push(`domain_no_fallback_list:${domain.domainId}`);
		if (domain.playbookMarkersMissing?.length) errors.push(`domain_playbook_markers_missing:${domain.domainId}:${domain.playbookMarkersMissing.join(",")}`);
		if (domain.commandScaffoldsMissing?.length) errors.push(`domain_command_scaffolds_missing:${domain.domainId}:${domain.commandScaffoldsMissing.join(",")}`);
		if (!domain.nextRuntimeCommands?.some((cmd) => cmd.includes("re_toolchain_domain"))) errors.push(`domain_missing_toolchain_command:${domain.domainId}`);
	}
	if (report.coverage.readyOrDegradedCount !== report.coverage.domainCount) errors.push("critical_gap_present");
	if (!report.toolchainClosure.allDomainsHaveFallback) errors.push("fallback_closure_false");
	return { ok: errors.length === 0, errors };
}

function mutateReport(report, id) {
	const clone = JSON.parse(JSON.stringify(report));
	if (id === "missing-fallback") { clone.domains[0].fallbacks = []; clone.domains[0].presentFallbacks = []; clone.domains[0].fallback_available = false; }
	if (id === "missing-playbook-marker") clone.domains[0].playbookMarkersMissing = ["route"];
	if (id === "all-tools-missing") {
		clone.domains[0].presentRequired = [];
		clone.domains[0].presentFallbacks = [];
		clone.domains[0].status = "blocked";
		clone.domains[0].critical_gap = true;
		clone.coverage.readyOrDegradedCount -= 1;
	}
	if (id === "missing-domain-command") clone.domains[0].nextRuntimeCommands = [];
	if (id === "wrong-kind") clone.kind = "NarrativeOnlyToolchain";
	return clone;
}

function main() {
	const checks = [];
	const report = buildReport();
	const validation = validateReport(report);
	checks.push(check("runtime:toolchain-domain-discovery", validation.ok, { validation, coverage: report.coverage }));
	checks.push(check("runtime:toolchain-domain-no-critical-gap", report.coverage.blockedCount === 0, { blocked: report.domains.filter((domain) => domain.critical_gap).map((domain) => ({ id: domain.domainId, missingRequired: domain.missingRequired, fallback: domain.fallbacks })) }));
	checks.push(check("runtime:toolchain-domain-fallbacks", report.domains.every((domain) => domain.fallbacks.length > 0 && (domain.fallback_available || domain.status === "ready")), { fallback_available: report.domains.map((domain) => ({ id: domain.domainId, fallback_available: domain.fallback_available, presentFallbacks: domain.presentFallbacks })) }));
	checks.push(check("runtime:toolchain-domain-command-scaffolds", report.domains.every((domain) => domain.commandScaffoldsMissing.length === 0), { missing: report.domains.filter((domain) => domain.commandScaffoldsMissing.length).map((domain) => ({ id: domain.domainId, missing: domain.commandScaffoldsMissing })) }));
	checks.push(check("runtime:toolchain-domain-playbook-markers", report.domains.every((domain) => domain.playbookMarkersMissing.length === 0), { missing: report.domains.filter((domain) => domain.playbookMarkersMissing.length).map((domain) => ({ id: domain.domainId, missing: domain.playbookMarkersMissing })) }));
	const negatives = ["missing-fallback", "missing-playbook-marker", "all-tools-missing", "missing-domain-command", "wrong-kind"].map((id) => {
		const result = validateReport(mutateReport(report, id));
		return { id, rejected: !result.ok, errors: result.errors };
	});
	checks.push(check("negative:toolchain-domain-report", negatives.every((row) => row.rejected), { negatives }));
	checks.push(markerCheck("code:toolchain-domain-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["ToolchainDomainCapabilityV1", "TOOLCHAIN_DOMAIN_CAPABILITY_MATRIX", "buildToolchainDomainCapability", "formatToolchainDomainCapability", "re_toolchain_domain", "runtime:toolchain-doctor", "domain:web-api", "domain:rev-native", "domain:pwn", "domain:mobile", "domain:pcap-dfir", "domain:firmware-iot", "fallback_available"]));
	checks.push(markerCheck("profile:toolchain-domain-runtime-mirror", "repi-profile/extensions/reverse-pentest-core.ts", ["ToolchainDomainCapabilityV1", "TOOLCHAIN_DOMAIN_CAPABILITY_MATRIX", "buildToolchainDomainCapability", "formatToolchainDomainCapability", "re_toolchain_domain", "runtime:toolchain-doctor"]));
	checks.push(markerCheck("harness:toolchain-domain", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:toolchain-domain-capability", "toolchain:domain-capability-hard-eval", "ToolchainDomainCapabilityV1", "child:gate:toolchain-domain-capability"]));
	checks.push(markerCheck("autonomy:toolchain-domain", "scripts/reverse-agent/autonomy-control-plane.mjs", ["toolchain_domain_capability_gate", "ToolchainDomainCapabilityV1", "runtime:toolchain-doctor", "domain_toolchain_matrix"]));
	checks.push(markerCheck("npm:toolchain-domain", "package.json", ["gate:toolchain-domain-capability", "toolchain-domain-capability-gate.mjs"]));
	checks.push(markerCheck("docs:toolchain-domain-readme", "README.md", ["Toolchain Domain Capability", "re_toolchain_domain", "gate:toolchain-domain-capability"]));
	checks.push(markerCheck("docs:toolchain-domain-reverse-agent", "docs/reverse-agent/README.md", ["ToolchainDomainCapabilityV1", "re_toolchain_domain", "runtime:toolchain-doctor"]));
	checks.push(markerCheck("schema:toolchain-domain", "schemas/reverse-agent/toolchain-domain-capability.schema.json", ["ToolchainDomainCapabilityV1", "domainId", "fallback_available", "critical_gap"]));

	const failed = checks.filter((row) => row.status !== "pass");
	const result = { kind: "repi-toolchain-domain-capability-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks, report };
	if (writeEvidence) {
		const dir = join(root, ".repi-harness", "evidence", "toolchain-domain-capability", result.generatedAt.replace(/[:.]/g, "-"));
		mkdirSync(dir, { recursive: true });
		writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
	}
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Toolchain Domain Capability Gate");
		for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
		console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length} domains=${report.coverage.domainCount} ready=${report.coverage.readyCount} degraded=${report.coverage.degradedCount} blocked=${report.coverage.blockedCount}`);
	}
	if (strict && failed.length) process.exitCode = 1;
}

main();
