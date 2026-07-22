import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

let root;
let noWrite;
let writePrivate;
let redact;
let shortHash;
let bufferSha256;
let readJsonArtifact;
let shellQuote;
let run;
let slug;

export function configureEngageProofRuntime(runtime) {
	({ root, noWrite, writePrivate, redact, shortHash, bufferSha256, readJsonArtifact, shellQuote, run, slug } = runtime);
}
function proofArtifactPath(artifactDir, relPath) {
	return join(artifactDir, relPath);
}

function proofArtifactExists(artifactDir, relPath) {
	return existsSync(proofArtifactPath(artifactDir, relPath));
}

function proofArtifactRow(artifactDir, relPath, role, expectedMode) {
	const path = proofArtifactPath(artifactDir, relPath);
	return {
		id: slug(relPath),
		role,
		path,
		relPath,
		expectedMode,
		minBytes: 1,
	};
}

function buildProofArtifactRows(targetInfo, artifactDir) {
	const candidates = [];
	const add = (relPath, role, expectedMode = 0o600) => {
		if (proofArtifactExists(artifactDir, relPath)) candidates.push(proofArtifactRow(artifactDir, relPath, role, expectedMode));
	};
	if (targetInfo.kind === "url") {
		for (const relPath of [
			"web-security-posture.json",
			"web-discovery-matrix.json",
			"web-api-schema-probes.json",
			"web-replay-matrix.json",
			"web-identity-jwt.json",
			"web-ssrf-matrix.json",
			"web-redirect-matrix.json",
			"web-cors-matrix.json",
			"web-object-matrix.json",
			"web-runtime-capture-plan.json",
			"web-runtime-replay-plan.json",
			"web-signer-rebuild-workbench-plan.json",
			"web-js-signature-control-plan.json",
			"web-exploit-claims.json",
			"web-exploit-verification.json",
			"web-js-sourcemap-summary.json",
			"web-runtime-replay-results.json",
		]) add(relPath, "web/API runtime evidence");
		add("web-runtime-capture-harness.mjs", "browser runtime capture harness", 0o700);
		add("web-runtime-replay-verifier.mjs", "browser replay negative-control verifier", 0o700);
		add("web-signer-rebuild-workbench.mjs", "JS signer byte-for-byte workbench", 0o700);
		add("web-js-signature-control-harness.mjs", "JS signature negative-control harness", 0o700);
		add("web-exploit-verifier.mjs", "web exploit evidence verifier", 0o700);
	}
	if (targetInfo.kind === "directory") {
		add("workspace-source-runtime-map.json", "workspace source-to-runtime route/sink/auth map");
		add("workspace-source-runtime-verification.json", "workspace source-to-runtime verifier output");
		add("workspace-source-runtime-harness.mjs", "workspace source-to-runtime extraction harness", 0o700);
		add("workspace-source-runtime-verifier.mjs", "workspace source-to-runtime verifier", 0o700);
		add("workspace-route-replay-plan.json", "workspace route replay/authz matrix plan");
		add("workspace-route-replay-results.json", "workspace route replay/authz matrix output");
		add("workspace-route-claim-promotion.json", "workspace route replay claim-promotion ledger");
		add("workspace-route-repair-queue.json", "workspace route replay repair queue");
		add("workspace-source-runtime-claims.json", "workspace source-to-runtime exploit claim ledger");
		add("workspace-route-replay-harness.mjs", "workspace route replay/authz matrix harness", 0o700);
	}
	if (targetInfo.lane === "native-pwn") {
		add("native-elf-hardening.json", "ELF mitigation/import/relocation parser output");
		add("native-pe-quicklook.json", "PE mitigation/import parser output");
		add("native-macho-quicklook.json", "Mach-O load-command/symbol parser output");
		add("native-static-triage.json", "native static sink/gadget triage");
		add("native-exploit-hypotheses.json", "native exploit hypothesis matrix");
		add("native-runtime-verification.json", "native runtime replay/hash/negative-control verifier output");
		add("native-primitive-claims.json", "native primitive claim ledger and repair queue");
		add("native-replay-verifier.py", "native crash replay verifier", 0o700);
		add("native-runtime-verifier.py", "native runtime proof verifier", 0o700);
		add("native-gdb-trace.gdb", "native debugger trace script");
		add("native-cyclic-payload.bin", "native cyclic proof payload");
		add("native-cyclic-offset.py", "native cyclic offset helper", 0o700);
	}
	if (targetInfo.lane === "js-reverse") {
		add("js-reverse-workbench.json", "local JS/WASM reverse workbench output");
		add("js-reverse-workbench.mjs", "local JS/WASM signer/API reverse harness", 0o700);
	}
	if (targetInfo.lane === "mobile" || targetInfo.lane === "mobile-ios") {
		add("mobile-archive-summary.json", "mobile archive manifest/plist/dex quicklook");
		add("mobile-archive-verification.json", "mobile archive entry/hash verifier output");
		add("mobile-attack-surface-claims.json", "mobile manifest/plist/dex runtime claim ledger");
		add("mobile-archive-verifier.py", "mobile archive verification harness", 0o700);
		add("mobile-frida-hooks.js", "mobile runtime hook harness", 0o700);
	}
	if (targetInfo.lane === "pcap-dfir") {
		add("pcap-flow-summary.json", "packet/flow/TCP/HTTP/DNS/TLS quicklook");
		add("pcap-flow-verification.json", "PCAP capture/object/flow verifier output");
		add("pcap-flow-claims.json", "PCAP flow/credential/object claim ledger");
		add("pcap-http-objects.json", "PCAP HTTP object carve manifest");
		add("pcap-flow-verifier.mjs", "PCAP capture/object verification harness", 0o700);
		add("pcap-http-object-verifier.py", "PCAP object verifier", 0o700);
	}
	if (targetInfo.lane === "memory-forensics") {
		add("memory-quicklook.json", "memory forensic quicklook/correlation output");
		add("memory-evidence-verification.json", "memory signal/correlation offset verifier output");
		add("memory-evidence-claims.json", "memory process/network/credential correlation claim ledger");
		add("memory-evidence-verifier.py", "memory signal/correlation verification harness", 0o700);
		add("memory-triage-plan.sh", "memory forensic triage harness", 0o700);
	}
	if (targetInfo.lane === "windows-ad") {
		add("windows-ad-quicklook.json", "Windows/AD identity quicklook output");
		add("windows-ad-verification.json", "Windows/AD file/hash/path verifier output");
		add("windows-ad-attack-paths.json", "Windows/AD BloodHound owned-to-high-value attack path claims");
		add("windows-ad-verifier.py", "Windows/AD evidence verifier", 0o700);
		add("windows-ad-triage-plan.sh", "Windows/AD triage harness", 0o700);
	}
	if (targetInfo.lane === "malware") {
		add("malware-quicklook.json", "malware IOC/capability quicklook output");
		add("malware-config-verification.json", "malware static IOC/config/overlay verifier output");
		add("malware-behavior-claims.json", "malware IOC/config/capability claim ledger");
		add("malware-config-verifier.py", "malware IOC/config/overlay verification harness", 0o700);
		add("malware-triage-plan.sh", "malware triage harness", 0o700);
	}
	if (targetInfo.lane === "firmware-iot") {
		add("firmware-quicklook.json", "firmware structure/string/signature quicklook output");
		add("firmware-extraction-verification.json", "firmware signature/rootfs carve verifier output");
		add("firmware-attack-surface.json", "firmware rootfs/service/credential claim ledger");
		add("firmware-extraction-verifier.py", "firmware signature/rootfs carve verification harness", 0o700);
		add("firmware-extract-plan.sh", "firmware extraction harness", 0o700);
	}
	if (targetInfo.lane === "crypto-stego") {
		add("crypto-stego-media-quicklook.json", "crypto/stego media structure quicklook output");
		add("crypto-stego-verification.json", "crypto/stego file/offset verifier output");
		add("crypto-stego-transform-claims.json", "crypto/stego transform claim ledger");
		add("crypto-stego-verifier.py", "crypto/stego structure verifier harness", 0o700);
		add("crypto-stego-solver.py", "crypto/stego transform-chain solver harness", 0o700);
	}
	if (targetInfo.lane === "agent-boundary") {
		add("agent-boundary-map.json", "agent prompt/tool boundary evidence map");
		add("agent-boundary-replay-results.json", "agent boundary runtime replay/self-test output");
		add("agent-boundary-verification.json", "agent boundary map/replay verifier output");
		add("agent-boundary-claim-promotion.json", "agent boundary replay claim-promotion ledger");
		add("agent-boundary-repair-queue.json", "agent boundary replay repair queue");
		add("agent-boundary-verifier.py", "agent boundary verification harness", 0o700);
		add("agent-boundary-payloads.py", "agent boundary replay payload harness", 0o700);
	}
	if (targetInfo.lane === "cloud-identity") {
		add("cloud-identity-map.json", "cloud/container identity trust-chain map");
		add("cloud-identity-verification.json", "cloud identity source-line verifier output");
		add("cloud-identity-trust-claims.json", "cloud/container identity trust-chain claim ledger");
		add("cloud-identity-verifier.py", "cloud identity source-line verifier", 0o700);
		add("cloud-identity-verify.sh", "cloud identity verification harness", 0o700);
	}
	add("repi-proof-graph.json", "unified proof graph and runtime repair loop");
	add("repi-runtime-repair-loop.mjs", "runtime repair-loop planner/executor", 0o700);
	return candidates;
}

function buildProofCoverageGaps(targetInfo, artifactRows) {
	const present = new Set(artifactRows.map((row) => row.relPath));
	const gaps = [];
	const requireAny = (id, relPaths, reason) => {
		if (!relPaths.some((relPath) => present.has(relPath))) gaps.push({ id, reason, expectedAnyOf: relPaths });
	};
	if (targetInfo.kind === "url") {
		requireAny("web-runtime-replay", ["web-exploit-verification.json", "web-exploit-verifier.mjs", "web-runtime-replay-verifier.mjs", "web-replay-matrix.json"], "web targets need replayable HTTP/browser evidence and verifier-bound hash gates");
		requireAny("web-route-matrix", ["web-exploit-claims.json", "web-api-schema-probes.json", "web-discovery-matrix.json", "web-object-matrix.json"], "web targets need route/schema/object matrix evidence");
	}
	if (targetInfo.kind === "directory") requireAny("workspace-source-runtime-map", ["workspace-source-runtime-verification.json", "workspace-source-runtime-verifier.mjs", "workspace-source-runtime-claims.json", "workspace-source-runtime-map.json", "workspace-source-runtime-harness.mjs"], "workspace targets need source-to-runtime route/sink/auth evidence");
	if (targetInfo.lane === "native-pwn") requireAny("native-replay", ["native-runtime-verification.json", "native-primitive-claims.json", "native-runtime-verifier.py", "native-replay-verifier.py", "native-exploit-hypotheses.json", "native-static-triage.json"], "native targets need replay/triage/hypothesis/verifier artifacts");
	if (targetInfo.lane === "js-reverse") requireAny("js-reverse-workbench", ["js-reverse-workbench.json", "js-reverse-workbench.mjs", "workspace-source-runtime-map.json"], "JS reverse targets need local signer/API/workspace evidence artifacts");
	if (targetInfo.lane === "pcap-dfir") requireAny("pcap-flow-summary", ["pcap-flow-claims.json", "pcap-flow-verification.json", "pcap-flow-verifier.mjs", "pcap-flow-summary.json"], "PCAP targets need parsed flow/stream verifier evidence");
	if (targetInfo.lane === "crypto-stego") requireAny("crypto-transform-solver", ["crypto-stego-verification.json", "crypto-stego-verifier.py", "crypto-stego-transform-claims.json", "crypto-stego-solver.py", "crypto-stego-media-quicklook.json"], "crypto/stego targets need a transform-chain verifier or media structure proof");
	if (targetInfo.lane === "mobile" || targetInfo.lane === "mobile-ios") requireAny("mobile-runtime-hook", ["mobile-archive-verification.json", "mobile-archive-verifier.py", "mobile-attack-surface-claims.json", "mobile-frida-hooks.js", "mobile-archive-summary.json"], "mobile targets need archive/runtime hook anchors");
	if (targetInfo.lane === "firmware-iot") requireAny("firmware-extract-plan", ["firmware-attack-surface.json", "firmware-extraction-verification.json", "firmware-extraction-verifier.py", "firmware-extract-plan.sh", "firmware-quicklook.json"], "firmware targets need structure/extraction verifier anchors");
	if (targetInfo.lane === "memory-forensics") requireAny("memory-triage-plan", ["memory-evidence-claims.json", "memory-evidence-verification.json", "memory-evidence-verifier.py", "memory-triage-plan.sh", "memory-quicklook.json"], "memory targets need triage/correlation verifier anchors");
	if (targetInfo.lane === "windows-ad") requireAny("windows-ad-triage-plan", ["windows-ad-verification.json", "windows-ad-verifier.py", "windows-ad-attack-paths.json", "windows-ad-triage-plan.sh", "windows-ad-quicklook.json"], "identity targets need AD graph/credential triage anchors");
	if (targetInfo.lane === "malware") requireAny("malware-triage-plan", ["malware-behavior-claims.json", "malware-config-verification.json", "malware-config-verifier.py", "malware-triage-plan.sh", "malware-quicklook.json"], "malware targets need IOC/capability triage and verifier anchors");
	if (targetInfo.lane === "agent-boundary") requireAny("agent-boundary-replay", ["agent-boundary-verification.json", "agent-boundary-verifier.py", "agent-boundary-payloads.py", "agent-boundary-map.json"], "agent-boundary targets need replay payloads and flow map");
	if (targetInfo.lane === "cloud-identity") requireAny("cloud-identity-verify", ["cloud-identity-verification.json", "cloud-identity-verifier.py", "cloud-identity-trust-claims.json", "cloud-identity-verify.sh", "cloud-identity-map.json"], "cloud targets need trust-chain verification anchors");
	return gaps;
}

function buildProofLiveChecks(targetInfo, artifactDir, toolState) {
	const available = new Set(toolState.filter((row) => row.available).map((row) => row.tool));
	const checks = [];
	const add = (row) => checks.push({ timeoutMs: 20_000, destructive: false, selfTest: true, ...row });
	const python = available.has("python3") ? "python3" : available.has("python") ? "python" : undefined;
	if (targetInfo.kind === "url") {
		const replayVerifier = proofArtifactPath(artifactDir, "web-runtime-replay-verifier.mjs");
		if (existsSync(replayVerifier)) add({ id: "web-runtime-replay-verifier-self-test", command: process.execPath, args: [replayVerifier, "--self-test"], reason: "execute browser replay verifier self-test with negative controls" });
		const signerWorkbench = proofArtifactPath(artifactDir, "web-signer-rebuild-workbench.mjs");
		if (existsSync(signerWorkbench)) add({ id: "web-signer-rebuild-workbench-self-test", command: process.execPath, args: [signerWorkbench, "--self-test"], reason: "execute signer rebuild regression self-test" });
		const signatureHarness = proofArtifactPath(artifactDir, "web-js-signature-control-harness.mjs");
		if (existsSync(signatureHarness)) add({ id: "web-js-signature-control-harness-smoke", command: process.execPath, args: [signatureHarness], reason: "execute JS signature-control harness plan smoke" });
		const exploitVerifier = proofArtifactPath(artifactDir, "web-exploit-verifier.mjs");
		if (existsSync(exploitVerifier)) add({ id: "web-exploit-verifier-self-test", command: process.execPath, args: [exploitVerifier, "--self-test"], reason: "execute web exploit evidence verifier self-test with hash and mutation controls" });
	}
	if (targetInfo.lane === "js-reverse") {
		const jsWorkbench = proofArtifactPath(artifactDir, "js-reverse-workbench.mjs");
		if (existsSync(jsWorkbench)) add({ id: "js-reverse-workbench-self-test", command: process.execPath, args: [jsWorkbench, "--self-test"], reason: "execute local JS reverse workbench self-test" });
	}
	if (targetInfo.lane === "pcap-dfir") {
		const pcapFlowVerifier = proofArtifactPath(artifactDir, "pcap-flow-verifier.mjs");
		if (existsSync(pcapFlowVerifier)) add({ id: "pcap-flow-verifier-self-test", command: process.execPath, args: [pcapFlowVerifier, "--self-test"], reason: "execute PCAP flow verifier self-test with capture/object mutation controls" });
	}
	if (targetInfo.kind === "directory") {
		const workspaceHarness = proofArtifactPath(artifactDir, "workspace-source-runtime-harness.mjs");
		if (existsSync(workspaceHarness)) add({ id: "workspace-source-runtime-harness-self-test", command: process.execPath, args: [workspaceHarness, "--self-test"], reason: "execute workspace source-to-runtime harness self-test" });
		const routeReplayHarness = proofArtifactPath(artifactDir, "workspace-route-replay-harness.mjs");
		if (existsSync(routeReplayHarness)) add({ id: "workspace-route-replay-harness-self-test", command: process.execPath, args: [routeReplayHarness, "--self-test"], reason: "execute workspace route replay/authz harness self-test" });
		const workspaceVerifier = proofArtifactPath(artifactDir, "workspace-source-runtime-verifier.mjs");
		if (existsSync(workspaceVerifier)) add({ id: "workspace-source-runtime-verifier-self-test", command: process.execPath, args: [workspaceVerifier, "--self-test"], reason: "execute workspace source-to-runtime verifier self-test with repair gates" });
	}
	const runtimeRepairLoop = proofArtifactPath(artifactDir, "repi-runtime-repair-loop.mjs");
	if (existsSync(runtimeRepairLoop)) add({ id: "repi-runtime-repair-loop-self-test", command: process.execPath, args: [runtimeRepairLoop, "--self-test"], reason: "execute unified runtime repair-loop planner self-test" });
	if (targetInfo.lane === "native-pwn" && python) {
		const offsetHelper = proofArtifactPath(artifactDir, "native-cyclic-offset.py");
		const payloadPath = proofArtifactPath(artifactDir, "native-cyclic-payload.bin");
		if (existsSync(offsetHelper) && existsSync(payloadPath)) {
			let needleHex = "";
			try {
				needleHex = readFileSync(payloadPath).subarray(30, 34).toString("hex");
			} catch {
				needleHex = "";
			}
			if (needleHex) add({ id: "native-cyclic-offset-self-test", command: python, args: [offsetHelper, `hex:${needleHex}`], reason: "execute cyclic offset helper against generated cyclic payload" });
		}
		const verifier = proofArtifactPath(artifactDir, "native-replay-verifier.py");
		if (existsSync(verifier)) {
			checks.push({
				id: "native-replay-verifier-live",
				command: python,
				args: [verifier, targetInfo.representativePath || targetInfo.path || targetInfo.target],
				timeoutMs: 20_000,
				destructive: false,
				selfTest: false,
				reason: "live native replay; intentionally operator-triggered with --execute",
			});
		}
		const runtimeVerifier = proofArtifactPath(artifactDir, "native-runtime-verifier.py");
		if (existsSync(runtimeVerifier)) {
			add({ id: "native-runtime-verifier-self-test", command: python, args: [runtimeVerifier, "--self-test"], reason: "execute native runtime verifier self-test with replay and mutation controls" });
			checks.push({
				id: "native-runtime-verifier-live",
				command: python,
				args: [runtimeVerifier, targetInfo.representativePath || targetInfo.path || targetInfo.target, artifactDir, proofArtifactPath(artifactDir, "native-runtime-verification.json")],
				timeoutMs: 30_000,
				destructive: false,
				selfTest: false,
				reason: "live native runtime proof replay; intentionally operator-triggered with --execute",
			});
		}
	}
	if (python) {
		for (const [id, relPath, reason] of [
			["native-runtime-verifier-pycompile", "native-runtime-verifier.py", "syntax-check native runtime verifier"],
			["pcap-http-object-verifier-pycompile", "pcap-http-object-verifier.py", "syntax-check PCAP object verifier"],
			["crypto-stego-verifier-pycompile", "crypto-stego-verifier.py", "syntax-check crypto/stego verifier"],
			["crypto-stego-solver-pycompile", "crypto-stego-solver.py", "syntax-check crypto/stego solver harness"],
			["mobile-archive-verifier-pycompile", "mobile-archive-verifier.py", "syntax-check mobile archive verifier"],
			["agent-boundary-verifier-pycompile", "agent-boundary-verifier.py", "syntax-check agent boundary verifier"],
			["agent-boundary-payloads-pycompile", "agent-boundary-payloads.py", "syntax-check agent boundary payload harness"],
			["cloud-identity-verifier-pycompile", "cloud-identity-verifier.py", "syntax-check cloud identity verifier"],
			["windows-ad-verifier-pycompile", "windows-ad-verifier.py", "syntax-check Windows/AD verifier"],
			["memory-evidence-verifier-pycompile", "memory-evidence-verifier.py", "syntax-check memory evidence verifier"],
			["malware-config-verifier-pycompile", "malware-config-verifier.py", "syntax-check malware config verifier"],
			["firmware-extraction-verifier-pycompile", "firmware-extraction-verifier.py", "syntax-check firmware extraction verifier"],
		]) {
			const path = proofArtifactPath(artifactDir, relPath);
			if (existsSync(path)) add({ id, command: python, args: ["-m", "py_compile", path], reason });
		}
		const agentBoundaryPayloads = proofArtifactPath(artifactDir, "agent-boundary-payloads.py");
		if (existsSync(agentBoundaryPayloads)) add({ id: "agent-boundary-payloads-self-test", command: python, args: [agentBoundaryPayloads, "--self-test"], reason: "execute agent boundary replay harness self-test with unsafe/control payloads" });
		const agentBoundaryVerifier = proofArtifactPath(artifactDir, "agent-boundary-verifier.py");
		if (existsSync(agentBoundaryVerifier)) add({ id: "agent-boundary-verifier-self-test", command: python, args: [agentBoundaryVerifier, "--self-test"], reason: "execute agent boundary verifier self-test with replay negative controls" });
		const cryptoVerifier = proofArtifactPath(artifactDir, "crypto-stego-verifier.py");
		if (existsSync(cryptoVerifier)) add({ id: "crypto-stego-verifier-self-test", command: python, args: [cryptoVerifier, "--self-test"], reason: "execute crypto/stego verifier self-test with offset/hash negative controls" });
		const mobileVerifier = proofArtifactPath(artifactDir, "mobile-archive-verifier.py");
		if (existsSync(mobileVerifier)) add({ id: "mobile-archive-verifier-self-test", command: python, args: [mobileVerifier, "--self-test"], reason: "execute mobile archive verifier self-test with ZIP entry negative controls" });
		const cloudIdentityVerifier = proofArtifactPath(artifactDir, "cloud-identity-verifier.py");
		if (existsSync(cloudIdentityVerifier)) add({ id: "cloud-identity-verifier-self-test", command: python, args: [cloudIdentityVerifier, "--self-test"], reason: "execute cloud identity verifier self-test with source-line negative controls" });
		const windowsAdVerifier = proofArtifactPath(artifactDir, "windows-ad-verifier.py");
		if (existsSync(windowsAdVerifier)) add({ id: "windows-ad-verifier-self-test", command: python, args: [windowsAdVerifier, "--self-test"], reason: "execute Windows/AD verifier self-test with BloodHound negative controls" });
		const memoryVerifier = proofArtifactPath(artifactDir, "memory-evidence-verifier.py");
		if (existsSync(memoryVerifier)) add({ id: "memory-evidence-verifier-self-test", command: python, args: [memoryVerifier, "--self-test"], reason: "execute memory evidence verifier self-test with offset/correlation negative controls" });
		const malwareVerifier = proofArtifactPath(artifactDir, "malware-config-verifier.py");
		if (existsSync(malwareVerifier)) add({ id: "malware-config-verifier-self-test", command: python, args: [malwareVerifier, "--self-test"], reason: "execute malware config verifier self-test with offset/hash negative controls" });
		const firmwareVerifier = proofArtifactPath(artifactDir, "firmware-extraction-verifier.py");
		if (existsSync(firmwareVerifier)) add({ id: "firmware-extraction-verifier-self-test", command: python, args: [firmwareVerifier, "--self-test"], reason: "execute firmware extraction verifier self-test with signature/carve negative controls" });
	}
	if (available.has("bash")) {
		for (const [id, relPath, reason] of [
			["memory-triage-plan-shellcheck", "memory-triage-plan.sh", "syntax-check memory triage harness"],
			["windows-ad-triage-plan-shellcheck", "windows-ad-triage-plan.sh", "syntax-check Windows/AD triage harness"],
			["malware-triage-plan-shellcheck", "malware-triage-plan.sh", "syntax-check malware triage harness"],
			["firmware-extract-plan-shellcheck", "firmware-extract-plan.sh", "syntax-check firmware extraction harness"],
			["cloud-identity-verify-shellcheck", "cloud-identity-verify.sh", "syntax-check cloud identity verifier"],
		]) {
			const path = proofArtifactPath(artifactDir, relPath);
			if (existsSync(path)) add({ id, command: "bash", args: ["-n", path], reason });
		}
	}
	const mobileHook = proofArtifactPath(artifactDir, "mobile-frida-hooks.js");
	if (existsSync(mobileHook)) add({ id: "mobile-frida-hook-syntax", command: process.execPath, args: ["--check", mobileHook], reason: "syntax-check mobile Frida hook harness" });
	return checks;
}

function proofHarnessSource(plan) {
	const planJson = JSON.stringify(plan, null, 2);
	return `#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";

const plan = ${planJson};
const execute = process.argv.includes("--execute");
const selfTest = process.argv.includes("--self-test") || !execute;

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function redact(value) {
	return String(value ?? "")
		.replace(/\\bsk-[A-Za-z0-9._-]{8,}\\b/g, "<redacted:api-key>")
		.replace(/\\bBearer\\s+[A-Za-z0-9._~+/=-]{8,}/gi, "Bearer <redacted>")
		.replace(/([?&](?:api[_-]?key|token|access_token|refresh_token|client_secret|secret|password)=)[^&\\s"'<>]{4,}/gi, "$1<redacted>")
		.replace(/((?:authorization|x-api-key|api-key|cookie|set-cookie)\\s*[:=]\\s*["']?)([^"'\\n;]{4,})/gi, "$1<redacted>");
}

function checkArtifact(row) {
	if (!existsSync(row.path)) return { ...row, ok: false, error: "missing" };
	const stat = statSync(row.path);
	const data = readFileSync(row.path);
	const mode = stat.mode & 0o777;
	const modeOk = typeof row.expectedMode !== "number" || mode === row.expectedMode;
	const sizeOk = stat.size >= (row.minBytes ?? 1);
	return {
		id: row.id,
		role: row.role,
		relPath: row.relPath,
		ok: modeOk && sizeOk,
		size: stat.size,
		mode: "0o" + mode.toString(8),
		expectedMode: typeof row.expectedMode === "number" ? "0o" + row.expectedMode.toString(8) : null,
		sha256: sha256(data),
		error: modeOk ? (sizeOk ? undefined : "empty-or-too-small") : "mode-mismatch",
	};
}

function runLiveCheck(row) {
	const started = Date.now();
	const result = spawnSync(row.command, row.args || [], {
		cwd: row.cwd || plan.cwd,
		encoding: "utf8",
		timeout: row.timeoutMs || 20000,
		maxBuffer: 4 * 1024 * 1024,
		env: {
			...process.env,
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
		},
	});
	const stdout = redact(result.stdout || "");
	const stderr = redact(result.stderr || "");
	return {
		id: row.id,
		reason: row.reason,
		selfTest: row.selfTest !== false,
		destructive: Boolean(row.destructive),
		command: redact([row.command, ...(row.args || [])].join(" ")),
		exit: result.status ?? (result.signal ? 128 : 1),
		signal: result.signal,
		durationMs: Date.now() - started,
		ok: (result.status ?? (result.signal ? 128 : 1)) === 0,
		stdoutSha256: sha256(stdout),
		stderrSha256: sha256(stderr),
		stdoutSample: stdout.slice(0, 1200),
		stderrSample: stderr.slice(0, 1200),
		error: result.error ? redact(result.error.message || String(result.error)) : undefined,
	};
}

function main() {
	const artifactRows = (plan.artifacts || []).map(checkArtifact);
	const selectedChecks = (plan.liveChecks || []).filter((row) => execute || row.selfTest !== false);
	const liveRows = selectedChecks.map(runLiveCheck);
	const failedArtifacts = artifactRows.filter((row) => !row.ok);
	const failedLive = liveRows.filter((row) => !row.ok);
	const proofReady = failedArtifacts.length === 0 && failedLive.length === 0 && (artifactRows.length > 0 || liveRows.length > 0);
	const report = {
		kind: "repi-proof-harness-self-test",
		schemaVersion: 1,
		target: plan.target,
		lane: plan.lane,
		mode: execute ? "execute" : selfTest ? "self-test" : "plan",
		proofReady,
		artifactCheckCount: artifactRows.length,
		liveCheckCount: liveRows.length,
		coverageGaps: plan.coverageGaps || [],
		artifactRows,
		liveRows,
		next: execute
			? "Use failed rows as repair targets; successful rows are claim-ready proof anchors."
			: "Run this harness with --execute only after reviewing the live checks; --self-test stays local/non-destructive.",
	};
	console.log(JSON.stringify(report, null, 2));
	process.exit(proofReady ? 0 : 1);
}

main();
`;
}

export function proofHarnessRows(targetInfo, artifactDir, commands, toolState) {
	if (noWrite || !artifactDir) return [];
	const artifacts = buildProofArtifactRows(targetInfo, artifactDir);
	const liveChecks = buildProofLiveChecks(targetInfo, artifactDir, toolState);
	if (!artifacts.length && !liveChecks.length) return [];
	const planPath = join(artifactDir, "proof-matrix.json");
	const harnessPath = join(artifactDir, "proof-harness.mjs");
	const plan = {
		kind: "repi-proof-harness-plan",
		schemaVersion: 1,
		target: redact(targetInfo.target),
		lane: targetInfo.lane,
		domain: targetInfo.domain,
		cwd: root,
		artifactDir,
		generatedAt: new Date().toISOString(),
		commandIds: commands.map((row) => row.id),
		artifacts: artifacts.map((row) => ({ ...row, path: row.path })),
		coverageGaps: buildProofCoverageGaps(targetInfo, artifacts),
		liveChecks: liveChecks.map((row) => ({ ...row, cwd: row.cwd ?? root })),
		proofExitRules: [
			"Every promoted claim must bind to an artifact sha256 or live check row from this matrix.",
			"Self-test rows validate harness syntax/local invariants; --execute rows are operator-triggered live proof replays.",
			"Negative controls and replay/hash differentials outrank static signatures; policy gaps are not exploit proof.",
		],
	};
	const harness = proofHarnessSource(plan);
	writePrivate(planPath, `${JSON.stringify(plan, null, 2)}\n`, 0o600);
	writePrivate(harnessPath, harness, 0o700);
	const rows = [
		{
			id: "proof-harness-plan",
			command: "internal",
			args: [redact(planPath), redact(harnessPath)],
			cwd: root,
			exit: 0,
			signal: null,
			durationMs: 0,
			stdout: `${JSON.stringify(
				{
					...plan,
					artifacts: plan.artifacts.map((row) => ({ ...row, path: redact(row.path) })),
					liveChecks: plan.liveChecks.map((row) => ({ ...row, command: redact(row.command), args: row.args.map((arg) => redact(arg)) })),
					planPath: redact(planPath),
					harnessPath: redact(harnessPath),
				},
				null,
				2,
			)}\n`,
			stderr: "",
			error: undefined,
		},
		run(process.execPath, [harnessPath, "--self-test"], { id: "proof-harness-self-test", timeout: 30_000 }),
	];
	return rows;
}

const unifiedProofGraphArtifactCandidates = [
	"web-exploit-claims.json",
	"web-exploit-verification.json",
	"workspace-source-runtime-verification.json",
	"workspace-source-runtime-claims.json",
	"workspace-route-claim-promotion.json",
	"workspace-route-repair-queue.json",
	"native-runtime-verification.json",
	"native-primitive-claims.json",
	"crypto-stego-verification.json",
	"crypto-stego-transform-claims.json",
	"mobile-archive-verification.json",
	"mobile-attack-surface-claims.json",
	"pcap-flow-verification.json",
	"pcap-flow-claims.json",
	"memory-evidence-verification.json",
	"memory-evidence-claims.json",
	"windows-ad-verification.json",
	"windows-ad-attack-paths.json",
	"malware-config-verification.json",
	"malware-behavior-claims.json",
	"firmware-extraction-verification.json",
	"firmware-attack-surface.json",
	"agent-boundary-verification.json",
	"agent-boundary-claim-promotion.json",
	"agent-boundary-repair-queue.json",
	"cloud-identity-verification.json",
	"cloud-identity-trust-claims.json",
];

function proofGraphRedactJson(value, depth = 0) {
	if (value == null || typeof value === "number" || typeof value === "boolean") return value;
	if (typeof value === "string") return redact(value).slice(0, 1400);
	if (depth >= 6) return `<truncated-depth:${depth}>`;
	if (Array.isArray(value)) return value.slice(0, 80).map((item) => proofGraphRedactJson(item, depth + 1));
	if (typeof value === "object") {
		const out = {};
		for (const [key, row] of Object.entries(value).slice(0, 80)) out[redact(key).slice(0, 160)] = proofGraphRedactJson(row, depth + 1);
		return out;
	}
	return redact(String(value));
}

function proofGraphArray(value) {
	return Array.isArray(value) ? value : [];
}

function proofGraphClaimRows(parsed) {
	return proofGraphArray(parsed?.claimLedger).slice(0, 240);
}

function proofGraphComposedPathRows(parsed) {
	const rows = [];
	for (const row of [...proofGraphArray(parsed?.composedPaths), ...proofGraphArray(parsed?.promotionReport?.composedPaths)]) {
		if (!row?.id && !row?.claimType) continue;
		const key = row.id || `${row.claimType}:${shortHash(JSON.stringify(row))}`;
		if (rows.some((existing) => (existing.id || `${existing.claimType}:${shortHash(JSON.stringify(existing))}`) === key)) continue;
		rows.push(row);
		if (rows.length >= 120) break;
	}
	return rows;
}

function proofGraphRepairRows(parsed) {
	if (Array.isArray(parsed?.repairQueue)) return parsed.repairQueue.slice(0, 240);
	if (Array.isArray(parsed?.repairQueue?.queue)) return parsed.repairQueue.queue.slice(0, 240);
	if (Array.isArray(parsed?.queue)) return parsed.queue.slice(0, 240);
	return [];
}

function proofGraphRepairPriority(blocker) {
	if (/missing-base-url|no-live-response|no-status|service|unreachable|endpoint/i.test(blocker)) return "high";
	if (/missing-session|credential|authorization|cookie|token|principal/i.test(blocker)) return "high";
	if (/missing-web-(?:artifact-hash|replay-hash|risk-matrix|runtime-negative-control|live-runtime-replay|composed-path|verifier-negative-control)/i.test(blocker)) return "high";
	if (/missing-pcap-(?:capture-hash|quicklook-determinism|credential-signal|reassembly-hash|dns-tunnel|object-artifact|verifier-negative-control)/i.test(blocker)) return "high";
	if (/missing-native-(?:target-hash|replay-case|crash-differential|cyclic-payload|runtime-negative-control)/i.test(blocker)) return "high";
	if (/missing-crypto-(?:file-hash|media-determinism|structure-offset|negative-control)/i.test(blocker)) return "high";
	if (/missing-mobile-(?:archive-hash|zip-entry|dex-quicklook|manifest|hook|negative-control)/i.test(blocker)) return "high";
	if (/missing-agent-boundary-(?:map-flow|replay-coverage|response-hash|negative-control)/i.test(blocker)) return "high";
	if (/missing-workspace-(?:source-line|route-template|replay-gate|repair-queue|live-route-replay|negative-control)/i.test(blocker)) return "high";
	if (/missing-cloud-(?:source-line|trust-claim|composed-path|negative-control)/i.test(blocker)) return "high";
	if (/missing-windows-ad-(?:file-hash|bloodhound-path|signal-coverage|composed-path|negative-control)/i.test(blocker)) return "high";
	if (/missing-memory-(?:image-hash|signal-offset|process-network|credential-context|timeline|negative-control)/i.test(blocker)) return "high";
	if (/missing-(?:ioc-offset|config-extraction|overlay-carve|sample-hash|import-parser|network-ioc-negative-control)/i.test(blocker)) return "high";
	if (/missing-(?:firmware-image-hash|signature-offset|rootfs-carve|firmware-extraction-negative-control)|rootfs-carve-truncated/i.test(blocker)) return "high";
	if (/no-differential|object-mutation|baseline|negative-control|oracle/i.test(blocker)) return "medium";
	if (/missing-source|missing-.*map|missing-.*plan|missing-.*harness/i.test(blocker)) return "medium";
	return "normal";
}

function proofGraphRepairAction(blocker) {
	const actions = {
		"missing-base-url": "Start the target runtime and pass the exact base URL to the replay harness.",
		"no-live-response": "Fix endpoint/body/auth configuration until the runtime harness captures a response hash.",
		"no-status": "Fix reachability, route params, host binding, or timeout until an HTTP status is captured.",
		"no-differential": "Add negative controls or credentials until success/error/status/body hashes diverge.",
		"missing-session-credentials": "Provide a valid low/high privilege Cookie or Authorization value for replay.",
		"object-mutation-inconclusive": "Bind route parameters to owned and tampered objects before replay.",
		"baseline-not-accepted": "Make the benign baseline succeed before interpreting blocked malicious controls.",
		"no-boundary-differential": "Bind the payload to a stronger leak, tool side-effect, audit log, or blocked/refused oracle.",
		"missing-web-artifact-hash-verification": "Rerun web-exploit-verifier.mjs against the artifact directory and require size/SHA-256 equality for key web artifacts.",
		"missing-web-replay-hash-verification": "Regenerate web-replay-matrix.json until every replay row has HTTP status plus 64-hex responseSha256 evidence.",
		"missing-web-risk-matrix-coverage": "Collect schema/object/SSRF/redirect/CORS/JWT/posture/runtime matrix evidence and bind it to replay hashes.",
		"missing-web-runtime-negative-control": "Run browser runtime replay or signer controls so captured-signed succeeds while missing/tampered controls fail, or keep the proof path blocked.",
		"missing-web-live-runtime-replay-proof": "Run web-runtime-replay-verifier.mjs with a real web-runtime-capture.json and --live to capture status/body hashes for signature controls.",
		"missing-web-composed-path-verification": "Require every web composed-path segment to resolve to a promoted claim in web-exploit-claims.json.",
		"missing-web-verifier-negative-control": "Run missing-artifact, missing-replay-hash, mutated-segment, and runtime-gate controls before promotion.",
		"missing-ioc-offset-verification": "Rerun malware-config-verifier.py after binding each IOC to sourceOffset, valueSha256, and valueLength.",
		"missing-config-extraction-oracle": "Bind decoded malware config fields to a source offset/hash oracle before promotion.",
		"missing-overlay-carve-verifier": "Carve overlay bytes by offset/size and match SHA-256 before treating it as payload/config proof.",
		"missing-network-ioc-negative-control": "Add mismatch or mutated-offset controls so IOC matches also prove rejection behavior.",
		"missing-firmware-image-hash-verification": "Rerun firmware-extraction-verifier.py against original bytes and require size/SHA-256 equality.",
		"missing-signature-offset-verification": "Verify TRX/uImage/SquashFS/UBI signatures at exact offsets before carving.",
		"missing-rootfs-carve-verifier": "Produce a rootfs carve with offset, bounded size, header/magic, and SHA-256.",
		"rootfs-carve-truncated": "Acquire complete firmware/rootfs bytes or correct the requested carve size before full extraction claims.",
		"missing-firmware-extraction-negative-control": "Add mutated image/offset controls so bad firmware offsets and bytes are rejected.",
		"missing-memory-image-hash-verification": "Rerun memory-evidence-verifier.py against original bytes and require size/SHA-256 equality.",
		"missing-memory-signal-offset-verification": "Bind memory signal rows to sourceOffset/valueSha256/valueLength and rerun the verifier.",
		"missing-memory-process-network-verification": "Require source-bound command line and network offsets within the correlation window.",
		"missing-memory-credential-context-verification": "Tie credential bytes to source-bound process, command line, network, or file offsets.",
		"missing-memory-timeline-verification": "Bind timestamps to source-bound process/network offsets before claiming timeline proof.",
		"missing-memory-negative-control": "Add memory byte mutation controls so altered evidence hashes are rejected.",
		"missing-pcap-capture-hash-verification": "Rerun pcap-flow-verifier.mjs against original bytes and require capture size/SHA-256 equality.",
		"missing-pcap-quicklook-determinism": "Reparse the capture and resolve parser nondeterminism before promoting flow evidence.",
		"missing-pcap-credential-signal-verification": "Require credential signal hashes/lengths to reproduce from a fresh parse.",
		"missing-pcap-reassembly-hash-verification": "Require TCP stream payload hashes to reproduce from a fresh reassembly.",
		"missing-pcap-dns-tunnel-verification": "Require DNS tunnel label hashes/base-domain grouping to reproduce from a fresh parse.",
		"missing-pcap-object-artifact-verification": "Verify carved HTTP objects, archive entries, and decoded artifacts against manifest size/SHA-256.",
		"missing-pcap-verifier-negative-control": "Add capture/object byte mutation controls so altered evidence hashes are rejected.",
		"missing-native-target-hash-verification": "Rerun native-runtime-verifier.py against the original executable and require size/SHA-256/header/mode binding.",
		"missing-native-replay-case-verification": "Replay empty stdin, argv help/cyclic, format stdin, env marker, short stdin, and repeated cyclic cases.",
		"missing-native-crash-differential-verification": "Require repeated cyclic crashes with stable exit/signal and a non-crashing baseline control.",
		"missing-native-cyclic-payload-verification": "Regenerate native-cyclic-payload.bin and verify offset self-test binding with native-cyclic-offset.py.",
		"missing-native-runtime-negative-control": "Add target/payload mutation and benign-baseline controls before promoting exploit proof.",
		"missing-crypto-file-hash-verification": "Rerun crypto-stego-verifier.py against the original file and require size/SHA-256 equality.",
		"missing-crypto-media-determinism": "Reparse PNG/WAV quicklook deterministically before promoting chunk or bit-plane evidence.",
		"missing-crypto-structure-offset-verification": "Verify chunks, trailing bytes, embedded archives, or audio slices by exact offset and SHA-256.",
		"missing-crypto-negative-control": "Add file mutation and shifted-offset controls so hidden-channel matches have a rejection oracle.",
		"missing-mobile-archive-hash-verification": "Rerun mobile-archive-verifier.py against the original APK/IPA and require size/SHA-256 equality.",
		"missing-mobile-zip-entry-verification": "Verify manifest, DEX, native library, certificate, and config ZIP entries by CRC, size, and SHA-256.",
		"missing-mobile-dex-quicklook-verification": "Bind DEX quicklook strings/header claims to the exact classes.dex entry bytes.",
		"missing-mobile-manifest-verification": "Bind AndroidManifest.xml, Info.plist, or entitlements fields to exact archive entry bytes.",
		"missing-mobile-hook-verification": "Hash and syntax-check mobile-frida-hooks.js against promoted hook targets.",
		"missing-mobile-negative-control": "Add archive byte mutation and entry-metadata mismatch controls before promoting runtime pivots.",
		"missing-agent-boundary-map-flow-verification": "Verify agent-boundary-map.json has source-bound boundaryFlows and payload IDs before replay proof.",
		"missing-agent-boundary-replay-coverage": "Rerun agent-boundary-payloads.py until baseline and unsafe/control payload IDs are all observed.",
		"missing-agent-boundary-response-hash": "Require every promoted replay claim to include request/response SHA-256 and status evidence.",
		"missing-agent-boundary-negative-control": "Require a benign accepted baseline and at least one unsafe or blocked-control differential.",
		"missing-workspace-source-line-verification": "Re-read workspace source files and bind routes/sinks/auth/state/signers to exact file/line hashes.",
		"missing-workspace-route-template-verification": "Require every source route to have a replay template and proof target coverage for risky routes.",
		"missing-workspace-replay-gate-verification": "Verify route replay plan/output/claim-promotion gates before any source-only claim becomes runtime proof.",
		"missing-workspace-repair-queue-verification": "Require missing-base-url/live-replay blockers to remain queued until response hash differentials exist.",
		"missing-workspace-live-route-replay-proof": "Start the target service and run workspace-route-replay-harness.mjs --live to collect status/body-hash controls.",
		"missing-workspace-negative-control": "Run missing-source, shifted-line, missing-base-url, and mutated-route controls before promotion.",
		"missing-cloud-source-line-verification": "Re-read cloud source files and bind trust claims to exact file/line SHA-256 evidence.",
		"missing-cloud-trust-claim-coverage": "Require promoted cloud trust claims to cover OIDC/IAM plus runtime or exposure source anchors.",
		"missing-cloud-composed-path-verification": "Verify each composed cloud pivot segment resolves to a source-bound promoted claim.",
		"missing-cloud-negative-control": "Run missing-file, shifted-line, and mutated-segment controls before promoting cloud trust-chain proof.",
		"missing-windows-ad-file-hash-verification": "Re-read Windows/AD artifacts and require size/SHA-256 equality for every quicklook file row.",
		"missing-windows-ad-bloodhound-path-verification": "Verify BloodHound attack path edge files, owned source, high-value target, and relationship chain.",
		"missing-windows-ad-signal-coverage": "Require credential/Kerberos/logon/ADCS signals or matching artifact classes before promotion.",
		"missing-windows-ad-composed-path-verification": "Verify each Windows/AD composed pivot segment resolves to a promoted source-bound claim.",
		"missing-windows-ad-negative-control": "Run missing-artifact, mutated-edge, and mutated-segment controls before promoting AD proof.",
	};
	return actions[blocker] ?? "Drain this blocker by collecting source-bound runtime evidence and rerun the relevant harness.";
}

export function writeUnifiedProofGraph(targetInfo, artifactDir, commands, toolState) {
	if (noWrite || !artifactDir) return undefined;
	const artifactFiles = [];
	const nodes = [];
	const edges = [];
	const claimLedger = [];
	const composedPaths = [];
	const repairQueue = [];
	const nodeIds = new Set();
	const edgeIds = new Set();
	const claimNodeByClaimId = new Map();
	const addNode = (node) => {
		if (!node?.id || nodeIds.has(node.id)) return;
		nodeIds.add(node.id);
		nodes.push(node);
	};
	const addEdge = (from, to, relation, data = {}) => {
		if (!from || !to || !relation) return;
		const id = `${from}->${relation}->${to}`;
		if (edgeIds.has(id)) return;
		edgeIds.add(id);
		edges.push({ id, from, to, relation, ...data });
	};
	for (const relPath of unifiedProofGraphArtifactCandidates) {
		const path = join(artifactDir, relPath);
		const parsed = readJsonArtifact(path);
		if (!parsed) continue;
		let size = 0;
		let artifactSha256 = "";
		try {
			const data = readFileSync(path);
			size = data.length;
			artifactSha256 = bufferSha256(data);
		} catch {
			// Artifact content is optional for graph construction once parsed.
		}
		artifactFiles.push({ relPath, size, sha256: artifactSha256, kind: parsed.kind ?? null });
		const artifactNodeId = `artifact:${relPath}`;
		addNode({ id: artifactNodeId, nodeType: "artifact", relPath, kind: parsed.kind ?? null, size, sha256: artifactSha256 });
		for (const claim of proofGraphClaimRows(parsed)) {
			const claimId = claim.id || claim.claimId || `${claim.claimType || "claim"}-${shortHash(JSON.stringify(claim))}`;
			const nodeId = `claim:${relPath}:${claimId}`;
			const normalized = {
				graphNodeId: nodeId,
				sourceArtifact: relPath,
				id: claimId,
				claimType: claim.claimType ?? claim.verdict ?? "claim",
				verdict: claim.verdict ?? "unknown",
				confidence: typeof claim.confidence === "number" ? claim.confidence : null,
				blockers: proofGraphArray(claim.blockers).map(String),
				sourceBinding: proofGraphRedactJson(claim.sourceBinding ?? {}),
				evidenceBinding: proofGraphRedactJson(claim.evidenceBinding ?? {}),
				statement: claim.statement ? redact(claim.statement) : null,
				rerunCommand: claim.rerunCommand ? redact(claim.rerunCommand) : null,
				claimSha256: createHash("sha256").update(JSON.stringify(proofGraphRedactJson(claim))).digest("hex"),
			};
			claimLedger.push(normalized);
			if (!claimNodeByClaimId.has(claimId)) claimNodeByClaimId.set(claimId, nodeId);
			addNode({
				id: nodeId,
				nodeType: "claim",
				sourceArtifact: relPath,
				claimId,
				claimType: normalized.claimType,
				verdict: normalized.verdict,
				confidence: normalized.confidence,
				blockers: normalized.blockers,
				statement: normalized.statement,
			});
			addEdge(artifactNodeId, nodeId, "emits-claim");
			for (const sourceArtifact of proofGraphArray(claim.sourceBinding?.artifacts)) addEdge(`artifact:${sourceArtifact}`, nodeId, "source-bound");
			if (claim.sourceBinding?.artifact) addEdge(`artifact:${claim.sourceBinding.artifact}`, nodeId, "source-bound");
		}
		for (const pathRow of proofGraphComposedPathRows(parsed)) {
			const pathId = pathRow.id || `${pathRow.claimType || "path"}-${shortHash(JSON.stringify(pathRow))}`;
			const nodeId = `path:${relPath}:${pathId}`;
			const normalized = {
				graphNodeId: nodeId,
				sourceArtifact: relPath,
				id: pathId,
				claimType: pathRow.claimType ?? "composed-proof-path",
				verdict: pathRow.verdict ?? "unknown",
				confidence: typeof pathRow.confidence === "number" ? pathRow.confidence : null,
				blockers: proofGraphArray(pathRow.blockers).map(String),
				sourceBinding: proofGraphRedactJson(pathRow.sourceBinding ?? {}),
				evidenceBinding: proofGraphRedactJson(pathRow.evidenceBinding ?? {}),
				statement: pathRow.statement ? redact(pathRow.statement) : null,
				rerunCommand: pathRow.rerunCommand ? redact(pathRow.rerunCommand) : null,
				pathSha256: createHash("sha256").update(JSON.stringify(proofGraphRedactJson(pathRow))).digest("hex"),
			};
			composedPaths.push(normalized);
			addNode({
				id: nodeId,
				nodeType: "composed-path",
				sourceArtifact: relPath,
				pathId,
				claimType: normalized.claimType,
				verdict: normalized.verdict,
				confidence: normalized.confidence,
				blockers: normalized.blockers,
				statement: normalized.statement,
			});
			addEdge(artifactNodeId, nodeId, "emits-composed-path");
			for (const segment of proofGraphArray(pathRow.sourceBinding?.segments)) {
				const claimNode = claimNodeByClaimId.get(segment?.id);
				if (claimNode) addEdge(claimNode, nodeId, "segment-of");
			}
			if (pathRow.sourceBinding?.replayClaimId) {
				const claimNode = claimNodeByClaimId.get(pathRow.sourceBinding.replayClaimId);
				if (claimNode) {
					addEdge(claimNode, nodeId, "replay-claim-of");
					addEdge(claimNode, nodeId, "segment-of");
				}
			}
		}
		for (const row of proofGraphRepairRows(parsed)) {
			const blocker = String(row.blocker ?? row.reason ?? "unknown-blocker");
			const repairId = row.id || `${relPath}-${row.claimId || row.route || row.payloadId || blocker}-${shortHash(JSON.stringify(row))}`;
			const nodeId = `repair:${relPath}:${repairId}`;
			const normalized = {
				graphNodeId: nodeId,
				sourceArtifact: relPath,
				id: repairId,
				claimId: row.claimId ?? null,
				blocker,
				priority: proofGraphRepairPriority(blocker),
				action: row.action ? redact(row.action) : proofGraphRepairAction(blocker),
				route: row.route ?? row.sourceBinding?.route ?? null,
				method: row.method ?? row.sourceBinding?.method ?? null,
				payloadId: row.payloadId ?? null,
				sourceBinding: proofGraphRedactJson(row.sourceBinding ?? {}),
				rerunCommand: row.rerunCommand ? redact(row.rerunCommand) : null,
			};
			repairQueue.push(normalized);
			addNode({ id: nodeId, nodeType: "repair", sourceArtifact: relPath, blocker, priority: normalized.priority, claimId: normalized.claimId, action: normalized.action });
			addEdge(artifactNodeId, nodeId, "emits-repair");
			if (normalized.claimId) {
				const claimNode = claimNodeByClaimId.get(normalized.claimId);
				if (claimNode) addEdge(nodeId, claimNode, "repairs-claim");
			}
		}
		for (const blocker of proofGraphArray(parsed?.promotionReport?.blockers).map(String)) {
			if (repairQueue.some((row) => row.blocker === blocker && row.sourceArtifact === relPath)) continue;
			const repairId = `${relPath}-${blocker}`;
			const nodeId = `repair:${repairId}`;
			const normalized = {
				graphNodeId: nodeId,
				sourceArtifact: relPath,
				id: repairId,
				claimId: null,
				blocker,
				priority: proofGraphRepairPriority(blocker),
				action: proofGraphRepairAction(blocker),
				route: null,
				method: null,
				payloadId: null,
				sourceBinding: { artifact: relPath },
				rerunCommand: null,
			};
			repairQueue.push(normalized);
			addNode({ id: nodeId, nodeType: "repair", sourceArtifact: relPath, blocker, priority: normalized.priority, action: normalized.action });
			addEdge(artifactNodeId, nodeId, "emits-repair");
		}
	}
	for (const command of commands.slice(0, 160)) {
		const nodeId = `command:${command.id}`;
		addNode({
			id: nodeId,
			nodeType: "command",
			commandId: command.id,
			exit: command.exit,
			durationMs: command.durationMs,
			stdoutSha256: createHash("sha256").update(command.stdout ?? "").digest("hex"),
			stderrSha256: createHash("sha256").update(command.stderr ?? "").digest("hex"),
		});
	}
	const blockers = Array.from(new Set([...claimLedger.flatMap((claim) => claim.blockers), ...composedPaths.flatMap((path) => path.blockers), ...repairQueue.map((row) => row.blocker).filter(Boolean)])).sort();
	const promotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted" || /promoted|unsafe-promoted|control-promoted/i.test(claim.verdict));
	const promotedPaths = composedPaths.filter((path) => path.verdict === "promoted" || /promoted/i.test(path.verdict));
	const nextCommands = Array.from(
		new Set([
			...repairQueue.map((row) => row.rerunCommand).filter(Boolean),
			...(existsSync(join(artifactDir, "proof-harness.mjs")) ? [`node ${shellQuote(join(artifactDir, "proof-harness.mjs"))} --self-test`, `node ${shellQuote(join(artifactDir, "proof-harness.mjs"))} --execute`] : []),
		]),
	).slice(0, 60);
	const summary = {
		kind: "repi-unified-proof-graph",
		schemaVersion: 1,
		target: redact(targetInfo.target),
		lane: targetInfo.lane,
		domain: targetInfo.domain,
		generatedAt: new Date().toISOString(),
		artifactFiles,
		proofReady: promotedClaims.length > 0,
		exploitProofReady: promotedPaths.length > 0,
		nodeCount: nodes.length,
		edgeCount: edges.length,
		claimLedger,
		composedPaths,
		repairQueue,
		runtimeRepairLoop: {
			ready: repairQueue.length > 0,
			blockers,
			queue: repairQueue,
			nextCommands,
			exitRule: "Drain repairQueue until each promoted path has source binding, runtime/status/hash evidence, and a negative-control or verifier oracle.",
		},
		graph: {
			nodes,
			edges,
		},
		promotionReport: {
			proofReady: promotedClaims.length > 0,
			exploitProofReady: promotedPaths.length > 0,
			promotedClaims,
			composedPaths: promotedPaths,
			blockers,
		},
		toolState: toolState.map((row) => ({ tool: row.tool, available: row.available })),
	};
	const path = join(artifactDir, "repi-proof-graph.json");
	writePrivate(path, `${JSON.stringify(summary, null, 2)}\n`, 0o600);
	return { path, summary };
}

function runtimeRepairLoopSource(plan) {
	const planJson = JSON.stringify(plan, null, 2);
	return `#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { spawnSync } from "node:child_process";

const plan = ${planJson};
const selfTest = process.argv.includes("--self-test") || process.argv.includes("--plan") || !process.argv.includes("--execute");
const execute = process.argv.includes("--execute");
const graphPath = process.argv.find((arg) => arg.endsWith(".json")) || plan.graphPath;
const maxIndex = process.argv.findIndex((arg) => arg === "--max");
const maxRepairs = Number((maxIndex >= 0 ? process.argv[maxIndex + 1] : "") || process.env.REPI_REPAIR_MAX || "1");
const timeoutMs = Number(process.env.REPI_REPAIR_TIMEOUT_MS || "20000");

function sha256(value) {
	return createHash("sha256").update(String(value ?? "")).digest("hex");
}

function redact(value) {
	return String(value ?? "")
		.replace(/\\bsk-[A-Za-z0-9._-]{8,}\\b/g, "<redacted:api-key>")
		.replace(/\\bBearer\\s+[A-Za-z0-9._~+/=-]{8,}/gi, "Bearer <redacted>")
		.replace(/((?:authorization|x-api-key|api-key|cookie|set-cookie)\\s*[:=]\\s*["']?)([^"'\\n;]{4,})/gi, "$1<redacted>")
		.replace(/([?&](?:api[_-]?key|token|access_token|refresh_token|client_secret|secret|password)=)[^&\\s"'<>]{4,}/gi, "$1<redacted>");
}

function priorityScore(priority) {
	if (/^high$/i.test(priority || "")) return 3;
	if (/^medium$/i.test(priority || "")) return 2;
	if (/^normal$/i.test(priority || "")) return 1;
	return 0;
}

function readGraph() {
	if (!existsSync(graphPath)) throw new Error("proof graph missing: " + graphPath);
	return JSON.parse(readFileSync(graphPath, "utf8"));
}

function selectedRepairs(graph) {
	const queue = Array.isArray(graph.runtimeRepairLoop?.queue) ? graph.runtimeRepairLoop.queue : Array.isArray(graph.repairQueue) ? graph.repairQueue : [];
	return queue
		.filter((row) => row && row.blocker)
		.sort((a, b) => priorityScore(b.priority) - priorityScore(a.priority))
		.slice(0, Math.max(1, maxRepairs))
		.map((row) => ({
			id: row.id || row.graphNodeId || sha256(JSON.stringify(row)).slice(0, 12),
			blocker: row.blocker,
			priority: row.priority || "normal",
			action: redact(row.action || ""),
			rerunCommand: row.rerunCommand ? redact(row.rerunCommand) : null,
			sourceArtifact: row.sourceArtifact || null,
			claimId: row.claimId || null,
			route: row.route || null,
			payloadId: row.payloadId || null,
		}));
}

function executeRepair(row) {
	if (!row.rerunCommand) return { id: row.id, skipped: true, reason: "missing-rerun-command", ok: false };
	const started = Date.now();
	const result = spawnSync("bash", ["-lc", row.rerunCommand], {
		cwd: dirname(graphPath),
		encoding: "utf8",
		timeout: timeoutMs,
		maxBuffer: 4 * 1024 * 1024,
		env: {
			...process.env,
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
		},
	});
	const stdout = redact(result.stdout || "");
	const stderr = redact(result.stderr || "");
	return {
		id: row.id,
		blocker: row.blocker,
		command: row.rerunCommand,
		exit: result.status ?? (result.signal ? 128 : 1),
		signal: result.signal,
		durationMs: Date.now() - started,
		ok: (result.status ?? (result.signal ? 128 : 1)) === 0,
		stdoutSha256: sha256(stdout),
		stderrSha256: sha256(stderr),
		stdoutSample: stdout.slice(0, 1000),
		stderrSample: stderr.slice(0, 1000),
		error: result.error ? redact(result.error.message || String(result.error)) : undefined,
	};
}

function main() {
	const graph = readGraph();
	const repairs = selectedRepairs(graph);
	const executionRows = execute ? repairs.map(executeRepair) : [];
	const report = {
		kind: "repi-runtime-repair-loop",
		schemaVersion: 1,
		mode: execute ? "execute" : selfTest ? "self-test" : "plan",
		graphPath: redact(graphPath),
		graphSha256: sha256(readFileSync(graphPath, "utf8")),
		lane: graph.lane,
		domain: graph.domain,
		proofReady: Boolean(graph.proofReady),
		exploitProofReady: Boolean(graph.exploitProofReady),
		blockers: graph.runtimeRepairLoop?.blockers || [],
		selectedRepairs: repairs,
		executionRows,
		next: execute
			? "Re-run repi engage after successful repairs to rebuild claimLedger/composedPaths and verify the blocker drained."
			: "Review selectedRepairs, set required env/credentials/URLs, then run this harness with --execute.",
	};
	console.log(JSON.stringify(report, null, 2));
	process.exit(execute && executionRows.length ? (executionRows.every((row) => row.ok) ? 0 : 1) : 0);
}

try {
	main();
} catch (error) {
	console.error(redact(error?.stack || error?.message || String(error)));
	process.exit(1);
}
`;
}

export function writeRuntimeRepairLoopHarness(artifactDir, graphPath) {
	if (noWrite || !artifactDir || !graphPath || !existsSync(graphPath)) return undefined;
	const path = join(artifactDir, "repi-runtime-repair-loop.mjs");
	writePrivate(
		path,
		runtimeRepairLoopSource({
			kind: "repi-runtime-repair-loop-plan",
			schemaVersion: 1,
			graphPath,
			proofExitRule: "A repair is successful only when rerunning repi engage removes the blocker and promotes a source-bound proof path with hashes/negative controls.",
		}),
		0o700,
	);
	return { path };
}
