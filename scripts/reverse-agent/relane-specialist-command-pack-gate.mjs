#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const writeEvidence = !argv.includes("--no-write");
const SCHEMA_PATH = "schemas/reverse-agent/relane-specialist-command-pack.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/relane-specialist-command-pack.fixture.json";

const REQUIRED_GATES = [
  "relane_specialist_command_pack_gate",
  "route_to_domain_lane_seed_matrix",
  "domain_lane_command_pack_markers",
  "specialist_evidence_analyzer_anchor_matrix",
  "self_heal_command_fallback_matrix",
  "proof_exit_bridge_matrix",
  "runtime_re_lane_specialist_pack_tool",
  "completion_audit_domain_proof_exit_bridge",
];
const REQUIRED_NEGATIVE_CASES = [
  "missing-route-matchers",
  "missing-lane-seeds",
  "missing-command-pack-markers",
  "missing-analyzer-anchors",
  "missing-self-heal-commands",
  "missing-proof-exit-bridge",
  "runtime-tool-not-registered",
];

const DOMAIN_REQUIREMENTS = [
  {
    domainId: "web-api",
    routeMatchers: ["Web / API security", "auth/session", "IDOR/BOLA", "XHR/WS"],
    laneSeeds: ["surface", "state", "authz", "replay"],
    commandPackMarkers: ["re_live_browser run", "re_web_authz_state run", "curl -i", "route-auth-map"],
    analyzerAnchors: ["browser/XHR/WS runtime anchors", "browser route graph anchors", "browser auth matrix anchors", "browser authz object ownership anchors"],
    selfHealCommands: ["re_lane plan state <target>", "re_web_authz_state plan <target>", "re_operator plan"],
    proofExitBridge: ["principal matrix", "object ownership", "state rollback", "signed replay divergence"],
  },
  {
    domainId: "web-scan",
    routeMatchers: ["Web vulnerability scanning", "nuclei", "ffuf", "content discovery"],
    laneSeeds: ["scope", "crawl", "template", "verify"],
    commandPackMarkers: ["web scanner scope", "web scanner crawl", "web scanner template", "web scanner manual replay"],
    analyzerAnchors: ["web scanner scope anchors", "web scanner crawl corpus anchors", "web scanner finding queue anchors", "manual replay verifier anchors"],
    selfHealCommands: ["re_lane plan scope <target>", "re_replayer run", "re_verifier matrix"],
    proofExitBridge: ["scope baseline", "crawl corpus", "scanner finding queue", "manual replay verifier"],
  },
  {
    domainId: "frontend-js",
    routeMatchers: ["Frontend JS reverse", "crypto.subtle", "sign", "WebSocket"],
    laneSeeds: ["observe", "rebuild", "divergence", "replay"],
    commandPackMarkers: ["js-network-surface", "source-map-search", "js signing rebuild", "js first-divergence"],
    analyzerAnchors: ["JS signing rebuild anchors", "crypto.subtle operation anchors", "JS signing normalized artifact anchors", "JS first-divergence anchors"],
    selfHealCommands: ["re_lane plan rebuild <target>", "re_live_browser run <target>", "re_replayer run"],
    proofExitBridge: ["observed normalizer", "first divergence", "signed replay harness"],
  },
  {
    domainId: "rev-native",
    routeMatchers: ["Native reverse", "ELF", "Mach-O", "headers/imports"],
    laneSeeds: ["triage", "control", "runtime", "patch"],
    commandPackMarkers: ["headers-imports", "strings-interesting", "r2-xrefs", "objdump-control"],
    analyzerAnchors: ["Native deep symbol/import/string anchors", "Native decompiler/control-flow anchors", "Native compare trace anchors", "Native patch hypothesis anchors"],
    selfHealCommands: ["re_native_runtime plan <target>", "re_lane plan control <target>", "re_verifier matrix"],
    proofExitBridge: ["symbol/import map", "comparison sink", "runtime trace", "patch/replay proof"],
  },
  {
    domainId: "pwn",
    routeMatchers: ["Pwn / exploit", "mitigations", "crash", "ROP/libc"],
    laneSeeds: ["triage", "primitive", "leak", "verify"],
    commandPackMarkers: ["pwn-mitigations", "crash-seed", "cyclic", "ROP/libc"],
    analyzerAnchors: ["pwn primitive crash/control anchors", "pwn cyclic offset anchors", "pwn gadget anchors", "pwn ROP/libc chain anchors"],
    selfHealCommands: ["re_native_runtime run <target>", "re_exploit_lab run <target> 3", "re_proof_loop run <target> 4 2"],
    proofExitBridge: ["offset", "leak source", "controllable bytes", "local verifier"],
  },
  {
    domainId: "mobile",
    routeMatchers: ["Mobile / Android", "APK", "Frida", "jadx"],
    laneSeeds: ["manifest", "control", "runtime", "hook"],
    commandPackMarkers: ["apk-manifest", "jadx-keyword-map", "frida-hook-scaffold", "native-lib-map"],
    analyzerAnchors: ["mobile APK manifest anchors", "Frida/GDB trace anchors", "Java crypto hooks", "native compare hooks"],
    selfHealCommands: ["re_mobile_runtime plan <target>", "re_lane plan control <target>", "re_verifier matrix"],
    proofExitBridge: ["manifest/package map", "Java/native hook", "anti-debug evidence", "runtime anchors"],
  },
  {
    domainId: "mobile-ios",
    routeMatchers: ["Mobile / iOS", "iOS IPA", "Info.plist", "Keychain"],
    laneSeeds: ["ipa-inventory", "macho", "hook", "network"],
    commandPackMarkers: ["ios-ipa-inventory-scaffold", "ios-macho-class-map", "ios-frida-hook-template", "ios-network-keychain-replay"],
    analyzerAnchors: ["iOS IPA anchors", "Mach-O/class map anchors", "iOS Frida/objection hook anchors", "keychain/network replay anchors"],
    selfHealCommands: ["re_lane plan ipa-inventory <target>", "re_mobile_runtime run <target>", "re_replayer run"],
    proofExitBridge: ["IPA inventory", "Mach-O/class map", "Frida/objection hook", "network/keychain replay"],
  },
  {
    domainId: "pcap-dfir",
    routeMatchers: ["DFIR / PCAP / stego", "tcp.stream", "flow conversation", "carved object"],
    laneSeeds: ["flow", "stream", "extract", "timeline"],
    commandPackMarkers: ["pcap-flow", "pcap-stream", "pcap-extract", "pcap-secret"],
    analyzerAnchors: ["PCAP/DFIR traffic flow anchors", "PCAP stream ranking anchors", "PCAP extracted artifact anchors", "PCAP secret timeline anchors"],
    selfHealCommands: ["re_lane plan extract <target>", "re_knowledge_graph build", "re_verifier matrix"],
    proofExitBridge: ["flow conversation", "follow-stream", "carved object", "timeline evidence"],
  },
  {
    domainId: "memory-forensics",
    routeMatchers: ["Memory forensics", "volatility", "vmem", "process/network"],
    laneSeeds: ["image", "process-network", "credential", "timeline"],
    commandPackMarkers: ["memory-image-profile-scaffold", "memory-process-network-scaffold", "memory-credential-artifact-scaffold", "memory-timeline-carve-scaffold"],
    analyzerAnchors: ["memory forensics image anchors", "memory forensics process/network anchors", "memory forensics credential/artifact anchors", "memory forensics timeline/carve anchors"],
    selfHealCommands: ["re_lane plan process-network <target>", "re_replayer run", "re_verifier matrix"],
    proofExitBridge: ["image profile", "process/network map", "credential/artifact proof", "timeline/carve evidence"],
  },
  {
    domainId: "firmware-iot",
    routeMatchers: ["Firmware / IoT", "rootfs", "squashfs", "emulation"],
    laneSeeds: ["extract", "service", "config", "emulate"],
    commandPackMarkers: ["firmware-image-fingerprint", "firmware-extraction-rootfs", "firmware-service-surface", "firmware-config-secret"],
    analyzerAnchors: ["Firmware image metadata anchors", "Firmware extraction/rootfs anchors", "Firmware config/secret anchors", "Firmware emulation/runtime anchors"],
    selfHealCommands: ["re_lane plan extract <target>", "re_campaign plan <target>", "re_operation plan <target>"],
    proofExitBridge: ["filesystem extraction", "service map", "credential/config proof", "emulation notes"],
  },
  {
    domainId: "crypto",
    routeMatchers: ["Crypto / stego", "oracle", "lattice", "transform chain"],
    laneSeeds: ["params", "solver", "kat", "transform"],
    commandPackMarkers: ["crypto-param-oracle-scaffold", "crypto-solver-scaffold", "known-answer test", "crypto-stego-extraction-scaffold"],
    analyzerAnchors: ["Crypto transform chain anchors", "crypto parameter derivation anchors", "solver script anchors", "known-answer test anchors"],
    selfHealCommands: ["re_lane plan solver <target>", "re_replayer run", "re_proof_loop run <target>"],
    proofExitBridge: ["parameter derivation", "solver script", "known-answer test", "transform replay"],
  },
  {
    domainId: "cloud-identity",
    routeMatchers: ["Cloud / container", "Identity / Windows / AD", "K8s", "AD graph"],
    laneSeeds: ["config", "metadata", "privilege", "graph"],
    commandPackMarkers: ["cloud-identity-config-map", "cloud-metadata-probe-scaffold", "cloud-privilege-edge-scaffold", "identity-ad-graph-scaffold"],
    analyzerAnchors: ["Cloud identity anchors", "Cloud metadata probe anchors", "Cloud privilege edge anchors", "Identity/AD graph edge anchors"],
    selfHealCommands: ["re_lane plan privilege <target>", "re_campaign plan <target>", "re_supervisor review"],
    proofExitBridge: ["token source", "credential usability", "privilege edge", "graph/path evidence"],
  },
  {
    domainId: "agent-security",
    routeMatchers: ["Agent / LLM security", "agent-security", "prompt injection", "tool boundary"],
    laneSeeds: ["surface", "boundary", "poison", "injection"],
    commandPackMarkers: ["agent-prompt-surface-map", "agent-tool-boundary-scaffold", "agent-memory-poisoning-scaffold", "agent-injection-replay-harness"],
    analyzerAnchors: ["Agent prompt surface anchors", "Agent tool boundary anchors", "Agent memory poisoning anchors", "Agent injection replay anchors"],
    selfHealCommands: ["re_lane plan injection", "re_replayer run", "re_verifier matrix"],
    proofExitBridge: ["prompt surface map", "tool boundary proof", "memory poisoning proof", "injection replay proof"],
  },
  {
    domainId: "malware-analysis",
    routeMatchers: ["Malware analysis", "malware-analysis", "IOC", "behavior trace"],
    laneSeeds: ["static", "rules", "ioc", "behavior"],
    commandPackMarkers: ["malware-static-triage-scaffold", "malware-yara-capa-floss-scaffold", "malware-ioc-config-scaffold", "malware-behavior-trace-scaffold"],
    analyzerAnchors: ["Malware static triage anchors", "Malware rule/capability anchors", "Malware IOC/config anchors", "Malware behavior trace anchors"],
    selfHealCommands: ["re_lane plan behavior", "re_knowledge_graph build", "re_verifier matrix"],
    proofExitBridge: ["static triage proof", "rule/capability signal", "IOC/config proof", "behavior trace"],
  },
  {
    domainId: "exploit-reliability",
    routeMatchers: ["Exploit reliability", "PoC", "replay matrix", "flake triage"],
    laneSeeds: ["inventory", "matrix", "pin", "bundle"],
    commandPackMarkers: ["exploit-poc-inventory", "poc-replay-matrix", "exploit-environment-pin", "exploit-artifact-bundle"],
    analyzerAnchors: ["Exploit PoC inventory anchors", "PoC replay matrix anchors", "Exploit environment pin anchors", "Exploit artifact bundle anchors"],
    selfHealCommands: ["re_exploit_lab run <target> 5", "re_autofix plan", "re_complete audit"],
    proofExitBridge: ["multi-run success rate", "stdout/stderr hash", "environment pin", "bundle manifest"],
  },
];

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const shortHash = (value) => sha256(value).slice(0, 24);
const check = (id, ok, evidence = {}) => ({ id, status: ok ? "pass" : "fail", evidence });
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));
const clone = (value) => JSON.parse(JSON.stringify(value));

function markerCheck(id, path, markers) {
  const full = join(root, path);
  if (!existsSync(full)) return check(id, false, { path, exists: false });
  const text = readFileSync(full, "utf8");
  const missing = markers.filter((marker) => !text.includes(marker));
  return check(id, missing.length === 0, { path, missing, sha256: shortHash(text) });
}

function sourceCorpus() {
  return [
    "packages/coding-agent/src/core/recon-profile.ts",
    "repi-profile/extensions/reverse-pentest-core.ts",
    "repi-profile/SYSTEM.md",
    "README.md",
    "docs/reverse-agent/README.md",
  ]
    .filter((path) => existsSync(join(root, path)))
    .map((path) => readText(path))
    .join("\n---REPI_SPECIALIST_CORPUS---\n");
}

function rowFromRequirement(req, corpus) {
  const gaps = [];
  const routeMatchers = req.routeMatchers.filter((marker) => corpus.includes(marker));
  const laneSeeds = req.laneSeeds.filter((marker) => corpus.includes(marker));
  const commandPackMarkers = req.commandPackMarkers.filter((marker) => corpus.includes(marker));
  const analyzerAnchors = req.analyzerAnchors.filter((marker) => corpus.includes(marker));
  const selfHealCommands = req.selfHealCommands.filter((marker) => corpus.includes(marker));
  const proofExitBridge = req.proofExitBridge.filter((marker) => corpus.includes(marker));
  if (routeMatchers.length < Math.min(2, req.routeMatchers.length)) gaps.push("route_matchers_missing");
  if (laneSeeds.length < Math.min(2, req.laneSeeds.length)) gaps.push("lane_seeds_missing");
  if (commandPackMarkers.length < Math.min(3, req.commandPackMarkers.length)) gaps.push("command_pack_markers_missing");
  if (analyzerAnchors.length < Math.min(3, req.analyzerAnchors.length)) gaps.push("analyzer_anchors_missing");
  if (selfHealCommands.length < Math.min(2, req.selfHealCommands.length)) gaps.push("self_heal_commands_missing");
  if (proofExitBridge.length < Math.min(3, req.proofExitBridge.length)) gaps.push("proof_exit_bridge_missing");
  return { ...req, routeMatchers, laneSeeds, commandPackMarkers, analyzerAnchors, selfHealCommands, proofExitBridge, status: gaps.length ? "blocked" : "ready", gaps };
}

function buildRuntimeReport() {
  const corpus = sourceCorpus();
  const rows = DOMAIN_REQUIREMENTS.map((req) => rowFromRequirement(req, corpus));
  return {
    kind: "ReLaneSpecialistCommandPackGateV1",
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    ReLaneSpecialistCommandPackGateV1: true,
    runtime: "runtime:re_lane-specialist-command-pack",
    requiredGates: REQUIRED_GATES,
    domainCount: rows.length,
    readyDomainCount: rows.filter((row) => row.status === "ready").length,
    rows,
    closure: {
      allDomainsHaveRouteMatchers: rows.every((row) => row.routeMatchers.length >= 2),
      allDomainsHaveLaneSeeds: rows.every((row) => row.laneSeeds.length >= 2),
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
    negativeCases: REQUIRED_NEGATIVE_CASES.map((id) => ({ id, expect: "rejected" })),
    invariants: REQUIRED_GATES,
  };
}

function validatePackage(pkg) {
  const errors = [];
  if (pkg?.kind !== "ReLaneSpecialistCommandPackGateV1") errors.push("pkg.kind");
  if (pkg?.ReLaneSpecialistCommandPackGateV1 !== true) errors.push("pkg.ReLaneSpecialistCommandPackGateV1");
  if (pkg?.runtime !== "runtime:re_lane-specialist-command-pack") errors.push("pkg.runtime");
  const gates = new Set(pkg?.requiredGates || []);
  for (const gate of REQUIRED_GATES) if (!gates.has(gate)) errors.push(`requiredGate_missing:${gate}`);
  const negativeIds = new Set((pkg?.negativeCases || []).map((row) => row.id));
  for (const id of REQUIRED_NEGATIVE_CASES) if (!negativeIds.has(id)) errors.push(`negativeCase_missing:${id}`);
  const rows = pkg?.rows || [];
  const domainIds = new Set(rows.map((row) => row.domainId));
  if (!Array.isArray(rows) || rows.length < DOMAIN_REQUIREMENTS.length) errors.push("rows.minItems");
  for (const req of DOMAIN_REQUIREMENTS) if (!domainIds.has(req.domainId)) errors.push(`domain_missing:${req.domainId}`);
  for (const row of rows) {
    if (row.status !== "ready") errors.push(`${row.domainId}.status_not_ready`);
    if ((row.gaps || []).length !== 0) errors.push(`${row.domainId}.gaps_nonempty`);
    if (!Array.isArray(row.routeMatchers) || row.routeMatchers.length < 2) errors.push(`${row.domainId}.routeMatchers_minItems`);
    if (!Array.isArray(row.laneSeeds) || row.laneSeeds.length < 2) errors.push(`${row.domainId}.laneSeeds_minItems`);
    if (!Array.isArray(row.commandPackMarkers) || row.commandPackMarkers.length < 3) errors.push(`${row.domainId}.commandPackMarkers_minItems`);
    if (!Array.isArray(row.analyzerAnchors) || row.analyzerAnchors.length < 3) errors.push(`${row.domainId}.analyzerAnchors_minItems`);
    if (!Array.isArray(row.selfHealCommands) || row.selfHealCommands.length < 2) errors.push(`${row.domainId}.selfHealCommands_minItems`);
    if (!Array.isArray(row.proofExitBridge) || row.proofExitBridge.length < 3) errors.push(`${row.domainId}.proofExitBridge_minItems`);
  }
  const closure = pkg?.closure || {};
  for (const key of ["allDomainsHaveRouteMatchers", "allDomainsHaveLaneSeeds", "allDomainsHaveCommandPacks", "allDomainsHaveAnalyzerAnchors", "allDomainsHaveSelfHeal", "allDomainsHaveProofExitBridge"]) {
    if (closure[key] !== true) errors.push(`closure.${key}_not_true`);
  }
  if ((pkg?.readyDomainCount ?? 0) !== rows.filter((row) => row.status === "ready").length) errors.push("readyDomainCount_mismatch");
  if ((pkg?.domainCount ?? 0) !== rows.length) errors.push("domainCount_mismatch");
  if (!String(pkg?.nextRuntimeCommands || []).includes("re_domain_proof_exit")) errors.push("nextRuntimeCommands_missing_domain_proof_exit");
  return { ok: errors.length === 0, errors };
}

function mutateFixture(fixture, id) {
  const row = clone(fixture);
  const first = row.rows?.[0];
  if (id === "missing-route-matchers") first.routeMatchers = [];
  if (id === "missing-lane-seeds") first.laneSeeds = [];
  if (id === "missing-command-pack-markers") first.commandPackMarkers = [];
  if (id === "missing-analyzer-anchors") first.analyzerAnchors = [];
  if (id === "missing-self-heal-commands") first.selfHealCommands = [];
  if (id === "missing-proof-exit-bridge") first.proofExitBridge = [];
  if (id === "runtime-tool-not-registered") row.nextRuntimeCommands = ["re_lane plan <target>"];
  first.status = "ready";
  first.gaps = [];
  row.closure = {
    allDomainsHaveRouteMatchers: row.rows.every((item) => item.routeMatchers.length >= 2),
    allDomainsHaveLaneSeeds: row.rows.every((item) => item.laneSeeds.length >= 2),
    allDomainsHaveCommandPacks: row.rows.every((item) => item.commandPackMarkers.length >= 3),
    allDomainsHaveAnalyzerAnchors: row.rows.every((item) => item.analyzerAnchors.length >= 3),
    allDomainsHaveSelfHeal: row.rows.every((item) => item.selfHealCommands.length >= 2),
    allDomainsHaveProofExitBridge: row.rows.every((item) => item.proofExitBridge.length >= 3),
  };
  return row;
}

function writeEvidenceReport(result) {
  const dir = join(root, ".repi-harness", "evidence", "relane-specialist-command-pack");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${result.generatedAt.replace(/[:.]/g, "-")}.json`);
  writeFileSync(path, `${JSON.stringify(result, null, 2)}\n`);
  return path;
}

function main() {
  const checks = [];
  let runtimePackage = null;
  try {
    const schema = readJson(SCHEMA_PATH);
    const fixture = readJson(FIXTURE_PATH);
    checks.push(check("schema:parse", Boolean(schema?.$defs?.ReLaneSpecialistCommandPackGateV1 && schema?.$defs?.ReLaneSpecialistDomainPackV1), { path: SCHEMA_PATH }));
    checks.push(check("fixture:required-gates", REQUIRED_GATES.every((gate) => fixture.requiredGates?.includes(gate)), { required: REQUIRED_GATES, present: fixture.requiredGates }));
    const positive = validatePackage(fixture);
    checks.push(check("fixture:positive-specialist-command-pack", positive.ok, positive));
    const negativeResults = REQUIRED_NEGATIVE_CASES.map((id) => {
      const result = validatePackage(mutateFixture(fixture, id));
      return { id, rejected: !result.ok, errors: result.errors };
    });
    checks.push(check("fixture:negative-specialist-command-pack", negativeResults.every((row) => row.rejected), { negativeResults }));
    runtimePackage = buildRuntimeReport();
    const runtimeValidation = validatePackage(runtimePackage);
    checks.push(check("runtime:relane-specialist-command-pack", runtimeValidation.ok, runtimeValidation));
    checks.push(check("runtime:all-domains-ready", runtimePackage.readyDomainCount === runtimePackage.domainCount && runtimePackage.domainCount >= DOMAIN_REQUIREMENTS.length, { readyDomainCount: runtimePackage.readyDomainCount, domainCount: runtimePackage.domainCount }));

    checks.push(markerCheck("core:relane-specialist-command-pack", "packages/coding-agent/src/core/recon-profile.ts", ["ReLaneSpecialistCommandPackGateV1", "runtime:re_lane-specialist-command-pack", "buildReLaneSpecialistCommandPackGate", "formatReLaneSpecialistCommandPackGate", "re_lane_specialist_pack", "re-lane-specialist-pack", "routeMatchers", "analyzerAnchors", "selfHealCommands", "proofExitBridge"]));
    checks.push(markerCheck("profile:relane-specialist-command-pack", "repi-profile/extensions/reverse-pentest-core.ts", ["ReLaneSpecialistCommandPackGateV1", "runtime:re_lane-specialist-command-pack", "re_lane_specialist_pack", "self-heal commands", "proof-exit bridge"]));
    checks.push(markerCheck("autonomy:relane-specialist-command-pack", "scripts/reverse-agent/autonomy-control-plane.mjs", ["relane_specialist_command_pack_gate", "ReLaneSpecialistCommandPackGateV1", "gate:relane-specialist-command-pack"]));
    checks.push(markerCheck("harness:relane-specialist-command-pack", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:relane-specialist-command-pack", "ReLaneSpecialistCommandPackGateV1", "child:gate:relane-specialist-command-pack"]));
    checks.push(markerCheck("npm:relane-specialist-command-pack", "package.json", ["gate:relane-specialist-command-pack", "relane-specialist-command-pack-gate.mjs"]));
    checks.push(markerCheck("docs:readme-relane-specialist-command-pack", "README.md", ["ReLaneSpecialistCommandPackGateV1", "gate:relane-specialist-command-pack", "re_lane_specialist_pack", "/re-lane-specialist-pack"]));
    checks.push(markerCheck("docs:reverse-relane-specialist-command-pack", "docs/reverse-agent/README.md", ["ReLaneSpecialistCommandPackGateV1", "gate:relane-specialist-command-pack", "runtime:re_lane-specialist-command-pack"]));
    checks.push(markerCheck("docs:system-relane-specialist-command-pack", "repi-profile/SYSTEM.md", ["ReLaneSpecialistCommandPackGateV1", "specialist_command_pack_gate", "re_lane_specialist_pack"]));
  } catch (error) {
    checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
  }
  const failed = checks.filter((row) => row.status !== "pass");
  const result = {
    kind: "repi-relane-specialist-command-pack-gate",
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    ReLaneSpecialistCommandPackGateV1: true,
    ok: failed.length === 0,
    checks,
    failed: failed.map((row) => row.id),
    runtimePackage,
  };
  if (writeEvidence) result.evidencePath = writeEvidenceReport(result);
  if (json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log(`repi-relane-specialist-command-pack-gate ok=${result.ok}`);
    for (const row of checks) console.log(`${row.status}\t${row.id}`);
    if (failed.length) console.log(`failed=${failed.map((row) => row.id).join(",")}`);
  }
  if (strict && failed.length) process.exitCode = 1;
}

main();

// negative:specialist-command-pack protects missing route/lane/command/analyzer/self-heal/proof-exit fields.
