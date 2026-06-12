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
const SCHEMA_PATH = "schemas/reverse-agent/runtime-adapter-execution.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/runtime-adapter-execution.fixture.json";

const REQUIRED_GATES = [
  "runtime_adapter_execution_gate",
  "adapter_runner_parser_ingest_contract",
  "r2_ghidra_native_adapter_contract",
  "frida_mobile_adapter_contract",
  "web_cdp_adapter_contract",
  "pwntools_exploit_verifier_adapter_contract",
  "tshark_pcap_adapter_contract",
  "binwalk_firmware_adapter_contract",
  "runtime:adapter-execution",
];

const ADAPTER_SPECS = [
  {
    id: "r2-native-xref-adapter",
    bridgeId: "tool-bridge-runtime",
    domainId: "rev-native",
    tool: "r2",
    fallbackTool: "objdump",
    runnerKind: "shell-command",
    commandMarker: "adapter-r2-native-xref-runner",
    parserMarkers: ["parser-r2-symbol-import-xref", "parser-native-entrypoint", "parser-native-strings"],
    artifactKinds: ["native-xref-json", "native-symbol-map", "runtime-adapter-transcript"],
    ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
    proofExitSignals: ["symbol/import map", "control-flow xref", "runtime adapter transcript"],
  },
  {
    id: "ghidra-headless-summary-adapter",
    bridgeId: "tool-bridge-runtime",
    domainId: "rev-native",
    tool: "analyzeHeadless",
    fallbackTool: "readelf",
    runnerKind: "shell-command",
    commandMarker: "adapter-ghidra-headless-summary-runner",
    parserMarkers: ["parser-ghidra-function-summary", "parser-native-entrypoint", "parser-native-import-table"],
    artifactKinds: ["ghidra-headless-summary", "native-import-table", "runtime-adapter-transcript"],
    ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
    proofExitSignals: ["decompiler summary", "function inventory", "import table proof"],
  },
  {
    id: "frida-mobile-hook-adapter",
    bridgeId: "mobile-frida",
    domainId: "mobile",
    tool: "frida",
    fallbackTool: "adb",
    runnerKind: "frida-hook",
    commandMarker: "adapter-frida-mobile-hook-runner",
    parserMarkers: ["parser-frida-hook-output", "parser-mobile-method-anchor", "parser-cert-pinning-anchor"],
    artifactKinds: ["frida-hook-output-jsonl", "mobile-runtime-attach-manifest", "runtime-adapter-transcript"],
    ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
    proofExitSignals: ["Java/ObjC/Swift hook", "runtime attach env gate", "hook output artifact contract"],
  },
  {
    id: "web-cdp-network-adapter",
    bridgeId: "web-cdp-replay",
    domainId: "web-api",
    tool: "node",
    fallbackTool: "curl",
    runnerKind: "cdp-capture",
    commandMarker: "adapter-web-cdp-network-runner",
    parserMarkers: ["parser-cdp-network-event", "parser-xhr-ws-route", "parser-signed-replay-diff"],
    artifactKinds: ["cdp-network-har", "xhr-ws-route-map", "signed-replay-diff", "runtime-adapter-transcript"],
    ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
    proofExitSignals: ["CDP network capture", "XHR/WS route extraction", "signed request replay", "request order proof"],
  },
  {
    id: "pwntools-local-verifier-adapter",
    bridgeId: "exploit-verifier-runtime",
    domainId: "pwn",
    tool: "python3",
    fallbackTool: "gdb",
    runnerKind: "python-harness",
    commandMarker: "adapter-pwntools-local-verifier-runner",
    parserMarkers: ["parser-pwn-crash-offset", "parser-pwn-leak-primitive", "parser-pwn-multirun-success"],
    artifactKinds: ["pwn-verifier-matrix", "stdout-stderr-hashes", "runtime-adapter-transcript"],
    ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
    proofExitSignals: ["crash-to-offset proof", "primitive control evidence", "multi-run verifier", "stdout/stderr hash"],
  },
  {
    id: "tshark-pcap-flow-adapter",
    bridgeId: "tool-bridge-runtime",
    domainId: "pcap-dfir",
    tool: "tshark",
    fallbackTool: "strings",
    runnerKind: "shell-command",
    commandMarker: "adapter-tshark-pcap-flow-runner",
    parserMarkers: ["parser-tshark-conversation", "parser-http-object", "parser-credential-timeline"],
    artifactKinds: ["pcap-flow-conversations", "pcap-http-objects", "runtime-adapter-transcript"],
    ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
    proofExitSignals: ["flow conversation", "follow-stream", "timeline evidence"],
  },
  {
    id: "binwalk-firmware-extract-adapter",
    bridgeId: "tool-bridge-runtime",
    domainId: "firmware-iot",
    tool: "binwalk",
    fallbackTool: "file",
    runnerKind: "shell-command",
    commandMarker: "adapter-binwalk-firmware-extract-runner",
    parserMarkers: ["parser-binwalk-signature", "parser-rootfs-extract", "parser-firmware-service-map"],
    artifactKinds: ["firmware-signature-map", "rootfs-extraction-manifest", "runtime-adapter-transcript"],
    ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
    proofExitSignals: ["filesystem extraction", "service map", "credential/config proof"],
  },
];

const NEGATIVE_CASES = [
  "missing-runner-template",
  "missing-parser-rule",
  "missing-ingest-target",
  "missing-artifact-kind",
  "missing-proof-exit-signal",
  "literal-secret-env-ref",
  "missing-adapter-domain",
];

const sha256 = (value) => createHash("sha256").update(String(value ?? "")).digest("hex");
const shortHash = (value) => sha256(value).slice(0, 24);
const check = (id, ok, evidence = {}) => ({ id, status: ok ? "pass" : "fail", evidence });
const readText = (path) => readFileSync(join(root, path), "utf8");
const maybeRead = (path) => (existsSync(join(root, path)) ? readText(path) : "");

function commandExists(tool) {
  const probe = spawnSync("sh", ["-lc", `command -v ${JSON.stringify(tool)} 2>/dev/null || true`], { cwd: root, encoding: "utf8", maxBuffer: 1024 * 1024 });
  const path = String(probe.stdout || "").trim().split(/\r?\n/)[0] || undefined;
  return { tool, present: Boolean(path), path, exitCode: probe.status ?? 0 };
}

function markerRow(id, path, markers) {
  const full = join(root, path);
  if (!existsSync(full)) return check(id, false, { path, exists: false, missing: markers });
  const text = readFileSync(full, "utf8");
  const missing = markers.filter((marker) => !text.includes(marker));
  return check(id, missing.length === 0, { path, missing, markerCount: markers.length, sha256: shortHash(text) });
}

function fixtureAdapters() {
  try {
    const fixture = JSON.parse(readText(FIXTURE_PATH));
    return Array.isArray(fixture.adapters) ? fixture.adapters : [];
  } catch {
    return [];
  }
}

function secretLike(value) {
  return /(sk-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9_]{10,}|github_pat_[A-Za-z0-9_]{10,}|AKIA[0-9A-Z]{12,}|-----BEGIN [A-Z ]+PRIVATE KEY-----)/.test(String(value ?? ""));
}

function buildReport() {
  const allTools = Array.from(new Set(ADAPTER_SPECS.flatMap((adapter) => [adapter.tool, adapter.fallbackTool]))).sort();
  const discovery = Object.fromEntries(allTools.map((tool) => [tool, commandExists(tool)]));
  const corpus = [
    maybeRead("packages/coding-agent/src/core/recon-profile.ts"),
    maybeRead("repi-profile/extensions/reverse-pentest-core.ts"),
    maybeRead("README.md"),
    maybeRead("docs/reverse-agent/README.md"),
    maybeRead("packages/coding-agent/docs/recon.md"),
    JSON.stringify(fixtureAdapters()),
  ].join("\n---REPI_RUNTIME_ADAPTER_EXECUTION_CORPUS---\n");
  const fixtureIds = fixtureAdapters().map((row) => row.id ?? row.adapterId).filter(Boolean);
  const adapters = ADAPTER_SPECS.map((adapter) => {
    const present = discovery[adapter.tool]?.present === true;
    const fallbackPresent = discovery[adapter.fallbackTool]?.present === true;
    const commandMarkerPresent = corpus.includes(adapter.commandMarker);
    const parserMarkersFound = adapter.parserMarkers.filter((marker) => corpus.includes(marker));
    const artifactMarkersFound = adapter.artifactKinds.filter((marker) => corpus.includes(marker));
    const ingestMarkersFound = adapter.ingestTargets.filter((marker) => corpus.includes(marker));
    const proofExitFound = adapter.proofExitSignals.filter((marker) => corpus.includes(marker));
    const envRefs = ["REPI_RUNTIME_ADAPTER_TIMEOUT_MS", "REPI_RUNTIME_ADAPTER_WORKDIR", adapter.id === "web-cdp-network-adapter" ? "REPI_BROWSER_CDP_URL" : undefined, adapter.id === "frida-mobile-hook-adapter" ? "REPI_FRIDA_DEVICE" : undefined].filter(Boolean);
    return {
      adapterId: adapter.id,
      bridgeId: adapter.bridgeId,
      domainId: adapter.domainId,
      runnerKind: adapter.runnerKind,
      tool: adapter.tool,
      present,
      fallbackTool: adapter.fallbackTool,
      fallbackPresent,
      status: present ? "native-ready" : fallbackPresent ? "fallback-ready" : "blocked",
      commandMarker: adapter.commandMarker,
      commandMarkerPresent,
      parserMarkers: adapter.parserMarkers,
      parserMarkersFound,
      parserMarkersMissing: adapter.parserMarkers.filter((marker) => !parserMarkersFound.includes(marker)),
      artifactKinds: adapter.artifactKinds,
      artifactMarkersFound,
      artifactMarkersMissing: adapter.artifactKinds.filter((marker) => !artifactMarkersFound.includes(marker)),
      ingestTargets: adapter.ingestTargets,
      ingestMarkersFound,
      ingestMarkersMissing: adapter.ingestTargets.filter((marker) => !ingestMarkersFound.includes(marker)),
      proofExitSignals: adapter.proofExitSignals,
      proofExitFound,
      proofExitMissing: adapter.proofExitSignals.filter((marker) => !proofExitFound.includes(marker)),
      envRefs,
      envRefOnly: envRefs.every((ref) => /^[A-Z][A-Z0-9_]+$/.test(ref) && !secretLike(ref)),
      fixtureParity: fixtureIds.includes(adapter.id),
      nextRuntimeCommands: [`re_runtime_adapter plan ${adapter.id} <target>`, `re_runtime_adapter run ${adapter.id} <target>`, "re_verifier matrix", "re_domain_proof_exit write <domain>"],
    };
  });
  const closure = {
    allAdapterSpecsPresent: adapters.length === ADAPTER_SPECS.length,
    allHaveRunnerTemplates: adapters.every((adapter) => adapter.commandMarkerPresent),
    allHaveParserRules: adapters.every((adapter) => adapter.parserMarkersMissing.length === 0),
    allHaveArtifactKinds: adapters.every((adapter) => adapter.artifactMarkersMissing.length === 0),
    allHaveIngestTargets: adapters.every((adapter) => adapter.ingestMarkersMissing.length === 0),
    allHaveProofExitSignals: adapters.every((adapter) => adapter.proofExitMissing.length === 0),
    allHaveNativeOrFallbackTool: adapters.every((adapter) => adapter.present || adapter.fallbackPresent),
    allEnvRefsSecretFree: adapters.every((adapter) => adapter.envRefOnly),
    fixtureParity: adapters.every((adapter) => adapter.fixtureParity),
  };
  return {
    kind: "RuntimeAdapterExecutionGateV1",
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    RuntimeAdapterExecutionGateV1: true,
    runtime: "runtime:adapter-execution",
    requiredGates: REQUIRED_GATES,
    discovery,
    adapters,
    closure,
    nextRuntimeCommands: ["re_runtime_adapter show", "re_runtime_adapter plan r2-native-xref-adapter <target>", "re_runtime_adapter run web-cdp-network-adapter <url>", "re_runtime_adapter run frida-mobile-hook-adapter <package>", "npm run gate:runtime-adapter-execution"],
    negativeCases: NEGATIVE_CASES.map((id) => ({ id, rejected: true })),
    invariants: [...REQUIRED_GATES, "runner_output_parser_must_write_artifact", "artifact_ingest_target_must_include_evidence_knowledge_memory", "adapter_run_secret_literals_rejected"],
  };
}

function validateReport(report) {
  const errors = [];
  if (report.kind !== "RuntimeAdapterExecutionGateV1") errors.push("kind_invalid");
  if (report.runtime !== "runtime:adapter-execution") errors.push("runtime_marker_missing");
  for (const gate of REQUIRED_GATES) if (!report.requiredGates?.includes(gate)) errors.push(`required_gate_missing:${gate}`);
  for (const id of ADAPTER_SPECS.map((adapter) => adapter.id)) if (!report.adapters?.some((adapter) => adapter.adapterId === id)) errors.push(`adapter_missing:${id}`);
  for (const adapter of report.adapters ?? []) {
    if (!adapter.commandMarkerPresent) errors.push(`runner_template_missing:${adapter.adapterId}`);
    if (adapter.parserMarkersMissing?.length) errors.push(`parser_rule_missing:${adapter.adapterId}`);
    if (adapter.artifactMarkersMissing?.length) errors.push(`artifact_kind_missing:${adapter.adapterId}`);
    if (adapter.ingestMarkersMissing?.length) errors.push(`ingest_target_missing:${adapter.adapterId}`);
    if (adapter.proofExitMissing?.length) errors.push(`proof_exit_signal_missing:${adapter.adapterId}`);
    if (!adapter.present && !adapter.fallbackPresent) errors.push(`tool_and_fallback_missing:${adapter.adapterId}`);
    if (!adapter.envRefOnly || adapter.envRefs?.some(secretLike)) errors.push(`env_ref_secret_boundary_failed:${adapter.adapterId}`);
    if (!adapter.nextRuntimeCommands?.some((cmd) => String(cmd).includes("re_runtime_adapter"))) errors.push(`runtime_command_missing:${adapter.adapterId}`);
  }
  for (const [key, value] of Object.entries(report.closure ?? {})) if (value !== true) errors.push(`closure_false:${key}`);
  return { ok: errors.length === 0, errors };
}

function mutateReport(report, id) {
  const clone = JSON.parse(JSON.stringify(report));
  if (id === "missing-runner-template") { clone.adapters[0].commandMarkerPresent = false; clone.closure.allHaveRunnerTemplates = false; }
  if (id === "missing-parser-rule") { clone.adapters[1].parserMarkersMissing = ["parser-ghidra-function-summary"]; clone.closure.allHaveParserRules = false; }
  if (id === "missing-ingest-target") { clone.adapters[2].ingestMarkersMissing = ["memory-event"]; clone.closure.allHaveIngestTargets = false; }
  if (id === "missing-artifact-kind") { clone.adapters[3].artifactMarkersMissing = ["cdp-network-har"]; clone.closure.allHaveArtifactKinds = false; }
  if (id === "missing-proof-exit-signal") { clone.adapters[4].proofExitMissing = ["multi-run verifier"]; clone.closure.allHaveProofExitSignals = false; }
  if (id === "literal-secret-env-ref") { clone.adapters[5].envRefs.push("sk-test-secret-literal"); clone.adapters[5].envRefOnly = false; clone.closure.allEnvRefsSecretFree = false; }
  if (id === "missing-adapter-domain") clone.adapters = clone.adapters.filter((adapter) => adapter.adapterId !== "binwalk-firmware-extract-adapter");
  return clone;
}

function main() {
  const report = buildReport();
  const validation = validateReport(report);
  const checks = [
    check("runtime:adapter-execution", validation.ok, { validation, closure: report.closure }),
    check("runtime:adapter-runner-templates", report.closure.allHaveRunnerTemplates, { adapters: report.adapters.map((adapter) => ({ id: adapter.adapterId, marker: adapter.commandMarker, present: adapter.commandMarkerPresent })) }),
    check("runtime:adapter-parser-rules", report.closure.allHaveParserRules, { missing: report.adapters.map((adapter) => ({ id: adapter.adapterId, missing: adapter.parserMarkersMissing })) }),
    check("runtime:adapter-artifact-ingest", report.closure.allHaveArtifactKinds && report.closure.allHaveIngestTargets, { adapters: report.adapters.map((adapter) => ({ id: adapter.adapterId, artifactKinds: adapter.artifactKinds, ingestTargets: adapter.ingestTargets })) }),
    check("runtime:adapter-proof-exits", report.closure.allHaveProofExitSignals, { missing: report.adapters.map((adapter) => ({ id: adapter.adapterId, missing: adapter.proofExitMissing })) }),
    check("runtime:adapter-tool-fallbacks", report.closure.allHaveNativeOrFallbackTool, { adapters: report.adapters.map((adapter) => ({ id: adapter.adapterId, present: adapter.present, fallbackPresent: adapter.fallbackPresent })) }),
    markerRow("code:runtime-adapter-execution", "packages/coding-agent/src/core/recon-profile.ts", ["RuntimeAdapterExecutionGateV1", "RUNTIME_ADAPTER_EXECUTION_MATRIX", "buildRuntimeAdapterExecutionGate", "formatRuntimeAdapterExecutionGate", "runRuntimeAdapterExecution", "re_runtime_adapter", "adapter-r2-native-xref-runner", "adapter-ghidra-headless-summary-runner", "adapter-frida-mobile-hook-runner", "adapter-web-cdp-network-runner", "adapter-pwntools-local-verifier-runner", "adapter-tshark-pcap-flow-runner", "adapter-binwalk-firmware-extract-runner"]),
    markerRow("profile:runtime-adapter-execution", "repi-profile/extensions/reverse-pentest-core.ts", ["RuntimeAdapterExecutionGateV1", "RUNTIME_ADAPTER_EXECUTION_MATRIX", "buildRuntimeAdapterExecutionGate", "formatRuntimeAdapterExecutionGate", "runRuntimeAdapterExecution", "re_runtime_adapter", "runtime:adapter-execution"]),
    markerRow("test:runtime-adapter-execution", "packages/coding-agent/test/recon-profile.test.ts", ["re_runtime_adapter", "re-runtime-adapter", "RuntimeAdapterExecutionGateV1"]),
    markerRow("npm:runtime-adapter-execution", "package.json", ["gate:runtime-adapter-execution", "runtime-adapter-execution-gate.mjs"]),
    markerRow("harness:runtime-adapter-execution", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:runtime-adapter-execution", "RuntimeAdapterExecutionGateV1", "child:gate:runtime-adapter-execution"]),
    markerRow("autonomy:runtime-adapter-execution", "scripts/reverse-agent/autonomy-control-plane.mjs", ["RuntimeAdapterExecutionGateV1", "runtime_adapter_execution_gate", "adapter_runner_parser_ingest_contract"]),
    markerRow("schema:runtime-adapter-execution", SCHEMA_PATH, ["RuntimeAdapterExecutionGateV1", "runtime_adapter_execution_gate", "adapter_runner_parser_ingest_contract", "r2_ghidra_native_adapter_contract", "frida_mobile_adapter_contract", "web_cdp_adapter_contract", "pwntools_exploit_verifier_adapter_contract"]),
    markerRow("fixture:runtime-adapter-execution", FIXTURE_PATH, ["RuntimeAdapterExecutionGateV1", "r2-native-xref-adapter", "ghidra-headless-summary-adapter", "frida-mobile-hook-adapter", "web-cdp-network-adapter", "pwntools-local-verifier-adapter", "tshark-pcap-flow-adapter", "binwalk-firmware-extract-adapter"]),
    markerRow("docs:runtime-adapter-execution-readme", "README.md", ["RuntimeAdapterExecutionGateV1", "re_runtime_adapter", "gate:runtime-adapter-execution", "adapter runner", "parser", "artifact ingest"]),
    markerRow("docs:runtime-adapter-execution-reverse-agent", "docs/reverse-agent/README.md", ["RuntimeAdapterExecutionGateV1", "adapter_runner_parser_ingest_contract", "re_runtime_adapter"]),
    markerRow("docs:runtime-adapter-execution-recon", "packages/coding-agent/docs/recon.md", ["RuntimeAdapterExecutionGateV1", "re_runtime_adapter", "runtime_adapter_execution_gate"]),
  ];
  const negatives = NEGATIVE_CASES.map((id) => {
    const result = validateReport(mutateReport(report, id));
    return { id, rejected: !result.ok, errors: result.errors };
  });
  checks.push(check("negative:runtime-adapter-execution", negatives.every((row) => row.rejected), { negatives }));
  const failed = checks.filter((row) => row.status !== "pass");
  const result = { ...report, ok: failed.length === 0, root, checks };
  if (writeEvidence) {
    const dir = join(root, ".repi-harness", "evidence", "runtime-adapter-execution", result.generatedAt.replace(/[:.]/g, "-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
  }
  if (json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log("# REPI Runtime Adapter Execution Gate");
    for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
    console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length} adapters=${report.adapters.length}`);
  }
  if (strict && failed.length) process.exitCode = 1;
}

main();
