#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const DEFAULT_SCHEMA_FILES = [
  "schemas/reverse-agent/role-contract.schema.json",
  "schemas/reverse-agent/claim-ledger-event.schema.json",
  "schemas/reverse-agent/claim-gate.schema.json",
  "schemas/reverse-agent/context-resume-contract.schema.json",
  "schemas/reverse-agent/failure-repair-contract.schema.json",
  "schemas/reverse-agent/division-validation-contract.schema.json",
];

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function safeJson(text, fallback = null) {
  try { return JSON.parse(text); } catch { return fallback; }
}

function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => { data += chunk; });
    process.stdin.on("end", () => resolve(data));
  });
}

function resolvePath(root, path) {
  if (!path) return "";
  if (existsSync(path)) return path;
  const rooted = join(root, path);
  return existsSync(rooted) ? rooted : path;
}

function requiredMissing(obj, fields) {
  return fields.filter((field) => obj?.[field] === undefined || obj?.[field] === null);
}

function dotValue(obj, query) {
  if (!query) return undefined;
  const gateMatch = /^gates\[name=([^\]]+)\]\.passed$/.exec(query);
  if (gateMatch) return Boolean((obj?.gates || []).find((gate) => gate?.name === gateMatch[1])?.passed);
  const parts = query.split(".");
  let cur = obj;
  for (const part of parts) {
    if (!part) continue;
    if (cur === undefined || cur === null) return undefined;
    cur = cur[part];
  }
  return cur;
}

function compareValue(observed, op, expected) {
  if (op === "==") return observed === expected;
  if (op === ">") return Number(observed) > Number(expected);
  if (op === "exists") return observed !== undefined && observed !== null;
  return false;
}

function validateSchemaFiles(root) {
  return DEFAULT_SCHEMA_FILES.map((file) => {
    const path = resolvePath(root, file);
    const text = existsSync(path) ? readFileSync(path, "utf8") : "";
    const json = text ? safeJson(text) : null;
    return { file, exists: Boolean(text), parseOk: Boolean(json), sha256: text ? sha256(text).slice(0, 24) : null };
  });
}

function validateRoleContract(contract) {
  const missing = requiredMissing(contract, ["contractVersion", "runId", "evidenceOrder", "roles", "ledgerPolicy", "conflictPolicy", "claimGatePolicy"]);
  const roleRequired = ["id", "mustEmit", "allowedClaimKinds", "forbiddenClaimKinds", "handoffTargets", "evidenceContract"];
  const roleRows = Array.isArray(contract?.roles) ? contract.roles.map((role) => ({ id: role.id, missing: requiredMissing(role, roleRequired) })) : [];
  const roleIds = new Set((contract?.roles || []).map((role) => role.id));
  const requiredRoles = ["mapper", "verifier", "adversary", "synthesizer"];
  const missingRoles = requiredRoles.filter((role) => !roleIds.has(role));
  const policyOk = contract?.ledgerPolicy?.appendOnly === true && contract?.conflictPolicy?.unresolvedBlocksFinal === true && contract?.claimGatePolicy?.finalPassRequiresVerifier === true;
  const ok = missing.length === 0 && missingRoles.length === 0 && roleRows.every((row) => row.missing.length === 0) && Array.isArray(contract.evidenceOrder) && contract.evidenceOrder.includes("same_window_live") && policyOk;
  return { status: ok ? "pass" : "fail", missing, missingRoles, roleRows, policyOk };
}

function validateHashChain(ledger) {
  const rows = [];
  let prevHash = "0".repeat(64);
  for (const event of ledger || []) {
    const { eventHash, ...withoutHash } = event;
    const expected = sha256(JSON.stringify(withoutHash));
    const ok = event.seq === rows.length + 1 && event.prevHash === prevHash && eventHash === expected;
    rows.push({ seq: event.seq, type: event.type, ok, expected: expected.slice(0, 16), actual: String(eventHash || "").slice(0, 16) });
    prevHash = eventHash;
  }
  return { status: rows.length && rows.every((row) => row.ok) ? "pass" : "fail", events: rows.length, badRows: rows.filter((row) => !row.ok).slice(0, 20) };
}

function loadArtifactMap(root, ledger) {
  const artifacts = new Map();
  const rows = [];
  for (const event of ledger.filter((item) => item.type === "artifact_handoff")) {
    const path = resolvePath(root, event.path);
    const exists = event.path ? existsSync(path) : false;
    const bytes = exists ? readFileSync(path) : null;
    const actualSha256 = bytes ? sha256(bytes) : null;
    const shaOk = exists && event.sha256 ? actualSha256 === event.sha256 : exists;
    const json = exists ? safeJson(bytes.toString("utf8")) : null;
    artifacts.set(event.artifactId, { event, path, exists, actualSha256, shaOk, json });
    rows.push({ artifactId: event.artifactId, path: event.path, exists, shaOk, expectedSha256: event.sha256 || null, actualSha256 });
  }
  return { artifacts, rows, status: rows.length && rows.every((row) => row.exists && row.shaOk) ? "pass" : "fail" };
}

function validateClaims(root, ledger) {
  const { artifacts, rows: artifactRows, status: artifactStatus } = loadArtifactMap(root, ledger);
  const claims = ledger.filter((item) => item.type === "claim");
  const validations = new Map(ledger.filter((item) => item.type === "validation").map((item) => [item.claimId, item]));
  const challenges = new Map();
  for (const event of ledger.filter((item) => item.type === "challenge")) {
    if (!challenges.has(event.claimId)) challenges.set(event.claimId, []);
    challenges.get(event.claimId).push(event);
  }
  const resolutions = new Map();
  for (const event of ledger.filter((item) => item.type === "resolution")) {
    for (const claimId of event.claimIds || []) {
      if (!resolutions.has(claimId)) resolutions.set(claimId, []);
      resolutions.get(claimId).push(event);
    }
  }
  const claimRows = claims.map((claim) => {
    const missing = requiredMissing(claim, ["claimId", "role", "scope", "kind", "statement", "evidenceRefs"]);
    const refs = claim.evidenceRefs || [];
    const refRows = refs.map((ref) => {
      const artifact = artifacts.get(ref.artifactId);
      const observed = artifact?.json ? dotValue(artifact.json, ref.query) : undefined;
      return { artifactId: ref.artifactId, query: ref.query, op: ref.op, expected: ref.value, observed, satisfied: compareValue(observed, ref.op, ref.value), artifactLoaded: Boolean(artifact?.json), artifactHashBound: Boolean(artifact?.event?.sha256 && artifact?.shaOk) };
    });
    const highConfidence = ["proven", "final_pass"].includes(claim.kind);
    const validation = validations.get(claim.claimId);
    const requiredGap = claim.required === true && claim.kind !== "proven";
    return {
      claimId: claim.claimId,
      scope: claim.scope,
      kind: claim.kind,
      required: Boolean(claim.required),
      highConfidence,
      requiredGap,
      missing,
      evidenceRefs: refs.length,
      refRows,
      refsSatisfied: highConfidence ? refRows.length > 0 && refRows.every((row) => row.satisfied && row.artifactHashBound && row.query) : true,
      validationResult: validation?.result || null,
      validated: highConfidence ? validation?.result === "pass" : Boolean(validation),
      challenged: !requiredGap || (challenges.get(claim.claimId) || []).length > 0,
      resolved: !requiredGap || (resolutions.get(claim.claimId) || []).length > 0,
    };
  });
  const badClaims = claimRows.filter((row) => row.missing.length || !row.evidenceRefs || !row.refsSatisfied || !row.validated || !row.challenged || !row.resolved);
  return { status: artifactStatus === "pass" && claimRows.length && badClaims.length === 0 ? "pass" : "fail", artifactRows, claimRows, badClaims: badClaims.slice(0, 20) };
}

function validateGateAndScores(result, options) {
  const gate = result.gate || {};
  const scores = result.scores || {};
  const platformRequiredScore = Number(scores.platformRequired?.score ?? NaN);
  const orchestrationScore = Number(scores.orchestration?.score ?? NaN);
  const requiredGaps = (result.claims?.platform || []).filter((claim) => claim.required && claim.kind !== "proven");
  const baseOk = gate.artifactPathsExist === true && gate.artifactHashesBound === true && gate.claimLedgerPresent === true && gate.orchestrationSeparatedFromPlatform === true && gate.antiSelfDelusion === true && Number.isFinite(platformRequiredScore) && Number.isFinite(orchestrationScore);
  const strictOk = options.strictClaims ? gate.requiredPlatformClaimsValidated === true && requiredGaps.length === 0 && platformRequiredScore === 100 : true;
  const gapsAllowed = options.allowPlatformGaps || options.strictClaims === false;
  const gapPolicyOk = requiredGaps.length === 0 || gapsAllowed || options.strictClaims === false;
  return { status: baseOk && strictOk && gapPolicyOk ? "pass" : "fail", baseOk, strictOk, gapPolicyOk, orchestrationScore, platformRequiredScore, requiredGaps: requiredGaps.map((claim) => ({ claimId: claim.claimId, scope: claim.scope, gate: claim.gate, kind: claim.kind })) };
}

function writeClaimReleaseMarker(root, report, inputText) {
  const stamp = report.generatedAt.replace(/[:.]/g, "-");
  const outDir = join(root, ".repi-harness", "evidence", "claim-release", stamp);
  mkdirSync(outDir, { recursive: true });
  const markerPath = join(outDir, "result.json");
  const gateAndScores = report.checks.gateAndScores || {};
  const marker = {
    kind: "pi-recon-claim-release-marker",
    generatedAt: report.generatedAt,
    mode: report.mode,
    ok: report.ok,
    root,
    markerPath,
    source: report.source,
    sourceSha256: sha256(inputText || ""),
    platformRequiredScore: gateAndScores.platformRequiredScore,
    orchestrationScore: gateAndScores.orchestrationScore,
    requiredGaps: gateAndScores.requiredGaps || [],
    checks: report.checks,
  };
  writeFileSync(markerPath, `${JSON.stringify(marker, null, 2)}\n`, "utf8");
  return { markerPath, marker };
}

function printHelp() {
  console.log(`Usage: node scripts/reverse-agent/validate-claim-ledger.mjs [result.json] [--stdin] [--root <root>] [--json] [--allow-platform-gaps] [--strict-claims] [--write-marker]\n\nValidates hard-eval claim contract/ledger/gates without running live benchmarks or model providers.`);
}

function formatText(report) {
  const lines = [
    "REPI claim ledger validation",
    `status: ${report.ok ? "pass" : "fail"}`,
    `mode: ${report.mode}`,
    "",
  ];
  for (const [name, check] of Object.entries(report.checks)) lines.push(`- ${name}: ${check.status}`);
  lines.push("", `platform_required_score: ${report.checks.gateAndScores.platformRequiredScore}`, `required_gaps: ${report.checks.gateAndScores.requiredGaps.map((gap) => gap.gate).join(",") || "none"}`);
  if (report.markerPath) lines.push(`claim_release_marker: ${report.markerPath}`);
  return `${lines.join("\n")}\n`;
}

async function main(argv) {
  if (argv.includes("--help") || argv.includes("-h")) return printHelp();
  const rootFlag = argv.indexOf("--root");
  const root = resolve(rootFlag >= 0 ? argv[rootFlag + 1] : process.cwd());
  const options = {
    allowPlatformGaps: argv.includes("--allow-platform-gaps"),
    strictClaims: argv.includes("--strict-claims"),
  };
  const inputText = argv.includes("--stdin")
    ? await readStdin()
    : (() => {
        const fileArg = argv.find((arg, index) => !arg.startsWith("-") && argv[index - 1] !== "--root");
        return fileArg ? readFileSync(resolvePath(root, fileArg), "utf8") : "";
      })();
  const input = safeJson(inputText);
  const checks = {
    schemaFiles: { status: "pass", rows: validateSchemaFiles(root) },
    roleContract: validateRoleContract(input?.contract || {}),
    hashChain: validateHashChain(input?.ledger || []),
    claims: validateClaims(root, input?.ledger || []),
    gateAndScores: validateGateAndScores(input || {}, options),
  };
  checks.schemaFiles.status = checks.schemaFiles.rows.every((row) => row.exists && row.parseOk) ? "pass" : "fail";
  const ok = Boolean(input) && Object.values(checks).every((check) => check.status === "pass");
  const report = {
    kind: "pi-recon-claim-ledger-validation",
    generatedAt: new Date().toISOString(),
    mode: options.strictClaims ? "strict-claims" : options.allowPlatformGaps ? "allow-platform-gaps" : "default",
    ok,
    source: input?.kind || "missing",
    checks,
  };
  if (argv.includes("--write-marker")) {
    const { markerPath } = writeClaimReleaseMarker(root, report, inputText);
    report.markerPath = markerPath;
  }
  if (argv.includes("--json")) console.log(JSON.stringify(report, null, 2));
  else process.stdout.write(formatText(report));
  if (!ok) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main(process.argv.slice(2));
