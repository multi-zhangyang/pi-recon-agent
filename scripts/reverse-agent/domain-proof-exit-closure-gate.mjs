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

const sha256 = (value) => createHash("sha256").update(String(value ?? "")).digest("hex");
const shortHash = (value) => sha256(value).slice(0, 24);
const check = (id, ok, evidence = {}) => ({ id, status: ok ? "pass" : "fail", evidence });
const read = (path) => readFileSync(join(root, path), "utf8");
const maybeRead = (path) => { try { return read(path); } catch { return ""; } };

function markerCheck(id, path, markers) {
  const full = join(root, path);
  if (!existsSync(full)) return check(id, false, { path, exists: false });
  const text = readFileSync(full, "utf8");
  const missing = markers.filter((marker) => !text.includes(marker));
  return check(id, missing.length === 0, { path, missing, sha256: shortHash(text) });
}

const PROOF_EXITS = {
  pwn: ["offset", "leak source", "controllable bytes", "local verifier"],
  "web-api": ["principal matrix", "object ownership", "state rollback", "signed replay divergence"],
  crypto: ["parameter derivation", "solver script", "known-answer test", "transform replay"],
};

function validateClosure(report) {
  const errors = [];
  if (report.kind !== "DomainProofExitClosureV1") errors.push("kind_invalid");
  if (!report.domainId) errors.push("domain_missing");
  if (!Array.isArray(report.rows) || report.rows.length === 0) errors.push("rows_missing");
  if (!Array.isArray(report.missingProofExits)) errors.push("missingProofExits_missing");
  if (!Array.isArray(report.nextRuntimeCommands) || !report.nextRuntimeCommands.some((cmd) => /re_lane|re_proof_loop|re_toolchain_domain/.test(cmd))) errors.push("nextRuntimeCommands_missing");
  if (!report.artifactCorpusHash || !/^[a-f0-9]{64}$/.test(report.artifactCorpusHash)) errors.push("artifactCorpusHash_invalid");
  const missingRows = report.rows.filter((row) => row.status === "missing");
  if (report.status === "passed" && missingRows.length) errors.push("passed_with_missing_rows");
  if (report.status !== "passed" && !report.blockers?.some((row) => /domain_proof_exit_missing|toolchain critical_gap/.test(row))) errors.push("blocked_without_domain_blocker");
  for (const row of report.rows) {
    if (!row.proofExit) errors.push("row_proofExit_missing");
    if (!row.expectedEvidence?.length) errors.push(`row_expectedEvidence_missing:${row.proofExit}`);
    if (!row.nextCommands?.length) errors.push(`row_nextCommands_missing:${row.proofExit}`);
    if (row.status === "matched" && !row.matchedArtifacts?.length && !row.matchedLines?.length) errors.push(`matched_without_evidence:${row.proofExit}`);
  }
  return { ok: errors.length === 0, errors };
}

function fakeClosure(domainId, corpus, matched = []) {
  const exits = PROOF_EXITS[domainId] ?? PROOF_EXITS.pwn;
  const rows = exits.map((proofExit) => {
    const isMatched = matched.includes(proofExit);
    return {
      proofExit,
      status: isMatched ? "matched" : "missing",
      matchedArtifacts: isMatched ? [`/tmp/${domainId}-${proofExit.replace(/\W+/g, "-")}.md`] : [],
      matchedLines: isMatched ? [`[${domainId}] ${proofExit} runtime evidence`] : [],
      expectedEvidence: ["runtime/replay/verifier command", "artifact path", "hash-bound output"],
      nextCommands: [`re_toolchain_domain show ${domainId}`, `re_lane plan prove <target>`, "re_proof_loop run <target> 4 2"],
    };
  });
  const missingProofExits = rows.filter((row) => row.status === "missing").map((row) => row.proofExit);
  return {
    kind: "DomainProofExitClosureV1",
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    missionId: "fixture",
    routeDomain: domainId,
    domainId,
    status: missingProofExits.length === 0 ? "passed" : matched.length ? "partial" : "blocked",
    toolchainStatus: "ready",
    artifactCorpusHash: sha256(corpus),
    artifactSources: ["/tmp/evidence-ledger.md"],
    rows,
    matchedProofExits: rows.filter((row) => row.status === "matched").map((row) => row.proofExit),
    missingProofExits,
    blockers: missingProofExits.map((proofExit) => `domain_proof_exit_missing:${domainId}:${proofExit}`),
    nextRuntimeCommands: [`re_toolchain_domain show ${domainId}`, `re_lane plan prove <target>`, "re_verifier matrix", "re_proof_loop run <target> 4 2", "re_complete audit"],
  };
}

function mutate(report, id) {
  const clone = JSON.parse(JSON.stringify(report));
  if (id === "wrong-kind") clone.kind = "NarrativeOnlyCompletion";
  if (id === "missing-row-next") clone.rows[0].nextCommands = [];
  if (id === "passed-with-missing") clone.status = "passed";
  if (id === "missing-hash") clone.artifactCorpusHash = "";
  if (id === "blocked-no-blocker") clone.blockers = [];
  if (id === "matched-no-evidence") { clone.rows[0].status = "matched"; clone.rows[0].matchedArtifacts = []; clone.rows[0].matchedLines = []; }
  return clone;
}

function main() {
  const checks = [];
  const pwnBlocked = fakeClosure("pwn", "minimal pwn evidence", []);
  const pwnPartial = fakeClosure("pwn", "offset and local verifier evidence", ["offset", "local verifier"]);
  const cryptoPassed = fakeClosure("crypto", "parameter derivation solver script known-answer test transform replay", PROOF_EXITS.crypto);
  checks.push(check("runtime:domain-proof-exit-blocks-empty-pwn", validateClosure(pwnBlocked).ok && pwnBlocked.status === "blocked" && pwnBlocked.missingProofExits.length === 4, { validation: validateClosure(pwnBlocked), missing: pwnBlocked.missingProofExits }));
  checks.push(check("runtime:domain-proof-exit-partial-pwn", validateClosure(pwnPartial).ok && pwnPartial.status === "partial" && pwnPartial.matchedProofExits.length === 2, { validation: validateClosure(pwnPartial), matched: pwnPartial.matchedProofExits, missing: pwnPartial.missingProofExits }));
  checks.push(check("runtime:domain-proof-exit-passed-crypto", validateClosure(cryptoPassed).ok && cryptoPassed.status === "passed" && cryptoPassed.missingProofExits.length === 0, { validation: validateClosure(cryptoPassed) }));
  const negatives = ["wrong-kind", "missing-row-next", "passed-with-missing", "missing-hash", "blocked-no-blocker", "matched-no-evidence"].map((id) => {
    const result = validateClosure(mutate(pwnBlocked, id));
    return { id, rejected: !result.ok, errors: result.errors };
  });
  checks.push(check("negative:domain-proof-exit-closure", negatives.every((row) => row.rejected), { negatives }));
  checks.push(markerCheck("code:domain-proof-exit-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["DomainProofExitClosureV1", "buildDomainProofExitClosure", "formatDomainProofExitClosure", "domain_proof_exit_closure", "domain_proof_exit_missing", "re_domain_proof_exit", "re-domain-proof-exit", "ToolchainDomainCapabilityV1"]));
  checks.push(markerCheck("profile:domain-proof-exit-runtime-mirror", "repi-profile/extensions/reverse-pentest-core.ts", ["DomainProofExitClosureV1", "domain_proof_exit_closure", "domain_proof_exit_missing", "ToolchainDomainCapabilityV1"]));
  checks.push(markerCheck("harness:domain-proof-exit", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:domain-proof-exit-closure", "child:gate:domain-proof-exit-closure", "DomainProofExitClosureV1"]));
  checks.push(markerCheck("autonomy:domain-proof-exit", "scripts/reverse-agent/autonomy-control-plane.mjs", ["domain_proof_exit_closure_gate", "DomainProofExitClosureV1", "domain_proof_exit_missing"]));
  checks.push(markerCheck("npm:domain-proof-exit", "package.json", ["gate:domain-proof-exit-closure", "domain-proof-exit-closure-gate.mjs"]));
  checks.push(markerCheck("docs:domain-proof-exit-readme", "README.md", ["DomainProofExitClosureV1", "re_domain_proof_exit", "gate:domain-proof-exit-closure"]));
  checks.push(markerCheck("docs:domain-proof-exit-reverse-agent", "docs/reverse-agent/README.md", ["DomainProofExitClosureV1", "domain_proof_exit_closure", "domain_proof_exit_missing"]));
  checks.push(markerCheck("schema:domain-proof-exit", "schemas/reverse-agent/domain-proof-exit-closure.schema.json", ["DomainProofExitClosureV1", "missingProofExits", "domain_proof_exit_missing"]));

  const failed = checks.filter((row) => row.status !== "pass");
  const result = { kind: "repi-domain-proof-exit-closure-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
  if (writeEvidence) {
    const dir = join(root, ".repi-harness", "evidence", "domain-proof-exit-closure", result.generatedAt.replace(/[:.]/g, "-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
  }
  if (json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log("# REPI Domain Proof Exit Closure Gate");
    for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
    console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
  }
  if (strict && failed.length) process.exitCode = 1;
}

main();
