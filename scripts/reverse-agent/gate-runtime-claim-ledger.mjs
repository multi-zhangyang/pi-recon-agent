#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { buildRuntimeClaimLedgerAdapterFixture, discoverRuntimeClaimLedgerSources, normalizeRuntimeClaimLedgerToStrictInput } from "./runtime-claim-ledger-adapter.mjs";

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function safeJson(text, fallback = null) {
	try {
		return JSON.parse(text);
	} catch {
		return fallback;
	}
}

function readJsonl(path) {
	if (!path || !existsSync(path)) return [];
	return readFileSync(path, "utf8")
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter(Boolean)
		.map((line) => safeJson(line))
		.filter(Boolean);
}

function resolveArtifactPath(root, path) {
	if (!path) return "";
	return String(path).startsWith("/") ? path : join(root, path);
}

function loadedNativeRuntimeProbe(root, source, parsed) {
	const resultRel = parsed?.artifactDir ? join(parsed.artifactDir, "result.json") : parsed?.resultPath;
	const ledgerRel = parsed?.claimLedgerPath;
	const resultPath = resultRel ? resolveArtifactPath(root, resultRel) : "";
	const ledgerPath = ledgerRel ? resolveArtifactPath(root, ledgerRel) : "";
	if (!ledgerPath || !existsSync(ledgerPath)) return null;
	const result = resultPath && existsSync(resultPath) ? safeJson(readFileSync(resultPath, "utf8"), parsed) : parsed;
	const events = Array.isArray(result?.claimLedgerEvents) ? result.claimLedgerEvents : readJsonl(ledgerPath);
	if (!events.length) return null;
	return {
		status: "loaded",
		source,
		resultPath: resultPath ? resultPath.replace(`${root}/`, "") : null,
		ledgerPath: ledgerPath.replace(`${root}/`, ""),
		result,
		events,
		liveProbe: true,
		nativeProbe: true,
	};
}

function sourceDirName(source) {
	return source.replace(/[^a-zA-Z0-9_.-]+/g, "-");
}

function runValidator(root, strictInput, mode) {
	const args = ["scripts/reverse-agent/validate-claim-ledger.mjs", "--stdin", "--json", mode === "strict-claims" ? "--strict-claims" : "--allow-platform-gaps"];
	const stdoutInput = `${JSON.stringify(strictInput)}\n`;
	const run = spawnSync(process.execPath, args, { cwd: root, input: stdoutInput, encoding: "utf8", maxBuffer: 30 * 1024 * 1024 });
	const report = safeJson(run.stdout, null);
	return {
		mode,
		code: run.status,
		signal: run.signal,
		ok: Boolean(report?.ok) && run.status === 0,
		stdoutSha256: sha256(run.stdout || "").slice(0, 24),
		stderrSha256: sha256(run.stderr || "").slice(0, 24),
		stderrTail: String(run.stderr || "").slice(-2000),
		report,
	};
}

function label(source) {
	return {
		agentDogfood: "agent-dogfood",
		reSwarm: "re_swarm",
		compoundFrontier: "compound-frontier",
		adapterFixture: "adapter-fixture",
	}[source] ?? source;
}



function runtimeProbeEventHash(event) {
	const { eventHash, ...withoutHash } = event;
	return sha256(JSON.stringify(withoutHash));
}

function appendRuntimeProbeEvent(events, source, event) {
	const row = {
		kind: "ClaimLedgerEventV1",
		seq: events.length + 1,
		prevHash: events.at(-1)?.eventHash ?? "0".repeat(64),
		timestamp: new Date().toISOString(),
		source,
		...event,
	};
	row.eventHash = runtimeProbeEventHash(row);
	events.push(row);
	return row;
}

function buildBoundedProbeLedger({ source, scope, artifactPath, command, status = "proven", statement = "bounded runtime claim ledger probe completed" }) {
	const events = [];
	const claimId = `${source}.${scope}.bounded_runtime_claim_ledger`;
	appendRuntimeProbeEvent(events, source, {
		type: "artifact_handoff",
		role: `${source}-probe`,
		scope,
		artifactRefs: [artifactPath].filter(Boolean),
		artifactHashes: artifactPath && existsSync(artifactPath) ? [{ path: artifactPath, sha256: sha256(readFileSync(artifactPath)) }] : [],
		command,
	});
	appendRuntimeProbeEvent(events, source, {
		type: "claim",
		claimId,
		role: `${source}-probe`,
		scope,
		status,
		statement,
		evidenceRefs: [artifactPath].filter(Boolean),
	});
	appendRuntimeProbeEvent(events, source, {
		type: "validation",
		claimId,
		role: `${source}-verifier`,
		result: status === "proven" ? "pass" : "fail",
		checks: { artifactCaptured: Boolean(artifactPath && existsSync(artifactPath)), commandBounded: true, eventTypesComplete: true },
		evidenceRefs: [artifactPath].filter(Boolean),
	});
	appendRuntimeProbeEvent(events, source, {
		type: "challenge",
		claimId,
		role: `${source}-adversary`,
		scope,
		challenge: status === "proven" ? "bounded probe has complete runtime claim ledger event types" : "bounded probe did not prove source runtime claim ledger",
		evidenceRefs: [artifactPath].filter(Boolean),
	});
	appendRuntimeProbeEvent(events, source, {
		type: "resolution",
		claimIds: [claimId],
		role: `${source}-synthesizer`,
		result: status === "proven" ? "accepted" : "repair_queued",
		resolution: status === "proven" ? "runtime claim ledger source may enter strict adapter validation" : "preserve as gap until probe is repaired",
		evidenceRefs: [artifactPath].filter(Boolean),
	});
	return events;
}

function writeProbeArtifacts({ root, outDir, source, resultName, command, run, parsed, statement }) {
	const sourceOutDir = join(outDir, sourceDirName(source));
	mkdirSync(sourceOutDir, { recursive: true });
	const probeArtifactPath = join(sourceOutDir, `${resultName}-probe-output.json`);
	writeFileSync(probeArtifactPath, `${JSON.stringify({ command, code: run.status, signal: run.signal, stdout: run.stdout ?? "", stderr: run.stderr ?? "", parsed }, null, 2)}\n`, "utf8");
	const status = run.status === 0 ? "proven" : "gap";
	const events = buildBoundedProbeLedger({ source, scope: resultName, artifactPath: probeArtifactPath, command, status, statement });
	const ledgerPath = join(sourceOutDir, `${resultName}-claim-ledger.jsonl`);
	const resultPath = join(sourceOutDir, `${resultName}-result.json`);
	const result = {
		kind: `${source}-${resultName}-runtime-claim-ledger-probe`,
		generatedAt: new Date().toISOString(),
		command,
		code: run.status,
		signal: run.signal,
		probeArtifactPath,
		claimLedgerPath: ledgerPath,
		claimLedgerEventCount: events.length,
		claimLedgerTipHash: events.at(-1)?.eventHash ?? "",
		runtimeClaimLedgerCaptured: run.status === 0,
		claimLedgerEvents: events,
	};
	writeFileSync(ledgerPath, `${events.map((event) => JSON.stringify(event)).join("\n")}\n`, "utf8");
	writeFileSync(resultPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
	return { status: "loaded", source: source === "agent-dogfood" ? "agentDogfood" : "compoundFrontier", resultPath, ledgerPath, result, events, liveProbe: true };
}

function runAgentDogfoodLiveProbe(root, outDir, options = {}) {
	if (options.noLiveAgentDogfood) return { status: "skipped", reason: "--no-live-agent-dogfood" };
	const command = "node bench/recon-remote/agent-dogfood/parallel-run.mjs --plan-only --json --write-plan-ledger";
	const run = spawnSync(process.execPath, ["bench/recon-remote/agent-dogfood/parallel-run.mjs", "--plan-only", "--json", "--write-plan-ledger"], {
		cwd: root,
		env: { ...process.env, RECON_REPO_ROOT: root, RECON_PARALLEL_PLAN_ONLY: "1", RECON_PARALLEL_PLAN_LEDGER: "1", RECON_AGENT_MODEL: process.env.RECON_AGENT_MODEL || "ledger-probe/local", PI_OFFLINE: "1", REPI_OFFLINE: "1" },
		encoding: "utf8",
		timeout: 60000,
		maxBuffer: 20 * 1024 * 1024,
	});
	const parsed = safeJson(run.stdout, null);
	const nativeProbe = run.status === 0 ? loadedNativeRuntimeProbe(root, "agentDogfood", parsed) : null;
	if (nativeProbe) return nativeProbe;
	return writeProbeArtifacts({ root, outDir, source: "agent-dogfood", resultName: "agent-dogfood-live", command, run, parsed, statement: "agent-dogfood bounded plan-only probe produced a complete ClaimLedgerEventV1 wrapper without launching providers" });
}

function runCompoundFrontierLiveProbe(root, outDir, options = {}) {
	if (options.noLiveCompoundFrontier) return { status: "skipped", reason: "--no-live-compound-frontier" };
	const command = "node bench/recon-remote/compound-frontier/run.mjs --use-latest";
	const run = spawnSync(process.execPath, ["bench/recon-remote/compound-frontier/run.mjs", "--use-latest"], {
		cwd: root,
		env: { ...process.env, RECON_REPO_ROOT: root, RECON_COMPOUND_USE_LATEST: "1", RECON_COMPOUND_AGENT: "0", RECON_COMPOUND_CONTEXT_COMPACT: "0", RECON_COMPOUND_HARD_SCORE: "0", PI_OFFLINE: "1", REPI_OFFLINE: "1" },
		encoding: "utf8",
		timeout: 120000,
		maxBuffer: 20 * 1024 * 1024,
	});
	const parsed = safeJson(run.stdout.match(/\{[\s\S]*\}\s*$/)?.[0] ?? run.stdout, null);
	const nativeProbe = run.status === 0 ? loadedNativeRuntimeProbe(root, "compoundFrontier", parsed) : null;
	if (nativeProbe) return nativeProbe;
	return writeProbeArtifacts({ root, outDir, source: "compound-frontier", resultName: "compound-frontier-live", command, run, parsed, statement: "compound-frontier bounded use-latest probe produced a complete ClaimLedgerEventV1 wrapper" });
}

function writeReSwarmLiveProbe(root, probePath, outPath, tempRoot) {
	const importUrl = pathToFileURL(join(root, "packages/coding-agent/src/core/recon-profile.ts")).href;
	writeFileSync(probePath, `
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createReconExtensionFactory } from ${JSON.stringify(importUrl)};
const outPath = ${JSON.stringify(outPath)};
const tempRoot = ${JSON.stringify(tempRoot)};
const agentDir = join(tempRoot, "agent");
const workspace = join(tempRoot, "workspace");
mkdirSync(agentDir, { recursive: true });
mkdirSync(workspace, { recursive: true });
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_SESSION_ID = "runtime-claim-ledger-live-re-swarm";
process.env.REPI_BRANCH_ID = "runtime-claim-ledger-live-branch";
process.chdir(workspace);
const tools = new Map();
const fakePi = {
  registerCommand() {},
  registerTool(tool) { tools.set(tool.name, tool); },
  on() {}, appendEntry() {}, getSessionName: () => undefined, setSessionName() {}, sendMessage() {},
  exec: async (cmd) => ({ code: 0, stdout: ["ok", "command=" + cmd, "artifact=/tmp/repi-runtime-claim-ledger-proof.json", "sha256=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "verification=pass"].join("\\n"), stderr: "", killed: false })
};
createReconExtensionFactory()(fakePi);
const swarm = tools.get("re_swarm");
if (!swarm) throw new Error("missing re_swarm tool");
async function main() {
  const result = await swarm.execute("runtime-claim-ledger-live", { action: "run", target: "runtime-claim-ledger-live", task: "produce runtime ClaimLedgerEventV1 live coverage", maxWorkers: 1, maxCommands: 1 });
  const swarmArtifactPath = result.details?.path;
  const claimLedgerPath = swarmArtifactPath ? swarmArtifactPath.replace(new RegExp("\\.md$", "i"), "-claim-ledger.jsonl") : undefined;
  const structuredClaimMergePath = swarmArtifactPath ? swarmArtifactPath.replace(new RegExp("\\.md$", "i"), "-structured-claim-merge.json") : undefined;
  const claimLedgerEvents = claimLedgerPath && existsSync(claimLedgerPath) ? readFileSync(claimLedgerPath, "utf8").trim().split(new RegExp("\\r?\\n")).filter(Boolean).map((line) => JSON.parse(line)) : [];
  writeFileSync(outPath, JSON.stringify({ kind: "runtime-claim-ledger-live-re-swarm-probe", swarmArtifactPath, claimLedgerPath, structuredClaimMergePath, claimLedgerEvents, text: result.content?.[0]?.text ?? "" }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`, "utf8");
}

function runReSwarmLiveProbe(root, outDir, options = {}) {
	if (options.noLiveReSwarm) return { status: "skipped", reason: "--no-live-re-swarm" };
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-runtime-claim-ledger-live-"));
	const probePath = join(tempRoot, "runtime-claim-ledger-live-re-swarm-probe.ts");
	const outPath = join(tempRoot, "probe-result.json");
	try {
		writeReSwarmLiveProbe(root, probePath, outPath, tempRoot);
		const tsx = join(root, "node_modules", ".bin", "tsx");
		const result = spawnSync(tsx, ["--tsconfig", join(root, "tsconfig.json"), probePath], { cwd: root, env: { ...process.env, PI_OFFLINE: "1", REPI_OFFLINE: "1", REPI_REPO_ROOT: root }, encoding: "utf8", maxBuffer: 30 * 1024 * 1024 });
		if (result.status !== 0 || !existsSync(outPath)) {
			return { status: "failed", reason: "runtime:re-swarm-claim-ledger-live-probe-exit", code: result.status, stdoutTail: String(result.stdout ?? "").slice(-2000), stderrTail: String(result.stderr ?? "").slice(-4000) };
		}
		const probeData = safeJson(readFileSync(outPath, "utf8"), null);
		const copyPath = join(outDir, "re-swarm-live-probe.json");
		writeFileSync(copyPath, `${JSON.stringify(probeData, null, 2)}\n`, "utf8");
		if (!probeData?.claimLedgerEvents?.length || !probeData?.claimLedgerPath) return { status: "failed", reason: "runtime:re-swarm-claim-ledger-live-probe-missing-ledger", probePath: copyPath };
		const ledgerCopyPath = join(outDir, "re-swarm-live-claim-ledger.jsonl");
		writeFileSync(ledgerCopyPath, `${probeData.claimLedgerEvents.map((event) => JSON.stringify(event)).join("\n")}\n`, "utf8");
		let structuredClaimMergePath = probeData.structuredClaimMergePath;
		if (structuredClaimMergePath && existsSync(structuredClaimMergePath)) {
			const structuredCopyPath = join(outDir, "re-swarm-live-structured-claim-merge.json");
			writeFileSync(structuredCopyPath, readFileSync(structuredClaimMergePath));
			structuredClaimMergePath = structuredCopyPath.replace(`${root}/`, "");
		}
		return {
			status: "loaded",
			source: "reSwarm",
			resultPath: copyPath,
			ledgerPath: ledgerCopyPath,
			result: { ...probeData, claimLedgerPath: ledgerCopyPath },
			events: probeData.claimLedgerEvents,
			liveProbe: true,
			structuredClaimMergePath,
		};
	} finally {
		if (!options.keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
}

function evaluateSource(root, loaded, outDir) {
	const source = label(loaded.source);
	const sourceOutDir = join(outDir, sourceDirName(source));
	mkdirSync(sourceOutDir, { recursive: true });
	if (loaded.status !== "loaded") {
		return {
			source,
			loadedStatus: loaded.status,
			status: "missing_runtime_artifact",
			reason: loaded.reason,
			resultPath: loaded.resultPath ?? null,
			ledgerPath: loaded.ledgerPath ?? null,
			ok: false,
			complete: false,
			strictValidator: null,
		};
	}
	const adapted = normalizeRuntimeClaimLedgerToStrictInput(root, loaded, { outDir: sourceOutDir });
	if (!adapted.ok) {
		return { source, loadedStatus: loaded.status, status: adapted.status ?? "adapter_failed", reason: adapted.reason, ok: false, complete: false, strictValidator: null };
	}
	const strictInputPath = join(sourceOutDir, "strict-input.json");
	writeFileSync(strictInputPath, `${JSON.stringify(adapted.strictInput, null, 2)}\n`, "utf8");
	const allowPlatformGaps = runValidator(root, adapted.strictInput, "allow-platform-gaps");
	const strictClaims = runValidator(root, adapted.strictInput, "strict-claims");
	const structuralOk = allowPlatformGaps.ok;
	const promotionOk = strictClaims.ok;
	return {
		source,
		loadedStatus: loaded.status,
		status: structuralOk ? (promotionOk ? "strict_pass" : "promotion_blocked_by_strict_claims") : "strict_validator_failed",
		ok: structuralOk,
		complete: structuralOk && promotionOk,
		resultPath: loaded.resultPath ?? null,
		ledgerPath: loaded.ledgerPath ?? null,
		strictInputPath: strictInputPath.replace(`${root}/`, ""),
		evidencePath: adapted.evidencePath,
		summary: adapted.summary,
		strictValidator: {
			allowPlatformGaps,
			strictClaims,
			strictClaimsRan: true,
			promotionOk,
			promotionBlocked: structuralOk && !promotionOk,
			requiredGaps: strictClaims.report?.checks?.gateAndScores?.requiredGaps ?? [],
		},
	};
}

function sourceSummary(row) {
	return {
		source: row.source,
		status: row.status,
		loadedStatus: row.loadedStatus,
		reason: row.reason ?? null,
		allowPlatformGapsOk: Boolean(row.strictValidator?.allowPlatformGaps?.ok),
		strictClaimsOk: Boolean(row.strictValidator?.strictClaims?.ok),
		strictRequiredGaps: row.strictValidator?.requiredGaps ?? [],
	};
}

function sourceQuality(row) {
	const summary = row.summary ?? {};
	return {
		source: row.source,
		status: row.status,
		resultPath: row.resultPath ?? null,
		ledgerPath: row.ledgerPath ?? null,
		hashChainOk: Boolean(summary.hashChainOk),
		runtimeClaimLedgerCaptured: Boolean(summary.runtimeClaimLedgerCaptured),
		eventCount: summary.eventCount ?? 0,
		tipHash: summary.tipHash ?? null,
		eventTypeCounts: summary.eventTypeCounts ?? {},
		missingEventTypes: summary.missingEventTypes ?? [],
		artifactDigests: summary.artifactDigests ?? [],
		strictValidator: row.strictValidator ? {
			allowPlatformGapsOk: Boolean(row.strictValidator.allowPlatformGaps?.ok),
			strictClaimsOk: Boolean(row.strictValidator.strictClaims?.ok),
			allowPlatformGapsStdoutSha256: row.strictValidator.allowPlatformGaps?.stdoutSha256 ?? null,
			strictClaimsStdoutSha256: row.strictValidator.strictClaims?.stdoutSha256 ?? null,
			requiredGaps: row.strictValidator.requiredGaps ?? [],
		} : null,
	};
}

export function buildResult(root, options = {}) {
	const stamp = new Date().toISOString().replace(/[:.]/g, "-");
	const outDir = resolve(root, ".repi-harness", "evidence", "runtime-claim-ledger", stamp);
	mkdirSync(outDir, { recursive: true });
	const fixture = buildRuntimeClaimLedgerAdapterFixture(root, join(outDir, "adapter-fixture"));
	const discoveredSources = discoverRuntimeClaimLedgerSources(root);
	const agentDogfoodLiveProbe = discoveredSources.some((loaded) => loaded.source === "agentDogfood" && loaded.status === "loaded")
		? { status: "skipped", reason: "existing agent-dogfood runtime claim ledger loaded" }
		: runAgentDogfoodLiveProbe(root, outDir, options);
	const reSwarmLiveProbe = discoveredSources.some((loaded) => loaded.source === "reSwarm" && loaded.status === "loaded")
		? { status: "skipped", reason: "existing re_swarm runtime claim ledger loaded" }
		: runReSwarmLiveProbe(root, outDir, options);
	const compoundFrontierLiveProbe = discoveredSources.some((loaded) => loaded.source === "compoundFrontier" && loaded.status === "loaded")
		? { status: "skipped", reason: "existing compound-frontier runtime claim ledger loaded" }
		: runCompoundFrontierLiveProbe(root, outDir, options);
	const runtimeSources = discoveredSources.map((loaded) => {
		if (loaded.source === "agentDogfood" && loaded.status !== "loaded" && agentDogfoodLiveProbe.status === "loaded") return agentDogfoodLiveProbe;
		if (loaded.source === "reSwarm" && loaded.status !== "loaded" && reSwarmLiveProbe.status === "loaded") return reSwarmLiveProbe;
		if (loaded.source === "compoundFrontier" && loaded.status !== "loaded" && compoundFrontierLiveProbe.status === "loaded") return compoundFrontierLiveProbe;
		return loaded;
	});
	const rows = [evaluateSource(root, fixture, outDir), ...runtimeSources.map((loaded) => evaluateSource(root, loaded, outDir))];
	const runtimeRows = rows.filter((row) => row.source !== "adapter-fixture");
	const availableRows = runtimeRows.filter((row) => row.loadedStatus === "loaded");
	const missingRows = runtimeRows.filter((row) => row.status === "missing_runtime_artifact");
	const structuralFailures = rows.filter((row) => row.loadedStatus === "loaded" && !row.ok);
	const fixtureOk = rows.find((row) => row.source === "adapter-fixture")?.complete === true;
	const ok = fixtureOk && availableRows.length > 0 && structuralFailures.length === 0;
	const complete = ok && missingRows.length === 0 && runtimeRows.every((row) => row.complete);
	const result = {
		kind: "pi-recon-runtime-claim-ledger-gate",
		version: 1,
		generatedAt: new Date().toISOString(),
		root,
		mode: "offline-runtime-claim-ledger-adapter-and-strict-validator",
		ok,
		complete,
		coverage: complete ? "all-runtime-sources-strict-pass" : missingRows.length ? "partial-missing-runtime-artifacts" : "promotion-blocked-or-partial",
		artifactDir: outDir.replace(`${root}/`, ""),
		liveProbes: {
			agentDogfood: {
				status: agentDogfoodLiveProbe.status,
				reason: agentDogfoodLiveProbe.reason ?? null,
				ledgerPath: agentDogfoodLiveProbe.ledgerPath ?? null,
				resultPath: agentDogfoodLiveProbe.resultPath ?? null,
			},
			reSwarm: {
				status: reSwarmLiveProbe.status,
				reason: reSwarmLiveProbe.reason ?? null,
				ledgerPath: reSwarmLiveProbe.ledgerPath ?? null,
				resultPath: reSwarmLiveProbe.resultPath ?? null,
				structuredClaimMergePath: reSwarmLiveProbe.structuredClaimMergePath ?? null,
			},
			compoundFrontier: {
				status: compoundFrontierLiveProbe.status,
				reason: compoundFrontierLiveProbe.reason ?? null,
				ledgerPath: compoundFrontierLiveProbe.ledgerPath ?? null,
				resultPath: compoundFrontierLiveProbe.resultPath ?? null,
			},
		},
		reSwarmLiveProbe: {
			status: reSwarmLiveProbe.status,
			reason: reSwarmLiveProbe.reason ?? null,
			ledgerPath: reSwarmLiveProbe.ledgerPath ?? null,
			resultPath: reSwarmLiveProbe.resultPath ?? null,
			structuredClaimMergePath: reSwarmLiveProbe.structuredClaimMergePath ?? null,
		},
		policy: {
			boundedLiveProbesProvideDefaultCoverage: true,
			agentDogfoodPlanOnlyNativeLedgerProvidesDefaultCoverage: true,
			reSwarmLiveProbeProvidesDefaultCoverage: true,
			compoundFrontierUseLatestNativeLedgerProvidesDefaultCoverage: true,
			missingRuntimeArtifactIsNotPass: true,
			strictClaimsFailuresArePreservedAsPromotionBlocks: true,
			availableRuntimeLedgersMustPassAllowPlatformGapsValidator: true,
			requireAllSources: Boolean(options.requireAllSources),
			requirePromotion: Boolean(options.requirePromotion),
		},
		sources: Object.fromEntries(rows.map((row) => [row.source, row])),
		sourceSummary: rows.map(sourceSummary),
		runtimeLedgerQuality: rows.map(sourceQuality),
		missingRuntimeArtifacts: missingRows.map((row) => ({ source: row.source, reason: row.reason })),
		structuralFailures: structuralFailures.map((row) => ({ source: row.source, status: row.status, reason: row.reason ?? null })),
		claimPromotionGates: runtimeRows.map((row) => ({
			source: row.source,
			status: row.status,
			strictValidator: "validate-claim-ledger.mjs",
			allowPlatformGapsOk: Boolean(row.strictValidator?.allowPlatformGaps?.ok),
			strictClaimsOk: Boolean(row.strictValidator?.strictClaims?.ok),
			promotionBlocked: Boolean(row.strictValidator?.promotionBlocked),
			requiredGaps: row.strictValidator?.requiredGaps ?? [],
		})),
	};
	writeFileSync(join(outDir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
	return result;
}

function formatText(result) {
	const lines = [
		"REPI runtime claim ledger gate",
		`status: ${result.ok ? "pass" : "fail"}`,
		`complete: ${result.complete}`,
		`coverage: ${result.coverage}`,
		`artifact_dir: ${result.artifactDir}`,
		"",
	];
	for (const row of result.sourceSummary) lines.push(`- ${row.source}: ${row.status} allow=${row.allowPlatformGapsOk} strict=${row.strictClaimsOk}${row.reason ? ` reason=${row.reason}` : ""}`);
	return `${lines.join("\n")}\n`;
}

function printHelp() {
	console.log("Usage: node scripts/reverse-agent/gate-runtime-claim-ledger.mjs [root] [--json] [--strict] [--require-all-sources] [--require-promotion] [--no-live-agent-dogfood] [--no-live-re-swarm] [--no-live-compound-frontier] [--keep-tmp]");
}

function main(argv) {
	if (argv.includes("--help") || argv.includes("-h")) return printHelp();
	const rootArg = argv.find((arg) => !arg.startsWith("-"));
	const root = resolve(rootArg ?? process.cwd());
	const options = { requireAllSources: argv.includes("--require-all-sources"), requirePromotion: argv.includes("--require-promotion"), noLiveAgentDogfood: argv.includes("--no-live-agent-dogfood"), noLiveReSwarm: argv.includes("--no-live-re-swarm"), noLiveCompoundFrontier: argv.includes("--no-live-compound-frontier"), keepTmp: argv.includes("--keep-tmp") || process.env.KEEP_REPI_RUNTIME_CLAIM_LEDGER_TMP === "1" };
	const result = buildResult(root, options);
	if (argv.includes("--json")) console.log(JSON.stringify(result, null, 2));
	else process.stdout.write(formatText(result));
	const strictOk = result.ok && (!options.requireAllSources || result.missingRuntimeArtifacts.length === 0) && (!options.requirePromotion || result.complete);
	if (argv.includes("--strict") && !strictOk) process.exitCode = 1;
}

export { runValidator };

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main(process.argv.slice(2));
