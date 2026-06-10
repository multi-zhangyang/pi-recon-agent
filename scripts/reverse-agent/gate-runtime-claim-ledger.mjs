#!/usr/bin/env node
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
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

export function buildResult(root, options = {}) {
	const stamp = new Date().toISOString().replace(/[:.]/g, "-");
	const outDir = resolve(root, ".repi-harness", "evidence", "runtime-claim-ledger", stamp);
	mkdirSync(outDir, { recursive: true });
	const fixture = buildRuntimeClaimLedgerAdapterFixture(root, join(outDir, "adapter-fixture"));
	const rows = [evaluateSource(root, fixture, outDir), ...discoverRuntimeClaimLedgerSources(root).map((loaded) => evaluateSource(root, loaded, outDir))];
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
		policy: {
			missingRuntimeArtifactIsNotPass: true,
			strictClaimsFailuresArePreservedAsPromotionBlocks: true,
			availableRuntimeLedgersMustPassAllowPlatformGapsValidator: true,
			requireAllSources: Boolean(options.requireAllSources),
			requirePromotion: Boolean(options.requirePromotion),
		},
		sources: Object.fromEntries(rows.map((row) => [row.source, row])),
		sourceSummary: rows.map(sourceSummary),
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
	console.log("Usage: node scripts/reverse-agent/gate-runtime-claim-ledger.mjs [root] [--json] [--strict] [--require-all-sources] [--require-promotion]");
}

function main(argv) {
	if (argv.includes("--help") || argv.includes("-h")) return printHelp();
	const rootArg = argv.find((arg) => !arg.startsWith("-"));
	const root = resolve(rootArg ?? process.cwd());
	const options = { requireAllSources: argv.includes("--require-all-sources"), requirePromotion: argv.includes("--require-promotion") };
	const result = buildResult(root, options);
	if (argv.includes("--json")) console.log(JSON.stringify(result, null, 2));
	else process.stdout.write(formatText(result));
	const strictOk = result.ok && (!options.requireAllSources || result.missingRuntimeArtifacts.length === 0) && (!options.requirePromotion || result.complete);
	if (argv.includes("--strict") && !strictOk) process.exitCode = 1;
}

export { runValidator };

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main(process.argv.slice(2));
