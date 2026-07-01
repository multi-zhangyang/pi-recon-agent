#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, readFileSync } from "node:fs";
import { safeWriteReport } from "./lib/report-write-helpers.mjs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

const rawArgs = process.argv.slice(2);
let root = process.cwd();
if (rawArgs[0] && !rawArgs[0].startsWith("--")) root = resolve(rawArgs.shift());
const json = rawArgs.includes("--json");
const stdoutOnly = rawArgs.includes("--stdout");
const agentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const outputFlag = flagValue(rawArgs, ["--output", "-o"]);
const defaultOutput = join(agentDir, "recon", "bugreports", `repi-bugreport-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
const outputPath = outputFlag ? (outputFlag === "-" ? null : resolve(outputFlag)) : stdoutOnly ? null : defaultOutput;
const repi = process.env.REPI_BIN_PATH || join(root, "repi");

function usage() {
	return `Usage:
  repi bugreport [--output <path>] [--json]
  repi bugreport --stdout

Creates a strictly redacted local diagnostic bundle: doctor/model/memory summaries, swarm latest status, git/node/npm versions and runtime paths. It does not export auth.json, raw memory events, API keys, GitHub tokens, Authorization headers or base URLs.
`;
}

function flagValue(args, names, fallback = undefined) {
	const list = Array.isArray(names) ? names : [names];
	for (let index = 0; index < args.length; index++) {
		for (const name of list) {
			if (args[index] === name) return args[index + 1] ?? fallback;
			if (args[index].startsWith(`${name}=`)) return args[index].slice(name.length + 1);
		}
	}
	return fallback;
}

function hash(value) {
	return createHash("sha256").update(String(value ?? "")).digest("hex").slice(0, 16);
}

function redactText(value) {
	return String(value ?? "")
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\bglpat-[A-Za-z0-9_-]{16,}\b/g, "<redacted:gitlab-token>")
		.replace(/(?:AUTH_TOKEN|API_KEY|PASSWORD|SECRET|TOKEN|AUTHORIZATION)=\S+/gi, (match) => `${match.split("=")[0]}=<redacted>`)
		.replace(/Authorization:\s*Bearer\s+\S+/gi, "Authorization: Bearer <redacted>")
		.replace(/https?:\/\/[^\s"'<>]+/gi, (match) => `<redacted:url:${hash(match)}>`)
		.replace(/(baseUrl|baseURL|endpoint|url)"?\s*[:=]\s*"?[^\s",}]+/gi, (match) => `${match.split(/[:=]/)[0]}:<redacted:url>`);
}

function redactJson(value, depth = 0) {
	if (depth > 8) return "<truncated-depth>";
	if (value === null || value === undefined) return value;
	if (typeof value === "string") {
		const text = redactText(value);
		return text.length > 2000 ? `${text.slice(0, 1800)}...<truncated:${text.length - 1800}>` : text;
	}
	if (typeof value === "number" || typeof value === "boolean") return value;
	if (Array.isArray(value)) return value.slice(0, 200).map((item) => redactJson(item, depth + 1));
	if (typeof value === "object") {
		const out = {};
		for (const [key, inner] of Object.entries(value)) {
			if (/api[-_]?key|authorization|password|secret|token|credential|baseUrl|baseURL|endpoint|url/i.test(key)) {
				if (typeof inner === "string" && /url|baseUrl|endpoint/i.test(key)) out[key] = `<redacted:url:${hash(inner)}>`;
				else out[key] = "<redacted>";
			} else if (/stdout|stderr|prompt|target|task|command|cmd/i.test(key)) {
				out[key] = redactJson(inner, depth + 1);
			} else {
				out[key] = redactJson(inner, depth + 1);
			}
		}
		return out;
	}
	return redactText(String(value));
}

function run(cmd, args, options = {}) {
	const result = spawnSync(cmd, args, {
		cwd: root,
		env: {
			...process.env,
			REPI_OFFLINE: options.offline ?? "1",
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			PI_SKIP_VERSION_CHECK: "1",
			PI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
			PI_TELEMETRY: "0",
			REPI_PRINT_PROGRESS: "0",
		},
		encoding: "utf8",
		timeout: options.timeout ?? 30_000,
		maxBuffer: options.maxBuffer ?? 4 * 1024 * 1024,
	});
	const stdout = redactText(result.stdout ?? "");
	const stderr = redactText(result.stderr ?? "");
	let parsed;
	try {
		parsed = stdout.trim() ? JSON.parse(stdout) : undefined;
	} catch {
		parsed = undefined;
	}
	return {
		exit: result.status ?? (result.signal ? 128 : 1),
		signal: result.signal,
		stdoutTail: stdout.slice(-4000),
		stderrTail: stderr.slice(-4000),
		parsed: redactJson(parsed),
		error: result.error ? redactText(String(result.error.message || result.error)) : undefined,
	};
}

function fileExists(path) {
	try {
		return existsSync(path);
	} catch {
		return false;
	}
}

function safeReadPackage() {
	try {
		const parsed = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
		return { name: parsed.name, version: parsed.version, packageManager: parsed.packageManager };
	} catch (error) {
		return { error: String(error instanceof Error ? error.message : error) };
	}
}

function compactDoctor(parsed) {
	if (!parsed || typeof parsed !== "object") return parsed;
	return {
		kind: parsed.kind,
		ok: parsed.ok,
		root: parsed.root,
		agentDir: parsed.agentDir,
		checks: Array.isArray(parsed.checks)
			? parsed.checks.map((row) => ({ id: row.id, status: row.status, evidence: redactText(row.evidence), fix: redactText(row.fix) }))
			: undefined,
	};
}

function compactModelDoctor(parsed) {
	if (!parsed || typeof parsed !== "object") return parsed;
	return {
		kind: parsed.kind,
		ok: parsed.ok,
		agentDir: parsed.agentDir,
		providerCount: parsed.providerCount,
		modelCount: parsed.modelCount,
		diagnostics: parsed.diagnostics,
		providers: Array.isArray(parsed.providers)
			? parsed.providers.map((provider) => ({
				id: provider.id,
				api: provider.api,
				baseUrl: "<redacted>",
				authConfigured: provider.authConfigured,
				modelCount: Array.isArray(provider.models) ? provider.models.length : 0,
				models: (provider.models ?? []).map((model) => ({ modelHash: hash(model.id), contextWindow: model.contextWindow, maxTokens: model.maxTokens, reasoning: model.reasoning, cost: model.cost, issues: model.issues })),
				issues: provider.issues,
			}))
			: undefined,
	};
}

function compactMemoryDoctor(parsed) {
	if (!parsed || typeof parsed !== "object") return parsed;
	const status = parsed.status ?? {};
	return {
		kind: parsed.kind,
		ok: parsed.ok,
		agentDir: parsed.agentDir,
		memoryDir: parsed.memoryDir,
		diagnostics: parsed.diagnostics,
		posture: status.posture,
		pollutionGuardOk: status.pollutionGuardOk,
		eventStore: status.eventStore
			? {
				path: status.eventStore.path,
				missing: status.eventStore.missing,
				invalidLines: status.eventStore.invalidLines,
				total: status.eventStore.total,
				highValue: status.eventStore.highValue,
				pendingHighValue: status.eventStore.pendingHighValue,
			}
			: undefined,
		consolidation: status.consolidation,
		governance: status.governance,
		files: status.files,
	};
}

function scanSecrets(serialized) {
	const findings = [];
	const patterns = [
		["api-key", /\bsk-[A-Za-z0-9._-]{8,}\b/],
		["github-token", /\b(?:ghp_|github_pat_)[A-Za-z0-9_]{16,}\b/],
		["authorization", /Authorization:\s*Bearer\s+\S+/i],
		["url", /https?:\/\/[^\s"'<>]+/i],
	];
	for (const [id, pattern] of patterns) {
		if (pattern.test(serialized)) findings.push(id);
	}
	return findings;
}

if (rawArgs.includes("--help") || rawArgs.includes("-h")) {
	console.log(usage());
	process.exit(0);
}

const doctor = fileExists(repi) ? run(repi, ["doctor", "--json"], { timeout: 60_000 }) : { exit: 1, error: "missing repi launcher" };
const modelDoctor = fileExists(repi) ? run(repi, ["model", "doctor", "--json"], { timeout: 60_000 }) : { exit: 1, error: "missing repi launcher" };
const memoryDoctor = fileExists(repi) ? run(repi, ["memory", "doctor", "--json"], { timeout: 60_000 }) : { exit: 1, error: "missing repi launcher" };
const swarmStatus = fileExists(repi) ? run(repi, ["swarm", "status", "latest", "--json"], { timeout: 30_000 }) : { exit: 1, error: "missing repi launcher" };

const report = {
	kind: "repi-bugreport",
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	redaction: {
		strict: true,
		policy: "no auth.json export; no raw memory event export; API keys/tokens/Authorization/base URLs are redacted; model ids are hashed in model doctor summary",
	},
	runtime: {
		root,
		agentDir,
		repi,
		package: safeReadPackage(),
		node: redactText(process.version),
		platform: process.platform,
		arch: process.arch,
	},
	git: {
		commit: run("git", ["rev-parse", "--short", "HEAD"], { timeout: 10_000 }).stdoutTail.trim(),
		branch: run("git", ["rev-parse", "--abbrev-ref", "HEAD"], { timeout: 10_000 }).stdoutTail.trim(),
		statusShort: run("git", ["status", "--short"], { timeout: 10_000 }).stdoutTail.split(/\r?\n/).filter(Boolean).slice(0, 200),
	},
	commands: {
		doctor: { exit: doctor.exit, signal: doctor.signal, error: doctor.error, stderrTail: doctor.stderrTail, summary: compactDoctor(doctor.parsed) },
		modelDoctor: { exit: modelDoctor.exit, signal: modelDoctor.signal, error: modelDoctor.error, stderrTail: modelDoctor.stderrTail, summary: compactModelDoctor(modelDoctor.parsed) },
		memoryDoctor: { exit: memoryDoctor.exit, signal: memoryDoctor.signal, error: memoryDoctor.error, stderrTail: memoryDoctor.stderrTail, summary: compactMemoryDoctor(memoryDoctor.parsed) },
		swarmStatus: { exit: swarmStatus.exit, signal: swarmStatus.signal, error: swarmStatus.error, stderrTail: swarmStatus.stderrTail, summary: swarmStatus.parsed },
	},
};

let serialized = JSON.stringify(redactJson(report), null, 2);
const findings = scanSecrets(serialized);
const finalReport = {
	...redactJson(report),
	secretScan: {
		ok: findings.length === 0,
		findings,
	},
};
serialized = JSON.stringify(finalReport, null, 2);

if (outputPath) {
	// opt #177: wrap the final report write so an ENOSPC/EACCES mid-write does
	// not discard the ENTIRE gathered diagnostics with no partial output.
	// fallbackToStdout salvages the collection to stdout (redirect to recover).
	const written = safeWriteReport(outputPath, `${serialized}\n`, { fallbackToStdout: true });
	if (written) {
		try {
			chmodSync(outputPath, 0o600);
		} catch {
			// best effort
		}
	}
}

if (json || stdoutOnly || !outputPath) {
	console.log(serialized);
} else {
	console.log("REPI Bugreport");
	console.log(`output=${outputPath}`);
	console.log(`doctor=${finalReport.commands.doctor.exit} modelDoctor=${finalReport.commands.modelDoctor.exit} memoryDoctor=${finalReport.commands.memoryDoctor.exit} swarmStatus=${finalReport.commands.swarmStatus.exit}`);
	console.log(`secretScan=${finalReport.secretScan.ok ? "pass" : `fail:${finalReport.secretScan.findings.join(",")}`}`);
}

process.exit(finalReport.secretScan.ok ? 0 : 1);
