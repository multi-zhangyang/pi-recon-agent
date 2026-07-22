#!/usr/bin/env node

/**
 * Opt-in live contract for the generic REPI_* model provider.
 *
 * This script intentionally does not know any provider, endpoint, or model
 * names. It is a small process-level check so it exercises the same launcher
 * and CLI path a user runs. Set REPI_RUN_LIVE_MODEL=1 to enable it; without
 * that flag the command is a no-op and never makes a network request.
 */
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
const root = resolve(args[0] && !args[0].startsWith("--") ? args.shift() : process.cwd());
const json = args.includes("--json");
const help = args.includes("--help") || args.includes("-h");

const BASE_URL_ENV = ["REPI_BASE_URL", "REPI_MODEL_BASE_URL", "REPI_API_BASE_URL", "REPI_ENDPOINT", "REPI_MODEL_ENDPOINT"];
const MODEL_ENV = ["REPI_MODEL", "REPI_MODEL_ID"];
const TOKEN_ENV = ["REPI_AUTH_TOKEN", "REPI_API_KEY", "REPI_MODEL_API_KEY", "REPI_TOKEN", "REPI_MODEL_TOKEN"];
const MAX_CAPTURE_BYTES = 8 * 1024 * 1024;

function usage() {
	console.log(`Usage: node scripts/reverse-agent/repi-live-model-contract.mjs [root] [--json]\n\n` +
		"Runs opt-in live checks for single response, tool round trip, and sequential multi-turn state.\n" +
		"Set REPI_RUN_LIVE_MODEL=1 and the generic REPI_* model variables to run.\n");
}

function firstEnv(names) {
	for (const name of names) {
		const value = process.env[name]?.trim();
		if (value) return { name, value };
	}
	return undefined;
}

function redact(value, secrets = []) {
	let text = String(value ?? "");
	for (const secret of secrets) {
		if (secret.length >= 4) text = text.split(secret).join("<redacted>");
	}
	return text
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\b(?:ghp_|github_pat_)[A-Za-z0-9_]{12,}\b/g, "<redacted:token>")
		.replace(/(authorization|x-api-key|api-key)\s*[:=]\s*(?:bearer\s+)?[^,\s}"']+/gi, "$1: <redacted>")
		.replace(/(https?:\/\/)[^/\s:@]+:[^/\s@]+@/gi, "$1<redacted>@");
}

function parseTimeout() {
	const raw = process.env.REPI_LIVE_MODEL_TIMEOUT_MS ?? "120000";
	const value = Number(raw);
	if (!Number.isSafeInteger(value) || value < 5_000 || value > 900_000) {
		throw new Error("REPI_LIVE_MODEL_TIMEOUT_MS must be an integer between 5000 and 900000");
	}
	return value;
}

function appendCapture(current, chunk) {
	const next = current + String(chunk);
	return next.length <= MAX_CAPTURE_BYTES ? next : next.slice(-MAX_CAPTURE_BYTES);
}

function parseJsonLines(stdout) {
	const events = [];
	let malformed = 0;
	for (const line of stdout.split(/\r?\n/)) {
		if (!line.trim()) continue;
		try {
			events.push(JSON.parse(line));
		} catch {
			malformed++;
		}
	}
	return { events, malformed };
}

function textFromContent(content) {
	if (!Array.isArray(content)) return "";
	return content
		.filter((part) => part && part.type === "text")
		.map((part) => String(part.text ?? ""))
		.join("");
}

function finalAssistantText(events) {
	const agentEnd = [...events].reverse().find((event) => event?.type === "agent_end");
	const messages = Array.isArray(agentEnd?.messages) ? agentEnd.messages : [];
	for (const message of [...messages].reverse()) {
		if (message?.role !== "assistant") continue;
		if (Array.isArray(message.content) && message.content.some((part) => part?.type === "toolCall")) continue;
		const text = textFromContent(message.content);
		if (text) return text;
	}
	return "";
}

function finalAssistantError(events) {
	const agentEnd = [...events].reverse().find((event) => event?.type === "agent_end");
	const messages = Array.isArray(agentEnd?.messages) ? agentEnd.messages : [];
	for (const message of [...messages].reverse()) {
		if (message?.role !== "assistant") continue;
		const errorMessage = typeof message.errorMessage === "string" ? message.errorMessage.trim() : "";
		if (errorMessage) return errorMessage;
	}
	return "";
}

function toolName(event) {
	return event?.toolName ?? event?.name ?? event?.tool?.name ?? "";
}

function runCli(caseId, commandArgs, secrets, timeoutMs, env) {
	return new Promise((resolveCase) => {
		const startedAt = Date.now();
		const command = process.env.REPI_BIN_PATH || join(root, "repi");
		const child = spawn(command, commandArgs, {
			cwd: root,
			env,
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		let timedOut = false;
		let settled = false;
		let killTimer;
		const finish = (code, signal, error) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			if (killTimer) clearTimeout(killTimer);
			const parsed = parseJsonLines(stdout);
			const events = parsed.events;
			const readStarts = events.filter((event) => event?.type === "tool_execution_start" && toolName(event) === "read");
			const readEnds = events.filter((event) => event?.type === "tool_execution_end" && toolName(event) === "read");
			resolveCase({
				id: caseId,
				exit: code ?? (signal ? 128 : 1),
				signal: signal ?? undefined,
				timedOut,
				ms: Date.now() - startedAt,
				malformedJsonLines: parsed.malformed,
				events,
				readStarts,
				readEnds,
				finalText: finalAssistantText(events),
				providerError: redact(finalAssistantError(events), secrets).slice(-2000),
				stderr: redact(stderr, secrets).slice(-2000),
				error: error ? redact(error.message ?? error, secrets) : undefined,
			});
		};
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill("SIGTERM");
			killTimer = setTimeout(() => child.kill("SIGKILL"), 5_000);
		}, timeoutMs);
		child.stdout?.on("data", (chunk) => {
			stdout = appendCapture(stdout, chunk);
		});
		child.stderr?.on("data", (chunk) => {
			stderr = appendCapture(stderr, chunk);
		});
		// A timeout can close pipes while the child is being terminated. These
		// listeners keep the contract reporter alive long enough to emit evidence.
		child.stdout?.on("error", () => {});
		child.stderr?.on("error", () => {});
		child.once("error", (error) => finish(1, undefined, error));
		child.once("close", (code, signal) => finish(code, signal));
	});
}

function summarizeCase(row, expectedText, needsRead, expectedTurns = 1) {
	const readIds = new Set(row.readStarts.map((event) => event?.toolCallId).filter((id) => typeof id === "string"));
	const matchingReadEnds = row.readEnds.filter((event) => readIds.has(event?.toolCallId));
	const agentEnds = row.events.filter((event) => event?.type === "agent_end");
	const checks = [
		["exit", row.exit === 0],
		["timeout", !row.timedOut],
		["json", row.malformedJsonLines === 0],
		["final", row.finalText === expectedText],
		["turn count", agentEnds.length === expectedTurns],
	];
	if (needsRead) {
		// Models may retry a read after a truncated/ambiguous tool result. Treat
		// that as normal bounded behavior: require at least one read and one
		// successful matching result, while still catching runaway tool loops.
		checks.push(["bounded read calls", row.readStarts.length >= 1 && row.readStarts.length <= 4]);
		checks.push(["read start id", row.readStarts.every((event) => typeof event?.toolCallId === "string" && event.toolCallId.length > 0)]);
		checks.push(["matching read end", matchingReadEnds.length >= 1]);
		checks.push(["successful read", row.readEnds.some((event) => event?.isError === false)]);
	}
	const failures = checks.filter(([, pass]) => !pass).map(([name]) => name);
	return {
		id: row.id,
		ok: failures.length === 0,
		exit: row.exit,
		ms: row.ms,
		finalText: row.finalText,
		readCalls: row.readStarts.length,
		turns: agentEnds.length,
		readSuccesses: row.readEnds.filter((event) => event?.isError === false).length,
		failures,
		...(row.timedOut ? { timeout: true } : {}),
		...(row.error ? { error: row.error } : {}),
		...(row.providerError ? { providerError: row.providerError } : {}),
		...(row.stderr ? { stderr: row.stderr } : {}),
	};
}

if (help) {
	usage();
	process.exit(0);
}

if (process.env.REPI_RUN_LIVE_MODEL !== "1") {
	const report = {
		kind: "repi-live-model-contract",
		schemaVersion: 1,
		enabled: false,
		skipped: true,
		reason: "set REPI_RUN_LIVE_MODEL=1 to enable network-backed checks",
	};
	if (json) console.log(JSON.stringify(report, null, 2));
	else console.log(`SKIP ${report.reason}`);
	process.exit(0);
}

const baseUrl = firstEnv(BASE_URL_ENV);
const model = firstEnv(MODEL_ENV);
const token = firstEnv(TOKEN_ENV);
const missing = [
	...(baseUrl ? [] : ["REPI_BASE_URL"]),
	...(model ? [] : ["REPI_MODEL"]),
	...(token ? [] : ["REPI_AUTH_TOKEN"]),
];
if (missing.length) {
	const report = {
		kind: "repi-live-model-contract",
		schemaVersion: 1,
		enabled: true,
		ok: false,
		error: `missing required environment values: ${missing.join(", ")}`,
	};
	if (json) console.log(JSON.stringify(report, null, 2));
	else console.error(`FAIL ${report.error}`);
	process.exit(2);
}

let timeoutMs;
try {
	timeoutMs = parseTimeout();
} catch (error) {
	console.error(`FAIL ${error.message}`);
	process.exit(2);
}

const packageName = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).name;
const temporaryProfile = process.env.REPI_LIVE_AGENT_DIR ? undefined : mkdtempSync(join(tmpdir(), "repi-live-contract-"));
const profileDir = process.env.REPI_LIVE_AGENT_DIR || temporaryProfile;
const childEnv = {
	...process.env,
	REPI_CODING_AGENT_DIR: profileDir,
	REPI_PRINT_PROGRESS: "0",
	REPI_SKIP_VERSION_CHECK: "1",
	REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
	REPI_TELEMETRY: "0",
};
const secrets = TOKEN_ENV.map((name) => process.env[name]).filter((value) => Boolean(value));
const commonArgs = [
	"--mode",
	"json",
	"--print",
	"--no-session",
	"--no-extensions",
	"--no-skills",
	"--no-prompt-templates",
	"--no-context-files",
	"--thinking",
	"off",
];

try {
	const single = await runCli(
		"single-response",
		[...commonArgs, "--no-tools", "Reply exactly: REPI_LIVE_SINGLE_OK"],
		secrets,
		timeoutMs,
		childEnv,
	);
	const tool = await runCli(
		"read-tool-round-trip",
		[
			...commonArgs,
			"--tools",
			"read",
			`Use the read tool exactly once to read package.json in the current repository. After the tool result, reply exactly with the package name field and no other text.`,
		],
		secrets,
		timeoutMs,
		childEnv,
	);
	const multiTurn = await runCli(
		"multi-turn",
		[
			...commonArgs,
			"Reply exactly: REPI_LIVE_TURN_ONE_OK",
			"Reply exactly: REPI_LIVE_TURN_TWO_OK",
			"Reply exactly: REPI_LIVE_TURN_THREE_OK",
		],
		secrets,
		timeoutMs,
		childEnv,
	);
	const cases = [
		summarizeCase(single, "REPI_LIVE_SINGLE_OK", false),
		summarizeCase(tool, packageName, true),
		summarizeCase(multiTurn, "REPI_LIVE_TURN_THREE_OK", false, 3),
	];
	const report = {
		kind: "repi-live-model-contract",
		schemaVersion: 1,
		enabled: true,
		ok: cases.every((row) => row.ok),
		model: model.value,
		modelEnv: model.name,
		api: process.env.REPI_MODEL_API || process.env.REPI_API || "openai-completions",
		cases,
	};
	if (json) console.log(JSON.stringify(report, null, 2));
	else {
		for (const row of cases) {
			console.log(`${row.ok ? "PASS" : "FAIL"} ${row.id} exit=${row.exit} ms=${row.ms}`);
			if (!row.ok && row.providerError) console.log(`  provider: ${row.providerError}`);
		}
		console.log(`verdict: ${report.ok ? "pass" : "fail"}`);
	}
	process.exitCode = report.ok ? 0 : 1;
} finally {
	if (temporaryProfile) rmSync(temporaryProfile, { recursive: true, force: true });
}
