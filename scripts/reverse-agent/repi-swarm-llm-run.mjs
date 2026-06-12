#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";

const rawArgs = process.argv.slice(2);
let root = process.cwd();
if (rawArgs[0] && !rawArgs[0].startsWith("--")) root = resolve(rawArgs.shift());

function usage() {
	return `Usage:
  repi swarm llm-run <target> --workers N [--provider <id>] [--model <id>] [--prompt <text>]

Options:
  --target <text>          Target/task label if no positional target is supplied
  --workers <N>            Number of parallel LLM workers (default: 3, max: 16)
  --provider <id>          Provider id from ~/.repi/agent/models.json or built-ins
  --model <id>             Model id
  --prompt <text>          Worker prompt. Supports {id}, {{id}}, <id>, {target}, <target>
  --tools <list>           Enable tools for workers, e.g. bash,read,grep,ls (default: --no-tools)
  --expect <regex>         Per-worker success regex. Supports the same substitutions
  --timeout-ms <ms>        Per-worker timeout (default: REPI_SWARM_LLM_TIMEOUT_MS or 210000)
  --keep-profiles          Keep temporary isolated worker profiles for debugging
  --json                   Print JSON report only

Examples:
  repi swarm llm-run local-selfcheck --workers 3 --provider openai-compatible --model vendor/model \\
    --prompt "Reply exactly: REPI_SWARM_WORKER_{id}_OK" --expect "REPI_SWARM_WORKER_{id}_OK"
  repi swarm llm-run ./target --workers 4 --tools bash,read,grep,ls \\
    --prompt "Worker {id}: map one independent attack/reverse path for {target}; return evidence and blockers."
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

function parseIntFlag(args, names, fallback, min, max) {
	const raw = flagValue(args, names, "");
	const parsed = Number.parseInt(raw, 10);
	if (!Number.isFinite(parsed)) return fallback;
	return Math.max(min, Math.min(max, parsed));
}

function positionalTarget(args) {
	for (const arg of args) {
		if (!arg.startsWith("--")) return arg;
	}
	return undefined;
}

function redact(value) {
	return String(value ?? "")
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/(?:AUTH_TOKEN|API_KEY|PASSWORD|SECRET|TOKEN)=\S+/gi, (match) => `${match.split("=")[0]}=<redacted>`);
}

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function clip(value, max = 12000) {
	const text = redact(value);
	return text.length > max ? `${text.slice(0, max - 32)}\n...<truncated:${text.length - max + 32}>` : text;
}

function substitute(template, workerId, target) {
	return String(template ?? "")
		.replaceAll("{{id}}", String(workerId))
		.replaceAll("{id}", String(workerId))
		.replaceAll("<id>", String(workerId))
		.replaceAll("{{target}}", target)
		.replaceAll("{target}", target)
		.replaceAll("<target>", target);
}

function copyIfExists(from, to) {
	if (existsSync(from)) copyFileSync(from, to);
}

function prepareWorkerAgentDir(sourceAgentDir, tempRoot, workerId) {
	const dir = join(tempRoot, `worker-${workerId}`, "agent");
	mkdirSync(dir, { recursive: true, mode: 0o700 });
	for (const name of ["models.json", "auth.json", "settings.json"]) copyIfExists(join(sourceAgentDir, name), join(dir, name));
	return dir;
}

function runWorker({ workerId, target, promptTemplate, expectTemplate, provider, model, tools, timeoutMs, runRoot, sourceAgentDir, tempRoot }) {
	return new Promise((resolveWorker) => {
		const workerAgentDir = prepareWorkerAgentDir(sourceAgentDir, tempRoot, workerId);
		const prompt = substitute(promptTemplate, workerId, target);
		const args = [
			"--approve",
			...(provider ? ["--provider", provider] : []),
			...(model ? ["--model", model] : []),
			"--thinking",
			"off",
			"--no-session",
			...(tools ? ["--tools", tools] : ["--no-tools"]),
			"-p",
			prompt,
		];
		const startedAt = Date.now();
		const child = spawn(join(root, "repi"), args, {
			cwd: runRoot,
			env: {
				...process.env,
				REPI_CODING_AGENT_DIR: workerAgentDir,
				PI_CODING_AGENT_DIR: workerAgentDir,
				REPI_SKIP_VERSION_CHECK: "1",
				REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
				PI_SKIP_VERSION_CHECK: "1",
				PI_SKIP_PACKAGE_UPDATE_CHECK: "1",
				REPI_TELEMETRY: "0",
				PI_TELEMETRY: "0",
				REPI_PRINT_PROGRESS: process.env.REPI_SWARM_LLM_PROGRESS ?? "0",
			},
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill("SIGTERM");
			setTimeout(() => {
				if (child.exitCode === null) child.kill("SIGKILL");
			}, 2000).unref();
		}, timeoutMs);
		child.stdout.on("data", (chunk) => {
			stdout += chunk;
			if (stdout.length > 1024 * 1024) stdout = stdout.slice(-1024 * 1024);
		});
		child.stderr.on("data", (chunk) => {
			stderr += chunk;
			if (stderr.length > 1024 * 1024) stderr = stderr.slice(-1024 * 1024);
		});
		child.on("close", (code, signal) => {
			clearTimeout(timer);
			const redactedStdout = clip(stdout);
			const redactedStderr = clip(stderr);
			let expectOk = redactedStdout.trim().length > 0;
			let expect = undefined;
			if (expectTemplate) {
				expect = substitute(expectTemplate, workerId, target);
				try {
					expectOk = new RegExp(expect, "m").test(redactedStdout);
				} catch {
					expectOk = redactedStdout.includes(expect);
				}
			}
			resolveWorker({
				workerId,
				status: code === 0 && expectOk && !timedOut ? "pass" : timedOut ? "timeout" : "fail",
				exit: code ?? (signal ? 128 : 1),
				signal,
				timedOut,
				ms: Date.now() - startedAt,
				provider: provider ?? "default",
				model: model ?? "default",
				workerAgentDir,
				stdoutSha256: sha256(redactedStdout),
				stderrSha256: sha256(redactedStderr),
				stdoutPreview: redactedStdout.slice(-4000),
				stderrPreview: redactedStderr.slice(-2000),
				expect,
				expectOk,
				promptSha256: sha256(redact(prompt)),
			});
		});
		child.on("error", (error) => {
			clearTimeout(timer);
			resolveWorker({
				workerId,
				status: "fail",
				exit: 1,
				signal: null,
				timedOut,
				ms: Date.now() - startedAt,
				provider: provider ?? "default",
				model: model ?? "default",
				workerAgentDir,
				stdoutSha256: sha256(""),
				stderrSha256: sha256(redact(String(error.message || error))),
				stdoutPreview: "",
				stderrPreview: redact(String(error.message || error)),
				expect: expectTemplate ? substitute(expectTemplate, workerId, target) : undefined,
				expectOk: false,
				promptSha256: sha256(redact(prompt)),
			});
		});
	});
}

if (rawArgs.includes("--help") || rawArgs.includes("-h")) {
	console.log(usage());
	process.exit(0);
}

const json = rawArgs.includes("--json");
const keepProfiles = rawArgs.includes("--keep-profiles");
const target = flagValue(rawArgs, "--target") ?? positionalTarget(rawArgs) ?? "local-selfcheck";
const workers = parseIntFlag(rawArgs, ["--workers", "-w"], 3, 1, 16);
const provider = flagValue(rawArgs, "--provider");
const model = flagValue(rawArgs, "--model");
const tools = flagValue(rawArgs, "--tools");
const timeoutMs = parseIntFlag(rawArgs, "--timeout-ms", Number(process.env.REPI_SWARM_LLM_TIMEOUT_MS ?? 210000), 5000, 30 * 60 * 1000);
const promptTemplate =
	flagValue(rawArgs, "--prompt") ??
	`You are REPI parallel worker {id}. Target/task: {target}. Work independently. Return concise JSON with workerId, findings, evidence, blockers, nextCommands. Do not mention other workers.`;
const expectTemplate = flagValue(rawArgs, "--expect");
const sourceAgentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const runRoot = resolve(flagValue(rawArgs, "--cwd") ?? process.cwd());
const tempRoot = mkdtempSync(join(tmpdir(), "repi-llm-swarm-"));
const runId = `${new Date().toISOString().replace(/[:.]/g, "-")}-${sha256(`${target}:${workers}:${Date.now()}`).slice(0, 10)}`;
const evidenceRoot = join(sourceAgentDir, "recon", "evidence", "llm-swarms", runId);
mkdirSync(evidenceRoot, { recursive: true, mode: 0o700 });

let report;
try {
	const workerRows = await Promise.all(
		Array.from({ length: workers }, (_, index) =>
			runWorker({
				workerId: index + 1,
				target,
				promptTemplate,
				expectTemplate,
				provider,
				model,
				tools,
				timeoutMs,
				runRoot,
				sourceAgentDir,
				tempRoot,
			}),
		),
	);
	for (const worker of workerRows) {
		writeFileSync(join(evidenceRoot, `worker-${worker.workerId}.stdout.txt`), worker.stdoutPreview, "utf8");
		writeFileSync(join(evidenceRoot, `worker-${worker.workerId}.stderr.txt`), worker.stderrPreview, "utf8");
	}
	report = {
		kind: "repi-llm-worker-pool-report",
		schemaVersion: 1,
		LLMWorkerPoolV1: true,
		generatedAt: new Date().toISOString(),
		runId,
		root,
		runRoot,
		target: redact(target),
		provider: provider ?? "default",
		model: model ?? "default",
		workers,
		timeoutMs,
		tools: tools ?? "none",
		evidenceRoot,
		tempRoot: keepProfiles ? tempRoot : undefined,
		promptTemplateSha256: sha256(redact(promptTemplate)),
		workersReport: workerRows.map((worker) => ({
			workerId: worker.workerId,
			status: worker.status,
			exit: worker.exit,
			signal: worker.signal,
			timedOut: worker.timedOut,
			ms: worker.ms,
			provider: worker.provider,
			model: worker.model,
			stdoutSha256: worker.stdoutSha256,
			stderrSha256: worker.stderrSha256,
			promptSha256: worker.promptSha256,
			expect: worker.expect,
			expectOk: worker.expectOk,
			stdoutTail: worker.stdoutPreview.slice(-1200),
			stderrTail: worker.stderrPreview.slice(-800),
		})),
		mergeDigest: sha256(workerRows.map((worker) => `${worker.workerId}:${worker.status}:${worker.stdoutSha256}`).join("\n")),
		ok: workerRows.every((worker) => worker.status === "pass"),
	};
	writeFileSync(join(evidenceRoot, "report.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");
} finally {
	if (!keepProfiles) rmSync(tempRoot, { recursive: true, force: true });
}

if (json) {
	console.log(JSON.stringify(report, null, 2));
} else {
	console.log("REPI LLM Worker Pool");
	console.log(`runId=${report.runId} provider=${report.provider} model=${report.model} workers=${report.workers} target=${report.target}`);
	for (const worker of report.workersReport) {
		console.log(`${worker.status === "pass" ? "PASS" : "FAIL"} worker-${worker.workerId} exit=${worker.exit} ms=${worker.ms} stdout=${worker.stdoutSha256.slice(0, 12)} stderr=${worker.stderrSha256.slice(0, 12)}`);
		if (worker.status !== "pass" && worker.stderrTail) console.log(`  stderr: ${worker.stderrTail.replace(/\n/g, "\\n").slice(-600)}`);
		if (worker.status !== "pass" && worker.stdoutTail) console.log(`  stdout: ${worker.stdoutTail.replace(/\n/g, "\\n").slice(-600)}`);
	}
	console.log(`evidence=${report.evidenceRoot}`);
	console.log(`verdict=${report.ok ? "pass" : "fail"}`);
}

process.exit(report.ok ? 0 : 1);
