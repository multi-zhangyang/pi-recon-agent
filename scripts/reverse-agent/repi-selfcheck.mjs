#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
	capWorkerBuffer,
	killWorkerWithGrace,
	resolveWorkerMaxBytes,
	DEFAULT_WORKER_KILL_GRACE_MS,
} from "./lib/worker-spawn-helpers.mjs";

const workerMaxBytes = resolveWorkerMaxBytes();
const workerKillGraceMs = (() => {
	const raw = process.env.REPI_SELFCHECK_WORKER_KILL_GRACE_MS;
	if (raw === undefined || raw === null || raw === "") return DEFAULT_WORKER_KILL_GRACE_MS;
	const n = Number(raw);
	return Number.isFinite(n) && n >= 0 ? Math.floor(n) : DEFAULT_WORKER_KILL_GRACE_MS;
})();

const root = resolve(process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : process.cwd());
const args = process.argv.slice(process.argv[2] && !process.argv[2].startsWith("--") ? 3 : 2);
const json = args.includes("--json");
const deep = args.includes("--deep") || args.includes("--full");

function valueAfter(flag) {
	const index = args.indexOf(flag);
	return index >= 0 ? args[index + 1] : undefined;
}

const provider = valueAfter("--provider") ?? process.env.REPI_SELFCHECK_PROVIDER;
const model = valueAfter("--model") ?? process.env.REPI_SELFCHECK_MODEL;
const timeoutMs = Number(valueAfter("--timeout-ms") ?? process.env.REPI_SELFCHECK_TIMEOUT_MS ?? 120_000);
const repi = join(root, "repi");
const modelArgs = [
	...(provider ? ["--provider", provider] : []),
	...(model ? ["--model", model] : []),
	"--thinking",
	"off",
];

function cleanEnv(extra = {}) {
	return {
		...process.env,
		REPI_SKIP_VERSION_CHECK: "1",
		REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
		REPI_TELEMETRY: "0",
		REPI_PRINT_PROGRESS: extra.REPI_PRINT_PROGRESS ?? "0",
		REPI_MEMORY_WRITEBACK_NO_SESSION: "0",
		REPI_RUNTIME_WRITEBACK_NO_SESSION: "0",
		...extra,
	};
}

function redactFull(text) {
	return String(text ?? "")
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\b(?:A3T|AKIA|ASIA)[A-Z0-9]{16}\b/g, "<redacted:aws-access-key>")
		.replace(/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, "<redacted:slack-token>")
		.replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "<redacted:jwt>")
		.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "<redacted:private-key>")
		.replace(/(https?:\/\/)[^/\s:@]+:[^/\s@]+@/gi, "$1<redacted:credentials>@")
		.replace(/(?:AUTH_TOKEN|API_KEY|PASSWORD|SECRET|TOKEN|ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|CLIENT_SECRET)=\S+/gi, (match) => `${match.split("=")[0]}=<redacted>`)
		.replace(/(authorization|x-api-key|api-key)\s*[:=]\s*bearer\s+[A-Za-z0-9._-]+/gi, "$1: Bearer <redacted>")
		.replace(/(authorization|x-api-key|api-key)\s*[:=]\s*[A-Za-z0-9._-]{12,}/gi, "$1: <redacted>")
		.replace(/(baseUrl|baseURL|endpoint|url)\s*[:=]\s*https?:\/\/[^\s"',}]+/gi, "$1=<redacted:url>")
		.replace(/\bhttps?:\/\/api\.[^\s"',}<)]+/gi, "<redacted:url>");
}

function redact(text) {
	return redactFull(text).slice(-4000);
}

function runStep(id, cmd, stepArgs, options = {}) {
	const startedAt = Date.now();
	const result = spawnSync(cmd, stepArgs, {
		cwd: root,
		env: cleanEnv(options.env),
		encoding: "utf8",
		timeout: options.timeoutMs ?? timeoutMs,
		maxBuffer: 8 * 1024 * 1024,
	});
	const stdout = redactFull(result.stdout);
	const stderr = redactFull(result.stderr);
	const exit = result.status ?? (result.signal ? 128 : 1);
	return {
		id,
		cmd: [cmd, ...stepArgs].join(" "),
		exit,
		ok: exit === 0 && !(options.expectStdout && !options.expectStdout.test(stdout)),
		ms: Date.now() - startedAt,
		stdoutTail: stdout.slice(-4000),
		stderrTail: stderr.slice(-4000),
		error: result.error ? String(result.error.message || result.error) : undefined,
	};
}

function runRepi(id, stepArgs, options = {}) {
	return runStep(id, repi, stepArgs, options);
}

function runWorker(index) {
	return new Promise((resolveWorker) => {
		const startedAt = Date.now();
		const child = spawn(
			repi,
			[
				...modelArgs,
				"--no-session",
				"--no-tools",
				"-p",
				`Reply exactly: REPI_PARALLEL_WORKER_${index}_OK`,
			],
			{ cwd: root, env: cleanEnv(), stdio: ["ignore", "pipe", "pipe"] },
		);
		let stdout = "";
		let stderr = "";
		const timer = setTimeout(() => {
			// SIGTERM, then escalate to SIGKILL after a short grace so a
			// SIGTERM-ignoring worker cannot hang Promise.all. The child's
			// "close" handler below resolves the worker; killWorkerWithGrace
			// only guarantees reaping.
			void killWorkerWithGrace(child, workerKillGraceMs);
		}, timeoutMs);
		child.stdout.on("data", (chunk) => {
			stdout = capWorkerBuffer(stdout, chunk, workerMaxBytes);
		});
		child.stderr.on("data", (chunk) => {
			stderr = capWorkerBuffer(stderr, chunk, workerMaxBytes);
		});
		// Foundational opt #272: piped child stdio emits 'error' (EIO/EPIPE)
		// independent of the child's own 'error'/'close' — the timeout path calls
		// killWorkerWithGrace (SIGTERM→SIGKILL), and killing a worker mid-output
		// tears the pipe → the parent-side Readable emits 'error' with NO listener
		// → Unhandled 'error' event crashes the whole `repi selfcheck` parallel
		// pool (the Promise.all never resolves). Swallow so the close handler still
		// resolves the worker with whatever was captured. Same doctrine as opt
		// #188 (repi-swarm-llm-run) / #36 (mcp-manager) / #40 (waitForChildProcess).
		child.stdout?.on("error", () => {});
		child.stderr?.on("error", () => {});
		child.on("close", (code, signal) => {
			clearTimeout(timer);
			const expected = new RegExp(`REPI_PARALLEL_WORKER_${index}_OK`);
			resolveWorker({
				id: `parallel-worker-${index}`,
				exit: code ?? (signal ? 128 : 1),
				ok: code === 0 && expected.test(stdout),
				ms: Date.now() - startedAt,
				stdoutTail: redact(stdout),
				stderrTail: redact(stderr),
				signal,
			});
		});
		child.on("error", (error) => {
			clearTimeout(timer);
			resolveWorker({
				id: `parallel-worker-${index}`,
				exit: 1,
				ok: false,
				ms: Date.now() - startedAt,
				stdoutTail: redact(stdout),
				stderrTail: redact(stderr),
				error: redact(String(error.message || error)),
			});
		});
	});
}

function orchestrationSourceCheck() {
	const path = join(root, "packages/coding-agent/src/core/recon-profile.ts");
	const source = existsSync(path) ? readFileSync(path, "utf8") : "";
	const markers = [
		'name: "re_delegate"',
		'name: "re_swarm"',
		'name: "re_operator"',
		"function buildDelegate",
		"function runSwarm",
		"function dispatchOperatorQueue",
	];
	const missing = markers.filter((marker) => !source.includes(marker));
	return {
		id: "orchestration-source",
		exit: missing.length ? 1 : 0,
		ok: missing.length === 0,
		ms: 0,
		stdoutTail: missing.length ? `missing=${missing.join(",")}` : "re_delegate/re_swarm/re_operator implementation markers present",
		stderrTail: "",
	};
}

const rows = [];

rows.push(runRepi("doctor", ["doctor"], { timeoutMs: 60_000 }));
rows.push(runRepi("model-doctor", ["model", "doctor"], { timeoutMs: 60_000 }));
rows.push(runRepi("model-list", ["model", "list", "--json"], { timeoutMs: 60_000, expectStdout: /repi-model-list-report/ }));
rows.push(runRepi("memory-doctor", ["memory", "doctor", "--json"], { timeoutMs: 60_000, expectStdout: /repi-memory-doctor-report/ }));
rows.push(runRepi("bugreport", ["bugreport", "--stdout"], { timeoutMs: 90_000, expectStdout: /repi-bugreport/ }));
rows.push(
	runRepi("swarm-plan", ["swarm", "plan", "local-selfcheck", "--workers", "2", "--json"], {
		expectStdout: /SwarmPlannerV1/,
		timeoutMs: 60_000,
	}),
);
rows.push(
	runRepi("model-min", [...modelArgs, "--no-session", "--no-tools", "-p", "Reply exactly: REPI_MODEL_OK"], {
		expectStdout: /REPI_MODEL_OK/,
		timeoutMs,
	}),
);
rows.push(
	runRepi(
		"tool-min",
		[
			...modelArgs,
			"--no-session",
			"--tools",
			"bash",
			"-p",
			"Use bash to run exactly: echo REPI_TOOL_OK. Then output only the command result.",
		],
		{ expectStdout: /REPI_TOOL_OK/, timeoutMs },
	),
);
rows.push(
	runRepi(
		"memory-visibility-probe",
		[
			...modelArgs,
			"--no-session",
			"--no-tools",
			"-p",
			"Do you see prior task memory in the current prompt? Reply exactly YES or NO.",
		],
		{ expectStdout: /\bNO\b/i, timeoutMs },
	),
);

rows.push(...(await Promise.all([runWorker(1), runWorker(2), runWorker(3)])));
rows.push(orchestrationSourceCheck());

if (deep) {
	const isolatedProfileRoot = mkdtempSync(join(tmpdir(), "repi-selfcheck-"));
	const isolatedAgentDir = join(isolatedProfileRoot, "agent");
	try {
		mkdirSync(isolatedAgentDir, { recursive: true });
		const sourceAgentDir = process.env.REPI_CODING_AGENT_DIR || join(homedir(), ".repi", "agent");
		for (const name of ["models.json"]) {
			const source = join(sourceAgentDir, name);
			if (existsSync(source)) copyFileSync(source, join(isolatedAgentDir, name));
		}
		rows.push(
			runRepi(
				"swarm-llm-run",
				[
					"swarm",
					"llm-run",
					"local-selfcheck",
					"--workers",
					"3",
					...modelArgs,
					"--prompt",
					"Reply exactly: REPI_SWARM_WORKER_{id}_OK",
					"--expect",
					"REPI_SWARM_WORKER_{id}_OK",
					"--timeout-ms",
					String(timeoutMs),
				],
				{ timeoutMs: Math.max(timeoutMs + 15_000, timeoutMs * 2) },
			),
		);
		rows.push(
			runRepi(
				"re-swarm-slash",
				[...modelArgs, "--no-session", "--mode", "json", "/re-swarm run local-selfcheck 1 1"],
				{
					timeoutMs,
					expectStdout: /re_swarm|swarm|worker/i,
					env: { REPI_CODING_AGENT_DIR: isolatedAgentDir, PI_CODING_AGENT_DIR: isolatedAgentDir },
				},
			),
		);
	} finally {
		rmSync(isolatedProfileRoot, { recursive: true, force: true });
	}
}

const report = {
	kind: "repi-selfcheck-report",
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	root,
	provider: provider ?? "default",
	model: model ?? "default",
	deep,
	ok: rows.every((row) => row.ok),
	rows,
};

if (json) {
	console.log(JSON.stringify(report, null, 2));
} else {
	console.log("REPI Selfcheck");
	console.log(`root: ${root}`);
	console.log(`provider=${report.provider} model=${report.model} deep=${deep}`);
	for (const row of rows) {
		console.log(`${row.ok ? "PASS" : "FAIL"} ${row.id} exit=${row.exit} ms=${row.ms}`);
		if (!row.ok) {
			if (row.stderrTail) console.log(`  stderr: ${row.stderrTail.replace(/\n/g, "\\n").slice(-1000)}`);
			if (row.stdoutTail) console.log(`  stdout: ${row.stdoutTail.replace(/\n/g, "\\n").slice(-1000)}`);
			if (row.error) console.log(`  error: ${row.error}`);
		}
	}
	console.log(`verdict: ${report.ok ? "pass" : "fail"}`);
}

process.exit(report.ok ? 0 : 1);
