#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : process.cwd());
const json = process.argv.includes("--json");
const strict = process.argv.includes("--strict");
const tempRoot = mkdtempSync(join(tmpdir(), "repi-cli-ux-gate-"));
const agentDir = join(tempRoot, "agent");

function mkdir(path) {
	mkdirSync(path, { recursive: true, mode: 0o700 });
	try {
		chmodSync(path, 0o700);
	} catch {
		// Best-effort on non-POSIX filesystems.
	}
}

function run(args, env = {}) {
	const result = spawnSync(process.execPath, args, {
		cwd: root,
		env: {
			...process.env,
			REPI_CODING_AGENT_DIR: agentDir,
			REPI_AGENT_DIR: agentDir,
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
			...env,
		},
		encoding: "utf8",
		timeout: 30_000,
		maxBuffer: 4 * 1024 * 1024,
	});
	return {
		exit: result.status ?? 1,
		stdout: result.stdout ?? "",
		stderr: result.stderr ?? "",
		error: result.error ? String(result.error.message || result.error) : undefined,
	};
}

function check(id, pass, evidence = {}) {
	return { id, status: pass ? "pass" : "fail", evidence };
}

function nonEmptyLineCount(path) {
	try {
		return readFileSync(path, "utf8").split(/\r?\n/).filter((line) => line.trim()).length;
	} catch {
		return 0;
	}
}

function mode(path) {
	try {
		return statSync(path).mode & 0o777;
	} catch {
		return 0;
	}
}

mkdir(agentDir);
mkdir(join(agentDir, "recon", "memory"));
writeFileSync(
	join(agentDir, "models.json"),
	`${JSON.stringify(
		{
			providers: {
				alpha: {
					api: "openai-completions",
					baseUrl: "https://private-alpha.example.invalid/v1",
					apiKey: "$REPI_ALPHA_KEY",
					models: [{ id: "alpha/model", contextWindow: 262144, maxTokens: 8192, cost: { input: 1, output: 2, cacheRead: 0.1, cacheWrite: 0.2 } }],
				},
				beta: {
					api: "anthropic-messages",
					baseUrl: "https://private-beta.example.invalid",
					apiKey: "$REPI_BETA_KEY",
					models: [{ id: "beta/model", contextWindow: 131072, maxTokens: 4096, cost: { input: 3, output: 4, cacheRead: 0, cacheWrite: 0 } }],
				},
			},
		},
		null,
		2,
	)}\n`,
	{ encoding: "utf8", mode: 0o600 },
);

const memoryEventsPath = join(agentDir, "recon", "memory", "events.jsonl");
writeFileSync(
	memoryEventsPath,
	[
			{
				kind: "repi-memory-event",
				id: "mem-alpha",
				ts: "2026-01-01T00:00:00.000Z",
				outcome: "success",
				route: "test",
				target: "alpha",
				commands: ["alpha"],
				lessons: ["alpha lesson baseUrl=https://api.private-alpha.example.invalid/v1"],
			},
		{ kind: "repi-memory-event", id: "mem-beta", ts: "2026-01-02T00:00:00.000Z", outcome: "success", route: "test", target: "beta", commands: ["beta"], lessons: ["beta lesson"] },
	]
		.map((row) => JSON.stringify(row))
		.join("\n") + "\n",
	{ encoding: "utf8", mode: 0o600 },
);

const checks = [];
const listFiltered = run(["scripts/reverse-agent/model-inspect.mjs", root, "list", "--provider", "alpha"]);
checks.push(
	check("model:list-provider-filter", listFiltered.exit === 0 && /alpha\/alpha\/model/.test(listFiltered.stdout) && !/beta\/beta\/model/.test(listFiltered.stdout), {
		exit: listFiltered.exit,
		stdoutTail: listFiltered.stdout.slice(-800),
		stderrTail: listFiltered.stderr.slice(-400),
	}),
);
checks.push(
	check("model:list-redacts-base-url-by-default", !/private-alpha\.example\.invalid|private-beta\.example\.invalid/.test(listFiltered.stdout) && /<redacted:url:[a-f0-9]{16}>/.test(listFiltered.stdout), {
		stdoutTail: listFiltered.stdout.slice(-800),
	}),
);
const listShowUrls = run(["scripts/reverse-agent/model-inspect.mjs", root, "list", "--provider", "alpha", "--show-urls"]);
checks.push(
	check("model:list-show-urls-opt-in", listShowUrls.exit === 0 && /private-alpha\.example\.invalid/.test(listShowUrls.stdout) && !/private-beta\.example\.invalid/.test(listShowUrls.stdout), {
		exit: listShowUrls.exit,
		stdoutTail: listShowUrls.stdout.slice(-800),
	}),
);
const doctorRedacted = run(["scripts/reverse-agent/model-inspect.mjs", root, "doctor"]);
checks.push(
	check("model:doctor-redacts-base-url-by-default", doctorRedacted.exit === 0 && !/private-alpha\.example\.invalid|private-beta\.example\.invalid/.test(doctorRedacted.stdout), {
		exit: doctorRedacted.exit,
		stdoutTail: doctorRedacted.stdout.slice(-800),
	}),
);

const memoryListRedacted = run(["scripts/reverse-agent/memory-inspect.mjs", root, "list", "--all"]);
checks.push(
	check("memory:list-redacts-provider-base-url", memoryListRedacted.exit === 0 && !/api\.private-alpha\.example\.invalid/.test(memoryListRedacted.stdout) && /<redacted:url:[a-f0-9]{16}>/.test(memoryListRedacted.stdout), {
		exit: memoryListRedacted.exit,
		stdoutTail: memoryListRedacted.stdout.slice(-800),
	}),
);

const purgeBlocked = run(["scripts/reverse-agent/memory-inspect.mjs", root, "purge", "--apply", "--all"]);
checks.push(
	check("memory:purge-apply-requires-yes", purgeBlocked.exit !== 0 && /requires --yes/.test(`${purgeBlocked.stdout}\n${purgeBlocked.stderr}`) && nonEmptyLineCount(memoryEventsPath) === 2, {
		exit: purgeBlocked.exit,
		lines: nonEmptyLineCount(memoryEventsPath),
		stderrTail: purgeBlocked.stderr.slice(-400),
	}),
);
const purgeConfirmed = run(["scripts/reverse-agent/memory-inspect.mjs", root, "purge", "--apply", "--yes", "--id", "mem-alpha"]);
checks.push(
	check("memory:purge-confirmed-removes-selected-only", purgeConfirmed.exit === 0 && /removed=1/.test(purgeConfirmed.stdout) && nonEmptyLineCount(memoryEventsPath) === 1 && readFileSync(memoryEventsPath, "utf8").includes("mem-beta"), {
		exit: purgeConfirmed.exit,
		lines: nonEmptyLineCount(memoryEventsPath),
		stdoutTail: purgeConfirmed.stdout.slice(-800),
	}),
);

const initAgentDir = join(tempRoot, "profile-agent");
const initRun = run(["scripts/reverse-agent/init-repi-profile.mjs", root], { REPI_CODING_AGENT_DIR: initAgentDir, REPI_AGENT_DIR: initAgentDir });
checks.push(
	check("profile:init-private-directories", initRun.exit === 0 && existsSync(join(initAgentDir, "sessions")) && mode(initAgentDir) === 0o700 && mode(join(initAgentDir, "recon", "memory")) === 0o700, {
		exit: initRun.exit,
		agentDirMode: `0${mode(initAgentDir).toString(8)}`,
		memoryDirMode: `0${mode(join(initAgentDir, "recon", "memory")).toString(8)}`,
	}),
);

const report = {
	kind: "repi-cli-ux-gate-report",
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	root,
	ok: checks.every((item) => item.status === "pass"),
	checks,
	tempRoot: process.env.KEEP_REPI_CLI_UX_GATE_TMP === "1" ? tempRoot : undefined,
};

if (process.env.KEEP_REPI_CLI_UX_GATE_TMP !== "1") rmSync(tempRoot, { recursive: true, force: true });

if (json) {
	console.log(JSON.stringify(report, null, 2));
} else {
	console.log("REPI CLI UX Gate");
	for (const item of checks) console.log(`${item.status === "pass" ? "PASS" : "FAIL"} ${item.id}`);
	console.log(`verdict: ${report.ok ? "pass" : "fail"}`);
}

process.exit(report.ok || !strict ? 0 : 1);
