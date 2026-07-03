#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
const root = resolve(args[0] && !args[0].startsWith("--") ? args[0] : process.cwd());
const json = args.includes("--json");
const keep = args.includes("--keep");
const repiBinArgIndex = args.indexOf("--repi-bin");
const repiBin =
	repiBinArgIndex >= 0 && args[repiBinArgIndex + 1] ? resolve(args[repiBinArgIndex + 1]) : join(root, "repi");
const outDir = mkdtempSync(join(tmpdir(), "repi-extension-compat-smoke-"));
const agentDir = join(outDir, "agent");
const rows = [];

const env = {
	...process.env,
	REPI_CODING_AGENT_DIR: agentDir,
	REPI_LOAD_BUILTIN_MODELS: "0",
	REPI_AUTH_TOKEN: "extension-smoke-token",
	REPI_BASE_URL: "https://extension-smoke.invalid/v1",
	REPI_PROVIDER: "extension-smoke",
	REPI_MODEL: "extension-smoke-model",
	REPI_MODEL_API: "openai-compatible",
	REPI_CONTEXT_WINDOW: "262144",
	REPI_AUTO_COMPACT_WINDOW: "262144",
	REPI_SKIP_VERSION_CHECK: "1",
	REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
	REPI_TELEMETRY: "0",
	REPI_PRINT_PROGRESS: "0",
};

function commandForPlatform(command) {
	return process.platform === "win32" ? `${command}.cmd` : command;
}

function run(id, command, commandArgs, options = {}) {
	const startedAt = Date.now();
	if (!json) console.log(`RUN ${id}: ${command} ${commandArgs.join(" ")}`);
	const result = spawnSync(commandForPlatform(command), commandArgs, {
		cwd: options.cwd ?? root,
		env: { ...env, ...(options.env ?? {}) },
		encoding: "utf8",
		timeout: options.timeout ?? 360_000,
		maxBuffer: 8 * 1024 * 1024,
		stdio: options.capture === false ? "inherit" : ["pipe", "pipe", "pipe"],
	});
	const stdout = result.stdout ?? "";
	const stderr = result.stderr ?? "";
	const combined = `${stdout}\n${stderr}`;
	const missing = (options.expectOutput ?? []).filter((needle) => !combined.includes(needle));
	const forbidden = (options.rejectOutput ?? []).filter((needle) => combined.includes(needle));
	const processExit = result.status ?? (result.signal ? 128 : 1);
	const expectedExit = options.expectExit ?? 0;
	const exit = processExit === expectedExit && missing.length === 0 && forbidden.length === 0 ? 0 : processExit || 1;
	const row = {
		id,
		cmd: [command, ...commandArgs].join(" "),
		exit,
		processExit,
		expectedExit,
		missing,
		forbidden,
		ms: Date.now() - startedAt,
		stdoutTail: stdout.slice(-1600),
		stderrTail: stderr.slice(-1600),
		error: result.error ? String(result.error.message || result.error) : undefined,
	};
	if (!json) console.log(`${exit === 0 ? "PASS" : "FAIL"} ${id} exit=${exit} ms=${row.ms}`);
	rows.push(row);
	return row;
}

function parseJsonl(text) {
	const rows = [];
	for (const line of text.split(/\r?\n/)) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		try {
			rows.push(JSON.parse(trimmed));
		} catch {
			rows.push({ type: "parse_error", line: trimmed });
		}
	}
	return rows;
}

function responseByCommand(lines, command) {
	return lines.find((line) => line?.type === "response" && line.command === command);
}

async function runRpcProbe() {
	const startedAt = Date.now();
	const id = "rpc:pi-web-access-and-goal";
	if (!json) console.log(`RUN ${id}: ${repiBin} --offline --mode rpc --no-session`);
	const child = spawn(commandForPlatform(repiBin), ["--offline", "--mode", "rpc", "--no-session"], {
		cwd: root,
		env,
		stdio: ["pipe", "pipe", "pipe"],
	});
	let stdout = "";
	let stderr = "";
	let settled = false;
	const finish = (signal = "SIGTERM") => {
		if (settled) return;
		settled = true;
		try {
			child.kill(signal);
		} catch {}
	};
	const timer = setTimeout(() => finish("SIGKILL"), 60_000);
	child.stdout.setEncoding("utf8");
	child.stderr.setEncoding("utf8");
	child.stdout.on("data", (chunk) => {
		stdout += chunk;
		const lines = parseJsonl(stdout);
		if (responseByCommand(lines, "get_commands") && responseByCommand(lines, "get_tools")) finish();
	});
	child.stderr.on("data", (chunk) => {
		stderr += chunk;
	});
	child.stdin.write(`${JSON.stringify({ id: "commands", type: "get_commands" })}\n`);
	child.stdin.write(`${JSON.stringify({ id: "tools", type: "get_tools" })}\n`);
	child.stdin.end();
	const close = await new Promise((resolve) => {
		child.on("close", (code, signal) => resolve({ code, signal }));
		child.on("error", (error) => resolve({ code: 1, signal: undefined, error }));
	});
	clearTimeout(timer);

	const lines = parseJsonl(stdout);
	const commandResponse = responseByCommand(lines, "get_commands");
	const toolResponse = responseByCommand(lines, "get_tools");
	const commands = commandResponse?.data?.commands ?? [];
	const tools = toolResponse?.data?.tools ?? [];
	const commandNames = commands.map((command) => command.name);
	const toolNames = tools.map((tool) => tool.name);
	const goalCommands = commands.filter((command) => command.name === "goal");
	const goalTools = tools.filter((tool) => tool.name === "goal_complete");
	const failures = [];
	if (!commandResponse?.success) failures.push("missing get_commands response");
	if (!toolResponse?.success) failures.push("missing get_tools response");
	for (const name of ["websearch", "curator", "search", "skill:librarian"]) {
		if (!commandNames.includes(name)) failures.push(`missing command ${name}`);
	}
	for (const name of ["web_search", "fetch_content", "get_search_content", "goal_complete"]) {
		if (!toolNames.includes(name)) failures.push(`missing tool ${name}`);
	}
	if (goalCommands.length !== 1) failures.push(`expected one /goal command, got ${goalCommands.length}`);
	if (goalTools.length !== 1) failures.push(`expected one goal_complete tool, got ${goalTools.length}`);
	if (goalCommands[0] && !String(goalCommands[0].sourceInfo?.path ?? "").startsWith("<inline:")) {
		failures.push("/goal command was not owned by built-in REPI goal mode");
	}
	if (goalTools[0] && !String(goalTools[0].sourceInfo?.path ?? "").startsWith("<inline:")) {
		failures.push("goal_complete tool was not owned by built-in REPI goal mode");
	}
	if (!commands.some((command) => command.name === "skill:librarian" && command.sourceInfo?.source === "npm:pi-web-access")) {
		failures.push("pi-web-access librarian skill did not keep npm source metadata");
	}
	if (!tools.some((tool) => tool.name === "web_search" && tool.sourceInfo?.source === "npm:pi-web-access")) {
		failures.push("pi-web-access web_search tool did not keep npm source metadata");
	}

	const exit = failures.length === 0 ? 0 : 1;
	const row = {
		id,
		cmd: `${repiBin} --offline --mode rpc --no-session`,
		exit,
		processExit: close.code,
		signal: close.signal,
		failures,
		ms: Date.now() - startedAt,
		stdoutTail: stdout.slice(-2400),
		stderrTail: stderr.slice(-2400),
		error: close.error ? String(close.error.message || close.error) : undefined,
		summary: {
			commandCount: commands.length,
			toolCount: tools.length,
			webCommands: commandNames.filter((name) => ["websearch", "curator", "search", "skill:librarian"].includes(name)),
			webTools: toolNames.filter((name) => ["web_search", "fetch_content", "get_search_content"].includes(name)),
			goalCommands: goalCommands.map((command) => command.sourceInfo?.path),
			goalTools: goalTools.map((tool) => tool.sourceInfo?.path),
		},
	};
	if (!json) console.log(`${exit === 0 ? "PASS" : "FAIL"} ${id} exit=${exit} ms=${row.ms}`);
	rows.push(row);
}

let ok = false;
try {
	run("install:pi-web-access", repiBin, ["install", "npm:pi-web-access", "--no-approve"], {
		expectOutput: ["Installed npm:pi-web-access"],
		timeout: 360_000,
	});
	run("install:pi-goal", repiBin, ["install", "npm:@narumitw/pi-goal", "--no-approve"], {
		expectOutput: ["Installed npm:@narumitw/pi-goal"],
		timeout: 360_000,
	});
	run("list:packages", repiBin, ["list", "--no-approve"], {
		expectOutput: ["npm:pi-web-access", "npm:@narumitw/pi-goal"],
		timeout: 120_000,
	});
	await runRpcProbe();
	ok = rows.every((row) => row.exit === 0);
} catch (error) {
	rows.push({
		id: "exception",
		exit: 1,
		processExit: 1,
		failures: [error instanceof Error ? error.message : String(error)],
		ms: 0,
		stdoutTail: "",
		stderrTail: "",
	});
	ok = false;
} finally {
	if (!keep) rmSync(outDir, { recursive: true, force: true });
}

const report = {
	kind: "repi-extension-compat-smoke-report",
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	root,
	repiBin,
	outDir: keep ? outDir : undefined,
	agentDir: keep ? agentDir : undefined,
	ok,
	rows,
};
if (json) console.log(JSON.stringify(report, null, 2));
else console.log(`verdict: ${ok ? "pass" : "fail"}`);
process.exit(ok ? 0 : 1);
