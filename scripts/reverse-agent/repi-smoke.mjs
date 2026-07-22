#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : process.cwd());
const full = process.argv.includes("--full");
const json = process.argv.includes("--json");
const scriptDir = dirname(fileURLToPath(import.meta.url));

function script(name) {
	const sourcePath = join(root, "scripts", "reverse-agent", name);
	if (existsSync(sourcePath)) return sourcePath;
	return join(scriptDir, name);
}

const repiPath = process.env.REPI_BIN_PATH || (existsSync(join(root, "repi")) ? join(root, "repi") : "repi");
const tempAgentDirs = [];
function tempAgentDir(label) {
	const dir = mkdtempSync(join(tmpdir(), `repi-smoke-${label}-`));
	tempAgentDirs.push(dir);
	return dir;
}
const freshAgentDir = tempAgentDir("fresh");
const envModelAgentDir = tempAgentDir("env-model");
const rpcGoalAgentDir = tempAgentDir("rpc-goal");
const envModelProbe = {
	REPI_AUTH_TOKEN: "repi-smoke-token",
	REPI_BASE_URL: "https://repi-smoke.invalid/v1",
	REPI_PROVIDER: "repi-env",
	REPI_MODEL: "repi-smoke-env-model",
	REPI_MODEL_API: "openai-compatible",
	REPI_CONTEXT_WINDOW: "262144",
	REPI_AUTO_COMPACT_WINDOW: "262144",
};
const repiEnvModelUnset = Object.fromEntries(
	[
		"REPI_AUTH_TOKEN",
		"REPI_API_KEY",
		"REPI_MODEL_API_KEY",
		"REPI_BASE_URL",
		"REPI_MODEL_BASE_URL",
		"REPI_PROVIDER",
		"REPI_MODEL_PROVIDER",
		"REPI_PROVIDER_ID",
		"REPI_MODEL",
		"REPI_MODEL_ID",
		"REPI_MODEL_API",
		"REPI_API",
		"REPI_CONTEXT_WINDOW",
		"REPI_MODEL_CONTEXT_WINDOW",
		"REPI_AUTO_COMPACT_WINDOW",
		"REPI_MODEL_AUTO_COMPACT_WINDOW",
		"REPI_MAX_TOKENS",
		"REPI_MODEL_MAX_TOKENS",
		"REPI_MAX_OUTPUT_TOKENS",
		"REPI_SUBAGENT_MODEL",
		"REPI_MODEL_INPUT",
		"REPI_INPUT",
		"REPI_MODEL_REASONING",
		"REPI_REASONING",
		"REPI_PROVIDER_NAME",
		"REPI_MODEL_PROVIDER_NAME",
		"REPI_MODEL_NAME",
		"REPI_SUBAGENT_MODEL_NAME",
	].map((key) => [key, undefined]),
);
const steps = [
	{ id: "product-contract", cmd: "node", args: [script("repi-product-contract.mjs"), root, "--json"] },
	// `repi doctor` intentionally performs two cold launcher probes (`--help` and
	// `--list-models`). On release/operator machines with a populated model profile
	// those probes can take ~15-20s each; keep smoke fast but do not make the
	// aggregate doctor step race its own internal 45s probe budget.
	{ id: "doctor", cmd: "node", args: [script("repi-doctor.mjs"), root], timeout: 90_000 },
	{ id: "model-doctor", cmd: "node", args: [script("model-inspect.mjs"), root, "doctor", "--json"] },
	{
		id: "model-status-env",
		cmd: "node",
		args: [script("model-inspect.mjs"), root, "status", "--json"],
		env: envModelProbe,
		expectOutput: ['"source": "REPI_* environment"', '"provider": "repi-env"', '"model": "repi-smoke-env-model"'],
		rejectOutput: ["https://repi-smoke.invalid"],
	},
	{ id: "launcher-help", cmd: repiPath, args: ["--offline", "--help"] },
	{ id: "launcher-list-models", cmd: repiPath, args: ["--offline", "--list-models"] },
	{
		id: "fresh-install-envless-models",
		cmd: repiPath,
		args: ["--offline", "--list-models"],
		env: { ...repiEnvModelUnset, REPI_CODING_AGENT_DIR: freshAgentDir },
		expectOutput: ["No models available", "Configure a model with REPI_* environment variables"],
		rejectOutput: ["kimchi", "aigateway"],
	},
	{
		id: "env-model-provider",
		cmd: repiPath,
		args: ["--offline", "--list-models"],
		env: { ...envModelProbe, REPI_CODING_AGENT_DIR: envModelAgentDir },
		expectOutput: ["repi-env", "repi-smoke-env-model", "262.1K"],
		rejectOutput: ["kimchi", "aigateway"],
	},
	{
		id: "rpc-goal-command-and-tool",
		cmd: repiPath,
		args: ["--offline", "--mode", "rpc", "--no-session"],
		env: { ...envModelProbe, REPI_CODING_AGENT_DIR: rpcGoalAgentDir },
		input: `${JSON.stringify({ id: "commands", type: "get_commands" })}\n${JSON.stringify({ id: "tools", type: "get_tools" })}\n`,
		expectOutput: ['"name":"goal"', '"name":"goal_complete"', '"activeToolNames"'],
	},
];
if (full) steps.push({ id: "full-check", cmd: "npm", args: ["run", "check"], timeout: 180_000 });

function runStep(step) {
	const startedAt = Date.now();
	const result = spawnSync(step.cmd, step.args, {
		cwd: root,
		env: {
			...process.env,
			REPI_OFFLINE: "1",
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
			...(step.env ?? {}),
		},
		input: step.input,
		encoding: "utf8",
		timeout: step.timeout ?? (full ? 120_000 : 45_000),
		maxBuffer: 4 * 1024 * 1024,
	});
	const stdout = result.stdout ?? "";
	const stderr = result.stderr ?? "";
	const combined = `${stdout}\n${stderr}`;
	const missing = (step.expectOutput ?? []).filter((needle) => !combined.includes(needle));
	const forbidden = (step.rejectOutput ?? []).filter((needle) => combined.includes(needle));
	const processExit = result.status ?? 1;
	const validationExit = missing.length === 0 && forbidden.length === 0 ? 0 : 1;
	return {
		id: step.id,
		cmd: [step.cmd, ...step.args].join(" "),
		exit: processExit === 0 && validationExit === 0 ? 0 : processExit || validationExit,
		processExit,
		missing,
		forbidden,
		ms: Date.now() - startedAt,
		stdoutTail: stdout.slice(-1600),
		stderrTail: stderr.slice(-1600),
		error: result.error ? String(result.error.message || result.error) : undefined,
	};
}

const rows = [];
for (const step of steps) {
	if (!json) console.log(`RUN ${step.id}: ${step.cmd} ${step.args.join(" ")}`);
	const row = runStep(step);
	rows.push(row);
	if (!json) console.log(`${row.exit === 0 ? "PASS" : "FAIL"} ${row.id} exit=${row.exit} ms=${row.ms}`);
	if (row.exit !== 0) break;
}

const report = { kind: "repi-smoke-report", schemaVersion: 1, generatedAt: new Date().toISOString(), root, full, ok: rows.every((row) => row.exit === 0) && rows.length === steps.length, rows };
for (const dir of tempAgentDirs) rmSync(dir, { recursive: true, force: true });
if (json) console.log(JSON.stringify(report, null, 2));
else console.log(`verdict: ${report.ok ? "pass" : "fail"}`);
process.exit(report.ok ? 0 : 1);
