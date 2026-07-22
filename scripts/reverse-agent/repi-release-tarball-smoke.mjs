#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { findPackedOutputsWithoutSources } from "./lib/packed-source-closure.mjs";

const root = resolve(process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : process.cwd());
const skipBuild = process.argv.includes("--skip-build");
const keep = process.argv.includes("--keep");
const json = process.argv.includes("--json");
const help = process.argv.includes("--help") || process.argv.includes("-h");
const packages = [
	{ directory: "packages/ai", name: "@pi-recon/repi-ai" },
	{ directory: "packages/tui", name: "@pi-recon/repi-tui" },
	{ directory: "packages/agent", name: "@pi-recon/repi-agent-core" },
	{ directory: "packages/coding-agent", name: "@pi-recon/repi-coding-agent" },
];

if (help) {
	console.log(
		"Usage: node scripts/reverse-agent/repi-release-tarball-smoke.mjs [root] [--skip-build] [--keep] [--json]",
	);
	process.exit(0);
}

const rootPackageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

function commandForPlatform(command) {
	return process.platform === "win32" ? `${command}.cmd` : command;
}

function run(id, command, args, options = {}) {
	const startedAt = Date.now();
	if (!json) console.log(`RUN ${id}: ${command} ${args.join(" ")}`);
	const result = spawnSync(commandForPlatform(command), args, {
		cwd: options.cwd ?? root,
		env: { ...process.env, ...(options.env ?? {}) },
		input: options.input,
		encoding: "utf8",
		timeout: options.timeout ?? 120_000,
		maxBuffer: 8 * 1024 * 1024,
		stdio: options.capture === false && !json ? "inherit" : ["pipe", "pipe", "pipe"],
	});
	const stdout = result.stdout ?? "";
	const stderr = result.stderr ?? "";
	const combined = `${stdout}\n${stderr}`;
	const missing = (options.expectOutput ?? []).filter((needle) => !combined.includes(needle));
	const forbidden = (options.rejectOutput ?? []).filter((needle) => combined.includes(needle));
	const processExit = result.status ?? 1;
	const expectedExit = options.expectExit ?? 0;
	const exit = processExit === expectedExit && missing.length === 0 && forbidden.length === 0 ? 0 : processExit || 1;
	const row = {
		id,
		cmd: [command, ...args].join(" "),
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
	if (options.keepStdout) row.stdout = stdout;
	if (!json) console.log(`${exit === 0 ? "PASS" : "FAIL"} ${id} exit=${exit} ms=${row.ms}`);
	return row;
}

function packPackage(pkg, tarballDirectory) {
	const row = run(`pack:${pkg.name}`, "npm", ["pack", "--json", "--pack-destination", tarballDirectory], {
		cwd: join(root, pkg.directory),
		keepStdout: true,
	});
	rows.push(row);
	const stdout = row.stdout ?? "";
	delete row.stdout;
	if (row.exit !== 0) throw new Error(`npm pack failed for ${pkg.name}: ${row.stderrTail || row.stdoutTail}`);
	const packed = JSON.parse(stdout.trim())[0];
	const packedSourceMaps = (packed?.files ?? [])
		.map((file) => file.path)
		.filter((path) => path.endsWith(".map"));
	if (packedSourceMaps.length > 0) {
		row.exit = 1;
		row.forbidden.push(...packedSourceMaps.map((path) => `packed source map: ${path}`));
		throw new Error(`${pkg.name} tarball contains source maps: ${packedSourceMaps.join(", ")}`);
	}
	const staleOutputs = findPackedOutputsWithoutSources(join(root, pkg.directory), packed?.files ?? []);
	if (staleOutputs.length > 0) {
		row.exit = 1;
		row.forbidden.push(...staleOutputs.map((path) => `packed output has no source: ${path}`));
		throw new Error(`${pkg.name} tarball contains stale compiled outputs: ${staleOutputs.join(", ")}`);
	}
	return join(tarballDirectory, packed.filename);
}

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

const outDir = mkdtempSync(join(tmpdir(), "repi-release-tarball-smoke-"));
const tarballDir = join(outDir, "tarballs");
const installDir = join(outDir, "install");
const rows = [];
let ok = false;
try {
	if (!skipBuild) {
		rows.push(
			run("clean:production-dist", process.execPath, [join(root, "scripts", "clean-production-dist.mjs"), root], {
				cwd: root,
			}),
		);
		if (rows.some((row) => row.exit !== 0)) throw new Error("production dist cleanup failed");
		for (const pkg of packages) rows.push(run(`build:${pkg.name}`, "npm", ["run", "build"], { cwd: join(root, pkg.directory), capture: false, timeout: 180_000 }));
		if (rows.some((row) => row.exit !== 0)) throw new Error("build failed");
	}
	rows.push(run("mkdir:install", process.execPath, ["-e", `require('node:fs').mkdirSync(${JSON.stringify(tarballDir)}, {recursive:true}); require('node:fs').mkdirSync(${JSON.stringify(installDir)}, {recursive:true})`], { cwd: root }));
	const tarballs = new Map();
	for (const pkg of packages) tarballs.set(pkg.name, packPackage(pkg, tarballDir));
	rows.push(
		run(
			"npm-install:four-tarballs-global",
			"npm",
			["install", "--global", "--prefix", installDir, "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund", ...tarballs.values()],
			{ cwd: installDir, timeout: 180_000 },
		),
	);
	const repiBin = process.platform === "win32" ? join(installDir, "repi.cmd") : join(installDir, "bin", "repi");
	const freshAgentDir = join(outDir, "fresh-agent");
	const envAgentDir = join(outDir, "env-agent");
	const rpcAgentDir = join(outDir, "rpc-agent");
	const envModel = {
		REPI_AUTH_TOKEN: "release-smoke-token",
		REPI_BASE_URL: "https://release-smoke.invalid/v1",
		REPI_PROVIDER: "repi-env",
		REPI_MODEL: "release-smoke-env-model",
		REPI_MODEL_API: "openai-compatible",
		REPI_CONTEXT_WINDOW: "262144",
		REPI_AUTO_COMPACT_WINDOW: "262144",
	};
	rows.push(run("package-bin:help", repiBin, ["--offline", "--help"], { cwd: installDir, expectOutput: ["REPI reverse/pentest", "REPI_AUTH_TOKEN", "REPI_MODEL_API"] }));
	rows.push(run("package-bin:mcp-help", repiBin, ["mcp", "--help"], { cwd: installDir, expectOutput: ["REPI MCP manager", "repi mcp status"], rejectOutput: ["Usage:\n  repi [options]"] }));
	rows.push(run("package-bin:bootstrap-help", repiBin, ["bootstrap", "--help"], { cwd: installDir, expectOutput: ["repi bootstrap", "--dry-run", "--only a,b"] }));
	rows.push(run("package-bin:commands-help", repiBin, ["commands", "--help"], { cwd: installDir, expectOutput: ["REPI command quick reference", "repi mcp status"] }));
	rows.push(run("package-bin:uninstall-help", repiBin, ["uninstall", "--help"], { cwd: installDir, expectOutput: ["repi uninstall", "--apply", "--purge"] }));
	rows.push(run("package-bin:uninstall-package-route", repiBin, ["uninstall", "npm:release-smoke-fixture"], { cwd: installDir, env: { ...repiEnvModelUnset, REPI_CODING_AGENT_DIR: join(outDir, "uninstall-package-agent") }, expectExit: 1, expectOutput: ["No matching package found for npm:release-smoke-fixture"], rejectOutput: ["Launcher symlink(s):"] }));
	rows.push(run("package-bin:path-command", "repi", ["--version"], { cwd: installDir, env: { PATH: `${dirname(repiBin)}:${process.env.PATH ?? ""}` }, expectOutput: [rootPackageJson.version] }));
	rows.push(run("package-bin:fresh-list-models", repiBin, ["--offline", "--list-models"], { cwd: installDir, env: { ...repiEnvModelUnset, REPI_CODING_AGENT_DIR: freshAgentDir }, expectOutput: ["No models available"], rejectOutput: ["kimchi", "aigateway"] }));
	rows.push(run("package-bin:goal-help-print", repiBin, ["--offline", "-p", "/goal help"], { cwd: installDir, env: { ...repiEnvModelUnset, REPI_CODING_AGENT_DIR: join(outDir, "goal-help-agent"), REPI_PRINT_PROGRESS: "0" }, expectOutput: ["REPI /goal runs a task until verified completion.", "Completion:"], rejectOutput: ["kimchi", "aigateway"] }));
	rows.push(run("package-bin:goal-status-fresh-print", repiBin, ["--offline", "-p", "/goal status"], { cwd: installDir, env: { ...repiEnvModelUnset, REPI_CODING_AGENT_DIR: join(outDir, "goal-status-agent"), REPI_PRINT_PROGRESS: "0", REPI_PRINT_STATUS: "1" }, expectOutput: ["Usage: /goal <objective>", "No goal is currently set.", "Status: clear", "Footer: 🎯 <clear>", "[repi:status] goal=<clear>"], rejectOutput: ["kimchi", "aigateway"] }));
	rows.push(
		run("package-bin:goal-help-json", repiBin, ["--offline", "--mode", "json", "-p", "/goal help"], {
			cwd: installDir,
			env: { ...repiEnvModelUnset, REPI_CODING_AGENT_DIR: join(outDir, "goal-help-json-agent"), REPI_PRINT_PROGRESS: "0" },
			expectOutput: ['"type":"extension_ui_request"', '"method":"notify"', "REPI /goal runs a task until verified completion.", '"statusKey":"goal"'],
			rejectOutput: ["kimchi", "aigateway"],
		}),
	);
	rows.push(run("package-bin:goal-status-fresh-json", repiBin, ["--offline", "--mode", "json", "-p", "/goal status"], { cwd: installDir, env: { ...repiEnvModelUnset, REPI_CODING_AGENT_DIR: join(outDir, "goal-status-json-agent"), REPI_PRINT_PROGRESS: "0" }, expectOutput: ['"type":"extension_ui_request"', '"method":"notify"', "No goal is currently set.", "Status: clear", "Footer: 🎯 <clear>", '"statusKey":"goal"'], rejectOutput: ["kimchi", "aigateway"] }));
	rows.push(run("package-bin:env-incomplete-guard", repiBin, ["--offline", "--list-models"], { cwd: installDir, env: { ...repiEnvModelUnset, REPI_CODING_AGENT_DIR: join(outDir, "bad-env-agent"), REPI_MODEL: "release-smoke-env-model", REPI_MODEL_API: "openai-compatible" }, expectExit: 2, expectOutput: ["REPI env model config is incomplete", "missing: REPI_BASE_URL"], rejectOutput: ["kimchi", "aigateway"] }));
	rows.push(run("package-bin:env-model", repiBin, ["--offline", "--list-models"], { cwd: installDir, env: { ...envModel, REPI_CODING_AGENT_DIR: envAgentDir }, expectOutput: ["repi-env", "release-smoke-env-model", "262.1K"], rejectOutput: ["kimchi", "aigateway"] }));
	rows.push(run("package-bin:model-status-env", repiBin, ["model", "status", "--json"], { cwd: installDir, env: { ...envModel, REPI_CODING_AGENT_DIR: join(outDir, "model-status-agent") }, expectOutput: ['"source": "REPI_* environment"', '"provider": "repi-env"', '"model": "release-smoke-env-model"'], rejectOutput: ["https://release-smoke.invalid"] }));
	rows.push(run("package-bin:doctor-env-model", repiBin, ["doctor", "--json"], { cwd: installDir, env: { ...envModel, REPI_CODING_AGENT_DIR: join(outDir, "doctor-agent") }, timeout: 120_000, expectOutput: ['"ok": true', '"launcher:path-command-resolution"', '"launcher:shell-rc-path-activation"', '"goal:built-in-mode"', '"goal:footer-status-contract"', '"goal:rpc-runtime-registration"', '"models:env-only-contract"', '"models:env-rpc-runtime"', '"models:env-overrides-saved-default"', '"repi:launch-readiness"'] }));
	rows.push(run("package-bin:doctor-fix-fresh-profile", repiBin, ["doctor", "--fix", "--json"], { cwd: installDir, env: { ...envModel, REPI_CODING_AGENT_DIR: join(outDir, "doctor-fix-agent") }, timeout: 120_000, expectOutput: ['"ok": true', '"id": "profile-init"', '"exit": 0', '"runtime:settings"', '"repi:launch-readiness"'], rejectOutput: ['"provider":"kimchi"', '"id":"kimi-k2.7"'] }));
	rows.push(
		run("package-bin:rpc-fresh-env-footer", repiBin, ["--offline", "--mode", "rpc", "--no-session"], {
			cwd: installDir,
			env: { ...envModel, REPI_CODING_AGENT_DIR: join(outDir, "rpc-fresh-env-footer-agent") },
			input: `${JSON.stringify({ id: "state", type: "get_state" })}\n`,
			expectOutput: [
				'"statusKey":"repi"',
				'"statusText":"REPI kernel profile ready"',
				'"statusKey":"goal"',
				'"provider":"repi-env"',
				'"id":"release-smoke-env-model"',
				'"contextWindow":262144',
			],
			rejectOutput: ['"provider":"kimchi"', '"id":"kimi-k2.7"'],
		}),
	);
	rows.push(
		run("package-bin:rpc-goal-status-env", repiBin, ["--offline", "--mode", "rpc", "--no-session"], {
			cwd: installDir,
			env: { ...envModel, REPI_CODING_AGENT_DIR: join(outDir, "rpc-goal-status-env-agent") },
			input: `${JSON.stringify({ id: "state", type: "get_state" })}\n${JSON.stringify({ id: "goal-status", type: "prompt", message: "/goal status" })}\n`,
			expectOutput: [
				'"provider":"repi-env"',
				'"id":"release-smoke-env-model"',
				'"contextWindow":262144',
				'"method":"notify"',
				"🎯 REPI Goal Status",
				"Status: clear",
				"Footer: 🎯 <clear>",
				'"statusKey":"goal"',
			],
			rejectOutput: ['"provider":"kimchi"', '"id":"kimi-k2.7"'],
		}),
	);
	const staleDefaultAgentDir = join(outDir, "stale-default-agent");
	mkdirSync(staleDefaultAgentDir, { recursive: true });
	writeFileSync(join(staleDefaultAgentDir, "settings.json"), `${JSON.stringify({ defaultProvider: "kimchi", defaultModel: "kimi-k2.7" }, null, "\t")}\n`);
	writeFileSync(
		join(staleDefaultAgentDir, "models.json"),
		`${JSON.stringify(
			{
				providers: {
					kimchi: {
						name: "Kimchi stale default",
						baseUrl: "https://kimchi-stale.invalid/v1",
						apiKey: "$KIMCHI_RELEASE_SMOKE_KEY",
						api: "openai-completions",
						models: [
							{
								id: "kimi-k2.7",
								name: "Kimi stale default",
								contextWindow: 262144,
								maxTokens: 16384,
								input: ["text"],
								reasoning: false,
								cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
							},
						],
					},
				},
			},
			null,
			"\t",
		)}\n`,
	);
	rows.push(
		run("package-bin:rpc-env-overrides-saved-default", repiBin, ["--offline", "--mode", "rpc", "--no-session"], {
			cwd: installDir,
			env: {
				...envModel,
				REPI_CODING_AGENT_DIR: staleDefaultAgentDir,
				REPI_PROVIDER: "morph",
				REPI_MODEL: "morph-env-model",
				KIMCHI_RELEASE_SMOKE_KEY: "stale-kimchi-key",
			},
			input: `${JSON.stringify({ id: "state", type: "get_state" })}\n`,
			expectOutput: ['"provider":"morph"', '"id":"morph-env-model"', '"contextWindow":262144'],
			rejectOutput: ['"provider":"kimchi"', '"id":"kimi-k2.7"'],
		}),
	);
	rows.push(
		run("package-bin:rpc-goal", repiBin, ["--offline", "--mode", "rpc", "--no-session"], {
			cwd: installDir,
			env: { ...envModel, REPI_CODING_AGENT_DIR: rpcAgentDir },
			input: `${JSON.stringify({ id: "commands", type: "get_commands" })}\n${JSON.stringify({ id: "tools", type: "get_tools" })}\n`,
			expectOutput: ['"name":"goal"', '"name":"goal_complete"', '"activeToolNames"'],
		}),
	);
	ok = rows.every((row) => row.exit === 0);
} catch (error) {
	rows.push({ id: "exception", exit: 1, processExit: 1, missing: [], forbidden: [], ms: 0, stdoutTail: "", stderrTail: error instanceof Error ? error.message : String(error) });
	ok = false;
} finally {
	if (!keep) rmSync(outDir, { recursive: true, force: true });
}

const report = { kind: "repi-release-tarball-smoke-report", schemaVersion: 1, generatedAt: new Date().toISOString(), root, outDir: keep ? outDir : undefined, skipBuild, ok, rows };
if (json) console.log(JSON.stringify(report, null, 2));
else console.log(`verdict: ${ok ? "pass" : "fail"}`);
process.exit(ok ? 0 : 1);
