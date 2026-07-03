#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";

const root = resolve(process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : process.cwd());
const skipBuild = process.argv.includes("--skip-build");
const keep = process.argv.includes("--keep");
const json = process.argv.includes("--json");
const packages = [
	{ directory: "packages/ai", name: "@pi-recon/repi-ai" },
	{ directory: "packages/tui", name: "@pi-recon/repi-tui" },
	{ directory: "packages/agent", name: "@pi-recon/repi-agent-core" },
	{ directory: "packages/coding-agent", name: "@pi-recon/repi-coding-agent" },
];
const rootPackageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const generatedModelFiles = ["packages/ai/src/models.generated.ts", "packages/ai/src/image-models.generated.ts"];
const generatedModelSnapshots = generatedModelFiles
	.map((file) => {
		const path = join(root, file);
		return existsSync(path) ? { file, path, content: readFileSync(path, "utf8") } : undefined;
	})
	.filter(Boolean);

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

function fileSpecifier(fromDirectory, file) {
	const rel = relative(fromDirectory, file).replaceAll("\\", "/");
	return `file:${rel.startsWith(".") ? rel : `./${rel}`}`;
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
	return join(tarballDirectory, packed.filename);
}

function restoreGeneratedModelSnapshots() {
	for (const snapshot of generatedModelSnapshots) {
		writeFileSync(snapshot.path, snapshot.content);
	}
}

const outDir = mkdtempSync(join(tmpdir(), "repi-release-tarball-smoke-"));
const tarballDir = join(outDir, "tarballs");
const installDir = join(outDir, "install");
const rows = [];
let ok = false;
try {
	if (!skipBuild) {
		for (const pkg of packages) rows.push(run(`build:${pkg.name}`, "npm", ["run", "build"], { cwd: join(root, pkg.directory), capture: false, timeout: 180_000 }));
		if (rows.some((row) => row.exit !== 0)) throw new Error("build failed");
	}
	rows.push(run("mkdir:install", process.execPath, ["-e", `require('node:fs').mkdirSync(${JSON.stringify(tarballDir)}, {recursive:true}); require('node:fs').mkdirSync(${JSON.stringify(installDir)}, {recursive:true})`], { cwd: root }));
	const tarballs = new Map();
	for (const pkg of packages) tarballs.set(pkg.name, packPackage(pkg, tarballDir));
	const dependencies = Object.fromEntries(packages.map((pkg) => [pkg.name, fileSpecifier(installDir, tarballs.get(pkg.name))]));
	writeFileSync(join(installDir, "package.json"), `${JSON.stringify({ private: true, dependencies, overrides: dependencies }, null, "\t")}\n`);
	rows.push(run("npm-install:tarballs", "npm", ["install", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"], { cwd: installDir, timeout: 180_000 }));
	const repiBin = join(installDir, "node_modules", ".bin", process.platform === "win32" ? "repi.cmd" : "repi");
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
		REPI_LOAD_BUILTIN_MODELS: "0",
	};
	rows.push(run("package-bin:help", repiBin, ["--offline", "--help"], { cwd: installDir, expectOutput: ["REPI reverse/pentest", "REPI_AUTH_TOKEN", "REPI_LOAD_BUILTIN_MODELS"] }));
	rows.push(run("package-bin:path-command", "repi", ["--version"], { cwd: installDir, env: { PATH: `${dirname(repiBin)}:${process.env.PATH ?? ""}` }, expectOutput: [rootPackageJson.version] }));
	rows.push(run("package-bin:fresh-list-models", repiBin, ["--offline", "--list-models"], { cwd: installDir, env: { REPI_CODING_AGENT_DIR: freshAgentDir, REPI_LOAD_BUILTIN_MODELS: "0" }, expectOutput: ["No models available"], rejectOutput: ["kimchi", "aigateway"] }));
	rows.push(run("package-bin:env-incomplete-guard", repiBin, ["--offline", "--list-models"], { cwd: installDir, env: { REPI_CODING_AGENT_DIR: join(outDir, "bad-env-agent"), REPI_LOAD_BUILTIN_MODELS: "0", REPI_MODEL: "release-smoke-env-model", REPI_MODEL_API: "openai-compatible" }, expectExit: 2, expectOutput: ["REPI env model config is incomplete", "missing: REPI_BASE_URL"], rejectOutput: ["kimchi", "aigateway"] }));
	rows.push(run("package-bin:env-model", repiBin, ["--offline", "--list-models"], { cwd: installDir, env: { ...envModel, REPI_CODING_AGENT_DIR: envAgentDir }, expectOutput: ["repi-env", "release-smoke-env-model", "262.1K"], rejectOutput: ["kimchi", "aigateway"] }));
	rows.push(run("package-bin:model-status-env", repiBin, ["model", "status", "--json"], { cwd: installDir, env: { ...envModel, REPI_CODING_AGENT_DIR: join(outDir, "model-status-agent") }, expectOutput: ['"source": "REPI_* environment"', '"provider": "repi-env"', '"model": "release-smoke-env-model"'], rejectOutput: ["https://release-smoke.invalid"] }));
	rows.push(run("package-bin:doctor-env-model", repiBin, ["doctor", "--json"], { cwd: installDir, env: { ...envModel, REPI_CODING_AGENT_DIR: join(outDir, "doctor-agent") }, timeout: 120_000, expectOutput: ['"ok": true', '"goal:built-in-mode"', '"goal:footer-status-contract"', '"models:env-only-contract"'] }));
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
	restoreGeneratedModelSnapshots();
	if (!keep) rmSync(outDir, { recursive: true, force: true });
}

const report = { kind: "repi-release-tarball-smoke-report", schemaVersion: 1, generatedAt: new Date().toISOString(), root, outDir: keep ? outDir : undefined, skipBuild, ok, rows };
if (json) console.log(JSON.stringify(report, null, 2));
else console.log(`verdict: ${ok ? "pass" : "fail"}`);
process.exit(ok ? 0 : 1);
