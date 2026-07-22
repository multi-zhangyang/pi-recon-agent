#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import {
	chmodSync,
	copyFileSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	realpathSync,
	rmSync,
	utimesSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

const args = process.argv.slice(2);
const root = resolve(args[0] && !args[0].startsWith("--") ? args.shift() : process.cwd());
const json = args.includes("--json");
const keep = args.includes("--keep");
const skipRuntimeBuild = process.env.REPI_SKIP_RUNTIME_BUILD === "1";
const outDir = mkdtempSync(join(tmpdir(), "repi-install-path-smoke-"));
const rows = [];

function commandForPlatform(command) {
	return process.platform === "win32" ? `${command}.cmd` : command;
}

function run(id, command, commandArgs, options = {}) {
	const startedAt = Date.now();
	if (!json) console.log(`RUN ${id}: ${command} ${commandArgs.join(" ")}`);
	const result = spawnSync(commandForPlatform(command), commandArgs, {
		cwd: options.cwd ?? root,
		env: { ...process.env, ...(options.env ?? {}) },
		input: options.input,
		encoding: "utf8",
		timeout: options.timeout ?? 120_000,
		maxBuffer: 8 * 1024 * 1024,
		stdio: ["pipe", "pipe", "pipe"],
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
		stdoutTail: stdout.slice(-1800),
		stderrTail: stderr.slice(-1800),
		error: result.error ? String(result.error.message || result.error) : undefined,
	};
	if (!json) console.log(`${exit === 0 ? "PASS" : "FAIL"} ${id} exit=${exit} ms=${row.ms}`);
	rows.push(row);
	return row;
}

async function runSignalSemantics(id, command, commandArgs, options = {}) {
	const startedAt = Date.now();
	if (!json) console.log(`RUN ${id}: ${command} ${commandArgs.join(" ")}`);
	const child = spawn(commandForPlatform(command), commandArgs, {
		cwd: options.cwd ?? root,
		env: { ...process.env, ...(options.env ?? {}) },
		stdio: ["ignore", "pipe", "pipe"],
	});
	let stdout = "";
	let stderr = "";
	child.stdout.setEncoding("utf8");
	child.stderr.setEncoding("utf8");
	child.stdout.on("data", (chunk) => {
		stdout += chunk;
	});
	child.stderr.on("data", (chunk) => {
		stderr += chunk;
	});
	const closed = new Promise((resolveClose) => {
		child.once("close", (code, signal) => resolveClose({ code, signal }));
	});
	const ready = await new Promise((resolveReady) => {
		const timeout = setTimeout(() => resolveReady(false), 5_000);
		const onData = () => {
			if (!stdout.includes("fixture-ready")) return;
			clearTimeout(timeout);
			child.stdout.off("data", onData);
			resolveReady(true);
		};
		child.stdout.on("data", onData);
		onData();
	});
	if (ready) child.kill("SIGTERM");
	else child.kill("SIGKILL");
	const result = await closed;
	const samePid = stdout.includes(`pid=${child.pid}`);
	const pass = ready && samePid && result.code === null && result.signal === "SIGTERM";
	const row = {
		id,
		cmd: [command, ...commandArgs].join(" "),
		exit: pass ? 0 : 1,
		processExit: result.code ?? (result.signal ? 128 : 1),
		expectedExit: 0,
		missing: [
			...(ready ? [] : ["fixture-ready"]),
			...(samePid ? [] : [`pid=${child.pid}`]),
			...(result.signal === "SIGTERM" ? [] : ["signal=SIGTERM"]),
		],
		forbidden: [],
		ms: Date.now() - startedAt,
		stdoutTail: stdout.slice(-1800),
		stderrTail: stderr.slice(-1800),
	};
	if (!json) console.log(`${pass ? "PASS" : "FAIL"} ${id} exit=${row.exit} ms=${row.ms}`);
	rows.push(row);
	return row;
}

function pathWithout(pathToRemove) {
	return (process.env.PATH ?? "")
		.split(":")
		.filter((entry) => entry && resolve(entry) !== resolve(pathToRemove))
		.join(":");
}

function fileContains(path, needle) {
	try {
		return readFileSync(path, "utf8").includes(needle);
	} catch {
		return false;
	}
}

function writeLauncherRuntimeManifest(fixtureRoot, runtimeMarker, runtimeManifest, manifestTime) {
	const result = spawnSync(process.execPath, [runtimeMarker, fixtureRoot], {
		cwd: fixtureRoot,
		encoding: "utf8",
		stdio: ["ignore", "pipe", "pipe"],
	});
	if (result.status !== 0) {
		throw new Error(`fixture manifest generation failed: ${result.stderr || result.stdout}`);
	}
	utimesSync(runtimeManifest, manifestTime, manifestTime);
}

function median(values) {
	const sorted = [...values].sort((a, b) => a - b);
	const middle = Math.floor(sorted.length / 2);
	return sorted.length % 2 === 0 ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle];
}

function benchmarkRuntimeManifestVerify(fixture, samples = 7) {
	const measure = (commandArgs) => {
		const startedAt = process.hrtime.bigint();
		const result = spawnSync(process.execPath, commandArgs, {
			cwd: fixture.root,
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
		});
		return { status: result.status, ms: Number(process.hrtime.bigint() - startedAt) / 1_000_000 };
	};

	measure([fixture.distCli, "--version"]);
	measure([fixture.runtimeMarker, fixture.root, "--launch", "--", "--version"]);
	const baseline = [];
	const verified = [];
	const pairedDeltas = [];
	let failed = false;
	for (let index = 0; index < samples; index++) {
		const baselineArgs = [fixture.distCli, "--version"];
		const verifiedArgs = [fixture.runtimeMarker, fixture.root, "--launch", "--", "--version"];
		const [firstArgs, secondArgs] = index % 2 === 0 ? [baselineArgs, verifiedArgs] : [verifiedArgs, baselineArgs];
		const firstSample = measure(firstArgs);
		const secondSample = measure(secondArgs);
		const baselineSample = index % 2 === 0 ? firstSample : secondSample;
		const verifiedSample = index % 2 === 0 ? secondSample : firstSample;
		failed ||= baselineSample.status !== 0 || verifiedSample.status !== 0;
		baseline.push(baselineSample.ms);
		verified.push(verifiedSample.ms);
		pairedDeltas.push(verifiedSample.ms - baselineSample.ms);
	}
	const baselineMedianMs = median(baseline);
	const verifyMedianMs = median(verified);
	const addedStartupMedianMs = median(pairedDeltas);
	rows.push({
		id: "benchmark:runtime-manifest-verify-overhead",
		cmd: `${process.execPath} mark-repi-runtime.mjs --launch vs direct dist (${samples} samples)`,
		exit: failed ? 1 : 0,
		processExit: failed ? 1 : 0,
		expectedExit: 0,
		missing: [],
		forbidden: [],
		ms: Math.round(verifyMedianMs),
		stdoutTail: JSON.stringify({
			samples,
			directDistMedianMs: Number(baselineMedianMs.toFixed(2)),
			verifiedLaunchMedianMs: Number(verifyMedianMs.toFixed(2)),
			addedStartupMedianMs: Number(addedStartupMedianMs.toFixed(2)),
		}),
		stderrTail: "",
	});
}

function createLauncherFixture() {
	const fixtureRoot = join(outDir, "launcher-runtime-fixture");
	const fakeBin = join(fixtureRoot, "fake-bin");
	const sourceTime = new Date(Date.now() - 120_000);
	const buildTime = new Date(Date.now() - 60_000);
	const manifestTime = new Date(Date.now() - 30_000);
	const sourcePaths = [];
	const buildPaths = [];

	mkdirSync(fakeBin, { recursive: true });
	copyFileSync(join(root, "repi"), join(fixtureRoot, "repi"));
	chmodSync(join(fixtureRoot, "repi"), 0o755);
	const scriptRoot = join(fixtureRoot, "scripts", "reverse-agent");
	const runtimeMarker = join(scriptRoot, "mark-repi-runtime.mjs");
	const doctorPath = join(scriptRoot, "repi-doctor.mjs");
	mkdirSync(scriptRoot, { recursive: true });
	copyFileSync(join(root, "scripts", "reverse-agent", "mark-repi-runtime.mjs"), runtimeMarker);
	writeFileSync(doctorPath, "// doctor fixture\n");

	for (const [packageName, entry] of [
		["tui", "dist/index.js"],
		["ai", "dist/index.js"],
		["agent", "dist/index.js"],
		["coding-agent", "dist/cli.js"],
	]) {
		const packageRoot = join(fixtureRoot, "packages", packageName);
		const sourcePath = join(packageRoot, "src", packageName === "coding-agent" ? "cli.ts" : "index.ts");
		const entryPath = join(packageRoot, entry);
		mkdirSync(dirname(sourcePath), { recursive: true });
		mkdirSync(dirname(entryPath), { recursive: true });
		writeFileSync(sourcePath, `// ${packageName} source fixture\n`);
		writeFileSync(
			entryPath,
			packageName === "coding-agent"
				? `const fixtureArgs = process.argv.slice(2);
console.log('runtime=node');
console.log('pid=' + process.pid);
console.log('arg=' + process.argv[1]);
for (const arg of fixtureArgs) console.log('arg=' + arg);
const exitArg = fixtureArgs.find((arg) => arg.startsWith('--fixture-exit='));
if (exitArg) process.exitCode = Number(exitArg.slice('--fixture-exit='.length));
if (fixtureArgs.includes('--fixture-wait-for-sigterm')) {
  console.log('fixture-ready');
  setInterval(() => {}, 1000);
}
`
				: `// ${packageName} production fixture\n`,
		);
		writeFileSync(join(packageRoot, "package.json"), '{"private":true}\n');
		writeFileSync(join(packageRoot, "tsconfig.build.json"), "{}\n");
		sourcePaths.push(sourcePath, join(packageRoot, "package.json"), join(packageRoot, "tsconfig.build.json"));
		buildPaths.push(entryPath);
	}
	const transitiveRuntime = join(fixtureRoot, "packages", "agent", "dist", "core", "runtime.js");
	mkdirSync(dirname(transitiveRuntime), { recursive: true });
	writeFileSync(transitiveRuntime, "// transitive production fixture\n");
	buildPaths.push(transitiveRuntime);
	const declarationMap = join(fixtureRoot, "packages", "agent", "dist", "index.d.ts.map");
	writeFileSync(declarationMap, '{}\n');
	buildPaths.push(declarationMap);
	const removableSource = join(fixtureRoot, "packages", "agent", "src", "removable.ts");
	writeFileSync(removableSource, "// removable source fixture\n");
	sourcePaths.push(removableSource);

	for (const themeName of ["dark.json", "light.json"]) {
		const themePath = join(fixtureRoot, "packages", "coding-agent", "dist", "modes", "interactive", "theme", themeName);
		mkdirSync(dirname(themePath), { recursive: true });
		writeFileSync(themePath, "{}\n");
		buildPaths.push(themePath);
	}
	for (const configName of ["package-lock.json", "tsconfig.base.json", "tsconfig.json"]) {
		const configPath = join(fixtureRoot, configName);
		writeFileSync(configPath, "{}\n");
		sourcePaths.push(configPath);
	}
	const rootPackagePath = join(fixtureRoot, "package.json");
	writeFileSync(rootPackagePath, '{"version":"fixture-version"}\n');
	sourcePaths.push(rootPackagePath);
	const runtimeManifest = join(fixtureRoot, "packages", "coding-agent", "dist", "repi-runtime.json");

	const tsxPath = join(fixtureRoot, "node_modules", ".bin", "tsx");
	mkdirSync(dirname(tsxPath), { recursive: true });
	writeFileSync(
		tsxPath,
		`#!/usr/bin/env bash
printf 'runtime=tsx\\n'
printf 'arg=%s\\n' "$@"
`,
	);
	chmodSync(tsxPath, 0o755);

	const nodePath = join(fakeBin, "node");
	writeFileSync(
		nodePath,
		`#!/usr/bin/env bash
if [ "$1" = ${JSON.stringify(runtimeMarker)} ]; then
  exec ${JSON.stringify(process.execPath)} "$@"
fi
printf 'runtime=node\\n'
printf 'arg=%s\\n' "$@"
`,
	);
	chmodSync(nodePath, 0o755);
	sourcePaths.push(doctorPath);

	for (const path of sourcePaths) utimesSync(path, sourceTime, sourceTime);
	for (const packageName of ["tui", "ai", "agent", "coding-agent"]) {
		utimesSync(join(fixtureRoot, "packages", packageName, "src"), sourceTime, sourceTime);
	}
	for (const path of buildPaths) utimesSync(path, buildTime, buildTime);
	writeLauncherRuntimeManifest(fixtureRoot, runtimeMarker, runtimeManifest, manifestTime);
	const agentEntry = join(fixtureRoot, "packages", "agent", "dist", "index.js");

	return {
		root: fixtureRoot,
		launcher: join(fixtureRoot, "repi"),
		fakeBin,
		doctorPath,
		runtimeMarker,
		runtimeManifest,
		distCli: join(fixtureRoot, "packages", "coding-agent", "dist", "cli.js"),
		agentEntry,
		agentEntryContent: readFileSync(agentEntry, "utf8"),
		transitiveRuntime,
		transitiveRuntimeContent: readFileSync(transitiveRuntime, "utf8"),
		removableSource,
		codingSource: join(fixtureRoot, "packages", "coding-agent", "src", "cli.ts"),
		sourceTime,
		buildTime,
		manifestTime,
	};
}

let ok = false;
try {
	const script = join(root, "scripts", "reverse-agent", "install-repi.sh");
	const expectedVersion = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
	const launcherFixture = createLauncherFixture();
	const fixtureManifest = JSON.parse(readFileSync(launcherFixture.runtimeManifest, "utf8"));
	const fixtureManifestExcludesMaps =
		Array.isArray(fixtureManifest.entries) &&
		fixtureManifest.entries.every((entry) => typeof entry?.path === "string" && !entry.path.endsWith(".map"));
	rows.push({
		id: "assert:runtime-manifest-excludes-source-maps",
		cmd: "inspect fixture runtime manifest paths",
		exit: fixtureManifestExcludesMaps ? 0 : 1,
		processExit: fixtureManifestExcludesMaps ? 0 : 1,
		expectedExit: 0,
		missing: fixtureManifestExcludesMaps ? [] : ["source-map exclusion"],
		forbidden: ["*.map"],
		ms: 0,
		stdoutTail: JSON.stringify(fixtureManifest.entries?.map((entry) => entry.path) ?? []),
		stderrTail: "",
	});
	const launcherEnv = {
		HOME: join(launcherFixture.root, "home"),
		PATH: `${launcherFixture.fakeBin}:${process.env.PATH ?? ""}`,
		REPI_CODING_AGENT_DIR: join(launcherFixture.root, "agent-home"),
		REPI_USE_SOURCE: "0",
	};
	const fixtureDistCli = join(launcherFixture.root, "packages", "coding-agent", "dist", "cli.js");
	const fixtureSourceCli = join(launcherFixture.root, "packages", "coding-agent", "src", "cli.ts");
	run("launcher:prefers-current-dist", launcherFixture.launcher, ["--version"], {
		cwd: launcherFixture.root,
		env: launcherEnv,
		expectOutput: ["runtime=node", `arg=${fixtureDistCli}`],
		rejectOutput: ["runtime=tsx"],
	});
	const allBaseUrlEnvNames = [
		"REPI_BASE_URL",
		"REPI_MODEL_BASE_URL",
		"REPI_API_BASE_URL",
		"REPI_ENDPOINT",
		"REPI_MODEL_ENDPOINT",
	];
	const baseUrlAliasTargets = ["REPI_API_BASE_URL", "REPI_ENDPOINT", "REPI_MODEL_ENDPOINT"];
	for (const baseUrlAlias of baseUrlAliasTargets) {
		const aliasEnv = Object.fromEntries(
			allBaseUrlEnvNames.filter((name) => name !== baseUrlAlias).map((name) => [name, undefined]),
		);
		run(`launcher:env-base-alias-${baseUrlAlias}`, launcherFixture.launcher, ["--version"], {
			cwd: launcherFixture.root,
			env: {
				...launcherEnv,
				...aliasEnv,
				REPI_AUTH_TOKEN: "fixture-token",
				REPI_MODEL: "fixture-model",
				REPI_MODEL_API: "openai-compatible",
				[baseUrlAlias]: "https://fixture.invalid/v1",
			},
			expectOutput: ["runtime=node", `arg=${fixtureDistCli}`],
			rejectOutput: ["runtime=tsx", "REPI env model config is incomplete", "missing: REPI_BASE_URL"],
		});
	}
	benchmarkRuntimeManifestVerify(launcherFixture);
	run("launcher:single-process-exit-semantics", launcherFixture.launcher, ["--fixture-exit=23"], {
		cwd: launcherFixture.root,
		env: launcherEnv,
		expectExit: 23,
		expectOutput: ["runtime=node", `arg=--fixture-exit=23`],
		rejectOutput: ["runtime=tsx"],
	});
	await runSignalSemantics(
		"launcher:single-process-signal-semantics",
		launcherFixture.launcher,
		["--fixture-wait-for-sigterm"],
		{ cwd: launcherFixture.root, env: launcherEnv },
	);
	run("launcher:explicit-source-mode", launcherFixture.launcher, ["--version"], {
		cwd: launcherFixture.root,
		env: { ...launcherEnv, REPI_USE_SOURCE: "1" },
		expectOutput: ["runtime=tsx", `arg=${fixtureSourceCli}`],
		rejectOutput: ["runtime=node", "ExperimentalWarning"],
	});
	rmSync(launcherFixture.runtimeManifest);
	run("launcher:missing-runtime-manifest-falls-back-to-tsx", launcherFixture.launcher, ["--version"], {
		cwd: launcherFixture.root,
		env: launcherEnv,
		expectOutput: ["runtime=tsx", `arg=${fixtureSourceCli}`],
		rejectOutput: ["runtime=node", "ExperimentalWarning"],
	});
	writeFileSync(launcherFixture.runtimeManifest, "{}\n");
	utimesSync(launcherFixture.runtimeManifest, launcherFixture.manifestTime, launcherFixture.manifestTime);
	run("launcher:corrupt-runtime-manifest-falls-back-to-tsx", launcherFixture.launcher, ["--version"], {
		cwd: launcherFixture.root,
		env: launcherEnv,
		expectOutput: ["runtime=tsx", `arg=${fixtureSourceCli}`],
		rejectOutput: ["runtime=node", "ExperimentalWarning"],
	});
	writeLauncherRuntimeManifest(
		launcherFixture.root,
		launcherFixture.runtimeMarker,
		launcherFixture.runtimeManifest,
		launcherFixture.manifestTime,
	);
	run("launcher:package-command-uses-dist", launcherFixture.launcher, ["install", "npm:fixture-package"], {
		cwd: launcherFixture.root,
		env: launcherEnv,
		expectOutput: ["runtime=node", `arg=${fixtureDistCli}`, "arg=install", "arg=npm:fixture-package"],
		rejectOutput: ["runtime=tsx"],
	});
	rmSync(launcherFixture.agentEntry);
	run("launcher:missing-dist-falls-back-to-tsx", launcherFixture.launcher, ["--version"], {
		cwd: launcherFixture.root,
		env: launcherEnv,
		expectOutput: ["runtime=tsx", `arg=${fixtureSourceCli}`],
		rejectOutput: ["runtime=node", "ExperimentalWarning"],
	});
	writeFileSync(launcherFixture.agentEntry, launcherFixture.agentEntryContent);
	utimesSync(launcherFixture.agentEntry, launcherFixture.buildTime, launcherFixture.buildTime);
	const corruptAgentEntry = launcherFixture.agentEntryContent.replace("production", "pr0duction");
	if (corruptAgentEntry === launcherFixture.agentEntryContent) {
		throw new Error("agent dist fixture does not contain the corruption marker");
	}
	writeFileSync(launcherFixture.agentEntry, corruptAgentEntry);
	utimesSync(launcherFixture.agentEntry, launcherFixture.buildTime, launcherFixture.buildTime);
	run("launcher:corrupt-dist-falls-back-to-tsx", launcherFixture.launcher, ["--version"], {
		cwd: launcherFixture.root,
		env: launcherEnv,
		expectOutput: ["runtime=tsx", `arg=${fixtureSourceCli}`],
		rejectOutput: ["runtime=node", "ExperimentalWarning"],
	});
	writeFileSync(launcherFixture.agentEntry, launcherFixture.agentEntryContent);
	utimesSync(launcherFixture.agentEntry, launcherFixture.buildTime, launcherFixture.buildTime);
	const corruptTransitiveRuntime = launcherFixture.transitiveRuntimeContent.replace("production", "pr0duction");
	if (corruptTransitiveRuntime === launcherFixture.transitiveRuntimeContent) {
		throw new Error("transitive dist fixture does not contain the corruption marker");
	}
	writeFileSync(launcherFixture.transitiveRuntime, corruptTransitiveRuntime);
	utimesSync(launcherFixture.transitiveRuntime, launcherFixture.buildTime, launcherFixture.buildTime);
	run("launcher:corrupt-transitive-dist-falls-back-to-tsx", launcherFixture.launcher, ["--version"], {
		cwd: launcherFixture.root,
		env: launcherEnv,
		expectOutput: ["runtime=tsx", `arg=${fixtureSourceCli}`],
		rejectOutput: ["runtime=node", "ExperimentalWarning"],
	});
	writeFileSync(launcherFixture.transitiveRuntime, launcherFixture.transitiveRuntimeContent);
	utimesSync(launcherFixture.transitiveRuntime, launcherFixture.buildTime, launcherFixture.buildTime);
	const newerSourceTime = new Date(Date.now());
	utimesSync(launcherFixture.codingSource, newerSourceTime, newerSourceTime);
	run("launcher:stale-dist-falls-back-to-tsx", launcherFixture.launcher, ["--version"], {
		cwd: launcherFixture.root,
		env: launcherEnv,
		expectOutput: ["runtime=tsx", `arg=${fixtureSourceCli}`],
		rejectOutput: ["runtime=node"],
	});
	utimesSync(launcherFixture.codingSource, launcherFixture.sourceTime, launcherFixture.sourceTime);
	rmSync(launcherFixture.removableSource);
	run("launcher:deleted-source-falls-back-to-tsx", launcherFixture.launcher, ["--version"], {
		cwd: launcherFixture.root,
		env: launcherEnv,
		expectOutput: ["runtime=tsx", `arg=${fixtureSourceCli}`],
		rejectOutput: ["runtime=node"],
	});
	run("launcher:product-command-stays-shell-routed", launcherFixture.launcher, ["doctor", "--json"], {
		cwd: launcherFixture.root,
		env: launcherEnv,
		expectOutput: ["runtime=node", `arg=${launcherFixture.doctorPath}`, `arg=${launcherFixture.root}`, "arg=--json"],
		rejectOutput: [`arg=${fixtureDistCli}`, "runtime=tsx"],
	});

	const oldNodeBin = join(outDir, "old-node-bin");
	mkdirSync(oldNodeBin, { recursive: true });
	writeFileSync(
		join(oldNodeBin, "node"),
		`#!/usr/bin/env bash
if [ "$1" = "-p" ]; then
  printf '22.18.0\\n'
  exit 0
fi
printf 'v22.18.0\\n'
exit 0
`,
	);
	chmodSync(join(oldNodeBin, "node"), 0o755);
	run("install:reject-node-before-22-19", "bash", [join(root, "install.sh"), "--skip-npm", "--bin-dir", join(outDir, "old-node-bin-target")], {
		env: {
			HOME: join(outDir, "old-node-home"),
			PATH: `${oldNodeBin}:${process.env.PATH ?? ""}`,
			REPI_CODING_AGENT_DIR: join(outDir, "old-node-agent"),
		},
		expectExit: 1,
		expectOutput: ["Node.js >= 22.19.0 required (found v22.18.0). Upgrade via nvm: nvm install 22"],
		rejectOutput: ["INFO: Installing REPI launcher", "installed successfully, to start:"],
	});

	const directHome = join(outDir, "direct-home");
	const directBin = join(outDir, "direct-bin");
	const directAgent = join(outDir, "direct-agent");
	const directPath = `${directBin}:${process.env.PATH ?? ""}`;
	run("install:explicit-bin-on-path", "bash", [script, "--root", root, "--bin-dir", directBin], {
		env: {
			HOME: directHome,
			PATH: directPath,
			REPI_CODING_AGENT_DIR: directAgent,
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
		},
		expectOutput: [
			skipRuntimeBuild
				? "INFO: Skipping REPI production runtime build (REPI_SKIP_RUNTIME_BUILD=1)"
				: "INFO: Building REPI production runtime",
			"INFO: Installing REPI launcher",
			"■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ 100%",
			"INFO: Verifying offline startup",
			"Successfully linked repi",
			`REPI ${expectedVersion} installed successfully, to start:`,
			"For more information visit https://github.com/multi-zhangyang/pi-recon-agent",
		],
		rejectOutput: ["launcher: /usr/local/bin/repi", "launcher: ~/.local/bin/repi"],
		timeout: 180_000,
	});
	run("path:explicit-bin-current-shell", "bash", ["-lc", "command -v repi && repi --version"], {
		env: {
			HOME: directHome,
			PATH: directPath,
			REPI_CODING_AGENT_DIR: directAgent,
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
		},
		expectOutput: [`${directBin}/repi`, expectedVersion],
	});
	const directLinkOk = existsSync(join(directBin, "repi")) && realpathSync(join(directBin, "repi")) === realpathSync(join(root, "repi"));
	rows.push({
		id: "assert:explicit-bin-symlink",
		cmd: "fs.realpath explicit bin",
		exit: directLinkOk ? 0 : 1,
		processExit: directLinkOk ? 0 : 1,
		expectedExit: 0,
		missing: [],
		forbidden: [],
		ms: 0,
		stdoutTail: `link=${join(directBin, "repi")} resolved=${existsSync(join(directBin, "repi")) ? realpathSync(join(directBin, "repi")) : "<missing>"}`,
		stderrTail: "",
	});

	const userHome = join(outDir, "user-home");
	const userBin = join(userHome, ".local", "bin");
	const userAgent = join(outDir, "user-agent");
	const userInstallPath = pathWithout(userBin);
	run("install:user-bin-off-path", "bash", [script, "--root", root, "--user"], {
		env: {
			HOME: userHome,
			PATH: userInstallPath,
			REPI_CODING_AGENT_DIR: userAgent,
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
			REPI_SKIP_RUNTIME_BUILD: "1",
		},
		expectOutput: [
			"INFO: Installing REPI launcher",
			"■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ 100%",
			"INFO: Verifying offline startup",
			"Successfully added repi to $PATH in ~/.bashrc",
			`REPI ${expectedVersion} installed successfully, to start:`,
			"source ~/.bashrc  # Load new PATH (or open a new terminal)",
		],
		rejectOutput: ["launcher: /usr/local/bin/repi"],
		timeout: 180_000,
	});
	const rcLine = `export PATH="${userBin}:$PATH"`;
	const rcOk = fileContains(join(userHome, ".profile"), rcLine) || fileContains(join(userHome, ".bashrc"), rcLine);
	rows.push({
		id: "assert:user-rc-path-export",
		cmd: "grep PATH export in user rc",
		exit: rcOk ? 0 : 1,
		processExit: rcOk ? 0 : 1,
		expectedExit: 0,
		missing: rcOk ? [] : [rcLine],
		forbidden: [],
		ms: 0,
		stdoutTail: `profile=${fileContains(join(userHome, ".profile"), rcLine)} bashrc=${fileContains(join(userHome, ".bashrc"), rcLine)}`,
		stderrTail: "",
	});
	run("path:user-rc-new-shell", "bash", ["-lc", `. \"$HOME/.profile\" 2>/dev/null || true; command -v repi && repi --version`], {
		env: {
			HOME: userHome,
			PATH: userInstallPath,
			REPI_CODING_AGENT_DIR: userAgent,
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
		},
		expectOutput: [`${userBin}/repi`, expectedVersion],
	});

	const rootInstallHome = join(outDir, "root-installer-home");
	const rootInstallBin = join(outDir, "root-installer-bin");
	const rootInstallAgent = join(outDir, "root-installer-agent");
	run("install:root-friendly-summary", "bash", [join(root, "install.sh"), "--skip-npm", "--bin-dir", rootInstallBin], {
		env: {
			HOME: rootInstallHome,
			PATH: `${rootInstallBin}:${process.env.PATH ?? ""}`,
			REPI_CODING_AGENT_DIR: rootInstallAgent,
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
			REPI_SKIP_RUNTIME_BUILD: "1",
		},
		expectOutput: [
			"INFO: Refreshing REPI",
			"■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ 100%",
			"INFO: Installing REPI launcher",
			"INFO: Verifying offline startup",
			"Successfully linked repi",
			`REPI ${expectedVersion} installed successfully, to start:`,
			"cd <project>  # Open directory",
			"repi          # Run command",
			"For more information visit https://github.com/multi-zhangyang/pi-recon-agent",
		],
		timeout: 180_000,
	});

	ok = rows.every((row) => row.exit === 0);
} catch (error) {
	rows.push({
		id: "exception",
		cmd: "exception",
		exit: 1,
		processExit: 1,
		expectedExit: 0,
		missing: [],
		forbidden: [],
		ms: 0,
		stdoutTail: "",
		stderrTail: error instanceof Error ? error.message : String(error),
	});
	ok = false;
} finally {
	if (!keep) rmSync(outDir, { recursive: true, force: true });
}

const report = {
	kind: "repi-install-path-smoke-report",
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	root,
	outDir: keep ? outDir : undefined,
	ok,
	rows,
};
if (json) console.log(JSON.stringify(report, null, 2));
else console.log(`verdict: ${ok ? "pass" : "fail"}`);
process.exit(ok ? 0 : 1);
