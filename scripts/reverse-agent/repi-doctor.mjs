#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	lstatSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	readlinkSync,
	realpathSync,
	renameSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const rootArg = args[0] && !args[0].startsWith("--") ? args.shift() : undefined;
const root = resolve(rootArg ?? process.cwd());
const json = args.includes("--json");
const fix = args.includes("--fix");
const agentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const repiBin = process.env.REPI_BIN_PATH || join(root, "repi");
const runtimeMemory = join(agentDir, "recon", "memory");
const packageBinMode = process.env.REPI_PACKAGE_BIN === "1";
const installedRepi = process.env.REPI_INSTALLED_BIN_PATH || "/usr/local/bin/repi";
const localScriptsDir = dirname(fileURLToPath(import.meta.url));

function readJson(path) {
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch {
		return undefined;
	}
}

function lineCount(path) {
	try {
		return readFileSync(path, "utf8").split(/\r?\n/).filter((line) => line.trim()).length;
	} catch {
		return 0;
	}
}

function check(id, pass, evidence, fix) {
	return { id, status: pass ? "pass" : "fail", evidence, fix };
}

function run(cmd, args, options = {}) {
	const result = spawnSync(cmd, args, {
		cwd: root,
		env: {
			...process.env,
			REPI_OFFLINE: "1",
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
		},
		encoding: "utf8",
		timeout: options.timeout ?? 20_000,
		maxBuffer: 2 * 1024 * 1024,
	});
	return {
		code: result.status ?? 1,
		stdout: result.stdout ?? "",
		stderr: result.stderr ?? "",
		error: result.error ? String(result.error.message || result.error) : undefined,
	};
}

function resolveScript(script) {
	const sourcePath = join(root, "scripts", "reverse-agent", script);
	if (existsSync(sourcePath)) return sourcePath;
	const bundledPath = join(localScriptsDir, basename(script));
	if (existsSync(bundledPath)) return bundledPath;
	return sourcePath;
}

function pathEntry(path) {
	try {
		const stat = lstatSync(path);
		const isSymlink = stat.isSymbolicLink();
		let linkTarget = null;
		let resolved = null;
		try {
			linkTarget = isSymlink ? readlinkSync(path) : null;
			resolved = realpathSync(path);
		} catch {
			resolved = null;
		}
		return { exists: true, bytes: stat.size, isSymlink, linkTarget, resolved };
	} catch {
		return { exists: false, bytes: 0, isSymlink: false, linkTarget: null, resolved: null };
	}
}

function safeEntries(path) {
	try {
		return readdirSync(path);
	} catch {
		return [];
	}
}

function isManagedToolEntry(name) {
	const lower = name.toLowerCase();
	return lower === "fd" || lower === "rg" || lower === "fd.exe" || lower === "rg.exe" || name.startsWith(".");
}

function hasLegacyRepiMarker(path) {
	try {
		const text = readFileSync(path, "utf8").slice(0, 80_000);
		return /REPI|pi-recon|reverse[-_/ ]?pentest|Reverse Pentest/i.test(text);
	} catch {
		return false;
	}
}

function legacyFileProfileEntries() {
	const candidates = [
		{ rel: "extensions/reverse-pentest-core.ts", markerPath: "extensions/reverse-pentest-core.ts" },
		{ rel: "skills/reverse-pentest-orchestrator", markerPath: "skills/reverse-pentest-orchestrator/SKILL.md" },
		{ rel: "prompts/websec.md", markerPath: "prompts/websec.md" },
		{ rel: "prompts/wr.md", markerPath: "prompts/wr.md" },
		{ rel: "prompts/audit-agent.md", markerPath: "prompts/audit-agent.md" },
		{ rel: "prompts/memory.md", markerPath: "prompts/memory.md" },
	];
	const entries = [];
	for (const candidate of candidates) {
		const path = join(agentDir, candidate.rel);
		if (!existsSync(path)) continue;
		const markerPath = join(agentDir, candidate.markerPath);
		if (hasLegacyRepiMarker(markerPath)) entries.push({ ...candidate, path });
	}
	return entries;
}

function legacyExtensionLayout() {
	const hooksDir = join(agentDir, "hooks");
	const toolsDir = join(agentDir, "tools");
	const hooksPresent = existsSync(hooksDir);
	const customToolEntries = existsSync(toolsDir) ? safeEntries(toolsDir).filter((name) => !isManagedToolEntry(name)) : [];
	const legacyProfileEntries = legacyFileProfileEntries();
	return {
		clean: !hooksPresent && customToolEntries.length === 0 && legacyProfileEntries.length === 0,
		hooksPresent,
		hooksEntries: hooksPresent ? safeEntries(hooksDir).filter((name) => !name.startsWith(".")) : [],
		customToolEntries,
		legacyProfileEntries,
	};
}

function timestampSuffix() {
	return new Date().toISOString().replace(/[:.]/g, "-");
}

function uniquePath(path) {
	if (!existsSync(path)) return path;
	for (let index = 2; index < 1000; index++) {
		const candidate = `${path}.${index}`;
		if (!existsSync(candidate)) return candidate;
	}
	return `${path}.${process.pid}`;
}

function ensurePrivateDir(path) {
	mkdirSync(path, { recursive: true, mode: 0o700 });
	try {
		chmodSync(path, 0o700);
	} catch {
		// Best effort on filesystems that do not support POSIX modes.
	}
}

function repairLegacyExtensionLayout() {
	const before = legacyExtensionLayout();
	if (before.clean) {
		return {
			id: "legacy-extension-layout",
			exit: 0,
			stdoutTail: "legacy extension layout already clean",
			stderrTail: "",
		};
	}

	const extensionRoot = join(agentDir, "extensions");
	ensurePrivateDir(extensionRoot);
	const stamp = timestampSuffix();
	const moved = [];
	const errors = [];
	const archiveRoot = join(agentDir, "recon", "archive", `legacy-file-profile-${stamp}`);

	if (before.legacyProfileEntries.length > 0) {
		ensurePrivateDir(archiveRoot);
		for (const entry of before.legacyProfileEntries) {
			const dest = uniquePath(join(archiveRoot, entry.rel));
			ensurePrivateDir(dirname(dest));
			try {
				renameSync(entry.path, dest);
				moved.push({ from: entry.path, to: dest });
			} catch (error) {
				errors.push(`${entry.rel}: ${error instanceof Error ? error.message : String(error)}`);
			}
		}
	}

	if (before.hooksPresent) {
		const src = join(agentDir, "hooks");
		const dest = uniquePath(join(extensionRoot, `legacy-hooks-${stamp}`));
		try {
			renameSync(src, dest);
			moved.push({ from: src, to: dest });
		} catch (error) {
			errors.push(`hooks: ${error instanceof Error ? error.message : String(error)}`);
		}
	}

	if (before.customToolEntries.length > 0) {
		const toolsDir = join(agentDir, "tools");
		const destDir = uniquePath(join(extensionRoot, `legacy-tools-${stamp}`));
		ensurePrivateDir(destDir);
		for (const name of before.customToolEntries) {
			const src = join(toolsDir, name);
			const dest = uniquePath(join(destDir, name));
			try {
				renameSync(src, dest);
				moved.push({ from: src, to: dest });
			} catch (error) {
				errors.push(`tools/${name}: ${error instanceof Error ? error.message : String(error)}`);
			}
		}
	}

	const after = legacyExtensionLayout();
	return {
		id: "legacy-extension-layout",
		exit: errors.length === 0 ? 0 : 1,
		stdoutTail: `moved=${moved.length} remainingHooks=${after.hooksPresent ? 1 : 0} remainingCustomTools=${after.customToolEntries.length} remainingLegacyProfile=${after.legacyProfileEntries.length}`,
		stderrTail: errors.slice(-8).join("\n"),
		moved,
	};
}

const fixActions = [];
if (fix) {
	const installerArgs = [join(root, "scripts/reverse-agent/install-repi.sh"), root];
	if (
		process.env.REPI_INSTALLED_BIN_PATH &&
		!packageBinMode &&
		resolve(process.env.REPI_INSTALLED_BIN_PATH) !== resolve(join(root, "repi"))
	) {
		installerArgs.push(dirname(process.env.REPI_INSTALLED_BIN_PATH));
	}
	const installer = run("bash", installerArgs, { timeout: 45_000 });
	fixActions.push({
		id: "install-repi",
		exit: installer.code,
		stdoutTail: installer.stdout.slice(-1200),
		stderrTail: installer.stderr.slice(-1200),
		error: installer.error,
	});
	const memoryRepair = run(process.execPath, [resolveScript("memory-inspect.mjs"), root, "repair", "--apply", "--yes", "--json"], { timeout: 60_000 });
	fixActions.push({
		id: "memory-repair",
		exit: memoryRepair.code,
		stdoutTail: memoryRepair.stdout.slice(-1200),
		stderrTail: memoryRepair.stderr.slice(-1200),
		error: memoryRepair.error,
	});
	const memorySanitize = run(process.execPath, [resolveScript("memory-inspect.mjs"), root, "sanitize", "--apply", "--yes", "--json"], { timeout: 90_000 });
	fixActions.push({
		id: "memory-sanitize",
		exit: memorySanitize.code,
		stdoutTail: memorySanitize.stdout.slice(-1200),
		stderrTail: memorySanitize.stderr.slice(-1200),
		error: memorySanitize.error,
	});
	fixActions.push(repairLegacyExtensionLayout());
}

const settings = readJson(join(agentDir, "settings.json"));
const memory = settings?.memory ?? {};
const models = readJson(join(agentDir, "models.json"));
const help = existsSync(repiBin) ? run(repiBin, ["--offline", "--help"], { timeout: 20_000 }) : { code: 1, stdout: "", stderr: "missing repi" };
const listModels = existsSync(repiBin) ? run(repiBin, ["--offline", "--list-models"], { timeout: 25_000 }) : { code: 1, stdout: "", stderr: "missing repi" };
const helpText = `${help.stdout}\n${help.stderr}`;
const globalRepi = pathEntry(installedRepi);
const localRepi = pathEntry(repiBin);
const globalRepiOk = packageBinMode || (globalRepi.exists && globalRepi.resolved === localRepi.resolved);
const bootstrapSource = existsSync(join(root, "packages/coding-agent/src/cli/repi-bootstrap.ts"))
	? readFileSync(join(root, "packages/coding-agent/src/cli/repi-bootstrap.ts"), "utf8")
	: "";
const guardrailMarkers = [
	"REPI_PRINT_PROGRESS",
	"REPI_PRINT_TIMEOUT_MS",
	"REPI_PRINT_MAX_TURNS",
	"REPI_PRINT_MAX_TOOL_CALLS",
	"REPI_STDIN_READ_TIMEOUT_MS",
	"REPI_BASH_DEFAULT_TIMEOUT_SECONDS",
];
const missingHelpGuardrails = guardrailMarkers.filter((marker) => !helpText.includes(marker));
const missingBootstrapGuardrails = guardrailMarkers.filter((marker) => !bootstrapSource.includes(marker));
const legacyExtensions = legacyExtensionLayout();

const checks = [
	check("repo:root", existsSync(join(root, "package.json")) && existsSync(repiBin), `root=${root}`),
	check("launcher:local", existsSync(repiBin), `path=${repiBin}`, "run npm run install:repi"),
	check(
		"launcher:global",
		globalRepiOk,
		packageBinMode
			? `package-bin-direct path=${repiBin}`
			: `path=${installedRepi} exists=${globalRepi.exists} symlink=${globalRepi.isSymlink} target=${globalRepi.linkTarget ?? "<none>"} resolved=${globalRepi.resolved ?? "<none>"}`,
		"run repi doctor --fix or npm run install:repi",
	),
	check("runtime:agent-dir", existsSync(agentDir), `agentDir=${agentDir}`, "run npm run install:repi"),
	check("runtime:settings", Boolean(settings), `settings=${join(agentDir, "settings.json")}`, "run npm run install:repi"),
	check(
		"memory:scoped-defaults",
		memory.schemaVersion === 2 && memory.mode === "scoped" && memory.autoRecall === true && memory.autoDeposit === "high-value" && memory.startupDigest === "scoped" && memory.rawAutoInject === false,
		`memory=${JSON.stringify({ schemaVersion: memory.schemaVersion, mode: memory.mode, autoRecall: memory.autoRecall, autoDeposit: memory.autoDeposit, startupDigest: memory.startupDigest, rawAutoInject: memory.rawAutoInject })}`,
		"run npm run install:repi or edit ~/.repi/agent/settings.json",
	),
	check("memory:core-file", existsSync(join(runtimeMemory, "core-memory.md")), `path=${join(runtimeMemory, "core-memory.md")}`, "run npm run install:repi"),
	check("memory:project-file", existsSync(join(runtimeMemory, "project-memory.md")), `path=${join(runtimeMemory, "project-memory.md")}`, "run npm run install:repi"),
	check("memory:procedural-file", existsSync(join(runtimeMemory, "procedural-memory.md")), `path=${join(runtimeMemory, "procedural-memory.md")}`, "run npm run install:repi"),
	check("memory:event-store", existsSync(join(runtimeMemory, "events.jsonl")), `events=${lineCount(join(runtimeMemory, "events.jsonl"))}`, "run repi doctor --fix"),
	check(
		"runtime:legacy-extension-layout",
		legacyExtensions.clean,
		`hooks=${legacyExtensions.hooksPresent ? 1 : 0} customTools=${legacyExtensions.customToolEntries.length} legacyProfile=${legacyExtensions.legacyProfileEntries.length}`,
		"run repi doctor --fix",
	),
	check("models:parse", listModels.code === 0, `exit=${listModels.code} stdout=${listModels.stdout.slice(0, 120).replace(/\s+/g, " ")} stderr=${listModels.stderr.slice(0, 120).replace(/\s+/g, " ")}`, "fix ~/.repi/agent/models.json"),
	check("models:config-present", Boolean(models) || listModels.code === 0, `modelsJson=${Boolean(models)} listModelsExit=${listModels.code}`, "configure ~/.repi/agent/models.json if no provider exists"),
	check("cli:help", help.code === 0 && /REPI reverse\/pentest/.test(helpText), `exit=${help.code}`, "run npm install && npm run install:repi"),
	check(
		"runtime:long-run-guardrails-help",
		missingHelpGuardrails.length === 0,
		`missing=${missingHelpGuardrails.join(",") || "<none>"}`,
		"run git pull && npm run install:repi",
	),
	check(
		"runtime:package-bootstrap-guardrails",
		missingBootstrapGuardrails.length === 0,
		`missing=${missingBootstrapGuardrails.join(",") || "<none>"}`,
		"run git pull && npm install",
	),
	check("network:update-suppressed", /--offline/.test(helpText) && /REPI_SKIP_VERSION_CHECK/.test(helpText), "offline/version-check controls available"),
];

const result = {
	kind: "repi-doctor-report",
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	root,
	agentDir,
	repiBin,
	installedRepi,
	fix,
	fixActions,
	checks,
	ok: checks.every((item) => item.status === "pass") && fixActions.every((item) => item.exit === 0),
};

if (json) {
	console.log(JSON.stringify(result, null, 2));
} else {
	console.log("REPI Doctor");
	console.log(`root: ${root}`);
	console.log(`agentDir: ${agentDir}`);
	for (const action of fixActions) {
		console.log(`${action.exit === 0 ? "FIXED" : "FIX-FAIL"} ${action.id} exit=${action.exit}`);
		if (action.exit !== 0 && action.stderrTail) console.log(action.stderrTail);
	}
	for (const item of checks) {
		console.log(`${item.status === "pass" ? "PASS" : "FAIL"} ${item.id} :: ${item.evidence}`);
		if (item.status !== "pass" && item.fix) console.log(`  fix: ${item.fix}`);
	}
	console.log(`verdict: ${result.ok ? "pass" : "fail"}`);
}

process.exit(result.ok ? 0 : 1);
