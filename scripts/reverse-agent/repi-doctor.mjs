#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, readFileSync, readlinkSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
const rootArg = args[0] && !args[0].startsWith("--") ? args.shift() : undefined;
const root = resolve(rootArg ?? process.cwd());
const json = args.includes("--json");
const fix = args.includes("--fix");
const agentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const repiBin = join(root, "repi");
const runtimeMemory = join(agentDir, "recon", "memory");
const installedRepi = "/usr/local/bin/repi";

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

const fixActions = [];
if (fix) {
	const installer = run("bash", [join(root, "scripts/reverse-agent/install-repi.sh"), root], { timeout: 45_000 });
	fixActions.push({
		id: "install-repi",
		exit: installer.code,
		stdoutTail: installer.stdout.slice(-1200),
		stderrTail: installer.stderr.slice(-1200),
		error: installer.error,
	});
}

const settings = readJson(join(agentDir, "settings.json"));
const memory = settings?.memory ?? {};
const models = readJson(join(agentDir, "models.json"));
const help = existsSync(repiBin) ? run(repiBin, ["--offline", "--help"], { timeout: 20_000 }) : { code: 1, stdout: "", stderr: "missing repi" };
const listModels = existsSync(repiBin) ? run(repiBin, ["--offline", "--list-models"], { timeout: 25_000 }) : { code: 1, stdout: "", stderr: "missing repi" };
const helpText = `${help.stdout}\n${help.stderr}`;
const globalRepi = pathEntry(installedRepi);
const localRepi = pathEntry(repiBin);
const globalRepiOk = globalRepi.exists && globalRepi.resolved === localRepi.resolved;

const checks = [
	check("repo:root", existsSync(join(root, "package.json")) && existsSync(repiBin), `root=${root}`),
	check("launcher:local", existsSync(repiBin), `path=${repiBin}`, "run npm run install:repi"),
	check(
		"launcher:global",
		globalRepiOk,
		`path=${installedRepi} exists=${globalRepi.exists} symlink=${globalRepi.isSymlink} target=${globalRepi.linkTarget ?? "<none>"} resolved=${globalRepi.resolved ?? "<none>"}`,
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
	check("models:parse", listModels.code === 0, `exit=${listModels.code} stdout=${listModels.stdout.slice(0, 120).replace(/\s+/g, " ")} stderr=${listModels.stderr.slice(0, 120).replace(/\s+/g, " ")}`, "fix ~/.repi/agent/models.json"),
	check("models:config-present", Boolean(models) || listModels.code === 0, `modelsJson=${Boolean(models)} listModelsExit=${listModels.code}`, "configure ~/.repi/agent/models.json if no provider exists"),
	check("cli:help", help.code === 0 && /REPI reverse\/pentest/.test(helpText), `exit=${help.code}`, "run npm install && npm run install:repi"),
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
