#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(process.argv[2] ?? process.cwd());
const repiPath = join(root, "repi");
const tempRoot = mkdtempSync(join(tmpdir(), "repi-isolation-"));
const home = join(tempRoot, "home");
const fakePiAgent = join(home, ".pi", "agent");

function mkdir(path) {
	mkdirSync(path, { recursive: true });
}

function write(path, body) {
	mkdir(dirname(path));
	writeFileSync(path, body, "utf8");
}

function json(path) {
	return JSON.parse(readFileSync(path, "utf8"));
}

function sha256(text) {
	return createHash("sha256").update(text).digest("hex");
}

function walkFiles(dir, prefix = dir) {
	if (!existsSync(dir)) return [];
	const rows = [];
	for (const name of readdirSync(dir).sort()) {
		const path = join(dir, name);
		const stat = statSync(path);
		if (stat.isDirectory()) {
			rows.push(...walkFiles(path, prefix));
		} else if (stat.isFile()) {
			rows.push({
				path: relative(prefix, path),
				mode: stat.mode & 0o777,
				size: stat.size,
				sha256: sha256(readFileSync(path, "utf8")),
			});
		}
	}
	return rows;
}

function treeHash(dir) {
	return sha256(JSON.stringify(walkFiles(dir)));
}

function cleanEnv(extra = {}) {
	const env = { ...process.env };
	for (const key of [
		"PI_CODING_AGENT_APP_NAME",
		"PI_CODING_AGENT_CONFIG_DIR",
		"REPI_CODING_AGENT_DIR",
		"REPI_AGENT_DIR",
		"REPI_CODING_AGENT_SESSION_DIR",
		"PI_AGENT_IMPORT_DIR",
		"REPI_IMPORT_PI_PROFILE",
		"REPI_IMPORT_PI_AUTH",
	]) {
		delete env[key];
	}
	Object.assign(env, extra);
	env.HOME = home;
	env.PI_OFFLINE = "1";
	return env;
}

function run(args, env = cleanEnv()) {
	const child = spawnSync(repiPath, args, {
		cwd: root,
		env,
		encoding: "utf8",
		maxBuffer: 20 * 1024 * 1024,
	});
	return {
		code: child.status,
		signal: child.signal,
		stdout: child.stdout || "",
		stderr: child.stderr || "",
		combined: `${child.stdout || ""}\n${child.stderr || ""}`,
	};
}

function fail(message, detail = {}) {
	console.error(
		JSON.stringify(
			{
				ok: false,
				message,
				tempRoot,
				...detail,
			},
			null,
			2,
		),
	);
	process.exit(1);
}

if (!existsSync(repiPath)) fail("missing repi launcher", { repiPath });

mkdir(fakePiAgent);
write(
	join(fakePiAgent, "settings.json"),
	JSON.stringify(
		{
			enabledModels: ["2go-anthropic/moonshot/kimi-k2.6", "2go-openai/moonshot/kimi-k2.6"],
			extensions: ["extensions/reverse-pentest-core.ts"],
			prompts: ["prompts"],
			skills: ["skills/reverse-pentest-orchestrator/SKILL.md"],
		},
		null,
		2,
	),
);
write(join(fakePiAgent, "extensions", "reverse-pentest-core.ts"), "export default {};\n");
write(join(fakePiAgent, "prompts", "wr.md"), "# stale REPI prompt\n");
write(join(fakePiAgent, "tools", "legacy-tool"), "#!/usr/bin/env bash\n");
write(join(fakePiAgent, "auth.json"), JSON.stringify({ fake: { apiKey: "not-real" } }, null, 2));
write(join(fakePiAgent, "models.json"), JSON.stringify({ models: [{ provider: "fake", id: "fake-model" }] }, null, 2));

const beforePiHash = treeHash(fakePiAgent);
const help = run(["--offline", "--help"], cleanEnv({ REPI_INIT_VERBOSE: "1" }));
if (help.code !== 0) fail("repi --offline --help failed", { code: help.code, stderr: help.stderr.slice(-4000) });
if (!help.combined.includes("repi - REPI reverse/pentest autonomous agent")) {
	fail("help output did not use repi app name", { combined: help.combined.slice(0, 2000) });
}

const listModels = run(["--offline", "--list-models"]);
if (listModels.code !== 0) {
	fail("repi --offline --list-models failed", {
		code: listModels.code,
		stdout: listModels.stdout.slice(-4000),
		stderr: listModels.stderr.slice(-4000),
	});
}

const combined = `${help.combined}\n${listModels.combined}`;
const forbiddenPatterns = [
	/No models match pattern/i,
	/No API key found for/i,
	/"wr" collision/i,
	/collision:/i,
	/Global tools\/ directory contains custom tools/i,
	/reverse-pentest-core.*skipped/i,
	/update \[source\|self\|pi\]/i,
	/Update pi/i,
	/\bpi update/i,
	/Update Available/i,
	/pi\.dev\/changelog/i,
	/default:\s*https:\/\/pi\.dev\/session/i,
];
for (const pattern of forbiddenPatterns) {
	if (pattern.test(combined)) fail("repi leaked normal pi profile warning/error", { pattern: String(pattern) });
}

const afterPiHash = treeHash(fakePiAgent);
if (afterPiHash !== beforePiHash) fail("repi modified ~/.pi/agent during isolated startup");

const repiAgent = join(home, ".repi", "agent");
const profilePath = join(repiAgent, "recon", "profile.json");
if (!existsSync(profilePath)) fail("repi profile manifest missing", { profilePath });
const profile = json(profilePath);
if (profile.agentDir !== repiAgent) fail("repi profile agentDir mismatch", { expected: repiAgent, actual: profile.agentDir });
if (profile.legacyPiImported?.requested !== false) {
	fail("repi default startup requested legacy pi import", { legacyPiImported: profile.legacyPiImported });
}
if (existsSync(join(repiAgent, "models.json"))) fail("repi copied ~/.pi/agent/models.json without opt-in");

const importAgent = join(home, ".repi-import", "agent");
const importEnv = cleanEnv({
	REPI_CODING_AGENT_DIR: importAgent,
	REPI_IMPORT_PI_PROFILE: "1",
});
const imported = spawnSync(process.execPath, [join(root, "scripts", "reverse-agent", "init-repi-profile.mjs"), root], {
	cwd: root,
	env: importEnv,
	encoding: "utf8",
	maxBuffer: 10 * 1024 * 1024,
});
if (imported.status !== 0) {
	fail("opt-in legacy import init failed", { stderr: imported.stderr.slice(-4000), stdout: imported.stdout.slice(-4000) });
}
if (!existsSync(join(importAgent, "models.json")) || !existsSync(join(importAgent, "auth.json"))) {
	fail("opt-in legacy import did not copy auth/models", { importAgent });
}
const importProfile = json(join(importAgent, "recon", "profile.json"));
if (importProfile.legacyPiImported?.requested !== true) {
	fail("opt-in import manifest did not record requested=true", { legacyPiImported: importProfile.legacyPiImported });
}

const result = {
	ok: true,
	repi: {
		launcher: repiPath,
		agentDir: repiAgent,
		defaultLegacyImport: false,
		help: "pass",
		listModels: "pass",
	},
	normalPi: {
		agentDir: fakePiAgent,
		unchanged: true,
		poisonedModelScopeIgnored: true,
		globalToolsWarningIgnored: true,
	},
	optInImport: {
		agentDir: importAgent,
		authCopied: true,
		modelsCopied: true,
	},
};
console.log(JSON.stringify(result, null, 2));

if (process.env.KEEP_REPI_ISOLATION_TMP !== "1") {
	rmSync(tempRoot, { recursive: true, force: true });
}
