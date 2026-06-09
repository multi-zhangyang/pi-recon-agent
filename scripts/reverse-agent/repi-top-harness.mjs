#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const json = argv.includes("--json");
const strict = argv.includes("--strict");
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_TOP_HARNESS_TMP === "1";
const tempRoot = mkdtempSync(join(tmpdir(), "repi-top-harness-"));

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function mkdir(path) {
	mkdirSync(path, { recursive: true });
}

function walkFiles(dir, prefix = dir) {
	if (!existsSync(dir)) return [];
	const rows = [];
	for (const name of readdirSync(dir).sort()) {
		const path = join(dir, name);
		const stat = lstatSync(path);
		if (stat.isDirectory()) rows.push(...walkFiles(path, prefix));
		else if (stat.isFile()) rows.push({ path: relative(prefix, path), size: stat.size, sha256: sha256(readFileSync(path)) });
		else if (stat.isSymbolicLink()) rows.push({ path: relative(prefix, path), symlink: true });
	}
	return rows;
}

function treeHash(dir) {
	return sha256(JSON.stringify(walkFiles(dir)));
}

function run(command, args, options = {}) {
	const child = spawnSync(command, args, {
		cwd: options.cwd ?? root,
		env: { ...process.env, ...(options.env ?? {}) },
		input: options.input,
		encoding: "utf8",
		maxBuffer: options.maxBuffer ?? 40 * 1024 * 1024,
	});
	return {
		command,
		args,
		code: child.status,
		signal: child.signal,
		stdout: child.stdout || "",
		stderr: child.stderr || "",
		combined: `${child.stdout || ""}\n${child.stderr || ""}`,
	};
}

function resultCheck(id, status, evidence = {}, detail = {}) {
	return { id, status, evidence, ...detail };
}

function markerCheck(id, path, required, forbidden = []) {
	const full = join(root, path);
	if (!existsSync(full)) return resultCheck(id, "fail", { path, exists: false });
	const text = readFileSync(full, "utf8");
	const missing = required.filter((marker) => !text.includes(marker));
	const presentForbidden = forbidden.filter((pattern) => (pattern instanceof RegExp ? pattern.test(text) : text.includes(pattern)));
	return resultCheck(missing.length === 0 && presentForbidden.length === 0 ? id : id, missing.length === 0 && presentForbidden.length === 0 ? "pass" : "fail", {
		path,
		sha256: sha256(text).slice(0, 24),
		required: required.map((marker) => ({ marker, present: text.includes(marker) })),
		forbidden: forbidden.map((pattern) => ({ pattern: String(pattern), present: presentForbidden.includes(pattern) })),
	});
}

function staticContractChecks() {
	const checks = [];
	checks.push(
		markerCheck("launcher:repi-product-env", "repi", [
			'PI_CODING_AGENT_APP_NAME="repi"',
			'PI_CODING_AGENT_CONFIG_DIR=".repi"',
			"PI_RECON_PRODUCT=1",
			"PI_SKIP_VERSION_CHECK",
			"PI_SKIP_PACKAGE_UPDATE_CHECK",
			"PI_TELEMETRY",
			"ARGS=(--recon --no-extensions --no-skills --no-prompt-templates --no-approve --no-context-files)",
			"install|remove|uninstall|update|list|config",
		]),
	);
	checks.push(markerCheck("launcher:pi-non-owning-shim", "pi", ["no longer owns the `pi` command", "exec \"$candidate\" \"$@\""], ["ARGS=(--recon", "PI_RECON_PRODUCT=1", "PI_RECON_PRIMARY=1"]));
	checks.push(
		markerCheck(
			"installer:repi-no-pi-takeover",
			"scripts/reverse-agent/install-repi.sh",
			["ln -sfn \"$ROOT/repi\" \"$BIN_DIR/repi\"", "pi    -> upstream Pi only", "not modified by install-repi.sh"],
			[/ln\s+-sfn\s+"\$ROOT\/pi"\s+"\$BIN_DIR\/pi"/, /rm\s+-rf\s+"\$HOME\/\.pi"/, /@earendil-works\/pi-coding-agent\*/],
		),
	);
	checks.push(markerCheck("installer:legacy-no-takeover", "scripts/reverse-agent/install-recon-pi.sh", ["deprecated", "exec \"$ROOT/scripts/reverse-agent/install-repi.sh"], [/ln\s+-s.*\$ROOT\/pi/, /rm\s+-rf/, /deleted upstream/],));
	checks.push(markerCheck("code:repi-product-switch", "packages/coding-agent/src/config.ts", ["IS_REPI_PRODUCT", "PI_RECON_PRODUCT", "APP_NAME === \"repi\"", "https://gist.github.com/"], []));
	checks.push(markerCheck("code:update-branding-disabled", "packages/coding-agent/src/modes/interactive/interactive-mode.ts", ["if (!IS_REPI_PRODUCT)", "PI_SKIP_PACKAGE_UPDATE_CHECK", "if (IS_REPI_PRODUCT) return;", "Pi-RECON Changelog"], []));
	checks.push(markerCheck("code:provider-attribution-rebranded", "packages/coding-agent/src/core/provider-attribution.ts", ["IS_REPI_PRODUCT", "X-OpenRouter-Title", "repi-coding-agent", "x-opencode-client"], []));
	checks.push(markerCheck("npm:top-harness-script", "package.json", ["gate:repi-product", "gate:repi-isolation", "install:repi"], []));
	checks.push(markerCheck("docs:independent-entry", "README.md", ["repi  -> Pi-RECON", "pi    -> 你本机安装的原版 Pi", "npm run install:repi", "npm run gate:repi-product"], ["npm run install:recon-pi\n", "npm run gate:pi-recon-primary\n"]));
	return checks;
}

function forbiddenRuntimePatterns() {
	return [
		/update \[source\|self\|pi\]/i,
		/Update pi/i,
		/\bpi update/i,
		/Update Available/i,
		/Package Updates Available/i,
		/pi\.dev\/changelog/i,
		/default:\s*https:\/\/pi\.dev\/session/i,
		/No models match pattern/i,
		/No API key found/i,
		/collision:/i,
		/Global tools\/ directory contains custom tools/i,
	];
}

function runtimeInstallProbe() {
	const home = join(tempRoot, "home");
	const installBin = join(tempRoot, "bin");
	const npmPrefix = join(tempRoot, "npm-prefix");
	const fakePiAgent = join(home, ".pi", "agent");
	mkdir(installBin);
	mkdir(join(home, ".local", "bin"));
	mkdir(join(npmPrefix, "bin"));
	mkdir(fakePiAgent);

	const fakePi = join(installBin, "pi");
	writeFileSync(fakePi, "#!/usr/bin/env bash\necho UPSTREAM_PI_STUB \"$@\"\n", "utf8");
	spawnSync("chmod", ["755", fakePi]);
	try {
		symlinkSync(join(root, "pi"), join(home, ".local", "bin", "pi"));
	} catch {}
	try {
		symlinkSync(join(root, "pi"), join(npmPrefix, "bin", "pi"));
	} catch {}

	writeFileSync(join(fakePiAgent, "settings.json"), JSON.stringify({ enabledModels: ["2go-anthropic/moonshot/kimi-k2.6"], extensions: ["extensions/reverse-pentest-core.ts"] }, null, 2));
	mkdir(join(fakePiAgent, "extensions"));
	writeFileSync(join(fakePiAgent, "extensions", "reverse-pentest-core.ts"), "export default {};\n");
	writeFileSync(join(fakePiAgent, "auth.json"), JSON.stringify({ fake: { apiKey: "do-not-copy-by-default" } }, null, 2));
	writeFileSync(join(fakePiAgent, "models.json"), JSON.stringify({ models: [{ provider: "fake", id: "fake-model" }] }, null, 2));
	const beforePiHash = treeHash(fakePiAgent);

	const env = {
		HOME: home,
		PATH: `${installBin}:${process.env.PATH}`,
		npm_config_prefix: npmPrefix,
		PI_OFFLINE: "1",
		PI_SKIP_VERSION_CHECK: "1",
		PI_SKIP_PACKAGE_UPDATE_CHECK: "1",
		PI_TELEMETRY: "0",
	};
	const install = run("bash", ["scripts/reverse-agent/install-repi.sh", root, installBin], { env });
	const repiPath = join(installBin, "repi");
	const piProbe = run(fakePi, ["--version"], { env });
	const help = run(repiPath, ["--offline", "--help"], { env });
	const updateHelp = run(repiPath, ["update", "--help"], { env });
	const listModels = run(repiPath, ["--offline", "--list-models"], { env });
	const modelsBeforeImport = existsSync(join(home, ".repi", "agent", "models.json"));
	const authBeforeImport = existsSync(join(home, ".repi", "agent", "auth.json"));
	const importRun = run(repiPath, ["--import-pi-auth", "--offline", "--list-models"], { env });
	const profilePath = join(home, ".repi", "agent", "recon", "profile.json");
	const profile = existsSync(profilePath) ? JSON.parse(readFileSync(profilePath, "utf8")) : null;
	const afterPiHash = treeHash(fakePiAgent);
	const combined = `${install.combined}\n${piProbe.combined}\n${help.combined}\n${updateHelp.combined}\n${listModels.combined}`;
	const forbidden = forbiddenRuntimePatterns().filter((pattern) => pattern.test(combined));
	const modelsAfterImport = existsSync(join(home, ".repi", "agent", "models.json"));
	const authAfterImport = existsSync(join(home, ".repi", "agent", "auth.json"));

	const checks = [];
	checks.push(resultCheck("runtime:install-repi-code", install.code === 0 ? "pass" : "fail", { code: install.code, stderrTail: install.stderr.slice(-2000) }));
	checks.push(resultCheck("runtime:repi-symlink-created", existsSync(repiPath) ? "pass" : "fail", { repiPath, target: existsSync(repiPath) ? lstatSync(repiPath).isFile() || lstatSync(repiPath).isSymbolicLink() : false }));
	checks.push(resultCheck("runtime:pi-stub-preserved", piProbe.stdout.includes("UPSTREAM_PI_STUB") ? "pass" : "fail", { stdout: piProbe.stdout.trim(), code: piProbe.code }));
	checks.push(resultCheck("runtime:stale-recon-pi-shims-removed", !existsSync(join(home, ".local", "bin", "pi")) && !existsSync(join(npmPrefix, "bin", "pi")) ? "pass" : "fail", { homeLocalPiExists: existsSync(join(home, ".local", "bin", "pi")), npmPiExists: existsSync(join(npmPrefix, "bin", "pi")) }));
	checks.push(resultCheck("runtime:normal-pi-profile-unchanged", beforePiHash === afterPiHash ? "pass" : "fail", { beforePiHash, afterPiHash }));
	checks.push(resultCheck("runtime:repi-help-product", help.code === 0 && help.combined.includes("repi - Pi-RECON reverse/pentest autonomous agent") && help.combined.includes("built-in reverse/pentest kernel is enabled") ? "pass" : "fail", { code: help.code, head: help.combined.slice(0, 1200) }));
	checks.push(resultCheck("runtime:repi-update-help-independent", updateHelp.code === 0 && updateHelp.combined.includes("repi update [source]") && !/--self|--force|Update pi|source\|self\|pi/i.test(updateHelp.combined) ? "pass" : "fail", { code: updateHelp.code, text: updateHelp.combined.slice(0, 1200) }));
	checks.push(resultCheck("runtime:repi-list-models", listModels.code === 0 ? "pass" : "fail", { code: listModels.code, stdout: listModels.stdout.trim().slice(0, 1200), stderrTail: listModels.stderr.slice(-1000) }));
	checks.push(resultCheck("runtime:no-upstream-warning-leak", forbidden.length === 0 ? "pass" : "fail", { forbidden: forbidden.map(String) }));
	checks.push(resultCheck("runtime:profile-in-repi-home", profile?.agentDir === join(home, ".repi", "agent") ? "pass" : "fail", { profilePath, agentDir: profile?.agentDir ?? null }));
	checks.push(resultCheck("runtime:legacy-import-explicit-only", importRun.code === 0 && !modelsBeforeImport && modelsAfterImport && authAfterImport ? "pass" : "fail", { importCode: importRun.code, modelsBeforeImport, authBeforeImport, modelsAfterImport, authAfterImport }));
	return { checks, tempRoot, installBin, home };
}

function childGateChecks() {
	const gates = [
		["gate:repi-product", ["scripts/reverse-agent/assert-repi-product.mjs", root]],
		["gate:repi-isolation", ["scripts/reverse-agent/assert-repi-isolated.mjs", root]],
		["gate:context-compact", ["scripts/reverse-agent/context-compact-audit.mjs", root]],
		["gate:autonomous-runtime", ["scripts/reverse-agent/autonomous-runtime-contracts.mjs", root, "--strict"]],
		["gate:autonomy-control", ["scripts/reverse-agent/autonomy-control-plane.mjs", root, "--strict"]],
	];
	return gates.map(([id, args]) => {
		const runResult = run(process.execPath, args, { env: { PI_OFFLINE: "1", PI_SKIP_VERSION_CHECK: "1" } });
		return resultCheck(`child:${id}`, runResult.code === 0 ? "pass" : "fail", {
			code: runResult.code,
			stdoutSha256: sha256(runResult.stdout).slice(0, 24),
			stderrSha256: sha256(runResult.stderr).slice(0, 24),
			stdoutTail: runResult.stdout.slice(-2000),
			stderrTail: runResult.stderr.slice(-2000),
		});
	});
}

function summarize(checks) {
	const failed = checks.filter((check) => check.status !== "pass");
	const byPrefix = {};
	for (const check of checks) {
		const prefix = check.id.split(":")[0];
		byPrefix[prefix] ??= { pass: 0, fail: 0 };
		byPrefix[prefix][check.status === "pass" ? "pass" : "fail"]++;
	}
	return {
		ok: failed.length === 0,
		failed: failed.map((check) => check.id),
		byPrefix,
	};
}

function formatMarkdown(result) {
	const lines = [
		"# REPI Top Harness Audit",
		"",
		`generated_at: ${result.generatedAt}`,
		`ok: ${result.ok}`,
		`current_level: ${result.currentLevel}`,
		`independence_verdict: ${result.independenceVerdict}`,
		`ability_verdict: ${result.abilityVerdict}`,
		`temp_root: ${result.tempRoot}`,
		"",
		"## Outcome",
		"",
		result.ok
			? "REPI passes the independent-product harness: install path, command ownership, profile storage, update/branding behavior, and reverse/pentest control-plane gates are all independently verified."
			: `REPI harness failed: ${result.summary.failed.join(", ")}`,
		"",
		"## Checks",
	];
	for (const check of result.checks) lines.push(`- ${check.id}: ${check.status}`);
	lines.push("", "## Child gates");
	for (const check of result.checks.filter((row) => row.id.startsWith("child:"))) lines.push(`- ${check.id}: ${check.status} code=${check.evidence.code}`);
	lines.push("", "## Next hardening");
	for (const item of result.nextHardening) lines.push(`- ${item}`);
	return `${lines.join("\n")}\n`;
}

function main() {
	let result;
	try {
		const staticChecks = staticContractChecks();
		const runtimeProbe = runtimeInstallProbe();
		const childChecks = childGateChecks();
		const checks = [...staticChecks, ...runtimeProbe.checks, ...childChecks];
		const summary = summarize(checks);
		result = {
			kind: "repi-top-harness-audit",
			version: 1,
			generatedAt: new Date().toISOString(),
			root,
			tempRoot,
			ok: summary.ok,
			currentLevel: summary.ok ? "independent professional reverse/pentest organization agent harness" : "independence/capability harness gaps",
			independenceVerdict: checks.filter((row) => ["launcher", "installer", "runtime", "code", "docs", "npm"].includes(row.id.split(":")[0])).every((row) => row.status === "pass") ? "pass" : "fail",
			abilityVerdict: checks.filter((row) => row.id.startsWith("child:gate:autonomy") || row.id.startsWith("child:gate:autonomous") || row.id.startsWith("child:gate:context")).every((row) => row.status === "pass") ? "pass" : "fail",
			summary,
			checks,
			nextHardening: [
				"Keep repi as the only REPI product command; never reintroduce pi takeover into installers or docs.",
				"Promote optional live provider/child-session runtime gates only after the offline independence harness stays green.",
				"Keep command ownership, profile isolation, and update/branding checks in release CI before any capability claims.",
			],
		};
		if (json) console.log(JSON.stringify(result, null, 2));
		else process.stdout.write(formatMarkdown(result));
		if (strict && !result.ok) process.exitCode = 1;
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
}

main();
