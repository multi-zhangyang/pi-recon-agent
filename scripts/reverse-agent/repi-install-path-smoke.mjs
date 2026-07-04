#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

const args = process.argv.slice(2);
const root = resolve(args[0] && !args[0].startsWith("--") ? args.shift() : process.cwd());
const json = args.includes("--json");
const keep = args.includes("--keep");
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

let ok = false;
try {
	const script = join(root, "scripts", "reverse-agent", "install-repi.sh");
	const expectedVersion = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;

	const directHome = join(outDir, "direct-home");
	const directBin = join(outDir, "direct-bin");
	const directAgent = join(outDir, "direct-agent");
	const directPath = `${directBin}:${process.env.PATH ?? ""}`;
	run("install:explicit-bin-on-path", "bash", [script, "--root", root, "--bin-dir", directBin], {
		env: {
			HOME: directHome,
			PATH: directPath,
			REPI_CODING_AGENT_DIR: directAgent,
			REPI_LOAD_BUILTIN_MODELS: "0",
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
		},
		expectOutput: [
			"Installed REPI",
			`launcher: ${directBin}/repi -> ${root}/repi`,
			"repi doctor",
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
			REPI_LOAD_BUILTIN_MODELS: "0",
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
			REPI_LOAD_BUILTIN_MODELS: "0",
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
		},
		expectOutput: [
			"Installed REPI",
			`launcher: ${userBin}/repi -> ${root}/repi`,
			"Added PATH export to: ~/.bashrc",
			"Successfully added repi to $PATH in ~/.bashrc",
			`REPI ${expectedVersion} installed successfully, to start:`,
			"source ~/.bashrc  # Load new PATH (or open a new terminal)",
			`export PATH=\"${userBin}:$PATH\"`,
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
			REPI_LOAD_BUILTIN_MODELS: "0",
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
			REPI_LOAD_BUILTIN_MODELS: "0",
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
		},
		expectOutput: [
			"INFO: Refreshing REPI",
			"REPI launcher ready:",
			"INFO: Verifying offline startup",
			"Successfully linked repi",
			`REPI ${expectedVersion} installed successfully, to start:`,
			"cd <project>  # Open target/project directory",
			"repi          # Run command",
			"For more information visit https://github.com/multi-zhangyang/pi-recon-agent",
			"Install details:",
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
