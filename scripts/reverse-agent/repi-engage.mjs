#!/usr/bin/env node
import { createHash } from "node:crypto";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	readFileSync,
	readdirSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, extname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const argv = process.argv.slice(2);
const rootArg = argv[0] && !argv[0].startsWith("-") ? argv.shift() : undefined;
const root = resolve(rootArg ?? process.cwd());
const json = argv.includes("--json");
const deep = argv.includes("--deep") || argv.includes("--full");
const noMission = argv.includes("--no-mission");
const swarm = argv.includes("--swarm");
const noWrite = argv.includes("--no-write");
const agentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const localScriptsDir = dirname(fileURLToPath(import.meta.url));
const timeoutMs = Number(argValue("--timeout-ms") || (deep ? 20_000 : 10_000));
const maxBuffer = 16 * 1024 * 1024;

function usage() {
	return `Usage:
  repi engage <target> [--json] [--full|--deep] [--swarm --provider <id> --model <id>] [--workers N]
  repi attack <target> [same options]
  repi reverse <file-or-dir> [same options]
  repi web <url-or-dir> [same options]

Active Engagement Engine turns a target into an executable reverse/pentest run:
- classify target and select lane
- run bounded real tool probes immediately
- write engagement artifacts, command ledger, evidence summary and next queue
- optionally create/update mission and dispatch swarm workers
`;
}

if (argv.includes("--help") || argv.includes("-h")) {
	console.log(usage());
	process.exit(0);
}

function argValue(flag) {
	const index = argv.indexOf(flag);
	if (index === -1) return undefined;
	const next = argv[index + 1];
	return next && !next.startsWith("--") ? next : "";
}

function positionalTarget() {
	const parts = [];
	for (let index = 0; index < argv.length; index++) {
		const arg = argv[index];
		if (arg.startsWith("--")) {
			const next = argv[index + 1];
			if (next && !next.startsWith("--")) index++;
			continue;
		}
		parts.push(arg);
	}
	return parts.join(" ").trim();
}

function redact(value) {
	return String(value ?? "")
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\b(?:A3T|AKIA|ASIA)[A-Z0-9]{16}\b/g, "<redacted:aws-access-key>")
		.replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "<redacted:jwt>")
		.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "<redacted:private-key>")
		.replace(/(?:AUTH_TOKEN|API_KEY|PASSWORD|SECRET|TOKEN|ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|CLIENT_SECRET)=\S+/gi, (match) => `${match.split("=")[0]}=<redacted>`);
}

function ensureDir(path) {
	mkdirSync(path, { recursive: true, mode: 0o700 });
	try {
		chmodSync(path, 0o700);
	} catch {
		// Best effort.
	}
}

function writePrivate(path, content, mode = 0o600) {
	ensureDir(dirname(path));
	writeFileSync(path, content, { encoding: "utf8", mode });
	try {
		chmodSync(path, mode);
	} catch {
		// Best effort.
	}
}

function shortHash(value) {
	return createHash("sha256").update(String(value ?? "")).digest("hex").slice(0, 16);
}

function slug(value) {
	return String(value || "target")
		.toLowerCase()
		.replace(/[^a-z0-9\u4e00-\u9fa5._-]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(0, 48) || "target";
}

function stamp() {
	return new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
}

function isUrl(value) {
	try {
		const url = new URL(value);
		return url.protocol === "http:" || url.protocol === "https:";
	} catch {
		return false;
	}
}

function commandExists(tool) {
	const result = spawnSync("bash", ["-lc", `command -v ${shellQuote(tool)} >/dev/null 2>&1`], { encoding: "utf8", timeout: 3000 });
	return result.status === 0;
}

function shellQuote(value) {
	return `'${String(value).replace(/'/g, "'\\''")}'`;
}

function resolveScript(name) {
	const source = join(root, "scripts", "reverse-agent", name);
	if (existsSync(source)) return source;
	const bundled = join(localScriptsDir, name);
	if (existsSync(bundled)) return bundled;
	return source;
}

function run(command, args, options = {}) {
	const started = Date.now();
	const child = spawnSync(command, args, {
		cwd: options.cwd ?? root,
		env: {
			...process.env,
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
			...(options.env ?? {}),
		},
		input: options.input,
		encoding: "utf8",
		timeout: options.timeout ?? timeoutMs,
		maxBuffer,
	});
	return {
		id: options.id ?? `${basename(command)}-${shortHash(args.join(" "))}`,
		command,
		args,
		cwd: options.cwd ?? root,
		exit: child.status ?? (child.signal ? 128 : 1),
		signal: child.signal,
		durationMs: Date.now() - started,
		stdout: redact(child.stdout ?? ""),
		stderr: redact(child.stderr ?? ""),
		error: child.error ? redact(String(child.error.message || child.error)) : undefined,
	};
}

function compactCommand(row) {
	return `${row.command} ${row.args.map(shellQuote).join(" ")}`.trim();
}

function classify(target) {
	if (isUrl(target)) {
		const parsed = new URL(target);
		return {
			kind: "url",
			lane: "web-api",
			domain: "Web/API pentest",
			target,
			path: null,
			reason: `url protocol=${parsed.protocol} host=${parsed.host}`,
			adapter: "web-runtime",
		};
	}

	const path = resolve(target || process.cwd());
	if (!existsSync(path)) {
		return {
			kind: "text",
			lane: "reverse-pentest-general",
			domain: "Reverse/Pentest general",
			target,
			path: null,
			reason: "target is not a local path or URL; treating it as task text",
			adapter: "general-operator",
		};
	}

	const stat = statSync(path);
	if (stat.isDirectory()) {
		const names = safeList(path).map((name) => name.toLowerCase());
		if (names.includes("androidmanifest.xml") || names.some((name) => name.endsWith(".apk"))) return directoryTarget(path, "mobile", "Mobile reverse", "android/mobile artifacts found");
		if (names.includes("package.json") || names.includes("pnpm-lock.yaml") || names.includes("yarn.lock") || names.includes("vite.config.ts")) return directoryTarget(path, "js-reverse", "JS/Web reverse", "frontend/node artifacts found");
		if (names.includes("dockerfile") || names.some((name) => name.endsWith(".tf") || name.includes("k8s") || name.includes("kubernetes"))) return directoryTarget(path, "cloud-identity", "Cloud/container pentest", "cloud/container artifacts found");
		return directoryTarget(path, "workspace", "Workspace reverse/pentest", "directory target");
	}

	const ext = extname(path).toLowerCase();
	if ([".apk", ".ipa", ".dex"].includes(ext)) return fileTarget(path, "mobile", "Mobile reverse", "mobile package extension");
	if ([".pcap", ".pcapng", ".cap"].includes(ext)) return fileTarget(path, "pcap-dfir", "PCAP/DFIR", "packet capture extension");
	if ([".bin", ".img", ".trx", ".squashfs", ".ubi", ".ubifs"].includes(ext)) return fileTarget(path, "firmware-iot", "Firmware/IoT reverse", "firmware-like extension");
	if ([".js", ".mjs", ".cjs", ".wasm"].includes(ext)) return fileTarget(path, "js-reverse", "JS/WASM reverse", "script or wasm extension");

	let magic = "";
	if (commandExists("file")) {
		const fileRun = run("file", ["-b", path], { id: "classify-file", timeout: 5000 });
		magic = fileRun.stdout.trim();
	}
	if (/ELF|PE32|Mach-O|shared object|executable/i.test(magic)) return fileTarget(path, "native-pwn", "Native reverse/pwn", magic || "native executable");
	return fileTarget(path, "reverse", "File reverse", magic || "local file");
}

function directoryTarget(path, lane, domain, reason) {
	return { kind: "directory", lane, domain, target: path, path, reason, adapter: "workspace-runtime" };
}

function fileTarget(path, lane, domain, reason) {
	return { kind: "file", lane, domain, target: path, path, reason, adapter: "file-runtime" };
}

function safeList(path) {
	try {
		return readdirSync(path).slice(0, 200);
	} catch {
		return [];
	}
}

function writeCommandLedger(artifactDir, rows) {
	const jsonl = rows
		.map((row) =>
			JSON.stringify({
				id: row.id,
				command: row.command,
				args: row.args,
				cwd: row.cwd,
				exit: row.exit,
				signal: row.signal,
				durationMs: row.durationMs,
				stdoutSha256: shortHash(row.stdout),
				stderrSha256: shortHash(row.stderr),
				error: row.error,
			}),
		)
		.join("\n");
	writePrivate(join(artifactDir, "commands.jsonl"), `${jsonl}\n`);
	for (const row of rows) {
		writePrivate(join(artifactDir, "stdout", `${row.id}.txt`), row.stdout.slice(0, 80_000));
		writePrivate(join(artifactDir, "stderr", `${row.id}.txt`), row.stderr.slice(0, 40_000));
	}
}

function toolSnapshot() {
	const tools = [
		"file",
		"sha256sum",
		"strings",
		"readelf",
		"objdump",
		"checksec",
		"r2",
		"gdb",
		"python3",
		"find",
		"curl",
		"jq",
		"rg",
		"tshark",
		"binwalk",
		"unblob",
		"jadx",
		"apktool",
		"frida",
		"adb",
	];
	return tools.map((tool) => ({ tool, available: commandExists(tool) }));
}

function engageFile(targetInfo, artifactDir) {
	const target = targetInfo.path;
	const rows = [];
	rows.push(run("stat", ["--printf", "%n\nsize=%s\nmode=%A\nmtime=%y\n", target], { id: "file-stat", timeout: 5000 }));
	if (commandExists("file")) rows.push(run("file", [target], { id: "file-magic", timeout: 5000 }));
	if (commandExists("sha256sum")) rows.push(run("sha256sum", [target], { id: "file-sha256", timeout: 5000 }));
	if (commandExists("strings")) rows.push(run("bash", ["-lc", `strings -a -n 6 ${shellQuote(target)} | head -160`], { id: "file-strings-head", timeout: timeoutMs }));
	const magic = rows.find((row) => row.id === "file-magic")?.stdout ?? "";
	if (/ELF/i.test(magic) || targetInfo.lane === "native-pwn") {
		if (commandExists("readelf")) {
			rows.push(run("readelf", ["-h", target], { id: "elf-header", timeout: timeoutMs }));
			rows.push(run("readelf", ["-l", target], { id: "elf-program-headers", timeout: timeoutMs }));
			rows.push(run("readelf", ["-sW", target], { id: "elf-symbols-head", timeout: timeoutMs }));
			rows.push(run("readelf", ["-d", target], { id: "elf-dynamic", timeout: timeoutMs }));
		}
		if (commandExists("objdump")) rows.push(run("objdump", ["-f", "-p", target], { id: "objdump-fingerprint", timeout: timeoutMs }));
		if (commandExists("checksec")) rows.push(run("checksec", ["--file", target], { id: "checksec", timeout: timeoutMs }));
	}
	if (targetInfo.lane === "pcap-dfir" && commandExists("tshark")) {
		rows.push(run("tshark", ["-r", target, "-q", "-z", "io,phs"], { id: "pcap-protocol-hierarchy", timeout: timeoutMs }));
		rows.push(run("tshark", ["-r", target, "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol", "-e", "_ws.col.Info", "-c", "80"], { id: "pcap-flow-head", timeout: timeoutMs }));
	}
	if (targetInfo.lane === "firmware-iot") {
		if (commandExists("binwalk")) rows.push(run("binwalk", [target], { id: "firmware-binwalk", timeout: timeoutMs }));
		if (commandExists("unblob")) rows.push(run("unblob", ["--help"], { id: "firmware-unblob-present", timeout: 5000 }));
	}
	return rows;
}

function engageDirectory(targetInfo) {
	const target = targetInfo.path;
	const rows = [];
	rows.push(run("pwd", [], { id: "workspace-pwd", cwd: target, timeout: 3000 }));
	rows.push(run("bash", ["-lc", "find . -maxdepth 3 -type f | sed 's#^./##' | sort | head -240"], { id: "workspace-file-inventory", cwd: target, timeout: timeoutMs }));
	if (commandExists("rg")) {
		rows.push(run("rg", ["-n", "--hidden", "--glob", "!node_modules", "--glob", "!.git", "(route|router|endpoint|auth|jwt|token|cookie|session|sign|signature|crypto|password|secret|admin|upload|download)", "."], { id: "workspace-auth-route-search", cwd: target, timeout: timeoutMs }));
		rows.push(run("rg", ["-n", "--hidden", "--glob", "!node_modules", "--glob", "!.git", "(exec\\(|spawn\\(|system\\(|eval\\(|deserialize|pickle|yaml\\.load|innerHTML|dangerouslySetInnerHTML|sql|query\\()", "."], { id: "workspace-sink-search", cwd: target, timeout: timeoutMs }));
	} else {
		rows.push(run("bash", ["-lc", "grep -RInE '(route|auth|jwt|token|session|sign|crypto|password|secret)' . 2>/dev/null | head -160"], { id: "workspace-auth-route-search", cwd: target, timeout: timeoutMs }));
	}
	for (const manifest of ["package.json", "pyproject.toml", "requirements.txt", "go.mod", "Cargo.toml", "Dockerfile", "AndroidManifest.xml"]) {
		if (existsSync(join(target, manifest))) rows.push(run("bash", ["-lc", `sed -n '1,180p' ${shellQuote(manifest)}`], { id: `manifest-${manifest.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}`, cwd: target, timeout: timeoutMs }));
	}
	return rows;
}

function engageUrl(targetInfo, artifactDir) {
	const target = targetInfo.target;
	const rows = [];
	if (!commandExists("curl")) {
		rows.push({ id: "curl-missing", command: "curl", args: [], cwd: root, exit: 127, signal: null, durationMs: 0, stdout: "", stderr: "curl not found", error: "curl not found" });
		return rows;
	}
	const headersPath = join(artifactDir, "http-headers.txt");
	const bodyPath = join(artifactDir, "http-body-sample.txt");
	rows.push(run("curl", ["-k", "-L", "-I", "--max-time", String(Math.ceil(timeoutMs / 1000)), target], { id: "http-head", timeout: timeoutMs + 3000 }));
	rows.push(run("curl", ["-k", "-L", "--max-time", String(Math.ceil(timeoutMs / 1000)), "-D", headersPath, "-o", bodyPath, target], { id: "http-get-sample", timeout: timeoutMs + 5000 }));
	let body = "";
	try {
		body = readFileSync(bodyPath, "utf8").slice(0, 400_000);
	} catch {
		body = "";
	}
	const assets = Array.from(body.matchAll(/(?:src|href)=["']([^"']+)["']/gi))
		.map((match) => match[1])
		.filter(Boolean)
		.slice(0, 120);
	writePrivate(join(artifactDir, "web-assets.json"), `${JSON.stringify({ target, assets }, null, 2)}\n`);
	if (assets.some((asset) => /\.js(?:\?|$)/i.test(asset))) {
		const firstJs = assets.find((asset) => /\.js(?:\?|$)/i.test(asset));
		rows.push({ id: "web-js-asset-hint", command: "internal", args: [firstJs], cwd: root, exit: 0, signal: null, durationMs: 0, stdout: `first_js_asset=${firstJs}\n`, stderr: "", error: undefined });
	}
	return rows;
}

function nextQueue(targetInfo, artifactDir, toolState) {
	const target = targetInfo.target;
	const q = [];
	const quotedTarget = shellQuote(target);
	q.push(`repi mission status`);
	q.push(`repi -p ${shellQuote(`Use engagement artifact ${artifactDir}. Continue ${targetInfo.domain}: parse decisive anchors, choose one minimal proof path, execute it, then output Outcome → Key Evidence → Verification → Next Step.`)}`);
	if (targetInfo.kind === "url") {
		q.push(`repi -p ${shellQuote(`For ${target}, build route/auth/session matrix from ${artifactDir}; run browser/XHR/WS capture if needed; produce replay commands and IDOR/BOLA/object ownership proof.`)}`);
		q.push(`repi swarm plan ${quotedTarget} --workers ${argValue("--workers") || "5"}`);
	}
	if (targetInfo.lane === "native-pwn") {
		if (toolState.some((row) => row.tool === "r2" && row.available)) q.push(`r2 -A ${quotedTarget}`);
		if (toolState.some((row) => row.tool === "gdb" && row.available)) q.push(`gdb -q ${quotedTarget}`);
		q.push(`repi -p ${shellQuote(`Continue native/pwn from ${artifactDir}: locate compare/decode/crash primitive, generate GDB or r2 trace, and produce a local verifier.`)}`);
	}
	if (targetInfo.kind === "directory") {
		q.push(`repi -p ${shellQuote(`Use ${artifactDir}/commands.jsonl to continue workspace exploitation: bind routes/sinks to runtime proof and create replay matrix.`)}`);
	}
	if (swarm) {
		const provider = argValue("--provider");
		const model = argValue("--model");
		q.push(`repi swarm run ${quotedTarget} --workers ${argValue("--workers") || "5"}${provider ? ` --provider ${shellQuote(provider)}` : ""}${model ? ` --model ${shellQuote(model)}` : ""} --prompt ${shellQuote(`Use engagement artifact ${artifactDir}; each worker must return structured evidence, commands, blockers, and next exploit/reverse step.`)}`);
	}
	q.push(`repi mission pack`);
	return q;
}

function summarizeEvidence(rows, targetInfo, toolState) {
	const passed = rows.filter((row) => row.exit === 0).length;
	const failed = rows.length - passed;
	const availableTools = toolState.filter((row) => row.available).map((row) => row.tool);
	const missingCritical = [];
	for (const tool of criticalTools(targetInfo)) {
		if (!availableTools.includes(tool)) missingCritical.push(tool);
	}
	const anchors = [];
	for (const row of rows) {
		const text = `${row.stdout}\n${row.stderr}`.slice(0, 6000);
		if (/ELF|PE32|Mach-O|executable|shared object/i.test(text)) anchors.push("native binary fingerprint");
		if (/GNU_STACK|RELRO|NX|Canary|PIE/i.test(text)) anchors.push("mitigation anchors");
		if (/HTTP\/|server:|set-cookie|location:/i.test(text)) anchors.push("HTTP/header anchors");
		if (/jwt|token|session|cookie|auth|signature|crypto/i.test(text)) anchors.push("auth/signing anchors");
		if (/pcap|ethernet|tcp|udp|http|dns/i.test(text) && targetInfo.lane === "pcap-dfir") anchors.push("traffic anchors");
	}
	return {
		commandCount: rows.length,
		passed,
		failed,
		availableTools,
		missingCritical,
		anchors: Array.from(new Set(anchors)).slice(0, 24),
		evidenceQuality: passed >= 3 && missingCritical.length === 0 ? "good" : passed >= 2 ? "partial" : "weak",
	};
}

function criticalTools(targetInfo) {
	if (targetInfo.kind === "url") return ["curl"];
	if (targetInfo.lane === "native-pwn") return ["file", "sha256sum", "strings", "readelf"];
	if (targetInfo.lane === "pcap-dfir") return ["file", "sha256sum", "tshark"];
	if (targetInfo.lane === "firmware-iot") return ["file", "sha256sum", "binwalk"];
	if (targetInfo.kind === "directory") return ["find", "rg"];
	return ["file", "sha256sum", "strings"];
}

function renderMarkdown(report) {
	const lines = [];
	lines.push("# REPI Active Engagement Report", "");
	lines.push(`generatedAt: ${report.generatedAt}`);
	lines.push(`runId: ${report.runId}`);
	lines.push(`target: ${report.target.redacted}`);
	lines.push(`lane: ${report.target.lane}`);
	lines.push(`domain: ${report.target.domain}`);
	lines.push(`artifactDir: ${report.artifactDir}`, "");
	lines.push("## Outcome", "");
	lines.push(`- evidenceQuality: ${report.summary.evidenceQuality}`);
	lines.push(`- commands: ${report.summary.commandCount}, passed=${report.summary.passed}, failed=${report.summary.failed}`);
	lines.push(`- anchors: ${report.summary.anchors.length ? report.summary.anchors.join(", ") : "<none-yet>"}`);
	lines.push(`- missingCriticalTools: ${report.summary.missingCritical.length ? report.summary.missingCritical.join(", ") : "<none>"}`, "");
	lines.push("## Key Evidence", "");
	for (const row of report.commands) {
		lines.push(`- ${row.exit === 0 ? "PASS" : "FAIL"} ${row.id}: \`${compactCommand(row)}\` exit=${row.exit} stdout=${shortHash(row.stdout)} stderr=${shortHash(row.stderr)}`);
	}
	lines.push("", "## Verification", "");
	lines.push(`- command ledger: ${join(report.artifactDir, "commands.jsonl")}`);
	lines.push(`- stdout/stderr snapshots: ${join(report.artifactDir, "stdout")} / ${join(report.artifactDir, "stderr")}`);
	lines.push("", "## Next Step", "");
	for (const command of report.nextQueue) lines.push(`- \`${command}\``);
	lines.push("");
	return lines.join("\n");
}

function createMission(targetInfo) {
	if (noMission) return undefined;
	const task = `Active engage ${targetInfo.domain}: ${targetInfo.target}`;
	const result = run(process.execPath, [resolveScript("repi-mission.mjs"), root, "new", task, "--target", targetInfo.target, "--json"], {
		id: "mission-new",
		timeout: 15_000,
	});
	try {
		return { exit: result.exit, report: JSON.parse(result.stdout) };
	} catch {
		return { exit: result.exit, stdoutTail: result.stdout.slice(-1200), stderrTail: result.stderr.slice(-1200) };
	}
}

function maybeRunSwarm(targetInfo) {
	if (!swarm) return undefined;
	const provider = argValue("--provider");
	const model = argValue("--model");
	if (!provider || !model) return { skipped: true, reason: "--swarm requires --provider and --model for live worker dispatch" };
	const workers = argValue("--workers") || "5";
	const prompt = argValue("--prompt") || "Return structured reverse/pentest evidence, blockers, commands, and next proof step.";
	const result = run(process.execPath, [resolveScript("repi-swarm-llm-run.mjs"), root, "run", targetInfo.target, "--workers", workers, "--provider", provider, "--model", model, "--prompt", prompt, "--json"], {
		id: "swarm-run",
		timeout: deep ? 300_000 : 180_000,
	});
	return { exit: result.exit, stdoutTail: result.stdout.slice(-4000), stderrTail: result.stderr.slice(-2000) };
}

const target = positionalTarget() || process.cwd();
const targetInfo = classify(target);
const runId = `${stamp()}-${slug(targetInfo.lane)}-${shortHash(targetInfo.target)}`;
const artifactDir = join(agentDir, "recon", "evidence", "engagements", runId);
if (!noWrite) {
	ensureDir(artifactDir);
	ensureDir(join(artifactDir, "stdout"));
	ensureDir(join(artifactDir, "stderr"));
}

const toolState = toolSnapshot();
const mission = createMission(targetInfo);
let commands = [];
if (targetInfo.kind === "url") commands = engageUrl(targetInfo, artifactDir);
else if (targetInfo.kind === "directory") commands = engageDirectory(targetInfo, artifactDir);
else if (targetInfo.kind === "file") commands = engageFile(targetInfo, artifactDir);
else commands = [run("bash", ["-lc", `printf '%s\n' ${shellQuote(targetInfo.target)}`], { id: "task-text", timeout: 3000 })];
const swarmReport = maybeRunSwarm(targetInfo);
const summary = summarizeEvidence(commands, targetInfo, toolState);
const nextQueueRows = nextQueue(targetInfo, artifactDir, toolState);

const report = {
	kind: "repi-active-engagement-report",
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	runId,
	root,
	agentDir,
	artifactDir,
	mode: deep ? "deep" : "quick",
	target: {
		redacted: redact(targetInfo.target),
		kind: targetInfo.kind,
		lane: targetInfo.lane,
		domain: targetInfo.domain,
		adapter: targetInfo.adapter,
		reason: redact(targetInfo.reason),
		pathExists: targetInfo.path ? existsSync(targetInfo.path) : false,
	},
	toolState,
	summary,
	mission,
	swarm: swarmReport,
	commands,
	nextQueue: nextQueueRows,
};

if (!noWrite) {
	writeCommandLedger(artifactDir, commands);
	writePrivate(join(artifactDir, "report.json"), `${JSON.stringify({ ...report, commands: commands.map((row) => ({ ...row, stdout: row.stdout.slice(0, 4000), stderr: row.stderr.slice(0, 2000) })) }, null, 2)}\n`);
	writePrivate(join(artifactDir, "summary.md"), renderMarkdown(report));
	writePrivate(join(artifactDir, "next-commands.sh"), `#!/usr/bin/env bash\nset -euo pipefail\n\n${nextQueueRows.join("\n")}\n`, 0o700);
	writePrivate(join(agentDir, "recon", "evidence", "engagements", "latest.json"), `${JSON.stringify({ runId, artifactDir, generatedAt: report.generatedAt, target: report.target, summary }, null, 2)}\n`);
}

if (json) {
	console.log(JSON.stringify({ ...report, commands: commands.map((row) => ({ ...row, stdout: row.stdout.slice(0, 2000), stderr: row.stderr.slice(0, 1200) })) }, null, 2));
} else {
	console.log("REPI Active Engagement");
	console.log(`runId: ${runId}`);
	console.log(`target: ${report.target.redacted}`);
	console.log(`lane: ${report.target.lane} (${report.target.domain})`);
	console.log(`artifactDir: ${artifactDir}`);
	console.log(`evidenceQuality: ${summary.evidenceQuality}; commands=${summary.commandCount}; passed=${summary.passed}; failed=${summary.failed}`);
	if (summary.missingCritical.length) console.log(`missingCriticalTools: ${summary.missingCritical.join(", ")}`);
	if (summary.anchors.length) console.log(`anchors: ${summary.anchors.join(", ")}`);
	console.log("Next queue:");
	for (const command of nextQueueRows.slice(0, 8)) console.log(`- ${command}`);
	console.log(`report: ${join(artifactDir, "summary.md")}`);
}

process.exit(summary.passed > 0 ? 0 : 1);
