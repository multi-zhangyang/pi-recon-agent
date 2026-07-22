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
	rmSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defaultReportWriteError } from "./lib/report-write-helpers.mjs";

const args = process.argv.slice(2);
const rootArg = args[0] && !args[0].startsWith("--") ? args.shift() : undefined;
const root = resolve(rootArg ?? process.cwd());
const json = args.includes("--json");
const fix = args.includes("--fix");
const agentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const repiBin = process.env.REPI_BIN_PATH || join(root, "repi");
const probeTimeoutMs = (() => {
	const raw = process.env.REPI_DOCTOR_PROBE_TIMEOUT_MS;
	const value = Number(raw);
	return Number.isFinite(value) && value >= 1000 ? Math.floor(value) : 45_000;
})();
const packageBinMode = process.env.REPI_PACKAGE_BIN === "1";
const installedRepi = process.env.REPI_INSTALLED_BIN_PATH || (existsSync(join(root, "repi")) ? join(root, "repi") : "/usr/local/bin/repi");
const localScriptsDir = dirname(fileURLToPath(import.meta.url));
const envModelApiAliases = new Set([
	"openai-compatible",
	"openai-chat",
	"chat",
	"chat-completions",
	"openai-completions",
	"response",
	"responses",
	"openai-response",
	"openai-responses",
	"anthropic",
	"claude",
	"anthropic-compatible",
	"anthropic-messages",
]);

function readJson(path) {
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch {
		return undefined;
	}
}

function readFirstExistingText(candidates) {
	for (const rel of candidates) {
		try {
			const path = join(root, rel);
			if (existsSync(path)) return readFileSync(path, "utf8");
		} catch {
			// Try the next source/dist candidate.
		}
	}
	return "";
}

function check(id, pass, evidence, fix) {
	return { id, status: pass ? "pass" : "fail", evidence, fix };
}

function redactText(value) {
	return String(value ?? "")
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\bglpat-[A-Za-z0-9_-]{16,}\b/g, "<redacted:gitlab-token>")
		.replace(/\b(?:A3T|AKIA|ASIA)[A-Z0-9]{16}\b/g, "<redacted:aws-access-key>")
		.replace(/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, "<redacted:slack-token>")
		.replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "<redacted:jwt>")
		.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "<redacted:private-key>")
		.replace(/(?:AUTH_TOKEN|API_KEY|PASSWORD|SECRET|TOKEN|ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|CLIENT_SECRET)=\S+/gi, (match) => `${match.split("=")[0]}=<redacted>`)
		.replace(/(authorization|x-api-key|api-key)\s*[:=]\s*bearer\s+[A-Za-z0-9._-]+/gi, "$1: Bearer <redacted>")
		.replace(/(authorization|x-api-key|api-key)\s*[:=]\s*[A-Za-z0-9._-]{12,}/gi, "$1: <redacted>")
		.replace(/(baseUrl|baseURL|endpoint|url)\s*[:=]\s*https?:\/\/[^\s"',}]+/gi, "$1=<redacted:url>")
		.replace(/\bhttps?:\/\/api\.[^\s"',}<)]+/gi, "<redacted:url>");
}

function firstEnv(names) {
	for (const name of names) {
		const value = process.env[name]?.trim();
		if (value) return value;
	}
	return undefined;
}

function normalizeEnvModelApi(value) {
	const normalized = String(value || "openai-completions").trim().toLowerCase().replace(/_/g, "-");
	if (["openai-compatible", "openai-chat", "chat", "chat-completions", "openai-completions"].includes(normalized))
		return "openai-completions";
	if (["response", "responses", "openai-response", "openai-responses"].includes(normalized)) return "openai-responses";
	if (["anthropic", "claude", "anthropic-compatible", "anthropic-messages"].includes(normalized))
		return "anthropic-messages";
	return "openai-completions";
}

function currentEnvModelConfigStatus() {
	const baseUrl = firstEnv(["REPI_BASE_URL", "REPI_MODEL_BASE_URL"]);
	const model = firstEnv(["REPI_MODEL", "REPI_MODEL_ID"]);
	const provider = firstEnv(["REPI_PROVIDER", "REPI_MODEL_PROVIDER", "REPI_PROVIDER_ID"]) || "repi-env";
	const rawApi = firstEnv(["REPI_MODEL_API", "REPI_API"]);
	const normalizedApi = rawApi ? rawApi.trim().toLowerCase().replace(/_/g, "-") : "";
	const invalidApi = rawApi && !envModelApiAliases.has(normalizedApi) ? rawApi : undefined;
	const authEnv = firstEnv(["REPI_AUTH_TOKEN"])
		? "REPI_AUTH_TOKEN"
		: firstEnv(["REPI_API_KEY"])
			? "REPI_API_KEY"
			: firstEnv(["REPI_MODEL_API_KEY"])
				? "REPI_MODEL_API_KEY"
				: "REPI_AUTH_TOKEN";
	const touched = Boolean(baseUrl || model || rawApi);
	const missing = [];
	if (touched && !baseUrl) missing.push("REPI_BASE_URL");
	if (touched && !model) missing.push("REPI_MODEL");
	const enabled = Boolean(baseUrl && model);
	return {
		touched,
		enabled,
		mode: enabled ? "env-model" : touched ? "incomplete-env-model" : "saved-profile",
		provider: enabled || touched ? provider : "<env-disabled>",
		model: model ? redactText(model) : "<unset>",
		api: normalizeEnvModelApi(rawApi),
		rawApi: rawApi ?? "<default>",
		invalidApi,
		authEnv,
		authPresent: Boolean(process.env[authEnv]),
		missing,
	};
}

function run(cmd, args, options = {}) {
	const timeoutMs = options.timeout ?? 20_000;
	const result = spawnSync(cmd, args, {
		cwd: root,
		env: {
			...process.env,
			REPI_OFFLINE: "1",
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
		},
		input: options.input,
		encoding: "utf8",
		timeout: timeoutMs,
		maxBuffer: 2 * 1024 * 1024,
	});
	const stdout = redactText(result.stdout ?? "");
	const stderr = redactText(result.stderr ?? "");
	const errorMessage = result.error ? redactText(String(result.error.message || result.error)) : undefined;
	const timedOut = Boolean(result.error && String(result.error.message || result.error).includes("ETIMEDOUT"));
	return {
		code: result.status ?? (result.signal === "SIGTERM" ? 143 : result.signal === "SIGKILL" ? 137 : 1),
		stdout,
		stderr,
		error: errorMessage,
		signal: result.signal ?? undefined,
		timedOut,
		timeoutMs,
	};
}

function parseJsonl(text) {
	const rows = [];
	for (const line of String(text ?? "").split(/\r?\n/)) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		try {
			rows.push(JSON.parse(trimmed));
		} catch {
			rows.push({ type: "parse_error", line: trimmed.slice(0, 240) });
		}
	}
	return rows;
}

function rpcResponse(lines, command) {
	return lines.find((line) => line?.type === "response" && line.command === command);
}

function rpcCommandAndToolProbeSummary(probe) {
	const lines = parseJsonl(probe.stdout);
	const commandResponse = rpcResponse(lines, "get_commands");
	const toolResponse = rpcResponse(lines, "get_tools");
	const stateResponse = rpcResponse(lines, "get_state");
	const commands = Array.isArray(commandResponse?.data?.commands) ? commandResponse.data.commands : [];
	const tools = Array.isArray(toolResponse?.data?.tools) ? toolResponse.data.tools : [];
	const goalCommands = commands.filter((command) => command?.name === "goal");
	const goalTools = tools.filter((tool) => tool?.name === "goal_complete");
	const model = stateResponse?.data?.model;
	return {
		exit: probe.code,
		timedOut: Boolean(probe.timedOut),
		parseErrors: lines.filter((line) => line?.type === "parse_error").length,
		commandResponseOk: commandResponse?.success === true,
		toolResponseOk: toolResponse?.success === true,
		stateResponseOk: stateResponse?.success === true,
		commandCount: commands.length,
		toolCount: tools.length,
		goalCommandCount: goalCommands.length,
		goalToolCount: goalTools.length,
		goalCommandInline: goalCommands.every((command) => String(command?.sourceInfo?.path ?? "").startsWith("<inline:")),
		goalToolInline: goalTools.every((tool) => String(tool?.sourceInfo?.path ?? "").startsWith("<inline:")),
		modelProvider: typeof model?.provider === "string" ? model.provider : undefined,
		modelId: typeof model?.id === "string" ? model.id : undefined,
		modelApi: typeof model?.api === "string" ? model.api : undefined,
		contextWindow: typeof model?.contextWindow === "number" ? model.contextWindow : undefined,
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

function pathDirs() {
	return String(process.env.PATH || "")
		.split(delimiter)
		.map((item) => item.trim())
		.filter(Boolean);
}

function sameResolvedPath(a, b) {
	return Boolean(a && b && a === b);
}

function repiEntriesOnPath() {
	const seen = new Set();
	const entries = [];
	for (const dir of pathDirs()) {
		const path = join(dir, "repi");
		if (seen.has(path)) continue;
		seen.add(path);
		const entry = pathEntry(path);
		if (entry.exists) entries.push({ dir, path, ...entry });
	}
	return entries;
}

function shellRcPathStatus(expectedBinPath) {
	const expectedDir = dirname(expectedBinPath || installedRepi);
	const userLocalBin = join(homedir(), ".local", "bin");
	const rcCandidates = [".bashrc", ".profile", ".bash_profile", ".zshrc"].map((name) => join(homedir(), name));
	const rcHits = [];
	for (const path of rcCandidates) {
		try {
			const text = readFileSync(path, "utf8");
			if (text.includes(expectedDir) || text.includes("$HOME/.local/bin") || text.includes("~/.local/bin")) {
				rcHits.push(path);
			}
		} catch {
			// Missing shell rc files are normal in containers and CI.
		}
	}
	const pathHasExpectedDir = pathDirs().some((dir) => {
		try {
			return realpathSync(dir) === realpathSync(expectedDir);
		} catch {
			return dir === expectedDir;
		}
	});
	const userLocalInstall = expectedDir === userLocalBin || expectedDir.endsWith("/.local/bin");
	const requireRc = process.env.REPI_DOCTOR_REQUIRE_PATH === "1" || (userLocalInstall && !pathHasExpectedDir);
	return {
		expectedDir,
		pathHasExpectedDir,
		userLocalInstall,
		requireRc,
		rcHits,
		ok: !requireRc || pathHasExpectedDir || rcHits.length > 0,
	};
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

// Mirror the runtime's explicit isolated-profile layouts. Do not recursively
// scan evidence for arbitrary settings.json fixtures.
function knownIsolatedProfileSettings(root = agentDir) {
	const paths = [join(root, "settings.json")];
	const add = (path) => paths.push(path);
	const threadRoot = join(root, "recon", "agent-threads");
	try {
		for (const entry of readdirSync(threadRoot, { withFileTypes: true })) {
			if (entry.isDirectory()) add(join(threadRoot, entry.name, "agent-home", "settings.json"));
		}
	} catch {}
	const swarmsRoot = join(root, "recon", "evidence", "swarms");
	try {
		for (const entry of readdirSync(swarmsRoot, { withFileTypes: true })) {
			if (!entry.isDirectory()) continue;
			if (/-sessions$/.test(entry.name)) add(join(swarmsRoot, entry.name, ".repi", "agent", "settings.json"));
			if (/-worker-child-session-runtime-child-process$/.test(entry.name)) {
				add(join(swarmsRoot, entry.name, "home", ".repi", "agent", "settings.json"));
			}
		}
	} catch {}
	return [...new Set(paths)];
}

function retiredRuntimeState() {
	const paths = [];
	const add = (path) => {
		if (existsSync(path)) paths.push(path);
	};
	for (const settingsPath of knownIsolatedProfileSettings()) {
		const settings = readJson(settingsPath);
		if (settings && !Array.isArray(settings) && Object.prototype.hasOwnProperty.call(settings, "memory")) {
			paths.push(`${settingsPath}#memory`);
		}
	}
	for (const path of [
		join(agentDir, "memory"),
		join(agentDir, "SYSTEM.md"),
		join(agentDir, "APPEND_SYSTEM.md"),
		join(agentDir, "prompts", "memory.md"),
		join(agentDir, "skills", "reverse-pentest-orchestrator"),
		join(agentDir, "recon", "memory"),
		join(agentDir, "recon", "evidence", "tool-calls"),
		join(agentDir, "recon", "evidence", "knowledge"),
		join(agentDir, "recon", "builtin", "prompts", "memory.md"),
	]) add(path);
	try {
		for (const entry of readdirSync(join(agentDir, "recon", "evidence", "runs"), { withFileTypes: true })) {
			if (/(?:case-memory|knowledge-graph)/i.test(entry.name)) add(join(agentDir, "recon", "evidence", "runs", entry.name));
		}
	} catch {}
	try {
		for (const entry of readdirSync(join(agentDir, "recon", "archive"), { withFileTypes: true })) {
			if (entry.isDirectory() && /^(?:legacy-file-profile|poison-cleanup-runtime)-/.test(entry.name)) {
				add(join(agentDir, "recon", "archive", entry.name));
			}
		}
	} catch {}
	try {
		for (const entry of readdirSync(join(agentDir, "recon", "agent-threads"), { withFileTypes: true })) {
			if (!entry.isDirectory()) continue;
			const worker = join(agentDir, "recon", "agent-threads", entry.name, "agent-home");
			for (const path of [
				join(worker, "memory"),
				join(worker, "SYSTEM.md"),
				join(worker, "APPEND_SYSTEM.md"),
				join(worker, "prompts", "memory.md"),
				join(worker, "skills", "reverse-pentest-orchestrator"),
				join(worker, "recon", "memory"),
				join(worker, "recon", "evidence", "tool-calls"),
				join(worker, "recon", "evidence", "knowledge"),
				join(worker, "recon", "builtin", "prompts", "memory.md"),
			]) add(path);
		}
	} catch {}
	return { clean: paths.length === 0, paths };
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
	// opt #177: guard the mkdir so an ENOSPC/EACCES in the --fix repair path
	// (archive/extension dirs) becomes an observable stderr diagnostic +
	// non-zero exit instead of an uncaught throw that aborts the doctor.
	// The doctor report itself is emitted to stdout; this guards its only
	// on-disk write path (the --fix repair layout).
	try {
		mkdirSync(path, { recursive: true, mode: 0o700 });
	} catch (err) {
		defaultReportWriteError(
			`Error creating report directory ${path}: ${err instanceof Error ? err.message : String(err)}`,
		);
	}
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
	if (before.legacyProfileEntries.length > 0) {
		for (const entry of before.legacyProfileEntries) {
			try {
				rmSync(entry.path, { recursive: true, force: true });
				moved.push({ from: entry.path, removed: true });
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
	const installerScript = join(root, "scripts/reverse-agent/install-repi.sh");
	if (packageBinMode || !existsSync(installerScript)) {
		fixActions.push({
			id: "install-repi",
			exit: 0,
			stdoutTail: packageBinMode
				? "skipped: package-bin mode; launcher install is managed outside this package"
				: `skipped: source installer unavailable at ${installerScript}`,
			stderrTail: "",
		});
	} else {
		const installerArgs = [installerScript, root];
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
	}
	const profileInit = run(process.execPath, [resolveScript("init-repi-profile.mjs"), root], { timeout: 30_000 });
	fixActions.push({
		id: "profile-init",
		exit: profileInit.code,
		stdoutTail: profileInit.stdout.slice(-1200),
		stderrTail: profileInit.stderr.slice(-1200),
		error: profileInit.error,
	});
	const modelFix = run(process.execPath, [resolveScript("model-inspect.mjs"), root, "doctor", "--fix", "--json"], { timeout: 60_000 });
	fixActions.push({
		id: "model-config-fix",
		exit: modelFix.code,
		stdoutTail: modelFix.stdout.slice(-1200),
		stderrTail: modelFix.stderr.slice(-1200),
		error: modelFix.error,
	});
	fixActions.push(repairLegacyExtensionLayout());
}

const settings = readJson(join(agentDir, "settings.json"));
const models = readJson(join(agentDir, "models.json"));
const help = existsSync(repiBin) ? run(repiBin, ["--offline", "--help"], { timeout: probeTimeoutMs }) : { code: 1, stdout: "", stderr: "missing repi", timedOut: false };
const listModels = existsSync(repiBin) ? run(repiBin, ["--offline", "--list-models"], { timeout: probeTimeoutMs }) : { code: 1, stdout: "", stderr: "missing repi", timedOut: false };
const rpcProbe = existsSync(repiBin)
	? run(repiBin, ["--offline", "--mode", "rpc", "--no-session"], {
			timeout: probeTimeoutMs,
			input: `${JSON.stringify({ id: "state", type: "get_state" })}\n${JSON.stringify({ id: "commands", type: "get_commands" })}\n${JSON.stringify({ id: "tools", type: "get_tools" })}\n`,
		})
	: { code: 1, stdout: "", stderr: "missing repi", timedOut: false };
const rpcRuntime = rpcCommandAndToolProbeSummary(rpcProbe);
const helpText = `${help.stdout}\n${help.stderr}`;
const envModelRuntime = currentEnvModelConfigStatus();
const expectedEnvModel = firstEnv(["REPI_MODEL", "REPI_MODEL_ID"]);
const expectedEnvProvider = envModelRuntime.enabled
	? firstEnv(["REPI_PROVIDER", "REPI_MODEL_PROVIDER", "REPI_PROVIDER_ID"]) || "repi-env"
	: undefined;
const expectedEnvContextWindow = Number(
	firstEnv(["REPI_CONTEXT_WINDOW", "REPI_MODEL_CONTEXT_WINDOW", "REPI_AUTO_COMPACT_WINDOW", "REPI_MODEL_AUTO_COMPACT_WINDOW"]),
);
const globalRepi = pathEntry(installedRepi);
const localRepi = pathEntry(repiBin);
const globalRepiOk = packageBinMode || (globalRepi.exists && globalRepi.resolved === localRepi.resolved);
const expectedRepiResolved = localRepi.resolved || globalRepi.resolved;
const pathRepiEntries = repiEntriesOnPath();
const firstPathRepi = pathRepiEntries[0];
const pathHasExpectedRepi = pathRepiEntries.some((entry) => sameResolvedPath(entry.resolved, expectedRepiResolved));
const pathShadowed =
	Boolean(firstPathRepi?.resolved && expectedRepiResolved) &&
	!sameResolvedPath(firstPathRepi.resolved, expectedRepiResolved);
const pathActivationRequired = process.env.REPI_DOCTOR_REQUIRE_PATH === "1" || Boolean(process.env.REPI_INSTALLED_BIN_PATH);
const pathCommandOk = !pathActivationRequired || packageBinMode || (pathHasExpectedRepi && !pathShadowed);
const shellRcPath = shellRcPathStatus(repiBin);
const launcherSource = readFirstExistingText(["repi", "dist/cli.js", "dist/cli/repi-bootstrap.js"]);
const bootstrapSource = readFirstExistingText([
	"packages/coding-agent/src/cli/repi-bootstrap.ts",
	"dist/cli/repi-bootstrap.js",
]);
const argsSource = readFirstExistingText(["packages/coding-agent/src/cli/args.ts", "dist/cli/args.js"]);
const printModeSource = readFirstExistingText(["packages/coding-agent/src/modes/print-mode.ts", "dist/modes/print-mode.js"]);
const releaseSmokeSource = readFirstExistingText([
	"scripts/reverse-agent/repi-release-tarball-smoke.mjs",
	"dist/reverse-agent/repi-release-tarball-smoke.mjs",
]);
const goalSource = readFirstExistingText(["packages/coding-agent/src/core/repi/goal.ts", "dist/core/repi/goal.js"]);
const reconProfileSource = readFirstExistingText([
	"packages/coding-agent/src/core/recon-profile.ts",
	"dist/core/recon-profile.js",
]);
const sessionLifecycleSource = readFirstExistingText([
	"packages/coding-agent/src/core/repi/session-lifecycle-runtime.ts",
	"dist/core/repi/session-lifecycle-runtime.js",
]);
const resourceSource = readFirstExistingText([
	"packages/coding-agent/src/core/repi/resources.ts",
	"dist/core/repi/resources.js",
]);
const modelRegistrySource = readFirstExistingText([
	"packages/coding-agent/src/core/model-registry.ts",
	"dist/core/model-registry.js",
]);
const modelRuntimeSource = readFirstExistingText([
	"packages/coding-agent/src/core/model-runtime.ts",
	"dist/core/model-runtime.js",
]);
const repiEnvProviderSource = readFirstExistingText([
	"packages/coding-agent/src/core/repi-env-provider.ts",
	"dist/core/repi-env-provider.js",
]);
const modelInspectSource = readFirstExistingText([
	"scripts/reverse-agent/model-inspect.mjs",
	"dist/reverse-agent/model-inspect.mjs",
]);

const guardrailMarkers = [
	"REPI_PRINT_PROGRESS",
	"REPI_PRINT_TIMEOUT_MS",
	"REPI_PRINT_TIMEOUT_GRACE_MS",
	"REPI_PRINT_TIMEOUT_TOOL_GRACE_MS",
	"REPI_PRINT_MAX_TURNS",
	"REPI_PRINT_MAX_TOOL_CALLS",
	"REPI_STDIN_READ_TIMEOUT_MS",
	"REPI_BASH_DEFAULT_TIMEOUT_SECONDS",
];
const missingHelpGuardrails = guardrailMarkers.filter((marker) => !helpText.includes(marker));
const missingBootstrapGuardrails = guardrailMarkers.filter((marker) => !bootstrapSource.includes(marker));
const goalModeBuiltInOk =
	goalSource.includes("installRepiGoalMode") &&
	goalSource.includes("goal_complete") &&
	goalSource.includes("REPI_GOAL_STATE_ENTRY_TYPE") &&
	goalSource.includes("formatGoalFooterStatus") &&
	(reconProfileSource.includes("installRepiGoalMode(pi)") || sessionLifecycleSource.includes("installRepiGoalMode(pi)"));
const goalFooterStatusOk =
	goalSource.includes("formatGoalFooterStatus") &&
	goalSource.includes("formatGoalStatus") &&
	goalSource.includes('ctx.ui.setStatus(STATUS_KEY, formatGoalFooterStatus(goal))') &&
	goalSource.includes('"🎯 complete"') &&
	goalSource.includes("The footer shows");
const goalPrintUiOk =
	printModeSource.includes("createPrintExtensionUIContext") &&
	printModeSource.includes("formatPrintNotify") &&
	printModeSource.includes("extension_ui_request") &&
	printModeSource.includes("REPI_PRINT_STATUS") &&
	releaseSmokeSource.includes("package-bin:goal-help-print") &&
	releaseSmokeSource.includes("package-bin:goal-help-json") &&
	releaseSmokeSource.includes("package-bin:goal-status-fresh-print") &&
	releaseSmokeSource.includes("package-bin:goal-status-fresh-json");
const goalConflictSuppressionOk =
	resourceSource.includes("hasGoalModeSignature") &&
	resourceSource.includes("isExternalGoalModeExtension") &&
	resourceSource.includes("suppressLegacyReconConflicts");
const envModelSource = [launcherSource, bootstrapSource, argsSource].join("\n");
const envModelGuardOk =
	launcherSource.includes("validate_repi_env_model_config") ||
	bootstrapSource.includes("missingRepiEnvModelConfig");
const envModelContractOk =
	envModelGuardOk &&
	envModelSource.includes("REPI_MODEL_API") &&
	modelRegistrySource.includes("repiEnvProviderConfig") &&
	modelRuntimeSource.includes("getRepiEnvProviderConfig") &&
	repiEnvProviderSource.includes("REPI_AUTO_COMPACT_WINDOW") &&
	repiEnvProviderSource.includes("openai-compatible") &&
	modelInspectSource.includes("buildStatusReport") &&
	modelInspectSource.includes("repi model status");
const envModelRpcMatchesExpected =
	!envModelRuntime.enabled ||
	(rpcRuntime.stateResponseOk &&
		rpcRuntime.modelProvider === expectedEnvProvider &&
		rpcRuntime.modelId === expectedEnvModel &&
		(!Number.isFinite(expectedEnvContextWindow) || rpcRuntime.contextWindow === expectedEnvContextWindow));
const launchReadinessOk =
	goalModeBuiltInOk &&
	goalFooterStatusOk &&
	goalPrintUiOk &&
	goalConflictSuppressionOk &&
	envModelContractOk &&
	envModelRuntime.missing.length === 0 &&
	!envModelRuntime.invalidApi &&
	envModelRpcMatchesExpected &&
	rpcRuntime.commandResponseOk &&
	rpcRuntime.toolResponseOk &&
	rpcRuntime.goalCommandCount === 1 &&
	rpcRuntime.goalToolCount === 1;
const savedDefaultProvider = typeof settings?.defaultProvider === "string" ? settings.defaultProvider : undefined;
const savedDefaultModel = typeof settings?.defaultModel === "string" ? settings.defaultModel : undefined;
const legacyExtensions = legacyExtensionLayout();
const retiredState = retiredRuntimeState();
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
	check(
		"launcher:path-command-resolution",
		pathCommandOk,
		`required=${pathActivationRequired} entries=${pathRepiEntries.length} expected=${expectedRepiResolved ?? "<none>"} first=${firstPathRepi ? `${firstPathRepi.path}->${firstPathRepi.resolved ?? "<unresolved>"}` : "<none>"} hasExpected=${pathHasExpectedRepi} shadowed=${pathShadowed}`,
		"put the installed repi bin directory first in PATH or rerun install-repi.sh/doctor --fix",
	),
	check(
		"launcher:shell-rc-path-activation",
		shellRcPath.ok,
		`required=${shellRcPath.requireRc} expectedDir=${shellRcPath.expectedDir} pathHasDir=${shellRcPath.pathHasExpectedDir} userLocal=${shellRcPath.userLocalInstall} rcHits=${shellRcPath.rcHits.length}`,
		"add export PATH=\"$HOME/.local/bin:$PATH\" to ~/.bashrc or source the installer-updated shell rc",
	),
	check("runtime:agent-dir", existsSync(agentDir), `agentDir=${agentDir}`, "run npm run install:repi"),
	check("runtime:settings", Boolean(settings), `settings=${join(agentDir, "settings.json")}`, "run npm run install:repi"),
	check(
		"runtime:legacy-extension-layout",
		legacyExtensions.clean,
		`hooks=${legacyExtensions.hooksPresent ? 1 : 0} customTools=${legacyExtensions.customToolEntries.length} legacyProfile=${legacyExtensions.legacyProfileEntries.length}`,
		"run repi doctor --fix",
	),
	check(
		"runtime:retired-state-absent",
		retiredState.clean,
		retiredState.clean ? "memory/trace/file-profile state absent" : `paths=${retiredState.paths.slice(0, 8).join(",")}`,
		"run repi doctor --fix to remove retired memory, trace, and legacy profile state",
	),
	check("models:parse", listModels.code === 0, `exit=${listModels.code} stdout=${listModels.stdout.slice(0, 120).replace(/\s+/g, " ")} stderr=${listModels.stderr.slice(0, 120).replace(/\s+/g, " ")}`, "fix ~/.repi/agent/models.json"),
	check("models:config-present", Boolean(models) || listModels.code === 0, `modelsJson=${Boolean(models)} listModelsExit=${listModels.code}`, "configure ~/.repi/agent/models.json if no provider exists"),
	check(
		"cli:help",
		help.code === 0 && /REPI reverse\/pentest/.test(helpText),
		`exit=${help.code} timeoutMs=${help.timeoutMs ?? probeTimeoutMs}${help.signal ? ` signal=${help.signal}` : ""}${help.timedOut ? " timedOut=true" : ""}`,
		"run npm install && npm run install:repi",
	),
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
	check(
		"goal:built-in-mode",
		goalModeBuiltInOk,
		`goalSource=${Boolean(goalSource)} profileInstall=${reconProfileSource.includes("installRepiGoalMode(pi)")} lifecycleInstall=${sessionLifecycleSource.includes("installRepiGoalMode(pi)")}`,
		"update REPI so /goal and goal_complete are built into the inline profile",
	),
	check(
		"goal:footer-status-contract",
		goalFooterStatusOk,
		`formatFooter=${goalSource.includes("formatGoalFooterStatus")} setStatus=${goalSource.includes("ctx.ui.setStatus")} completeStatus=${goalSource.includes("🎯 complete")}`,
		"keep /goal footer status visible for active, paused, budget-limited, and complete states",
	),
	check(
		"goal:print-non-tui-ui-context",
		goalPrintUiOk,
		`printUiContext=${printModeSource.includes("createPrintExtensionUIContext")} notify=${printModeSource.includes("formatPrintNotify")} jsonUi=${printModeSource.includes("extension_ui_request")} statusOptIn=${printModeSource.includes("REPI_PRINT_STATUS")} releaseSmokePrint=${releaseSmokeSource.includes("package-bin:goal-help-print")} releaseSmokeJson=${releaseSmokeSource.includes("package-bin:goal-help-json")} releaseSmokeFreshPrint=${releaseSmokeSource.includes("package-bin:goal-status-fresh-print")} releaseSmokeFreshJson=${releaseSmokeSource.includes("package-bin:goal-status-fresh-json")}`,
		"keep /goal help/status visible in print/json non-TUI mode and covered by release tarball smoke",
	),
	check(
		"goal:rpc-runtime-registration",
		rpcRuntime.exit === 0 &&
			!rpcRuntime.timedOut &&
			rpcRuntime.commandResponseOk &&
			rpcRuntime.toolResponseOk &&
			rpcRuntime.goalCommandCount === 1 &&
			rpcRuntime.goalToolCount === 1 &&
			rpcRuntime.goalCommandInline &&
			rpcRuntime.goalToolInline,
		`exit=${rpcRuntime.exit} timeout=${rpcRuntime.timedOut} commands=${rpcRuntime.commandCount} tools=${rpcRuntime.toolCount} goalCommands=${rpcRuntime.goalCommandCount} inlineCommand=${rpcRuntime.goalCommandInline} goalTools=${rpcRuntime.goalToolCount} inlineTool=${rpcRuntime.goalToolInline} parseErrors=${rpcRuntime.parseErrors}`,
		"run repi doctor --fix; remove conflicting external goal extension if /goal is not inline-owned",
	),
	check(
		"goal:extension-conflict-suppression",
		goalConflictSuppressionOk,
		`hasGoalSignature=${resourceSource.includes("hasGoalModeSignature")} externalGoalSuppression=${resourceSource.includes("isExternalGoalModeExtension")}`,
		"suppress external @narumitw/pi-goal when built-in REPI goal mode is active",
	),
	check(
		"models:env-only-contract",
		envModelContractOk,
		`envGuard=${envModelGuardOk} envApi=${envModelSource.includes("REPI_MODEL_API")} registryEnv=${modelRegistrySource.includes("repiEnvProviderConfig")} runtimeEnv=${modelRuntimeSource.includes("getRepiEnvProviderConfig")} modelStatus=${modelInspectSource.includes("buildStatusReport")}`,
		"keep Claude-Code-style REPI_* env model config as the default path",
	),
	check(
		"models:env-runtime-config",
		envModelRuntime.missing.length === 0 && !envModelRuntime.invalidApi,
		`touched=${envModelRuntime.touched} enabled=${envModelRuntime.enabled} provider=${envModelRuntime.provider} model=${envModelRuntime.model} api=${envModelRuntime.api} rawApi=${envModelRuntime.rawApi} auth=${envModelRuntime.authEnv}:${envModelRuntime.authPresent ? "set" : "missing"} missing=${envModelRuntime.missing.join(",") || "<none>"} invalidApi=${envModelRuntime.invalidApi ?? "<none>"}`,
		"export REPI_AUTH_TOKEN, REPI_BASE_URL, REPI_MODEL, and REPI_MODEL_API=openai-compatible|openai-responses|anthropic",
	),
	check(
		"models:env-rpc-runtime",
		envModelRpcMatchesExpected,
		`mode=${envModelRuntime.mode} envEnabled=${envModelRuntime.enabled} savedProfileActive=${Boolean(savedDefaultProvider || savedDefaultModel)} stateOk=${rpcRuntime.stateResponseOk} provider=${rpcRuntime.modelProvider ?? "<none>"} expectedEnvProvider=${expectedEnvProvider ?? "<env-disabled>"} model=${redactText(rpcRuntime.modelId ?? "<none>")} expectedEnvModel=${redactText(expectedEnvModel ?? "<env-disabled>")} api=${rpcRuntime.modelApi ?? "<none>"} context=${rpcRuntime.contextWindow ?? "<none>"} expectedContext=${Number.isFinite(expectedEnvContextWindow) ? expectedEnvContextWindow : "<unset>"}`,
		"fix REPI_* exports or run `repi model reset --yes` to clear stale saved default provider/model",
	),
	check(
		"models:env-overrides-saved-default",
		envModelRpcMatchesExpected,
		`mode=${envModelRuntime.mode} envEnabled=${envModelRuntime.enabled} savedProvider=${redactText(savedDefaultProvider ?? "<none>")} savedModel=${redactText(savedDefaultModel ?? "<none>")} runtimeProvider=${rpcRuntime.modelProvider ?? "<none>"} runtimeModel=${redactText(rpcRuntime.modelId ?? "<none>")} expectedEnvProvider=${expectedEnvProvider ?? "<env-disabled>"} expectedEnvModel=${redactText(expectedEnvModel ?? "<env-disabled>")}`,
		"when REPI_* is set it must win over stale ~/.repi/agent/settings.json defaults; run `repi model reset --yes` or fix env exports",
	),
	check(
		"repi:launch-readiness",
		launchReadinessOk,
		`goalMode=${goalModeBuiltInOk} footer=${goalFooterStatusOk} nonTui=${goalPrintUiOk} goalConflictSuppression=${goalConflictSuppressionOk} rpcGoal=${rpcRuntime.goalCommandCount}/${rpcRuntime.goalToolCount} envContract=${envModelContractOk} envRuntimeMissing=${envModelRuntime.missing.join(",") || "<none>"} envInvalidApi=${envModelRuntime.invalidApi ?? "<none>"} envRpc=${envModelRpcMatchesExpected}`,
		"run repi doctor --fix; remove conflicting external goal extensions; fix REPI_* env exports or run `repi model reset --yes`",
	),
	check("network:update-suppressed", /--offline/.test(helpText) && /REPI_SKIP_VERSION_CHECK/.test(helpText), "offline/version-check controls available"),
];

function statusOf(id) {
	return checks.find((item) => item.id === id)?.status ?? "fail";
}

const failedChecks = checks.filter((item) => item.status !== "pass");
const readiness = {
	kind: "RepiLaunchReadinessSummaryV1",
	schemaVersion: 1,
	status: launchReadinessOk ? "pass" : "fail",
	goal: {
		builtIn: statusOf("goal:built-in-mode"),
		footer: statusOf("goal:footer-status-contract"),
		nonTui: statusOf("goal:print-non-tui-ui-context"),
		rpc: statusOf("goal:rpc-runtime-registration"),
		rpcGoalCommands: rpcRuntime.goalCommandCount,
		rpcGoalTools: rpcRuntime.goalToolCount,
		inlineCommand: rpcRuntime.goalCommandInline,
		inlineTool: rpcRuntime.goalToolInline,
	},
	extensions: {
		conflictSuppression: statusOf("goal:extension-conflict-suppression"),
	},
	envModel: {
		contract: statusOf("models:env-only-contract"),
		runtime: statusOf("models:env-runtime-config"),
		rpc: statusOf("models:env-rpc-runtime"),
		enabled: envModelRuntime.enabled,
		provider: envModelRuntime.provider,
		model: envModelRuntime.model,
		api: envModelRuntime.api,
		auth: `${envModelRuntime.authEnv}:${envModelRuntime.authPresent ? "set" : "missing"}`,
		missing: envModelRuntime.missing,
		invalidApi: envModelRuntime.invalidApi ?? null,
		runtimeProvider: rpcRuntime.modelProvider ?? null,
		runtimeModel: redactText(rpcRuntime.modelId ?? "<none>"),
		contextWindow: rpcRuntime.contextWindow ?? null,
	},
	next: failedChecks.length
		? Array.from(new Set(failedChecks.map((item) => item.fix).filter(Boolean))).slice(0, 6)
		: ["repi", "/goal status", "repi model status"],
};

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
	readiness,
	checks,
	ok: checks.every((item) => item.status === "pass") && fixActions.every((item) => item.exit === 0),
};

if (json) {
	console.log(JSON.stringify(result, null, 2));
} else {
	console.log("REPI Doctor");
	console.log(`root: ${root}`);
	console.log(`agentDir: ${agentDir}`);
	console.log(`readiness: ${readiness.status}`);
	console.log(
		`goal: built-in=${readiness.goal.builtIn} footer=${readiness.goal.footer} nonTui=${readiness.goal.nonTui} rpc=${readiness.goal.rpc} commands/tools=${readiness.goal.rpcGoalCommands}/${readiness.goal.rpcGoalTools}`,
	);
	console.log(
		`env-model: enabled=${readiness.envModel.enabled} provider=${readiness.envModel.provider} model=${readiness.envModel.model} api=${readiness.envModel.api} auth=${readiness.envModel.auth} context=${readiness.envModel.contextWindow ?? "<none>"}`,
	);
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
