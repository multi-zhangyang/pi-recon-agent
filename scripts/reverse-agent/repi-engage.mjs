#!/usr/bin/env node
import { createHash } from "node:crypto";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	readFileSync,
	readdirSync,
	statSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, extname, join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { inflateRawSync } from "node:zlib";
import { atomicWriteFile } from "./lib/atomic-file.mjs";
import {
	classifyTarget,
	collectDirectoryFiles,
	fileTarget,
	malwareArtifactFile,
	readSmallText,
	textLikeAgentFile,
	textLikeCloudFile,
	textLikeMalwareFile,
	textLikeWindowsAdFile,
} from "./lib/engage-target-classifier.mjs";
import { configureWebEngagementRuntime, engageUrl, extractJsonObjectFromText } from "./lib/web-engagement-runtime.mjs";
import { pcapQuicklookRows } from "./lib/pcap-dfir-runtime.mjs";
import {
	configureNativeRuntime,
	nativeElfHardeningRows,
	nativeExecutionRows,
	nativeMachOQuicklookRows,
	nativePeQuicklookRows,
	nativeStaticTriageRows,
	parseElfHardening,
	parsePeQuicklook,
	writeNativeExploitHypotheses,
	writeNativeGdbTraceArtifacts,
	writeNativePrimitiveClaims,
	writeNativeReplayVerifier,
	writeNativeRuntimeVerification,
	writeNativeRuntimeVerifier,
} from "./lib/native-reverse-runtime.mjs";
import {
	configureMobileRuntime,
	mobileArchiveQuicklookRows,
	mobileAttackSurfaceClaims,
	writeMobileArchiveVerification,
	writeMobileArchiveVerifier,
	writeMobileFridaHook,
} from "./lib/mobile-reverse-runtime.mjs";
import {
	configureCryptoStegoRuntime,
	cryptoStegoMediaQuicklookRows,
	dataLooksLikeCryptoStegoMedia,
	embeddedZipArchives,
	writeCryptoStegoSolver,
	writeCryptoStegoTransformClaims,
	writeCryptoStegoVerification,
	writeCryptoStegoVerifier,
} from "./lib/crypto-stego-runtime.mjs";
import { configureFirmwareRuntime, firmwareQuicklookRows } from "./lib/firmware-reverse-runtime.mjs";
import { configureMemoryRuntime, memoryQuicklookRows } from "./lib/memory-forensics-runtime.mjs";
import {
	configureWorkspaceSourceRuntime,
	writeJsReverseWorkbench,
	writeWorkspaceRouteReplayHarness,
	writeWorkspaceSourceRuntimeClaims,
	writeWorkspaceSourceRuntimeHarness,
	writeWorkspaceSourceRuntimeVerification,
	writeWorkspaceSourceRuntimeVerifier,
} from "./lib/workspace-source-runtime.mjs";
import { cloudIdentityRows } from "./lib/cloud-identity-runtime.mjs";
import { agentBoundaryRows } from "./lib/agent-boundary-runtime.mjs";
import { windowsAdRows } from "./lib/windows-ad-runtime.mjs";
import { malwareRows } from "./lib/malware-runtime.mjs";
import {
	configureEngageProofRuntime,
	proofHarnessRows,
	writeRuntimeRepairLoopHarness,
	writeUnifiedProofGraph,
} from "./lib/engage-proof-runtime.mjs";

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
const commandExistsCache = new Map();

function firstEnv(names) {
	for (const name of names) {
		const value = process.env[name]?.trim();
		if (value) return value;
	}
	return undefined;
}

const DEFAULT_SWARM_PROVIDER = firstEnv(["REPI_SWARM_DEFAULT_PROVIDER", "REPI_PROVIDER", "REPI_MODEL_PROVIDER", "REPI_PROVIDER_ID"]);
const DEFAULT_SWARM_MODEL = firstEnv(["REPI_SWARM_DEFAULT_MODEL", "REPI_MODEL", "REPI_MODEL_ID"]);
const DEFAULT_SWARM_LABEL = DEFAULT_SWARM_PROVIDER || DEFAULT_SWARM_MODEL ? `${DEFAULT_SWARM_PROVIDER ?? "<auto>"}/${DEFAULT_SWARM_MODEL ?? "<auto>"}` : "REPI env/default";

function usage() {
	return `Usage:
  repi engage <target> [--json] [--full|--deep] [--swarm [--provider <id>] [--model <id>]] [--workers N]
  repi attack <target> [same options]
  repi reverse <file-or-dir> [same options]
  repi web <url-or-dir> [same options]

Active Engagement Engine turns a target into an executable reverse/pentest run:
- classify target and select lane
- run bounded real tool probes immediately
- write engagement artifacts, command ledger, evidence summary and next queue
- optionally create/update mission and dispatch swarm workers (default model selection: ${DEFAULT_SWARM_LABEL})
`;
}

if (argv.includes("--help") || argv.includes("-h")) {
	console.log(usage());
	process.exit(0);
}

const valueFlags = new Set(["--timeout-ms", "--provider", "--model", "--workers", "--prompt"]);

function argValue(flag) {
	for (let index = 0; index < argv.length; index++) {
		const arg = argv[index];
		if (arg === flag) {
			const next = argv[index + 1];
			return next && !next.startsWith("--") ? next : "";
		}
		if (arg.startsWith(`${flag}=`)) return arg.slice(flag.length + 1);
	}
	return undefined;
}

function positionalTarget() {
	const parts = [];
	for (let index = 0; index < argv.length; index++) {
		const arg = argv[index];
		if (arg === "--") {
			parts.push(...argv.slice(index + 1));
			break;
		}
		if (arg.startsWith("--")) {
			const flagName = arg.includes("=") ? arg.slice(0, arg.indexOf("=")) : arg;
			if (!arg.includes("=") && valueFlags.has(flagName)) index++;
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
		.replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, "Bearer <redacted>")
		.replace(/\b([A-Za-z0-9_-]{24,})(?=\.[A-Za-z0-9-]{1,63}\.[A-Za-z]{2,63}\b)/g, (match) => `<redacted:dns-label:${match.length}:${createHash("sha256").update(match).digest("hex").slice(0, 12)}>`)
		.replace(/\b((?:secret|token|password|passwd|flag)[A-Za-z0-9_-]{4,})(?=\.[A-Za-z0-9-]{1,63}\.[A-Za-z]{2,63}\b)/gi, (match) => `<redacted:dns-label:${match.length}:${createHash("sha256").update(match).digest("hex").slice(0, 12)}>`)
		.replace(/\b(?=[A-Za-z0-9_]{32,}\b)(?=[A-Za-z0-9_]*[G-Zg-z_])[A-Za-z0-9_]+\b/g, (match) => `<redacted:encoded-blob:${match.length}:${createHash("sha256").update(match).digest("hex").slice(0, 12)}>`)
		.replace(/((?:authorization|x-api-key|api-key|cookie|set-cookie)\s*[:=]\s*["']?)([^"'\n;]{8,})/gi, "$1<redacted>")
		.replace(/(\b(?:USER|PASS)\s+)([^\s\r\n]{3,})/gi, "$1<redacted>")
		.replace(/(\bAUTH\s+(?:PLAIN|LOGIN|CRAM-MD5|XOAUTH2)?\s*)([A-Za-z0-9+/=._~-]{4,})/gi, "$1<redacted>")
		.replace(/(\b[A-Za-z0-9_.-]+\s+LOGIN\s+)(?:"[^"\r\n]+"|\S+)\s+(?:"[^"\r\n]+"|\S+)/gi, "$1<redacted> <redacted>")
		.replace(/(<meta[^>]+name=["'](?:csrf-token|csrf_token|_csrf)["'][^>]+content=["'])([^"']+)(["'])/gi, "$1<redacted>$3")
		.replace(/(<input[^>]+name=["'][^"']*(?:csrf|token)[^"']*["'][^>]+value=["'])([^"']+)(["'])/gi, "$1<redacted>$3")
		.replace(/(["']?(?:api[_-]?key|token|secret|password|client_secret|access_token|refresh_token)["']?\s*[:=]\s*["'])([^"']{8,})(["'])/gi, "$1<redacted>$3")
		.replace(/(["'][^"'\n]*(?:secret|token|password|api[_-]?key|client[_-]?secret|access[_-]?key)[^"'\n]{8,}["'])/gi, '"<redacted:secret-literal>"')
		.replace(/([?&](?:api[_-]?key|token|access_token|refresh_token|client_secret|secret|password)=)[^&\s"'<>]{8,}/gi, "$1<redacted>")
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
	atomicWriteFile(path, content, mode);
	try {
		chmodSync(path, mode);
	} catch {
		// Best effort.
	}
}

function shortHash(value) {
	return createHash("sha256").update(String(value ?? "")).digest("hex").slice(0, 16);
}

function httpSecretHash(value) {
	return createHash("sha256").update(String(value ?? ""), "utf8").digest("hex");
}

function readJsonArtifact(path) {
	try {
		if (!path || !existsSync(path)) return null;
		return JSON.parse(readFileSync(path, "utf8"));
	} catch {
		return null;
	}
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

function commandExists(tool) {
	if (commandExistsCache.has(tool)) return commandExistsCache.get(tool);
	const result = spawnSync("bash", ["-lc", `command -v ${shellQuote(tool)} >/dev/null 2>&1`], { encoding: "utf8", timeout: 3000 });
	const available = result.status === 0;
	commandExistsCache.set(tool, available);
	return available;
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
	const row = {
		id: options.id ?? `${basename(command)}-${shortHash(args.join(" "))}`,
		command,
		args: args.map((arg) => redact(arg)),
		cwd: redact(options.cwd ?? root),
		exit: child.status ?? (child.signal ? 128 : 1),
		signal: child.signal,
		durationMs: Date.now() - started,
		stdout: redact(child.stdout ?? ""),
		stderr: redact(child.stderr ?? ""),
		error: child.error ? redact(String(child.error.message || child.error)) : undefined,
	};
	if (options.includeRaw) {
		Object.defineProperty(row, "rawStdout", { value: child.stdout ?? "", enumerable: false });
		Object.defineProperty(row, "rawStderr", { value: child.stderr ?? "", enumerable: false });
	}
	return row;
}

function compactCommand(row) {
	return `${row.command} ${row.args.map(shellQuote).join(" ")}`.trim();
}

function webEngagementRuntime() {
	return {
		deep,
		root,
		noWrite,
		redact,
		shellQuote,
		writePrivate,
		readJsonArtifact,
		bufferSha256,
		httpSecretHash,
		shortHash,
		slug,
		commandExists,
		run,
		timeoutMs,
		localScriptsDir,
	};
}

function pcapDfirRuntime() {
	return {
		deep,
		noWrite,
		root,
		redact,
		writePrivate,
		bufferSha256,
		shortHash,
		httpSecretHash,
		slug,
		findSignatureOffsets,
		embeddedZipArchives,
		parseZipCentralDirectory,
		zipEntryData,
	};
}

function nativeReverseRuntime() {
	return {
		deep,
		noWrite,
		root,
		redact,
		writePrivate,
		bufferSha256,
		shortHash,
		httpSecretHash,
		readJsonArtifact,
		byteEntropy,
		firmwareStrings,
		firmwareEntropySamples,
		timeoutMs,
		run,
		shellQuote,
	};
}

function mobileReverseRuntime() {
	return {
		noWrite,
		root,
		redact,
		writePrivate,
		bufferSha256,
		httpSecretHash,
		shortHash,
		shellQuote,
		firmwareStrings,
		parseZipCentralDirectory,
		zipEntryData,
	};
}

function cryptoStegoRuntime() {
	return {
		noWrite,
		root,
		redact,
		writePrivate,
		bufferSha256,
		httpSecretHash,
		shortHash,
		shellQuote,
		readJsonArtifact,
		byteEntropy,
		parseZipCentralDirectory,
	};
}

function firmwareRuntime() {
	return {
		root,
		redact,
		shortHash,
		bufferSha256,
		writePrivate,
		noWrite,
		shellQuote,
		findSignatureOffsets,
		firmwareStrings,
		firmwareEntropySamples,
	};
}

function memoryRuntime() {
	return {
		root,
		redact,
		shortHash,
		bufferSha256,
		writePrivate,
		noWrite,
		shellQuote,
		firmwareStrings,
		firmwareEntropySamples,
	};
}

function workspaceSourceRuntime() {
	return {
		noWrite,
		writePrivate,
		readJsonArtifact,
		redact,
		httpSecretHash,
		shortHash,
		shellQuote,
	};
}

function cloudIdentityRuntime() {
	return {
		root,
		redact,
		shortHash,
		shellQuote,
		noWrite,
		writePrivate,
		httpSecretHash,
		readSmallText,
		readJsonArtifact,
		collectDirectoryFiles,
		textLikeCloudFile,
		bufferSha256,
	};
}

function agentBoundaryRuntime() {
	return {
		root,
		redact,
		shortHash,
		shellQuote,
		noWrite,
		writePrivate,
		httpSecretHash,
		readSmallText,
		readJsonArtifact,
		collectDirectoryFiles,
		textLikeAgentFile,
		commandExists,
		run,
		timeoutMs,
	};
}

function windowsAdRuntime() {
	return {
		root,
		redact,
		shortHash,
		shellQuote,
		noWrite,
		writePrivate,
		readSmallText,
		readJsonArtifact,
		collectDirectoryFiles,
		textLikeWindowsAdFile,
		bufferSha256,
		firmwareStrings,
	};
}

function malwareRuntime() {
	return {
		root,
		redact,
		shortHash,
		shellQuote,
		noWrite,
		writePrivate,
		collectDirectoryFiles,
		malwareArtifactFile,
		textLikeMalwareFile,
		bufferSha256,
		byteEntropy,
		firmwareStrings,
		parseElfHardening,
		parsePeQuicklook,
	};
}

function engageProofRuntime() {
	return {
		root,
		noWrite,
		writePrivate,
		redact,
		shortHash,
		bufferSha256,
		readJsonArtifact,
		shellQuote,
		run,
		slug,
	};
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
		"bash",
		"node",
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
		"unzip",
		"xxd",
		"exiftool",
		"yara",
		"capa",
		"floss",
		"strace",
		"vol",
		"volatility3",
		"zsteg",
		"steghide",
		"pngcheck",
		"foremost",
		"stegseek",
	];
	const script = tools
		.map((tool) => `if command -v ${shellQuote(tool)} >/dev/null 2>&1; then printf '%s\\t1\\n' ${shellQuote(tool)}; else printf '%s\\t0\\n' ${shellQuote(tool)}; fi`)
		.join("\n");
	const result = spawnSync("bash", ["-lc", script], { encoding: "utf8", timeout: 10_000 });
	const batch = new Map();
	if (result.status === 0 || result.stdout) {
		for (const line of String(result.stdout ?? "").split(/\r?\n/)) {
			const [tool, value] = line.split("\t");
			if (!tool) continue;
			batch.set(tool, value === "1");
			commandExistsCache.set(tool, value === "1");
		}
	}
	return tools.map((tool) => ({ tool, available: batch.has(tool) ? batch.get(tool) : commandExists(tool) }));
}

function dataLooksLikeZip(target) {
	try {
		const data = readFileSync(target);
		return data.length >= 4 && data.subarray(0, 4).toString("hex") === "504b0304";
	} catch {
		return false;
	}
}

function findZipEndOfCentralDirectory(data) {
	const minimum = Math.max(0, data.length - (65_535 + 22));
	for (let offset = data.length - 22; offset >= minimum; offset--) {
		if (data.readUInt32LE(offset) === 0x06054b50) {
			return {
				offset,
				entryCount: data.readUInt16LE(offset + 10),
				centralDirectorySize: data.readUInt32LE(offset + 12),
				centralDirectoryOffset: data.readUInt32LE(offset + 16),
				commentLength: data.readUInt16LE(offset + 20),
			};
		}
	}
	return undefined;
}

function parseZipCentralDirectory(data, limit = 2000) {
	const eocd = findZipEndOfCentralDirectory(data);
	if (!eocd) throw new Error("ZIP end-of-central-directory not found");
	const entries = [];
	let cursor = eocd.centralDirectoryOffset;
	const end = Math.min(data.length, eocd.centralDirectoryOffset + eocd.centralDirectorySize);
	while (cursor + 46 <= end && entries.length < Math.min(eocd.entryCount || limit, limit)) {
		if (data.readUInt32LE(cursor) !== 0x02014b50) break;
		const flags = data.readUInt16LE(cursor + 8);
		const method = data.readUInt16LE(cursor + 10);
		const crc32 = data.readUInt32LE(cursor + 16);
		const compressedSize = data.readUInt32LE(cursor + 20);
		const uncompressedSize = data.readUInt32LE(cursor + 24);
		const nameLength = data.readUInt16LE(cursor + 28);
		const extraLength = data.readUInt16LE(cursor + 30);
		const commentLength = data.readUInt16LE(cursor + 32);
		const externalAttributes = data.readUInt32LE(cursor + 38);
		const localHeaderOffset = data.readUInt32LE(cursor + 42);
		const nameStart = cursor + 46;
		const nameEnd = nameStart + nameLength;
		if (nameEnd > end) break;
		const name = data.toString(flags & 0x800 ? "utf8" : "latin1", nameStart, nameEnd);
		entries.push({
			name,
			lower: name.toLowerCase(),
			method,
			crc32: `0x${crc32.toString(16).padStart(8, "0")}`,
			compressedSize,
			uncompressedSize,
			externalAttributes,
			localHeaderOffset,
		});
		cursor = nameEnd + extraLength + commentLength;
	}
	return { eocd, entries };
}

function zipEntryData(data, entry, maxBytes = 512 * 1024) {
	if (!entry || entry.localHeaderOffset + 30 > data.length) return undefined;
	const offset = entry.localHeaderOffset;
	if (data.readUInt32LE(offset) !== 0x04034b50) return undefined;
	const nameLength = data.readUInt16LE(offset + 26);
	const extraLength = data.readUInt16LE(offset + 28);
	const start = offset + 30 + nameLength + extraLength;
	if (start < 0 || start > data.length) return undefined;
	if (entry.compressedSize > maxBytes || entry.uncompressedSize > maxBytes) return undefined;
	const compressed = data.subarray(start, Math.min(data.length, start + entry.compressedSize));
	try {
		if (entry.method === 0) return compressed;
		if (entry.method === 8) return inflateRawSync(compressed);
	} catch {
		return undefined;
	}
	return undefined;
}

function bufferSha256(data) {
	return createHash("sha256").update(data).digest("hex");
}

function findSignatureOffsets(data, signature, limit = 20) {
	const offsets = [];
	let cursor = 0;
	while (offsets.length < limit) {
		const offset = data.indexOf(signature, cursor);
		if (offset < 0) break;
		offsets.push(offset);
		cursor = offset + Math.max(1, signature.length);
	}
	return offsets;
}

function byteEntropy(buffer) {
	if (!buffer.length) return 0;
	const counts = new Array(256).fill(0);
	for (const byte of buffer) counts[byte] += 1;
	let entropy = 0;
	for (const count of counts) {
		if (!count) continue;
		const p = count / buffer.length;
		entropy -= p * Math.log2(p);
	}
	return Math.round(entropy * 1000) / 1000;
}

function firmwareEntropySamples(data) {
	const windowSize = Math.min(65_536, Math.max(256, data.length));
	const step = Math.max(windowSize, Math.floor(data.length / 8) || windowSize);
	const samples = [];
	for (let offset = 0; offset < data.length && samples.length < 12; offset += step) {
		const window = data.subarray(offset, Math.min(data.length, offset + windowSize));
		samples.push({ offset, size: window.length, entropy: byteEntropy(window) });
	}
	return samples;
}

function firmwareStrings(data, minLength = 5, limit = 3000) {
	const strings = [];
	const maxScan = Math.min(data.length, 32 * 1024 * 1024);
	let start = -1;
	for (let index = 0; index < maxScan; index++) {
		const byte = data[index];
		const printable = byte === 0x09 || byte === 0x0a || byte === 0x0d || (byte >= 0x20 && byte <= 0x7e);
		if (printable) {
			if (start < 0) start = index;
			continue;
		}
		if (start >= 0 && index - start >= minLength) {
			strings.push({ offset: start, text: data.toString("utf8", start, index) });
			if (strings.length >= limit) return strings;
		}
		start = -1;
	}
	if (start >= 0 && maxScan - start >= minLength && strings.length < limit) strings.push({ offset: start, text: data.toString("utf8", start, maxScan) });
	return strings;
}

function dataLooksLikeElf(target) {
	try {
		const data = readFileSync(target, { encoding: null, flag: "r" });
		return data.length >= 4 && data.subarray(0, 4).toString("hex") === "7f454c46";
	} catch {
		return false;
	}
}

function dataLooksLikePe(target) {
	try {
		const data = readFileSync(target, { encoding: null, flag: "r" });
		if (data.length < 0x40 || data.subarray(0, 2).toString("ascii") !== "MZ") return false;
		const peOffset = data.readUInt32LE(0x3c);
		return peOffset > 0 && peOffset + 4 <= data.length && data.subarray(peOffset, peOffset + 4).toString("hex") === "50450000";
	} catch {
		return false;
	}
}

function dataLooksLikeMachO(target) {
	try {
		const data = readFileSync(target, { encoding: null, flag: "r" });
		if (data.length < 4) return false;
		const magic = data.subarray(0, 4).toString("hex");
		return ["feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe", "bebafeca", "cafebabf", "bfbafeca"].includes(magic);
	} catch {
		return false;
	}
}

function engageFile(targetInfo, artifactDir) {
	const target = targetInfo.path;
	const rows = [];
	configureNativeRuntime(nativeReverseRuntime());
	configureMobileRuntime(mobileReverseRuntime());
	configureCryptoStegoRuntime(cryptoStegoRuntime());
	configureFirmwareRuntime(firmwareRuntime());
	configureMemoryRuntime(memoryRuntime());
	configureWorkspaceSourceRuntime(workspaceSourceRuntime());
	rows.push(run("stat", ["--printf", "%n\nsize=%s\nmode=%A\nmtime=%y\n", target], { id: "file-stat", timeout: 5000 }));
	if (commandExists("file")) rows.push(run("file", [target], { id: "file-magic", timeout: 5000 }));
	if (commandExists("sha256sum")) rows.push(run("sha256sum", [target], { id: "file-sha256", timeout: 5000 }));
	if (commandExists("strings") && targetInfo.lane !== "pcap-dfir") rows.push(run("bash", ["-lc", `strings -a -n 6 ${shellQuote(target)} | head -160`], { id: "file-strings-head", timeout: timeoutMs }));
	const magic = rows.find((row) => row.id === "file-magic")?.stdout ?? "";
	if (/ELF/i.test(magic) || targetInfo.lane === "native-pwn") {
		const isElf = dataLooksLikeElf(target);
		const isPe = dataLooksLikePe(target);
		const isMachO = dataLooksLikeMachO(target);
		if (isElf) rows.push(...nativeElfHardeningRows(target, artifactDir));
		if (isPe) rows.push(...nativePeQuicklookRows(target, artifactDir));
		if (isMachO) rows.push(...nativeMachOQuicklookRows(target, artifactDir));
		rows.push(...nativeStaticTriageRows(target, artifactDir));
		if (isElf && commandExists("readelf")) {
			rows.push(run("readelf", ["-h", target], { id: "elf-header", timeout: timeoutMs }));
			rows.push(run("readelf", ["-l", target], { id: "elf-program-headers", timeout: timeoutMs }));
			rows.push(run("readelf", ["-sW", target], { id: "elf-symbols-head", timeout: timeoutMs }));
			rows.push(run("readelf", ["-d", target], { id: "elf-dynamic", timeout: timeoutMs }));
		}
		if (commandExists("objdump")) rows.push(run("objdump", ["-f", "-p", target], { id: "objdump-fingerprint", timeout: timeoutMs }));
		if (commandExists("checksec")) rows.push(run("checksec", ["--file", target], { id: "checksec", timeout: timeoutMs }));
		rows.push(...nativeExecutionRows(target));
		const verifierPath = writeNativeReplayVerifier(artifactDir, target);
		if (verifierPath) {
			rows.push({ id: "native-replay-verifier-artifact", command: "internal", args: [redact(verifierPath)], cwd: root, exit: 0, signal: null, durationMs: 0, stdout: `verifier=${redact(verifierPath)}\nrun=python3 ${redact(verifierPath)} ${redact(target)}\n`, stderr: "", error: undefined });
		}
		const traceArtifacts = writeNativeGdbTraceArtifacts(artifactDir, target);
		if (traceArtifacts) {
			rows.push({
				id: "native-gdb-trace-artifact",
				command: "internal",
				args: [redact(traceArtifacts.gdbPath), redact(traceArtifacts.payloadPath), redact(traceArtifacts.offsetPath)],
				cwd: root,
				exit: 0,
				signal: null,
				durationMs: 0,
				stdout: `gdbScript=${redact(traceArtifacts.gdbPath)}\npayload=${redact(traceArtifacts.payloadPath)}\noffsetHelper=${redact(traceArtifacts.offsetPath)}\nrun=gdb -q -x ${redact(traceArtifacts.gdbPath)} ${redact(target)}\n`,
				stderr: "",
				error: undefined,
			});
		}
		const runtimeVerifierPath = writeNativeRuntimeVerifier(artifactDir);
		if (runtimeVerifierPath) {
			rows.push({
				id: "native-runtime-verifier-artifact",
				command: "internal",
				args: [redact(runtimeVerifierPath)],
				cwd: root,
				exit: 0,
				signal: null,
				durationMs: 0,
				stdout: `verifier=${redact(runtimeVerifierPath)}\nrun=python3 ${redact(runtimeVerifierPath)} ${redact(target)} ${redact(artifactDir)} ${redact(join(artifactDir, "native-runtime-verification.json"))}\n`,
				stderr: "",
				error: undefined,
			});
		}
		const hypotheses = writeNativeExploitHypotheses(artifactDir, target, rows);
		if (hypotheses) {
			rows.push({
				id: "native-exploit-hypotheses",
				command: "internal",
				args: [redact(hypotheses.path)],
				cwd: root,
				exit: 0,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(hypotheses.summary, null, 2)}\n`,
				stderr: "",
				error: undefined,
			});
		}
		const runtimeVerification = writeNativeRuntimeVerification(artifactDir, target, rows);
		if (runtimeVerification) {
			rows.push({
				id: "native-runtime-verification",
				command: "internal",
				args: [redact(runtimeVerification.path)],
				cwd: root,
				exit: runtimeVerification.summary.proofReady ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(runtimeVerification.summary, null, 2)}\n`,
				stderr: "",
				error: runtimeVerification.summary.proofReady ? undefined : "native runtime verification blockers present",
			});
		}
		const primitiveClaims = writeNativePrimitiveClaims(artifactDir, target, rows, hypotheses?.summary, runtimeVerification?.summary);
		if (primitiveClaims) {
			rows.push({
				id: "native-primitive-claims",
				command: "internal",
				args: [redact(primitiveClaims.path)],
				cwd: root,
				exit: primitiveClaims.summary.proofReady ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(primitiveClaims.summary, null, 2)}\n`,
				stderr: "",
				error: primitiveClaims.summary.proofReady ? undefined : "no native primitive claims promoted",
			});
		}
	}
	if (targetInfo.lane === "js-reverse") {
		const pattern = "fetch|xhr|XMLHttpRequest|websocket|sign|signature|encrypt|decrypt|crypto|subtle|wasm|WebAssembly";
		if (commandExists("rg")) rows.push(run("rg", ["-n", "--no-heading", pattern, target], { id: "js-pattern-search", timeout: timeoutMs }));
		else rows.push(run("bash", ["-lc", `grep -nE ${shellQuote(pattern)} ${shellQuote(target)} 2>/dev/null | head -160`], { id: "js-pattern-search", timeout: timeoutMs }));
		if (extname(target).toLowerCase() === ".wasm") rows.push(run("bash", ["-lc", `xxd -l 256 ${shellQuote(target)} 2>/dev/null || true`], { id: "wasm-header-hex", timeout: timeoutMs }));
		const workbenchPath = writeJsReverseWorkbench(artifactDir, target);
		if (workbenchPath) {
			const outputPath = join(artifactDir, "js-reverse-workbench.json");
			rows.push(run(process.execPath, [workbenchPath, target, outputPath], { id: "js-reverse-workbench", timeout: timeoutMs + 3000 }));
		}
	}
	if (targetInfo.lane === "mobile" || targetInfo.lane === "mobile-ios") {
		if (dataLooksLikeZip(target)) rows.push(...mobileArchiveQuicklookRows(target, artifactDir, targetInfo.lane));
		if (commandExists("unzip")) rows.push(run("unzip", ["-l", target], { id: "mobile-archive-list", timeout: timeoutMs }));
		if (targetInfo.lane === "mobile" && commandExists("aapt")) rows.push(run("aapt", ["dump", "badging", target], { id: "android-aapt-badging", timeout: timeoutMs }));
		if (targetInfo.lane === "mobile-ios") rows.push(run("bash", ["-lc", `unzip -p ${shellQuote(target)} 'Payload/*.app/Info.plist' 2>/dev/null | head -c 12000 || true`], { id: "ios-info-plist", timeout: timeoutMs }));
		const hookPath = writeMobileFridaHook(artifactDir, targetInfo.lane);
		if (hookPath) {
			rows.push({
				id: "mobile-frida-hook-artifact",
				command: "internal",
				args: [redact(hookPath)],
				cwd: root,
				exit: 0,
				signal: null,
				durationMs: 0,
				stdout: `hook=${redact(hookPath)}\nrun=frida -U -f <package-or-bundle-id> -l ${redact(hookPath)} --no-pause\n`,
				stderr: "",
				error: undefined,
			});
		}
		const mobileSummary = artifactDir ? readJsonArtifact(join(artifactDir, "mobile-archive-summary.json")) : null;
		const mobileVerifierPath = writeMobileArchiveVerifier(artifactDir);
		if (mobileVerifierPath) {
			rows.push({
				id: "mobile-archive-verifier-artifact",
				command: "internal",
				args: [redact(mobileVerifierPath)],
				cwd: root,
				exit: 0,
				signal: null,
				durationMs: 0,
				stdout: `verifier=${redact(mobileVerifierPath)}\nrun=python3 ${redact(mobileVerifierPath)} ${redact(target)} ${redact(join(artifactDir, "mobile-archive-summary.json"))} ${redact(join(artifactDir, "mobile-archive-verification.json"))}\n`,
				stderr: "",
				error: undefined,
			});
		}
		const mobileVerification = mobileSummary ? writeMobileArchiveVerification(artifactDir, target, mobileSummary) : undefined;
		if (mobileVerification) {
			rows.push({
				id: "mobile-archive-verification",
				command: "internal",
				args: [redact(mobileVerification.path)],
				cwd: root,
				exit: mobileVerification.summary.proofReady ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(mobileVerification.summary, null, 2)}\n`,
				stderr: "",
				error: mobileVerification.summary.proofReady ? undefined : "mobile archive verification blockers present",
			});
			if (!noWrite && artifactDir && mobileSummary) {
				const attackSurface = mobileAttackSurfaceClaims(mobileSummary, mobileVerification.summary);
				writePrivate(join(artifactDir, "mobile-attack-surface-claims.json"), `${JSON.stringify(attackSurface, null, 2)}\n`, 0o600);
			}
		}
	}
	if (targetInfo.lane === "pcap-dfir" && commandExists("tshark")) {
		rows.push(...pcapQuicklookRows(target, artifactDir, pcapDfirRuntime()));
		rows.push(run("tshark", ["-r", target, "-q", "-z", "io,phs"], { id: "pcap-protocol-hierarchy", timeout: timeoutMs }));
		rows.push(run("tshark", ["-r", target, "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol", "-e", "_ws.col.Info", "-c", "80"], { id: "pcap-flow-head", timeout: timeoutMs }));
	} else if (targetInfo.lane === "pcap-dfir") {
		rows.push(...pcapQuicklookRows(target, artifactDir, pcapDfirRuntime()));
	}
	if (targetInfo.lane === "memory-forensics") {
		rows.push(...memoryQuicklookRows(target, artifactDir));
		if (deep && commandExists("vol")) rows.push(run("vol", ["-f", target, "windows.info"], { id: "memory-vol-windows-info", timeout: 60_000 }));
		else if (deep && commandExists("volatility3")) rows.push(run("volatility3", ["-f", target, "windows.info"], { id: "memory-vol-windows-info", timeout: 60_000 }));
		if (commandExists("strings")) rows.push(run("bash", ["-lc", `strings -a -n 8 ${shellQuote(target)} | grep -Ei 'process|cmdline|password|token|lsass|http|user' | head -180`], { id: "memory-artifact-strings", timeout: timeoutMs }));
	}
	if (targetInfo.lane === "windows-ad") {
		rows.push(...windowsAdRows(target, artifactDir, windowsAdRuntime()));
		if (commandExists("strings")) rows.push(run("bash", ["-lc", `strings -a -n 5 ${shellQuote(target)} | grep -Ei 'krbtgt|ntds|dcsync|kerberoast|as-rep|spn|ldap|adcs|certipy|bloodhound|sharphound|mimikatz|eventid|4769|4624|4672' | head -220`], { id: "windows-ad-signal-strings", timeout: timeoutMs }));
	}
	if (targetInfo.lane === "malware") {
		rows.push(...malwareRows(target, artifactDir, malwareRuntime()));
		if (commandExists("strings")) rows.push(run("bash", ["-lc", `strings -a -n 5 ${shellQuote(target)} | grep -Ei 'https?://|CreateRemoteThread|VirtualAlloc|WriteProcessMemory|CurrentVersion\\\\Run|schtasks|mutex|User-Agent|UPX|IsDebuggerPresent|capa|FLOSS|YARA|ATT&CK|C2|beacon' | head -240`], { id: "malware-signal-strings", timeout: timeoutMs }));
	}
	if (targetInfo.lane === "firmware-iot") {
		rows.push(...firmwareQuicklookRows(target, artifactDir));
		if (deep && commandExists("binwalk")) rows.push(run("binwalk", [target], { id: "firmware-binwalk", timeout: timeoutMs }));
		if (deep && commandExists("unblob")) rows.push(run("unblob", ["--help"], { id: "firmware-unblob-present", timeout: 5000 }));
	}
	if (targetInfo.lane === "crypto-stego") {
		if (dataLooksLikeCryptoStegoMedia(target)) rows.push(...cryptoStegoMediaQuicklookRows(target, artifactDir));
		if (commandExists("xxd")) rows.push(run("xxd", ["-l", "512", target], { id: "crypto-stego-header-hex", timeout: timeoutMs }));
		if (commandExists("exiftool")) rows.push(run("exiftool", [target], { id: "crypto-stego-metadata", timeout: timeoutMs }));
		if (commandExists("binwalk")) rows.push(run("binwalk", [target], { id: "crypto-stego-binwalk", timeout: timeoutMs }));
		if (commandExists("pngcheck") && /\.png$/i.test(target)) rows.push(run("pngcheck", ["-vtp7", target], { id: "crypto-stego-pngcheck", timeout: timeoutMs }));
		if (commandExists("zsteg") && /\.(png|bmp)$/i.test(target)) rows.push(run("zsteg", ["-a", target], { id: "crypto-stego-zsteg", timeout: deep ? 60_000 : timeoutMs }));
		if (commandExists("strings")) {
			rows.push(
				run("bash", ["-lc", `strings -a -n 4 ${shellQuote(target)} | grep -Ei 'flag|ctf|key|password|salt|iv|nonce|base64|BEGIN|PK|crypto|xor|cipher' | head -200`], {
					id: "crypto-stego-signal-strings",
					timeout: timeoutMs,
				}),
			);
		}
		const solverPath = writeCryptoStegoSolver(artifactDir, target);
		if (solverPath) {
			rows.push({
				id: "crypto-stego-solver-artifact",
				command: "internal",
				args: [redact(solverPath)],
				cwd: root,
				exit: 0,
				signal: null,
				durationMs: 0,
				stdout: `solver=${redact(solverPath)}\nrun=python3 ${redact(solverPath)} ${redact(target)}\n`,
				stderr: "",
				error: undefined,
			});
		}
		const verifierPath = writeCryptoStegoVerifier(artifactDir);
		if (verifierPath) {
			rows.push({
				id: "crypto-stego-verifier-artifact",
				command: "internal",
				args: [redact(verifierPath)],
				cwd: root,
				exit: 0,
				signal: null,
				durationMs: 0,
				stdout: `verifier=${redact(verifierPath)}\nrun=python3 ${redact(verifierPath)} ${redact(target)} ${redact(join(artifactDir, "crypto-stego-media-quicklook.json"))} ${redact(join(artifactDir, "crypto-stego-verification.json"))}\n`,
				stderr: "",
				error: undefined,
			});
		}
		const stegoVerification = writeCryptoStegoVerification(artifactDir, target);
		if (stegoVerification) {
			rows.push({
				id: "crypto-stego-verification",
				command: "internal",
				args: [redact(stegoVerification.path)],
				cwd: root,
				exit: stegoVerification.summary.proofReady ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(stegoVerification.summary, null, 2)}\n`,
				stderr: "",
				error: stegoVerification.summary.proofReady ? undefined : "crypto/stego verification blockers present",
			});
		}
		const transformClaims = writeCryptoStegoTransformClaims(artifactDir, target, stegoVerification?.summary);
		if (transformClaims) {
			rows.push({
				id: "crypto-stego-transform-claims",
				command: "internal",
				args: [redact(transformClaims.path)],
				cwd: root,
				exit: transformClaims.summary.proofReady ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(transformClaims.summary, null, 2)}\n`,
				stderr: "",
				error: transformClaims.summary.proofReady ? undefined : "no crypto/stego transform claims promoted",
			});
		}
	}
	return rows;
}

function engageDirectory(targetInfo, artifactDir) {
	const target = targetInfo.path;
	const rows = [];
	configureWorkspaceSourceRuntime(workspaceSourceRuntime());
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
	const workspaceHarnessPath = writeWorkspaceSourceRuntimeHarness(artifactDir);
	if (workspaceHarnessPath) {
		const outputPath = join(artifactDir, "workspace-source-runtime-map.json");
		rows.push(run(process.execPath, [workspaceHarnessPath, target, outputPath], { id: "workspace-source-runtime-map", timeout: timeoutMs + 5000 }));
	}
	const routeReplayArtifacts = writeWorkspaceRouteReplayHarness(artifactDir);
	if (routeReplayArtifacts) {
		rows.push({
			id: "workspace-route-replay-harness-artifact",
			command: "internal",
			args: [redact(routeReplayArtifacts.planPath), redact(routeReplayArtifacts.harnessPath)],
			cwd: root,
			exit: 0,
			signal: null,
			durationMs: 0,
			stdout: `plan=${redact(routeReplayArtifacts.planPath)}\nharness=${redact(routeReplayArtifacts.harnessPath)}\nclaims=${redact(routeReplayArtifacts.claimPromotionPath)}\nrepairQueue=${redact(routeReplayArtifacts.repairQueuePath)}\nrun=REPI_WORKSPACE_BASE_URL=http://127.0.0.1:PORT node ${redact(routeReplayArtifacts.harnessPath)} ${redact(routeReplayArtifacts.outputPath)} --live\n`,
			stderr: "",
			error: undefined,
		});
		const replayPlanRun = run(process.execPath, [routeReplayArtifacts.harnessPath, routeReplayArtifacts.outputPath], { id: "workspace-route-replay-plan", timeout: timeoutMs + 3000 });
		rows.push(replayPlanRun);
		if (!existsSync(routeReplayArtifacts.outputPath) && replayPlanRun.stdout.trim()) writePrivate(routeReplayArtifacts.outputPath, replayPlanRun.stdout, 0o600);
	}
	const workspaceClaims = writeWorkspaceSourceRuntimeClaims(artifactDir, target);
	if (workspaceClaims) {
		rows.push({
			id: "workspace-source-runtime-claims",
			command: "internal",
			args: [redact(workspaceClaims.path)],
			cwd: root,
			exit: workspaceClaims.summary.proofReady ? 0 : 1,
			signal: null,
			durationMs: 0,
			stdout: `${JSON.stringify(
				{
					kind: workspaceClaims.summary.kind,
					proofReady: workspaceClaims.summary.proofReady,
					runtimeProofReady: workspaceClaims.summary.runtimeProofReady,
					exploitProofReady: workspaceClaims.summary.exploitProofReady,
					claimLedger: workspaceClaims.summary.claimLedger.map((claim) => ({ id: claim.id, claimType: claim.claimType, verdict: claim.verdict, blockers: claim.blockers })),
					composedPaths: workspaceClaims.summary.composedPaths.map((claim) => ({ id: claim.id, claimType: claim.claimType, verdict: claim.verdict })),
					repairQueue: workspaceClaims.summary.repairQueue.map((row) => ({ id: row.id, blocker: row.blocker, route: row.route })),
				},
				null,
				2,
			)}\n`,
			stderr: "",
			error: workspaceClaims.summary.proofReady ? undefined : "no workspace source-runtime claims promoted",
		});
	}
	if (!noWrite && artifactDir) {
		const verifierPath = writeWorkspaceSourceRuntimeVerifier(artifactDir);
		if (verifierPath) {
			rows.push({
				id: "workspace-source-runtime-verifier-artifact",
				command: "internal",
				args: [redact(verifierPath)],
				cwd: root,
				exit: 0,
				signal: null,
				durationMs: 0,
				stdout: `verifier=${redact(verifierPath)}\nrun=node ${redact(verifierPath)} ${redact(target)} ${redact(join(artifactDir, "workspace-source-runtime-map.json"))} ${redact(join(artifactDir, "workspace-route-replay-plan.json"))} ${redact(join(artifactDir, "workspace-route-claim-promotion.json"))} ${redact(join(artifactDir, "workspace-route-repair-queue.json"))} ${redact(join(artifactDir, "workspace-source-runtime-claims.json"))} ${redact(join(artifactDir, "workspace-source-runtime-verification.json"))}\n`,
				stderr: "",
				error: undefined,
			});
		}
		const verification = writeWorkspaceSourceRuntimeVerification(artifactDir, target, workspaceClaims?.summary);
		if (verification) {
			rows.push({
				id: "workspace-source-runtime-verification",
				command: "internal",
				args: [redact(verification.path)],
				cwd: root,
				exit: verification.summary.proofReady ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(
					{
						kind: verification.summary.kind,
						proofReady: verification.summary.proofReady,
						runtimeProofReady: verification.summary.runtimeProofReady,
						exploitProofReady: verification.summary.exploitProofReady,
						stats: verification.summary.stats,
						claimLedger: verification.summary.claimLedger.map((claim) => ({ id: claim.id, claimType: claim.claimType, verdict: claim.verdict, blockers: claim.blockers })),
						composedPaths: verification.summary.composedPaths.map((claim) => ({ id: claim.id, claimType: claim.claimType, verdict: claim.verdict, blockers: claim.blockers })),
						repairQueue: verification.summary.repairQueue.map((row) => ({ id: row.id, blocker: row.blocker })),
					},
					null,
					2,
				)}\n`,
				stderr: "",
				error: verification.summary.proofReady ? undefined : "workspace source-runtime verification blockers present",
			});
		}
	}
	if (targetInfo.lane === "agent-boundary") {
		rows.push(...agentBoundaryRows(target, artifactDir, agentBoundaryRuntime()));
	}
	if (targetInfo.lane === "cloud-identity") {
		rows.push(...cloudIdentityRows(target, artifactDir, cloudIdentityRuntime()));
	}
	if (targetInfo.lane === "windows-ad") {
		rows.push(...windowsAdRows(target, artifactDir, windowsAdRuntime()));
	}
	if (targetInfo.lane === "malware") {
		rows.push(...malwareRows(target, artifactDir, malwareRuntime()));
	}
	if (targetInfo.representativePath && existsSync(targetInfo.representativePath)) {
		const representativeArtifactDir = ["agent-boundary", "cloud-identity", "windows-ad", "malware"].includes(targetInfo.lane) && artifactDir ? join(artifactDir, "representative") : artifactDir;
		const representativeRows = engageFile(fileTarget(targetInfo.representativePath, targetInfo.lane, targetInfo.domain, `representative artifact for ${targetInfo.reason}`), representativeArtifactDir);
		rows.push(...representativeRows.map((row) => ({ ...row, id: `representative-${row.id}` })));
	}
	return rows;
}

const fullSpectrumSwarmRoutes = [
	"native-pwn",
	"web-api",
	"js-reverse",
	"mobile",
	"pcap-dfir",
	"memory-forensics",
	"firmware-iot",
	"cloud-identity",
	"windows-ad",
	"malware",
	"crypto-stego",
	"agent-boundary",
];

function wantsFullSpectrumRoutes(targetInfo) {
	const text = `${targetInfo.target ?? ""} ${targetInfo.domain ?? ""} ${targetInfo.reason ?? ""}`;
	return (
		((deep || /(?:full[- ]?spectrum|all[- ]?routes|all[- ]?domains|multi[- ]?domain|red[- ]?team|ctf|全域|全部能力|综合|全路线|全能力)/i.test(text)) &&
			["reverse-pentest-general", "workspace", "reverse"].includes(targetInfo.lane)) ||
		/--route\s+all/i.test(text)
	);
}

function swarmRoutesForTargetInfo(targetInfo) {
	if (targetInfo.kind === "url") return ["web-api", "js-reverse"];
	if (wantsFullSpectrumRoutes(targetInfo)) return fullSpectrumSwarmRoutes;
	const laneRoutes = {
		"native-pwn": ["native-pwn"],
		"js-reverse": ["js-reverse"],
		mobile: ["mobile"],
		"mobile-ios": ["mobile"],
		"pcap-dfir": ["pcap-dfir"],
		"memory-forensics": ["memory-forensics"],
		"firmware-iot": ["firmware-iot"],
		"cloud-identity": ["cloud-identity"],
		"windows-ad": ["windows-ad"],
		malware: ["malware"],
		"crypto-stego": ["crypto-stego"],
		"agent-boundary": ["agent-boundary"],
		"reverse-pentest-general": ["reverse-pentest-general"],
	};
	return laneRoutes[targetInfo.lane] ?? [];
}

function swarmRouteArgs(targetInfo) {
	const routes = swarmRoutesForTargetInfo(targetInfo);
	return routes.length ? ["--route", routes.join(",")] : [];
}

function swarmRouteFlagsText(targetInfo) {
	const routes = swarmRoutesForTargetInfo(targetInfo);
	return routes.length ? ` --route ${shellQuote(routes.join(","))}` : "";
}

function nextQueue(targetInfo, artifactDir, toolState) {
	const target = targetInfo.target;
	const q = [];
	const primaryTarget = targetInfo.representativePath || target;
	const quotedTarget = shellQuote(primaryTarget);
	q.push(`repi mission status`);
	q.push(`repi -p ${shellQuote(`Use engagement artifact ${artifactDir}. Continue ${targetInfo.domain}: parse decisive anchors, choose one minimal proof path, execute it, then output Outcome → Key Evidence → Verification → Next Step.`)}`);
	if (!noWrite && existsSync(join(artifactDir, "proof-harness.mjs"))) {
		q.push(`node ${shellQuote(join(artifactDir, "proof-harness.mjs"))} --self-test`);
		q.push(`node ${shellQuote(join(artifactDir, "proof-harness.mjs"))} --execute`);
	}
	if (!noWrite && existsSync(join(artifactDir, "repi-proof-graph.json"))) {
		q.push(`cat ${shellQuote(join(artifactDir, "repi-proof-graph.json"))}`);
		q.push(`repi -p ${shellQuote(`Use ${artifactDir}/repi-proof-graph.json graph.nodes/edges plus runtimeRepairLoop.queue to pick the highest-priority blocker, run its rerunCommand, and promote only paths with source binding, response/artifact hash, and a negative-control/verifier oracle.`)}`);
	}
	if (!noWrite && existsSync(join(artifactDir, "repi-runtime-repair-loop.mjs"))) {
		q.push(`node ${shellQuote(join(artifactDir, "repi-runtime-repair-loop.mjs"))} --plan`);
		q.push(`node ${shellQuote(join(artifactDir, "repi-runtime-repair-loop.mjs"))} --execute --max 1`);
	}
	if (targetInfo.kind === "url") {
		if (!noWrite && existsSync(join(artifactDir, "web-exploit-claims.json"))) q.push(`cat ${shellQuote(join(artifactDir, "web-exploit-claims.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "web-exploit-verification.json"))) q.push(`cat ${shellQuote(join(artifactDir, "web-exploit-verification.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "web-exploit-verifier.mjs"))) q.push(`node ${shellQuote(join(artifactDir, "web-exploit-verifier.mjs"))} ${shellQuote(artifactDir)} ${shellQuote(join(artifactDir, "web-exploit-verification.json"))}`);
		q.push(`repi -p ${shellQuote(`For ${target}, use ${artifactDir}/web-exploit-claims.json and web-exploit-verification.json claimLedger/composedPaths/repairQueue plus verifier hash proofs/negative controls; bind web-security-posture.json, web-discovery-matrix.json, web-api-schema-probes.json, web-ssrf-matrix.json, web-redirect-matrix.json, web-cors-matrix.json, web-object-matrix.json, web-replay-matrix.json, web-identity-jwt.json, web-js-sourcemap-summary.json, web-runtime-capture-plan.json/web-runtime-capture-harness.mjs, web-runtime-replay-plan.json/web-runtime-replay-verifier.mjs, web-signer-rebuild-workbench-plan.json/web-signer-rebuild-workbench.mjs, and web-js-signature-control-plan.json/web-js-signature-control-harness.mjs; rerun web-exploit-verifier.mjs to prove artifact SHA-256, replay responseSha256, risk-matrix coverage, composed-path segment resolution, and runtime proof gates before promoting IDOR/BOLA/object ownership/signature proof.`)}`);
		q.push(`repi swarm plan ${quotedTarget} --workers ${argValue("--workers") || "5"}${swarmRouteFlagsText(targetInfo)}`);
	} else if (swarmRoutesForTargetInfo(targetInfo).length > 1) {
		q.push(`repi swarm plan ${quotedTarget} --workers ${argValue("--workers") || String(swarmRoutesForTargetInfo(targetInfo).length)}${swarmRouteFlagsText(targetInfo)}`);
	}
	if (targetInfo.lane === "native-pwn") {
		if (toolState.some((row) => row.tool === "r2" && row.available)) q.push(`r2 -A ${quotedTarget}`);
		if (toolState.some((row) => row.tool === "gdb" && row.available)) q.push(`gdb -q ${quotedTarget}`);
		if (!noWrite && dataLooksLikeElf(primaryTarget)) q.push(`cat ${shellQuote(join(artifactDir, "native-elf-hardening.json"))}`);
		if (!noWrite && dataLooksLikePe(primaryTarget)) q.push(`cat ${shellQuote(join(artifactDir, "native-pe-quicklook.json"))}`);
		if (!noWrite && dataLooksLikeMachO(primaryTarget)) q.push(`cat ${shellQuote(join(artifactDir, "native-macho-quicklook.json"))}`);
		if (!noWrite) q.push(`cat ${shellQuote(join(artifactDir, "native-static-triage.json"))}`);
		if (!noWrite) q.push(`cat ${shellQuote(join(artifactDir, "native-exploit-hypotheses.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "native-runtime-verification.json"))) q.push(`cat ${shellQuote(join(artifactDir, "native-runtime-verification.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "native-primitive-claims.json"))) q.push(`cat ${shellQuote(join(artifactDir, "native-primitive-claims.json"))}`);
		if (!noWrite) q.push(`python3 ${shellQuote(join(artifactDir, "native-replay-verifier.py"))} ${quotedTarget}`);
		if (!noWrite && existsSync(join(artifactDir, "native-runtime-verifier.py"))) q.push(`python3 ${shellQuote(join(artifactDir, "native-runtime-verifier.py"))} ${quotedTarget} ${shellQuote(artifactDir)} ${shellQuote(join(artifactDir, "native-runtime-verification.json"))}`);
		if (!noWrite && toolState.some((row) => row.tool === "gdb" && row.available)) q.push(`gdb -q -x ${shellQuote(join(artifactDir, "native-gdb-trace.gdb"))} ${quotedTarget}`);
		if (!noWrite) q.push(`python3 ${shellQuote(join(artifactDir, "native-cyclic-offset.py"))} hex:<register-or-stack-bytes>`);
		q.push(`repi -p ${shellQuote(`Continue native/pwn from ${artifactDir}: use native-runtime-verification.json plus native-primitive-claims.json claimLedger/composedPaths/repairQueue, native-exploit-hypotheses.json, native-elf-hardening.json dynamic.imports/relocations, native-pe-quicklook.json/native-macho-quicklook.json, and native-static-triage.json gadgetQuicklook to prioritize mitigations/imports/PLT-GOT/load-commands/symbols/sinks/ROP primitives; rerun native-runtime-verifier.py and native-replay-verifier.py to compare stdin/argv/env I/O contract cases plus format/short/cyclic controls, bind deterministic crash differentials and negative controls, locate compare/decode/crash primitive, then generate debugger/r2 trace and exact offset proof.`)}`);
	}
	if (targetInfo.lane === "js-reverse") {
		if (!noWrite && existsSync(join(artifactDir, "js-reverse-workbench.json"))) q.push(`cat ${shellQuote(join(artifactDir, "js-reverse-workbench.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "js-reverse-workbench.mjs"))) q.push(`node ${shellQuote(join(artifactDir, "js-reverse-workbench.mjs"))} ${quotedTarget} ${shellQuote(join(artifactDir, "js-reverse-workbench.json"))}`);
		q.push(`repi -p ${shellQuote(`Continue JS/WASM reverse from ${artifactDir}: trace signing/crypto/fetch initiators, rebuild the minimal function in Node, and verify with a replay diff.`)}`);
	}
	if (targetInfo.lane === "mobile" || targetInfo.lane === "mobile-ios") {
		if (!noWrite && dataLooksLikeZip(primaryTarget)) q.push(`cat ${shellQuote(join(artifactDir, "mobile-archive-summary.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "mobile-archive-verification.json"))) q.push(`cat ${shellQuote(join(artifactDir, "mobile-archive-verification.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "mobile-attack-surface-claims.json"))) q.push(`cat ${shellQuote(join(artifactDir, "mobile-attack-surface-claims.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "mobile-archive-verifier.py"))) q.push(`python3 ${shellQuote(join(artifactDir, "mobile-archive-verifier.py"))} ${quotedTarget} ${shellQuote(join(artifactDir, "mobile-archive-summary.json"))} ${shellQuote(join(artifactDir, "mobile-archive-verification.json"))}`);
		if (!noWrite) q.push(`frida -U -f <package-or-bundle-id> -l ${shellQuote(join(artifactDir, "mobile-frida-hooks.js"))} --no-pause`);
		q.push(`repi -p ${shellQuote(`Continue mobile reverse from ${artifactDir}: use mobile-archive-verification.json plus mobile-archive-summary.json manifestAnalysis/iosPlistAnalysis/iosEntitlements/dexQuicklook and mobile-attack-surface-claims.json claimLedger/hookTargets/repairQueue to map manifest/plist exported entrypoints, permissions, URL schemes, ATS/entitlements, DEX endpoints/classes, native libs, crypto/pinning/root checks; rerun mobile-archive-verifier.py for archive hash, ZIP entry/Dex/manifest/hook and negative-control proof, then adapt mobile-frida-hooks.js and replay the network/deeplink path.`)}`);
	}
	if (targetInfo.lane === "memory-forensics") {
		if (!noWrite) q.push(`cat ${shellQuote(join(artifactDir, "memory-quicklook.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "memory-evidence-verification.json"))) q.push(`cat ${shellQuote(join(artifactDir, "memory-evidence-verification.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "memory-evidence-claims.json"))) q.push(`cat ${shellQuote(join(artifactDir, "memory-evidence-claims.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "memory-evidence-verifier.py"))) q.push(`python3 ${shellQuote(join(artifactDir, "memory-evidence-verifier.py"))} ${quotedTarget} ${shellQuote(join(artifactDir, "memory-quicklook.json"))} ${shellQuote(join(artifactDir, "memory-evidence-verification.json"))}`);
		if (!noWrite) q.push(`bash ${shellQuote(join(artifactDir, "memory-triage-plan.sh"))} ${quotedTarget}`);
		q.push(`repi -p ${shellQuote(`Continue memory forensics from ${artifactDir}: use memory-quicklook.json correlations plus memory-evidence-verification.json and memory-evidence-claims.json claimLedger/composedPaths/repairQueue to identify profile, rank process/cmdline/network/credential artifacts, rerun memory-evidence-verifier.py for offset/hash/correlation/negative-control proof, carve IOC evidence, and produce timeline verification.`)}`);
	}
	if (targetInfo.lane === "windows-ad") {
		if (!noWrite) q.push(`cat ${shellQuote(join(artifactDir, "windows-ad-quicklook.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "windows-ad-verification.json"))) q.push(`cat ${shellQuote(join(artifactDir, "windows-ad-verification.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "windows-ad-attack-paths.json"))) q.push(`cat ${shellQuote(join(artifactDir, "windows-ad-attack-paths.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "windows-ad-verifier.py"))) q.push(`python3 ${shellQuote(join(artifactDir, "windows-ad-verifier.py"))} ${quotedTarget} ${shellQuote(join(artifactDir, "windows-ad-quicklook.json"))} ${shellQuote(join(artifactDir, "windows-ad-attack-paths.json"))} ${shellQuote(join(artifactDir, "windows-ad-verification.json"))}`);
		if (!noWrite) q.push(`bash ${shellQuote(join(artifactDir, "windows-ad-triage-plan.sh"))} ${quotedTarget}`);
		q.push(`repi -p ${shellQuote(`Continue Windows/AD identity work from ${artifactDir}: use windows-ad-verification.json, windows-ad-quicklook.json, and windows-ad-attack-paths.json claimLedger/composedPaths/repairQueue to bind credential/Kerberos/logon/ADCS evidence to BloodHound owned principals and high-value targets with exact edge chains; rerun windows-ad-verifier.py for artifact hash equality, BloodHound edge-chain verification, composed segment resolution, and negative controls, then verify one credential usability, ADCS, DCSync, or high-value graph path.`)}`);
	}
	if (targetInfo.lane === "malware") {
		if (!noWrite) q.push(`cat ${shellQuote(join(artifactDir, "malware-quicklook.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "malware-config-verification.json"))) q.push(`cat ${shellQuote(join(artifactDir, "malware-config-verification.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "malware-behavior-claims.json"))) q.push(`cat ${shellQuote(join(artifactDir, "malware-behavior-claims.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "malware-config-verifier.py"))) q.push(`python3 ${shellQuote(join(artifactDir, "malware-config-verifier.py"))} ${quotedTarget} ${shellQuote(join(artifactDir, "malware-quicklook.json"))} ${shellQuote(join(artifactDir, "malware-config-verification.json"))}`);
		if (!noWrite) q.push(`bash ${shellQuote(join(artifactDir, "malware-triage-plan.sh"))} ${quotedTarget}`);
		q.push(`repi -p ${shellQuote(`Continue malware analysis from ${artifactDir}: normalize IOCs from malware-quicklook.json plus malware-config-verification.json and malware-behavior-claims.json claimLedger/configFields/composedPaths/repairQueue, use staticStructure sections/imports/overlay to prioritize packer and injection leads, rerun malware-config-verifier.py for offset/hash/negative-control proof, verify capa/FLOSS/YARA or behavior anchors, and produce one corroborated capability/config proof.`)}`);
	}
	if (targetInfo.lane === "pcap-dfir") {
		if (!noWrite) q.push(`cat ${shellQuote(join(artifactDir, "pcap-flow-summary.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "pcap-flow-verification.json"))) q.push(`cat ${shellQuote(join(artifactDir, "pcap-flow-verification.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "pcap-flow-claims.json"))) q.push(`cat ${shellQuote(join(artifactDir, "pcap-flow-claims.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "pcap-flow-verifier.mjs"))) q.push(`node ${shellQuote(join(artifactDir, "pcap-flow-verifier.mjs"))} ${quotedTarget} ${shellQuote(join(artifactDir, "pcap-flow-summary.json"))} ${shellQuote(join(artifactDir, "pcap-flow-verification.json"))} ${shellQuote(join(artifactDir, "pcap-http-objects.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "pcap-http-objects.json"))) q.push(`python3 ${shellQuote(join(artifactDir, "pcap-http-object-verifier.py"))} ${shellQuote(join(artifactDir, "pcap-http-objects.json"))}`);
		q.push(`repi -p ${shellQuote(`Continue PCAP/DFIR from ${artifactDir}: use pcap-flow-summary.json flows/tcpStreams plus pcap-flow-verification.json and pcap-flow-claims.json claimLedger/composedPaths/repairQueue and pcap-http-objects.json object carves/entry hashes/decodedArtifacts; rerun pcap-flow-verifier.mjs for capture/object/hash/negative-control proof; rank http bodySummary/embeddedArchives, http/dns/tls SNI samples, HTTP credentialSignals/risks, plaintextAuth, DNS answers, dnsTunnels, TLS JA3/SNI, extract objects, decode transform chain, and bind recovered artifacts to packet/frame evidence without leaking raw secrets.`)}`);
	}
	if (targetInfo.lane === "firmware-iot") {
		if (!noWrite) q.push(`cat ${shellQuote(join(artifactDir, "firmware-quicklook.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "firmware-extraction-verification.json"))) q.push(`cat ${shellQuote(join(artifactDir, "firmware-extraction-verification.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "firmware-attack-surface.json"))) q.push(`cat ${shellQuote(join(artifactDir, "firmware-attack-surface.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "firmware-extraction-verifier.py"))) q.push(`python3 ${shellQuote(join(artifactDir, "firmware-extraction-verifier.py"))} ${quotedTarget} ${shellQuote(join(artifactDir, "firmware-quicklook.json"))} ${shellQuote(join(artifactDir, "firmware-extraction-verification.json"))}`);
		if (!noWrite) q.push(`bash ${shellQuote(join(artifactDir, "firmware-extract-plan.sh"))} ${quotedTarget}`);
		q.push(`repi -p ${shellQuote(`Continue firmware/IoT from ${artifactDir}: use firmware-quicklook.json plus firmware-extraction-verification.json and firmware-attack-surface.json claimLedger/extractionTargets/composedPaths/repairQueue to parse TRX/uImage/SquashFS/UBI offsets, rerun firmware-extraction-verifier.py for signature/carve/hash/negative-control proof, extract complete rootfs when available, map services/config/CGI, identify credentials, and build an emulation smoke path.`)}`);
	}
	if (targetInfo.lane === "crypto-stego") {
		if (!noWrite && dataLooksLikeCryptoStegoMedia(primaryTarget)) q.push(`cat ${shellQuote(join(artifactDir, "crypto-stego-media-quicklook.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "crypto-stego-verification.json"))) q.push(`cat ${shellQuote(join(artifactDir, "crypto-stego-verification.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "crypto-stego-transform-claims.json"))) q.push(`cat ${shellQuote(join(artifactDir, "crypto-stego-transform-claims.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "crypto-stego-verifier.py"))) q.push(`python3 ${shellQuote(join(artifactDir, "crypto-stego-verifier.py"))} ${quotedTarget} ${shellQuote(join(artifactDir, "crypto-stego-media-quicklook.json"))} ${shellQuote(join(artifactDir, "crypto-stego-verification.json"))}`);
		if (!noWrite) q.push(`python3 ${shellQuote(join(artifactDir, "crypto-stego-solver.py"))} ${quotedTarget}`);
		q.push(`repi -p ${shellQuote(`Continue crypto/stego from ${artifactDir}: use crypto-stego-verification.json plus crypto-stego-transform-claims.json claimLedger/composedPaths/repairQueue and crypto-stego-media-quicklook.json when present to prioritize PNG/WAV chunks/text/LSB/trailing data; rerun crypto-stego-verifier.py for file hash, deterministic media quicklook, exact offset/carve/audio hashes, and negative controls; then use crypto-stego-solver.py to reconstruct the transform chain and bind the result to artifact offsets/hashes.`)}`);
	}
	if (targetInfo.lane === "agent-boundary") {
		if (!noWrite) q.push(`cat ${shellQuote(join(artifactDir, "agent-boundary-map.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "agent-boundary-verification.json"))) q.push(`cat ${shellQuote(join(artifactDir, "agent-boundary-verification.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "agent-boundary-claim-promotion.json"))) q.push(`cat ${shellQuote(join(artifactDir, "agent-boundary-claim-promotion.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "agent-boundary-repair-queue.json"))) q.push(`cat ${shellQuote(join(artifactDir, "agent-boundary-repair-queue.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "agent-boundary-verifier.py"))) q.push(`python3 ${shellQuote(join(artifactDir, "agent-boundary-verifier.py"))} ${shellQuote(join(artifactDir, "agent-boundary-map.json"))} ${shellQuote(join(artifactDir, "agent-boundary-replay-results.json"))} ${shellQuote(join(artifactDir, "agent-boundary-verification.json"))}`);
		if (!noWrite) q.push(`python3 ${shellQuote(join(artifactDir, "agent-boundary-payloads.py"))} <chat-or-agent-endpoint> ${shellQuote(join(artifactDir, "agent-boundary-replay-results.json"))} --execute`);
		q.push(`repi -p ${shellQuote(`Continue agent-boundary pentest from ${artifactDir}: use agent-boundary-verification.json, agent-boundary-map.json boundaryFlows, agent-boundary-claim-promotion.json claimLedger/composedPaths, and agent-boundary-repair-queue.json repairQueue to bind untrusted input to prompts/tools/credentials, replay HTTP payloads from agent-boundary-payloads.py, rerun agent-boundary-verifier.py for source-bound map flow coverage, response hash oracle, and negative controls, then prove one unsafe leak/tool execution or baseline-accepted blocked-control flow with request/response hashes.`)}`);
	}
	if (targetInfo.lane === "cloud-identity") {
		if (!noWrite) q.push(`cat ${shellQuote(join(artifactDir, "cloud-identity-map.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "cloud-identity-verification.json"))) q.push(`cat ${shellQuote(join(artifactDir, "cloud-identity-verification.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "cloud-identity-trust-claims.json"))) q.push(`cat ${shellQuote(join(artifactDir, "cloud-identity-trust-claims.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "cloud-identity-verifier.py"))) q.push(`python3 ${shellQuote(join(artifactDir, "cloud-identity-verifier.py"))} ${quotedTarget} ${shellQuote(join(artifactDir, "cloud-identity-map.json"))} ${shellQuote(join(artifactDir, "cloud-identity-trust-claims.json"))} ${shellQuote(join(artifactDir, "cloud-identity-verification.json"))}`);
		if (!noWrite) q.push(`bash ${shellQuote(join(artifactDir, "cloud-identity-verify.sh"))} ${quotedTarget}`);
		q.push(`repi -p ${shellQuote(`Continue cloud/identity pentest from ${artifactDir}: use cloud-identity-verification.json, cloud-identity-map.json trustChains, and cloud-identity-trust-claims.json claimLedger/composedPaths/repairQueue to bind GitHub OIDC roles, Terraform IAM, Kubernetes service accounts/RBAC, and container principals to deploy truth; rerun cloud-identity-verifier.py for exact source-line hashes, composed segment resolution, and negative controls, then verify privilege boundaries and promote one exact pivot or least-privilege proof.`)}`);
	}
	if (targetInfo.kind === "directory") {
		const quotedDirectoryTarget = shellQuote(target);
		if (!noWrite && existsSync(join(artifactDir, "workspace-source-runtime-map.json"))) q.push(`cat ${shellQuote(join(artifactDir, "workspace-source-runtime-map.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "workspace-source-runtime-harness.mjs"))) q.push(`node ${shellQuote(join(artifactDir, "workspace-source-runtime-harness.mjs"))} ${quotedDirectoryTarget} ${shellQuote(join(artifactDir, "workspace-source-runtime-map.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "workspace-source-runtime-verification.json"))) q.push(`cat ${shellQuote(join(artifactDir, "workspace-source-runtime-verification.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "workspace-source-runtime-verifier.mjs"))) q.push(`node ${shellQuote(join(artifactDir, "workspace-source-runtime-verifier.mjs"))} ${quotedDirectoryTarget} ${shellQuote(join(artifactDir, "workspace-source-runtime-map.json"))} ${shellQuote(join(artifactDir, "workspace-route-replay-plan.json"))} ${shellQuote(join(artifactDir, "workspace-route-claim-promotion.json"))} ${shellQuote(join(artifactDir, "workspace-route-repair-queue.json"))} ${shellQuote(join(artifactDir, "workspace-source-runtime-claims.json"))} ${shellQuote(join(artifactDir, "workspace-source-runtime-verification.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "workspace-route-claim-promotion.json"))) q.push(`cat ${shellQuote(join(artifactDir, "workspace-route-claim-promotion.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "workspace-route-repair-queue.json"))) q.push(`cat ${shellQuote(join(artifactDir, "workspace-route-repair-queue.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "workspace-source-runtime-claims.json"))) q.push(`cat ${shellQuote(join(artifactDir, "workspace-source-runtime-claims.json"))}`);
		if (!noWrite && existsSync(join(artifactDir, "workspace-route-replay-harness.mjs"))) q.push(`REPI_WORKSPACE_BASE_URL=http://127.0.0.1:PORT node ${shellQuote(join(artifactDir, "workspace-route-replay-harness.mjs"))} ${shellQuote(join(artifactDir, "workspace-route-replay-results.json"))} --live`);
		q.push(`repi -p ${shellQuote(`Use ${artifactDir}/commands.jsonl plus workspace-source-runtime-verification.json, workspace-source-runtime-claims.json, workspace-route-claim-promotion.json, and workspace-route-repair-queue.json to continue workspace exploitation: rerun workspace-source-runtime-verifier.mjs to prove exact source file/line bindings, route replay templates, proof gates, and repairQueue blockers; drain claimLedger/composedPaths/repairQueue blockers, bind routes/sinks to runtime proof, and promote only source-bound replay differentials.`)}`);
	}
	if (swarm) {
		const provider = argValue("--provider") || DEFAULT_SWARM_PROVIDER;
		const model = argValue("--model") || DEFAULT_SWARM_MODEL;
		q.push(`repi swarm run ${quotedTarget} --workers ${argValue("--workers") || "5"}${swarmRouteFlagsText(targetInfo)}${provider ? ` --provider ${shellQuote(provider)}` : ""}${model ? ` --model ${shellQuote(model)}` : ""} --prompt ${shellQuote(`Use engagement artifact ${artifactDir}; each worker must return structured evidence, commands, blockers, and next exploit/reverse step.`)}`);
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
		const text = `${row.stdout}\n${row.stderr}`.slice(0, row.id === "pcap-quicklook" ? 50_000 : 6000);
		if (/ELF|PE32|Mach-O|executable|shared object/i.test(text)) anchors.push("native binary fingerprint");
		if (/repi-proof-harness|proof-harness|proofReady|artifactRows|liveRows|coverageGaps/i.test(text)) anchors.push("proof harness/self-test anchors");
		if (/repi-unified-proof-graph|repi-proof-graph|repi-runtime-repair-loop|runtimeRepairLoop|selectedRepairs|graph\.nodes|graph\.edges|composedPaths|repairQueue/i.test(text)) anchors.push("unified proof graph anchors");
		if (/GNU_STACK|RELRO|NX|Canary|PIE/i.test(text)) anchors.push("mitigation anchors");
		if (/repi-native-elf-hardening|stackExecutable|native-elf-hardening|no-gnu-relro|executable-stack/i.test(text)) anchors.push("native hardening anchors");
		if (/elf-(?:unsafe-import|command-exec-import|dynamic-loader|plt-relocation|lazy-binding)|R_X86_64_JUMP_SLOT|dynamic.*imports|symtab|JUMP_SLOT/i.test(text)) anchors.push("native ELF import/relocation anchors");
		if (/repi-native-pe-quicklook|native-pe-quicklook|dllCharacteristics|suspicious-import-surface|VirtualAlloc|CreateRemoteThread|no-control-flow-guard/i.test(text)) anchors.push("native PE/import anchors");
		if (/repi-native-macho-quicklook|native-macho-quicklook|LC_SEGMENT_64|LC_CODE_SIGNATURE|LC_MAIN|LC_SYMTAB|rpath-dylib-hijack|Mach-O/i.test(text)) anchors.push("native Mach-O anchors");
		if (/macho-dangerous-symbol|macho-dynamic-loader-symbol|macho-objc-swift|macho-crypto-network|_objc_msgSend|_system|SecTrustEvaluate|NSURLSession/i.test(text)) anchors.push("native Mach-O symbol anchors");
		if (/repi-native-static-triage|native-static-triage|unsafe-input-sink|format-string-signal|command-execution-sink|crypto-codec-transform/i.test(text)) anchors.push("native static sink anchors");
		if (/repi-native-gadget-quicklook|gadgetQuicklook|native-rop-gadget|native-ret2libc|native-syscall-rop|native-stack-pivot|pop rdi; ret|syscall; ret/i.test(text)) anchors.push("native ROP/gadget anchors");
		if (/\[native-exec\].*(mode=empty|mode=cyclic|crash_signal|exit=1[3-9][0-9])/i.test(text)) anchors.push("dynamic execution/crash anchors");
		if (/native-cyclic-offset|native-gdb-trace|gdbScript/i.test(text)) anchors.push("gdb/cyclic offset artifacts");
		if (/repi-native-exploit-hypotheses|native-exploit-hypotheses|ret2libc-system-binsh|cyclic-crash-control-proof|plt-got-resolution-surface|syscall-rop-chain/i.test(text)) anchors.push("native exploit hypothesis anchors");
		if (/repi-native-runtime-verification|native-runtime-verification|native-runtime-verifier|native-replay-case-verification-proof|native-crash-differential-verification-proof|native-runtime-negative-control-proof|native-runtime-exploit-proof-path/i.test(text) && targetInfo.lane === "native-pwn") anchors.push("native runtime verifier anchors");
		if (/repi-native-primitive-claims|native-primitive-claims|native-crash-replay-signal|native-io-contract-harness|native-offset-control-workbench|native-exploit-proof-path|native-ret2libc-surface|native-windows-injection-surface|native-macho-loader-surface|repairQueue/i.test(text) && targetInfo.lane === "native-pwn") anchors.push("native primitive claim anchors");
		if (/HTTP\/|server:|set-cookie|location:/i.test(text)) anchors.push("HTTP/header anchors");
		if (/jwt|token|session|cookie|auth|signature|crypto/i.test(text)) anchors.push("auth/signing anchors");
		if (/repi-web-session-hints|csrf|cookie-session/i.test(text) && targetInfo.kind === "url") anchors.push("session/CSRF anchors");
		if (/repi-web-security-posture|web-security-posture|session-cookie-missing|content-security-policy|clickjacking-header|missing-x-content-type/i.test(text) && targetInfo.kind === "url") anchors.push("web security header/cookie anchors");
		if (/repi-web-identity-jwt|web-identity-jwt|openid-configuration|jwks|jwt-alg|jwt-kid|jwt-remote-key|jwt-embedded-jwk|jwt-x5c|oidc/i.test(text) && targetInfo.kind === "url") anchors.push("JWT/OIDC identity anchors");
		if (/fetch|XMLHttpRequest|WebSocket|WebAssembly|signature|crypto\.subtle/i.test(text) && (targetInfo.lane === "js-reverse" || targetInfo.kind === "url")) anchors.push("JS signing/runtime anchors");
		if (/repi-js-reverse-workbench|js-reverse-workbench|js-signature-rebuild-candidate|js-crypto-transform-candidate|rebuildChecklist/i.test(text) && targetInfo.lane === "js-reverse") anchors.push("JS reverse workbench anchors");
		if (/repi-web-js-sourcemap-summary|web-js-asset-\d+-sourcemap-scan|sourcesWithContent|sourceMapUrl/i.test(text) && targetInfo.kind === "url") anchors.push("JS sourcemap reverse anchors");
		if (/repi-web-runtime-capture|web-runtime-capture|fetch-call|xhr-open|websocket-open|crypto-subtle-|browser-request/i.test(text) && targetInfo.kind === "url") anchors.push("browser runtime capture anchors");
		if (/repi-web-runtime-replay|web-runtime-replay|captured-signed|missing-signature|tampered-signature|stale-timestamp|signer_proven_negative_controls/i.test(text) && targetInfo.kind === "url") anchors.push("browser runtime replay verifier anchors");
		if (/repi-web-signer-rebuild-workbench|web-signer-rebuild|assertByteForByte|canonicalUnsigned|byteForByteRule|regressionGates/i.test(text) && targetInfo.kind === "url") anchors.push("signer rebuild workbench anchors");
		if (/repi-web-js-signature-control|web-js-signature-control|missing-signature|tampered-signature|assertPermutation|policy_gap_not_signer_proof/i.test(text) && targetInfo.kind === "url") anchors.push("JS signature control anchors");
		if (/repi-web-exploit-claims|web-exploit-claims|web-authz-object-proof-path|web-client-signer-proof-path|web-session-auth-differential|web-object-authz-bola-signal|web-ssrf-canary-evidence|claimLedger|repairQueue/i.test(text) && targetInfo.kind === "url") anchors.push("web exploit claim anchors");
		if (/repi-web-exploit-verification|web-exploit-verifier|web-artifact-hash-verification-proof|web-replay-hash-verification-proof|web-risk-matrix-coverage-proof|web-runtime-negative-control-proof|web-composed-path-verification-proof|web-exploit-verifier-negative-control-proof|web-exploit-verification-(?:proof|blocked)-path/i.test(text) && targetInfo.kind === "url") anchors.push("web exploit verifier anchors");
		if (/AndroidManifest|classes\.dex|Info\.plist|Payload\/|CFBundle|Mach-O/i.test(text) && (targetInfo.lane === "mobile" || targetInfo.lane === "mobile-ios")) anchors.push("mobile package anchors");
		if (/repi-mobile-archive-quicklook|mobile-archive-summary|mobile-attack-surface-claims|mobile-frida-hooks|hookTargets|mobile-runtime-pivot|CertificatePinner|TrustManager|network-or-pinning-signal/i.test(text) && (targetInfo.lane === "mobile" || targetInfo.lane === "mobile-ios")) anchors.push("mobile runtime hook anchors");
		if (/repi-mobile-archive-verification|mobile-archive-verification|mobile-archive-verifier|mobile-archive-hash-verification-proof|mobile-zip-entry-verification-proof|mobile-manifest-verification-proof|mobile-runtime-evidence-proof-path|mobile-verifier-negative-control-proof/i.test(text) && (targetInfo.lane === "mobile" || targetInfo.lane === "mobile-ios")) anchors.push("mobile archive verifier anchors");
		if (/manifestAnalysis|android-exported-component|android-debuggable|android-dangerous-permission|usesCleartextTraffic|AndroidManifest|android-exported-component-entrypoint|android-cleartext-traffic/i.test(text) && (targetInfo.lane === "mobile" || targetInfo.lane === "mobile-ios")) anchors.push("mobile manifest attack-surface anchors");
		if (/iosPlistAnalysis|iosEntitlements|ios-ats-|ios-url-scheme|ios-get-task-allow|ios-debug-entitlement|ios-keychain-access-group|CFBundleURLSchemes|LSApplicationQueriesSchemes|keychain-access-groups/i.test(text) && (targetInfo.lane === "mobile" || targetInfo.lane === "mobile-ios")) anchors.push("mobile iOS plist/entitlements anchors");
		if (/dexQuicklook|dex-pinning-signal|dex-crypto-transform-signal|dex-anti-tamper-signal|dex-native-bridge-signal|stringIdsSize/i.test(text) && (targetInfo.lane === "mobile" || targetInfo.lane === "mobile-ios")) anchors.push("mobile DEX quicklook anchors");
		if (/pcap|ethernet|tcp|udp|http|dns|tls|sni/i.test(text) && targetInfo.lane === "pcap-dfir") anchors.push("traffic anchors");
		if (/repi-pcap-quicklook|repi-pcap-flow-claims|pcap-flow-verification|pcap-flow-verifier|pcap-flow-claims|HTTP-candidate|DNS-candidate|TLS-candidate|dnsAnswers|packetCount|claimLedger/i.test(text) && targetInfo.lane === "pcap-dfir") anchors.push("pcap quicklook anchors");
		if (/tcpStreams|TCP-reassembled|HTTP-reassembled|plaintext-auth-reassembled|TLS-reassembled|reassembledBytes|payloadSha256|tcp-sequence|outOfOrder|pcap-tcp-reassembly-proof|pcap-reassembly-hash-verification-proof/i.test(text) && targetInfo.lane === "pcap-dfir") anchors.push("TCP reassembly anchors");
		if (/credentialSignals|pcap-http-credential-flow|pcap-flow-evidence-pivot|pcap-flow-verification-proof-path|pcap-http-(?:authorization-header|basic-auth|bearer-token|cookie-session|set-cookie-session|form-credential|query-token|cleartext-credential-flow)|pcap-credential-signal-verification-proof|authorizationScheme|cookieNames/i.test(text) && targetInfo.lane === "pcap-dfir") anchors.push("PCAP HTTP credential anchors");
		if (/bodySummary|embeddedArchives|pcap-http-objects|pcap-http-object-carve|pcap-http-decoded-artifact|pcap-http-archive-entry|pcap-http-object-verifier|pcap-object-artifact-verification-proof|object carves|pcap-http-(?:object-body|embedded-zip-object|embedded-archive-parsed|executable-object|compressed-object|body-truncated)|contentDisposition/i.test(text) && targetInfo.lane === "pcap-dfir") anchors.push("PCAP HTTP object/body anchors");
		if (/pcap-flow-verification|pcap-flow-verifier|pcap-capture-hash-verification-proof|pcap-quicklook-determinism-proof|pcap-verifier-negative-control-proof|artifact-size-sha256-match/i.test(text) && targetInfo.lane === "pcap-dfir") anchors.push("PCAP verifier proof anchors");
		if (/plaintextAuth|pcap-plaintext-auth|plaintext-auth-field|USER|PASS|LOGIN|AUTH PLAIN/i.test(text) && targetInfo.lane === "pcap-dfir") anchors.push("PCAP plaintext auth anchors");
		if (/dnsTunnels|pcap-dns-tunnel-exfil|pcap-dns-(?:long-label|high-entropy-label|encoded-label|sensitive-label|deep-subdomain)|labelSignals|base32-like-label|base64url-like-label/i.test(text) && targetInfo.lane === "pcap-dfir") anchors.push("DNS tunnel/exfil anchors");
		if (/TLS-candidate|client-hello|recordVersion|clientVersion|sni|alpn|ja3/i.test(text) && targetInfo.lane === "pcap-dfir") anchors.push("TLS/SNI anchors");
		if (/endpoint|graphql|oauth|api\/|\/api|form|fetch|axios/i.test(text) && targetInfo.kind === "url") anchors.push("route/API anchors");
		if (/repi-workspace-source-runtime-map|workspace-source-runtime-map|sourceToRuntimeEdges|route-sensitive-no-nearby-auth-anchor|route-to-dangerous-sink-candidate|routeReplayTemplates/i.test(text) && targetInfo.kind === "directory") anchors.push("workspace source-to-runtime anchors");
		if (/repi-workspace-route-replay|workspace-route-replay|workspace-route-claim-promotion|workspace-route-repair-queue|tampered-object|authDifferential|objectDifferential|promotionReport|claimLedger|repairQueue/i.test(text) && targetInfo.kind === "directory") anchors.push("workspace route replay/authz anchors");
		if (/repi-workspace-source-runtime-claims|workspace-source-runtime-claims|workspace-source-runtime-proof-path|workspace-authz-replay-proof-path|claimLedger|composedPaths|repairQueue/i.test(text) && targetInfo.kind === "directory") anchors.push("workspace source-runtime claim anchors");
		if (/repi-workspace-source-runtime-verification|workspace-source-runtime-verifier|workspace-source-line-verification-proof|workspace-route-template-verification-proof|workspace-replay-gate-verification-proof|workspace-repair-queue-verification-proof|workspace-verifier-negative-control-proof|workspace-source-runtime-verification-(?:proof|blocked)-path/i.test(text) && targetInfo.kind === "directory") anchors.push("workspace source-runtime verifier anchors");
		if (/repi-web-discovery-matrix|web-discovery|robots\.txt|sitemap\.xml|openapi|swagger|graphql/i.test(text) && targetInfo.kind === "url") anchors.push("web discovery anchors");
		if (/repi-web-api-schema-probes|web-api-schema-probes|__typename|__schema|graphql-introspection|graphql-mutation-surface|openapi-unauthenticated|openapi-upload-surface|securitySchemes|openapi|swagger|GraphQL/i.test(text) && targetInfo.kind === "url") anchors.push("API schema anchors");
		if (/repi-web-ssrf-matrix|web-ssrf-matrix|ssrf-|169\.254\.169\.254|repi-ssrf-canary/i.test(text) && targetInfo.kind === "url") anchors.push("SSRF parameter anchors");
		if (/repi-web-redirect-matrix|web-redirect-matrix|open-redirect|external-redirect-location|Location:/i.test(text) && targetInfo.kind === "url") anchors.push("open redirect anchors");
		if (/repi-web-cors-matrix|web-cors-matrix|cors-reflected-origin|access-control-allow-origin|CORS/i.test(text) && targetInfo.kind === "url") anchors.push("CORS policy anchors");
		if (/repi-web-object-matrix|web-object|bolaSignal|path-number|query-number/i.test(text) && targetInfo.kind === "url") anchors.push("object authorization anchors");
		if (/repi-web-replay-matrix|web-replay|responseSha256/i.test(text) && targetInfo.kind === "url") anchors.push("HTTP replay matrix anchors");
		if (/volatility|windows\.info|linux\.banners|process|cmdline|lsass|netscan/i.test(text) && targetInfo.lane === "memory-forensics") anchors.push("memory forensic anchors");
		if (/repi-memory-quicklook|memory-quicklook|memory-evidence-verification|memory-evidence-verifier|memory-evidence-claims|memory-triage-plan|credential-string-signal|network-artifact-signal|suspicious-commandline-signal/i.test(text) && targetInfo.lane === "memory-forensics") anchors.push("memory quicklook anchors");
		if (/process-network-correlation-signal|credential-context-correlation-signal|timeline-correlation-signal|processNetwork|credentialContext|memory-credential-network-pivot|memory-forensic-proof-path|claimLedger/i.test(text) && targetInfo.lane === "memory-forensics") anchors.push("memory correlation anchors");
		if (/memory-evidence-verification|memory-evidence-verifier|memory-signal-offset-verification-proof|memory-process-network-verification-proof|memory-credential-context-verification-proof|memory-verifier-negative-control-proof|memory-signal-offset-hash-match/i.test(text) && targetInfo.lane === "memory-forensics") anchors.push("memory verifier proof anchors");
		if (/repi-windows-ad-quicklook|windows-ad-quicklook|windows-ad-triage|krbtgt|Kerberoast|DCSync|ADCS|Certipy|BloodHound|4769|4624/i.test(text) && targetInfo.lane === "windows-ad") anchors.push("Windows/AD identity anchors");
		if (/bloodhound-graph-data-present|bloodhound-privilege-edge-signal|bloodhound-owned-principal-signal|bloodhound-owned-to-high-value-path|relationCounts|privilegeEdges|highValue|attackPaths|windows-ad-attack-path|windows-ad-credential-graph-pivot|windows-ad-adcs-graph-pivot|claimLedger|composedPaths|repairQueue/i.test(text) && targetInfo.lane === "windows-ad") anchors.push("BloodHound graph anchors");
		if (/repi-windows-ad-verification|windows-ad-verifier|windows-ad-file-hash-verification-proof|windows-ad-bloodhound-path-verification-proof|windows-ad-signal-coverage-verification-proof|windows-ad-composed-path-verification-proof|windows-ad-verifier-negative-control-proof|windows-ad-verification-proof-path/i.test(text) && targetInfo.lane === "windows-ad") anchors.push("Windows/AD verifier anchors");
		if (/repi-malware-quicklook|malware-quicklook|malware-behavior-claims|malware-config-verification|malware-config-verifier|malware-triage|malware-behavior-chain|malware-ioc-config-proof-path|claimLedger|configFields|network-ioc-signal|CreateRemoteThread|VirtualAlloc|FLOSS|YARA|capa|ATT&CK|mutex|User-Agent/i.test(text) && targetInfo.lane === "malware") anchors.push("malware IOC/capability anchors");
		if (/staticStructure|malware-overlay-signal|malware-suspicious-import-signal|suspiciousImports|overlay-data-present|rwx-section-signal|structured-executable-analysis-signal|malware-overlay-carve-target|malware-rwx-section/i.test(text) && targetInfo.lane === "malware") anchors.push("malware static structure anchors");
		if (/malware-config-verification|malware-config-verifier|malware-overlay-carve-verifier-proof|signal-offset-hash-match|negative-control|malware-ioc-config-proof-path/i.test(text) && targetInfo.lane === "malware") anchors.push("malware verifier proof anchors");
		if (/repi-firmware-quicklook|firmware-quicklook|firmware-attack-surface|firmware-extraction-verification|firmware-extraction-verifier|firmware-extract-plan|claimLedger|extractionTargets|management-credential-pivot|firmware-rootfs-carve-proof|SquashFS|UBI|uImage|dropbear|telnetd|cgi-bin|hardcoded-credential-signal/i.test(text) && targetInfo.lane === "firmware-iot") anchors.push("firmware quicklook anchors");
		if (/firmware-container-header-parsed|filesystem-superblock-parsed|ubi-header-parsed|partitionOffsets|bytesUsed|vidHeaderOffset|signature-magic-match|carve-header-match|firmware-rootfs-carve-proof-path|negative-control/i.test(text) && targetInfo.lane === "firmware-iot") anchors.push("firmware structure anchors");
		if (/firmware-extraction-verification|firmware-extraction-verifier|firmware-rootfs-carve-proof|firmware-extraction-negative-control-proof|rootfs-carve-truncated|carve-offset-size-hash-match/i.test(text) && targetInfo.lane === "firmware-iot") anchors.push("firmware extraction verifier anchors");
		if (/repi-agent-boundary-map|agent-boundary|prompt-injection|llm-to-shell-tool-boundary|tool-secret-exfiltration-boundary|tool_call|system-prompt/i.test(text) && targetInfo.lane === "agent-boundary") anchors.push("agent boundary anchors");
		if (/boundaryFlows|untrusted-input-to-shell-execution-flow|llm-to-shell-execution-flow|tool-secret-exfiltration-flow|prompt-injection-evidence-flow/i.test(text) && targetInfo.lane === "agent-boundary") anchors.push("agent boundary flow anchors");
		if (/repi-agent-boundary-replay|agent-boundary-(?:claim-promotion|repair-queue)|agent-boundary-unsafe-tool-proof-path|agent-boundary-blocked-control-proof-path|unsafe-promoted|control-promoted|responseSha256|composedPaths|claimLedger/i.test(text) && targetInfo.lane === "agent-boundary") anchors.push("agent boundary replay anchors");
		if (/repi-agent-boundary-verification|agent-boundary-verifier|agent-boundary-map-flow-verification-proof|agent-boundary-replay-coverage-proof|agent-boundary-response-hash-oracle-proof|agent-boundary-negative-control-proof|agent-boundary-verification-proof-path/i.test(text) && targetInfo.lane === "agent-boundary") anchors.push("agent boundary verifier anchors");
		if (/repi-cloud-identity-map|cloud-identity|terraform|ClusterRoleBinding|aws_iam|id-token|public-network-exposure|ci-oidc-deployment-trust-chain/i.test(text) && targetInfo.lane === "cloud-identity") anchors.push("cloud identity anchors");
		if (/trustChains|cloud-identity-trust-claims|cloud-trust-chain-pivot|claimLedger|repairQueue|github-oidc-role-assumption-signal|terraform-wildcard-iam-policy-signal|kubernetes-privileged-service-account-signal|kubernetes-clusterrolebinding-signal|container-build-runtime-risk-signal/i.test(text) && targetInfo.lane === "cloud-identity") anchors.push("cloud trust-chain anchors");
		if (/repi-cloud-identity-verification|cloud-identity-verifier|cloud-source-line-verification-proof|cloud-trust-claim-coverage-proof|cloud-composed-path-verification-proof|cloud-verifier-negative-control-proof|cloud-identity-verification-proof-path/i.test(text) && targetInfo.lane === "cloud-identity") anchors.push("cloud identity verifier anchors");
		if (/ExifTool|PNG|IHDR|zsteg|binwalk|PK|flag|ctf|cipher|nonce|salt|base64|xor/i.test(text) && targetInfo.lane === "crypto-stego") anchors.push("crypto/stego anchors");
		if (/repi-crypto-stego-media-quicklook|crypto-stego-media-quicklook|png-text-stego-signal|appended-data-after-iend|appended-zip-after-iend|private-or-nonstandard-png-chunk|embedded-zip-archive-parsed/i.test(text) && targetInfo.lane === "crypto-stego") anchors.push("PNG/stego structure anchors");
		if (/wav-lsb-printable-signal|wav-info-metadata-signal|appended-data-after-riff|appended-zip-after-riff|embedded-zip-archive-parsed|audioData|RIFF|WAVE/i.test(text) && targetInfo.lane === "crypto-stego") anchors.push("WAV/stego structure anchors");
		if (/repi-crypto-stego-verification|crypto-stego-verification|crypto-stego-verifier|crypto-file-hash-verification-proof|crypto-structure-offset-verification-proof|crypto-hidden-channel-negative-control-proof|crypto-stego-verification-proof-path/i.test(text) && targetInfo.lane === "crypto-stego") anchors.push("crypto/stego verifier anchors");
		if (/repi-crypto-stego-transform-claims|crypto-stego-transform-claims|crypto-transform-proof-path|crypto-transform-solver-harness|crypto-embedded-archive-carve|claimLedger|repairQueue/i.test(text) && targetInfo.lane === "crypto-stego") anchors.push("crypto/stego transform claim anchors");
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
	if (targetInfo.lane === "native-pwn") {
		const primaryTarget = targetInfo.representativePath || targetInfo.path || targetInfo.target;
		if (primaryTarget && (dataLooksLikePe(primaryTarget) || dataLooksLikeMachO(primaryTarget))) return ["file", "sha256sum", "strings"];
		return ["file", "sha256sum", "strings", "readelf"];
	}
	if (targetInfo.lane === "js-reverse") return ["file", "sha256sum", "strings"];
	if (targetInfo.lane === "mobile" || targetInfo.lane === "mobile-ios") return ["file", "sha256sum"];
	if (targetInfo.lane === "pcap-dfir") return ["file", "sha256sum"];
	if (targetInfo.lane === "memory-forensics") return ["file", "sha256sum"];
	if (targetInfo.lane === "windows-ad") return ["file", "sha256sum"];
	if (targetInfo.lane === "malware") return ["file", "sha256sum", "strings"];
	if (targetInfo.lane === "firmware-iot") return ["file", "sha256sum"];
	if (targetInfo.lane === "crypto-stego") return ["file", "sha256sum", "strings"];
	if (targetInfo.lane === "agent-boundary") return ["find"];
	if (targetInfo.lane === "cloud-identity") return ["find"];
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
	if (report.swarm) {
		lines.push("", "## Swarm", "");
		if (report.swarm.skipped) lines.push(`- skipped: ${report.swarm.reason}`);
		else {
			lines.push(`- provider/model: ${report.swarm.provider}/${report.swarm.model}`);
			lines.push(`- exit: ${report.swarm.exit}; parsed=${report.swarm.parsed}`);
			if (report.swarm.summary) {
				lines.push(`- runId: ${report.swarm.summary.runId ?? "<unknown>"}`);
				lines.push(`- finalPromotionReady: ${report.swarm.summary.finalPromotionReady}`);
				lines.push(`- routeProofReady: ${report.swarm.summary.routeProofReady}; missingProofRoutes=${report.swarm.summary.missingProofRoutes.join(",") || "<none>"}`);
				if (report.swarm.summary.mergeVerification) lines.push(`- mergeVerificationProofReady: ${report.swarm.summary.mergeVerification.proofReady}; blockers=${report.swarm.summary.mergeVerification.blockers.join(",") || "<none>"}`);
				if (report.swarm.summary.mergeFailureReason) lines.push(`- mergeFailureReason: ${report.swarm.summary.mergeFailureReason}`);
			}
		}
	}
	lines.push("", "## Next Step", "");
	for (const command of report.nextQueue) lines.push(`- \`${command}\``);
	lines.push("");
	return lines.join("\n");
}

function createMission(targetInfo) {
	if (noMission || noWrite) return noWrite && !noMission ? { skipped: true, reason: "--no-write disables mission writes" } : undefined;
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

function summarizeSwarmJson(parsed) {
	if (!parsed || typeof parsed !== "object") return undefined;
	const isMergeReport = parsed.kind === "repi-swarm-merge-report" || parsed.StructuredSubagentMergeV1 === true;
	const merge = isMergeReport ? parsed : parsed.merge && typeof parsed.merge === "object" ? parsed.merge : {};
	const routeCoverage = merge.routeCoverage && typeof merge.routeCoverage === "object" ? merge.routeCoverage : undefined;
	const routeReadinessRows = Array.isArray(merge.routeReadinessRows)
		? merge.routeReadinessRows.map((row) => ({
				routeId: row.routeId ?? row.route?.id ?? null,
				proofReady: Boolean(row.proofReady),
				promotedClaims: Array.isArray(row.promotedClaimIds) ? row.promotedClaimIds.length : 0,
				proofReadyPromotedClaims: Array.isArray(row.proofReadyPromotedClaimIds) ? row.proofReadyPromotedClaimIds.length : 0,
				missing: Array.isArray(row.missing) ? row.missing.map((item) => redact(String(item))).slice(0, 8) : [],
			}))
		: [];
	const missingProofRoutes = Array.isArray(merge.missingProofRoutes)
		? merge.missingProofRoutes.map((route) => route?.id ?? route?.routeId ?? route?.domain).filter(Boolean).map((item) => redact(String(item))).slice(0, 16)
		: [];
	return {
		ok: Boolean(parsed.ok),
		runId: parsed.runId ?? merge.runId ?? null,
		evidenceRoot: parsed.evidenceRoot ?? merge.evidenceRoot ?? null,
		mergeFailureReason: parsed.mergeFailureReason ? redact(String(parsed.mergeFailureReason)) : undefined,
		finalPromotionReady: Boolean(merge.finalPromotionReady),
		proofPromotionReady: Boolean(merge.proofPromotionReady),
		routeProofReady: Boolean(merge.routeProofReady),
		routeCoverage: routeCoverage
			? {
					complete: routeCoverage.complete !== false,
					coveredCount: Number(routeCoverage.coveredCount ?? 0),
					routeCount: Number(routeCoverage.routeCount ?? 0),
					uncoveredCount: Number(routeCoverage.uncoveredCount ?? 0),
				}
			: undefined,
		proofReadyRouteIds: Array.isArray(merge.proofReadyRouteIds) ? merge.proofReadyRouteIds.map((item) => redact(String(item))).slice(0, 16) : [],
		missingProofRoutes,
		routeReadinessRows,
		promotedClaims: Array.isArray(merge.promotedClaims) ? merge.promotedClaims.length : 0,
		proofReadyPromotedClaims: Array.isArray(merge.proofReadyPromotedClaims) ? merge.proofReadyPromotedClaims.length : 0,
		mergeVerification: merge.mergeVerification
			? {
					proofReady: Boolean(merge.mergeVerification.proofReady),
					finalPromotionReady: Boolean(merge.mergeVerification.finalPromotionReady),
					blockers: Array.isArray(merge.mergeVerification.promotionReport?.blockers)
						? merge.mergeVerification.promotionReport.blockers.map((item) => redact(String(item))).slice(0, 12)
						: [],
					stats: merge.mergeVerification.stats ?? {},
				}
			: undefined,
		nextCommands: Array.isArray(merge.nextCommands) ? merge.nextCommands.map((command) => redact(String(command))).slice(0, 12) : [],
	};
}

function maybeRunSwarm(targetInfo) {
	if (!swarm) return undefined;
	if (noWrite) return { skipped: true, reason: "--no-write disables persistent swarm dispatch" };
	const provider = argValue("--provider") || DEFAULT_SWARM_PROVIDER;
	const model = argValue("--model") || DEFAULT_SWARM_MODEL;
	const workers = argValue("--workers") || "5";
	const prompt = argValue("--prompt") || "Return structured reverse/pentest evidence, blockers, commands, and next proof step.";
	const swarmArgs = [
		resolveScript("repi-swarm-llm-run.mjs"),
		root,
		"run",
		targetInfo.target,
		"--workers",
		workers,
		...swarmRouteArgs(targetInfo),
		...(provider ? ["--provider", provider] : []),
		...(model ? ["--model", model] : []),
		"--prompt",
		prompt,
		"--json",
	];
	const result = run(process.execPath, swarmArgs, {
		id: "swarm-run",
		timeout: deep ? 300_000 : 180_000,
		includeRaw: true,
	});
	let parsed = extractJsonObjectFromText(result.rawStdout ?? result.stdout);
	let summary = summarizeSwarmJson(parsed);
	let summarySource = "stdout";
	if (!summary?.runId) {
		const fallback = run(process.execPath, [resolveScript("repi-swarm-llm-run.mjs"), root, "merge", "latest", "--json"], {
			id: "swarm-merge-latest",
			timeout: 45_000,
			includeRaw: true,
		});
		const fallbackParsed = extractJsonObjectFromText(fallback.rawStdout ?? fallback.stdout);
		const fallbackSummary = summarizeSwarmJson(fallbackParsed);
		if (fallbackSummary?.runId) {
			parsed = parsed ?? fallbackParsed;
			summary = {
				...(summary ?? {}),
				...fallbackSummary,
				mergeFailureReason: summary?.mergeFailureReason,
			};
			summarySource = "merge-latest";
		}
	}
	return {
		exit: result.exit,
		provider: provider ?? "default",
		model: model ?? "default",
		parsed: Boolean(parsed),
		summarySource,
		summary,
		stdoutTail: result.stdout.slice(-4000),
		stderrTail: result.stderr.slice(-2000),
	};
}

const target = positionalTarget() || process.cwd();
const targetInfo = classifyTarget(target, { commandExists, run });
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
configureEngageProofRuntime(engageProofRuntime());
configureWebEngagementRuntime(webEngagementRuntime());
if (targetInfo.kind === "url") commands = engageUrl(targetInfo, artifactDir);
else if (targetInfo.kind === "directory") commands = engageDirectory(targetInfo, artifactDir);
else if (targetInfo.kind === "file") commands = engageFile(targetInfo, artifactDir);
else commands = [run("bash", ["-lc", `printf '%s\n' ${shellQuote(targetInfo.target)}`], { id: "task-text", timeout: 3000 })];
const proofGraph = writeUnifiedProofGraph(targetInfo, artifactDir, commands, toolState);
if (proofGraph) {
	commands.push({
		id: "repi-proof-graph",
		command: "internal",
		args: [redact(proofGraph.path)],
		cwd: root,
		exit: proofGraph.summary.claimLedger.length || proofGraph.summary.artifactFiles.length ? 0 : 1,
		signal: null,
		durationMs: 0,
		stdout: `${JSON.stringify(
			{
				kind: proofGraph.summary.kind,
				proofReady: proofGraph.summary.proofReady,
				exploitProofReady: proofGraph.summary.exploitProofReady,
				nodeCount: proofGraph.summary.nodeCount,
				edgeCount: proofGraph.summary.edgeCount,
				claimCount: proofGraph.summary.claimLedger.length,
				composedPathCount: proofGraph.summary.composedPaths.length,
				repairQueueCount: proofGraph.summary.repairQueue.length,
				runtimeRepairLoop: {
					ready: proofGraph.summary.runtimeRepairLoop.ready,
					blockers: proofGraph.summary.runtimeRepairLoop.blockers,
					nextCommands: proofGraph.summary.runtimeRepairLoop.nextCommands.slice(0, 8),
				},
			},
			null,
			2,
		)}\n`,
		stderr: "",
		error: proofGraph.summary.claimLedger.length || proofGraph.summary.artifactFiles.length ? undefined : "no proof graph evidence artifacts collected",
	});
	const repairLoop = writeRuntimeRepairLoopHarness(artifactDir, proofGraph.path);
	if (repairLoop) {
		commands.push({
			id: "repi-runtime-repair-loop-artifact",
			command: "internal",
			args: [redact(repairLoop.path), redact(proofGraph.path)],
			cwd: root,
			exit: 0,
			signal: null,
			durationMs: 0,
			stdout: `harness=${redact(repairLoop.path)}\ngraph=${redact(proofGraph.path)}\nrun=node ${redact(repairLoop.path)} --plan\nexecute=node ${redact(repairLoop.path)} --execute --max 1\n`,
			stderr: "",
			error: undefined,
		});
	}
}
commands.push(...proofHarnessRows(targetInfo, artifactDir, commands, toolState));
const swarmReport = maybeRunSwarm(targetInfo);
const summary = summarizeEvidence(commands, targetInfo, toolState);
const nextQueueRows = Array.from(new Set([
	...nextQueue(targetInfo, artifactDir, toolState).map((command) => redact(command)),
	...(Array.isArray(swarmReport?.summary?.nextCommands) ? swarmReport.summary.nextCommands : []),
])).slice(0, 80);

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
		representativePath: targetInfo.representativePath ? redact(targetInfo.representativePath) : null,
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
