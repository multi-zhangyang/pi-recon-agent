#!/usr/bin/env node
import { createHash } from "node:crypto";
import {
	chmodSync,
	existsSync,
	readFileSync,
	readdirSync,
	statSync,
} from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { safeWriteReport } from "./lib/report-write-helpers.mjs";

const argv = process.argv.slice(2);
const rootArg = argv[0] && !argv[0].startsWith("-") ? argv.shift() : undefined;
const root = resolve(rootArg ?? process.cwd());
const command = (argv.shift() ?? "status").toLowerCase();
const json = argv.includes("--json");
const agentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const missionDir = join(agentDir, "recon", "mission");
const evidenceDir = join(agentDir, "recon", "evidence");
const contextDir = join(evidenceDir, "contexts");
const missionPath = join(missionDir, "current.json");
const historyPath = join(missionDir, "history.jsonl");
const operatorCwd = resolve(process.env.REPI_OPERATOR_CWD || process.env.PWD || process.cwd());

const ROUTES = [
	{
		id: "web-api",
		domain: "Web / API",
		prompt: "websec",
		match: /\b(web|http|https|api|graphql|rest|route|endpoint|auth|session|jwt|cookie|idor|bola|cors|csrf|ssrf|xss|sql|sqli)\b/i,
		workflow: ["route inventory", "auth/session baseline", "request replay", "state/authorization proof", "verifier/replayer"],
		tools: ["curl/httpie", "browser/CDP", "mitmproxy/burp", "jq", "re_web_authz_state", "re_live_browser"],
		evidence: ["routes", "requests/responses", "principal matrix", "object ownership", "replay commands"],
	},
	{
		id: "js-reverse",
		domain: "Frontend / JS reverse",
		prompt: "jsre",
		match: /\b(js|javascript|webpack|vite|sign|signature|crypto\.subtle|wasm|bundle|xhr|fetch|websocket|anti-debug)\b/i,
		workflow: ["asset inventory", "beautify/deobfuscate", "signing path trace", "first divergence", "replayer"],
		tools: ["node", "playwright/CDP", "esbuild", "jq", "re_live_browser"],
		evidence: ["served assets", "signing function anchors", "request diff", "replay script", "verification matrix"],
	},
	{
		id: "native-pwn",
		domain: "Native / Pwn",
		prompt: "native",
		match: /\b(binary|elf|pe|macho|so|exe|pwn|rop|heap|tcache|format-string|shellcode|crash|core|gdb|lldb|libc|ret2|srop)\b/i,
		workflow: ["file/mitigation map", "imports/strings/xrefs", "crash or trace primitive", "exploit hypothesis", "local replay"],
		tools: ["file/readelf/checksec", "r2/ghidra", "gdb/lldb", "pwntools", "re_native_runtime"],
		evidence: ["hash/arch/mitigations", "crash registers", "offset/leak source", "controlled bytes", "replay PoC"],
	},
	{
		id: "mobile",
		domain: "Mobile reverse",
		prompt: "mobile",
		match: /\b(apk|ipa|android|ios|jadx|apktool|frida|objection|keystore|keychain|pinning|root|emulator|magisk)\b/i,
		workflow: ["package inventory", "manifest/permission map", "static hooks", "runtime trace", "bypass/replay proof"],
		tools: ["jadx/apktool", "frida", "adb", "objection", "re_mobile_runtime"],
		evidence: ["package/hash", "manifest anchors", "hook scripts", "runtime trace", "replay commands"],
	},
	{
		id: "pcap-dfir",
		domain: "PCAP / DFIR",
		prompt: "pcap",
		match: /\b(pcap|traffic|wireshark|tshark|forensic|dfir|memory dump|volatility|timeline|ioc)\b/i,
		workflow: ["artifact fingerprint", "stream/session ranking", "transform chain", "secret/ioc timeline", "report"],
		tools: ["tshark", "tcpdump", "volatility", "strings", "python"],
		evidence: ["hash/magic", "flow table", "stream extracts", "decoded payloads", "timeline"],
	},
	{
		id: "firmware-iot",
		domain: "Firmware / IoT",
		prompt: "firmware",
		match: /\b(firmware|iot|router|rootfs|squashfs|ubi|uimage|binwalk|unblob|busybox|nvram|cgi)\b/i,
		workflow: ["image fingerprint", "extract rootfs", "service/config map", "emulation smoke", "web/API proof"],
		tools: ["binwalk/unblob", "unsquashfs", "qemu", "grep", "re_web_authz_state"],
		evidence: ["image hash", "rootfs path", "service list", "credentials/config anchors", "emulation/replay"],
	},
	{
		id: "cloud-identity",
		domain: "Cloud / Identity",
		prompt: "cloud",
		match: /\b(cloud|aws|gcp|azure|k8s|kubernetes|iam|sts|role|serviceaccount|metadata|rbac|terraform|docker)\b/i,
		workflow: ["credential/config map", "runtime identity", "permission graph", "metadata probe", "least proof"],
		tools: ["aws/gcloud/az/kubectl", "jq", "docker", "terraform", "re_knowledge_graph"],
		evidence: ["identity anchors", "RBAC/IAM edges", "metadata status", "privilege path", "replay commands"],
	},
	{
		id: "malware",
		domain: "Malware / sample analysis",
		prompt: "malware",
		match: /\b(malware|sample|yara|capa|floss|packer|upx|ioc|c2|mutex|persistence|sandbox)\b/i,
		workflow: ["static triage", "rule/capability scan", "config/ioc extraction", "behavior trace", "report"],
		tools: ["file/strings", "yara/capa/floss", "strace/ltrace", "python", "clamscan"],
		evidence: ["hash/magic", "rule hits", "config/IOC anchors", "behavior trace", "replay commands"],
	},
	{
		id: "crypto-stego",
		domain: "Crypto / Stego",
		prompt: "reverse",
		match: /\b(crypto|cipher|rsa|aes|xor|hash|padding|oracle|stego|image|exif|metadata|zsteg)\b/i,
		workflow: ["artifact inventory", "parameter extraction", "transform chain", "oracle/test vector", "solve verifier"],
		tools: ["python", "openssl", "sage", "exiftool", "zsteg/binwalk"],
		evidence: ["params", "known plaintext/test vectors", "transform script", "decoded artifact", "verification"],
	},
];

function usage() {
	return `Usage:
  repi mission new <task> [--target <target>] [--domain <domain>] [--json]
  repi mission plan [task] [--target <target>] [--domain <domain>] [--json]
  repi mission status [--json]
  repi mission next [--json]
  repi mission pack [--output <path>] [--json]
  repi mission close [--summary <text>] [--json]
  repi mission reset [--yes] [--json]

Mission Control is the task-level control plane. It creates a scoped mission,
selects the reverse/pentest lane, writes an evidence contract, generates the
next operator commands, and emits a compact resume pack without auto-injecting
old memory into unrelated tasks.
`;
}

function argValue(flag) {
	const index = argv.indexOf(flag);
	if (index === -1) return undefined;
	return argv[index + 1] && !argv[index + 1].startsWith("--") ? argv[index + 1] : "";
}

function hasFlag(flag) {
	return argv.includes(flag);
}

function positionalText() {
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

function writePrivate(path, text) {
	// opt #177: route the mission artifact/state write through safeWriteReport
	// so an ENOSPC/EACCES mid-write is observable instead of a bare uncaught
	// throw that discards the artifact with no partial output. onWriteError
	// rethrows a descriptive Error so the script-level catch emits the
	// structured error report (JSON in --json mode, stderr + exit 2 otherwise).
	safeWriteReport(path, text, {
		onWriteError: (msg) => {
			throw new Error(msg);
		},
	});
	try {
		chmodSync(path, 0o600);
	} catch {
		// Best effort.
	}
}

function appendPrivate(path, text) {
	const old = existsSync(path) ? readFileSync(path, "utf8") : "";
	writePrivate(path, `${old}${text}`);
}

function readJson(path) {
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch {
		return undefined;
	}
}

function sha(value) {
	return createHash("sha256").update(String(value)).digest("hex").slice(0, 16);
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

function slugify(value) {
	return String(value || "mission")
		.toLowerCase()
		.replace(/[^a-z0-9\u4e00-\u9fa5]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(0, 42) || "mission";
}

function nowStamp() {
	return new Date().toISOString();
}

function compactTime() {
	return new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
}

function selectRoute(task, explicitDomain) {
	const text = `${task || ""} ${argValue("--target") || ""} ${explicitDomain || ""}`;
	if (explicitDomain) {
		const byDomain = ROUTES.find((route) => route.id === explicitDomain || route.domain.toLowerCase().includes(explicitDomain.toLowerCase()));
		if (byDomain) return byDomain;
	}
	return ROUTES.find((route) => route.match.test(text)) ?? {
		id: "reverse-pentest-general",
		domain: "Reverse/Pentest general",
		prompt: "reverse",
		workflow: ["passive map", "choose one minimal proof path", "execute bounded verification", "compile evidence", "record reusable lesson only if high-value"],
		tools: ["rg", "file/strings", "curl", "python", "re_verifier", "re_compiler"],
		evidence: ["target inventory", "runtime or artifact anchors", "verification command", "claim matrix", "next step"],
	};
}

function buildPlan(task, options = {}) {
	const route = selectRoute(task, options.domain);
	const target = options.target || argValue("--target") || task;
	const basePrompt = `Mission: ${task}\nTarget: ${target}\nRoute: ${route.domain}\nExecute passive map first, prove one end-to-end path, bind claims to evidence, and stop narrative-only drift.`;
	return {
		route: {
			id: route.id,
			domain: route.domain,
			prompt: route.prompt,
			workflow: route.workflow,
			recommendedTools: route.tools,
		},
		lanes: [
			{ id: "map", objective: "建立目标/代码/流量/二进制/运行态清单", exit: "有 hash/path/route/runtime anchor" },
			{ id: "proof", objective: "选择一条最小可验证链路并执行", exit: "有命令、输出摘要、可复现路径" },
			{ id: "verify", objective: "反证检查与报告编译", exit: "verifier matrix 无阻塞矛盾" },
		],
		evidenceContract: {
			required: route.evidence,
			forbidden: ["raw secrets", "unscoped old-memory injection", "narrative-only exploitability claim"],
			outputOrder: "Outcome → Key Evidence → Verification → Next Step",
		},
		nextActions: [
			"repi health",
			`repi -p ${JSON.stringify(basePrompt)}`,
			`repi swarm plan ${JSON.stringify(target)} --workers 5`,
			"repi mission pack",
		],
		operatorPrompt: basePrompt,
	};
}

function newMission(task, options = {}) {
	const cleanTask = redact(task || "").trim();
	if (!cleanTask) throw new Error("No mission task provided. Usage: repi mission new <task>");
	const createdAt = nowStamp();
	const plan = buildPlan(cleanTask, options);
	const id = `${compactTime()}-${slugify(cleanTask)}-${sha(`${createdAt}:${cleanTask}`)}`;
	return {
		kind: "repi-mission",
		schemaVersion: 1,
		id,
		status: "active",
		createdAt,
		updatedAt: createdAt,
		workspace: operatorCwd,
		root,
		task: cleanTask,
		target: redact(options.target || argValue("--target") || cleanTask),
		route: plan.route,
		lanes: plan.lanes,
		evidenceContract: plan.evidenceContract,
		nextActions: plan.nextActions,
		artifacts: {
			missionPath,
			historyPath,
			contextDir,
			evidenceLedger: join(evidenceDir, "ledger.md"),
		},
		notes: [
			"Memory is scoped by mission/workspace/target; this command does not auto-inject unrelated old tasks.",
			"Close explicitly with repi mission close; deposit long-term lessons only when they are reusable and sanitized.",
		],
	};
}

function saveMission(mission) {
	const normalized = { ...mission, updatedAt: nowStamp() };
	writePrivate(missionPath, `${JSON.stringify(normalized, null, 2)}\n`);
	appendPrivate(historyPath, `${JSON.stringify({ ts: nowStamp(), event: "mission_write", id: normalized.id, status: normalized.status, task: normalized.task, target: normalized.target, route: normalized.route?.id })}\n`);
	return normalized;
}

function loadMission() {
	return readJson(missionPath);
}

function evidenceTail(maxLines = 60) {
	const path = join(evidenceDir, "ledger.md");
	try {
		const lines = readFileSync(path, "utf8").split(/\r?\n/).filter(Boolean);
		return lines.slice(-maxLines);
	} catch {
		return [];
	}
}

function latestArtifacts(maxItems = 16) {
	const rows = [];
	function walk(dir, depth = 0) {
		if (depth > 3 || !existsSync(dir)) return;
		let entries = [];
		try {
			entries = readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}
		for (const entry of entries) {
			const path = join(dir, entry.name);
			if (entry.isDirectory()) walk(path, depth + 1);
			else if (entry.isFile()) {
				try {
					const stat = statSync(path);
					rows.push({ path, bytes: stat.size, mtimeMs: stat.mtimeMs });
				} catch {
					// Ignore transient artifacts.
				}
			}
		}
	}
	walk(evidenceDir);
	return rows
		.sort((a, b) => b.mtimeMs - a.mtimeMs)
		.slice(0, maxItems)
		.map((row) => ({ path: row.path.replace(`${agentDir}/`, "~/.repi/agent/"), bytes: row.bytes, mtime: new Date(row.mtimeMs).toISOString() }));
}

function buildContextPack(mission) {
	const active = mission && mission.kind === "repi-mission" ? mission : undefined;
	const generatedAt = nowStamp();
	const pack = {
		kind: "repi-mission-context-pack",
		schemaVersion: 1,
		generatedAt,
		mission: active
			? {
					id: active.id,
					status: active.status,
					task: active.task,
					target: active.target,
					route: active.route,
					lanes: active.lanes,
					evidenceContract: active.evidenceContract,
				}
			: null,
		evidenceTail: evidenceTail(),
		latestArtifacts: latestArtifacts(),
		nextActions: active?.nextActions ?? ["repi mission new <task>", "repi health", "repi model doctor"],
		resumeBrief: active
			? `Continue mission ${active.id}: ${active.task}. Route=${active.route?.domain}. Next=${(active.nextActions ?? [])[0] ?? "map target"}.`
			: "No active mission. Start with repi mission new <task>.",
		memoryPolicy: {
			scoped: true,
			autoInjectRawMemory: false,
			requireExplicitPromotion: true,
			reason: "避免旧任务污染新任务；只把当前 mission/workspace/target 范围内的摘要作为恢复上下文。",
		},
	};
	return pack;
}

function writeContextPack(pack, output) {
	const outPath = output || join(contextDir, `mission-context-${compactTime()}.json`);
	writePrivate(outPath, `${JSON.stringify(pack, null, 2)}\n`);
	const mdPath = outPath.endsWith(".json") ? outPath.replace(/\.json$/, ".md") : `${outPath}.md`;
	const mission = pack.mission;
	const artifactLines = pack.latestArtifacts.map((row) => `- ${row.path} (${row.bytes} bytes, ${row.mtime})`).join("\n") || "- <none>";
	const evidenceLines = pack.evidenceTail.slice(-20).map((line) => `> ${line}`).join("\n") || "> <none>";
	writePrivate(
		mdPath,
		[
			"# REPI Mission Context Pack",
			"",
			`generatedAt: ${pack.generatedAt}`,
			`mission: ${mission?.id ?? "<none>"}`,
			`status: ${mission?.status ?? "none"}`,
			`route: ${mission?.route?.domain ?? "none"}`,
			"",
			"## Resume brief",
			"",
			pack.resumeBrief,
			"",
			"## Next actions",
			"",
			...(pack.nextActions ?? []).map((action) => `- \`${action}\``),
			"",
			"## Latest artifacts",
			"",
			artifactLines,
			"",
			"## Evidence tail",
			"",
			evidenceLines,
			"",
		].join("\n"),
	);
	return { jsonPath: outPath, markdownPath: mdPath };
}

function reportHuman(report) {
	switch (report.kind) {
		case "repi-mission-report":
			console.log(`REPI Mission ${report.action}`);
			console.log(`status: ${report.mission?.status ?? "none"}`);
			if (report.mission) {
				console.log(`id: ${report.mission.id}`);
				console.log(`task: ${report.mission.task}`);
				console.log(`target: ${report.mission.target}`);
				console.log(`route: ${report.mission.route?.domain}`);
				console.log(`workspace: ${report.mission.workspace}`);
				console.log("next:");
				for (const action of report.mission.nextActions ?? []) console.log(`  - ${action}`);
			} else {
				console.log("next:");
				for (const action of report.nextActions ?? []) console.log(`  - ${action}`);
			}
			if (report.output) {
				console.log(`contextPack: ${report.output.jsonPath}`);
				console.log(`contextMarkdown: ${report.output.markdownPath}`);
			}
			if (report.message) console.log(report.message);
			break;
		case "repi-mission-plan":
			console.log("REPI Mission Plan");
			console.log(`task: ${report.task}`);
			console.log(`target: ${report.target}`);
			console.log(`route: ${report.plan.route.domain}`);
			console.log("workflow:");
			for (const step of report.plan.route.workflow) console.log(`  - ${step}`);
			console.log("evidence:");
			for (const step of report.plan.evidenceContract.required) console.log(`  - ${step}`);
			console.log("next:");
			for (const action of report.plan.nextActions) console.log(`  - ${action}`);
			break;
		default:
			console.log(JSON.stringify(report, null, 2));
	}
}

function finish(report, exitCode = 0) {
	if (json) console.log(JSON.stringify(report, null, 2));
	else reportHuman(report);
	process.exit(exitCode);
}

try {
	if (["help", "--help", "-h"].includes(command)) {
		console.log(usage());
		process.exit(0);
	}

	if (["new", "start", "init"].includes(command)) {
		const task = positionalText();
		const mission = saveMission(newMission(task, { target: argValue("--target"), domain: argValue("--domain") }));
		finish({ kind: "repi-mission-report", schemaVersion: 1, action: "new", root, agentDir, missionPath, mission });
	}

	if (command === "plan") {
		const current = loadMission();
		const task = positionalText() || current?.task || argValue("--target") || "";
		if (!task) throw new Error("No task to plan. Use: repi mission plan <task> or repi mission new <task>");
		const target = argValue("--target") || current?.target || task;
		const plan = buildPlan(task, { target, domain: argValue("--domain") });
		finish({ kind: "repi-mission-plan", schemaVersion: 1, root, agentDir, task: redact(task), target: redact(target), plan });
	}

	if (["status", "show", "doctor"].includes(command)) {
		const mission = loadMission();
		const ok = mission?.kind === "repi-mission" && mission?.schemaVersion === 1 && mission?.status === "active";
		finish({
			kind: "repi-mission-report",
			schemaVersion: 1,
			action: "status",
			root,
			agentDir,
			missionPath,
			ok,
			mission: ok ? mission : null,
			nextActions: ok ? mission.nextActions : ["repi mission new <task>", "repi health", "repi model doctor"],
			message: ok ? undefined : `No active mission at ${missionPath}`,
		});
	}

	if (command === "next") {
		const mission = loadMission();
		const ok = mission?.kind === "repi-mission" && mission?.status === "active";
		finish({
			kind: "repi-mission-report",
			schemaVersion: 1,
			action: "next",
			root,
			agentDir,
			missionPath,
			ok,
			mission: ok ? mission : null,
			nextActions: ok ? mission.nextActions : ["repi mission new <task>", "repi health"],
			message: ok ? undefined : "No active mission; create one first.",
		});
	}

	if (["pack", "context", "resume"].includes(command)) {
		const mission = loadMission();
		const pack = buildContextPack(mission);
		const output = writeContextPack(pack, argValue("--output"));
		finish({
			kind: "repi-mission-report",
			schemaVersion: 1,
			action: "pack",
			root,
			agentDir,
			missionPath,
			ok: true,
			mission: mission?.kind === "repi-mission" ? mission : null,
			contextPack: pack,
			output,
		});
	}

	if (["close", "done", "complete"].includes(command)) {
		const mission = loadMission();
		if (!mission?.kind) throw new Error("No active mission to close.");
		const summary = redact(argValue("--summary") || positionalText() || "");
		const closed = saveMission({
			...mission,
			status: "closed",
			closedAt: nowStamp(),
			summary,
			nextActions: ["repi mission new <next-task>", "repi memory consolidate --dry-run", "repi health"],
		});
		finish({ kind: "repi-mission-report", schemaVersion: 1, action: "close", root, agentDir, missionPath, ok: true, mission: closed, message: "Mission closed. Long-term memory deposition is explicit; no raw session history was promoted automatically." });
	}

	if (["reset", "clear"].includes(command)) {
		if (!hasFlag("--yes")) throw new Error("reset requires --yes");
		const current = loadMission();
		if (current?.kind) {
			appendPrivate(historyPath, `${JSON.stringify({ ts: nowStamp(), event: "mission_reset", id: current.id, status: current.status })}\n`);
		}
		writePrivate(missionPath, `${JSON.stringify({ kind: "repi-mission", schemaVersion: 1, status: "empty", updatedAt: nowStamp(), task: null }, null, 2)}\n`);
		finish({ kind: "repi-mission-report", schemaVersion: 1, action: "reset", root, agentDir, missionPath, ok: true, mission: null, nextActions: ["repi mission new <task>"] });
	}

	throw new Error(`Unknown repi mission command: ${command}`);
} catch (error) {
	const message = error instanceof Error ? error.message : String(error);
	if (json) {
		console.log(JSON.stringify({ kind: "repi-mission-report", schemaVersion: 1, action: command, root, agentDir, missionPath, ok: false, error: message }, null, 2));
	} else {
		console.error(`REPI Mission error: ${message}`);
		console.error("Run: repi mission --help");
	}
	process.exit(2);
}
