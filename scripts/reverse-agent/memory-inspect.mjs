#!/usr/bin/env node
import { appendFileSync, existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";

const rawArgs = process.argv.slice(2);
const knownCommands = new Set(["status", "diff", "why", "forget", "quarantine", "help"]);
let root = process.cwd();
if (rawArgs[0] && !rawArgs[0].startsWith("--") && !knownCommands.has(rawArgs[0])) {
	root = resolve(rawArgs.shift());
}
const helpRequested = rawArgs.includes("--help") || rawArgs.includes("-h");
const command = helpRequested ? "help" : rawArgs[0] && !rawArgs[0].startsWith("--") ? rawArgs.shift() : "status";
const json = rawArgs.includes("--json");
const all = rawArgs.includes("--all");
const limit = parseLimit(rawArgs, 12);
const agentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const memoryDir = join(agentDir, "recon", "memory");
const eventsPath = join(memoryDir, "events.jsonl");
const reportPath = join(memoryDir, "consolidation-report.json");
const governancePath = join(memoryDir, "governance-ledger.jsonl");

const memoryFiles = [
	"core-memory.md",
	"project-memory.md",
	"procedural-memory.md",
	"field-journal.md",
	"case-index.md",
	"evolution-log.md",
	"events.jsonl",
	"consolidation-report.json",
];

function usage() {
	return `Usage:
  repi memory status [--json]
  repi memory diff [--json] [--limit N] [--all]
  repi memory why <query-or-event-id> [--json] [--limit N]
  repi memory forget <query-or-event-id> [--reason <text>] [--json]
  repi memory quarantine <query-or-event-id> [--reason <text>] [--json]

status  Show scoped memory posture, file sizes, pending consolidation count.
diff    Show high-value memory events not yet consolidated.
why     Explain which memory rows match a query and why they would be visible.
forget  Append a tombstone governance decision. It does not rewrite history.
quarantine Append a quarantine governance decision. It blocks future recall/injection.
`;
}

function parseLimit(args, fallback) {
	const index = args.indexOf("--limit");
	if (index < 0) return fallback;
	const parsed = Number.parseInt(args[index + 1] ?? "", 10);
	return Number.isFinite(parsed) ? Math.max(1, Math.min(200, parsed)) : fallback;
}

function flagValue(args, names, fallback = undefined) {
	const list = Array.isArray(names) ? names : [names];
	for (let index = 0; index < args.length; index++) {
		for (const name of list) {
			if (args[index] === name) return args[index + 1] ?? fallback;
			if (args[index].startsWith(`${name}=`)) return args[index].slice(name.length + 1);
		}
	}
	return fallback;
}

function positional(args, offset = 0) {
	return args.filter((arg) => !arg.startsWith("--"))[offset];
}

function readJson(path) {
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch {
		return undefined;
	}
}

function readJsonl(path) {
	const rows = [];
	let invalid = 0;
	try {
		for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
			if (!line.trim()) continue;
			try {
				rows.push(JSON.parse(line));
			} catch {
				invalid++;
			}
		}
	} catch {
		return { rows, invalid, missing: true };
	}
	return { rows, invalid, missing: false };
}

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function redact(value) {
	return String(value ?? "")
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/(?:AUTH_TOKEN|API_KEY|PASSWORD|SECRET|TOKEN)=\S+/gi, (match) => `${match.split("=")[0]}=<redacted>`)
		.replace(/\s+/g, " ")
		.trim();
}

function clip(value, max = 260) {
	const text = redact(value);
	return text.length > max ? `${text.slice(0, max - 14)}...<truncated>` : text;
}

function scoreEvent(event) {
	let score = 0;
	if (event.outcome === "success") score += 35;
	if (event.outcome === "partial" || event.outcome === "repair") score += 18;
	if (event.quality?.replayVerified) score += 25;
	if (event.promotion?.playbookCandidate) score += 16;
	if ((event.commands ?? []).length) score += 12;
	if ((event.reuseRules ?? []).length) score += 10;
	if ((event.lessons ?? []).length) score += 8;
	score += Math.round((event.quality?.confidence ?? 0) * 20);
	if (event.outcome === "failure" || event.outcome === "blocked") score -= 15;
	return score;
}

function safeTime(value) {
	const date = new Date(value ?? 0);
	return Number.isFinite(date.getTime()) ? date.toISOString() : undefined;
}

function isAfter(ts, since) {
	if (!since) return true;
	const eventTime = new Date(ts ?? 0).getTime();
	const sinceTime = new Date(since).getTime();
	return Number.isFinite(eventTime) && Number.isFinite(sinceTime) && eventTime > sinceTime;
}

function fileInfo(name) {
	const path = join(memoryDir, name);
	try {
		const stat = statSync(path);
		return { name, path, exists: true, bytes: stat.size, mtime: stat.mtime.toISOString() };
	} catch {
		return { name, path, exists: false, bytes: 0, mtime: null };
	}
}

function eventSummary(event, score) {
	return {
		id: redact(event.id ?? "unknown"),
		ts: safeTime(event.ts),
		score,
		outcome: redact(event.outcome ?? "unknown"),
		route: clip(event.route ?? "unknown", 120),
		target: clip(event.target ?? "workspace", 160),
		commands: (event.commands ?? []).slice(0, 3).map((value) => clip(value, 260)),
		reuseRules: (event.reuseRules ?? []).slice(0, 3).map((value) => clip(value, 260)),
		lessons: (event.lessons ?? []).slice(0, 3).map((value) => clip(value, 260)),
	};
}

function governanceRows() {
	return readJsonl(governancePath).rows.filter((row) => row && typeof row === "object" && /memory.*governance|governance/i.test(String(row.kind ?? "")));
}

function governedSourceIds() {
	const rows = governanceRows();
	const out = new Map();
	for (const row of rows) {
		const source = String(row.sourceEventId ?? row.eventId ?? "").trim();
		if (!source) continue;
		const action = String(row.action ?? "").toLowerCase();
		if (action === "forget" || action === "quarantine") out.set(source, { action, row });
		if (action === "promote" || action === "retain") out.delete(source);
	}
	return out;
}

function memoryText(event) {
	return [
		event.id,
		event.caseSignature,
		event.route,
		event.target,
		event.task,
		...(event.domainTags ?? []),
		...(event.commands ?? []),
		...(event.reuseRules ?? []),
		...(event.lessons ?? []),
		...(event.failurePatterns ?? []),
	].join("\n");
}

function queryTokens(query) {
	return String(query ?? "")
		.toLowerCase()
		.split(/[^a-z0-9一-鿿._:/-]+/)
		.map((token) => token.trim())
		.filter((token) => token.length >= 2)
		.slice(0, 24);
}

function explainMatches(events, query, max = limit) {
	const tokens = queryTokens(query);
	const lower = String(query ?? "").toLowerCase().trim();
	const governed = governedSourceIds();
	return events
		.map((event) => {
			const haystack = memoryText(event).toLowerCase();
			const reasons = [];
			let matchScore = 0;
			if (event.id === query || event.caseSignature === query || event.entryHash === query) {
				matchScore += 100;
				reasons.push("exact-id-or-signature");
			}
			if (lower && haystack.includes(lower)) {
				matchScore += 35;
				reasons.push("substring");
			}
			for (const token of tokens) {
				if (haystack.includes(token)) {
					matchScore += 6;
					reasons.push(`token:${token}`);
				}
			}
			const governance = governed.get(event.id);
			if (governance) {
				matchScore -= governance.action === "quarantine" ? 80 : 60;
				reasons.push(`governance:${governance.action}`);
			}
			matchScore += Math.max(-20, Math.min(20, scoreEvent(event) / 3));
			return { event, score: matchScore, reasons, governance: governance?.action ?? "none" };
		})
		.filter((row) => row.score > 0 || row.reasons.some((reason) => reason.startsWith("exact")))
		.sort((left, right) => right.score - left.score || String(right.event.ts).localeCompare(String(left.event.ts)))
		.slice(0, max);
}

function buildWhyReport() {
	const query = flagValue(rawArgs, "--query") ?? positional(rawArgs, 0) ?? "";
	const jsonl = readJsonl(eventsPath);
	const events = jsonl.rows.filter((event) => event && event.kind === "repi-memory-event");
	const matches = explainMatches(events, query);
	return {
		kind: "repi-memory-why-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		root,
		agentDir,
		memoryDir,
		governancePath,
		query,
		ok: true,
		matches: matches.map((row) => ({
			...eventSummary(row.event, row.score),
			reasons: row.reasons,
			governance: row.governance,
			visibleByDefault: row.governance === "none" && row.score > 0,
		})),
	};
}

function findEvent(identifier) {
	const jsonl = readJsonl(eventsPath);
	const events = jsonl.rows.filter((event) => event && event.kind === "repi-memory-event");
	const value = String(identifier ?? "").trim();
	if (!events.length) return undefined;
	if (!value) return events.at(-1);
	const lower = value.toLowerCase();
	return (
		events.find((event) => event.id === value || event.caseSignature === value || event.entryHash === value) ??
		events.find((event) => String(event.id).toLowerCase().includes(lower) || String(event.caseSignature).toLowerCase().includes(lower)) ??
		explainMatches(events, value, 1)[0]?.event
	);
}

function applyGovernance(action) {
	mkdirSync(memoryDir, { recursive: true, mode: 0o700 });
	const identifier = flagValue(rawArgs, "--id") ?? flagValue(rawArgs, "--query") ?? positional(rawArgs, 0) ?? "";
	const reason = flagValue(rawArgs, "--reason") ?? flagValue(rawArgs, "--text") ?? `manual ${action} through repi memory ${action}`;
	const source = findEvent(identifier);
	const ts = new Date().toISOString();
	const decision = {
		kind: "repi-memory-ux-governance-decision",
		schemaVersion: 1,
		id: source
			? `memory-cli:${action}:${source.id}:${sha256(`${ts}:${reason}`).slice(0, 12)}`
			: `memory-cli:${action}:missing:${sha256(`${identifier}:${reason}`).slice(0, 16)}`,
		ts,
		MemoryUxDashboardV16: true,
		append_only_memory_governance: true,
		action,
		applied: Boolean(source),
		sourceEventId: source?.id,
		sourceCaseSignature: source?.caseSignature,
		reason: clip(reason, 360),
		nextCommands: ["repi memory status", `repi memory why ${source?.id ?? JSON.stringify(identifier)}`, "repi memory diff"],
	};
	appendFileSync(governancePath, `${JSON.stringify(decision)}\n`, "utf8");
	return {
		kind: "repi-memory-governance-report",
		schemaVersion: 1,
		generatedAt: ts,
		root,
		agentDir,
		memoryDir,
		governancePath,
		ok: decision.applied,
		decision,
	};
}

function buildReport() {
	const settings = readJson(join(agentDir, "settings.json")) ?? {};
	const memory = settings.memory ?? {};
	const jsonl = readJsonl(eventsPath);
	const events = jsonl.rows.filter((event) => event && event.kind === "repi-memory-event");
	const scored = events
		.filter((event) => !governedSourceIds().has(event.id))
		.map((event) => ({ event, score: scoreEvent(event) }))
		.sort((a, b) => b.score - a.score || String(b.event.ts).localeCompare(String(a.event.ts)));
	const highValue = scored.filter((row) => row.score >= 45);
	const consolidation = readJson(reportPath);
	const consolidatedAt = consolidation?.generatedAt;
	const pending = highValue.filter(({ event }) => all || isAfter(event.ts, consolidatedAt));
	const lastEvent = [...events].sort((a, b) => String(b.ts).localeCompare(String(a.ts)))[0];
	const files = memoryFiles.map(fileInfo);
	const posture = {
		mode: memory.mode ?? "unknown",
		schemaVersion: memory.schemaVersion ?? null,
		autoRecall: memory.autoRecall ?? null,
		autoInject: memory.autoInject ?? null,
		rawAutoInject: memory.rawAutoInject ?? null,
		autoDeposit: memory.autoDeposit ?? null,
		startupDigest: memory.startupDigest ?? null,
		scopePolicy: memory.scopePolicy ?? null,
		contextMemoryMode: memory.contextMemoryMode ?? null,
		includeGlobalMemoryInContextPack: memory.includeGlobalMemoryInContextPack ?? null,
		activeRecall: memory.activeRecall ?? null,
		maxInjectedTokens: memory.maxInjectedTokens ?? null,
	};
	const pollutionGuardOk =
		posture.mode === "scoped" &&
		posture.rawAutoInject === false &&
		posture.autoInject === false &&
		posture.includeGlobalMemoryInContextPack === false;
	return {
		kind: "repi-memory-inspection",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		root,
		agentDir,
		memoryDir,
		posture,
		pollutionGuardOk,
		eventStore: {
			path: eventsPath,
			missing: jsonl.missing,
			invalidLines: jsonl.invalid,
			total: events.length,
			highValue: highValue.length,
			pendingHighValue: pending.length,
			lastEvent: lastEvent ? eventSummary(lastEvent, scoreEvent(lastEvent)) : null,
		},
		consolidation: {
			path: reportPath,
			present: existsSync(reportPath),
			generatedAt: consolidatedAt ?? null,
			selectedCount: consolidation?.selectedCount ?? null,
		},
		files,
		governance: {
			path: governancePath,
			total: governanceRows().length,
			blockingSourceIds: governedSourceIds().size,
		},
		pending: pending.slice(0, limit).map(({ event, score }) => eventSummary(event, score)),
	};
}

function printStatus(report) {
	console.log("REPI Memory Status");
	console.log(`agentDir: ${report.agentDir}`);
	console.log(
		`mode=${report.posture.mode} schema=${report.posture.schemaVersion} autoRecall=${report.posture.autoRecall} autoDeposit=${report.posture.autoDeposit}`,
	);
	console.log(
		`pollutionGuard=${report.pollutionGuardOk ? "pass" : "fail"} rawAutoInject=${report.posture.rawAutoInject} autoInject=${report.posture.autoInject} globalContext=${report.posture.includeGlobalMemoryInContextPack}`,
	);
	console.log(
		`events: total=${report.eventStore.total} highValue=${report.eventStore.highValue} pending=${report.eventStore.pendingHighValue} invalid=${report.eventStore.invalidLines}`,
	);
	console.log(
		`consolidation: ${report.consolidation.present ? report.consolidation.generatedAt : "never"} selected=${report.consolidation.selectedCount ?? 0}`,
	);
	console.log(`governance: rows=${report.governance.total} blockingSourceIds=${report.governance.blockingSourceIds} path=${report.governance.path}`);
	if (report.eventStore.lastEvent) {
		const last = report.eventStore.lastEvent;
		console.log(`lastEvent: ${last.ts ?? "unknown"} id=${last.id} score=${last.score} route=${last.route} target=${last.target}`);
	}
	console.log("files:");
	for (const file of report.files) {
		const status = file.exists ? `${file.bytes} bytes mtime=${file.mtime}` : "missing";
		console.log(`  ${basename(file.path)}: ${status}`);
	}
	console.log("next: repi memory diff && repi memory consolidate --dry-run");
}

function printWhy(report) {
	console.log("REPI Memory Why");
	console.log(`query=${report.query || "<empty>"}`);
	console.log(`governance=${report.governancePath}`);
	if (!report.matches.length) {
		console.log("No matching memory rows.");
		return;
	}
	for (const item of report.matches) {
		console.log(`- id=${item.id} score=${item.score} visible=${item.visibleByDefault} governance=${item.governance}`);
		console.log(`  route=${item.route} target=${item.target} outcome=${item.outcome}`);
		console.log(`  reasons=${item.reasons.join(",") || "none"}`);
		for (const command of item.commands) console.log(`  cmd: ${command}`);
		for (const lesson of item.lessons) console.log(`  lesson: ${lesson}`);
	}
}

function printGovernance(report) {
	const decision = report.decision;
	console.log("REPI Memory Governance");
	console.log(`action=${decision.action} applied=${decision.applied}`);
	console.log(`sourceEventId=${decision.sourceEventId ?? "none"}`);
	console.log(`caseSignature=${decision.sourceCaseSignature ?? "none"}`);
	console.log(`reason=${decision.reason}`);
	console.log(`governanceLedger=${report.governancePath}`);
	for (const next of decision.nextCommands ?? []) console.log(`next: ${next}`);
	console.log(`verdict: ${report.ok ? "pass" : "blocked"}`);
}

function printDiff(report) {
	console.log("REPI Memory Diff");
	console.log(`since: ${all ? "all high-value events" : report.consolidation.generatedAt || "never consolidated"}`);
	console.log(`pendingHighValue=${report.eventStore.pendingHighValue} limit=${limit}`);
	if (!report.pending.length) {
		console.log("No pending high-value memory events.");
		return;
	}
	for (const item of report.pending) {
		console.log(`- id=${item.id} score=${item.score} ts=${item.ts ?? "unknown"}`);
		console.log(`  route=${item.route} target=${item.target} outcome=${item.outcome}`);
		for (const command of item.commands) console.log(`  cmd: ${command}`);
		for (const rule of item.reuseRules) console.log(`  rule: ${rule}`);
		for (const lesson of item.lessons) console.log(`  lesson: ${lesson}`);
	}
}

if (command === "help" || command === "--help" || command === "-h") {
	console.log(usage());
	process.exit(0);
}
if (!["status", "diff", "why", "forget", "quarantine"].includes(command)) {
	console.error(`Unknown memory command: ${command}`);
	console.error(usage());
	process.exit(2);
}

const report =
	command === "why"
		? buildWhyReport()
		: command === "forget" || command === "quarantine"
			? applyGovernance(command)
			: buildReport();
if (json) console.log(JSON.stringify(report, null, 2));
else if (command === "status") printStatus(report);
else if (command === "why") printWhy(report);
else if (command === "forget" || command === "quarantine") printGovernance(report);
else printDiff(report);
process.exit(report.ok === false ? 1 : 0);
