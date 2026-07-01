#!/usr/bin/env node
import { chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { atomicWriteFile, withFileLock, scopedMemoryRootFor } from "./lib/memory-purge-helpers.mjs";

const rawArgs = process.argv.slice(2);
const knownCommands = new Set(["status", "list", "show", "diff", "why", "forget", "quarantine", "doctor", "export", "purge", "sanitize", "repair", "help"]);
// opt #273: --cwd <dir> scopes the memory tree to a specific project
// (recon/memory/projects/<encoded-cwd>/) instead of the legacy global root.
function valueAfterFlag(args, flag) {
	const index = args.indexOf(flag);
	return index >= 0 && index + 1 < args.length ? args[index + 1] : undefined;
}
const cwdScope = valueAfterFlag(rawArgs, "--cwd");
let root = process.cwd();
if (rawArgs[0] && !rawArgs[0].startsWith("--") && !knownCommands.has(rawArgs[0])) {
	root = resolve(rawArgs.shift());
}
const helpRequested = rawArgs.includes("--help") || rawArgs.includes("-h");
const command = helpRequested ? "help" : rawArgs[0] && !rawArgs[0].startsWith("--") ? rawArgs.shift() : "status";
const json = rawArgs.includes("--json");
const all = rawArgs.includes("--all");
const verbose = rawArgs.includes("--verbose") || rawArgs.includes("-v");
const limit = parseLimit(rawArgs, 12);
const agentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const memoryDir = scopedMemoryRootFor(agentDir, cwdScope);
const eventsPath = join(memoryDir, "events.jsonl");
const caseMemoryPath = join(memoryDir, "case-memory.jsonl");
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
	"case-memory.jsonl",
	"consolidation-report.json",
];

function usage() {
	return `Usage:
  repi memory status [--json]
  repi memory list [--json] [--limit N] [--all] [--query <text>] [--verbose]
  repi memory show <query-or-event-id> [--json]
  repi memory diff [--json] [--limit N] [--all]
  repi memory why <query-or-event-id> [--json] [--limit N]
  repi memory forget <query-or-event-id> [--reason <text>] [--json]
  repi memory quarantine <query-or-event-id> [--reason <text>] [--json]
  repi memory doctor [--json]
  repi memory export [--output <path>] [--full] [--limit N] [--json]
  repi memory purge [--dry-run|--apply --yes] [--governed|--older-than-days N|--query <text>|--id <event-id>|--all] [--json]
  repi memory sanitize [--dry-run|--apply --yes] [--include-evidence] [--include-sessions] [--backup] [--json]
  repi memory repair [--dry-run|--apply --yes] [--json]

status  Show scoped memory posture, file sizes, pending consolidation count.
list    List sanitized memory events. By default hides forget/quarantine rows and long lessons; add --verbose for details.
show    Show one sanitized memory event and its governance state.
diff    Show high-value memory events not yet consolidated.
why     Explain which memory rows match a query and why they would be visible.
forget  Append a tombstone governance decision. It does not rewrite history.
quarantine Append a quarantine governance decision. It blocks future recall/injection.
doctor  Check memory pollution posture and store health.
export  Write a sanitized memory diagnostic bundle. API keys/tokens are redacted.
purge   Physically remove selected event rows after creating a .bak backup; default is dry-run. --apply requires --yes.
sanitize Redact leaked API keys/tokens/private API URLs from local memory files; default is dry-run. --apply requires --yes. Raw backups are off by default; add --backup only if you accept keeping pre-redaction copies locally.
repair  Quarantine invalid events/case-memory JSONL rows and rechain events.jsonl when seq/hash drift is detected; default is dry-run. --apply requires --yes.
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

function hasFlag(args, names) {
	const list = Array.isArray(names) ? names : [names];
	return args.some((arg) => list.some((name) => arg === name || arg.startsWith(`${name}=`)));
}

function uniqueValues(values, limit = 2000) {
	const out = [];
	const seen = new Set();
	for (const value of values) {
		const text = String(value ?? "").trim();
		if (!text || seen.has(text)) continue;
		seen.add(text);
		out.push(text);
		if (out.length >= limit) break;
	}
	return out;
}

function numberFlag(args, names, fallback = 0) {
	const raw = flagValue(args, names, "");
	const parsed = Number(raw);
	return Number.isFinite(parsed) ? parsed : fallback;
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

function memoryEventHash(event) {
	const copy = { ...(event ?? {}) };
	delete copy.entryHash;
	return sha256(JSON.stringify(copy));
}

function analyzeEventChain(events) {
	const errors = [];
	let prevHash = "0".repeat(64);
	for (const [index, event] of events.entries()) {
		const expectedSeq = index + 1;
		if (event.seq !== expectedSeq) errors.push(`events:${event.id ?? `line-${expectedSeq}`}:seq_expected_${expectedSeq}_got_${event.seq}`);
		if (event.prevHash !== prevHash) errors.push(`events:${event.id ?? `line-${expectedSeq}`}:prev_hash_mismatch`);
		const expectedHash = memoryEventHash(event);
		if (event.entryHash !== expectedHash) errors.push(`events:${event.id ?? `line-${expectedSeq}`}:entry_hash_mismatch`);
		prevHash = event.entryHash || expectedHash;
	}
	return {
		ok: errors.length === 0,
		errors,
		latestEventHash: events.at(-1)?.entryHash ?? "0".repeat(64),
	};
}

function rechainMemoryEvents(events) {
	let prevHash = "0".repeat(64);
	return events.map((event, index) => {
		const row = { ...event, seq: index + 1, prevHash, entryHash: "" };
		row.entryHash = memoryEventHash(row);
		prevHash = row.entryHash;
		return row;
	});
}

function appendGovernanceDecision(decision) {
	mkdirSync(memoryDir, { recursive: true, mode: 0o700 });
	withFileLock(governancePath, () => {
		const previous = existsSync(governancePath) ? readFileSync(governancePath, "utf8") : "";
		const separator = previous && !previous.endsWith("\n") ? "\n" : "";
		atomicWriteFile(governancePath, `${previous}${separator}${JSON.stringify(decision)}\n`, 0o600);
	});
	try {
		chmodSync(governancePath, 0o600);
	} catch {
		// Best-effort on non-POSIX filesystems.
	}
}

function redactSensitiveRaw(value) {
	return String(value ?? "")
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\b(?:A3T|AKIA|ASIA)[A-Z0-9]{16}\b/g, "<redacted:aws-access-key>")
		.replace(/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, "<redacted:slack-token>")
		.replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "<redacted:jwt>")
		.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "<redacted:private-key>")
		.replace(/(https?:\/\/)[^/\s:@]+:[^/\s@]+@/gi, "$1<redacted:credentials>@")
		.replace(/((?:baseUrl|baseURL|endpoint|url)"?\s*[:=]\s*"?)(https?:\/\/[^\s"',}]+)/gi, (_match, prefix, url) => `${prefix}<redacted:url:${sha256(url).slice(0, 16)}>`)
		.replace(/\bhttps?:\/\/api\.[^\s"',}<)]+/gi, (url) => `<redacted:url:${sha256(url).slice(0, 16)}>`)
		.replace(/(?:AUTH_TOKEN|API_KEY|PASSWORD|SECRET|TOKEN|ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|CLIENT_SECRET)=\S+/gi, (match) => `${match.split("=")[0]}=<redacted>`)
		.replace(/(authorization|x-api-key|api-key)\s*[:=]\s*bearer\s+[A-Za-z0-9._-]+/gi, "$1: Bearer <redacted>")
		.replace(/(authorization|x-api-key|api-key)\s*[:=]\s*[A-Za-z0-9._-]{12,}/gi, "$1: <redacted>")
		.replace(/(cookie|set-cookie)\s*[:=]\s*[^\n\r]+/gi, "$1: <redacted>");
}

function redact(value) {
	return redactSensitiveRaw(value)
		.replace(/\s+/g, " ")
		.trim();
}

function clip(value, max = 260) {
	const text = redact(value);
	return text.length > max ? `${text.slice(0, max - 14)}...<truncated>` : text;
}

function normalizeRouteLabel(value) {
	const raw = String(value ?? "").trim();
	if (!raw) return "unknown";
	if (/^Agent \/ LLM security$/i.test(raw)) return "Agent / LLM boundary";
	if (/^Web \/ API security$/i.test(raw)) return "Web / API pentest";
	if (/^Security general$/i.test(raw)) return "Reverse/Pentest general";
	return raw
		.replace(/\bAgent \/ LLM security\b/gi, "Agent / LLM boundary")
		.replace(/\bWeb \/ API security\b/gi, "Web / API pentest")
		.replace(/\bSecurity general\b/gi, "Reverse/Pentest general")
		.replace(/\bred[- ]team\b/gi, "reverse/pentest");
}

function redactJson(value, depth = 0) {
	if (depth > 8) return "<truncated-depth>";
	if (value === null || value === undefined) return value;
	if (typeof value === "string") return clip(value, 1200);
	if (typeof value === "number" || typeof value === "boolean") return value;
	if (Array.isArray(value)) return value.slice(0, 200).map((item) => redactJson(item, depth + 1));
	if (typeof value === "object") {
		const out = {};
		for (const [key, inner] of Object.entries(value)) {
			if (/api[-_]?key|auth|authorization|password|secret|token/i.test(key)) {
				out[key] = "<redacted>";
			} else if (key === "route" && typeof inner === "string") {
				out[key] = clip(normalizeRouteLabel(inner), 1200);
			} else {
				out[key] = redactJson(inner, depth + 1);
			}
		}
		return out;
	}
	return clip(String(value), 1200);
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

function eventSummary(event, score, options = {}) {
	const summary = {
		id: redact(event.id ?? "unknown"),
		ts: safeTime(event.ts),
		score,
		outcome: redact(event.outcome ?? "unknown"),
		route: clip(normalizeRouteLabel(event.route), 120),
		target: clip(event.target ?? "workspace", 160),
	};
	if (options.details !== false) {
		summary.commands = (event.commands ?? []).slice(0, 3).map((value) => clip(value, 260));
		summary.reuseRules = (event.reuseRules ?? []).slice(0, 3).map((value) => clip(value, 260));
		summary.lessons = (event.lessons ?? []).slice(0, 3).map((value) => clip(value, 260));
	}
	return summary;
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
		normalizeRouteLabel(event.route),
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

function loadMemoryEvents() {
	const jsonl = readJsonl(eventsPath);
	return {
		jsonl,
		events: jsonl.rows.filter((event) => event && event.kind === "repi-memory-event"),
	};
}

function buildListReport() {
	const query = flagValue(rawArgs, "--query");
	const { jsonl, events } = loadMemoryEvents();
	const governed = governedSourceIds();
	let rows = query
		? explainMatches(events, query, limit).map((row) => ({ event: row.event, score: row.score, reasons: row.reasons, governance: row.governance }))
		: events
				.map((event) => ({ event, score: scoreEvent(event), reasons: [], governance: governed.get(event.id)?.action ?? "none" }))
				.sort((left, right) => String(right.event.ts).localeCompare(String(left.event.ts)));
	if (!all) rows = rows.filter((row) => row.governance === "none");
	rows = rows.slice(0, limit);
	return {
		kind: "repi-memory-list-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		root,
		agentDir,
		memoryDir,
		eventsPath,
		query: query ?? null,
		totalEvents: events.length,
		returned: rows.length,
		invalidLines: jsonl.invalid,
		ok: true,
		rows: rows.map((row) => ({
			...eventSummary(row.event, row.score, { details: verbose }),
			reasons: row.reasons,
			governance: row.governance,
			visibleByDefault: row.governance === "none",
		})),
	};
}

function buildShowReport() {
	const identifier = flagValue(rawArgs, "--id") ?? flagValue(rawArgs, "--query") ?? positional(rawArgs, 0) ?? "";
	const event = findEvent(identifier);
	const governance = event ? governedSourceIds().get(event.id)?.action ?? "none" : "none";
	return {
		kind: "repi-memory-show-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		root,
		agentDir,
		memoryDir,
		eventsPath,
		ok: Boolean(event),
		query: identifier,
		governance,
		summary: event ? eventSummary(event, scoreEvent(event)) : null,
		event: event ? redactJson(event) : null,
		error: event ? undefined : `memory event not found: ${identifier || "<latest>"}`,
	};
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
	appendGovernanceDecision(decision);
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
	const caseJsonl = readJsonl(caseMemoryPath);
	const events = jsonl.rows.filter((event) => event && event.kind === "repi-memory-event");
	const eventChain = analyzeEventChain(events);
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
			chainOk: eventChain.ok,
			chainErrors: eventChain.errors.slice(0, 24),
			total: events.length,
			highValue: highValue.length,
			pendingHighValue: pending.length,
			lastEvent: lastEvent ? eventSummary(lastEvent, scoreEvent(lastEvent), { details: false }) : null,
		},
		caseStore: {
			path: caseMemoryPath,
			missing: caseJsonl.missing,
			invalidLines: caseJsonl.invalid,
			total: caseJsonl.rows.filter((row) => row && row.kind === "repi-case-memory").length,
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
		pending: pending.slice(0, limit).map(({ event, score }) => eventSummary(event, score, { details: false })),
	};
}

function buildDoctorReport() {
	const status = buildReport();
	const { events } = loadMemoryEvents();
	const governed = governedSourceIds();
	const referenced = new Set(events.map((event) => event.id));
	const orphanGovernance = governanceRows().filter((row) => {
		const source = String(row.sourceEventId ?? row.eventId ?? "").trim();
		return source && !referenced.has(source);
	});
	const diagnostics = [];
	const secretScanRows = [];
	for (const path of walkTextFiles(memoryDir, 2000)) {
		let before = "";
		try {
			before = readFileSync(path, "utf8");
		} catch {
			continue;
		}
		if (redactSensitiveRaw(before) === before) continue;
		secretScanRows.push({ path, sha256: sha256(before).slice(0, 16), bytes: before.length });
		if (secretScanRows.length >= 24) break;
	}
	if (!status.pollutionGuardOk) diagnostics.push({ level: "fail", id: "pollution-guard", message: "scoped memory defaults are not pollution-safe" });
	if (status.eventStore.invalidLines > 0) diagnostics.push({ level: "fail", id: "invalid-jsonl", message: `${status.eventStore.invalidLines} invalid events.jsonl lines` });
	if (status.eventStore.chainOk === false) diagnostics.push({ level: "fail", id: "event-hash-chain", message: `${status.eventStore.chainErrors.length} events.jsonl seq/hash-chain errors; run repi memory repair --apply --yes` });
	if ((status.caseStore?.invalidLines ?? 0) > 0) diagnostics.push({ level: "fail", id: "invalid-case-jsonl", message: `${status.caseStore.invalidLines} invalid case-memory.jsonl lines` });
	if (status.posture.rawAutoInject === true || status.posture.autoInject === true) diagnostics.push({ level: "fail", id: "raw-auto-inject", message: "raw/full memory injection is enabled" });
	if (status.posture.contextMemoryMode === "global" || status.posture.includeGlobalMemoryInContextPack === true) diagnostics.push({ level: "fail", id: "global-context-memory", message: "global memory context injection is enabled" });
	if (secretScanRows.length) diagnostics.push({ level: "fail", id: "memory-secret-scan", message: `${secretScanRows.length} memory files still contain redaction matches; run repi memory sanitize --dry-run` });
	if (orphanGovernance.length) diagnostics.push({ level: "warn", id: "orphan-governance", message: `${orphanGovernance.length} governance rows reference missing events` });
	for (const file of status.files) {
		if (file.exists && file.bytes > 256 * 1024 && /(?:core|project|procedural)-memory\.md/.test(file.name)) {
			diagnostics.push({ level: "warn", id: `large-${file.name}`, message: `${file.name} is ${file.bytes} bytes; consider repi memory consolidate/purge` });
		}
	}
	return {
		kind: "repi-memory-doctor-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		root,
		agentDir,
		memoryDir,
		status,
		governedSourceIds: governed.size,
		orphanGovernance: orphanGovernance.slice(0, 24).map((row) => redactJson(row)),
		secretScanRows,
		diagnostics,
		ok: !diagnostics.some((item) => item.level === "fail"),
	};
}

function buildExportReport() {
	const output = flagValue(rawArgs, ["--output", "-o"]);
	const full = rawArgs.includes("--full");
	const status = buildReport();
	const { events } = loadMemoryEvents();
	const governed = governedSourceIds();
	const rows = events
		.map((event) => ({ event, score: scoreEvent(event), governance: governed.get(event.id)?.action ?? "none" }))
		.sort((left, right) => String(right.event.ts).localeCompare(String(left.event.ts)))
		.slice(0, full ? Math.max(limit, 200) : limit);
	const bundle = {
		kind: "repi-memory-export-bundle",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		root,
		agentDir,
		memoryDir,
		status,
		rows: rows.map((row) => ({
			summary: eventSummary(row.event, row.score),
			governance: row.governance,
			...(full ? { event: redactJson(row.event) } : {}),
		})),
		governance: governanceRows().slice(-Math.max(limit, 50)).map((row) => redactJson(row)),
		redaction: "API keys, tokens, passwords, authorization fields, and long strings are redacted/truncated",
	};
	if (output) {
		const outputPath = resolve(output);
		try {
			mkdirSync(dirname(outputPath), { recursive: true, mode: 0o700 });
			atomicWriteFile(outputPath, `${JSON.stringify(bundle, null, 2)}\n`, 0o600);
		} catch (error) {
			// opt #176/#278: export writes are temp+rename and still surfaced
			// as a structured ok:false report on ENOSPC/EACCES.
			const message = error instanceof Error ? error.message : String(error);
			console.error(`repi memory export: failed to write output ${outputPath}: ${message}`);
			return {
				kind: "repi-memory-export-report",
				schemaVersion: 1,
				generatedAt: new Date().toISOString(),
				ok: false,
				outputPath,
				error: `failed to write output: ${message}`,
			};
		}
	}
	return {
		kind: "repi-memory-export-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: true,
		outputPath: output ? resolve(output) : null,
		bundle,
	};
}

function selectPurgeCandidates(events) {
	const governed = governedSourceIds();
	const id = flagValue(rawArgs, "--id");
	const query = flagValue(rawArgs, "--query");
	const olderThanDays = numberFlag(rawArgs, "--older-than-days", 0);
	const purgeAll = rawArgs.includes("--all");
	const purgeGoverned = rawArgs.includes("--governed");
	const selected = new Map();
	if (id) {
		for (const event of events) {
			if (event.id === id || event.caseSignature === id || event.entryHash === id) selected.set(event.id, "id");
		}
	}
	if (query) {
		for (const row of explainMatches(events, query, 200)) selected.set(row.event.id, "query");
	}
	if (purgeGoverned) {
		for (const event of events) {
			if (governed.has(event.id)) selected.set(event.id, `governed:${governed.get(event.id).action}`);
		}
	}
	if (olderThanDays > 0) {
		const cutoff = Date.now() - olderThanDays * 24 * 60 * 60 * 1000;
		for (const event of events) {
			const ts = new Date(event.ts ?? 0).getTime();
			if (Number.isFinite(ts) && ts < cutoff) selected.set(event.id, `older-than:${olderThanDays}d`);
		}
	}
	if (purgeAll) {
		for (const event of events) selected.set(event.id, "all");
	}
	return { selected, filters: { id, query, olderThanDays, purgeGoverned, purgeAll } };
}

function buildPurgeReport() {
	const { jsonl, events } = loadMemoryEvents();
	const { selected, filters } = selectPurgeCandidates(events);
	const apply = rawArgs.includes("--apply") && !rawArgs.includes("--dry-run");
	const confirmed = rawArgs.includes("--yes") || rawArgs.includes("-y") || process.env.REPI_MEMORY_PURGE_CONFIRM === "1";
	const hasFilter = Boolean(filters.id || filters.query || filters.olderThanDays > 0 || filters.purgeGoverned || filters.purgeAll);
	if (!hasFilter) {
		return {
			kind: "repi-memory-purge-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: "memory purge requires at least one selector: --governed, --older-than-days N, --query <text>, --id <event-id>, or --all",
		};
	}
	if (apply && !confirmed) {
		return {
			kind: "repi-memory-purge-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			apply,
			confirmed,
			eventsPath,
			totalEvents: events.length,
			invalidLines: jsonl.invalid,
			candidateCount: selected.size,
			removedCount: 0,
			filters,
			error: "memory purge --apply requires --yes (or REPI_MEMORY_PURGE_CONFIRM=1). Run without --apply first to preview candidates.",
			next: ["repi memory purge --dry-run <same selectors>", "repi memory purge --apply --yes <same selectors>"],
		};
	}
	const candidateRows = events
		.filter((event) => selected.has(event.id))
		.map((event) => ({ ...eventSummary(event, scoreEvent(event)), purgeReason: selected.get(event.id) }))
		.slice(0, limit);
	const ts = new Date().toISOString().replace(/[:.]/g, "-");
	const backupPath = `${eventsPath}.bak-${ts}`;
	let removed = 0;
	if (apply && selected.size > 0) {
		mkdirSync(memoryDir, { recursive: true, mode: 0o700 });
		// Lock the events.jsonl RMW so a concurrent runtime appendFile (or a
		// racing second purge) cannot interleave: previously the purge did an
		// unlocked copy→read→filter→writeFileSync (truncate-then-rewrite), so
		// an in-flight append was silently lost and a crash mid-write left a
		// truncated events log. withFileLock (proper-lockfile) serializes the
		// RMW across processes; atomicWriteFile (temp+rename, same-dir) ensures
		// a crash mid-write leaves the prior events log intact. opt #176.
		withFileLock(eventsPath, () => {
			if (existsSync(eventsPath)) copyFileSync(eventsPath, backupPath);
			const nextLines = [];
			for (const line of readFileSync(eventsPath, "utf8").split(/\r?\n/)) {
				if (!line.trim()) continue;
				let row;
				try {
					row = JSON.parse(line);
				} catch {
					nextLines.push(line);
					continue;
				}
				if (row?.kind === "repi-memory-event" && selected.has(row.id)) {
					removed++;
					continue;
				}
				nextLines.push(line);
			}
			atomicWriteFile(eventsPath, `${nextLines.join("\n")}${nextLines.length ? "\n" : ""}`, 0o600);
		});
		appendGovernanceDecision({
				kind: "repi-memory-ux-governance-decision",
				schemaVersion: 1,
				id: `memory-cli:purge:${sha256(`${ts}:${[...selected.keys()].join(",")}`).slice(0, 16)}`,
				ts: new Date().toISOString(),
				MemoryUxDashboardV16: true,
				action: "purge",
				applied: true,
				removedEventIds: [...selected.keys()].slice(0, 500),
				reason: clip(flagValue(rawArgs, "--reason", "manual purge through repi memory purge"), 360),
				backupPath,
			});
	}
	return {
		kind: "repi-memory-purge-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: true,
		apply,
		confirmed,
		eventsPath,
		backupPath: apply && selected.size > 0 ? backupPath : null,
		totalEvents: events.length,
		invalidLines: jsonl.invalid,
		candidateCount: selected.size,
		removedCount: removed,
		filters,
		candidates: candidateRows,
		next: apply ? ["repi memory doctor", "repi memory list"] : ["repi memory purge --apply --yes <same selectors>", "repi memory show <event-id>"],
	};
}

function walkTextFiles(rootDir, maxFiles = 2000) {
	const out = [];
	const stack = [rootDir];
	while (stack.length && out.length < maxFiles) {
		const dir = stack.pop();
		if (!dir || !existsSync(dir)) continue;
		for (const entry of readdirSync(dir, { withFileTypes: true })) {
			const path = join(dir, entry.name);
			if (entry.isDirectory()) {
				if (/node_modules|\.git|transactions$/.test(path)) continue;
				stack.push(path);
				continue;
			}
			if (!entry.isFile()) continue;
			if (!/\.(?:json|jsonl|md|txt|log)$/i.test(entry.name)) continue;
			if (/\.bak-|\.tmp$/.test(entry.name)) continue;
			out.push(path);
			if (out.length >= maxFiles) break;
		}
	}
	return out;
}

function buildSanitizeReport() {
	const apply = rawArgs.includes("--apply") && !rawArgs.includes("--dry-run");
	const confirmed = rawArgs.includes("--yes") || rawArgs.includes("-y") || process.env.REPI_MEMORY_SANITIZE_CONFIRM === "1";
	const backup = rawArgs.includes("--backup") && !rawArgs.includes("--no-backup");
	const roots = [memoryDir];
	if (rawArgs.includes("--include-evidence")) roots.push(join(agentDir, "recon", "evidence"));
	if (rawArgs.includes("--include-sessions")) roots.push(join(agentDir, "sessions"));
	const files = uniqueValues(roots.flatMap((dir) => walkTextFiles(dir, 4000)), 8000);
	const rows = [];
	const writeErrors = [];
	const ts = new Date().toISOString().replace(/[:.]/g, "-");
	for (const path of files) {
		let before = "";
		try {
			before = readFileSync(path, "utf8");
		} catch {
			continue;
		}
		const after = redactSensitiveRaw(before);
		if (after === before) continue;
		rows.push({
			path,
			bytes: before.length,
			redactedBytes: after.length,
			backupPath: apply && backup ? `${path}.bak-${ts}` : null,
		});
		if (apply && confirmed) {
			if (backup) copyFileSync(path, `${path}.bak-${ts}`);
			// opt #176/#278: temp+rename prevents a crash mid-sanitize from
			// truncating the target file; failures are still recorded so the
			// final report exits non-zero instead of throwing.
			try {
				atomicWriteFile(path, after, 0o600);
				try {
					chmodSync(path, 0o600);
				} catch {
					// Best-effort on non-POSIX filesystems.
				}
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				console.error(`repi memory sanitize: failed to write ${path}: ${message}`);
				writeErrors.push({ path, error: message });
			}
		}
	}
	if (apply && !confirmed) {
		return {
			kind: "repi-memory-sanitize-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			apply,
			confirmed,
			backup,
			roots,
			scannedFiles: files.length,
			changedFiles: rows.length,
			error: "memory sanitize --apply requires --yes (or REPI_MEMORY_SANITIZE_CONFIRM=1). Run without --apply first to preview changed files.",
			rows: rows.slice(0, limit),
			next: ["repi memory sanitize --dry-run", "repi memory sanitize --apply --yes"],
		};
	}
	return {
		kind: "repi-memory-sanitize-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: writeErrors.length === 0,
		apply,
		confirmed,
		backup,
		roots,
		scannedFiles: files.length,
		changedFiles: rows.length,
		writeErrors: writeErrors.length ? writeErrors.slice(0, limit) : undefined,
		error: writeErrors.length ? `${writeErrors.length} file(s) failed to write during sanitize; see writeErrors` : undefined,
		rows: rows.slice(0, limit),
		next: apply ? ["repi memory doctor", "repi memory list"] : ["repi memory sanitize --apply --yes"],
	};
}

function buildRepairReport() {
	const apply = rawArgs.includes("--apply") && !rawArgs.includes("--dry-run");
	const confirmed = rawArgs.includes("--yes") || rawArgs.includes("-y") || process.env.REPI_MEMORY_REPAIR_CONFIRM === "1";
	const ts = new Date().toISOString().replace(/[:.]/g, "-");
	const stores = [
		{ label: "events", path: eventsPath, quarantinePath: join(memoryDir, `events.invalid-${ts}.jsonl`) },
		{ label: "case-memory", path: caseMemoryPath, quarantinePath: join(memoryDir, `case-memory.invalid-${ts}.jsonl`) },
	];
	const files = stores.map((store) => {
		let text = "";
		try {
			text = readFileSync(store.path, "utf8");
		} catch {
			return {
				...store,
				missing: true,
				validLines: [],
				invalidRows: [],
			};
		}
		const validLines = [];
		const invalidRows = [];
		for (const [index, line] of text.split(/\r?\n/).entries()) {
			if (!line.trim()) continue;
			try {
				JSON.parse(line);
				validLines.push(line);
			} catch (error) {
				invalidRows.push({
					file: store.label,
					path: store.path,
					line: index + 1,
					error: error instanceof Error ? error.message : String(error),
					sha256: sha256(line),
					redactedPreview: redactSensitiveRaw(line).slice(0, 1200),
				});
			}
		}
		return {
			...store,
			missing: false,
			validLines,
			invalidRows,
		};
	});
	const validLines = files.reduce((sum, file) => sum + file.validLines.length, 0);
	const invalidRows = files.flatMap((file) => file.invalidRows);
	const firstQuarantinePath = files.find((file) => file.invalidRows.length > 0)?.quarantinePath ?? null;
	const eventFile = files.find((file) => file.label === "events");
	const eventRows = (eventFile?.validLines ?? [])
		.map((line) => {
			try {
				return JSON.parse(line);
			} catch {
				return undefined;
			}
		})
		.filter((row) => row && row.kind === "repi-memory-event");
	const eventChain = analyzeEventChain(eventRows);
	const eventChainRepair = {
		needed: eventRows.length > 0 && !eventChain.ok,
		errors: eventChain.errors.slice(0, limit),
		rehashedRows: 0,
		backupPath: null,
	};
	if (apply && (invalidRows.length > 0 || eventChainRepair.needed) && !confirmed) {
		return {
			kind: "repi-memory-repair-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			apply,
			confirmed,
			eventsPath,
			caseMemoryPath,
			validLines,
			invalidLines: invalidRows.length,
			quarantinePath: null,
			files: files.map((file) => ({
				label: file.label,
				path: file.path,
				missing: file.missing,
				validLines: file.validLines.length,
				invalidLines: file.invalidRows.length,
				quarantinePath: file.invalidRows.length ? file.quarantinePath : null,
			})),
			eventChainRepair,
			error: "memory repair --apply requires --yes (or REPI_MEMORY_REPAIR_CONFIRM=1). Run without --apply first to preview invalid lines/hash-chain drift.",
			invalidRows: invalidRows.slice(0, limit),
		};
	}
	if (apply && (invalidRows.length > 0 || eventChainRepair.needed)) {
		mkdirSync(memoryDir, { recursive: true, mode: 0o700 });
		for (const file of files) {
			if (file.missing) continue;
			const shouldWrite = file.invalidRows.length > 0 || (file.label === "events" && eventChainRepair.needed);
			if (!shouldWrite) continue;
			let nextLines = file.validLines;
			if (file.label === "events" && eventChainRepair.needed) {
				const backupPath = join(memoryDir, `events.repair-backup-${ts}.jsonl`);
				copyFileSync(file.path, backupPath);
				eventChainRepair.backupPath = backupPath;
				const rechained = rechainMemoryEvents(eventRows);
				eventChainRepair.rehashedRows = rechained.length;
				nextLines = rechained.map((row) => JSON.stringify(row));
			}
			atomicWriteFile(file.path, `${nextLines.join("\n")}${nextLines.length ? "\n" : ""}`, 0o600);
			if (file.invalidRows.length) atomicWriteFile(file.quarantinePath, `${file.invalidRows.map((row) => JSON.stringify(row)).join("\n")}\n`, 0o600);
			try {
				chmodSync(file.path, 0o600);
				if (file.invalidRows.length) chmodSync(file.quarantinePath, 0o600);
				if (eventChainRepair.backupPath) chmodSync(eventChainRepair.backupPath, 0o600);
			} catch {
				// Best-effort on non-POSIX filesystems.
			}
		}
	}
	return {
		kind: "repi-memory-repair-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: true,
		apply,
		confirmed,
		eventsPath,
		caseMemoryPath,
		validLines,
		invalidLines: invalidRows.length,
			quarantinePath: firstQuarantinePath,
		files: files.map((file) => ({
			label: file.label,
			path: file.path,
			missing: file.missing,
			validLines: file.validLines.length,
			invalidLines: file.invalidRows.length,
			quarantinePath: file.invalidRows.length ? file.quarantinePath : null,
		})),
		eventChainRepair,
		invalidRows: invalidRows.slice(0, limit),
		next: apply ? ["repi memory doctor", "repi memory status"] : ["repi memory repair --apply --yes"],
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
		`events: total=${report.eventStore.total} highValue=${report.eventStore.highValue} pending=${report.eventStore.pendingHighValue} invalid=${report.eventStore.invalidLines} chain=${report.eventStore.chainOk ? "pass" : "fail"}`,
	);
	if (report.caseStore) console.log(`case-memory: total=${report.caseStore.total} invalid=${report.caseStore.invalidLines}`);
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

function printList(report) {
	console.log("REPI Memory List");
	console.log(`events=${report.totalEvents} returned=${report.returned} invalid=${report.invalidLines} query=${report.query ?? "<none>"}`);
	if (!report.rows.length) {
		console.log("No memory events matched.");
		return;
	}
	for (const item of report.rows) {
		console.log(`- id=${item.id} score=${item.score} ts=${item.ts ?? "unknown"} governance=${item.governance}`);
		console.log(`  route=${item.route} target=${item.target} outcome=${item.outcome}`);
		if (verbose) {
			for (const command of item.commands) console.log(`  cmd: ${command}`);
			for (const rule of item.reuseRules) console.log(`  rule: ${rule}`);
			for (const lesson of item.lessons) console.log(`  lesson: ${lesson}`);
		}
	}
	if (!verbose) console.log("hint: add --verbose to print commands, reuse rules, and lessons.");
}

function printShow(report) {
	if (!report.ok) {
		console.error(report.error);
		return;
	}
	console.log("REPI Memory Show");
	console.log(`id=${report.summary.id} score=${report.summary.score} governance=${report.governance}`);
	console.log(`ts=${report.summary.ts ?? "unknown"} route=${report.summary.route} target=${report.summary.target}`);
	console.log(JSON.stringify(report.event, null, 2));
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

function printDoctor(report) {
	console.log("REPI Memory Doctor");
	console.log(`agentDir=${report.agentDir}`);
	console.log(`pollutionGuard=${report.status.pollutionGuardOk ? "pass" : "fail"} events=${report.status.eventStore.total} invalid=${report.status.eventStore.invalidLines}`);
	for (const diagnostic of report.diagnostics) console.log(`${diagnostic.level.toUpperCase()} ${diagnostic.id}: ${diagnostic.message}`);
	for (const item of report.secretScanRows ?? []) console.log(`secret-scan path=${item.path} bytes=${item.bytes} sha256=${item.sha256}`);
	console.log(`verdict: ${report.ok ? "pass" : "fail"}`);
}

function printExport(report) {
	if (!report.ok) {
		console.error(report.error);
		return;
	}
	if (report.outputPath) {
		console.log("REPI Memory Export");
		console.log(`output=${report.outputPath}`);
		console.log(`events=${report.bundle.status.eventStore.total} rows=${report.bundle.rows.length}`);
		console.log(report.bundle.redaction);
		return;
	}
	console.log(JSON.stringify(report.bundle, null, 2));
}

function printPurge(report) {
	if (!report.ok) {
		console.error(report.error);
		return;
	}
	console.log("REPI Memory Purge");
	console.log(`apply=${report.apply} candidates=${report.candidateCount} removed=${report.removedCount}`);
	if (report.backupPath) console.log(`backup=${report.backupPath}`);
	for (const item of report.candidates) {
		console.log(`- id=${item.id} reason=${item.purgeReason} ts=${item.ts ?? "unknown"} route=${item.route} target=${item.target}`);
	}
	for (const next of report.next ?? []) console.log(`next: ${next}`);
	console.log(`verdict: ${report.ok ? "pass" : "fail"}`);
}

function printSanitize(report) {
	if (!report.ok) {
		console.error(report.error);
		return;
	}
	console.log("REPI Memory Sanitize");
	console.log(`apply=${report.apply} scanned=${report.scannedFiles} changed=${report.changedFiles}`);
	for (const item of report.rows) {
		console.log(`- path=${item.path} bytes=${item.bytes} backup=${item.backupPath ?? "<none>"}`);
	}
	for (const next of report.next ?? []) console.log(`next: ${next}`);
	console.log(`verdict: ${report.ok ? "pass" : "fail"}`);
}

function printRepair(report) {
	if (!report.ok) {
		console.error(report.error);
		return;
	}
	console.log("REPI Memory Repair");
	console.log(`apply=${report.apply} valid=${report.validLines} invalid=${report.invalidLines}`);
	for (const file of report.files ?? []) {
		console.log(`- ${file.label}: valid=${file.validLines} invalid=${file.invalidLines} path=${file.path}`);
		if (file.quarantinePath) console.log(`  quarantine=${file.quarantinePath}`);
	}
	if (report.eventChainRepair?.needed) {
		console.log(`event-chain-repair: rehashed=${report.eventChainRepair.rehashedRows} backup=${report.eventChainRepair.backupPath ?? "<pending>"}`);
		for (const error of report.eventChainRepair.errors ?? []) console.log(`  chain: ${error}`);
	}
	for (const item of report.invalidRows ?? []) console.log(`- ${item.file ?? "jsonl"}:${item.line} sha256=${item.sha256.slice(0, 16)} error=${item.error}`);
	for (const next of report.next ?? []) console.log(`next: ${next}`);
	console.log(`verdict: ${report.ok ? "pass" : "fail"}`);
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
if (!["status", "list", "show", "diff", "why", "forget", "quarantine", "doctor", "export", "purge", "sanitize", "repair"].includes(command)) {
	console.error(`Unknown memory command: ${command}`);
	console.error(usage());
	process.exit(2);
}

const report =
	command === "list"
		? buildListReport()
		: command === "show"
			? buildShowReport()
			: command === "why"
		? buildWhyReport()
		: command === "forget" || command === "quarantine"
			? applyGovernance(command)
			: command === "doctor"
				? buildDoctorReport()
				: command === "export"
					? buildExportReport()
					: command === "purge"
						? buildPurgeReport()
						: command === "sanitize"
							? buildSanitizeReport()
							: command === "repair"
								? buildRepairReport()
								: buildReport();
if (json) console.log(JSON.stringify(report, null, 2));
else if (command === "status") printStatus(report);
else if (command === "list") printList(report);
else if (command === "show") printShow(report);
else if (command === "why") printWhy(report);
else if (command === "forget" || command === "quarantine") printGovernance(report);
else if (command === "doctor") printDoctor(report);
else if (command === "export") printExport(report);
else if (command === "purge") printPurge(report);
else if (command === "sanitize") printSanitize(report);
else if (command === "repair") printRepair(report);
else printDiff(report);
process.exit(report.ok === false ? 1 : 0);
