import { statSync } from "node:fs";
import type { CaseMemoryV1 } from "./case-memory.ts";
import { cachedJsonlDerived, jsonlRecords } from "./jsonl.ts";
import { isMemoryEvent, type MemoryEventV1 } from "./memory-event.ts";
import {
	caseMemoryPath,
	ensureRepiStorage,
	memoryEventsPath,
	memoryGovernanceLedgerPath,
	readTextFile,
	writePrivateTextFile,
} from "./storage.ts";
import { truncateMiddle, uniqueNonEmpty } from "./text.ts";

export type MemoryRetrievalHit = {
	event: MemoryEventV1;
	score: number;
	reasons: string[];
};

// opt #74 — the governance ledger predicate is a STABLE module-level function ref (not a
// fresh inline literal per call) so jsonl.ts's parsed-rows cache can key on the predicate
// reference. A fresh-literal predicate would have a new ref every call → cache always
// misses → no parse-cache win. One predicate per ledger path; the ref is invariant.
export type MemoryGovernanceLedgerRowV8 = {
	action?: string;
	applied?: boolean;
	sourceEventId?: string;
	eventId?: string;
	reason?: string;
	id?: string;
};

export function isMemoryGovernanceLedgerRow(value: unknown): value is MemoryGovernanceLedgerRowV8 {
	if (typeof value !== "object" || value === null) return false;
	const row = value as MemoryGovernanceLedgerRowV8;
	return typeof row.action === "string" && (typeof row.sourceEventId === "string" || typeof row.eventId === "string");
}

// opt #107: the governance ledger is an append-only jsonl file (no hash-chain
// fields — rows have no prevHash/entryHash/seq, so the head is disposable without
// re-hash, same contract as case-memory #99). It was appended via bare
// `writeFileSync(flag:"a")` (non-atomic — a crash mid-append leaves a partial
// trailing JSON line that jsonlRecords silently drops per-line) and had NO
// rotation cap, so it grew unbounded over a session and every cold read parsed
// the whole file. The append sites now use the shared atomic appendPrivateTextFile
// (#67), and this rotation caps on-disk rows to the last
// REPI_GOVERNANCE_LEDGER_MAX_ROWS (default 500, 0=disable). Raw-line tail-keep
// preserves unparseable rows verbatim. Atomic rewrite via writePrivateTextFile.
const DEFAULT_GOVERNANCE_LEDGER_MAX_ROWS = 500;
const ENV_GOVERNANCE_LEDGER_MAX_ROWS = "REPI_GOVERNANCE_LEDGER_MAX_ROWS";

export function governanceLedgerMaxRows(): number {
	const raw = process.env[ENV_GOVERNANCE_LEDGER_MAX_ROWS];
	if (raw === undefined) return DEFAULT_GOVERNANCE_LEDGER_MAX_ROWS;
	const parsed = Number.parseInt(raw, 10);
	if (Number.isNaN(parsed)) return DEFAULT_GOVERNANCE_LEDGER_MAX_ROWS;
	return parsed < 0 ? DEFAULT_GOVERNANCE_LEDGER_MAX_ROWS : parsed;
}

export function rotateGovernanceLedgerIfNeeded(): void {
	const cap = governanceLedgerMaxRows();
	if (cap === 0) return;
	ensureRepiStorage();
	const path = memoryGovernanceLedgerPath();
	const text = readTextFile(path);
	const lines = text.split(/\r?\n/).filter((line) => line.trim());
	if (lines.length <= cap) return;
	const kept = lines.slice(lines.length - cap);
	writePrivateTextFile(path, `${kept.join("\n")}\n`);
}

export function readMemoryEvents(): MemoryEventV1[] {
	ensureRepiStorage();
	return jsonlRecords(memoryEventsPath(), isMemoryEvent);
}

export function memoryTextForSearch(event: MemoryEventV1): string {
	return [
		event.task,
		event.route,
		event.target ?? "",
		event.source,
		event.outcome,
		...event.domainTags,
		...event.lessons,
		...event.failurePatterns,
		...event.reuseRules,
		...event.commands,
		...event.artifactHashes.map((artifact) => `${artifact.path} ${artifact.tier} ${artifact.sha256 ?? ""}`),
	]
		.join("\n")
		.toLowerCase();
}

export function memorySearchTokens(text: string): Set<string> {
	return new Set(
		uniqueNonEmpty(
			String(text ?? "")
				.toLowerCase()
				.split(/[^a-z0-9一-鿿]+/),
			240,
		).filter((token) => token.length >= 2),
	);
}

export function memorySemanticAliases(token: string): string[] {
	const aliases: Record<string, string[]> = {
		acl: ["authz", "authorization", "permission", "role", "ownership"],
		authorization: ["authz", "permission", "role", "ownership"],
		authz: ["authorization", "permission", "role", "ownership", "principal"],
		bola: ["authz", "authorization", "ownership", "object", "principal"],
		idor: ["authz", "authorization", "ownership", "object", "principal"],
		owner: ["ownership", "principal", "object", "tenant"],
		ownership: ["owner", "principal", "object", "tenant", "authz"],
		tenant: ["ownership", "principal", "object", "scope"],
		crash: ["segfault", "core", "overflow", "primitive", "pwn"],
		exploit: ["pwn", "poc", "payload", "primitive", "replay"],
		leak: ["libc", "address", "rop", "pwn"],
		ret2libc: ["rop", "libc", "pwn", "chain"],
		segfault: ["crash", "core", "overflow", "primitive"],
		signature: ["sign", "hmac", "crypto", "nonce", "timestamp"],
		signing: ["sign", "signature", "hmac", "crypto", "nonce"],
		packet: ["pcap", "stream", "tshark", "flow"],
		stream: ["pcap", "packet", "tshark", "flow"],
		rootfs: ["firmware", "squashfs", "binwalk", "iot"],
		metadata: ["cloud", "iam", "instance", "k8s", "kubernetes"],
		ioc: ["malware", "c2", "yara", "capa", "floss"],
	};
	return aliases[token] ?? [];
}

export function memoryHybridQueryTokens(queryTokens: string[]): string[] {
	return uniqueNonEmpty(
		queryTokens.flatMap((token) => memorySemanticAliases(token)),
		48,
	);
}

export function memoryVectorTokens(text: string): string[] {
	const tokens = Array.from(memorySearchTokens(text));
	return uniqueNonEmpty([...tokens, ...memoryHybridQueryTokens(tokens)], 256);
}

export function memoryVectorQualityWeight(event: MemoryEventV1): number {
	let weight = 0.55 + event.quality.confidence * 0.45;
	if (event.quality.replayVerified) weight += 0.18;
	if (event.outcome === "success") weight += 0.12;
	if (event.outcome === "failure" || event.outcome === "blocked") weight -= 0.22;
	weight += Math.min(0.16, event.quality.reuseCount * 0.03);
	weight -= Math.min(0.24, event.quality.failureCount * 0.06 + event.quality.decay * 0.12);
	return Number(Math.max(0.1, Math.min(1.35, weight)).toFixed(4));
}

export function memoryCaseTextForSearch(row: CaseMemoryV1 | undefined): string {
	if (!row) return "";
	return [
		row.summary,
		row.route,
		row.target ?? "",
		...row.domainTags,
		...row.commands,
		...row.reuseRules,
		...row.failurePatterns,
	]
		.join("\n")
		.toLowerCase();
}

export function memoryArtifactTextForSearch(event: MemoryEventV1): string {
	return event.artifactHashes
		.map((artifact) => `${artifact.path} ${artifact.tier}`)
		.join("\n")
		.toLowerCase();
}

export function memoryHybridOverlapScore(params: {
	tokens: string[];
	haystack: Set<string>;
	reasonPrefix: string;
	points: number;
	max: number;
	reasons: string[];
}): number {
	let score = 0;
	for (const token of params.tokens) {
		if (!params.haystack.has(token)) continue;
		score += params.points;
		params.reasons.push(`${params.reasonPrefix}:${token}`);
		if (score >= params.max) return params.max;
	}
	return score;
}

// opt #81 — lexical token-Set cache (the lexical analog of #76's vector-index cache).
// searchMemoryEvents runs on every tool_result and, per event, built FOUR token Sets via
// memorySearchTokens — an O(text) lower-case+split+uniqueNonEmpty+Set construction of text
// that is a PURE function of (event, caseRow): event text (once for the haystack .has() loop
// in searchMemoryEvents, once inside memoryHybridSignalScore), case text, and artifact text.
// events.jsonl / case-memory.jsonl only change on deposit, so between deposits these Sets are
// re-deriving IDENTICAL output R tool_results × N events × 4 times = O(R·N·4) wasted work over
// a session. Cache them: event/artifact tokens under event.id, case tokens under caseSignature,
// each entry validated by a generation token = (events mtime+size, case mtime+size). A deposit
// bumps mtime → generation changes → stale entries rebuilt lazily on the next recall. The
// generation is computed ONCE per searchMemoryEvents call (2 stat(2)s — same cost shape as #76)
// and threaded through, so per-event lookups are Map.get + ref-equality, zero text work on a hit.
//
// Shared-reference safety (same precedent as #65/#74/#76 returning cached objects directly):
// every consumer reads the Set read-only — memoryHybridOverlapScore does params.haystack.has(),
// the searchMemoryEvents haystack loop does haystackTokens.has(token). NONE mutate the Set. A
// freeze/deep-copy would re-introduce the O(text) cost the cache eliminates. Latent invariant:
// any new caller that mutates a returned token Set would corrupt the cache for all readers —
// preserve "treat cached lexical token Sets as read-only" when adding callers.
const EMPTY_TOKEN_SET: Set<string> = new Set();

const eventLexicalTokenCache = new Map<
	string,
	{ generation: string; eventTokens: Set<string>; artifactTokens: Set<string> }
>();
const caseLexicalTokenCache = new Map<string, { generation: string; caseTokens: Set<string> }>();

// opt #86 — generation-change eviction for the lexical token-Set caches. event ids are unique
// (never reused across deposits), so every new deposit added a PERMANENT entry to
// eventLexicalTokenCache under a fresh event.id; over a long session the caches grew without
// bound even though stale-generation entries are skipped on lookup. lexicalTokenGeneration()
// changes on every deposit (events.jsonl/case-memory.jsonl mtime+size bump) — when it does,
// clear both caches: the entries are all stale (their stored generation no longer matches) and
// the caches are lazily rebuilt on the next recall (which re-scans all events anyway), so
// clearing is lossless. Pure memory-bounding layer — default behavior (which entries are hit)
// is unchanged.
let lastLexicalGeneration = "";

function lexicalStatKey(path: string): string {
	try {
		const s = statSync(path);
		return `${s.mtimeMs}:${s.size}`;
	} catch {
		return "missing";
	}
}

/**
 * Generation token for the lexical token-Set cache: (events.jsonl mtime+size,
 * case-memory.jsonl mtime+size). A deposit rewrites either file (atomic temp+rename →
 * mtime+size change) → generation changes → cached per-event/per-case token Sets are
 * stale and rebuilt lazily. "missing" sentinel keeps the cache usable before any deposit.
 * On a generation change the lexical token caches are cleared (#86) so unique event ids do
 * not accumulate permanent stale entries over a session.
 */
export function lexicalTokenGeneration(): string {
	const generation = `${lexicalStatKey(memoryEventsPath())}|${lexicalStatKey(caseMemoryPath())}`;
	if (generation !== lastLexicalGeneration) {
		eventLexicalTokenCache.clear();
		caseLexicalTokenCache.clear();
		lastLexicalGeneration = generation;
	}
	return generation;
}

/** Cached event-text token Set, keyed by event.id, validated by generation. */
export function cachedEventSearchTokens(event: MemoryEventV1, generation: string): Set<string> {
	const hit = eventLexicalTokenCache.get(event.id);
	if (hit && hit.generation === generation) return hit.eventTokens;
	const eventTokens = memorySearchTokens(memoryTextForSearch(event));
	const artifactTokens = memorySearchTokens(memoryArtifactTextForSearch(event));
	eventLexicalTokenCache.set(event.id, { generation, eventTokens, artifactTokens });
	return eventTokens;
}

/** Cached artifact-text token Set (built alongside the event-text Set, same cache entry). */
export function cachedArtifactSearchTokens(event: MemoryEventV1, generation: string): Set<string> {
	const hit = eventLexicalTokenCache.get(event.id);
	if (hit && hit.generation === generation) return hit.artifactTokens;
	cachedEventSearchTokens(event, generation);
	return eventLexicalTokenCache.get(event.id)?.artifactTokens ?? EMPTY_TOKEN_SET;
}

/** Cached case-text token Set, keyed by caseSignature, validated by generation. */
export function cachedCaseSearchTokens(caseRow: CaseMemoryV1 | undefined, generation: string): Set<string> {
	if (!caseRow) return EMPTY_TOKEN_SET;
	const hit = caseLexicalTokenCache.get(caseRow.caseSignature);
	if (hit && hit.generation === generation) return hit.caseTokens;
	const caseTokens = memorySearchTokens(memoryCaseTextForSearch(caseRow));
	caseLexicalTokenCache.set(caseRow.caseSignature, { generation, caseTokens });
	return caseTokens;
}

/** Test/observability helper: returns the current lexical token-cache sizes so the generation-
 *  change eviction (#86) can be verified — the caches must be cleared on a generation change so
 *  unique event ids do not accumulate permanent stale entries over a session. */
export function lexicalTokenCacheSizes(): { events: number; cases: number } {
	return { events: eventLexicalTokenCache.size, cases: caseLexicalTokenCache.size };
}

export function memoryHybridSignalScore(
	event: MemoryEventV1,
	caseRow: CaseMemoryV1 | undefined,
	queryTokens: string[],
	semanticTokens: string[],
	reasons: string[],
	precomputed?: { eventTokens: Set<string>; caseTokens: Set<string>; artifactTokens: Set<string> },
): number {
	const caseTokens = precomputed?.caseTokens ?? memorySearchTokens(memoryCaseTextForSearch(caseRow));
	const artifactTokens = precomputed?.artifactTokens ?? memorySearchTokens(memoryArtifactTextForSearch(event));
	const eventTokens = precomputed?.eventTokens ?? memorySearchTokens(memoryTextForSearch(event));
	let score = 0;
	score += memoryHybridOverlapScore({
		tokens: semanticTokens,
		haystack: eventTokens,
		reasonPrefix: "memory_semantic_hybrid_reuse",
		points: 2,
		max: 12,
		reasons,
	});
	score += memoryHybridOverlapScore({
		tokens: queryTokens,
		haystack: caseTokens,
		reasonPrefix: "case-memory-hybrid",
		points: 2.5,
		max: 12,
		reasons,
	});
	score += memoryHybridOverlapScore({
		tokens: [...queryTokens, ...semanticTokens],
		haystack: artifactTokens,
		reasonPrefix: "artifact-hybrid",
		points: 3,
		max: 9,
		reasons,
	});
	return score;
}

export function memoryRecallQuery(options: { route?: string; target?: string; query?: string } = {}): string {
	return uniqueNonEmpty([options.query, options.target, options.route], 3).join(" ");
}

export function memoryNormalizedRecallScore(hit: MemoryRetrievalHit): number {
	return Math.max(0, Math.min(1, hit.score > 1 ? hit.score / 100 : hit.score));
}

export function memoryRecallCardLines(hit: MemoryRetrievalHit, index: number): string[] {
	const event = hit.event;
	const score = memoryNormalizedRecallScore(hit).toFixed(2);
	const lessons = event.lessons.slice(0, 2).map((item) => truncateMiddle(item, 180));
	const reuseRules = event.reuseRules.slice(0, 2).map((item) => truncateMiddle(item, 180));
	const commands = event.commands.slice(0, 3).map((item) => truncateMiddle(item, 180));
	return [
		`- card=${index + 1} id=${event.id} score=${score} outcome=${event.outcome} route=${event.route} target=${event.target ?? "workspace"}`,
		...(lessons.length ? lessons.map((item) => `  lesson: ${item}`) : []),
		...(reuseRules.length ? reuseRules.map((item) => `  reuse: ${item}`) : []),
		...(commands.length ? commands.map((item) => `  command: ${item}`) : []),
		`  source: case=${event.caseSignature} ts=${event.ts} reasons=${hit.reasons.slice(0, 6).join(",") || "score"}`,
	];
}

export function memoryBlockingGovernanceBySource(): Map<
	string,
	{ action: "forget" | "quarantine"; reason?: string; id?: string }
> {
	// opt #83 — the blocked Map is a pure function of the governance ledger rows (which only
	// change on a governance op). Cache it keyed by (path, mtime+size) so the per-tool_result
	// recall path skips the O(rows) rebuild on a hit. The value objects are built fresh once
	// and shared; consumers read .action/.reason/.id read-only.
	return cachedJsonlDerived(memoryGovernanceLedgerPath(), () => {
		const rows = jsonlRecords(memoryGovernanceLedgerPath(), isMemoryGovernanceLedgerRow);
		const blocked = new Map<string, { action: "forget" | "quarantine"; reason?: string; id?: string }>();
		for (const row of rows) {
			if (row.applied === false) continue;
			const sourceEventId = String(row.sourceEventId ?? (row as { eventId?: string }).eventId ?? "").trim();
			if (!sourceEventId) continue;
			const action = String(row.action ?? "").toLowerCase();
			if (action === "forget" || action === "quarantine") {
				blocked.set(sourceEventId, { action, reason: row.reason, id: row.id });
			} else if (action === "promote" || action === "retain") {
				blocked.delete(sourceEventId);
			}
		}
		return blocked;
	});
}
