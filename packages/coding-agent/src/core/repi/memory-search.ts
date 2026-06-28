import type { CaseMemoryV1 } from "./case-memory.ts";
import { jsonlRecords } from "./jsonl.ts";
import { isMemoryEvent, type MemoryEventV1 } from "./memory-event.ts";
import { ensureRepiStorage, memoryEventsPath, memoryGovernanceLedgerPath } from "./storage.ts";
import { truncateMiddle, uniqueNonEmpty } from "./text.ts";

export type MemoryRetrievalHit = {
	event: MemoryEventV1;
	score: number;
	reasons: string[];
};

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

export function memoryHybridSignalScore(
	event: MemoryEventV1,
	caseRow: CaseMemoryV1 | undefined,
	queryTokens: string[],
	semanticTokens: string[],
	reasons: string[],
): number {
	const caseTokens = memorySearchTokens(memoryCaseTextForSearch(caseRow));
	const artifactTokens = memorySearchTokens(memoryArtifactTextForSearch(event));
	const eventTokens = memorySearchTokens(memoryTextForSearch(event));
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
	const rows = jsonlRecords(
		memoryGovernanceLedgerPath(),
		(value): value is { action?: string; applied?: boolean; sourceEventId?: string; reason?: string; id?: string } =>
			typeof value === "object" &&
			value !== null &&
			typeof (value as { action?: unknown }).action === "string" &&
			(typeof (value as { sourceEventId?: unknown }).sourceEventId === "string" ||
				typeof (value as { eventId?: unknown }).eventId === "string"),
	);
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
}
