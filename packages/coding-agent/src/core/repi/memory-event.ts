import type { RepiMemoryScope } from "./memory-scope.ts";
import { hashFileSha256, sha256Text, uniqueNonEmpty } from "./text.ts";

export type MemoryEventSource =
	| "reflect"
	| "complete"
	| "proof_loop"
	| "replayer"
	| "autofix"
	| "operator"
	| "deposition"
	| "manual"
	| "knowledge_graph";

export type MemoryOutcome = "success" | "failure" | "partial" | "blocked" | "repair";

export type MemoryArtifactHash = {
	path: string;
	sha256: string | null;
	tier: string;
	required?: boolean;
};

export type MemoryQuality = {
	confidence: number;
	replayVerified: boolean;
	reuseCount: number;
	failureCount: number;
	lastUsefulAt: string;
	decay: number;
	retrievalScore?: number;
};

export type MemoryEventV1 = {
	kind: "repi-memory-event";
	schemaVersion: 1;
	id: string;
	seq: number;
	ts: string;
	source: MemoryEventSource;
	task: string;
	route: string;
	target?: string;
	domainTags: string[];
	caseSignature: string;
	outcome: MemoryOutcome;
	lessons: string[];
	failurePatterns: string[];
	reuseRules: string[];
	commands: string[];
	artifacts: MemoryArtifactHash[];
	artifactHashes: MemoryArtifactHash[];
	memoryScope?: RepiMemoryScope;
	quality: MemoryQuality;
	promotion: {
		playbookCandidate: boolean;
		workerRoutingHint?: string;
		verifierRuleCandidate: boolean;
	};
	prevHash: string;
	entryHash: string;
};

export type MemoryEventInput = {
	source: MemoryEventSource;
	task?: string;
	route?: string;
	target?: string;
	domainTags?: string[];
	caseSignature?: string;
	outcome?: MemoryOutcome;
	lessons?: string[];
	failurePatterns?: string[];
	reuseRules?: string[];
	commands?: string[];
	artifactPaths?: string[];
	artifacts?: MemoryArtifactHash[];
	confidence?: number;
	replayVerified?: boolean;
	playbookCandidate?: boolean;
	workerRoutingHint?: string;
	verifierRuleCandidate?: boolean;
};

export function isMemoryArtifactHash(value: unknown): value is MemoryArtifactHash {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const row = value as MemoryArtifactHash;
	return (
		typeof row.path === "string" &&
		(typeof row.sha256 === "string" || row.sha256 === null) &&
		typeof row.tier === "string"
	);
}

export function isMemoryQuality(value: unknown): value is MemoryQuality {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const row = value as MemoryQuality;
	return (
		typeof row.confidence === "number" &&
		typeof row.replayVerified === "boolean" &&
		typeof row.reuseCount === "number" &&
		typeof row.failureCount === "number" &&
		typeof row.lastUsefulAt === "string" &&
		typeof row.decay === "number"
	);
}

export function isMemoryEvent(value: unknown): value is MemoryEventV1 {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const row = value as MemoryEventV1;
	return (
		row.kind === "repi-memory-event" &&
		row.schemaVersion === 1 &&
		typeof row.id === "string" &&
		Number.isInteger(row.seq) &&
		typeof row.ts === "string" &&
		typeof row.source === "string" &&
		typeof row.task === "string" &&
		typeof row.route === "string" &&
		Array.isArray(row.domainTags) &&
		typeof row.caseSignature === "string" &&
		typeof row.outcome === "string" &&
		Array.isArray(row.lessons) &&
		Array.isArray(row.failurePatterns) &&
		Array.isArray(row.reuseRules) &&
		Array.isArray(row.commands) &&
		Array.isArray(row.artifactHashes) &&
		row.artifactHashes.every(isMemoryArtifactHash) &&
		isMemoryQuality(row.quality) &&
		typeof row.prevHash === "string" &&
		typeof row.entryHash === "string"
	);
}

export function memoryArtifactTier(path: string): string {
	if (
		/\/evidence\/(?:browser|web-authz|mobile-runtime|native-runtime|exploit-lab|runs|proof-loops|replayers)\//i.test(
			path,
		)
	)
		return "runtime_artifact";
	if (/\/evidence\/(?:maps|kernel|decisions|harness|knowledge)\//i.test(path)) return "process_config";
	if (/\/evidence\//i.test(path)) return "persisted_state";
	if (/\/memory\//i.test(path)) return "persisted_memory";
	return "artifact";
}

export function memoryArtifactHashes(paths: string[], limit = 80): MemoryArtifactHash[] {
	return uniqueNonEmpty(paths, limit).map((path) => {
		let sha256: string | null = null;
		try {
			// opt #159: stream the hash (shared hashFileSha256) instead of
			// readFileSync-whole — runtime_artifact paths (evidence/{browser,
			// web-authz,mobile-runtime,native-runtime,exploit-lab,runs,proof-
			// loops,replayers}) are captured dumps/coredumps/binary replays that
			// routinely reach multi-GB and OOM-crashed the parent before the
			// digest ran. Try/catch → null preserved (missing/unreadable file).
			sha256 = hashFileSha256(path);
		} catch {
			sha256 = null;
		}
		return { path, sha256, tier: memoryArtifactTier(path), required: sha256 !== null };
	});
}

export function memoryEventHash(event: MemoryEventV1): string {
	const { entryHash: _entryHash, ...withoutHash } = event;
	return sha256Text(JSON.stringify(withoutHash));
}

export function memoryEventHashChainOk(events: MemoryEventV1[]): boolean {
	let prevHash = "0".repeat(64);
	for (const event of events) {
		if (event.prevHash !== prevHash) return false;
		if (event.entryHash !== memoryEventHash(event)) return false;
		prevHash = event.entryHash;
	}
	return true;
}

export function memoryEventSignature(
	input: Pick<MemoryEventInput, "task" | "route" | "target" | "domainTags">,
): string {
	const tags = uniqueNonEmpty(input.domainTags ?? [], 24)
		.map((item) => item.toLowerCase())
		.sort()
		.join(",");
	return sha256Text([input.route ?? "unknown", input.target ?? "", input.task ?? "", tags].join("\n")).slice(0, 24);
}
