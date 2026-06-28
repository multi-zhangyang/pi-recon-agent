import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { type MemoryArtifactHash, type MemoryEventV1, memoryEventHashChainOk } from "./memory-event.ts";
import { memoryRouteMatches, memoryTargetScope } from "./memory-scope.ts";
import {
	memoryTextForSearch,
	memoryVectorQualityWeight,
	memoryVectorTokens,
	readMemoryEvents,
} from "./memory-search.ts";
import { writeFileAtomic } from "./memory-store.ts";
import { ensureRepiStorage, memoryEventsPath, memoryVectorIndexPath, memoryVectorSearchReportPath } from "./storage.ts";
import { sha256Text, uniqueNonEmpty } from "./text.ts";

export type MemoryEmbeddingProviderKind = "local-hash" | "openai-compatible" | "mock-remote";

export type MemoryEmbeddingProviderV1 = {
	kind: "repi-memory-embedding-provider";
	schemaVersion: 1;
	MemoryEmbeddingProviderV1: true;
	backend: MemoryEmbeddingProviderKind;
	requestedBackend: MemoryEmbeddingProviderKind;
	model: string;
	dimensions: number;
	status: "active" | "fallback";
	source: "default" | "env";
	allowRemote: boolean;
	baseUrl?: string;
	endpoint?: string;
	apiKeyEnv?: string;
	timeoutMs: number;
	fallbackReason?: string;
	requiredChecks: string[];
};

export type MemoryVectorIndexEntryV1 = {
	kind: "repi-memory-vector-index-entry";
	schemaVersion: 1;
	eventId: string;
	caseSignature: string;
	route: string;
	targetScope: string;
	model: string;
	embeddingProvider: MemoryEmbeddingProviderV1;
	dimensions: number;
	tokens: string[];
	vector: number[];
	qualityWeight: number;
	artifactRefs: MemoryArtifactHash[];
	entryHash: string;
};

export type MemoryVectorIndexV1 = {
	kind: "repi-memory-vector-index";
	schemaVersion: 1;
	generatedAt: string;
	MemoryVectorIndexV1: true;
	model: string;
	embeddingProvider: MemoryEmbeddingProviderV1;
	dimensions: number;
	eventsPath: string;
	indexPath: string;
	eventCount: number;
	hashChainOk: boolean;
	entries: MemoryVectorIndexEntryV1[];
	requiredChecks: string[];
};

export type MemoryVectorSearchHitV1 = {
	eventId: string;
	caseSignature: string;
	score: number;
	cosine: number;
	qualityWeight: number;
	reasons: string[];
	commands: string[];
};

export type MemoryVectorSearchReportV1 = {
	kind: "repi-memory-vector-search-report";
	schemaVersion: 1;
	generatedAt: string;
	MemoryVectorSearchV1: true;
	query: string;
	route?: string;
	target?: string;
	indexPath: string;
	reportPath: string;
	model: string;
	embeddingProvider: MemoryEmbeddingProviderV1;
	dimensions: number;
	hits: MemoryVectorSearchHitV1[];
	requiredChecks: string[];
};

export const MEMORY_VECTOR_DIMENSIONS = 64;
export const MEMORY_VECTOR_MODEL = "repi-local-hash-embedding-v1" as const;
export const MEMORY_EMBEDDING_PROVIDER_GATE_MARKERS = [
	"MemoryEmbeddingProviderV1",
	"local_hash_embedding_fallback",
	"openai_compatible_embedding_contract",
	"embedding_api_key_env_ref_only",
	"remote_embedding_requires_explicit_allow",
];

export function memoryVectorForTokens(tokens: string[], dimensions = MEMORY_VECTOR_DIMENSIONS): number[] {
	const vector = Array.from({ length: dimensions }, () => 0);
	for (const token of tokens) {
		const digest = createHash("sha256").update(token).digest();
		const index = digest[0] % dimensions;
		const sign = digest[1] % 2 === 0 ? 1 : -1;
		const weight = 1 + Math.min(2.5, token.length / 10);
		vector[index] += sign * weight;
	}
	const norm = Math.sqrt(vector.reduce((sum, value) => sum + value * value, 0));
	if (!norm) return vector;
	return vector.map((value) => Number((value / norm).toFixed(6)));
}

export function memoryVectorForText(text: string): number[] {
	return memoryVectorForTokens(memoryVectorTokens(text));
}

export function memoryEmbeddingProviderKind(value: string | undefined): MemoryEmbeddingProviderKind {
	const normalized = String(value ?? "")
		.trim()
		.toLowerCase();
	if (normalized === "openai" || normalized === "openai-compatible" || normalized === "openai_compatible")
		return "openai-compatible";
	if (normalized === "mock" || normalized === "mock-remote" || normalized === "mock_remote") return "mock-remote";
	return "local-hash";
}

export function memoryEmbeddingProviderConfig(
	overrides?: Partial<MemoryEmbeddingProviderV1>,
): MemoryEmbeddingProviderV1 {
	const requestedBackend = memoryEmbeddingProviderKind(process.env.REPI_MEMORY_EMBEDDING_PROVIDER);
	const source = process.env.REPI_MEMORY_EMBEDDING_PROVIDER ? "env" : "default";
	const requestedModel =
		process.env.REPI_MEMORY_EMBEDDING_MODEL ??
		(requestedBackend === "openai-compatible"
			? "text-embedding-3-small"
			: requestedBackend === "mock-remote"
				? "repi-mock-remote-embedding-v1"
				: MEMORY_VECTOR_MODEL);
	const requestedDimensions = Number(process.env.REPI_MEMORY_EMBEDDING_DIMENSIONS);
	const timeoutMs = Math.max(250, Math.min(30_000, Number(process.env.REPI_MEMORY_EMBEDDING_TIMEOUT_MS) || 6000));
	const allowRemote = process.env.REPI_MEMORY_EMBEDDING_ALLOW_REMOTE === "1";
	const baseUrl = process.env.REPI_MEMORY_EMBEDDING_BASE_URL;
	const endpoint = process.env.REPI_MEMORY_EMBEDDING_ENDPOINT ?? "/v1/embeddings";
	const apiKeyEnv = process.env.REPI_MEMORY_EMBEDDING_API_KEY_ENV ?? "REPI_MEMORY_EMBEDDING_API_KEY";
	let backend = requestedBackend;
	let model = requestedModel;
	let dimensions =
		Number.isFinite(requestedDimensions) && requestedDimensions > 0
			? Math.floor(requestedDimensions)
			: MEMORY_VECTOR_DIMENSIONS;
	let status: MemoryEmbeddingProviderV1["status"] = "active";
	let fallbackReason: string | undefined;
	if (requestedBackend === "openai-compatible") {
		dimensions =
			Number.isFinite(requestedDimensions) && requestedDimensions > 0 ? Math.floor(requestedDimensions) : 1536;
		if (!allowRemote) fallbackReason = "remote_embedding_requires_explicit_allow";
		else if (!baseUrl) fallbackReason = "embedding_base_url_missing";
		else if (!apiKeyEnv || !process.env[apiKeyEnv]) fallbackReason = "embedding_api_key_env_missing";
		if (fallbackReason) {
			backend = "local-hash";
			model = MEMORY_VECTOR_MODEL;
			dimensions = MEMORY_VECTOR_DIMENSIONS;
			status = "fallback";
		}
	}
	if (requestedBackend === "mock-remote") {
		dimensions =
			Number.isFinite(requestedDimensions) && requestedDimensions > 0 ? Math.floor(requestedDimensions) : 96;
	}
	return {
		kind: "repi-memory-embedding-provider",
		schemaVersion: 1,
		MemoryEmbeddingProviderV1: true,
		backend,
		requestedBackend,
		model,
		dimensions,
		status,
		source,
		allowRemote,
		baseUrl: requestedBackend === "openai-compatible" ? baseUrl : undefined,
		endpoint: requestedBackend === "openai-compatible" ? endpoint : undefined,
		apiKeyEnv: requestedBackend === "openai-compatible" ? apiKeyEnv : undefined,
		timeoutMs,
		fallbackReason,
		requiredChecks: MEMORY_EMBEDDING_PROVIDER_GATE_MARKERS,
		...overrides,
	};
}

export function normalizeMemoryEmbeddingVector(vector: number[]): number[] {
	const norm = Math.sqrt(vector.reduce((sum, value) => sum + value * value, 0));
	if (!norm) return vector.map((value) => Number(value.toFixed(6)));
	return vector.map((value) => Number((value / norm).toFixed(6)));
}

export function memoryOpenAiCompatibleEmbeddings(
	texts: string[],
	provider: MemoryEmbeddingProviderV1,
): { ok: true; vectors: number[][]; dimensions: number } | { ok: false; error: string } {
	if (provider.backend !== "openai-compatible" || !provider.baseUrl || !provider.apiKeyEnv) {
		return { ok: false, error: "openai_compatible_embedding_contract_incomplete" };
	}
	const script = `
const fs = require("node:fs");
const payload = JSON.parse(fs.readFileSync(0, "utf8"));
const controller = new AbortController();
const timer = setTimeout(() => controller.abort(), payload.timeoutMs);
(async () => {
  try {
    const url = new URL(payload.endpoint || "/v1/embeddings", payload.baseUrl).toString();
    const apiKey = process.env[payload.apiKeyEnv];
    if (!apiKey) throw new Error("embedding_api_key_env_missing");
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer " + apiKey },
      body: JSON.stringify({ model: payload.model, input: payload.texts }),
      signal: controller.signal,
    });
    const json = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error("embedding_http_" + response.status + ":" + JSON.stringify(json).slice(0, 500));
    const vectors = (json.data || []).map((row) => row && row.embedding).filter(Array.isArray);
    if (vectors.length !== payload.texts.length) throw new Error("embedding_count_mismatch");
    process.stdout.write(JSON.stringify({ vectors }));
  } catch (error) {
    process.stderr.write(String(error && error.message ? error.message : error));
    process.exit(1);
  } finally {
    clearTimeout(timer);
  }
})();
`;
	const child = spawnSync(process.execPath, ["-e", script], {
		input: JSON.stringify({
			baseUrl: provider.baseUrl,
			endpoint: provider.endpoint,
			model: provider.model,
			texts,
			apiKeyEnv: provider.apiKeyEnv,
			timeoutMs: provider.timeoutMs,
		}),
		encoding: "utf8",
		timeout: provider.timeoutMs + 1000,
		env: process.env,
		maxBuffer: 20 * 1024 * 1024,
	});
	if (child.status !== 0)
		return { ok: false, error: (child.stderr || child.error?.message || "embedding_child_failed").slice(0, 800) };
	try {
		const parsed = JSON.parse(child.stdout || "{}");
		const vectors = parsed.vectors;
		if (!Array.isArray(vectors) || vectors.some((vector) => !Array.isArray(vector)))
			return { ok: false, error: "embedding_response_invalid" };
		const normalized = vectors.map((vector) => normalizeMemoryEmbeddingVector(vector.map(Number)));
		const dimensions = normalized[0]?.length ?? 0;
		if (!dimensions) return { ok: false, error: "embedding_empty_vector" };
		return { ok: true, vectors: normalized, dimensions };
	} catch (error) {
		return { ok: false, error: `embedding_parse_failed:${String(error).slice(0, 300)}` };
	}
}

export function memoryEmbeddingVectorsForTexts(
	texts: string[],
	provider = memoryEmbeddingProviderConfig(),
): { provider: MemoryEmbeddingProviderV1; vectors: number[][] } {
	if (provider.backend === "openai-compatible") {
		const remote = memoryOpenAiCompatibleEmbeddings(texts, provider);
		if (remote.ok) {
			return {
				provider: memoryEmbeddingProviderConfig({ ...provider, dimensions: remote.dimensions, status: "active" }),
				vectors: remote.vectors,
			};
		}
		const fallback = memoryEmbeddingProviderConfig({
			backend: "local-hash",
			model: MEMORY_VECTOR_MODEL,
			dimensions: MEMORY_VECTOR_DIMENSIONS,
			status: "fallback",
			fallbackReason: `openai_compatible_embedding_failed:${remote.error}`,
		});
		return {
			provider: fallback,
			vectors: texts.map((text) => memoryVectorForText(text)),
		};
	}
	const dimensions = provider.dimensions || MEMORY_VECTOR_DIMENSIONS;
	return {
		provider,
		vectors: texts.map((text) =>
			memoryVectorForTokens(
				provider.backend === "mock-remote"
					? uniqueNonEmpty([...memoryVectorTokens(text), "mock_remote_embedding_provider"], 260)
					: memoryVectorTokens(text),
				dimensions,
			),
		),
	};
}

export function memoryVectorCosine(left: number[], right: number[]): number {
	const length = Math.min(left.length, right.length);
	if (!length) return 0;
	let dot = 0;
	let leftNorm = 0;
	let rightNorm = 0;
	for (let index = 0; index < length; index += 1) {
		dot += (left[index] ?? 0) * (right[index] ?? 0);
		leftNorm += (left[index] ?? 0) ** 2;
		rightNorm += (right[index] ?? 0) ** 2;
	}
	if (!leftNorm || !rightNorm) return 0;
	return dot / Math.sqrt(leftNorm * rightNorm);
}

export function memoryVectorEntryFromEvent(
	event: MemoryEventV1,
	provider: MemoryEmbeddingProviderV1,
	vector: number[],
): MemoryVectorIndexEntryV1 {
	const tokens = memoryVectorTokens(memoryTextForSearch(event));
	const base = {
		kind: "repi-memory-vector-index-entry" as const,
		schemaVersion: 1 as const,
		eventId: event.id,
		caseSignature: event.caseSignature,
		route: event.route,
		targetScope: memoryTargetScope(event.target),
		model: provider.model,
		embeddingProvider: provider,
		dimensions: provider.dimensions,
		tokens,
		vector,
		qualityWeight: memoryVectorQualityWeight(event),
		artifactRefs: event.artifactHashes.filter((artifact) => artifact.sha256).slice(0, 32),
	};
	return { ...base, entryHash: sha256Text(JSON.stringify(base)) };
}

export function formatMemoryVectorSearch(report: MemoryVectorSearchReportV1): string {
	return [
		"memory_vector_search:",
		`MemoryVectorSearchV1=${report.MemoryVectorSearchV1}`,
		`query=${report.query}`,
		`model=${report.model}`,
		`dimensions=${report.dimensions}`,
		`embedding_provider=${report.embeddingProvider.backend}`,
		`embedding_provider_status=${report.embeddingProvider.status}`,
		`embedding_requested_backend=${report.embeddingProvider.requestedBackend}`,
		`embedding_fallback_reason=${report.embeddingProvider.fallbackReason ?? "none"}`,
		`index=${report.indexPath}`,
		`report=${report.reportPath}`,
		"hits:",
		...(report.hits.length
			? report.hits.map(
					(hit) =>
						`- event=${hit.eventId} score=${hit.score.toFixed(2)} cosine=${hit.cosine.toFixed(3)} quality=${hit.qualityWeight.toFixed(2)} case=${hit.caseSignature} reasons=${hit.reasons.join(",") || "none"} commands=${hit.commands.length}`,
				)
			: ["- none"]),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}

export function formatMemoryEmbeddingProvider(provider: MemoryEmbeddingProviderV1): string {
	return [
		"memory_embedding_provider:",
		`MemoryEmbeddingProviderV1=${provider.MemoryEmbeddingProviderV1}`,
		`backend=${provider.backend}`,
		`requested_backend=${provider.requestedBackend}`,
		`model=${provider.model}`,
		`dimensions=${provider.dimensions}`,
		`status=${provider.status}`,
		`source=${provider.source}`,
		`allow_remote=${provider.allowRemote}`,
		`base_url=${provider.baseUrl ?? "none"}`,
		`endpoint=${provider.endpoint ?? "none"}`,
		`api_key_env=${provider.apiKeyEnv ?? "none"}`,
		`fallback_reason=${provider.fallbackReason ?? "none"}`,
		"required_checks:",
		...provider.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}

export function buildMemoryVectorIndex(events = readMemoryEvents()): MemoryVectorIndexV1 {
	ensureRepiStorage();
	const embedding = memoryEmbeddingVectorsForTexts(events.map(memoryTextForSearch));
	const index: MemoryVectorIndexV1 = {
		kind: "repi-memory-vector-index",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		MemoryVectorIndexV1: true,
		model: embedding.provider.model,
		embeddingProvider: embedding.provider,
		dimensions: embedding.provider.dimensions,
		eventsPath: memoryEventsPath(),
		indexPath: memoryVectorIndexPath(),
		eventCount: events.length,
		hashChainOk: memoryEventHashChainOk(events),
		entries: events.map((event, index) =>
			memoryVectorEntryFromEvent(
				event,
				embedding.provider,
				embedding.vectors[index] ?? memoryVectorForText(memoryTextForSearch(event)),
			),
		),
		requiredChecks: [
			"MemoryVectorIndexV1",
			"MemoryEmbeddingProviderV1",
			"deterministic_local_hash_embedding",
			"local_hash_embedding_fallback",
			"openai_compatible_embedding_contract",
			"embedding_api_key_env_ref_only",
			"remote_embedding_requires_explicit_allow",
			"route_scoped_vector_rerank",
			"quality_weighted_vector_score",
			"forbidden_cross_route_vector_leak_blocked",
		],
	};
	writeFileAtomic(memoryVectorIndexPath(), `${JSON.stringify(index, null, 2)}\n`);
	return index;
}

export function searchMemoryVectors(
	query?: string,
	options?: { route?: string; target?: string; limit?: number },
): MemoryVectorSearchReportV1 {
	ensureRepiStorage();
	const events = readMemoryEvents();
	const eventsById = new Map(events.map((event) => [event.id, event]));
	const index = buildMemoryVectorIndex(events);
	const queryText = query ?? "";
	const queryTokens = memoryVectorTokens(queryText);
	const queryEmbedding = memoryEmbeddingVectorsForTexts([queryText], index.embeddingProvider);
	const queryVector = queryEmbedding.vectors[0] ?? memoryVectorForTokens(queryTokens, index.dimensions);
	const hits = index.entries
		.flatMap((entry) => {
			const event = eventsById.get(entry.eventId);
			if (!event) return [];
			if (options?.route && !memoryRouteMatches(entry.route, options.route)) return [];
			if (
				options?.target &&
				entry.targetScope !== "global" &&
				!entry.targetScope.includes(memoryTargetScope(options.target))
			)
				return [];
			const cosine = memoryVectorCosine(queryVector, entry.vector);
			const reasons: string[] = [];
			if (cosine > 0) reasons.push(`memory_vector_rerank:${cosine.toFixed(3)}`);
			if (options?.route && memoryRouteMatches(entry.route, options.route)) reasons.push("route_scoped_vector");
			if (entry.qualityWeight >= 1) reasons.push("quality_weighted_vector_score");
			const score = Number((Math.max(0, cosine) * 100 * entry.qualityWeight).toFixed(2));
			if (queryTokens.length > 0 && score <= 0) return [];
			return [
				{
					eventId: entry.eventId,
					caseSignature: entry.caseSignature,
					score,
					cosine: Number(cosine.toFixed(4)),
					qualityWeight: entry.qualityWeight,
					reasons,
					commands: event.commands.slice(0, 8),
				},
			];
		})
		.sort((left, right) => right.score - left.score || left.eventId.localeCompare(right.eventId))
		.slice(0, options?.limit ?? 12);
	const report: MemoryVectorSearchReportV1 = {
		kind: "repi-memory-vector-search-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		MemoryVectorSearchV1: true,
		query: queryText,
		route: options?.route,
		target: options?.target,
		indexPath: memoryVectorIndexPath(),
		reportPath: memoryVectorSearchReportPath(),
		model: index.embeddingProvider.model,
		embeddingProvider: queryEmbedding.provider,
		dimensions: queryEmbedding.provider.dimensions,
		hits,
		requiredChecks: [
			"MemoryVectorSearchV1",
			"MemoryEmbeddingProviderV1",
			"vector_index_built_before_search",
			"openai_compatible_embedding_contract",
			"embedding_api_key_env_ref_only",
			"local_hash_embedding_fallback",
			"route_scoped_vector_rerank",
			"quality_weighted_vector_score",
			"forbidden_cross_route_vector_leak_blocked",
		],
	};
	writeFileAtomic(memoryVectorSearchReportPath(), `${JSON.stringify(report, null, 2)}\n`);
	return report;
}
