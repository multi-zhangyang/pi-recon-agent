import { dirname, join } from "node:path";
import type { Api, Model, ModelsStore, ModelsStoreEntry } from "@pi-recon/repi-ai";
import { getAgentDir } from "../config.ts";
import { type AuthStorageBackend, FileAuthStorageBackend } from "./auth-storage.ts";

type StoredModels = Record<string, ModelsStoreEntry>;

function emptyStoredModels(): StoredModels {
	return Object.create(null) as StoredModels;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isFiniteNumber(value: unknown): value is number {
	return typeof value === "number" && Number.isFinite(value);
}

function isStoredModel(value: unknown): value is Model<Api> {
	if (!isRecord(value) || !isRecord(value.cost)) return false;
	return (
		typeof value.id === "string" &&
		typeof value.name === "string" &&
		typeof value.api === "string" &&
		typeof value.provider === "string" &&
		typeof value.baseUrl === "string" &&
		typeof value.reasoning === "boolean" &&
		Array.isArray(value.input) &&
		value.input.every((input) => input === "text" || input === "image") &&
		isFiniteNumber(value.cost.input) &&
		isFiniteNumber(value.cost.output) &&
		isFiniteNumber(value.cost.cacheRead) &&
		isFiniteNumber(value.cost.cacheWrite) &&
		isFiniteNumber(value.contextWindow) &&
		value.contextWindow > 0 &&
		isFiniteNumber(value.maxTokens) &&
		value.maxTokens > 0
	);
}

function isModelsStoreEntry(value: unknown): value is ModelsStoreEntry {
	if (!isRecord(value) || !Array.isArray(value.models) || !value.models.every(isStoredModel)) return false;
	return value.checkedAt === undefined || (isFiniteNumber(value.checkedAt) && value.checkedAt >= 0);
}

/** In-memory model catalog storage with immutable read/write boundaries. */
export class InMemoryCodingAgentModelsStore implements ModelsStore {
	private readonly entries = new Map<string, ModelsStoreEntry>();

	async read(providerId: string): Promise<ModelsStoreEntry | undefined> {
		const entry = this.entries.get(providerId);
		return entry ? structuredClone(entry) : undefined;
	}

	async write(providerId: string, entry: ModelsStoreEntry): Promise<void> {
		this.entries.set(providerId, structuredClone(entry));
	}

	async delete(providerId: string): Promise<void> {
		this.entries.delete(providerId);
	}
}

/** Locked, atomically rewritten last-known provider catalogs. */
export class FileModelsStore implements ModelsStore {
	private readonly storage: AuthStorageBackend;

	constructor(path: string = join(getAgentDir(), "models-store.json")) {
		this.storage = new FileAuthStorageBackend(path);
	}

	private parse(content: string | undefined): StoredModels {
		if (!content) return emptyStoredModels();
		let parsed: unknown;
		try {
			parsed = JSON.parse(content);
		} catch {
			return emptyStoredModels();
		}
		if (!isRecord(parsed)) return emptyStoredModels();
		const entries = emptyStoredModels();
		for (const [providerId, entry] of Object.entries(parsed)) {
			if (isModelsStoreEntry(entry)) entries[providerId] = entry;
		}
		return entries;
	}

	async read(providerId: string): Promise<ModelsStoreEntry | undefined> {
		return this.storage.withLock((content) => {
			const entries = this.parse(content);
			const entry = Object.hasOwn(entries, providerId) ? entries[providerId] : undefined;
			return { result: entry ? structuredClone(entry) : undefined };
		});
	}

	async write(providerId: string, entry: ModelsStoreEntry): Promise<void> {
		if (!isModelsStoreEntry(entry)) throw new Error(`Invalid model catalog entry for provider "${providerId}"`);
		await this.storage.withLockAsync(async (content) => {
			const current = this.parse(content);
			current[providerId] = structuredClone(entry);
			return { result: undefined, next: JSON.stringify(current, null, 2) };
		});
	}

	async delete(providerId: string): Promise<void> {
		await this.storage.withLockAsync(async (content) => {
			const current = this.parse(content);
			delete current[providerId];
			return { result: undefined, next: JSON.stringify(current, null, 2) };
		});
	}
}

/** Default persistent cache path paired with a models.json location. */
export function getModelsStorePath(modelsPath: string): string {
	return join(dirname(modelsPath), "models-store.json");
}
