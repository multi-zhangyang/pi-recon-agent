import type { Api, Model } from "./types.ts";

export interface ModelsStoreEntry {
	models: readonly Model<Api>[];
	/** Unix timestamp of the last completed remote catalog check. */
	checkedAt?: number;
}

/** Persistent last-known model catalogs keyed by provider ID. */
export interface ModelsStore {
	read(providerId: string): Promise<ModelsStoreEntry | undefined>;
	write(providerId: string, entry: ModelsStoreEntry): Promise<void>;
	delete(providerId: string): Promise<void>;
}

/** Provider-scoped view that cannot access another provider's catalog. */
export interface ProviderModelsStore {
	read(): Promise<ModelsStoreEntry | undefined>;
	write(entry: ModelsStoreEntry): Promise<void>;
	delete(): Promise<void>;
}

/** In-memory store that clones at both boundaries to prevent aliasing. */
export class InMemoryModelsStore implements ModelsStore {
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
