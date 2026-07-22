import type { Credential, CredentialInfo, CredentialStore } from "@pi-recon/repi-ai";
import type { CredentialStoreChange, CredentialStoreChangeSource, ObservableCredentialStore } from "./auth-storage.ts";

interface RuntimeCredentialInfo extends CredentialInfo {
	source: CredentialStoreChangeSource;
}

/** Async credential store overlay for non-persistent runtime API keys. */
export class RuntimeCredentials implements CredentialStore {
	private readonly store: CredentialStore;
	private readonly overrides = new Map<string, { key: string; version: number }>();
	private readonly backingCredentials = new Map<string, RuntimeCredentialInfo>();
	private readonly listeners = new Set<(change: CredentialStoreChange) => void>();
	private readonly observableStore: Partial<ObservableCredentialStore>;
	private readonly observesStoreMutations: boolean;
	private readonly unsubscribeStoreChanges: () => void;
	private disposed = false;
	private nextOverrideVersion = 0;

	constructor(store: CredentialStore) {
		this.store = store;
		const observable = store as Partial<ObservableCredentialStore>;
		this.observableStore = observable;
		this.observesStoreMutations = typeof observable.subscribe === "function";
		this.unsubscribeStoreChanges =
			observable.subscribe?.((change) => {
				if (this.disposed) return;
				this.updateBackingCredential(change);
				if (!this.overrides.has(change.providerId)) this.emit(change);
			}) ?? (() => {});
	}

	/** Release the subscription to the persistent store and all runtime listeners. */
	dispose(): void {
		if (this.disposed) return;
		this.disposed = true;
		try {
			this.unsubscribeStoreChanges();
		} finally {
			this.listeners.clear();
			this.overrides.clear();
			this.backingCredentials.clear();
		}
	}

	subscribe(listener: (change: CredentialStoreChange) => void): () => void {
		this.listeners.add(listener);
		return () => this.listeners.delete(listener);
	}

	private emit(change: CredentialStoreChange): void {
		for (const listener of [...this.listeners]) {
			try {
				listener(change);
			} catch {
				// Credential mutations must not depend on observer health.
			}
		}
	}

	private updateBackingCredential(change: CredentialStoreChange): void {
		if (change.credentialType === undefined) {
			this.backingCredentials.delete(change.providerId);
			return;
		}
		this.backingCredentials.set(change.providerId, {
			providerId: change.providerId,
			type: change.credentialType,
			source: change.source ?? "stored",
		});
	}

	private effectiveChange(providerId: string): CredentialStoreChange {
		if (this.overrides.has(providerId)) {
			return { providerId, credentialType: "api_key", source: "runtime" };
		}
		const backing = this.backingCredentials.get(providerId);
		return backing ? { providerId, credentialType: backing.type, source: backing.source } : { providerId };
	}

	setRuntimeApiKey(providerId: string, apiKey: string): void {
		if (apiKey.length === 0) throw new Error("Runtime API key must not be empty");
		this.overrides.set(providerId, { key: apiKey, version: ++this.nextOverrideVersion });
		this.emit(this.effectiveChange(providerId));
	}

	removeRuntimeApiKey(providerId: string): void {
		if (this.overrides.delete(providerId)) this.emit(this.effectiveChange(providerId));
	}

	hasRuntimeApiKey(providerId: string): boolean {
		return this.overrides.has(providerId);
	}

	getCredentialSource(providerId: string): CredentialStoreChangeSource | undefined {
		return this.overrides.has(providerId) ? "runtime" : this.backingCredentials.get(providerId)?.source;
	}

	async read(providerId: string): Promise<Credential | undefined> {
		const override = this.overrides.get(providerId);
		if (override !== undefined) return { type: "api_key", key: override.key };
		const credential = await this.store.read(providerId);
		if (credential) {
			const source =
				this.observableStore.getCredentialSource?.(providerId) ??
				this.backingCredentials.get(providerId)?.source ??
				"stored";
			this.backingCredentials.set(providerId, { providerId, type: credential.type, source });
		} else {
			this.backingCredentials.delete(providerId);
		}
		return credential;
	}

	async list(): Promise<readonly CredentialInfo[]> {
		const stored = await this.store.list();
		this.backingCredentials.clear();
		for (const entry of stored) {
			const source = this.observableStore.getCredentialSource?.(entry.providerId) ?? "stored";
			this.backingCredentials.set(entry.providerId, { ...entry, source });
		}
		const entries = new Map(this.backingCredentials);
		for (const providerId of this.overrides.keys()) {
			entries.set(providerId, { providerId, type: "api_key", source: "runtime" });
		}
		return [...entries.values()].map(({ providerId, type }) => ({ providerId, type }));
	}

	async modify(
		providerId: string,
		fn: (current: Credential | undefined) => Promise<Credential | undefined>,
	): Promise<Credential | undefined> {
		const credential = await this.store.modify(providerId, fn);
		if (!this.observesStoreMutations) {
			this.updateBackingCredential({
				providerId,
				credentialType: credential?.type,
				source: credential ? "stored" : undefined,
			});
			if (!this.overrides.has(providerId)) this.emit(this.effectiveChange(providerId));
		}
		return credential;
	}

	async delete(providerId: string): Promise<void> {
		const overrideVersion = this.overrides.get(providerId)?.version;
		await this.store.delete(providerId);
		if (!this.observesStoreMutations) this.backingCredentials.delete(providerId);
		const removesOverride =
			overrideVersion !== undefined && this.overrides.get(providerId)?.version === overrideVersion;
		if (removesOverride) this.overrides.delete(providerId);
		if (!this.observesStoreMutations || removesOverride) this.emit(this.effectiveChange(providerId));
	}
}
