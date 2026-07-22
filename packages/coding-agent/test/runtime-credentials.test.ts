import { type CredentialStore, InMemoryCredentialStore } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";
import type { CredentialStoreChange, ObservableCredentialStore } from "../src/core/auth-storage.ts";
import { RuntimeCredentials } from "../src/core/runtime-credentials.ts";

describe("RuntimeCredentials", () => {
	it("unsubscribes from an observable backing store when disposed", () => {
		const persistent = new InMemoryCredentialStore();
		const backingListeners = new Set<(change: CredentialStoreChange) => void>();
		let activeSubscriptions = 0;
		const observable: ObservableCredentialStore = {
			read: (providerId) => persistent.read(providerId),
			list: () => persistent.list(),
			modify: (providerId, fn) => persistent.modify(providerId, fn),
			delete: (providerId) => persistent.delete(providerId),
			getCredentialSource: () => "stored",
			subscribe: (listener) => {
				activeSubscriptions++;
				backingListeners.add(listener);
				return () => {
					if (!backingListeners.delete(listener)) return;
					activeSubscriptions--;
				};
			},
		};
		const credentials = new RuntimeCredentials(observable);
		const changes: CredentialStoreChange[] = [];
		credentials.subscribe((change) => changes.push(change));

		expect(activeSubscriptions).toBe(1);
		credentials.dispose();
		credentials.dispose();
		expect(activeSubscriptions).toBe(0);

		for (const listener of backingListeners) {
			listener({ providerId: "provider", credentialType: "api_key", source: "stored" });
		}
		expect(changes).toEqual([]);
	});

	it("publishes non-secret events for overlay and persistent mutations", async () => {
		const credentials = new RuntimeCredentials(new InMemoryCredentialStore());
		const changes: unknown[] = [];
		credentials.subscribe((change) => changes.push(change));

		credentials.setRuntimeApiKey("provider", "secret-runtime-key");
		credentials.removeRuntimeApiKey("provider");
		await credentials.modify("provider", async () => ({ type: "api_key", key: "secret-stored-key" }));
		await credentials.delete("provider");

		expect(changes).toEqual([
			{ providerId: "provider", credentialType: "api_key", source: "runtime" },
			{ providerId: "provider" },
			{ providerId: "provider", credentialType: "api_key", source: "stored" },
			{ providerId: "provider" },
		]);
		expect(JSON.stringify(changes)).not.toContain("secret-");
	});

	it("rejects empty runtime API keys without publishing configured state", async () => {
		const credentials = new RuntimeCredentials(new InMemoryCredentialStore());

		expect(() => credentials.setRuntimeApiKey("provider", "")).toThrow("must not be empty");
		expect(credentials.hasRuntimeApiKey("provider")).toBe(false);
		expect(await credentials.read("provider")).toBeUndefined();
		expect(await credentials.list()).toEqual([]);
	});

	it("retains the runtime override when persistent deletion fails", async () => {
		const persistent = new InMemoryCredentialStore();
		await persistent.modify("provider", async () => ({ type: "api_key", key: "stored-key" }));
		const failingStore: CredentialStore = {
			read: (providerId) => persistent.read(providerId),
			list: () => persistent.list(),
			modify: (providerId, fn) => persistent.modify(providerId, fn),
			delete: async () => {
				throw new Error("persistent delete failed");
			},
		};
		const credentials = new RuntimeCredentials(failingStore);
		credentials.setRuntimeApiKey("provider", "runtime-key");

		await expect(credentials.delete("provider")).rejects.toThrow("persistent delete failed");
		expect(credentials.hasRuntimeApiKey("provider")).toBe(true);
		expect(await credentials.read("provider")).toEqual({ type: "api_key", key: "runtime-key" });
		expect(await persistent.read("provider")).toEqual({ type: "api_key", key: "stored-key" });
	});

	it("does not remove a newer runtime override after an older delete completes", async () => {
		const persistent = new InMemoryCredentialStore();
		let releaseDelete = () => {};
		let markDeleteStarted = () => {};
		const deleteStarted = new Promise<void>((resolve) => {
			markDeleteStarted = resolve;
		});
		const deleteGate = new Promise<void>((resolve) => {
			releaseDelete = resolve;
		});
		const delayedStore: CredentialStore = {
			read: (providerId) => persistent.read(providerId),
			list: () => persistent.list(),
			modify: (providerId, fn) => persistent.modify(providerId, fn),
			delete: async (providerId) => {
				markDeleteStarted();
				await deleteGate;
				await persistent.delete(providerId);
			},
		};
		const credentials = new RuntimeCredentials(delayedStore);
		credentials.setRuntimeApiKey("provider", "old-runtime-key");

		const deleting = credentials.delete("provider");
		await deleteStarted;
		credentials.setRuntimeApiKey("provider", "new-runtime-key");
		releaseDelete();
		await deleting;

		expect(await credentials.read("provider")).toEqual({ type: "api_key", key: "new-runtime-key" });
	});
});
