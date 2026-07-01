/**
 * opt #244 — loadModels wraps each OAuth provider's modifyModels in try/catch
 * (and refresh() wraps each applyProviderConfig) so a throwing OAuth provider
 * no longer crashes ModelRegistry construction / startup.
 *
 * Pre-fix loadModels looped `authStorage.getOAuthProviders()` and called
 * `oauthProvider.modifyModels(combined, cred)` with NO try/catch — the one
 * asymmetry in an otherwise-wrapped file (loadCustomModels, getApiKeyAndHeaders
 * both catch). A throw propagated out of loadModels → the ModelRegistry
 * constructor → startup crash. refresh() had the same shape: it
 * resetApiProviders()/resetOAuthProviders() + cleared config maps BEFORE the
 * applyProviderConfig loop, so one throwing provider aborted the loop, left the
 * global registries wiped, this.models partially rebuilt, and every remaining
 * registered provider never reapplied — one bad extension provider poisoned ALL
 * dynamic providers.
 *
 * Fix: try/catch each iteration; surface via loadError; keep `combined`/loop
 * proceeding. The test registers an OAuth provider whose modifyModels throws,
 * stores an oauth cred for it, and asserts ModelRegistry.inMemory does not
 * throw and getError() records the failure. Pre-fix (catch removed) create
 * throws "modifyModels BOOM".
 */
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { OAuthProviderInterface } from "@pi-recon/repi-ai/oauth";
import { registerOAuthProvider, unregisterOAuthProvider } from "@pi-recon/repi-ai/oauth";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";

const PROVIDER_ID = "opt244-throwing-oauth";

const throwingProvider: OAuthProviderInterface = {
	id: PROVIDER_ID,
	name: "opt244 throwing",
	login: async () => {
		throw new Error("no login in test");
	},
	refreshToken: async (cred) => cred,
	getApiKey: () => "fake-key",
	modifyModels: () => {
		throw new Error("modifyModels BOOM");
	},
};

describe("opt #244: a throwing OAuth modifyModels does not crash ModelRegistry construction", () => {
	let tempDir: string;
	let authStorage: AuthStorage;

	beforeEach(() => {
		tempDir = join(tmpdir(), `opt244-oauth-modify-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		authStorage = AuthStorage.create(join(tempDir, "auth.json"));
		registerOAuthProvider(throwingProvider);
		// Store an oauth cred so loadModels' `cred?.type === "oauth"` gate passes
		// and modifyModels is actually invoked for this provider.
		authStorage.set(PROVIDER_ID, { type: "oauth", refresh: "r", access: "a", expires: Date.now() + 100000 });
	});

	afterEach(() => {
		unregisterOAuthProvider(PROVIDER_ID);
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("inMemory() does not throw and getError() records the provider failure", () => {
		// Post-fix: caught → loadError set, construction succeeds.
		// Pre-fix: modifyModels throw propagates out of the constructor.
		let registry: ModelRegistry;
		expect(() => {
			registry = ModelRegistry.inMemory(authStorage);
		}).not.toThrow();

		expect(registry!).toBeDefined();
		const err = registry!.getError();
		expect(err).toBeDefined();
		expect(err).toContain("modifyModels");
		expect(err).toContain(PROVIDER_ID);
	});
});
