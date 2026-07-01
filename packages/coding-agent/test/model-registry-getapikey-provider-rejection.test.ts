/**
 * opt #245 — getApiKeyForProvider wraps its body in try/catch, mirroring the
 * sibling getApiKeyAndHeaders, so an authStorage.getApiKey rejection surfaces
 * as undefined instead of an unhandled rejection.
 *
 * getApiKeyAndHeaders converts any throw into {ok:false,error}. getApiKeyForProvider
 * did the same authStorage.getApiKey + config-value resolution with NO try/catch,
 * so an OAuth provider.getApiKey rejection (auth-storage non-refresh branch)
 * propagated to the caller. Same operation, two different error contracts.
 *
 * Fix: try/catch → return undefined (the "resolution failed → undefined"
 * contract the rest of the file uses). The test spies authStorage.getApiKey to
 * reject and asserts getApiKeyForProvider resolves to undefined. Pre-fix (catch
 * removed) the await rejects.
 */
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";

describe("opt #245: getApiKeyForProvider returns undefined when authStorage.getApiKey rejects", () => {
	let tempDir: string;
	let authStorage: AuthStorage;

	beforeEach(() => {
		tempDir = join(tmpdir(), `opt245-getapikey-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		authStorage = AuthStorage.create(join(tempDir, "auth.json"));
	});

	afterEach(() => {
		vi.restoreAllMocks();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("resolves to undefined (does not reject) when getApiKey throws", async () => {
		const registry = ModelRegistry.inMemory(authStorage);
		const getApiKeySpy = vi.spyOn(authStorage, "getApiKey").mockRejectedValue(new Error("oauth provider boom"));

		// Post-fix: caught → resolves undefined. Pre-fix: the await rejects with
		// "oauth provider boom" → toHaveResolved fails.
		await expect(registry.getApiKeyForProvider("some-provider")).resolves.toBeUndefined();
		expect(getApiKeySpy).toHaveBeenCalled();
	});
});
