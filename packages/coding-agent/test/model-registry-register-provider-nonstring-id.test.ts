import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";

// Foundational opt #269: validateProviderConfig checked only `api` for each
// model in an extension registerProvider config — NOT that `id` is a non-empty
// string. The schema-validated models.json path requires id, but the extension
// registerProvider path flows through this validator only. A model with
// `id: undefined` (extension forgot the field) or `id: 123` (typed wrong) entered
// `this.models` verbatim and crashed model resolution at model-resolver.ts
// findExactModelReferenceMatch/tryMatchModel (`model.id.toLowerCase()` /
// `b.id.localeCompare(a.id)`) — uncaught TypeError aborting --list-models /
// startup / any resolve. Same class as opt #44 (undefined.localeCompare). The
// fix mirrors ModelDefinitionSchema's `id: Type.String({ minLength: 1 })` at the
// extension entry gate so the bad model is rejected before poisoning the table.

describe("opt #269: registerProvider rejects a model with a non-string / empty id", () => {
	let tempDir: string;
	let authStorage: AuthStorage;
	let registry: ModelRegistry;

	beforeEach(() => {
		tempDir = join(tmpdir(), `opt269-model-id-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		authStorage = AuthStorage.create(join(tempDir, "auth.json"));
		registry = ModelRegistry.inMemory(authStorage);
	});

	afterEach(() => {
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("throws on id: undefined (extension forgot the field)", () => {
		expect(() =>
			registry.registerProvider("badprov", {
				baseUrl: "http://localhost:1",
				apiKey: "fake-key",
				api: "openai",
				models: [
					{
						id: undefined as unknown as string,
						name: "x",
						reasoning: false,
						input: ["text"],
						cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
						contextWindow: 4096,
						maxTokens: 1024,
					},
				],
			}),
		).toThrow(/"id" must be a non-empty string/);
	});

	it("throws on id: 123 (typed wrong — non-string)", () => {
		expect(() =>
			registry.registerProvider("badprov2", {
				baseUrl: "http://localhost:1",
				apiKey: "fake-key",
				api: "openai",
				models: [
					{
						id: 123 as unknown as string,
						name: "x",
						reasoning: false,
						input: ["text"],
						cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
						contextWindow: 4096,
						maxTokens: 1024,
					},
				],
			}),
		).toThrow(/"id" must be a non-empty string/);
	});

	it("throws on id: '' / whitespace-only (empty string)", () => {
		expect(() =>
			registry.registerProvider("badprov3", {
				baseUrl: "http://localhost:1",
				apiKey: "fake-key",
				api: "openai",
				models: [
					{
						id: "   ",
						name: "x",
						reasoning: false,
						input: ["text"],
						cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
						contextWindow: 4096,
						maxTokens: 1024,
					},
				],
			}),
		).toThrow(/"id" must be a non-empty string/);
	});

	it("accepts a valid non-empty string id (regression guard)", () => {
		expect(() =>
			registry.registerProvider("goodprov", {
				baseUrl: "http://localhost:1",
				apiKey: "fake-key",
				api: "openai",
				models: [
					{
						id: "goodprov-x",
						name: "x",
						reasoning: false,
						input: ["text"],
						cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
						contextWindow: 4096,
						maxTokens: 1024,
					},
				],
			}),
		).not.toThrow();
		// The model actually entered the table and is resolvable without crashing.
		const all = registry.getAll();
		expect(all.some((m) => m.id === "goodprov-x" && m.provider === "goodprov")).toBe(true);
	});
});
