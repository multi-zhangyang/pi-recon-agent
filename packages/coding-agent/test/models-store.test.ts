import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Model } from "@pi-recon/repi-ai";
import { afterEach, describe, expect, it } from "vitest";
import { FileModelsStore } from "../src/core/models-store.ts";

const tempDirs: string[] = [];

afterEach(() => {
	for (const path of tempDirs.splice(0)) {
		if (existsSync(path)) rmSync(path, { recursive: true, force: true });
	}
});

function model(provider: string, id: string): Model<"openai-completions"> {
	return {
		id,
		name: id,
		api: "openai-completions",
		provider,
		baseUrl: "https://example.test/v1",
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 1_000,
		maxTokens: 100,
	};
}

describe("FileModelsStore", () => {
	it("does not materialize a missing cache on read and creates the first write privately", async () => {
		const dir = join(tmpdir(), `repi-models-store-lazy-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		tempDirs.push(dir);
		mkdirSync(dir, { recursive: true });
		const path = join(dir, "models-store.json");
		const store = new FileModelsStore(path);

		expect(await store.read("missing")).toBeUndefined();
		expect(existsSync(path)).toBe(false);

		await store.write("dynamic", { models: [model("dynamic", "first")], checkedAt: 1 });
		expect(statSync(path).mode & 0o777).toBe(0o600);
		expect((await store.read("dynamic"))?.models[0]?.id).toBe("first");
	});

	it("serializes concurrent provider updates without replacing siblings", async () => {
		const dir = join(tmpdir(), `repi-models-store-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		tempDirs.push(dir);
		mkdirSync(dir, { recursive: true });
		const path = join(dir, "models-store.json");
		const stores = Array.from({ length: 8 }, () => new FileModelsStore(path));

		await Promise.all(
			stores.map((store, index) =>
				store.write(`provider-${index}`, {
					models: [model(`provider-${index}`, `model-${index}`)],
					checkedAt: index,
				}),
			),
		);

		const persisted = JSON.parse(readFileSync(path, "utf-8")) as Record<string, unknown>;
		expect(Object.keys(persisted).sort()).toEqual(
			Array.from({ length: 8 }, (_, index) => `provider-${index}`).sort(),
		);
		expect(statSync(path).mode & 0o777).toBe(0o600);

		const reloaded = new FileModelsStore(path);
		expect((await reloaded.read("provider-3"))?.models[0]?.id).toBe("model-3");
		await reloaded.delete("provider-3");
		expect(await reloaded.read("provider-3")).toBeUndefined();
		expect((await reloaded.read("provider-4"))?.models[0]?.id).toBe("model-4");
	});

	it("treats malformed JSON and invalid entries as cache misses that can be healed", async () => {
		const dir = join(tmpdir(), `repi-models-store-corrupt-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		tempDirs.push(dir);
		mkdirSync(dir, { recursive: true });
		const path = join(dir, "models-store.json");
		const store = new FileModelsStore(path);

		writeFileSync(path, "{not-json");
		expect(await store.read("dynamic")).toBeUndefined();
		await store.write("dynamic", { models: [model("dynamic", "healed")], checkedAt: 10 });
		expect((await store.read("dynamic"))?.models[0]?.id).toBe("healed");

		writeFileSync(
			path,
			JSON.stringify({
				dynamic: { models: "not-an-array", checkedAt: "not-a-number" },
				valid: { models: [model("valid", "preserved")], checkedAt: 20 },
			}),
		);
		expect(await store.read("dynamic")).toBeUndefined();
		expect((await store.read("valid"))?.models[0]?.id).toBe("preserved");
		await store.write("dynamic", { models: [model("dynamic", "recovered")], checkedAt: 30 });
		expect((await store.read("dynamic"))?.models[0]?.id).toBe("recovered");
		expect((await store.read("valid"))?.models[0]?.id).toBe("preserved");
	});

	it("round-trips provider ids that overlap Object prototype properties", async () => {
		const dir = join(tmpdir(), `repi-models-store-keys-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		tempDirs.push(dir);
		mkdirSync(dir, { recursive: true });
		const path = join(dir, "models-store.json");
		const store = new FileModelsStore(path);

		for (const providerId of ["__proto__", "toString", "constructor"]) {
			await store.write(providerId, {
				models: [model(providerId, `${providerId}-model`)],
				checkedAt: 1,
			});
		}

		for (const providerId of ["__proto__", "toString", "constructor"]) {
			expect((await store.read(providerId))?.models[0]?.provider).toBe(providerId);
		}
		expect(Object.keys(JSON.parse(readFileSync(path, "utf-8")) as Record<string, unknown>).sort()).toEqual(
			["__proto__", "constructor", "toString"].sort(),
		);
	});
});
