import { afterEach, describe, expect, it } from "vitest";
import {
	clearImageModelCatalog,
	getImageModel,
	getImageModels,
	getImageProviders,
	registerImageModelCatalog,
} from "../src/image-models.ts";
import type { ImagesModel } from "../src/types.ts";

const model: ImagesModel<"custom-images-api"> = {
	id: "example/image-model",
	name: "Example Image Model",
	api: "custom-images-api",
	provider: "custom-images",
	baseUrl: "https://example.test/v1",
	input: ["text", "image"],
	output: ["image"],
	cost: { input: 1, output: 2, cacheRead: 0, cacheWrite: 0 },
};

describe("image model catalog", () => {
	afterEach(() => clearImageModelCatalog());

	it("starts empty instead of loading a generated catalog", () => {
		clearImageModelCatalog();

		expect(getImageProviders()).toEqual([]);
		expect(getImageModels("openrouter")).toEqual([]);
		expect(getImageModel("openrouter", model.id)).toBeUndefined();
	});

	it("loads only catalogs explicitly registered by the host", () => {
		registerImageModelCatalog({ "custom-images": { [model.id]: model } });

		expect(getImageProviders()).toEqual(["custom-images"]);
		expect(getImageModels("custom-images")).toEqual([model]);
		expect(getImageModel("custom-images", model.id)).toBe(model);
	});
});
