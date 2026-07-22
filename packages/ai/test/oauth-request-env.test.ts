import { describe, expect, it } from "vitest";
import {
	createAssistantMessageEventStream,
	createModels,
	InMemoryCredentialStore,
	type Model,
	type OAuthCredential,
	type Provider,
} from "../src/index.ts";

const model: Model<"test-oauth-api"> = {
	id: "oauth-model",
	name: "OAuth Model",
	api: "test-oauth-api",
	provider: "oauth-provider",
	baseUrl: "https://example.test/v1",
	reasoning: false,
	input: ["text"],
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
	contextWindow: 10_000,
	maxTokens: 1_000,
};

describe("OAuth request-scoped env", () => {
	it("projects request env into toAuth after refresh without persisting it", async () => {
		const credentials = new InMemoryCredentialStore();
		await credentials.modify("oauth-provider", async () => ({
			type: "oauth",
			access: "expired-access",
			refresh: "refresh-token",
			expires: 0,
			env: { PERSISTED: "persisted", SHARED: "stored" },
		}));
		let refreshInput: OAuthCredential | undefined;
		let toAuthInput: OAuthCredential | undefined;
		const provider: Provider = {
			id: "oauth-provider",
			name: "OAuth Provider",
			auth: {
				oauth: {
					name: "OAuth",
					login: async () => {
						throw new Error("not used");
					},
					refresh: async (credential) => {
						refreshInput = structuredClone(credential);
						return { ...credential, access: "fresh-access", expires: Date.now() + 60_000 };
					},
					toAuth: async (credential) => {
						toAuthInput = structuredClone(credential);
						const env = credential.env as Record<string, string>;
						return { apiKey: credential.access, headers: { "x-request-env": env.REQUEST_ONLY } };
					},
				},
			},
			getModels: () => [model],
			stream: () => createAssistantMessageEventStream(),
			streamSimple: () => createAssistantMessageEventStream(),
		};
		const models = createModels({ credentials });
		models.setProvider(provider);

		const auth = await models.getAuth(model, {
			env: { REQUEST_ONLY: "request", SHARED: "request-wins" },
		});

		expect(auth?.auth).toEqual({ apiKey: "fresh-access", headers: { "x-request-env": "request" } });
		expect(refreshInput).toMatchObject({
			access: "expired-access",
			env: { PERSISTED: "persisted", SHARED: "stored" },
		});
		expect(refreshInput).not.toHaveProperty("env.REQUEST_ONLY");
		expect(toAuthInput).toMatchObject({
			access: "fresh-access",
			env: { PERSISTED: "persisted", REQUEST_ONLY: "request", SHARED: "request-wins" },
		});
		expect(await credentials.read("oauth-provider")).toMatchObject({
			access: "fresh-access",
			env: { PERSISTED: "persisted", SHARED: "stored" },
		});
		expect(await credentials.read("oauth-provider")).not.toHaveProperty("env.REQUEST_ONLY");
	});
});
