import type { ApiKeyAuth, OAuthAuth } from "./types.ts";

/** Standard stored-key then environment-variable auth policy. */
export function envApiKeyAuth(name: string, envVars: readonly string[]): ApiKeyAuth {
	return {
		name,
		login: async (interaction) => ({
			type: "api_key",
			key: await interaction.prompt({ type: "secret", message: `Enter ${name}` }),
		}),
		resolve: async ({ ctx, credential }) => {
			if (credential?.key) return { auth: { apiKey: credential.key }, source: "stored credential" };
			for (const envVar of envVars) {
				const value = await ctx.env(envVar);
				if (value) return { auth: { apiKey: value }, source: envVar };
			}
			return undefined;
		},
	};
}

/** Defers loading an OAuth implementation until it is first used. */
export function lazyOAuth(input: { name: string; loginLabel?: string; load: () => Promise<OAuthAuth> }): OAuthAuth {
	let promise: Promise<OAuthAuth> | undefined;
	const loaded = () => {
		promise ??= input.load();
		return promise;
	};
	return {
		name: input.name,
		loginLabel: input.loginLabel,
		login: async (interaction) => (await loaded()).login(interaction),
		refresh: async (credential, signal) => (await loaded()).refresh(credential, signal),
		toAuth: async (credential) => (await loaded()).toAuth(credential),
	};
}
