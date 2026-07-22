import type { ProviderEnv } from "../types.ts";
import type {
	ApiKeyAuth,
	ApiKeyCredential,
	AuthContext,
	AuthResult,
	Credential,
	CredentialStore,
	OAuthAuth,
	OAuthCredential,
	ProviderAuth,
} from "./types.ts";

export type ModelsErrorCode = "model_source" | "model_validation" | "provider" | "stream" | "auth" | "oauth";

export interface AuthResolutionOverrides {
	apiKey?: string;
	env?: ProviderEnv;
}

export class ModelsError extends Error {
	readonly code: ModelsErrorCode;

	constructor(code: ModelsErrorCode, message: string, options?: { cause?: unknown }) {
		super(message, options);
		this.name = "ModelsError";
		this.code = code;
	}
}

/** Resolve provider auth with stored credentials taking ownership over ambient sources. */
export async function resolveProviderAuth(
	provider: { id: string; auth: ProviderAuth },
	credentials: CredentialStore,
	authContext: AuthContext,
	overrides?: AuthResolutionOverrides,
): Promise<AuthResult | undefined> {
	const requestAuthContext = overrides?.env ? overlayEnvAuthContext(authContext, overrides.env) : authContext;

	if (overrides?.apiKey !== undefined && provider.auth.apiKey) {
		return resolveApiKey(requestAuthContext, provider.auth.apiKey, provider.id, {
			type: "api_key",
			key: overrides.apiKey,
			env: overrides.env,
		});
	}

	const stored = await readCredential(credentials, provider.id);
	if (stored) {
		if (stored.type === "oauth" && provider.auth.oauth) {
			return resolveStoredOAuth(credentials, provider.id, provider.auth.oauth, stored, overrides?.env);
		}
		if (stored.type === "api_key" && provider.auth.apiKey) {
			const credential = overrides?.env ? { ...stored, env: { ...stored.env, ...overrides.env } } : stored;
			return resolveApiKey(requestAuthContext, provider.auth.apiKey, provider.id, credential);
		}
		return undefined;
	}

	return provider.auth.apiKey
		? resolveApiKey(requestAuthContext, provider.auth.apiKey, provider.id, undefined)
		: undefined;
}

function overlayEnvAuthContext(base: AuthContext, env: ProviderEnv): AuthContext {
	return {
		env: async (name) => env[name] || (await base.env(name)),
		fileExists: (path) => base.fileExists(path),
	};
}

async function resolveStoredOAuth(
	credentials: CredentialStore,
	providerId: string,
	oauth: OAuthAuth,
	stored: OAuthCredential,
	requestEnv?: ProviderEnv,
): Promise<AuthResult | undefined> {
	let credential = stored;

	if (Date.now() >= credential.expires) {
		let post: Credential | undefined;
		try {
			post = await credentials.modify(providerId, async (current) => {
				if (current?.type !== "oauth" || Date.now() < current.expires) return undefined;
				try {
					return await oauth.refresh(current);
				} catch (error) {
					throw new ModelsError("oauth", `OAuth refresh failed for ${providerId}`, { cause: error });
				}
			});
		} catch (error) {
			if (error instanceof ModelsError) throw error;
			throw new ModelsError("auth", `Credential store modify failed for ${providerId}`, { cause: error });
		}
		if (post?.type !== "oauth") return undefined;
		credential = post;
	}

	try {
		const requestCredential = requestEnv
			? {
					...credential,
					env: {
						...credentialProviderEnv(credential),
						...requestEnv,
					},
				}
			: credential;
		return { auth: await oauth.toAuth(requestCredential), source: "OAuth" };
	} catch (error) {
		throw new ModelsError("oauth", `OAuth auth derivation failed for ${providerId}`, { cause: error });
	}
}

function credentialProviderEnv(credential: OAuthCredential): ProviderEnv | undefined {
	const env = credential.env;
	if (typeof env !== "object" || env === null || Array.isArray(env)) return undefined;
	const entries = Object.entries(env).filter((entry): entry is [string, string] => typeof entry[1] === "string");
	return entries.length > 0 ? Object.fromEntries(entries) : undefined;
}

async function resolveApiKey(
	authContext: AuthContext,
	auth: ApiKeyAuth,
	providerId: string,
	credential: ApiKeyCredential | undefined,
): Promise<AuthResult | undefined> {
	try {
		return await auth.resolve({ ctx: authContext, credential });
	} catch (error) {
		throw new ModelsError("auth", `API key auth failed for provider ${providerId}`, { cause: error });
	}
}

async function readCredential(credentials: CredentialStore, providerId: string): Promise<Credential | undefined> {
	try {
		return await credentials.read(providerId);
	} catch (error) {
		throw new ModelsError("auth", `Credential store read failed for ${providerId}`, { cause: error });
	}
}
