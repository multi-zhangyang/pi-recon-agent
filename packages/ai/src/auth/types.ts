import type { ProviderEnv, ProviderHeaders } from "../types.ts";

/** Request-scoped authentication values understood by every provider. */
export interface ModelAuth {
	apiKey?: string;
	headers?: ProviderHeaders;
	baseUrl?: string;
}

/** Stored API-key credential, aligned with the existing auth.json format. */
export interface ApiKeyCredential {
	type: "api_key";
	key?: string;
	env?: ProviderEnv;
}

/** OAuth token fields shared with the compatibility OAuth layer. */
export interface OAuthCredentials {
	refresh: string;
	access: string;
	expires: number;
	[key: string]: unknown;
}

/** Stored canonical OAuth credential. */
export interface OAuthCredential extends OAuthCredentials {
	type: "oauth";
}

export type Credential = ApiKeyCredential | OAuthCredential;

/** Non-secret metadata used for account and status enumeration. */
export interface CredentialInfo {
	providerId: string;
	type: Credential["type"];
}

/**
 * App-owned credential persistence. `modify` is the sole write path so OAuth
 * token rotation can be serialized across concurrent requests.
 */
export interface CredentialStore {
	read(providerId: string): Promise<Credential | undefined>;
	list(): Promise<readonly CredentialInfo[]>;
	modify(
		providerId: string,
		fn: (current: Credential | undefined) => Promise<Credential | undefined>,
	): Promise<Credential | undefined>;
	delete(providerId: string): Promise<void>;
}

/** Injectable ambient environment and filesystem access for auth resolution. */
export interface AuthContext {
	env(name: string): Promise<string | undefined>;
	fileExists(path: string): Promise<boolean>;
}

export interface AuthResult {
	auth: ModelAuth;
	env?: ProviderEnv;
	/** Human-readable source label for status surfaces. */
	source?: string;
}

export interface AuthCheck {
	source?: string;
	type: "api_key" | "oauth";
}

export type AuthType = "api_key" | "oauth";

export type AuthPrompt = { signal?: AbortSignal } & (
	| { type: "text"; message: string; placeholder?: string }
	| { type: "secret"; message: string; placeholder?: string }
	| { type: "select"; message: string; options: readonly { id: string; label: string; description?: string }[] }
	| { type: "manual_code"; message: string; placeholder?: string }
);

export interface AuthInfoLink {
	url: string;
	label?: string;
}

export type AuthEvent =
	| { type: "info"; message: string; links?: readonly AuthInfoLink[] }
	| { type: "auth_url"; url: string; instructions?: string }
	| {
			type: "device_code";
			userCode: string;
			verificationUri: string;
			intervalSeconds?: number;
			expiresInSeconds?: number;
	  }
	| { type: "progress"; message: string };

/** Host callbacks used by both API-key and OAuth login flows. */
export interface AuthInteraction {
	signal?: AbortSignal;
	prompt(prompt: AuthPrompt): Promise<string>;
	notify(event: AuthEvent): void;
}

export interface ApiKeyAuth {
	name: string;
	login?(interaction: AuthInteraction): Promise<ApiKeyCredential>;
	/** Optional side-effect-free availability check. */
	check?(input: { ctx: AuthContext; credential?: ApiKeyCredential }): Promise<AuthCheck | undefined>;
	resolve(input: { ctx: AuthContext; credential?: ApiKeyCredential }): Promise<AuthResult | undefined>;
}

export interface OAuthAuth {
	name: string;
	loginLabel?: string;
	login(interaction: AuthInteraction): Promise<OAuthCredential>;
	refresh(credential: OAuthCredential, signal?: AbortSignal): Promise<OAuthCredential>;
	toAuth(credential: OAuthCredential): Promise<ModelAuth>;
}

/** Provider-owned authentication methods. */
export interface ProviderAuth {
	apiKey?: ApiKeyAuth;
	oauth?: OAuthAuth;
}
