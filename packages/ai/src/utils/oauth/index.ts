/**
 * OAuth credential management for AI providers.
 *
 * Provider implementations are exported as opt-in building blocks. Importing
 * this module never registers a provider; hosts own the active registry.
 */

// Anthropic
export { anthropicOAuthProvider, loginAnthropic, refreshAnthropicToken } from "./anthropic.ts";
export * from "./device-code.ts";
// GitHub Copilot
export {
	getGitHubCopilotBaseUrl,
	githubCopilotOAuthProvider,
	loginGitHubCopilot,
	normalizeDomain,
	refreshGitHubCopilotToken,
} from "./github-copilot.ts";
// OpenAI Codex (ChatGPT OAuth)
export {
	loginOpenAICodex,
	loginOpenAICodexDeviceCode,
	OPENAI_CODEX_BROWSER_LOGIN_METHOD,
	OPENAI_CODEX_DEVICE_CODE_LOGIN_METHOD,
	openaiCodexOAuthProvider,
	refreshOpenAICodexToken,
} from "./openai-codex.ts";

export * from "./types.ts";

// ============================================================================
// Provider Registry
// ============================================================================

import { anthropicOAuthProvider } from "./anthropic.ts";
import { githubCopilotOAuthProvider } from "./github-copilot.ts";
import { openaiCodexOAuthProvider } from "./openai-codex.ts";
import type { OAuthCredentials, OAuthProviderId, OAuthProviderInfo, OAuthProviderInterface } from "./types.ts";

type RegisteredOAuthProvider = {
	provider: OAuthProviderInterface;
	sourceId?: string;
};

const BUILT_IN_OAUTH_PROVIDER_SOURCE = "pi-ai:built-in";
const oauthProviderRegistry = new Map<string, RegisteredOAuthProvider[]>();

const BUILT_IN_OAUTH_PROVIDERS: readonly OAuthProviderInterface[] = [
	anthropicOAuthProvider,
	githubCopilotOAuthProvider,
	openaiCodexOAuthProvider,
];

/**
 * Register the OAuth implementations owned by the CLI host.
 *
 * The AI package deliberately keeps provider registration opt-in so importing
 * it in a browser or library does not mutate process-global state. Hosts that
 * expose the standard login flow call this once during bootstrap and again
 * after resetting extension registrations.
 */
export function registerBuiltInOAuthProviders(): void {
	for (const provider of BUILT_IN_OAUTH_PROVIDERS) {
		const entries = oauthProviderRegistry.get(provider.id) ?? [];
		const retained = entries.filter((entry) => entry.sourceId !== BUILT_IN_OAUTH_PROVIDER_SOURCE);
		oauthProviderRegistry.set(provider.id, [{ provider, sourceId: BUILT_IN_OAUTH_PROVIDER_SOURCE }, ...retained]);
	}
}

/**
 * Get an OAuth provider by ID
 */
export function getOAuthProvider(id: OAuthProviderId): OAuthProviderInterface | undefined {
	return oauthProviderRegistry.get(id)?.at(-1)?.provider;
}

/**
 * Register an OAuth provider
 */
export function registerOAuthProvider(provider: OAuthProviderInterface, sourceId?: string): void {
	const entries = oauthProviderRegistry.get(provider.id) ?? [];
	const retained = entries.filter((entry) => entry.sourceId !== sourceId);
	oauthProviderRegistry.set(provider.id, [...retained, { provider, sourceId }]);
}

/**
 * Unregister an OAuth provider.
 *
 * Removes override layers and reveals the built-in implementation, when one exists.
 */
export function unregisterOAuthProvider(id: string): void {
	const entries = oauthProviderRegistry.get(id);
	if (!entries) return;
	const retained = entries.filter((entry) => entry.sourceId === BUILT_IN_OAUTH_PROVIDER_SOURCE);
	if (retained.length > 0) oauthProviderRegistry.set(id, retained);
	else oauthProviderRegistry.delete(id);
}

/** Remove registrations owned by one host/runtime while preserving other layers. */
export function unregisterOAuthProviders(sourceId: string): void {
	for (const [id, entries] of oauthProviderRegistry.entries()) {
		const retained = entries.filter((entry) => entry.sourceId !== sourceId);
		if (retained.length > 0) oauthProviderRegistry.set(id, retained);
		else oauthProviderRegistry.delete(id);
	}
}

/**
 * Clear all process-local OAuth provider registrations.
 */
export function resetOAuthProviders(): void {
	oauthProviderRegistry.clear();
}

/**
 * Get all registered OAuth providers
 */
export function getOAuthProviders(): OAuthProviderInterface[] {
	return Array.from(oauthProviderRegistry.values(), (entries) => entries.at(-1)?.provider).filter(
		(provider): provider is OAuthProviderInterface => provider !== undefined,
	);
}

/**
 * @deprecated Use getOAuthProviders() which returns OAuthProviderInterface[]
 */
export function getOAuthProviderInfoList(): OAuthProviderInfo[] {
	return getOAuthProviders().map((p) => ({
		id: p.id,
		name: p.name,
		available: true,
	}));
}

// ============================================================================
// High-level API (uses provider registry)
// ============================================================================

/**
 * Refresh token for any OAuth provider.
 * @deprecated Use getOAuthProvider(id).refreshToken() instead
 */
export async function refreshOAuthToken(
	providerId: OAuthProviderId,
	credentials: OAuthCredentials,
): Promise<OAuthCredentials> {
	const provider = getOAuthProvider(providerId);
	if (!provider) {
		throw new Error(`Unknown OAuth provider: ${providerId}`);
	}
	return provider.refreshToken(credentials);
}

/**
 * Get API key for a provider from OAuth credentials.
 * Automatically refreshes expired tokens.
 *
 * @returns API key string and updated credentials, or null if no credentials
 * @throws Error if refresh fails
 */
export async function getOAuthApiKey(
	providerId: OAuthProviderId,
	credentials: Record<string, OAuthCredentials>,
): Promise<{ newCredentials: OAuthCredentials; apiKey: string } | null> {
	const provider = getOAuthProvider(providerId);
	if (!provider) {
		throw new Error(`Unknown OAuth provider: ${providerId}`);
	}

	let creds = credentials[providerId];
	if (!creds) {
		return null;
	}

	// Refresh if expired
	if (Date.now() >= creds.expires) {
		try {
			creds = await provider.refreshToken(creds);
		} catch (_error) {
			throw new Error(`Failed to refresh OAuth token for ${providerId}`);
		}
	}

	const apiKey = provider.getApiKey(creds);
	return { newCredentials: creds, apiKey };
}
