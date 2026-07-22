import type { Agent as HttpAgent } from "node:http";
import type { Agent as HttpsAgent } from "node:https";
import { HttpProxyAgent } from "http-proxy-agent";
import { HttpsProxyAgent } from "https-proxy-agent";
import type { ProviderEnv } from "../types.ts";
import { resolveHttpProxyUrlForTarget } from "./http-proxy-env.ts";

export { resolveHttpProxyUrlForTarget, UNSUPPORTED_PROXY_PROTOCOL_MESSAGE } from "./http-proxy-env.ts";

export interface NodeHttpProxyAgents {
	httpAgent: HttpAgent;
	httpsAgent: HttpsAgent;
}

export function createHttpProxyAgentsForTarget(
	targetUrl: string | URL,
	env?: ProviderEnv,
): NodeHttpProxyAgents | undefined {
	const proxyUrl = resolveHttpProxyUrlForTarget(targetUrl, env);
	if (!proxyUrl) {
		return undefined;
	}

	return {
		httpAgent: new HttpProxyAgent(proxyUrl),
		httpsAgent: new HttpsProxyAgent(proxyUrl) as unknown as HttpsAgent,
	};
}
