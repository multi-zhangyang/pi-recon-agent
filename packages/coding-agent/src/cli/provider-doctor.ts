import { createHash } from "node:crypto";
import chalk from "chalk";

type ApiStyle = "openai-completions" | "openai-responses" | "anthropic-messages";

type ProbeStatus = "pass" | "blocked" | "skipped";

interface ProviderDoctorOptions {
	baseUrl: string;
	model: string;
	api: ApiStyle | "auto";
	providerName: string;
	apiKeyEnv: string;
	apiKeyValue: string;
	contextWindow: number;
	maxTokens: number;
	timeoutMs: number;
	json: boolean;
	templateOnly: boolean;
}

interface CandidateEndpoint {
	url: string;
	recommendedBaseUrl: string;
}

interface ProbeResult {
	api: ApiStyle;
	status: ProbeStatus;
	classification: string;
	endpoint?: string;
	recommendedBaseUrl?: string;
	statusCode?: number;
	elapsedMs?: number;
	responseSha256?: string;
	contentPreview?: string;
	errorPreview?: string;
	modelsJson?: string;
}

interface ProviderDoctorReport {
	kind: "ProviderEndpointDoctorV1";
	schemaVersion: 1;
	generatedAt: string;
	providerName: string;
	model: string;
	apiKeyEnv: string;
	baseUrlInput: string;
	mode: "template-only" | "live";
	recommendedApi?: ApiStyle;
	recommendedBaseUrl?: string;
	probes: ProbeResult[];
	modelsJsonTemplate?: string;
	diagnostics: string[];
	secretHandling: {
		envRefOnly: boolean;
		literalApiKeySuppressed: boolean;
	};
}

const SUPPORTED_APIS: ApiStyle[] = ["openai-completions", "openai-responses", "anthropic-messages"];
const DEFAULT_API_KEY_ENV = "REPI_PROVIDER_DOCTOR_API_KEY";
const MARKER_BY_API: Record<ApiStyle, string> = {
	"openai-completions": "REPI_PROVIDER_DOCTOR_CHAT_OK",
	"openai-responses": "REPI_PROVIDER_DOCTOR_RESPONSES_OK",
	"anthropic-messages": "REPI_PROVIDER_DOCTOR_ANTHROPIC_OK",
};

function usage(): string {
	return `Usage:
  repi provider-doctor --base-url <url> --model <id> [options]

Options:
  --api <auto|openai-completions|openai-responses|anthropic-messages>
  --provider-name <name>         Provider id for generated models.json (default: remote-doctor)
  --api-key-env <ENV>            API key environment variable (default: ${DEFAULT_API_KEY_ENV})
  --context-window <tokens>      Context window for generated template (default: 262144)
  --max-tokens <tokens>          Max output tokens for generated template (default: 4096)
  --timeout-ms <ms>              Per-endpoint probe timeout (default: 120000; reasoning
                                 models can take >45s on even a trivial probe, so the
                                 default is widened to avoid false "blocked request_exception")
  --template-only                Only print models.json template; do not call endpoint
  --json                         Print ProviderEndpointDoctorV1 JSON

Examples:
  export ${DEFAULT_API_KEY_ENV}=sk-...
  repi provider-doctor --base-url https://gateway.example/v1 --model vendor/model --api auto
  repi provider-doctor --base-url http://127.0.0.1:8000/v1 --model local/model --api openai-completions --json
`;
}

function parseArgs(args: string[]): ProviderDoctorOptions | null {
	const options: ProviderDoctorOptions = {
		baseUrl: "",
		model: "",
		api: "auto",
		providerName: "remote-doctor",
		apiKeyEnv: DEFAULT_API_KEY_ENV,
		apiKeyValue: "",
		contextWindow: 262144,
		maxTokens: 4096,
		timeoutMs: 120000,
		json: false,
		templateOnly: false,
	};
	for (let index = 0; index < args.length; index++) {
		const arg = args[index];
		const next = () => args[++index] ?? "";
		if (arg === "--help" || arg === "-h") return null;
		if (arg === "--base-url") options.baseUrl = next();
		else if (arg === "--model") options.model = next();
		else if (arg === "--api") {
			const value = next();
			if (value === "auto" || SUPPORTED_APIS.includes(value as ApiStyle))
				options.api = value as ProviderDoctorOptions["api"];
			else throw new Error(`Unsupported --api ${value}; expected auto, ${SUPPORTED_APIS.join(", ")}`);
		} else if (arg === "--provider-name") options.providerName = next();
		else if (arg === "--api-key-env") options.apiKeyEnv = next();
		else if (arg === "--context-window") options.contextWindow = parseBoundedInt(next(), 1024, 1048576, 262144);
		else if (arg === "--max-tokens") options.maxTokens = parseBoundedInt(next(), 64, 65536, 4096);
		else if (arg === "--timeout-ms") options.timeoutMs = parseBoundedInt(next(), 1000, 300000, 120000);
		else if (arg === "--json") options.json = true;
		else if (arg === "--template-only") options.templateOnly = true;
		else throw new Error(`Unknown provider-doctor argument: ${arg}`);
	}
	if (!options.baseUrl) throw new Error("provider-doctor requires --base-url");
	if (!options.model) throw new Error("provider-doctor requires --model");
	if (!/^[A-Z_][A-Z0-9_]*$/.test(options.apiKeyEnv))
		throw new Error("--api-key-env must be an environment variable name");
	options.apiKeyValue = process.env[options.apiKeyEnv] ?? "";
	if (!options.templateOnly && !options.apiKeyValue)
		throw new Error(`Missing API key env ${options.apiKeyEnv}; export it or use --template-only`);
	return options;
}

function parseBoundedInt(value: string, min: number, max: number, fallback: number): number {
	const parsed = Number.parseInt(value, 10);
	if (!Number.isFinite(parsed)) return fallback;
	return Math.max(min, Math.min(max, parsed));
}

function trimTrailingSlash(value: string): string {
	return value.replace(/\/+$/, "");
}

function sha256(value: string): string {
	return createHash("sha256").update(value).digest("hex");
}

function redact(value: string, apiKey: string): string {
	let text = value;
	if (apiKey) text = text.split(apiKey).join("[REDACTED_API_KEY]");
	return text
		.replace(/Bearer\s+[A-Za-z0-9._:-]{8,}/gi, "Bearer [REDACTED]")
		.replace(/sk-[A-Za-z0-9._-]{8,}/gi, "[REDACTED_SK]");
}

function endpointCandidates(baseUrl: string, api: ApiStyle): CandidateEndpoint[] {
	const base = trimTrailingSlash(baseUrl);
	const hasV1 = /\/v1$/i.test(base);
	if (api === "openai-completions") {
		const candidates = [{ url: `${base}/chat/completions`, recommendedBaseUrl: base }];
		if (!hasV1) candidates.push({ url: `${base}/v1/chat/completions`, recommendedBaseUrl: `${base}/v1` });
		return uniqueCandidates(candidates);
	}
	if (api === "openai-responses") {
		const candidates = [{ url: `${base}/responses`, recommendedBaseUrl: base }];
		if (!hasV1) candidates.push({ url: `${base}/v1/responses`, recommendedBaseUrl: `${base}/v1` });
		return uniqueCandidates(candidates);
	}
	const candidates = [{ url: `${base}/v1/messages`, recommendedBaseUrl: base }];
	if (hasV1) candidates.unshift({ url: `${base}/messages`, recommendedBaseUrl: base.replace(/\/v1$/i, "") });
	return uniqueCandidates(candidates);
}

function uniqueCandidates(candidates: CandidateEndpoint[]): CandidateEndpoint[] {
	const seen = new Set<string>();
	return candidates.filter((candidate) => {
		if (seen.has(candidate.url)) return false;
		seen.add(candidate.url);
		return true;
	});
}

function providerCompat(api: ApiStyle): Record<string, unknown> {
	if (api === "anthropic-messages") {
		return {
			supportsLongCacheRetention: false,
			sendSessionAffinityHeaders: false,
			supportsCacheControlOnTools: false,
			supportsEagerToolInputStreaming: true,
		};
	}
	if (api === "openai-responses") {
		return { supportsDeveloperRole: false, supportsLongCacheRetention: false, sendSessionIdHeader: false };
	}
	return {
		supportsDeveloperRole: false,
		supportsReasoningEffort: false,
		supportsStore: false,
		supportsStrictMode: false,
		supportsUsageInStreaming: false,
		maxTokensField: "max_tokens",
	};
}

function buildModelsJson(options: ProviderDoctorOptions, api: ApiStyle, baseUrl: string): string {
	return `${JSON.stringify(
		{
			providers: {
				[options.providerName]: {
					baseUrl,
					api,
					apiKey: `$${options.apiKeyEnv}`,
					compat: providerCompat(api),
					models: [
						{
							id: options.model,
							contextWindow: options.contextWindow,
							maxTokens: options.maxTokens,
						},
					],
				},
			},
		},
		null,
		2,
	)}\n`;
}

function buildRequest(
	api: ApiStyle,
	model: string,
	marker: string,
	apiKey: string,
): { headers: Record<string, string>; body: unknown } {
	if (api === "anthropic-messages") {
		return {
			headers: { "content-type": "application/json", "x-api-key": apiKey, "anthropic-version": "2023-06-01" },
			body: {
				model,
				max_tokens: 256,
				stream: false,
				messages: [{ role: "user", content: `Reply exactly: ${marker}` }],
			},
		};
	}
	if (api === "openai-responses") {
		return {
			headers: { "content-type": "application/json", Authorization: `Bearer ${apiKey}` },
			body: { model, input: `Reply exactly: ${marker}`, max_output_tokens: 256, stream: false },
		};
	}
	return {
		headers: { "content-type": "application/json", Authorization: `Bearer ${apiKey}` },
		body: {
			model,
			max_tokens: 256,
			stream: false,
			messages: [{ role: "user", content: `Reply exactly: ${marker}` }],
		},
	};
}

function extractContent(api: ApiStyle, payload: unknown): string {
	const value = payload as Record<string, unknown>;
	if (api === "anthropic-messages") {
		const content = value.content;
		if (Array.isArray(content))
			return content.map((item) => (typeof item?.text === "string" ? item.text : "")).join("");
	}
	if (api === "openai-responses") {
		if (typeof value.output_text === "string") return value.output_text;
		if (Array.isArray(value.output)) {
			return value.output
				.map((item) => {
					const content = item?.content;
					return Array.isArray(content)
						? content.map((part) => (typeof part?.text === "string" ? part.text : "")).join("")
						: "";
				})
				.join("");
		}
	}
	const choices = value.choices;
	if (Array.isArray(choices)) {
		const message = choices[0]?.message;
		if (typeof message?.content === "string") return message.content;
	}
	return "";
}

function classifyHttpStatus(statusCode: number): string {
	if (statusCode === 401 || statusCode === 403) return "auth_failed";
	if (statusCode === 404) return "endpoint_not_found";
	if (statusCode === 429) return "rate_limited";
	if (statusCode >= 500) return "server_error";
	return "http_error";
}

async function probeCandidate(
	options: ProviderDoctorOptions,
	api: ApiStyle,
	candidate: CandidateEndpoint,
): Promise<ProbeResult> {
	const marker = MARKER_BY_API[api];
	const started = Date.now();
	try {
		const request = buildRequest(api, options.model, marker, options.apiKeyValue);
		const response = await fetch(candidate.url, {
			method: "POST",
			headers: request.headers,
			body: JSON.stringify(request.body),
			signal: AbortSignal.timeout(options.timeoutMs),
		});
		const text = await response.text();
		const elapsedMs = Date.now() - started;
		const base = {
			api,
			endpoint: candidate.url,
			recommendedBaseUrl: candidate.recommendedBaseUrl,
			statusCode: response.status,
			elapsedMs,
			responseSha256: sha256(text),
			errorPreview: redact(text.slice(0, 500), options.apiKeyValue),
		};
		if (!response.ok) {
			return { ...base, status: "blocked", classification: classifyHttpStatus(response.status) };
		}
		let parsed: unknown;
		try {
			parsed = JSON.parse(text);
		} catch {
			return { ...base, status: "blocked", classification: "json_parse_failed" };
		}
		const content = extractContent(api, parsed);
		const contentPreview = redact(content.slice(0, 500), options.apiKeyValue);
		const markerObserved = content.includes(marker);
		return {
			...base,
			status: markerObserved || content.trim() ? "pass" : "blocked",
			classification: markerObserved
				? "marker_observed"
				: content.trim()
					? "nonempty_assistant_content"
					: "empty_assistant_content",
			contentPreview,
			errorPreview: undefined,
			modelsJson: buildModelsJson(options, api, candidate.recommendedBaseUrl),
		};
	} catch (error) {
		return {
			api,
			status: "blocked",
			classification: "request_exception",
			endpoint: candidate.url,
			recommendedBaseUrl: candidate.recommendedBaseUrl,
			elapsedMs: Date.now() - started,
			errorPreview: redact(error instanceof Error ? error.message : String(error), options.apiKeyValue),
		};
	}
}

async function probeApi(options: ProviderDoctorOptions, api: ApiStyle): Promise<ProbeResult> {
	if (options.templateOnly) {
		return {
			api,
			status: "skipped",
			classification: "template_only",
			recommendedBaseUrl: trimTrailingSlash(options.baseUrl),
			modelsJson: buildModelsJson(options, api, trimTrailingSlash(options.baseUrl)),
		};
	}
	const candidates = endpointCandidates(options.baseUrl, api);
	const blocked: ProbeResult[] = [];
	for (const candidate of candidates) {
		const result = await probeCandidate(options, api, candidate);
		if (result.status === "pass") return result;
		blocked.push(result);
	}
	return (
		blocked.find((result) => result.classification === "endpoint_not_found" && result.endpoint?.includes("/v1/")) ??
		blocked.find((result) => result.classification === "endpoint_not_found") ??
		blocked[0] ?? { api, status: "blocked", classification: "no_endpoint_candidates" }
	);
}

function selectRecommendation(probes: ProbeResult[]): ProbeResult | undefined {
	const passing = probes.filter((probe) => probe.status === "pass");
	return (
		passing.find((probe) => probe.api === "openai-completions") ??
		passing.find((probe) => probe.api === "anthropic-messages") ??
		passing[0]
	);
}

async function buildReport(options: ProviderDoctorOptions): Promise<ProviderDoctorReport> {
	const apis = options.api === "auto" ? SUPPORTED_APIS : [options.api];
	const probes = [];
	for (const api of apis) probes.push(await probeApi(options, api));
	const recommendation = selectRecommendation(probes);
	const modelsJsonTemplate =
		recommendation?.modelsJson ?? buildModelsJson(options, apis[0], trimTrailingSlash(options.baseUrl));
	const diagnostics = [];
	if (!recommendation && !options.templateOnly) diagnostics.push("no_supported_endpoint_passed");
	for (const probe of probes) {
		if (probe.api === "openai-responses" && probe.classification === "endpoint_not_found") {
			diagnostics.push(
				"openai-responses endpoint not found; configure openai-completions if /chat/completions passed",
			);
		}
	}
	return {
		kind: "ProviderEndpointDoctorV1",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		providerName: options.providerName,
		model: options.model,
		apiKeyEnv: options.apiKeyEnv,
		baseUrlInput: options.baseUrl,
		mode: options.templateOnly ? "template-only" : "live",
		recommendedApi: recommendation?.api,
		recommendedBaseUrl: recommendation?.recommendedBaseUrl,
		probes,
		modelsJsonTemplate,
		diagnostics,
		secretHandling: {
			envRefOnly:
				modelsJsonTemplate.includes(`"$${options.apiKeyEnv}"`) && !modelsJsonTemplate.includes(options.apiKeyValue),
			literalApiKeySuppressed:
				!options.apiKeyValue || !JSON.stringify({ probes, modelsJsonTemplate }).includes(options.apiKeyValue),
		},
	};
}

function printText(report: ProviderDoctorReport): void {
	console.log(chalk.bold("# REPI Provider Endpoint Doctor"));
	console.log(`mode: ${report.mode}`);
	console.log(`provider: ${report.providerName}`);
	console.log(`model: ${report.model}`);
	for (const probe of report.probes) {
		const icon = probe.status === "pass" ? "✓" : probe.status === "skipped" ? "-" : "✗";
		const detail = [probe.classification, probe.statusCode ? `http=${probe.statusCode}` : undefined, probe.endpoint]
			.filter(Boolean)
			.join(" ");
		console.log(`${icon} ${probe.api}: ${probe.status} ${detail}`);
	}
	if (report.recommendedApi) {
		console.log(`recommended_api: ${report.recommendedApi}`);
		console.log(`recommended_base_url: ${report.recommendedBaseUrl}`);
	}
	for (const diagnostic of report.diagnostics) console.log(chalk.yellow(`diagnostic: ${diagnostic}`));
	console.log("\nmodels.json template:\n");
	console.log(report.modelsJsonTemplate?.trimEnd() ?? "");
}

export async function handleProviderDoctorCommand(args: string[]): Promise<boolean> {
	if (args[0] !== "provider-doctor" && args[0] !== "doctor-provider") return false;
	try {
		const parsed = parseArgs(args.slice(1));
		if (!parsed) {
			console.log(usage());
			return true;
		}
		const report = await buildReport(parsed);
		if (parsed.json) console.log(JSON.stringify(report, null, 2));
		else printText(report);
		if (report.mode === "live" && !report.recommendedApi) process.exitCode = 1;
		return true;
	} catch (error) {
		console.error(chalk.red(`Error: ${error instanceof Error ? error.message : String(error)}`));
		console.error(usage());
		process.exitCode = 1;
		return true;
	}
}
