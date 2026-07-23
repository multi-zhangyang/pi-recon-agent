import { shellQuote } from "./target.ts";

/**
 * Web specialist planning is intentionally declarative.  Browser/CDP, HAR,
 * replay and authorization work all execute through the web DomainAdapter;
 * this module only decides when that adapter belongs in a lane command pack.
 */
export type WebSpecialistCommandProviderDependencies = {
	target?: string;
	domain: string;
	laneName: string;
	context: string;
	specialists: string[];
	add(
		label: string,
		command: string,
		evidence: string,
		runtimeAdapter?: {
			adapter: string;
			target?: string;
			timeoutMs?: number;
			specialist?: string;
		},
	): void;
};

const WEB_ADAPTER = "web-cdp-network-adapter";
const WEB_ALIASES = [
	"browser-xhr-ws-capture-scaffold",
	"localStorage sessionStorage document.cookie",
	"websocket",
	"browser-xhr-ws-auth-diff-scaffold",
	"browser-cdp-artifact-scaffold",
	"browser-replay-evaluator-scaffold",
	"browser-route-graph-scaffold",
	"browser-auth-matrix-scaffold",
	"browser-idor-bola-probe-scaffold",
	"browser-authz-state-machine-scaffold",
	"browser-authz-sequence-replay-scaffold",
	"browser-authz-object-ownership-scaffold",
	"browser-authz-state-rollback-scaffold",
	"web-api-authz-static-scaffold",
	"web-api-schema-diff-scaffold",
	"web-api-state-source-scaffold",
	"browser-authz-report-scaffold",
	"browser-authz-state-report-scaffold",
	"/tmp/repi-browser-artifact.json",
];
const WEB_SCANNER_ALIASES = [
	"web-scan-scope-baseline",
	"web-scan-crawl-corpus-scaffold",
	"web-scan-content-discovery-scaffold",
	"web-scan-template-scan-scaffold",
	"web-scan-manual-replay-verifier",
];
const WEB_SIGNING_ALIASES = [
	"JS signing rebuild",
	"js-signing-rebuild-browser-hooks",
	"crypto.subtle",
	"XMLHttpRequest",
	"js-signing-rebuild-node-scaffold",
	"js-signing-observation-normalizer",
	"js-signing-first-divergence-scaffold",
	"js-signing-replay-harness-scaffold",
];

function wants(text: string, pattern: RegExp): boolean {
	return pattern.test(text);
}

export function createWebSpecialistCommandProvider(dependencies: WebSpecialistCommandProviderDependencies) {
	const { target, domain, laneName, context, specialists, add } = dependencies;
	const targetIsUrl = Boolean(target && /^https?:\/\//i.test(target));
	const webContext =
		domain === "Web pentest scanning" ||
		domain === "Web / API pentest" ||
		wants(
			context,
			/web|api|graphql|jwt|oauth|session|cookie|csrf|ssrf|idor|bola|xss|sqli|ssti|rce|browser|xhr|websocket|渗透/,
		);
	const laneContext = wants(
		laneName,
		/surface|map|state|poc|runtime|proof|verify|observe|prove|scope|crawl|scan|report|rebuild/,
	);
	const scannerContext =
		domain === "Web pentest scanning" ||
		wants(context, /nuclei|ffuf|gobuster|feroxbuster|nikto|dalfox|sqlmap|katana|crawler|漏洞扫描|目录扫描|指纹/);
	const signingContext = wants(
		context,
		/frontend|javascript|\bjs\b|签名|sign|signature|crypto|subtle|webpack|sourcemap|nonce|timestamp|encrypt|decrypt|风控/,
	);
	const authzContext = wants(
		context,
		/jwt|oauth|session|cookie|csrf|idor|bola|authz|ownership|principal|state|replay|权限/,
	);

	if (!webContext || !laneContext) return { appendScanner() {}, appendBrowserAndSigning() {} };

	function appendScanner(): void {
		if (!scannerContext) return;
		specialists.push("web vulnerability scanner/triage");
		if (!targetIsUrl) {
			add(
				"web-scan-target-discovery",
				'rg -n "https?://|baseURL|apiUrl|NEXT_PUBLIC|VITE_|openapi|swagger|graphql|sitemap|robots" . 2>/dev/null | head -220',
				"discover concrete web/API URLs before invoking the web DomainAdapter",
			);
			return;
		}
	}

	function appendBrowserAndSigning(): void {
		if (!targetIsUrl) {
			add(
				"web-route-target-discovery",
				'rg -n "https?://|baseURL|apiUrl|openapi|swagger|graphql|router|route|endpoint" . 2>/dev/null | head -260',
				"discover an explicit URL before browser/CDP execution",
			);
			return;
		}

		const aliases = [
			...WEB_ALIASES,
			...(scannerContext ? WEB_SCANNER_ALIASES : []),
			...(signingContext ? WEB_SIGNING_ALIASES : []),
		];
		const tags = [
			"browser-xhr-ws",
			authzContext ? "web-authz-principal-object-state-replay" : undefined,
			signingContext ? "js-signing-rebuild" : undefined,
			scannerContext ? "web-scan-template" : undefined,
		]
			.filter(Boolean)
			.join(" ");
		specialists.push("browser/XHR/WS");
		if (authzContext) specialists.push("principal/object/state/replay");
		if (signingContext) specialists.push("JS signing/replay");
		add(
			"web-domain-adapter-capture",
			`re_runtime_adapter run ${WEB_ADAPTER} ${shellQuote(target!)} # ${aliases.join(" ")}`,
			"single Web DomainAdapter: Playwright/CDP or HAR capture, route graph, principal/object/state probes, and replay evidence",
			{ adapter: WEB_ADAPTER, target: target!, specialist: tags },
		);
	}

	return { appendScanner, appendBrowserAndSigning };
}
