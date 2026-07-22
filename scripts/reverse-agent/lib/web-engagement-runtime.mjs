import { createHash } from "node:crypto";
import { join } from "node:path";
import {
	webRuntimeReplayVerifierRows,
	webSignerRebuildWorkbenchRows,
	writeWebExploitClaims,
	writeWebExploitVerification,
	writeWebExploitVerifier,
} from "./web-replay-proof.mjs";

let deep;
let noWrite;
let root;
let redact;
let shellQuote;
let writePrivate;
let readJsonArtifact;
let bufferSha256;
let httpSecretHash;
let shortHash;
let slug;
let commandExists;
let run;
let timeoutMs;
let localScriptsDir;

export function configureWebEngagementRuntime(runtime) {
	({
		deep,
		noWrite,
		root,
		redact,
		shellQuote,
		writePrivate,
		readJsonArtifact,
		bufferSha256,
		httpSecretHash,
		shortHash,
		slug,
		commandExists,
		run,
		timeoutMs,
		localScriptsDir,
	} = runtime);
}

function isUrl(value) {
	try {
		const url = new URL(value);
		return url.protocol === "http:" || url.protocol === "https:";
	} catch {
		return false;
	}
}

function resolveHttpAssetUrl(base, asset) {
	try {
		const url = new URL(asset, base);
		return url.protocol === "http:" || url.protocol === "https:" ? url.href : undefined;
	} catch {
		return undefined;
	}
}

function webReplayProofRuntime() {
	return {
		root,
		noWrite,
		redact,
		shellQuote,
		writePrivate,
		readJsonArtifact,
		bufferSha256,
		httpSecretHash,
		shortHash,
		jsSignatureEndpointCandidates,
	};
}

function collectWebEndpointHints(body, baseUrl) {
	const hints = new Set();
	const patterns = [
		/\b(?:fetch|open)\(\s*["'`]([^"'`]+)["'`]/gi,
		/\b(?:axios|request)\.(?:get|post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]/gi,
		/\baction=["']([^"']+)["']/gi,
		/\bhref=["']([^"']+)["']/gi,
		/["'`](\/(?:api|graphql|oauth|auth|login|admin|v\d+|static|assets)\/[^"'`\s<>]*)["'`]/gi,
	];
	for (const pattern of patterns) {
		for (const match of body.matchAll(pattern)) {
			const value = match[1];
			if (!value || value.startsWith("data:") || value.startsWith("javascript:")) continue;
			const resolved = resolveHttpAssetUrl(baseUrl, value) ?? value;
			if (/\.(?:png|jpg|jpeg|gif|css|ico|svg|woff2?)(?:[?#]|$)/i.test(resolved)) continue;
			hints.add(resolved.slice(0, 240));
			if (hints.size >= 80) return Array.from(hints);
		}
	}
	return Array.from(hints);
}

function sameOriginHttpUrl(baseUrl, value) {
	try {
		const base = new URL(baseUrl);
		const url = new URL(value, baseUrl);
		if (!["http:", "https:"].includes(url.protocol)) return undefined;
		if (url.origin !== base.origin) return undefined;
		return url.href;
	} catch {
		return undefined;
	}
}

function parseReplayMeta(stdout) {
	const match = String(stdout ?? "").match(/\[repi-web-replay\]\s+status=(\d{3})\s+effective=(\S+)\s+bytes=(\d+)\s+redirects=(\d+)/);
	if (!match) return {};
	return {
		status: Number(match[1]),
		effectiveUrl: match[2],
		bytes: Number(match[3]),
		redirects: Number(match[4]),
	};
}

function parseDiscoveryMeta(stdout) {
	const match = String(stdout ?? "").match(/\[repi-web-discovery\]\s+status=(\d{3})\s+effective=(\S+)\s+bytes=(\d+)\s+redirects=(\d+)\s+type=([^\n\r]*)/);
	if (!match) return {};
	return {
		status: Number(match[1]),
		effectiveUrl: match[2],
		bytes: Number(match[3]),
		redirects: Number(match[4]),
		contentType: match[5]?.trim() || null,
	};
}

function parseSchemaProbeMeta(stdout) {
	const match = String(stdout ?? "").match(/\[repi-web-schema\]\s+kind=([a-z-]+)\s+status=(\d{3})\s+effective=(\S+)\s+bytes=(\d+)\s+redirects=(\d+)/);
	if (!match) return {};
	return {
		kind: match[1],
		status: Number(match[2]),
		effectiveUrl: match[3],
		bytes: Number(match[4]),
		redirects: Number(match[5]),
	};
}

function responseBodyBeforeMarker(stdout, marker) {
	return String(stdout ?? "").replace(new RegExp(`\\n\\[${marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\][\\s\\S]*$`), "");
}

function sha256Hex(value) {
	return createHash("sha256").update(String(value ?? "")).digest("hex");
}

function extractSetCookiePairs(transcript) {
	const pairs = [];
	for (const match of String(transcript ?? "").matchAll(/^set-cookie:\s*([^=\s;]+)=([^;\r\n]*)/gim)) {
		const name = match[1]?.trim();
		const value = match[2] ?? "";
		if (!name || pairs.some((pair) => pair.name === name)) continue;
		pairs.push({ name, value, valueSha256: sha256Hex(value) });
		if (pairs.length >= 12) break;
	}
	return pairs;
}

function parseSetCookieRows(transcript) {
	const rows = [];
	for (const match of String(transcript ?? "").matchAll(/^set-cookie:\s*([^\r\n]+)/gim)) {
		const raw = match[1] ?? "";
		const parts = raw.split(";").map((part) => part.trim()).filter(Boolean);
		const [nameValue, ...attributes] = parts;
		const eq = nameValue.indexOf("=");
		if (eq <= 0) continue;
		const name = nameValue.slice(0, eq).trim();
		const value = nameValue.slice(eq + 1);
		if (!name || rows.some((row) => row.name === name)) continue;
		const attr = new Map();
		for (const item of attributes) {
			const index = item.indexOf("=");
			const key = (index >= 0 ? item.slice(0, index) : item).trim().toLowerCase();
			const attrValue = index >= 0 ? item.slice(index + 1).trim() : true;
			if (key) attr.set(key, attrValue);
		}
		const sessionLike = /(?:sid|sess|session|auth|token|jwt|id[_-]?token|access|refresh|remember|sso)/i.test(name);
		const sameSite = attr.has("samesite") ? String(attr.get("samesite")).slice(0, 40) : null;
		const secure = attr.has("secure");
		const httpOnly = attr.has("httponly");
		const risks = [];
		if (sessionLike && !httpOnly) risks.push("session-cookie-missing-httponly");
		if (sessionLike && !secure) risks.push("session-cookie-missing-secure");
		if (sessionLike && !sameSite) risks.push("session-cookie-missing-samesite");
		if (/^none$/i.test(sameSite ?? "") && !secure) risks.push("cookie-samesite-none-without-secure");
		if (name.startsWith("__Host-") && (!secure || attr.has("domain") || attr.get("path") !== "/")) risks.push("__Host-cookie-prefix-violation");
		if (name.startsWith("__Secure-") && !secure) risks.push("__Secure-cookie-prefix-violation");
		rows.push({
			name,
			valueLength: value.length,
			valueSha256: sha256Hex(value),
			httpOnly,
			secure,
			sameSite,
			path: attr.has("path") ? redact(String(attr.get("path")).slice(0, 160)) : null,
			domain: attr.has("domain") ? redact(String(attr.get("domain")).slice(0, 160)) : null,
			maxAge: attr.has("max-age") ? redact(String(attr.get("max-age")).slice(0, 80)) : null,
			expires: attr.has("expires") ? redact(String(attr.get("expires")).slice(0, 120)) : null,
			sessionLike,
			risks,
		});
		if (rows.length >= 40) break;
	}
	return rows;
}

function cookieHeaderFromPairs(pairs) {
	if (!pairs.length) return undefined;
	return pairs.map((pair) => `${pair.name}=${pair.value}`).join("; ");
}

function collectCsrfHints(body) {
	const hints = [];
	const text = String(body ?? "");
	const add = (name, value, source) => {
		if (!name && !value) return;
		const normalizedName = String(name || "csrf").slice(0, 80);
		const normalizedValue = String(value ?? "");
		if (hints.some((hint) => hint.name === normalizedName && hint.valueSha256 === sha256Hex(normalizedValue))) return;
		hints.push({
			name: normalizedName,
			source,
			valueLength: normalizedValue.length,
			valueSha256: normalizedValue ? sha256Hex(normalizedValue) : null,
		});
	};
	for (const match of text.matchAll(/<meta[^>]+name=["'](?:csrf-token|csrf_token|_csrf)["'][^>]+content=["']([^"']+)["'][^>]*>/gi)) {
		add("csrf-token", match[1], "meta");
	}
	for (const match of text.matchAll(/<input[^>]+name=["']([^"']*(?:csrf|token)[^"']*)["'][^>]*value=["']([^"']*)["'][^>]*>/gi)) {
		add(match[1], match[2], "input");
	}
	return hints.slice(0, 20);
}

function base64UrlDecode(value) {
	try {
		const normalized = String(value ?? "").replace(/-/g, "+").replace(/_/g, "/");
		const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
		return Buffer.from(padded, "base64");
	} catch {
		return Buffer.alloc(0);
	}
}

function parseJsonSafe(text) {
	try {
		return JSON.parse(text);
	} catch {
		return undefined;
	}
}

function extractJsonObjectFromText(text) {
	const input = String(text ?? "");
	const direct = parseJsonSafe(input.trim());
	if (direct && typeof direct === "object") return direct;
	let best;
	let bestScore = -1;
	for (let start = input.indexOf("{"); start >= 0; start = input.indexOf("{", start + 1)) {
		let depth = 0;
		let inString = false;
		let escape = false;
		for (let index = start; index < input.length; index++) {
			const char = input[index];
			if (inString) {
				if (escape) escape = false;
				else if (char === "\\") escape = true;
				else if (char === "\"") inString = false;
				continue;
			}
			if (char === "\"") {
				inString = true;
				continue;
			}
			if (char === "{") depth++;
			else if (char === "}") {
				depth--;
				if (depth === 0) {
					const parsed = parseJsonSafe(input.slice(start, index + 1));
					if (parsed && typeof parsed === "object") {
						const score = (parsed.merge ? 1000 : 0)
							+ (parsed.runId ? 200 : 0)
							+ (parsed.evidenceRoot ? 100 : 0)
							+ (typeof parsed.kind === "string" && /swarm|worker-pool|run-report/i.test(parsed.kind) ? 100 : 0)
							+ (parsed.merge?.runId ? 50 : 0)
							+ Math.min(49, Math.floor((index - start) / 10000));
						if (score > bestScore) {
							best = parsed;
							bestScore = score;
						}
					}
					break;
				}
			}
		}
	}
	return best;
}

function hostLooksPrivateOrLocal(hostname) {
	const host = String(hostname ?? "").toLowerCase().replace(/^\[|\]$/g, "");
	if (!host) return false;
	if (host === "localhost" || host.endsWith(".localhost") || host === "::1") return true;
	if (/^(?:0|10|127)\./.test(host)) return true;
	if (/^169\.254\./.test(host)) return true;
	if (/^192\.168\./.test(host)) return true;
	const ipv4 = host.match(/^172\.(\d{1,3})\./);
	if (ipv4 && Number(ipv4[1]) >= 16 && Number(ipv4[1]) <= 31) return true;
	if (/^(?:fc|fd|fe80):/i.test(host)) return true;
	return false;
}

function summarizeJwtRemoteUrl(value, baseUrl) {
	try {
		const url = new URL(String(value));
		let sameOrigin = null;
		try {
			sameOrigin = new URL(baseUrl).origin === url.origin;
		} catch {
			// Leave null when no base URL is available.
		}
		return {
			url: redact(url.href).slice(0, 240),
			scheme: url.protocol.replace(/:$/, ""),
			host: redact(url.host).slice(0, 160),
			sameOrigin,
			privateOrLocalHost: hostLooksPrivateOrLocal(url.hostname),
		};
	} catch {
		return { url: redact(String(value)).slice(0, 240), invalid: true };
	}
}

function summarizeJwtHeaderJwk(jwk) {
	if (!jwk || typeof jwk !== "object") return null;
	const privateKeys = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
	return {
		kty: typeof jwk.kty === "string" ? redact(jwk.kty).slice(0, 40) : null,
		kid: typeof jwk.kid === "string" ? redact(jwk.kid).slice(0, 180) : null,
		use: typeof jwk.use === "string" ? redact(jwk.use).slice(0, 40) : null,
		alg: typeof jwk.alg === "string" ? redact(jwk.alg).slice(0, 40) : null,
		crv: typeof jwk.crv === "string" ? redact(jwk.crv).slice(0, 40) : null,
		hasPrivateOrSymmetricMaterial: privateKeys.some((key) => typeof jwk[key] !== "undefined"),
	};
}

function decodeJwtEvidence(token, source, baseUrl = undefined) {
	const parts = String(token ?? "").split(".");
	if (parts.length !== 3 || !parts[0] || !parts[1]) return undefined;
	const header = parseJsonSafe(base64UrlDecode(parts[0]).toString("utf8"));
	const payload = parseJsonSafe(base64UrlDecode(parts[1]).toString("utf8"));
	if (!header || typeof header !== "object" || !payload || typeof payload !== "object") return undefined;
	const nowSeconds = Math.floor(Date.now() / 1000);
	const risks = [];
	const alg = typeof header.alg === "string" ? header.alg : null;
	const kid = typeof header.kid === "string" ? header.kid : null;
	if (alg && /^none$/i.test(alg)) risks.push("jwt-alg-none");
	if (alg && /^HS/i.test(alg)) risks.push("jwt-symmetric-algorithm-review");
	if (kid && /(?:\.\.|\/|\\|%2e|%2f|%5c)/i.test(kid)) risks.push("jwt-kid-path-traversal-signal");
	const remoteKeys = {};
	for (const key of ["jku", "x5u"]) {
		if (typeof header[key] !== "string") continue;
		risks.push("jwt-remote-key-reference");
		const summary = summarizeJwtRemoteUrl(header[key], baseUrl);
		remoteKeys[key] = summary;
		if (summary.invalid) risks.push("jwt-remote-key-invalid-url");
		if (summary.scheme === "http") risks.push("jwt-remote-key-insecure-url");
		if (summary.sameOrigin === false) risks.push("jwt-remote-key-cross-origin");
		if (summary.privateOrLocalHost) risks.push("jwt-remote-key-private-or-local-host");
	}
	const headerJwk = summarizeJwtHeaderJwk(header.jwk);
	if (headerJwk) {
		risks.push("jwt-embedded-jwk-header");
		if (headerJwk.hasPrivateOrSymmetricMaterial) risks.push("jwt-embedded-jwk-private-or-symmetric-material");
		if (/^oct$/i.test(headerJwk.kty ?? "")) risks.push("jwt-embedded-jwk-symmetric-key");
	}
	const x5c = Array.isArray(header.x5c)
		? {
				count: header.x5c.length,
				firstSha256: typeof header.x5c[0] === "string" ? sha256Hex(header.x5c[0]) : undefined,
			}
		: null;
	if (x5c?.count) risks.push("jwt-x5c-header-chain");
	if (Array.isArray(header.crit) && header.crit.length) risks.push("jwt-critical-header-present");
	if (typeof payload.exp !== "number") risks.push("jwt-missing-exp");
	else if (payload.exp < nowSeconds) risks.push("jwt-expired");
	else if (payload.exp > nowSeconds + 370 * 24 * 60 * 60) risks.push("jwt-long-lived");
	if (typeof payload.nbf === "number" && payload.nbf > nowSeconds + 60) risks.push("jwt-not-yet-valid");
	if (typeof payload.iss !== "string") risks.push("jwt-missing-iss");
	if (typeof payload.aud === "undefined") risks.push("jwt-missing-aud");
	const summarizeStringOrArray = (value) => {
		if (typeof value === "string") return redact(value).slice(0, 240);
		if (Array.isArray(value)) return value.slice(0, 12).map((item) => redact(String(item)).slice(0, 160));
		if (typeof value === "number" || typeof value === "boolean") return value;
		return undefined;
	};
	const claims = {
		iss: summarizeStringOrArray(payload.iss),
		aud: summarizeStringOrArray(payload.aud),
		exp: typeof payload.exp === "number" ? payload.exp : undefined,
		expIso: typeof payload.exp === "number" ? new Date(payload.exp * 1000).toISOString() : undefined,
		nbf: typeof payload.nbf === "number" ? payload.nbf : undefined,
		iat: typeof payload.iat === "number" ? payload.iat : undefined,
		jtiSha256: typeof payload.jti === "string" ? sha256Hex(payload.jti) : undefined,
		subSha256: typeof payload.sub === "string" ? sha256Hex(payload.sub) : undefined,
		scope: summarizeStringOrArray(payload.scope ?? payload.scp),
	};
	for (const key of Object.keys(claims)) {
		if (typeof claims[key] === "undefined") delete claims[key];
	}
	return {
		source,
		tokenSha256: sha256Hex(token),
		tokenLength: String(token).length,
		signatureSha256: sha256Hex(parts[2] ?? ""),
		header: {
			alg,
			typ: typeof header.typ === "string" ? redact(header.typ).slice(0, 80) : null,
			kid: kid ? redact(kid).slice(0, 180) : null,
			remoteKeys,
			jwk: headerJwk,
			x5c,
			crit: Array.isArray(header.crit) ? header.crit.slice(0, 12).map((item) => redact(String(item)).slice(0, 80)) : [],
		},
		claimKeys: Object.keys(payload).sort().slice(0, 80),
		claims,
		risks,
	};
}

function collectJwtEvidence(transcript, cookies = [], baseUrl = undefined) {
	const out = [];
	const seen = new Set();
	const add = (token, source) => {
		const candidate = String(token ?? "").trim().replace(/^["']|["']$/g, "");
		if (!/^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/.test(candidate)) return;
		const hash = sha256Hex(candidate);
		if (seen.has(hash)) return;
		const decoded = decodeJwtEvidence(candidate, source, baseUrl);
		if (!decoded) return;
		seen.add(hash);
		out.push(decoded);
	};
	const text = String(transcript ?? "");
	for (const match of text.matchAll(/\bBearer\s+([A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)/gi)) add(match[1], "bearer");
	for (const match of text.matchAll(/\b(?:id_token|access_token|jwt|token)=([^&\s"'<>]{20,})/gi)) {
		try {
			add(decodeURIComponent(match[1]), "parameter");
		} catch {
			add(match[1], "parameter");
		}
	}
	for (const match of text.matchAll(/\b([A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)\b/g)) add(match[1], "inline");
	for (const cookie of cookies) add(cookie.value, `cookie:${cookie.name}`);
	return out.slice(0, 24);
}

function parseWebIdentityMeta(stdout) {
	const match = String(stdout ?? "").match(/\[repi-web-identity\]\s+kind=([a-z-]+)\s+status=(\d{3})\s+effective=(\S+)\s+bytes=(\d+)\s+redirects=(\d+)/);
	if (!match) return {};
	return {
		kind: match[1],
		status: Number(match[2]),
		effectiveUrl: match[3],
		bytes: Number(match[4]),
		redirects: Number(match[5]),
	};
}

function summarizeOidcDocument(document) {
	if (!document || typeof document !== "object") return undefined;
	return {
		issuer: typeof document.issuer === "string" ? redact(document.issuer).slice(0, 240) : null,
		jwksUri: typeof document.jwks_uri === "string" ? redact(document.jwks_uri).slice(0, 240) : null,
		authorizationEndpoint: typeof document.authorization_endpoint === "string" ? redact(document.authorization_endpoint).slice(0, 240) : null,
		tokenEndpoint: typeof document.token_endpoint === "string" ? redact(document.token_endpoint).slice(0, 240) : null,
		responseTypes: Array.isArray(document.response_types_supported) ? document.response_types_supported.slice(0, 20).map((item) => redact(String(item)).slice(0, 80)) : [],
		grantTypes: Array.isArray(document.grant_types_supported) ? document.grant_types_supported.slice(0, 20).map((item) => redact(String(item)).slice(0, 80)) : [],
		idTokenAlgs: Array.isArray(document.id_token_signing_alg_values_supported) ? document.id_token_signing_alg_values_supported.slice(0, 20).map((item) => redact(String(item)).slice(0, 80)) : [],
	};
}

function summarizeJwksDocument(document) {
	if (!document || typeof document !== "object" || !Array.isArray(document.keys)) return undefined;
	return {
		keyCount: document.keys.length,
		keys: document.keys.slice(0, 60).map((key) => ({
			kty: typeof key.kty === "string" ? redact(key.kty).slice(0, 40) : null,
			kid: typeof key.kid === "string" ? redact(key.kid).slice(0, 180) : null,
			use: typeof key.use === "string" ? redact(key.use).slice(0, 40) : null,
			alg: typeof key.alg === "string" ? redact(key.alg).slice(0, 40) : null,
			crv: typeof key.crv === "string" ? redact(key.crv).slice(0, 40) : null,
			x5cCount: Array.isArray(key.x5c) ? key.x5c.length : 0,
			modulusBytes: typeof key.n === "string" ? Math.floor((key.n.length * 3) / 4) : undefined,
		})),
	};
}

function webIdentityJwtRows(baseUrl, transcript, cookies, artifactDir) {
	const tokens = collectJwtEvidence(transcript, cookies, baseUrl);
	const shouldProbe = tokens.length || /\b(?:openid|jwks|oauth|id_token|access_token|bearer|jwt)\b/i.test(String(transcript ?? ""));
	if (!tokens.length && !shouldProbe) return [];
	const rows = [];
	const documents = [];
	const maxSeconds = String(Math.max(1, Math.min(3, Math.ceil(timeoutMs / 1000))));
	for (const [kind, path] of [
		["openid-configuration", "/.well-known/openid-configuration"],
		["jwks", "/.well-known/jwks.json"],
		["jwks", "/jwks.json"],
	].slice(0, deep ? 3 : 2)) {
		const url = sameOriginHttpUrl(baseUrl, path);
		if (!url) continue;
		const probe = run(
			"curl",
			[
				"-k",
				"-sS",
				"-L",
				"--max-time",
				maxSeconds,
				"-o",
				"-",
				"-w",
				`\n[repi-web-identity] kind=${kind} status=%{http_code} effective=%{url_effective} bytes=%{size_download} redirects=%{num_redirects}\n`,
				url,
			],
			{ id: `web-identity-${slug(path)}-fetch`, timeout: Number(maxSeconds) * 1000 + 1500, includeRaw: true },
		);
		rows.push(probe);
		const raw = probe.rawStdout ?? probe.stdout;
		const meta = parseWebIdentityMeta(raw);
		if (meta.status && meta.status >= 200 && meta.status < 300) {
			const body = responseBodyBeforeMarker(raw, "repi-web-identity").trim();
			const parsed = parseJsonSafe(body);
			if (parsed) documents.push({ kind, url: redact(meta.effectiveUrl ?? url), document: parsed });
		}
	}
	const oidc = documents.map((row) => (row.kind === "openid-configuration" ? summarizeOidcDocument(row.document) : undefined)).filter(Boolean)[0] ?? null;
	const jwksRows = documents.map((row) => (row.kind === "jwks" ? summarizeJwksDocument(row.document) : undefined)).filter(Boolean);
	const jwks = jwksRows[0] ?? { keyCount: 0, keys: [] };
	const risks = Array.from(new Set(tokens.flatMap((token) => token.risks)));
	const jwksKids = new Set(jwks.keys.map((key) => key.kid).filter(Boolean));
	for (const token of tokens) {
		if (jwksKids.size && token.header.kid && !jwksKids.has(token.header.kid)) risks.push("jwt-kid-not-in-jwks");
		if (oidc?.idTokenAlgs?.length && token.header.alg && !oidc.idTokenAlgs.includes(token.header.alg)) risks.push("jwt-alg-not-advertised-by-oidc");
	}
	if (oidc?.jwksUri && /^http:\/\//i.test(oidc.jwksUri)) risks.push("oidc-insecure-jwks-uri");
	const summary = {
		kind: "repi-web-identity-jwt",
		schemaVersion: 1,
		target: redact(baseUrl),
		jwtCount: tokens.length,
		tokens,
		oidc,
		jwks,
		risks: Array.from(new Set(risks)).slice(0, 80),
	};
	if (!noWrite && artifactDir) writePrivate(join(artifactDir, "web-identity-jwt.json"), `${JSON.stringify(summary, null, 2)}\n`);
	rows.push({
		id: "web-identity-jwt",
		command: "internal",
		args: [redact(baseUrl)],
		cwd: root,
		exit: tokens.length || oidc || jwks.keyCount ? 0 : 1,
		signal: null,
		durationMs: 0,
		stdout: `${JSON.stringify(summary, null, 2)}\n`,
		stderr: "",
		error: tokens.length || oidc || jwks.keyCount ? undefined : "no JWT/OIDC evidence",
	});
	return rows;
}

function webReplayMatrix(baseUrl, hints, artifactDir, session = {}) {
	const urls = [];
	for (const value of [baseUrl, ...hints]) {
		const url = sameOriginHttpUrl(baseUrl, value);
		if (!url) continue;
		if (/\.(?:png|jpg|jpeg|gif|css|ico|svg|woff2?|js|map)(?:[?#]|$)/i.test(url)) continue;
		if (!urls.includes(url)) urls.push(url);
		if (urls.length >= (deep ? 12 : 6)) break;
	}
	const rows = [];
	const matrix = [];
	const principals = [
		{ id: "anonymous", cookieHeader: undefined },
		...(session.cookieHeader ? [{ id: "cookie-session", cookieHeader: session.cookieHeader }] : []),
	];
	for (let index = 0; index < urls.length; index++) {
		const url = urls[index];
		for (const principal of principals) {
			const probeArgs = [
				"-k",
				"-sS",
				"-L",
				"--max-time",
				String(Math.ceil(timeoutMs / 1000)),
				"-D",
				"-",
				"-o",
				"-",
				"-w",
				"\n[repi-web-replay] status=%{http_code} effective=%{url_effective} bytes=%{size_download} redirects=%{num_redirects}\n",
				url,
			];
			if (principal.cookieHeader) probeArgs.splice(-1, 0, "-H", `Cookie: ${principal.cookieHeader}`);
			const rowId = principal.id === "anonymous" ? `web-replay-${index + 1}` : `web-replay-${index + 1}-${principal.id}`;
			const probe = run("curl", probeArgs, { id: rowId, timeout: timeoutMs + 3000, includeRaw: true });
			rows.push({ ...probe, stdout: probe.stdout.slice(0, 80_000) });
			const raw = String(probe.rawStdout ?? probe.stdout);
			const meta = parseReplayMeta(raw);
			matrix.push({
				id: rowId,
				principal: principal.id,
				url: redact(url),
				exit: probe.exit,
				status: meta.status ?? null,
				effectiveUrl: meta.effectiveUrl ? redact(meta.effectiveUrl) : null,
				bytes: meta.bytes ?? null,
				redirects: meta.redirects ?? null,
				responseSha256: sha256Hex(raw.replace(/\n\[repi-web-replay\][\s\S]*$/, "")),
			});
		}
	}
	if (matrix.length) {
		const anyReachable = matrix.some((row) => Number.isFinite(row.status) && row.status >= 100);
		const summary = {
			kind: "repi-web-replay-matrix",
			schemaVersion: 1,
			baseUrl: redact(baseUrl),
			session: {
				cookieNames: session.cookies?.map((cookie) => cookie.name) ?? [],
				csrf: session.csrfHints ?? [],
			},
			count: matrix.length,
			rows: matrix,
		};
		rows.push({ id: "web-replay-matrix", command: "internal", args: [redact(baseUrl)], cwd: root, exit: anyReachable ? 0 : 1, signal: null, durationMs: 0, stdout: `${JSON.stringify(summary, null, 2)}\n`, stderr: "", error: anyReachable ? undefined : "no reachable replay targets" });
		if (!noWrite) writePrivate(join(artifactDir, "web-replay-matrix.json"), `${JSON.stringify(summary, null, 2)}\n`);
	}
	return rows;
}

function parseObjectProbeMeta(stdout) {
	const match = String(stdout ?? "").match(/\[repi-web-object\]\s+status=(\d{3})\s+effective=(\S+)\s+bytes=(\d+)\s+redirects=(\d+)/);
	if (!match) return {};
	return {
		status: Number(match[1]),
		effectiveUrl: match[2],
		bytes: Number(match[3]),
		redirects: Number(match[4]),
	};
}

function parseRedirectProbeMeta(stdout) {
	const match = String(stdout ?? "").match(/\[repi-web-redirect\]\s+status=(\d{3})\s+effective=(\S+)\s+bytes=(\d+)\s+redirects=(\d+)/);
	if (!match) return {};
	return {
		status: Number(match[1]),
		effectiveUrl: match[2],
		bytes: Number(match[3]),
		redirects: Number(match[4]),
	};
}

function parseSsrfProbeMeta(stdout) {
	const match = String(stdout ?? "").match(/\[repi-web-ssrf\]\s+kind=([a-z0-9-]+)\s+status=(\d{3})\s+effective=(\S+)\s+bytes=(\d+)\s+redirects=(\d+)/);
	if (!match) return {};
	return {
		kind: match[1],
		status: Number(match[2]),
		effectiveUrl: match[3],
		bytes: Number(match[4]),
		redirects: Number(match[5]),
	};
}

function mutateHexLike(value) {
	const chars = String(value);
	for (let index = chars.length - 1; index >= 0; index--) {
		const current = chars[index].toLowerCase();
		if (!/[0-9a-f]/.test(current)) continue;
		const next = current === "a" ? "b" : "a";
		return `${chars.slice(0, index)}${next}${chars.slice(index + 1)}`;
	}
	return undefined;
}

function objectMutationPairs(baseUrl, hints, limit = deep ? 10 : 5) {
	const urls = uniqueSameOriginUrls(baseUrl, hints, 30);
	const pairs = [];
	const addPair = (source, variant, reason) => {
		if (!variant || source === variant) return;
		if (pairs.some((pair) => pair.source === source && pair.variant === variant)) return;
		pairs.push({ source, variant, reason });
	};
	for (const urlText of urls) {
		let parsed;
		try {
			parsed = new URL(urlText);
		} catch {
			continue;
		}
		if (/\.(?:png|jpg|jpeg|gif|css|ico|svg|woff2?|js|map)(?:[?#]|$)/i.test(parsed.pathname)) continue;
		const segments = parsed.pathname.split("/");
		for (let index = 0; index < segments.length; index++) {
			const segment = segments[index];
			if (/^\d{1,12}$/.test(segment)) {
				const value = Number(segment);
				if (Number.isSafeInteger(value)) {
					for (const candidate of [value + 1, value > 1 ? value - 1 : undefined]) {
						if (!candidate || candidate === value) continue;
						const next = new URL(parsed.href);
						const nextSegments = next.pathname.split("/");
						nextSegments[index] = String(candidate);
						next.pathname = nextSegments.join("/");
						addPair(parsed.href, next.href, `path-number:${segment}->${candidate}`);
					}
				}
			} else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(segment)) {
				const mutated = mutateHexLike(segment);
				if (mutated) {
					const next = new URL(parsed.href);
					const nextSegments = next.pathname.split("/");
					nextSegments[index] = mutated;
					next.pathname = nextSegments.join("/");
					addPair(parsed.href, next.href, "path-uuid-last-nibble");
				}
			}
			if (pairs.length >= limit) return pairs;
		}
		for (const [name, value] of parsed.searchParams.entries()) {
			if (!/(?:^|_|\b)(?:id|uid|user|account|order|org|tenant|project|invoice|owner)(?:$|_|\b)/i.test(name)) continue;
			if (/token|secret|key|password/i.test(name)) continue;
			if (/^\d{1,12}$/.test(value)) {
				const number = Number(value);
				if (Number.isSafeInteger(number)) {
					const next = new URL(parsed.href);
					next.searchParams.set(name, String(number + 1));
					addPair(parsed.href, next.href, `query-number:${name}`);
				}
			} else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
				const mutated = mutateHexLike(value);
				if (mutated) {
					const next = new URL(parsed.href);
					next.searchParams.set(name, mutated);
					addPair(parsed.href, next.href, `query-uuid:${name}`);
				}
			}
			if (pairs.length >= limit) return pairs;
		}
	}
	return pairs;
}

function redirectMutationTargets(baseUrl, hints, limit = deep ? 12 : 6) {
	const urls = uniqueSameOriginUrls(baseUrl, [baseUrl, ...hints], 80);
	const targets = [];
	const redirectNames = /^(?:next|url|uri|redirect|redirect_uri|return|return_to|continue|callback|callback_url|destination|dest|target|to|go)$/i;
	const canary = "https://repi.invalid/open-redirect";
	for (const urlText of urls) {
		let parsed;
		try {
			parsed = new URL(urlText);
		} catch {
			continue;
		}
		if (/\.(?:png|jpg|jpeg|gif|css|ico|svg|woff2?|js|map)(?:[?#]|$)/i.test(parsed.pathname)) continue;
		for (const [name, value] of parsed.searchParams.entries()) {
			if (!redirectNames.test(name)) continue;
			if (/token|secret|key|password/i.test(name)) continue;
			const mutated = new URL(parsed.href);
			mutated.searchParams.set(name, canary);
			if (targets.some((row) => row.url === mutated.href)) continue;
			targets.push({
				source: parsed.href,
				url: mutated.href,
				param: name,
				originalValueLength: value.length,
				originalValueSha256: sha256Hex(value),
			});
			if (targets.length >= limit) return targets;
		}
	}
	return targets;
}

function ssrfMutationTargets(baseUrl, hints, limit = deep ? 10 : 5) {
	const urls = uniqueSameOriginUrls(baseUrl, [baseUrl, ...hints], 80);
	const targets = [];
	const ssrfNames = /^(?:url|uri|endpoint|target|dest|destination|proxy|fetch|fetch_url|image|image_url|avatar|avatar_url|feed|webhook|callback|callback_url|api_url|service|host|site|path)$/i;
	const payloads = [
		{ kind: "loopback", value: "http://127.0.0.1:1/repi-ssrf-canary" },
		{ kind: "metadata", value: "http://169.254.169.254/latest/meta-data/" },
	];
	for (const urlText of urls) {
		let parsed;
		try {
			parsed = new URL(urlText);
		} catch {
			continue;
		}
		if (/\.(?:png|jpg|jpeg|gif|css|ico|svg|woff2?|js|map)(?:[?#]|$)/i.test(parsed.pathname)) continue;
		for (const [name, value] of parsed.searchParams.entries()) {
			if (!ssrfNames.test(name)) continue;
			if (/token|secret|key|password/i.test(name)) continue;
			if (!/^(?:https?:\/\/|\/\/|[A-Za-z0-9.-]+\.[A-Za-z]{2,}|\/)/.test(value)) continue;
			for (const payload of payloads) {
				const mutated = new URL(parsed.href);
				mutated.searchParams.set(name, payload.value);
				if (targets.some((row) => row.url === mutated.href && row.kind === payload.kind)) continue;
				targets.push({
					source: parsed.href,
					url: mutated.href,
					param: name,
					kind: payload.kind,
					payload: payload.value,
					originalValueLength: value.length,
					originalValueSha256: sha256Hex(value),
				});
				if (targets.length >= limit) return targets;
			}
		}
	}
	return targets;
}

function webSsrfMatrix(baseUrl, hints, artifactDir, session = {}) {
	const targets = ssrfMutationTargets(baseUrl, hints);
	if (!targets.length) return [];
	const rows = [];
	const matrix = [];
	const maxSeconds = String(Math.max(1, Math.min(4, Math.ceil(timeoutMs / 1000))));
	const probeOne = (rowId, url, kind) => {
		const args = [
			"-k",
			"-sS",
			"-L",
			"--max-time",
			maxSeconds,
			"-D",
			"-",
			"-o",
			"-",
			"-w",
			`\n[repi-web-ssrf] kind=${kind} status=%{http_code} effective=%{url_effective} bytes=%{size_download} redirects=%{num_redirects}\n`,
			url,
		];
		if (session.cookieHeader) args.splice(-1, 0, "-H", `Cookie: ${session.cookieHeader}`);
		const probe = run("curl", args, { id: rowId, timeout: Number(maxSeconds) * 1000 + 2500, includeRaw: true });
		rows.push({ ...probe, stdout: probe.stdout.slice(0, 50_000) });
		const raw = probe.rawStdout ?? probe.stdout;
		const body = responseBodyBeforeMarker(raw, "repi-web-ssrf");
		return {
			exit: probe.exit,
			meta: parseSsrfProbeMeta(raw),
			body,
			sha: sha256Hex(body),
		};
	};
	let index = 0;
	for (const target of targets) {
		index += 1;
		const source = probeOne(`web-ssrf-${index}-${slug(target.param)}-baseline`, target.source, "baseline");
		const variant = probeOne(`web-ssrf-${index}-${slug(target.param)}-${target.kind}`, target.url, target.kind);
		const variantText = variant.body.slice(0, 12_000);
		const canaryEvidence = /repi-ssrf-canary|169\.254\.169\.254|latest\/meta-data|ami-id|instance-id|metadata/i.test(variantText);
		const statusDifferential = (source.meta.status ?? null) !== (variant.meta.status ?? null);
		const bodyDifferential = source.sha !== variant.sha;
		const risks = [];
		if (canaryEvidence) risks.push(target.kind === "metadata" ? "ssrf-metadata-service-signal" : "ssrf-loopback-canary-signal");
		if (statusDifferential || bodyDifferential) risks.push("ssrf-response-differential");
		matrix.push({
			id: `web-ssrf-${index}`,
			param: target.param,
			kind: target.kind,
			sourceUrl: redact(target.source),
			mutatedUrl: redact(target.url),
			payloadHost: (() => {
				try {
					return new URL(target.payload).host;
				} catch {
					return null;
				}
			})(),
			originalValueLength: target.originalValueLength,
			originalValueSha256: target.originalValueSha256,
			source: {
				exit: source.exit,
				status: Number.isFinite(source.meta.status) ? source.meta.status : null,
				bytes: Number.isFinite(source.meta.bytes) ? source.meta.bytes : null,
				responseSha256: source.sha,
			},
			variant: {
				exit: variant.exit,
				status: Number.isFinite(variant.meta.status) ? variant.meta.status : null,
				bytes: Number.isFinite(variant.meta.bytes) ? variant.meta.bytes : null,
				responseSha256: variant.sha,
				bodySample: redact(variantText.slice(0, 800)),
			},
			statusDifferential,
			bodyDifferential,
			canaryEvidence,
			risks,
		});
	}
	const summary = {
		kind: "repi-web-ssrf-matrix",
		schemaVersion: 1,
		baseUrl: redact(baseUrl),
		session: {
			cookieNames: session.cookies?.map((cookie) => cookie.name) ?? [],
		},
		count: matrix.length,
		riskCount: matrix.filter((row) => row.risks.length).length,
		risks: Array.from(new Set(matrix.flatMap((row) => row.risks))),
		rows: matrix,
	};
	rows.push({
		id: "web-ssrf-matrix",
		command: "internal",
		args: [redact(baseUrl)],
		cwd: root,
		exit: matrix.some((row) => Number.isFinite(row.variant.status) && row.variant.status >= 100 && row.variant.status < 600) ? 0 : 1,
		signal: null,
		durationMs: 0,
		stdout: `${JSON.stringify(summary, null, 2)}\n`,
		stderr: "",
		error: matrix.some((row) => Number.isFinite(row.variant.status) && row.variant.status >= 100 && row.variant.status < 600) ? undefined : "no SSRF probes reached target",
	});
	if (!noWrite && artifactDir) writePrivate(join(artifactDir, "web-ssrf-matrix.json"), `${JSON.stringify(summary, null, 2)}\n`);
	return rows;
}

function webRedirectMatrix(baseUrl, hints, artifactDir, session = {}) {
	const targets = redirectMutationTargets(baseUrl, hints);
	if (!targets.length) return [];
	const rows = [];
	const matrix = [];
	const canaryHost = "repi.invalid";
	const maxSeconds = String(Math.max(1, Math.min(3, Math.ceil(timeoutMs / 1000))));
	let index = 0;
	for (const target of targets) {
		index += 1;
		const args = [
			"-k",
			"-sS",
			"--max-time",
			maxSeconds,
			"--max-redirs",
			"0",
			"-D",
			"-",
			"-o",
			"/dev/null",
			"-w",
			"\n[repi-web-redirect] status=%{http_code} effective=%{url_effective} bytes=%{size_download} redirects=%{num_redirects}\n",
			target.url,
		];
		if (session.cookieHeader) args.splice(-1, 0, "-H", `Cookie: ${session.cookieHeader}`);
		const probe = run("curl", args, { id: `web-redirect-${index}-${slug(target.param)}`, timeout: Number(maxSeconds) * 1000 + 1500, includeRaw: true });
		rows.push(probe);
		const raw = probe.rawStdout ?? probe.stdout;
		const meta = parseRedirectProbeMeta(raw);
		const location = lastHeader(raw, "location");
		let locationHost = null;
		let externalLocation = false;
		let canaryLocation = false;
		if (location) {
			try {
				const resolved = new URL(location, baseUrl);
				locationHost = resolved.host;
				const baseHost = new URL(baseUrl).host;
				externalLocation = resolved.host !== baseHost;
				canaryLocation = resolved.host === canaryHost;
			} catch {
				locationHost = "<invalid-url>";
			}
		}
		const risks = [];
		if ([301, 302, 303, 307, 308].includes(meta.status ?? 0) && canaryLocation) risks.push("open-redirect-external-location");
		else if ([301, 302, 303, 307, 308].includes(meta.status ?? 0) && externalLocation) risks.push("external-redirect-location");
		matrix.push({
			id: `web-redirect-${index}`,
			param: target.param,
			sourceUrl: redact(target.source),
			mutatedUrl: redact(target.url),
			originalValueLength: target.originalValueLength,
			originalValueSha256: target.originalValueSha256,
			exit: probe.exit,
			status: Number.isFinite(meta.status) ? meta.status : null,
			effectiveUrl: meta.effectiveUrl ? redact(meta.effectiveUrl) : null,
			location: location ? redact(location).slice(0, 600) : null,
			locationHost,
			externalLocation,
			canaryLocation,
			risks,
		});
	}
	const summary = {
		kind: "repi-web-redirect-matrix",
		schemaVersion: 1,
		baseUrl: redact(baseUrl),
		session: {
			cookieNames: session.cookies?.map((cookie) => cookie.name) ?? [],
		},
		count: matrix.length,
		riskCount: matrix.filter((row) => row.risks.length).length,
		risks: Array.from(new Set(matrix.flatMap((row) => row.risks))),
		rows: matrix,
	};
	rows.push({
		id: "web-redirect-matrix",
		command: "internal",
		args: [redact(baseUrl)],
		cwd: root,
		exit: matrix.some((row) => Number.isFinite(row.status) && row.status >= 100 && row.status < 600) ? 0 : 1,
		signal: null,
		durationMs: 0,
		stdout: `${JSON.stringify(summary, null, 2)}\n`,
		stderr: "",
		error: matrix.some((row) => Number.isFinite(row.status) && row.status >= 100 && row.status < 600) ? undefined : "no redirect probes reached target",
	});
	if (!noWrite && artifactDir) writePrivate(join(artifactDir, "web-redirect-matrix.json"), `${JSON.stringify(summary, null, 2)}\n`);
	return rows;
}

function webObjectMatrix(baseUrl, hints, artifactDir, session = {}) {
	const pairs = objectMutationPairs(baseUrl, hints);
	if (!pairs.length) return [];
	const principals = [
		{ id: "anonymous", cookieHeader: undefined },
		...(session.cookieHeader ? [{ id: "cookie-session", cookieHeader: session.cookieHeader }] : []),
	];
	const rows = [];
	const matrix = [];
	const maxSeconds = String(Math.max(1, Math.min(4, Math.ceil(timeoutMs / 1000))));
	const probeOne = (rowId, url, principal) => {
		const args = [
			"-k",
			"-sS",
			"-L",
			"--max-time",
			maxSeconds,
			"-D",
			"-",
			"-o",
			"-",
			"-w",
			"\n[repi-web-object] status=%{http_code} effective=%{url_effective} bytes=%{size_download} redirects=%{num_redirects}\n",
			url,
		];
		if (principal.cookieHeader) args.splice(-1, 0, "-H", `Cookie: ${principal.cookieHeader}`);
		const probe = run("curl", args, { id: rowId, timeout: Number(maxSeconds) * 1000 + 2500, includeRaw: true });
		rows.push({ ...probe, stdout: probe.stdout.slice(0, 50_000) });
		const raw = String(probe.rawStdout ?? probe.stdout);
		const body = raw.replace(/\n\[repi-web-object\][\s\S]*$/, "");
		return { meta: parseObjectProbeMeta(raw), sha: sha256Hex(body), exit: probe.exit };
	};
	let index = 0;
	for (const pair of pairs) {
		index += 1;
		for (const principal of principals) {
			const source = probeOne(`web-object-${index}-${principal.id}-source`, pair.source, principal);
			const variant = probeOne(`web-object-${index}-${principal.id}-variant`, pair.variant, principal);
			matrix.push({
				id: `web-object-${index}-${principal.id}`,
				principal: principal.id,
				reason: pair.reason,
				sourceUrl: redact(pair.source),
				variantUrl: redact(pair.variant),
				source: {
					exit: source.exit,
					status: source.meta.status ?? null,
					bytes: source.meta.bytes ?? null,
					effectiveUrl: source.meta.effectiveUrl ? redact(source.meta.effectiveUrl) : null,
					responseSha256: source.sha,
				},
				variant: {
					exit: variant.exit,
					status: variant.meta.status ?? null,
					bytes: variant.meta.bytes ?? null,
					effectiveUrl: variant.meta.effectiveUrl ? redact(variant.meta.effectiveUrl) : null,
					responseSha256: variant.sha,
				},
				statusDelta: (variant.meta.status ?? 0) - (source.meta.status ?? 0),
				hashDelta: source.sha !== variant.sha,
				bolaSignal: principal.id !== "anonymous" && [200, 201, 202, 204, 206, 302, 304].includes(variant.meta.status ?? 0),
			});
		}
	}
	const summary = {
		kind: "repi-web-object-matrix",
		schemaVersion: 1,
		baseUrl: redact(baseUrl),
		session: {
			cookieNames: session.cookies?.map((cookie) => cookie.name) ?? [],
		},
		count: matrix.length,
		pairCount: pairs.length,
		signalCount: matrix.filter((row) => row.bolaSignal).length,
		rows: matrix,
	};
	const anyReachable = matrix.some((row) => Number.isFinite(row.source.status) || Number.isFinite(row.variant.status));
	rows.push({
		id: "web-object-matrix",
		command: "internal",
		args: [redact(baseUrl)],
		cwd: root,
		exit: anyReachable ? 0 : 1,
		signal: null,
		durationMs: 0,
		stdout: `${JSON.stringify(summary, null, 2)}\n`,
		stderr: "",
		error: anyReachable ? undefined : "no reachable object mutation probes",
	});
	if (!noWrite) writePrivate(join(artifactDir, "web-object-matrix.json"), `${JSON.stringify(summary, null, 2)}\n`);
	return rows;
}

function uniqueSameOriginUrls(baseUrl, values, limit) {
	const out = [];
	for (const value of values) {
		const url = sameOriginHttpUrl(baseUrl, value);
		if (!url) continue;
		if (!out.includes(url)) out.push(url);
		if (out.length >= limit) break;
	}
	return out;
}

function summarizeOpenApi(body) {
	try {
		const doc = JSON.parse(body);
		if (!doc || typeof doc !== "object") return undefined;
		const paths = doc.paths && typeof doc.paths === "object" ? doc.paths : {};
		const httpMethods = /^(get|post|put|patch|delete|options|head|trace)$/i;
		const securitySchemes =
			doc.components?.securitySchemes && typeof doc.components.securitySchemes === "object"
				? doc.components.securitySchemes
				: doc.securityDefinitions && typeof doc.securityDefinitions === "object"
					? doc.securityDefinitions
					: {};
		const pathRows = Object.entries(paths)
			.slice(0, 60)
			.map(([path, value]) => ({
				path: redact(path),
				methods: value && typeof value === "object" ? Object.keys(value).filter((key) => httpMethods.test(key)).map((key) => key.toUpperCase()) : [],
			}));
		const operationSamples = [];
		const risks = [];
		const globalSecurity = Array.isArray(doc.security) ? doc.security : undefined;
		for (const [path, pathItem] of Object.entries(paths).slice(0, 80)) {
			if (!pathItem || typeof pathItem !== "object") continue;
			for (const method of Object.keys(pathItem).filter((key) => httpMethods.test(key))) {
				const operation = pathItem[method] && typeof pathItem[method] === "object" ? pathItem[method] : {};
				const security = Array.isArray(operation.security) ? operation.security : Array.isArray(pathItem.security) ? pathItem.security : globalSecurity;
				const authRequired = Array.isArray(security) ? security.length > 0 : false;
				const requestContentTypes = operation.requestBody?.content && typeof operation.requestBody.content === "object" ? Object.keys(operation.requestBody.content).slice(0, 20) : [];
				const responseStatuses = operation.responses && typeof operation.responses === "object" ? Object.keys(operation.responses).slice(0, 20) : [];
				const operationText = `${path} ${method} ${operation.operationId ?? ""} ${Array.isArray(operation.tags) ? operation.tags.join(" ") : ""}`;
				const writeOperation = /^(post|put|patch|delete)$/i.test(method);
				const sensitiveOperation = /admin|user|account|order|payment|invoice|token|secret|credential|password|role|permission|upload|file|delete|debug|internal/i.test(operationText);
				const uploadSurface = requestContentTypes.some((type) => /multipart\/form-data|application\/octet-stream|image\/|audio\/|video\//i.test(type));
				const operationRisks = [];
				if (sensitiveOperation && !authRequired) operationRisks.push("openapi-unauthenticated-sensitive-operation");
				if (writeOperation) operationRisks.push("openapi-write-operation-surface");
				if (writeOperation && !authRequired) operationRisks.push("openapi-unauthenticated-write-operation");
				if (/\/admin\b|admin/i.test(operationText) && !authRequired) operationRisks.push("openapi-unauthenticated-admin-operation");
				if (uploadSurface) operationRisks.push("openapi-upload-surface");
				if (uploadSurface && !authRequired) operationRisks.push("openapi-unauthenticated-upload-surface");
				if (/^trace$/i.test(method)) operationRisks.push("openapi-trace-method-surface");
				risks.push(...operationRisks);
				if (operationSamples.length < 80) {
					operationSamples.push({
						path: redact(path),
						method: method.toUpperCase(),
						operationId: operation.operationId ? redact(String(operation.operationId)).slice(0, 160) : null,
						tags: Array.isArray(operation.tags) ? operation.tags.slice(0, 12).map((tag) => redact(String(tag)).slice(0, 80)) : [],
						authRequired,
						security: Array.isArray(security)
							? security.slice(0, 8).map((row) => (row && typeof row === "object" ? Object.keys(row).map(redact).slice(0, 12) : []))
							: [],
						requestContentTypes,
						responseStatuses,
						parameterCount: (Array.isArray(pathItem.parameters) ? pathItem.parameters.length : 0) + (Array.isArray(operation.parameters) ? operation.parameters.length : 0),
						risks: operationRisks,
					});
				}
			}
		}
		return {
			version: doc.openapi || doc.swagger || null,
			title: doc.info?.title ? redact(doc.info.title) : null,
			pathCount: Object.keys(paths).length,
			operationCount: pathRows.reduce((count, row) => count + row.methods.length, 0),
			securitySchemes: Object.entries(securitySchemes)
				.slice(0, 20)
				.map(([name, scheme]) => ({
					name: redact(name),
					type: scheme && typeof scheme === "object" ? redact(scheme.type ?? "") : "",
					scheme: scheme && typeof scheme === "object" ? redact(scheme.scheme ?? "") : "",
				})),
			pathSamples: pathRows.slice(0, 20),
			operationSamples,
			risks: Array.from(new Set(risks)).slice(0, 80),
		};
	} catch {
		return undefined;
	}
}

function summarizeGraphqlIntrospection(body) {
	try {
		const doc = JSON.parse(body);
		const schema = doc?.data?.__schema;
		if (!schema || typeof schema !== "object") return undefined;
		const types = Array.isArray(schema.types) ? schema.types : [];
		const typeByName = new Map(types.filter((type) => type && typeof type.name === "string").map((type) => [type.name, type]));
		const fieldNames = (typeName) => {
			const fields = typeByName.get(typeName)?.fields;
			if (!Array.isArray(fields)) return [];
			return fields
				.map((field) => (field && typeof field.name === "string" ? redact(field.name).slice(0, 120) : null))
				.filter(Boolean)
				.slice(0, 80);
		};
		const queryType = typeof schema.queryType?.name === "string" ? schema.queryType.name : null;
		const mutationType = typeof schema.mutationType?.name === "string" ? schema.mutationType.name : null;
		const subscriptionType = typeof schema.subscriptionType?.name === "string" ? schema.subscriptionType.name : null;
		const queryFields = queryType ? fieldNames(queryType) : [];
		const mutationFields = mutationType ? fieldNames(mutationType) : [];
		return {
			enabled: true,
			queryType: queryType ? redact(queryType).slice(0, 120) : null,
			mutationType: mutationType ? redact(mutationType).slice(0, 120) : null,
			subscriptionType: subscriptionType ? redact(subscriptionType).slice(0, 120) : null,
			typeCount: types.length,
			fieldCount: types.reduce((count, type) => count + (Array.isArray(type?.fields) ? type.fields.length : 0), 0),
			queryFields,
			mutationFields,
			directives: Array.isArray(schema.directives)
				? schema.directives
						.map((directive) => (directive && typeof directive.name === "string" ? redact(directive.name).slice(0, 80) : null))
						.filter(Boolean)
						.slice(0, 40)
				: [],
		};
	} catch {
		return undefined;
	}
}

function webApiSchemaProbes(baseUrl, hints, artifactDir, session = {}, schemaHints = []) {
	const principals = [
		{ id: "anonymous", cookieHeader: undefined },
		...(session.cookieHeader ? [{ id: "cookie-session", cookieHeader: session.cookieHeader }] : []),
	];
	const graphqlCandidates = uniqueSameOriginUrls(
		baseUrl,
		[
			...schemaHints.filter((hint) => /graphql/i.test(hint)),
			...hints.filter((hint) => /graphql/i.test(hint)),
			"/graphql",
		],
		deep ? 4 : 2,
	);
	const openApiCandidates = uniqueSameOriginUrls(
		baseUrl,
		[
			...schemaHints.filter((hint) => /openapi|swagger|api-docs/i.test(hint)),
			...hints.filter((hint) => /openapi|swagger|api-docs/i.test(hint)),
			"/openapi.json",
			"/swagger.json",
			"/v3/api-docs",
		],
		deep ? 5 : 2,
	);
	const rows = [];
	const summaryRows = [];
	const replayHints = [];
	const maxSeconds = String(Math.max(1, Math.min(4, Math.ceil(timeoutMs / 1000))));
	const graphqlPayload = JSON.stringify({ query: "query RepiTypenameProbe { __typename }" });
	const graphqlIntrospectionPayload = JSON.stringify({
		query: "query RepiIntrospectionProbe { __schema { queryType { name } mutationType { name } subscriptionType { name } directives { name } types { kind name fields { name } } } }",
	});
	let graphqlIndex = 0;
	for (const url of graphqlCandidates) {
		for (const principal of principals) {
			graphqlIndex += 1;
			const args = [
				"-k",
				"-sS",
				"-L",
				"--max-time",
				maxSeconds,
				"-H",
				"Content-Type: application/json",
				"-o",
				"-",
				"-w",
				"\n[repi-web-schema] kind=graphql status=%{http_code} effective=%{url_effective} bytes=%{size_download} redirects=%{num_redirects}\n",
				"--data-binary",
				graphqlPayload,
				url,
			];
			if (principal.cookieHeader) args.splice(-3, 0, "-H", `Cookie: ${principal.cookieHeader}`);
			const probe = run("curl", args, { id: `web-graphql-${graphqlIndex}-${principal.id}`, timeout: Number(maxSeconds) * 1000 + 2500, includeRaw: true });
			rows.push({ ...probe, stdout: probe.stdout.slice(0, 40_000) });
			const raw = String(probe.rawStdout ?? probe.stdout);
			const body = responseBodyBeforeMarker(raw, "repi-web-schema");
			const meta = parseSchemaProbeMeta(raw);
			const looksGraphql = /"data"\s*:|"errors"\s*:|__typename|Cannot query field|GraphQL/i.test(body);
			summaryRows.push({
				kind: "graphql",
				principal: principal.id,
				url: redact(url),
				exit: probe.exit,
				status: meta.status ?? null,
				effectiveUrl: meta.effectiveUrl ? redact(meta.effectiveUrl) : null,
				bytes: meta.bytes ?? null,
				redirects: meta.redirects ?? null,
				looksGraphql,
				responseSha256: sha256Hex(body),
				bodySample: redact(body.slice(0, 1200)),
			});
			if (looksGraphql && !replayHints.includes(url)) replayHints.push(url);
			const introspectionArgs = [
				"-k",
				"-sS",
				"-L",
				"--max-time",
				maxSeconds,
				"-H",
				"Content-Type: application/json",
				"-o",
				"-",
				"-w",
				"\n[repi-web-schema] kind=graphql-introspection status=%{http_code} effective=%{url_effective} bytes=%{size_download} redirects=%{num_redirects}\n",
				"--data-binary",
				graphqlIntrospectionPayload,
				url,
			];
			if (principal.cookieHeader) introspectionArgs.splice(-3, 0, "-H", `Cookie: ${principal.cookieHeader}`);
			const introspectionProbe = run("curl", introspectionArgs, { id: `web-graphql-introspection-${graphqlIndex}-${principal.id}`, timeout: Number(maxSeconds) * 1000 + 2500, includeRaw: true });
			rows.push({ ...introspectionProbe, stdout: introspectionProbe.stdout.slice(0, 60_000) });
			const introspectionRaw = String(introspectionProbe.rawStdout ?? introspectionProbe.stdout);
			const introspectionBody = responseBodyBeforeMarker(introspectionRaw, "repi-web-schema");
			const introspectionMeta = parseSchemaProbeMeta(introspectionRaw);
			const introspection = summarizeGraphqlIntrospection(introspectionBody);
			const introspectionRisks = [];
			if (introspection?.enabled) introspectionRisks.push("graphql-introspection-enabled");
			if (introspection?.mutationFields?.length) introspectionRisks.push("graphql-mutation-surface");
			if (introspection?.queryFields?.some((field) => /admin|user|account|order|secret|token|flag/i.test(field))) introspectionRisks.push("graphql-sensitive-query-field-signal");
			summaryRows.push({
				kind: "graphql-introspection",
				principal: principal.id,
				url: redact(url),
				exit: introspectionProbe.exit,
				status: introspectionMeta.status ?? null,
				effectiveUrl: introspectionMeta.effectiveUrl ? redact(introspectionMeta.effectiveUrl) : null,
				bytes: introspectionMeta.bytes ?? null,
				redirects: introspectionMeta.redirects ?? null,
				introspection: introspection ?? null,
				responseSha256: sha256Hex(introspectionBody),
				bodySample: introspection ? undefined : redact(introspectionBody.slice(0, 1200)),
				risks: introspectionRisks,
			});
		}
	}
	let openApiIndex = 0;
	for (const url of openApiCandidates) {
		openApiIndex += 1;
		const probe = run(
			"curl",
			[
				"-k",
				"-sS",
				"-L",
				"--max-time",
				maxSeconds,
				"-o",
				"-",
				"-w",
				"\n[repi-web-schema] kind=openapi status=%{http_code} effective=%{url_effective} bytes=%{size_download} redirects=%{num_redirects}\n",
				url,
			],
			{ id: `web-openapi-${openApiIndex}`, timeout: Number(maxSeconds) * 1000 + 2500, includeRaw: true },
		);
		rows.push({ ...probe, stdout: probe.stdout.slice(0, 60_000) });
		const raw = String(probe.rawStdout ?? probe.stdout);
		const body = responseBodyBeforeMarker(raw, "repi-web-schema");
		const meta = parseSchemaProbeMeta(raw);
		const openapi = summarizeOpenApi(body);
		if (openapi) {
			for (const sample of openapi.pathSamples) {
				const hint = sameOriginHttpUrl(baseUrl, sample.path);
				if (hint && !replayHints.includes(hint)) replayHints.push(hint);
			}
		}
		summaryRows.push({
			kind: "openapi",
			url: redact(url),
			exit: probe.exit,
			status: meta.status ?? null,
			effectiveUrl: meta.effectiveUrl ? redact(meta.effectiveUrl) : null,
			bytes: meta.bytes ?? null,
			redirects: meta.redirects ?? null,
			openapi: openapi ?? null,
			risks: openapi?.risks ?? [],
			responseSha256: sha256Hex(body),
			bodySample: openapi ? undefined : redact(body.slice(0, 1200)),
		});
	}
	if (!summaryRows.length) return { rows, replayHints: [] };
	const risks = Array.from(new Set(summaryRows.flatMap((row) => row.risks ?? [])));
	const anySchema = summaryRows.some((row) => row.looksGraphql || row.openapi || row.introspection?.enabled);
	const summary = {
		kind: "repi-web-api-schema-probes",
		schemaVersion: 1,
		baseUrl: redact(baseUrl),
		session: {
			cookieNames: session.cookies?.map((cookie) => cookie.name) ?? [],
		},
		count: summaryRows.length,
		riskCount: summaryRows.filter((row) => row.risks?.length).length,
		risks,
		rows: summaryRows,
	};
	rows.push({
		id: "web-api-schema-probes",
		command: "internal",
		args: [redact(baseUrl)],
		cwd: root,
		exit: anySchema ? 0 : 1,
		signal: null,
		durationMs: 0,
		stdout: `${JSON.stringify(summary, null, 2)}\n`,
		stderr: "",
		error: anySchema ? undefined : "no GraphQL/OpenAPI schema evidence",
	});
	if (!noWrite) writePrivate(join(artifactDir, "web-api-schema-probes.json"), `${JSON.stringify(summary, null, 2)}\n`);
	return { rows, replayHints };
}

function webDiscoveryMatrix(baseUrl, artifactDir) {
	const commonPaths = [
		"/robots.txt",
		"/sitemap.xml",
		"/.well-known/security.txt",
		"/api",
		"/graphql",
		"/openapi.json",
		"/swagger.json",
		"/swagger-ui/",
		"/admin",
		"/login",
		"/health",
		"/actuator/health",
	];
	const maxSeconds = String(Math.max(1, Math.min(3, Math.ceil(timeoutMs / 1000))));
	const rows = [];
	const matrix = [];
	for (const path of commonPaths.slice(0, deep ? commonPaths.length : 6)) {
		const url = sameOriginHttpUrl(baseUrl, path);
		if (!url) continue;
		const probe = run(
			"curl",
			[
				"-k",
				"-sS",
				"-L",
				"--max-time",
				maxSeconds,
				"-o",
				"/dev/null",
				"-w",
				"\n[repi-web-discovery] status=%{http_code} effective=%{url_effective} bytes=%{size_download} redirects=%{num_redirects} type=%{content_type}\n",
				url,
			],
			{ id: `web-discovery-${slug(path)}`, timeout: Number(maxSeconds) * 1000 + 1500, includeRaw: true },
		);
		rows.push(probe);
		const meta = parseDiscoveryMeta(probe.rawStdout ?? probe.stdout);
		matrix.push({
			url: redact(url),
			exit: probe.exit,
			status: Number.isFinite(meta.status) ? meta.status : null,
			effectiveUrl: meta.effectiveUrl ? redact(meta.effectiveUrl) : null,
			bytes: Number.isFinite(meta.bytes) ? meta.bytes : null,
			redirects: Number.isFinite(meta.redirects) ? meta.redirects : null,
			contentType: meta.contentType ? redact(meta.contentType) : null,
		});
	}
	const reachable = matrix.filter((row) => Number.isFinite(row.status) && row.status >= 100 && row.status < 500);
	const summary = {
		kind: "repi-web-discovery-matrix",
		schemaVersion: 1,
		baseUrl: redact(baseUrl),
		count: matrix.length,
		reachableCount: reachable.length,
		rows: matrix,
	};
	rows.push({
		id: "web-discovery-matrix",
		command: "internal",
		args: [redact(baseUrl)],
		cwd: root,
		exit: reachable.length ? 0 : 1,
		signal: null,
		durationMs: 0,
		stdout: `${JSON.stringify(summary, null, 2)}\n`,
		stderr: "",
		error: reachable.length ? undefined : "no reachable common endpoints",
	});
	if (!noWrite) writePrivate(join(artifactDir, "web-discovery-matrix.json"), `${JSON.stringify(summary, null, 2)}\n`);
	return {
		rows,
		replayHints: reachable
			.filter((row) => row.status !== 404)
			.map((row) => row.effectiveUrl || row.url)
			.filter(Boolean),
		schemaHints: reachable
			.filter((row) => row.status !== 404 && /graphql|openapi|swagger|api-docs/i.test(row.effectiveUrl || row.url))
			.map((row) => row.effectiveUrl || row.url)
			.filter(Boolean),
	};
}

function parseCorsMeta(stdout) {
	const match = String(stdout ?? "").match(/\[repi-web-cors\]\s+mode=([a-z-]+)\s+status=(\d{3})\s+effective=(\S+)\s+bytes=(\d+)\s+redirects=(\d+)/);
	if (!match) return {};
	return {
		mode: match[1],
		status: Number(match[2]),
		effectiveUrl: match[3],
		bytes: Number(match[4]),
		redirects: Number(match[5]),
	};
}

function headerValues(transcript, name) {
	const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
	return Array.from(String(transcript ?? "").matchAll(new RegExp(`^${escaped}:\\s*([^\\r\\n]+)`, "gim"))).map((match) => match[1].trim());
}

function lastHeader(transcript, name) {
	const values = headerValues(transcript, name);
	return values.length ? values[values.length - 1] : null;
}

function webSecurityPostureRows(baseUrl, transcript, artifactDir) {
	const csp = lastHeader(transcript, "content-security-policy");
	const hsts = lastHeader(transcript, "strict-transport-security");
	const xFrame = lastHeader(transcript, "x-frame-options");
	const xcto = lastHeader(transcript, "x-content-type-options");
	const referrerPolicy = lastHeader(transcript, "referrer-policy");
	const permissionsPolicy = lastHeader(transcript, "permissions-policy");
	const coop = lastHeader(transcript, "cross-origin-opener-policy");
	const coep = lastHeader(transcript, "cross-origin-embedder-policy");
	const corp = lastHeader(transcript, "cross-origin-resource-policy");
	const cookies = parseSetCookieRows(transcript);
	const risks = [];
	const httpsTarget = /^https:/i.test(baseUrl);
	if (!csp) risks.push("missing-content-security-policy");
	if (csp && /'unsafe-inline'/.test(csp)) risks.push("weak-csp-unsafe-inline");
	if (csp && /'unsafe-eval'/.test(csp)) risks.push("weak-csp-unsafe-eval");
	if (!xFrame && !/frame-ancestors/i.test(csp ?? "")) risks.push("clickjacking-header-missing");
	if (!/^nosniff$/i.test(xcto ?? "")) risks.push("missing-x-content-type-options-nosniff");
	if (httpsTarget && !hsts) risks.push("missing-hsts");
	if (hsts) {
		const maxAge = Number(hsts.match(/\bmax-age=(\d+)/i)?.[1] ?? "0");
		if (Number.isFinite(maxAge) && maxAge < 15_552_000) risks.push("hsts-max-age-low");
	}
	if (!referrerPolicy) risks.push("missing-referrer-policy");
	for (const cookie of cookies) risks.push(...cookie.risks);
	const summary = {
		kind: "repi-web-security-posture",
		schemaVersion: 1,
		target: redact(baseUrl),
		headers: {
			contentSecurityPolicy: csp ? redact(csp).slice(0, 1200) : null,
			strictTransportSecurity: hsts ? redact(hsts).slice(0, 400) : null,
			xFrameOptions: xFrame ? redact(xFrame).slice(0, 120) : null,
			xContentTypeOptions: xcto ? redact(xcto).slice(0, 120) : null,
			referrerPolicy: referrerPolicy ? redact(referrerPolicy).slice(0, 240) : null,
			permissionsPolicy: permissionsPolicy ? redact(permissionsPolicy).slice(0, 800) : null,
			crossOriginOpenerPolicy: coop ? redact(coop).slice(0, 160) : null,
			crossOriginEmbedderPolicy: coep ? redact(coep).slice(0, 160) : null,
			crossOriginResourcePolicy: corp ? redact(corp).slice(0, 160) : null,
		},
		cookies,
		risks: Array.from(new Set(risks)).slice(0, 120),
	};
	if (!noWrite && artifactDir) writePrivate(join(artifactDir, "web-security-posture.json"), `${JSON.stringify(summary, null, 2)}\n`);
	return [
		{
			id: "web-security-posture",
			command: "internal",
			args: [redact(baseUrl)],
			cwd: root,
			exit: cookies.length || Object.values(summary.headers).some(Boolean) ? 0 : 1,
			signal: null,
			durationMs: 0,
			stdout: `${JSON.stringify(summary, null, 2)}\n`,
			stderr: "",
			error: cookies.length || Object.values(summary.headers).some(Boolean) ? undefined : "no HTTP security headers or cookies observed",
		},
	];
}

function corsRowFromProbe(probe, url, origin, mode) {
	const raw = probe.rawStdout ?? probe.stdout;
	const meta = parseCorsMeta(raw);
	const acao = lastHeader(raw, "access-control-allow-origin");
	const acac = lastHeader(raw, "access-control-allow-credentials");
	const acam = lastHeader(raw, "access-control-allow-methods");
	const acah = lastHeader(raw, "access-control-allow-headers");
	const varyValues = headerValues(raw, "vary");
	const varyOrigin = varyValues.some((value) => /\borigin\b/i.test(value));
	const reflectedOrigin = acao === origin;
	const wildcardOrigin = acao === "*";
	const allowCredentials = /^true$/i.test(acac ?? "");
	const risks = [];
	if (reflectedOrigin && allowCredentials) risks.push("cors-reflected-origin-with-credentials");
	if (wildcardOrigin && allowCredentials) risks.push("cors-wildcard-with-credentials");
	if (acao && !varyOrigin && reflectedOrigin) risks.push("cors-missing-vary-origin");
	if (mode === "preflight" && /(?:PUT|PATCH|DELETE)/i.test(acam ?? "")) risks.push("cors-dangerous-methods-exposed");
	return {
		mode,
		url: redact(url),
		status: Number.isFinite(meta.status) ? meta.status : null,
		effectiveUrl: meta.effectiveUrl ? redact(meta.effectiveUrl) : null,
		exit: probe.exit,
		origin,
		allowOrigin: acao ? redact(acao) : null,
		allowCredentials,
		allowMethods: acam ? redact(acam) : null,
		allowHeaders: acah ? redact(acah) : null,
		varyOrigin,
		reflectedOrigin,
		wildcardOrigin,
		risks,
	};
}

function webCorsMatrix(baseUrl, hints, artifactDir, session = {}) {
	const origin = "https://evil.repi.invalid";
	const urls = uniqueSameOriginUrls(
		baseUrl,
		[
			baseUrl,
			...hints.filter((hint) => /\/(?:api|graphql|oauth|auth|login|admin|v\d+)\b|[?&](?:id|user|account|order)=/i.test(hint)),
			"/api",
			"/graphql",
		],
		deep ? 8 : 4,
	);
	if (!urls.length) return [];
	const maxSeconds = String(Math.max(1, Math.min(3, Math.ceil(timeoutMs / 1000))));
	const rows = [];
	const matrix = [];
	let index = 0;
	for (const url of urls) {
		index += 1;
		const baseArgs = ["-k", "-sS", "-L", "--max-time", maxSeconds, "-D", "-", "-o", "/dev/null", "-H", `Origin: ${origin}`];
		if (session.cookieHeader) baseArgs.push("-H", `Cookie: ${session.cookieHeader}`);
		const getProbe = run(
			"curl",
			[
				...baseArgs,
				"-w",
				"\n[repi-web-cors] mode=get status=%{http_code} effective=%{url_effective} bytes=%{size_download} redirects=%{num_redirects}\n",
				url,
			],
			{ id: `web-cors-${index}-get`, timeout: Number(maxSeconds) * 1000 + 1500, includeRaw: true },
		);
		rows.push(getProbe);
		matrix.push(corsRowFromProbe(getProbe, url, origin, "get"));
		const optionsProbe = run(
			"curl",
			[
				...baseArgs,
				"-X",
				"OPTIONS",
				"-H",
				"Access-Control-Request-Method: PUT",
				"-H",
				"Access-Control-Request-Headers: authorization,content-type",
				"-w",
				"\n[repi-web-cors] mode=preflight status=%{http_code} effective=%{url_effective} bytes=%{size_download} redirects=%{num_redirects}\n",
				url,
			],
			{ id: `web-cors-${index}-preflight`, timeout: Number(maxSeconds) * 1000 + 1500, includeRaw: true },
		);
		rows.push(optionsProbe);
		matrix.push(corsRowFromProbe(optionsProbe, url, origin, "preflight"));
	}
	const riskRows = matrix.filter((row) => row.risks.length);
	const summary = {
		kind: "repi-web-cors-matrix",
		schemaVersion: 1,
		baseUrl: redact(baseUrl),
		origin,
		session: {
			cookieNames: session.cookies?.map((cookie) => cookie.name) ?? [],
		},
		count: matrix.length,
		riskCount: riskRows.length,
		risks: Array.from(new Set(riskRows.flatMap((row) => row.risks))),
		rows: matrix,
	};
	rows.push({
		id: "web-cors-matrix",
		command: "internal",
		args: [redact(baseUrl)],
		cwd: root,
		exit: matrix.some((row) => Number.isFinite(row.status) && row.status >= 100 && row.status < 600) ? 0 : 1,
		signal: null,
		durationMs: 0,
		stdout: `${JSON.stringify(summary, null, 2)}\n`,
		stderr: "",
		error: matrix.some((row) => Number.isFinite(row.status) && row.status >= 100 && row.status < 600) ? undefined : "no CORS probes reached target",
	});
	if (!noWrite && artifactDir) writePrivate(join(artifactDir, "web-cors-matrix.json"), `${JSON.stringify(summary, null, 2)}\n`);
	return rows;
}

function jsSigningSignalPresent(signalLines) {
	return signalLines.some((line) =>
		/(?:\bsign(?:ed|ature|Params|Request|Query)?\b|x-signature|x-sign|signature|crypto\.subtle|\b(?:md5|sha-?1|sha-?256|hmac)\b|\bnonce\b|\btimestamp\b|\bcanonical\b|\bpermutation\b|\bsalt\b|\bsecret\b)/i.test(
			line,
		),
	);
}

function extractSignatureSignalNames(signalLines) {
	const names = new Set();
	const patterns = [
		["sign/signature", /\bsign(?:ed|ature|Params|Request|Query)?\b|signature|x-signature|x-sign/i],
		["crypto.subtle", /crypto\.subtle/i],
		["hash", /\b(?:md5|sha-?1|sha-?256|hmac)\b/i],
		["nonce", /\bnonce\b/i],
		["timestamp", /\btimestamp\b/i],
		["canonicalization", /\bcanonical\b/i],
		["permutation/table", /\bpermutation|lookup table|index table\b/i],
		["secret/salt", /\bsecret|salt|key\b/i],
	];
	for (const line of signalLines) {
		for (const [name, pattern] of patterns) {
			if (pattern.test(line)) names.add(name);
		}
	}
	return Array.from(names);
}

function jsSignatureEndpointCandidates(target, replayHints, signalLines) {
	const urls = [];
	const add = (value) => {
		if (!value) return;
		const raw = String(value).trim().replace(/[),;'"`]+$/g, "");
		const resolved = sameOriginHttpUrl(target, raw) || (isUrl(raw) ? raw : undefined);
		if (!resolved) return;
		if (!urls.includes(resolved)) urls.push(resolved);
	};
	for (const hint of replayHints) {
		if (/(?:\/(?:api|graphql|oauth|auth|login|admin|v\d+)\b|[?&](?:id|user|account|order|sign|sig|signature|timestamp|ts|nonce)=)/i.test(hint)) add(hint);
	}
	for (const line of signalLines) {
		for (const match of line.matchAll(/https?:\/\/[^\s"'<>`),;]+|\/[A-Za-z0-9._~:/?#[\]@!$&*+,=%-]+/g)) {
			if (/(?:\/(?:api|graphql|oauth|auth|login|admin|v\d+)\b|[?&](?:id|user|account|order|sign|sig|signature|timestamp|ts|nonce)=)/i.test(match[0])) add(match[0]);
		}
	}
	return urls.slice(0, deep ? 16 : 8).map((url) => redact(url));
}

function collectJsRuntimeSignalLines(text, label, limit = 40) {
	if (limit <= 0) return [];
	const lines = [];
	for (const [lineIndex, line] of String(text ?? "").split(/\r?\n/).entries()) {
		if (/(fetch|XMLHttpRequest|websocket|sign|signature|encrypt|decrypt|crypto\.subtle|nonce|timestamp|token|authorization|canonical|permutation|salt|secret)/i.test(line)) {
			lines.push(`${label}:${lineIndex + 1}: ${line.trim().slice(0, 220)}`);
			if (lines.length >= limit) break;
		}
	}
	return lines;
}

function summarizeJsSourceMap(rawMap, sourceMapUrl, baseUrl) {
	const summary = {
		sourceMapUrl: redact(sourceMapUrl),
		sourceCount: 0,
		sourcesWithContent: 0,
		signalLines: [],
		endpointHints: [],
		parseError: undefined,
	};
	try {
		const parsed = JSON.parse(String(rawMap ?? ""));
		const sources = Array.isArray(parsed.sources) ? parsed.sources : [];
		const sourcesContent = Array.isArray(parsed.sourcesContent) ? parsed.sourcesContent : [];
		summary.sourceCount = sources.length;
		summary.sourcesWithContent = sourcesContent.filter((content) => typeof content === "string").length;
		const endpointHints = new Set();
		for (let index = 0; index < sourcesContent.length && summary.signalLines.length < 40; index += 1) {
			const content = typeof sourcesContent[index] === "string" ? sourcesContent[index].slice(0, 120_000) : "";
			if (!content) continue;
			const sourceName = redact(String(sources[index] ?? `source-${index + 1}`)).slice(0, 160);
			const label = `${redact(sourceMapUrl)}::${sourceName}`;
			for (const line of collectJsRuntimeSignalLines(content, label, 40 - summary.signalLines.length)) summary.signalLines.push(redact(line));
			for (const hint of collectWebEndpointHints(content, baseUrl)) endpointHints.add(redact(hint));
		}
		const rawEndpointHints = Array.from(endpointHints).slice(0, 40);
		summary.endpointHints = rawEndpointHints.map((hint) => redact(hint));
		Object.defineProperty(summary, "rawEndpointHints", { value: rawEndpointHints, enumerable: false });
		return summary;
	} catch (error) {
		summary.parseError = redact(error?.message ?? String(error));
		return summary;
	}
}

function jsSignatureControlHarnessSource(plan) {
	const planJson = JSON.stringify(plan, null, 2);
	return `#!/usr/bin/env node
import { createHash } from "node:crypto";

const harnessFeatures = ["assertPermutation", "negative-controls", "policy-gap-classifier"];
const plan = ${planJson};
const requiredControls = ["signed", "missing-signature", "tampered-signature"];
const proofRule = "signed acceptance alone is not proof; require missing/tampered rejection or byte-for-byte browser-captured signature match";

export function assertPermutation(table, expectedLength = 64) {
	if (!Array.isArray(table)) throw new TypeError("table must be an array");
	if (table.length !== expectedLength) throw new Error(\`expected \${expectedLength} entries, got \${table.length}\`);
	const sorted = [...table].sort((a, b) => a - b);
	const gaps = [];
	for (let index = 0; index < expectedLength; index += 1) {
		if (sorted[index] !== index) gaps.push(index);
	}
	if (gaps.length) {
		const duplicates = sorted.filter((value, index) => index > 0 && value === sorted[index - 1]);
		throw new Error(\`table is not a true 0..\${expectedLength - 1} permutation; missing_or_wrong=\${gaps.join(",")} duplicates=\${[...new Set(duplicates)].join(",")}\`);
	}
	return true;
}

export function canonicalQuery(params) {
	return Object.entries(params)
		.sort(([left], [right]) => left.localeCompare(right))
		.map(([key, value]) => \`\${encodeURIComponent(key)}=\${encodeURIComponent(String(value))}\`)
		.join("&");
}

export function md5Hex(value) {
	return createHash("md5").update(String(value), "utf8").digest("hex");
}

export async function signParams(params, context = {}) {
	throw new Error(\`TODO: rebuild the target signer from JS assets. Enforce \${proofRule}. Context keys: \${Object.keys(context).join(",")}\`);
}

function tamperSignedParams(params) {
	const out = { ...params };
	if ("signature" in out) out.signature = "0".repeat(String(out.signature).length || 32);
	else if ("sign" in out) out.sign = "0".repeat(String(out.sign).length || 32);
	else if ("sig" in out) out.sig = "0".repeat(String(out.sig).length || 32);
	else if ("_signature" in out) out._signature = "0".repeat(String(out._signature).length || 32);
	else out.__repi_tampered_signature = "1";
	return out;
}

export async function probeEndpoint(endpoint, baseParams = {}, context = {}) {
	const signedParams = await signParams({ ...baseParams }, context);
	const url = new URL(endpoint);
	const variants = [
		{ control: "signed", params: signedParams },
		{ control: "missing-signature", params: { ...baseParams } },
		{ control: "tampered-signature", params: tamperSignedParams(signedParams) },
	];
	const rows = [];
	for (const variant of variants) {
		const requestUrl = new URL(url);
		for (const [key, value] of Object.entries(variant.params)) requestUrl.searchParams.set(key, String(value));
		const response = await fetch(requestUrl, { headers: context.headers ?? {} });
		const text = await response.text();
		let json = null;
		try {
			json = JSON.parse(text);
		} catch {
			// Non-JSON endpoint; keep hash/length evidence.
		}
		rows.push({
			control: variant.control,
			status: response.status,
			code: json && typeof json === "object" ? json.code ?? null : null,
			message: json && typeof json === "object" ? json.message ?? null : null,
			bytes: Buffer.byteLength(text),
			responseSha256: createHash("sha256").update(text).digest("hex"),
		});
	}
	return rows;
}

export function evaluateControlMatrix(rows, { browserSignatureMatch = false } = {}) {
	const byControl = Object.fromEntries(rows.map((row) => [row.control, row]));
	const accepted = (row) => row && ((row.status >= 200 && row.status < 300 && (row.code === 0 || row.code === null)) || row.status === 304);
	if (browserSignatureMatch) return "signer_proven_browser_byte_for_byte";
	if (accepted(byControl.signed) && !accepted(byControl["missing-signature"]) && !accepted(byControl["tampered-signature"])) return "signer_proven_negative_controls";
	if (accepted(byControl.signed) && accepted(byControl["missing-signature"]) && accepted(byControl["tampered-signature"])) return "policy_gap_not_signer_proof";
	if (accepted(byControl.signed)) return "partial_or_inconclusive";
	return "signer_failed";
}

if (import.meta.url === \`file://\${process.argv[1]}\`) {
	console.log(JSON.stringify({
		kind: "repi-web-js-signature-control-harness",
		requiredControls,
		proofRule,
		policyGapRule: plan.policyGapRule,
		tableChecks: plan.tableChecks,
		candidateEndpoints: plan.candidateEndpoints,
		next: "Fill signParams(), run probeEndpoint() for >=2 routes/samples, then accept proof only via negative controls or browser byte-for-byte signature match.",
	}, null, 2));
}
`;
}

function webJsSignatureControlRows(target, jsUrls, signalLines, replayHints, artifactDir) {
	if (!signalLines.length || !jsSigningSignalPresent(signalLines)) return [];
	const plan = {
		kind: "repi-web-js-signature-control-plan",
		schemaVersion: 1,
		target: redact(target),
		assets: jsUrls.map((url) => redact(url)).slice(0, deep ? 8 : 3),
		signatureSignals: extractSignatureSignalNames(signalLines),
		signalSamples: signalLines.map((line) => redact(line)).slice(0, 24),
		candidateEndpoints: jsSignatureEndpointCandidates(target, replayHints, signalLines),
		requiredControls: ["signed", "missing-signature", "tampered-signature"],
		tableChecks: [
			"assert permutation tables are true 0..N-1 permutations before trusting JS deobfuscation",
			"fail closed on duplicate or missing indices; stale tables are signer bugs until disproven",
		],
		proofRule: "signed acceptance alone is not proof; require missing/tampered rejection or byte-for-byte browser-captured signature match",
		policyGapRule: "if signed/missing/tampered all succeed, classify as policy_gap/inconclusive instead of signer_proven",
		verifierSteps: [
			"rebuild the minimal canonicalization/sign function from runtime JS assets",
			"run at least two samples or routes when available",
			"record request URLs minus secrets, HTTP status, app code/message, response hashes and byte lengths",
		],
	};
	const harness = jsSignatureControlHarnessSource(plan);
	const rows = [
		{
			id: "web-js-signature-control-plan",
			command: "internal",
			args: [redact(target)],
			cwd: root,
			exit: 0,
			signal: null,
			durationMs: 0,
			stdout: `${JSON.stringify(plan, null, 2)}\n`,
			stderr: "",
			error: undefined,
		},
		{
			id: "web-js-signature-control-harness",
			command: "internal",
			args: [redact(target)],
			cwd: root,
			exit: 0,
			signal: null,
			durationMs: 0,
			stdout: harness.slice(0, 60_000),
			stderr: "",
			error: undefined,
		},
	];
	if (!noWrite && artifactDir) {
		writePrivate(join(artifactDir, "web-js-signature-control-plan.json"), `${JSON.stringify(plan, null, 2)}\n`, 0o600);
		writePrivate(join(artifactDir, "web-js-signature-control-harness.mjs"), harness, 0o700);
	}
	return rows;
}

function webRuntimeCaptureHarnessSource(plan) {
	const planJson = JSON.stringify(plan, null, 2);
	return `#!/usr/bin/env node
import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";

const plan = ${planJson};
const target = process.argv[2] || plan.target;
const output = process.argv[3] || "web-runtime-capture.json";
const timeoutMs = Number(process.env.REPI_WEB_RUNTIME_TIMEOUT_MS || 45000);
const settleMs = Number(process.env.REPI_WEB_RUNTIME_SETTLE_MS || 4000);

if (process.argv.includes("--print-plan")) {
	console.log(JSON.stringify({ kind: "repi-web-runtime-capture-harness", hooks: plan.hooks, candidateEndpoints: plan.candidateEndpoints, output: plan.output }, null, 2));
	process.exit(0);
}

function sha256(value) {
	return createHash("sha256").update(String(value ?? "")).digest("hex");
}

function redact(value) {
	return String(value ?? "")
		.replace(/\\bBearer\\s+[A-Za-z0-9._~+/=-]{8,}/gi, "Bearer <redacted>")
		.replace(/([?&](?:api[_-]?key|token|access_token|refresh_token|client_secret|secret|password)=)[^&\\s"'<>]{4,}/gi, "$1<redacted>")
		.replace(/((?:authorization|x-api-key|api-key|cookie|set-cookie)\\s*[:=]\\s*["']?)([^"'\\n;]{4,})/gi, "$1<redacted>")
		.replace(/(["']?(?:api[_-]?key|token|secret|password|client_secret|access_token|refresh_token)["']?\\s*[:=]\\s*["'])([^"']{4,})(["'])/gi, "$1<redacted>$3");
}

function sanitize(value, depth = 0) {
	if (depth > 5) return "<max-depth>";
	if (value == null || typeof value === "number" || typeof value === "boolean") return value;
	if (typeof value === "string") {
		const text = redact(value);
		return text.length > 1200 ? { sample: text.slice(0, 1200), sha256: sha256(text), length: text.length } : text;
	}
	if (Array.isArray(value)) return value.slice(0, 200).map((item) => sanitize(item, depth + 1));
	if (typeof value === "object") {
		const out = {};
		for (const [key, item] of Object.entries(value).slice(0, 80)) out[redact(key)] = sanitize(item, depth + 1);
		return out;
	}
	return redact(String(value));
}

function runtimeInitScript() {
	return \`(() => {
	const events = [];
	const maxEvents = 600;
	const clip = (value, limit = 1000) => {
		try {
			const text = typeof value === "string" ? value : String(value);
			return text.length > limit ? text.slice(0, limit) : text;
		} catch {
			return "<unstringifiable>";
		}
	};
	const stack = () => {
		try {
			return String(new Error().stack || "").split("\\\\n").slice(2, 9).join("\\\\n");
		} catch {
			return "";
		}
	};
	const headerNames = (headers) => {
		try {
			if (!headers) return [];
			if (headers instanceof Headers) return Array.from(headers.keys()).slice(0, 40);
			if (Array.isArray(headers)) return headers.map((row) => Array.isArray(row) ? row[0] : String(row)).slice(0, 40);
			if (typeof headers === "object") return Object.keys(headers).slice(0, 40);
		} catch {}
		return [];
	};
	const urlOf = (input) => {
		try {
			if (typeof input === "string" || input instanceof URL) return String(input);
			if (input && typeof input.url === "string") return input.url;
		} catch {}
		return clip(input);
	};
	const push = (event) => {
		try {
			events.push({ at: Date.now(), stack: stack(), ...event });
			if (events.length > maxEvents) events.shift();
		} catch {}
	};
	Object.defineProperty(window, "__REPI_RUNTIME_EVENTS__", { value: events, configurable: true });

	const originalFetch = window.fetch;
	if (typeof originalFetch === "function") {
		window.fetch = function repiFetch(input, init = {}) {
			push({
				kind: "fetch-call",
				url: urlOf(input),
				method: clip(init?.method || input?.method || "GET", 40),
				headerNames: Array.from(new Set([...headerNames(input?.headers), ...headerNames(init?.headers)])),
				bodyType: init && "body" in init ? Object.prototype.toString.call(init.body) : null,
			});
			return originalFetch.apply(this, arguments).then((response) => {
				push({ kind: "fetch-response", url: response.url, status: response.status, ok: response.ok, type: response.type });
				return response;
			});
		};
	}

	const OriginalXHR = window.XMLHttpRequest;
	if (OriginalXHR) {
		const open = OriginalXHR.prototype.open;
		const send = OriginalXHR.prototype.send;
		OriginalXHR.prototype.open = function repiXhrOpen(method, url) {
			this.__repi = { method: clip(method, 40), url: urlOf(url) };
			push({ kind: "xhr-open", method: this.__repi.method, url: this.__repi.url });
			return open.apply(this, arguments);
		};
		OriginalXHR.prototype.send = function repiXhrSend(body) {
			push({ kind: "xhr-send", method: this.__repi?.method, url: this.__repi?.url, bodyType: body == null ? null : Object.prototype.toString.call(body) });
			this.addEventListener("loadend", () => push({ kind: "xhr-loadend", method: this.__repi?.method, url: this.__repi?.url, status: this.status, responseURL: this.responseURL }));
			return send.apply(this, arguments);
		};
	}

	const OriginalWebSocket = window.WebSocket;
	if (OriginalWebSocket) {
		window.WebSocket = new Proxy(OriginalWebSocket, {
			construct(Target, args) {
				push({ kind: "websocket-open", url: urlOf(args[0]), protocols: Array.isArray(args[1]) ? args[1].slice(0, 12) : args[1] || null });
				return Reflect.construct(Target, args);
			},
		});
	}

	if (window.crypto?.subtle) {
		for (const name of ["digest", "sign", "verify", "encrypt", "decrypt", "importKey", "deriveKey", "deriveBits"]) {
			const original = window.crypto.subtle[name]?.bind(window.crypto.subtle);
			if (!original) continue;
			window.crypto.subtle[name] = function repiSubtleHook(...args) {
				const algorithm = typeof args[0] === "string" ? args[0] : args[0]?.name || args[0]?.hash?.name || null;
				push({ kind: "crypto-subtle-" + name, algorithm: algorithm ? clip(algorithm, 80) : null, argTypes: args.map((arg) => Object.prototype.toString.call(arg)).slice(0, 8) });
				return original(...args);
			};
		}
	}
})();\`;
}

async function loadPlaywright() {
	try {
		return await import("playwright");
	} catch (firstError) {
		const roots = [process.cwd(), ...(Array.isArray(plan.moduleRoots) ? plan.moduleRoots : []), process.env.REPI_NODE_MODULE_ROOT].filter(Boolean);
		for (const base of roots) {
			try {
				return createRequire(join(base, "repi-runtime-capture.js"))("playwright");
			} catch {
				// Keep trying module roots captured when the harness was generated.
			}
		}
		throw firstError;
	}
}

async function main() {
	const { chromium } = await loadPlaywright().catch((error) => {
		console.error("playwright is required: npm install playwright");
		console.error("Set REPI_NODE_MODULE_ROOT to a directory containing node_modules if this artifact is outside the repo.");
		console.error(error?.message || String(error));
		process.exit(2);
	});
	const events = [];
	const browser = await chromium.launch({ headless: process.env.REPI_HEADFUL !== "1" });
	try {
		const context = await browser.newContext({
			userAgent: process.env.REPI_WEB_RUNTIME_UA || "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36",
			ignoreHTTPSErrors: true,
		});
		await context.addInitScript({ content: runtimeInitScript() });
		const page = await context.newPage();
		page.on("request", (request) => {
			events.push({ kind: "browser-request", url: request.url(), method: request.method(), resourceType: request.resourceType(), headerNames: Object.keys(request.headers()).slice(0, 40) });
		});
		page.on("response", (response) => {
			events.push({ kind: "browser-response", url: response.url(), status: response.status(), resourceType: response.request().resourceType(), headerNames: Object.keys(response.headers()).slice(0, 40) });
		});
		page.on("websocket", (ws) => {
			events.push({ kind: "browser-websocket", url: ws.url() });
		});
		await page.goto(target, { waitUntil: "domcontentloaded", timeout: timeoutMs });
		await page.waitForTimeout(settleMs);
		const runtimeEvents = await page.evaluate(() => Array.isArray(window.__REPI_RUNTIME_EVENTS__) ? window.__REPI_RUNTIME_EVENTS__ : []);
		const report = sanitize({
			kind: "repi-web-runtime-capture",
			schemaVersion: 1,
			target,
			generatedAt: new Date().toISOString(),
			plan,
			eventCount: events.length + runtimeEvents.length,
			browserEvents: events,
			runtimeEvents,
		});
		await writeFile(output, JSON.stringify(report, null, 2) + "\\n", { mode: 0o600 });
		console.log(JSON.stringify({ kind: "repi-web-runtime-capture", output, eventCount: report.eventCount }, null, 2));
	} finally {
		await browser.close();
	}
}

main().catch((error) => {
	console.error(error?.stack || error?.message || String(error));
	process.exit(1);
});
`;
}

function webRuntimeCaptureRows(target, jsUrls, signalLines, replayHints, artifactDir) {
	const hasRuntimeLeads = Boolean(jsUrls.length || signalLines.length || replayHints.length);
	const plan = {
		kind: "repi-web-runtime-capture-plan",
		schemaVersion: 1,
		target: redact(target),
		assets: jsUrls.map((url) => redact(url)).slice(0, deep ? 8 : 3),
		candidateEndpoints: jsSignatureEndpointCandidates(target, replayHints, signalLines),
		moduleRoots: [process.cwd(), localScriptsDir],
		hooks: ["fetch", "XMLHttpRequest", "WebSocket", "crypto.subtle.digest", "crypto.subtle.sign", "crypto.subtle.importKey", "browser request/response"],
		output: "web-runtime-capture.json",
		run: `node ${shellQuote(join(artifactDir, "web-runtime-capture-harness.mjs"))} <target-url> ${shellQuote(join(artifactDir, "web-runtime-capture.json"))}`,
		evidenceRules: [
			"capture runtime request order and stack initiators before replaying signed/API requests",
			"treat browser-captured signatures as byte-for-byte ground truth for signer rebuilds",
			"store only redacted URLs/header names/body metadata plus response hashes/lengths",
		],
	};
	const harness = webRuntimeCaptureHarnessSource(plan);
	const rows = [
		{
			id: "web-runtime-capture-plan",
			command: "internal",
			args: [redact(target)],
			cwd: root,
			exit: hasRuntimeLeads ? 0 : 1,
			signal: null,
			durationMs: 0,
			stdout: `${JSON.stringify(plan, null, 2)}\n`,
			stderr: "",
			error: hasRuntimeLeads ? undefined : "runtime harness scaffolded but no JS/API leads were observed",
		},
		{
			id: "web-runtime-capture-harness",
			command: "internal",
			args: [redact(target)],
			cwd: root,
			exit: hasRuntimeLeads ? 0 : 1,
			signal: null,
			durationMs: 0,
			stdout: harness.slice(0, 60_000),
			stderr: "",
			error: hasRuntimeLeads ? undefined : "runtime harness scaffolded but no JS/API leads were observed",
		},
	];
	if (!noWrite && artifactDir) {
		writePrivate(join(artifactDir, "web-runtime-capture-plan.json"), `${JSON.stringify(plan, null, 2)}\n`, 0o600);
		writePrivate(join(artifactDir, "web-runtime-capture-harness.mjs"), harness, 0o700);
	}
	return rows;
}

export function engageUrl(targetInfo, artifactDir) {
	const target = targetInfo.target;
	const rows = [];
	const proofRuntime = webReplayProofRuntime();
	if (!commandExists("curl")) {
		rows.push({ id: "curl-missing", command: "curl", args: [], cwd: root, exit: 127, signal: null, durationMs: 0, stdout: "", stderr: "curl not found", error: "curl not found" });
		return rows;
	}
	rows.push(run("curl", ["-k", "-L", "-I", "--max-time", String(Math.ceil(timeoutMs / 1000)), target], { id: "http-head", timeout: timeoutMs + 3000 }));
	let body = "";
	if (noWrite) {
		const sample = run("curl", ["-k", "-L", "--max-time", String(Math.ceil(timeoutMs / 1000)), "-D", "-", "-o", "-", target], { id: "http-get-sample", timeout: timeoutMs + 5000, includeRaw: true });
		rows.push(sample);
		body = (sample.rawStdout ?? sample.stdout).slice(0, 400_000);
	} else {
		const sample = run("curl", ["-k", "-L", "--max-time", String(Math.ceil(timeoutMs / 1000)), "-D", "-", "-o", "-", target], { id: "http-get-sample", timeout: timeoutMs + 5000, includeRaw: true });
		rows.push(sample);
		body = (sample.rawStdout ?? sample.stdout).slice(0, 400_000);
		writePrivate(join(artifactDir, "http-response-sample.txt"), redact(body));
	}
	const assets = Array.from(body.matchAll(/(?:src|href)=["']([^"']+)["']/gi))
		.map((match) => match[1])
		.filter(Boolean)
		.slice(0, 120);
	if (!noWrite) writePrivate(join(artifactDir, "web-assets.json"), `${JSON.stringify({ target: redact(target), assets: assets.map((asset) => redact(asset)) }, null, 2)}\n`);
	rows.push(...webSecurityPostureRows(target, body, artifactDir));
	const cookies = extractSetCookiePairs(body);
	const csrfHints = collectCsrfHints(body);
	const sessionContext = { cookies, cookieHeader: cookieHeaderFromPairs(cookies), csrfHints };
	if (cookies.length || csrfHints.length) {
		const sessionHints = {
			kind: "repi-web-session-hints",
			schemaVersion: 1,
			cookies: cookies.map((cookie) => ({ name: cookie.name, valueSha256: cookie.valueSha256 })),
			csrf: csrfHints,
		};
		rows.push({ id: "web-session-hints", command: "internal", args: [redact(target)], cwd: root, exit: 0, signal: null, durationMs: 0, stdout: `${JSON.stringify(sessionHints, null, 2)}\n`, stderr: "", error: undefined });
		if (!noWrite) writePrivate(join(artifactDir, "web-session-hints.json"), `${JSON.stringify(sessionHints, null, 2)}\n`);
	}
	rows.push(...webIdentityJwtRows(target, body, cookies, artifactDir));
	const endpointHints = collectWebEndpointHints(body, target);
	const replayHints = [...endpointHints];
	if (endpointHints.length) {
		rows.push({ id: "web-endpoint-scan", command: "internal", args: [redact(target)], cwd: root, exit: 0, signal: null, durationMs: 0, stdout: `${endpointHints.map((hint) => redact(hint)).join("\n")}\n`, stderr: "", error: undefined });
	}
	const discovery = webDiscoveryMatrix(target, artifactDir);
	rows.push(...discovery.rows);
	let jsUrls = [];
	let jsSignalLines = [];
	if (assets.some((asset) => /\.js(?:\?|$)/i.test(asset))) {
		jsUrls = assets
			.filter((asset) => /\.js(?:[?#]|$)/i.test(asset))
			.map((asset) => resolveHttpAssetUrl(target, asset))
			.filter(Boolean)
			.slice(0, deep ? 8 : 3);
		rows.push({ id: "web-js-asset-hint", command: "internal", args: jsUrls.map((url) => redact(url)), cwd: root, exit: 0, signal: null, durationMs: 0, stdout: `js_assets=${jsUrls.map((url) => redact(url)).join("\n")}\n`, stderr: "", error: undefined });
		const signalLines = [];
		const sourceMapSummaries = [];
		for (let index = 0; index < jsUrls.length; index++) {
			const jsUrl = jsUrls[index];
			const fetched = run("curl", ["-k", "-L", "--max-time", String(Math.ceil(timeoutMs / 1000)), jsUrl], { id: `web-js-asset-${index + 1}-fetch`, timeout: timeoutMs + 3000, includeRaw: true });
			rows.push({ ...fetched, stdout: fetched.stdout.slice(0, 300_000) });
			const jsBody = (fetched.rawStdout ?? fetched.stdout).slice(0, 300_000);
			if (!noWrite && fetched.exit === 0) writePrivate(join(artifactDir, "web-js-assets", `asset-${index + 1}.js`), redact(jsBody));
			const jsEndpointHints = collectWebEndpointHints(jsBody, jsUrl);
			if (jsEndpointHints.length) {
				replayHints.push(...jsEndpointHints);
				rows.push({ id: `web-js-asset-${index + 1}-endpoint-scan`, command: "internal", args: [redact(jsUrl)], cwd: root, exit: 0, signal: null, durationMs: 0, stdout: `${jsEndpointHints.map((hint) => redact(hint)).join("\n")}\n`, stderr: "", error: undefined });
			}
			signalLines.push(...collectJsRuntimeSignalLines(jsBody, jsUrl, Math.max(0, 40 - signalLines.length)));
			const sourceMapMatch = jsBody.match(/sourceMappingURL=([^\s*]+)/i);
			const sourceMapUrl = sourceMapMatch ? resolveHttpAssetUrl(jsUrl, sourceMapMatch[1].trim()) : undefined;
			if (sourceMapUrl) {
				const sourceMap = run("curl", ["-k", "-L", "--max-time", String(Math.ceil(timeoutMs / 1000)), sourceMapUrl], { id: `web-js-asset-${index + 1}-sourcemap-fetch`, timeout: timeoutMs + 3000, includeRaw: true });
				rows.push({ ...sourceMap, stdout: sourceMap.stdout.slice(0, 200_000) });
				const sourceMapBody = (sourceMap.rawStdout ?? sourceMap.stdout).slice(0, 300_000);
				if (!noWrite && sourceMap.exit === 0) writePrivate(join(artifactDir, "web-js-assets", `asset-${index + 1}.map`), redact(sourceMapBody.slice(0, 200_000)));
				if (sourceMap.exit === 0) {
					const sourceMapSummary = summarizeJsSourceMap(sourceMapBody, sourceMapUrl, jsUrl);
					sourceMapSummaries.push(sourceMapSummary);
					if (sourceMapSummary.rawEndpointHints?.length) replayHints.push(...sourceMapSummary.rawEndpointHints);
					if (sourceMapSummary.signalLines.length) signalLines.push(...sourceMapSummary.signalLines.slice(0, Math.max(0, 40 - signalLines.length)));
					if (sourceMapSummary.signalLines.length || sourceMapSummary.endpointHints.length || sourceMapSummary.parseError) {
						rows.push({
							id: `web-js-asset-${index + 1}-sourcemap-scan`,
							command: "internal",
							args: [redact(sourceMapUrl)],
							cwd: root,
							exit: sourceMapSummary.parseError ? 1 : 0,
							signal: null,
							durationMs: 0,
							stdout: `${JSON.stringify(sourceMapSummary, null, 2)}\n`,
							stderr: "",
							error: sourceMapSummary.parseError ? "source map parse failed" : undefined,
						});
					}
				}
			}
		}
		if (!noWrite && sourceMapSummaries.length) {
			writePrivate(join(artifactDir, "web-js-sourcemap-summary.json"), `${JSON.stringify({ kind: "repi-web-js-sourcemap-summary", schemaVersion: 1, sourceMaps: sourceMapSummaries }, null, 2)}\n`);
		}
		if (signalLines.length) {
			rows.push({ id: "web-js-asset-scan", command: "internal", args: jsUrls.map((url) => redact(url)), cwd: root, exit: 0, signal: null, durationMs: 0, stdout: `${signalLines.map((line) => redact(line)).join("\n")}\n`, stderr: "", error: undefined });
		}
		rows.push(...webJsSignatureControlRows(target, jsUrls, signalLines, replayHints, artifactDir));
		jsSignalLines = signalLines;
	}
	rows.push(...webRuntimeCaptureRows(target, jsUrls, jsSignalLines, replayHints, artifactDir));
	rows.push(...webRuntimeReplayVerifierRows(target, jsUrls, jsSignalLines, replayHints, artifactDir, proofRuntime));
	rows.push(...webSignerRebuildWorkbenchRows(target, jsUrls, jsSignalLines, replayHints, artifactDir, proofRuntime));
	replayHints.push(...discovery.replayHints);
	const schemaProbes = webApiSchemaProbes(target, replayHints, artifactDir, sessionContext, discovery.schemaHints);
	rows.push(...schemaProbes.rows);
	replayHints.push(...schemaProbes.replayHints);
	rows.push(...webSsrfMatrix(target, replayHints, artifactDir, sessionContext));
	rows.push(...webRedirectMatrix(target, replayHints, artifactDir, sessionContext));
	rows.push(...webCorsMatrix(target, replayHints, artifactDir, sessionContext));
	rows.push(...webObjectMatrix(target, replayHints, artifactDir, sessionContext));
	rows.push(...webReplayMatrix(target, replayHints, artifactDir, sessionContext));
	const exploitClaims = writeWebExploitClaims(target, artifactDir, proofRuntime);
	if (exploitClaims) {
		rows.push({
			id: "web-exploit-claims",
			command: "internal",
			args: [redact(exploitClaims.path)],
			cwd: root,
			exit: exploitClaims.summary.proofReady ? 0 : 1,
			signal: null,
			durationMs: 0,
			stdout: `${JSON.stringify(exploitClaims.summary, null, 2)}\n`,
			stderr: "",
			error: exploitClaims.summary.proofReady ? undefined : "no web exploit claims promoted",
		});
	}
	const exploitVerifierPath = writeWebExploitVerifier(artifactDir, proofRuntime);
	if (exploitVerifierPath) {
		rows.push({
			id: "web-exploit-verifier-artifact",
			command: "internal",
			args: [redact(exploitVerifierPath)],
			cwd: root,
			exit: 0,
			signal: null,
			durationMs: 0,
			stdout: `verifier=${redact(exploitVerifierPath)}\nrun=node ${redact(exploitVerifierPath)} ${redact(artifactDir)} ${redact(join(artifactDir, "web-exploit-verification.json"))}\n`,
			stderr: "",
			error: undefined,
		});
	}
	const exploitVerification = writeWebExploitVerification(target, artifactDir, exploitClaims?.summary, proofRuntime);
	if (exploitVerification) {
		rows.push({
			id: "web-exploit-verification",
			command: "internal",
			args: [redact(exploitVerification.path)],
			cwd: root,
			exit: exploitVerification.summary.proofReady ? 0 : 1,
			signal: null,
			durationMs: 0,
			stdout: `${JSON.stringify(exploitVerification.summary, null, 2)}\n`,
			stderr: "",
			error: exploitVerification.summary.proofReady ? undefined : "web exploit verification proof gates not satisfied",
		});
	}
	return rows;
}
