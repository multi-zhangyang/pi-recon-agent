import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

export function webRuntimeReplayVerifierSource(plan) {
	const planJson = JSON.stringify(plan, null, 2);
	return `#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

const plan = ${planJson};
const input = process.argv[2] || plan.captureFile || "web-runtime-capture.json";
const output = process.argv[3] || "web-runtime-replay-results.json";
const liveReplay = process.argv.includes("--live");
const selfTest = process.argv.includes("--self-test");
const signatureParamPattern = /^(?:signature|sign|sig|_signature|x-signature|x-sign|timestamp|ts|nonce)$/i;
const strongSignatureParamPattern = /^(?:signature|sign|sig|_signature|x-signature|x-sign)$/i;

function sha256(value) {
	return createHash("sha256").update(String(value ?? "")).digest("hex");
}

function redact(value) {
	return String(value ?? "")
		.replace(/\\bBearer\\s+[A-Za-z0-9._~+/=-]{8,}/gi, "Bearer <redacted>")
		.replace(/([?&](?:api[_-]?key|token|access_token|refresh_token|client_secret|secret|password)=)[^&\\s"'<>]{4,}/gi, "$1<redacted>")
		.replace(/((?:authorization|x-api-key|api-key|cookie|set-cookie)\\s*[:=]\\s*["']?)([^"'\\n;]{4,})/gi, "$1<redacted>");
}

function sanitizeUrl(url) {
	try {
		const parsed = new URL(url);
		for (const key of [...parsed.searchParams.keys()]) {
			if (/api[_-]?key|token|access_token|refresh_token|client_secret|secret|password/i.test(key)) parsed.searchParams.set(key, "<redacted>");
		}
		return redact(parsed.href);
	} catch {
		return redact(url);
	}
}

function allEvents(capture) {
	const out = [];
	const push = (event, source) => {
		if (event && typeof event === "object") out.push({ source, ...event });
	};
	for (const event of Array.isArray(capture?.browserEvents) ? capture.browserEvents : []) push(event, "browserEvents");
	for (const event of Array.isArray(capture?.runtimeEvents) ? capture.runtimeEvents : []) push(event, "runtimeEvents");
	return out;
}

function extractCandidates(capture) {
	const seen = new Set();
	const candidates = [];
	for (const event of allEvents(capture)) {
		if (typeof event.url !== "string") continue;
		let url;
		try {
			url = new URL(event.url);
		} catch {
			continue;
		}
		if (!["http:", "https:"].includes(url.protocol)) continue;
		const params = [...url.searchParams.keys()];
		const signatureParams = params.filter((key) => signatureParamPattern.test(key));
		if (!signatureParams.length) continue;
		const strongSignatureParams = signatureParams.filter((key) => strongSignatureParamPattern.test(key));
		const key = \`\${event.method || "GET"} \${url.href}\`;
		if (seen.has(key)) continue;
		seen.add(key);
		candidates.push({
			source: event.source,
			eventKind: event.kind || null,
			method: event.method || "GET",
			url: url.href,
			redactedUrl: sanitizeUrl(url.href),
			signatureParams,
			strongSignatureParams,
			headerNames: Array.isArray(event.headerNames) ? event.headerNames.slice(0, 40).map(redact) : [],
		});
	}
	return candidates.slice(0, 40);
}

function variantUrl(url, mode) {
	const parsed = new URL(url);
	if (mode === "missing-signature") {
		for (const key of [...parsed.searchParams.keys()]) {
			if (signatureParamPattern.test(key)) parsed.searchParams.delete(key);
		}
		return parsed.href;
	}
	if (mode === "tampered-signature") {
		for (const key of [...parsed.searchParams.keys()]) {
			if (strongSignatureParamPattern.test(key)) {
				const current = parsed.searchParams.get(key) || "";
				parsed.searchParams.set(key, "0".repeat(Math.max(8, Math.min(64, current.length || 32))));
			}
		}
		return parsed.href;
	}
	if (mode === "stale-timestamp") {
		for (const key of [...parsed.searchParams.keys()]) {
			if (/^(?:timestamp|ts|time)$/i.test(key)) parsed.searchParams.set(key, "1234567890");
		}
		return parsed.href;
	}
	return parsed.href;
}

function buildMatrix(candidates) {
	return candidates.map((candidate) => ({
		candidate: {
			...candidate,
			url: candidate.redactedUrl,
			redactedUrl: candidate.redactedUrl,
		},
		negativeControls: ["captured-signed", "missing-signature", "tampered-signature", "stale-timestamp"],
		variants: ["captured-signed", "missing-signature", "tampered-signature", "stale-timestamp"].map((control) => ({
			control,
			url: sanitizeUrl(variantUrl(candidate.url, control)),
		})),
	}));
}

function accepted(row) {
	return row && row.skipped !== true && row.status >= 200 && row.status < 300 && (row.code === 0 || row.code === null || typeof row.code === "undefined");
}

function evaluate(rows) {
	const byControl = Object.fromEntries(rows.map((row) => [row.control, row]));
	if (accepted(byControl["captured-signed"]) && !accepted(byControl["missing-signature"]) && !accepted(byControl["tampered-signature"])) return "signer_proven_negative_controls";
	if (accepted(byControl["captured-signed"]) && accepted(byControl["missing-signature"]) && accepted(byControl["tampered-signature"])) return "policy_gap_not_signer_proof";
	if (accepted(byControl["captured-signed"])) return "partial_or_inconclusive";
	return "inconclusive_or_replay_failed";
}

function rejected(row) {
	return row && row.skipped !== true && row.status >= 400 && row.status < 600;
}

function statusEvidence(row) {
	if (!row) return "missing row";
	const status = typeof row.status === "number" ? "HTTP " + row.status : row.skipped ? "skipped" : "no status";
	const code = row.code === null || typeof row.code === "undefined" ? "" : " code=" + row.code;
	const reason = row.reason ? " reason=" + row.reason : "";
	const hash = row.responseSha256 ? " sha256=" + String(row.responseSha256).slice(0, 16) : "";
	return row.control + ": " + status + code + reason + hash;
}

function timestampControlRequired(candidate) {
	return Array.isArray(candidate?.signatureParams) && candidate.signatureParams.some((key) => /^(?:timestamp|ts|time)$/i.test(key));
}

function promotionForRow(row) {
	const byControl = Object.fromEntries((row.variants || []).map((variant) => [variant.control, variant]));
	const capturedAccepted = accepted(byControl["captured-signed"]);
	const missingRejected = rejected(byControl["missing-signature"]) || !accepted(byControl["missing-signature"]);
	const tamperedRejected = rejected(byControl["tampered-signature"]) || !accepted(byControl["tampered-signature"]);
	const staleRequired = timestampControlRequired(row.candidate);
	const staleRejected = !staleRequired || rejected(byControl["stale-timestamp"]) || !accepted(byControl["stale-timestamp"]);
	const negativeControlsOk = capturedAccepted && missingRejected && tamperedRejected && staleRejected;
	const signatureParams = Array.isArray(row.candidate?.signatureParams) ? row.candidate.signatureParams : [];
	const evidence = [
		"candidate=" + (row.candidate?.redactedUrl || row.candidate?.url || "<unknown>"),
		statusEvidence(byControl["captured-signed"]),
		statusEvidence(byControl["missing-signature"]),
		statusEvidence(byControl["tampered-signature"]),
		statusEvidence(byControl["stale-timestamp"]),
		"signatureParams=" + signatureParams.join(","),
		"verdict=" + row.verdict,
	];
	const blockers = [];
	if (!capturedAccepted) blockers.push("captured-signed replay was not accepted");
	if (!missingRejected) blockers.push("missing-signature control was accepted");
	if (!tamperedRejected) blockers.push("tampered-signature control was accepted");
	if (staleRequired && !staleRejected) blockers.push("stale-timestamp control was accepted");
	if (!signatureParams.some((key) => strongSignatureParamPattern.test(key))) blockers.push("no strong signature parameter observed");
	return {
		id: "runtime-replay-" + sha256(JSON.stringify([row.candidate?.redactedUrl, signatureParams])).slice(0, 12),
		statement: negativeControlsOk
			? "Browser-captured signed request passed while signature negative controls failed."
			: "Runtime replay negative-control matrix is not sufficient for signer proof.",
		evidence,
		confidence: negativeControlsOk ? 0.9 : capturedAccepted ? 0.45 : 0.2,
		blockers,
		verdict: negativeControlsOk ? "promoted" : "observation",
	};
}

function buildPromotionReport(rows) {
	const claims = rows.map(promotionForRow);
	return {
		kind: "repi-web-runtime-replay-promotion-report",
		proofReady: claims.some((claim) => claim.verdict === "promoted"),
		promotedClaims: claims.filter((claim) => claim.verdict === "promoted"),
		observations: claims.filter((claim) => claim.verdict !== "promoted"),
	};
}

async function replayVariant(candidate, control) {
	const url = variantUrl(candidate.url, control);
	if (!/^GET|HEAD$/i.test(candidate.method || "GET")) {
		return { control, url: sanitizeUrl(url), skipped: true, reason: "non-GET capture has no body material" };
	}
	const response = await fetch(url, { method: candidate.method || "GET", headers: { "User-Agent": "REPI-runtime-replay-verifier" } });
	const text = await response.text();
	let body = null;
	try {
		body = JSON.parse(text);
	} catch {
		// Keep hash-only evidence for non-JSON.
	}
	return {
		control,
		url: sanitizeUrl(url),
		status: response.status,
		code: body && typeof body === "object" ? body.code ?? null : null,
		message: body && typeof body === "object" ? redact(body.message ?? "") : null,
		bytes: Buffer.byteLength(text),
		responseSha256: sha256(text),
	};
}

async function runReplay(candidates) {
	const rows = [];
	for (const candidate of candidates) {
		const controls = ["captured-signed", "missing-signature", "tampered-signature", "stale-timestamp"];
		const variants = [];
		for (const control of controls) variants.push(await replayVariant(candidate, control));
		const verdict = evaluate(variants);
		rows.push({
			candidate: { ...candidate, url: candidate.redactedUrl, redactedUrl: candidate.redactedUrl },
			variants,
			verdict,
			promotion: promotionForRow({ candidate: { ...candidate, url: candidate.redactedUrl, redactedUrl: candidate.redactedUrl }, variants, verdict }),
		});
	}
	return rows;
}

function selfTestReport() {
	const capture = {
		browserEvents: [
			{
				kind: "browser-request",
				method: "GET",
				url: "https://example.test/api/signed/view?object_id=demo&timestamp=1782930000&signature=abcdef1234567890abcdef1234567890&access_token=secret-token",
				headerNames: ["user-agent", "authorization"],
			},
		],
		runtimeEvents: [],
	};
	const candidates = extractCandidates(capture);
	const row = {
		candidate: { ...candidates[0], url: candidates[0].redactedUrl, redactedUrl: candidates[0].redactedUrl },
		variants: [
			{ control: "captured-signed", status: 200, code: 0, responseSha256: sha256("ok") },
			{ control: "missing-signature", status: 403, code: -400, responseSha256: sha256("missing") },
			{ control: "tampered-signature", status: 403, code: -400, responseSha256: sha256("tampered") },
			{ control: "stale-timestamp", status: 403, code: -400, responseSha256: sha256("stale") },
		],
	};
	row.verdict = evaluate(row.variants);
	row.promotion = promotionForRow(row);
	return {
		kind: "repi-web-runtime-replay-verifier-self-test",
		candidateCount: candidates.length,
		matrix: buildMatrix(candidates),
		rows: [row],
		promotionReport: buildPromotionReport([row]),
		negativeControls: ["captured-signed", "missing-signature", "tampered-signature", "stale-timestamp"],
	};
}

async function main() {
	if (selfTest) {
		console.log(JSON.stringify(selfTestReport(), null, 2));
		return;
	}
	const capture = JSON.parse(await readFile(input, "utf8"));
	const candidates = extractCandidates(capture);
	const result = {
		kind: "repi-web-runtime-replay-results",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		liveReplay,
		input,
		output,
		candidateCount: candidates.length,
		plan,
		matrix: buildMatrix(candidates),
		rows: liveReplay ? await runReplay(candidates) : [],
		next: liveReplay ? "Use verdicts directly; signer proof requires captured-signed accepted and missing/tampered rejected." : "Run with --live after reviewing candidate URLs to execute negative-control replays.",
	};
	result.promotionReport = buildPromotionReport(result.rows);
	await writeFile(output, JSON.stringify(result, null, 2) + "\\n", { mode: 0o600 });
	console.log(JSON.stringify({ kind: result.kind, output, candidateCount: result.candidateCount, liveReplay, proofReady: result.promotionReport.proofReady }, null, 2));
}

main().catch((error) => {
	console.error(error?.stack || error?.message || String(error));
	process.exit(1);
});
`;
}

export function webRuntimeReplayVerifierRows(target, jsUrls, signalLines, replayHints, artifactDir, runtime) {
	const { redact, shellQuote, root, noWrite, writePrivate, jsSignatureEndpointCandidates } = runtime;
	const hasRuntimeLeads = Boolean(jsUrls.length || signalLines.length || replayHints.length);
	const plan = {
		kind: "repi-web-runtime-replay-plan",
		schemaVersion: 1,
		target: redact(target),
		captureFile: join(artifactDir, "web-runtime-capture.json"),
		output: join(artifactDir, "web-runtime-replay-results.json"),
		candidateEndpoints: jsSignatureEndpointCandidates(target, replayHints, signalLines),
		signatureParams: ["signature", "sign", "sig", "_signature", "x-signature", "x-sign", "timestamp", "ts", "nonce"],
		negativeControls: ["captured-signed", "missing-signature", "tampered-signature", "stale-timestamp"],
		proofRule: "captured-signed replay accepted while missing/tampered variants fail, or browser-captured signature matches rebuilt signer byte-for-byte",
		run: `node ${shellQuote(join(artifactDir, "web-runtime-replay-verifier.mjs"))} ${shellQuote(join(artifactDir, "web-runtime-capture.json"))} ${shellQuote(join(artifactDir, "web-runtime-replay-results.json"))} --live`,
	};
	const verifier = webRuntimeReplayVerifierSource(plan);
	const rows = [
		{
			id: "web-runtime-replay-plan",
			command: "internal",
			args: [redact(target)],
			cwd: root,
			exit: hasRuntimeLeads ? 0 : 1,
			signal: null,
			durationMs: 0,
			stdout: `${JSON.stringify(plan, null, 2)}\n`,
			stderr: "",
			error: hasRuntimeLeads ? undefined : "runtime replay scaffolded but no JS/API leads were observed",
		},
		{
			id: "web-runtime-replay-verifier",
			command: "internal",
			args: [redact(target)],
			cwd: root,
			exit: hasRuntimeLeads ? 0 : 1,
			signal: null,
			durationMs: 0,
			stdout: verifier.slice(0, 60_000),
			stderr: "",
			error: hasRuntimeLeads ? undefined : "runtime replay scaffolded but no JS/API leads were observed",
		},
	];
	if (!noWrite && artifactDir) {
		writePrivate(join(artifactDir, "web-runtime-replay-plan.json"), `${JSON.stringify(plan, null, 2)}\n`, 0o600);
		writePrivate(join(artifactDir, "web-runtime-replay-verifier.mjs"), verifier, 0o700);
	}
	return rows;
}

export function webSignerRebuildWorkbenchSource(plan) {
	const planJson = JSON.stringify(plan, null, 2);
	return String.raw`#!/usr/bin/env node
import { createHash, createHmac } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";

const plan = ${planJson};
const outPath = process.argv[2] || plan.sampleOutput || "web-signer-rebuild-samples.json";
const selfTest = process.argv.includes("--self-test");
const signatureParamPattern = /^(?:signature|sign|sig|_signature|x-signature|x-sign)$/i;
const volatileParamPattern = /^(?:timestamp|ts|time|nonce|_ts|_t|_rnd|random)$/i;
const secretParamPattern = /(?:secret|salt|key|appkey|app_key|appsec|app_secret|client_salt)$/i;
const redactedPattern = /<redacted>|\bredacted\b/i;

function hashHex(algorithm, value) {
	return createHash(algorithm).update(String(value ?? "")).digest("hex");
}

function md5Hex(value) {
	return hashHex("md5", value);
}

function sha256(value) {
	return hashHex("sha256", value);
}

function hmacHex(algorithm, key, value) {
	return createHmac(algorithm, String(key ?? "")).update(String(value ?? "")).digest("hex");
}

function redact(value) {
	return String(value ?? "")
		.replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, "Bearer <redacted>")
		.replace(/([?&](?:api[_-]?key|token|access_token|refresh_token|client_secret|secret|password)=)[^&\s"'<>]{4,}/gi, "$1<redacted>")
		.replace(/((?:authorization|x-api-key|api-key|cookie|set-cookie)\s*[:=]\s*["']?)([^"'\n;]{4,})/gi, "$1<redacted>");
}

function sanitizeUrl(url) {
	try {
		const parsed = new URL(url);
		for (const key of [...parsed.searchParams.keys()]) {
			if (/api[_-]?key|token|access_token|refresh_token|client_secret|secret|password/i.test(key)) parsed.searchParams.set(key, "<redacted>");
		}
		return redact(parsed.href);
	} catch {
		return redact(url);
	}
}

export function assertPermutation(table, expectedLength = 64) {
	if (!Array.isArray(table)) throw new TypeError("table must be an array");
	if (table.length !== expectedLength) throw new Error("expected " + expectedLength + " entries, got " + table.length);
	const sorted = [...table].sort((a, b) => a - b);
	for (let index = 0; index < expectedLength; index += 1) {
		if (sorted[index] !== index) throw new Error("table is not a true permutation");
	}
	return true;
}

export function permutationKeyFromRawKey(rawKey, table) {
	assertPermutation(table, Array.isArray(table) ? table.length : 0);
	const text = String(rawKey ?? "");
	return table.map((index) => text[index] || "").join("");
}

export function canonicalQuery(params) {
	return Object.entries(params)
		.filter(([, value]) => value !== undefined && value !== null)
		.sort(([left], [right]) => left.localeCompare(right))
		.map(([key, value]) => encodeURIComponent(key) + "=" + encodeURIComponent(String(value)))
		.join("&");
}

function canonicalQueryStripped(params) {
	return Object.entries(params)
		.filter(([key, value]) => value !== undefined && value !== null && !signatureParamPattern.test(key))
		.sort(([left], [right]) => left.localeCompare(right))
		.map(([key, value]) => encodeURIComponent(key) + "=" + encodeURIComponent(String(value).replace(/[!'()*]/g, "")))
		.join("&");
}

function stableInputParams(sample) {
	return { ...(sample?.unsignedParams || {}), ...(sample?.volatileParams || {}) };
}

export async function signParams(_params, _context = {}) {
	throw new Error("TODO: implement target signer. Regression gate: every browser-captured sample must match byte-for-byte before live replay proof.");
}

export async function assertByteForByte(sample, context = {}) {
	const params = stableInputParams(sample);
	const signed = await signParams(params, context);
	for (const [key, expected] of Object.entries(sample.signatureParams || {})) {
		if (String(signed[key]) !== String(expected)) {
			throw new Error("signature mismatch for " + key + ": expected " + expected + ", got " + signed[key]);
		}
	}
	return true;
}

async function readJson(path) {
	if (!path || !existsSync(path)) return null;
	return JSON.parse(await readFile(path, "utf8"));
}

function captureEvents(capture) {
	return [
		...(Array.isArray(capture?.browserEvents) ? capture.browserEvents.map((event) => ({ source: "browserEvents", ...event })) : []),
		...(Array.isArray(capture?.runtimeEvents) ? capture.runtimeEvents.map((event) => ({ source: "runtimeEvents", ...event })) : []),
	];
}

function sampleFromUrl(event) {
	if (typeof event.url !== "string") return null;
	let parsed;
	try {
		parsed = new URL(event.url);
	} catch {
		return null;
	}
	const signatureParams = {};
	const volatileParams = {};
	const unsignedParams = {};
	for (const [key, value] of parsed.searchParams.entries()) {
		if (signatureParamPattern.test(key)) signatureParams[key] = value;
		else if (volatileParamPattern.test(key)) volatileParams[key] = value;
		else unsignedParams[key] = value;
	}
	if (!Object.keys(signatureParams).length) return null;
	return {
		source: event.source,
		eventKind: event.kind || null,
		method: event.method || "GET",
		origin: parsed.origin,
		pathname: parsed.pathname,
		redactedUrl: sanitizeUrl(parsed.href),
		unsignedParams,
		volatileParams,
		signatureParams,
		canonicalUnsigned: canonicalQuery({ ...unsignedParams, ...volatileParams }),
		signatureParamNames: Object.keys(signatureParams).sort(),
		sampleHash: sha256((event.method || "GET") + " " + parsed.origin + parsed.pathname + "?" + canonicalQuery({ ...unsignedParams, ...volatileParams })),
	};
}

function extractSamples(capture) {
	const seen = new Set();
	const samples = [];
	for (const event of captureEvents(capture)) {
		const sample = sampleFromUrl(event);
		if (!sample) continue;
		const key = sample.method + " " + sample.redactedUrl;
		if (seen.has(key)) continue;
		seen.add(key);
		samples.push(sample);
	}
	return samples.slice(0, 80);
}

function summarizeSourceSignals(sourceMap) {
	const rows = [];
	for (const item of Array.isArray(sourceMap?.sourceMaps) ? sourceMap.sourceMaps : []) {
		for (const line of Array.isArray(item.signalLines) ? item.signalLines : []) {
			if (/sign|signature|crypto\.subtle|nonce|timestamp|salt|secret|key|canonical|permutation|hmac|md5|sha/i.test(line)) rows.push(redact(line).slice(0, 400));
		}
	}
	return rows.slice(0, 80);
}

function summarizeReplay(replay) {
	const rows = Array.isArray(replay?.rows) ? replay.rows : [];
	const verdicts = rows.map((row) => row.verdict).filter(Boolean);
	const matrix = Array.isArray(replay?.matrix) ? replay.matrix : [];
	return {
		liveReplay: Boolean(replay?.liveReplay),
		candidateCount: replay?.candidateCount ?? matrix.length,
		verdicts: Array.from(new Set(verdicts)),
		negativeControls: ["captured-signed", "missing-signature", "tampered-signature", "stale-timestamp"],
	};
}

function plausibleSecret(value) {
	const text = String(value ?? "");
	if (text.length < 4 || text.length > 256) return false;
	if (redactedPattern.test(text)) return false;
	if (/^https?:\/\//i.test(text)) return false;
	if (/^[/?#]/.test(text)) return false;
	if (/^[0-9]+$/.test(text) && text.length < 16) return false;
	return true;
}

function addSecret(secrets, seen, value, source, label) {
	const text = String(value ?? "");
	if (!plausibleSecret(text)) return;
	const fingerprint = sha256(text).slice(0, 16);
	if (seen.has(fingerprint)) return;
	seen.add(fingerprint);
	secrets.push({
		id: "secret-" + String(secrets.length + 1).padStart(2, "0"),
		value: text,
		source,
		label,
		fingerprint,
		length: text.length,
	});
}

function extractCandidateSecrets(samples, sourceSignals) {
	const secrets = [];
	const seen = new Set();
	for (const sample of samples) {
		const params = stableInputParams(sample);
		for (const [key, value] of Object.entries(params)) {
			if (secretParamPattern.test(key)) addSecret(secrets, seen, value, "sample-param", key);
		}
	}
	const quoted = /["']([^"'\n]{4,128})["']/g;
	for (const line of sourceSignals) {
		if (!/sign|signature|salt|secret|key|canonical|permutation|md5|sha|hmac/i.test(line)) continue;
		let match;
		while ((match = quoted.exec(line))) {
			addSecret(secrets, seen, match[1], "source-signal", "quoted-string");
		}
		const assignment = /(?:salt|secret|appkey|app_key|appsec|app_secret|client_salt|key)\s*[:=]\s*([A-Za-z0-9._~+/=-]{4,128})/gi;
		while ((match = assignment.exec(line))) {
			addSecret(secrets, seen, match[1], "source-signal", "assignment");
		}
	}
	return secrets.slice(0, 40);
}

function secretRef(secret) {
	if (!secret) return null;
	return {
		id: secret.id,
		source: secret.source,
		label: secret.label,
		length: secret.length,
		sha256Prefix: secret.fingerprint,
	};
}

function inputValue(sample, inputName) {
	const params = stableInputParams(sample);
	if (inputName === "sample-canonicalUnsigned") return sample.canonicalUnsigned || canonicalQuery(params);
	if (inputName === "canonical-query-stripped") return canonicalQueryStripped(params);
	if (inputName === "path-and-canonical") return (sample.pathname || "") + "?" + canonicalQuery(params);
	if (inputName === "method-path-canonical") return String(sample.method || "GET").toUpperCase() + "\n" + (sample.pathname || "") + "\n" + canonicalQuery(params);
	return canonicalQuery(params);
}

function pushCandidate(candidates, candidate) {
	const key = [candidate.strategy, candidate.algorithm || "", candidate.inputName || "", candidate.secret?.id || ""].join("|");
	if (candidates.some((item) => item.key === key)) return;
	candidates.push({ ...candidate, key });
}

function buildCandidateCatalog(secrets) {
	const candidates = [];
	const inputNames = ["canonical-query", "sample-canonicalUnsigned", "canonical-query-stripped", "path-and-canonical", "method-path-canonical"];
	for (const inputName of inputNames) {
		for (const algorithm of ["md5", "sha1", "sha256"]) {
			pushCandidate(candidates, {
				strategy: "hash(input)",
				algorithm,
				inputName,
				predict: (sample) => hashHex(algorithm, inputValue(sample, inputName)),
			});
		}
		for (const secret of secrets) {
			for (const algorithm of ["md5", "sha1", "sha256"]) {
				pushCandidate(candidates, {
					strategy: "hash(input + secret)",
					algorithm,
					inputName,
					secret,
					predict: (sample) => hashHex(algorithm, inputValue(sample, inputName) + secret.value),
				});
				pushCandidate(candidates, {
					strategy: "hash(secret + input)",
					algorithm,
					inputName,
					secret,
					predict: (sample) => hashHex(algorithm, secret.value + inputValue(sample, inputName)),
				});
			}
			for (const algorithm of ["md5", "sha1", "sha256"]) {
				pushCandidate(candidates, {
					strategy: "hmac(input, secret)",
					algorithm,
					inputName,
					secret,
					predict: (sample) => hmacHex(algorithm, secret.value, inputValue(sample, inputName)),
				});
			}
		}
	}
	for (const secret of secrets) {
		pushCandidate(candidates, {
			strategy: "hash(canonical-stripped + secret32)",
			algorithm: "md5",
			inputName: "canonical-query-stripped",
			secret,
			predict: (sample) => md5Hex(canonicalQueryStripped(stableInputParams(sample)) + secret.value.slice(0, 32)),
		});
	}
	return candidates;
}

function compareCandidate(candidate, samples) {
	let matchedSamples = 0;
	const matchedSignatureParams = new Set();
	const matchedSampleHashes = [];
	for (const sample of samples) {
		let predicted;
		try {
			predicted = String(candidate.predict(sample));
		} catch {
			continue;
		}
		const signatureEntries = Object.entries(sample.signatureParams || {});
		if (!signatureEntries.length) continue;
		const matchedForSample = [];
		for (const [key, expected] of signatureEntries) {
			if (predicted === String(expected)) {
				matchedForSample.push(key);
				matchedSignatureParams.add(key);
			}
		}
		if (matchedForSample.length === signatureEntries.length) {
			matchedSamples += 1;
			matchedSampleHashes.push(sample.sampleHash);
		}
	}
	const sampleCount = samples.length;
	let verdict = "candidate_miss";
	if (sampleCount > 0 && matchedSamples === sampleCount) verdict = "candidate_match";
	else if (matchedSamples > 0) verdict = "partial_candidate_match";
	return {
		id: candidate.key,
		strategy: candidate.strategy,
		algorithm: candidate.algorithm || null,
		input: candidate.inputName || null,
		secretRef: secretRef(candidate.secret),
		matchedSamples,
		sampleCount,
		matchedSignatureParams: Array.from(matchedSignatureParams).sort(),
		matchedSampleHashes,
		verdict,
	};
}

export function runCandidateRegression(samples, options = {}) {
	const sourceSignals = Array.isArray(options.sourceSignals) ? options.sourceSignals : [];
	const providedSecrets = Array.isArray(options.candidateSecrets) ? options.candidateSecrets : null;
	const candidateSecrets = providedSecrets || extractCandidateSecrets(samples, sourceSignals);
	const candidates = buildCandidateCatalog(candidateSecrets);
	const results = candidates
		.map((candidate) => compareCandidate(candidate, samples))
		.sort((left, right) => right.matchedSamples - left.matchedSamples || String(left.strategy).localeCompare(String(right.strategy)))
		.slice(0, 50);
	return {
		candidateSecretRefs: candidateSecrets.map(secretRef),
		candidateStrategies: Array.from(new Set(candidates.map((candidate) => candidate.strategy))).sort(),
		totalCandidateCount: candidates.length,
		candidateResults: results,
		bestCandidate: results[0] || null,
	};
}

function buildReport({ capture, sourceMap, replay }) {
	const samples = extractSamples(capture);
	const sourceSignals = summarizeSourceSignals(sourceMap);
	const candidateRegression = runCandidateRegression(samples, { sourceSignals });
	return {
		kind: "repi-web-signer-rebuild-workbench",
		schemaVersion: 2,
		generatedAt: new Date().toISOString(),
		plan,
		sampleCount: samples.length,
		samples,
		sourceSignals,
		replay: summarizeReplay(replay),
		candidateSecretRefs: candidateRegression.candidateSecretRefs,
		candidateStrategies: candidateRegression.candidateStrategies,
		totalCandidateCount: candidateRegression.totalCandidateCount,
		candidateResults: candidateRegression.candidateResults,
		bestCandidate: candidateRegression.bestCandidate,
		regressionGates: [
			"runCandidateRegression(samples) should produce candidate_match or explain candidate_miss before live replay",
			"promote the best candidate_match into signParams(params, context)",
			"assertByteForByte(sample) must pass for every browser-captured sample",
			"only then run web-runtime-replay-verifier.mjs --live and require negative controls to fail",
		],
		pitfalls: [
			"canonical query order, URL encoding and stripped characters must match browser byte-for-byte",
			"timestamp/nonce parameters are sample inputs, not random values during regression",
			"public endpoints accepting unsigned/bad signatures are policy gaps, not signer proof",
			"candidate_match is an offline byte-for-byte signer hypothesis; live proof still requires negative controls",
		],
	};
}

function selfTestReport() {
	const params = { object_id: "demo", timestamp: "1782930000" };
	const signature = md5Hex(canonicalQuery(params) + "test-client-salt");
	return buildReport({
		capture: {
			browserEvents: [
				{
					kind: "browser-request",
					method: "GET",
					url: "https://example.test/api/signed/view?object_id=" + params.object_id + "&timestamp=" + params.timestamp + "&signature=" + signature,
				},
			],
			runtimeEvents: [],
		},
		sourceMap: {
			sourceMaps: [
				{
					signalLines: ["app.js.map::src/signer.ts:1: const clientSalt = 'test-client-salt'; function sign(params){ return md5(canonicalQuery(params)+clientSalt) }"],
				},
			],
		},
		replay: {
			liveReplay: false,
			candidateCount: 1,
			matrix: [],
			rows: [],
		},
	});
}

async function main() {
	if (selfTest) {
		console.log(JSON.stringify(selfTestReport(), null, 2));
		return;
	}
	const capture = await readJson(plan.captureFile);
	const sourceMap = await readJson(plan.sourceMapSummaryFile);
	const replay = await readJson(plan.replayResultsFile);
	const report = buildReport({ capture, sourceMap, replay });
	await writeFile(outPath, JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
	console.log(JSON.stringify({ kind: report.kind, sampleOutput: outPath, sampleCount: report.sampleCount, bestCandidate: report.bestCandidate?.verdict || null }, null, 2));
}

main().catch((error) => {
	console.error(error?.stack || error?.message || String(error));
	process.exit(1);
});
`;
}

export function webSignerRebuildWorkbenchRows(target, jsUrls, signalLines, replayHints, artifactDir, runtime) {
	const { redact, shellQuote, root, noWrite, writePrivate, jsSignatureEndpointCandidates } = runtime;
	const hasSignerLeads = Boolean(jsUrls.length || signalLines.some((line) => /sign|signature|crypto\.subtle|nonce|timestamp|canonical|permutation|salt|secret/i.test(line)) || replayHints.some((hint) => /[?&](?:signature|sign|sig|timestamp|ts|nonce)=/i.test(hint)));
	const plan = {
		kind: "repi-web-signer-rebuild-workbench-plan",
		schemaVersion: 1,
		target: redact(target),
		captureFile: join(artifactDir, "web-runtime-capture.json"),
		sourceMapSummaryFile: join(artifactDir, "web-js-sourcemap-summary.json"),
		replayResultsFile: join(artifactDir, "web-runtime-replay-results.json"),
		sampleOutput: join(artifactDir, "web-signer-rebuild-samples.json"),
		candidateEndpoints: jsSignatureEndpointCandidates(target, replayHints, signalLines),
		byteForByteRule: "rebuild signer until all browser-captured signature params match exactly for frozen timestamp/nonce samples",
		run: `node ${shellQuote(join(artifactDir, "web-signer-rebuild-workbench.mjs"))} ${shellQuote(join(artifactDir, "web-signer-rebuild-samples.json"))}`,
	};
	const workbench = webSignerRebuildWorkbenchSource(plan);
	const rows = [
		{
			id: "web-signer-rebuild-workbench-plan",
			command: "internal",
			args: [redact(target)],
			cwd: root,
			exit: hasSignerLeads ? 0 : 1,
			signal: null,
			durationMs: 0,
			stdout: `${JSON.stringify(plan, null, 2)}\n`,
			stderr: "",
			error: hasSignerLeads ? undefined : "signer workbench scaffolded but no signer leads were observed",
		},
		{
			id: "web-signer-rebuild-workbench",
			command: "internal",
			args: [redact(target)],
			cwd: root,
			exit: hasSignerLeads ? 0 : 1,
			signal: null,
			durationMs: 0,
			stdout: `features=assertByteForByte canonicalUnsigned runCandidateRegression candidateResults permutation-table regressionGates signer-workbench\n${workbench.slice(0, 60_000)}`,
			stderr: "",
			error: hasSignerLeads ? undefined : "signer workbench scaffolded but no signer leads were observed",
		},
	];
	if (!noWrite && artifactDir) {
		writePrivate(join(artifactDir, "web-signer-rebuild-workbench-plan.json"), `${JSON.stringify(plan, null, 2)}\n`, 0o600);
		writePrivate(join(artifactDir, "web-signer-rebuild-workbench.mjs"), workbench, 0o700);
	}
	return rows;
}

export function webAcceptedStatus(status) {
	return [200, 201, 202, 204, 206, 301, 302, 304].includes(Number(status));
}

export function webDeniedStatus(status) {
	return [401, 403, 404].includes(Number(status));
}

export function webClaimArtifacts(artifactDir, runtime) {
	const { readJsonArtifact } = runtime;
	const names = [
		"web-security-posture.json",
		"web-discovery-matrix.json",
		"web-api-schema-probes.json",
		"web-replay-matrix.json",
		"web-identity-jwt.json",
		"web-ssrf-matrix.json",
		"web-redirect-matrix.json",
		"web-cors-matrix.json",
		"web-object-matrix.json",
		"web-runtime-capture-plan.json",
		"web-runtime-replay-plan.json",
		"web-runtime-replay-results.json",
		"web-signer-rebuild-workbench-plan.json",
		"web-js-signature-control-plan.json",
		"web-js-sourcemap-summary.json",
	];
	return Object.fromEntries(names.map((name) => [name, readJsonArtifact(join(artifactDir, name))]));
}

export function webExploitClaims(target, artifactDir, runtime) {
	const { readJsonArtifact, shortHash, redact, shellQuote } = runtime;
	const artifacts = webClaimArtifacts(artifactDir, runtime);
	const replay = artifacts["web-replay-matrix.json"];
	const objectMatrix = artifacts["web-object-matrix.json"];
	const schema = artifacts["web-api-schema-probes.json"];
	const ssrf = artifacts["web-ssrf-matrix.json"];
	const redirect = artifacts["web-redirect-matrix.json"];
	const cors = artifacts["web-cors-matrix.json"];
	const identity = artifacts["web-identity-jwt.json"];
	const posture = artifacts["web-security-posture.json"];
	const sourceMap = artifacts["web-js-sourcemap-summary.json"];
	const runtimeCapturePlan = artifacts["web-runtime-capture-plan.json"];
	const runtimeReplayPlan = artifacts["web-runtime-replay-plan.json"];
	const runtimeReplayResults = artifacts["web-runtime-replay-results.json"];
	const signerPlan = artifacts["web-signer-rebuild-workbench-plan.json"];
	const signatureControlPlan = artifacts["web-js-signature-control-plan.json"];
	const artifactFiles = Object.entries(artifacts)
		.filter(([, value]) => Boolean(value))
		.map(([name]) => name);
	const claimLedger = [];
	const addClaim = (claim) => {
		if (!claim?.id || claimLedger.some((row) => row.id === claim.id)) return undefined;
		const normalized = {
			verdict: "promoted",
			confidence: 0.7,
			blockers: [],
			...claim,
		};
		claimLedger.push(normalized);
		return normalized;
	};
	const replayRows = replay?.rows ?? [];
	if (replayRows.length) {
		addClaim({
			id: "web-http-replay-evidence-" + shortHash(`${target}:${replayRows.map((row) => `${row.principal}:${row.status}:${row.responseSha256}`).join("|")}`),
			claimType: "web-http-replay-evidence",
			sourceBinding: { artifact: "web-replay-matrix.json", rowCount: replayRows.length },
			evidenceBinding: {
				count: replayRows.length,
				session: replay?.session ?? {},
				statuses: Array.from(new Set(replayRows.map((row) => row.status).filter((status) => status != null))).slice(0, 24),
				rows: replayRows.slice(0, 24).map((row) => ({
					id: row.id,
					principal: row.principal,
					url: row.url,
					status: row.status,
					bytes: row.bytes ?? null,
					responseSha256: row.responseSha256,
				})),
			},
			statement: "HTTP replay matrix binds routes to status/body hashes for anonymous and session principals.",
			confidence: replayRows.some((row) => webAcceptedStatus(row.status)) ? 0.8 : 0.66,
			rerunCommand: "cat web-replay-matrix.json",
		});
	}
	const replayByUrl = new Map();
	for (const row of replayRows) {
		const url = row.url || row.effectiveUrl || "";
		if (!url) continue;
		if (!replayByUrl.has(url)) replayByUrl.set(url, []);
		replayByUrl.get(url).push(row);
	}
	for (const [url, rows] of replayByUrl) {
		const anonymous = rows.find((row) => row.principal === "anonymous");
		const session = rows.find((row) => row.principal !== "anonymous");
		if (!anonymous || !session) continue;
		if (!webDeniedStatus(anonymous.status) || !webAcceptedStatus(session.status)) continue;
		addClaim({
			id: "web-session-auth-differential-" + shortHash(`${url}:${anonymous.status}:${session.status}:${session.responseSha256}`),
			claimType: "web-session-auth-differential",
			sourceBinding: { artifact: "web-replay-matrix.json", url },
			evidenceBinding: {
				url,
				anonymous: { status: anonymous.status, responseSha256: anonymous.responseSha256 },
				session: { principal: session.principal, status: session.status, responseSha256: session.responseSha256 },
				cookieNames: replay?.session?.cookieNames ?? [],
			},
			statement: "Replay evidence proves a route-level authorization differential between anonymous and session principals.",
			confidence: 0.86,
			rerunCommand: "cat web-replay-matrix.json | jq '.rows'",
		});
	}
	const objectClaims = [];
	for (const row of objectMatrix?.rows ?? []) {
		if (!row.bolaSignal) continue;
		const claim = addClaim({
			id: "web-object-authz-bola-" + shortHash(`${row.id}:${row.sourceUrl}:${row.variantUrl}:${row.variant?.responseSha256}`),
			claimType: "web-object-authz-bola-signal",
			sourceBinding: { artifact: "web-object-matrix.json", rowId: row.id },
			evidenceBinding: {
				principal: row.principal,
				reason: row.reason,
				sourceUrl: row.sourceUrl,
				variantUrl: row.variantUrl,
				source: { status: row.source?.status, responseSha256: row.source?.responseSha256 },
				variant: { status: row.variant?.status, responseSha256: row.variant?.responseSha256 },
				statusDelta: row.statusDelta,
				hashDelta: Boolean(row.hashDelta),
			},
			statement: "Object mutation matrix shows a session principal can access a mutated object identifier; requires ownership proof before final exploit claim.",
			confidence: 0.82,
			rerunCommand: "cat web-object-matrix.json | jq '.rows[] | select(.bolaSignal)'",
		});
		if (claim) objectClaims.push(claim);
	}
	for (const row of schema?.rows ?? []) {
		const risks = row.risks ?? row.openapi?.risks ?? [];
		for (const risk of risks) {
			if (!/graphql|openapi|upload|unauthenticated|write|admin|sensitive/i.test(risk)) continue;
			addClaim({
				id: "web-api-schema-risk-" + shortHash(`${row.kind}:${row.principal ?? ""}:${row.url}:${risk}`),
				claimType: risk,
				sourceBinding: { artifact: "web-api-schema-probes.json", kind: row.kind, url: row.url },
				evidenceBinding: {
					principal: row.principal ?? null,
					url: row.url,
					status: row.status,
					risk,
					introspection: row.introspection
						? {
								enabled: Boolean(row.introspection.enabled),
								queryType: row.introspection.queryType ?? null,
								mutationType: row.introspection.mutationType ?? null,
								queryFields: row.introspection.queryFields ?? [],
								mutationFields: row.introspection.mutationFields ?? [],
							}
						: null,
					openapi: row.openapi
						? {
								pathCount: row.openapi.pathCount,
								operationCount: row.openapi.operationCount,
								operationSamples: (row.openapi.operationSamples ?? []).slice(0, 20).map((operation) => ({
									path: operation.path,
									method: operation.method,
									operationId: operation.operationId,
									authRequired: operation.authRequired,
									risks: operation.risks ?? [],
								})),
							}
						: null,
				},
				statement: "API schema probe exposes a GraphQL/OpenAPI attack surface that can seed direct route replay and authz tests.",
				confidence: /unauthenticated|introspection-enabled|admin|upload/i.test(risk) ? 0.84 : 0.74,
				rerunCommand: "cat web-api-schema-probes.json | jq '.rows'",
			});
		}
	}
	for (const row of ssrf?.rows ?? []) {
		if (!(row.risks ?? []).length) continue;
		addClaim({
			id: "web-ssrf-probe-signal-" + shortHash(`${row.id}:${row.param}:${row.kind}:${row.variant?.responseSha256}`),
			claimType: row.canaryEvidence ? "web-ssrf-canary-evidence" : "web-ssrf-response-differential",
			sourceBinding: { artifact: "web-ssrf-matrix.json", rowId: row.id },
			evidenceBinding: {
				param: row.param,
				kind: row.kind,
				payloadHost: row.payloadHost,
				source: row.source,
				variant: { status: row.variant?.status, bytes: row.variant?.bytes, responseSha256: row.variant?.responseSha256 },
				statusDifferential: Boolean(row.statusDifferential),
				bodyDifferential: Boolean(row.bodyDifferential),
				canaryEvidence: Boolean(row.canaryEvidence),
				risks: row.risks ?? [],
			},
			statement: "SSRF probe matrix produced canary/body/status evidence for a URL-like parameter.",
			confidence: row.canaryEvidence ? 0.88 : 0.74,
			rerunCommand: "cat web-ssrf-matrix.json | jq '.rows[] | select(.risks|length>0)'",
		});
	}
	for (const row of redirect?.rows ?? []) {
		if (!(row.risks ?? []).length) continue;
		addClaim({
			id: "web-open-redirect-" + shortHash(`${row.param}:${row.mutatedUrl}:${row.location}`),
			claimType: row.canaryLocation ? "web-open-redirect-canary" : "web-external-redirect-signal",
			sourceBinding: { artifact: "web-redirect-matrix.json", rowId: row.id },
			evidenceBinding: {
				param: row.param,
				mutatedUrl: row.mutatedUrl,
				status: row.status,
				location: row.location,
				locationHost: row.locationHost,
				canaryLocation: Boolean(row.canaryLocation),
				risks: row.risks ?? [],
			},
			statement: "Redirect matrix evidence shows an externally controllable redirect location.",
			confidence: row.canaryLocation ? 0.88 : 0.76,
			rerunCommand: "cat web-redirect-matrix.json | jq '.rows[] | select(.risks|length>0)'",
		});
	}
	for (const row of cors?.rows ?? []) {
		if (!(row.risks ?? []).length) continue;
		addClaim({
			id: "web-cors-policy-gap-" + shortHash(`${row.url}:${row.origin}:${row.mode}:${(row.risks ?? []).join(",")}`),
			claimType: "web-cors-policy-gap",
			sourceBinding: { artifact: "web-cors-matrix.json", rowId: row.id },
			evidenceBinding: {
				url: row.url,
				origin: row.origin,
				mode: row.mode,
				status: row.status,
				allowOrigin: row.headers?.accessControlAllowOrigin ?? row.acao ?? null,
				allowCredentials: row.headers?.accessControlAllowCredentials ?? row.allowCredentials ?? null,
				risks: row.risks ?? [],
			},
			statement: "CORS matrix evidence identifies a cross-origin policy gap that needs browser credential proof before data-exfil claim.",
			confidence: 0.78,
			rerunCommand: "cat web-cors-matrix.json | jq '.rows[] | select(.risks|length>0)'",
		});
	}
	for (const risk of identity?.risks ?? []) {
		addClaim({
			id: "web-jwt-identity-risk-" + shortHash(`${risk}:${identity.jwtCount}:${JSON.stringify(identity.jwks ?? {})}`),
			claimType: risk,
			sourceBinding: { artifact: "web-identity-jwt.json", risk },
			evidenceBinding: {
				jwtCount: identity.jwtCount ?? 0,
				oidc: identity.oidc ?? null,
				jwks: identity.jwks ? { keyCount: identity.jwks.keyCount, keys: (identity.jwks.keys ?? []).slice(0, 12) } : null,
				risk,
			},
			statement: "JWT/OIDC identity evidence exposes token validation, key-discovery, or claim-policy risk.",
			confidence: 0.78,
			rerunCommand: "cat web-identity-jwt.json",
		});
	}
	if (posture?.risks?.length || posture?.cookies?.some((cookie) => cookie.risks?.length)) {
		addClaim({
			id: "web-security-posture-gap-" + shortHash(`${target}:${JSON.stringify(posture?.risks ?? [])}:${JSON.stringify(posture?.cookies ?? [])}`),
			claimType: "web-security-posture-gap",
			sourceBinding: { artifact: "web-security-posture.json" },
			evidenceBinding: {
				risks: posture?.risks ?? [],
				cookies: (posture?.cookies ?? []).slice(0, 20).map((cookie) => ({
					name: cookie.name,
					sessionLike: cookie.sessionLike,
					httpOnly: cookie.httpOnly,
					secure: cookie.secure,
					sameSite: cookie.sameSite,
					risks: cookie.risks ?? [],
				})),
				headers: posture?.headers ?? {},
			},
			statement: "HTTP header/cookie posture evidence identifies hardening gaps that should be tied to browser or session proof.",
			confidence: 0.7,
			rerunCommand: "cat web-security-posture.json",
		});
	}
	if (runtimeCapturePlan || runtimeReplayPlan || signerPlan || signatureControlPlan) {
		addClaim({
			id: "web-client-runtime-proof-harness-" + shortHash(`${target}:${artifactFiles.join(",")}`),
			claimType: "web-client-runtime-proof-harness",
			sourceBinding: {
				artifacts: [
					runtimeCapturePlan ? "web-runtime-capture-plan.json" : null,
					runtimeReplayPlan ? "web-runtime-replay-plan.json" : null,
					signerPlan ? "web-signer-rebuild-workbench-plan.json" : null,
					signatureControlPlan ? "web-js-signature-control-plan.json" : null,
				].filter(Boolean),
			},
			evidenceBinding: {
				captureHooks: runtimeCapturePlan?.hooks ?? [],
				replayNegativeControls: runtimeReplayPlan?.negativeControls ?? [],
				liveReplayProofReady: Boolean(runtimeReplayResults?.liveReplay && runtimeReplayResults?.promotionReport?.proofReady),
				byteForByteRule: signerPlan?.byteForByteRule ?? null,
				signatureControlRule: signatureControlPlan?.requiredControls ?? signatureControlPlan?.proofRule ?? null,
				sourceMapSignals: (sourceMap?.sourceMaps ?? []).reduce((count, item) => count + (item.signalLines?.length ?? 0), 0),
			},
			statement: "Client runtime capture, replay negative controls, and signer workbench artifacts are ready for browser-grounded proof.",
			confidence: runtimeCapturePlan && runtimeReplayPlan ? 0.78 : 0.68,
			rerunCommand: "node web-runtime-replay-verifier.mjs web-runtime-capture.json web-runtime-replay-results.json --live",
		});
	}
	const promotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted");
	const authDifferentialClaim = promotedClaims.find((claim) => claim.claimType === "web-session-auth-differential");
	const objectClaim = objectClaims[0];
	const runtimeClaim = promotedClaims.find((claim) => claim.claimType === "web-client-runtime-proof-harness");
	const signerOrSchemaClaim = promotedClaims.find((claim) => /signature|signer|graphql|openapi|unauthenticated|web-api-schema/i.test(claim.claimType));
	const highImpactClaim = promotedClaims.find((claim) => /ssrf|redirect|cors|jwt|object-authz/.test(claim.claimType));
	const liveRuntimeProofReady = Boolean(runtimeReplayResults?.liveReplay && runtimeReplayResults?.promotionReport?.proofReady);
	const composedPaths = [];
	if (authDifferentialClaim && objectClaim) {
		const segments = [authDifferentialClaim, objectClaim];
		composedPaths.push({
			id: "web-authz-object-proof-path-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "web-authz-object-proof-path",
			sourceBinding: { target: redact(target), segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType })) },
			evidenceBinding: {
				hasSessionDifferential: true,
				hasObjectMutationSignal: true,
				replayArtifacts: ["web-replay-matrix.json", "web-object-matrix.json"],
			},
			statement: "Web evidence composes session authorization differential and object mutation replay into an IDOR/BOLA proof path.",
			verdict: "promoted",
			confidence: 0.88,
			blockers: ["Need target-specific ownership assertion before reporting business-impact BOLA."],
			rerunCommand: "cat web-replay-matrix.json web-object-matrix.json",
		});
	}
	if (runtimeClaim && signerOrSchemaClaim) {
		const segments = [runtimeClaim, signerOrSchemaClaim];
		const runtimePathBlockers = liveRuntimeProofReady ? [] : ["missing-web-live-runtime-replay-proof", "missing-web-runtime-negative-control"];
		composedPaths.push({
			id: (liveRuntimeProofReady ? "web-client-signer-proof-path-" : "web-client-signer-blocked-path-") + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: liveRuntimeProofReady ? "web-client-signer-proof-path" : "web-client-signer-blocked-path",
			sourceBinding: { target: redact(target), segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType })) },
			evidenceBinding: {
				hasRuntimeHarness: true,
				hasSignerOrSchemaLead: true,
				liveRuntimeProofReady,
				runtimeReplayResults: runtimeReplayResults ? "web-runtime-replay-results.json" : null,
				negativeControls: runtimeReplayPlan?.negativeControls ?? [],
				candidateEndpoints: runtimeReplayPlan?.candidateEndpoints ?? signatureControlPlan?.candidateEndpoints ?? [],
			},
			statement: liveRuntimeProofReady
				? "Web evidence composes browser runtime capture/replay harnesses with signer/schema leads and live negative-control proof."
				: "Web verifier keeps signer/schema proof blocked until live browser replay or byte-for-byte signer controls provide response hashes.",
			verdict: liveRuntimeProofReady ? "promoted" : "blocked",
			confidence: liveRuntimeProofReady ? 0.84 : 0.52,
			blockers: runtimePathBlockers,
			rerunCommand: "node web-runtime-capture-harness.mjs <target-url> web-runtime-capture.json && node web-runtime-replay-verifier.mjs web-runtime-capture.json web-runtime-replay-results.json --live",
		});
	}
	if (authDifferentialClaim && highImpactClaim && highImpactClaim !== objectClaim) {
		const segments = [authDifferentialClaim, highImpactClaim];
		composedPaths.push({
			id: "web-route-impact-proof-path-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "web-route-impact-proof-path",
			sourceBinding: { target: redact(target), segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType })) },
			evidenceBinding: {
				hasSessionDifferential: true,
				impactClaimType: highImpactClaim.claimType,
				artifactFiles,
			},
			statement: "Web evidence composes authenticated route reachability with a high-impact API/browser policy signal.",
			verdict: "promoted",
			confidence: 0.8,
			blockers: highImpactClaim.blockers ?? [],
			rerunCommand: "cat web-exploit-claims.json | jq '.composedPaths'",
		});
	}
	for (const path of composedPaths) claimLedger.push(path);
	const finalPromotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted");
	const blockers = [];
	if (!replay) blockers.push("missing-http-replay-matrix");
	if (!schema && !objectMatrix && !ssrf && !redirect && !cors) blockers.push("missing-route-risk-matrix");
	if (!authDifferentialClaim) blockers.push("missing-auth-differential");
	if (!objectClaims.length) blockers.push("missing-object-mutation-signal");
	if (!runtimeCapturePlan) blockers.push("missing-browser-runtime-capture");
	if (!runtimeReplayPlan) blockers.push("missing-runtime-negative-controls");
	if (runtimeReplayPlan && !liveRuntimeProofReady) blockers.push("missing-web-live-runtime-replay-proof", "missing-web-runtime-negative-control");
	if (!signerPlan && !signatureControlPlan) blockers.push("missing-signer-or-signature-control-workbench");
	const repairActions = {
		"missing-http-replay-matrix": "Run web replay matrix with anonymous/session principals and bind status/body hashes to each route.",
		"missing-route-risk-matrix": "Collect API schema, object mutation, SSRF, redirect, or CORS matrix evidence before impact ranking.",
		"missing-auth-differential": "Capture a route where anonymous is denied and a session principal is accepted.",
		"missing-object-mutation-signal": "Mutate numeric/UUID object IDs and replay with anonymous/session controls to test BOLA.",
		"missing-browser-runtime-capture": "Run web-runtime-capture-harness.mjs in a browser to bind JS/XHR/WS/signature order.",
		"missing-runtime-negative-controls": "Run web-runtime-replay-verifier.mjs with captured requests and require missing/tampered controls to fail.",
		"missing-web-live-runtime-replay-proof": "Run web-runtime-capture-harness.mjs and web-runtime-replay-verifier.mjs --live to bind captured-signed and tampered controls to response hashes.",
		"missing-web-runtime-negative-control": "Keep signer/schema proof blocked until captured-signed succeeds while missing/tampered signature controls fail.",
		"missing-signer-or-signature-control-workbench": "Use source maps/signature hints to build byte-for-byte signer regression or JS signature controls.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "web-exploit-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect web/API evidence and rerun exploit claim promotion.",
		rerunCommand: `repi engage ${shellQuote(target)} --json`,
	}));
	return {
		kind: "repi-web-exploit-claims",
		schemaVersion: 1,
		target: redact(target),
		generatedAt: new Date().toISOString(),
		artifactFiles,
		proofReady: finalPromotedClaims.length > 0,
		exploitProofReady: composedPaths.some((path) => path.verdict === "promoted"),
		claimLedger,
		composedPaths,
		promotionReport: {
			proofReady: finalPromotedClaims.length > 0,
			exploitProofReady: composedPaths.some((path) => path.verdict === "promoted"),
			promotedClaims: finalPromotedClaims,
			blockers,
		},
		repairQueue,
	};
}

export function writeWebExploitClaims(target, artifactDir, runtime) {
	const { noWrite, writePrivate } = runtime;
	if (noWrite || !artifactDir) return undefined;
	const summary = webExploitClaims(target, artifactDir, runtime);
	const path = join(artifactDir, "web-exploit-claims.json");
	writePrivate(path, `${JSON.stringify(summary, null, 2)}\n`, 0o600);
	return { path, summary };
}

const webExploitVerificationArtifactNames = [
	"web-exploit-claims.json",
	"web-replay-matrix.json",
	"web-api-schema-probes.json",
	"web-object-matrix.json",
	"web-ssrf-matrix.json",
	"web-redirect-matrix.json",
	"web-cors-matrix.json",
	"web-identity-jwt.json",
	"web-security-posture.json",
	"web-js-sourcemap-summary.json",
	"web-runtime-capture-plan.json",
	"web-runtime-replay-plan.json",
	"web-runtime-replay-results.json",
	"web-signer-rebuild-workbench-plan.json",
	"web-js-signature-control-plan.json",
	"web-exploit-verifier.mjs",
];

export function webArtifactHashCheck(artifactDir, relPath, runtime) {
	const { bufferSha256, redact } = runtime;
	const path = join(artifactDir, relPath);
	if (!existsSync(path)) return { relPath, exists: false, size: 0, sha256: null, mode: null };
	try {
		const data = readFileSync(path);
		const stat = statSync(path);
		return {
			relPath,
			exists: true,
			size: data.length,
			sha256: bufferSha256(data),
			mode: stat.mode & 0o777,
		};
	} catch (error) {
		return { relPath, exists: false, size: 0, sha256: null, mode: null, error: error instanceof Error ? redact(error.message) : "read-failed" };
	}
}

function webReplayRowHasStatusAndHash(row) {
	return Number.isFinite(Number(row?.status)) && /^[a-f0-9]{64}$/i.test(String(row?.responseSha256 ?? ""));
}

export function webRuntimeLiveProofRows(runtimeReplayResults) {
	const rows = Array.isArray(runtimeReplayResults?.rows) ? runtimeReplayResults.rows : [];
	return rows.filter((row) => {
		if (row?.promotion?.verdict === "promoted") return true;
		if (row?.verdict === "signer_proven_negative_controls") return true;
		const variants = Array.isArray(row?.variants) ? row.variants : [];
		return variants.some((variant) => Number.isFinite(Number(variant?.status)) && /^[a-f0-9]{64}$/i.test(String(variant?.responseSha256 ?? "")));
	});
}

export function webExploitVerificationSummary(target, artifactDir, claimsSummary, runtime) {
	const { readJsonArtifact, bufferSha256, httpSecretHash, shortHash, redact, shellQuote } = runtime;
	const claims = claimsSummary ?? readJsonArtifact(join(artifactDir, "web-exploit-claims.json"));
	const replay = readJsonArtifact(join(artifactDir, "web-replay-matrix.json"));
	const schema = readJsonArtifact(join(artifactDir, "web-api-schema-probes.json"));
	const objectMatrix = readJsonArtifact(join(artifactDir, "web-object-matrix.json"));
	const ssrf = readJsonArtifact(join(artifactDir, "web-ssrf-matrix.json"));
	const redirect = readJsonArtifact(join(artifactDir, "web-redirect-matrix.json"));
	const cors = readJsonArtifact(join(artifactDir, "web-cors-matrix.json"));
	const identity = readJsonArtifact(join(artifactDir, "web-identity-jwt.json"));
	const posture = readJsonArtifact(join(artifactDir, "web-security-posture.json"));
	const sourceMap = readJsonArtifact(join(artifactDir, "web-js-sourcemap-summary.json"));
	const runtimeCapturePlan = readJsonArtifact(join(artifactDir, "web-runtime-capture-plan.json"));
	const runtimeReplayPlan = readJsonArtifact(join(artifactDir, "web-runtime-replay-plan.json"));
	const runtimeReplayResults = readJsonArtifact(join(artifactDir, "web-runtime-replay-results.json"));
	const signerPlan = readJsonArtifact(join(artifactDir, "web-signer-rebuild-workbench-plan.json"));
	const signatureControlPlan = readJsonArtifact(join(artifactDir, "web-js-signature-control-plan.json"));
	const artifactChecks = webExploitVerificationArtifactNames.map((relPath) =>
		webArtifactHashCheck(artifactDir, relPath, { bufferSha256, redact }),
	);
	const presentArtifacts = artifactChecks.filter((row) => row.exists);
	const requiredArtifacts = ["web-exploit-claims.json", "web-replay-matrix.json", "web-exploit-verifier.mjs"];
	const artifactHashVerification = {
		verified: requiredArtifacts.every((relPath) => artifactChecks.some((row) => row.relPath === relPath && row.exists && row.size > 0 && /^[a-f0-9]{64}$/i.test(String(row.sha256 ?? "")))),
		requiredArtifacts,
		presentCount: presentArtifacts.length,
		artifactChecks,
	};
	const replayRows = Array.isArray(replay?.rows) ? replay.rows : [];
	const replayRowChecks = replayRows.map((row) => ({
		id: row?.id ?? null,
		principal: row?.principal ?? null,
		url: row?.url ?? null,
		status: row?.status ?? null,
		responseSha256: row?.responseSha256 ?? null,
		verified: webReplayRowHasStatusAndHash(row),
	}));
	const replayHashVerification = {
		verified: replayRowChecks.length > 0 && replayRowChecks.every((row) => row.verified),
		rowCount: replayRowChecks.length,
		verifiedRows: replayRowChecks.filter((row) => row.verified).length,
		statuses: Array.from(new Set(replayRowChecks.map((row) => row.status).filter((status) => status != null))).slice(0, 24),
		principals: Array.from(new Set(replayRowChecks.map((row) => row.principal).filter(Boolean))).slice(0, 24),
		replaySha256: replay ? httpSecretHash(JSON.stringify(replay)) : null,
		rowChecks: replayRowChecks.slice(0, 80),
	};
	const riskCategories = [];
	if (replayHashVerification.verified) riskCategories.push("replay");
	if ((schema?.rows ?? []).some((row) => (row.risks ?? []).length || (row.openapi?.risks ?? []).length || row.introspection?.enabled)) riskCategories.push("schema");
	if ((objectMatrix?.rows ?? []).some((row) => row.bolaSignal || row.hashDelta || row.statusDelta)) riskCategories.push("object");
	if ((ssrf?.rows ?? []).some((row) => (row.risks ?? []).length)) riskCategories.push("ssrf");
	if ((redirect?.rows ?? []).some((row) => (row.risks ?? []).length)) riskCategories.push("redirect");
	if ((cors?.rows ?? []).some((row) => (row.risks ?? []).length)) riskCategories.push("cors");
	if ((identity?.risks ?? []).length || Number(identity?.jwtCount ?? 0) > 0) riskCategories.push("jwt");
	if ((posture?.risks ?? []).length || (posture?.cookies ?? []).some((cookie) => (cookie.risks ?? []).length)) riskCategories.push("posture");
	if (runtimeCapturePlan || runtimeReplayPlan || signerPlan || signatureControlPlan || (sourceMap?.sourceMaps ?? []).length) riskCategories.push("runtime-harness");
	const riskMatrixCoverage = {
		verified: riskCategories.includes("replay") && riskCategories.some((category) => category !== "replay"),
		categories: Array.from(new Set(riskCategories)),
		matrixArtifacts: [
			schema ? "web-api-schema-probes.json" : null,
			objectMatrix ? "web-object-matrix.json" : null,
			ssrf ? "web-ssrf-matrix.json" : null,
			redirect ? "web-redirect-matrix.json" : null,
			cors ? "web-cors-matrix.json" : null,
			identity ? "web-identity-jwt.json" : null,
			posture ? "web-security-posture.json" : null,
			runtimeCapturePlan || runtimeReplayPlan ? "web-runtime-*.json" : null,
		].filter(Boolean),
	};
	const claimRows = Array.isArray(claims?.claimLedger) ? claims.claimLedger : [];
	const composedPathRows = Array.isArray(claims?.composedPaths) ? claims.composedPaths : [];
	const claimById = new Map(claimRows.filter((claim) => claim?.id).map((claim) => [claim.id, claim]));
	const runtimePaths = composedPathRows.filter((path) => /web-client-signer-(?:proof|blocked)-path/.test(String(path?.claimType ?? "")));
	const liveProofRows = webRuntimeLiveProofRows(runtimeReplayResults);
	const runtimeProofReady = Boolean(runtimeReplayResults?.liveReplay && runtimeReplayResults?.promotionReport?.proofReady && liveProofRows.length);
	const promotedRuntimePathsWithoutProof = runtimePaths.filter((path) => path?.verdict === "promoted" && !runtimeProofReady);
	const derivedRuntimeBlockers = runtimeProofReady ? [] : ["missing-web-live-runtime-replay-proof", "missing-web-runtime-negative-control"];
	const runtimeNegativeControlVerification = {
		verified: runtimeProofReady || (Boolean(runtimeReplayPlan || runtimeCapturePlan || runtimePaths.length) && promotedRuntimePathsWithoutProof.length === 0),
		runtimeProofReady,
		liveReplay: Boolean(runtimeReplayResults?.liveReplay),
		liveRuntimeProofs: liveProofRows.length,
		promotedRuntimePathsWithoutProof: promotedRuntimePathsWithoutProof.map((path) => path.id),
		negativeControls: runtimeReplayPlan?.negativeControls ?? [],
		blockers: derivedRuntimeBlockers,
		resultsSha256: runtimeReplayResults ? httpSecretHash(JSON.stringify(runtimeReplayResults)) : null,
	};
	const pathChecks = composedPathRows.map((pathRow) => {
		const segments = pathRow?.sourceBinding?.segments ?? [];
		const resolvedSegments = segments.map((segment) => {
			const claim = claimById.get(segment?.id);
			return {
				id: segment?.id ?? null,
				claimType: segment?.claimType ?? null,
				claimPresent: Boolean(claim),
				claimPromoted: claim?.verdict === "promoted",
			};
		});
		return {
			id: pathRow?.id ?? null,
			claimType: pathRow?.claimType ?? null,
			verdict: pathRow?.verdict ?? null,
			verified: resolvedSegments.length > 0 && resolvedSegments.every((segment) => segment.claimPresent && segment.claimPromoted),
			segments: resolvedSegments,
		};
	});
	const composedPathVerification = {
		verified: pathChecks.length > 0 && pathChecks.every((row) => row.verified),
		pathCount: pathChecks.length,
		verifiedPathCount: pathChecks.filter((row) => row.verified).length,
		promotedPathCount: pathChecks.filter((row) => row.verified && row.verdict === "promoted").length,
		pathChecks,
	};
	const firstPresentArtifact = presentArtifacts[0];
	const firstRequiredArtifact = requiredArtifacts
		.map((relPath) => artifactChecks.find((row) => row.relPath === relPath && row.exists))
		.find(Boolean);
	const firstReplayRow = replayRows.find((row) => webReplayRowHasStatusAndHash(row));
	const firstSegment = pathChecks.flatMap((row) => row.segments).find((segment) => segment.id);
	const firstVerifiedPath = pathChecks.find((row) => row.verified);
	const runtimeGateAccepts = ({ proofReady, hasInputs, promotedWithoutProof }) =>
		Boolean(proofReady || (hasInputs && promotedWithoutProof === 0));
	const runtimeGateOriginalAccepted = runtimeGateAccepts({
		proofReady: runtimeProofReady,
		hasInputs: Boolean(runtimeReplayPlan || runtimeCapturePlan || runtimePaths.length),
		promotedWithoutProof: promotedRuntimePathsWithoutProof.length,
	});
	const runtimeGateMutatedAccepted = runtimeGateAccepts({
		proofReady: false,
		hasInputs: true,
		promotedWithoutProof: Math.max(1, promotedRuntimePathsWithoutProof.length),
	});
	const mutatedArtifactChecks = firstRequiredArtifact
		? artifactChecks.map((row) =>
				row.relPath === firstRequiredArtifact.relPath ? { ...row, exists: false, size: 0, sha256: null } : row,
			)
		: [];
	const mutatedArtifactGateAccepted =
		mutatedArtifactChecks.length > 0 &&
		requiredArtifacts.every((relPath) =>
			mutatedArtifactChecks.some(
				(row) => row.relPath === relPath && row.exists && row.size > 0 && /^[a-f0-9]{64}$/i.test(String(row.sha256 ?? "")),
			),
		);
	const mutatedPathSegments = firstVerifiedPath
		? firstVerifiedPath.segments.map((segment, index) =>
				index === 0 ? { ...segment, id: `${segment.id}:negative-control-mutation` } : segment,
			)
		: [];
	const mutatedPathAccepted =
		mutatedPathSegments.length > 0 &&
		mutatedPathSegments.every((segment) => claimById.has(segment.id) && claimById.get(segment.id)?.verdict === "promoted");
	const negativeControls = [
		{
			controlType: "web-missing-artifact-negative-control",
			artifact: firstRequiredArtifact?.relPath ?? firstPresentArtifact?.relPath ?? null,
			mutatedArtifactGateAccepted,
			passed: Boolean(firstRequiredArtifact && artifactHashVerification.verified && !mutatedArtifactGateAccepted),
		},
		{
			controlType: "web-missing-replay-hash-negative-control",
			rowId: firstReplayRow?.id ?? null,
			passed: Boolean(firstReplayRow && !webReplayRowHasStatusAndHash({ ...firstReplayRow, responseSha256: "" })),
		},
		{
			controlType: "web-mutated-composed-segment-negative-control",
			segmentId: firstSegment?.id ?? null,
			mutatedPathAccepted,
			passed: Boolean(firstSegment?.id && firstVerifiedPath?.verified && !mutatedPathAccepted),
		},
		{
			controlType: "web-runtime-proof-gate-negative-control",
			mutatedRuntimeGateAccepted: runtimeGateMutatedAccepted,
			passed: Boolean(runtimeGateOriginalAccepted && !runtimeGateMutatedAccepted),
		},
	];
	const negativeControlVerification = {
		verified: negativeControls.length >= 4 && negativeControls.every((row) => row.passed),
		negativeControlsPassed: negativeControls.filter((row) => row.passed).length,
		negativeControls,
	};
	const claimLedger = [];
	const composedPaths = [];
	const addClaim = (claim) => {
		const normalized = { verdict: "promoted", confidence: 0.78, blockers: [], ...claim };
		claimLedger.push(normalized);
		return normalized;
	};
	const artifactClaim = artifactHashVerification.verified
		? addClaim({
				id: "web-artifact-hash-verification-" + shortHash(presentArtifacts.map((row) => `${row.relPath}:${row.sha256}`).join("|")),
				claimType: "web-artifact-hash-verification-proof",
				sourceBinding: { artifact: "web-exploit-verification.json", artifacts: presentArtifacts.map((row) => row.relPath) },
				evidenceBinding: artifactHashVerification,
				statement: "Web verifier rebound exploit, replay, and harness artifacts to exact size/SHA-256 evidence.",
				confidence: 0.86,
				rerunCommand: "node web-exploit-verifier.mjs <artifact-dir> web-exploit-verification.json",
			})
		: undefined;
	const replayClaim = replayHashVerification.verified
		? addClaim({
				id: "web-replay-hash-verification-" + shortHash(JSON.stringify(replayHashVerification.statuses)),
				claimType: "web-replay-hash-verification-proof",
				sourceBinding: { artifact: "web-exploit-verification.json", replay: "web-replay-matrix.json" },
				evidenceBinding: replayHashVerification,
				statement: "Web verifier confirmed every replay row has an HTTP status and 64-hex response hash.",
				confidence: 0.84,
				rerunCommand: "node web-exploit-verifier.mjs <artifact-dir> web-exploit-verification.json",
			})
		: undefined;
	const riskClaim = riskMatrixCoverage.verified
		? addClaim({
				id: "web-risk-matrix-coverage-" + shortHash(riskMatrixCoverage.categories.join("|")),
				claimType: "web-risk-matrix-coverage-proof",
				sourceBinding: { artifact: "web-exploit-verification.json", replay: "web-replay-matrix.json", matrices: riskMatrixCoverage.matrixArtifacts },
				evidenceBinding: riskMatrixCoverage,
				statement: "Web verifier confirmed replay evidence is paired with schema/object/browser/policy risk-matrix coverage.",
				confidence: 0.82,
				rerunCommand: "node web-exploit-verifier.mjs <artifact-dir> web-exploit-verification.json",
			})
		: undefined;
	const runtimeGateClaim = runtimeNegativeControlVerification.verified
		? addClaim({
				id: "web-runtime-negative-control-" + shortHash(JSON.stringify(runtimeNegativeControlVerification.blockers)),
				claimType: "web-runtime-negative-control-proof",
				sourceBinding: { artifact: "web-exploit-verification.json", runtimePlan: "web-runtime-replay-plan.json", runtimeResults: runtimeReplayResults ? "web-runtime-replay-results.json" : null },
				evidenceBinding: runtimeNegativeControlVerification,
				statement: runtimeProofReady ? "Web verifier confirmed live browser runtime negative-control replay proof." : "Web verifier kept runtime signer proof blocked until live captured-signed/missing/tampered controls provide response hashes.",
				confidence: runtimeProofReady ? 0.86 : 0.74,
				rerunCommand: runtimeReplayPlan?.run ?? "node web-runtime-replay-verifier.mjs web-runtime-capture.json web-runtime-replay-results.json --live",
			})
		: undefined;
	const pathClaim = composedPathVerification.verified
		? addClaim({
				id: "web-composed-path-verification-" + shortHash(JSON.stringify(pathChecks.map((row) => row.id))),
				claimType: "web-composed-path-verification-proof",
				sourceBinding: { artifact: "web-exploit-verification.json", claims: "web-exploit-claims.json" },
				evidenceBinding: composedPathVerification,
				statement: "Web verifier confirmed every composed-path segment resolves to a promoted exploit claim.",
				confidence: 0.84,
				rerunCommand: "node web-exploit-verifier.mjs <artifact-dir> web-exploit-verification.json",
			})
		: undefined;
	const negativeClaim = negativeControlVerification.verified
		? addClaim({
				id: "web-exploit-verifier-negative-control-" + shortHash(JSON.stringify(negativeControls)),
				claimType: "web-exploit-verifier-negative-control-proof",
				sourceBinding: { artifact: "web-exploit-verification.json" },
				evidenceBinding: negativeControlVerification,
				statement: "Web verifier rejected missing-artifact, missing-replay-hash, mutated-segment, and runtime proof-gate controls.",
				confidence: 0.84,
				rerunCommand: "node web-exploit-verifier.mjs <artifact-dir> web-exploit-verification.json",
			})
		: undefined;
	const sourceExploitReady = Boolean(claims?.exploitProofReady || runtimeProofReady);
	if (artifactClaim && replayClaim && riskClaim && runtimeGateClaim && pathClaim && negativeClaim) {
		const segments = [artifactClaim, replayClaim, riskClaim, runtimeGateClaim, pathClaim, negativeClaim];
		const composed = {
			id: (sourceExploitReady ? "web-exploit-verification-proof-path-" : "web-exploit-verification-blocked-path-") + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: sourceExploitReady ? "web-exploit-verification-proof-path" : "web-exploit-verification-blocked-path",
			sourceBinding: { segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType, artifact: claim.sourceBinding?.artifact })) },
			evidenceBinding: {
				presentArtifacts: artifactHashVerification.presentCount,
				replayRows: replayHashVerification.verifiedRows,
				riskCategories: riskMatrixCoverage.categories,
				liveRuntimeProofs: runtimeNegativeControlVerification.liveRuntimeProofs,
				verifiedPathCount: composedPathVerification.verifiedPathCount,
				negativeControlsPassed: negativeControlVerification.negativeControlsPassed,
			},
			statement: sourceExploitReady
				? "Web exploit proof path composes artifact hashes, replay body hashes, risk matrices, composed-path resolution, and verifier negative controls."
				: "Web verifier blocks final exploit promotion until live runtime proof or a promoted route/object impact path is present.",
			verdict: sourceExploitReady ? "promoted" : "blocked",
			confidence: sourceExploitReady ? 0.88 : 0.56,
			blockers: sourceExploitReady ? [] : derivedRuntimeBlockers,
			rerunCommand: "node web-exploit-verifier.mjs <artifact-dir> web-exploit-verification.json",
		};
		claimLedger.push(composed);
		composedPaths.push(composed);
	}
	const blockers = [];
	if (!artifactHashVerification.verified) blockers.push("missing-web-artifact-hash-verification");
	if (!replayHashVerification.verified) blockers.push("missing-web-replay-hash-verification");
	if (!riskMatrixCoverage.verified) blockers.push("missing-web-risk-matrix-coverage");
	if (!runtimeProofReady) blockers.push("missing-web-live-runtime-replay-proof");
	if (!runtimeNegativeControlVerification.verified || !runtimeProofReady) blockers.push("missing-web-runtime-negative-control");
	if (!composedPathVerification.verified) blockers.push("missing-web-composed-path-verification");
	if (!negativeControlVerification.verified) blockers.push("missing-web-verifier-negative-control");
	const repairActions = {
		"missing-web-artifact-hash-verification": "Rerun web-exploit-verifier.mjs after generating web-exploit-claims.json, web-replay-matrix.json, and web-exploit-verifier.mjs.",
		"missing-web-replay-hash-verification": "Regenerate web-replay-matrix.json until every replay row has status plus responseSha256.",
		"missing-web-risk-matrix-coverage": "Collect schema/object/SSRF/redirect/CORS/JWT/posture/runtime matrix evidence before promotion.",
		"missing-web-live-runtime-replay-proof": "Run web-runtime-capture-harness.mjs and web-runtime-replay-verifier.mjs --live against captured browser traffic.",
		"missing-web-runtime-negative-control": "Keep signer/schema proof blocked until captured-signed succeeds while missing/tampered signature controls fail.",
		"missing-web-composed-path-verification": "Resolve every composed-path segment ID to a promoted claim in web-exploit-claims.json.",
		"missing-web-verifier-negative-control": "Run missing-artifact, missing-replay-hash, mutated-segment, and runtime-gate negative controls.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "web-exploit-verification-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect verifier-bound web evidence and rerun web-exploit-verifier.mjs.",
		rerunCommand: blocker === "missing-web-live-runtime-replay-proof" ? runtimeReplayPlan?.run ?? `node ${shellQuote(join(artifactDir, "web-runtime-replay-verifier.mjs"))} ${shellQuote(join(artifactDir, "web-runtime-capture.json"))} ${shellQuote(join(artifactDir, "web-runtime-replay-results.json"))} --live` : `node ${shellQuote(join(artifactDir, "web-exploit-verifier.mjs"))} ${shellQuote(artifactDir)} ${shellQuote(join(artifactDir, "web-exploit-verification.json"))}`,
	}));
	const proofReady = Boolean(artifactClaim && replayClaim && riskClaim && runtimeGateClaim && pathClaim && negativeClaim);
	const promotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted");
	const promotedPaths = composedPaths.filter((path) => path.verdict === "promoted");
	return {
		kind: "repi-web-exploit-verification",
		schemaVersion: 1,
		target: redact(target),
		generatedAt: new Date().toISOString(),
		proofReady,
		runtimeProofReady,
		exploitProofReady: promotedPaths.length > 0,
		artifactHashVerification,
		replayHashVerification,
		riskMatrixCoverage,
		runtimeNegativeControlVerification,
		composedPathVerification,
		negativeControlVerification,
		stats: {
			presentArtifacts: artifactHashVerification.presentCount,
			replayRows: replayHashVerification.rowCount,
			verifiedReplayRows: replayHashVerification.verifiedRows,
			riskCategories: riskMatrixCoverage.categories.length,
			liveRuntimeProofs: runtimeNegativeControlVerification.liveRuntimeProofs,
			verifiedPathCount: composedPathVerification.verifiedPathCount,
			negativeControlsPassed: negativeControlVerification.negativeControlsPassed,
		},
		claimLedger,
		composedPaths,
		promotionReport: { proofReady, runtimeProofReady, exploitProofReady: promotedPaths.length > 0, promotedClaims, composedPaths: promotedPaths, blockers },
		repairQueue,
	};
}

export function webExploitVerifierSource() {
	return String.raw`#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const selfTestMode = process.argv.includes("--self-test");

function sha256(value) {
	return createHash("sha256").update(value ?? "").digest("hex");
}

function sha256Text(value) {
	return createHash("sha256").update(String(value ?? ""), "utf8").digest("hex");
}

function short(value) {
	return sha256Text(value).slice(0, 16);
}

function load(path, fallback = null) {
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch {
		return fallback;
	}
}

function writeJson(path, value) {
	writeFileSync(path, JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
}

function artifactCheck(dir, relPath) {
	const path = join(dir, relPath);
	if (!existsSync(path)) return { relPath, exists: false, size: 0, sha256: null, mode: null };
	const data = readFileSync(path);
	const stat = statSync(path);
	return { relPath, exists: true, size: data.length, sha256: sha256(data), mode: stat.mode & 0o777 };
}

function replayRowValid(row) {
	return Number.isFinite(Number(row && row.status)) && /^[a-f0-9]{64}$/i.test(String((row && row.responseSha256) || ""));
}

function liveRows(results) {
	const rows = Array.isArray(results && results.rows) ? results.rows : [];
	return rows.filter((row) => {
		if (row && row.promotion && row.promotion.verdict === "promoted") return true;
		if (row && row.verdict === "signer_proven_negative_controls") return true;
		const variants = Array.isArray(row && row.variants) ? row.variants : [];
		return variants.some((variant) => Number.isFinite(Number(variant && variant.status)) && /^[a-f0-9]{64}$/i.test(String((variant && variant.responseSha256) || "")));
	});
}

function addClaim(rows, claim) {
	const row = Object.assign({ verdict: "promoted", confidence: 0.78, blockers: [] }, claim);
	rows.push(row);
	return row;
}

function verify(dir) {
	const names = [
		"web-exploit-claims.json",
		"web-replay-matrix.json",
		"web-api-schema-probes.json",
		"web-object-matrix.json",
		"web-ssrf-matrix.json",
		"web-redirect-matrix.json",
		"web-cors-matrix.json",
		"web-identity-jwt.json",
		"web-security-posture.json",
		"web-js-sourcemap-summary.json",
		"web-runtime-capture-plan.json",
		"web-runtime-replay-plan.json",
		"web-runtime-replay-results.json",
		"web-signer-rebuild-workbench-plan.json",
		"web-js-signature-control-plan.json",
		"web-exploit-verifier.mjs",
	];
	const claims = load(join(dir, "web-exploit-claims.json"), {});
	const replay = load(join(dir, "web-replay-matrix.json"), {});
	const schema = load(join(dir, "web-api-schema-probes.json"), {});
	const objectMatrix = load(join(dir, "web-object-matrix.json"), {});
	const ssrf = load(join(dir, "web-ssrf-matrix.json"), {});
	const redirect = load(join(dir, "web-redirect-matrix.json"), {});
	const cors = load(join(dir, "web-cors-matrix.json"), {});
	const identity = load(join(dir, "web-identity-jwt.json"), {});
	const posture = load(join(dir, "web-security-posture.json"), {});
	const sourceMap = load(join(dir, "web-js-sourcemap-summary.json"), {});
	const runtimeCapturePlan = load(join(dir, "web-runtime-capture-plan.json"), null);
	const runtimeReplayPlan = load(join(dir, "web-runtime-replay-plan.json"), null);
	const runtimeResults = load(join(dir, "web-runtime-replay-results.json"), null);
	const signerPlan = load(join(dir, "web-signer-rebuild-workbench-plan.json"), null);
	const signaturePlan = load(join(dir, "web-js-signature-control-plan.json"), null);
	const checks = names.map((name) => artifactCheck(dir, name));
	const present = checks.filter((row) => row.exists);
	const required = ["web-exploit-claims.json", "web-replay-matrix.json", "web-exploit-verifier.mjs"];
	const artifactHashVerification = { verified: required.every((name) => checks.some((row) => row.relPath === name && row.exists && row.size > 0 && /^[a-f0-9]{64}$/i.test(String(row.sha256 || "")))), requiredArtifacts: required, presentCount: present.length, artifactChecks: checks };
	const replayRows = Array.isArray(replay.rows) ? replay.rows : [];
	const rowChecks = replayRows.map((row) => ({ id: row.id || null, principal: row.principal || null, url: row.url || null, status: row.status ?? null, responseSha256: row.responseSha256 || null, verified: replayRowValid(row) }));
	const replayHashVerification = { verified: rowChecks.length > 0 && rowChecks.every((row) => row.verified), rowCount: rowChecks.length, verifiedRows: rowChecks.filter((row) => row.verified).length, statuses: [...new Set(rowChecks.map((row) => row.status).filter((status) => status != null))].slice(0, 24), principals: [...new Set(rowChecks.map((row) => row.principal).filter(Boolean))].slice(0, 24), replaySha256: sha256Text(JSON.stringify(replay)), rowChecks: rowChecks.slice(0, 80) };
	const cats = [];
	if (replayHashVerification.verified) cats.push("replay");
	if ((schema.rows || []).some((row) => (row.risks || []).length || (((row.openapi || {}).risks) || []).length || ((row.introspection || {}).enabled))) cats.push("schema");
	if ((objectMatrix.rows || []).some((row) => row.bolaSignal || row.hashDelta || row.statusDelta)) cats.push("object");
	if ((ssrf.rows || []).some((row) => (row.risks || []).length)) cats.push("ssrf");
	if ((redirect.rows || []).some((row) => (row.risks || []).length)) cats.push("redirect");
	if ((cors.rows || []).some((row) => (row.risks || []).length)) cats.push("cors");
	if ((identity.risks || []).length || Number(identity.jwtCount || 0) > 0) cats.push("jwt");
	if ((posture.risks || []).length || (posture.cookies || []).some((cookie) => (cookie.risks || []).length)) cats.push("posture");
	if (runtimeCapturePlan || runtimeReplayPlan || signerPlan || signaturePlan || (sourceMap.sourceMaps || []).length) cats.push("runtime-harness");
	const categories = [...new Set(cats)];
	const riskMatrixCoverage = { verified: categories.includes("replay") && categories.some((category) => category !== "replay"), categories, matrixArtifacts: names.filter((name) => !["web-exploit-claims.json", "web-replay-matrix.json", "web-exploit-verifier.mjs"].includes(name) && checks.some((row) => row.relPath === name && row.exists)) };
	const claimRows = Array.isArray(claims.claimLedger) ? claims.claimLedger : [];
	const pathRows = Array.isArray(claims.composedPaths) ? claims.composedPaths : [];
	const byId = new Map(claimRows.filter((claim) => claim && claim.id).map((claim) => [claim.id, claim]));
	const runtimePaths = pathRows.filter((path) => /web-client-signer-(?:proof|blocked)-path/.test(String((path && path.claimType) || "")));
	const live = liveRows(runtimeResults);
	const runtimeProofReady = Boolean(runtimeResults && runtimeResults.liveReplay && runtimeResults.promotionReport && runtimeResults.promotionReport.proofReady && live.length);
	const badRuntimePaths = runtimePaths.filter((path) => path && path.verdict === "promoted" && !runtimeProofReady);
	const runtimeBlockers = runtimeProofReady ? [] : ["missing-web-live-runtime-replay-proof", "missing-web-runtime-negative-control"];
	const runtimeNegativeControlVerification = { verified: runtimeProofReady || (Boolean(runtimeReplayPlan || runtimeCapturePlan || runtimePaths.length) && badRuntimePaths.length === 0), runtimeProofReady, liveReplay: Boolean(runtimeResults && runtimeResults.liveReplay), liveRuntimeProofs: live.length, promotedRuntimePathsWithoutProof: badRuntimePaths.map((path) => path.id), negativeControls: (runtimeReplayPlan && runtimeReplayPlan.negativeControls) || [], blockers: runtimeBlockers, resultsSha256: runtimeResults ? sha256Text(JSON.stringify(runtimeResults)) : null };
	const pathChecks = pathRows.map((path) => {
		const segments = (((path || {}).sourceBinding || {}).segments || []).map((segment) => {
			const claim = byId.get(segment.id);
			return { id: segment.id || null, claimType: segment.claimType || null, claimPresent: Boolean(claim), claimPromoted: claim && claim.verdict === "promoted" };
		});
		return { id: (path || {}).id || null, claimType: (path || {}).claimType || null, verdict: (path || {}).verdict || null, verified: segments.length > 0 && segments.every((segment) => segment.claimPresent && segment.claimPromoted), segments };
	});
	const composedPathVerification = { verified: pathChecks.length > 0 && pathChecks.every((row) => row.verified), pathCount: pathChecks.length, verifiedPathCount: pathChecks.filter((row) => row.verified).length, promotedPathCount: pathChecks.filter((row) => row.verified && row.verdict === "promoted").length, pathChecks };
		const firstPresent = present[0];
		const firstRequired = required.map((name) => checks.find((row) => row.relPath === name && row.exists)).find(Boolean);
		const firstReplay = replayRows.find((row) => replayRowValid(row));
		const firstSegment = pathChecks.flatMap((row) => row.segments).find((segment) => segment.id);
		const firstVerifiedPath = pathChecks.find((row) => row.verified);
		const mutatedChecks = firstRequired
			? checks.map((row) => row.relPath === firstRequired.relPath ? Object.assign({}, row, { exists: false, size: 0, sha256: null }) : row)
			: [];
		const mutatedArtifactGateAccepted = mutatedChecks.length > 0 && required.every((name) => mutatedChecks.some((row) => row.relPath === name && row.exists && row.size > 0 && /^[a-f0-9]{64}$/i.test(String(row.sha256 || ""))));
		const mutatedSegments = firstVerifiedPath
			? firstVerifiedPath.segments.map((segment, index) => index === 0 ? Object.assign({}, segment, { id: segment.id + ":negative-control-mutation" }) : segment)
			: [];
		const mutatedPathAccepted = mutatedSegments.length > 0 && mutatedSegments.every((segment) => byId.has(segment.id) && byId.get(segment.id).verdict === "promoted");
		const runtimeGateAccepts = ({ proofReady, hasInputs, promotedWithoutProof }) => Boolean(proofReady || (hasInputs && promotedWithoutProof === 0));
		const runtimeGateOriginalAccepted = runtimeGateAccepts({ proofReady: runtimeProofReady, hasInputs: Boolean(runtimeReplayPlan || runtimeCapturePlan || runtimePaths.length), promotedWithoutProof: badRuntimePaths.length });
		const runtimeGateMutatedAccepted = runtimeGateAccepts({ proofReady: false, hasInputs: true, promotedWithoutProof: Math.max(1, badRuntimePaths.length) });
		const negativeControls = [
			{ controlType: "web-missing-artifact-negative-control", artifact: firstRequired ? firstRequired.relPath : (firstPresent ? firstPresent.relPath : null), mutatedArtifactGateAccepted, passed: Boolean(firstRequired && artifactHashVerification.verified && !mutatedArtifactGateAccepted) },
			{ controlType: "web-missing-replay-hash-negative-control", rowId: firstReplay ? firstReplay.id : null, passed: Boolean(firstReplay && !replayRowValid(Object.assign({}, firstReplay, { responseSha256: "" }))) },
			{ controlType: "web-mutated-composed-segment-negative-control", segmentId: firstSegment ? firstSegment.id : null, mutatedPathAccepted, passed: Boolean(firstSegment && firstSegment.id && firstVerifiedPath && firstVerifiedPath.verified && !mutatedPathAccepted) },
			{ controlType: "web-runtime-proof-gate-negative-control", mutatedRuntimeGateAccepted: runtimeGateMutatedAccepted, passed: Boolean(runtimeGateOriginalAccepted && !runtimeGateMutatedAccepted) },
		];
	const negativeControlVerification = { verified: negativeControls.length >= 4 && negativeControls.every((row) => row.passed), negativeControlsPassed: negativeControls.filter((row) => row.passed).length, negativeControls };
	const ledger = [];
	const paths = [];
	const artifactClaim = artifactHashVerification.verified ? addClaim(ledger, { id: "web-artifact-hash-verification-" + short(present.map((row) => row.relPath + ":" + row.sha256).join("|")), claimType: "web-artifact-hash-verification-proof", sourceBinding: { artifact: "web-exploit-verification.json", artifacts: present.map((row) => row.relPath) }, evidenceBinding: artifactHashVerification, statement: "Web verifier rebound exploit, replay, and harness artifacts to exact size/SHA-256 evidence.", confidence: 0.86 }) : null;
	const replayClaim = replayHashVerification.verified ? addClaim(ledger, { id: "web-replay-hash-verification-" + short(JSON.stringify(replayHashVerification.statuses)), claimType: "web-replay-hash-verification-proof", sourceBinding: { artifact: "web-exploit-verification.json", replay: "web-replay-matrix.json" }, evidenceBinding: replayHashVerification, statement: "Web verifier confirmed every replay row has an HTTP status and 64-hex response hash.", confidence: 0.84 }) : null;
	const riskClaim = riskMatrixCoverage.verified ? addClaim(ledger, { id: "web-risk-matrix-coverage-" + short(riskMatrixCoverage.categories.join("|")), claimType: "web-risk-matrix-coverage-proof", sourceBinding: { artifact: "web-exploit-verification.json", replay: "web-replay-matrix.json", matrices: riskMatrixCoverage.matrixArtifacts }, evidenceBinding: riskMatrixCoverage, statement: "Web verifier confirmed replay evidence is paired with schema/object/browser/policy risk-matrix coverage.", confidence: 0.82 }) : null;
	const runtimeClaim = runtimeNegativeControlVerification.verified ? addClaim(ledger, { id: "web-runtime-negative-control-" + short(JSON.stringify(runtimeNegativeControlVerification.blockers)), claimType: "web-runtime-negative-control-proof", sourceBinding: { artifact: "web-exploit-verification.json", runtimePlan: "web-runtime-replay-plan.json", runtimeResults: runtimeResults ? "web-runtime-replay-results.json" : null }, evidenceBinding: runtimeNegativeControlVerification, statement: runtimeProofReady ? "Web verifier confirmed live browser runtime negative-control replay proof." : "Web verifier kept runtime signer proof blocked until live captured-signed/missing/tampered controls provide response hashes.", confidence: runtimeProofReady ? 0.86 : 0.74 }) : null;
	const pathClaim = composedPathVerification.verified ? addClaim(ledger, { id: "web-composed-path-verification-" + short(JSON.stringify(pathChecks.map((row) => row.id))), claimType: "web-composed-path-verification-proof", sourceBinding: { artifact: "web-exploit-verification.json", claims: "web-exploit-claims.json" }, evidenceBinding: composedPathVerification, statement: "Web verifier confirmed every composed-path segment resolves to a promoted exploit claim.", confidence: 0.84 }) : null;
	const negativeClaim = negativeControlVerification.verified ? addClaim(ledger, { id: "web-exploit-verifier-negative-control-" + short(JSON.stringify(negativeControls)), claimType: "web-exploit-verifier-negative-control-proof", sourceBinding: { artifact: "web-exploit-verification.json" }, evidenceBinding: negativeControlVerification, statement: "Web verifier rejected missing-artifact, missing-replay-hash, mutated-segment, and runtime proof-gate controls.", confidence: 0.84 }) : null;
	const sourceExploitReady = Boolean(claims.exploitProofReady || runtimeProofReady);
	if (artifactClaim && replayClaim && riskClaim && runtimeClaim && pathClaim && negativeClaim) {
		const segments = [artifactClaim, replayClaim, riskClaim, runtimeClaim, pathClaim, negativeClaim];
		const path = { id: (sourceExploitReady ? "web-exploit-verification-proof-path-" : "web-exploit-verification-blocked-path-") + short(segments.map((claim) => claim.id).join(">")), claimType: sourceExploitReady ? "web-exploit-verification-proof-path" : "web-exploit-verification-blocked-path", sourceBinding: { segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType, artifact: (claim.sourceBinding || {}).artifact })) }, evidenceBinding: { presentArtifacts: artifactHashVerification.presentCount, replayRows: replayHashVerification.verifiedRows, riskCategories: riskMatrixCoverage.categories, liveRuntimeProofs: runtimeNegativeControlVerification.liveRuntimeProofs, verifiedPathCount: composedPathVerification.verifiedPathCount, negativeControlsPassed: negativeControlVerification.negativeControlsPassed }, statement: sourceExploitReady ? "Web exploit proof path composes artifact hashes, replay body hashes, risk matrices, composed-path resolution, and verifier negative controls." : "Web verifier blocks final exploit promotion until live runtime proof or a promoted route/object impact path is present.", verdict: sourceExploitReady ? "promoted" : "blocked", confidence: sourceExploitReady ? 0.88 : 0.56, blockers: sourceExploitReady ? [] : runtimeBlockers };
		ledger.push(path);
		paths.push(path);
	}
	const blockers = [];
	if (!artifactHashVerification.verified) blockers.push("missing-web-artifact-hash-verification");
	if (!replayHashVerification.verified) blockers.push("missing-web-replay-hash-verification");
	if (!riskMatrixCoverage.verified) blockers.push("missing-web-risk-matrix-coverage");
	if (!runtimeProofReady) blockers.push("missing-web-live-runtime-replay-proof");
	if (!runtimeNegativeControlVerification.verified || !runtimeProofReady) blockers.push("missing-web-runtime-negative-control");
	if (!composedPathVerification.verified) blockers.push("missing-web-composed-path-verification");
	if (!negativeControlVerification.verified) blockers.push("missing-web-verifier-negative-control");
	const proofReady = Boolean(artifactClaim && replayClaim && riskClaim && runtimeClaim && pathClaim && negativeClaim);
	const promotedPaths = paths.filter((path) => path.verdict === "promoted");
	return { kind: "repi-web-exploit-verification", schemaVersion: 1, generatedAt: new Date().toISOString(), proofReady, runtimeProofReady, exploitProofReady: promotedPaths.length > 0, artifactHashVerification, replayHashVerification, riskMatrixCoverage, runtimeNegativeControlVerification, composedPathVerification, negativeControlVerification, stats: { presentArtifacts: artifactHashVerification.presentCount, replayRows: replayHashVerification.rowCount, verifiedReplayRows: replayHashVerification.verifiedRows, riskCategories: riskMatrixCoverage.categories.length, liveRuntimeProofs: runtimeNegativeControlVerification.liveRuntimeProofs, verifiedPathCount: composedPathVerification.verifiedPathCount, negativeControlsPassed: negativeControlVerification.negativeControlsPassed }, claimLedger: ledger, composedPaths: paths, promotionReport: { proofReady, runtimeProofReady, exploitProofReady: promotedPaths.length > 0, promotedClaims: ledger.filter((claim) => claim.verdict === "promoted"), composedPaths: promotedPaths, blockers }, repairQueue: blockers.map((blocker) => ({ id: "web-exploit-verification-" + blocker, blocker, action: "Collect verifier-bound web evidence and rerun web-exploit-verifier.mjs.", rerunCommand: "node web-exploit-verifier.mjs <artifact-dir> web-exploit-verification.json" })) };
}

function runSelfTest() {
	const dir = join(tmpdir(), "repi-web-exploit-verifier-" + Date.now() + "-" + process.pid);
	mkdirSync(dir, { recursive: true, mode: 0o700 });
	const replay = { kind: "repi-web-replay-matrix", rows: [{ id: "anon", principal: "anonymous", url: "https://example.test/api/orders/1001", status: 401, responseSha256: sha256Text("anon") }, { id: "session", principal: "cookie-session", url: "https://example.test/api/orders/1001", status: 200, responseSha256: sha256Text("session") }] };
	const object = { rows: [{ id: "object", bolaSignal: true, hashDelta: true, statusDelta: false }] };
	const claimA = { id: "auth", claimType: "web-session-auth-differential", verdict: "promoted" };
	const claimB = { id: "object", claimType: "web-object-authz-bola-signal", verdict: "promoted" };
	const path = { id: "web-authz-object-proof-path-selftest", claimType: "web-authz-object-proof-path", verdict: "promoted", sourceBinding: { segments: [{ id: "auth", claimType: "web-session-auth-differential" }, { id: "object", claimType: "web-object-authz-bola-signal" }] } };
	const claims = { kind: "repi-web-exploit-claims", proofReady: true, exploitProofReady: true, claimLedger: [claimA, claimB, path], composedPaths: [path], repairQueue: [{ blocker: "missing-web-live-runtime-replay-proof" }, { blocker: "missing-web-runtime-negative-control" }] };
	writeJson(join(dir, "web-replay-matrix.json"), replay);
	writeJson(join(dir, "web-object-matrix.json"), object);
	writeJson(join(dir, "web-runtime-capture-plan.json"), { hooks: ["fetch"] });
	writeJson(join(dir, "web-runtime-replay-plan.json"), { negativeControls: ["captured-signed", "missing-signature", "tampered-signature"], run: "node web-runtime-replay-verifier.mjs capture results --live" });
	writeJson(join(dir, "web-exploit-claims.json"), claims);
	writeFileSync(join(dir, "web-exploit-verifier.mjs"), "self-test verifier\n", { mode: 0o700 });
	const result = verify(dir);
	if (!result.proofReady || !result.exploitProofReady || result.runtimeProofReady || result.negativeControlVerification.negativeControlsPassed < 4) throw new Error(JSON.stringify(result));
	const mutated = Object.assign({}, replay.rows[0], { responseSha256: "" });
	if (replayRowValid(mutated)) throw new Error("missing replay hash negative control failed");
	console.log(JSON.stringify({ kind: "repi-web-exploit-verifier-self-test", status: "ok", stats: result.stats }, null, 2));
}

if (selfTestMode) {
	runSelfTest();
} else {
	const dir = process.argv[2] || ".";
	const output = process.argv[3] || join(dir, "web-exploit-verification.json");
	const result = verify(dir);
	writeJson(output, result);
	console.log(JSON.stringify({ kind: result.kind, proofReady: result.proofReady, runtimeProofReady: result.runtimeProofReady, exploitProofReady: result.exploitProofReady, stats: result.stats, output }, null, 2));
	process.exit(result.proofReady ? 0 : 1);
}
`;
}

export function writeWebExploitVerifier(artifactDir, runtime) {
	const { noWrite, writePrivate } = runtime;
	if (noWrite || !artifactDir) return undefined;
	const path = join(artifactDir, "web-exploit-verifier.mjs");
	writePrivate(path, webExploitVerifierSource(), 0o700);
	return path;
}

export function writeWebExploitVerification(target, artifactDir, claimsSummary, runtime) {
	const { noWrite, writePrivate } = runtime;
	if (noWrite || !artifactDir) return undefined;
	const summary = webExploitVerificationSummary(target, artifactDir, claimsSummary, runtime);
	const path = join(artifactDir, "web-exploit-verification.json");
	writePrivate(path, `${JSON.stringify(summary, null, 2)}\n`, 0o600);
	return { path, summary };
}
