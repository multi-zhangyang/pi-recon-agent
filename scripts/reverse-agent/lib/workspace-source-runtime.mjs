import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

let noWrite;
let writePrivate;
let readJsonArtifact;
let redact;
let httpSecretHash;
let shortHash;
let shellQuote;

export function configureWorkspaceSourceRuntime(runtime) {
	({ noWrite, writePrivate, readJsonArtifact, redact, httpSecretHash, shortHash, shellQuote } = runtime);
}

function jsReverseWorkbenchSource(target) {
	return `#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const input = process.argv.includes("--self-test") ? "<self-test>" : (process.argv[2] || ${JSON.stringify(target)});
const output = process.argv[3] || "js-reverse-workbench.json";
const selfTest = process.argv.includes("--self-test");
const maxFiles = Number(process.env.REPI_JS_REVERSE_MAX_FILES || 80);
const maxBytesPerFile = Number(process.env.REPI_JS_REVERSE_MAX_BYTES || 300000);

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function redact(value) {
	return String(value ?? "")
		.replace(/\\bBearer\\s+[A-Za-z0-9._~+/=-]{8,}/gi, "Bearer <redacted>")
		.replace(/([?&](?:api[_-]?key|token|access_token|refresh_token|client_secret|secret|password)=)[^&\\s"'<>]{4,}/gi, "$1<redacted>")
		.replace(/((?:authorization|x-api-key|api-key|cookie|set-cookie)\\s*[:=]\\s*["']?)([^"'\\n;]{4,})/gi, "$1<redacted>")
		.replace(/(["']?(?:api[_-]?key|token|secret|password|client_secret|access_token|refresh_token)["']?\\s*[:=]\\s*["'])([^"']{4,})(["'])/gi, "$1<redacted>$3");
}

function walkFiles(root) {
	if (!existsSync(root)) return [];
	const stat = statSync(root);
	if (stat.isFile()) return [root];
	const out = [];
	const skip = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
	function walk(dir, depth) {
		if (out.length >= maxFiles || depth > 4) return;
		for (const entry of readdirSync(dir, { withFileTypes: true })) {
			if (out.length >= maxFiles) return;
			const path = join(dir, entry.name);
			if (entry.isDirectory()) {
				if (!skip.has(entry.name)) walk(path, depth + 1);
			} else if (/\\.(?:js|mjs|cjs|ts|tsx|jsx|wasm)$/i.test(entry.name)) {
				out.push(path);
			}
		}
	}
	walk(root, 0);
	return out;
}

function endpointHints(text) {
	const hints = new Set();
	const patterns = [
		/\\b(?:fetch|open)\\(\\s*["'\`]([^"'\`]+)["'\`]/gi,
		/\\b(?:axios|request)\\.(?:get|post|put|patch|delete)\\(\\s*["'\`]([^"'\`]+)["'\`]/gi,
		/["'\`](https?:\\/\\/[^"'\`\\s<>]+|\\/(?:api|graphql|oauth|auth|login|admin|v\\d+)\\/[^"'\`\\s<>]*)["'\`]/gi,
	];
	for (const pattern of patterns) {
		for (const match of text.matchAll(pattern)) {
			if (match[1]) hints.add(redact(match[1]).slice(0, 240));
			if (hints.size >= 80) return Array.from(hints);
		}
	}
	return Array.from(hints);
}

function signalLines(text, label) {
	const out = [];
	const lines = String(text ?? "").split(/\\r?\\n/);
	for (const [index, line] of lines.entries()) {
		if (/(fetch|XMLHttpRequest|websocket|sign|signature|encrypt|decrypt|crypto\\.subtle|hmac|md5|sha-?1|sha-?256|nonce|timestamp|token|authorization|canonical|permutation|salt|secret|WebAssembly)/i.test(line)) {
			out.push({ file: label, line: index + 1, text: redact(line.trim().slice(0, 260)) });
			if (out.length >= 80) break;
		}
	}
	return out;
}

function functionCandidates(text, label) {
	const rows = [];
	const pattern = /(?:async\\s+)?function\\s+([A-Za-z_$][\\w$]{0,80})\\s*\\(|(?:const|let|var)\\s+([A-Za-z_$][\\w$]{0,80})\\s*=\\s*(?:async\\s*)?\\([^)]*\\)\\s*=>|([A-Za-z_$][\\w$]{0,80})\\s*[:=]\\s*(?:async\\s*)?function\\s*\\(/g;
	for (const match of text.matchAll(pattern)) {
		const name = match[1] || match[2] || match[3] || "";
		if (!/(sign|sig|auth|token|encrypt|decrypt|hash|hmac|nonce|timestamp|canonical|wbi|mixin|key|crypto)/i.test(name)) continue;
		const start = Math.max(0, match.index - 240);
		const end = Math.min(text.length, match.index + 800);
		const window = text.slice(start, end);
		rows.push({
			file: label,
			name: redact(name),
			offset: match.index,
			windowSha256: sha256(window),
			signals: Array.from(new Set((window.match(/crypto\\.subtle|md5|sha-?1|sha-?256|hmac|nonce|timestamp|signature|canonical|sort\\(|encodeURIComponent|URLSearchParams|permutation/gi) || []).map((item) => item.toLowerCase()))).slice(0, 20),
			sample: redact(window.replace(/\\s+/g, " ").slice(0, 500)),
		});
		if (rows.length >= 60) break;
	}
	return rows;
}

function signatureParams(text) {
	return Array.from(
		new Set(
			Array.from(text.matchAll(/(?:[?&]|["'])((?:signature|sign|sig|_signature|x-signature|x-sign|timestamp|ts|nonce|w_rid|wts))\\b/gi)).map((match) =>
				redact(match[1]),
			),
		),
	).slice(0, 40);
}

function analyzeFile(path) {
	const data = readFileSync(path);
	const text = data.subarray(0, maxBytesPerFile).toString("utf8");
	const label = path;
	return {
		path: redact(path),
		size: data.length,
		sha256: sha256(data),
		truncated: data.length > maxBytesPerFile,
		endpoints: endpointHints(text),
		signalLines: signalLines(text, label),
		functionCandidates: functionCandidates(text, label),
		signatureParams: signatureParams(text),
	};
}

function buildReport(files) {
	const analyses = files.map(analyzeFile);
	const risks = [];
	if (analyses.some((row) => row.signatureParams.length || row.functionCandidates.length)) risks.push("js-signature-rebuild-candidate");
	if (analyses.some((row) => row.signalLines.some((line) => /crypto\\.subtle|hmac|md5|sha/i.test(line.text)))) risks.push("js-crypto-transform-candidate");
	if (analyses.some((row) => row.endpoints.some((endpoint) => /\\/api|graphql|auth|login|admin/i.test(endpoint)))) risks.push("js-api-route-candidate");
	return {
		kind: "repi-js-reverse-workbench",
		schemaVersion: 1,
		input: redact(input),
		fileCount: analyses.length,
		risks,
		files: analyses,
		rebuildChecklist: [
			"freeze captured timestamp/nonce inputs before rebuilding signer",
			"extract exact canonical query order and URL encoding from runtime/source evidence",
			"run missing-signature and tampered-signature negative controls before calling a signer proof-ready",
		],
	};
}

function selfTestReport() {
	const sample = "function signRequest(params){ const base = Object.keys(params).sort().map(k=>k+'='+encodeURIComponent(params[k])).join('&'); return md5(base + client_salt); }\\nfetch('/api/proof?timestamp=1&signature=abc&nonce=n')\\ncrypto.subtle.digest('SHA-256', new TextEncoder().encode('x'))";
	return {
		kind: "repi-js-reverse-workbench-self-test",
		signalLines: signalLines(sample, "self-test"),
		endpoints: endpointHints(sample),
		functionCandidates: functionCandidates(sample, "self-test"),
		signatureParams: signatureParams(sample),
	};
}

function main() {
	if (selfTest) {
		const report = selfTestReport();
		console.log(JSON.stringify(report, null, 2));
		process.exit(report.functionCandidates?.length && report.endpoints?.length ? 0 : 1);
	}
	const files = walkFiles(input).slice(0, maxFiles);
	const report = buildReport(files);
	if (output && output !== "-") {
		writeFileSync(output, JSON.stringify(report, null, 2) + "\\n", { mode: 0o600 });
	}
	console.log(JSON.stringify({ kind: report.kind, output, fileCount: report.fileCount, risks: report.risks, functionCandidates: report.files.reduce((count, row) => count + row.functionCandidates.length, 0), endpoints: report.files.reduce((count, row) => count + row.endpoints.length, 0) }, null, 2));
}

try {
	main();
} catch (error) {
	console.error(error?.stack || error?.message || String(error));
	process.exit(1);
}
`;
}

function writeJsReverseWorkbench(artifactDir, target) {
	if (noWrite || !artifactDir) return undefined;
	const path = join(artifactDir, "js-reverse-workbench.mjs");
	writePrivate(path, jsReverseWorkbenchSource(target), 0o700);
	return path;
}

function workspaceSourceRuntimeHarnessSource() {
	return String.raw`#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, join, relative } from "node:path";

const selfTest = process.argv.includes("--self-test");
const target = selfTest ? "<self-test>" : process.argv[2] || process.cwd();
const output = process.argv[3] || "workspace-source-runtime-map.json";
const maxFiles = Number(process.env.REPI_WORKSPACE_MAP_MAX_FILES || 420);
const maxBytes = Number(process.env.REPI_WORKSPACE_MAP_MAX_BYTES || 260000);
const maxDepth = Number(process.env.REPI_WORKSPACE_MAP_MAX_DEPTH || 6);

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function redact(value) {
	return String(value ?? "")
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, "Bearer <redacted>")
		.replace(/([?&](?:api[_-]?key|token|access_token|refresh_token|client_secret|secret|password)=)[^&\s"'<>]{4,}/gi, "$1<redacted>")
		.replace(/((?:authorization|x-api-key|api-key|cookie|set-cookie)\s*[:=]\s*["']?)([^"'\n;]{4,})/gi, "$1<redacted>")
		.replace(/(["']?(?:api[_-]?key|token|secret|password|client_secret|access_token|refresh_token|private_key|access_key)["']?\s*[:=]\s*["'])([^"']{4,})(["'])/gi, "$1<redacted>$3");
}

function isTextSource(path) {
	return /\.(?:js|mjs|cjs|ts|tsx|jsx|py|go|rs|java|kt|kts|php|rb|cs|scala|swift|json|ya?ml|toml|env|ini|conf|properties|tf|Dockerfile)$/i.test(path) || /(?:^|\/)(?:Dockerfile|docker-compose\.ya?ml|compose\.ya?ml|Makefile)$/i.test(path);
}

function walkFiles(root) {
	const out = [];
	const skip = new Set([".git", "node_modules", "dist", "build", ".next", "coverage", ".venv", "venv", "__pycache__", "target"]);
	function walk(dir, depth) {
		if (out.length >= maxFiles || depth > maxDepth) return;
		let entries = [];
		try {
			entries = readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}
		for (const entry of entries) {
			if (out.length >= maxFiles) return;
			const path = join(dir, entry.name);
			if (entry.isDirectory()) {
				if (!skip.has(entry.name)) walk(path, depth + 1);
			} else if (entry.isFile() && isTextSource(path)) {
				out.push(path);
			}
		}
	}
	if (!existsSync(root)) return [];
	const stat = statSync(root);
	if (stat.isFile()) return isTextSource(root) ? [root] : [];
	walk(root, 0);
	return out;
}

function lineRows(text) {
	return String(text ?? "").split(/\r?\n/);
}

function relPath(root, path) {
	if (root === "<self-test>") return path;
	try {
		return relative(root, path) || basename(path);
	} catch {
		return path;
	}
}

function addRow(rows, limit, row) {
	if (rows.length >= limit) return;
	rows.push(row);
}

function routeMatches(line) {
	const rows = [];
	const patterns = [
		{ kind: "express-router", regex: /\b(?:app|router|server|api)\s*\.\s*(get|post|put|patch|delete|all|use)\s*\(\s*["'\x60]([^"'\x60)]+)/gi },
		{ kind: "fastify-route", regex: /\bfastify\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*["'\x60]([^"'\x60)]+)/gi },
		{ kind: "flask-fastapi-route", regex: /@(?:app|router|blueprint|bp)\s*\.\s*(get|post|put|patch|delete|route)\s*\(\s*["']([^"']+)/gi },
		{ kind: "django-path", regex: /\b(?:path|re_path)\s*\(\s*["']([^"']+)/gi, method: "ANY", pathGroup: 1 },
		{ kind: "go-http", regex: /\b(?:http\.)?HandleFunc\s*\(\s*["']([^"']+)/gi, method: "ANY", pathGroup: 1 },
		{ kind: "java-mapping", regex: /@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*(?:\([^"']*["']([^"']+)["'])?/gi },
		{ kind: "rails-route", regex: /\b(get|post|put|patch|delete)\s+["']([^"']+)/gi },
	];
	for (const pattern of patterns) {
		for (const match of line.matchAll(pattern.regex)) {
			const method = pattern.method || String(match[1] || "ANY").replace(/Mapping$/i, "").toUpperCase();
			const path = match[pattern.pathGroup || 2] || "/";
			rows.push({ kind: pattern.kind, method: method.toUpperCase(), path: redact(path).slice(0, 240) });
		}
	}
	return rows;
}

function authKind(line) {
	const patterns = [
		["jwt", /\b(jwt|jsonwebtoken|bearer|jwks|jwk|id_token|access_token)\b/i],
		["session-cookie", /\b(session|cookie|csrf|xsrf|sameSite|secure:\s*true|httpOnly)\b/i],
		["middleware-guard", /\b(auth|authenticate|authorize|guard|middleware|requireAuth|isAuthenticated|permission|role|rbac|acl)\b/i],
		["oauth-sso", /\b(oauth|oidc|saml|passport|openid|callback_uri|redirect_uri)\b/i],
		["api-key", /\b(api[_-]?key|x-api-key|client_secret|secret_key)\b/i],
	];
	for (const [kind, regex] of patterns) if (regex.test(line)) return kind;
	return undefined;
}

function sinkKind(line) {
	const patterns = [
		["command-exec", /\b(child_process|execSync|exec\s*\(|spawn\s*\(|spawnSync\s*\(|system\s*\(|popen\s*\(|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|subprocess\.(?:run|Popen|call)|os\.system)\b/i],
		["sql-query", /\b(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,80}\+|\.query\s*\(|rawQuery\s*\(|execute\s*\(|cursor\.execute\s*\(|sequelize\.query\s*\(/i],
		["deserialize", /\b(pickle\.loads?|yaml\.load\s*\(|ObjectInputStream|readObject\s*\(|JSON\.parse\s*\([^)]*req|deserialize\s*\()/i],
		["ssrf-fetch", /\b(fetch|axios|request|got|urllib|requests\.|http\.get|curl)\s*\([^)]*(?:req\.|request\.|params|query|body)/i],
		["file-write-read", /\b(readFile|writeFile|createReadStream|createWriteStream|sendFile|open\s*\(|FileInputStream|Path\.of|filepath|filename|upload|download)\b/i],
		["template-render", /\b(render_template_string|Template\s*\(|innerHTML|dangerouslySetInnerHTML|eval\s*\(|new Function\s*\()/i],
	];
	for (const [kind, regex] of patterns) if (regex.test(line)) return kind;
	return undefined;
}

function stateKind(line) {
	const patterns = [
		["db-write", /\b(INSERT|UPDATE|DELETE|UPSERT|\.save\s*\(|\.update\s*\(|\.delete\s*\(|\.create\s*\(|commit\s*\()\b/i],
		["file-write", /\b(writeFile|appendFile|createWriteStream|openSync\s*\([^)]*["']w|fs\.promises\.writeFile)\b/i],
		["queue-event", /\b(queue|publish|sendMessage|enqueue|kafka|rabbit|sqs|pubsub)\b/i],
		["privilege-change", /\b(role|permission|isAdmin|admin|scope|grant|revoke)\b/i],
	];
	for (const [kind, regex] of patterns) if (regex.test(line)) return kind;
	return undefined;
}

function signerKind(line) {
	const patterns = [
		["signature", /\b(sign|signature|x-signature|x-sign|sig|w_rid|wts)\b/i],
		["crypto", /\b(crypto\.subtle|createHash|createHmac|md5|sha-?1|sha-?256|hmac|AES|RSA|ECDSA)\b/i],
		["canonicalization", /\b(canonical|URLSearchParams|encodeURIComponent|sort\s*\(|nonce|timestamp|salt|secret|mixin|permutation)\b/i],
	];
	for (const [kind, regex] of patterns) if (regex.test(line)) return kind;
	return undefined;
}

function cloudKind(line) {
	const patterns = [
		["github-oidc", /\b(id-token:\s*write|aws-actions\/configure-aws-credentials|workload_identity_provider)\b/i],
		["iam-policy", /\b(aws_iam|Action:\s*["']?\*|Resource:\s*["']?\*|sts:AssumeRole|iam:PassRole)\b/i],
		["kubernetes-rbac", /\b(ClusterRoleBinding|ServiceAccount|privileged:\s*true|hostPath|automountServiceAccountToken)\b/i],
		["container-exposure", /(?:^\s*(?:FROM\s+\S+|EXPOSE\s+\d+)\b|\b(?:docker-compose|--privileged)\b|^\s*ports\s*:)/i],
	];
	for (const [kind, regex] of patterns) if (regex.test(line)) return kind;
	return undefined;
}

function scanText(root, file, text) {
	const routes = [];
	const authAnchors = [];
	const sinks = [];
	const stateMutations = [];
	const signerCrypto = [];
	const cloudTrust = [];
	const lines = lineRows(text);
	for (const [index, line] of lines.entries()) {
		const lineNo = index + 1;
		const sample = redact(line.trim().slice(0, 320));
		for (const route of routeMatches(line)) addRow(routes, 240, { ...route, file, line: lineNo, sample });
		const auth = authKind(line);
		if (auth) addRow(authAnchors, 240, { kind: auth, file, line: lineNo, sample });
		const sink = sinkKind(line);
		if (sink) addRow(sinks, 240, { kind: sink, file, line: lineNo, sample });
		const state = stateKind(line);
		if (state) addRow(stateMutations, 200, { kind: state, file, line: lineNo, sample });
		const signer = signerKind(line);
		if (signer) addRow(signerCrypto, 200, { kind: signer, file, line: lineNo, sample });
		const cloud = cloudKind(line);
		if (cloud) addRow(cloudTrust, 180, { kind: cloud, file, line: lineNo, sample });
	}
	return {
		file,
		lineCount: lines.length,
		textSha256: sha256(text),
		truncated: Buffer.byteLength(text, "utf8") >= maxBytes,
		routes,
		authAnchors,
		sinks,
		stateMutations,
		signerCrypto,
		cloudTrust,
	};
}

function parseManifest(root) {
	const manifests = [];
	const runtimeCommands = [];
	const addManifest = (path, kind, data = {}) => manifests.push({ path: relPath(root, path), kind, ...data });
	const packageJson = join(root, "package.json");
	if (existsSync(packageJson)) {
		try {
			const parsed = JSON.parse(readFileSync(packageJson, "utf8"));
			const scripts = parsed && typeof parsed.scripts === "object" ? parsed.scripts : {};
			addManifest(packageJson, "node-package", { scripts: Object.keys(scripts).slice(0, 40), dependencies: Object.keys(parsed.dependencies || {}).slice(0, 80) });
			for (const name of ["dev", "start", "serve", "test", "build"]) {
				if (scripts[name]) runtimeCommands.push({ kind: "npm-script", command: "npm run " + name, source: "package.json:scripts." + name });
			}
		} catch (error) {
			addManifest(packageJson, "node-package-parse-error", { error: redact(error.message || String(error)) });
		}
	}
	for (const [name, kind, command] of [
		["pyproject.toml", "python-project", "python -m pytest"],
		["requirements.txt", "python-requirements", "python -m pytest"],
		["go.mod", "go-module", "go test ./..."],
		["Cargo.toml", "rust-crate", "cargo test"],
		["Dockerfile", "dockerfile", "docker build -t repi-target ."],
		["docker-compose.yml", "docker-compose", "docker compose config"],
		["compose.yml", "docker-compose", "docker compose config"],
	]) {
		const path = join(root, name);
		if (existsSync(path)) {
			addManifest(path, kind);
			runtimeCommands.push({ kind, command, source: name });
		}
	}
	return { manifests, runtimeCommands };
}

function buildEdges(routes, authAnchors, sinks, stateMutations, signerCrypto) {
	const edges = [];
	const proofTargets = [];
	const replayTemplates = [];
	for (const route of routes.slice(0, 120)) {
		const sameFileAuth = authAnchors.filter((row) => row.file === route.file && Math.abs(row.line - route.line) <= 45).slice(0, 6);
		const sameFileSinks = sinks.filter((row) => row.file === route.file && Math.abs(row.line - route.line) <= 90).slice(0, 8);
		const sameFileState = stateMutations.filter((row) => row.file === route.file && Math.abs(row.line - route.line) <= 90).slice(0, 8);
		const sameFileSigner = signerCrypto.filter((row) => row.file === route.file && Math.abs(row.line - route.line) <= 120).slice(0, 8);
		const sensitive = /admin|account|user|order|payment|invoice|upload|download|file|debug|internal|token|secret|role|permission/i.test(route.path);
		const risks = [];
		if (sensitive && !sameFileAuth.length) risks.push("route-sensitive-no-nearby-auth-anchor");
		if (sameFileSinks.length) risks.push("route-to-dangerous-sink-candidate");
		if (sameFileState.length && /^(POST|PUT|PATCH|DELETE|ANY|ALL)$/i.test(route.method)) risks.push("state-changing-route-candidate");
		if (sameFileSigner.length) risks.push("route-near-signature-crypto-candidate");
		const edge = {
			route,
			nearbyAuth: sameFileAuth,
			nearbySinks: sameFileSinks,
			nearbyState: sameFileState,
			nearbySignerCrypto: sameFileSigner,
			risks,
		};
		edges.push(edge);
		if (risks.length) {
			proofTargets.push({
				id: "route-proof-" + sha256(JSON.stringify([route.file, route.line, route.method, route.path])).slice(0, 12),
				route,
				risks,
				proofNeed: "bind source route -> runtime request -> auth/session/negative-control response -> artifact hash",
			});
		}
		replayTemplates.push({
			route: route.path,
			method: route.method === "ANY" || route.method === "ALL" ? "GET" : route.method,
			command: "curl -i -sS -X " + (route.method === "ANY" || route.method === "ALL" ? "GET" : route.method) + " \"$BASE_URL" + route.path + "\"",
			negativeControls: [
				"repeat without Cookie/Authorization",
				"repeat with low-privilege Cookie/Authorization",
				"mutate numeric/uuid object identifiers when present",
			],
		});
	}
	return { edges, proofTargets, replayTemplates };
}

function aggregate(root, scans, manifest) {
	const routes = scans.flatMap((scan) => scan.routes);
	const authAnchors = scans.flatMap((scan) => scan.authAnchors);
	const sinks = scans.flatMap((scan) => scan.sinks);
	const stateMutations = scans.flatMap((scan) => scan.stateMutations);
	const signerCrypto = scans.flatMap((scan) => scan.signerCrypto);
	const cloudTrust = scans.flatMap((scan) => scan.cloudTrust);
	const graph = buildEdges(routes, authAnchors, sinks, stateMutations, signerCrypto);
	const risks = Array.from(new Set([...graph.proofTargets.flatMap((row) => row.risks), ...(cloudTrust.length ? ["cloud-identity-trust-chain-candidate"] : []), ...(signerCrypto.length ? ["workspace-signer-crypto-candidate"] : [])])).slice(0, 80);
	return {
		kind: "repi-workspace-source-runtime-map",
		schemaVersion: 1,
		target: redact(root),
		generatedAt: new Date().toISOString(),
		fileCount: scans.length,
		manifests: manifest.manifests,
		runtimeCommands: manifest.runtimeCommands,
		counts: {
			routes: routes.length,
			authAnchors: authAnchors.length,
			sinks: sinks.length,
			stateMutations: stateMutations.length,
			signerCrypto: signerCrypto.length,
			cloudTrust: cloudTrust.length,
			proofTargets: graph.proofTargets.length,
		},
		risks,
		routes: routes.slice(0, 240),
		authAnchors: authAnchors.slice(0, 160),
		sinks: sinks.slice(0, 160),
		stateMutations: stateMutations.slice(0, 140),
		signerCrypto: signerCrypto.slice(0, 140),
		cloudTrust: cloudTrust.slice(0, 120),
		sourceToRuntimeEdges: graph.edges.slice(0, 160),
		proofTargets: graph.proofTargets.slice(0, 120),
		routeReplayTemplates: graph.replayTemplates.slice(0, 120),
		proofExitRules: [
			"Do not promote a source-only sink: bind source file/line to a runtime request, response status/body hash, and a negative control.",
			"For authz/BOLA claims require at least two principals or anonymous-vs-session replay.",
			"For signer claims require captured signed success plus missing/tampered signature rejection or byte-for-byte rebuilt signer samples.",
		],
	};
}

function analyzeWorkspace(root) {
	const files = walkFiles(root);
	const scans = [];
	for (const path of files) {
		let data;
		try {
			data = readFileSync(path);
		} catch {
			continue;
		}
		const text = data.subarray(0, maxBytes).toString("utf8");
		scans.push(scanText(root, relPath(root, path), text));
	}
	return aggregate(root, scans, parseManifest(root));
}

function selfTestReport() {
	const sample = [
		"const express = require('express');",
		"const child_process = require('child_process');",
		"const app = express();",
		"const requireAuth = (req,res,next)=> next();",
		"app.get('/api/account/:id', requireAuth, (req,res)=> db.query('SELECT * FROM users WHERE id=' + req.params.id));",
		"app.post('/api/admin/run', (req,res)=> child_process.exec(req.body.cmd));",
		"function signRequest(params){ return crypto.createHash('md5').update(Object.keys(params).sort().join('&') + secret).digest('hex') }",
	].join("\n");
	return aggregate("<self-test>", [scanText("<self-test>", "src/server.js", sample)], { manifests: [{ path: "package.json", kind: "node-package", scripts: ["start"] }], runtimeCommands: [{ kind: "npm-script", command: "npm run start", source: "package.json:scripts.start" }] });
}

function main() {
	const report = selfTest ? selfTestReport() : analyzeWorkspace(target);
	if (!selfTest && output && output !== "-") writeFileSync(output, JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
	console.log(JSON.stringify({ kind: report.kind, target: report.target, fileCount: report.fileCount, counts: report.counts, risks: report.risks, output: selfTest ? null : output }, null, 2));
	process.exit(report.fileCount > 0 ? 0 : 1);
}

try {
	main();
} catch (error) {
	console.error(redact(error?.stack || error?.message || String(error)));
	process.exit(1);
}
`;
}

function writeWorkspaceSourceRuntimeHarness(artifactDir) {
	if (noWrite || !artifactDir) return undefined;
	const path = join(artifactDir, "workspace-source-runtime-harness.mjs");
	writePrivate(path, workspaceSourceRuntimeHarnessSource(), 0o700);
	return path;
}

function workspaceRouteReplayHarnessSource(plan) {
	const planJson = JSON.stringify(plan, null, 2);
	return String.raw`#!/usr/bin/env node
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

const plan = ${planJson};
const selfTest = process.argv.includes("--self-test");
const live = process.argv.includes("--live") || process.argv.includes("--execute");
const baseUrlArgIndex = process.argv.findIndex((arg) => arg === "--base-url");
const explicitBaseUrl = baseUrlArgIndex >= 0 ? process.argv[baseUrlArgIndex + 1] : undefined;
const baseUrl = explicitBaseUrl || process.env.REPI_WORKSPACE_BASE_URL || "";
const output = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : plan.output;
const maxRoutes = Number(process.env.REPI_WORKSPACE_REPLAY_MAX_ROUTES || "24");
const timeoutMs = Number(process.env.REPI_WORKSPACE_REPLAY_TIMEOUT_MS || "6000");

function sha256(value) {
	return createHash("sha256").update(String(value ?? "")).digest("hex");
}

function redact(value) {
	return String(value ?? "")
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, "Bearer <redacted>")
		.replace(/([?&](?:api[_-]?key|token|access_token|refresh_token|client_secret|secret|password)=)[^&\s"'<>]{4,}/gi, "$1<redacted>")
		.replace(/((?:authorization|x-api-key|api-key|cookie|set-cookie)\s*[:=]\s*["']?)([^"'\n;]{4,})/gi, "$1<redacted>");
}

function readMap() {
	if (selfTest) return selfTestMap();
	const mapPath = plan.mapPath || "workspace-source-runtime-map.json";
	if (!existsSync(mapPath)) throw new Error("workspace source-runtime map missing: " + mapPath);
	return JSON.parse(readFileSync(mapPath, "utf8"));
}

function selfTestMap() {
	return {
		kind: "repi-workspace-source-runtime-map",
		counts: { routes: 2, proofTargets: 2 },
		proofTargets: [
			{
				id: "self-account",
				route: { method: "GET", path: "/api/account/:id", file: "src/server.js", line: 5 },
				risks: ["route-to-dangerous-sink-candidate"],
			},
			{
				id: "self-admin-run",
				route: { method: "POST", path: "/api/admin/run", file: "src/server.js", line: 6 },
				risks: ["state-changing-route-candidate", "route-to-dangerous-sink-candidate"],
			},
		],
		routeReplayTemplates: [
			{ route: "/api/account/:id", method: "GET", negativeControls: ["repeat without Cookie/Authorization", "mutate numeric/uuid object identifiers when present"] },
			{ route: "/api/admin/run", method: "POST", negativeControls: ["repeat without Cookie/Authorization"] },
		],
	};
}

function routeTemplateRows(map) {
	const fromProof = Array.isArray(map.proofTargets)
		? map.proofTargets.map((target) => ({ route: target.route?.path || "/", method: target.route?.method || "GET", proofTargetId: target.id, risks: target.risks || [], source: target.route || {} }))
		: [];
	const fromTemplates = Array.isArray(map.routeReplayTemplates)
		? map.routeReplayTemplates.map((template) => ({ route: template.route || "/", method: template.method || "GET", proofTargetId: null, risks: [], source: {}, negativeControls: template.negativeControls || [] }))
		: [];
	const rows = [];
	const seen = new Set();
	for (const row of [...fromProof, ...fromTemplates]) {
		const route = String(row.route || "/");
		const method = String(row.method || "GET").toUpperCase();
		const key = method + " " + route;
		if (seen.has(key)) continue;
		seen.add(key);
		rows.push({ ...row, route, method });
		if (rows.length >= maxRoutes) break;
	}
	return rows;
}

function pathParamNames(route) {
	const names = [];
	for (const match of String(route).matchAll(/(?::([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\}|<([A-Za-z_][A-Za-z0-9_]*)>|\[([A-Za-z_][A-Za-z0-9_]*)\])/g)) {
		names.push(match[1] || match[2] || match[3] || match[4]);
	}
	return names;
}

function defaultParamValue(name) {
	const envName = "REPI_ROUTE_PARAM_" + String(name || "ID").toUpperCase().replace(/[^A-Z0-9]+/g, "_");
	const fromEnv = process.env[envName];
	if (fromEnv) return fromEnv;
	if (/uuid|guid/i.test(name)) return "00000000-0000-4000-8000-000000000001";
	if (/slug|name/i.test(name)) return "demo";
	return "1";
}

function mutatedParamValue(value) {
	const text = String(value ?? "1");
	if (/^\d+$/.test(text)) return String(Number(text) + 1);
	if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(text)) return text.replace(/[0-9a-f](?=[^0-9a-f]*$)/i, (char) => (char.toLowerCase() === "a" ? "b" : "a"));
	return text + "-repi-mutated";
}

function materializeRoute(route, mutated = false) {
	let path = String(route || "/");
	const params = {};
	for (const name of pathParamNames(path)) {
		const value = defaultParamValue(name);
		const selected = mutated ? mutatedParamValue(value) : value;
		params[name] = { value, selected };
		path = path
			.replace(new RegExp(":" + name + "\\b", "g"), encodeURIComponent(selected))
			.replace(new RegExp("\\{" + name + "\\}", "g"), encodeURIComponent(selected))
			.replace(new RegExp("<" + name + ">", "g"), encodeURIComponent(selected))
			.replace(new RegExp("\\[" + name + "\\]", "g"), encodeURIComponent(selected));
	}
	return { path, params };
}

function headersFor(control) {
	const headers = { "User-Agent": "REPI-workspace-route-replay" };
	if (control === "session" || control === "tampered-object") {
		if (process.env.REPI_REPLAY_COOKIE) headers.Cookie = process.env.REPI_REPLAY_COOKIE;
		if (process.env.REPI_REPLAY_AUTHORIZATION) headers.Authorization = process.env.REPI_REPLAY_AUTHORIZATION;
		if (!headers.Cookie && !headers.Authorization && selfTest) headers.Authorization = "Bearer self-test";
	}
	return headers;
}

function bodyFor(method, control) {
	if (!/^(POST|PUT|PATCH|DELETE)$/i.test(method)) return undefined;
	const raw = process.env.REPI_REPLAY_JSON_BODY || (selfTest ? JSON.stringify({ cmd: control === "tampered-object" ? "id" : "whoami" }) : "{}");
	return raw;
}

function requestVariants(row) {
	const base = materializeRoute(row.route, false);
	const mutated = materializeRoute(row.route, true);
	const method = row.method === "ANY" || row.method === "ALL" ? "GET" : row.method;
	const controls = [
		{ control: "anonymous", materialized: base, headers: headersFor("anonymous") },
		{ control: "session", materialized: base, headers: headersFor("session") },
	];
	if (Object.keys(base.params).length) controls.push({ control: "tampered-object", materialized: mutated, headers: headersFor("tampered-object") });
	return controls.map((variant) => ({
		...variant,
		method,
		body: bodyFor(method, variant.control),
	}));
}

function joinUrl(base, path) {
	const url = new URL(path.startsWith("/") ? path : "/" + path, base.endsWith("/") ? base : base + "/");
	return url.href;
}

async function fetchWithTimeout(url, options) {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const response = await fetch(url, { ...options, signal: controller.signal });
		const text = await response.text();
		let appCode = null;
		try {
			const json = JSON.parse(text);
			if (json && typeof json === "object") appCode = json.code ?? json.error ?? null;
		} catch {
			// Hash-only body evidence is enough for non-JSON responses.
		}
		return {
			status: response.status,
			ok: response.ok,
			bytes: Buffer.byteLength(text),
			responseSha256: sha256(text),
			appCode: appCode == null ? null : redact(appCode),
			bodySample: redact(text.slice(0, 500)),
		};
	} catch (error) {
		return { status: null, ok: false, error: redact(error?.message || String(error)) };
	} finally {
		clearTimeout(timer);
	}
}

async function replayRow(row, base) {
	const variants = [];
	for (const variant of requestVariants(row)) {
		const url = joinUrl(base, variant.materialized.path);
		const headers = variant.body ? { ...variant.headers, "Content-Type": "application/json" } : variant.headers;
		const result = await fetchWithTimeout(url, {
			method: variant.method,
			headers,
			body: variant.body,
		});
		variants.push({
			control: variant.control,
			method: variant.method,
			url: redact(url),
			paramBindings: variant.materialized.params,
			headerNames: Object.keys(headers),
			requestBodySha256: variant.body ? sha256(variant.body) : null,
			...result,
		});
	}
	const byControl = Object.fromEntries(variants.map((variant) => [variant.control, variant]));
	const anonymous = byControl.anonymous;
	const session = byControl.session;
	const tampered = byControl["tampered-object"];
	const authDifferential = Boolean(anonymous && session && anonymous.status !== session.status);
	const objectDifferential = Boolean(tampered && session && (tampered.status !== session.status || tampered.responseSha256 !== session.responseSha256));
	const statusCoverage = variants.some((variant) => typeof variant.status === "number");
	const proofReady = statusCoverage && (authDifferential || objectDifferential);
	return {
		route: row.route,
		method: row.method,
		proofTargetId: row.proofTargetId,
		risks: row.risks || [],
		source: row.source || {},
		variants,
		authDifferential,
		objectDifferential,
		proofReady,
	};
}

function sourceBinding(row) {
	const source = row.source || {};
	return {
		proofTargetId: row.proofTargetId || null,
		file: source.file || null,
		line: typeof source.line === "number" ? source.line : null,
		route: row.route,
		method: row.method,
		risks: Array.isArray(row.risks) ? row.risks : [],
	};
}

function variantEvidence(variant) {
	return {
		control: variant.control,
		method: variant.method,
		url: variant.url,
		status: typeof variant.status === "number" ? variant.status : null,
		ok: Boolean(variant.ok),
		bytes: typeof variant.bytes === "number" ? variant.bytes : null,
		responseSha256: variant.responseSha256 || null,
		appCode: variant.appCode ?? null,
		error: variant.error || null,
		paramBindings: variant.paramBindings || {},
		headerNames: Array.isArray(variant.headerNames) ? variant.headerNames : [],
		requestBodySha256: variant.requestBodySha256 || null,
	};
}

function hasSessionCredential(row) {
	return row.variants.some((variant) => variant.control === "session" && Array.isArray(variant.headerNames) && variant.headerNames.some((name) => /^(cookie|authorization)$/i.test(name)));
}

function hasObjectMutation(row) {
	return row.variants.some((variant) => variant.control === "tampered-object");
}

function rowBlockers(row, options = {}) {
	const blockers = [];
	const statusCoverage = row.variants.some((variant) => typeof variant.status === "number");
	if (options.baseUrlRequired) blockers.push("missing-base-url");
	if (!statusCoverage) blockers.push("no-status");
	if (statusCoverage && !row.authDifferential && !row.objectDifferential) blockers.push("no-differential");
	if (!selfTest && !options.baseUrlRequired && !hasSessionCredential(row)) blockers.push("missing-session-credentials");
	if (hasObjectMutation(row) && !row.objectDifferential) blockers.push("object-mutation-inconclusive");
	return blockers;
}

function claimId(row) {
	return "workspace-route-replay-" + sha256(JSON.stringify([row.method, row.route, row.proofTargetId || null])).slice(0, 12);
}

function rerunCommand(row) {
	const routeParamHints = pathParamNames(row.route)
		.map((name) => "REPI_ROUTE_PARAM_" + String(name).toUpperCase().replace(/[^A-Z0-9]+/g, "_") + "=<value>")
		.join(" ");
	const prefix = [routeParamHints, "REPI_REPLAY_COOKIE=<cookie>", "REPI_REPLAY_AUTHORIZATION=<bearer-or-basic>", "REPI_WORKSPACE_BASE_URL=http://127.0.0.1:PORT"]
		.filter(Boolean)
		.join(" ");
	return prefix + " node " + plan.harnessPath + " " + (plan.outputPath || plan.output || "workspace-route-replay-results.json") + " --live";
}

function claimForReplayRow(row, options = {}) {
	const blockers = rowBlockers(row, options);
	const promoted = row.proofReady && blockers.length === 0;
	const blocked = options.baseUrlRequired || blockers.includes("no-status");
	const evidenceVariants = row.variants.map(variantEvidence);
	const controls = {
		anonymous: evidenceVariants.some((variant) => variant.control === "anonymous"),
		session: evidenceVariants.some((variant) => variant.control === "session"),
		tamperedObject: evidenceVariants.some((variant) => variant.control === "tampered-object"),
		authDifferential: Boolean(row.authDifferential),
		objectDifferential: Boolean(row.objectDifferential),
		statusCoverage: evidenceVariants.some((variant) => typeof variant.status === "number"),
	};
	return {
		id: claimId(row),
		claimId: claimId(row),
		sourceBinding: sourceBinding(row),
		evidenceBinding: {
			baseUrl: options.baseUrlRequired ? null : redact(options.baseUrl || ""),
			proofTargetId: row.proofTargetId || null,
			variants: evidenceVariants,
			negativeControls: controls,
			headerNames: Array.from(new Set(evidenceVariants.flatMap((variant) => variant.headerNames))).sort(),
			paramBindings: evidenceVariants.reduce((acc, variant) => {
				for (const [name, binding] of Object.entries(variant.paramBindings || {})) acc[name] = binding;
				return acc;
			}, {}),
		},
		statement: promoted
			? "Runtime route replay promoted a source-bound auth/object-control claim with status/hash evidence."
			: blocked
				? "Runtime route replay is blocked before claim promotion."
				: "Runtime route replay captured observations but needs stronger negative-control differential before promotion.",
		verdict: promoted ? "promoted" : blocked ? "blocked" : "observation",
		confidence: promoted ? 0.86 : blocked ? 0.12 : 0.38,
		blockers,
		rerunCommand: rerunCommand(row),
	};
}

function planOnlyRows(map) {
	return routeTemplateRows(map).map((row) => ({
		route: row.route,
		method: row.method,
		proofTargetId: row.proofTargetId,
		risks: row.risks || [],
		source: row.source || {},
		variants: [],
		authDifferential: false,
		objectDifferential: false,
		proofReady: false,
	}));
}

function promotionRows(rows, options = {}) {
	return rows.map((row) => claimForReplayRow(row, options));
}

function repairAction(blocker) {
	const actions = {
		"missing-base-url": "Start the workspace service and provide REPI_WORKSPACE_BASE_URL or --base-url.",
		"no-status": "Fix service reachability, route params, host binding, or timeout until at least one HTTP status is captured.",
		"no-differential": "Replay with valid session credentials and mutated object identifiers until anonymous/session or object controls diverge.",
		"missing-session-credentials": "Provide REPI_REPLAY_COOKIE or REPI_REPLAY_AUTHORIZATION for the session control.",
		"object-mutation-inconclusive": "Set concrete REPI_ROUTE_PARAM_<NAME> values for an owned object and verify the tampered-object control.",
	};
	return actions[blocker] || "Re-run the route replay harness after resolving this blocker.";
}

function repairQueueRows(claims) {
	const queue = [];
	for (const claim of claims) {
		for (const blocker of claim.blockers || []) {
			queue.push({
				id: claim.id + "-" + blocker,
				claimId: claim.id,
				route: claim.sourceBinding.route,
				method: claim.sourceBinding.method,
				proofTargetId: claim.sourceBinding.proofTargetId,
				blocker,
				action: repairAction(blocker),
				sourceBinding: claim.sourceBinding,
				rerunCommand: claim.rerunCommand,
			});
		}
	}
	return queue;
}

function promotionReportFor(claims) {
	return {
		proofReady: claims.some((claim) => claim.verdict === "promoted"),
		promotedClaims: claims.filter((claim) => claim.verdict === "promoted"),
		observations: claims.filter((claim) => claim.verdict === "observation"),
		blockedClaims: claims.filter((claim) => claim.verdict === "blocked"),
	};
}

function resultSidecars(result) {
	const claims = Array.isArray(result.claimLedger) ? result.claimLedger : [];
	const repairQueue = Array.isArray(result.repairQueue) ? result.repairQueue : repairQueueRows(claims);
	return {
		claimPromotion: {
			kind: "repi-workspace-route-claim-promotion",
			schemaVersion: 1,
			generatedAt: result.generatedAt || new Date().toISOString(),
			baseUrl: result.baseUrl || null,
			baseUrlRequired: Boolean(result.baseUrlRequired),
			live: Boolean(result.live),
			selfTest: Boolean(result.selfTest),
			proofReady: Boolean(result.proofReady),
			routeCount: result.routeCount || claims.length,
			promotionReport: result.promotionReport || promotionReportFor(claims),
			claimLedger: claims,
		},
		repairQueue: {
			kind: "repi-workspace-route-repair-queue",
			schemaVersion: 1,
			generatedAt: result.generatedAt || new Date().toISOString(),
			baseUrlRequired: Boolean(result.baseUrlRequired),
			proofReady: Boolean(result.proofReady),
			queue: repairQueue,
		},
	};
}

function writeSidecarOutputs(result) {
	if (selfTest) return;
	const sidecars = resultSidecars(result);
	if (plan.claimPromotionPath) writeFileSync(plan.claimPromotionPath, JSON.stringify(sidecars.claimPromotion, null, 2) + "\n", { mode: 0o600 });
	if (plan.repairQueuePath) writeFileSync(plan.repairQueuePath, JSON.stringify(sidecars.repairQueue, null, 2) + "\n", { mode: 0o600 });
}

async function withSelfTestServer(callback) {
	const server = createServer((request, response) => {
		const authed = /^Bearer self-test$/i.test(String(request.headers.authorization || ""));
		if (request.url?.startsWith("/api/account/")) {
			if (!authed) {
				response.writeHead(401, { "content-type": "application/json" });
				response.end(JSON.stringify({ code: "missing_auth" }));
				return;
			}
			const id = request.url.split("/").pop();
			response.writeHead(id === "1" ? 200 : 404, { "content-type": "application/json" });
			response.end(JSON.stringify({ code: id === "1" ? 0 : "not_found", id }));
			return;
		}
		if (request.url === "/api/admin/run") {
			response.writeHead(authed ? 403 : 401, { "content-type": "application/json" });
			response.end(JSON.stringify({ code: authed ? "blocked_admin" : "missing_auth" }));
			return;
		}
		response.writeHead(404, { "content-type": "application/json" });
		response.end(JSON.stringify({ code: "not_found" }));
	});
	await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
	try {
		const address = server.address();
		return await callback("http://127.0.0.1:" + address.port);
	} finally {
		await new Promise((resolve) => server.close(resolve));
	}
}

async function runAgainst(base, map) {
	const rows = [];
	for (const row of routeTemplateRows(map)) rows.push(await replayRow(row, base));
	const claims = promotionRows(rows, { baseUrl: base });
	const promotionReport = promotionReportFor(claims);
	const repairQueue = repairQueueRows(claims);
	return {
		kind: "repi-workspace-route-replay-results",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		baseUrl: redact(base),
		live,
		selfTest,
		mapKind: map.kind,
		routeCount: rows.length,
		proofReady: promotionReport.proofReady,
		rows,
		claimLedger: claims,
		promotionReport,
		repairQueue,
		next: repairQueue.length
			? "Drain repairQueue until each target has live status/hash evidence plus anonymous/session or object-control differential."
			: "Bind promoted replay rows back to source file/line and keep anonymous/session/tampered controls with status/body hashes.",
	};
}

async function main() {
	const map = readMap();
	const result = selfTest
		? await withSelfTestServer((serverBase) => runAgainst(serverBase, map))
		: baseUrl
			? await runAgainst(baseUrl, map)
			: (() => {
					const rows = planOnlyRows(map);
					const claims = promotionRows(rows, { baseUrlRequired: true });
					const promotionReport = promotionReportFor(claims);
					const repairQueue = repairQueueRows(claims);
					return {
						kind: "repi-workspace-route-replay-plan",
						schemaVersion: 1,
						generatedAt: new Date().toISOString(),
						baseUrlRequired: true,
						proofReady: false,
						mapPath: plan.mapPath,
						routeCount: rows.length,
						routes: rows.map((row) => ({ route: row.route, method: row.method, proofTargetId: row.proofTargetId, risks: row.risks, sourceBinding: sourceBinding(row) })),
						run: "REPI_WORKSPACE_BASE_URL=http://127.0.0.1:PORT node " + plan.harnessPath + " " + (plan.outputPath || plan.output || "workspace-route-replay-results.json") + " --live",
						controls: ["anonymous", "session", "tampered-object"],
						claimLedger: claims,
						promotionReport,
						repairQueue,
					};
				})();
	writeSidecarOutputs(result);
	if (!selfTest && output && output !== "-") writeFileSync(output, JSON.stringify(result, null, 2) + "\n", { mode: 0o600 });
	console.log(JSON.stringify(result, null, 2));
	process.exit(result.proofReady || result.baseUrlRequired ? 0 : 1);
}

main().catch((error) => {
	console.error(redact(error?.stack || error?.message || String(error)));
	process.exit(1);
});
`;
}

function writeWorkspaceRouteReplayHarness(artifactDir) {
	if (noWrite || !artifactDir) return undefined;
	const harnessPath = join(artifactDir, "workspace-route-replay-harness.mjs");
	const planPath = join(artifactDir, "workspace-route-replay-plan.json");
	const outputPath = join(artifactDir, "workspace-route-replay-results.json");
	const claimPromotionPath = join(artifactDir, "workspace-route-claim-promotion.json");
	const repairQueuePath = join(artifactDir, "workspace-route-repair-queue.json");
	const plan = {
		kind: "repi-workspace-route-replay-plan",
		schemaVersion: 1,
		mapPath: join(artifactDir, "workspace-source-runtime-map.json"),
		harnessPath,
		outputPath,
		output: outputPath,
		claimPromotionPath,
		repairQueuePath,
		controls: ["anonymous", "session", "tampered-object"],
		env: {
			baseUrl: "REPI_WORKSPACE_BASE_URL or --base-url",
			cookie: "REPI_REPLAY_COOKIE",
			authorization: "REPI_REPLAY_AUTHORIZATION",
			jsonBody: "REPI_REPLAY_JSON_BODY",
			routeParams: "REPI_ROUTE_PARAM_<NAME>",
		},
		proofExitRule: "A promoted workspace route proof requires source file/line + live status/body hash + anonymous/session or object-mutation negative-control differential.",
	};
	writePrivate(planPath, `${JSON.stringify(plan, null, 2)}\n`, 0o600);
	writePrivate(harnessPath, workspaceRouteReplayHarnessSource(plan), 0o700);
	return { harnessPath, planPath, outputPath, claimPromotionPath, repairQueuePath };
}

function workspaceSourceRuntimeClaims(target, artifactDir) {
	const map = readJsonArtifact(join(artifactDir, "workspace-source-runtime-map.json"));
	const routeReplay = readJsonArtifact(join(artifactDir, "workspace-route-replay-results.json"));
	const routePromotion = readJsonArtifact(join(artifactDir, "workspace-route-claim-promotion.json"));
	const routeRepair = readJsonArtifact(join(artifactDir, "workspace-route-repair-queue.json"));
	const routePlan = readJsonArtifact(join(artifactDir, "workspace-route-replay-plan.json"));
	const artifactFiles = [
		map ? "workspace-source-runtime-map.json" : null,
		existsSync(join(artifactDir, "workspace-source-runtime-harness.mjs")) ? "workspace-source-runtime-harness.mjs" : null,
		routePlan ? "workspace-route-replay-plan.json" : null,
		routeReplay ? "workspace-route-replay-results.json" : null,
		routePromotion ? "workspace-route-claim-promotion.json" : null,
		routeRepair ? "workspace-route-repair-queue.json" : null,
		existsSync(join(artifactDir, "workspace-route-replay-harness.mjs")) ? "workspace-route-replay-harness.mjs" : null,
	].filter(Boolean);
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
	const mapEdges = Array.isArray(map?.sourceToRuntimeEdges) ? map.sourceToRuntimeEdges : [];
	const proofTargets = Array.isArray(map?.proofTargets) ? map.proofTargets : [];
	const routeRows = Array.isArray(map?.routes) ? map.routes : [];
	const routeSample = (rows) =>
		rows.slice(0, 24).map((row) => ({
			method: row.method ?? row.route?.method ?? null,
			path: row.path ?? row.route?.path ?? null,
			file: row.file ?? row.route?.file ?? null,
			line: row.line ?? row.route?.line ?? null,
			risks: row.risks ?? [],
		}));
	const edgeSample = (rows) =>
		rows.slice(0, 16).map((edge) => ({
			route: edge.route
				? {
						method: edge.route.method ?? null,
						path: edge.route.path ?? null,
						file: edge.route.file ?? null,
						line: edge.route.line ?? null,
					}
				: null,
			risks: edge.risks ?? [],
			nearbyAuthCount: Array.isArray(edge.nearbyAuth) ? edge.nearbyAuth.length : 0,
			nearbySinkKinds: Array.from(new Set((edge.nearbySinks ?? []).map((row) => row.kind).filter(Boolean))).slice(0, 12),
			nearbyStateKinds: Array.from(new Set((edge.nearbyState ?? []).map((row) => row.kind).filter(Boolean))).slice(0, 12),
			nearbySignerKinds: Array.from(new Set((edge.nearbySignerCrypto ?? []).map((row) => row.kind).filter(Boolean))).slice(0, 12),
		}));
	if (routeRows.length) {
		addClaim({
			id: "workspace-source-route-surface-" + shortHash(`${target}:${routeRows.length}:${JSON.stringify(routeRows.slice(0, 12))}`),
			claimType: "workspace-source-route-surface",
			sourceBinding: { artifact: "workspace-source-runtime-map.json", field: "routes" },
			evidenceBinding: {
				counts: map?.counts ?? {},
				routes: routeSample(routeRows),
				runtimeCommands: (map?.runtimeCommands ?? []).slice(0, 12),
				risks: map?.risks ?? [],
			},
			statement: "Workspace source scan bound framework route declarations to replay templates and runtime-start hints.",
			confidence: proofTargets.length ? 0.78 : 0.68,
			rerunCommand: `node ${shellQuote(join(artifactDir, "workspace-source-runtime-harness.mjs"))} ${shellQuote(target)} ${shellQuote(join(artifactDir, "workspace-source-runtime-map.json"))}`,
		});
	}
	const dangerousSinkEdges = mapEdges.filter((edge) => (edge.risks ?? []).includes("route-to-dangerous-sink-candidate") || (edge.nearbySinks ?? []).length);
	if (dangerousSinkEdges.length || (map?.sinks ?? []).length) {
		addClaim({
			id: "workspace-route-dangerous-sink-surface-" + shortHash(`${target}:${JSON.stringify(dangerousSinkEdges.slice(0, 12))}:${JSON.stringify((map?.sinks ?? []).slice(0, 12))}`),
			claimType: "workspace-route-dangerous-sink-surface",
			sourceBinding: { artifact: "workspace-source-runtime-map.json", fields: ["sourceToRuntimeEdges", "sinks"] },
			evidenceBinding: {
				edgeCount: dangerousSinkEdges.length,
				sinkCount: Array.isArray(map?.sinks) ? map.sinks.length : 0,
				edges: edgeSample(dangerousSinkEdges),
				sinkKinds: Array.from(new Set((map?.sinks ?? []).map((row) => row.kind).filter(Boolean))).slice(0, 24),
			},
			statement: "Source-only evidence identifies route-adjacent dangerous sinks; do not call this exploitable until live replay reaches the sink with controls.",
			confidence: dangerousSinkEdges.length ? 0.76 : 0.62,
			rerunCommand: "cat workspace-source-runtime-map.json | jq '.sourceToRuntimeEdges[] | select(.risks[]? == \"route-to-dangerous-sink-candidate\")'",
		});
	}
	const authGapEdges = mapEdges.filter((edge) => (edge.risks ?? []).includes("route-sensitive-no-nearby-auth-anchor"));
	if (authGapEdges.length) {
		addClaim({
			id: "workspace-route-auth-gap-surface-" + shortHash(`${target}:${JSON.stringify(authGapEdges.slice(0, 16))}`),
			claimType: "workspace-route-auth-gap-surface",
			sourceBinding: { artifact: "workspace-source-runtime-map.json", field: "sourceToRuntimeEdges" },
			evidenceBinding: {
				edgeCount: authGapEdges.length,
				edges: edgeSample(authGapEdges),
			},
			statement: "Sensitive-looking source routes lack a nearby auth anchor and need anonymous/session replay before promotion.",
			confidence: 0.72,
			rerunCommand: "cat workspace-source-runtime-map.json | jq '.sourceToRuntimeEdges[] | select(.risks[]? == \"route-sensitive-no-nearby-auth-anchor\")'",
		});
	}
	const stateEdges = mapEdges.filter((edge) => (edge.risks ?? []).includes("state-changing-route-candidate") || (edge.nearbyState ?? []).length);
	if (stateEdges.length || (map?.stateMutations ?? []).length) {
		addClaim({
			id: "workspace-state-changing-route-surface-" + shortHash(`${target}:${JSON.stringify(stateEdges.slice(0, 16))}:${JSON.stringify((map?.stateMutations ?? []).slice(0, 12))}`),
			claimType: "workspace-state-changing-route-surface",
			sourceBinding: { artifact: "workspace-source-runtime-map.json", fields: ["sourceToRuntimeEdges", "stateMutations"] },
			evidenceBinding: {
				edgeCount: stateEdges.length,
				stateMutationCount: Array.isArray(map?.stateMutations) ? map.stateMutations.length : 0,
				edges: edgeSample(stateEdges),
			},
			statement: "State-changing route candidates are source-bound and require CSRF/authz/session negative controls at runtime.",
			confidence: stateEdges.length ? 0.76 : 0.64,
			rerunCommand: "cat workspace-source-runtime-map.json | jq '.sourceToRuntimeEdges[] | select(.risks[]? == \"state-changing-route-candidate\")'",
		});
	}
	const signerEdges = mapEdges.filter((edge) => (edge.risks ?? []).includes("route-near-signature-crypto-candidate") || (edge.nearbySignerCrypto ?? []).length);
	if (signerEdges.length || (map?.signerCrypto ?? []).length) {
		addClaim({
			id: "workspace-signer-crypto-surface-" + shortHash(`${target}:${JSON.stringify(signerEdges.slice(0, 16))}:${JSON.stringify((map?.signerCrypto ?? []).slice(0, 12))}`),
			claimType: "workspace-signer-crypto-surface",
			sourceBinding: { artifact: "workspace-source-runtime-map.json", fields: ["signerCrypto", "sourceToRuntimeEdges"] },
			evidenceBinding: {
				signerSignalCount: Array.isArray(map?.signerCrypto) ? map.signerCrypto.length : 0,
				edges: edgeSample(signerEdges),
				signerKinds: Array.from(new Set((map?.signerCrypto ?? []).map((row) => row.kind).filter(Boolean))).slice(0, 20),
			},
			statement: "Source evidence contains signer/crypto/canonicalization signals that need captured signed success plus tamper/missing-signature controls.",
			confidence: signerEdges.length ? 0.78 : 0.68,
			rerunCommand: "cat workspace-source-runtime-map.json | jq '.signerCrypto,.sourceToRuntimeEdges[]?.nearbySignerCrypto'",
		});
	}
	const routeClaims = Array.isArray(routePromotion?.claimLedger)
		? routePromotion.claimLedger
		: Array.isArray(routeReplay?.claimLedger)
			? routeReplay.claimLedger
			: [];
	const hasStatusHash = (claim) =>
		(claim?.evidenceBinding?.variants ?? []).some(
			(variant) => typeof variant.status === "number" && /^[a-f0-9]{64}$/i.test(String(variant.responseSha256 ?? "")),
		);
	const hasDifferential = (claim) => {
		const controls = claim?.evidenceBinding?.negativeControls ?? {};
		return Boolean(controls.authDifferential || controls.objectDifferential);
	};
	const promotedRouteClaims = routeClaims.filter((claim) => claim.verdict === "promoted" && hasStatusHash(claim) && hasDifferential(claim));
	for (const claim of promotedRouteClaims.slice(0, 16)) {
		addClaim({
			id: "workspace-runtime-replay-proof-" + shortHash(`${target}:${claim.id}:${JSON.stringify(claim.sourceBinding ?? {})}`),
			claimType: "workspace-runtime-replay-proof",
			sourceBinding: {
				artifact: "workspace-route-claim-promotion.json",
				routeClaimId: claim.id,
				...(claim.sourceBinding ?? {}),
			},
			evidenceBinding: {
				baseUrl: claim.evidenceBinding?.baseUrl ?? routePromotion?.baseUrl ?? routeReplay?.baseUrl ?? null,
				variants: (claim.evidenceBinding?.variants ?? []).slice(0, 8),
				negativeControls: claim.evidenceBinding?.negativeControls ?? {},
				headerNames: claim.evidenceBinding?.headerNames ?? [],
				paramBindings: claim.evidenceBinding?.paramBindings ?? {},
			},
			statement: "Live workspace replay bound a source route to HTTP status/body hashes and an auth/object-control differential.",
			confidence: 0.88,
			rerunCommand: claim.rerunCommand ?? routePlan?.run ?? `REPI_WORKSPACE_BASE_URL=http://127.0.0.1:PORT node ${shellQuote(join(artifactDir, "workspace-route-replay-harness.mjs"))} ${shellQuote(join(artifactDir, "workspace-route-replay-results.json"))} --live`,
		});
	}
	const blockedRouteClaims = routeClaims.filter((claim) => claim.verdict === "blocked" || (claim.blockers ?? []).length);
	const routeBlockers = Array.from(
		new Set([
			...blockedRouteClaims.flatMap((claim) => claim.blockers ?? []),
			...(Array.isArray(routeRepair?.queue) ? routeRepair.queue.map((row) => row.blocker).filter(Boolean) : []),
			...(routeReplay?.baseUrlRequired || routePromotion?.baseUrlRequired ? ["missing-base-url"] : []),
		]),
	).sort();
	if (routeBlockers.length || blockedRouteClaims.length) {
		addClaim({
			id: "workspace-runtime-replay-plan-blocked-" + shortHash(`${target}:${routeBlockers.join(",")}:${blockedRouteClaims.length}`),
			claimType: "workspace-runtime-replay-plan-blocked",
			sourceBinding: { artifacts: ["workspace-route-replay-results.json", "workspace-route-claim-promotion.json", "workspace-route-repair-queue.json"].filter((name) => artifactFiles.includes(name)) },
			evidenceBinding: {
				baseUrlRequired: Boolean(routeReplay?.baseUrlRequired || routePromotion?.baseUrlRequired),
				blockedClaimCount: blockedRouteClaims.length,
				blockers: routeBlockers,
				blockedClaims: blockedRouteClaims.slice(0, 16).map((claim) => ({
					id: claim.id,
					route: claim.sourceBinding?.route ?? null,
					method: claim.sourceBinding?.method ?? null,
					proofTargetId: claim.sourceBinding?.proofTargetId ?? null,
					blockers: claim.blockers ?? [],
					verdict: claim.verdict,
				})),
			},
			statement: "Workspace route replay is not promoted yet; blockers must be drained before claiming live exploitability.",
			verdict: "blocked",
			confidence: 0.18,
			blockers: routeBlockers,
			rerunCommand: routePlan?.run ?? blockedRouteClaims[0]?.rerunCommand ?? `REPI_WORKSPACE_BASE_URL=http://127.0.0.1:PORT node ${shellQuote(join(artifactDir, "workspace-route-replay-harness.mjs"))} ${shellQuote(join(artifactDir, "workspace-route-replay-results.json"))} --live`,
		});
	}
	if (!map) {
		addClaim({
			id: "workspace-source-runtime-map-missing-" + shortHash(target),
			claimType: "workspace-source-runtime-map-missing",
			sourceBinding: { artifact: "workspace-source-runtime-map.json" },
			evidenceBinding: { artifactFiles },
			statement: "Workspace source-to-runtime map is missing; route/sink/auth claims cannot be promoted.",
			verdict: "blocked",
			confidence: 0.1,
			blockers: ["missing-source-runtime-map"],
			rerunCommand: `node ${shellQuote(join(artifactDir, "workspace-source-runtime-harness.mjs"))} ${shellQuote(target)} ${shellQuote(join(artifactDir, "workspace-source-runtime-map.json"))}`,
		});
	}
	const composedPaths = [];
	const sourceSurfaceClaim = claimLedger.find((claim) => claim.claimType === "workspace-source-route-surface");
	const dangerousSurfaceClaim = claimLedger.find((claim) => claim.claimType === "workspace-route-dangerous-sink-surface");
	const stateSurfaceClaim = claimLedger.find((claim) => claim.claimType === "workspace-state-changing-route-surface");
	const authGapClaim = claimLedger.find((claim) => claim.claimType === "workspace-route-auth-gap-surface");
	const runtimeProofClaims = claimLedger.filter((claim) => claim.claimType === "workspace-runtime-replay-proof");
	for (const runtimeClaim of runtimeProofClaims.slice(0, 8)) {
		const segments = [sourceSurfaceClaim, dangerousSurfaceClaim, stateSurfaceClaim, runtimeClaim].filter(Boolean);
		const sourceRuntimePath = {
			id: "workspace-source-runtime-proof-path-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "workspace-source-runtime-proof-path",
			sourceBinding: {
				target: redact(target),
				segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType })),
			},
			evidenceBinding: {
				route: runtimeClaim.sourceBinding?.route ?? null,
				method: runtimeClaim.sourceBinding?.method ?? null,
				file: runtimeClaim.sourceBinding?.file ?? null,
				line: runtimeClaim.sourceBinding?.line ?? null,
				hasRuntimeStatusHash: true,
				negativeControls: runtimeClaim.evidenceBinding?.negativeControls ?? {},
				artifactFiles,
			},
			statement: "Source route, nearby risk surface, and live replay evidence compose into a rerunnable source-to-runtime proof path.",
			verdict: "promoted",
			confidence: 0.88,
			blockers: [],
			rerunCommand: runtimeClaim.rerunCommand,
		};
		claimLedger.push(sourceRuntimePath);
		composedPaths.push(sourceRuntimePath);
		const controls = runtimeClaim.evidenceBinding?.negativeControls ?? {};
		if (controls.authDifferential || controls.objectDifferential) {
			const authSegments = [authGapClaim, runtimeClaim].filter(Boolean);
			const authzPath = {
				id: "workspace-authz-replay-proof-path-" + shortHash(`${runtimeClaim.id}:${JSON.stringify(controls)}:${authSegments.map((claim) => claim.id).join(">")}`),
				claimType: "workspace-authz-replay-proof-path",
				sourceBinding: {
					target: redact(target),
					segments: authSegments.length ? authSegments.map((claim) => ({ id: claim.id, claimType: claim.claimType })) : [{ id: runtimeClaim.id, claimType: runtimeClaim.claimType }],
				},
				evidenceBinding: {
					route: runtimeClaim.sourceBinding?.route ?? null,
					method: runtimeClaim.sourceBinding?.method ?? null,
					file: runtimeClaim.sourceBinding?.file ?? null,
					line: runtimeClaim.sourceBinding?.line ?? null,
					authDifferential: Boolean(controls.authDifferential),
					objectDifferential: Boolean(controls.objectDifferential),
					variantCount: (runtimeClaim.evidenceBinding?.variants ?? []).length,
					artifactFiles,
				},
				statement: "Anonymous/session/object controls produced a live status/hash differential tied back to a source route.",
				verdict: "promoted",
				confidence: 0.86,
				blockers: [],
				rerunCommand: runtimeClaim.rerunCommand,
			};
			claimLedger.push(authzPath);
			composedPaths.push(authzPath);
		}
	}
	const promotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted");
	const observationClaims = claimLedger.filter((claim) => claim.verdict === "observation");
	const blockedClaims = claimLedger.filter((claim) => claim.verdict === "blocked");
	const blockers = Array.from(
		new Set([
			...(map ? [] : ["missing-source-runtime-map"]),
			...(routePlan || routeReplay || routePromotion ? [] : ["missing-route-replay-plan"]),
			...blockedClaims.flatMap((claim) => claim.blockers ?? []),
			...(composedPaths.length ? [] : promotedRouteClaims.length ? [] : routeRows.length ? ["missing-live-route-replay-proof"] : []),
		]),
	).sort();
	const repairActions = {
		"missing-source-runtime-map": "Run workspace-source-runtime-harness.mjs against the workspace and keep source file/line bindings.",
		"missing-route-replay-plan": "Generate workspace-route-replay-harness.mjs and route replay sidecars before claim promotion.",
		"missing-base-url": "Start the service and set REPI_WORKSPACE_BASE_URL or pass --base-url to the replay harness.",
		"no-status": "Fix host/port/routes/params until replay captures at least one HTTP status.",
		"no-differential": "Replay anonymous, session, and object mutation controls until status/body hashes diverge.",
		"missing-session-credentials": "Provide REPI_REPLAY_COOKIE or REPI_REPLAY_AUTHORIZATION for session replay.",
		"object-mutation-inconclusive": "Bind concrete REPI_ROUTE_PARAM_<NAME> values for owned and tampered objects.",
		"missing-live-route-replay-proof": "Run workspace-route-replay-harness.mjs --live and promote only rows with status/body hash plus a control differential.",
	};
	const routeQueue = Array.isArray(routeRepair?.queue) ? routeRepair.queue : Array.isArray(routeReplay?.repairQueue) ? routeReplay.repairQueue : [];
	const repairQueue = [
		...routeQueue.slice(0, 80).map((row) => ({
			id: row.id ?? "workspace-route-repair-" + shortHash(`${row.claimId ?? ""}:${row.blocker ?? ""}:${row.route ?? ""}`),
			claimId: row.claimId ?? null,
			route: row.route ?? row.sourceBinding?.route ?? null,
			method: row.method ?? row.sourceBinding?.method ?? null,
			proofTargetId: row.proofTargetId ?? row.sourceBinding?.proofTargetId ?? null,
			blocker: row.blocker ?? "unknown-route-replay-blocker",
			action: row.action ?? repairActions[row.blocker] ?? "Drain route replay blocker and rerun claim promotion.",
			sourceBinding: row.sourceBinding ?? null,
			rerunCommand: row.rerunCommand ?? routePlan?.run ?? null,
		})),
		...blockers
			.filter((blocker) => !routeQueue.some((row) => row.blocker === blocker))
			.map((blocker) => ({
				id: "workspace-source-runtime-" + blocker,
				claimId: null,
				route: null,
				method: null,
				proofTargetId: null,
				blocker,
				action: repairActions[blocker] ?? "Collect missing source/runtime evidence and rerun claim promotion.",
				sourceBinding: { artifact: "workspace-source-runtime-claims.json" },
				rerunCommand: `repi engage ${shellQuote(target)} --json`,
			})),
	];
	return {
		kind: "repi-workspace-source-runtime-claims",
		schemaVersion: 1,
		target: redact(target),
		generatedAt: new Date().toISOString(),
		artifactFiles,
		counts: {
			routes: routeRows.length,
			proofTargets: proofTargets.length,
			sourceEdges: mapEdges.length,
			routeClaims: routeClaims.length,
			runtimeProofClaims: runtimeProofClaims.length,
		},
		proofReady: promotedClaims.length > 0,
		runtimeProofReady: runtimeProofClaims.length > 0,
		exploitProofReady: composedPaths.length > 0,
		claimLedger,
		composedPaths,
		promotionReport: {
			proofReady: promotedClaims.length > 0,
			runtimeProofReady: runtimeProofClaims.length > 0,
			exploitProofReady: composedPaths.length > 0,
			promotedClaims,
			observations: observationClaims,
			blockedClaims,
			blockers,
		},
		repairQueue,
	};
}

function writeWorkspaceSourceRuntimeClaims(artifactDir, target) {
	if (noWrite || !artifactDir) return undefined;
	const summary = workspaceSourceRuntimeClaims(target, artifactDir);
	const path = join(artifactDir, "workspace-source-runtime-claims.json");
	writePrivate(path, `${JSON.stringify(summary, null, 2)}\n`, 0o600);
	return { path, summary };
}

function workspaceSourceRuntimeRowsForVerification(map) {
	const rows = [];
	const push = (kind, row) => {
		if (!row?.file || !row?.line) return;
		rows.push({ kind, file: row.file, line: row.line, sample: row.sample ?? "", route: row.path ?? row.route?.path ?? null, method: row.method ?? row.route?.method ?? null, sinkKind: row.kind ?? null });
	};
	for (const row of map?.routes ?? []) push("route", row);
	for (const row of map?.authAnchors ?? []) push("auth", row);
	for (const row of map?.sinks ?? []) push("sink", row);
	for (const row of map?.stateMutations ?? []) push("state", row);
	for (const row of map?.signerCrypto ?? []) push("signer", row);
	const seen = new Set();
	return rows.filter((row) => {
		const key = `${row.kind}:${row.file}:${row.line}:${row.sample}`;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	}).slice(0, 260);
}

function workspaceSourceLineCheck(target, row) {
	const rootDir = resolve(target);
	const path = resolve(rootDir, row.file ?? "");
	if (path !== rootDir && !path.startsWith(`${rootDir}/`)) return { ...row, verified: false, error: "path-outside-target" };
	if (!existsSync(path)) return { ...row, verified: false, error: "missing-source-file" };
	let text = "";
	try {
		text = readFileSync(path, "utf8");
	} catch (error) {
		return { ...row, verified: false, error: error instanceof Error ? redact(error.message) : "read-failed" };
	}
	const lines = text.split(/\r?\n/);
	const lineText = lines[Number(row.line) - 1] ?? "";
	const directSample = lineText.trim().slice(0, 320);
	const actualSample = redact(lineText.trim().slice(0, 320));
	const sampleMatched = !row.sample || actualSample === row.sample || directSample === row.sample;
	return {
		...row,
		verified: Boolean(lineText) && sampleMatched,
		lineSha256: httpSecretHash(lineText),
		lineLength: lineText.length,
		sampleMatched,
	};
}

function workspaceSourceRuntimeVerificationSummary(target, artifactDir, claimsSummary) {
	const map = readJsonArtifact(join(artifactDir, "workspace-source-runtime-map.json"));
	const routePlan = readJsonArtifact(join(artifactDir, "workspace-route-replay-plan.json"));
	const routeReplay = readJsonArtifact(join(artifactDir, "workspace-route-replay-results.json"));
	const routePromotion = readJsonArtifact(join(artifactDir, "workspace-route-claim-promotion.json"));
	const routeRepair = readJsonArtifact(join(artifactDir, "workspace-route-repair-queue.json"));
	const claims = claimsSummary ?? readJsonArtifact(join(artifactDir, "workspace-source-runtime-claims.json"));
	const sourceRows = workspaceSourceRuntimeRowsForVerification(map);
	const sourceLineChecks = sourceRows.map((row) => workspaceSourceLineCheck(target, row));
	const sourceLineVerification = {
		verified: sourceLineChecks.length > 0 && sourceLineChecks.every((row) => row.verified),
		checkedRows: sourceLineChecks.length,
		verifiedRows: sourceLineChecks.filter((row) => row.verified).length,
		files: Array.from(new Set(sourceLineChecks.filter((row) => row.verified).map((row) => row.file))).slice(0, 80),
		kinds: Array.from(new Set(sourceLineChecks.filter((row) => row.verified).map((row) => row.kind))).sort(),
		mapSha256: map ? httpSecretHash(JSON.stringify(map)) : null,
	};
	const routeRows = map?.routes ?? [];
	const templates = map?.routeReplayTemplates ?? [];
	const proofTargets = map?.proofTargets ?? [];
	const templateChecks = routeRows.slice(0, 120).map((route) => {
		const expectedMethod = /^(ANY|ALL)$/i.test(route.method ?? "") ? "GET" : String(route.method ?? "GET").toUpperCase();
		const matched = templates.some((template) => template.route === route.path && String(template.method ?? "GET").toUpperCase() === expectedMethod);
		return { file: route.file, line: route.line, route: route.path, method: route.method, expectedMethod, matched };
	});
	const sourceRouteKeys = new Set(
		routeRows.map((row) => `${row.file}:${row.line}:${row.method}:${row.path}`),
	);
	const proofTargetChecks = proofTargets.map((row) => {
		const route = row.route ?? {};
		const expectedMethod = /^(ANY|ALL)$/i.test(route.method ?? "")
			? "GET"
			: String(route.method ?? "GET").toUpperCase();
		return {
			id: row.id ?? null,
			route: route.path ?? null,
			method: route.method ?? null,
			sourceRoutePresent: sourceRouteKeys.has(`${route.file}:${route.line}:${route.method}:${route.path}`),
			templatePresent: templates.some(
				(template) =>
					template.route === route.path &&
					String(template.method ?? "GET").toUpperCase() === expectedMethod,
			),
		};
	});
	const routeTemplateVerification = {
		verified:
			routeRows.length > 0 &&
			templateChecks.every((row) => row.matched) &&
			proofTargetChecks.every((row) => row.sourceRoutePresent && row.templatePresent),
		routeCount: routeRows.length,
		templateCount: templates.length,
		proofTargetCount: proofTargets.length,
		matchedRoutes: templateChecks.filter((row) => row.matched).length,
		templateChecks,
		proofTargetChecks,
	};
	const routeClaims = Array.isArray(routePromotion?.claimLedger) ? routePromotion.claimLedger : Array.isArray(routeReplay?.claimLedger) ? routeReplay.claimLedger : [];
	const liveRuntimeProofs = routeClaims.filter((claim) => claim.verdict === "promoted" && (claim.evidenceBinding?.variants ?? []).some((variant) => typeof variant.status === "number" && /^[a-f0-9]{64}$/i.test(String(variant.responseSha256 ?? ""))));
	const routeBlockers = Array.from(
		new Set([
			...routeClaims.flatMap((claim) => claim.blockers ?? []),
			...(Array.isArray(routeRepair?.queue) ? routeRepair.queue.map((row) => row.blocker).filter(Boolean) : []),
			...(Array.isArray(claims?.repairQueue) ? claims.repairQueue.map((row) => row.blocker).filter(Boolean) : []),
		]),
	).sort();
	const replayGateVerification = {
		verified:
			Boolean(routePlan?.proofExitRule) &&
			(routePlan?.controls ?? []).includes("tampered-object") &&
			(routePlan?.controls ?? []).some((control) => /anonymous/i.test(control)) &&
			(Boolean(liveRuntimeProofs.length) || Boolean(routePromotion?.baseUrlRequired || routeReplay?.baseUrlRequired || routeBlockers.length)),
		baseUrlRequired: Boolean(routePromotion?.baseUrlRequired || routeReplay?.baseUrlRequired),
		controls: routePlan?.controls ?? [],
		liveRuntimeProofs: liveRuntimeProofs.length,
		blockers: routeBlockers,
	};
	const repairQueueVerification = {
		verified: Boolean(liveRuntimeProofs.length) || routeBlockers.includes("missing-base-url") || routeBlockers.includes("missing-live-route-replay-proof"),
		repairCount: routeBlockers.length,
		blockers: routeBlockers,
		runtimeProofReady: Boolean(claims?.runtimeProofReady || liveRuntimeProofs.length),
		exploitProofReady: Boolean(claims?.exploitProofReady),
	};
	const firstSource = sourceLineChecks.find((row) => row.verified);
	const negativeControls = [];
	if (firstSource) {
		const missingSource = workspaceSourceLineCheck(target, {
			...firstSource,
			file: `${firstSource.file}.missing-control`,
		});
		negativeControls.push({
			controlType: "workspace-missing-source-negative-control",
			file: firstSource.file,
			missingSourceVerified: missingSource.verified,
			passed: !missingSource.verified,
		});
		const shifted = workspaceSourceLineCheck(target, { ...firstSource, line: Number(firstSource.line) + 10000 });
		negativeControls.push({ controlType: "workspace-shifted-line-negative-control", file: firstSource.file, passed: !shifted.verified });
	}
	const firstRoute = routeRows[0];
	if (firstRoute) {
		const mutatedRoute = { ...firstRoute, path: `${firstRoute.path}/__negative_control__` };
		const mutatedExpectedMethod = /^(ANY|ALL)$/i.test(mutatedRoute.method ?? "")
			? "GET"
			: String(mutatedRoute.method ?? "GET").toUpperCase();
		const mutatedTemplateMatched = templates.some(
			(template) =>
				template.route === mutatedRoute.path &&
				String(template.method ?? "GET").toUpperCase() === mutatedExpectedMethod,
		);
		negativeControls.push({
			controlType: "workspace-mutated-route-template-negative-control",
			route: firstRoute.path,
			mutatedTemplateMatched,
			passed: Boolean(routeTemplateVerification.verified && !mutatedTemplateMatched),
		});
	}
	const liveProofGateAccepts = (proofCount, blockers) =>
		proofCount > 0 || blockers.includes("missing-base-url") || blockers.includes("missing-live-route-replay-proof");
	const liveProofGateAccepted = liveProofGateAccepts(liveRuntimeProofs.length, routeBlockers);
	const mutatedLiveProofGateAccepted = liveProofGateAccepts(
		0,
		routeBlockers.filter((blocker) => !["missing-base-url", "missing-live-route-replay-proof"].includes(blocker)),
	);
	negativeControls.push({
		controlType: "workspace-live-proof-gate-negative-control",
		mutatedLiveProofGateAccepted,
		passed: liveProofGateAccepted && !mutatedLiveProofGateAccepted,
	});
	const negativeControlVerification = {
		verified: negativeControls.length >= 4 && negativeControls.every((row) => row.passed),
		negativeControlsPassed: negativeControls.filter((row) => row.passed).length,
		negativeControls,
	};
	const claimLedger = [];
	const composedPaths = [];
	const addClaim = (claim) => {
		const normalized = { verdict: "promoted", confidence: 0.76, blockers: [], ...claim };
		claimLedger.push(normalized);
		return normalized;
	};
	const sourceClaim = sourceLineVerification.verified
		? addClaim({
				id: "workspace-source-line-verification-" + shortHash(sourceLineVerification.files.join("|")),
				claimType: "workspace-source-line-verification-proof",
				sourceBinding: { artifact: "workspace-source-runtime-verification.json", map: "workspace-source-runtime-map.json" },
				evidenceBinding: sourceLineVerification,
				statement: "Workspace verifier rebound route/auth/sink/state/signer rows to exact source file lines and hashes.",
				confidence: 0.86,
				rerunCommand: "node workspace-source-runtime-verifier.mjs <workspace-dir> workspace-source-runtime-map.json workspace-route-replay-plan.json workspace-route-claim-promotion.json workspace-route-repair-queue.json workspace-source-runtime-claims.json workspace-source-runtime-verification.json",
			})
		: undefined;
	const templateClaim = routeTemplateVerification.verified
		? addClaim({
				id: "workspace-route-template-verification-" + shortHash(`${routeTemplateVerification.routeCount}:${routeTemplateVerification.templateCount}:${routeTemplateVerification.proofTargetCount}`),
				claimType: "workspace-route-template-verification-proof",
				sourceBinding: { artifact: "workspace-source-runtime-verification.json", map: "workspace-source-runtime-map.json" },
				evidenceBinding: routeTemplateVerification,
				statement: "Workspace verifier confirmed source routes have replay templates and risky routes have proof targets.",
				confidence: 0.84,
				rerunCommand: "node workspace-source-runtime-verifier.mjs <workspace-dir> workspace-source-runtime-map.json workspace-route-replay-plan.json workspace-route-claim-promotion.json workspace-route-repair-queue.json workspace-source-runtime-claims.json workspace-source-runtime-verification.json",
			})
		: undefined;
	const gateClaim = replayGateVerification.verified
		? addClaim({
				id: "workspace-replay-gate-verification-" + shortHash(JSON.stringify(replayGateVerification.blockers)),
				claimType: "workspace-replay-gate-verification-proof",
				sourceBinding: { artifact: "workspace-source-runtime-verification.json", plan: "workspace-route-replay-plan.json", promotion: "workspace-route-claim-promotion.json" },
				evidenceBinding: replayGateVerification,
				statement: "Workspace verifier confirmed replay proof gates require live status/body hashes or keep source-only claims blocked.",
				confidence: 0.82,
				rerunCommand: "node workspace-source-runtime-verifier.mjs <workspace-dir> workspace-source-runtime-map.json workspace-route-replay-plan.json workspace-route-claim-promotion.json workspace-route-repair-queue.json workspace-source-runtime-claims.json workspace-source-runtime-verification.json",
			})
		: undefined;
	const repairClaim = repairQueueVerification.verified
		? addClaim({
				id: "workspace-repair-queue-verification-" + shortHash(JSON.stringify(repairQueueVerification.blockers)),
				claimType: "workspace-repair-queue-verification-proof",
				sourceBinding: { artifact: "workspace-source-runtime-verification.json", claims: "workspace-source-runtime-claims.json", repairQueue: "workspace-route-repair-queue.json" },
				evidenceBinding: repairQueueVerification,
				statement: "Workspace verifier confirmed live-replay blockers remain in repairQueue until runtime proof exists.",
				confidence: 0.8,
				rerunCommand: "node workspace-source-runtime-verifier.mjs <workspace-dir> workspace-source-runtime-map.json workspace-route-replay-plan.json workspace-route-claim-promotion.json workspace-route-repair-queue.json workspace-source-runtime-claims.json workspace-source-runtime-verification.json",
			})
		: undefined;
	const negativeClaim = negativeControlVerification.verified
		? addClaim({
				id: "workspace-verifier-negative-control-" + shortHash(JSON.stringify(negativeControls)),
				claimType: "workspace-verifier-negative-control-proof",
				sourceBinding: { artifact: "workspace-source-runtime-verification.json" },
				evidenceBinding: negativeControlVerification,
				statement: "Workspace verifier rejected missing-source, shifted-line, mutated-route, and live-proof-gate controls.",
				confidence: 0.82,
				rerunCommand: "node workspace-source-runtime-verifier.mjs <workspace-dir> workspace-source-runtime-map.json workspace-route-replay-plan.json workspace-route-claim-promotion.json workspace-route-repair-queue.json workspace-source-runtime-claims.json workspace-source-runtime-verification.json",
			})
		: undefined;
	const runtimeProofReady = Boolean(liveRuntimeProofs.length && claims?.runtimeProofReady);
	if (sourceClaim && templateClaim && gateClaim && repairClaim && negativeClaim) {
		const segments = [sourceClaim, templateClaim, gateClaim, repairClaim, negativeClaim];
		const composed = {
			id: (runtimeProofReady ? "workspace-source-runtime-verification-proof-path-" : "workspace-source-runtime-verification-blocked-path-") + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: runtimeProofReady ? "workspace-source-runtime-verification-proof-path" : "workspace-source-runtime-verification-blocked-path",
			sourceBinding: { segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType, artifact: claim.sourceBinding?.artifact })) },
			evidenceBinding: {
				verifiedRows: sourceLineVerification.verifiedRows,
				matchedRoutes: routeTemplateVerification.matchedRoutes,
				liveRuntimeProofs: liveRuntimeProofs.length,
				negativeControlsPassed: negativeControlVerification.negativeControlsPassed,
			},
			statement: runtimeProofReady
				? "Workspace source-to-runtime proof path composes source lines, replay templates, live route replay hashes, and negative controls."
				: "Workspace verifier blocks exploit promotion until live route replay hashes and control differentials are captured.",
			verdict: runtimeProofReady ? "promoted" : "blocked",
			confidence: runtimeProofReady ? 0.88 : 0.52,
			blockers: runtimeProofReady ? [] : ["missing-workspace-live-route-replay-proof", ...routeBlockers].filter((value, index, list) => list.indexOf(value) === index),
			rerunCommand: routePlan?.run ?? "REPI_WORKSPACE_BASE_URL=http://127.0.0.1:PORT node workspace-route-replay-harness.mjs workspace-route-replay-results.json --live",
		};
		claimLedger.push(composed);
		composedPaths.push(composed);
	}
	const blockers = [];
	if (!sourceLineVerification.verified) blockers.push("missing-workspace-source-line-verification");
	if (!routeTemplateVerification.verified) blockers.push("missing-workspace-route-template-verification");
	if (!replayGateVerification.verified) blockers.push("missing-workspace-replay-gate-verification");
	if (!repairQueueVerification.verified) blockers.push("missing-workspace-repair-queue-verification");
	if (!runtimeProofReady) blockers.push("missing-workspace-live-route-replay-proof");
	if (!negativeControlVerification.verified) blockers.push("missing-workspace-negative-control");
	const repairActions = {
		"missing-workspace-source-line-verification": "Rerun workspace-source-runtime-harness.mjs and ensure source file/line samples still match current files.",
		"missing-workspace-route-template-verification": "Generate replay templates for every source route and proof targets for risky routes.",
		"missing-workspace-replay-gate-verification": "Regenerate route replay plan and claim promotion sidecars before proof promotion.",
		"missing-workspace-repair-queue-verification": "Keep route replay blockers queued until live status/body hash differentials exist.",
		"missing-workspace-live-route-replay-proof": "Start the service, set REPI_WORKSPACE_BASE_URL, and run workspace-route-replay-harness.mjs --live.",
		"missing-workspace-negative-control": "Run missing-source, shifted-line, mutated-route, and live-proof-gate controls.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "workspace-source-runtime-verification-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect verifier-bound workspace source/runtime evidence and rerun workspace-source-runtime-verifier.mjs.",
		rerunCommand: blocker === "missing-workspace-live-route-replay-proof" ? routePlan?.run ?? `REPI_WORKSPACE_BASE_URL=http://127.0.0.1:PORT node ${shellQuote(join(artifactDir, "workspace-route-replay-harness.mjs"))} ${shellQuote(join(artifactDir, "workspace-route-replay-results.json"))} --live` : `node ${shellQuote(join(artifactDir, "workspace-source-runtime-verifier.mjs"))} ${shellQuote(target)} ${shellQuote(join(artifactDir, "workspace-source-runtime-map.json"))} ${shellQuote(join(artifactDir, "workspace-route-replay-plan.json"))} ${shellQuote(join(artifactDir, "workspace-route-claim-promotion.json"))} ${shellQuote(join(artifactDir, "workspace-route-repair-queue.json"))} ${shellQuote(join(artifactDir, "workspace-source-runtime-claims.json"))} ${shellQuote(join(artifactDir, "workspace-source-runtime-verification.json"))}`,
	}));
	const promotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted");
	return {
		kind: "repi-workspace-source-runtime-verification",
		schemaVersion: 1,
		target: redact(target),
		generatedAt: new Date().toISOString(),
		proofReady: sourceLineVerification.verified && routeTemplateVerification.verified && replayGateVerification.verified,
		runtimeProofReady,
		exploitProofReady: runtimeProofReady && composedPaths.some((path) => path.verdict === "promoted"),
		sourceLineVerification,
		sourceLineChecks,
		routeTemplateVerification,
		replayGateVerification,
		repairQueueVerification,
		negativeControlVerification,
		stats: {
			checkedRows: sourceLineVerification.checkedRows,
			verifiedRows: sourceLineVerification.verifiedRows,
			matchedRoutes: routeTemplateVerification.matchedRoutes,
			liveRuntimeProofs: liveRuntimeProofs.length,
			negativeControlsPassed: negativeControlVerification.negativeControlsPassed,
		},
		claimLedger,
		composedPaths,
		promotionReport: { proofReady: promotedClaims.length > 0, runtimeProofReady, exploitProofReady: runtimeProofReady, promotedClaims, composedPaths: composedPaths.filter((path) => path.verdict === "promoted"), blockers },
		repairQueue,
	};
}

function workspaceSourceRuntimeVerifierSource() {
	return String.raw`#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { tmpdir } from "node:os";

const selfTest = process.argv.includes("--self-test");

function sha256(value) {
	return createHash("sha256").update(value ?? "").digest("hex");
}

function short(value) {
	return sha256(String(value)).slice(0, 12);
}

function redact(value) {
	return String(value ?? "")
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, "Bearer <redacted>")
		.replace(/([?&](?:api[_-]?key|token|access_token|refresh_token|client_secret|secret|password)=)[^&\s"'<>]{4,}/gi, "$1<redacted>")
		.replace(/(["']?(?:api[_-]?key|token|secret|password|client_secret|access_token|refresh_token|private_key|access_key)["']?\s*[:=]\s*["'])([^"']{4,})(["'])/gi, "$1<redacted>$3");
}

function load(path, fallback = null) {
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch {
		return fallback;
	}
}

function sourceRows(map) {
	const rows = [];
	const push = (kind, row) => {
		if (!row?.file || !row?.line) return;
		rows.push({ kind, file: row.file, line: row.line, sample: row.sample || "", route: row.path || row.route?.path || null, method: row.method || row.route?.method || null });
	};
	for (const row of map?.routes || []) push("route", row);
	for (const row of map?.authAnchors || []) push("auth", row);
	for (const row of map?.sinks || []) push("sink", row);
	for (const row of map?.stateMutations || []) push("state", row);
	for (const row of map?.signerCrypto || []) push("signer", row);
	const seen = new Set();
	return rows.filter((row) => {
		const key = row.kind + ":" + row.file + ":" + row.line + ":" + row.sample;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	}).slice(0, 260);
}

function lineCheck(root, row) {
	const rootDir = resolve(root);
	const path = resolve(rootDir, row.file || "");
	if (path !== rootDir && !path.startsWith(rootDir + "/")) return { ...row, verified: false, error: "path-outside-target" };
	if (!existsSync(path)) return { ...row, verified: false, error: "missing-source-file" };
	const text = readFileSync(path, "utf8");
	const lineText = text.split(/\r?\n/)[Number(row.line) - 1] || "";
	const directSample = lineText.trim().slice(0, 320);
	const sample = redact(lineText.trim().slice(0, 320));
	const sampleMatched = !row.sample || sample === row.sample || directSample === row.sample;
	return { ...row, verified: Boolean(lineText) && sampleMatched, lineSha256: sha256(lineText), lineLength: lineText.length, sampleMatched };
}

function verify(root, mapPath, planPath, promotionPath, repairPath, claimsPath) {
	const map = load(mapPath, {});
	const plan = load(planPath, {});
	const promotion = load(promotionPath, {});
	const repair = load(repairPath, {});
	const claims = load(claimsPath, {});
	const checks = sourceRows(map).map((row) => lineCheck(root, row));
	const sourceLineVerification = { verified: checks.length > 0 && checks.every((row) => row.verified), checkedRows: checks.length, verifiedRows: checks.filter((row) => row.verified).length, files: [...new Set(checks.filter((row) => row.verified).map((row) => row.file))], kinds: [...new Set(checks.filter((row) => row.verified).map((row) => row.kind))].sort(), mapSha256: sha256(JSON.stringify(map)) };
	const routes = map.routes || [];
	const templates = map.routeReplayTemplates || [];
	const proofTargets = map.proofTargets || [];
	const templateChecks = routes.slice(0, 120).map((route) => {
		const expectedMethod = /^(ANY|ALL)$/i.test(route.method || "") ? "GET" : String(route.method || "GET").toUpperCase();
		return { file: route.file, line: route.line, route: route.path, method: route.method, expectedMethod, matched: templates.some((template) => template.route === route.path && String(template.method || "GET").toUpperCase() === expectedMethod) };
	});
	const sourceRouteKeys = new Set(routes.map((route) => [route.file, route.line, route.method, route.path].join(":")));
	const proofTargetChecks = proofTargets.map((row) => {
		const route = row.route || {};
		const expectedMethod = /^(ANY|ALL)$/i.test(route.method || "") ? "GET" : String(route.method || "GET").toUpperCase();
		return { id: row.id || null, route: route.path || null, method: route.method || null, sourceRoutePresent: sourceRouteKeys.has([route.file, route.line, route.method, route.path].join(":")), templatePresent: templates.some((template) => template.route === route.path && String(template.method || "GET").toUpperCase() === expectedMethod) };
	});
	const routeTemplateVerification = { verified: routes.length > 0 && templateChecks.every((row) => row.matched) && proofTargetChecks.every((row) => row.sourceRoutePresent && row.templatePresent), routeCount: routes.length, templateCount: templates.length, proofTargetCount: proofTargets.length, matchedRoutes: templateChecks.filter((row) => row.matched).length, templateChecks, proofTargetChecks };
	const routeClaims = Array.isArray(promotion.claimLedger) ? promotion.claimLedger : [];
	const liveRuntimeProofs = routeClaims.filter((claim) => claim.verdict === "promoted" && (claim.evidenceBinding?.variants || []).some((variant) => typeof variant.status === "number" && /^[a-f0-9]{64}$/i.test(String(variant.responseSha256 || ""))));
	const routeBlockers = [...new Set([...routeClaims.flatMap((claim) => claim.blockers || []), ...(repair.queue || []).map((row) => row.blocker).filter(Boolean), ...(claims.repairQueue || []).map((row) => row.blocker).filter(Boolean)])].sort();
	const replayGateVerification = { verified: Boolean(plan.proofExitRule) && (plan.controls || []).includes("tampered-object") && (plan.controls || []).some((control) => /anonymous/i.test(control)) && (Boolean(liveRuntimeProofs.length) || Boolean(promotion.baseUrlRequired || routeBlockers.length)), baseUrlRequired: Boolean(promotion.baseUrlRequired), controls: plan.controls || [], liveRuntimeProofs: liveRuntimeProofs.length, blockers: routeBlockers };
	const repairQueueVerification = { verified: Boolean(liveRuntimeProofs.length) || routeBlockers.includes("missing-base-url") || routeBlockers.includes("missing-live-route-replay-proof"), repairCount: routeBlockers.length, blockers: routeBlockers, runtimeProofReady: Boolean(claims.runtimeProofReady || liveRuntimeProofs.length), exploitProofReady: Boolean(claims.exploitProofReady) };
	const controls = [];
	const first = checks.find((row) => row.verified);
	if (first) {
		const missingSource = lineCheck(root, { ...first, file: first.file + ".missing-control" });
		controls.push({ controlType: "workspace-missing-source-negative-control", file: first.file, missingSourceVerified: missingSource.verified, passed: !missingSource.verified });
		controls.push({ controlType: "workspace-shifted-line-negative-control", file: first.file, passed: !lineCheck(root, { ...first, line: Number(first.line) + 10000 }).verified });
	}
	if (routes[0]) {
		const mutatedRoute = { ...routes[0], path: routes[0].path + "/__negative_control__" };
		const mutatedExpectedMethod = /^(ANY|ALL)$/i.test(mutatedRoute.method || "") ? "GET" : String(mutatedRoute.method || "GET").toUpperCase();
		const mutatedTemplateMatched = templates.some((template) => template.route === mutatedRoute.path && String(template.method || "GET").toUpperCase() === mutatedExpectedMethod);
		controls.push({ controlType: "workspace-mutated-route-template-negative-control", route: routes[0].path, mutatedTemplateMatched, passed: Boolean(routeTemplateVerification.verified && !mutatedTemplateMatched) });
	}
	const liveProofGateAccepts = (proofCount, blockers) => proofCount > 0 || blockers.includes("missing-base-url") || blockers.includes("missing-live-route-replay-proof");
	const liveProofGateAccepted = liveProofGateAccepts(liveRuntimeProofs.length, routeBlockers);
	const mutatedLiveProofGateAccepted = liveProofGateAccepts(0, routeBlockers.filter((blocker) => !["missing-base-url", "missing-live-route-replay-proof"].includes(blocker)));
	controls.push({ controlType: "workspace-live-proof-gate-negative-control", mutatedLiveProofGateAccepted, passed: liveProofGateAccepted && !mutatedLiveProofGateAccepted });
	const negativeControlVerification = { verified: controls.length >= 4 && controls.every((row) => row.passed), negativeControlsPassed: controls.filter((row) => row.passed).length, negativeControls: controls };
	const ledger = [];
	const paths = [];
	const add = (claim) => {
		const row = { verdict: "promoted", confidence: 0.76, blockers: [], ...claim };
		ledger.push(row);
		return row;
	};
	const sourceClaim = sourceLineVerification.verified ? add({ id: "workspace-source-line-verification-" + short(sourceLineVerification.files.join("|")), claimType: "workspace-source-line-verification-proof", sourceBinding: { artifact: "workspace-source-runtime-verification.json", map: "workspace-source-runtime-map.json" }, evidenceBinding: sourceLineVerification, statement: "Workspace verifier rebound route/auth/sink/state/signer rows to exact source file lines and hashes.", confidence: 0.86 }) : null;
	const templateClaim = routeTemplateVerification.verified ? add({ id: "workspace-route-template-verification-" + short(routeTemplateVerification.routeCount + ":" + routeTemplateVerification.templateCount), claimType: "workspace-route-template-verification-proof", sourceBinding: { artifact: "workspace-source-runtime-verification.json", map: "workspace-source-runtime-map.json" }, evidenceBinding: routeTemplateVerification, statement: "Workspace verifier confirmed source routes have replay templates and risky routes have proof targets.", confidence: 0.84 }) : null;
	const gateClaim = replayGateVerification.verified ? add({ id: "workspace-replay-gate-verification-" + short(JSON.stringify(routeBlockers)), claimType: "workspace-replay-gate-verification-proof", sourceBinding: { artifact: "workspace-source-runtime-verification.json", plan: "workspace-route-replay-plan.json" }, evidenceBinding: replayGateVerification, statement: "Workspace verifier confirmed replay proof gates require live status/body hashes or keep source-only claims blocked.", confidence: 0.82 }) : null;
	const repairClaim = repairQueueVerification.verified ? add({ id: "workspace-repair-queue-verification-" + short(JSON.stringify(routeBlockers)), claimType: "workspace-repair-queue-verification-proof", sourceBinding: { artifact: "workspace-source-runtime-verification.json", claims: "workspace-source-runtime-claims.json" }, evidenceBinding: repairQueueVerification, statement: "Workspace verifier confirmed live-replay blockers remain in repairQueue until runtime proof exists.", confidence: 0.8 }) : null;
	const negativeClaim = negativeControlVerification.verified ? add({ id: "workspace-verifier-negative-control-" + short(JSON.stringify(controls)), claimType: "workspace-verifier-negative-control-proof", sourceBinding: { artifact: "workspace-source-runtime-verification.json" }, evidenceBinding: negativeControlVerification, statement: "Workspace verifier rejected missing-source, shifted-line, mutated-route, and live-proof-gate controls.", confidence: 0.82 }) : null;
	const runtimeProofReady = Boolean(liveRuntimeProofs.length && claims.runtimeProofReady);
	if (sourceClaim && templateClaim && gateClaim && repairClaim && negativeClaim) {
		const segments = [sourceClaim, templateClaim, gateClaim, repairClaim, negativeClaim];
		const path = { id: (runtimeProofReady ? "workspace-source-runtime-verification-proof-path-" : "workspace-source-runtime-verification-blocked-path-") + short(segments.map((claim) => claim.id).join(">")), claimType: runtimeProofReady ? "workspace-source-runtime-verification-proof-path" : "workspace-source-runtime-verification-blocked-path", sourceBinding: { segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType, artifact: claim.sourceBinding?.artifact })) }, evidenceBinding: { verifiedRows: sourceLineVerification.verifiedRows, matchedRoutes: routeTemplateVerification.matchedRoutes, liveRuntimeProofs: liveRuntimeProofs.length, negativeControlsPassed: negativeControlVerification.negativeControlsPassed }, statement: runtimeProofReady ? "Workspace source-to-runtime proof path composes source lines, replay templates, live route replay hashes, and negative controls." : "Workspace verifier blocks exploit promotion until live route replay hashes and control differentials are captured.", verdict: runtimeProofReady ? "promoted" : "blocked", confidence: runtimeProofReady ? 0.88 : 0.52, blockers: runtimeProofReady ? [] : [...new Set(["missing-workspace-live-route-replay-proof", ...routeBlockers])], rerunCommand: plan.run || "REPI_WORKSPACE_BASE_URL=http://127.0.0.1:PORT node workspace-route-replay-harness.mjs workspace-route-replay-results.json --live" };
		ledger.push(path);
		paths.push(path);
	}
	const blockers = [];
	if (!sourceLineVerification.verified) blockers.push("missing-workspace-source-line-verification");
	if (!routeTemplateVerification.verified) blockers.push("missing-workspace-route-template-verification");
	if (!replayGateVerification.verified) blockers.push("missing-workspace-replay-gate-verification");
	if (!repairQueueVerification.verified) blockers.push("missing-workspace-repair-queue-verification");
	if (!runtimeProofReady) blockers.push("missing-workspace-live-route-replay-proof");
	if (!negativeControlVerification.verified) blockers.push("missing-workspace-negative-control");
	return { kind: "repi-workspace-source-runtime-verification", schemaVersion: 1, generatedAt: new Date().toISOString(), proofReady: sourceLineVerification.verified && routeTemplateVerification.verified && replayGateVerification.verified, runtimeProofReady, exploitProofReady: runtimeProofReady && paths.some((path) => path.verdict === "promoted"), sourceLineVerification, sourceLineChecks: checks, routeTemplateVerification, replayGateVerification, repairQueueVerification, negativeControlVerification, stats: { checkedRows: sourceLineVerification.checkedRows, verifiedRows: sourceLineVerification.verifiedRows, matchedRoutes: routeTemplateVerification.matchedRoutes, liveRuntimeProofs: liveRuntimeProofs.length, negativeControlsPassed: negativeControlVerification.negativeControlsPassed }, claimLedger: ledger, composedPaths: paths, promotionReport: { proofReady: ledger.some((claim) => claim.verdict === "promoted"), runtimeProofReady, exploitProofReady: runtimeProofReady, promotedClaims: ledger.filter((claim) => claim.verdict === "promoted"), composedPaths: paths.filter((path) => path.verdict === "promoted"), blockers }, repairQueue: blockers.map((blocker) => ({ id: "workspace-source-runtime-verification-" + blocker, blocker, action: blocker === "missing-workspace-live-route-replay-proof" ? "Start the service, set REPI_WORKSPACE_BASE_URL, and run workspace-route-replay-harness.mjs --live." : "Collect verifier-bound workspace source/runtime evidence and rerun workspace-source-runtime-verifier.mjs.", rerunCommand: blocker === "missing-workspace-live-route-replay-proof" ? (plan.run || "REPI_WORKSPACE_BASE_URL=http://127.0.0.1:PORT node workspace-route-replay-harness.mjs workspace-route-replay-results.json --live") : "node workspace-source-runtime-verifier.mjs <workspace-dir> workspace-source-runtime-map.json workspace-route-replay-plan.json workspace-route-claim-promotion.json workspace-route-repair-queue.json workspace-source-runtime-claims.json workspace-source-runtime-verification.json" })) };
}

function writeJson(path, value) {
	writeFileSync(path, JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
}

function runSelfTest() {
	const root = tmpdir() + "/repi-workspace-verifier-" + Date.now() + "-" + process.pid;
	mkdirSync(root + "/src", { recursive: true });
	const source = ["const express = require('express');", "const app = express();", "app.post('/api/admin/run', (req,res)=> child_process.exec(req.body.cmd));", "function signRequest(params){ return crypto.createHash('md5').update(Object.keys(params).sort().join('&') + secret).digest('hex') }"].join("\n");
	writeFileSync(root + "/src/server.js", source);
	const routeLine = source.split(/\r?\n/)[2].trim().slice(0, 320);
	const signerLine = source.split(/\r?\n/)[3].trim().slice(0, 320);
	const map = { routes: [{ kind: "express-router", method: "POST", path: "/api/admin/run", file: "src/server.js", line: 3, sample: routeLine }], authAnchors: [], sinks: [{ kind: "command-exec", file: "src/server.js", line: 3, sample: routeLine }], stateMutations: [], signerCrypto: [{ kind: "signature", file: "src/server.js", line: 4, sample: signerLine }], proofTargets: [{ id: "route-proof-test", route: { file: "src/server.js", line: 3, method: "POST", path: "/api/admin/run" }, risks: ["route-to-dangerous-sink-candidate"] }], routeReplayTemplates: [{ route: "/api/admin/run", method: "POST", negativeControls: ["repeat without Cookie/Authorization", "mutate numeric/uuid object identifiers when present"] }] };
	const plan = { controls: ["anonymous", "tampered-object"], proofExitRule: "anonymous/session differential", run: "REPI_WORKSPACE_BASE_URL=http://127.0.0.1:PORT node workspace-route-replay-harness.mjs workspace-route-replay-results.json --live" };
	const promotion = { baseUrlRequired: true, proofReady: false, claimLedger: [{ id: "blocked", verdict: "blocked", blockers: ["missing-base-url"] }] };
	const repair = { queue: [{ blocker: "missing-base-url" }] };
	const claims = { proofReady: true, runtimeProofReady: false, exploitProofReady: false, repairQueue: [{ blocker: "missing-base-url" }, { blocker: "missing-live-route-replay-proof" }] };
	writeJson(root + "/map.json", map);
	writeJson(root + "/plan.json", plan);
	writeJson(root + "/promotion.json", promotion);
	writeJson(root + "/repair.json", repair);
	writeJson(root + "/claims.json", claims);
	const report = verify(root, root + "/map.json", root + "/plan.json", root + "/promotion.json", root + "/repair.json", root + "/claims.json");
	if (!report.proofReady || report.runtimeProofReady || !report.repairQueue.some((row) => row.blocker === "missing-workspace-live-route-replay-proof")) throw new Error(JSON.stringify(report));
	console.log(JSON.stringify({ kind: "repi-workspace-source-runtime-verifier-self-test", status: "ok", stats: report.stats }, null, 2));
}

if (selfTest) {
	runSelfTest();
} else {
	const [, , root = ".", mapPath = "workspace-source-runtime-map.json", planPath = "workspace-route-replay-plan.json", promotionPath = "workspace-route-claim-promotion.json", repairPath = "workspace-route-repair-queue.json", claimsPath = "workspace-source-runtime-claims.json", outputPath = "workspace-source-runtime-verification.json"] = process.argv;
	const report = verify(root, mapPath, planPath, promotionPath, repairPath, claimsPath);
	writeJson(outputPath, report);
	console.log(JSON.stringify({ kind: report.kind, proofReady: report.proofReady, runtimeProofReady: report.runtimeProofReady, stats: report.stats, output: outputPath }));
	process.exit(report.proofReady ? 0 : 1);
}
`;
}

function writeWorkspaceSourceRuntimeVerifier(artifactDir) {
	if (noWrite || !artifactDir) return undefined;
	const path = join(artifactDir, "workspace-source-runtime-verifier.mjs");
	writePrivate(path, workspaceSourceRuntimeVerifierSource(), 0o700);
	return path;
}

function writeWorkspaceSourceRuntimeVerification(artifactDir, target, claimsSummary) {
	if (noWrite || !artifactDir) return undefined;
	const summary = workspaceSourceRuntimeVerificationSummary(target, artifactDir, claimsSummary);
	const path = join(artifactDir, "workspace-source-runtime-verification.json");
	writePrivate(path, `${JSON.stringify(summary, null, 2)}\n`, 0o600);
	return { path, summary };
}

export {
	writeJsReverseWorkbench,
	writeWorkspaceRouteReplayHarness,
	writeWorkspaceSourceRuntimeClaims,
	writeWorkspaceSourceRuntimeHarness,
	writeWorkspaceSourceRuntimeVerification,
	writeWorkspaceSourceRuntimeVerifier,
};
