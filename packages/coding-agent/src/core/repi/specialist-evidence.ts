import { shellQuote } from "./target.ts";
import { interestingLines, truncateMiddle, uniqueMatches } from "./text.ts";

type LaneCommand = {
	label: string;
	command: string;
	evidence: string;
};

type LaneCommandPack = {
	route: string;
	target?: string;
	commands: LaneCommand[];
	notes: string[];
};

function pythonString(value: string): string {
	return JSON.stringify(value);
}

function packHasSpecialistSignal(pack: LaneCommandPack, pattern: RegExp): boolean {
	return (
		pack.commands.some((command) => pattern.test(`${command.label}\n${command.evidence}\n${command.command}`)) ||
		pack.notes.some((note) => pattern.test(note))
	);
}

export type SpecialistEvidenceAnalysis = {
	findings: string[];
	followups: LaneCommand[];
	nextLane?: string;
};

export function mergeSpecialistEvidenceAnalysis(
	analysis: SpecialistEvidenceAnalysis,
	findings: string[],
	followups: LaneCommand[],
): string | undefined {
	for (const finding of analysis.findings) {
		if (!findings.includes(finding)) findings.push(finding);
	}
	for (const followup of analysis.followups) {
		if (!followups.some((command) => command.label === followup.label && command.command === followup.command)) {
			followups.push(followup);
		}
	}
	return analysis.nextLane;
}

export function analyzeBrowserXhrWsEvidence(
	pack: LaneCommandPack,
	combined: string,
	targetArg: string,
): SpecialistEvidenceAnalysis {
	const enabled =
		/web|api/.test(pack.route.toLowerCase()) || packHasSpecialistSignal(pack, /browser-xhr-ws|browser\/XHR\/WS/i);
	if (!enabled) return { findings: [], followups: [] };
	const findings: string[] = [];
	const followups: LaneCommand[] = [];
	const runtimeLines = interestingLines(
		combined,
		/\[request\]|\[response\]|\[websocket\]|\[cookies\]|\[localStorage\]|\[sessionStorage\]|\[cdp-request\]|\[cdp-response\]|\[cdp-ws\]|\[browser-artifact\]|\[storage-snapshot\]|\[replay-eval\]|set-cookie|authorization|bearer|csrf|jwt|status:/i,
		20,
	);
	if (runtimeLines.length > 0) {
		findings.push(
			`browser/XHR/WS runtime anchors: ${runtimeLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const websocketAnchors = uniqueMatches(combined, /\[websocket\]\s+(\S+)/gi, 8);
	if (websocketAnchors.length > 0) findings.push(`websocket endpoint anchors: ${websocketAnchors.join(", ")}`);
	const storageAnchors = interestingLines(
		combined,
		/\[cookies\]|\[localStorage\]|\[sessionStorage\]|access_token|refresh_token|session|jwt/i,
		8,
	);
	if (storageAnchors.length > 0) {
		findings.push(`cookie/storage anchors: ${storageAnchors.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
	}
	const cdpLines = interestingLines(
		combined,
		/\[cdp-request\]|\[cdp-response\]|\[cdp-ws\]|\[browser-artifact\]|\[storage-snapshot\]/i,
		18,
	);
	if (cdpLines.length > 0) {
		findings.push(`browser CDP artifact anchors: ${cdpLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
	}
	const artifactAnchors = uniqueMatches(combined, /\[browser-artifact\]\s+(\S+)/gi, 6);
	if (artifactAnchors.length > 0) findings.push(`browser runtime artifact paths: ${artifactAnchors.join(", ")}`);
	const replayLines = interestingLines(combined, /\[replay-eval\]/i, 10);
	if (replayLines.length > 0) {
		findings.push(
			`browser replay evaluator anchors: ${replayLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	const routeGraphLines = interestingLines(combined, /\[route-graph\]|\[route-node\]/i, 18);
	if (routeGraphLines.length > 0) {
		findings.push(
			`browser route graph anchors: ${routeGraphLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	const authMatrixLines = interestingLines(combined, /\[auth-matrix\]/i, 14);
	if (authMatrixLines.length > 0) {
		findings.push(
			`browser auth matrix anchors: ${authMatrixLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	const idorProbeLines = interestingLines(combined, /\[idor-candidate\]|\[idor-probe\]|IDOR|BOLA/i, 16);
	if (idorProbeLines.length > 0) {
		findings.push(
			`browser IDOR/BOLA probe anchors: ${idorProbeLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	const authzStateLines = interestingLines(combined, /\[authz-state\]|\[authz-state-machine\]/i, 20);
	if (authzStateLines.length > 0) {
		findings.push(
			`browser authz state machine anchors: ${authzStateLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	const authzSequenceLines = interestingLines(combined, /\[authz-sequence\]|\[authz-sequence-artifact\]/i, 16);
	if (authzSequenceLines.length > 0) {
		findings.push(
			`browser authz sequence replay anchors: ${authzSequenceLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	const authzOwnershipLines = interestingLines(combined, /\[authz-ownership\]|\[authz-ownership-candidate\]/i, 18);
	if (authzOwnershipLines.length > 0) {
		findings.push(
			`browser authz object ownership anchors: ${authzOwnershipLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	const authzRollbackLines = interestingLines(combined, /\[authz-rollback\]/i, 12);
	if (authzRollbackLines.length > 0) {
		findings.push(
			`browser authz state rollback anchors: ${authzRollbackLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	const webAuthzStaticLines = interestingLines(
		combined,
		/\[web-authz-static\]|\[web-authz-risk\]|\[web-authz-static-summary\]/i,
		22,
	);
	if (webAuthzStaticLines.length > 0) {
		findings.push(
			`web API static authz source anchors: ${webAuthzStaticLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	const webSchemaLines = interestingLines(
		combined,
		/\[web-schema\]|\[web-schema-route\]|\[web-schema-risk\]|\[web-schema-graphql\]/i,
		22,
	);
	if (webSchemaLines.length > 0) {
		findings.push(
			`web API schema/auth parameter anchors: ${webSchemaLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	const webStateSourceLines = interestingLines(combined, /\[web-state-source\]|\[web-state-risk\]/i, 22);
	if (webStateSourceLines.length > 0) {
		findings.push(
			`web API state mutation source anchors: ${webStateSourceLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	if (pack.target && /^https?:\/\//i.test(pack.target)) {
		followups.push({
			label: "browser-xhr-ws-auth-diff-rerun",
			command: `[ -x /tmp/repi-auth-diff.sh ] && /tmp/repi-auth-diff.sh ${targetArg} "\${COOKIE_A:-}" "\${COOKIE_B:-}" || printf '%s\n' 'set COOKIE_A/COOKIE_B and rerun auth-diff scaffold for two principals'`,
			evidence: "repeat browser/XHR/WS auth boundary diff with concrete principal cookies",
		});
		followups.push({
			label: "browser-xhr-ws-capture-rerun",
			command: `[ -f /tmp/repi-browser-xhr-ws.mjs ] && node /tmp/repi-browser-xhr-ws.mjs ${targetArg} || printf '%s\n' 'rerun re_lane plan to regenerate Playwright capture scaffold'`,
			evidence: "repeat browser runtime capture after route/auth hypotheses are narrowed",
		});
		followups.push({
			label: "browser-cdp-artifact-rerun",
			command: `[ -f /tmp/repi-browser-cdp-artifact.mjs ] && node /tmp/repi-browser-cdp-artifact.mjs ${targetArg} /tmp/repi-browser-artifact.json || printf '%s\n' 'rerun re_lane plan to regenerate CDP artifact scaffold'`,
			evidence: "repeat CDP-backed browser artifact capture with request/response/WS/storage serialization",
		});
		followups.push({
			label: "browser-replay-eval-rerun",
			command: `[ -f /tmp/repi-replay-eval.mjs ] && [ -f /tmp/repi-browser-artifact.json ] && node /tmp/repi-replay-eval.mjs /tmp/repi-browser-artifact.json || printf '%s\n' 'capture /tmp/repi-browser-artifact.json before replay evaluation'`,
			evidence: "evaluate whether captured browser request replays with matching status/body drift",
		});
		followups.push({
			label: "browser-route-graph-rerun",
			command: `[ -f /tmp/repi-route-graph.mjs ] && node /tmp/repi-route-graph.mjs /tmp/repi-browser-artifact.json ${targetArg} || printf '%s\n' 'rerun browser-route-graph-scaffold after CDP artifact capture'`,
			evidence: "regenerate normalized route graph from latest browser artifact",
		});
		followups.push({
			label: "browser-auth-matrix-rerun",
			command: `[ -f /tmp/repi-auth-matrix.mjs ] && COOKIE_A="\${COOKIE_A:-}" COOKIE_B="\${COOKIE_B:-}" AUTH_A="\${AUTH_A:-}" AUTH_B="\${AUTH_B:-}" node /tmp/repi-auth-matrix.mjs ${targetArg} || printf '%s\n' 'rerun browser-auth-matrix-scaffold and set principal cookies/tokens'`,
			evidence: "compare anonymous/principal-A/principal-B authorization boundaries per route",
		});
		followups.push({
			label: "browser-idor-bola-probe-rerun",
			command: `[ -f /tmp/repi-idor-bola-probe.mjs ] && REPI_IDOR_BASELINE="\${REPI_IDOR_BASELINE:-}" REPI_IDOR_ALT="\${REPI_IDOR_ALT:-}" COOKIE_A="\${COOKIE_A:-}" AUTH_A="\${AUTH_A:-}" node /tmp/repi-idor-bola-probe.mjs || printf '%s\n' 'generate route graph and set REPI_IDOR_BASELINE/REPI_IDOR_ALT for controlled object diff'`,
			evidence: "rerun controlled IDOR/BOLA alternate-object probe using route graph candidates",
		});
		followups.push({
			label: "browser-authz-state-machine-rerun",
			command: `[ -f /tmp/repi-authz-state-machine.mjs ] && COOKIE_A="\${COOKIE_A:-}" COOKIE_B="\${COOKIE_B:-}" AUTH_A="\${AUTH_A:-}" AUTH_B="\${AUTH_B:-}" node /tmp/repi-authz-state-machine.mjs ${targetArg} || printf '%s\n' 'rerun browser-authz-state-machine-scaffold and attach principal cookies/tokens'`,
			evidence: "rerun multi-principal authorization state machine across captured routes",
		});
		followups.push({
			label: "browser-authz-sequence-replay-rerun",
			command: `[ -f /tmp/repi-authz-sequence-replay.mjs ] && COOKIE_A="\${COOKIE_A:-}" COOKIE_B="\${COOKIE_B:-}" AUTH_A="\${AUTH_A:-}" AUTH_B="\${AUTH_B:-}" node /tmp/repi-authz-sequence-replay.mjs ${targetArg} || printf '%s\n' 'rerun browser-authz-sequence-replay-scaffold after route graph capture'`,
			evidence: "rerun authorization-sensitive request sequence for status/body-hash drift",
		});
		followups.push({
			label: "browser-authz-object-ownership-rerun",
			command: `[ -f /tmp/repi-authz-object-ownership.mjs ] && REPI_OWNER_URL="\${REPI_OWNER_URL:-}" COOKIE_A="\${COOKIE_A:-}" COOKIE_B="\${COOKIE_B:-}" AUTH_A="\${AUTH_A:-}" AUTH_B="\${AUTH_B:-}" node /tmp/repi-authz-object-ownership.mjs ${targetArg} || printf '%s\n' 'set REPI_OWNER_URL plus principal cookies/tokens before ownership check'`,
			evidence: "rerun owner-vs-alternate-principal object authorization check",
		});
		followups.push({
			label: "browser-authz-state-rollback-rerun",
			command: `[ -f /tmp/repi-authz-state-rollback.mjs ] && REPI_ROLLBACK_URL="\${REPI_ROLLBACK_URL:-}" REPI_ROLLBACK_BODY="\${REPI_ROLLBACK_BODY:-}" REPI_ROLLBACK_RESTORE_BODY="\${REPI_ROLLBACK_RESTORE_BODY:-}" COOKIE_A="\${COOKIE_A:-}" AUTH_A="\${AUTH_A:-}" node /tmp/repi-authz-state-rollback.mjs ${targetArg} || printf '%s\n' 'set rollback URL/body/restore body to prove state transition and cleanup'`,
			evidence: "rerun state-changing authorization proof with before/after/rollback hashes",
		});
	}
	if (artifactAnchors.length > 0) {
		const artifactPath = artifactAnchors[0] ?? "/tmp/repi-browser-artifact.json";
		followups.push({
			label: "browser-cdp-artifact-review",
			command: `python3 - <<'PY'\nimport json, pathlib\np = pathlib.Path(${pythonString(artifactPath)})\nprint('[browser-artifact-review]', p)\nobj = json.loads(p.read_text())\nprint('requests=', len(obj.get('requests', [])), 'responses=', len(obj.get('responses', [])), 'websockets=', len(obj.get('websockets', [])), 'wsFrames=', len(obj.get('wsFrames', [])), 'cookies=', len(obj.get('cookies', [])))\nfor req in obj.get('requests', [])[:12]:\n    print('REQ', req.get('method'), req.get('url'), 'type=' + str(req.get('resourceType')), 'initiator=' + str(req.get('initiator')))\nfor res in obj.get('responses', [])[:12]:\n    print('RES', res.get('status'), res.get('url'), res.get('mimeType'))\nprint('storage=', json.dumps(obj.get('storage', {}), ensure_ascii=False)[:1200])\nPY`,
			evidence: "review serialized CDP artifact for replayable requests, auth/session storage, and websocket frames",
		});
		followups.push({
			label: "browser-replay-eval-artifact-rerun",
			command: `[ -f /tmp/repi-replay-eval.mjs ] && node /tmp/repi-replay-eval.mjs ${shellQuote(artifactPath)} || printf '%s\n' 'rerun browser-replay-evaluator-scaffold first'`,
			evidence: "replay evaluator bound to captured browser artifact path",
		});
	}
	if (
		routeGraphLines.length > 0 ||
		authMatrixLines.length > 0 ||
		idorProbeLines.length > 0 ||
		authzStateLines.length > 0 ||
		authzSequenceLines.length > 0 ||
		authzOwnershipLines.length > 0 ||
		authzRollbackLines.length > 0 ||
		webAuthzStaticLines.length > 0 ||
		webSchemaLines.length > 0 ||
		webStateSourceLines.length > 0
	) {
		followups.push({
			label: "web-api-authz-static-rerun",
			command:
				"python3 - <<'PY'\nprint('[web-authz-static-rerun] rerun web-api-authz-static-scaffold via re_lane plan/run; then bind risky id lookup to browser auth matrix or source-level guard proof')\nPY",
			evidence: "rerun or review static route/auth/owner scanner and bind risks to runtime authz probes",
		});
		followups.push({
			label: "web-api-schema-diff-rerun",
			command:
				"python3 - <<'PY'\nprint('[web-schema-rerun] rerun web-api-schema-diff-scaffold; compare id_params/security rows with route graph and auth matrix')\nPY",
			evidence: "rerun OpenAPI/GraphQL auth parameter scanner and compare with captured route graph",
		});
		followups.push({
			label: "web-api-state-source-rerun",
			command:
				"python3 - <<'PY'\nprint('[web-state-source-rerun] rerun web-api-state-source-scaffold; prove one mutating route with before/after/rollback hashes')\nPY",
			evidence: "rerun state mutation source scanner and bridge to rollback proof",
		});
		followups.push({
			label: "browser-authz-report-scaffold",
			command: `python3 - <<'PY'\nimport json, pathlib\nprint('[authz-report] inputs=/tmp/repi-route-graph.json /tmp/repi-browser-artifact.json')\nif pathlib.Path('/tmp/repi-route-graph.json').exists():\n    graph=json.loads(pathlib.Path('/tmp/repi-route-graph.json').read_text())\n    print('[authz-report] routes=', len(graph), 'idor_candidates=', sum(len(r.get('idorParams', [])) for r in graph))\n    for r in graph[:20]: print('ROUTE', r.get('method'), r.get('path'), 'auth=' + str(r.get('auth')), 'idor=' + ','.join(r.get('idorParams', [])))\nprint('Next: attach COOKIE_A/COOKIE_B or AUTH_A/AUTH_B, rerun browser-auth-matrix-rerun, then set REPI_IDOR_BASELINE/ALT for one candidate.')\nPY`,
			evidence: "authz report scaffold consolidating route graph, auth matrix, and IDOR/BOLA candidates",
		});
		followups.push({
			label: "browser-authz-state-report-scaffold",
			command: `python3 - <<'PY'\nimport json, pathlib\npaths=[\n  '/tmp/repi-authz-state-machine.json',\n  '/tmp/repi-authz-sequence.json',\n  '/tmp/repi-authz-ownership.json',\n  '/tmp/repi-authz-rollback.json',\n]\nprint('[authz-state-report] inputs=' + ' '.join(paths))\nfor raw in paths:\n    p=pathlib.Path(raw)\n    print('[authz-state-report]', raw, 'exists=' + str(p.exists()))\n    if not p.exists(): continue\n    obj=json.loads(p.read_text())\n    if raw.endswith('state-machine.json'):\n        print('STATE_MACHINE principals=', ','.join(obj.get('principals', [])), 'routes=', len(obj.get('routes', [])), 'states=', len(obj.get('states', [])))\n    elif raw.endswith('sequence.json'):\n        print('SEQUENCE steps=', len(obj.get('sequence', [])), 'runs=', len(obj.get('runs', [])))\n    elif raw.endswith('ownership.json'):\n        print('OWNERSHIP route=', obj.get('route'), 'potential_bola=', obj.get('potentialBola'), 'sameBody=', obj.get('sameBody'))\n    elif raw.endswith('rollback.json'):\n        print('ROLLBACK method=', obj.get('method'), 'restored=', obj.get('restored'), 'before=', obj.get('before', {}).get('hash'), 'after=', obj.get('after', {}).get('hash'))\nprint('Next: promote confirmed authz-state/ownership/rollback deltas into a minimal repro script with principal fixtures.')\nPY`,
			evidence:
				"browser authz state report consolidating state machine, sequence, ownership, and rollback artifacts",
		});
	}
	if (websocketAnchors.length > 0) {
		const wsUrl = websocketAnchors[0] ?? "<WS_URL>";
		followups.push({
			label: "browser-xhr-ws-replay-scaffold",
			command: `node - <<'NODE'\nconst url = ${pythonString(wsUrl)};\nconsole.log('[repi-ws-replay] target=', url);\nconsole.log('Use captured cookies/headers/subprotocols from browser-xhr-ws runtime anchors before replay.');\nNODE`,
			evidence: "websocket replay scaffold seeded from captured runtime endpoint",
		});
	}
	return {
		findings,
		followups,
		nextLane:
			authMatrixLines.length > 0 || idorProbeLines.length > 0
				? "authz/poc"
				: runtimeLines.length > 0 ||
						websocketAnchors.length > 0 ||
						cdpLines.length > 0 ||
						replayLines.length > 0 ||
						routeGraphLines.length > 0
					? "state/poc"
					: undefined,
	};
}

export function analyzeJsSigningEvidence(pack: LaneCommandPack, combined: string): SpecialistEvidenceAnalysis {
	const enabled =
		/frontend|js/.test(pack.route.toLowerCase()) ||
		packHasSpecialistSignal(pack, /js-signing-rebuild|JS signing rebuild/i);
	if (!enabled) return { findings: [], followups: [] };
	const findings: string[] = [];
	const followups: LaneCommand[] = [];
	const hookLines = interestingLines(
		combined,
		/\[repi-js-hook\]|fetch\.args|xhr\.open|xhr\.send|ws\.open|ws\.send|crypto\.subtle\.|sha256\(body\)|observed=/i,
		20,
	);
	if (hookLines.length > 0) {
		findings.push(`JS signing rebuild anchors: ${hookLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
	}
	const cryptoOps = uniqueMatches(
		combined,
		/(crypto\.subtle\.(?:digest|sign|verify|encrypt|decrypt|importKey|deriveKey))/gi,
		12,
	);
	if (cryptoOps.length > 0) findings.push(`crypto.subtle operation anchors: ${cryptoOps.join(", ")}`);
	const normalizedLines = interestingLines(combined, /\[js-signing-normalized\]/i, 8);
	if (normalizedLines.length > 0) {
		findings.push(
			`JS signing normalized artifact anchors: ${normalizedLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	const firstDivergenceLines = interestingLines(
		combined,
		/\[js-first-divergence\]|\[js-first-divergence-candidate\]/i,
		14,
	);
	if (firstDivergenceLines.length > 0) {
		findings.push(
			`JS first-divergence anchors: ${firstDivergenceLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	const replayHarnessLines = interestingLines(combined, /\[js-replay-harness\]/i, 8);
	if (replayHarnessLines.length > 0) {
		findings.push(
			`JS signing replay harness anchors: ${replayHarnessLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	if (
		hookLines.length > 0 ||
		cryptoOps.length > 0 ||
		normalizedLines.length > 0 ||
		firstDivergenceLines.length > 0 ||
		replayHarnessLines.length > 0
	) {
		followups.push({
			label: "js-signing-observed-rebuild",
			command: `[ -f /tmp/repi-signing-rebuild.mjs ] && REPI_OBSERVED="\${REPI_OBSERVED:-{}}" node /tmp/repi-signing-rebuild.mjs || rg -n "sign|signature|nonce|timestamp|crypto|encrypt|decrypt|fetch\\(|XMLHttpRequest" . | head -260`,
			evidence: "turn captured hook arguments into local Node signing rebuild",
		});
		followups.push({
			label: "js-signing-hook-rerun",
			command: `[ -f /tmp/repi-js-runtime-hooks.js ] && sed -n '1,260p' /tmp/repi-js-runtime-hooks.js || rg -n "fetch\\(|XMLHttpRequest|WebSocket|crypto\\.subtle|sign|nonce|timestamp" . | head -260`,
			evidence: "rerun or review browser hooks around first-divergence point",
		});
		followups.push({
			label: "js-signing-normalizer-rerun",
			command: `[ -f /tmp/repi-js-normalize.mjs ] && REPI_JS_LOG="\${REPI_JS_LOG:-}" REPI_OBSERVED="\${REPI_OBSERVED:-{}}" node /tmp/repi-js-normalize.mjs || printf '%s\n' 'rerun js-signing-observation-normalizer after capturing hook logs'`,
			evidence: "normalize captured fetch/XHR/crypto hook logs into observed signing artifact",
		});
		followups.push({
			label: "js-first-divergence-rerun",
			command: `[ -f /tmp/repi-js-first-divergence.mjs ] && REPI_OBSERVED="\${REPI_OBSERVED:-}" REPI_EXPECTED_SIGNATURE="\${REPI_EXPECTED_SIGNATURE:-}" REPI_CANDIDATE_SIGNATURE="\${REPI_CANDIDATE_SIGNATURE:-}" REPI_SECRET="\${REPI_SECRET:-}" node /tmp/repi-js-first-divergence.mjs || printf '%s\n' 'rerun js-signing-first-divergence-scaffold after observed artifact exists'`,
			evidence: "compare rebuilt candidate signature against observed signature and identify first divergence",
		});
		followups.push({
			label: "js-signing-replay-harness-rerun",
			command: `[ -f /tmp/repi-js-replay-harness.mjs ] && REPI_REPLAY_URL="\${REPI_REPLAY_URL:-}" REPI_METHOD="\${REPI_METHOD:-GET}" REPI_HEADERS="\${REPI_HEADERS:-{}}" REPI_SIGNATURE_KEY="\${REPI_SIGNATURE_KEY:-}" REPI_SIGNATURE_VALUE="\${REPI_SIGNATURE_VALUE:-}" node /tmp/repi-js-replay-harness.mjs || printf '%s\n' 'rerun js-signing-replay-harness-scaffold and set replay env'`,
			evidence: "validate rebuilt signature through signed request replay and response drift",
		});
	}
	return {
		findings,
		followups,
		nextLane:
			firstDivergenceLines.length > 0 || replayHarnessLines.length > 0
				? "verify/replay"
				: hookLines.length > 0 || cryptoOps.length > 0 || normalizedLines.length > 0
					? "rebuild/verify"
					: undefined,
	};
}

export function analyzeCryptoStegoEvidence(
	pack: LaneCommandPack,
	combined: string,
	targetArg: string,
): SpecialistEvidenceAnalysis {
	const enabled =
		/crypto|stego/i.test(pack.route) ||
		packHasSpecialistSignal(pack, /crypto-stego|crypto\/stego|solver|known-answer/i) ||
		/\[crypto-(?:param|transform|solver|known-answer)\]|\bzsteg\b|\bexiftool\b/i.test(combined);
	if (!enabled) return { findings: [], followups: [] };
	const findings: string[] = [];
	const followups: LaneCommand[] = [];
	const paramLines = interestingLines(
		combined,
		/\[crypto-param\]|modulus|exponent|nonce|iv=|salt|PEM|integer_index/i,
		22,
	);
	if (paramLines.length > 0) {
		findings.push(
			`crypto parameter derivation anchors: ${paramLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	const transformLines = interestingLines(
		combined,
		/\[crypto-transform\]|chain=.*->|base64|hex|gzip|zlib|decoded=|transform replay/i,
		24,
	);
	if (transformLines.length > 0) {
		findings.push(
			`crypto transform replay anchors: ${transformLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	const solverLines = interestingLines(
		combined,
		/\[crypto-solver\]|z3=|sage|pycryptodome|solve\.py|oracle|lattice/i,
		18,
	);
	if (solverLines.length > 0) {
		findings.push(
			`crypto solver script anchors: ${solverLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	const knownAnswerLines = interestingLines(
		combined,
		/\[crypto-known-answer\]|known-answer|verification=pass|KAT|assert/i,
		14,
	);
	if (knownAnswerLines.length > 0) {
		findings.push(
			`crypto known-answer test anchors: ${knownAnswerLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`,
		);
	}
	const stegoLines = interestingLines(
		combined,
		/zsteg|exiftool|binwalk|steghide|strings.*flag|embedded|metadata/i,
		16,
	);
	if (stegoLines.length > 0) {
		findings.push(`stego extraction anchors: ${stegoLines.map((line) => truncateMiddle(line, 200)).join(" | ")}`);
	}
	if (paramLines.length > 0 || transformLines.length > 0 || solverLines.length > 0 || stegoLines.length > 0) {
		followups.push({
			label: "crypto-parameter-inventory-rerun",
			command: `[ -f /tmp/repi-crypto-inventory.py ] && python3 /tmp/repi-crypto-inventory.py ${targetArg} || printf '%s\n' 'rerun crypto-stego-parameter-inventory-scaffold via re_lane plan/run'`,
			evidence: "refresh parameter inventory before solver changes",
		});
		followups.push({
			label: "crypto-transform-replay-rerun",
			command: `[ -f /tmp/repi-crypto-transform.py ] && python3 /tmp/repi-crypto-transform.py ${targetArg} || printf '%s\n' 'rerun crypto-stego-transform-replay-scaffold via re_lane plan/run'`,
			evidence: "rerun deterministic transform replay chain with latest artifact",
		});
		followups.push({
			label: "crypto-solver-known-answer-rerun",
			command: `[ -f /tmp/repi-crypto-solver.py ] && REPI_KNOWN_ANSWER="\${REPI_KNOWN_ANSWER:-}" REPI_CANDIDATE="\${REPI_CANDIDATE:-}" python3 /tmp/repi-crypto-solver.py ${targetArg} || printf '%s\n' 'rerun crypto-stego-solver-known-answer-scaffold and set REPI_KNOWN_ANSWER/REPI_CANDIDATE'`,
			evidence: "verify solver result through known-answer or candidate hash",
		});
		followups.push({
			label: "crypto-solver-script-scaffold",
			command: `cat > /tmp/repi-solve.py <<'PY'\n#!/usr/bin/env python3\n# REPI crypto solver skeleton: fill parameters from [crypto-param] and verify with known-answer.\nimport hashlib, os\nKNOWN=os.getenv('REPI_KNOWN_ANSWER','')\nCANDIDATE=os.getenv('REPI_CANDIDATE','')\nprint('[crypto-solver-script]', 'known_set=' + str(bool(KNOWN)), 'candidate_sha256=' + hashlib.sha256(CANDIDATE.encode()).hexdigest() if CANDIDATE else 'candidate_sha256=none')\nif KNOWN and CANDIDATE:\n    assert CANDIDATE == KNOWN or hashlib.sha256(CANDIDATE.encode()).hexdigest() == KNOWN\n    print('[crypto-known-answer]', 'verification=pass')\nelse:\n    print('[crypto-known-answer]', 'mode=scaffold set REPI_KNOWN_ANSWER and REPI_CANDIDATE')\nPY\nchmod +x /tmp/repi-solve.py\nsed -n '1,220p' /tmp/repi-solve.py`,
			evidence: "materialize solve.py with explicit known-answer assertion",
		});
	}
	return {
		findings,
		followups,
		nextLane:
			knownAnswerLines.length > 0
				? "report"
				: solverLines.length > 0 || transformLines.length > 0
					? "verify"
					: paramLines.length > 0 || stegoLines.length > 0
						? "solver"
						: undefined,
	};
}

export function analyzeWebScannerEvidence(
	pack: LaneCommandPack,
	combined: string,
	targetArg: string,
): SpecialistEvidenceAnalysis {
	const enabled =
		/web vulnerability|web scan|scanner/i.test(pack.route) ||
		packHasSpecialistSignal(pack, /web-scan-|web vulnerability scanner/i) ||
		/\[web-scan-|\[web-finding-queue\]/i.test(combined);
	if (!enabled) return { findings: [], followups: [] };
	const findings: string[] = [];
	const followups: LaneCommand[] = [];
	const scopeLines = interestingLines(combined, /\[web-scan-scope\]|\[web-scan-header\]|\[web-scan-httpx\]/i, 18);
	if (scopeLines.length > 0)
		findings.push(`web scanner scope anchors: ${scopeLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
	const crawlLines = interestingLines(
		combined,
		/\[web-scan-crawl\]|\[web-scan-corpus\]|\[web-scan-robots\]|\[web-scan-sitemap\]/i,
		20,
	);
	if (crawlLines.length > 0)
		findings.push(
			`web scanner crawl corpus anchors: ${crawlLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	const contentLines = interestingLines(
		combined,
		/\[web-scan-ffuf\]|\[web-scan-ferox\]|\[web-scan-gobuster\]|\[web-scan-content\]/i,
		16,
	);
	if (contentLines.length > 0)
		findings.push(
			`web scanner content discovery anchors: ${contentLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	const templateLines = interestingLines(
		combined,
		/\[web-scan-nuclei\]|\[web-scan-nikto\]|\[web-scan-dalfox\]|\[web-scan-template\]/i,
		18,
	);
	if (templateLines.length > 0)
		findings.push(
			`web scanner template finding anchors: ${templateLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	const verifierLines = interestingLines(
		combined,
		/\[web-scan-verifier\]|body_sha256|status_meta=|\[web-finding-queue\]/i,
		20,
	);
	if (verifierLines.length > 0)
		findings.push(
			`web scanner manual replay anchors: ${verifierLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	if (scopeLines.length || crawlLines.length || contentLines.length || templateLines.length || verifierLines.length) {
		followups.push({
			label: "web-scan-scope-rerun",
			command: `[ -x /tmp/repi-web-scope.sh ] && /tmp/repi-web-scope.sh ${targetArg} || printf '%s\n' 'rerun web-scan-scope-baseline via re_lane plan/run'`,
			evidence: "refresh web scope baseline before expanding scanner output",
		});
		followups.push({
			label: "web-scan-corpus-rerun",
			command: `[ -x /tmp/repi-web-crawl.sh ] && /tmp/repi-web-crawl.sh ${targetArg} || printf '%s\n' 'rerun web-scan-crawl-corpus-scaffold'`,
			evidence: "refresh crawl/route corpus for content discovery and replay verifier",
		});
		followups.push({
			label: "web-scan-template-rerun",
			command: `[ -x /tmp/repi-web-template-scan.sh ] && /tmp/repi-web-template-scan.sh ${targetArg} || printf '%s\n' 'rerun bounded template scan and keep JSONL artifact'`,
			evidence: "rerun bounded nuclei/nikto/dalfox candidate finding queue",
		});
		followups.push({
			label: "web-scan-manual-replay-rerun",
			command: `[ -x /tmp/repi-web-verify.py ] && python3 /tmp/repi-web-verify.py ${targetArg} || printf '%s\n' 'rerun manual replay verifier after corpus/finding queue exists'`,
			evidence: "replay scanner candidates with status/body hash before claiming vulnerability",
		});
	}
	return {
		findings,
		followups,
		nextLane:
			verifierLines.length > 0
				? "report"
				: templateLines.length > 0 || contentLines.length > 0
					? "verify"
					: crawlLines.length > 0
						? "template-scan"
						: scopeLines.length > 0
							? "crawl"
							: undefined,
	};
}

export function analyzeMemoryForensicsEvidence(
	pack: LaneCommandPack,
	combined: string,
	targetArg: string,
): SpecialistEvidenceAnalysis {
	const enabled =
		/memory forensics/i.test(pack.route) ||
		packHasSpecialistSignal(pack, /memory-forensics|mem-image|mem-vol|mem-credential/i) ||
		/\[mem-(?:image|vol|process|credential|timeline|carve)/i.test(combined);
	if (!enabled) return { findings: [], followups: [] };
	const findings: string[] = [];
	const followups: LaneCommand[] = [];
	const imageLines = interestingLines(
		combined,
		/\[mem-image\]|\[mem-vol-info\]|volatility3=missing|sample_sha256/i,
		18,
	);
	if (imageLines.length > 0)
		findings.push(
			`memory forensics image/profile anchors: ${imageLines.map((line) => truncateMiddle(line, 190)).join(" | ")}`,
		);
	const processLines = interestingLines(
		combined,
		/\[mem-process\]|\[mem-vol\].*(pslist|pstree|cmdline|dlllist|handles|netscan|sockstat|netstat)|\[mem-strings\]/i,
		22,
	);
	if (processLines.length > 0)
		findings.push(
			`memory forensics process/network anchors: ${processLines.map((line) => truncateMiddle(line, 190)).join(" | ")}`,
		);
	const credentialLines = interestingLines(
		combined,
		/\[mem-credential\]|\[mem-vol-credential\]|hashdump|lsadump|cachedump|Authorization|Cookie|AWS_ACCESS_KEY|BEGIN (?:RSA|OPENSSH)|NTLM/i,
		22,
	);
	if (credentialLines.length > 0)
		findings.push(
			`memory forensics credential/artifact anchors: ${credentialLines.map((line) => truncateMiddle(line, 190)).join(" | ")}`,
		);
	const timelineLines = interestingLines(
		combined,
		/\[mem-timeline\]|\[mem-vol-timeline\]|\[mem-carve\]|malfind|filescan|dumpfiles|timeliner/i,
		22,
	);
	if (timelineLines.length > 0)
		findings.push(
			`memory forensics timeline/carve anchors: ${timelineLines.map((line) => truncateMiddle(line, 190)).join(" | ")}`,
		);
	if (imageLines.length || processLines.length || credentialLines.length || timelineLines.length) {
		followups.push({
			label: "memory-info-rerun",
			command: `[ -x /tmp/repi-memory-info.sh ] && /tmp/repi-memory-info.sh ${targetArg} || printf '%s\n' 'rerun memory-forensics-image-info-scaffold'`,
			evidence: "refresh memory image info/profile/banners before plugin selection",
		});
		followups.push({
			label: "memory-process-network-rerun",
			command: `[ -x /tmp/repi-memory-process.sh ] && /tmp/repi-memory-process.sh ${targetArg} || printf '%s\n' 'rerun memory process/network scaffold'`,
			evidence: "rerun process tree, command line, DLL/handle and network plugin bundle",
		});
		followups.push({
			label: "memory-credential-artifact-rerun",
			command: `[ -x /tmp/repi-memory-creds.sh ] && /tmp/repi-memory-creds.sh ${targetArg} || printf '%s\n' 'rerun credential/artifact hunt scaffold'`,
			evidence: "rerun credential/token/registry/browser/LSASS artifact hunt",
		});
		followups.push({
			label: "memory-timeline-carve-rerun",
			command: `[ -x /tmp/repi-memory-timeline.sh ] && /tmp/repi-memory-timeline.sh ${targetArg} || printf '%s\n' 'rerun memory timeline/carving scaffold'`,
			evidence: "rerun timeliner/malfind/filescan/dumpfiles and carved artifact review",
		});
	}
	return {
		findings,
		followups,
		nextLane:
			timelineLines.length > 0
				? "report"
				: credentialLines.length > 0
					? "timeline-carve"
					: processLines.length > 0
						? "credential-artifacts"
						: imageLines.length > 0
							? "process-network"
							: undefined,
	};
}

export function analyzeIosEvidence(
	pack: LaneCommandPack,
	combined: string,
	targetArg: string,
): SpecialistEvidenceAnalysis {
	const enabled =
		/mobile \/ ios/i.test(pack.route) ||
		packHasSpecialistSignal(pack, /ios-|iOS IPA|ios-frida|ios-macho/i) ||
		/\[ios-(?:ipa|plist|binary|macho|otool|symbol|class|string|frida|hook|network)/i.test(combined);
	if (!enabled) return { findings: [], followups: [] };
	const findings: string[] = [];
	const followups: LaneCommand[] = [];
	const inventoryLines = interestingLines(
		combined,
		/\[ios-ipa\]|\[ios-plist\]|\[ios-binary\]|CFBundleIdentifier|Entitlements/i,
		20,
	);
	if (inventoryLines.length > 0)
		findings.push(
			`iOS IPA inventory anchors: ${inventoryLines.map((line) => truncateMiddle(line, 190)).join(" | ")}`,
		);
	const machoLines = interestingLines(
		combined,
		/\[ios-macho\]|\[ios-otool\]|\[ios-symbol\]|\[ios-class\]|\[ios-string\]|SecItem|NSURLSession|CCCrypt|CryptoKit|SecTrust/i,
		24,
	);
	if (machoLines.length > 0)
		findings.push(
			`iOS Mach-O/class/selector anchors: ${machoLines.map((line) => truncateMiddle(line, 190)).join(" | ")}`,
		);
	const hookLines = interestingLines(
		combined,
		/\[ios-frida\]|\[ios-hook\]|\[ios-native-hook\]|\[ios-frida-hook-template\]|\[ios-frida-process\]|\[ios-objection\]/i,
		22,
	);
	if (hookLines.length > 0)
		findings.push(
			`iOS Frida/objection hook anchors: ${hookLines.map((line) => truncateMiddle(line, 190)).join(" | ")}`,
		);
	const replayLines = interestingLines(
		combined,
		/\[ios-network-replay\]|\[ios-network-anchor\]|signature|nonce|pinning|Authorization|body_sha256/i,
		18,
	);
	if (replayLines.length > 0)
		findings.push(
			`iOS network/keychain replay anchors: ${replayLines.map((line) => truncateMiddle(line, 190)).join(" | ")}`,
		);
	if (inventoryLines.length || machoLines.length || hookLines.length || replayLines.length) {
		followups.push({
			label: "ios-ipa-inventory-rerun",
			command: `[ -x /tmp/repi-ios-inventory.sh ] && /tmp/repi-ios-inventory.sh ${targetArg} || printf '%s\n' 'rerun ios-ipa-inventory-scaffold'`,
			evidence: "refresh IPA/App/Info.plist/binary inventory",
		});
		followups.push({
			label: "ios-macho-class-map-rerun",
			command: `[ -x /tmp/repi-ios-macho.sh ] && /tmp/repi-ios-macho.sh ${targetArg} || printf '%s\n' 'rerun iOS Mach-O/class map scaffold'`,
			evidence: "rerun Objective-C/Swift selector, crypto, keychain and TLS pinning map",
		});
		followups.push({
			label: "ios-frida-hook-rerun",
			command:
				"sed -n '1,260p' /tmp/repi-ios-frida-hooks.js 2>/dev/null; frida-ps -Uai 2>/dev/null | head -120 || true",
			evidence: "review/rerun iOS Frida hook template and device process map",
		});
		followups.push({
			label: "ios-network-replay-rerun",
			command: `python3 - <<'PY'\nprint('[ios-network-replay] rerun ios-network-replay-scaffold or set captured request headers/body from Frida hooks for curl/node verifier')\nPY`,
			evidence: "prepare replay verifier for iOS signed request/TLS-pinning evidence",
		});
	}
	return {
		findings,
		followups,
		nextLane:
			replayLines.length > 0
				? "report"
				: hookLines.length > 0
					? "network-replay"
					: machoLines.length > 0
						? "runtime-hooks"
						: inventoryLines.length > 0
							? "static-class-map"
							: undefined,
	};
}

export function analyzePwnPrimitiveEvidence(
	pack: LaneCommandPack,
	combined: string,
	targetArg: string,
): SpecialistEvidenceAnalysis {
	const enabled =
		/pwn|exploit/.test(pack.route.toLowerCase()) || packHasSpecialistSignal(pack, /pwn-primitive|pwn primitive/i);
	if (!enabled) return { findings: [], followups: [] };
	const findings: string[] = [];
	const followups: LaneCommand[] = [];
	const targetPython = pythonString(pack.target ?? "<TARGET>");
	const crashLines = interestingLines(
		combined,
		/SIGSEGV|segmentation fault|program received signal|RIP|EIP|RSP|RBP|registers|code=\s*-11|stack|cyclic/i,
		20,
	);
	if (crashLines.length > 0) {
		findings.push(
			`pwn primitive crash/control anchors: ${crashLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const crashRegisterValues = uniqueMatches(combined, /\b(?:RIP|EIP|PC)\s*[:=]?\s*(0x[0-9a-f]+)/gi, 8);
	if (crashRegisterValues.length > 0) {
		findings.push(`pwn crash register anchors: ${crashRegisterValues.join(", ")}`);
	}
	const offsetLines = interestingLines(combined, /\[pwn-offset\].*\boffset=-?\d+/i, 16);
	const offsetValues = uniqueMatches(combined, /\[pwn-offset\][^\n]*\boffset=(-?\d+)/gi, 12);
	const resolvedOffsets = offsetValues.map((value) => Number.parseInt(value, 10)).filter((value) => value >= 0);
	if (offsetLines.length > 0) {
		findings.push(`pwn cyclic offset anchors: ${offsetLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
	}
	const gadgetLines = interestingLines(
		combined,
		/ROPgadget|ropper|pop rdi|syscall|one_gadget|:\s*(pop|ret|syscall)/i,
		16,
	);
	if (gadgetLines.length > 0) {
		findings.push(`pwn gadget anchors: ${gadgetLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
	}
	const ropLibcLines = interestingLines(
		combined,
		/\[pwn-rop-chain\]|\[pwn-libc-fingerprint\]|\bsystem@(?:plt|got)\b|\/bin\/sh|puts@(?:plt|got)|printf@(?:plt|got)|read@(?:plt|got)|write@(?:plt|got)|__libc_start_main|pop[_ ]rdi/i,
		24,
	);
	if (ropLibcLines.length > 0) {
		findings.push(`pwn ROP/libc chain anchors: ${ropLibcLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
	}
	const verifierLines = interestingLines(
		combined,
		/\[pwn-local-verifier\]|payload_len=|interactive_candidate|timeout=true/i,
		16,
	);
	if (verifierLines.length > 0) {
		findings.push(
			`pwn local verifier anchors: ${verifierLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const heapTcacheLines = interestingLines(
		combined,
		/\[pwn-(?:heap|tcache)\]|tcachebins|fastbins|unsortedbin|smallbins|largebins|malloc_chunk|__malloc_hook|__free_hook|main_arena/i,
		24,
	);
	if (heapTcacheLines.length > 0) {
		findings.push(`pwn heap/tcache anchors: ${heapTcacheLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
	}
	const formatStringLines = interestingLines(
		combined,
		/\[pwn-fmtstr(?:-probe)?\]|FmtStr|fmtstr_payload|format[-_ ]string|%[0-9$.*]*[pxsn]|write_addr/i,
		24,
	);
	if (formatStringLines.length > 0) {
		findings.push(
			`pwn format-string anchors: ${formatStringLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const sropDlresolveLines = interestingLines(
		combined,
		/\[pwn-(?:srop|ret2dlresolve|srop-gadget)\]|SigreturnFrame|Ret2dlresolvePayload|rt_sigreturn|int 0x80|syscall.*gadget/i,
		24,
	);
	if (sropDlresolveLines.length > 0) {
		findings.push(
			`pwn SROP/ret2dlresolve anchors: ${sropDlresolveLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const oneGadgetLines = interestingLines(
		combined,
		/\[pwn-one-gadget(?:-constraint)?\]|one_gadget|constraint=.*(?:rsp|r12|rax|argv|envp)|candidate=0x[0-9a-f]+/i,
		20,
	);
	if (oneGadgetLines.length > 0) {
		findings.push(
			`pwn one_gadget constraint anchors: ${oneGadgetLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const seccompSandboxLines = interestingLines(
		combined,
		/\[pwn-(?:seccomp|sandbox|seccomp-dump|sandbox-strace)\]|seccomp-tools|SECCOMP|prctl\(|seccomp\(|BPF|sandbox/i,
		24,
	);
	if (seccompSandboxLines.length > 0) {
		findings.push(
			`pwn seccomp/sandbox anchors: ${seccompSandboxLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	if (pack.target && crashLines.length > 0) {
		followups.push({
			label: "pwn-cyclic-offset-helper",
			command: `python3 - <<'PY'\nimport os, pathlib\nneedle = os.getenv('REPI_CRASH_VALUE', '').lower().replace('0x','')\npat = pathlib.Path('/tmp/repi-cyclic.bin')\nif not needle or not pat.exists():\n    print('set REPI_CRASH_VALUE from RIP/EIP/register bytes and ensure /tmp/repi-cyclic.bin exists')\nelse:\n    data = pat.read_bytes()\n    raw = bytes.fromhex(needle)\n    for candidate in (raw, raw[::-1]):\n        off = data.find(candidate)\n        print('candidate', candidate.hex(), 'offset', off)\nPY`,
			evidence: "derive cyclic offset from crashed register/control bytes",
		});
		followups.push({
			label: "pwn-focused-gdb-rerun",
			command: `gdb -q ${targetArg} -ex 'set pagination off' -ex 'run < /tmp/repi-cyclic.bin' -ex 'info registers' -ex 'bt' -ex 'x/32gx $rsp' -ex 'quit'`,
			evidence: "repeat crash with register, stack, and backtrace evidence",
		});
	}
	if (pack.target && (crashRegisterValues.length > 0 || crashLines.length > 0 || offsetLines.length > 0)) {
		const crashEnv = crashRegisterValues[0] ? `REPI_CRASH_VALUE=${shellQuote(crashRegisterValues[0])} ` : "";
		followups.push({
			label: "pwn-offset-analyzer-rerun",
			command: `${crashEnv}python3 /tmp/repi-pwn-offset-analyzer.py 2>/dev/null || ${crashEnv}python3 - <<'PY'\nimport os, pathlib\nneedle=os.getenv('REPI_CRASH_VALUE','').lower().replace('0x','')\npat=pathlib.Path('/tmp/repi-cyclic.bin')\nif not needle or not pat.exists(): print('[pwn-offset] crash_value=<unset> offset=-1')\nelse:\n data=pat.read_bytes(); raw=bytes.fromhex(needle)\n for c in (raw, raw[::-1], raw[-4:], raw[-4:][::-1]):\n  off=data.find(c); print(f'[pwn-offset] crash_value=0x{needle} candidate={c.hex()} offset={off}')\nPY`,
			evidence: "rerun cyclic offset analyzer with parsed RIP/EIP/PC crash value",
		});
	}
	if (pack.target && (gadgetLines.length > 0 || crashLines.length > 0)) {
		followups.push({
			label: "pwn-rop-libc-followup",
			command: `ldd ${targetArg} 2>/dev/null || true; (ROPgadget --binary ${targetArg} --only 'pop|ret|syscall' 2>/dev/null || ropper --file ${targetArg} --search 'pop rdi; ret' 2>/dev/null || true) | head -220`,
			evidence: "libc/loader fingerprint and focused ROP gadget follow-up",
		});
	}
	if (pack.target && (ropLibcLines.length > 0 || gadgetLines.length > 0 || crashLines.length > 0)) {
		followups.push({
			label: "pwn-rop-libc-scaffold-rerun",
			command: `[ -f /tmp/repi-pwn-rop-libc.py ] && python3 /tmp/repi-pwn-rop-libc.py ${targetArg} || true; ldd ${targetArg} 2>/dev/null || true; objdump -R ${targetArg} 2>/dev/null | grep -Ei 'puts|printf|read|write|system|__libc_start_main' | head -80 || true; (ROPgadget --binary ${targetArg} --only 'pop|ret|syscall' 2>/dev/null || ropper --file ${targetArg} --search 'pop rdi; ret' 2>/dev/null || true) | head -220`,
			evidence: "rebuild ROP/libc scaffold from PLT/GOT/gadget/libc anchors",
		});
	}
	if (pack.target && (resolvedOffsets.length > 0 || verifierLines.length > 0 || crashLines.length > 0)) {
		const offsetEnv = resolvedOffsets[0] !== undefined ? `REPI_OFFSET=${resolvedOffsets[0]} ` : "";
		followups.push({
			label: "pwn-local-verifier-rerun",
			command: `${offsetEnv}[ -f /tmp/repi-pwn-local-verifier.py ] && ${offsetEnv}python3 /tmp/repi-pwn-local-verifier.py ${targetArg} || printf '%s\n' 'rerun pwn-primitive-local-verifier to regenerate /tmp/repi-pwn-local-verifier.py'`,
			evidence: "rerun local payload smoke verifier with parsed cyclic offset when available",
		});
	}
	if (pack.target && (resolvedOffsets.length > 0 || ropLibcLines.length > 0 || gadgetLines.length > 0)) {
		const offsetLiteral = resolvedOffsets[0] ?? 0;
		followups.push({
			label: "pwn-pwntools-exploit-template",
			command: `cat > /tmp/repi-exploit-template.py <<'PY'\nfrom pwn import *\nBIN = ${targetPython}\ncontext.binary = exe = ELF(BIN, checksec=False)\ncontext.log_level = 'debug'\nOFFSET = int(args.OFFSET or ${offsetLiteral})\nHOST, PORT = args.HOST or '127.0.0.1', int(args.PORT or 31337)\ndef start():\n    return remote(HOST, PORT) if args.REMOTE else process([BIN])\ndef flat_payload(chain):\n    return b'A' * OFFSET + flat(chain)\n# Patch gadgets/leak targets from pwn-rop-libc-scaffold-rerun output.\n# Example ret2plt leak: [pop_rdi, exe.got['puts'], exe.plt['puts'], exe.symbols['main']]\nio = start()\nlog.info('offset=%d', OFFSET)\n# io.sendlineafter(b'> ', flat_payload([...]))\nio.interactive()\nPY\nsed -n '1,240p' /tmp/repi-exploit-template.py`,
			evidence: "pwntools exploit template prefilled with parsed offset and ROP/libc patch points",
		});
	}
	if (pack.target && heapTcacheLines.length > 0) {
		followups.push({
			label: "pwn-heap-tcache-rerun",
			command: `[ -f /tmp/repi-pwn-heap-tcache.gdb ] && gdb -q ${targetArg} -x /tmp/repi-pwn-heap-tcache.gdb || printf '%s\\n' 'rerun pwn-advanced-heap-tcache-scaffold to regenerate heap/tcache probe'`,
			evidence: "rerun heap/tcache allocator state probe for bins, hooks, and main_arena anchors",
		});
	}
	if (pack.target && formatStringLines.length > 0) {
		followups.push({
			label: "pwn-format-string-rerun",
			command: `[ -f /tmp/repi-pwn-fmtstr.py ] && python3 /tmp/repi-pwn-fmtstr.py ${targetArg} || printf '%s\\n' 'rerun pwn-advanced-format-string-scaffold to regenerate fmtstr probes'`,
			evidence: "rerun format-string offset/leak/write probe and fmtstr_payload scaffold",
		});
	}
	if (pack.target && sropDlresolveLines.length > 0) {
		followups.push({
			label: "pwn-srop-ret2dlresolve-rerun",
			command: `[ -f /tmp/repi-pwn-srop-dlresolve.py ] && python3 /tmp/repi-pwn-srop-dlresolve.py ${targetArg} || (ROPgadget --binary ${targetArg} --only 'syscall|int|pop|ret' 2>/dev/null || objdump -d ${targetArg} | grep -Ei 'syscall|int 0x80|sigreturn' | head -160)`,
			evidence: "rerun SROP syscall surface and ret2dlresolve scaffold",
		});
	}
	if (pack.target && oneGadgetLines.length > 0) {
		followups.push({
			label: "pwn-one-gadget-constraints-rerun",
			command: `LIBC=$(ldd ${targetArg} 2>/dev/null | awk '/libc.so/{print $(NF-1); exit}'); [ -n "$LIBC" ] && one_gadget "$LIBC" 2>/dev/null | sed -n '1,160p' || printf '%s\\n' 'install one_gadget or inspect libc constraints from pwn-advanced-one-gadget-constraints output'`,
			evidence: "rerun one_gadget candidate and register/stack/environment constraint review",
		});
	}
	if (pack.target && seccompSandboxLines.length > 0) {
		followups.push({
			label: "pwn-seccomp-sandbox-rerun",
			command: `seccomp-tools dump ${targetArg} 2>/dev/null | sed -n '1,160p' || timeout 5 strace -f -e trace=prctl,seccomp,execve,openat,read,write ${targetArg} </dev/null 2>&1 | sed -n '1,160p' || true`,
			evidence: "rerun seccomp/sandbox syscall filter and strace triage",
		});
	}
	const hasAdvancedPwnAnchors =
		heapTcacheLines.length > 0 ||
		formatStringLines.length > 0 ||
		sropDlresolveLines.length > 0 ||
		oneGadgetLines.length > 0 ||
		seccompSandboxLines.length > 0;
	return {
		findings,
		followups,
		nextLane: hasAdvancedPwnAnchors
			? "advanced-exploit/verify"
			: resolvedOffsets.length > 0 || ropLibcLines.length > 0 || verifierLines.length > 0
				? "exploit/verify"
				: crashLines.length > 0
					? "exploit"
					: undefined,
	};
}

export function analyzeExploitReliabilityEvidence(
	pack: LaneCommandPack,
	combined: string,
	targetArg: string,
): SpecialistEvidenceAnalysis {
	const enabled =
		/exploit reliability/.test(pack.route.toLowerCase()) ||
		packHasSpecialistSignal(pack, /exploit-(poc|replay|environment|flake|artifact)|exploit reliability\/autopwn/i) ||
		/\[exploit-(candidate|poc|replay|env|flake|bundle)/i.test(combined);
	if (!enabled) return { findings: [], followups: [] };
	const findings: string[] = [];
	const followups: LaneCommand[] = [];
	const pocLines = interestingLines(
		combined,
		/\[exploit-candidate\]|\[exploit-poc\]|\[exploit-poc-summary\]|kind=|sha256=|executable=/i,
		24,
	);
	if (pocLines.length > 0) {
		findings.push(`Exploit PoC inventory anchors: ${pocLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
	}
	const replayLines = interestingLines(
		combined,
		/\[exploit-replay\]|\[exploit-replay-summary\]|success_rate=|stable=|unique_hashes=|unique_exits=|ok=/i,
		24,
	);
	if (replayLines.length > 0) {
		findings.push(`PoC replay matrix anchors: ${replayLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
	}
	const envLines = interestingLines(
		combined,
		/\[exploit-env\]|randomize_va_space|platform=|python=|target=|file=|sha256=|uname/i,
		18,
	);
	if (envLines.length > 0) {
		findings.push(
			`Exploit environment pin anchors: ${envLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const flakeLines = interestingLines(
		combined,
		/\[exploit-flake\]|\[exploit-flake-risk\]|\[exploit-flake-failure\]|exit_variance|output_hash_variance|timeout|failures=/i,
		24,
	);
	if (flakeLines.length > 0) {
		findings.push(`Exploit flake triage anchors: ${flakeLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
	}
	const bundleLines = interestingLines(
		combined,
		/\[exploit-bundle\]|\[exploit-bundle-artifact\]|manifest=|artifacts=/i,
		18,
	);
	if (bundleLines.length > 0) {
		findings.push(
			`Exploit artifact bundle anchors: ${bundleLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	if (
		pocLines.length > 0 ||
		replayLines.length > 0 ||
		envLines.length > 0 ||
		flakeLines.length > 0 ||
		bundleLines.length > 0
	) {
		followups.push({
			label: "exploit-poc-normalizer-rerun",
			command: `[ -f /tmp/repi-exploit-normalize.py ] && python3 /tmp/repi-exploit-normalize.py ${targetArg} || find . -maxdepth 6 -type f \\( -iname '*exploit*' -o -iname '*poc*' -o -iname '*payload*' -o -iname '*replay*' \\) -print | head -240`,
			evidence: "rerun exploit PoC/payload inventory normalizer",
		});
		followups.push({
			label: "exploit-replay-matrix-rerun",
			command:
				"[ -f /tmp/repi-exploit-replay-matrix.py ] && python3 /tmp/repi-exploit-replay-matrix.py || printf '%s\\n' 'set REPI_POC_CMD or rerun exploit-replay-matrix-scaffold'",
			evidence: "rerun multi-run PoC replay matrix and stability metrics",
		});
		followups.push({
			label: "exploit-env-pin-rerun",
			command: `file ${targetArg} 2>/dev/null || true; sha256sum ${targetArg} 2>/dev/null || true; python3 - <<'PY'\nimport platform, pathlib, sys\nprint('[exploit-env]', 'python=' + sys.version.split()[0], 'platform=' + platform.platform())\nfor p in ['/proc/sys/kernel/randomize_va_space','/proc/version']:\n path=pathlib.Path(p)\n print('[exploit-env]', p + '=' + (path.read_text().strip() if path.exists() else 'missing'))\nPY`,
			evidence: "rerun environment pinning for replay reproducibility",
		});
		followups.push({
			label: "exploit-flake-triage-rerun",
			command:
				"[ -f /tmp/repi-exploit-flake-triage.py ] && python3 /tmp/repi-exploit-flake-triage.py || jq '.runs' /tmp/repi-exploit-replay-matrix.json 2>/dev/null || true",
			evidence: "rerun flake triage over replay matrix",
		});
		followups.push({
			label: "exploit-artifact-bundle-rerun",
			command: "find /tmp -maxdepth 1 -type f -name 'repi-exploit*' -print -exec sha256sum {} \\; | head -160",
			evidence: "review exploit reliability artifact bundle inputs",
		});
		followups.push({
			label: "exploit-reliability-report-scaffold",
			command:
				"python3 - <<'PY'\nprint('[exploit-report] inputs=poc inventory,replay matrix,environment pins,flake triage,bundle manifest')\nprint('Next: report success_rate, stable output hashes, environment pins, known flake buckets, and one operator replay command.')\nPY",
			evidence: "consolidated exploit reliability report scaffold",
		});
	}
	return {
		findings,
		followups,
		nextLane:
			bundleLines.length > 0
				? "report"
				: flakeLines.length > 0
					? "bundle/report"
					: replayLines.length > 0
						? "flake-triage/bundle"
						: pocLines.length > 0 || envLines.length > 0
							? "replay/flake-triage"
							: undefined,
	};
}

export function analyzePcapDfirEvidence(
	pack: LaneCommandPack,
	combined: string,
	targetArg: string,
): SpecialistEvidenceAnalysis {
	const enabled =
		/dfir|pcap|forensic|stego/.test(pack.route.toLowerCase()) ||
		packHasSpecialistSignal(pack, /pcap-flow|PCAP\/DFIR/i) ||
		/\.(?:pcap|pcapng|cap)$/i.test(pack.target ?? "");
	if (!enabled) return { findings: [], followups: [] };
	const findings: string[] = [];
	const followups: LaneCommand[] = [];
	const flowLines = interestingLines(
		combined,
		/conversations|endpoints|<->|tcp\.stream|udp|http\.request|dns\.qry|tls\.handshake|authorization|cookie|password|token|flag|export-objects|repi-pcap-objects|foremost/i,
		24,
	);
	if (flowLines.length > 0) {
		findings.push(
			`PCAP/DFIR traffic flow anchors: ${flowLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const streamRankLines = interestingLines(combined, /\[pcap-stream-rank\]/i, 18);
	if (streamRankLines.length > 0) {
		findings.push(
			`PCAP stream ranking anchors: ${streamRankLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const secretTimelineLines = interestingLines(combined, /\[pcap-secret-timeline\]/i, 18);
	if (secretTimelineLines.length > 0) {
		findings.push(
			`PCAP secret timeline anchors: ${secretTimelineLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const extractedFiles = uniqueMatches(combined, /(\/tmp\/repi-(?:pcap-objects|carve)\/[^\s]+)/gi, 12);
	if (extractedFiles.length > 0) findings.push(`PCAP extracted artifact anchors: ${extractedFiles.join(", ")}`);
	const transformLines = interestingLines(combined, /\[pcap-transform-chain\]|base64|gzip|zlib|secret-string/i, 16);
	if (transformLines.length > 0) {
		findings.push(
			`PCAP transform chain anchors: ${transformLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	if (
		pack.target &&
		(flowLines.length > 0 ||
			streamRankLines.length > 0 ||
			secretTimelineLines.length > 0 ||
			extractedFiles.length > 0 ||
			transformLines.length > 0)
	) {
		followups.push({
			label: "pcap-follow-streams",
			command: `for s in 0 1 2 3 4; do echo "### tcp.stream=$s"; tshark -r ${targetArg} -q -z follow,tcp,ascii,$s 2>/dev/null | sed -n '1,120p'; done`,
			evidence: "follow high-priority TCP streams after conversation triage",
		});
		followups.push({
			label: "pcap-object-review",
			command: `find /tmp/repi-pcap-objects /tmp/repi-carve -type f 2>/dev/null | head -80 | while read -r f; do echo "### $f"; file "$f"; strings -a -n 5 "$f" | head -40; done`,
			evidence: "review carved/extracted payloads for transform chain",
		});
		followups.push({
			label: "pcap-stream-rank-rerun",
			command: `[ -f /tmp/repi-pcap-stream-rank.py ] && python3 /tmp/repi-pcap-stream-rank.py ${targetArg} || tshark -r ${targetArg} -q -z conv,tcp -z conv,udp 2>/dev/null | sed -n '1,220p'`,
			evidence: "rerun stream ranking to prioritize follow-stream extraction",
		});
		followups.push({
			label: "pcap-secret-timeline-rerun",
			command: `[ -f /tmp/repi-pcap-secret-timeline.py ] && python3 /tmp/repi-pcap-secret-timeline.py ${targetArg} || tshark -r ${targetArg} -Y 'http.authorization || http.cookie || dns.qry.name || tls.handshake.extensions_server_name || frame contains "token" || frame contains "flag"' -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.stream -e http.host -e http.request.uri -e dns.qry.name -e tls.handshake.extensions_server_name -e http.authorization -e http.cookie 2>/dev/null | head -260`,
			evidence: "rerun credential/secret timeline for high-value frames and streams",
		});
		followups.push({
			label: "pcap-transform-chain-rerun",
			command: `[ -f /tmp/repi-pcap-transform-chain.py ] && python3 /tmp/repi-pcap-transform-chain.py || find /tmp/repi-pcap-objects /tmp/repi-carve -type f 2>/dev/null | head -80 | while read -r f; do echo "### $f"; file "$f"; strings -a -n 5 "$f" | head -40; done`,
			evidence: "rerun transform-chain extractor over exported/carved artifacts",
		});
		followups.push({
			label: "pcap-dfir-report-scaffold",
			command: `python3 - <<'PY'\nimport pathlib\nprint('[pcap-dfir-report] target=' + ${pythonString(pack.target ?? "<TARGET>")})\nfor p in ['/tmp/repi-pcap-objects','/tmp/repi-carve']:\n    root=pathlib.Path(p)\n    files=list(root.rglob('*')) if root.exists() else []\n    print('[pcap-dfir-report]', p, 'files=' + str(sum(1 for f in files if f.is_file())))\nprint('Next: use pcap-stream-rank-rerun to select streams, pcap-secret-timeline-rerun for credentials, pcap-transform-chain-rerun for decoded artifacts.')\nPY`,
			evidence: "consolidated DFIR report scaffold with stream/timeline/transform next steps",
		});
	}
	return {
		findings,
		followups,
		nextLane:
			secretTimelineLines.length > 0 || transformLines.length > 0
				? "extract/decode/report"
				: flowLines.length > 0 || streamRankLines.length > 0 || extractedFiles.length > 0
					? "extract/decode"
					: undefined,
	};
}

export function analyzeFirmwareIotEvidence(
	pack: LaneCommandPack,
	combined: string,
	targetArg: string,
): SpecialistEvidenceAnalysis {
	const enabled =
		/firmware|iot/.test(pack.route.toLowerCase()) ||
		packHasSpecialistSignal(pack, /firmware-|Firmware[/]IoT rootfs|firmware-image|firmware-rootfs/i) ||
		/\.(?:bin|img|trx|chk|ubi|ubifs|squashfs|sqsh)$/i.test(pack.target ?? "");
	if (!enabled) return { findings: [], followups: [] };
	const findings: string[] = [];
	const followups: LaneCommand[] = [];
	const imageLines = interestingLines(
		combined,
		/\[firmware-image\]|\[firmware-candidate\]|Squashfs|UBI|uImage|TRX|U-Boot|OpenWrt|entropy=|sha256=|binwalk|rootfs|kernel/i,
		24,
	);
	if (imageLines.length > 0) {
		findings.push(
			`Firmware image metadata anchors: ${imageLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const extractLines = interestingLines(
		combined,
		/\[firmware-extract\]|\[firmware-rootfs\]|\[firmware-extract-file\]|squashfs-root|unsquashfs-root|\/tmp\/repi-firmware-extract|ubi_reader|unblob/i,
		24,
	);
	if (extractLines.length > 0) {
		findings.push(
			`Firmware extraction/rootfs anchors: ${extractLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const configLines = interestingLines(
		combined,
		/\[firmware-config\]|\[firmware-secret\]|passwd|shadow|authorized_keys|id_rsa|\.pem|password|psk|ssid|nvram|token|secret/i,
		24,
	);
	if (configLines.length > 0) {
		findings.push(
			`Firmware config/secret anchors: ${configLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const serviceLines = interestingLines(
		combined,
		/\[firmware-service\]|\[firmware-init\]|\[firmware-web\]|\[firmware-surface\]|httpd|uhttpd|boa|lighttpd|dropbear|telnetd|inetd|cgi-bin|upnp|endpoint=/i,
		24,
	);
	if (serviceLines.length > 0) {
		findings.push(
			`Firmware service/web surface anchors: ${serviceLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const emuLines = interestingLines(
		combined,
		/\[firmware-emulation\]|qemu-|chroot|arch=.*(?:MIPS|ARM)|service_smoke/i,
		18,
	);
	if (emuLines.length > 0) {
		findings.push(
			`Firmware emulation/runtime anchors: ${emuLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	if (
		imageLines.length > 0 ||
		extractLines.length > 0 ||
		configLines.length > 0 ||
		serviceLines.length > 0 ||
		emuLines.length > 0
	) {
		followups.push({
			label: "firmware-extract-rerun",
			command: `[ -f /tmp/repi-firmware-extract.sh ] && /tmp/repi-firmware-extract.sh ${targetArg} || binwalk -eM ${targetArg} 2>/dev/null || file ${targetArg}`,
			evidence: "rerun firmware extraction/rootfs recovery with binwalk/unblob/unsquashfs fallbacks",
		});
		followups.push({
			label: "firmware-config-secret-rerun",
			command: `[ -f /tmp/repi-firmware-config.sh ] && /tmp/repi-firmware-config.sh || find /tmp/repi-firmware-extract -maxdepth 6 -type f | head -200`,
			evidence: "rerun rootfs config/secret/NVRAM/key/web artifact extraction",
		});
		followups.push({
			label: "firmware-service-surface-rerun",
			command: `[ -f /tmp/repi-firmware-services.sh ] && /tmp/repi-firmware-services.sh || grep -RasnE 'httpd|dropbear|telnetd|cgi-bin|nvram' /tmp/repi-firmware-extract 2>/dev/null | head -220`,
			evidence: "rerun init/service/web/CGI surface mapping from extracted rootfs",
		});
		followups.push({
			label: "firmware-emulation-scaffold-rerun",
			command: `[ -f /tmp/repi-firmware-emulation.sh ] && /tmp/repi-firmware-emulation.sh || printf '%s\n' 'extract rootfs before firmware emulation scaffold'`,
			evidence: "rerun QEMU/chroot emulation scaffold and service smoke-test plan",
		});
		followups.push({
			label: "firmware-report-scaffold",
			command:
				"python3 - <<'PY'\nprint('[firmware-report] inputs=image,extract,config,service,emulation anchors')\nprint('Next: normalize rootfs paths, credentials, endpoints, init services, emulation commands, and reproduction evidence into attack graph.')\nPY",
			evidence: "consolidated firmware/IoT rootfs, secret, service, and emulation report scaffold",
		});
	}
	return {
		findings,
		followups,
		nextLane:
			emuLines.length > 0 || serviceLines.length > 0
				? "emulate/report"
				: configLines.length > 0
					? "services/emulate"
					: extractLines.length > 0
						? "filesystem/services"
						: imageLines.length > 0
							? "extract/filesystem"
							: undefined,
	};
}

export function analyzeAgentSecurityEvidence(
	pack: LaneCommandPack,
	combined: string,
	targetArg: string,
): SpecialistEvidenceAnalysis {
	const enabled =
		/agent|llm/.test(pack.route.toLowerCase()) ||
		packHasSpecialistSignal(pack, /agent-(prompt|tool|memory|injection|delegation)|agent prompt\/tool boundary/i);
	if (!enabled) return { findings: [], followups: [] };
	const findings: string[] = [];
	const followups: LaneCommand[] = [];
	const promptLines = interestingLines(
		combined,
		/\[agent-prompt\]|\[agent-prompt-risk\]|systemPrompt|developer message|prompt injection|ignore previous|untrusted/i,
		24,
	);
	if (promptLines.length > 0) {
		findings.push(
			`Agent prompt surface anchors: ${promptLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const toolLines = interestingLines(
		combined,
		/\[agent-tool\]|\[agent-tool-risk\]|\[agent-tool-summary\]|registerTool|tool_call|function_call|exec_without_visible_schema|tool_without_visible_schema|MCP|schema/i,
		24,
	);
	if (toolLines.length > 0) {
		findings.push(`Agent tool boundary anchors: ${toolLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
	}
	const memoryLines = interestingLines(
		combined,
		/\[agent-memory\]|\[agent-memory-risk\]|\[agent-memory-summary\]|memory poisoning|记忆投毒|RAG|retrieval|vector|playbook|journal/i,
		24,
	);
	if (memoryLines.length > 0) {
		findings.push(
			`Agent memory poisoning anchors: ${memoryLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const replayLines = interestingLines(
		combined,
		/\[agent-injection-replay\]|\[agent-injection-case\]|\[agent-injection-result\]|tool-json-smuggle|delimiter-breakout|indirect-ignore-previous/i,
		24,
	);
	if (replayLines.length > 0) {
		findings.push(
			`Agent injection replay anchors: ${replayLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const delegationLines = interestingLines(
		combined,
		/\[agent-delegation\]|\[agent-delegation-risk\]|\[agent-delegation-summary\]|sub-agent|handoff|delegat|capability drift|resources\/list|tools\/call/i,
		24,
	);
	if (delegationLines.length > 0) {
		findings.push(
			`Agent delegation trace anchors: ${delegationLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	if (
		promptLines.length > 0 ||
		toolLines.length > 0 ||
		memoryLines.length > 0 ||
		replayLines.length > 0 ||
		delegationLines.length > 0
	) {
		followups.push({
			label: "agent-prompt-surface-rerun",
			command:
				'rg -n "systemPrompt|developer|instructions|prompt injection|ignore previous|tool_call|registerTool|MCP|memory|RAG|retrieval|untrusted|sanitize|schema|approval|allowlist|denylist" . 2>/dev/null | head -360',
			evidence: "rerun agent prompt/resource/tool/memory surface keyword map",
		});
		followups.push({
			label: "agent-tool-boundary-rerun",
			command: `[ -f /tmp/repi-agent-tool-boundary.py ] && python3 /tmp/repi-agent-tool-boundary.py ${targetArg} || rg -n "registerTool|tool_call|function_call|exec\\(|spawn\\(|subprocess|schema|validate|allowlist|denylist" . 2>/dev/null | head -320`,
			evidence: "rerun tool-call boundary scanner and schema/exec audit",
		});
		followups.push({
			label: "agent-memory-poisoning-rerun",
			command: `[ -f /tmp/repi-agent-memory-poison.py ] && python3 /tmp/repi-agent-memory-poison.py ${targetArg} || find . -maxdepth 5 -type f \\( -iname '*memory*' -o -iname '*journal*' -o -iname '*playbook*' -o -iname '*rag*' -o -iname '*.md' \\) -print | head -160`,
			evidence: "rerun memory/RAG/playbook poisoning scanner",
		});
		followups.push({
			label: "agent-injection-replay-rerun",
			command:
				"[ -f /tmp/repi-agent-injection-replay.py ] && python3 /tmp/repi-agent-injection-replay.py || printf '%s\\n' 'rerun agent-injection-replay-harness to regenerate corpus'",
			evidence: "rerun bounded injection replay harness and payload corpus",
		});
		followups.push({
			label: "agent-delegation-trace-rerun",
			command: `[ -f /tmp/repi-agent-delegation.py ] && python3 /tmp/repi-agent-delegation.py ${targetArg} || rg -n "sub[-_ ]?agent|delegate|handoff|mcp|resources/list|tools/call|capability|approval|permission" . 2>/dev/null | head -260`,
			evidence: "rerun MCP/resource/sub-agent delegation trace scanner",
		});
		followups.push({
			label: "agent-security-report-scaffold",
			command:
				"python3 - <<'AGPY'\nprint('[agent-security-report] inputs=prompt-surface,tool-boundary,memory-poisoning,injection-replay,delegation-trace anchors')\nprint('Next: normalize boundary nodes, tainted channels, tool schemas, replay outcomes, and evidence into attack graph.')\nAGPY",
			evidence: "consolidated agent prompt/tool/memory/delegation boundary report scaffold",
		});
	}
	return {
		findings,
		followups,
		nextLane:
			replayLines.length > 0 || delegationLines.length > 0
				? "delegation/report"
				: toolLines.length > 0
					? "injection/delegation"
					: promptLines.length > 0 || memoryLines.length > 0
						? "tool-boundary/injection"
						: undefined,
	};
}

export function analyzeFridaGdbEvidence(
	pack: LaneCommandPack,
	combined: string,
	targetArg: string,
): SpecialistEvidenceAnalysis {
	const enabled =
		/android|mobile|native|reverse|pwn/.test(pack.route.toLowerCase()) ||
		packHasSpecialistSignal(pack, /frida-gdb-trace|Frida\/GDB trace/i);
	if (!enabled) return { findings: [], followups: [] };
	const findings: string[] = [];
	const followups: LaneCommand[] = [];
	const traceLines = interestingLines(
		combined,
		/\[repi-frida\]|\[native\]|\[doFinal\]|\[digest\]|Java runtime ready|Interceptor|Module\.findExportByName|Breakpoint|hit breakpoint|info registers|RIP|RSP|GDB/i,
		20,
	);
	if (traceLines.length > 0) {
		findings.push(`Frida/GDB trace anchors: ${traceLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
	}
	if (/\[doFinal\.ret\]|\[digest\.ret\]|hexdump|\[native\]/i.test(combined))
		findings.push("runtime hook return/value anchors captured");
	if (traceLines.length > 0) {
		followups.push({
			label: "frida-focused-trace-rerun",
			command: `[ -f /tmp/repi-frida-trace.js ] && sed -n '1,260p' /tmp/repi-frida-trace.js; frida-ps -Uai 2>/dev/null | head -120 || true`,
			evidence: "rerun/review Frida runtime hook with narrowed class/native targets",
		});
		if (pack.target) {
			followups.push({
				label: "gdb-focused-trace-rerun",
				command: `[ -f /tmp/repi-gdb-trace.gdb ] && gdb -q ${targetArg} -x /tmp/repi-gdb-trace.gdb || gdb -q ${targetArg} -ex 'set pagination off' -ex 'break strcmp' -ex 'break memcmp' -ex 'run' -ex 'bt' -ex 'quit'`,
				evidence: "repeat native breakpoint trace around comparison or crypto boundary",
			});
		}
	}
	return { findings, followups, nextLane: traceLines.length > 0 ? "runtime-proof/report" : undefined };
}

export function analyzeMalwareEvidence(
	pack: LaneCommandPack,
	combined: string,
	targetArg: string,
): SpecialistEvidenceAnalysis {
	const enabled =
		/malware/.test(pack.route.toLowerCase()) ||
		packHasSpecialistSignal(pack, /malware-|malware config\/IOC|malware-static|malware-ioc/i);
	if (!enabled) return { findings: [], followups: [] };
	const findings: string[] = [];
	const followups: LaneCommand[] = [];
	const staticLines = interestingLines(
		combined,
		/\[malware-static\]|format_hint=|entropy=|sha256=|PE32|ELF|Mach-O|UPX|packer|rabin2|import/i,
		20,
	);
	if (staticLines.length > 0) {
		findings.push(
			`Malware static triage anchors: ${staticLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const ruleLines = interestingLines(
		combined,
		/\[malware-yara\]|\[malware-capa\]|\[malware-floss\]|\[malware-clam\]|\[malware-packer\]|ATT&CK|MBC|namespace|capability|rule=/i,
		22,
	);
	if (ruleLines.length > 0) {
		findings.push(
			`Malware rule/capability anchors: ${ruleLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const iocLines = interestingLines(
		combined,
		/\[malware-ioc\]|\[malware-config-hint\]|\[malware-config-summary\]|https?:\/\/|type=(?:url|ipv4|domain|registry|mutex|user_agent)|C2|beacon/i,
		24,
	);
	if (iocLines.length > 0) {
		findings.push(`Malware IOC/config anchors: ${iocLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
	}
	const behaviorLines = interestingLines(
		combined,
		/\[malware-behavior\]|execve|clone|fork|ptrace|mprotect|openat|socket|connect|sendto|recvfrom|IsDebuggerPresent|anti-debug/i,
		24,
	);
	if (behaviorLines.length > 0) {
		findings.push(
			`Malware behavior trace anchors: ${behaviorLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	if (staticLines.length > 0 || ruleLines.length > 0 || iocLines.length > 0 || behaviorLines.length > 0) {
		followups.push({
			label: "malware-static-triage-rerun",
			command: `[ -f /tmp/repi-malware-static.sh ] && /tmp/repi-malware-static.sh ${targetArg} || file ${targetArg}; sha256sum ${targetArg}; strings -a -n 5 ${targetArg} | head -220`,
			evidence: "rerun static hash/import/string/YARA/capa/FLOSS triage for sample",
		});
		followups.push({
			label: "malware-ioc-config-rerun",
			command: `[ -f /tmp/repi-malware-ioc.py ] && python3 /tmp/repi-malware-ioc.py ${targetArg} || printf '%s\n' 'rerun malware-ioc-config-scaffold from re_lane plan'`,
			evidence: "rerun IOC/config extractor for URLs, IPs, domains, registry, mutex, and encoded hints",
		});
		followups.push({
			label: "malware-behavior-trace-rerun",
			command: `[ -f /tmp/repi-malware-behavior.sh ] && REPI_MALWARE_TIMEOUT="\${REPI_MALWARE_TIMEOUT:-8}" /tmp/repi-malware-behavior.sh ${targetArg} || printf '%s\n' 'rerun malware-behavior-trace-scaffold from re_lane plan'`,
			evidence: "rerun bounded sample behavior trace for process/file/network/anti-debug evidence",
		});
		followups.push({
			label: "malware-report-scaffold",
			command:
				"python3 - <<'PY'\nprint('[malware-report] inputs=static,rule,ioc,behavior anchors')\nprint('Next: normalize hash/format, IOCs, behavior chain, config hints, and exact reproduction commands into evidence ledger and attack graph.')\nPY",
			evidence: "consolidated malware IOC/config/behavior report scaffold",
		});
	}
	return {
		findings,
		followups,
		nextLane:
			behaviorLines.length > 0
				? "decode/report"
				: iocLines.length > 0 || ruleLines.length > 0
					? "behavior/decode"
					: staticLines.length > 0
						? "static-config/behavior"
						: undefined,
	};
}

export function analyzeCloudIdentityEvidence(pack: LaneCommandPack, combined: string): SpecialistEvidenceAnalysis {
	const enabled =
		/cloud|container|k8s|kubernetes/.test(pack.route.toLowerCase()) ||
		packHasSpecialistSignal(pack, /cloud-identity|Cloud\/K8s identity|cloud-runtime|cloud-metadata/i);
	if (!enabled) return { findings: [], followups: [] };
	const findings: string[] = [];
	const followups: LaneCommand[] = [];
	const identityLines = interestingLines(combined, /\[cloud-identity\]|\[k8s-serviceaccount\]/i, 18);
	if (identityLines.length > 0) {
		findings.push(`Cloud identity anchors: ${identityLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
	}
	const runtimeLines = interestingLines(
		combined,
		/\[cloud-runtime-config\]|\[k8s-context\]|\[k8s-rbac\]|\[k8s-resource\]/i,
		24,
	);
	if (runtimeLines.length > 0) {
		findings.push(
			`Cloud/K8s runtime config anchors: ${runtimeLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const metadataLines = interestingLines(combined, /\[cloud-metadata\]/i, 18);
	if (metadataLines.length > 0) {
		findings.push(
			`Cloud metadata probe anchors: ${metadataLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const privilegeLines = interestingLines(
		combined,
		/\[cloud-privilege-edge\]|ClusterRoleBinding|RoleBinding|iam\.gserviceaccount|arn:aws/i,
		18,
	);
	if (privilegeLines.length > 0) {
		findings.push(
			`Cloud privilege edge anchors: ${privilegeLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	if (identityLines.length > 0 || runtimeLines.length > 0 || metadataLines.length > 0 || privilegeLines.length > 0) {
		followups.push({
			label: "cloud-identity-rerun",
			command:
				"python3 - <<'PY'\nimport pathlib\np=pathlib.Path('/tmp/repi-cloud-runtime.sh')\nprint('[cloud-identity-rerun]', 'runtime_scaffold=' + str(p.exists()))\nPY\n[ -f /tmp/repi-cloud-runtime.sh ] && /tmp/repi-cloud-runtime.sh || env | grep -Ei 'AWS_|AZURE_|GOOGLE_|KUBE|KUBERNETES' | sort",
			evidence: "rerun cloud/K8s identity and runtime config map",
		});
		followups.push({
			label: "cloud-runtime-config-rerun",
			command:
				"[ -f /tmp/repi-cloud-runtime.sh ] && /tmp/repi-cloud-runtime.sh || find . -maxdepth 5 -type f \\( -name 'Dockerfile*' -o -name '*.tf' -o -name '*deployment*.yml' -o -name '*rbac*.yml' \\) -print | head -240",
			evidence: "rerun container/K8s/IaC runtime configuration map",
		});
		followups.push({
			label: "cloud-metadata-probe-rerun",
			command:
				"[ -f /tmp/repi-cloud-metadata-probe.py ] && python3 /tmp/repi-cloud-metadata-probe.py || printf '%s\n' 'rerun cloud-metadata-probe-scaffold from re_lane plan'",
			evidence: "rerun bounded cloud metadata identity probe",
		});
		followups.push({
			label: "cloud-privilege-report-scaffold",
			command:
				"python3 - <<'PY'\nimport pathlib\nprint('[cloud-privilege-report] inputs=cloud identity/runtime/metadata/privilege anchors')\nfor path in ['/tmp/repi-cloud-runtime.sh','/tmp/repi-cloud-metadata-probe.py']:\n    print('[cloud-privilege-report]', path, 'exists=' + str(pathlib.Path(path).exists()))\nprint('Next: bind one principal, one resource scope, and one minimal allowed/denied action; record request/CLI output in evidence ledger.')\nPY",
			evidence: "consolidated cloud privilege edge report scaffold",
		});
	}
	return {
		findings,
		followups,
		nextLane:
			privilegeLines.length > 0
				? "privilege/report"
				: metadataLines.length > 0 || runtimeLines.length > 0
					? "metadata/privilege"
					: identityLines.length > 0
						? "runtime-config/metadata"
						: undefined,
	};
}

export function analyzeIdentityAdEvidence(pack: LaneCommandPack, combined: string): SpecialistEvidenceAnalysis {
	const enabled =
		/identity|windows|ad/i.test(pack.route) ||
		packHasSpecialistSignal(pack, /identity-ad|Identity\/AD graph|ad-principal|ad-credential|ad-graph/i);
	if (!enabled) return { findings: [], followups: [] };
	const findings: string[] = [];
	const followups: LaneCommand[] = [];
	const principalLines = interestingLines(
		combined,
		/\[ad-principal\]|\[ldap-anchor\]|servicePrincipalName|distinguishedName/i,
		18,
	);
	if (principalLines.length > 0) {
		findings.push(
			`Identity/AD principal anchors: ${principalLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const credentialLines = interestingLines(
		combined,
		/\[ad-credential-check\]|\[kerberos-ticket\]|Pwn3d!|STATUS_|KRB5CCNAME|NT_STATUS/i,
		18,
	);
	if (credentialLines.length > 0) {
		findings.push(
			`Identity/AD credential usability anchors: ${credentialLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	const graphLines = interestingLines(
		combined,
		/\[ad-graph-edge\]|\[ad-cert-edge\]|\[ad-graph-summary\]|GenericAll|GenericWrite|WriteDacl|AdminTo|MemberOf|ESC[1-9]/i,
		22,
	);
	if (graphLines.length > 0) {
		findings.push(
			`Identity/AD graph edge anchors: ${graphLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
		);
	}
	if (principalLines.length > 0 || credentialLines.length > 0 || graphLines.length > 0) {
		followups.push({
			label: "identity-ad-enum-rerun",
			command:
				"[ -f /tmp/repi-ad-enum.sh ] && /tmp/repi-ad-enum.sh || printf '%s\n' 'rerun identity-ad-principal-enum-scaffold after setting DOMAIN/DC_IP/LDAP_URL/TARGET env'",
			evidence: "rerun AD principal/protocol/ticket enumeration scaffold",
		});
		followups.push({
			label: "identity-ad-credential-check-rerun",
			command:
				"[ -f /tmp/repi-ad-credential-check.sh ] && /tmp/repi-ad-credential-check.sh || printf '%s\n' 'rerun identity-ad-credential-usability-scaffold after setting TARGET/USERNAME/PASSWORD or NTLM_HASH'",
			evidence: "rerun credential/ticket/hash usability check with controlled env",
		});
		followups.push({
			label: "identity-ad-graph-rerun",
			command:
				"[ -f /tmp/repi-ad-graph.py ] && python3 /tmp/repi-ad-graph.py || find . /tmp -maxdepth 3 -type f \\( -iname '*.json' -o -iname '*certipy*' -o -iname '*bloodhound*' \\) -print 2>/dev/null | head -120",
			evidence: "rerun BloodHound/Certipy graph edge summarizer",
		});
		followups.push({
			label: "identity-ad-report-scaffold",
			command:
				"python3 - <<'PY'\nprint('[ad-report] inputs=principal,credential,graph anchors')\nprint('Next: prove one minimal usable credential or graph edge, record exact command/status, then update attack graph.')\nPY",
			evidence: "consolidated identity/AD report scaffold",
		});
	}
	return {
		findings,
		followups,
		nextLane:
			graphLines.length > 0
				? "pivot-proof/report"
				: credentialLines.length > 0
					? "graph/pivot-proof"
					: principalLines.length > 0
						? "credentials/graph"
						: undefined,
	};
}
