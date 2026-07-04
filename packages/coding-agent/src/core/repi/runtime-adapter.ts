import { closeSync, existsSync, openSync, readSync, statSync } from "node:fs";
import { join } from "node:path";
import { shellQuote } from "./target.ts";
import { truncateMiddle } from "./text.ts";

export type RuntimeAdapterStatus = "native-ready" | "fallback-ready" | "blocked";
export type RuntimeAdapterRunnerKind = "shell-command" | "cdp-capture" | "frida-hook" | "python-harness";
export type RuntimeAdapterTargetKind =
	| "web-url"
	| "cdp-endpoint"
	| "native-binary"
	| "pwn-binary"
	| "mobile-package"
	| "pcap-flow"
	| "firmware-image"
	| "firmware-rootfs"
	| "unknown";

export type RuntimeAdapterParserRuleV1 = {
	id: string;
	regex: string;
	evidenceRank: "runtime_artifact" | "network" | "served_asset" | "process_config";
	proofExitSignal: string;
};

export type RuntimeAdapterExecutionSpec = {
	id: string;
	bridgeId: string;
	domainId: string;
	tool: string;
	fallbackTool: string;
	runnerKind: RuntimeAdapterRunnerKind;
	commandTemplate: string;
	fallbackCommandTemplate: string;
	parserRules: RuntimeAdapterParserRuleV1[];
	artifactKinds: string[];
	ingestTargets: string[];
	envRefs: string[];
	proofExitSignals: string[];
};

export type RuntimeAdapterExecutionRowV1 = RuntimeAdapterExecutionSpec & {
	adapterId: string;
	present: boolean;
	fallbackPresent: boolean;
	status: RuntimeAdapterStatus;
	runnerReady: boolean;
	parserReady: boolean;
	artifactIngestReady: boolean;
	proofExitReady: boolean;
	envRefOnly: boolean;
	nextRuntimeCommands: string[];
};

export type RuntimeAdapterExecutionCheckV1 = {
	kind: "RuntimeAdapterExecutionCheckV1";
	schemaVersion: 1;
	generatedAt: string;
	RuntimeAdapterExecutionCheckV1: true;
	runtime: "runtime:adapter-execution";
	toolIndexPath: string;
	requiredChecks: string[];
	targetProfile?: RuntimeAdapterTargetProfileV1;
	adapters: RuntimeAdapterExecutionRowV1[];
	closure: {
		allAdapterSpecsPresent: boolean;
		allHaveRunnerTemplates: boolean;
		allHaveParserRules: boolean;
		allHaveArtifactKinds: boolean;
		allHaveIngestTargets: boolean;
		allHaveProofExitSignals: boolean;
		allHaveNativeOrFallbackTool: boolean;
		allEnvRefsSecretFree: boolean;
	};
	nextRuntimeCommands: string[];
	invariants: string[];
};

export type RuntimeAdapterExecutionArtifactV1 = {
	kind: "RuntimeAdapterExecutionArtifactV1";
	schemaVersion: 1;
	adapterId: string;
	domainId: string;
	bridgeId: string;
	target?: string;
	targetProfile?: RuntimeAdapterTargetProfileV1;
	startedAt: string;
	finishedAt: string;
	selectedRunner: "native" | "fallback";
	command: string;
	exitCode: number | null;
	killed: boolean;
	stdoutSha256: string;
	stderrSha256: string;
	parserSignals: Array<{
		ruleId: string;
		evidenceRank: RuntimeAdapterParserRuleV1["evidenceRank"];
		proofExitSignal: string;
		matches: string[];
	}>;
	parserSignalSummary?: RuntimeAdapterParserSignalSummaryV1;
	artifactKinds: string[];
	ingestTargets: string[];
	proofExitSignals: string[];
};

export type RuntimeAdapterTargetSignalV1 = {
	adapterId: string;
	targetKind: RuntimeAdapterTargetKind;
	reason: string;
	evidenceRank: "runtime_artifact" | "network" | "served_asset" | "process_config";
};

export type RuntimeAdapterTargetProfileV1 = {
	kind: "RuntimeAdapterTargetProfileV1";
	schemaVersion: 1;
	target: string;
	exists: boolean;
	pathKind?: "file" | "directory";
	magic?: string;
	targetKinds: RuntimeAdapterTargetKind[];
	adapterIds: string[];
	signals: RuntimeAdapterTargetSignalV1[];
	reasons: string[];
};

export type RuntimeAdapterParserSignalSummaryV1 = {
	matchedRules: number;
	totalRules: number;
	matchCount: number;
	evidenceRanks: Array<RuntimeAdapterParserRuleV1["evidenceRank"]>;
	matchedProofExitSignals: string[];
	missingProofExitSignals: string[];
};

export type RuntimeAdapterToolPresence = (tool: string) => boolean | undefined;

export const RUNTIME_ADAPTER_EXECUTION_MATRIX: RuntimeAdapterExecutionSpec[] = [
	{
		id: "r2-native-xref-adapter",
		bridgeId: "tool-bridge-runtime",
		domainId: "rev-native",
		tool: "r2",
		fallbackTool: "objdump",
		runnerKind: "shell-command",
		commandTemplate: "adapter-r2-native-xref-runner: r2 -A -q -c 'iI; afl; izz; axt @@ sym.main' <target>",
		fallbackCommandTemplate:
			"adapter-r2-native-xref-runner-fallback: file <target>; strings -a <target> | head -200; objdump -d <target> | head -240",
		parserRules: [
			{
				id: "parser-r2-symbol-import-xref",
				regex: "(sym\\.|imp\\.|xref|axt|CALL|JMP)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "symbol/import map",
			},
			{
				id: "parser-native-entrypoint",
				regex: "(entry|start|main|Entry point)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "control-flow xref",
			},
			{
				id: "parser-native-strings",
				regex: "(password|license|token|flag|secret|strcmp|memcmp)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "runtime adapter transcript",
			},
		],
		artifactKinds: ["native-xref-json", "native-symbol-map", "runtime-adapter-transcript"],
		ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
		envRefs: ["REPI_RUNTIME_ADAPTER_TIMEOUT_MS", "REPI_RUNTIME_ADAPTER_WORKDIR"],
		proofExitSignals: ["symbol/import map", "control-flow xref", "runtime adapter transcript"],
	},
	{
		id: "gdb-native-trace-adapter",
		bridgeId: "tool-bridge-runtime",
		domainId: "rev-native",
		tool: "gdb",
		fallbackTool: "objdump",
		runnerKind: "shell-command",
		commandTemplate:
			"adapter-gdb-native-trace-runner: gdb -q <target> -ex 'set pagination off' -ex 'set disassembly-flavor intel' -ex 'info files' -ex 'info functions' -ex 'break main' -ex 'run' -ex 'bt' -ex 'info registers' -ex 'quit'",
		fallbackCommandTemplate:
			"adapter-gdb-native-trace-runner-fallback: file <target>; readelf -h <target> 2>/dev/null; objdump -d <target> | head -260",
		parserRules: [
			{
				id: "parser-gdb-entry-registers",
				regex: "(Breakpoint|Program received signal|rip|eip|pc|info registers|backtrace|#0)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "debugger runtime trace",
			},
			{
				id: "parser-gdb-function-map",
				regex: "(All defined functions|main|sym\\.|Entry point|\\.text)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "function/runtime entry map",
			},
			{
				id: "parser-native-crash-signal",
				regex: "(SIGSEGV|SIGABRT|SIGILL|crash|stack|rsp|esp)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "crash/register proof",
			},
		],
		artifactKinds: ["gdb-runtime-trace", "native-register-map", "runtime-adapter-transcript"],
		ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
		envRefs: ["REPI_RUNTIME_ADAPTER_TIMEOUT_MS", "REPI_RUNTIME_ADAPTER_WORKDIR"],
		proofExitSignals: ["debugger runtime trace", "function/runtime entry map", "crash/register proof"],
	},
	{
		id: "ghidra-headless-summary-adapter",
		bridgeId: "tool-bridge-runtime",
		domainId: "rev-native",
		tool: "analyzeHeadless",
		fallbackTool: "readelf",
		runnerKind: "shell-command",
		commandTemplate:
			"adapter-ghidra-headless-summary-runner: analyzeHeadless " +
			"$" +
			"{REPI_GHIDRA_PROJECT_DIR:-/tmp/repi-ghidra} repi -import <target> -overwrite -scriptPath " +
			"$" +
			"{REPI_GHIDRA_SCRIPT_DIR:-/tmp} -postScript RepiSummary.java",
		fallbackCommandTemplate:
			"adapter-ghidra-headless-summary-runner-fallback: file <target>; readelf -h <target>; readelf -Ws <target> | head -160; objdump -T <target> 2>/dev/null | head -160 || true",
		parserRules: [
			{
				id: "parser-ghidra-function-summary",
				regex: "(Function|FUN_|decompile|symbol|xref)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "decompiler summary",
			},
			{
				id: "parser-native-entrypoint",
				regex: "(Entry point|start|main)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "function inventory",
			},
			{
				id: "parser-native-import-table",
				regex: "(UND|GLOBAL|GLIBC|Import|Symbol table)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "import table proof",
			},
		],
		artifactKinds: ["ghidra-headless-summary", "native-import-table", "runtime-adapter-transcript"],
		ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
		envRefs: ["REPI_GHIDRA_PROJECT_DIR", "REPI_GHIDRA_SCRIPT_DIR", "REPI_RUNTIME_ADAPTER_TIMEOUT_MS"],
		proofExitSignals: ["decompiler summary", "function inventory", "import table proof"],
	},
	{
		id: "frida-mobile-hook-adapter",
		bridgeId: "mobile-frida",
		domainId: "mobile",
		tool: "frida",
		fallbackTool: "bash",
		runnerKind: "frida-hook",
		commandTemplate:
			"adapter-frida-mobile-hook-runner: frida -U -f <target> -l " +
			"$" +
			"{REPI_FRIDA_HOOK:-hooks/repi-mobile.js} --no-pause",
		fallbackCommandTemplate: [
			"adapter-frida-mobile-hook-runner-fallback: target=<target>;",
			'if [ -f "$target" ]; then',
			'  file "$target";',
			"  if command -v unzip >/dev/null 2>&1; then unzip -l \"$target\" | sed -n '1,180p'; fi;",
			"  if command -v strings >/dev/null 2>&1; then strings -a \"$target\" | grep -E -i 'Crypto|Cipher|MessageDigest|NSURLSession|OkHttp|KeyStore|Keychain|TrustManager|CertificatePinner|SecTrust|pinning|X509' | head -180 || true; fi;",
			'  if command -v jadx >/dev/null 2>&1; then work="' +
				"$" +
				'{REPI_RUNTIME_ADAPTER_WORKDIR:-/tmp/repi-jadx-adapter}"; rm -rf "$work"; mkdir -p "$work"; jadx -q -d "$work" "$target" >/dev/null 2>&1 || true; grep -R -I -n -E \'Cipher|MessageDigest|OkHttp|TrustManager|CertificatePinner|KeyStore|Keychain|SecTrust|pinning\' "$work" 2>/dev/null | head -180 || true; fi;',
			"else",
			'  if command -v adb >/dev/null 2>&1; then adb shell pm path "$target" 2>/dev/null | head -20; adb shell dumpsys package "$target" 2>/dev/null | grep -E -i \'versionName|userId|permission|activity|service|provider|receiver|signatures\' | head -180 || true; else echo "[mobile-runtime-blocked] reason=adb_missing_and_target_not_file target=$target"; fi;',
			"fi",
		].join(" "),
		parserRules: [
			{
				id: "parser-frida-hook-output",
				regex: "(frida|hook|Interceptor|Java\\.perform|ObjC|Spawned|Attached)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "Java/ObjC/Swift hook",
			},
			{
				id: "parser-mobile-method-anchor",
				regex: "(Crypto|Cipher|MessageDigest|NSURLSession|OkHttp|KeyStore|Keychain|classes\\.dex|AndroidManifest\\.xml)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "runtime attach env checkpoint",
			},
			{
				id: "parser-cert-pinning-anchor",
				regex: "(TrustManager|CertificatePinner|SecTrust|pinning|X509)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "hook output artifact contract",
			},
		],
		artifactKinds: ["frida-hook-output-jsonl", "mobile-runtime-attach-manifest", "runtime-adapter-transcript"],
		ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
		envRefs: ["REPI_FRIDA_DEVICE", "REPI_FRIDA_HOOK", "REPI_ANDROID_SERIAL", "REPI_RUNTIME_ADAPTER_TIMEOUT_MS"],
		proofExitSignals: ["Java/ObjC/Swift hook", "runtime attach env checkpoint", "hook output artifact contract"],
	},
	{
		id: "web-cdp-network-adapter",
		bridgeId: "web-cdp-replay",
		domainId: "web-api",
		tool: "node",
		fallbackTool: "curl",
		runnerKind: "cdp-capture",
		commandTemplate: [
			"adapter-web-cdp-network-runner: node - <<'NODE'",
			"const crypto = require('node:crypto');",
			"const fs = require('node:fs');",
			"const target = process.env.REPI_ADAPTER_TARGET || '';",
			"const cdp = process.env.REPI_BROWSER_CDP_URL || '';",
			"function head(value, max = 8000) { return String(value ?? '').replace(/\\s+/g, ' ').slice(0, max); }",
			"function sha(value) { return crypto.createHash('sha256').update(String(value ?? '')).digest('hex').slice(0, 24); }",
			"function headerRows(headers) { return Array.isArray(headers) ? headers.map(h => [h.name || h.key || '', h.value || '']) : Object.entries(headers || {}); }",
			"function emitHar(targetPath) {",
			"  const har = JSON.parse(fs.readFileSync(targetPath, 'utf8'));",
			"  const entries = Array.isArray(har.log?.entries) ? har.log.entries : [];",
			"  console.log('[har-file] path=' + targetPath + ' entries=' + entries.length);",
			"  let routeIndex = 0;",
			"  for (const entry of entries.slice(0, 120)) {",
			"    const request = entry.request || {};",
			"    const response = entry.response || {};",
			"    const url = request.url || entry.url || '<unknown>';",
			"    const method = request.method || '<method>';",
			"    const bodyText = response.content?.text || request.postData?.text || '';",
			"    const status = response.status || 0;",
			"    routeIndex += 1;",
			"    console.log('[http-response] status=' + status + ' method=' + method + ' url=' + url + ' content_type=' + (response.content?.mimeType || '<none>') + ' bytes=' + String(bodyText).length + ' sha256=' + sha(bodyText));",
			"    console.log('[request-order] index=' + routeIndex + ' route=' + head(url, 700));",
			"    if (/\\/api\\/|graphql|websocket|wss?:\\/\\//i.test(url)) console.log('[route-candidate] ' + head(url, 700));",
			"    for (const [key, value] of [...headerRows(request.headers), ...headerRows(response.headers)]) if (/set-cookie|authorization|csrf|nonce|signature|timestamp|etag|location|x-[a-z0-9-]*sign/i.test(key + ': ' + value)) console.log('[http-header-signal] ' + key + ': ' + head(value, 500));",
			"    const signedSurface = [url, request.queryString, request.postData?.text, JSON.stringify(request.cookies || []), JSON.stringify(request.headers || [])].join(' ');",
			"    for (const match of signedSurface.matchAll(/(?:signature|\\bsign\\b|nonce|timestamp|x-[a-z0-9-]*sign[a-z0-9-]*|authorization|csrf)[^\\\"'<>\\s)]{0,180}/gi)) console.log('[crypto-request-field] ' + head(match[0], 400));",
			"  }",
			"}",
			"(async () => {",
			"  if (!target) { console.log('[adapter-error] missing target'); process.exitCode = 2; return; }",
			"  if (fs.existsSync(target) && fs.statSync(target).isFile()) { emitHar(target); return; }",
			"  if (cdp) {",
			"    const cdpHttp = cdp.replace(/^ws/i, 'http').replace(/\\/devtools\\/.*$/i, '');",
			"    try {",
			"      const cdpResponse = await fetch(cdpHttp.replace(/\\/$/, '') + '/json/version');",
			"      console.log('[cdp-endpoint] status=' + cdpResponse.status + ' url=' + cdpHttp);",
			"    } catch (error) {",
			"      console.log('[cdp-endpoint-error] ' + head(error && error.message ? error.message : error, 400));",
			"    }",
			"  }",
			"  const response = await fetch(target, { redirect: 'manual', headers: { 'User-Agent': 'REPI-runtime-adapter' } });",
			"  const body = await response.text();",
			"  console.log('[http-response] status=' + response.status + ' url=' + response.url + ' content_type=' + (response.headers.get('content-type') || '<none>') + ' bytes=' + body.length + ' sha256=' + sha(body));",
			"  for (const [key, value] of response.headers) if (/set-cookie|authorization|csrf|nonce|signature|timestamp|etag|location/i.test(key + ': ' + value)) console.log('[http-header-signal] ' + key + ': ' + head(value, 400));",
			"  console.log('[served-asset-head] ' + head(body));",
			"  const routeMatches = [...body.matchAll(/(?:fetch|XMLHttpRequest|WebSocket|graphql|\\/api\\/|wss?:\\/\\/)[^\\\"'<>\\s)]{0,240}/gi)].map((match) => match[0]);",
			"  const seenRoutes = new Set();",
			"  let routeIndex = 0;",
			"  for (const route of routeMatches) {",
			"    const compactRoute = head(route, 500);",
			"    if (seenRoutes.has(compactRoute)) continue;",
			"    seenRoutes.add(compactRoute);",
			"    routeIndex += 1;",
			"    console.log('[route-candidate] ' + compactRoute);",
			"    console.log('[request-order] index=' + routeIndex + ' route=' + compactRoute);",
			"    if (routeIndex >= 40) break;",
			"  }",
			"  const signingMatches = [...body.matchAll(/(?:signature|\\bsign\\b|nonce|timestamp|x-[a-z0-9-]*sign[a-z0-9-]*|authorization|csrf)[^\\\"'<>\\s)]{0,180}/gi)].map((match) => match[0]);",
			"  for (const item of [...new Set(signingMatches)].slice(0, 40)) console.log('[crypto-request-field] ' + head(item, 400));",
			"})().catch((error) => { console.log('[adapter-error] ' + head(error && error.stack ? error.stack : error)); process.exitCode = 1; });",
			"NODE",
		].join("\n"),
		fallbackCommandTemplate:
			'adapter-web-cdp-network-runner-fallback: body="' +
			"$" +
			'{REPI_RUNTIME_ADAPTER_WORKDIR:-/tmp}/repi-web-adapter-body.$$"; curl -k -L -sS -D - -o "$body" <target>; printf \'[http-response] curl_body=%s bytes=%s\\n\' "$body" "$(wc -c < "$body" 2>/dev/null || echo 0)"; head -c 12000 "$body"; rm -f "$body"',
		parserRules: [
			{
				id: "parser-cdp-network-event",
				regex: "(Network\\.|requestWillBeSent|responseReceived|\\[http-response\\]|HTTP/[0-9.]+|status=[0-9]{3})",
				evidenceRank: "network",
				proofExitSignal: "HTTP/CDP response capture",
			},
			{
				id: "parser-xhr-ws-route",
				regex: "(fetch|XMLHttpRequest|WebSocket|xhr|graphql|/api/|wss?://)",
				evidenceRank: "network",
				proofExitSignal: "XHR/WS route extraction",
			},
			{
				id: "parser-request-order-capture",
				regex: "(\\[request-order\\]|route_index=|request[_ -]?order)",
				evidenceRank: "served_asset",
				proofExitSignal: "request order proof",
			},
			{
				id: "parser-signed-replay-diff",
				regex: "(signature|\\bsign\\b|nonce|timestamp|x-[a-z0-9-]*sign|authorization|csrf)",
				evidenceRank: "network",
				proofExitSignal: "signed request replay",
			},
		],
		artifactKinds: [
			"cdp-network-har",
			"xhr-ws-route-map",
			"request-order-map",
			"signed-replay-diff",
			"runtime-adapter-transcript",
		],
		ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
		envRefs: ["REPI_BROWSER_CDP_URL", "REPI_BROWSER_PROFILE_DIR", "REPI_RUNTIME_ADAPTER_TIMEOUT_MS"],
		proofExitSignals: [
			"HTTP/CDP response capture",
			"XHR/WS route extraction",
			"signed request replay",
			"request order proof",
		],
	},
	{
		id: "pwntools-local-verifier-adapter",
		bridgeId: "exploit-verifier-runtime",
		domainId: "pwn",
		tool: "python3",
		fallbackTool: "gdb",
		runnerKind: "python-harness",
		commandTemplate: [
			"adapter-pwntools-local-verifier-runner: python3 - <<'PY'",
			"import hashlib, os, shutil, signal, stat, subprocess, sys",
			"target = os.environ.get('REPI_ADAPTER_TARGET', '')",
			"runs = max(1, min(int(os.environ.get('REPI_EXPLOIT_VERIFY_RUNS', '3') or '3'), 12))",
			"def sha(data): return hashlib.sha256(data or b'').hexdigest()[:24]",
			"def run(cmd, **kwargs):",
			"    try:",
			"        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=kwargs.pop('timeout', 4), **kwargs)",
			"        print('[tool-run] cmd=' + ' '.join(cmd[:3]) + ' exit=' + str(result.returncode) + ' stdout_sha256=' + sha(result.stdout) + ' stderr_sha256=' + sha(result.stderr))",
			"        out = (result.stdout + result.stderr).decode('latin1', 'replace')[:1600].replace('\\n', ' ')",
			"        if out: print('[tool-output-head] ' + out)",
			"        return result",
			"    except Exception as error:",
			"        print('[tool-error] cmd=' + ' '.join(cmd[:3]) + ' error=' + str(error))",
			"        return None",
			"print('[pwn-target] target=' + target + ' exists=' + str(os.path.exists(target)))",
			"if not target or not os.path.exists(target):",
			"    sys.exit(2)",
			"run(['file', target]) if shutil.which('file') else None",
			"run(['readelf', '-h', target]) if shutil.which('readelf') else None",
			"if shutil.which('strings'):",
			"    result = run(['strings', '-a', target], timeout=5)",
			"    text = ((result.stdout if result else b'') or b'').decode('latin1', 'replace')",
			"    interesting = sorted(set(x for x in ['system','execve','puts','printf','gets','strcpy','scanf','read','write','/bin/sh','flag','password','token'] if x in text))",
			"    if interesting: print('[pwn-primitive-candidate] symbols=' + ','.join(interesting))",
			"mode = os.stat(target).st_mode",
			"if not (mode & stat.S_IXUSR):",
			"    print('[pwn-exec-skip] reason=not_executable')",
			"    sys.exit(0)",
			"crashes = 0",
			"for index in range(runs):",
			"    try:",
			"        payload = (b'A' * 512) + b'\\n'",
			"        result = subprocess.run([target], input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=float(os.environ.get('REPI_EXPLOIT_RUN_TIMEOUT_SEC', '2')))",
			"        sig = -result.returncode if result.returncode < 0 else 0",
			"        if sig: crashes += 1",
			"        sig_name = signal.Signals(sig).name if sig else 'NONE'",
			"        print('[pwn-exec-run] run=' + str(index + 1) + ' exit=' + str(result.returncode) + ' signal=' + sig_name + ' stdout_sha256=' + sha(result.stdout) + ' stderr_sha256=' + sha(result.stderr) + ' stdout_bytes=' + str(len(result.stdout)) + ' stderr_bytes=' + str(len(result.stderr)))",
			"        if sig: print('[pwn-crash-observed] signal=' + sig_name + ' offset=needs_cyclic_repro')",
			"    except subprocess.TimeoutExpired as error:",
			"        print('[pwn-exec-timeout] run=' + str(index + 1) + ' timeout=' + str(error.timeout))",
			"print('[pwn-multirun-summary] runs=' + str(runs) + ' crash_runs=' + str(crashes))",
			"PY",
		].join("\n"),
		fallbackCommandTemplate:
			"adapter-pwntools-local-verifier-runner-fallback: file <target>; checksec --file=<target> 2>/dev/null || true; gdb -q <target> -ex 'set pagination off' -ex 'info files' -ex quit 2>/dev/null | head -220 || true",
		parserRules: [
			{
				id: "parser-pwn-crash-offset",
				regex: "(pwn-crash-observed|cyclic|offset=|SIGSEGV|SIGABRT|SIGILL|signal=SIG)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "crash-to-offset proof",
			},
			{
				id: "parser-pwn-leak-primitive",
				regex: "(pwn-primitive-candidate|leak|primitive|control|canary|libc|system|execve|puts|printf|gets|strcpy|read|write)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "primitive control evidence",
			},
			{
				id: "parser-pwn-multirun-success",
				regex: "(pwn-multirun-summary|pwn-exec-run|runs=)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "multi-run verifier",
			},
			{
				id: "parser-pwn-stdout-stderr-hash",
				regex: "(stdout_sha256|stderr_sha256)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "stdout/stderr hash",
			},
		],
		artifactKinds: ["pwn-verifier-matrix", "stdout-stderr-hashes", "runtime-adapter-transcript"],
		ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
		envRefs: ["REPI_EXPLOIT_VERIFY_RUNS", "REPI_RUNTIME_ADAPTER_TIMEOUT_MS"],
		proofExitSignals: [
			"crash-to-offset proof",
			"primitive control evidence",
			"multi-run verifier",
			"stdout/stderr hash",
		],
	},
	{
		id: "tshark-pcap-flow-adapter",
		bridgeId: "tool-bridge-runtime",
		domainId: "pcap-dfir",
		tool: "tshark",
		fallbackTool: "python3",
		runnerKind: "shell-command",
		commandTemplate:
			"adapter-tshark-pcap-flow-runner: tshark -r <target> -q -z conv,tcp; tshark -r <target> -Y http -T fields -e frame.number -e ip.src -e ip.dst -e http.host -e http.request.uri | head -200",
		fallbackCommandTemplate: [
			"adapter-tshark-pcap-flow-runner-fallback: python3 - <target> <<'PY'",
			"import collections, hashlib, re, socket, struct, sys",
			"path = sys.argv[1]",
			"data = open(path, 'rb').read()",
			"magic = data[:4]",
			"endian = '<' if magic in (b'\\xd4\\xc3\\xb2\\xa1', b'\\x4d\\x3c\\xb2\\xa1') else '>'",
			"off = 24 if len(data) >= 24 else len(data)",
			"packets = 0",
			"flows = collections.defaultdict(lambda: {'packets': 0, 'bytes': 0})",
			"def ip4(raw): return socket.inet_ntoa(raw)",
			"def sha(raw): return hashlib.sha256(raw).hexdigest()[:24]",
			"def clean(text): return re.sub(r'\\s+', ' ', text).strip()[:700]",
			"while off + 16 <= len(data) and packets < 10000:",
			"    try:",
			"        _sec, _usec, incl, _orig = struct.unpack(endian + 'IIII', data[off:off+16])",
			"    except Exception:",
			"        break",
			"    off += 16",
			"    frame = data[off:off+incl]",
			"    off += max(incl, 0)",
			"    packets += 1",
			"    ipoff = 14 if len(frame) >= 34 and frame[12:14] == b'\\x08\\x00' else 0",
			"    if len(frame) < ipoff + 20 or (frame[ipoff] >> 4) != 4 or frame[ipoff + 9] != 6:",
			"        continue",
			"    ihl = (frame[ipoff] & 15) * 4",
			"    tcpoff = ipoff + ihl",
			"    if len(frame) < tcpoff + 20:",
			"        continue",
			"    sport, dport = struct.unpack('!HH', frame[tcpoff:tcpoff+4])",
			"    doff = (frame[tcpoff + 12] >> 4) * 4",
			"    payload = frame[tcpoff + doff:]",
			"    src = ip4(frame[ipoff+12:ipoff+16]) + ':' + str(sport)",
			"    dst = ip4(frame[ipoff+16:ipoff+20]) + ':' + str(dport)",
			"    key = src + ' <-> ' + dst",
			"    flows[key]['packets'] += 1",
			"    flows[key]['bytes'] += len(payload)",
			"    text = payload.decode('latin1', 'replace')",
			"    if re.search(r'\\b(?:GET|POST|PUT|DELETE|PATCH|HTTP/)\\b|Host:', text, re.I):",
			"        first = text.splitlines()[0] if text.splitlines() else ''",
			"        host = (re.search(r'(?im)^Host:\\s*([^\\r\\n]+)', text) or [None, '<none>'])[1]",
			"        print('[http-object] frame=%d flow=%s first=%s Host: %s bytes=%d sha256=%s' % (packets, key, clean(first), clean(host), len(payload), sha(payload)))",
			"    for match in re.finditer(r'(?i)(cookie|authorization|password|passwd|token|credential|secret)[^\\r\\n;]{0,160}', text):",
			"        print('[credential-timeline] frame=%d flow=%s signal=%s' % (packets, key, clean(match.group(0))))",
			"print('[pcap-file] path=%s packets=%d flows=%d magic=%s' % (path, packets, len(flows), magic.hex()))",
			"for key, row in sorted(flows.items())[:200]:",
			"    print('[flow-conversation] %s packets=%d bytes=%d' % (key, row['packets'], row['bytes']))",
			"PY",
		].join("\n"),
		parserRules: [
			{
				id: "parser-tshark-conversation",
				regex: "(TCP Conversations|\\[flow-conversation\\]|<->|frames|packets=|bytes=)",
				evidenceRank: "network",
				proofExitSignal: "flow conversation",
			},
			{
				id: "parser-http-object",
				regex: "(\\[http-object\\]|HTTP|Host:|GET |POST |http\\.)",
				evidenceRank: "network",
				proofExitSignal: "follow-stream",
			},
			{
				id: "parser-credential-timeline",
				regex: "(\\[credential-timeline\\]|password|token|cookie|authorization|credential)",
				evidenceRank: "network",
				proofExitSignal: "timeline evidence",
			},
		],
		artifactKinds: ["pcap-flow-conversations", "pcap-http-objects", "runtime-adapter-transcript"],
		ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
		envRefs: ["REPI_RUNTIME_ADAPTER_TIMEOUT_MS"],
		proofExitSignals: ["flow conversation", "follow-stream", "timeline evidence"],
	},
	{
		id: "binwalk-firmware-extract-adapter",
		bridgeId: "tool-bridge-runtime",
		domainId: "firmware-iot",
		tool: "binwalk",
		fallbackTool: "file",
		runnerKind: "shell-command",
		commandTemplate:
			"adapter-binwalk-firmware-extract-runner: binwalk <target>; binwalk -eM <target> -C " +
			"$" +
			"{REPI_RUNTIME_ADAPTER_WORKDIR:-/tmp/repi-adapter-binwalk} 2>/dev/null || true",
		fallbackCommandTemplate:
			"adapter-binwalk-firmware-extract-runner-fallback: file <target>; strings -a <target> | grep -E 'squashfs|uboot|busybox|passwd|dropbear|httpd' -i | head -220 || true",
		parserRules: [
			{
				id: "parser-binwalk-signature",
				regex: "(DECIMAL|HEXADECIMAL|Squashfs|uImage|gzip|LZMA)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "filesystem extraction",
			},
			{
				id: "parser-rootfs-extract",
				regex: "(rootfs|squashfs|_.*\\.extracted|filesystem)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "service map",
			},
			{
				id: "parser-firmware-service-map",
				regex: "(httpd|dropbear|telnet|passwd|shadow|config)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "credential/config proof",
			},
		],
		artifactKinds: ["firmware-signature-map", "rootfs-extraction-manifest", "runtime-adapter-transcript"],
		ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
		envRefs: ["REPI_RUNTIME_ADAPTER_WORKDIR", "REPI_RUNTIME_ADAPTER_TIMEOUT_MS"],
		proofExitSignals: ["filesystem extraction", "service map", "credential/config proof"],
	},
	{
		id: "firmware-rootfs-service-map-adapter",
		bridgeId: "tool-bridge-runtime",
		domainId: "firmware-iot",
		tool: "find",
		fallbackTool: "grep",
		runnerKind: "shell-command",
		commandTemplate:
			"adapter-firmware-rootfs-service-map-runner: printf '[adapter-rootfs-target] target=%s\\n' <target>; find <target> -maxdepth 3 \\( -name passwd -o -name shadow -o -name '*.conf' -o -path '*/init.d/*' \\) -print | head -220; grep -R -I -n -E 'httpd|dropbear|telnet|busybox|passwd|shadow|uci|init\\.d|password|token|key' <target>/etc <target>/bin <target>/sbin 2>/dev/null | head -260 || true",
		fallbackCommandTemplate:
			"adapter-firmware-rootfs-service-map-runner-fallback: printf '[adapter-rootfs-target] target=%s\\n' <target>; file <target>; find <target> -maxdepth 3 -type f 2>/dev/null | head -220; grep -R -I -n -E 'httpd|dropbear|telnet|busybox|passwd|shadow|config' <target> 2>/dev/null | head -220 || true",
		parserRules: [
			{
				id: "parser-rootfs-passwd",
				regex: "(root:|/etc/passwd|passwd|shadow)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "account database proof",
			},
			{
				id: "parser-rootfs-service-init",
				regex: "(init\\.d|rc\\.d|systemd|httpd|dropbear|telnet|busybox)",
				evidenceRank: "process_config",
				proofExitSignal: "rootfs service map",
			},
			{
				id: "parser-rootfs-config-secret",
				regex: "(uci|config|password|token|key|credential|secret)",
				evidenceRank: "process_config",
				proofExitSignal: "credential/config proof",
			},
		],
		artifactKinds: ["rootfs-service-map", "rootfs-config-credential-scan", "runtime-adapter-transcript"],
		ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
		envRefs: ["REPI_RUNTIME_ADAPTER_TIMEOUT_MS", "REPI_RUNTIME_ADAPTER_WORKDIR"],
		proofExitSignals: ["account database proof", "rootfs service map", "credential/config proof"],
	},
];

function readFileHead(path: string, maxBytes = 4096): Buffer {
	const fd = openSync(path, "r");
	try {
		const buffer = Buffer.alloc(maxBytes);
		const bytesRead = readSync(fd, buffer, 0, buffer.length, 0);
		return buffer.subarray(0, bytesRead);
	} finally {
		closeSync(fd);
	}
}

function hasMagic(buffer: Buffer, bytes: number[]): boolean {
	return bytes.every((byte, index) => buffer[index] === byte);
}

function hasRootfsMarkers(path: string): boolean {
	const rootfsMarkers = [
		join(path, "etc", "passwd"),
		join(path, "etc", "shadow"),
		join(path, "etc", "init.d"),
		join(path, "etc", "config"),
		join(path, "etc", "os-release"),
		join(path, "bin", "busybox"),
		join(path, "sbin", "init"),
		join(path, "usr", "sbin", "httpd"),
	];
	return rootfsMarkers.some((marker) => existsSync(marker));
}

function magicLabel(head: Buffer, ascii: string): string | undefined {
	if (hasMagic(head, [0x7f, 0x45, 0x4c, 0x46])) return "elf";
	if (hasMagic(head, [0x4d, 0x5a])) return "pe-mz";
	if (
		hasMagic(head, [0xcf, 0xfa, 0xed, 0xfe]) ||
		hasMagic(head, [0xce, 0xfa, 0xed, 0xfe]) ||
		hasMagic(head, [0xfe, 0xed, 0xfa, 0xcf]) ||
		hasMagic(head, [0xfe, 0xed, 0xfa, 0xce]) ||
		hasMagic(head, [0xca, 0xfe, 0xba, 0xbe])
	)
		return "mach-o";
	if (hasMagic(head, [0x00, 0x61, 0x73, 0x6d])) return "wasm";
	if (hasMagic(head, [0x64, 0x65, 0x78, 0x0a])) return "android-dex";
	if (hasMagic(head, [0x50, 0x4b, 0x03, 0x04])) return "zip";
	if (
		hasMagic(head, [0xd4, 0xc3, 0xb2, 0xa1]) ||
		hasMagic(head, [0xa1, 0xb2, 0xc3, 0xd4]) ||
		hasMagic(head, [0x4d, 0x3c, 0xb2, 0xa1]) ||
		hasMagic(head, [0xa1, 0xb2, 0x3c, 0x4d])
	)
		return "pcap";
	if (hasMagic(head, [0x0a, 0x0d, 0x0d, 0x0a])) return "pcapng";
	if (/hsqs|sqsh/i.test(ascii)) return "squashfs";
	if (/UBI#|uImage|OpenWrt|BusyBox|u-boot|CFE/i.test(ascii)) return "firmware-signature";
	if (/^\s*[{[]/.test(ascii) && /"log"\s*:|"entries"\s*:|"request"\s*:|"response"\s*:/i.test(ascii)) return "har-json";
	return undefined;
}

function pushSignal(signals: RuntimeAdapterTargetSignalV1[], signal: RuntimeAdapterTargetSignalV1): void {
	if (signals.some((row) => row.adapterId === signal.adapterId && row.reason === signal.reason)) return;
	signals.push(signal);
}

function uniqueTargetKinds(signals: RuntimeAdapterTargetSignalV1[]): RuntimeAdapterTargetKind[] {
	return Array.from(new Set(signals.map((signal) => signal.targetKind)));
}

function uniqueAdapterIds(signals: RuntimeAdapterTargetSignalV1[]): string[] {
	return Array.from(new Set(signals.map((signal) => signal.adapterId)));
}

export function inspectRuntimeAdapterTarget(target?: string): RuntimeAdapterTargetProfileV1 {
	const text = target?.trim() ?? "";
	const signals: RuntimeAdapterTargetSignalV1[] = [];
	const add = (
		adapterId: string,
		targetKind: RuntimeAdapterTargetKind,
		reason: string,
		evidenceRank: RuntimeAdapterTargetSignalV1["evidenceRank"],
	) => pushSignal(signals, { adapterId, targetKind, reason, evidenceRank });
	if (!text) {
		return {
			kind: "RuntimeAdapterTargetProfileV1",
			schemaVersion: 1,
			target: "",
			exists: false,
			targetKinds: ["unknown"],
			adapterIds: [],
			signals: [],
			reasons: [],
		};
	}
	const lower = text.toLowerCase();
	let targetKind: "file" | "directory" | undefined;
	let exists = false;
	let magic: string | undefined;

	if (existsSync(text)) {
		try {
			const stat = statSync(text);
			exists = true;
			if (stat.isDirectory()) {
				targetKind = "directory";
				if (hasRootfsMarkers(text)) {
					add(
						"firmware-rootfs-service-map-adapter",
						"firmware-rootfs",
						"rootfs markers on existing directory",
						"process_config",
					);
				}
			} else if (stat.isFile()) {
				targetKind = "file";
			}
		} catch {
			// Best-effort target sniffing only; lexical detection below remains authoritative.
		}
	}

	if (/^https?:\/\//i.test(text)) add("web-cdp-network-adapter", "web-url", "http url target", "network");
	if (/\.(?:har)(?:$|[?#\s])/.test(lower))
		add("web-cdp-network-adapter", "web-url", "HAR network archive target", "network");
	if (
		/^(?:ws|wss):\/\//i.test(text) ||
		/\b(?:devtools\/browser|cdp|chrome-debugging|remote-debugging-port)\b/i.test(text)
	) {
		add("web-cdp-network-adapter", "cdp-endpoint", "cdp/websocket endpoint target", "network");
	}
	if (/\b(?:xhr|websocket|cookie|authorization|graphql|api|signed request|nonce|timestamp)\b/i.test(text)) {
		add("web-cdp-network-adapter", "web-url", "web api/replay lexical signal", "network");
	}
	if (
		targetKind !== "directory" &&
		(/\.(?:pcapng?|pcap|cap)(?:$|[?#\s])/.test(lower) || /\b(?:pcap|tshark|wireshark|packet|flow)\b/.test(lower))
	) {
		add("tshark-pcap-flow-adapter", "pcap-flow", "pcap/flow lexical signal", "network");
	}
	if (
		/\.(?:apk|ipa)(?:$|[?#\s])/.test(lower) ||
		/\b(?:frida|android|ios|objc|swift|keychain|okhttp|trustmanager|certificatepinner|jadx|dex|apktool)\b/.test(
			lower,
		) ||
		/^([a-z][a-z0-9_]*\.){2,}[a-z][a-z0-9_]*$/i.test(text)
	) {
		add("frida-mobile-hook-adapter", "mobile-package", "mobile package/runtime lexical signal", "runtime_artifact");
	}
	if (/\b(?:rootfs|openwrt-root|busybox-root|squashfs-root|init\.d|dropbear|uci)\b/.test(lower)) {
		add("firmware-rootfs-service-map-adapter", "firmware-rootfs", "rootfs/service lexical signal", "process_config");
	}
	if (
		/\.(?:bin|img|trx|chk|ubi|ubifs|squashfs|sqsh|uimage)(?:$|[?#\s])/.test(lower) ||
		/\b(?:firmware|rootfs|openwrt|busybox|u-boot|uboot|mtd|jffs2|cramfs)\b/.test(lower)
	) {
		add("binwalk-firmware-extract-adapter", "firmware-image", "firmware image lexical signal", "runtime_artifact");
	}
	if (/\b(?:pwn|exploit|rop|ret2|heap|tcache|format string|one_gadget|pwntools)\b/i.test(text)) {
		add("pwntools-local-verifier-adapter", "pwn-binary", "pwn/exploit lexical signal", "runtime_artifact");
	}
	if (/\b(?:gdb|breakpoint|register|core dump|coredump|sigsegv|crash)\b/i.test(text)) {
		add("gdb-native-trace-adapter", "native-binary", "debugger/crash lexical signal", "runtime_artifact");
	}
	if (
		/\b(?:radare2|\br2\b|xref|symbol|import|decompile|elf|pe|dll|so|wasm|binary|native|license|strcmp|memcmp)\b/i.test(
			text,
		) ||
		/\.(?:elf|exe|dll|so|wasm|dylib)(?:$|[?#\s])/.test(lower)
	) {
		add("r2-native-xref-adapter", "native-binary", "native reverse lexical signal", "runtime_artifact");
	}

	if (targetKind === "directory") {
		try {
			if (hasRootfsMarkers(text))
				add(
					"firmware-rootfs-service-map-adapter",
					"firmware-rootfs",
					"rootfs markers on directory",
					"process_config",
				);
		} catch {
			// Directory probes are advisory only.
		}
	} else if (targetKind === "file") {
		try {
			const head = readFileHead(text);
			const ascii = head.toString("latin1");
			magic = magicLabel(head, ascii);
			if (
				hasMagic(head, [0x7f, 0x45, 0x4c, 0x46]) ||
				hasMagic(head, [0x4d, 0x5a]) ||
				hasMagic(head, [0x00, 0x61, 0x73, 0x6d]) ||
				hasMagic(head, [0xcf, 0xfa, 0xed, 0xfe]) ||
				hasMagic(head, [0xce, 0xfa, 0xed, 0xfe]) ||
				hasMagic(head, [0xfe, 0xed, 0xfa, 0xcf]) ||
				hasMagic(head, [0xfe, 0xed, 0xfa, 0xce]) ||
				hasMagic(head, [0xca, 0xfe, 0xba, 0xbe])
			) {
				add("gdb-native-trace-adapter", "native-binary", `file magic=${magic ?? "native"}`, "runtime_artifact");
				add("r2-native-xref-adapter", "native-binary", `file magic=${magic ?? "native"}`, "runtime_artifact");
			}
			if (
				hasMagic(head, [0xd4, 0xc3, 0xb2, 0xa1]) ||
				hasMagic(head, [0xa1, 0xb2, 0xc3, 0xd4]) ||
				hasMagic(head, [0x4d, 0x3c, 0xb2, 0xa1]) ||
				hasMagic(head, [0xa1, 0xb2, 0x3c, 0x4d]) ||
				hasMagic(head, [0x0a, 0x0d, 0x0d, 0x0a])
			) {
				add("tshark-pcap-flow-adapter", "pcap-flow", `file magic=${magic ?? "pcap"}`, "network");
			}
			if (/^\s*[{[]/.test(ascii) && /"log"\s*:|"entries"\s*:|"request"\s*:|"response"\s*:/i.test(ascii)) {
				add("web-cdp-network-adapter", "web-url", `file magic=${magic ?? "har-json"}`, "network");
			}
			if (/hsqs|sqsh|UBI#|uImage|OpenWrt|BusyBox|u-boot|CFE/i.test(ascii))
				add(
					"binwalk-firmware-extract-adapter",
					"firmware-image",
					`file magic=${magic ?? "firmware-signature"}`,
					"runtime_artifact",
				);
			if (hasMagic(head, [0x64, 0x65, 0x78, 0x0a]))
				add("frida-mobile-hook-adapter", "mobile-package", "android dex magic", "runtime_artifact");
			if (
				hasMagic(head, [0x50, 0x4b, 0x03, 0x04]) &&
				(/\.(?:apk|ipa)$/i.test(text) || /AndroidManifest\.xml|classes\.dex|Payload\/|Info\.plist/i.test(ascii))
			) {
				add(
					"frida-mobile-hook-adapter",
					"mobile-package",
					`zip mobile manifest magic=${magic ?? "zip"}`,
					"runtime_artifact",
				);
			}
		} catch {
			// Best-effort file magic only; lexical detection above remains authoritative.
		}
	}
	const targetKinds = uniqueTargetKinds(signals);
	return {
		kind: "RuntimeAdapterTargetProfileV1",
		schemaVersion: 1,
		target: text,
		exists,
		pathKind: targetKind,
		magic,
		targetKinds: targetKinds.length ? targetKinds : ["unknown"],
		adapterIds: uniqueAdapterIds(signals),
		signals,
		reasons: Array.from(new Set(signals.map((signal) => signal.reason))),
	};
}

export function detectRuntimeAdapterIds(target?: string): string[] {
	return inspectRuntimeAdapterTarget(target).adapterIds;
}

export function runtimeAdapterSecretLike(value: string): boolean {
	return /(sk-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9_]{10,}|github_pat_[A-Za-z0-9_]{10,}|AKIA[0-9A-Z]{12,}|-----BEGIN [A-Z ]+PRIVATE KEY-----)/.test(
		value,
	);
}

export function buildRuntimeAdapterExecutionGate(
	adapterFilter: string | undefined,
	options: { toolIndexPath: string; isToolPresent: RuntimeAdapterToolPresence },
): RuntimeAdapterExecutionCheckV1 {
	const targetProfile = inspectRuntimeAdapterTarget(adapterFilter);
	const detectedAdapterIds = targetProfile.adapterIds;
	const specs = adapterFilter
		? RUNTIME_ADAPTER_EXECUTION_MATRIX.filter(
				(adapter) =>
					adapter.id === adapterFilter ||
					adapter.id.includes(adapterFilter) ||
					adapter.domainId.includes(adapterFilter) ||
					detectedAdapterIds.includes(adapter.id),
			)
		: RUNTIME_ADAPTER_EXECUTION_MATRIX;
	const adapters = specs.map<RuntimeAdapterExecutionRowV1>((adapter) => {
		const present = options.isToolPresent(adapter.tool) === true;
		const fallbackPresent = options.isToolPresent(adapter.fallbackTool) === true;
		return {
			...adapter,
			adapterId: adapter.id,
			present,
			fallbackPresent,
			status: present ? "native-ready" : fallbackPresent ? "fallback-ready" : "blocked",
			runnerReady:
				adapter.commandTemplate.includes("adapter-") && adapter.fallbackCommandTemplate.includes("fallback"),
			parserReady:
				adapter.parserRules.length >= 2 && adapter.parserRules.every((rule) => rule.id.startsWith("parser-")),
			artifactIngestReady:
				adapter.artifactKinds.length >= 2 &&
				adapter.ingestTargets.includes("evidence-ledger") &&
				adapter.ingestTargets.includes("knowledge-graph") &&
				adapter.ingestTargets.includes("memory-event"),
			proofExitReady: adapter.proofExitSignals.length >= 2,
			envRefOnly: adapter.envRefs.every((ref) => /^[A-Z][A-Z0-9_]+$/.test(ref) && !runtimeAdapterSecretLike(ref)),
			nextRuntimeCommands: [
				`re_runtime_adapter plan ${adapter.id} <target>`,
				`re_runtime_adapter run ${adapter.id} <target>`,
				"re_verifier matrix",
				`re_domain_proof_exit write ${adapter.domainId}`,
			],
		};
	});
	return {
		kind: "RuntimeAdapterExecutionCheckV1",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		RuntimeAdapterExecutionCheckV1: true,
		runtime: "runtime:adapter-execution",
		toolIndexPath: options.toolIndexPath,
		targetProfile: adapterFilter ? targetProfile : undefined,
		requiredChecks: [
			"runtime_adapter_execution_check",
			"adapter_runner_parser_ingest_contract",
			"gdb_native_trace_adapter_contract",
			"r2_ghidra_native_adapter_contract",
			"frida_mobile_adapter_contract",
			"web_cdp_adapter_contract",
			"pwntools_exploit_verifier_adapter_contract",
			"tshark_pcap_adapter_contract",
			"binwalk_firmware_adapter_contract",
			"firmware_rootfs_service_map_adapter_contract",
			"target_auto_detection_contract",
			"runtime_adapter_target_profile_contract",
			"parser_signal_summary_contract",
		],
		adapters,
		closure: {
			allAdapterSpecsPresent: adapters.length === RUNTIME_ADAPTER_EXECUTION_MATRIX.length || Boolean(adapterFilter),
			allHaveRunnerTemplates: adapters.every((adapter) => adapter.runnerReady),
			allHaveParserRules: adapters.every((adapter) => adapter.parserReady),
			allHaveArtifactKinds: adapters.every((adapter) => adapter.artifactKinds.length >= 2),
			allHaveIngestTargets: adapters.every((adapter) => adapter.artifactIngestReady),
			allHaveProofExitSignals: adapters.every((adapter) => adapter.proofExitReady),
			allHaveNativeOrFallbackTool: adapters.every((adapter) => adapter.present || adapter.fallbackPresent),
			allEnvRefsSecretFree: adapters.every((adapter) => adapter.envRefOnly),
		},
		nextRuntimeCommands: [
			"re_runtime_adapter show",
			"re_runtime_adapter plan <target-or-url-or-pcap>",
			"re_runtime_adapter run <target>",
			"re_runtime_adapter run web-cdp-network-adapter <url>",
			"re_runtime_adapter run gdb-native-trace-adapter <binary>",
			"re_runtime_adapter run firmware-rootfs-service-map-adapter <rootfs-dir>",
			"re_runtime_adapter show",
		],
		invariants: [
			"runtime_adapter_execution_check",
			"adapter_runner_parser_ingest_contract",
			"runner_output_parser_must_write_artifact",
			"artifact_ingest_target_must_include_evidence_knowledge_memory",
			"adapter_run_secret_literals_rejected",
		],
	};
}

export function formatRuntimeAdapterExecutionGate(report: RuntimeAdapterExecutionCheckV1, path?: string): string {
	return [
		"runtime_adapter_execution:",
		"RuntimeAdapterExecutionCheckV1: true",
		"runtime: runtime:adapter-execution",
		path ? `artifact: ${path}` : undefined,
		`tool_index: ${report.toolIndexPath}`,
		report.targetProfile
			? `target_profile: kinds=${report.targetProfile.targetKinds.join(",")} adapters=${report.targetProfile.adapterIds.join(",") || "<none>"} magic=${report.targetProfile.magic ?? "<none>"} reasons=${report.targetProfile.reasons.join(" | ") || "<none>"}`
			: undefined,
		`closure: specs=${report.closure.allAdapterSpecsPresent} runner=${report.closure.allHaveRunnerTemplates} parser=${report.closure.allHaveParserRules} artifact=${report.closure.allHaveArtifactKinds} ingest=${report.closure.allHaveIngestTargets} proof=${report.closure.allHaveProofExitSignals} fallback=${report.closure.allHaveNativeOrFallbackTool} env_ref=${report.closure.allEnvRefsSecretFree}`,
		"adapters:",
		...report.adapters.flatMap((adapter) => [
			`- adapter:${adapter.adapterId} bridge=${adapter.bridgeId} domain=${adapter.domainId} status=${adapter.status}`,
			`  runner_kind: ${adapter.runnerKind} tool=${adapter.tool} present=${adapter.present} fallback=${adapter.fallbackTool} fallback_present=${adapter.fallbackPresent}`,
			`  command_template: ${adapter.commandTemplate}`,
			`  fallback_template: ${adapter.fallbackCommandTemplate}`,
			`  parser_rules: ${adapter.parserRules.map((rule) => rule.id).join(", ")}`,
			`  artifact_kinds: ${adapter.artifactKinds.join(", ")}`,
			`  ingest_targets: ${adapter.ingestTargets.join(", ")}`,
			`  proof_exit_signals: ${adapter.proofExitSignals.join("; ")}`,
			`  env_refs: ${adapter.envRefs.join(", ")}`,
			`  next: ${adapter.nextRuntimeCommands.join(" | ")}`,
		]),
		"next_runtime_commands:",
		...report.nextRuntimeCommands.map((item) => `- ${item}`),
	]
		.filter(Boolean)
		.join("\n");
}

export function materializeRuntimeAdapterCommand(template: string, target?: string): string {
	const targetValue = target?.trim() || ".";
	return template.replace(/^[^:]+:\s*/, "").replaceAll("<target>", shellQuote(targetValue));
}

export function parseRuntimeAdapterSignals(
	adapter: RuntimeAdapterExecutionRowV1,
	combinedOutput: string,
): RuntimeAdapterExecutionArtifactV1["parserSignals"] {
	return adapter.parserRules.map((rule) => {
		let matches: string[] = [];
		try {
			const regex = new RegExp(rule.regex, "gi");
			matches = Array.from(combinedOutput.matchAll(regex))
				.map((match) => truncateMiddle(match[0], 180))
				.slice(0, 12);
		} catch (error) {
			matches = [`parser_error=${error instanceof Error ? error.message : String(error)}`];
		}
		return { ruleId: rule.id, evidenceRank: rule.evidenceRank, proofExitSignal: rule.proofExitSignal, matches };
	});
}

export function summarizeRuntimeAdapterSignals(
	adapter: RuntimeAdapterExecutionRowV1,
	parserSignals: RuntimeAdapterExecutionArtifactV1["parserSignals"],
): RuntimeAdapterParserSignalSummaryV1 {
	const matchedSignals = parserSignals.filter((signal) => signal.matches.length > 0);
	const matchedProofExitSignals = Array.from(new Set(matchedSignals.map((signal) => signal.proofExitSignal)));
	const missingProofExitSignals = adapter.proofExitSignals.filter(
		(signal) => !matchedProofExitSignals.includes(signal),
	);
	return {
		matchedRules: matchedSignals.length,
		totalRules: adapter.parserRules.length,
		matchCount: matchedSignals.reduce((sum, signal) => sum + signal.matches.length, 0),
		evidenceRanks: Array.from(new Set(matchedSignals.map((signal) => signal.evidenceRank))),
		matchedProofExitSignals,
		missingProofExitSignals,
	};
}

export function formatRuntimeAdapterExecutionArtifact(
	artifact: RuntimeAdapterExecutionArtifactV1,
	path?: string,
): string {
	return [
		"runtime_adapter_run:",
		"RuntimeAdapterExecutionArtifactV1: true",
		path ? `artifact: ${path}` : undefined,
		`adapter: ${artifact.adapterId}`,
		`domain: ${artifact.domainId}`,
		`bridge: ${artifact.bridgeId}`,
		`target: ${artifact.target ?? "<none>"}`,
		`runner: ${artifact.selectedRunner}`,
		`exit: ${artifact.exitCode} killed=${artifact.killed}`,
		`stdout_sha256: ${artifact.stdoutSha256}`,
		`stderr_sha256: ${artifact.stderrSha256}`,
		`command: ${artifact.command}`,
		"parser_signals:",
		...artifact.parserSignals.map(
			(signal) =>
				`- ${signal.ruleId} rank=${signal.evidenceRank} => ${signal.proofExitSignal}: ${signal.matches.join(" | ") || "no-match"}`,
		),
		artifact.parserSignalSummary
			? `parser_signal_summary: matched=${artifact.parserSignalSummary.matchedRules}/${artifact.parserSignalSummary.totalRules} matches=${artifact.parserSignalSummary.matchCount} ranks=${artifact.parserSignalSummary.evidenceRanks.join(",") || "<none>"} missing_proof=${artifact.parserSignalSummary.missingProofExitSignals.join("; ") || "<none>"}`
			: undefined,
		`artifact_kinds: ${artifact.artifactKinds.join(", ")}`,
		`ingest_targets: ${artifact.ingestTargets.join(", ")}`,
		`proof_exit_signals: ${artifact.proofExitSignals.join("; ")}`,
	]
		.filter(Boolean)
		.join("\n");
}
