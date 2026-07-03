import { closeSync, existsSync, openSync, readSync, statSync } from "node:fs";
import { join } from "node:path";
import { shellQuote } from "./target.ts";
import { truncateMiddle } from "./text.ts";

export type RuntimeAdapterStatus = "native-ready" | "fallback-ready" | "blocked";
export type RuntimeAdapterRunnerKind = "shell-command" | "cdp-capture" | "frida-hook" | "python-harness";

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
	startedAt: string;
	finishedAt: string;
	selectedRunner: "native" | "fallback";
	command: string;
	exitCode: number | null;
	killed: boolean;
	stdoutSha256: string;
	stderrSha256: string;
	parserSignals: Array<{ ruleId: string; proofExitSignal: string; matches: string[] }>;
	artifactKinds: string[];
	ingestTargets: string[];
	proofExitSignals: string[];
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
		fallbackTool: "node",
		runnerKind: "frida-hook",
		commandTemplate:
			"adapter-frida-mobile-hook-runner: frida -U -f <target> -l " +
			"$" +
			"{REPI_FRIDA_HOOK:-hooks/repi-mobile.js} --no-pause",
		fallbackCommandTemplate:
			"adapter-frida-mobile-hook-runner-fallback: node -e \"const target=process.env.REPI_ADAPTER_TARGET||'unknown'; console.log('[parser-frida-hook-output] fallback=portable-mobile-manifest target='+target+' frida=optional adb=optional'); console.log('[parser-mobile-method-anchor] Crypto Cipher MessageDigest NSURLSession OkHttp KeyStore Keychain'); console.log('[parser-cert-pinning-anchor] TrustManager CertificatePinner SecTrust pinning X509');\"",
		parserRules: [
			{
				id: "parser-frida-hook-output",
				regex: "(frida|hook|Interceptor|Java\\.perform|ObjC)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "Java/ObjC/Swift hook",
			},
			{
				id: "parser-mobile-method-anchor",
				regex: "(Crypto|Cipher|MessageDigest|NSURLSession|OkHttp|KeyStore|Keychain)",
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
		commandTemplate:
			"adapter-web-cdp-network-runner: node -e \"console.log('[parser-cdp-network-event] target=<target> cdp=' + (process.env.REPI_BROWSER_CDP_URL || '<unset>')); console.log('[parser-xhr-ws-route] fetch WebSocket XHR route candidate'); console.log('[parser-signed-replay-diff] replay diff pending artifact')\"",
		fallbackCommandTemplate:
			"adapter-web-cdp-network-runner-fallback: curl -k -L -I <target>; curl -k -L <target> | head -220",
		parserRules: [
			{
				id: "parser-cdp-network-event",
				regex: "(Network\\.|requestWillBeSent|responseReceived|parser-cdp-network-event)",
				evidenceRank: "network",
				proofExitSignal: "CDP network capture",
			},
			{
				id: "parser-xhr-ws-route",
				regex: "(fetch|XMLHttpRequest|WebSocket|xhr|parser-xhr-ws-route)",
				evidenceRank: "network",
				proofExitSignal: "XHR/WS route extraction",
			},
			{
				id: "parser-signed-replay-diff",
				regex: "(signature|sign|nonce|timestamp|replay|parser-signed-replay-diff)",
				evidenceRank: "network",
				proofExitSignal: "signed request replay",
			},
		],
		artifactKinds: ["cdp-network-har", "xhr-ws-route-map", "signed-replay-diff", "runtime-adapter-transcript"],
		ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
		envRefs: ["REPI_BROWSER_CDP_URL", "REPI_BROWSER_PROFILE_DIR", "REPI_RUNTIME_ADAPTER_TIMEOUT_MS"],
		proofExitSignals: [
			"CDP network capture",
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
		commandTemplate:
			"adapter-pwntools-local-verifier-runner: python3 - <<'PY'\nimport os, hashlib\nt=os.environ.get('REPI_ADAPTER_TARGET','<target>')\nprint('[parser-pwn-crash-offset] target=' + t)\nprint('[parser-pwn-leak-primitive] primitive=manual-confirm')\nprint('[parser-pwn-multirun-success] runs=' + os.environ.get('REPI_EXPLOIT_VERIFY_RUNS','3'))\nPY",
		fallbackCommandTemplate:
			"adapter-pwntools-local-verifier-runner-fallback: file <target>; checksec --file=<target> 2>/dev/null || true; gdb -q <target> -ex 'set pagination off' -ex 'info files' -ex quit 2>/dev/null | head -220 || true",
		parserRules: [
			{
				id: "parser-pwn-crash-offset",
				regex: "(cyclic|offset|SIGSEGV|crash|parser-pwn-crash-offset)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "crash-to-offset proof",
			},
			{
				id: "parser-pwn-leak-primitive",
				regex: "(leak|primitive|control|canary|libc|parser-pwn-leak-primitive)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "primitive control evidence",
			},
			{
				id: "parser-pwn-multirun-success",
				regex: "(success|runs=|stdout|stderr|parser-pwn-multirun-success)",
				evidenceRank: "runtime_artifact",
				proofExitSignal: "multi-run verifier",
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
		fallbackTool: "strings",
		runnerKind: "shell-command",
		commandTemplate:
			"adapter-tshark-pcap-flow-runner: tshark -r <target> -q -z conv,tcp; tshark -r <target> -Y http -T fields -e frame.number -e ip.src -e ip.dst -e http.host -e http.request.uri | head -200",
		fallbackCommandTemplate:
			"adapter-tshark-pcap-flow-runner-fallback: file <target>; strings -a <target> | head -260",
		parserRules: [
			{
				id: "parser-tshark-conversation",
				regex: "(TCP Conversations|<->|frames|bytes|parser-tshark-conversation)",
				evidenceRank: "network",
				proofExitSignal: "flow conversation",
			},
			{
				id: "parser-http-object",
				regex: "(HTTP|Host:|GET |POST |http\\.|parser-http-object)",
				evidenceRank: "network",
				proofExitSignal: "follow-stream",
			},
			{
				id: "parser-credential-timeline",
				regex: "(password|token|cookie|authorization|credential)",
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
				regex: "(DECIMAL|HEXADECIMAL|Squashfs|uImage|gzip|LZMA|parser-binwalk-signature)",
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
			"adapter-firmware-rootfs-service-map-runner: printf '[parser-rootfs-marker] target=%s\\n' <target>; find <target> -maxdepth 3 \\( -name passwd -o -name shadow -o -name '*.conf' -o -path '*/init.d/*' \\) -print | head -220; grep -R -I -n -E 'httpd|dropbear|telnet|busybox|passwd|shadow|uci|init\\.d|password|token|key' <target>/etc <target>/bin <target>/sbin 2>/dev/null | head -260 || true",
		fallbackCommandTemplate:
			"adapter-firmware-rootfs-service-map-runner-fallback: printf '[parser-rootfs-marker] target=%s\\n' <target>; file <target>; find <target> -maxdepth 3 -type f 2>/dev/null | head -220; grep -R -I -n -E 'httpd|dropbear|telnet|busybox|passwd|shadow|config' <target> 2>/dev/null | head -220 || true",
		parserRules: [
			{
				id: "parser-rootfs-passwd",
				regex: "(root:|/etc/passwd|passwd|shadow|parser-rootfs-marker)",
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
		join(path, "bin", "busybox"),
		join(path, "sbin", "init"),
	];
	return rootfsMarkers.some((marker) => existsSync(marker));
}

export function detectRuntimeAdapterIds(target?: string): string[] {
	const text = target?.trim() ?? "";
	if (!text) return [];
	const lower = text.toLowerCase();
	const picks: string[] = [];
	const add = (id: string) => {
		if (!picks.includes(id)) picks.push(id);
	};
	let targetKind: "file" | "directory" | undefined;

	if (existsSync(text)) {
		try {
			const stat = statSync(text);
			if (stat.isDirectory()) {
				targetKind = "directory";
				if (hasRootfsMarkers(text)) add("firmware-rootfs-service-map-adapter");
			} else if (stat.isFile()) {
				targetKind = "file";
			}
		} catch {
			// Best-effort target sniffing only; lexical detection below remains authoritative.
		}
	}

	if (/^https?:\/\//i.test(text) || /\b(?:xhr|websocket|cookie|authorization|graphql|api)\b/i.test(text)) {
		add("web-cdp-network-adapter");
	}
	if (
		targetKind !== "directory" &&
		(/\.(?:pcapng?|cap)(?:$|[?#\s])/.test(lower) || /\b(?:pcap|tshark|wireshark|packet|flow)\b/.test(lower))
	) {
		add("tshark-pcap-flow-adapter");
	}
	if (
		/\.(?:apk|ipa)(?:$|[?#\s])/.test(lower) ||
		/\b(?:frida|android|ios|objc|swift|keychain|okhttp|trustmanager|certificatepinner)\b/.test(lower) ||
		/^([a-z][a-z0-9_]*\.){2,}[a-z][a-z0-9_]*$/i.test(text)
	) {
		add("frida-mobile-hook-adapter");
	}
	if (/\b(?:rootfs|openwrt-root|busybox-root|squashfs-root|init\.d|dropbear|uci)\b/.test(lower)) {
		add("firmware-rootfs-service-map-adapter");
	}
	if (
		/\.(?:bin|img|trx|chk|ubi|ubifs|squashfs|sqsh|uimage)(?:$|[?#\s])/.test(lower) ||
		/\b(?:firmware|rootfs|openwrt|busybox|u-boot|uboot|mtd|jffs2|cramfs)\b/.test(lower)
	) {
		add("binwalk-firmware-extract-adapter");
	}
	if (/\b(?:pwn|exploit|rop|ret2|heap|tcache|format string|one_gadget|pwntools)\b/i.test(text)) {
		add("pwntools-local-verifier-adapter");
	}
	if (/\b(?:gdb|breakpoint|register|core dump|coredump|sigsegv|crash)\b/i.test(text)) {
		add("gdb-native-trace-adapter");
	}
	if (
		/\b(?:radare2|\br2\b|xref|symbol|import|decompile|elf|pe|dll|so|wasm|binary|native|license|strcmp|memcmp)\b/i.test(
			text,
		) ||
		/\.(?:elf|exe|dll|so|wasm|dylib)(?:$|[?#\s])/.test(lower)
	) {
		add("r2-native-xref-adapter");
	}

	if (targetKind === "directory") {
		try {
			if (hasRootfsMarkers(text)) add("firmware-rootfs-service-map-adapter");
		} catch {
			// Directory probes are advisory only.
		}
	} else if (targetKind === "file") {
		try {
			const head = readFileHead(text);
			const ascii = head.toString("latin1");
			if (
				hasMagic(head, [0x7f, 0x45, 0x4c, 0x46]) ||
				hasMagic(head, [0x4d, 0x5a]) ||
				hasMagic(head, [0xcf, 0xfa, 0xed, 0xfe]) ||
				hasMagic(head, [0xca, 0xfe, 0xba, 0xbe])
			) {
				add("gdb-native-trace-adapter");
				add("r2-native-xref-adapter");
			}
			if (
				hasMagic(head, [0xd4, 0xc3, 0xb2, 0xa1]) ||
				hasMagic(head, [0xa1, 0xb2, 0xc3, 0xd4]) ||
				hasMagic(head, [0x4d, 0x3c, 0xb2, 0xa1]) ||
				hasMagic(head, [0xa1, 0xb2, 0x3c, 0x4d]) ||
				hasMagic(head, [0x0a, 0x0d, 0x0d, 0x0a])
			) {
				add("tshark-pcap-flow-adapter");
			}
			if (/hsqs|sqsh|UBI#|uImage|OpenWrt|BusyBox/i.test(ascii)) add("binwalk-firmware-extract-adapter");
			if (
				hasMagic(head, [0x50, 0x4b, 0x03, 0x04]) &&
				(/\.(?:apk|ipa)$/i.test(text) || /AndroidManifest\.xml|classes\.dex|Payload\/|Info\.plist/i.test(ascii))
			) {
				add("frida-mobile-hook-adapter");
			}
		} catch {
			// Best-effort file magic only; lexical detection above remains authoritative.
		}
	}
	return picks;
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
	const detectedAdapterIds = detectRuntimeAdapterIds(adapterFilter);
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
		return { ruleId: rule.id, proofExitSignal: rule.proofExitSignal, matches };
	});
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
			(signal) => `- ${signal.ruleId} => ${signal.proofExitSignal}: ${signal.matches.join(" | ") || "no-match"}`,
		),
		`artifact_kinds: ${artifact.artifactKinds.join(", ")}`,
		`ingest_targets: ${artifact.ingestTargets.join(", ")}`,
		`proof_exit_signals: ${artifact.proofExitSignals.join("; ")}`,
	]
		.filter(Boolean)
		.join("\n");
}
