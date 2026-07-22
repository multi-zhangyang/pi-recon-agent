import { join } from "node:path";
import type { ExtensionAPI } from "../extensions/types.ts";
import type { ArtifactScopeFilterOptions } from "./artifact-scope.ts";
import type { EvidenceRecord } from "./evidence.ts";
import { type MissionCheckpointStatus, readCurrentMission } from "./mission.ts";
import { ensureReconStorage } from "./resources.ts";
import {
	evidenceMapsDir,
	evidenceNativeRuntimeDir,
	evidenceRunsDir,
	readTextFile as readText,
	recentMarkdownArtifacts,
	writePrivateTextFile,
} from "./storage.ts";
import { shellQuote } from "./target.ts";
import { interestingLines, parseJsonCodeFence, sha256Text, slug, truncateMiddle } from "./text.ts";

export type NativeRuntimeExecution = {
	label: string;
	command: string;
	status: "planned" | "passed" | "failed" | "blocked";
	exit?: number;
	killed?: boolean;
	stdoutHash?: string;
	stderrHash?: string;
	stdoutHead?: string;
	stderrHead?: string;
};

export type NativeRuntimeArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	mode: "plan" | "run";
	timeoutMs: number;
	captureScript: string;
	binaryInventory: string[];
	mitigationMatrix: string[];
	loaderLibc: string[];
	symbolMap: string[];
	crashPlan: string[];
	gdbTrace: string[];
	breakpointPlan: string[];
	exploitScaffold: string[];
	replayCommands: string[];
	executions: NativeRuntimeExecution[];
	runtimeAnchors: string[];
	nextActions: string[];
	sourceArtifacts: string[];
};

type RuntimeExecutionProofRow = {
	status?: unknown;
	command?: unknown;
	exit?: unknown;
	stdoutHash?: unknown;
	stdoutSha256?: unknown;
	stdout_sha256?: unknown;
	stderrHash?: unknown;
	stderrSha256?: unknown;
	stderr_sha256?: unknown;
	stdoutHead?: unknown;
	stderrHead?: unknown;
	output?: unknown;
};

type ArtifactSelector = (options?: ArtifactScopeFilterOptions) => string | undefined;
type LatestScopedMarkdownArtifact = (
	kind: string,
	dir: string,
	options?: ArtifactScopeFilterOptions,
) => string | undefined;
type AppendEvidence = (
	record: Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number },
) => EvidenceRecord;
type RuntimeCheckpointStatus = (
	mode: "plan" | "run" | "bundle",
	executions: readonly RuntimeExecutionProofRow[],
	target?: string,
) => MissionCheckpointStatus;
type UpdateMissionCheckpoint = (name: string, status: MissionCheckpointStatus, note?: string) => unknown;

export type NativeRuntimeDependencies = {
	latestScopedMarkdownArtifact: LatestScopedMarkdownArtifact;
	latestVerifierArtifactPath: ArtifactSelector;
	latestCompilerArtifactPath: ArtifactSelector;
	latestReplayerArtifactPath: ArtifactSelector;
	latestExploitLabArtifactPath: ArtifactSelector;
	appendEvidence: AppendEvidence;
	runtimeCheckpointStatus: RuntimeCheckpointStatus;
	updateMissionCheckpoint: UpdateMissionCheckpoint;
};

export function createNativeRuntime(dependencies: NativeRuntimeDependencies) {
	const {
		latestScopedMarkdownArtifact,
		latestVerifierArtifactPath,
		latestCompilerArtifactPath,
		latestReplayerArtifactPath,
		latestExploitLabArtifactPath,
		appendEvidence,
		runtimeCheckpointStatus,
		updateMissionCheckpoint,
	} = dependencies;
	const replayHash = sha256Text;
	const stripScriptIndent = (script: string): string => script.replace(/^\t/gm, "");
	function latestNativeRuntimeArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		return latestScopedMarkdownArtifact("native_runtime", evidenceNativeRuntimeDir(), options);
	}

	function inferNativeRuntimeTarget(target?: string): string | undefined {
		const trimmed = target?.trim();
		if (trimmed) return trimmed;
		for (const path of [
			recentMarkdownArtifacts(evidenceMapsDir(), 1)[0],
			recentMarkdownArtifacts(evidenceRunsDir(), 1)[0],
			latestNativeRuntimeArtifactPath(),
		]) {
			if (!path) continue;
			const text = readText(path);
			const explicit = /^target:\s*(.+)$/m.exec(text)?.[1]?.trim();
			if (explicit && !/^<.*>$|none$/i.test(explicit)) return explicit;
			const candidate = /binary[_ -]?candidate[^\n]*?([./\w-]+(?:\.elf|\.bin|\.so|vuln|challenge|license)?)/i
				.exec(text)?.[1]
				?.trim();
			if (candidate && !/^<.*>$|none$/i.test(candidate)) return candidate;
		}
		return undefined;
	}

	function nativeRuntimeGdbScript(): string {
		return stripScriptIndent(`set pagination off
	set confirm off
	set breakpoint pending on
	set disassembly-flavor intel
	set follow-fork-mode child
	set print pretty on
	printf "[native-gdb-script] loaded\\n"
	info files
	info functions main
	info functions strcmp
	info functions strncmp
	info functions memcmp
	info functions strstr
	info functions system
	break main
	rbreak strcmp
	rbreak strncmp
	rbreak memcmp
	rbreak strstr
	run
	printf "[native-gdb-after-run] stopped\\n"
	info registers
	bt
	x/16gx $sp
	quit`);
	}

	function nativeRuntimePythonAnalyzer(): string {
		return stripScriptIndent(`#!/usr/bin/env python3
	import json, os, shlex, sys
	path = sys.argv[1] if len(sys.argv) > 1 else './vuln'
	try:
	    import lief
	    binary = lief.parse(path)
	    imports = [str(item) for item in getattr(binary, 'imported_functions', [])[:80]]
	    print('[native-lief] format=%s entry=%s imports=%s' % (binary.format, hex(binary.entrypoint), json.dumps(imports)))
	except Exception as error:
	    print('[native-lief-unavailable] ' + str(error))
	try:
	    from pwn import ELF, context, cyclic, process
	    context.log_level = 'error'
	    elf = ELF(path, checksec=False)
	    print('[native-pwntools] arch=%s entry=%s bits=%s checksec=%s' % (elf.arch, hex(elf.entry), elf.bits, json.dumps(elf.checksec(), sort_keys=True)))
	    pattern = cyclic(512)
	    print('[native-cyclic] bytes=%d sha_head=%s' % (len(pattern), pattern[:48].hex()))
	    if os.environ.get('REPI_NATIVE_RUN') == '1':
	        argv = [path] + shlex.split(os.environ.get('REPI_NATIVE_ARGS', ''))
	        tube = process(argv)
	        tube.sendline(pattern)
	        tube.wait_for_close(timeout=float(os.environ.get('REPI_NATIVE_RUN_TIMEOUT_SEC', '5')))
	        print('[native-pwntools-run] exit=%s' % tube.poll())
	except Exception as error:
	    print('[native-pwntools-unavailable] ' + str(error))`);
	}

	function nativeRuntimeShellCommand(target?: string, timeoutMs = 12000): string {
		const targetArg = shellQuote(target?.trim() ?? "");
		const runTimeout = Math.max(3, Math.ceil(timeoutMs / 1000));
		return [
			"set +e",
			`TARGET=${targetArg}`,
			'printf "[native-env] file=%s readelf=%s objdump=%s gdb=%s checksec=%s ldd=%s strings=%s ROPgadget=%s ropper=%s patchelf=%s\\n" "$(command -v file || true)" "$(command -v readelf || true)" "$(command -v objdump || true)" "$(command -v gdb || true)" "$(command -v checksec || true)" "$(command -v ldd || true)" "$(command -v strings || true)" "$(command -v ROPgadget || true)" "$(command -v ropper || true)" "$(command -v patchelf || true)"',
			`if [ -n "$TARGET" ] && [ -e "$TARGET" ]; then printf "[native-binary] target=%s bytes=%s sha256=%s mode=%s file=%s\\n" "$TARGET" "$(wc -c < "$TARGET" 2>/dev/null || echo 0)" "$(sha256sum "$TARGET" 2>/dev/null | awk '{print $1}')" "$(stat -c "%a" "$TARGET" 2>/dev/null || echo NA)" "$(file -b "$TARGET" 2>/dev/null)"; else printf "[native-binary] target=%s exists=false\\n" "$TARGET"; echo "[native-runtime-blocked] reason=missing_target"; fi`,
			'if [ -n "$TARGET" ] && [ -e "$TARGET" ] && command -v checksec >/dev/null 2>&1; then checksec --file="$TARGET" 2>&1 | sed "s/^/[native-checksec] /"; else echo "[native-runtime-blocked] reason=checksec_missing_or_target_missing"; fi',
			'if [ -n "$TARGET" ] && [ -e "$TARGET" ] && command -v readelf >/dev/null 2>&1; then readelf -hW "$TARGET" 2>&1 | head -60 | sed "s/^/[native-readelf-header] /"; readelf -lW "$TARGET" 2>/dev/null | grep -E "GNU_STACK|GNU_RELRO|INTERP|LOAD" | sed "s/^/[native-readelf-program] /"; readelf -dW "$TARGET" 2>/dev/null | grep -E "NEEDED|RPATH|RUNPATH|BIND_NOW" | sed "s/^/[native-readelf-dynamic] /"; fi',
			'if [ -n "$TARGET" ] && [ -e "$TARGET" ] && command -v objdump >/dev/null 2>&1; then objdump -T "$TARGET" 2>/dev/null | grep -Ei "strcmp|strncmp|memcmp|strstr|gets|system|execve|printf|scanf|malloc|free|read|write" | head -80 | sed "s/^/[native-symbol] /"; objdump -d "$TARGET" 2>/dev/null | grep -En "call.*(strcmp|memcmp|strstr|system|gets)|<main>|<win>|<vuln>" | head -80 | sed "s/^/[native-disasm] /"; fi',
			'if [ -n "$TARGET" ] && [ -e "$TARGET" ] && command -v strings >/dev/null 2>&1; then strings -a "$TARGET" 2>/dev/null | grep -iE "flag|license|serial|password|key|/bin/sh|admin|debug|strcmp|memcmp|system" | head -80 | sed "s/^/[native-string] /"; fi',
			'if [ -n "$TARGET" ] && [ -e "$TARGET" ] && command -v ldd >/dev/null 2>&1; then ldd "$TARGET" 2>&1 | sed "s/^/[native-ldd] /"; fi',
			"cat > /tmp/repi-native-gdb.gdb <<'GDB'",
			nativeRuntimeGdbScript(),
			"GDB",
			'echo "[native-gdb-script] /tmp/repi-native-gdb.gdb breakpoints=main,strcmp,strncmp,memcmp,strstr run_env=REPI_NATIVE_RUN"',
			`if [ -n "$TARGET" ] && [ -e "$TARGET" ] && command -v gdb >/dev/null 2>&1 && [ "$REPI_NATIVE_RUN" = "1" ]; then timeout ${runTimeout}s gdb --interpreter=mi2 -q -batch -x /tmp/repi-native-gdb.gdb --args "$TARGET" $REPI_NATIVE_ARGS 2>&1 | sed "s/^/[native-gdb-mi] /"; else echo "[native-runtime-blocked] reason=gdb_run_skipped set_REPI_NATIVE_RUN=1 target=$TARGET"; fi`,
			"cat > /tmp/repi-native-analyze.py <<'PY'",
			nativeRuntimePythonAnalyzer(),
			"PY",
			'if [ -n "$TARGET" ] && [ -e "$TARGET" ]; then python3 /tmp/repi-native-analyze.py "$TARGET" 2>&1; fi',
		].join("\n");
	}

	function nativeRuntimeAnchors(stdout: string, stderr: string): string[] {
		const text = `${stdout}\n${stderr}`;
		return [
			...interestingLines(text, /\[native-env\]/i, 8).map(
				(line) => `native tool readiness anchors: ${truncateMiddle(line, 260)}`,
			),
			...interestingLines(text, /\[native-binary\]|\[native-file\]/i, 8).map(
				(line) => `native binary inventory anchors: ${truncateMiddle(line, 260)}`,
			),
			...interestingLines(text, /\[native-checksec\]|\[native-readelf/i, 24).map(
				(line) => `native mitigation/header anchors: ${truncateMiddle(line, 260)}`,
			),
			...interestingLines(text, /\[native-ldd\]/i, 16).map(
				(line) => `native loader/libc anchors: ${truncateMiddle(line, 260)}`,
			),
			...interestingLines(text, /\[native-symbol\]|\[native-disasm\]|\[native-string\]/i, 30).map(
				(line) => `native symbol/string anchors: ${truncateMiddle(line, 260)}`,
			),
			...interestingLines(text, /\[native-gdb-script\]|\[native-gdb\]/i, 40).map(
				(line) => `native GDB trace anchors: ${truncateMiddle(line, 260)}`,
			),
			...interestingLines(
				text,
				/SIGSEGV|Program received signal|RIP|RSP|EIP|ESP|info registers|bt|backtrace/i,
				30,
			).map((line) => `native crash/register anchors: ${truncateMiddle(line, 260)}`),
			...interestingLines(text, /\[native-(?:lief|pwntools|cyclic)/i, 12).map(
				(line) => `native analyzer anchors: ${truncateMiddle(line, 260)}`,
			),
			...interestingLines(text, /\[native-runtime-blocked\]/i, 12).map(
				(line) => `native runtime blocked anchors: ${truncateMiddle(line, 260)}`,
			),
		].slice(0, 120);
	}

	function buildNativeRuntimeArtifact(options: {
		target?: string;
		mode?: "plan" | "run";
		timeoutMs?: number;
		executions?: NativeRuntimeExecution[];
		runtimeAnchors?: string[];
	}): NativeRuntimeArtifact {
		ensureReconStorage();
		const mission = readCurrentMission();
		const target = inferNativeRuntimeTarget(options.target);
		const timeoutMs = Math.max(3000, Math.min(180000, Math.floor(options.timeoutMs ?? 12000)));
		const captureScript = nativeRuntimeShellCommand(target, timeoutMs);
		const binaryInventory = [
			target
				? `target=${target}: file/bytes/sha256/mode/ELF interpreter inventory`
				: "target=<missing>: pass ELF/SO/native executable path",
			"collect file, stat, sha256, strings, imported symbols, exported symbols, disassembly hotspots and candidate compare/crypto sinks",
		];
		const mitigationMatrix = [
			"checksec/readelf: NX, PIE, RELRO, canary, GNU_STACK, BIND_NOW and interpreter",
			"map mitigations to primitive path: overflow -> crash offset, format string -> leak, heap -> allocator/tcache anchors",
		];
		const loaderLibc = [
			"ldd/readelf NEEDED captures loader/libc path and dynamic dependencies",
			"record libc/ld-linux hash when local exploit depends on offsets; pin with patchelf or container if needed",
		];
		const symbolMap = [
			"objdump symbols/disassembly for strcmp/strncmp/memcmp/strstr/system/gets/read/write/malloc/free call sites",
			"strings for flag/license/key/password/debug/binsh markers and protocol prompts",
		];
		const crashPlan = [
			"generate cyclic pattern and capture crash register/stack under GDB only when REPI_NATIVE_RUN=1",
			"convert RIP/EIP/SP controlled bytes to offset, then rerun with focused breakpoint and verifier payload",
		];
		const breakpointPlan = [
			"GDB batch script breaks main and regex-breaks strcmp/strncmp/memcmp/strstr; records registers/backtrace/stack",
			"for SO/mobile-native use Frida or gdbserver attach; for foreign arch run under qemu-user with matching loader/rootfs",
		];
		const gdbTrace = [
			"/tmp/repi-native-gdb.gdb contains bounded GDB trace script",
			"default run skips target execution; set REPI_NATIVE_RUN=1 and optional REPI_NATIVE_ARGS for live trace",
		];
		const exploitScaffold = [
			"/tmp/repi-native-analyze.py uses LIEF and pwntools for format, imports, mitigations, and cyclic input",
			"REPI_NATIVE_RUN=1 enables the bounded pwntools process probe and GDB MI trace",
		];
		const replayCommands = [
			`re_native_runtime run ${target ?? "<elf-or-so>"} ${timeoutMs}`,
			"cat /tmp/repi-native-gdb.gdb",
			"cat /tmp/repi-native-analyze.py",
			target
				? `REPI_NATIVE_RUN=1 timeout ${Math.ceil(timeoutMs / 1000)}s gdb -q -batch -x /tmp/repi-native-gdb.gdb --args ${shellQuote(target)}`
				: "REPI_NATIVE_RUN=1 gdb -q -batch -x /tmp/repi-native-gdb.gdb --args <target>",
		];
		const nextActions = Array.from(
			new Set(
				[
					target && (options.mode ?? "plan") !== "run"
						? `re_native_runtime run ${target} ${timeoutMs}`
						: undefined,
					"re_lane plan primitive <target>",
					"re_verifier matrix",
					"re_compiler draft",
					"re_exploit_lab plan <poc>",
					"re_graph build",
				].filter((item): item is string => Boolean(item)),
			),
		).slice(0, 12);
		return {
			timestamp: new Date().toISOString(),
			missionId: mission?.id,
			route: mission?.route.domain,
			target,
			mode: options.mode ?? "plan",
			timeoutMs,
			captureScript,
			binaryInventory,
			mitigationMatrix,
			loaderLibc,
			symbolMap,
			crashPlan,
			gdbTrace,
			breakpointPlan,
			exploitScaffold,
			replayCommands,
			executions: options.executions ?? [],
			runtimeAnchors: options.runtimeAnchors ?? [],
			nextActions,
			sourceArtifacts: [
				recentMarkdownArtifacts(evidenceMapsDir(), 1)[0],
				recentMarkdownArtifacts(evidenceRunsDir(), 1)[0],
				latestVerifierArtifactPath(),
				latestCompilerArtifactPath(),
				latestReplayerArtifactPath(),
				latestExploitLabArtifactPath(),
			].filter((path): path is string => Boolean(path)),
		};
	}

	function formatNativeRuntime(
		native: NativeRuntimeArtifact,
		path?: string,
		options: { includeCaptureScript?: boolean } = {},
	): string {
		if (!options.includeCaptureScript) {
			const rows = (label: string, values: readonly string[], limit = 3) => [
				`${label}:`,
				...(values.length ? values.slice(0, limit).map((item) => `- ${truncateMiddle(item, 280)}`) : ["- none"]),
				...(values.length > limit ? [`- ... ${values.length - limit} more in artifact`] : []),
			];
			return [
				"native_runtime:",
				path ? `native_runtime_artifact: ${path}` : undefined,
				`timestamp: ${native.timestamp}`,
				`mode: ${native.mode}`,
				`mission_id: ${native.missionId ?? "none"}`,
				`route: ${native.route ?? "none"}`,
				`target: ${native.target ?? "<missing>"}`,
				`execution_count: ${native.executions.length}`,
				...rows(
					"executions",
					native.executions.map(
						(item) =>
							`${item.label} [${item.status}] exit=${item.exit ?? "n/a"} stdout_sha256=${item.stdoutHash ?? "n/a"} stderr_sha256=${item.stderrHash ?? "n/a"}`,
					),
					3,
				),
				...rows("runtime_anchors", native.runtimeAnchors, 16),
				...rows("next_actions", native.nextActions, 3),
				`next_native_command: ${native.mode === "run" ? "re_verifier matrix" : `re_native_runtime run ${native.target ?? "<elf-or-so>"}`}`,
				...(path ? [`details: read ${path}`] : []),
			]
				.filter(Boolean)
				.join("\n");
		}
		return [
			"native_runtime:",
			path ? `native_runtime_artifact: ${path}` : undefined,
			`timestamp: ${native.timestamp}`,
			`mode: ${native.mode}`,
			`mission_id: ${native.missionId ?? "none"}`,
			`route: ${native.route ?? "none"}`,
			`target: ${native.target ?? "<missing>"}`,
			`timeout_ms: ${native.timeoutMs}`,
			"binary_inventory:",
			...(native.binaryInventory.length ? native.binaryInventory.map((item) => `- ${item}`) : ["- none"]),
			"mitigation_matrix:",
			...(native.mitigationMatrix.length ? native.mitigationMatrix.map((item) => `- ${item}`) : ["- none"]),
			"loader_libc:",
			...(native.loaderLibc.length ? native.loaderLibc.map((item) => `- ${item}`) : ["- none"]),
			"symbol_map:",
			...(native.symbolMap.length ? native.symbolMap.map((item) => `- ${item}`) : ["- none"]),
			"crash_plan:",
			...(native.crashPlan.length ? native.crashPlan.map((item) => `- ${item}`) : ["- none"]),
			"gdb_trace:",
			...(native.gdbTrace.length ? native.gdbTrace.map((item) => `- ${item}`) : ["- none"]),
			"breakpoint_plan:",
			...(native.breakpointPlan.length ? native.breakpointPlan.map((item) => `- ${item}`) : ["- none"]),
			"exploit_scaffold:",
			...(native.exploitScaffold.length ? native.exploitScaffold.map((item) => `- ${item}`) : ["- none"]),
			"executions:",
			...(native.executions.length
				? native.executions.map(
						(item) =>
							`- ${item.label} [${item.status}] exit=${item.exit ?? "n/a"} stdout_sha256=${item.stdoutHash ?? "n/a"} stderr_sha256=${item.stderrHash ?? "n/a"}`,
					)
				: ["- planned native runtime capture; run re_native_runtime run <elf-or-so> [timeout-ms]"]),
			"runtime_anchors:",
			...(native.runtimeAnchors.length ? native.runtimeAnchors.map((item) => `- ${item}`) : ["- none"]),
			"replay_commands:",
			...(native.replayCommands.length ? native.replayCommands.map((item) => `- ${item}`) : ["- none"]),
			...(options.includeCaptureScript ? ["capture_script:", "```bash", native.captureScript, "```"] : []),
			"native_next_actions:",
			...(native.nextActions.length ? native.nextActions.map((item) => `- ${item}`) : ["- re_verifier matrix"]),
			`next_native_command: ${native.mode === "run" ? "re_verifier matrix" : `re_native_runtime run ${native.target ?? "<elf-or-so>"}`}`,
			"source_artifacts:",
			...(native.sourceArtifacts.length ? native.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
		]
			.filter(Boolean)
			.join("\n");
	}

	function writeNativeRuntimeArtifact(native: NativeRuntimeArtifact): string {
		ensureReconStorage();
		const path = join(
			evidenceNativeRuntimeDir(),
			`${native.timestamp.replace(/[:.]/g, "-")}-${slug(native.target ?? "native-runtime")}-${native.mode}.md`,
		);
		writePrivateTextFile(
			path,
			[
				"# REPI Native Runtime Artifact",
				"",
				formatNativeRuntime(native, path, { includeCaptureScript: true }),
				"",
				"## JSON",
				"",
				"```json",
				JSON.stringify(native, null, 2),
				"```",
				"",
			].join("\n"),
		);
		appendEvidence({
			kind: native.mode === "run" ? "runtime" : "artifact",
			title: `native-runtime-${native.mode} ${native.target ?? "no-target"}`,
			fact: `Native runtime ${native.mode}: target=${native.target ?? "<missing>"}, executions=${native.executions.length}, anchors=${native.runtimeAnchors.length}`,
			command: `re_native_runtime ${native.mode}${native.target ? ` ${native.target}` : ""}`,
			path,
			verify: `cat ${path}`,
			confidence: "native ELF/GDB/pwn runtime capture",
		});
		updateMissionCheckpoint(
			"native_runtime_ready",
			runtimeCheckpointStatus(native.mode, native.executions, native.target),
			path,
		);
		return path;
	}

	async function runNativeRuntime(
		pi: ExtensionAPI,
		options: { target?: string; timeoutMs?: number } = {},
	): Promise<string> {
		const target = inferNativeRuntimeTarget(options.target);
		const timeoutMs = Math.max(3000, Math.min(180000, Math.floor(options.timeoutMs ?? 12000)));
		const command = nativeRuntimeShellCommand(target, timeoutMs);
		const result = await pi.exec("bash", ["-lc", command], { timeout: timeoutMs + 10000 });
		const anchors = nativeRuntimeAnchors(result.stdout, result.stderr);
		const native = buildNativeRuntimeArtifact({
			...options,
			target,
			mode: "run",
			timeoutMs,
			executions: [
				{
					label: "native-runtime-capture",
					command,
					status: /\[native-runtime-blocked\] reason=missing_target/i.test(`${result.stdout}\n${result.stderr}`)
						? "blocked"
						: result.code === 0
							? "passed"
							: "failed",
					exit: result.code,
					killed: result.killed,
					stdoutHash: replayHash(result.stdout),
					stderrHash: replayHash(result.stderr),
					stdoutHead: truncateMiddle(result.stdout.trim(), 3000),
					stderrHead: truncateMiddle(result.stderr.trim(), 2000),
				},
			],
			runtimeAnchors: anchors,
		});
		const path = writeNativeRuntimeArtifact(native);
		return [
			formatNativeRuntime(native, path),
			result.stdout.trim() ? ["stdout:", "```", truncateMiddle(result.stdout.trim(), 1600), "```"].join("\n") : "",
			result.stderr.trim() ? ["stderr:", "```", truncateMiddle(result.stderr.trim(), 800), "```"].join("\n") : "",
		]
			.filter(Boolean)
			.join("\n");
	}

	function buildNativeRuntimeOutput(
		action: "plan" | "show" = "plan",
		options: { target?: string; timeoutMs?: number } = {},
	): string {
		if (action === "show") {
			const path = latestNativeRuntimeArtifactPath();
			if (!path) return "native_runtime:\nstatus: missing\nnext: re_native_runtime plan <elf-or-so>";
			const native = parseJsonCodeFence<NativeRuntimeArtifact>(readText(path));
			return native
				? formatNativeRuntime(native, path)
				: `native_runtime:\nstatus: unreadable\nnative_runtime_artifact: ${path}\nnext: read ${path}`;
		}
		const native = buildNativeRuntimeArtifact({ ...options, mode: "plan" });
		const path = writeNativeRuntimeArtifact(native);
		return formatNativeRuntime(native, path);
	}
	return {
		latestNativeRuntimeArtifactPath,
		inferNativeRuntimeTarget,
		nativeRuntimeGdbScript,
		nativeRuntimePythonAnalyzer,
		nativeRuntimeShellCommand,
		nativeRuntimeAnchors,
		buildNativeRuntimeArtifact,
		formatNativeRuntime,
		writeNativeRuntimeArtifact,
		runNativeRuntime,
		buildNativeRuntimeOutput,
	} as const;
}

export type NativeRuntime = ReturnType<typeof createNativeRuntime>;
