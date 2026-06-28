import { type ChildProcess, spawn } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { APP_NAME, getAgentDir } from "../config.ts";
import { createMcpManager } from "./mcp-manager.ts";

export type AgentThreadStatus = "planned" | "running" | "complete" | "failed" | "timeout" | "stopped";

export interface AgentThreadSpec {
	name: string;
	description: string;
	systemPrompt: string;
	tools: string[];
	thinkingLevel: "off" | "minimal" | "low" | "medium" | "high" | "xhigh";
	maxTurns: number;
	memory: "off" | "scoped";
	isolation: "agent-home" | "agent-home-and-cwd";
	color: string;
	mcp?: {
		inherit: boolean;
		allowedServers?: string[];
		allowedTools?: string[];
	};
}

export interface AgentThreadRunManifest {
	kind: "repi-agent-thread-run";
	schemaVersion: 1;
	runId: string;
	specName: string;
	task: string;
	status: AgentThreadStatus;
	createdAt: string;
	startedAt?: string;
	endedAt?: string;
	pid?: number;
	exitCode?: number | null;
	signal?: string | null;
	cwd: string;
	runRoot: string;
	agentDir: string;
	stdoutPath: string;
	stderrPath: string;
	manifestPath: string;
	mergePath?: string;
	handoffPath?: string;
	provider?: string;
	model?: string;
	tools: string[];
	mcpServers?: string[];
	mcpTools?: string[];
	mcpInherited?: boolean;
	promptSha256?: string;
	stdoutSha256?: string;
	stderrSha256?: string;
	error?: string;
}

export interface SpawnAgentThreadOptions {
	specName?: string;
	task: string;
	provider?: string;
	model?: string;
	cwd?: string;
	timeoutMs?: number;
	additionalPrompt?: string;
	mcpServers?: string[];
	mcpTools?: string[];
	inheritMcp?: boolean;
}

export interface AgentThreadManagerOptions {
	cwd: string;
	agentDir?: string;
	repiBinPath?: string;
}

interface WorkerMcpInheritance {
	inherited: boolean;
	serverIds: string[];
	allowedTools: string[];
	runtimeToolNames: string[];
	serverAllowlistEnv?: string;
	toolAllowlistEnv?: string;
}

const SECRET_PATTERNS: Array<[RegExp, string]> = [
	[/\bsk-[A-Za-z0-9_-]{8,}\b/g, "<redacted:api-key>"],
	[/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>"],
	[/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>"],
	[/\b(cfut_[A-Za-z0-9_-]{8,})\b/g, "<redacted:cloudflare-token>"],
	[/(API_KEY|AUTH_TOKEN|TOKEN|SECRET|PASSWORD)=([^\s]+)/gi, "$1=<redacted>"],
];

function redact(text: string): string {
	let out = text;
	for (const [pattern, replacement] of SECRET_PATTERNS) out = out.replace(pattern, replacement);
	return out;
}

async function sha256(text: string): Promise<string> {
	const { createHash } = await import("node:crypto");
	return createHash("sha256").update(text).digest("hex");
}

function nowIso(): string {
	return new Date().toISOString();
}

function safeIdPart(text: string): string {
	return text
		.toLowerCase()
		.replace(/[^a-z0-9._-]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(0, 48);
}

function makeRunId(specName: string): string {
	return `${new Date().toISOString().replace(/[:.]/g, "-")}-${safeIdPart(specName) || "agent"}`;
}

function mkdirp(path: string): void {
	mkdirSync(path, { recursive: true, mode: 0o700 });
}

function readText(path: string, maxChars = 12000): string {
	try {
		const raw = readFileSync(path, "utf8");
		return raw.length > maxChars ? raw.slice(-maxChars) : raw;
	} catch {
		return "";
	}
}

function writeJson(path: string, value: unknown): void {
	writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

function readJson(path: string): any | undefined {
	if (!existsSync(path)) return undefined;
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch {
		return undefined;
	}
}

function sanitizeMcpToolNamePart(value: string, fallback: string): string {
	const sanitized = value
		.replace(/[^A-Za-z0-9_]/g, "_")
		.replace(/_+/g, "_")
		.replace(/^_+|_+$/g, "");
	return (sanitized || fallback).slice(0, 64);
}

function formatCommandForDisplay(command: string, args: string[]): string {
	return [command, ...args].map((arg) => (/[\s"'`$]/.test(arg) ? JSON.stringify(arg) : arg)).join(" ");
}

function resolveRepiBin(cwd: string, explicit?: string): string {
	if (explicit) return explicit;
	if (process.env.REPI_BIN_PATH) return process.env.REPI_BIN_PATH;
	const local = join(cwd, "repi");
	if (existsSync(local)) return local;
	return APP_NAME || "repi";
}

const EXPLORER_DOCTRINE = [
	"You are a REPI explorer subagent: a FAST READ-ONLY mapper. Never modify, exploit, or send traffic that changes state.",
	"Map the target surface and return only distilled findings, evidence refs, gaps, and next probes.",
	"Method: enumerate files/routes/configs/manifests/exports/imports/strings/endpoints; identify entry points and trust boundaries; tag each finding with an artifact path or command ref.",
	"For binaries: file/headers/arch, checksec mitigations, imports, interesting strings+xrefs, entry points — do NOT decompile or trace (that is the reverser's job).",
	"For web/services: routes, params, auth surface, version fingerprints — passive only.",
	"Reject speculation: every claim cites a command you ran or a path you read. Mark unknowns as gaps, not facts.",
	"Handoff: Outcome, Surface Map (bulleted, each with ref), Candidate Targets, Gaps, Next Probes.",
].join("\n");

const PLANNER_DOCTRINE = [
	"You are a REPI planner subagent. Turn an ambiguous objective into a concrete, falsifiable execution plan. Do NOT perform broad execution.",
	"Produce: Goal, Context (what is known with refs), Constraints, Done-when (observable proof exits, not 'understood').",
	"Split into lanes/workers with a one-line objective + proof contract per lane. Assign the right specialist (reverser for native/pwn/firmware/malware/memory, explorer for read-only mapping, verifier for falsification).",
	"Every plan step must have a proof-exit: a concrete reproducible command or artifact that distinguishes proved from attempted. Never accept 'looks done'.",
	"Order by leverage: cheapest falsifiable step first. Identify the single highest-leverage probe.",
	"Handoff: Plan (ordered steps), Proof Exits, Worker Split, Abandonment Criteria.",
].join("\n");

const OPERATOR_DOCTRINE = [
	"You are a REPI operator subagent: a bounded executor for command packs. Capture stdout/stderr/exit and concrete artifact refs.",
	"Run the given commands faithfully. Do NOT improvise broad exploration — that is the explorer/reverser's job.",
	"Avoid repeating failing commands. If a command fails twice with the same error, report blocked with the error and a minimal fix hint, do not retry variants blindly.",
	"Quote/escape targets safely. Never paste secrets into output; redact credentials and raw tokens.",
	"For each command record: command, exit code, one-line outcome, and any artifact path it produced.",
	"Handoff: Executed Steps (command|exit|outcome|artifact), Blockers, Next Step.",
].join("\n");

const VERIFIER_DOCTRINE = [
	"You are a REPI verifier subagent. Treat every prior claim as an UNVERIFIED hypothesis. Your job is FALSIFICATION, not confirmation.",
	"Reproduce the smallest path that proves or breaks the claim. Default verdict: refuted or inconclusive. 'proved' requires a stable repro (runs ≥2× identically) AND no counter-evidence.",
	"Run the claimed repro command yourself; if it needs a script/artifact, reconstruct the minimal version. Watch for flakiness, environment-dependence, and hidden assumptions.",
	"Attack the claim from the side: does it hold under a different input? Does the asserted primitive actually control the bytes the claim says it does? Does the exploit depend on a leak that wasn't demonstrated?",
	"Never mark 'attempted' as 'proved'. A crash is not an exploit; a string hit is not a vulnerability; a decompilation guess is not a confirmed transform.",
	"Handoff: Verdict (proved|refuted|inconclusive), Repro (exact commands run, ≥2 runs), Counter-evidence, Notes, Evidence refs.",
].join("\n");

const REVERSER_DOCTRINE = [
	"You are a REPI reverser subagent — the specialist for native binaries, pwn/exploit, firmware/IoT, malware, and memory forensics. You do the hard RE work; do not hand it back as a gap unless you have actually attempted the concrete steps below.",
	"",
	"## Doctrine: hypothesis → test → observe, falsifiable. Every claim must be backed by a reproducible command + an offset/artifact ref. 'Attempted' is never 'proved'. A crash is not an exploit; a decompile guess is not a confirmed transform.",
	"",
	"## Phase 0 — Tool availability (always first, before any RE step):",
	"- Probe each tool you intend to use with `command -v <tool>` (or read `$REPI_WORKER_TOOL_INDEX` if present). Only rely on tools that are present. For any missing tool, switch to the generic fallback below and record the substitution under Gaps.",
	"- Generic fallback table (works with a minimal binutils/python env, no special-case per-provider logic):",
	"  - checksec → `readelf -lW` (PIE iff `Type: DYN`; NX iff GNU_STACK has no E flag), `readelf -dW` (Full RELRO iff both `BIND_NOW`+`GNU_RELRO`), `__stack_chk_fail` in dynsyms = Canary, `readelf -sW | grep -i fortify` = FORTIFY.",
	"  - gdb/pwndbg → `strace -f`/`ltrace` for behavior, `objdump -d`/`r2 -A` for static control flow, set breakpoints by hand-reading disasm; no live stepping.",
	"  - binwalk/unblob → `dd`/`head`/`xxd` + `strings -n 6` + `hexdump -C`, manual magic-byte table (e.g. `\\x1f\\x8b` gzip, `\\x28\\xb5\\x2f\\xfd` zstd, squashfs `hsqs`), then `unsquashfs`/`tar`/`gunzip` on the carved slice.",
	"  - ROPgadget/ropper/one_gadget → `objdump -d <bin> | grep -E 'ret|pop .*; ret|jmp .*\\(.*\\)'` and hand-pick gadgets; compute libc offsets from `readelf -sW`/`objdump -T` + a known libc copy.",
	"  - pwntools → `python3` with stdlib `socket`/`struct`/`subprocess`; pack/recv by hand (`struct.pack('<Q', addr)`), pipe over a socket or `socat`.",
	"  - angr/z3 → manual constraint modeling: enumerate paths from disasm, write the branch conditions as python `if` predicates, solve magic constants by brute force / `z3` if present.",
	"  - volatility3 → manual: `strings <img> | grep -iE 'Windows|Linux|profile|kernel'` to guess OS/profile, carve processes with `grep -abo` offsets + `dd`, parse EPROCESS by hand against known struct offsets.",
	"  - yara/capa/floss → `strings -n 6` + manual `grep -E` rules for IOCs/CAPA-style capability strings; for decoded strings, replicate the decode loop in python.",
	"  - upx → detect `UPX!` magic; unpack only by running `upx -d` on a COPY if present, else carve and inflate by hand.",
	"- Prefer present specialized tools, but NEVER block on a missing one — the fallback must always produce an answer.",
	"",
	"## Phase 1 — Mitigation-aware triage (always first):",
	"- `file`/headers, arch, linkage; `checksec --file=` (PIE/NX/RELRO/Canary/FORTIFY/Path) or the `readelf` fallback from Phase 0; identify libc/loader version (`ldd`, `strings | grep GLIBC`, library paths).",
	"- Record the threat model: what input reaches the target, what channel (stdin/argv/network/file), what privilege.",
	"",
	"## Phase 2 — Static (r2/Ghidra, correlate don't guess):",
	"- r2: `r2 -A -q` then `afl` (functions), `ii`/`iz` (imports/strings), `axt <sym>` (xrefs to), `pdf @<fn>` / `pdg @<fn>` (disasm/decompile), `agvd` (call graph). Rename/retyping as you go. (If r2/Ghidra absent, use `objdump -d`/`readelf -a`/`nm` from Phase 0 fallback.)",
	"- Ghidra headless: `analyzeHeadless <proj> <prog> -import <bin> -postScript <DecompilerScript> -deleteProject`. Use for decompilation correlation against r2.",
	"- Follow data flow from INPUT to SINK. Identify the parser/handler, the bounds check (or its absence), the controlled write/read/crash site. Note exact offsets.",
	"- Strings/obfuscation: `strings -n 6`, `floss` for decoded strings, `capa` for capability/MAEC, `yara` rules. For packed/upx: `upx -d` only on a copy.",
	"",
	"## Phase 3 — Dynamic (gdb/pwndbg, prove the primitive):",
	"- `gdb -ex 'b *<addr>' -ex 'r < <input>'`; watch the controlled bytes at the sink. (If gdb absent, use the Phase 0 fallback: `strace -f` for syscalls, `objdump -d` hand-reading to confirm which bytes the input controls.)",
	"- Confirm: which bytes you control, how many, what they corrupt (return addr, fn ptr, vtable, len field). Convert crash → primitive: controlled write? arbitrary read? leak? PC control? Record the primitive precisely with the offset that triggers it.",
	"",
	"## Phase 4 — Primitive → reliable exploit (pwn):",
	"- Leak → base → gadget chain. `ROPgadget --binary`/`ropper`/`one_gadget` or the `objdump | grep` fallback from Phase 0; for libc, leak a GOT entry → compute libc base → ret2libc/one_gadget/ROP.",
	"- Build with pwntools (`pwn template`) or the `python3`+`socket`/`struct` fallback; test LOCAL first (≥3 runs stable), then remote. Stability across runs is mandatory, not optional.",
	"- For kernels/drivers: ioctl interface, structure layout, OOB index control. For webAssembly: wasm2c/wabt, table/memory control.",
	"",
	"## Firmware/IoT: `binwalk -Me`/`unblob` or the `dd`+`strings`+magic fallback → `unsquashfs`/`ubireader` → grep rootfs for config/secrets/credentials/web creds → identify services+versions → `qemu-<arch>-static`/`qemu-system` emulation to reach the service → then treat each service as a Native reverse target.",
	"## Malware: strings/imports/yara/capa/floss (or `strings -n 6`+manual rules fallback) → sandbox/trace behavior → decode config/C2 (XOR/base64/custom; use `angr`/`z3` or manual constraint modeling) → IOC list.",
	"## Memory forensics: `volatility3 -f <img> windows.info`/`linux.info` for profile or the manual strings/carve fallback → `pslist`/`pstree`/`netscan`/`cmdline`/`handles`/`credentials`/`malfind` → timeline + carve.",
	"",
	"## Symbolic/constraint solving: when static+dynamic stall (opaque branch, magic values, format-string offsets), use `angr` (symbolic execution to reach the target state) or `z3` (solve the constraint). State the model assumptions explicitly.",
	"",
	"## Tools: you have read/grep/find/ls/bash/write/edit — author PoC scripts and decompilation helper scripts as files, run them, and cite the artifact path. Keep noisy exploration inside this worker.",
	"",
	"## Completion gate (non-negotiable):",
	"- A pwn/exploit/decode/emulate task is NOT done because you can see the answer in disasm. Static analysis is triage. You have finished ONLY when the concrete artifact exists and ran: a PoC script written to disk, executed, and its real output captured (shell spawned / flag printed / controlled crash at the right offset / decoded blob written). 'I can see it would work' is a Gap, not an Outcome.",
	"- Do NOT emit your final message or stop the run until BOTH hold: (1) the PoC/primitive artifact was actually built and run with captured output, and (2) `$REPI_WORKER_HANDOFF_PATH` exists on disk with your full handoff. If you stop before writing that file, your entire run is LOST — the parent cannot see your reasoning, only the file and artifact paths survive the transport.",
	"- Write the handoff file incrementally if needed, but it MUST exist by your last turn. Cite the PoC artifact path and paste the captured proof output (the real stdout, not a paraphrase) into the Verification field.",
	"- If a tool is missing, use the Phase 0 fallback and STILL produce the artifact — never end on 'tool not installed'.",
	"",
	"## Handoff (required): Outcome, Primitive Found (with exact offsets + triggering input), PoC (reproducible commands + script artifact path), Mitigations in play, Evidence refs, Gaps (only after real attempts), Next Step.",
	"Do not include secrets. Redact credentials and raw tokens.",
].join("\n");

export const BUILTIN_AGENT_THREAD_SPECS: AgentThreadSpec[] = [
	{
		name: "explorer",
		description: "Fast read-only mapper for files, routes, configs, manifests, and low-risk surface inventory.",
		systemPrompt: EXPLORER_DOCTRINE,
		tools: ["read", "grep", "find", "ls", "bash"],
		thinkingLevel: "low",
		maxTurns: 4,
		memory: "off",
		isolation: "agent-home",
		color: "cyan",
		mcp: { inherit: true },
	},
	{
		name: "planner",
		description:
			"Turns ambiguous objectives into lane plans, gates, proof contracts, and worker packets without noisy execution.",
		systemPrompt: PLANNER_DOCTRINE,
		tools: ["read", "grep", "find", "ls", "write"],
		thinkingLevel: "medium",
		maxTurns: 3,
		memory: "off",
		isolation: "agent-home",
		color: "blue",
		mcp: { inherit: true },
	},
	{
		name: "operator",
		description: "Bounded executor for command packs; captures stdout/stderr/exit and concrete artifact refs.",
		systemPrompt: OPERATOR_DOCTRINE,
		tools: ["read", "grep", "find", "ls", "bash", "write"],
		thinkingLevel: "low",
		maxTurns: 6,
		memory: "scoped",
		isolation: "agent-home",
		color: "yellow",
		mcp: { inherit: true },
	},
	{
		name: "verifier",
		description:
			"Independent verifier that challenges claims, reruns minimal repros, and reports contradictions/gaps.",
		systemPrompt: VERIFIER_DOCTRINE,
		tools: ["read", "grep", "find", "ls", "bash", "write"],
		thinkingLevel: "high",
		maxTurns: 6,
		memory: "off",
		isolation: "agent-home",
		color: "green",
		mcp: { inherit: true },
	},
	{
		name: "reverser",
		description:
			"Specialist reverse/pwn worker for binaries, mobile/native traces, signatures, PCAP/DFIR, and exploit proof paths.",
		systemPrompt: REVERSER_DOCTRINE,
		tools: ["read", "grep", "find", "ls", "bash", "write", "edit"],
		thinkingLevel: "xhigh",
		maxTurns: 12,
		memory: "scoped",
		isolation: "agent-home",
		color: "magenta",
		mcp: { inherit: true },
	},
];

export class AgentThreadManager {
	private cwd: string;
	private agentDir: string;
	private repiBinPath: string;
	private children = new Map<string, ChildProcess>();
	private runPromises = new Map<string, Promise<AgentThreadRunManifest>>();
	private runResolvers = new Map<string, (manifest: AgentThreadRunManifest) => void>();

	constructor(options: AgentThreadManagerOptions) {
		this.cwd = resolve(options.cwd);
		this.agentDir = options.agentDir ?? getAgentDir();
		this.repiBinPath = resolveRepiBin(this.cwd, options.repiBinPath);
	}

	get root(): string {
		return join(this.agentDir, "recon", "agent-threads");
	}

	listSpecs(): AgentThreadSpec[] {
		return [...BUILTIN_AGENT_THREAD_SPECS];
	}

	getSpec(name = "explorer"): AgentThreadSpec {
		const normalized = name.trim().toLowerCase();
		const spec = BUILTIN_AGENT_THREAD_SPECS.find((item) => item.name === normalized);
		if (!spec) {
			throw new Error(
				`Unknown agent thread spec: ${name}. Available: ${BUILTIN_AGENT_THREAD_SPECS.map((item) => item.name).join(", ")}`,
			);
		}
		return spec;
	}

	listRuns(): AgentThreadRunManifest[] {
		if (!existsSync(this.root)) return [];
		return readdirSync(this.root, { withFileTypes: true })
			.filter((entry) => entry.isDirectory())
			.map((entry) => join(this.root, entry.name, "manifest.json"))
			.filter((path) => existsSync(path))
			.map((path) => {
				try {
					return JSON.parse(readFileSync(path, "utf8")) as AgentThreadRunManifest;
				} catch {
					return undefined;
				}
			})
			.filter((item): item is AgentThreadRunManifest => Boolean(item))
			.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
	}

	getRun(id = "latest"): AgentThreadRunManifest | undefined {
		const runs = this.listRuns();
		if (id === "latest") return runs[0];
		return runs.find((run) => run.runId === id || run.runId.startsWith(id));
	}

	async spawnThread(options: SpawnAgentThreadOptions): Promise<AgentThreadRunManifest> {
		const spec = this.getSpec(options.specName ?? "explorer");
		const runId = makeRunId(spec.name);
		const runRoot = join(this.root, runId);
		const workerAgentDir = join(runRoot, "agent-home");
		mkdirp(runRoot);
		mkdirp(workerAgentDir);

		// Provision the worker's isolated agent-home with the parent's provider/model
		// config so the child can authenticate. The child boots with
		// REPI_CODING_AGENT_DIR=workerAgentDir and would otherwise read an empty
		// skeleton (no provider entries) and fail with "No API key found for the
		// selected model". API keys referenced as $ENV in models.json resolve via the
		// inherited process.env. Copying settings.json also makes the child default to
		// the parent's defaultProvider/defaultModel when the caller omits --model.
		for (const name of ["models.json", "settings.json"] as const) {
			const src = join(this.agentDir, name);
			const dst = join(workerAgentDir, name);
			if (existsSync(src) && !existsSync(dst)) {
				try {
					copyFileSync(src, dst);
					chmodSync(dst, 0o600);
				} catch {
					// Non-fatal: child falls back to default model resolution.
				}
			}
		}

		const cwd = resolve(options.cwd ?? this.cwd);
		const stdoutPath = join(runRoot, "stdout.txt");
		const stderrPath = join(runRoot, "stderr.txt");
		const manifestPath = join(runRoot, "manifest.json");
		const mcpInheritance = this.prepareWorkerMcp(spec, options, workerAgentDir, cwd);
		const prompt = this.buildWorkerPrompt(spec, options.task, options.additionalPrompt, mcpInheritance);
		const promptSha256 = await sha256(prompt);
		const toolNames = [...new Set([...spec.tools, ...mcpInheritance.runtimeToolNames])];
		const args = [
			"--approve",
			...(options.provider ? ["--provider", options.provider] : []),
			...(options.model ? ["--model", options.model] : []),
			"--thinking",
			spec.thinkingLevel,
			"--no-session",
			...(toolNames.length > 0 ? ["--tools", toolNames.join(",")] : ["--no-tools"]),
			"-p",
			prompt,
		];

		const manifest: AgentThreadRunManifest = {
			kind: "repi-agent-thread-run",
			schemaVersion: 1,
			runId,
			specName: spec.name,
			task: options.task,
			status: "running",
			createdAt: nowIso(),
			startedAt: nowIso(),
			cwd,
			runRoot,
			agentDir: workerAgentDir,
			handoffPath: join(runRoot, "handoff.md"),
			stdoutPath,
			stderrPath,
			manifestPath,
			provider: options.provider,
			model: options.model,
			tools: toolNames,
			mcpServers: mcpInheritance.serverIds,
			mcpTools: mcpInheritance.allowedTools,
			mcpInherited: mcpInheritance.inherited,
			promptSha256,
		};
		writeFileSync(stdoutPath, "", { encoding: "utf8", mode: 0o600 });
		writeFileSync(stderrPath, "", { encoding: "utf8", mode: 0o600 });
		writeJson(manifestPath, manifest);

		const timeoutMs = Math.max(1000, options.timeoutMs ?? 10 * 60 * 1000);
		// The child boots in print mode (--no-session -p) whose default 210s
		// self-timeout would fire before this manager's spawn timer for any
		// delegation budget > 210s, silently capping re_subagent/reason/challenge
		// timeoutMs at 210s. Lift the child's inner print timeout above the spawn
		// timeout so this manager's timer remains the authoritative kill.
		const childPrintTimeoutMs = timeoutMs + 60_000;
		const child = spawn(this.repiBinPath, args, {
			cwd,
			env: {
				...process.env,
				REPI_CODING_AGENT_DIR: workerAgentDir,
				PI_CODING_AGENT_DIR: workerAgentDir,
				REPI_AGENT_THREAD: "1",
				REPI_SKIP_VERSION_CHECK: "1",
				REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
				PI_SKIP_VERSION_CHECK: "1",
				PI_SKIP_PACKAGE_UPDATE_CHECK: "1",
				REPI_TELEMETRY: "0",
				PI_TELEMETRY: "0",
				REPI_PRINT_TIMEOUT_MS: String(childPrintTimeoutMs),
				// File-based handoff — the child writes its findings to this path
				// via a tool call (write/bash) so the parent can recover the work
				// even when the reasoning model drops the final text block.
				REPI_WORKER_RUN_ROOT: runRoot,
				REPI_WORKER_HANDOFF_PATH: join(runRoot, "handoff.md"),
				REPI_WORKER_TOOL_INDEX: join(workerAgentDir, "recon", "tools", "tool-index.md"),
				...(mcpInheritance.serverAllowlistEnv !== undefined
					? { REPI_MCP_ALLOWED_SERVERS: mcpInheritance.serverAllowlistEnv }
					: {}),
				...(mcpInheritance.toolAllowlistEnv !== undefined
					? { REPI_MCP_ALLOWED_TOOLS: mcpInheritance.toolAllowlistEnv }
					: {}),
			},
			stdio: ["ignore", "pipe", "pipe"],
		});
		manifest.pid = child.pid;
		writeJson(manifestPath, manifest);
		this.children.set(runId, child);
		const runPromise = new Promise<AgentThreadRunManifest>((resolve) => {
			this.runResolvers.set(runId, resolve);
		});
		this.runPromises.set(runId, runPromise);

		let stdout = "";
		let stderr = "";
		const timer = setTimeout(() => {
			this.updateManifest(runId, { status: "timeout", error: `timeout_ms=${timeoutMs}` });
			child.kill("SIGTERM");
			setTimeout(() => {
				if (child.exitCode === null) child.kill("SIGKILL");
			}, 2000).unref();
		}, timeoutMs);

		child.stdout?.on("data", (chunk) => {
			const text = redact(String(chunk));
			stdout += text;
			if (stdout.length > 2 * 1024 * 1024) stdout = stdout.slice(-2 * 1024 * 1024);
			writeFileSync(stdoutPath, stdout, { encoding: "utf8", mode: 0o600 });
		});
		child.stderr?.on("data", (chunk) => {
			const text = redact(String(chunk));
			stderr += text;
			if (stderr.length > 512 * 1024) stderr = stderr.slice(-512 * 1024);
			writeFileSync(stderrPath, stderr, { encoding: "utf8", mode: 0o600 });
		});
		child.on("error", (error) => {
			this.updateManifest(runId, { status: "failed", error: redact(error.message), endedAt: nowIso() });
			this.resolveRun(runId);
		});
		child.on("close", async (code, signal) => {
			clearTimeout(timer);
			this.children.delete(runId);
			const existing = this.getRun(runId);
			const status: AgentThreadStatus =
				existing?.status === "timeout" ? "timeout" : code === 0 ? "complete" : "failed";
			this.updateManifest(runId, {
				status,
				endedAt: nowIso(),
				exitCode: code,
				signal,
				stdoutSha256: await sha256(readText(stdoutPath, 2 * 1024 * 1024)),
				stderrSha256: await sha256(readText(stderrPath, 512 * 1024)),
			});
			this.resolveRun(runId);
		});

		return manifest;
	}

	stopRun(id = "latest"): AgentThreadRunManifest | undefined {
		const run = this.getRun(id);
		if (!run) return undefined;
		const child = this.children.get(run.runId);
		if (child && child.exitCode === null) {
			child.kill("SIGTERM");
			this.updateManifest(run.runId, { status: "stopped", endedAt: nowIso() });
		}
		return this.getRun(run.runId);
	}

	awaitRun(runId: string): Promise<AgentThreadRunManifest> {
		const promise = this.runPromises.get(runId);
		if (!promise) {
			return Promise.reject(new Error(`Unknown agent thread run: ${runId}`));
		}
		return promise;
	}

	private resolveRun(runId: string): void {
		const resolve = this.runResolvers.get(runId);
		if (!resolve) return;
		this.runResolvers.delete(runId);
		this.runPromises.delete(runId);
		const manifest = this.getRun(runId) ?? ({ runId } as unknown as AgentThreadRunManifest);
		resolve(manifest);
	}

	mergeRun(id = "latest"): { manifest: AgentThreadRunManifest; text: string } | undefined {
		const manifest = this.getRun(id);
		if (!manifest) return undefined;
		const stdoutTail = redact(readText(manifest.stdoutPath, 12000));
		const stderrTail = redact(readText(manifest.stderrPath, 4000));
		const handoffPath = manifest.handoffPath ?? join(manifest.runRoot, "handoff.md");
		const handoffText = existsSync(handoffPath) ? redact(readText(handoffPath, 16000)) : "";
		const mergePath = join(manifest.runRoot, "merge.md");
		const text = [
			"# REPI AgentThread Merge",
			"",
			`AgentThreadMergeV1: true`,
			`run_id: ${manifest.runId}`,
			`spec: ${manifest.specName}`,
			`status: ${manifest.status}`,
			`task: ${manifest.task}`,
			`stdout_sha256: ${manifest.stdoutSha256 ?? "pending"}`,
			`stderr_sha256: ${manifest.stderrSha256 ?? "pending"}`,
			`handoff_path: ${handoffPath}`,
			"",
			handoffText ? ["## Worker handoff", "```text", handoffText, "```"].join("\n") : "",
			"## Distilled output tail",
			"```text",
			stdoutTail || (handoffText ? "(empty — see Worker handoff above)" : "(empty)"),
			"```",
			stderrTail ? ["", "## Stderr tail", "```text", stderrTail, "```"].join("\n") : "",
			"",
			"## Main-thread merge contract",
			"- The Worker handoff above (written to handoff.md by the child) is the authoritative result; the distilled stdout tail may be empty when the reasoning model drops the final text block.",
			"- Treat worker output as evidence candidates, not as final truth.",
			"- Promote only concrete claims with artifact paths, command output, hashes, offsets, requests, or reproducible steps.",
			"- Send unresolved gaps to verifier/operator workers instead of pasting raw logs into the main context.",
		]
			.filter(Boolean)
			.join("\n");
		writeFileSync(mergePath, text, { encoding: "utf8", mode: 0o600 });
		this.updateManifest(manifest.runId, { mergePath });
		return { manifest: this.getRun(manifest.runId) ?? manifest, text };
	}

	formatSpecs(): string {
		return [
			"Agent thread specs:",
			...this.listSpecs().map(
				(spec) =>
					`- ${spec.name} [tools=${spec.tools.join(",") || "none"}, mcp=${spec.mcp?.inherit ? "inherit" : "off"}, memory=${spec.memory}, maxTurns=${spec.maxTurns}]: ${spec.description}`,
			),
			"",
			"Usage:",
			"- /spawn <spec> <task>",
			"- /agent [latest|run-id|stop <run-id>]",
			"- /merge [latest|run-id]",
		].join("\n");
	}

	formatRuns(): string {
		const runs = this.listRuns().slice(0, 12);
		if (runs.length === 0) return "Agent threads: none";
		return [
			"Agent threads:",
			...runs.map(
				(run) =>
					`- ${run.runId} [${run.status}] ${run.specName}: ${run.task}\n  root=${run.runRoot}\n  stdout=${run.stdoutPath}`,
			),
		].join("\n");
	}

	formatRun(run: AgentThreadRunManifest): string {
		return [
			`Agent thread: ${run.runId}`,
			`status: ${run.status}`,
			`spec: ${run.specName}`,
			`task: ${run.task}`,
			`pid: ${run.pid ?? "n/a"}`,
			`cwd: ${run.cwd}`,
			`root: ${run.runRoot}`,
			`agent_home: ${run.agentDir}`,
			`stdout: ${run.stdoutPath}`,
			`stderr: ${run.stderrPath}`,
			`merge: ${run.mergePath ?? `run /merge ${run.runId}`}`,
			`tools: ${run.tools.join(",") || "none"}`,
			`mcp: ${run.mcpInherited ? `servers=${run.mcpServers?.join(",") || "none"} tools=${run.mcpTools?.join(",") || "all"}` : "off"}`,
			`provider/model: ${run.provider ?? "default"}/${run.model ?? "default"}`,
		].join("\n");
	}

	private prepareWorkerMcp(
		spec: AgentThreadSpec,
		options: SpawnAgentThreadOptions,
		workerAgentDir: string,
		cwd: string,
	): WorkerMcpInheritance {
		const noMcpSentinel = "__repi_no_mcp_servers__";
		const noToolSentinel = "__repi_no_mcp_tools__";
		const inherit = options.inheritMcp ?? spec.mcp?.inherit ?? false;
		if (!inherit) {
			return {
				inherited: false,
				serverIds: [],
				allowedTools: [],
				runtimeToolNames: [],
				serverAllowlistEnv: noMcpSentinel,
			};
		}
		const manager = createMcpManager({ cwd, agentDir: this.agentDir });
		const allServers = manager.loadServers();
		const requestedServers = options.mcpServers ?? spec.mcp?.allowedServers;
		const serverFilterActive = requestedServers !== undefined;
		const allowedServerSet = requestedServers?.length ? new Set(requestedServers) : undefined;
		const serverIds = allServers
			.map((server) => server.id)
			.filter((id) => !allowedServerSet || allowedServerSet.has(id));
		const toolFilterActive = options.mcpTools !== undefined || spec.mcp?.allowedTools !== undefined;
		const allowedTools = options.mcpTools ?? spec.mcp?.allowedTools ?? [];
		const runtimeToolNames = manager
			.createProxyToolDefinitions()
			.filter((tool) =>
				serverIds.some((serverId) => tool.name.startsWith(`mcp__${sanitizeMcpToolNamePart(serverId, "server")}__`)),
			)
			.map((tool) => tool.name);

		const parentMcpConfigPath = join(this.agentDir, "mcp.json");
		const parentConfig = readJson(parentMcpConfigPath);
		if (parentConfig && serverIds.length > 0) {
			const table = parentConfig.mcpServers ?? parentConfig.servers ?? {};
			const filtered = Object.fromEntries(Object.entries(table).filter(([id]) => serverIds.includes(id)));
			if (Object.keys(filtered).length > 0) writeJson(join(workerAgentDir, "mcp.json"), { mcpServers: filtered });
		}

		return {
			inherited: true,
			serverIds,
			allowedTools,
			runtimeToolNames,
			serverAllowlistEnv:
				serverIds.length > 0 ? serverIds.join(",") : serverFilterActive ? noMcpSentinel : undefined,
			toolAllowlistEnv:
				allowedTools.length > 0 ? allowedTools.join(",") : toolFilterActive ? noToolSentinel : undefined,
		};
	}

	private buildWorkerPrompt(
		spec: AgentThreadSpec,
		task: string,
		additionalPrompt?: string,
		mcp?: WorkerMcpInheritance,
	): string {
		return [
			spec.systemPrompt,
			"",
			"You are running as an isolated REPI child agent thread. Keep noisy exploration inside this worker context.",
			"Return a compact handoff with: Outcome, Key Evidence, Verification, Next Step, unresolved gaps, and artifact refs.",
			"Do not include secrets. Redact credentials and raw tokens.",
			"",
			"IMPORTANT — your FINAL assistant message MUST be a non-empty text block containing the handoff above. Do all your reasoning, then write the handoff as plain text in your reply. Never end the run on an empty message or a message with only tool calls — if you have finished the task, emit the text handoff as your last turn.",
			"",
			"Authoritative handoff (file-based) — COMPLETION GATE, not optional:",
			"  Your work reaches the parent ONLY through the file at `$REPI_WORKER_HANDOFF_PATH`. Your final reply text is frequently dropped by the transport (reasoning models put the summary in thinking blocks that are not transmitted). Therefore: if that file does not exist when you stop, your run is recorded as empty and the parent gets nothing — regardless of how much you did.",
			"  BEFORE your final turn, WRITE the file using your `write` tool, or via bash:",
			"  cat > \"$REPI_WORKER_HANDOFF_PATH\" <<'REPI_EOF'",
			"  Outcome: ...",
			"  Key Evidence: ...",
			"  Verification: ... (paste real captured command output, not a paraphrase)",
			"  Next Step: ...",
			"  Gaps: ...",
			"  Artifacts: ... (absolute paths to PoC scripts / dumps you created)",
			"  REPI_EOF",
			"  If the task asked you to build/prove/execute anything, the handoff is incomplete unless an artifact was built AND run with captured output — cite its path and paste the real output in Verification. Do not stop on 'I can see it would work'.",
			"",
			`Worker spec: ${spec.name}`,
			`Tools allowed: ${spec.tools.join(",") || "none"}`,
			mcp?.inherited
				? `MCP inherited: servers=${mcp.serverIds.join(",") || "none"} allowedTools=${mcp.allowedTools.join(",") || "all"} runtimeTools=${mcp.runtimeToolNames.join(",") || "none"}`
				: "MCP inherited: off",
			`Task: ${task}`,
			additionalPrompt ? `Additional guidance: ${additionalPrompt}` : "",
		]
			.filter(Boolean)
			.join("\n");
	}

	private updateManifest(runId: string, patch: Partial<AgentThreadRunManifest>): void {
		const manifestPath = join(this.root, runId, "manifest.json");
		if (!existsSync(manifestPath)) return;
		try {
			const current = JSON.parse(readFileSync(manifestPath, "utf8")) as AgentThreadRunManifest;
			writeJson(manifestPath, { ...current, ...patch });
		} catch {
			// Ignore broken manifest updates; callers can inspect stdout/stderr paths directly.
		}
	}

	formatSpawned(manifest: AgentThreadRunManifest): string {
		return [
			"Spawned REPI agent thread:",
			`- run_id: ${manifest.runId}`,
			`- spec: ${manifest.specName}`,
			`- status: ${manifest.status}`,
			`- pid: ${manifest.pid ?? "pending"}`,
			`- root: ${manifest.runRoot}`,
			`- stdout: ${manifest.stdoutPath}`,
			`- stderr: ${manifest.stderrPath}`,
			`- command: ${formatCommandForDisplay(this.repiBinPath, ["--no-session", "-p", "<worker-prompt>"])}`,
			"Next: /agent latest or /merge latest",
		].join("\n");
	}
}

export function createAgentThreadManager(options: AgentThreadManagerOptions): AgentThreadManager {
	return new AgentThreadManager(options);
}
