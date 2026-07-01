import { type ChildProcess, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
	appendFileSync,
	chmodSync,
	closeSync,
	copyFileSync,
	existsSync,
	mkdirSync,
	openSync,
	readdirSync,
	readFileSync,
	readSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { APP_NAME, getAgentDir } from "../config.ts";
import { createMcpManager } from "./mcp-manager.ts";
import { atomicWriteFileSync } from "./tools/atomic-write.ts";
import { safeTailStart } from "./tools/truncate.ts";

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

export function makeRunId(specName: string): string {
	// Two spawns of the same spec in the same millisecond (parallel re_subagent
	// delegations, or sequential sub-ms spacing) produce an identical runId →
	// identical runRoot → the second spawn's writeFileSync(stdoutPath/"")
	// /writeJson(manifestPath) TRUNCATES the first run's logs + manifest, and
	// this.children.set(runId, secondChild) EVICTS the first child from the
	// children map (orphaning it: the exit-hook reaper can no longer kill it →
	// cost/quota leak; its close handler deletes the second child's map entry;
	// resolveRun delivers the wrong manifest to one caller). Append a
	// collision-resistant random suffix so runRoot is unique per spawn. The
	// ISO-ms prefix keeps run dirs human-sortable by start time.
	return `${new Date().toISOString().replace(/[:.]/g, "-")}-${safeIdPart(specName) || "agent"}-${randomBytes(4).toString("hex")}`;
}

function mkdirp(path: string): void {
	mkdirSync(path, { recursive: true, mode: 0o700 });
}

// Cap on bytes readText will ever load into memory (opt #156). maxChars is in
// UTF-16 code units; a UTF-8 byte stream can need up to 4 bytes per BMP char
// (and the tail slice may start mid-codepoint, so we read a little extra).
// Files larger than this are tail-read via a positioned readSync instead of
// readFileSync-whole, so a multi-GB worker stdout/stderr log can't OOM the
// parent before the slice runs. 64 KB floor so tiny maxChars calls still get a
// whole-file read when the file is small.
const READ_TEXT_MAX_BYTES = (maxChars: number): number => Math.max(maxChars * 8, 65536);

/**
 * Read a text file, returning at most its last `maxChars` characters.
 *
 * opt #156: the previous implementation read the ENTIRE file into memory via
 * readFileSync then sliced the tail — so a worker agent whose stdout/stderr log
 * grew to multiple GB (verbose build, `find /`, a chatty loop) OOM-crashed the
 * parent (V8 heap / ERR_FS_FILE_TOO_LARGE) before the slice ran. The maxChars
 * cap only bounded the returned string, not the allocation. Now: stat first; if
 * the file is larger than the byte cap, open it and readSync only the tail
 * bytes (dropping a partial leading UTF-8 codepoint so the tail doesn't begin
 * with a replacement char), then slice to maxChars. Small files keep the
 * fast readFileSync path. The callers hash/merge the TAIL of worker logs, so
 * tail-read preserves the existing fingerprint/merge semantics.
 */
export function readText(path: string, maxChars = 12000): string {
	try {
		const stat = statSync(path);
		const maxBytes = READ_TEXT_MAX_BYTES(maxChars);
		if (stat.size <= maxBytes) {
			const raw = readFileSync(path, "utf8");
			return raw.length > maxChars ? raw.slice(-maxChars) : raw;
		}
		// Large file: read only the tail bytes, decode, and slice.
		const len = Math.min(maxBytes, stat.size);
		const fd = openSync(path, "r");
		try {
			const buf = Buffer.alloc(len);
			const bytesRead = readSync(fd, buf, 0, len, stat.size - len);
			// If the tail begins mid-codepoint (a UTF-8 continuation byte
			// 0b10xxxxxx), advance to the next codepoint boundary so the decoded
			// string doesn't start with a U+FFFD replacement char.
			let start = 0;
			while (start < bytesRead && (buf[start] & 0xc0) === 0x80) {
				start++;
			}
			const raw = buf.toString("utf8", start, bytesRead);
			return raw.length > maxChars ? raw.slice(-maxChars) : raw;
		} finally {
			closeSync(fd);
		}
	} catch {
		return "";
	}
}

function writeJson(path: string, value: unknown): void {
	// Atomic temp+rename: the manifest is read-modify-written on every status
	// change (updateManifest reads it back from disk) AND concurrently read by
	// getRun/listRuns. A plain writeFileSync truncates then writes, so a reader
	// (or a crash) mid-write would see a truncated/partial JSON file → the run
	// vanishes from listRuns (JSON.parse throws → filtered) → status misreported
	// (e.g. "timeout" lost, reported as "failed"). temp+rename means readers see
	// either the complete prior manifest or the complete new one. Mode 0o600 is
	// preserved across rewrites (atomicWriteFileSync keeps the existing mode).
	atomicWriteFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
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
	"Orchestration tools (read-only, use them instead of hand-rolling): re_route to classify the target and pick the right lane, re_map <target> to build a structured passive-map (route/binary/service inventory), re_tool_index to see which RE tools are provisioned before you assume one is missing. NOTE: your worker agent-home is isolated — these artifacts do NOT merge back to the parent; only $REPI_WORKER_HANDOFF_PATH survives. Use the tools to map rigorously, then DISTILL the surface map (each finding with its ref) into the handoff file.",
	"Handoff: Outcome, Surface Map (bulleted, each with ref), Candidate Targets, Gaps, Next Probes.",
].join("\n");

const PLANNER_DOCTRINE = [
	"You are a REPI planner subagent. Turn an ambiguous objective into a concrete, falsifiable execution plan. Do NOT perform broad execution.",
	"Produce: Goal, Context (what is known with refs), Constraints, Done-when (observable proof exits, not 'understood').",
	"Split into lanes/workers with a one-line objective + proof contract per lane. Assign the right specialist (reverser for native/pwn/firmware/malware/memory, explorer for read-only mapping, verifier for falsification).",
	"Technique-aware lane planning: call re_techniques(domain=<domain>) (or re_techniques(format=index) to enumerate) before assigning a lane that targets a known vuln class, and pin each lane's done-when to that technique's falsifiable proofExit — the worker inherits a concrete playbook rather than a vague goal.",
	"Orchestration tools (use them to structure a rigorous plan, then distill the result into your handoff): re_route to classify the objective and emit the domain + technique ids, re_lane plan <lane> <target> to emit a minimal command-pack per lane, re_techniques for the proofExit each lane pins to. NOTE: your worker agent-home is isolated — re_mission/re_lane artifacts you write here do NOT merge back to the parent. The ONLY deliverable that survives is the file at $REPI_WORKER_HANDOFF_PATH. Use re_route/re_lane/re_techniques to think rigorously, then WRITE the final Plan / Proof Exits / Worker Split / Abandonment Criteria into that handoff file (the appended completion-gate block enforces this).",
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
	"Tool repair: if a command fails because a tool is missing (command not found), call re_tool_index to confirm, then re_bootstrap plan/install to provision it (or an equivalent) before retrying once — do NOT retry the bare missing-tool command blindly. If bootstrap cannot provide it, report the gap with the fallback command you used instead.",
	"Handoff: Executed Steps (command|exit|outcome|artifact), Blockers, Next Step.",
].join("\n");

const VERIFIER_DOCTRINE = [
	"You are a REPI verifier subagent. Treat every prior claim as an UNVERIFIED hypothesis. Your job is FALSIFICATION, not confirmation.",
	"Reproduce the smallest path that proves or breaks the claim. Default verdict: refuted or inconclusive. 'proved' requires a stable repro (runs ≥2× identically) AND no counter-evidence.",
	"Run the claimed repro command yourself; if it needs a script/artifact, reconstruct the minimal version. Watch for flakiness, environment-dependence, and hidden assumptions.",
	"Attack the claim from the side: does it hold under a different input? Does the asserted primitive actually control the bytes the claim says it does? Does the exploit depend on a leak that wasn't demonstrated?",
	"Never mark 'attempted' as 'proved'. A crash is not an exploit; a string hit is not a vulnerability; a decompilation guess is not a confirmed transform.",
	"Technique proof-exit check: when the claim asserts a named technique (e.g. tcache poisoning, Kerberoasting, padding oracle), call re_techniques(id=<id>) and compare the captured observation against that technique's falsifiable proofExit — the stated observation must actually hold before you mark 'proved'.",
	"Formal proof contract: call re_verifier(action=check|matrix, technique=<id>) to bind the assertion to the catalogued technique's proofExit — the contract surfaces the exact done-when AND each pitfall as a counter_evidence_probe you must actively attempt to refute. 'proved' requires the assertion satisfied AND every counter-probe attempted-and-failed.",
	"Stable repro via re_replayer: for the 'runs ≥2× identically' requirement, call re_replayer run with the minimal repro command(s) — it records exit codes + stdout/stderr hashes per run, so flakiness and environment-dependence surface as hash divergence instead of your subjective impression. Your worker agent-home is isolated, so the replay_matrix artifact does NOT merge back — PASTE the per-run hashes + verdict into the handoff (the parent reads the handoff, not your recon dir).",
	"Handoff: Verdict (proved|refuted|inconclusive), Repro (exact commands run, ≥2 runs + hashes), Counter-evidence, Notes, Evidence refs.",
].join("\n");

const REVERSER_DOCTRINE = [
	"You are a REPI reverser subagent — the specialist for native binaries, pwn/exploit, firmware/IoT, malware, and memory forensics. You do the hard RE work; do not hand it back as a gap unless you have actually attempted the concrete steps below.",
	"",
	"## Doctrine: hypothesis → test → observe, falsifiable. Every claim must be backed by a reproducible command + an offset/artifact ref. 'Attempted' is never 'proved'. A crash is not an exploit; a decompile guess is not a confirmed transform.",
	"",
	"## Technique knowledge: before executing a known vulnerability class, call re_techniques(domain=<domain>) to pull the concrete advanced-technique playbook (pwn / native-reverse / firmware-iot / malware / memory-forensics / crypto-stego / mobile / identity-ad / cloud-container / web-api / dfir-pcap). Match your target's signals to a catalogued technique's triggers, follow its ordered procedure, and use its falsifiable proofExit as your done-when — the playbook pins version/offset/tool facts you must not hand-wave. re_techniques(format=index) lists every technique id.",
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
	"- Before building, call re_techniques(domain=pwn) (or re_techniques(id=<id>)) to load the concrete advanced-technique playbook — match your primitive to the catalogued technique (e.g. pwn-tcache-poisoning, pwn-house-of-botcake, pwn-ret2libc, pwn-format-string, pwn-srop, pwn-ret2dlresolve), follow its ordered procedure, and use its falsifiable proofExit as your done-when. The playbook pins glibc-version-specific facts (safe-linking, hook removal) that you must not hand-wave.",
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
	"## Orchestration tools (use them to produce structured findings, then distill into the handoff — your worker agent-home is isolated, so these artifacts do NOT merge back; only $REPI_WORKER_HANDOFF_PATH survives):",
	"- Phase 0 tool repair: re_tool_index to see provisioned tools, re_bootstrap plan/install to provision a missing RE tool (or an equivalent). re_bootstrap installs persist (user-wide), so a provisioned tool IS inherited by the parent/future runs — but still record the substitution in your handoff.",
	"- Phase 1-3 native runtime: re_kernel build <target> emits binary inventory + mitigation matrix + loader/libc map + GDB breakpoint trace + pwntools scaffold; re_native_runtime plan/run does the full native runtime trace. Prefer these over ad-hoc bash when the target is an ELF — they pin the offsets/mitigations you must not hand-wave. PASTE the mitigation matrix + key offsets into the handoff (do not just cite the artifact path — the parent cannot read your isolated recon dir).",
	"- Phase 4 exploit chain: re_exploit_chain plan/compose to maintain exploit_chain / proof_path / replay_commands — record your primitive → leak → gadget chain → PoC as a reproducible chain. PASTE the chain + replay commands into the handoff so the parent can rerun them.",
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
		tools: ["read", "grep", "find", "ls", "bash", "re_map", "re_route", "re_tool_index"],
		thinkingLevel: "low",
		maxTurns: 8,
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
		tools: ["read", "grep", "find", "ls", "write", "re_techniques", "re_route", "re_lane", "re_mission"],
		thinkingLevel: "medium",
		maxTurns: 6,
		memory: "off",
		isolation: "agent-home",
		color: "blue",
		mcp: { inherit: true },
	},
	{
		name: "operator",
		description: "Bounded executor for command packs; captures stdout/stderr/exit and concrete artifact refs.",
		systemPrompt: OPERATOR_DOCTRINE,
		tools: ["read", "grep", "find", "ls", "bash", "write", "re_bootstrap", "re_tool_index"],
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
		tools: ["read", "grep", "find", "ls", "bash", "write", "re_techniques", "re_verifier", "re_replayer"],
		thinkingLevel: "high",
		maxTurns: 8,
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
		tools: [
			"read",
			"grep",
			"find",
			"ls",
			"bash",
			"write",
			"edit",
			"re_techniques",
			"re_kernel",
			"re_native_runtime",
			"re_exploit_chain",
			"re_bootstrap",
			"re_tool_index",
		],
		thinkingLevel: "xhigh",
		maxTurns: 16,
		memory: "scoped",
		isolation: "agent-home",
		color: "magenta",
		mcp: { inherit: true },
	},
];

/**
 * Foundational opt #255: cap on completed agent-thread run-dirs kept on disk.
 * Each spawnThread creates a fresh `<root>/<runId>/` dir (stdout.txt, stderr.txt,
 * manifest.json, agent-home/) and nothing pruned them — every
 * re_subagent/reasoning/challenge run leaked a dir forever (unbounded disk +
 * slowing listRuns' readdirSync+JSON.parse per run). After a run finalizes the
 * most-recent N completed run-dirs are kept; older ones are best-effort
 * rmSync'd. 0 disables. envNonNegativeInteger style — explicit 0 honored.
 */
const DEFAULT_AGENT_THREAD_MAX_RUN_DIRS = 50;
function runtimeAgentThreadMaxRunDirs(): number {
	const raw = process.env.REPI_AGENT_THREAD_MAX_RUN_DIRS;
	if (raw === undefined || raw.trim() === "") return DEFAULT_AGENT_THREAD_MAX_RUN_DIRS;
	const value = Number(raw);
	if (!Number.isFinite(value) || value < 0) return DEFAULT_AGENT_THREAD_MAX_RUN_DIRS;
	return Math.floor(value);
}

export class AgentThreadManager {
	private cwd: string;
	private agentDir: string;
	private repiBinPath: string;
	private children = new Map<string, ChildProcess>();
	private runPromises = new Map<string, Promise<AgentThreadRunManifest>>();
	private runResolvers = new Map<string, (manifest: AgentThreadRunManifest) => void>();
	// Per-run spawn-timeout timers (the outer SIGTERM timer at line ~545), tracked
	// so dispose() can clear them. The inner 2s SIGKILL escalation is unref'd and
	// self-fires — not tracked.
	private timers = new Map<string, NodeJS.Timeout>();
	// Re-entrancy guard for cooperative dispose().
	private disposed = false;
	// Synchronous reap hook installed only while this manager has in-flight
	// children, removed once idle — bounds live process listeners to the count of
	// managers with running children (createAgentThreadManager is called per
	// re_subagent/reasoning/challenge run, so a constructor-registered hook would
	// accumulate one listener per spawn).
	private exitHook: (() => void) | undefined;

	constructor(options: AgentThreadManagerOptions) {
		this.cwd = resolve(options.cwd);
		this.agentDir = options.agentDir ?? getAgentDir();
		this.repiBinPath = resolveRepiBin(this.cwd, options.repiBinPath);
	}

	/**
	 * Install the synchronous `process.on("exit")` reap hook if not already
	 * installed for this manager. Idempotent.
	 */
	private ensureExitHook(): void {
		if (this.exitHook) return;
		this.exitHook = () => this.disposeChildren("parent_exit");
		process.on("exit", this.exitHook);
	}

	private removeExitHook(): void {
		if (!this.exitHook) return;
		try {
			process.off("exit", this.exitHook);
		} catch {
			// ignore
		}
		this.exitHook = undefined;
	}

	/**
	 * Synchronously SIGKILL every in-flight child and mark its manifest stopped.
	 * Safe to call from a `process.on("exit")` handler (no async). Without this,
	 * a parent exit while re_subagent/reasoning/challenge runs are in flight
	 * reparents each child to init (PID 1) and it keeps running a full print-mode
	 * agent — continuing to make LLM API calls (cost/quota leak) for up to
	 * REPI_PRINT_TIMEOUT_MS (~11 min) after the user quit. The exit hook covers
	 * graceful shutdown and the uncaughtCrash → process.exit(1) path; a SIGKILL
	 * of the parent is unrecoverable (no handler runs) — those orphans
	 * self-terminate via their own print timeout.
	 */
	private disposeChildren(reason: string): void {
		for (const [runId, child] of this.children) {
			if (child.exitCode === null) {
				try {
					child.kill("SIGKILL");
				} catch {
					// ignore
				}
				try {
					this.updateManifest(runId, { status: "stopped", endedAt: nowIso(), error: `killed:${reason}` });
				} catch {
					// updateManifest is internally guarded; belt-and-suspenders.
				}
			}
		}
	}

	/**
	 * Cooperative teardown: kill all in-flight runs, clear tracked timers, unblock
	 * any awaitRun callers, and detach the exit hook. Re-entrancy-guarded. Safe to
	 * call multiple times. Intended for the session/host to invoke on abort or
	 * teardown; the `process.on("exit")` hook calls disposeChildren directly.
	 */
	dispose(reason = "disposed"): void {
		if (this.disposed) return;
		this.disposed = true;
		this.removeExitHook();
		this.disposeChildren(reason);
		this.children.clear();
		for (const timer of this.timers.values()) {
			try {
				clearTimeout(timer);
			} catch {
				// ignore
			}
		}
		this.timers.clear();
		// Unblock any awaitRun callers with a best-effort manifest so a hung
		// dispose does not leave a caller's awaitRun pending forever.
		for (const runId of [...this.runResolvers.keys()]) {
			try {
				this.resolveRun(runId);
			} catch {
				// resolveRun is guarded; ignore.
			}
		}
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
		return (
			readdirSync(this.root, { withFileTypes: true })
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
				// Null-safe comparator: a manifest can parse (passes the Boolean filter above) yet
				// lack `createdAt` — from hand-editing, an older schema, or external corruption. A
				// bare `b.createdAt.localeCompare(a.createdAt)` throws `undefined.localeCompare is
				// not a function` on such a row, crashing EVERY listRuns caller (getRun → interactive
				// /agent, formatRuns, stopRun, resolveRun). opt #44 guarded only resolveRun's getRun
				// consult with a try/catch; this fixes the throw at the source so all callers degrade
				// gracefully (a missing createdAt sorts as empty, i.e. earliest, no crash).
				.sort((a, b) => (b.createdAt ?? "").localeCompare(a.createdAt ?? ""))
		);
	}

	/**
	 * Foundational opt #255: best-effort prune of completed run-dirs so they do
	 * not accumulate unbounded under this.root. Keeps the most-recent
	 * REPI_AGENT_THREAD_MAX_RUN_DIRS completed run-dirs by mtime and rmSync's the
	 * rest. In-flight runs (still in this.children) are NEVER pruned. Called from
	 * the child 'close' finally after a run finalizes. Best-effort: any stat/rm
	 * error is swallowed (an unreadable/dir-we-can't-stat is left alone, never
	 * deleted blindly).
	 */
	private pruneRunsIfNeeded(): void {
		const maxDirs = runtimeAgentThreadMaxRunDirs();
		if (maxDirs <= 0) return;
		let names: string[];
		try {
			names = readdirSync(this.root, { withFileTypes: true })
				.filter((entry) => entry.isDirectory())
				.map((entry) => entry.name);
		} catch {
			return;
		}
		if (names.length <= maxDirs) return;
		const inflight = new Set(this.children.keys());
		const stamped: Array<{ name: string; mtime: number }> = [];
		for (const name of names) {
			if (inflight.has(name)) continue;
			try {
				stamped.push({ name, mtime: statSync(join(this.root, name)).mtimeMs });
			} catch {
				// Can't stat — leave it rather than risk deleting blindly.
			}
		}
		if (stamped.length <= maxDirs) return;
		stamped.sort((a, b) => b.mtime - a.mtime);
		for (const { name } of stamped.slice(maxDirs)) {
			try {
				rmSync(join(this.root, name), { recursive: true, force: true });
			} catch {
				// best-effort
			}
		}
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
		// selected model". Copy models.json + settings.json for provider/default
		// resolution, and auth.json so `repi model login` credentials (the standard
		// flow, where keys live in auth.json rather than $ENV refs) reach the child.
		// API keys referenced as $ENV in models.json also resolve via the inherited
		// process.env. Copying settings.json makes the child default to the parent's
		// defaultProvider/defaultModel when the caller omits --model.
		for (const name of ["models.json", "settings.json", "auth.json"] as const) {
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
		// Bytes written to each disk file since the last truncate. The disk file
		// is append-only (O(chunk) per 'data' event, not O(buffer) per chunk);
		// when it grows past 2x the in-memory cap we truncate it once to the
		// capped in-memory tail and reset — bounding disk at ~2x cap while keeping
		// I/O append-mostly (one full rewrite per cap-bytes of growth, not per
		// chunk). readText tail-slices + the sha256 cap make the between-truncate
		// growth observationally identical to the capped buffer.
		let stdoutDiskBytes = 0;
		let stderrDiskBytes = 0;
		const timer = setTimeout(() => {
			this.updateManifest(runId, { status: "timeout", error: `timeout_ms=${timeoutMs}` });
			child.kill("SIGTERM");
			setTimeout(() => {
				if (child.exitCode === null) child.kill("SIGKILL");
			}, 2000).unref();
		}, timeoutMs);
		// Track the outer timer so dispose() can clear it, and unref it so a
		// forgotten in-flight run's timeout does not keep the parent's event loop
		// alive — the child's own stdio pipes keep the loop alive while it runs,
		// and the exit hook reaps on parent termination regardless.
		this.timers.set(runId, timer);
		timer.unref();
		this.ensureExitHook();

		child.stdout?.on("data", (chunk) => {
			const text = redact(String(chunk));
			stdout += text;
			// In-memory cap (the returned/displayed buffer is the last 2MB).
			if (stdout.length > 2 * 1024 * 1024)
				stdout = stdout.slice(safeTailStart(stdout, stdout.length - 2 * 1024 * 1024));
			// Disk: append the delta (O(chunk)), and only when the file would
			// exceed 2x cap truncate it once to the capped tail (O(cap), once
			// per ~2MB of growth — NOT per chunk). This was a full writeFileSync
			// of the entire buffer per chunk before (~500 full 2MB rewrites for a
			// 2MB stream); now it's ~500 small appends + a handful of truncates.
			// writeFileSync/appendFileSync inside an EventEmitter 'data' callback:
			// a write failure (ENOSPC/EROFS — disk full while a subagent streams)
			// throws here, and a throw inside .on("data") is NOT caught by
			// child.on("error") (different emitter) → uncaught exception → process
			// crash on a recoverable condition. Best-effort: swallow so the run
			// continues; the log file is a debugging aid, not load-bearing.
			try {
				if (stdoutDiskBytes > 4 * 1024 * 1024) {
					writeFileSync(stdoutPath, stdout, { encoding: "utf8", mode: 0o600 });
					stdoutDiskBytes = stdout.length;
				} else {
					appendFileSync(stdoutPath, text, { encoding: "utf8", mode: 0o600 });
					stdoutDiskBytes += text.length;
				}
			} catch {}
		});
		child.stderr?.on("data", (chunk) => {
			const text = redact(String(chunk));
			stderr += text;
			if (stderr.length > 512 * 1024) stderr = stderr.slice(safeTailStart(stderr, stderr.length - 512 * 1024));
			try {
				if (stderrDiskBytes > 1024 * 1024) {
					writeFileSync(stderrPath, stderr, { encoding: "utf8", mode: 0o600 });
					stderrDiskBytes = stderr.length;
				} else {
					appendFileSync(stderrPath, text, { encoding: "utf8", mode: 0o600 });
					stderrDiskBytes += text.length;
				}
			} catch {}
		});
		// Stream-level error listeners: a broken-pipe/error on stdout/stderr
		// without these would throw `Unhandled 'error' event` (child.on("error")
		// does not cover the stdio streams). Swallow; child "close" handles cleanup.
		child.stdout?.on("error", () => {});
		child.stderr?.on("error", () => {});
		child.on("error", (error) => {
			// opt #228: do NOT unconditionally clobber the manifest status or
			// resolve the run early. Two pre-fix failure modes:
			//  (a) A LATE 'error' (e.g. child.kill() hitting a non-ESRCH error on
			//      an already-exited child) firing AFTER 'close' already wrote a
			//      terminal status would overwrite complete/timeout/stopped with
			//      "failed" on disk.
			//  (b) An EARLY 'error' (spawn ENOENT) firing BEFORE 'close' would
			//      resolveRun immediately with a partial manifest (no exitCode /
			//      sha256 — the close handler writes those), so awaitRun callers
			//      got status=failed but exitCode=undefined, stdoutSha256=undefined.
			// Fix: only record the failure while the run is still pending (close
			// hasn't finalized — runResolvers still has the runId); let 'close's
			// finally resolve the promise with the FULL manifest (exitCode + sha256).
			// Node guarantees 'close' fires after 'error', so the run always settles.
			if (!this.runResolvers.has(runId)) return;
			this.updateManifest(runId, { status: "failed", error: redact(error.message), endedAt: nowIso() });
		});
		child.on("close", async (code, signal) => {
			// Async EventEmitter callback: the returned promise is DROPPED by the
			// emitter, so a rejection here is an `unhandledRejection` (process crash)
			// AND resolveRun would never run → the run promise stays unsettled →
			// awaitRun hangs forever. The catch/finally below guarantee finalize +
			// resolve even if a defensive read throws. getRun can throw (listRuns →
			// readdirSync on a root whose perms changed mid-run, or a .sort over a
			// manifest missing createdAt); updateManifest is internally guarded; sha256
			// + readText cannot throw. So the only real throw source is the getRun
			// consult for the timeout-status override — guarded separately.
			try {
				clearTimeout(timer);
				this.children.delete(runId);
				if (this.disposed) {
					// dispose() already SIGKILLed the child and wrote status=stopped;
					// do not overwrite with a code-derived status. The finally still
					// unblocks the caller.
				} else {
					let existing: AgentThreadRunManifest | undefined;
					try {
						existing = this.getRun(runId);
					} catch {
						existing = undefined;
					}
					const status: AgentThreadStatus =
						existing?.status === "timeout" || existing?.status === "stopped"
							? existing.status
							: code === 0
								? "complete"
								: "failed";
					this.updateManifest(runId, {
						status,
						endedAt: nowIso(),
						exitCode: code,
						signal,
						stdoutSha256: await sha256(readText(stdoutPath, 2 * 1024 * 1024)),
						stderrSha256: await sha256(readText(stderrPath, 512 * 1024)),
					});
				}
			} catch {
				if (this.disposed) {
					// dispose() already recorded the stopped status; skip.
				} else {
					// Best-effort finalize WITHOUT consulting getRun (it may be the throw
					// source): record a code-derived status so the manifest reflects the
					// exit, then let the finally unblock the caller.
					try {
						this.updateManifest(runId, {
							status: code === 0 ? "complete" : "failed",
							endedAt: nowIso(),
							exitCode: code,
							signal,
						});
					} catch {
						// updateManifest is already internally guarded; belt-and-suspenders.
					}
				}
			} finally {
				clearTimeout(timer);
				this.children.delete(runId);
				this.timers.delete(runId);
				this.resolveRun(runId);
				// opt #255: bound on-disk run-dir growth. Best-effort prune of
				// completed run-dirs (never in-flight ones) after this run settles.
				try {
					this.pruneRunsIfNeeded();
				} catch {
					// best-effort — must not block the run resolver path.
				}
				// Drop the exit-reap hook once this manager is idle so per-call
				// managers (the common re_subagent case) don't accumulate process
				// listeners across runs.
				if (this.children.size === 0 && this.timers.size === 0) {
					this.removeExitHook();
				}
			}
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
		// getRun can throw (listRuns → readdirSync on a root whose perms changed,
		// or a .sort over a manifest missing createdAt → undefined.localeCompare).
		// This is called from event-handler callbacks (child "close"/"error") whose
		// throw would become an uncaughtException/unhandledRejection AND leave the
		// run promise unsettled → awaitRun hangs forever. Guard the read so the
		// caller always unblocks with at least a runId-bearing manifest.
		let manifest: AgentThreadRunManifest;
		try {
			manifest = this.getRun(runId) ?? ({ runId } as unknown as AgentThreadRunManifest);
		} catch {
			manifest = { runId } as unknown as AgentThreadRunManifest;
		}
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
		// opt #229: atomic temp+rename (mode 0o600 preserved) so a crash mid-write
		// doesn't truncate merge.md and lose the main-thread merge contract +
		// distilled output tail. Same crash-torn-write class as opts #38/#41/#42/#43.
		atomicWriteFileSync(mergePath, text);
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
