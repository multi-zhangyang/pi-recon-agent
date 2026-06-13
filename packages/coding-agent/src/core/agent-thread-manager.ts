import { type ChildProcess, spawn } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { APP_NAME, getAgentDir } from "../config.ts";

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
	provider?: string;
	model?: string;
	tools: string[];
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
}

export interface AgentThreadManagerOptions {
	cwd: string;
	agentDir?: string;
	repiBinPath?: string;
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

export const BUILTIN_AGENT_THREAD_SPECS: AgentThreadSpec[] = [
	{
		name: "explorer",
		description: "Fast read-only mapper for files, routes, configs, manifests, and low-risk surface inventory.",
		systemPrompt:
			"You are a REPI explorer subagent. Map the target quickly and read-only. Return only distilled findings, evidence refs, gaps, and next probes.",
		tools: ["read", "grep", "find", "ls", "bash"],
		thinkingLevel: "off",
		maxTurns: 3,
		memory: "off",
		isolation: "agent-home",
		color: "cyan",
	},
	{
		name: "planner",
		description:
			"Turns ambiguous objectives into lane plans, gates, proof contracts, and worker packets without noisy execution.",
		systemPrompt:
			"You are a REPI planner subagent. Produce a concise lane plan with Goal/Context/Constraints/Done-when, proof exits, and worker split. Do not perform broad execution.",
		tools: ["read", "grep", "find", "ls"],
		thinkingLevel: "off",
		maxTurns: 2,
		memory: "off",
		isolation: "agent-home",
		color: "blue",
	},
	{
		name: "operator",
		description: "Bounded executor for command packs; captures stdout/stderr/exit and concrete artifact refs.",
		systemPrompt:
			"You are a REPI operator subagent. Execute bounded command packs, avoid repeated failing commands, and return command/output/artifact evidence plus blockers.",
		tools: ["read", "grep", "find", "ls", "bash"],
		thinkingLevel: "off",
		maxTurns: 5,
		memory: "scoped",
		isolation: "agent-home",
		color: "yellow",
	},
	{
		name: "verifier",
		description:
			"Independent verifier that challenges claims, reruns minimal repros, and reports contradictions/gaps.",
		systemPrompt:
			"You are a REPI verifier subagent. Treat prior claims as hypotheses. Verify the smallest reproducible path and return proved/weak/contradicted/missing with evidence refs.",
		tools: ["read", "grep", "find", "ls", "bash"],
		thinkingLevel: "off",
		maxTurns: 4,
		memory: "off",
		isolation: "agent-home",
		color: "green",
	},
	{
		name: "reverser",
		description:
			"Specialist reverse/pwn worker for binaries, mobile/native traces, signatures, PCAP/DFIR, and exploit proof paths.",
		systemPrompt:
			"You are a REPI reverser subagent. Focus on reverse engineering evidence: headers/imports/strings, trace points, offsets, transforms, PoC proof path, and reproducible commands.",
		tools: ["read", "grep", "find", "ls", "bash"],
		thinkingLevel: "off",
		maxTurns: 5,
		memory: "scoped",
		isolation: "agent-home",
		color: "magenta",
	},
];

export class AgentThreadManager {
	private cwd: string;
	private agentDir: string;
	private repiBinPath: string;
	private children = new Map<string, ChildProcess>();

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

		const cwd = resolve(options.cwd ?? this.cwd);
		const stdoutPath = join(runRoot, "stdout.txt");
		const stderrPath = join(runRoot, "stderr.txt");
		const manifestPath = join(runRoot, "manifest.json");
		const prompt = this.buildWorkerPrompt(spec, options.task, options.additionalPrompt);
		const promptSha256 = await sha256(prompt);
		const args = [
			"--approve",
			...(options.provider ? ["--provider", options.provider] : []),
			...(options.model ? ["--model", options.model] : []),
			"--thinking",
			spec.thinkingLevel,
			"--no-session",
			...(spec.tools.length > 0 ? ["--tools", spec.tools.join(",")] : ["--no-tools"]),
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
			stdoutPath,
			stderrPath,
			manifestPath,
			provider: options.provider,
			model: options.model,
			tools: spec.tools,
			promptSha256,
		};
		writeFileSync(stdoutPath, "", { encoding: "utf8", mode: 0o600 });
		writeFileSync(stderrPath, "", { encoding: "utf8", mode: 0o600 });
		writeJson(manifestPath, manifest);

		const child = spawn(this.repiBinPath, args, {
			cwd,
			env: {
				...process.env,
				REPI_CODING_AGENT_DIR: workerAgentDir,
				PI_CODING_AGENT_DIR: workerAgentDir,
				REPI_SKIP_VERSION_CHECK: "1",
				REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
				PI_SKIP_VERSION_CHECK: "1",
				PI_SKIP_PACKAGE_UPDATE_CHECK: "1",
				REPI_TELEMETRY: "0",
				PI_TELEMETRY: "0",
			},
			stdio: ["ignore", "pipe", "pipe"],
		});
		manifest.pid = child.pid;
		writeJson(manifestPath, manifest);
		this.children.set(runId, child);

		let stdout = "";
		let stderr = "";
		const timeoutMs = Math.max(1000, options.timeoutMs ?? 10 * 60 * 1000);
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

	mergeRun(id = "latest"): { manifest: AgentThreadRunManifest; text: string } | undefined {
		const manifest = this.getRun(id);
		if (!manifest) return undefined;
		const stdoutTail = redact(readText(manifest.stdoutPath, 12000));
		const stderrTail = redact(readText(manifest.stderrPath, 4000));
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
			"",
			"## Distilled output tail",
			"```text",
			stdoutTail || "(empty)",
			"```",
			stderrTail ? ["", "## Stderr tail", "```text", stderrTail, "```"].join("\n") : "",
			"",
			"## Main-thread merge contract",
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
					`- ${spec.name} [tools=${spec.tools.join(",") || "none"}, memory=${spec.memory}, maxTurns=${spec.maxTurns}]: ${spec.description}`,
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
			`provider/model: ${run.provider ?? "default"}/${run.model ?? "default"}`,
		].join("\n");
	}

	private buildWorkerPrompt(spec: AgentThreadSpec, task: string, additionalPrompt?: string): string {
		return [
			spec.systemPrompt,
			"",
			"You are running as an isolated REPI child agent thread. Keep noisy exploration inside this worker context.",
			"Return a compact handoff with: Outcome, Key Evidence, Verification, Next Step, unresolved gaps, and artifact refs.",
			"Do not include secrets. Redact credentials and raw tokens.",
			"",
			`Worker spec: ${spec.name}`,
			`Tools allowed: ${spec.tools.join(",") || "none"}`,
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
