#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";

const argv = process.argv.slice(2);
let root = process.cwd();
if (argv[0] && !argv[0].startsWith("--")) root = resolve(argv.shift());
const commands = new Set(["llm-run", "run-llm", "workers", "plan", "run", "status", "merge", "help"]);
const command = argv[0] && commands.has(argv[0]) ? argv.shift() : "llm-run";

const sourceAgentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const swarmsRoot = join(sourceAgentDir, "recon", "evidence", "llm-swarms");

const roleLibrary = [
	{
		role: "mapper",
		objective: "被动 mapping：入口、文件/路由/协议面、运行方式、证据缺口。",
		evidenceContract: ["entrypoints", "reachable surfaces", "evidence gaps", "safe next commands"],
		mergeKeys: ["surface", "entrypoint", "route", "artifact"],
	},
	{
		role: "reverser",
		objective: "逆向核心逻辑：数据流、签名/校验/反调试/关键分支、可复现分析路径。",
		evidenceContract: ["control/data flow", "interesting symbols/strings", "first divergence", "reverse hypotheses"],
		mergeKeys: ["symbol", "function", "string", "signature"],
	},
	{
		role: "exploiter",
		objective: "攻击路径构造：输入控制点、鉴权/边界、primitive、利用链草案、稳定性风险。",
		evidenceContract: ["controllable input", "primitive or authz gap", "exploit path", "replay commands"],
		mergeKeys: ["primitive", "authz", "payload", "replay"],
	},
	{
		role: "verifier",
		objective: "验证与反证：最小复现、claim 质量、失败条件、需要补证的步骤。",
		evidenceContract: ["verification commands", "counter-evidence", "claim confidence", "blocking gaps"],
		mergeKeys: ["verifier", "claim", "counterexample", "gate"],
	},
	{
		role: "adversary",
		objective: "对抗审查：寻找误报、越界假设、未验证叙述、污染记忆/工具输出风险。",
		evidenceContract: ["false positive risks", "unproven assumptions", "scope/target mismatch", "downgrade advice"],
		mergeKeys: ["risk", "assumption", "downgrade", "conflict"],
	},
	{
		role: "specialist",
		objective: "专项补线：选择一个未覆盖专业域，补充具体命令、证据锚点和验证出口。",
		evidenceContract: ["domain-specific commands", "specialist evidence", "proof exit", "fallback path"],
		mergeKeys: ["specialist", "domain", "tool", "proof"],
	},
];

function usage() {
	return `Usage:
  repi swarm plan <target> --workers N [--roles mapper,reverser,exploiter,verifier,adversary] [--json]
  repi swarm run <target> --workers N [--provider <id>] [--model <id>] [--tools bash,read,grep,ls] [--json]
  repi swarm status [latest|run-id] [--json]
  repi swarm merge [latest|run-id] [--json]
  repi swarm llm-run <target> --workers N [--provider <id>] [--model <id>] [--prompt <text>]

Plan/run options:
  --target <text>          Target/task label if no positional target is supplied
  --workers <N>            Number of parallel LLM workers (default: 3, max: 16)
  --max-concurrency <N>    Max simultaneous child processes (default: workers)
  --provider <id>          Provider id from ~/.repi/agent/models.json or built-ins
  --model <id>             Model id
  --roles <csv>            Role order. Defaults to mapper,reverser,exploiter,verifier,adversary
  --tools <list>           Enable tools for workers (run default: bash,read,grep,find,ls; llm-run default: --no-tools)
  --no-tools               Disable all worker tools
  --timeout-ms <ms>        Per-worker timeout (default: REPI_SWARM_LLM_TIMEOUT_MS or 210000)
  --prompt <text>          llm-run prompt template, or extra mission guidance for swarm run
  --expect <regex>         llm-run per-worker success regex. Supports {id}/{target}
  --keep-profiles          Keep temporary isolated worker profiles for debugging
  --json                   Print JSON report only

Examples:
  repi swarm plan ./target --workers 5
  repi swarm run ./target --workers 5 --provider openai-compatible --model vendor/model --tools bash,read,grep,ls
  repi swarm status latest
  repi swarm merge latest
  repi swarm llm-run local-selfcheck --workers 3 --provider openai-compatible --model vendor/model \\
    --prompt "Reply exactly: REPI_SWARM_WORKER_{id}_OK" --expect "REPI_SWARM_WORKER_{id}_OK"
`;
}

function flagValue(args, names, fallback = undefined) {
	const list = Array.isArray(names) ? names : [names];
	for (let index = 0; index < args.length; index++) {
		for (const name of list) {
			if (args[index] === name) return args[index + 1] ?? fallback;
			if (args[index].startsWith(`${name}=`)) return args[index].slice(name.length + 1);
		}
	}
	return fallback;
}

function parseIntFlag(args, names, fallback, min, max) {
	const raw = flagValue(args, names, "");
	const parsed = Number.parseInt(raw, 10);
	if (!Number.isFinite(parsed)) return fallback;
	return Math.max(min, Math.min(max, parsed));
}

function positionalTarget(args, offset = 0) {
	return args.filter((arg) => !arg.startsWith("--"))[offset];
}

function redact(value) {
	return String(value ?? "")
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/(?:AUTH_TOKEN|API_KEY|PASSWORD|SECRET|TOKEN)=\S+/gi, (match) => `${match.split("=")[0]}=<redacted>`);
}

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function clip(value, max = 12000) {
	const text = redact(value);
	return text.length > max ? `${text.slice(0, max - 32)}\n...<truncated:${text.length - max + 32}>` : text;
}

function substitute(template, workerId, target, role = "worker") {
	return String(template ?? "")
		.replaceAll("{{id}}", String(workerId))
		.replaceAll("{id}", String(workerId))
		.replaceAll("<id>", String(workerId))
		.replaceAll("{{role}}", role)
		.replaceAll("{role}", role)
		.replaceAll("<role>", role)
		.replaceAll("{{target}}", target)
		.replaceAll("{target}", target)
		.replaceAll("<target>", target);
}

function readJson(path) {
	return JSON.parse(readFileSync(path, "utf8"));
}

function copyIfExists(from, to) {
	if (existsSync(from)) copyFileSync(from, to);
}

function prepareWorkerAgentDir(tempRoot, workerId) {
	const dir = join(tempRoot, `worker-${workerId}`, "agent");
	mkdirSync(dir, { recursive: true, mode: 0o700 });
	for (const name of ["models.json", "auth.json", "settings.json"]) copyIfExists(join(sourceAgentDir, name), join(dir, name));
	return dir;
}

function makeRunId(target) {
	return `${new Date().toISOString().replace(/[:.]/g, "-")}-${sha256(`${target}:${Date.now()}:${Math.random()}`).slice(0, 10)}`;
}

function parseRoles(args) {
	const requested = String(flagValue(args, "--roles", "mapper,reverser,exploiter,verifier,adversary"))
		.split(",")
		.map((role) => role.trim().toLowerCase())
		.filter(Boolean);
	return requested.length ? requested : ["mapper", "reverser", "exploiter", "verifier", "adversary"];
}

function roleSpec(role) {
	return roleLibrary.find((item) => item.role === role) ?? { ...roleLibrary.at(-1), role };
}

function buildSwarmPlan(args, options = {}) {
	const target = flagValue(args, "--target") ?? positionalTarget(args) ?? "local-selfcheck";
	const workers = parseIntFlag(args, ["--workers", "-w"], 3, 1, 16);
	const maxConcurrency = parseIntFlag(args, "--max-concurrency", workers, 1, workers);
	const provider = flagValue(args, "--provider");
	const model = flagValue(args, "--model");
	const tools = args.includes("--no-tools") ? undefined : flagValue(args, "--tools", "bash,read,grep,find,ls");
	const timeoutMs = parseIntFlag(args, "--timeout-ms", Number(process.env.REPI_SWARM_LLM_TIMEOUT_MS ?? 210000), 5000, 30 * 60 * 1000);
	const roles = parseRoles(args);
	const runId = options.runId ?? makeRunId(target);
	const workerPackets = Array.from({ length: workers }, (_, index) => {
		const spec = roleSpec(roles[index % roles.length] ?? "specialist");
		const workerId = index + 1;
		return {
			workerId,
			id: `worker-${workerId}`,
			role: spec.role,
			objective: spec.objective,
			tools,
			dependencies: [],
			evidenceContract: spec.evidenceContract,
			mergeKeys: spec.mergeKeys,
			limits: { timeoutMs, maxOutputChars: 12000 },
		};
	});
	return {
		kind: "repi-swarm-plan",
		schemaVersion: 1,
		SwarmPlannerV1: true,
		generatedAt: new Date().toISOString(),
		runId,
		root,
		runRoot: resolve(flagValue(args, "--cwd") ?? process.cwd()),
		target: redact(target),
		provider: provider ?? "default",
		model: model ?? "default",
		workers,
		maxConcurrency,
		timeoutMs,
		workerPackets,
		operatorGuidance: redact(flagValue(args, "--prompt", "")),
		mergeProtocol: {
			StructuredSubagentMergeV1: true,
			requiredWorkerFields: ["claims", "evidence", "blockers", "nextCommands"],
			promotionRule: "claim requires worker exit pass plus concrete evidence/artifact/command; narrative-only rows remain observations",
			conflictPolicy: "verifier/adversary counter-evidence downgrades mapper/reverser/exploiter claims until rechecked",
			mergeArtifacts: ["report.json", "merge-report.json", "worker-*.stdout.txt", "worker-*.stderr.txt"],
		},
	};
}

function evidenceRootFor(runId) {
	return join(swarmsRoot, runId);
}

function writePlan(plan) {
	const dir = evidenceRootFor(plan.runId);
	mkdirSync(dir, { recursive: true, mode: 0o700 });
	writeFileSync(join(dir, "plan.json"), `${JSON.stringify(plan, null, 2)}\n`, "utf8");
	writeFileSync(join(dir, "report.json"), `${JSON.stringify({ kind: "repi-swarm-plan-report", schemaVersion: 1, runId: plan.runId, generatedAt: plan.generatedAt, ok: true, planPath: join(dir, "plan.json"), evidenceRoot: dir, plan }, null, 2)}\n`, "utf8");
	return dir;
}

function promptForWorker(plan, packet, promptTemplate, mode) {
	if (mode === "llm-run") return substitute(promptTemplate, packet.workerId, plan.target, packet.role);
	return [
		`You are REPI swarm worker ${packet.workerId} (${packet.role}).`,
		`Target/task: ${plan.target}`,
		`Role objective: ${packet.objective}`,
		plan.operatorGuidance ? `Operator guidance: ${plan.operatorGuidance}` : undefined,
		"Work independently. Prefer concrete evidence over narrative.",
		`Evidence contract: ${packet.evidenceContract.join("; ")}`,
		`Merge keys: ${packet.mergeKeys.join(", ")}`,
		"Return concise structured JSON if possible:",
		JSON.stringify({
			workerId: packet.id,
			role: packet.role,
			claims: [{ id: `${packet.role}-claim-1`, statement: "...", evidence: ["command/output/path"], confidence: 0.0, blockers: [] }],
			artifacts: ["path or command output anchor"],
			blockers: [],
			nextCommands: [],
		}, null, 2),
	].filter(Boolean).join("\n");
}

function runWorker({ plan, packet, promptTemplate, expectTemplate, tempRoot, mode }) {
	return new Promise((resolveWorker) => {
		const workerAgentDir = prepareWorkerAgentDir(tempRoot, packet.workerId);
		const prompt = promptForWorker(plan, packet, promptTemplate, mode);
		const args = [
			"--approve",
			...(plan.provider !== "default" ? ["--provider", plan.provider] : []),
			...(plan.model !== "default" ? ["--model", plan.model] : []),
			"--thinking",
			"off",
			"--no-session",
			...(packet.tools ? ["--tools", packet.tools] : ["--no-tools"]),
			"-p",
			prompt,
		];
		const startedAt = Date.now();
		const child = spawn(join(root, "repi"), args, {
			cwd: plan.runRoot,
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
				REPI_PRINT_PROGRESS: process.env.REPI_SWARM_LLM_PROGRESS ?? "0",
			},
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill("SIGTERM");
			setTimeout(() => {
				if (child.exitCode === null) child.kill("SIGKILL");
			}, 2000).unref();
		}, packet.limits.timeoutMs);
		child.stdout.on("data", (chunk) => {
			stdout += chunk;
			if (stdout.length > 1024 * 1024) stdout = stdout.slice(-1024 * 1024);
		});
		child.stderr.on("data", (chunk) => {
			stderr += chunk;
			if (stderr.length > 1024 * 1024) stderr = stderr.slice(-1024 * 1024);
		});
		child.on("close", (code, signal) => {
			clearTimeout(timer);
			const redactedStdout = clip(stdout, packet.limits.maxOutputChars);
			const redactedStderr = clip(stderr, 6000);
			let expectOk = redactedStdout.trim().length > 0;
			let expect = undefined;
			if (expectTemplate) {
				expect = substitute(expectTemplate, packet.workerId, plan.target, packet.role);
				try {
					expectOk = new RegExp(expect, "m").test(redactedStdout);
				} catch {
					expectOk = redactedStdout.includes(expect);
				}
			}
			resolveWorker({
				workerId: packet.workerId,
				role: packet.role,
				status: code === 0 && expectOk && !timedOut ? "pass" : timedOut ? "timeout" : "fail",
				exit: code ?? (signal ? 128 : 1),
				signal,
				timedOut,
				ms: Date.now() - startedAt,
				provider: plan.provider,
				model: plan.model,
				workerAgentDir,
				stdoutSha256: sha256(redactedStdout),
				stderrSha256: sha256(redactedStderr),
				stdoutPreview: redactedStdout.slice(-4000),
				stderrPreview: redactedStderr.slice(-2000),
				expect,
				expectOk,
				promptSha256: sha256(redact(prompt)),
			});
		});
		child.on("error", (error) => {
			clearTimeout(timer);
			resolveWorker({
				workerId: packet.workerId,
				role: packet.role,
				status: "fail",
				exit: 1,
				signal: null,
				timedOut,
				ms: Date.now() - startedAt,
				provider: plan.provider,
				model: plan.model,
				workerAgentDir,
				stdoutSha256: sha256(""),
				stderrSha256: sha256(redact(String(error.message || error))),
				stdoutPreview: "",
				stderrPreview: redact(String(error.message || error)),
				expect: expectTemplate ? substitute(expectTemplate, packet.workerId, plan.target, packet.role) : undefined,
				expectOk: false,
				promptSha256: sha256(redact(promptForWorker(plan, packet, promptTemplate, mode))),
			});
		});
	});
}

async function runPool(plan, promptTemplate, expectTemplate, mode, keepProfiles) {
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-llm-swarm-"));
	const evidenceRoot = evidenceRootFor(plan.runId);
	mkdirSync(evidenceRoot, { recursive: true, mode: 0o700 });
	const rows = [];
	let next = 0;
	async function workerLoop() {
		while (next < plan.workerPackets.length) {
			const packet = plan.workerPackets[next++];
			rows.push(await runWorker({ plan, packet, promptTemplate, expectTemplate, tempRoot, mode }));
		}
	}
	try {
		await Promise.all(Array.from({ length: plan.maxConcurrency }, () => workerLoop()));
	} finally {
		if (!keepProfiles) rmSync(tempRoot, { recursive: true, force: true });
	}
	rows.sort((left, right) => left.workerId - right.workerId);
	for (const worker of rows) {
		writeFileSync(join(evidenceRoot, `worker-${worker.workerId}.stdout.txt`), worker.stdoutPreview, "utf8");
		writeFileSync(join(evidenceRoot, `worker-${worker.workerId}.stderr.txt`), worker.stderrPreview, "utf8");
	}
	return { rows, tempRoot: keepProfiles ? tempRoot : undefined };
}

function extractJsonObject(text) {
	const trimmed = String(text ?? "").trim();
	if (!trimmed) return undefined;
	const fenced = /```(?:json)?\s*([\s\S]*?)```/i.exec(trimmed)?.[1];
	for (const candidate of [fenced, trimmed]) {
		if (!candidate) continue;
		const start = candidate.indexOf("{");
		const end = candidate.lastIndexOf("}");
		if (start < 0 || end <= start) continue;
		try {
			return JSON.parse(candidate.slice(start, end + 1));
		} catch {
			// Keep trying fallback candidates.
		}
	}
	return undefined;
}

function linesMatching(text, pattern, limit = 12) {
	return String(text ?? "")
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter((line) => pattern.test(line))
		.slice(0, limit);
}

function buildMergeReport(evidenceRoot) {
	const reportPath = join(evidenceRoot, "report.json");
	const report = existsSync(reportPath) ? readJson(reportPath) : undefined;
	const plan = existsSync(join(evidenceRoot, "plan.json")) ? readJson(join(evidenceRoot, "plan.json")) : report?.plan;
	const workersReport = report?.workersReport ?? [];
	const claimRows = [];
	const observations = [];
	const blockerRows = [];
	const nextCommands = new Set();
	for (const worker of workersReport) {
		const stdoutPath = join(evidenceRoot, `worker-${worker.workerId}.stdout.txt`);
		const stdout = existsSync(stdoutPath) ? readFileSync(stdoutPath, "utf8") : worker.stdoutTail ?? "";
		const parsed = extractJsonObject(stdout);
		const parsedClaims = Array.isArray(parsed?.claims) ? parsed.claims : [];
		for (let index = 0; index < parsedClaims.length; index++) {
			const claim = parsedClaims[index] ?? {};
			const evidence = Array.isArray(claim.evidence) ? claim.evidence.map(String).filter(Boolean) : [];
			const confidence = Number.isFinite(Number(claim.confidence)) ? Number(claim.confidence) : 0;
			claimRows.push({
				claimId: String(claim.id ?? `worker-${worker.workerId}-claim-${index + 1}`),
				workerId: worker.workerId,
				role: worker.role ?? parsed?.role ?? "worker",
				statement: redact(String(claim.statement ?? claim.title ?? "")),
				evidence: evidence.map(redact).slice(0, 8),
				confidence,
				status: worker.status === "pass" && evidence.length > 0 && confidence >= 0.5 ? "promoted" : "observation",
				blockers: Array.isArray(claim.blockers) ? claim.blockers.map((item) => redact(String(item))).slice(0, 6) : [],
			});
		}
		for (const command of Array.isArray(parsed?.nextCommands) ? parsed.nextCommands : []) nextCommands.add(redact(String(command)));
		for (const blocker of Array.isArray(parsed?.blockers) ? parsed.blockers : []) blockerRows.push({ workerId: worker.workerId, role: worker.role, blocker: redact(String(blocker)) });
		if (!parsedClaims.length) {
			observations.push({
				workerId: worker.workerId,
				role: worker.role ?? "worker",
				status: worker.status,
				stdoutSha256: worker.stdoutSha256,
				signals: linesMatching(stdout, /claim|finding|evidence|blocker|next|发现|证据|阻塞|下一步/i, 10),
			});
		}
	}
	const promotedClaims = claimRows.filter((claim) => claim.status === "promoted");
	const mergeReport = {
		kind: "repi-swarm-merge-report",
		schemaVersion: 1,
		StructuredSubagentMergeV1: true,
		generatedAt: new Date().toISOString(),
		runId: report?.runId ?? plan?.runId ?? basename(evidenceRoot),
		evidenceRoot,
		planPath: existsSync(join(evidenceRoot, "plan.json")) ? join(evidenceRoot, "plan.json") : undefined,
		reportPath: existsSync(reportPath) ? reportPath : undefined,
		workerCount: workersReport.length,
		passedWorkers: workersReport.filter((worker) => worker.status === "pass").length,
		failedWorkers: workersReport.filter((worker) => worker.status !== "pass").map((worker) => ({ workerId: worker.workerId, role: worker.role, status: worker.status, exit: worker.exit })),
		claimRows,
		promotedClaims,
		observations,
		blockerRows,
		nextCommands: [...nextCommands].slice(0, 24),
		mergeDigest: sha256(JSON.stringify({ workers: workersReport.map((worker) => [worker.workerId, worker.status, worker.stdoutSha256]), promotedClaims, blockerRows })),
		ok: workersReport.length > 0 && workersReport.every((worker) => worker.status === "pass"),
		finalPromotionReady: promotedClaims.length > 0 && workersReport.every((worker) => worker.status === "pass"),
		narrativeOnlyBlocked: claimRows.length === 0 && observations.length > 0,
	};
	writeFileSync(join(evidenceRoot, "merge-report.json"), `${JSON.stringify(mergeReport, null, 2)}\n`, "utf8");
	return mergeReport;
}

function buildRunReport({ plan, rows, tempRoot, mode }) {
	const evidenceRoot = evidenceRootFor(plan.runId);
	const report = {
		kind: mode === "llm-run" ? "repi-llm-worker-pool-report" : "repi-swarm-run-report",
		schemaVersion: 1,
		LLMWorkerPoolV1: true,
		SwarmRunV1: mode !== "llm-run",
		generatedAt: new Date().toISOString(),
		runId: plan.runId,
		root,
		runRoot: plan.runRoot,
		target: plan.target,
		provider: plan.provider,
		model: plan.model,
		workers: plan.workers,
		maxConcurrency: plan.maxConcurrency,
		timeoutMs: plan.timeoutMs,
		tools: [...new Set(plan.workerPackets.map((packet) => packet.tools ?? "none"))].join(";"),
		evidenceRoot,
		tempRoot,
		planPath: join(evidenceRoot, "plan.json"),
		promptTemplateSha256: mode === "llm-run" ? sha256(plan.operatorGuidance) : undefined,
		plan,
		workersReport: rows.map((worker) => ({
			workerId: worker.workerId,
			role: worker.role,
			status: worker.status,
			exit: worker.exit,
			signal: worker.signal,
			timedOut: worker.timedOut,
			ms: worker.ms,
			provider: worker.provider,
			model: worker.model,
			stdoutSha256: worker.stdoutSha256,
			stderrSha256: worker.stderrSha256,
			promptSha256: worker.promptSha256,
			expect: worker.expect,
			expectOk: worker.expectOk,
			stdoutTail: worker.stdoutPreview.slice(-1200),
			stderrTail: worker.stderrPreview.slice(-800),
		})),
		mergeDigest: sha256(rows.map((worker) => `${worker.workerId}:${worker.role}:${worker.status}:${worker.stdoutSha256}`).join("\n")),
		ok: rows.every((worker) => worker.status === "pass"),
	};
	writeFileSync(join(evidenceRoot, "report.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");
	return report;
}

function listRuns() {
	if (!existsSync(swarmsRoot)) return [];
	return readdirSync(swarmsRoot)
		.map((name) => {
			const path = join(swarmsRoot, name);
			try {
				return statSync(path).isDirectory() ? { runId: name, path, mtimeMs: statSync(path).mtimeMs } : undefined;
			} catch {
				return undefined;
			}
		})
		.filter(Boolean)
		.sort((left, right) => right.mtimeMs - left.mtimeMs);
}

function resolveRunRef(ref = "latest") {
	if (ref && ref !== "latest") {
		const exact = join(swarmsRoot, ref);
		if (existsSync(exact)) return exact;
		const match = listRuns().find((run) => run.runId.includes(ref));
		if (match) return match.path;
	}
	return listRuns()[0]?.path;
}

function buildStatus(ref) {
	const evidenceRoot = resolveRunRef(ref);
	if (!evidenceRoot) return { kind: "repi-swarm-status-report", schemaVersion: 1, ok: false, error: "no swarm runs found", swarmsRoot };
	const report = existsSync(join(evidenceRoot, "report.json")) ? readJson(join(evidenceRoot, "report.json")) : undefined;
	const plan = existsSync(join(evidenceRoot, "plan.json")) ? readJson(join(evidenceRoot, "plan.json")) : report?.plan;
	const merge = existsSync(join(evidenceRoot, "merge-report.json")) ? readJson(join(evidenceRoot, "merge-report.json")) : undefined;
	return {
		kind: "repi-swarm-status-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: Boolean(report?.ok ?? plan),
		runId: report?.runId ?? plan?.runId ?? basename(evidenceRoot),
		evidenceRoot,
		state: report?.kind === "repi-swarm-plan-report" ? "planned" : report ? (report.ok ? "complete" : "failed") : "planned",
		target: report?.target ?? plan?.target,
		provider: report?.provider ?? plan?.provider,
		model: report?.model ?? plan?.model,
		workers: report?.workersReport?.map((worker) => ({ workerId: worker.workerId, role: worker.role, status: worker.status, exit: worker.exit, ms: worker.ms })) ?? plan?.workerPackets?.map((worker) => ({ workerId: worker.workerId, role: worker.role, status: "planned" })) ?? [],
		merge: merge ? { ok: merge.ok, promotedClaims: merge.promotedClaims?.length ?? 0, narrativeOnlyBlocked: merge.narrativeOnlyBlocked, mergeDigest: merge.mergeDigest } : undefined,
	};
}

function printPlan(plan, evidenceRoot) {
	console.log("REPI Swarm Plan");
	console.log(`runId=${plan.runId} target=${plan.target} workers=${plan.workers} maxConcurrency=${plan.maxConcurrency}`);
	for (const packet of plan.workerPackets) console.log(`- worker-${packet.workerId} role=${packet.role} tools=${packet.tools ?? "none"} objective=${packet.objective}`);
	console.log(`evidence=${evidenceRoot}`);
}

function printRun(report, merge) {
	console.log(report.kind === "repi-llm-worker-pool-report" ? "REPI LLM Worker Pool" : "REPI Swarm Run");
	console.log(`runId=${report.runId} provider=${report.provider} model=${report.model} workers=${report.workers} target=${report.target}`);
	for (const worker of report.workersReport) {
		console.log(`${worker.status === "pass" ? "PASS" : "FAIL"} worker-${worker.workerId}${worker.role ? `/${worker.role}` : ""} exit=${worker.exit} ms=${worker.ms} stdout=${worker.stdoutSha256.slice(0, 12)} stderr=${worker.stderrSha256.slice(0, 12)}`);
		if (worker.status !== "pass" && worker.stderrTail) console.log(`  stderr: ${worker.stderrTail.replace(/\n/g, "\\n").slice(-600)}`);
		if (worker.status !== "pass" && worker.stdoutTail) console.log(`  stdout: ${worker.stdoutTail.replace(/\n/g, "\\n").slice(-600)}`);
	}
	if (merge) console.log(`merge=promoted:${merge.promotedClaims.length} observations:${merge.observations.length} narrativeOnlyBlocked=${merge.narrativeOnlyBlocked}`);
	console.log(`evidence=${report.evidenceRoot}`);
	console.log(`verdict=${report.ok ? "pass" : "fail"}`);
}

function printStatus(status) {
	if (!status.ok) {
		console.error(status.error);
		return;
	}
	console.log("REPI Swarm Status");
	console.log(`runId=${status.runId} state=${status.state} target=${status.target ?? "none"}`);
	console.log(`provider=${status.provider ?? "default"} model=${status.model ?? "default"}`);
	for (const worker of status.workers) console.log(`- worker-${worker.workerId}/${worker.role ?? "worker"} status=${worker.status} exit=${worker.exit ?? "n/a"} ms=${worker.ms ?? "n/a"}`);
	if (status.merge) console.log(`merge ok=${status.merge.ok} promotedClaims=${status.merge.promotedClaims} narrativeOnlyBlocked=${status.merge.narrativeOnlyBlocked}`);
	console.log(`evidence=${status.evidenceRoot}`);
}

function printMerge(merge) {
	console.log("REPI Swarm Merge");
	console.log(`runId=${merge.runId} ok=${merge.ok} finalPromotionReady=${merge.finalPromotionReady}`);
	console.log(`workers=${merge.workerCount} passed=${merge.passedWorkers} promotedClaims=${merge.promotedClaims.length} observations=${merge.observations.length} blockers=${merge.blockerRows.length}`);
	for (const claim of merge.promotedClaims.slice(0, 8)) console.log(`- claim=${claim.claimId} worker=${claim.workerId}/${claim.role} conf=${claim.confidence} ${claim.statement}`);
	if (merge.narrativeOnlyBlocked) console.log("narrativeOnlyBlocked=true: worker output lacked structured evidence-bearing claims; keep as observations.");
	console.log(`evidence=${merge.evidenceRoot}`);
	console.log(`mergeDigest=${merge.mergeDigest}`);
}

if (argv.includes("--help") || argv.includes("-h") || command === "help") {
	console.log(usage());
	process.exit(0);
}

const json = argv.includes("--json");
const keepProfiles = argv.includes("--keep-profiles");

if (command === "plan") {
	const plan = buildSwarmPlan(argv);
	const evidenceRoot = writePlan(plan);
	if (json) console.log(JSON.stringify({ kind: "repi-swarm-plan-report", schemaVersion: 1, ok: true, evidenceRoot, plan }, null, 2));
	else printPlan(plan, evidenceRoot);
	process.exit(0);
}

if (command === "status") {
	const status = buildStatus(positionalTarget(argv));
	if (json) console.log(JSON.stringify(status, null, 2));
	else printStatus(status);
	process.exit(status.ok ? 0 : 1);
}

if (command === "merge") {
	const evidenceRoot = resolveRunRef(positionalTarget(argv));
	if (!evidenceRoot) {
		console.error("No swarm run found");
		process.exit(1);
	}
	const merge = buildMergeReport(evidenceRoot);
	if (json) console.log(JSON.stringify(merge, null, 2));
	else printMerge(merge);
	process.exit(merge.ok ? 0 : 1);
}

const mode = command === "run" ? "run" : "llm-run";
const runId = makeRunId(flagValue(argv, "--target") ?? positionalTarget(argv) ?? "local-selfcheck");
const plan = mode === "llm-run" ? (() => {
	const target = flagValue(argv, "--target") ?? positionalTarget(argv) ?? "local-selfcheck";
	const workers = parseIntFlag(argv, ["--workers", "-w"], 3, 1, 16);
	const timeoutMs = parseIntFlag(argv, "--timeout-ms", Number(process.env.REPI_SWARM_LLM_TIMEOUT_MS ?? 210000), 5000, 30 * 60 * 1000);
	return {
		...buildSwarmPlan([target, "--workers", String(workers), "--max-concurrency", String(workers), ...(flagValue(argv, "--provider") ? ["--provider", flagValue(argv, "--provider")] : []), ...(flagValue(argv, "--model") ? ["--model", flagValue(argv, "--model")] : []), "--tools", flagValue(argv, "--tools", "") || ""], { runId }),
		timeoutMs,
		workerPackets: Array.from({ length: workers }, (_, index) => ({
			workerId: index + 1,
			id: `worker-${index + 1}`,
			role: "worker",
			objective: "generic parallel llm worker",
			tools: argv.includes("--no-tools") ? undefined : flagValue(argv, "--tools"),
			dependencies: [],
			evidenceContract: ["non-empty stdout"],
			mergeKeys: ["worker"],
			limits: { timeoutMs, maxOutputChars: 12000 },
		})),
		operatorGuidance: flagValue(argv, "--prompt") ?? `You are REPI parallel worker {id}. Target/task: {target}. Work independently. Return concise JSON with workerId, findings, evidence, blockers, nextCommands. Do not mention other workers.`,
	};
})() : buildSwarmPlan(argv, { runId });
const evidenceRoot = writePlan(plan);
const promptTemplate = mode === "llm-run" ? plan.operatorGuidance : undefined;
const expectTemplate = flagValue(argv, "--expect");
const { rows, tempRoot } = await runPool(plan, promptTemplate, expectTemplate, mode, keepProfiles);
const report = buildRunReport({ plan, rows, tempRoot, mode });
const merge = buildMergeReport(evidenceRoot);
if (json) console.log(JSON.stringify({ ...report, merge }, null, 2));
else printRun(report, merge);
process.exit(report.ok ? 0 : 1);
