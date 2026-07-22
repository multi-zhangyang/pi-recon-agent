#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

const args = process.argv.slice(2);
const root = resolve(args[0] && !args[0].startsWith("--") ? args.shift() : process.cwd());
const json = args.includes("--json");
const enabled = process.env.REPI_RUN_LIVE_TASKSET === "1";
const fixture = JSON.parse(readFileSync(join(root, "scripts/reverse-agent/fixtures/live-taskset.json"), "utf8"));
const selectedCases = new Set(
	(process.env.REPI_LIVE_TASKSET_CASES || "")
		.split(",")
		.map((value) => value.trim())
		.filter(Boolean),
);
const shouldRun = (id) => selectedCases.size === 0 || selectedCases.has(id);

if (!enabled) {
	console.log(json ? JSON.stringify({ kind: "repi-live-taskset", enabled: false }) : "SKIP live taskset");
	process.exit(0);
}

const profileDir = mkdtempSync(join(tmpdir(), "repi-live-taskset-"));
const sessionDir = join(profileDir, "sessions");
const command = process.env.REPI_BIN_PATH || join(root, "repi");
const timeoutMs = Number(process.env.REPI_LIVE_TASKSET_TIMEOUT_MS || 3600000);
const childEnv = {
	...process.env,
	REPI_CODING_AGENT_DIR: profileDir,
	REPI_PRINT_PROGRESS: "0",
	REPI_PRINT_TIMEOUT_MS: String(timeoutMs),
	REPI_SKIP_VERSION_CHECK: "1",
	REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
	REPI_TELEMETRY: "0",
};

function parseEvents(stdout) {
	return stdout
		.split(/\r?\n/)
		.filter(Boolean)
		.flatMap((line) => {
			try {
				return [JSON.parse(line)];
			} catch {
				return [];
			}
		});
}

function assistantText(events) {
	return events
		.filter((event) => event?.type === "message_end" && event.message?.role === "assistant")
		.flatMap((event) => event.message.content || [])
		.filter((part) => part?.type === "text")
		.map((part) => String(part.text || ""))
		.join("\n");
}

function summarizeProviderFailures(events) {
	const messages = events
		.filter(
			(event) =>
				event?.type === "message_end" &&
				event.message?.role === "assistant" &&
				(event.message.stopReason === "error" || event.message.stopReason === "aborted"),
		)
		.map((event) => event.message);
	const errors = messages.filter((message) => message.stopReason === "error").length;
	const aborted = messages.filter((message) => message.stopReason === "aborted").length;
	return {
		ok: messages.length === 0,
		total: messages.length,
		errors,
		aborted,
		summaries: messages.map((message) => String(message.errorMessage || message.stopReason)).slice(0, 5),
	};
}

function toolName(event) {
	return event?.toolName ?? event?.name ?? event?.tool?.name ?? "";
}

function toolResultText(event) {
	const content = event?.result?.content;
	if (!Array.isArray(content)) return "";
	return content
		.filter((part) => part?.type === "text")
		.map((part) => String(part.text ?? ""))
		.join("\n");
}

function validateRuntimeAdapterFlow(events, spec, target) {
	const starts = events.filter(
		(event) => event?.type === "tool_execution_start" && toolName(event) === spec.expectedTool,
	);
	const startIds = new Set(starts.map((event) => event?.toolCallId).filter((value) => typeof value === "string"));
	const ends = events.filter(
		(event) =>
			event?.type === "tool_execution_end" &&
			toolName(event) === spec.expectedTool &&
			startIds.has(event?.toolCallId),
	);
	const failures = [];
	if (starts.length !== 1) failures.push(`tool_call_count:${starts.length}`);
	const start = starts[0];
	if (start?.args?.action !== "run") failures.push("route_action");
	if (start?.args?.adapter !== spec.adapter) failures.push("route_adapter");
	if (start?.args?.target !== target) failures.push("route_target");
	if (ends.length !== 1) failures.push(`tool_result_count:${ends.length}`);
	const end = ends[0];
	if (end?.isError !== false) failures.push("tool_result_error");

	const resultText = toolResultText(end);
	if (!resultText.includes("RuntimeAdapterExecutionArtifactV1: true")) failures.push("tool_result_contract");
	const artifactCandidate = /^artifact:\s*(.+)$/m.exec(resultText)?.[1]?.trim();
	let artifactPath;
	let artifact;
	if (!artifactCandidate) {
		failures.push("artifact_path_missing");
	} else {
		artifactPath = resolve(artifactCandidate);
		const profileRelative = relative(profileDir, artifactPath);
		if (!profileRelative || profileRelative.startsWith("..") || isAbsolute(profileRelative)) {
			failures.push("artifact_path_outside_profile");
		} else if (!existsSync(artifactPath)) {
			failures.push("artifact_file_missing");
		} else {
			try {
				artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
			} catch {
				failures.push("artifact_json_invalid");
			}
		}
	}

	if (artifact) {
		if (artifact.kind !== "RuntimeAdapterExecutionArtifactV1" || artifact.schemaVersion !== 1)
			failures.push("artifact_schema");
		if (artifact.adapterId !== spec.adapter) failures.push("artifact_adapter");
		if (artifact.target !== target) failures.push("artifact_target");
		if (artifact.exitCode !== 0 || artifact.killed !== false) failures.push("artifact_execution");
		if (!/^[a-f0-9]{64}$/.test(String(artifact.stdoutSha256 ?? ""))) failures.push("artifact_stdout_hash");
		if (!/^[a-f0-9]{64}$/.test(String(artifact.stderrSha256 ?? ""))) failures.push("artifact_stderr_hash");
		if (!Array.isArray(artifact.parserSignals) || !artifact.parserSignals.some((row) => row?.matches?.length > 0))
			failures.push("parser_signals");
		const summary = artifact.parserSignalSummary;
		if (
			!summary ||
			!Number.isSafeInteger(summary.matchedRules) ||
			summary.matchedRules < 1 ||
			!Number.isSafeInteger(summary.totalRules) ||
			summary.totalRules < summary.matchedRules ||
			!Number.isSafeInteger(summary.matchCount) ||
			summary.matchCount < 1 ||
			!Array.isArray(summary.evidenceRanks) ||
			summary.evidenceRanks.length === 0
		)
			failures.push("parser_verification");
		if (!Array.isArray(artifact.artifactKinds) || artifact.artifactKinds.length < 2)
			failures.push("artifact_kinds");
		if (!Array.isArray(artifact.ingestTargets) || !artifact.ingestTargets.includes("evidence-ledger"))
			failures.push("artifact_ingest");
		if (
			!artifact.replay ||
			!Number.isSafeInteger(artifact.replay.timeoutMs) ||
			artifact.replay.timeoutMs < 1 ||
			!String(artifact.replay.command ?? "").startsWith(`re_runtime_adapter run ${spec.adapter} `) ||
			!String(artifact.replay.command).includes(target)
		)
			failures.push("replay_contract");
	}

	return {
		ok: failures.length === 0,
		toolCalls: starts.length,
		toolResults: ends.length,
		artifactPath,
		parserMatches: artifact?.parserSignalSummary?.matchCount ?? 0,
		replay: artifact?.replay?.command,
		failures,
	};
}

function runCli(commandArgs) {
	return new Promise((resolveRun) => {
		const child = spawn(command, commandArgs, { cwd: root, env: childEnv, stdio: ["ignore", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill("SIGTERM");
		}, timeoutMs);
		child.stdout.on("data", (chunk) => (stdout += String(chunk)));
		child.stderr.on("data", (chunk) => (stderr += String(chunk)));
		child.once("close", (code) => {
			clearTimeout(timer);
			resolveRun({ code: code ?? 1, timedOut, stdout, stderr, events: parseEvents(stdout) });
		});
	});
}

function runRpcCompaction(sessionId, requestId) {
	return new Promise((resolveRun) => {
		const child = spawn(
			command,
			[
				"--mode",
				"rpc",
				"--session-dir",
				sessionDir,
				"--session-id",
				sessionId,
				"--no-skills",
				"--no-prompt-templates",
				"--no-context-files",
				"--thinking",
				"off",
			],
			{ cwd: root, env: childEnv, stdio: ["pipe", "pipe", "pipe"] },
		);
		let buffer = "";
		let settled = false;
		const finish = (result) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			child.kill("SIGTERM");
			resolveRun(result);
		};
		const timer = setTimeout(() => finish({ ok: false, error: "rpc compaction timeout" }), timeoutMs);
		child.stdout.on("data", (chunk) => {
			buffer += String(chunk);
			const lines = buffer.split(/\r?\n/);
			buffer = lines.pop() || "";
			for (const line of lines) {
				try {
					const event = JSON.parse(line);
					if (event?.id !== requestId || event?.type !== "response") continue;
					finish({ ok: event.success === true, error: event.error });
				} catch {
					// Ignore non-protocol startup output.
				}
			}
		});
		child.once("error", (error) => finish({ ok: false, error: error.message }));
		child.once("close", (code) => {
			if (!settled) finish({ ok: false, error: `rpc exited ${code}` });
		});
		child.stdin.write(`${JSON.stringify({ id: requestId, type: "compact" })}\n`);
	});
}

function filesBelow(path) {
	if (!existsSync(path)) return [];
	return readdirSync(path, { withFileTypes: true }).flatMap((entry) => {
		const child = join(path, entry.name);
		return entry.isDirectory() ? filesBelow(child) : [child];
	});
}

function countCompactions() {
	return filesBelow(sessionDir)
		.filter((path) => path.endsWith(".jsonl"))
		.reduce((total, path) => {
			const count = readFileSync(path, "utf8")
				.split(/\r?\n/)
				.filter((line) => line.includes('"type":"compaction"')).length;
			return total + count;
		}, 0);
}

function inspectPersistedSession(sessionId, nonce) {
	const candidates = filesBelow(sessionDir).filter((path) => path.endsWith(".jsonl"));
	const matching = [];
	for (const path of candidates) {
		const rows = readFileSync(path, "utf8")
			.split(/\r?\n/)
			.filter(Boolean)
			.flatMap((line) => {
				try {
					return [JSON.parse(line)];
				} catch {
					return [];
				}
			});
		if (rows.some((row) => row?.type === "session" && row.id === sessionId)) matching.push({ path, rows });
	}
	const rows = matching.flatMap((entry) => entry.rows);
	const userTurns = rows.filter((row) => row?.type === "message" && row.message?.role === "user").length;
	const assistantTurns = rows.filter((row) => row?.type === "message" && row.message?.role === "assistant").length;
	return {
		ok: matching.length === 1 && userTurns > 0 && assistantTurns > 0 && rows.some((row) => JSON.stringify(row).includes(nonce)),
		files: matching.length,
		userTurns,
		assistantTurns,
		noncePersisted: rows.some((row) => JSON.stringify(row).includes(nonce)),
	};
}

function inspectStateDatabase() {
	const path = join(profileDir, "recon", "state.sqlite3");
	if (!existsSync(path)) return { ok: false, exists: false, wal: false, schema: false, missionRows: 0 };
	let db;
	try {
		db = new DatabaseSync(path, { readOnly: true });
		db.exec("PRAGMA busy_timeout=10000");
		const journal = db.prepare("PRAGMA journal_mode").get();
		const table = db
			.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'repi_state'")
			.get();
		const mission = table
			? db.prepare("SELECT COUNT(*) AS count FROM repi_state WHERE namespace = 'mission'").get()
			: undefined;
		const wal = String(journal?.journal_mode ?? "").toLowerCase() === "wal";
		const schema = table?.name === "repi_state";
		const missionRows = Number(mission?.count ?? 0);
		return { ok: wal && schema && missionRows > 0, exists: true, wal, schema, missionRows };
	} catch (error) {
		return { ok: false, exists: true, wal: false, schema: false, missionRows: 0, error: error.message };
	} finally {
		db?.close();
	}
}

const common = [
	"--mode",
	"json",
	"--print",
	"--session-dir",
	sessionDir,
	"--no-skills",
	"--no-prompt-templates",
	"--no-context-files",
	"--thinking",
	"off",
];

const server = createServer((request, response) => {
	if (request.url === "/api/object/7") {
		response.setHeader("content-type", "application/json");
		response.end(JSON.stringify({ id: 7, owner: "principal-a", state: "ready" }));
		return;
	}
	response.setHeader("content-type", "text/html");
	response.end('<script>fetch("/api/object/7")</script><a href="/api/object/7">object</a>');
});
await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
const address = server.address();
const webTarget = `http://127.0.0.1:${address.port}/`;

const results = [];
try {
	for (const spec of fixture.cases.slice(0, 2).filter((row) => shouldRun(row.id))) {
		const target = spec.id.startsWith("web-") ? webTarget : spec.target;
		const prompt =
			`Call ${spec.expectedTool} exactly once with action=run, adapter=${spec.adapter}, target=${target}, timeoutMs=20000. ` +
			`Only after its result contains an execution artifact with parser verification and replay data, reply exactly ${spec.expectedText}.`;
		const run = await runCli([...common, "--no-session", prompt]);
		const flow = validateRuntimeAdapterFlow(run.events, spec, target);
		const providerFailures = summarizeProviderFailures(run.events);
		const text = assistantText(run.events);
		results.push({
			id: spec.id,
			...flow,
			ok: run.code === 0 && flow.ok && providerFailures.ok && text.includes(spec.expectedText),
			exit: run.code,
			timedOut: run.timedOut,
			providerFailures,
			expectedText: text.includes(spec.expectedText),
		});
	}

	const longSpec = fixture.cases.find((row) => row.id === "long-session-recovery");
	if (shouldRun(longSpec.id)) {
		const requestedTurns = Number(process.env.REPI_LIVE_TASKSET_TURNS || longSpec.turns);
		const turnsToRun = Number.isSafeInteger(requestedTurns) && requestedTurns >= 2 ? requestedTurns : longSpec.turns;
		const restartAfter = Math.min(longSpec.restartAfter, Math.max(1, Math.floor(turnsToRun / 2)));
		const nonce = `REPI-${Date.now().toString(36).toUpperCase()}`;
		const continuityPayloadRepeats = 1_000;
		const prompts = Array.from({ length: turnsToRun }, (_, index) => {
			const turn = index + 1;
			const ballast = ` Inert continuity payload: ${`turn-${String(turn).padStart(2, "0")}-`.repeat(continuityPayloadRepeats)}`;
			if (turn === 1) {
				return `Reverse engineering long-session harness benchmark. Remember nonce ${nonce}. Reply exactly REPI_TURN_01_OK.${ballast}`;
			}
			if (turn === turnsToRun) {
				return `Continue the same benchmark. If the original nonce is ${nonce}, reply exactly ${longSpec.expectedText}.${ballast}`;
			}
			return `Continue the same benchmark at turn ${turn}. Preserve the original nonce and reply exactly REPI_TURN_${String(turn).padStart(2, "0")}_OK.${ballast}`;
		});
		const sessionId = "019c1234-5678-7000-8000-000000000001";
		const first = await runCli([
		...common,
		"--session-id",
		sessionId,
		"--no-tools",
			...prompts.slice(0, restartAfter),
		]);
		const firstCompaction = await runRpcCompaction(sessionId, "compact-1");
		const second = await runCli([
		...common,
		"--session-id",
		sessionId,
		"--no-tools",
			...prompts.slice(restartAfter),
		]);
		const secondCompaction = await runRpcCompaction(sessionId, "compact-2");
		const turns = [...first.events, ...second.events].filter((event) => event?.type === "agent_end").length;
		const providerFailures = summarizeProviderFailures([...first.events, ...second.events]);
		const compactionEvents = [...first.events, ...second.events].filter(
			(event) => event?.type === "compaction_end" && event.aborted !== true,
		).length;
		const compactionFailures = [...first.events, ...second.events]
			.filter((event) => event?.type === "compaction_end" && !event.result)
			.map((event) => String(event.errorMessage || "no-result"))
			.slice(0, 5);
		const compactions = countCompactions();
		const recovered = assistantText(second.events).includes(longSpec.expectedText);
		const persistedSession = inspectPersistedSession(sessionId, nonce);
		const automaticContinuations = Math.max(0, persistedSession.assistantTurns - turnsToRun);
		const stateDatabase = inspectStateDatabase();
		results.push({
			id: longSpec.id,
			ok:
				first.code === 0 &&
				second.code === 0 &&
				providerFailures.ok &&
				firstCompaction.ok &&
				secondCompaction.ok &&
				turns >= turnsToRun &&
				persistedSession.userTurns >= turnsToRun &&
				persistedSession.assistantTurns >= turnsToRun &&
				compactions >= longSpec.minimumCompactions &&
				recovered &&
				persistedSession.ok &&
				stateDatabase.ok,
			exit: [first.code, second.code],
			timedOut: [first.timedOut, second.timedOut],
			compact: [firstCompaction, secondCompaction],
			turns,
			providerFailures,
			automaticContinuations,
			compactionEvents,
			compactionFailures,
			compactions,
			recovered,
			persistedSession,
			stateDatabase,
		});
	}

	const report = { kind: "repi-live-taskset", schemaVersion: 1, enabled: true, ok: results.every((row) => row.ok), results };
	console.log(json ? JSON.stringify(report, null, 2) : results.map((row) => `${row.ok ? "PASS" : "FAIL"} ${row.id}`).join("\n"));
	process.exitCode = report.ok ? 0 : 1;
} finally {
	server.close();
	if (process.env.REPI_KEEP_LIVE_TASKSET === "1") console.error(`REPI_LIVE_TASKSET_PROFILE=${profileDir}`);
	else rmSync(profileDir, { recursive: true, force: true });
}
