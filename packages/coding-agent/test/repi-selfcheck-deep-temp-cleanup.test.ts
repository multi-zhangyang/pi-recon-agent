import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const SELFCHECK = fileURLToPath(new URL("../../../scripts/reverse-agent/repi-selfcheck.mjs", import.meta.url));

const RECON_PROFILE_MARKERS = `
name: "re_delegate"
name: "re_swarm"
name: "re_operator"
function buildDelegate() {}
function dispatchOperatorQueue() {}
createSwarmSupervisorRuntime({})
`;

const SWARM_RUNTIME_MARKERS = `
function runSwarm() {}
`;

const FAKE_REPI = String.raw`#!/usr/bin/env node
const args = process.argv.slice(2).join(" ");
const parallel = args.match(/REPI_PARALLEL_WORKER_(\d+)_OK/);
if (parallel) {
	console.log(parallel[0]);
} else if (args.includes("model list")) {
	console.log("repi-model-list-report");
} else if (args.includes("bugreport")) {
	console.log("repi-bugreport");
} else if (args.includes("swarm plan")) {
	console.log("SwarmPlannerV1");
} else if (args.includes("REPI_MODEL_OK")) {
	console.log("REPI_MODEL_OK");
} else if (args.includes("REPI_TOOL_OK")) {
	console.log("REPI_TOOL_OK");
} else if (args.includes("/re-swarm")) {
	console.log("re_swarm worker ok");
} else {
	console.log("ok");
}
`;

const FAKE_REPI_FRESH_PROFILE = String.raw`#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const args = process.argv.slice(2).join(" ");
const stateDir = process.env.FAKE_REPI_STATE_DIR;
const fixedPath = path.join(stateDir, "fixed");
const parallel = args.match(/REPI_PARALLEL_WORKER_(\d+)_OK/);
if (parallel) {
	console.log(parallel[0]);
} else if (args === "doctor" && !fs.existsSync(fixedPath)) {
	console.log("REPI Doctor");
	console.log("FAIL runtime:settings :: settings=/tmp/fresh/settings.json");
	process.exit(1);
} else if (args === "doctor --fix --json") {
	fs.writeFileSync(fixedPath, "1");
	console.log(JSON.stringify({ kind: "repi-doctor-report", ok: true, fixActions: [{ id: "profile-init", exit: 0 }], checks: [{ id: "runtime:settings", status: "pass" }] }));
} else if (args.includes("model list")) {
	console.log("repi-model-list-report");
} else if (args.includes("bugreport")) {
	console.log("repi-bugreport");
} else if (args.includes("swarm plan")) {
	console.log("SwarmPlannerV1");
} else if (args.includes("REPI_MODEL_OK")) {
	console.log("REPI_MODEL_OK");
} else if (args.includes("REPI_TOOL_OK")) {
	console.log("REPI_TOOL_OK");
} else {
	console.log("ok");
}
`;

describe("repi-selfcheck --deep temporary profile cleanup", () => {
	let tempRoot: string;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-selfcheck-cleanup-test-"));
	});

	afterEach(() => {
		rmSync(tempRoot, { recursive: true, force: true });
	});

	it("removes the isolated repi-selfcheck-* profile after the deep slash-command probe", () => {
		const fakeRepo = join(tempRoot, "repo");
		const fakeTmp = join(tempRoot, "tmp");
		const sourceAgentDir = join(tempRoot, "source-agent");
		mkdirSync(join(fakeRepo, "packages", "coding-agent", "src", "core", "repi"), { recursive: true });
		mkdirSync(fakeTmp, { recursive: true });
		mkdirSync(sourceAgentDir, { recursive: true });
		writeFileSync(
			join(fakeRepo, "packages", "coding-agent", "src", "core", "recon-profile.ts"),
			RECON_PROFILE_MARKERS,
		);
		writeFileSync(
			join(fakeRepo, "packages", "coding-agent", "src", "core", "repi", "swarm-supervisor-runtime.ts"),
			SWARM_RUNTIME_MARKERS,
		);
		writeFileSync(join(sourceAgentDir, "models.json"), "{}\n");
		const fakeRepiPath = join(fakeRepo, "repi");
		writeFileSync(fakeRepiPath, FAKE_REPI);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(process.execPath, [SELFCHECK, fakeRepo, "--deep", "--json", "--timeout-ms", "1000"], {
			encoding: "utf8",
			env: {
				...process.env,
				REPI_CODING_AGENT_DIR: sourceAgentDir,
				TMPDIR: fakeTmp,
			},
			timeout: 10_000,
		});

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as { ok: boolean };
		expect(report.ok).toBe(true);
		expect(readdirSync(fakeTmp).filter((name) => name.startsWith("repi-selfcheck-"))).toEqual([]);
	});

	it("bootstraps a fresh runtime profile before continuing selfcheck probes", () => {
		const fakeRepo = join(tempRoot, "repo");
		const sourceAgentDir = join(tempRoot, "source-agent");
		const stateDir = join(tempRoot, "state");
		mkdirSync(join(fakeRepo, "packages", "coding-agent", "src", "core", "repi"), { recursive: true });
		mkdirSync(sourceAgentDir, { recursive: true });
		mkdirSync(stateDir, { recursive: true });
		writeFileSync(
			join(fakeRepo, "packages", "coding-agent", "src", "core", "recon-profile.ts"),
			RECON_PROFILE_MARKERS,
		);
		writeFileSync(
			join(fakeRepo, "packages", "coding-agent", "src", "core", "repi", "swarm-supervisor-runtime.ts"),
			SWARM_RUNTIME_MARKERS,
		);
		const fakeRepiPath = join(fakeRepo, "repi");
		writeFileSync(fakeRepiPath, FAKE_REPI_FRESH_PROFILE);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(process.execPath, [SELFCHECK, fakeRepo, "--json", "--timeout-ms=1000"], {
			encoding: "utf8",
			env: {
				...process.env,
				REPI_CODING_AGENT_DIR: sourceAgentDir,
				FAKE_REPI_STATE_DIR: stateDir,
			},
			timeout: 10_000,
		});

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			ok: boolean;
			warnings: Array<{ id: string; warning?: string }>;
			rows: Array<{ id: string; ok: boolean; warning?: string }>;
		};
		expect(report.ok).toBe(true);
		expect(report.rows.find((row) => row.id === "doctor")).toMatchObject({
			ok: true,
			exit: 0,
			originalExit: 1,
			warning: "fresh-profile-bootstrap-required",
			stdoutTail: "fresh runtime profile was incomplete; selfcheck ran repi doctor --fix and rechecked successfully",
			stderrTail: "",
		});
		expect(report.rows.find((row) => row.id === "doctor-fix-fresh-profile")).toMatchObject({ ok: true });
		expect(report.rows.find((row) => row.id === "doctor-post-fix")).toMatchObject({ ok: true });
		expect(report.warnings.some((row) => row.warning === "fresh-profile-bootstrap-required")).toBe(true);
	});

	it("keeps --offline structural and skips model/worker probes", () => {
		const fakeRepo = join(tempRoot, "offline-repo");
		const sourceAgentDir = join(tempRoot, "offline-source-agent");
		mkdirSync(join(fakeRepo, "packages", "coding-agent", "src", "core", "repi"), { recursive: true });
		mkdirSync(sourceAgentDir, { recursive: true });
		writeFileSync(
			join(fakeRepo, "packages", "coding-agent", "src", "core", "recon-profile.ts"),
			RECON_PROFILE_MARKERS,
		);
		writeFileSync(
			join(fakeRepo, "packages", "coding-agent", "src", "core", "repi", "swarm-supervisor-runtime.ts"),
			SWARM_RUNTIME_MARKERS,
		);
		const fakeRepiPath = join(fakeRepo, "repi");
		writeFileSync(fakeRepiPath, FAKE_REPI);
		chmodSync(fakeRepiPath, 0o755);

		const result = spawnSync(process.execPath, [SELFCHECK, fakeRepo, "--offline", "--json", "--timeout-ms", "1000"], {
			encoding: "utf8",
			env: { ...process.env, REPI_CODING_AGENT_DIR: sourceAgentDir },
			timeout: 10_000,
		});

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			ok: boolean;
			offline: boolean;
			rows: Array<{ id: string; skipped?: boolean }>;
		};
		expect(report.ok).toBe(true);
		expect(report.offline).toBe(true);
		expect(report.rows.find((row) => row.id === "offline-model-probes")).toMatchObject({ skipped: true });
		expect(
			report.rows.some(
				(row) => row.id === "model-min" || row.id === "tool-min" || row.id.startsWith("parallel-worker"),
			),
		).toBe(false);
	});
});
