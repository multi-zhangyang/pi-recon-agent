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
function runSwarm() {}
function dispatchOperatorQueue() {}
`;

const FAKE_REPI = String.raw`#!/usr/bin/env node
const args = process.argv.slice(2).join(" ");
const parallel = args.match(/REPI_PARALLEL_WORKER_(\d+)_OK/);
if (parallel) {
	console.log(parallel[0]);
} else if (args.includes("model list")) {
	console.log("repi-model-list-report");
} else if (args.includes("memory doctor")) {
	console.log("repi-memory-doctor-report");
} else if (args.includes("bugreport")) {
	console.log("repi-bugreport");
} else if (args.includes("swarm plan")) {
	console.log("SwarmPlannerV1");
} else if (args.includes("REPI_MODEL_OK")) {
	console.log("REPI_MODEL_OK");
} else if (args.includes("REPI_TOOL_OK")) {
	console.log("REPI_TOOL_OK");
} else if (args.includes("YES or NO")) {
	console.log("NO");
} else if (args.includes("/re-swarm")) {
	console.log("re_swarm worker ok");
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
		mkdirSync(join(fakeRepo, "packages", "coding-agent", "src", "core"), { recursive: true });
		mkdirSync(fakeTmp, { recursive: true });
		mkdirSync(sourceAgentDir, { recursive: true });
		writeFileSync(
			join(fakeRepo, "packages", "coding-agent", "src", "core", "recon-profile.ts"),
			RECON_PROFILE_MARKERS,
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
});
