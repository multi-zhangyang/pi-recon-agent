import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const DOCTOR = fileURLToPath(new URL("../../../scripts/reverse-agent/repi-doctor.mjs", import.meta.url));

describe("repi doctor redaction", () => {
	let tempRoot: string;
	let fakeRoot: string;
	let agentDir: string;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-doctor-redaction-"));
		fakeRoot = join(tempRoot, "repo");
		agentDir = join(tempRoot, "agent");
		mkdirSync(fakeRoot, { recursive: true });
		mkdirSync(agentDir, { recursive: true });
		mkdirSync(join(fakeRoot, "packages", "coding-agent", "src", "cli"), { recursive: true });
		writeFileSync(join(fakeRoot, "package.json"), JSON.stringify({ name: "fake-repi" }));
		writeFileSync(
			join(fakeRoot, "packages", "coding-agent", "src", "cli", "repi-bootstrap.ts"),
			[
				"REPI_PRINT_PROGRESS",
				"REPI_PRINT_TIMEOUT_MS",
				"REPI_PRINT_TIMEOUT_GRACE_MS",
				"REPI_PRINT_TIMEOUT_TOOL_GRACE_MS",
				"REPI_PRINT_MAX_TURNS",
				"REPI_PRINT_MAX_TOOL_CALLS",
				"REPI_STDIN_READ_TIMEOUT_MS",
				"REPI_BASH_DEFAULT_TIMEOUT_SECONDS",
			].join("\n"),
		);
		const fakeRepi = join(fakeRoot, "repi");
		writeFileSync(
			fakeRepi,
			`#!/usr/bin/env node
const args = process.argv.slice(2).join(" ");
if (args.includes("--help")) {
  console.log("REPI reverse/pentest --offline REPI_SKIP_VERSION_CHECK REPI_PRINT_PROGRESS REPI_PRINT_TIMEOUT_MS REPI_PRINT_TIMEOUT_GRACE_MS REPI_PRINT_TIMEOUT_TOOL_GRACE_MS REPI_PRINT_MAX_TURNS REPI_PRINT_MAX_TOOL_CALLS REPI_STDIN_READ_TIMEOUT_MS REPI_BASH_DEFAULT_TIMEOUT_SECONDS");
  process.exit(0);
}
if (args.includes("--list-models")) {
  console.log("provider leak sk-testSECRET1234567890 endpoint=https://api.example.invalid/v1");
  console.error("Authorization: Bearer ghp_secretSECRET1234567890");
  process.exit(1);
}
process.exit(0);
`,
		);
		chmodSync(fakeRepi, 0o755);
	});

	afterEach(() => {
		rmSync(tempRoot, { recursive: true, force: true });
	});

	it("redacts child stdout/stderr before embedding evidence in JSON reports", () => {
		const result = spawnSync(process.execPath, [DOCTOR, fakeRoot, "--json"], {
			encoding: "utf8",
			env: { ...process.env, REPI_CODING_AGENT_DIR: agentDir },
			timeout: 10_000,
		});
		expect(result.stdout).toContain("repi-doctor-report");
		expect(result.stdout).not.toContain("sk-testSECRET1234567890");
		expect(result.stdout).not.toContain("ghp_secretSECRET1234567890");
		expect(result.stdout).not.toContain("https://api.example.invalid/v1");
		expect(result.stdout).toContain("<redacted:api-key>");
		expect(result.stdout).toContain("<redacted:url>");
	});

	it("reports a retired settings.memory block", () => {
		writeFileSync(join(agentDir, "settings.json"), JSON.stringify({ memory: { autoRecall: true } }));
		const workerSettings = join(agentDir, "recon", "agent-threads", "run-1", "agent-home", "settings.json");
		const swarmSettings = join(
			agentDir,
			"recon",
			"evidence",
			"swarms",
			"2020-run-sessions",
			".repi",
			"agent",
			"settings.json",
		);
		const unrelatedSettings = join(agentDir, "recon", "evidence", "swarms", "notes", "settings.json");
		for (const path of [workerSettings, swarmSettings, unrelatedSettings]) {
			mkdirSync(join(path, ".."), { recursive: true });
			writeFileSync(path, JSON.stringify({ memory: { autoRecall: true } }));
		}
		const result = spawnSync(process.execPath, [DOCTOR, fakeRoot, "--json"], {
			encoding: "utf8",
			env: { ...process.env, REPI_CODING_AGENT_DIR: agentDir },
			timeout: 10_000,
		});
		const report = JSON.parse(result.stdout) as {
			checks: Array<{ id: string; status: string; evidence: string }>;
		};
		const retiredState = report.checks.find((check) => check.id === "runtime:retired-state-absent");
		expect(retiredState?.status).toBe("fail");
		expect(retiredState?.evidence).toContain(`${join(agentDir, "settings.json")}#memory`);
		expect(retiredState?.evidence).toContain(`${workerSettings}#memory`);
		expect(retiredState?.evidence).toContain(`${swarmSettings}#memory`);
	});
});
