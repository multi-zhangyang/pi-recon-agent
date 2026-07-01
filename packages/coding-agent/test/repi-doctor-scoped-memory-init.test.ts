import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const INIT = fileURLToPath(new URL("../../../scripts/reverse-agent/init-repi-profile.mjs", import.meta.url));
const DOCTOR = fileURLToPath(new URL("../../../scripts/reverse-agent/repi-doctor.mjs", import.meta.url));

const GUARDRAILS = [
	"REPI_PRINT_PROGRESS",
	"REPI_PRINT_TIMEOUT_MS",
	"REPI_PRINT_TIMEOUT_GRACE_MS",
	"REPI_PRINT_MAX_TURNS",
	"REPI_PRINT_MAX_TOOL_CALLS",
	"REPI_STDIN_READ_TIMEOUT_MS",
	"REPI_BASH_DEFAULT_TIMEOUT_SECONDS",
];

describe("repi doctor scoped memory bootstrap", () => {
	let tempRoot: string;
	let repoRoot: string;
	let agentDir: string;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-doctor-scoped-init-"));
		repoRoot = join(tempRoot, "repo");
		agentDir = join(tempRoot, "agent");
		mkdirSync(join(repoRoot, "packages", "coding-agent", "src", "cli"), { recursive: true });
		writeFileSync(join(repoRoot, "package.json"), '{"name":"fake-repi"}\n');
		writeFileSync(
			join(repoRoot, "packages", "coding-agent", "src", "cli", "repi-bootstrap.ts"),
			`${GUARDRAILS.join("\n")}\n`,
		);
		const fakeRepi = join(repoRoot, "repi");
		writeFileSync(
			fakeRepi,
			`#!/usr/bin/env node
const args = process.argv.slice(2).join(" ");
if (args.includes("--help")) {
  console.log("REPI reverse/pentest --offline REPI_SKIP_VERSION_CHECK ${GUARDRAILS.join(" ")}");
  process.exit(0);
}
if (args.includes("--list-models")) {
  console.log("No models available. Configure a provider in ~/.repi/agent/models.json");
  process.exit(0);
}
process.exit(0);
`,
		);
		chmodSync(fakeRepi, 0o755);
	});

	afterEach(() => {
		rmSync(tempRoot, { recursive: true, force: true });
	});

	it("passes after init without legacy global memory seed files", () => {
		const init = spawnSync(process.execPath, [INIT, repoRoot], {
			encoding: "utf8",
			env: { ...process.env, REPI_CODING_AGENT_DIR: agentDir, REPI_IMPORT_PI_PROFILE: "0" },
			timeout: 10_000,
		});
		expect(init.status, `${init.stderr}\n${init.stdout}`).toBe(0);

		const doctor = spawnSync(process.execPath, [DOCTOR, repoRoot, "--json"], {
			encoding: "utf8",
			env: { ...process.env, REPI_CODING_AGENT_DIR: agentDir },
			timeout: 10_000,
		});
		expect(doctor.status, `${doctor.stderr}\n${doctor.stdout}`).toBe(0);
		const report = JSON.parse(doctor.stdout) as {
			ok: boolean;
			checks: Array<{ id: string; status: string; evidence: string }>;
		};
		expect(report.ok).toBe(true);
		for (const id of ["memory:core-file", "memory:project-file", "memory:procedural-file", "memory:event-store"]) {
			expect(report.checks.find((check) => check.id === id)).toMatchObject({
				status: "pass",
				evidence: expect.stringContaining("lazyScoped=true"),
			});
		}
	});
});
