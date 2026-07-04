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
	"REPI_PRINT_TIMEOUT_TOOL_GRACE_MS",
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
		mkdirSync(join(repoRoot, "packages", "coding-agent", "src", "core", "repi"), { recursive: true });
		mkdirSync(join(repoRoot, "packages", "coding-agent", "src", "core"), { recursive: true });
		mkdirSync(join(repoRoot, "packages", "coding-agent", "src", "modes"), { recursive: true });
		mkdirSync(join(repoRoot, "scripts", "reverse-agent"), { recursive: true });
		writeFileSync(join(repoRoot, "package.json"), '{"name":"fake-repi"}\n');
		writeFileSync(
			join(repoRoot, "packages", "coding-agent", "src", "cli", "repi-bootstrap.ts"),
			`${GUARDRAILS.join("\n")}\nmissingRepiEnvModelConfig\nREPI_LOAD_BUILTIN_MODELS\nREPI_MODEL_API\nprocess.env.REPI_LOAD_BUILTIN_MODELS || "0"\n`,
		);
		writeFileSync(
			join(repoRoot, "packages", "coding-agent", "src", "cli", "args.ts"),
			"REPI_LOAD_BUILTIN_MODELS\nREPI_MODEL_API\n",
		);
		writeFileSync(
			join(repoRoot, "packages", "coding-agent", "src", "core", "model-registry.ts"),
			"repiEnvProviderConfig\nREPI_AUTO_COMPACT_WINDOW\nopenai-compatible\n",
		);
		writeFileSync(
			join(repoRoot, "scripts", "reverse-agent", "model-inspect.mjs"),
			"buildStatusReport\nrepi model status\n",
		);
		writeFileSync(
			join(repoRoot, "packages", "coding-agent", "src", "core", "repi", "goal.ts"),
			[
				"installRepiGoalMode",
				"goal_complete",
				"REPI_GOAL_STATE_ENTRY_TYPE",
				"formatGoalFooterStatus",
				"formatGoalStatus",
				"ctx.ui.setStatus(STATUS_KEY, formatGoalFooterStatus(goal))",
				'"🎯 complete"',
				"The footer shows",
			].join("\n"),
		);
		writeFileSync(
			join(repoRoot, "packages", "coding-agent", "src", "core", "repi", "resources.ts"),
			"hasGoalModeSignature\nisExternalGoalModeExtension\nsuppressLegacyReconConflicts\n",
		);
		writeFileSync(
			join(repoRoot, "packages", "coding-agent", "src", "modes", "print-mode.ts"),
			"createPrintExtensionUIContext\nformatPrintNotify\nextension_ui_request\nREPI_PRINT_STATUS\n",
		);
		writeFileSync(
			join(repoRoot, "scripts", "reverse-agent", "repi-release-tarball-smoke.mjs"),
			"package-bin:goal-help-print\npackage-bin:goal-help-json\npackage-bin:goal-status-fresh-print\npackage-bin:goal-status-fresh-json\n",
		);
		writeFileSync(
			join(repoRoot, "packages", "coding-agent", "src", "core", "recon-profile.ts"),
			"installRepiGoalMode(pi)\n",
		);
		const fakeRepi = join(repoRoot, "repi");
		writeFileSync(
			fakeRepi,
			`#!/usr/bin/env node
// validate_repi_env_model_config REPI_LOAD_BUILTIN_MODELS REPI_MODEL_API
const args = process.argv.slice(2).join(" ");
if (args.includes("--mode rpc")) {
  console.log(JSON.stringify({id:"state", type:"response", command:"get_state", success:true, data:{model:{provider:"fake-provider", id:"fake-model", api:"openai-completions", contextWindow:262144}}}));
  console.log(JSON.stringify({id:"commands", type:"response", command:"get_commands", success:true, data:{commands:[{name:"goal", sourceInfo:{path:"<inline:1>", source:"inline"}}]}}));
  console.log(JSON.stringify({id:"tools", type:"response", command:"get_tools", success:true, data:{tools:[{name:"goal_complete", sourceInfo:{path:"<inline:1>", source:"inline"}}]}}));
  process.exit(0);
}
if (args.includes("--help")) {
  console.log("REPI reverse/pentest --offline REPI_SKIP_VERSION_CHECK ${GUARDRAILS.join(" ")}");
  process.exit(0);
}
if (args.includes("--list-models")) {
  console.log("No models available. Configure a model with REPI_* environment variables (Claude Code-style) or ~/.repi/agent/models.json");
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
		expect(report.checks.find((check) => check.id === "goal:rpc-runtime-registration")).toMatchObject({
			status: "pass",
			evidence: expect.stringContaining("goalCommands=1"),
		});
		expect(report.checks.find((check) => check.id === "launcher:path-command-resolution")).toMatchObject({
			status: "pass",
		});
		expect(report.checks.find((check) => check.id === "launcher:shell-rc-path-activation")).toMatchObject({
			status: "pass",
		});
		expect(report.checks.find((check) => check.id === "models:env-rpc-runtime")).toMatchObject({
			status: "pass",
		});
		expect(report.checks.find((check) => check.id === "models:env-overrides-saved-default")).toMatchObject({
			status: "pass",
		});
	});

	it("fails the PATH resolution check when an installed repi command is shadowed", () => {
		const init = spawnSync(process.execPath, [INIT, repoRoot], {
			encoding: "utf8",
			env: { ...process.env, REPI_CODING_AGENT_DIR: agentDir, REPI_IMPORT_PI_PROFILE: "0" },
			timeout: 10_000,
		});
		expect(init.status, `${init.stderr}\n${init.stdout}`).toBe(0);

		const shadowDir = join(tempRoot, "shadow-bin");
		mkdirSync(shadowDir, { recursive: true });
		const shadowRepi = join(shadowDir, "repi");
		writeFileSync(shadowRepi, "#!/usr/bin/env sh\necho shadow-repi\n");
		chmodSync(shadowRepi, 0o755);

		const doctor = spawnSync(process.execPath, [DOCTOR, repoRoot, "--json"], {
			encoding: "utf8",
			env: {
				...process.env,
				PATH: `${shadowDir}:${repoRoot}`,
				REPI_CODING_AGENT_DIR: agentDir,
				REPI_DOCTOR_REQUIRE_PATH: "1",
				REPI_INSTALLED_BIN_PATH: join(repoRoot, "repi"),
			},
			timeout: 10_000,
		});
		expect(doctor.status).not.toBe(0);
		const report = JSON.parse(doctor.stdout) as {
			checks: Array<{ id: string; status: string; evidence: string }>;
		};
		expect(report.checks.find((check) => check.id === "launcher:path-command-resolution")).toMatchObject({
			status: "fail",
			evidence: expect.stringContaining("shadowed=true"),
		});
	});
});
