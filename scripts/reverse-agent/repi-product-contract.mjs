#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
const root = resolve(args[0] && !args[0].startsWith("--") ? args.shift() : process.cwd());
const json = args.includes("--json");

function read(rel) {
	return readFileSync(join(root, rel), "utf8");
}

function check(id, pass, evidence, fix) {
	return { id, status: pass ? "pass" : "fail", evidence, fix };
}

function includesAll(text, values) {
	return values.every((value) => text.includes(value));
}

function patternHits(rel, patterns, allow = () => false) {
	const text = read(rel);
	const hits = [];
	for (const [index, line] of text.split(/\r?\n/).entries()) {
		for (const pattern of patterns) {
			if (!pattern.re.test(line)) continue;
			if (allow({ rel, line, lineNumber: index + 1, id: pattern.id })) continue;
			hits.push({ rel, lineNumber: index + 1, id: pattern.id, line: line.trim().slice(0, 220) });
		}
	}
	return hits;
}

function firstMissing(text, values) {
	return values.filter((value) => !text.includes(value));
}

const requiredFiles = [
	"repi",
	".github/workflows/repi-ci.yml",
	".github/workflows/release.yml",
	"README.md",
	"AGENTS.md",
	"docs/reverse-agent/mainline-overhaul.md",
	"packages/coding-agent/src/core/agent-session-compaction.ts",
	"packages/coding-agent/src/core/agent-session-factory.ts",
	"packages/coding-agent/src/core/agent-session-extension-runtime.ts",
	"packages/coding-agent/src/core/agent-session-model-runtime.ts",
	"packages/coding-agent/src/core/agent-session-policy.ts",
	"packages/coding-agent/src/core/agent-session-presentation-runtime.ts",
	"packages/coding-agent/src/core/agent-session-retry-runtime.ts",
	"packages/coding-agent/src/core/agent-session-tree-runtime.ts",
	"packages/coding-agent/src/core/recon-profile.ts",
	"packages/coding-agent/src/core/repi/artifact-selection-runtime.ts",
	"packages/coding-agent/src/core/repi/artifact-scope.ts",
	"packages/coding-agent/src/core/repi/attack-graph-runtime.ts",
	"packages/coding-agent/src/core/repi/autofix-runtime.ts",
	"packages/coding-agent/src/core/repi/bootstrap-runtime.ts",
	"packages/coding-agent/src/core/repi/campaign-operation-runtime.ts",
	"packages/coding-agent/src/core/repi/claim-release-runtime.ts",
	"packages/coding-agent/src/core/repi/completion-audit-runtime.ts",
	"packages/coding-agent/src/core/repi/delegate-orchestration-runtime.ts",
	"packages/coding-agent/src/core/repi/domain-proof-exit-rules.ts",
	"packages/coding-agent/src/core/repi/domain-proof-exit-runtime.ts",
	"packages/coding-agent/src/core/repi/evidence.ts",
	"packages/coding-agent/src/core/repi/evidence-graph-runtime.ts",
	"packages/coding-agent/src/core/repi/evidence-runtime.ts",
	"packages/coding-agent/src/core/repi/execution-kernel.ts",
	"packages/coding-agent/src/core/repi/exploit-mobile-runtime.ts",
	"packages/coding-agent/src/core/repi/exploit-chain-runtime.ts",
	"packages/coding-agent/src/core/repi/failure-runtime.ts",
	"packages/coding-agent/src/core/repi/graph-artifacts.ts",
	"packages/coding-agent/src/core/repi/graph.ts",
	"packages/coding-agent/src/core/repi/goal.ts",
	"packages/coding-agent/src/core/repi/jsonl.ts",
	"packages/coding-agent/src/core/repi/lane-specialist-pack.ts",
	"packages/coding-agent/src/core/repi/native-runtime.ts",
	"packages/coding-agent/src/core/repi/operator-execution-runtime.ts",
	"packages/coding-agent/src/core/repi/operator-feedback-runtime.ts",
	"packages/coding-agent/src/core/repi/operator-orchestration-runtime.ts",
	"packages/coding-agent/src/core/repi/operator-policy-runtime.ts",
	"packages/coding-agent/src/core/repi/provider-worker-runtime.ts",
	"packages/coding-agent/src/core/repi/profile-check.ts",
	"packages/coding-agent/src/core/repi/profile-kernel-report-runtime.ts",
	"packages/coding-agent/src/core/repi/profile.ts",
	"packages/coding-agent/src/core/repi/proof-artifact-runtime.ts",
	"packages/coding-agent/src/core/repi/proof-loop.ts",
	"packages/coding-agent/src/core/repi/proof-loop-runtime.ts",
	"packages/coding-agent/src/core/repi/recon-commands.ts",
	"packages/coding-agent/src/core/repi/recon-lane-runtime.ts",
	"packages/coding-agent/src/core/repi/recon-tools.ts",
	"packages/coding-agent/src/core/repi/resources.ts",
	"packages/coding-agent/src/core/repi/runtime-adapter.ts",
	"packages/coding-agent/src/core/repi/runtime-adapter-execution-runtime.ts",
	"packages/coding-agent/src/core/repi/runtime-binding.ts",
	"packages/coding-agent/src/core/repi/specialist-command-planner.ts",
	"packages/coding-agent/src/core/repi/specialist-evidence.ts",
	"packages/coding-agent/src/core/repi/specialist-native-command-provider.ts",
	"packages/coding-agent/src/core/repi/specialist-web-command-provider.ts",
	"packages/coding-agent/src/core/repi/routes.ts",
	"packages/coding-agent/src/core/repi/session-lifecycle-runtime.ts",
	"packages/coding-agent/src/core/repi/mission.ts",
	"packages/coding-agent/src/core/repi/storage.ts",
	"packages/coding-agent/src/core/repi/target.ts",
	"packages/coding-agent/src/core/repi/text.ts",
	"packages/coding-agent/src/core/repi/tool-presence.ts",
	"packages/coding-agent/src/core/repi/toolchain.ts",
	"packages/coding-agent/src/core/repi/toolchain-runtime.ts",
	"packages/coding-agent/src/core/repi/toolchain-capability-runtime.ts",
	"packages/coding-agent/src/core/repi/web-runtime.ts",
	"packages/coding-agent/src/core/repi/worker-runtime.ts",
	"packages/coding-agent/src/core/repi/swarm-claim-runtime.ts",
	"packages/coding-agent/src/core/repi/swarm-commander-runtime.ts",
	"packages/coding-agent/src/core/repi/swarm-artifact-paths.ts",
	"packages/coding-agent/src/core/repi/swarm-runtime-types.ts",
	"packages/coding-agent/src/core/repi/swarm-supervisor-runtime.ts",
	"packages/coding-agent/src/core/repi/swarm-worker-artifact-runtime.ts",
	"packages/coding-agent/src/core/repi/swarm-worker-child-session-runtime.ts",
	"packages/coding-agent/src/core/repi/swarm-worker-lease-scheduler-runtime.ts",
	"packages/coding-agent/src/core/repi/swarm-worker-retry-handoff-runtime.ts",
	"packages/coding-agent/src/modes/interactive/external-process-runtime.ts",
	"packages/coding-agent/src/modes/interactive/interactive-auth-runtime.ts",
	"packages/coding-agent/src/modes/interactive/interactive-compaction-runtime.ts",
	"packages/coding-agent/src/modes/interactive/interactive-command-runtime.ts",
	"packages/coding-agent/src/modes/interactive/interactive-event-runtime.ts",
	"packages/coding-agent/src/modes/interactive/interactive-extension-runtime.ts",
	"packages/coding-agent/src/modes/interactive/interactive-selector-runtime.ts",
	"packages/coding-agent/src/modes/interactive/interactive-submit-runtime.ts",
	"packages/coding-agent/src/modes/interactive/interactive-resource-runtime.ts",
	"packages/coding-agent/test/recon-profile-proof-loop.test.ts",
	"packages/coding-agent/test/recon-profile-proof-swarm.test.ts",
	"packages/coding-agent/test/repi-session-lifecycle-runtime.test.ts",
	"packages/coding-agent/test/repi-goal-rpc-mode.test.ts",
	"packages/coding-agent/test/repi-goal.test.ts",
	"scripts/reverse-agent/repi-smoke.mjs",
	"scripts/reverse-agent/repi-install-path-smoke.mjs",
	"scripts/clean-production-dist.mjs",
	"scripts/reverse-agent/lib/packed-source-closure.mjs",
	"scripts/reverse-agent/mark-repi-runtime.mjs",
	"scripts/reverse-agent/repi-release-manifest.mjs",
	"scripts/reverse-agent/repi-release-tarball-smoke.mjs",
	"scripts/reverse-agent/repi-live-model-contract.mjs",
	"scripts/reverse-agent/repi-extension-compat-smoke.mjs",
];

const rows = [];
const missingFiles = requiredFiles.filter((rel) => !existsSync(join(root, rel)));
rows.push(
	check(
		"files:repi-mainline-modules",
		missingFiles.length === 0,
		missingFiles.length ? `missing=${missingFiles.join(", ")}` : `files=${requiredFiles.length}`,
		"Restore the REPI module split and product scripts before adding new features.",
	),
);

const packageJson = JSON.parse(read("package.json"));
rows.push(
	check(
		"product:package-identity",
		packageJson.name === "repi-monorepo" &&
			/REPI reverse\/pentest/i.test(packageJson.description ?? "") &&
			(packageJson.keywords ?? []).includes("reverse-pentest") &&
			(packageJson.keywords ?? []).includes("web-pentest"),
		`name=${packageJson.name} description=${packageJson.description}`,
		"Keep package metadata centered on REPI reverse/pentest, not generic security or upstream Pi.",
	),
);

rows.push(
	check(
		"validation:clean-production-dist-before-pack",
		packageJson.scripts?.["clean:production-dist"] === "node scripts/clean-production-dist.mjs ." &&
			packageJson.scripts?.build?.startsWith("npm run clean:production-dist && ") &&
			includesAll(read("scripts/clean-production-dist.mjs"), [
				'"tui", "ai", "agent", "coding-agent"',
				'rmSync(join(root, "packages", packageName, "dist")',
			]) &&
			includesAll(read("scripts/reverse-agent/repi-release-tarball-smoke.mjs"), [
				'run("clean:production-dist", process.execPath',
				"findPackedOutputsWithoutSources",
				"tarball contains stale compiled outputs",
				"production dist cleanup failed",
			]),
		"root build and release smoke remove production dist before compiling and packing",
		"Keep production builds clean so outputs from deleted source files cannot survive into runtime manifests or npm tarballs.",
	),
);

rows.push(
	check(
		"validation:release-tarball-smoke-script",
		packageJson.scripts?.["smoke:release"] === "node scripts/reverse-agent/repi-release-tarball-smoke.mjs" &&
			existsSync(join(root, "scripts/reverse-agent/repi-release-tarball-smoke.mjs")) &&
			includesAll(read("scripts/reverse-agent/repi-release-tarball-smoke.mjs"), [
				"npm-install:four-tarballs-global",
				'"install", "--global", "--prefix"',
				"package-bin:path-command",
				"package-bin:fresh-list-models",
				"package-bin:goal-help-print",
				"package-bin:goal-help-json",
				"package-bin:goal-status-fresh-print",
				"package-bin:goal-status-fresh-json",
				"package-bin:env-incomplete-guard",
				"package-bin:model-status-env",
				"package-bin:doctor-fix-fresh-profile",
				"profile-init",
				"REPI_* environment",
				"package-bin:rpc-fresh-env-footer",
				"package-bin:rpc-goal-status-env",
				"REPI Goal Status",
				"REPI kernel profile ready",
				"package-bin:rpc-env-overrides-saved-default",
				"package-bin:rpc-goal",
				"get_tools",
				"goal_complete",
				"repi:launch-readiness",
				"capture === false && !json",
			]),
		`smoke:release=${packageJson.scripts?.["smoke:release"] ?? "<missing>"}`,
		"Keep a release tarball smoke that installs packed npm artifacts and validates repi + /goal + REPI_* env + doctor --fix fresh-profile repair.",
	),
);
rows.push(
	check(
		"validation:live-model-contract-script",
		packageJson.scripts?.["smoke:live-model"] ===
				"node scripts/reverse-agent/repi-live-model-contract.mjs ." &&
			includesAll(read("scripts/reverse-agent/repi-live-model-contract.mjs"), [
				"REPI_RUN_LIVE_MODEL",
				"REPI_BASE_URL",
				"REPI_MODEL",
				"single-response",
				"read-tool-round-trip",
			]),
		`smoke:live-model=${packageJson.scripts?.["smoke:live-model"] ?? "<missing>"}`,
		"Keep the opt-in network contract generic and exercise both a response and a real tool round trip.",
	),
);
rows.push(
	check(
		"validation:release-workflow-tarball-gate",
			includesAll(read(".github/workflows/release.yml"), [
				"REPI release tarball install smoke",
				"npm run smoke:release -- . --skip-build --json",
				"repi-release-manifest.mjs",
				"repi-release-manifest.json",
				"four same-version files",
				"`repi` on PATH",
			"`/goal` in print/json/RPC",
			"fresh env-only models",
			"stale",
			"`repi doctor` diagnostics",
		]),
		"release workflow runs the same tarball install smoke before uploading assets",
		"Keep GitHub Releases gated by the packed-tarball install smoke, not just build/check.",
	),
);
rows.push(
	check(
		"validation:ci-workflow-user-entrypoint-smoke-gates",
		includesAll(read(".github/workflows/repi-ci.yml"), [
			"REPI offline smoke",
			"node scripts/reverse-agent/repi-smoke.mjs . --json",
			"REPI install path smoke",
			"npm run smoke:install-path -- --json",
			"REPI extension compatibility smoke",
			"npm run smoke:extensions -- --json",
			"No generated diff",
		]),
		"CI gates PRs on offline smoke, installer PATH smoke, and real npm extension compatibility smoke before diff cleanliness",
		"Keep PR/main CI wired to user-visible install and extension smokes, not only unit/type checks.",
	),
);
rows.push(
	check(
		"validation:recon-profile-test-shard-contract",
		!existsSync(join(root, "packages/coding-agent/test/recon-profile.test.ts")) &&
			includesAll(read("packages/coding-agent/test/recon-profile-proof-loop.test.ts"), [
				"REPI kernel profile proof-loop flow",
				"createRegisteredReconHarness",
				"quick_path_execution",
			]) &&
			includesAll(read("packages/coding-agent/test/recon-profile-proof-swarm.test.ts"), [
				"REPI kernel profile swarm flows",
				"repi-profile-swarm-timeout",
				"repi-profile-swarm-retry",
			]),
		"proof-loop and swarm tests are split into focused shards; monolithic recon-profile.test.ts is absent",
		"Keep recon profile coverage sharded so CI can run focused slices without a slow monolithic recon-profile.test.ts.",
	),
);
rows.push(
	check(
		"validation:extension-compat-smoke-script",
		packageJson.scripts?.["smoke:extensions"] === "node scripts/reverse-agent/repi-extension-compat-smoke.mjs" &&
			existsSync(join(root, "scripts/reverse-agent/repi-extension-compat-smoke.mjs")) &&
			includesAll(read("scripts/reverse-agent/repi-extension-compat-smoke.mjs"), [
				"npm:pi-web-access",
				"npm:@narumitw/pi-goal",
				"get_tools",
				"get_state",
				"goal-status",
				"web_search",
				"goal_complete",
				"skill:librarian",
				"REPI kernel profile ready",
				"extension-smoke-model",
			]),
		`smoke:extensions=${packageJson.scripts?.["smoke:extensions"] ?? "<missing>"}`,
		"Keep a real npm extension smoke that validates pi-web-access tools and @narumitw/pi-goal conflict suppression.",
	),
);
rows.push(
	check(
		"validation:install-path-smoke-script",
		packageJson.scripts?.["smoke:install-path"] === "node scripts/reverse-agent/repi-install-path-smoke.mjs ." &&
			existsSync(join(root, "scripts/reverse-agent/repi-install-path-smoke.mjs")) &&
			includesAll(read("scripts/reverse-agent/repi-install-path-smoke.mjs"), [
				"launcher:prefers-current-dist",
				"launcher:single-process-exit-semantics",
				"launcher:single-process-signal-semantics",
				"launcher:explicit-source-mode",
				"launcher:missing-runtime-manifest-falls-back-to-tsx",
				"launcher:corrupt-runtime-manifest-falls-back-to-tsx",
				"launcher:package-command-uses-dist",
				"launcher:missing-dist-falls-back-to-tsx",
				"launcher:corrupt-dist-falls-back-to-tsx",
				"launcher:corrupt-transitive-dist-falls-back-to-tsx",
				"launcher:stale-dist-falls-back-to-tsx",
				"launcher:deleted-source-falls-back-to-tsx",
				"launcher:product-command-stays-shell-routed",
				"benchmark:runtime-manifest-verify-overhead",
				"install:user-bin-off-path",
				"assert:user-rc-path-export",
				"path:user-rc-new-shell",
				"install:explicit-bin-on-path",
				"install:root-friendly-summary",
				"path:explicit-bin-current-shell",
				"INFO: Installing REPI launcher",
				"INFO: Building REPI production runtime",
				"INFO: Verifying offline startup",
				"■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ 100%",
				"Successfully added repi to $PATH in ~/.bashrc",
				"installed successfully, to start:",
				"cd <project>  # Open directory",
				"For more information visit https://github.com/multi-zhangyang/pi-recon-agent",
				"REPI_CODING_AGENT_DIR",
			]) &&
			includesAll(read("install.sh"), [
				"INFO: Downloading REPI",
				"print_done_bar",
				"■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ 100%",
				"REPI_INSTALL_EMBEDDED=1",
				"installed successfully, to start:",
				"source ~/.bashrc",
				"cd <project>  # Open directory",
				"repi          # Run command",
			]),
		`smoke:install-path=${packageJson.scripts?.["smoke:install-path"] ?? "<missing>"}`,
		"Keep an installer smoke proving fresh install writes a repi launcher into PATH or an rc-backed user path.",
	),
);
rows.push(
	check(
		"docs:product-launch-contract",
		includesAll(read("README.md"), [
			"Claude Code 风格",
			"REPI_AUTH_TOKEN",
			"REPI_MODEL_API",
			"Successfully added repi to $PATH in ~/.bashrc",
			"npm run smoke:release -- . --json",
			"repi install npm:pi-web-access",
		]) &&
				includesAll(read("packages/coding-agent/README.md"), [
				"# REPI Coding Agent",
				"Recommended source installer:",
					"Release tarball install uses the four same-version GitHub Release packages together",
					"installing only the coding-agent tarball fails",
				"source ~/.bashrc  # Load new PATH (or open a new terminal)",
				"REPI_CONTEXT_WINDOW=262144",
				"repi doctor",
				"/goal [--tokens 100k]",
				"repi install npm:pi-web-access",
			]) &&
			!read("packages/coding-agent/README.md").includes(
				"npm install -g --ignore-scripts @pi-recon/repi-coding-agent",
			),
		"README and package README lead with install, env model, goal/footer, extension, and release-smoke launch paths",
		"Keep docs product-first and operator-usable; do not regress to a generic npm package README or hide REPI_* env setup.",
	),
);

const releaseInstallDocs = [
	"packages/ai/README.md",
	"packages/agent/README.md",
	"packages/coding-agent/README.md",
	"packages/coding-agent/docs/quickstart.md",
	"packages/coding-agent/docs/sdk.md",
	"packages/coding-agent/docs/containerization.md",
];
const registryInstallClaims = releaseInstallDocs.filter((rel) => /npm install(?: -g)? @pi-recon\//.test(read(rel)));
rows.push(
	check(
		"docs:no-unpublished-registry-install",
		registryInstallClaims.length === 0 &&
			includesAll(read("packages/ai/README.md"), ["GitHub Release tarballs", "pi-recon-repi-ai-", ".tgz"]) &&
			includesAll(read("packages/agent/README.md"), ["matching AI package", "pi-recon-repi-agent-core-", ".tgz"]) &&
			includesAll(read("packages/coding-agent/docs/quickstart.md"), ["repi-release-manifest.json", "four files"]),
		registryInstallClaims.length > 0 ? `false registry installs=${registryInstallClaims.join(", ")}` : "release docs use local tarball sets",
		"Do not document registry installs until every referenced @pi-recon package is actually published at the same version.",
	),
);
rows.push(
	check(
		"doctor:launch-readiness-contract",
		includesAll(read("scripts/reverse-agent/repi-doctor.mjs"), [
			"repi:launch-readiness",
			"RepiLaunchReadinessSummaryV1",
			"readiness:",
			"env-model:",
			"launchReadinessOk",
			"goalModeBuiltInOk",
			"goalFooterStatusOk",
			"goalPrintUiOk",
			"goalConflictSuppressionOk",
			"envModelContractOk",
			"envModelRpcMatchesExpected",
			"rpcRuntime.goalCommandCount",
			"rpcRuntime.goalToolCount",
			"profile-init",
			"init-repi-profile.mjs",
			"fix REPI_* env exports",
		]),
		"doctor exposes one launch-readiness row covering goal mode, footer/non-TUI UI, extension conflict suppression, and env-model runtime",
		"Keep repi doctor useful as a pre-release operator check, not only a list of low-level probes.",
	),
);

const launcher = read("repi");
const repiBootstrap = read("packages/coding-agent/src/cli/repi-bootstrap.ts");
const printMode = read("packages/coding-agent/src/modes/print-mode.ts");
rows.push(
	check(
		"launcher:bounded-print-budget",
		includesAll(launcher, [
			'REPI_PRINT_MAX_TURNS="${REPI_PRINT_MAX_TURNS:-10}"',
			'REPI_PRINT_MAX_TOOL_CALLS="${REPI_PRINT_MAX_TOOL_CALLS:-48}"',
		]) &&
			includesAll(repiBootstrap, [
				'process.env.REPI_PRINT_MAX_TURNS = process.env.REPI_PRINT_MAX_TURNS || "10"',
				'process.env.REPI_PRINT_MAX_TOOL_CALLS = process.env.REPI_PRINT_MAX_TOOL_CALLS || "48"',
			]) &&
			includesAll(printMode, [
				"return isRepiProductMode() ? 10 : undefined",
				"return isRepiProductMode() ? 48 : undefined",
			]),
		"launcher, bootstrap, and print runtime use the same bounded 10-turn/48-tool defaults",
		"Keep every executable entrypoint aligned so the reserved final synthesis turn is reached before the wall timeout.",
	),
);
const cliSource = read("packages/coding-agent/src/cli.ts");
const productCommandsSource = read("packages/coding-agent/src/cli/repi-product-commands.ts");
const modelInspectSource = read("scripts/reverse-agent/model-inspect.mjs");
rows.push(
	check(
		"launcher:independent-repi-entrypoint",
		includesAll(launcher, [
			"REPI_PRODUCT=1",
			"REPI_PRIMARY=1",
			"REPI_CODING_AGENT_DIR",
			"REPI does not manage upstream pi",
			"Active reverse/pentest execution entry",
		]) &&
			!/\bPI_CODING_AGENT_APP_NAME\b/.test(launcher) &&
			!/\bPI_CODING_AGENT_CONFIG_DIR\b/.test(launcher),
		"entrypoint=repi env=REPI_*",
		"Keep the launcher as the independent REPI product entrypoint. Do not reintroduce Pi app/config identity exports.",
	),
);
rows.push(
	check(
		"launcher:production-runtime-contract",
		includesAll(launcher, [
			"repi_dist_candidate_is_current",
			"run_repi_cli",
			"packages/coding-agent/dist/cli.js",
			"packages/coding-agent/dist/repi-runtime.json",
			"REPI_RUNTIME_MARKER",
			'exec node "$REPI_RUNTIME_MARKER" "$ROOT" --launch -- "$@"',
			'node_modules/.bin/tsx',
			"REPI_USE_SOURCE",
		]) &&
			packageJson.scripts?.build?.includes("mark-repi-runtime.mjs") &&
			includesAll(read("scripts/reverse-agent/install-repi.sh"), [
				"build_repi_runtime",
				"INFO: Building REPI production runtime",
				"npm run clean",
				"node_modules/.bin/tsgo",
				"npm run build",
				"packages/tui/dist/index.js",
				"packages/ai/dist/index.js",
				"packages/agent/dist/index.js",
				"packages/coding-agent/dist/cli.js",
				"mark-repi-runtime.mjs",
				"packages/coding-agent/dist/repi-runtime.json",
			]) &&
			includesAll(read("scripts/reverse-agent/mark-repi-runtime.mjs"), [
				"repi-source-runtime",
				"schemaVersion: 2",
				"runtimeRoots",
				"listRuntimeFiles",
				'!relativePath.endsWith(".map")',
				"manifest.entries.length !== runtimeFiles.length",
				"verifyRuntimeManifest",
				"--verify",
				"--launch",
				"process.execve",
				"process.argv =",
				"pathToFileURL",
				"manifest.kind",
				"manifest.schemaVersion",
				"manifest.version",
				"manifest.entries",
				"entry.bytes",
				"entry.sha256",
				"REPI runtime manifest verification failed",
				"sha256",
				"renameSync",
				"--invalidate",
				"unlinkSync",
			]),
		"fresh source installs build all workspace entrypoints; one Node process verifies manifest schema/version/bytes/digests, restores CLI argv, and retains same-PID tsx fallback",
		"Keep source installs on the verified compiled Node runtime while preserving an explicit development fallback when dist is absent, stale, or corrupt.",
	),
);
rows.push(
	check(
		"launcher:fast-metadata-env-contract",
		includesAll(cliSource, [
			"TOP_LEVEL_VALUE_FLAGS",
			"isFastMetadataOnlyRequest",
			"runFastMetadataCommand",
			"listModels",
		]) &&
			includesAll(productCommandsSource, ['case "model"', "model-inspect.mjs"]) &&
			includesAll(modelInspectSource, ["model status", "REPI_* environment"]),
		"cli has a pure metadata fast path for --help/--version/--list-models while preserving env model UX",
		"Keep launcher metadata commands fast and safe to run before the full REPI profile is loaded.",
	),
);

const profile = read("packages/coding-agent/src/core/repi/profile.ts");
rows.push(
	check(
		"profile:source-and-tool-surface",
		includesAll(profile, [
			'REPI_SOURCE = "builtin:repi"',
			'REPI_PROMPT_BASE = "<builtin:repi/prompts>"',
			"REPI_TOOL_INDEX_CANDIDATES",
			"REPI_TOOL_NAMES",
			"REPI_COMMAND_NAMES",
		]),
		"source=builtin:repi tool/command names externalized",
		"Add REPI profile constants in core/repi/profile.ts instead of growing recon-profile.ts.",
	),
);
rows.push(
	check(
		"profile:resource-loader-split-contract",
		includesAll(read("packages/coding-agent/src/core/repi/resources.ts"), [
			"RECON_SYSTEM_PROMPT",
			"RECON_APPEND_SYSTEM_PROMPT",
			"RECON_SKILL_CONTENT",
			"RECON_PROMPTS",
			"ensureReconStorage",
			"createReconResourceLoaderOptions",
			"suppressLegacyReconConflicts",
			"isExternalGoalModeExtension",
		]),
		"REPI prompt/skill/resource-loader and legacy extension suppression live outside recon-profile.ts",
		"Keep prompt/resource-loader contracts in core/repi/resources.ts so recon-profile.ts remains an assembly layer.",
	),
);

const routes = read("packages/coding-agent/src/core/repi/routes.ts");
rows.push(
	check(
		"routes:reverse-pentest-domains",
		includesAll(routes, [
			"Native reverse",
			"Web / API pentest",
			"Web pentest scanning",
			"Agent / LLM boundary",
			"Reverse/Pentest general",
			"routeRepiTask",
			"isRepiTask",
		]),
		"domains=reverse/pentest routeRepiTask=yes",
		"Route new work through core/repi/routes.ts and keep labels reverse/pentest-specific.",
	),
);

const mission = read("packages/coding-agent/src/core/repi/mission.ts");
rows.push(
	check(
		"mission:lane-contract",
		includesAll(mission, [
			"missionLanesForRoute",
			"initializeMissionLanes",
			"defaultMissionCheckpoints",
			"createMission",
			"normalizeMission",
			"tool_index_checked",
			"minimal_path_proven",
		]),
		"mission factory and checkpoints externalized",
		"Put new lane/checkpoint defaults in core/repi/mission.ts, not inside the profile monolith.",
	),
);

const evidence = read("packages/coding-agent/src/core/repi/evidence.ts");
rows.push(
	check(
		"evidence:ledger-contract",
		includesAll(evidence, [
			"EvidenceKind",
			"EvidenceRecord",
			"evidencePriority",
			"formatEvidenceRecord",
			"appendEvidenceRecord",
			"buildEvidenceDigest",
			"buildStartupEvidenceDigest",
			"buildContextEvidenceTail",
			"evidenceLedgerGraphNodes",
		]),
		"evidence ledger contract externalized",
		"Put evidence ledger types, formatting, digest, and graph parsing in core/repi/evidence.ts.",
	),
);

const graph = read("packages/coding-agent/src/core/repi/graph.ts");
rows.push(
	check(
		"graph:execution-artifact-contract",
		includesAll(graph, [
			"AttackGraphArtifact",
			"AttackGraphNode",
			"ExploitChainArtifact",
			"ExploitChainNode",
			"createExploitChainNode",
			"formatAttackGraph",
			"formatAttackGraphArtifactMarkdown",
			"formatExploitChain",
			"formatExploitChainArtifactMarkdown",
		]),
		"attack graph and exploit chain schema externalized",
		"Put execution graph/chain artifact schemas and formatters in core/repi/graph.ts.",
	),
);

const jsonl = read("packages/coding-agent/src/core/repi/jsonl.ts");
rows.push(
	check(
		"jsonl:ledger-read-contract",
		includesAll(jsonl, ["jsonlRecords", "jsonlScan", "json_parse_error", "invalid_"]),
		"JSONL record readers externalized",
		"Put append-only ledger JSONL parsing and scan diagnostics in core/repi/jsonl.ts.",
	),
);

const storage = read("packages/coding-agent/src/core/repi/storage.ts");
rows.push(
	check(
		"storage:artifact-and-defaults-contract",
		includesAll(storage, [
			"reconDir",
			"RepiStorageDefaultsOptions",
			"ensureRepiStorage",
			"currentMissionPath",
			"evidenceLedgerPath",
			"builtinSkillFilePath",
			"builtinPromptFilePath",
			"toolIndexPath",
			"chmodPrivate",
			"writePrivateTextFile",
			"readTextFile",
			"appendPrivateTextFile",
			"recentMarkdownArtifacts",
			"readJsonObjectFile",
			"0o700",
			"0o600",
		]),
		"storage paths, private permissions, and default artifact initialization externalized",
		"Add new REPI artifact paths and default file initialization to core/repi/storage.ts so future features share the same filesystem contract.",
	),
);

const artifactScope = read("packages/coding-agent/src/core/repi/artifact-scope.ts");
rows.push(
	check(
		"artifact-scope:scope-filter-contract",
		includesAll(artifactScope, [
			"ArtifactScopeFilterOptions",
			"artifactScopeInferTarget",
			"artifactScopeDefaultOptions",
			"artifactTargetMatches",
		]),
		"artifact target inference and mission-defaulted filtering externalized",
		"Keep target inference, mission defaults, and target matching in core/repi/artifact-scope.ts.",
	),
);

const target = read("packages/coding-agent/src/core/repi/target.ts");
rows.push(
	check(
		"target:intake-safety-contract",
		includesAll(target, [
			"RepiTargetKind",
			"REPI_POISON_PATTERNS",
			"classifyRepiTarget",
			"sanitizeTargetForCommand",
			"commandTarget",
			"commandContainsPoison",
			"looksLikeNaturalLanguageTarget",
			"shellQuote",
			"escapeRegExp",
			"isHttpUrlTarget",
			"isDirectoryTarget",
		]),
		"target intake and command quoting externalized",
		"Put target classification, natural-language rejection, poison guards, and command quoting in core/repi/target.ts.",
	),
);

const text = read("packages/coding-agent/src/core/repi/text.ts");
rows.push(
	check(
		"text:shared-formatting-contract",
		includesAll(text, [
			"truncateMiddle",
			"metadataValue",
			"numericMetadataValue",
			"slug",
			"uniqueMatches",
			"interestingLines",
			"sha256Text",
			"clamp01",
			"uniqueNonEmpty",
		]),
		"shared text and metadata helpers externalized",
		"Put shared text truncation, metadata parsing, slugging, hashing, and de-duplication helpers in core/repi/text.ts.",
	),
);

const toolchain = read("packages/coding-agent/src/core/repi/toolchain.ts");
const missingTools = firstMissing(toolchain, [
	"checksec",
	"gdb",
	"radare2",
	"ghidra",
	"binwalk",
	"nmap",
	"ffuf",
	"sqlmap",
	"burpsuite",
	"jadx",
	"frida",
	"tshark",
	"wireshark",
	"volatility3",
	"ROPgadget",
	"pwntools",
	"playwright",
]);
rows.push(
	check(
		"toolchain:bootstrap-catalog",
		toolchain.includes("REPI_TOOL_BOOTSTRAP_CATALOG") && missingTools.length === 0,
		missingTools.length ? `missingTools=${missingTools.join(", ")}` : "bootstrap catalog covers core REPI lanes",
		"Put install/verify metadata for new lane tools in core/repi/toolchain.ts.",
	),
);

const reconProfile = read("packages/coding-agent/src/core/recon-profile.ts");
const agentSessionSource = read("packages/coding-agent/src/core/agent-session.ts");
const agentThreadProcessRuntime = read("packages/coding-agent/src/core/agent-thread-process-runtime.ts");
const agentThreadRuntime = read("packages/coding-agent/src/core/agent-thread-runtime.ts");
const agentThreadMergeRuntime = read("packages/coding-agent/src/core/agent-thread-merge-runtime.ts");
const attackGraphRuntime = read("packages/coding-agent/src/core/repi/attack-graph-runtime.ts");
const artifactSelectionRuntime = read("packages/coding-agent/src/core/repi/artifact-selection-runtime.ts");
const autofixRuntime = read("packages/coding-agent/src/core/repi/autofix-runtime.ts");
const bootstrapRuntime = read("packages/coding-agent/src/core/repi/bootstrap-runtime.ts");
const campaignOperationRuntime = read("packages/coding-agent/src/core/repi/campaign-operation-runtime.ts");
const claimReleaseRuntime = read("packages/coding-agent/src/core/repi/claim-release-runtime.ts");
const completionAuditRuntime = read("packages/coding-agent/src/core/repi/completion-audit-runtime.ts");
const domainProofExitRules = read("packages/coding-agent/src/core/repi/domain-proof-exit-rules.ts");
const domainProofExitRuntime = read("packages/coding-agent/src/core/repi/domain-proof-exit-runtime.ts");
const evidenceGraphRuntime = read("packages/coding-agent/src/core/repi/evidence-graph-runtime.ts");
const evidenceRuntime = read("packages/coding-agent/src/core/repi/evidence-runtime.ts");
const exploitChainRuntime = read("packages/coding-agent/src/core/repi/exploit-chain-runtime.ts");
const agentSessionExtensionRuntime = read("packages/coding-agent/src/core/agent-session-extension-runtime.ts");
const delegateOrchestrationRuntime = read("packages/coding-agent/src/core/repi/delegate-orchestration-runtime.ts");
const operatorExecutionRuntime = read("packages/coding-agent/src/core/repi/operator-execution-runtime.ts");
const operatorFeedbackRuntime = read("packages/coding-agent/src/core/repi/operator-feedback-runtime.ts");
const operatorOrchestrationRuntime = read("packages/coding-agent/src/core/repi/operator-orchestration-runtime.ts");
const operatorPolicyRuntime = read("packages/coding-agent/src/core/repi/operator-policy-runtime.ts");
const proofLoopRuntime = read("packages/coding-agent/src/core/repi/proof-loop-runtime.ts");
const profileKernelReportRuntime = read("packages/coding-agent/src/core/repi/profile-kernel-report-runtime.ts");
const reconLaneRuntime = read("packages/coding-agent/src/core/repi/recon-lane-runtime.ts");
const runtimeAdapterExecutionRuntime = read(
	"packages/coding-agent/src/core/repi/runtime-adapter-execution-runtime.ts",
);
const runtimeBinding = read("packages/coding-agent/src/core/repi/runtime-binding.ts");
const sessionLifecycleRuntime = read("packages/coding-agent/src/core/repi/session-lifecycle-runtime.ts");
const swarmSupervisorRuntime = read("packages/coding-agent/src/core/repi/swarm-supervisor-runtime.ts");
const toolchainCapabilityRuntime = read("packages/coding-agent/src/core/repi/toolchain-capability-runtime.ts");
const legacyProfileImplementations = [
	"function buildAttackGraph(",
	"function proofLoopGapItems(",
	"function buildProofLoop(",
	"async function runProofLoop(",
	"function laneCommandPack(",
	"async function runLaneCommandPack(",
	"function buildDecisionCore(",
	"function buildOperator(",
	"async function executeOperatorStep(",
	"function latestCompilerClaimCheckInputs(",
	"function latestClaimReleaseMarkerPath(",
	"function strictClaimCheckSnapshot(",
	"function buildClaimCheckResult(",
	"function auditCompletion(",
	"function formatCompletionAuditFromAudit(",
	"function proofExitRegexes(",
	"function proofExitExpectedEvidence(",
	"function domainProofExitArtifactCorpus(",
	"function buildDomainProofExitClosure(",
	"function writeDomainProofExitClosureArtifact(",
	"function buildAutofix(",
	"function formatAutofix(",
	"function writeAutofixArtifact(",
	"function buildExploitChain(",
	"function writeExploitChainArtifact(",
	"function buildDelegate(",
	"function autonomousExecutionBudget(",
	"function buildSwarm(",
	"function buildSupervisor(",
	"function createSessionScopedExtensionApi(",
	'pi.on("before_agent_start"',
	'pi.on("session_tree"',
	"function persistedReconStats(",
	"function buildToolDigest(",
	"function parseToolIndex(",
	"function recommendedToolsForRoute(",
	"function fallbackForMissingTools(",
	"function autopilotExecutionStrategy(",
	"async function installBootstrapTools(",
	"async function refreshToolIndex(",
	"function buildProfessionalRuntimeBridgesGate(",
	"function writeProfessionalRuntimeBridgesArtifact(",
	"function buildRuntimeAdapterExecutionGate(",
	"function writeRuntimeAdapterExecutionArtifact(",
	"async function runRuntimeAdapterExecution(",
	"function buildToolchainDomainCapability(",
	"function writeToolchainDomainCapabilityArtifact(",
	"function appendEvidence(",
	"function buildPentestingTaskTreeSnapshot(",
	"function writeAttackGraphArtifact(",
	"function latestScopedMarkdownArtifact(",
	"function contextArtifactIndex(",
	"function buildProfileCheckOutput(",
	"function writeKernelArtifact(",
	"function buildKernelOutput(",
	"function writeReportScaffold(",
].filter((marker) => reconProfile.includes(marker));
rows.push(
	check(
		"architecture:profile-is-assembly-layer",
		includesAll(reconProfile, [
			"./repi/artifact-selection-runtime.ts",
			"./repi/evidence.ts",
			"./repi/evidence-graph-runtime.ts",
			"./repi/evidence-runtime.ts",
			"./repi/artifact-scope.ts",
			"./repi/attack-graph-runtime.ts",
			"./repi/autofix-runtime.ts",
			"./repi/bootstrap-runtime.ts",
			"./repi/campaign-operation-runtime.ts",
			"./repi/claim-release-runtime.ts",
			"./repi/completion-audit-runtime.ts",
			"./repi/delegate-orchestration-runtime.ts",
			"./repi/domain-proof-exit-rules.ts",
			"./repi/domain-proof-exit-runtime.ts",
			"./repi/exploit-mobile-runtime.ts",
			"./repi/exploit-chain-runtime.ts",
			"./repi/failure-runtime.ts",
			"./repi/graph.ts",
			"./repi/lane-specialist-pack.ts",
			"./repi/native-runtime.ts",
			"./repi/operator-orchestration-runtime.ts",
			"./repi/profile.ts",
			"./repi/profile-kernel-report-runtime.ts",
			"./repi/proof-loop-runtime.ts",
			"./repi/recon-commands.ts",
			"./repi/recon-lane-runtime.ts",
			"./repi/recon-tools.ts",
			"./repi/resources.ts",
			"./repi/routes.ts",
			"./repi/session-lifecycle-runtime.ts",
			"./repi/mission.ts",
			"./repi/storage.ts",
			"./repi/target.ts",
			"./repi/text.ts",
			"./repi/toolchain-capability-runtime.ts",
			"./repi/runtime-adapter-execution-runtime.ts",
			"./repi/runtime-binding.ts",
			"./repi/web-runtime.ts",
			"./repi/swarm-supervisor-runtime.ts",
			"createExploitChainRuntime({",
			"createAttackGraphRuntime({",
			"createAutofixRuntime({",
			"createClaimReleaseRuntime({",
			"createCompletionAuditRuntime<DomainProofExitClosureV1>({",
			"createDelegateOrchestrationRuntime({",
			"createDomainProofExitRules({ activeLane, readCurrentMission })",
			"createDomainProofExitRuntime({",
			"createEvidenceGraphRuntime({",
			"createOperatorOrchestrationRuntime({",
			"createProofLoopRuntime({",
			"createProfileKernelReportRuntime<DomainProofExitClosureV1>({",
			"createReconLaneRuntime({",
			"createRuntimeAdapterExecutionRuntime({ appendEvidence })",
			"createSwarmSupervisorRuntime({",
			"createToolchainCapabilityRuntime({ appendEvidence })",
			"installRepiSessionLifecycle(",
		]) &&
			includesAll(artifactSelectionRuntime, [
				"function scopedMarkdownArtifacts(",
				"function latestScopedMarkdownArtifact(",
				"function contextArtifactIndex(",
			]) &&
			includesAll(attackGraphRuntime, ["export function createAttackGraphRuntime", "function buildAttackGraph("]) &&
			includesAll(evidenceRuntime, ["function appendEvidence(", "function appendAgentThreadEvidence("]) &&
			includesAll(evidenceGraphRuntime, [
				"export function createEvidenceGraphRuntime",
				"function buildPentestingTaskTreeSnapshot(",
				"function writeAttackGraphArtifact(",
			]) &&
			includesAll(profileKernelReportRuntime, [
				"export function createProfileKernelReportRuntime",
				"function buildProfileCheckOutput(",
				"function buildKernelOutput(",
				"function writeReportScaffold(",
			]) &&
			includesAll(autofixRuntime, [
				"export function createAutofixRuntime",
				"function buildAutofix(",
				"function formatAutofix(",
				"function writeAutofixArtifact(",
				"appendRuntimeFailureRepairFromAutofix",
			]) &&
			includesAll(bootstrapRuntime, [
				'from "./toolchain.ts"',
				"export function buildToolDigest",
				"export function parseToolIndex",
				"export function recommendedToolsForRoute",
				"function fallbackForMissingTools(",
				"export function autopilotExecutionStrategy",
				"export async function installBootstrapTools",
				"export async function refreshToolIndex",
			]) &&
			includesAll(claimReleaseRuntime, [
				"export function createClaimReleaseRuntime",
				"function strictClaimCheckSnapshot(",
				"function buildClaimCheckResult(",
				"schemaVersion: 3",
				"sourceBindings",
			]) &&
			includesAll(completionAuditRuntime, [
				"export function createCompletionAuditRuntime",
				"function auditCompletion(",
				"function formatCompletionAuditFromAudit(",
				"artifactMatchesScope",
				"replayClosureBlockers",
			]) &&
			includesAll(domainProofExitRules, [
				"export function createDomainProofExitRules",
				"function proofExitRegexes(",
				"function proofExitExpectedEvidence(",
				"function domainProofExitNextCommands(",
			]) &&
			includesAll(domainProofExitRuntime, [
				"export function createDomainProofExitRuntime",
				"function domainProofExitArtifactCorpus(",
				"function buildDomainProofExitClosure(",
				"function writeDomainProofExitClosureArtifact(",
			]) &&
			includesAll(exploitChainRuntime, [
				"export function createExploitChainRuntime",
				"function buildExploitChain(",
				"function writeExploitChainArtifact(",
			]) &&
			includesAll(agentSessionExtensionRuntime, [
				"export class AgentSessionExtensionRuntime",
				"bindExtensions",
			]) &&
			includesAll(agentSessionSource, ["new AgentSessionExtensionRuntime(", "this._extensionRuntime.bindExtensions("]) &&
			includesAll(delegateOrchestrationRuntime, [
				"export function createDelegateOrchestrationRuntime",
				"function buildDelegate(",
				"function autonomousExecutionBudget(",
			]) &&
			includesAll(operatorOrchestrationRuntime, [
				"export function createOperatorOrchestrationRuntime",
				"function buildDecisionCore(",
				"function buildOperator(",
				"async function executeOperatorStep(",
				"function latestCompilerClaimCheckInputs(",
			]) &&
			includesAll(proofLoopRuntime, ["export function createProofLoopRuntime", "function buildProofLoop(", "async function runProofLoop("]) &&
			includesAll(reconLaneRuntime, ["export function createReconLaneRuntime", "function laneCommandPack(", "async function runLaneCommandPack("]) &&
			includesAll(runtimeAdapterExecutionRuntime, [
				'from "./runtime-adapter.ts"',
				'from "./domain-adapter.ts"',
				"export function createRuntimeAdapterExecutionRuntime",
				"function buildExecutionGate(",
				"function writeExecutionArtifact(",
				"async function runExecution(",
				"new DomainAdapterRegistry(",
				"domainAdapter.execute(",
				"domainAdapter.verify(execution)",
				"domainAdapter.replay(execution)",
				"atomicWriteFileSync(",
			]) &&
			includesAll(sessionLifecycleRuntime, [
				'from "./goal.ts"',
				"export function installRepiSessionLifecycle",
				"function createSessionScopedExtensionApi(",
				'pi.on("before_agent_start"',
				'pi.on("session_tree"',
				"lastInjectedState: stats.lastInjectedState",
				"updateMissionRuntimeStats(persistedReconStats(stats))",
			]) &&
			includesAll(toolchainCapabilityRuntime, [
				'from "./toolchain-runtime.ts"',
				"export function createToolchainCapabilityRuntime",
				"function buildProfessionalRuntimeBridges(",
				"function writeProfessionalRuntimeBridges(",
				"function buildDomainCapability(",
				"function writeDomainCapability(",
			]) &&
			legacyProfileImplementations.length === 0,
		legacyProfileImplementations.length
			? `legacy_profile_implementations=${legacyProfileImplementations.join(",")}`
			: "recon-profile wires split REPI runtimes without retaining their heavy implementations",
		"New REPI domains should land in core/repi/* modules first; recon-profile.ts should assemble and register.",
	),
);

rows.push(
	check(
		"runtime:operation-checkpoint-transitions",
		includesAll(campaignOperationRuntime, [
			"const output = await refreshToolIndex(pi)",
			'updateMissionCheckpoint("tool_index_checked", "done", command)',
			"return done(output)",
		]),
		"internal operation commands persist tool-index completion before returning to the planner",
		"Every successful internal operation that satisfies a mission gate must persist the matching checkpoint transition.",
	),
);

rows.push(
	check(
		"architecture:operator-feedback-boundary",
		includesAll(operatorFeedbackRuntime, [
			"export function createOperatorFeedbackRuntime",
			"function classifyOperatorFeedback(",
			"successfulControlPlaneCommand",
			"explicitRuntimeFailure",
		]) &&
			includesAll(operatorOrchestrationRuntime, [
				'from "./operator-feedback-runtime.ts"',
				"createOperatorFeedbackRuntime({ latestSwarmRetryQueue })",
			]) &&
			!operatorOrchestrationRuntime.includes("function classifyOperatorFeedback("),
		"operator feedback classification is isolated and protects control-plane output from data-plane keyword matches",
		"Keep feedback signal classification in operator-feedback-runtime and consume only its structured rows in orchestration.",
	),
);

rows.push(
	check(
		"architecture:operator-policy-boundary",
		includesAll(operatorPolicyRuntime, [
			"export function createOperatorPolicyRuntime",
			"function operatorFeedbackFallbackCommands",
			"function dispatcherFeedbackScoreboard",
			"function operatorVerificationLines",
		]) &&
			includesAll(operatorOrchestrationRuntime, [
				'from "./operator-policy-runtime.ts"',
				"createOperatorPolicyRuntime({",
				"operatorPolicyRuntime",
			]) &&
			![
				"function operatorStepPriority(",
				"function operatorFeedbackFallbackCommands(",
				"function dispatcherFeedbackScoreboard(",
			].some((marker) => operatorOrchestrationRuntime.includes(marker)),
		"operator priority, feedback routing, scoring, and verification policy are isolated from orchestration",
		"Keep deterministic operator policy in operator-policy-runtime and side effects in orchestration/execution runtimes.",
	),
);

rows.push(
	check(
		"architecture:operator-planner-executor-boundary",
		includesAll(operatorExecutionRuntime, [
			"export type OperatorExecutionRuntimeDependencies",
			"export type OperatorExecutionControl",
			"export function createOperatorExecutionRuntime",
			"dependencies.executeOperationStep",
		]) &&
			includesAll(operatorOrchestrationRuntime, [
				'from "./operator-execution-runtime.ts"',
				"createOperatorExecutionRuntime(dependencies)",
				"operatorExecutionRuntime.executeOperatorStep",
			]) &&
			!["const missionMatch =", "const kernelMatch =", "function operationStepFromOperator("].some((marker) =>
				operatorOrchestrationRuntime.includes(marker),
			),
		"operator planning and command execution use separate runtimes with explicit control ports",
		"Keep policy/artifact planning in operator-orchestration-runtime and command parsing/execution in operator-execution-runtime.",
	),
);

rows.push(
	check(
		"architecture:orchestration-runtime-binding-contract",
		includesAll(runtimeBinding, [
			"export function createRuntimeBinding",
			"accessed before initialization",
			"already initialized",
			"export function assertRuntimeBindings",
			"runtime topology incomplete",
		]) &&
			includesAll(reconProfile, [
				'createRuntimeBinding<ReturnType<typeof createOperatorOrchestrationRuntime>>("operator")',
				'createRuntimeBinding<ReturnType<typeof createCampaignOperationRuntime>>("campaign-operation")',
				'createRuntimeBinding<ReturnType<typeof createDelegateOrchestrationRuntime>>("delegate")',
				'createRuntimeBinding<ReturnType<typeof createSwarmSupervisorRuntime>>("swarm-supervisor")',
				"operatorRuntimeBinding.bind(",
				"campaignRuntimeBinding.bind(",
				"delegateRuntimeBinding.bind(",
				"swarmRuntimeBinding.bind(",
				"assertRuntimeBindings([",
			]) &&
			!["let operatorRuntime:", "let delegateRuntime:", "latestSupervisorArtifactPathForFailure"].some((marker) =>
				reconProfile.includes(marker),
			),
		"cyclic orchestration ports are single-assignment, fail-fast, and audited before tool registration",
		"Keep unavoidable orchestration cycles behind explicit runtime bindings; never restore uninitialized module-level runtime variables.",
	),
);

const specialistEvidenceSource = read("packages/coding-agent/src/core/repi/specialist-evidence.ts");
const webRuntimeSource = read("packages/coding-agent/src/core/repi/web-runtime.ts");
const exploitMobileRuntimeSource = read("packages/coding-agent/src/core/repi/exploit-mobile-runtime.ts");
const nativeRuntimeSource = read("packages/coding-agent/src/core/repi/native-runtime.ts");
const legacyRuntimeImplementations = [
	"function liveBrowserNodeScript(",
	"function webAuthzStateNodeScript(",
	"function exploitLabRunnerScript(",
	"function mobileRuntimeFridaHookScript(",
	"function nativeRuntimeGdbScript(",
	"function buildLiveBrowserArtifact(",
	"function buildWebAuthzStateArtifact(",
	"function buildExploitLabArtifact(",
	"function buildMobileRuntimeArtifact(",
	"function buildNativeRuntimeArtifact(",
].filter((marker) => reconProfile.includes(marker));
rows.push(
	check(
		"architecture:professional-runtime-split-contract",
		includesAll(reconProfile, [
			"createExploitMobileRuntime({",
			"createNativeRuntime({",
			"runWebRuntimeLiveBrowser(pi, options, webRuntimeDependencies)",
			"runWebRuntimeAuthzState(pi, options, webRuntimeDependencies)",
		]) &&
			includesAll(specialistEvidenceSource, [
				"export function analyzeBrowserXhrWsEvidence",
				"export function analyzeIdentityAdEvidence",
			]) &&
			includesAll(webRuntimeSource, [
				"export type WebRuntimeDependencies",
				"export async function runLiveBrowser",
				"export function buildWebAuthzStateOutput",
			]) &&
			includesAll(exploitMobileRuntimeSource, [
				"export function createExploitMobileRuntime",
				"buildExploitLabOutput",
				"buildMobileRuntimeOutput",
				"stripScriptIndent",
			]) &&
			includesAll(nativeRuntimeSource, [
				"export function createNativeRuntime",
				"buildNativeRuntimeOutput",
				"stripScriptIndent",
			]) &&
			legacyRuntimeImplementations.length === 0,
		legacyRuntimeImplementations.length
			? `legacy_runtime_implementations=${legacyRuntimeImplementations.join(",")}`
			: "specialist, web, exploit/mobile, and native runtimes are split and wired through the profile assembly",
		"Keep heavy specialist analyzers and runtime artifact builders in core/repi modules; recon-profile.ts should only wire dependencies and register commands/tools.",
	),
);

const workerRuntime = read("packages/coding-agent/src/core/repi/worker-runtime.ts");
const providerWorkerRuntime = read("packages/coding-agent/src/core/repi/provider-worker-runtime.ts");
const swarmWorkerArtifactRuntime = read("packages/coding-agent/src/core/repi/swarm-worker-artifact-runtime.ts");
const swarmWorkerChildSessionRuntime = read("packages/coding-agent/src/core/repi/swarm-worker-child-session-runtime.ts");
const swarmWorkerLeaseSchedulerRuntime = read("packages/coding-agent/src/core/repi/swarm-worker-lease-scheduler-runtime.ts");
const swarmWorkerRetryHandoffRuntime = read("packages/coding-agent/src/core/repi/swarm-worker-retry-handoff-runtime.ts");
rows.push(
	check(
		"profile:worker-runtime-split-contract",
		includesAll(workerRuntime, [
			"WorkerRuntimePoolV1",
			"verifyWorkerRuntimePool",
			"workerLeaseSchedulerEventHash",
			"verifyWorkerLeaseSchedulerV1",
			"WorkerRetryHandoffClosureV1",
			"verifyWorkerRetryHandoffClosureV1",
			"runtime:retry-handoff-closure-validation",
			"workerChildSessionLaunchPolicy",
			"workerChildSessionToWorkerRuntimePoolBridge",
			"verifyWorkerChildSessionRuntimeBatch",
			"REPI_MODEL_ENV_VARIABLES",
			"child_session_provider_env_not_allowlisted",
			"runtime:worker-runtime-pool-validation",
			"runtime:claim-aware-worker-merge",
			"runtime:child-session-pool-bridge-validation",
		]) &&
			includesAll(swarmSupervisorRuntime, [
				'from "./swarm-worker-artifact-runtime.ts"',
				"createSwarmWorkerArtifactRuntime({",
			]) &&
			includesAll(swarmWorkerArtifactRuntime, [
				"createSwarmWorkerChildSessionRuntime",
				"createSwarmWorkerLeaseSchedulerRuntime",
				"createSwarmWorkerRetryHandoffRuntime",
			]) &&
			includesAll(swarmWorkerChildSessionRuntime, [
				"verifyWorkerChildSessionRuntimeBatch",
				"verifyWorkerRuntimePool",
				"workerChildSessionLaunchPolicy",
				"workerChildSessionToWorkerRuntimePoolBridge",
			]) &&
			includesAll(swarmWorkerLeaseSchedulerRuntime, [
				"verifyWorkerLeaseSchedulerV1",
				"workerLeaseSchedulerEventHash",
			]) &&
			includesAll(swarmWorkerRetryHandoffRuntime, [
				"buildWorkerRetryHandoffMergeSummaryV1",
				"verifyWorkerRetryHandoffClosureV1",
				"verifyWorkerRetryHandoffMergeSummaryV1",
			]) &&
			includesAll(reconProfile, [
				"./repi/swarm-supervisor-runtime.ts",
				"createSwarmSupervisorRuntime({",
			]),
		"worker/subagent runtime pool, lease scheduler, retry-handoff closure, and child-session validation live in a split pure module",
		"Keep heavy runtime validation outside recon-profile.ts; profile should assemble live artifacts and call pure contracts.",
	),
);

rows.push(
	check(
		"architecture:provider-worker-runtime-split-contract",
		includesAll(providerWorkerRuntime, [
			"RepiProviderRuntimeMatrixV1",
			"RepiProviderFailureInjectionReportV1",
			"RepiRepairRollbackPolicyV1",
			"verifyProviderRuntimeMatrixV1",
			"verifyProviderFailureInjectionReportV1",
			"verifyRepairRollbackPolicyV1",
			"verifyParallelProviderWorkerMatrixV1",
			"verifyRemoteProviderLongRunV1",
		]) &&
			workerRuntime.includes('from "./provider-worker-runtime.ts"') &&
			!workerRuntime.includes("export function verifyProviderRuntimeMatrixV1("),
		"provider reliability matrices and rollback policy validation are isolated from the worker pool core",
		"Keep provider transport evaluation in provider-worker-runtime.ts; worker-runtime.ts owns scheduling, leases, and handoff closure only.",
	),
);

const swarmRuntimeTypes = read("packages/coding-agent/src/core/repi/swarm-runtime-types.ts");
const swarmClaimRuntime = read("packages/coding-agent/src/core/repi/swarm-claim-runtime.ts");
const swarmCommanderRuntime = read("packages/coding-agent/src/core/repi/swarm-commander-runtime.ts");
rows.push(
	check(
		"architecture:swarm-runtime-types-split-contract",
		includesAll(swarmRuntimeTypes, [
			"export type SwarmArtifact",
			"export type SupervisorArtifact",
			"export type SwarmSupervisorRuntimeDependencies",
			"export type StructuredClaimMergeV1",
		]) &&
			swarmSupervisorRuntime.includes('from "./swarm-runtime-types.ts"') &&
			swarmSupervisorRuntime.includes('export type * from "./swarm-runtime-types.ts"') &&
			!swarmSupervisorRuntime.includes("export type SwarmArtifact ="),
		"swarm schemas and dependency contracts are separated from execution and persistence",
		"Keep schema-only swarm types free of process, filesystem, and persistence implementation code.",
	),
);

const legacySwarmSupervisorImplementations = [
	"function buildSwarmRuntimeClaimLedger(",
	"function buildStructuredClaimMergeFromSwarm(",
	"function refreshSwarmRuntimeClaimLedger(",
	"function supervisorClaimCheckPolicy(",
	"function supervisorPlanCoverage(",
	"function buildSupervisor(",
	"function parseSupervisorCritique(",
].filter((marker) => swarmSupervisorRuntime.includes(marker));
rows.push(
	check(
		"architecture:swarm-runtime-components-split-contract",
		includesAll(swarmSupervisorRuntime, [
			'from "./swarm-claim-runtime.ts"',
			'from "./swarm-commander-runtime.ts"',
			"createSwarmClaimRuntime({",
			"createSwarmCommanderRuntime({",
		]) &&
			includesAll(swarmClaimRuntime, [
				"export function createSwarmClaimRuntime",
				"function buildSwarmRuntimeClaimLedger(",
				"function buildStructuredClaimMergeFromSwarm(",
				"function refreshSwarmRuntimeClaimLedger(",
			]) &&
			includesAll(swarmCommanderRuntime, [
				"export function createSwarmCommanderRuntime",
				"function supervisorClaimCheckPolicy(",
				"function supervisorPlanCoverage(",
				"function buildSupervisor(",
				"function parseSupervisorCritique(",
			]) &&
			legacySwarmSupervisorImplementations.length === 0,
		legacySwarmSupervisorImplementations.length
			? `legacy_swarm_supervisor_implementations=${legacySwarmSupervisorImplementations.join(",")}`
			: "swarm supervisor composes claim, commander, and worker runtimes without retaining their implementations",
		"Keep claim merging, supervisor review, and worker artifact construction in their dedicated swarm runtime modules.",
	),
);

const goalMode = read("packages/coding-agent/src/core/repi/goal.ts");
const resourceSource = read("packages/coding-agent/src/core/repi/resources.ts");
const extensionLoader = read("packages/coding-agent/src/core/extensions/loader.ts");
rows.push(
	check(
		"goal:built-in-mode-contract",
		includesAll(goalMode, [
			"installRepiGoalMode",
			"goal_complete",
			"REPI_GOAL_STATE_ENTRY_TYPE",
			"buildGoalSystemPrompt",
			"formatGoalFooterStatus",
			"Status panel:",
			"Non-TUI/RPC:",
			"Footer: ${footer}",
			"repi-goal-continuation",
		]) &&
			includesAll(reconProfile, ["./repi/session-lifecycle-runtime.ts", "installRepiSessionLifecycle(", "./repi/resources.ts"]) &&
			includesAll(sessionLifecycleRuntime, ['from "./goal.ts"', "installRepiGoalMode(pi)"]) &&
			includesAll(resourceSource, ["createReconResourceLoaderOptions", "isExternalGoalModeExtension"]),
		"/goal command, goal_complete tool, footer status, continuation, and legacy conflict suppression are built in",
		"Keep REPI goal mode built into the session lifecycle and suppress external @narumitw/pi-goal conflicts.",
	),
);
const goalUnitTests = read("packages/coding-agent/test/repi-goal.test.ts");
const goalRpcTests = read("packages/coding-agent/test/repi-goal-rpc-mode.test.ts");
const printModeTests = read("packages/coding-agent/test/print-mode.test.ts");
rows.push(
	check(
		"goal:non-tui-rpc-test-contract",
		includesAll(goalUnitTests, [
			"queues goal prompts as follow-up when print/RPC contexts are already busy",
			"keeps a fresh profile without legacy goal state quiet in non-TUI startup/shutdown",
			"replaces an existing goal without waiting for RPC/non-TUI confirmation dialogs",
			"retries recoverable provider interruptions in print/RPC/json modes without pausing the goal",
			"compacts then resumes active goals after context overflow instead of clearing state",
			"shows a fresh status panel in print/RPC/json without starting a model turn",
			"Footer: 🎯 active 0/1k",
			"Status panel:",
		]) &&
			includesAll(goalRpcTests, [
				"REPI goal mode over RPC",
				"get_commands",
				"get_tools",
				"goal_complete",
				"🎯 active 0/1k",
				"🎯 complete",
				"returns /goal help and fresh status over RPC without starting a model turn",
				"keeps RPC budget-limited goal lifecycle bounded without extra model turns",
				"Goal token budget is still reached:",
				"Goal cleared: rpc budget lifecycle",
				"No goal is currently set.",
				"Status: clear",
			]) &&
			includesAll(printModeTests, [
				"prints extension notifications in text mode so slash-command help is visible without a TUI",
				"emits extension UI requests in json print mode for headless clients",
			]) &&
			includesAll(read("scripts/reverse-agent/repi-release-tarball-smoke.mjs"), [
				"package-bin:goal-status-fresh-print",
				"package-bin:goal-status-fresh-json",
				"No goal is currently set.",
			]),
		"/goal has explicit print/json/RPC/fresh-profile coverage plus an RPC wire test for status/footer events",
		"Keep /goal usable outside TUI: no blocking confirm dialogs, follow-up queuing when busy, fresh profile silence, print-visible help, and RPC/JSON-visible status events.",
	),
);
rows.push(
	check(
		"extensions:upstream-pi-compat-contract",
		includesAll(extensionLoader, [
			"_bundledPiCodingAgentExtensionSdk",
			"tryNative: false",
			"@earendil-works/pi-coding-agent",
			"@earendil-works/pi-ai",
			"@earendil-works/pi-ai/compat",
			"@earendil-works/pi-tui",
		]) &&
			includesAll(read("packages/coding-agent/src/modes/rpc/rpc-types.ts"), ["get_tools", "activeToolNames"]) &&
			includesAll(read("packages/coding-agent/src/modes/rpc/rpc-mode.ts"), ["case \"get_tools\"", "session.getAllTools()"]),
		"loader maps upstream pi imports through lightweight SDK aliases; RPC exposes tool registry for proof",
		"Keep pi-web-access and @narumitw/pi-goal installable without loading the full coding-agent entrypoint through extension imports.",
	),
);

const runtimeAdapterSource = read("packages/coding-agent/src/core/repi/runtime-adapter.ts");
const toolPresenceSource = read("packages/coding-agent/src/core/repi/tool-presence.ts");
rows.push(
	check(
		"runtime:adapter-auto-detect-contract",
		includesAll(runtimeAdapterSource, [
			"detectRuntimeAdapterIds",
			"inspectRuntimeAdapterTarget",
			"RuntimeAdapterTargetProfileV1",
			"summarizeRuntimeAdapterSignals",
			"target_auto_detection_contract",
			"runtime_adapter_target_profile_contract",
			"parser_signal_summary_contract",
			"readFileTail",
			"zip mobile manifest",
			"Info\\.plist",
			"[mobile-ios-info]",
			"[mobile-ios-binary]",
			"gdb-native-trace-adapter",
			"r2-native-xref-adapter",
			"frida-mobile-hook-adapter",
			"web-cdp-network-adapter",
			"tshark-pcap-flow-adapter",
			"binwalk-firmware-extract-adapter",
			"firmware-rootfs-service-map-adapter",
		]) &&
			includesAll(runtimeAdapterExecutionRuntime, [
				'from "./runtime-adapter.ts"',
				"runRuntimeAdapterExecution: runExecution",
			]),
		"runtime adapter matrix covers GDB/r2/Frida/CDP/PCAP/firmware/rootfs and target auto-detection",
		"Keep re_runtime_adapter able to infer the runner from URL, PCAP, APK/IPA/package, firmware/rootfs, pwn/crash, and native target shapes.",
	),
);
const syntheticRuntimeAdapterHits = patternHits("packages/coding-agent/src/core/repi/runtime-adapter.ts", [
	{ id: "synthetic-mobile-fallback", re: /fallback=portable|frida=optional|adb=optional/i },
	{ id: "synthetic-pwn-success", re: /manual-confirm|primitive=manual-confirm/i },
	{ id: "synthetic-web-replay", re: /replay diff pending|parser-signed-replay-diff.*pending/i },
	{ id: "parser-marker-proof", re: /parser-(?:frida|mobile|cert|cdp|xhr|signed|pwn|tshark|http|binwalk|rootfs)[^"]*\|parser-/i },
]);
rows.push(
	check(
		"runtime:adapter-real-runner-contract",
		syntheticRuntimeAdapterHits.length === 0 &&
			includesAll(runtimeAdapterSource, [
				"[http-response]",
				"[har-file]",
				"[web-route-map]",
				"[request-order]",
				"[route-candidate]",
				"[crypto-request-field]",
				"[web-signed-field]",
				"[mobile-ios-info]",
				"[mobile-ios-binary]",
				"[mobile-artifact-string]",
				"[native-mitigation]",
				"[pwn-exec-run]",
				"[pwn-mitigation]",
				"[pwn-multirun-summary]",
				"[pcap-file]",
				"[flow-conversation]",
				"[ipv6-flow]",
				"[tcp-reassembly]",
				"[adapter-rootfs-target]",
				"stdout_sha256",
				"stderr_sha256",
				"binary-mitigation-map",
				"binary mitigation map",
			]) &&
			includesAll(toolPresenceSource, ["repiHostToolPresent", "repiResolvedToolPresent"]) &&
			includesAll(runtimeAdapterExecutionRuntime, [
				"createDomainAdapter",
				"repiResolvedToolPresent",
				"runner_preflight_blocked_no_synthetic_success",
			]),
		syntheticRuntimeAdapterHits.length
			? JSON.stringify(syntheticRuntimeAdapterHits.slice(0, 12))
			: "runtime adapters collect live/local artifacts and do not synthesize proof-exit success markers",
		"Keep runtime adapters evidence-backed: fallbacks may collect passive local artifacts, but must not print fake parser successes or placeholder proof-exit markers.",
	),
);

const graphSource = read("packages/coding-agent/src/core/repi/graph.ts");
const graphArtifactsSource = read("packages/coding-agent/src/core/repi/graph-artifacts.ts");
rows.push(
	check(
		"evidence:task-tree-graph-contract",
		includesAll(graphSource, [
			"AttackGraphTaskTreeNode",
			"taskTree",
			"counter_evidence",
			"hypothesis",
			"target_profile",
			"parser_summary",
			"gap",
			"evidence=${truncate",
		]) &&
			includesAll(graphArtifactsSource, [
				"parseProofLoopArtifact",
				"recentProofLoopArtifacts",
				"recentRuntimeAdapterExecutionArtifacts",
				"runtimeAdapterMitigationEvidenceForGraph",
				"runtimeAdapterParserSummaryForGraph",
				"runtimeAdapterClosure",
			]) &&
			includesAll(attackGraphRuntime, [
				"export function createAttackGraphRuntime",
				"function buildAttackGraph(",
				"artifact:binary-mitigation-map",
				"runtime-adapter-json",
				"runtime-adapter-lineage",
				"runtime-adapter-artifact",
				"runtime-adapter-closure",
				"swarm-worker-closure",
				"worker-retry-handoff-closure",
				"worker-closure-next",
				"runtime-output-hash",
				"evidence-output-hash",
				"proof-loop-output",
				"output_sha256",
				"quick_plan_assertions",
				"proof-loop quick path",
				"gap_classifier",
				"tool:runtime-adapter",
				"target-profile-auto-detect",
				"parser_signal_summary",
				"missing-proof-exit",
				"counter-evidence-prior-hypothesis",
				"command-output-hypothesis",
				"produces",
				"refutes",
				"verifies",
			]) &&
			includesAll(reconProfile, [
				"createAttackGraphRuntime({",
				"const { buildAttackGraph } = createAttackGraphRuntime({",
				"buildAttackGraphOutput",
				"writeAttackGraphArtifact",
				"parseEvidenceLedgerTaskRecords",
				"evidenceRecordHasCounterSignal",
				"evidenceRecordHasHypothesisSignal",
			]),
		"attack graph includes taskTree nodes linking commands, runtime adapter artifacts, hypotheses, verification, and counter-evidence",
		"Keep re_graph build as a traceable task tree, not just a flat mission/lane summary.",
	),
);

const proofLoopSource = read("packages/coding-agent/src/core/repi/proof-loop.ts");
rows.push(
	check(
		"proof-loop:gap-classifier-contract",
		includesAll(proofLoopSource, [
			"RepiProofLoopGapClass",
			"runtime_adapter_gap",
			"proof_spine_seed",
			"classifyRepiProofLoopGap",
			"repiProofLoopQuickPathFromItems",
			"repiProofLoopRuntimeAdapterCommands",
			"runtimeAdapterIdsFromGapText",
			"RepiProofLoopRuntimeAdapterClosureRowV1",
			"repiProofLoopRuntimeAdapterClosureRows",
			"proof_spine_ready",
			"needs_adapter_rerun",
			"appendProofSpine",
			"re_runtime_adapter run",
		]) &&
			includesAll(proofLoopRuntime, [
				"export function createProofLoopRuntime",
				"parseAttackGraphArtifact",
				"proofLoopAttackGraphGapItems",
				"proofLoopGapItems",
				"proofLoopQuickPlanFromItems",
				"proofLoopQuickPlanRows",
				"runtime_adapter_closure",
				"proofLoopQuickPath",
				"proofLoopTargetRuntimeAdapterCommands",
				"source=target_auto_detection",
				"source=attack_graph_gap",
				"quick_plan_phases",
				"runtime_adapter_before_replay",
				"executeProofLoopQuickPathCommand",
				"pruneExecutedQuickCommands",
				"normalizeExecutedCommand",
				"quick_path_execution",
				"gap_classifier",
				"quick_path",
				"re_graph build",
				"re_verifier matrix",
				"re_compiler draft",
				"re_replayer run",
				"re_autofix plan",
			]) &&
			includesAll(reconProfile, [
				"./repi/proof-loop-runtime.ts",
				"createProofLoopRuntime({",
				"latestProofLoopArtifactPath",
				"runProofLoop",
				"buildProofLoopOutput",
			]),
		"proof loop classifies gaps in a split pure module and executes a quick verifier/compiler/replayer/autofix path",
		"Keep re_proof_loop focused on fast executable gap classification and bounded proof repair, not only static queue dumps.",
	),
);

rows.push(
	check(
		"swarm:timeout-budget-contract",
			includesAll(swarmSupervisorRuntime, [
				"swarmWorkerTimeoutMs",
				"REPI_SWARM_SUBAGENT_TIMEOUT_MS",
				"swarmWorkerRetryLimit",
				"REPI_SWARM_RETRY_LIMIT",
				"retry_execution",
				"retryAttempt",
				"timeoutMs",
				"timedOut",
				"cancelledAt",
				"workerRetryHandoffClosure",
				"worker_retry_handoff_closure",
				"workerRetryHandoffMergeSummary",
				"worker_retry_handoff_merge_summary",
			]) &&
			includesAll(swarmWorkerRetryHandoffRuntime, [
				"buildSwarmWorkerRetryHandoffClosure",
				"buildWorkerRetryHandoffMergeSummaryV1",
				"verifyWorkerRetryHandoffClosureV1",
				"verifyWorkerRetryHandoffMergeSummaryV1",
			]) &&
			includesAll(read("packages/coding-agent/src/core/repi/worker-runtime.ts"), [
				"WorkerRetryHandoffMergeSummaryV1",
				"buildWorkerRetryHandoffMergeSummaryV1",
				"verifyWorkerRetryHandoffMergeSummaryV1",
				"retryBudgetVisible",
				"handoffEvidenceBound",
				"workerClosures",
				"buildWorkerRetryHandoffClosureRowsV1",
				"sourceArtifactsPreserved",
				"runtime:retry-handoff-merge-summary-validation",
			]) &&
			includesAll(reconProfile, ["./repi/swarm-supervisor-runtime.ts", "createSwarmSupervisorRuntime({", "runSwarm"]) &&
			includesAll(read("packages/coding-agent/src/core/agent-thread-manager.ts"), [
				"killWorkerProcessTree",
				"REPI_PRINT_MAX_TURNS",
				"handoffRecovered",
				"timeoutMs",
				"maxTurns",
				"cancelledAt",
				"stopped_by_user",
				"SIGKILL",
			]) &&
			includesAll(agentThreadProcessRuntime, ["detached: process.platform"]) &&
			includesAll(agentThreadRuntime, ["runtimeAgentThreadStopKillGraceMs", "REPI_AGENT_THREAD_STOP_KILL_GRACE_MS"]) &&
			includesAll(agentThreadMergeRuntime, ["handoff_recovered"]),
		"swarm/subagent workers carry explicit timeout/cancel/max-turn metadata, process-tree kill, and recoverable handoff merge evidence",
		"Keep subagent scheduling bounded, cancellable, and retry-budget visible across handoff manifests.",
	),
);

const scanFiles = [
	"README.md",
	"AGENTS.md",
	"docs/reverse-agent/README.md",
	"docs/reverse-agent/mainline-overhaul.md",
	"repi",
	"packages/coding-agent/src/core/recon-profile.ts",
	"packages/coding-agent/src/core/repi/artifact-scope.ts",
	"packages/coding-agent/src/core/repi/evidence.ts",
	"packages/coding-agent/src/core/repi/exploit-mobile-runtime.ts",
	"packages/coding-agent/src/core/repi/graph.ts",
	"packages/coding-agent/src/core/repi/goal.ts",
	"packages/coding-agent/src/core/repi/jsonl.ts",
	"packages/coding-agent/src/core/repi/native-runtime.ts",
	"packages/coding-agent/src/core/repi/profile.ts",
	"packages/coding-agent/src/core/repi/resources.ts",
	"packages/coding-agent/src/core/repi/runtime-adapter.ts",
	"packages/coding-agent/src/core/repi/specialist-evidence.ts",
	"packages/coding-agent/src/core/repi/routes.ts",
	"packages/coding-agent/src/core/repi/mission.ts",
	"packages/coding-agent/src/core/repi/storage.ts",
	"packages/coding-agent/src/core/repi/target.ts",
	"packages/coding-agent/src/core/repi/text.ts",
	"packages/coding-agent/src/core/repi/tool-presence.ts",
	"packages/coding-agent/src/core/repi/toolchain.ts",
	"packages/coding-agent/src/core/repi/web-runtime.ts",
	"packages/coding-agent/src/core/repi/worker-runtime.ts",
	"scripts/reverse-agent/repi-smoke.mjs",
	"scripts/reverse-agent/repi-release-tarball-smoke.mjs",
];
const forbiddenPatterns = [
	{ id: "old-source", re: /builtin:pi-recon/ },
	{ id: "old-env", re: /\bPI_RECON\b/ },
	{ id: "old-internal-marker", re: /__pi_/ },
	{ id: "old-route-agent-security", re: /Agent \/ LLM security/ },
	{ id: "old-route-web-security", re: /Web \/ API security/ },
	{ id: "old-route-security-general", re: /Security general/ },
	{ id: "red-team-theme", re: /\bred[- ]team\b/i },
];
const forbiddenHits = scanFiles.flatMap((rel) => patternHits(rel, forbiddenPatterns));
rows.push(
	check(
		"theme:no-old-pi-or-generic-security-drift",
		forbiddenHits.length === 0,
		forbiddenHits.length ? JSON.stringify(forbiddenHits.slice(0, 12)) : `scanned=${scanFiles.length}`,
		"Do not reintroduce old Pi-recon markers, old generic security route labels, or red-team theme text in product surfaces.",
	),
);

const retiredMemorySurfaceFiles = [
	"README.md",
	"docs/reverse-agent/mainline-overhaul.md",
	"docs/reverse-agent/repi-runtime-configuration.md",
	"packages/coding-agent/src/core/recon-profile.ts",
	"packages/coding-agent/src/core/repi/exploit-mobile-runtime.ts",
	"packages/coding-agent/src/core/repi/native-runtime.ts",
	"packages/coding-agent/src/core/repi/profile.ts",
	"packages/coding-agent/src/core/repi/resources.ts",
	"packages/coding-agent/src/core/repi/specialist-evidence.ts",
	"packages/coding-agent/src/core/repi/storage.ts",
	"packages/coding-agent/src/core/repi/web-runtime.ts",
	"packages/coding-agent/src/main.ts",
	"scripts/reverse-agent/repi-smoke.mjs",
];
const retiredMemoryPatterns = [
	{ id: "retired-memory-command", re: /\bre_(?:memory|note|reflect|context)\b|\/re-(?:memory|note|reflect|context)\b/ },
	{ id: "retired-memory-module", re: /(?:memory-(?:recall|deposition|distill|vector|store|runtime)|case-memory|knowledge-scope|tool-call-trace)/i },
	{ id: "retired-memory-policy", re: /MemoryPolicy(?:V\d+)?|autoRecall|autoDeposit|maxInjectedTokens/ },
];
const retiredMemoryHits = retiredMemorySurfaceFiles.flatMap((rel) => patternHits(rel, retiredMemoryPatterns));
rows.push(
	check(
		"runtime:no-retired-persistent-memory-surface",
		retiredMemoryHits.length === 0,
		retiredMemoryHits.length ? JSON.stringify(retiredMemoryHits.slice(0, 12)) : `scanned=${retiredMemorySurfaceFiles.length}`,
		"Remove retired recall/deposit/inject/writeback, case/vector/knowledge, and trace-ledger references from product surfaces.",
	),
);

const smoke = read("scripts/reverse-agent/repi-smoke.mjs");
rows.push(
	check(
		"validation:smoke-covers-usable-entrypoints",
		includesAll(smoke, [
			"product-contract",
			"doctor",
			"model-doctor",
			"model-status-env",
			"launcher-help",
			"launcher-list-models",
			"fresh-install-envless-models",
			"env-model-provider",
			"rpc-goal-command-and-tool",
			"get_tools",
			"goal_complete",
			"activeToolNames",
		]),
		"smoke covers product contract, doctor, model parse, launcher help/list, fresh env-only models, and RPC /goal",
		"Keep smoke focused on fast user-facing REPI usability checks.",
	),
);

const ok = rows.every((row) => row.status === "pass");
const report = {
	kind: "repi-product-contract-report",
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	root,
	ok,
	rows,
};

if (json) {
	console.log(JSON.stringify(report, null, 2));
} else {
	console.log("REPI Product Contract");
	console.log(`root: ${root}`);
	for (const row of rows) {
		console.log(`${row.status === "pass" ? "PASS" : "FAIL"} ${row.id} :: ${row.evidence}`);
		if (row.status !== "pass") console.log(`  fix: ${row.fix}`);
	}
	console.log(`verdict: ${ok ? "pass" : "fail"}`);
}

process.exit(ok ? 0 : 1);
