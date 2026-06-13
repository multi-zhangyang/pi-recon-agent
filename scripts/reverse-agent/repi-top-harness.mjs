#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const json = argv.includes("--json");
const strict = argv.includes("--strict");
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_TOP_HARNESS_TMP === "1";
const tempRoot = mkdtempSync(join(tmpdir(), "repi-top-harness-"));

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function mkdir(path) {
	mkdirSync(path, { recursive: true });
}

function walkFiles(dir, prefix = dir) {
	if (!existsSync(dir)) return [];
	const rows = [];
	for (const name of readdirSync(dir).sort()) {
		const path = join(dir, name);
		const stat = lstatSync(path);
		if (stat.isDirectory()) rows.push(...walkFiles(path, prefix));
		else if (stat.isFile()) rows.push({ path: relative(prefix, path), size: stat.size, sha256: sha256(readFileSync(path)) });
		else if (stat.isSymbolicLink()) rows.push({ path: relative(prefix, path), symlink: true });
	}
	return rows;
}

function treeHash(dir) {
	return sha256(JSON.stringify(walkFiles(dir)));
}

function run(command, args, options = {}) {
	const child = spawnSync(command, args, {
		cwd: options.cwd ?? root,
		env: { ...process.env, ...(options.env ?? {}) },
		input: options.input,
		encoding: "utf8",
		maxBuffer: options.maxBuffer ?? 40 * 1024 * 1024,
	});
	return {
		command,
		args,
		code: child.status,
		signal: child.signal,
		stdout: child.stdout || "",
		stderr: child.stderr || "",
		combined: `${child.stdout || ""}\n${child.stderr || ""}`,
	};
}

function resultCheck(id, status, evidence = {}, detail = {}) {
	return { id, status, evidence, ...detail };
}

function markerCheck(id, path, required, forbidden = []) {
	const full = join(root, path);
	if (!existsSync(full)) return resultCheck(id, "fail", { path, exists: false });
	const text = readFileSync(full, "utf8");
	const missing = required.filter((marker) => !text.includes(marker));
	const presentForbidden = forbidden.filter((pattern) => (pattern instanceof RegExp ? pattern.test(text) : text.includes(pattern)));
	return resultCheck(missing.length === 0 && presentForbidden.length === 0 ? id : id, missing.length === 0 && presentForbidden.length === 0 ? "pass" : "fail", {
		path,
		sha256: sha256(text).slice(0, 24),
		required: required.map((marker) => ({ marker, present: text.includes(marker) })),
		forbidden: forbidden.map((pattern) => ({ pattern: String(pattern), present: presentForbidden.includes(pattern) })),
	});
}

function readJsonFile(path) {
	return JSON.parse(readFileSync(join(root, path), "utf8"));
}

function packageIdentityChecks() {
	const checks = [];
	const expectedPackages = [
		["packages/ai/package.json", "@pi-recon/repi-ai"],
		["packages/agent/package.json", "@pi-recon/repi-agent-core"],
		["packages/tui/package.json", "@pi-recon/repi-tui"],
		["packages/coding-agent/package.json", "@pi-recon/repi-coding-agent"],
	];

	try {
		const rootPackage = readJsonFile("package.json");
		checks.push(resultCheck("package:root-repi-monorepo", rootPackage.name === "repi-monorepo" ? "pass" : "fail", { name: rootPackage.name }));
	} catch (error) {
		checks.push(resultCheck("package:root-repi-monorepo", "fail", { error: String(error) }));
	}

	for (const [path, expectedName] of expectedPackages) {
		try {
			const pkg = readJsonFile(path);
			checks.push(resultCheck(`package:name:${expectedName}`, pkg.name === expectedName ? "pass" : "fail", { path, name: pkg.name, expectedName }));
			checks.push(
				resultCheck(`package:repo:${expectedName}`, String(pkg.repository?.url ?? "").includes("multi-zhangyang/pi-recon-agent") ? "pass" : "fail", {
					path,
					repository: pkg.repository ?? null,
				}),
			);
		} catch (error) {
			checks.push(resultCheck(`package:name:${expectedName}`, "fail", { path, error: String(error) }));
		}
	}

	try {
		const coding = readJsonFile("packages/coding-agent/package.json");
		const binKeys = Object.keys(coding.bin ?? {}).sort();
		checks.push(
			resultCheck(
				"package:coding-bin-repi-only",
				JSON.stringify(binKeys) === JSON.stringify(["repi"]) && coding.bin.repi === "dist/cli.js" ? "pass" : "fail",
				{ bin: coding.bin ?? null },
			),
		);
		checks.push(
			resultCheck("package:coding-piconfig-repi", coding.piConfig?.name === "repi" && coding.piConfig?.configDir === ".repi" ? "pass" : "fail", {
				piConfig: coding.piConfig ?? null,
			}),
		);
		const deps = Object.keys(coding.dependencies ?? {});
		const oldDeps = deps.filter((name) => /@(earendil-works|mariozechner)\/pi-/.test(name) || name.includes("rerepi"));
		checks.push(
			resultCheck(
				"package:coding-deps-repi-only",
				oldDeps.length === 0 && deps.includes("@pi-recon/repi-agent-core") && deps.includes("@pi-recon/repi-ai") && deps.includes("@pi-recon/repi-tui")
					? "pass"
					: "fail",
				{ deps, oldDeps },
			),
		);
	} catch (error) {
		checks.push(resultCheck("package:coding-bin-repi-only", "fail", { error: String(error) }));
	}

	for (const lockPath of ["package-lock.json", "packages/coding-agent/npm-shrinkwrap.json"]) {
		try {
			const text = readFileSync(join(root, lockPath), "utf8");
			const forbidden = [/@earendil-works\/pi-/, /@mariozechner\/pi-/, /@pi-recon\/rerepi/, /"pi"\s*:\s*"dist\/cli\.js"/];
			const hits = forbidden.filter((pattern) => pattern.test(text)).map(String);
			checks.push(
				resultCheck(
					`package:lock-clean:${lockPath}`,
					hits.length === 0 && text.includes("@pi-recon/repi-coding-agent") && text.includes('"repi": "dist/cli.js"') ? "pass" : "fail",
					{ path: lockPath, hits },
				),
			);
		} catch (error) {
			checks.push(resultCheck(`package:lock-clean:${lockPath}`, "fail", { error: String(error) }));
		}
	}

	return checks;
}

function staticContractChecks() {
	const checks = [];
	checks.push(
		resultCheck("repo:no-root-dot-pi-profile", !existsSync(join(root, ".pi")) ? "pass" : "fail", {
			forbiddenPath: ".pi",
			reason: "The checkout must not contain a project .pi profile that can be auto-loaded by upstream pi.",
		}),
	);
	checks.push(
		resultCheck(
			"repo:repi-profile-mirror",
			existsSync(join(root, "repi-profile", "SYSTEM.md")) &&
				existsSync(join(root, "repi-profile", "extensions", "reverse-pentest-core.ts"))
				? "pass"
				: "fail",
			{ profileDir: "repi-profile" },
		),
	);
	checks.push(
		markerCheck("launcher:repi-product-env", "repi", [
			"REPI_CODING_AGENT_APP_NAME",
			"REPI_CODING_AGENT_CONFIG_DIR",
			"PI_CODING_AGENT_APP_NAME",
			"PI_CODING_AGENT_CONFIG_DIR",
			"REPI_PRIMARY=1",
			"REPI_PRODUCT=1",
			"PI_RECON_PRODUCT=1",
			"REPI_SKIP_VERSION_CHECK",
			"REPI_SKIP_PACKAGE_UPDATE_CHECK",
			"REPI_TELEMETRY",
			"REPI_OFFLINE",
			"REPI_PRINT_TIMEOUT_MS",
			"REPI_PRINT_MAX_TURNS",
			"REPI_PRINT_MAX_TOOL_CALLS",
			"REPI_STDIN_READ_TIMEOUT_MS",
			"REPI_BASH_DEFAULT_TIMEOUT_SECONDS",
			"PI_SKIP_VERSION_CHECK",
			"PI_SKIP_PACKAGE_UPDATE_CHECK",
			"PI_TELEMETRY",
			"packages/coding-agent/src/cli.ts",
		], ["ARGS=(--recon"]),
	);
	checks.push(markerCheck("runtime:print-mode-guardrails", "packages/coding-agent/src/modes/print-mode.ts", ["REPI_PRINT_PROGRESS", "REPI_PRINT_TIMEOUT_MS", "REPI_PRINT_MAX_TURNS", "REPI_PRINT_MAX_TOOL_CALLS", "still_running", "guard_abort", "max_tool_calls_exceeded"], []));
	checks.push(markerCheck("runtime:stdin-noninteractive-guard", "packages/coding-agent/src/main.ts", ["REPI_READ_STDIN_WITH_PROMPT", "REPI_STDIN_READ_TIMEOUT_MS", "skipWhenExplicitPrompt", "readPipedStdin"], []));
	checks.push(markerCheck("runtime:bash-default-timeout", "packages/coding-agent/src/core/tools/bash.ts", ["REPI_BASH_DEFAULT_TIMEOUT_SECONDS", "PI_BASH_DEFAULT_TIMEOUT_SECONDS", "effectiveTimeout", "Command timed out after"], []));
	checks.push(markerCheck("runtime:sse-idle-timeout", "packages/ai/src/providers/openai-codex-responses.ts", ["Codex SSE stream idle timeout", "readSSEChunk", "idleTimeoutMs"], []));
	checks.push(markerCheck("runtime:anthropic-sse-idle-timeout", "packages/ai/src/providers/anthropic.ts", ["Anthropic SSE stream idle timeout", "readSseChunk", "idleTimeoutMs"], []));
	checks.push(markerCheck("launcher:repi-swarm-llm-run", "repi", ["swarm)", "plan|run|status|merge|llm-run", "repi-swarm-llm-run.mjs"], []));
	checks.push(markerCheck("swarm:llm-worker-pool-cli", "scripts/reverse-agent/repi-swarm-llm-run.mjs", ["repi-llm-worker-pool-report", "LLMWorkerPoolV1", "SwarmPlannerV1", "StructuredSubagentMergeV1", "repi swarm plan", "repi swarm run", "REPI_CODING_AGENT_DIR", "--no-session", "stdoutSha256", "evidenceRoot"], []));
	checks.push(markerCheck("mission:control-plane-cli", "scripts/reverse-agent/repi-mission.mjs", ["repi mission new", "repi mission plan", "repi mission pack", "repi-mission-context-pack", "evidenceContract", "unscoped old-memory injection", "nextActions"], []));
	checks.push(markerCheck("model:cli-control-plane", "scripts/reverse-agent/model-inspect.mjs", ["repi model list", "repi model add", "repi model edit", "repi model remove", "repi model export", "repi model import", "repi model login", "repi model test", "repi model default", "auth.json", "settings.json", "apiKeyEnvPresent", "--show-urls", "baseUrlHidden"], []));
	checks.push(markerCheck("memory:cli-governance", "scripts/reverse-agent/memory-inspect.mjs", ["repi memory list", "repi memory show", "repi memory why", "repi memory doctor", "repi memory export", "repi memory purge", "repi memory sanitize", "repi memory repair", "governance-ledger.jsonl", "append_only_memory_governance", "quarantine", "visibleByDefault", "REPI_MEMORY_PURGE_CONFIRM", "REPI_MEMORY_SANITIZE_CONFIRM", "REPI_MEMORY_REPAIR_CONFIRM", "--yes"], []));
	checks.push(markerCheck("diagnostics:bugreport-control-plane", "scripts/reverse-agent/repi-bugreport.mjs", ["repi-bugreport", "strictly redacted local diagnostic bundle", "no auth.json export", "secretScan", "compactModelDoctor", "compactMemoryDoctor"], []));
	checks.push(
		markerCheck("code:repi-bootstrap-defaults", "packages/coding-agent/src/cli/repi-bootstrap.ts", [
			"bootstrapRepiCli",
			"initializeRepiProfile",
			"CLEAN_ROOM_FLAGS",
			'"--recon"',
			'"--import-pi-auth"',
			'"--clean-room"',
			'"--project-context"',
			'"--with-project-resources"',
			"PACKAGE_COMMANDS",
			"REPI_PRINT_PROGRESS",
			"REPI_PRINT_TIMEOUT_MS",
			"REPI_PRINT_MAX_TURNS",
			"REPI_PRINT_MAX_TOOL_CALLS",
			"REPI_STDIN_READ_TIMEOUT_MS",
			"REPI_BASH_DEFAULT_TIMEOUT_SECONDS",
			"PI_BASH_DEFAULT_TIMEOUT_SECONDS",
		], []),
	);
	checks.push(markerCheck("code:repi-product-command-dispatch", "packages/coding-agent/src/cli/repi-product-commands.ts", ["dispatchRepiProductCommand", "PRODUCT_COMMANDS", "repi-health.mjs", "repi-doctor.mjs", "repi-mission.mjs", "model-inspect.mjs", "memory-inspect.mjs", "repi-swarm-llm-run.mjs", "REPI_BIN_PATH", "dist/reverse-agent"], []));
	checks.push(markerCheck("code:repi-cli-dispatch-wired", "packages/coding-agent/src/cli.ts", ["dispatchRepiProductCommand(cliArgs)", "bootstrapRepiCli"], []));
	checks.push(
		markerCheck("code:repi-profile-init-core", "packages/coding-agent/src/core/repi-profile-init.ts", [
			"initializeRepiProfile",
			"isolated-repi-profile",
			"legacyPiImported",
			'join(homedir(), ".pi", "agent")',
			"settings.compaction",
			"existingCompaction",
			"triggerPercent: existingCompaction.triggerPercent ?? 85",
			"warningPercent: existingCompaction.warningPercent ?? 80",
			"settings.memory",
			"schemaVersion: 2",
			"rawAutoInject: existingMemory.rawAutoInject ?? false",
			"includeGlobalMemoryInContextPack: existingMemory.includeGlobalMemoryInContextPack ?? false",
			"core-memory.md",
			"events.jsonl",
		], []),
	);
	checks.push(markerCheck("code:repi-update-pi-boundary", "packages/coding-agent/src/package-manager-cli.ts", ["does not manage upstream pi", "repi update only updates REPI packages", 'options.source === "pi"'], []));
	checks.push(markerCheck("launcher:pi-non-owning-shim", "pi", ["no longer owns the `pi` command", "exec \"$candidate\" \"$@\""], ["ARGS=(--recon", "REPI_PRODUCT=1", "REPI_PRIMARY=1", "PI_RECON_PRODUCT=1", "PI_RECON_PRIMARY=1"]));
	checks.push(
		markerCheck(
			"installer:repi-no-pi-takeover",
			"scripts/reverse-agent/install-repi.sh",
			["ln -sfn \"$ROOT/repi\" \"$BIN_DIR/repi\"", "cleanup_stale_recon_pi", "Do not install or overwrite `pi`", "Installed REPI:"],
			[/ln\s+-sfn\s+"\$ROOT\/pi"\s+"\$BIN_DIR\/pi"/, /rm\s+-rf\s+"\$HOME\/\.pi"/, /@earendil-works\/(?:pi|repi)-coding-agent/],
		),
	);
	checks.push(markerCheck("installer:global-profile-deprecated", "scripts/reverse-agent/install-global-profile.sh", ["install-global-profile.sh is deprecated", "no longer installs a file-based global profile", "init-repi-profile.mjs", "install-repi.sh", "does not copy SYSTEM.md", "write ~/.pi/agent"], [/cp \"\$ROOT\/repi-profile/, /extensions\/reverse-pentest-core\.ts" "\$AGENT_DIR/, /settings\.extensions =/, /settings\.skills =/, /settings\.prompts =/]));
	checks.push(markerCheck("installer:legacy-no-takeover", "scripts/reverse-agent/install-recon-pi.sh", ["deprecated", 'exec "$ROOT/scripts/reverse-agent/install-repi.sh'], [/ln\s+-s.*\$ROOT\/pi/, /rm\s+-rf/, /deleted upstream/],));
	checks.push(markerCheck("installer:repi-legacy-cleaner", "scripts/reverse-agent/clean-global-repi-profile.sh", ["Cleaned global pi REPI file-profile pollution", "repi-legacy-backup", "Default is dry-run", "--apply", "--force-tools", "file_has_marker", "reverse-pentest"], []));
	checks.push(markerCheck("audit:repi-product-surface", "scripts/reverse-agent/repi-product-surface-audit.mjs", ["REPI product_surface_audit", "PRODUCT_SURFACE_FILES", "compatibilityProtocolMarkers"], []));
	checks.push(markerCheck("release:binary-archives-repi", "scripts/build-binaries.sh", ["repi-linux-x64.tar.gz", '--outfile "$OUTPUT_DIR/$platform/repi', "repi-$platform.tar.gz", "repi-$platform.zip"], [/\bpi-linux-x64\.tar\.gz/, /--outfile .*\/pi(?:\.exe)?"/, /\bpi-\$platform\.(?:zip|tar\.gz)/]));
	checks.push(markerCheck("release:local-shims-repi", "scripts/local-release.mjs", ["createRepiShim", '"repi.cmd"', '"repi"', "repi-${platform}.tar.gz"], ["createPiShim", /node_modules\/\.bin\/pi\b/, /\bpi\.cmd\b/, /\bpi-\$\{platform\}\.tar\.gz/]));
	checks.push(markerCheck("code:repi-product-switch", "packages/coding-agent/src/config.ts", ["IS_REPI_PRODUCT", "REPI_PRODUCT", "PI_RECON_PRODUCT", "APP_NAME === \"repi\"", "https://gist.github.com/"], []));
	checks.push(markerCheck("code:update-branding-disabled", "packages/coding-agent/src/modes/interactive/interactive-mode.ts", ["if (!IS_REPI_PRODUCT)", "PI_SKIP_PACKAGE_UPDATE_CHECK", "if (IS_REPI_PRODUCT) return;", "REPI Changelog"], []));
	checks.push(markerCheck("code:auto-compact-threshold", "packages/coding-agent/src/core/compaction/compaction.ts", ["compactionTriggerTokens", "triggerPercent", "contextWindow * triggerPercent", "contextWindow - reserveTokens"], []));
	checks.push(markerCheck("code:provider-attribution-rebranded", "packages/coding-agent/src/core/provider-attribution.ts", ["IS_REPI_PRODUCT", "X-OpenRouter-Title", "repi-coding-agent", "x-opencode-client"], []));
	checks.push(markerCheck("kernel:false-refusal-rewrite-source", "packages/coding-agent/src/core/recon-profile.ts", ["authorized_task_bias", "public_target_no_auto_refusal", "scope_gap_to_passive_mapping", "authorization_context_missing", "public_target_request"], []));
	checks.push(markerCheck("kernel:false-refusal-rewrite-profile", "repi-profile/extensions/reverse-pentest-core.ts", ["authorized_task_bias", "scope_gap_to_passive_mapping", "authorization_context_missing", "public_target_request"], []));
	checks.push(markerCheck("profile:false-refusal-rewrite-docs", "repi-profile/SYSTEM.md", ["authorized_task_bias", "public_target_no_auto_refusal", "scope_gap_to_passive_mapping"], []));
	checks.push(markerCheck("profile:runtime-config-knowledge", "repi-profile/SYSTEM.md", ["model_provider_configuration_runtime", "~/.repi/agent/models.json", "openai-completions", "anthropic-messages", "repi --offline --list-models", "triggerPercent"], []));
	checks.push(markerCheck("prompt:repi-config", "repi-profile/prompts/repi-config.md", ["~/.repi/agent/models.json", "OpenAI-compatible", "anthropic-messages", "triggerPercent=85"], []));
	checks.push(markerCheck("docs:runtime-configuration", "docs/reverse-agent/repi-runtime-configuration.md", ["model_provider_configuration_runtime", "~/.repi/agent/models.json", "repi --offline", "openai-completions", "triggerPercent"], []));
	checks.push(markerCheck("npm:top-harness-script", "package.json", ["gate:repi-harness", "gate:repi-cli-ux", "gate:open-source-readiness", "gate:repi-product", "gate:repi-isolation", "gate:repi-product-surface", "gate:context-compact", "gate:compact-resume-chain", "gate:compact-resume-ledger-v2", "gate:multi-compact-pressure", "gate:cross-session-resume-live", "gate:cross-session-multi-compact-matrix", "gate:context-runtime-schema", "gate:memory-contract", "gate:memory-utility", "gate:memory-feedback", "gate:memory-feedback-closure", "gate:memory-scope-isolation", "gate:knowledge-scope-isolation", "gate:artifact-scope-filter", "gate:latest-artifact-consumer-scope", "gate:failure-signature-priority", "gate:memory-orchestrator", "gate:memory-deposition", "gate:memory-experience", "gate:memory-quality-ledger", "gate:memory-replay-evaluator", "gate:memory-strategy-capsule", "gate:memory-active-kernel", "gate:memory-maturation-runtime", "gate:memory-ux", "gate:memory-hybrid", "gate:memory-vector", "gate:memory-usefulness", "gate:memory-distiller", "gate:memory-sedimentation", "gate:memory-store", "gate:memory-swarm-writeback", "gate:memory-supervisor", "gate:worker-runtime-pool", "gate:worker-lease-scheduler", "gate:worker-child-session", "gate:provider-runtime-matrix", "gate:provider-endpoint-doctor", "gate:toolchain-domain-capability", "gate:domain-proof-exit-closure", "gate:relane-specialist-command-pack", "gate:pwn-advanced-capability", "gate:professional-runtime-bridges", "gate:runtime-adapter-execution", "gate:provider-failure-injection", "gate:repair-rollback-policy", "gate:worker-provider-repair-rollback-unification", "gate:tool-call-trace-ledger", "gate:parallel-provider-worker-matrix", "gate:remote-provider-longrun", "gate:structured-claim-merge", "gate:live-conflict-arbitration-matrix", "gate:autonomous-hardening-gap-ledger", "gate:autonomous-closure-readiness", "gate:capability-release-bundle", "gate:release-ci-pipeline", "gate:release-evidence-index", "install:repi", "clean:repi-legacy-profile", "clean:repi-legacy-profile:apply", "clean:repi-legacy-profile:force-tools"], ["install:recon-pi", "gate:pi-recon-primary"]));
	checks.push(markerCheck("release:open-source-readiness-gate", "scripts/reverse-agent/open-source-readiness-gate.mjs", ["repi-open-source-readiness-report", "CODE_OF_CONDUCT.md", "SUPPORT.md", "PULL_REQUEST_TEMPLATE.md", "privacy:tracked-secret-scan", "docs:security-no-upstream-stale-text"], []));
	checks.push(markerCheck("release:open-source-governance-docs", "README.md", ["开源治理", "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "SUPPORT.md", "gate:open-source-readiness"], []));
	checks.push(markerCheck("ci:open-source-readiness-workflow", ".github/workflows/repi-harness.yml", ["REPI open source readiness gate", "npm run gate:open-source-readiness"], []));
	checks.push(markerCheck("npm:coding-agent-bundles-product-commands", "packages/coding-agent/package.json", ["dist/reverse-agent", "repi-health.mjs", "repi-doctor.mjs", "repi-mission.mjs", "model-inspect.mjs", "memory-inspect.mjs", "repi-swarm-llm-run.mjs"], []));
	checks.push(markerCheck("memory:v2-runtime-contract", "packages/coding-agent/src/core/recon-profile.ts", ["type MemoryEventV1", "function appendMemoryEvent", "function appendReplayerMemoryEvent", "appendReplayerMemoryEvent(replay, path)", "function appendAutofixMemoryEvent", "appendAutofixMemoryEvent(autofix, path)", "function appendProofLoopMemoryEvent", "appendProofLoopMemoryEvent(proof, path)", "function appendCompletionMemoryEvent", "appendCompletionMemoryEvent(audit", "function searchMemoryEvents", "memory_event_reuse", "events.jsonl", "case-memory.jsonl"], []));
	checks.push(markerCheck("memory:v2-schema-fixture", "schemas/reverse-agent/memory-event.schema.json", ["MemoryEventV1", "CaseMemoryV1", "MemoryRetrievalReportV1", "confidence"], []));
	checks.push(markerCheck("memory:utility-hard-eval", "scripts/reverse-agent/memory-utility-gate.mjs", ["repi-memory-utility-gate", "scenario:", "mustSuggestCommands", "mustNotSuggestCommands", "routeMatches"], []));
	checks.push(markerCheck("memory:utility-fixture", "fixtures/reverse-agent/memory-utility.fixture.json", ["repi-memory-utility-fixture", "authz-transfer-to-new-target", "pwn-replay-reuse", "mustNotRecallEventIds"], []));
	checks.push(markerCheck("memory:feedback-hard-eval", "scripts/reverse-agent/memory-feedback-gate.mjs", ["repi-memory-feedback-gate", "case-memory-feedback:reuse", "case-memory-feedback:penalty", "mustNotSuggestCommands"], []));
	checks.push(markerCheck("memory:feedback-fixture", "fixtures/reverse-agent/memory-feedback.fixture.json", ["repi-memory-feedback-fixture", "success-feedback-promotes-source-case", "failure-feedback-demotes-bad-case", "memory_reuse_feedback_demote"], []));
	checks.push(markerCheck("memory:feedback-closure-hard-eval", "scripts/reverse-agent/memory-feedback-closure-gate.mjs", ["repi-memory-feedback-closure-gate", "runtime:success-feedback-promotes", "runtime:failure-feedback-demotes", "runtime:pending-feedback-tracked"], []));
	checks.push(markerCheck("memory:feedback-closure-schema", "schemas/reverse-agent/memory-feedback-closure.schema.json", ["MemoryFeedbackClosureReportV1", "MemoryFeedbackClosureRowV1", "pending_injection_requires_feedback_writeback"], []));
	checks.push(markerCheck("memory:feedback-closure-fixture", "fixtures/reverse-agent/memory-feedback-closure.fixture.json", ["repi-memory-feedback-closure-fixture", "success-feedback-promotes-injected-memory", "failure-feedback-demotes-injected-memory", "pending-injection-requires-writeback"], []));
	checks.push(markerCheck("memory:scope-isolation-hard-eval", "scripts/reverse-agent/memory-scope-isolation-gate.mjs", ["repi-memory-scope-isolation-gate", "runtime:same-scope-allows-injection", "runtime:cross-workspace-blocks-injection", "runtime:cross-target-blocks-injection", "runtime:legacy-memory-scope-manual-review", "runtime:sedimentation-blocks-cross-scope-injection"], []));
	checks.push(markerCheck("memory:scope-isolation-schema", "schemas/reverse-agent/memory-scope-isolation.schema.json", ["MemoryScopeIsolationV1", "MemoryScopeV1", "scope_filter_by_mission_session_workspace_target", "cross_workspace_contamination_blocks_injection", "cross_target_contamination_blocks_injection"], []));
	checks.push(markerCheck("memory:scope-isolation-fixture", "fixtures/reverse-agent/memory-scope-isolation.fixture.json", ["repi-memory-scope-isolation-fixture", "same-scope-allows-injection", "cross-session-workspace-blocks-injection", "legacy-scope-warns-manual-review"], []));
	checks.push(markerCheck("knowledge:scope-isolation-hard-eval", "scripts/reverse-agent/knowledge-scope-isolation-gate.mjs", ["repi-knowledge-scope-isolation-gate", "runtime:blocked-artifact-quarantined", "runtime:command-hints-exclude-blocked", "runtime:similarity-excludes-blocked-artifact"], []));
	checks.push(markerCheck("knowledge:scope-isolation-schema", "schemas/reverse-agent/knowledge-scope-isolation.schema.json", ["KnowledgeScopeIsolationV1", "MemoryScopeIsolationV1", "knowledge_graph_scope_filter_blocks_quarantined_artifacts", "knowledge_graph_command_hints_exclude_scope_blocked_sources"], []));
	checks.push(markerCheck("knowledge:scope-isolation-fixture", "fixtures/reverse-agent/knowledge-scope-isolation.fixture.json", ["repi-knowledge-scope-isolation-fixture", "blocked-artifact-excluded-from-command-hints", "allowed-artifact-remains-queryable", "scope-report-embedded-in-knowledge-graph"], []));
	checks.push(markerCheck("artifact:scope-filter-hard-eval", "scripts/reverse-agent/artifact-scope-filter-gate.mjs", ["repi-artifact-scope-filter-gate", "runtime:blocked-latest-artifact-quarantined", "runtime:context-index-excludes-blocked-latest", "runtime:context-index-selects-allowed-older"], []));
	checks.push(markerCheck("artifact:scope-filter-schema", "schemas/reverse-agent/artifact-scope-filter.schema.json", ["ArtifactScopeFilterV1", "MemoryScopeIsolationV1", "latest_artifact_side_channel_scope_filter", "context_artifact_index_excludes_scope_blocked_artifacts"], []));
	checks.push(markerCheck("artifact:scope-filter-fixture", "fixtures/reverse-agent/artifact-scope-filter.fixture.json", ["repi-artifact-scope-filter-fixture", "blocked-latest-artifact-skipped", "older-allowed-artifact-selected", "artifact-scope-report-embedded-in-context-pack"], []));
	checks.push(markerCheck("artifact:latest-consumer-scope-hard-eval", "scripts/reverse-agent/latest-artifact-consumer-scope-gate.mjs", ["repi-latest-artifact-consumer-scope-gate", "LatestArtifactConsumerScopeGateV1", "runtime:no-cross-target-latest-leak", "runtime:operator-feedback-scope", "runtime:proof-loop-gap-scope", "runtime:compiler-claim-gate-scope"], []));
	checks.push(markerCheck("artifact:latest-consumer-scope-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["artifactTargetMatches", "artifactScopeVerdictPriority", "operator_feedback_latest_artifact_consumer", "proof_loop_gap_latest_artifact_consumer", "proof_loop_evidence_latest_artifact_consumer", "proof_loop_source_latest_artifact_consumer", "compiler_claim_gate"], []));
	checks.push(markerCheck("artifact:latest-consumer-scope-schema", "schemas/reverse-agent/latest-artifact-consumer-scope.schema.json", ["LatestArtifactConsumerScopeGateV1", "LatestArtifactConsumerScopeScenarioV1", "proof_loop_source_latest_artifact_consumer", "cross_target_latest_artifact_blocked"], []));
	checks.push(markerCheck("artifact:latest-consumer-scope-fixture", "fixtures/reverse-agent/latest-artifact-consumer-scope.fixture.json", ["repi-latest-artifact-consumer-scope-fixture", "operator-feedback-cross-target-block", "proof-loop-source-cross-target-block", "compiler-claim-gate-cross-target-block"], []));
	checks.push(markerCheck("runtime:failure-signature-priority-hard-eval", "scripts/reverse-agent/failure-signature-priority-gate.mjs", ["repi-failure-signature-priority-gate", "FailureSignaturePriorityGateV1", "runtime:proof-loop-failure-priority", "runtime:knowledge-consumes-failure-signature", "runtime:no-unrelated-target-leak"], []));
	checks.push(markerCheck("runtime:failure-signature-priority-core", "packages/coding-agent/src/core/recon-profile.ts", ["failureSignaturePriorityReport", "failureSignatureRepairQueue", "failure_signature_priority", "runtimeRepairTargetMatches", "knowledge_graph_failure_signature_priority"], []));
	checks.push(markerCheck("runtime:failure-signature-priority-schema", "schemas/reverse-agent/failure-signature-priority.schema.json", ["FailureSignaturePriorityGateV1", "FailureSignaturePriorityScenarioV1", "runtime_failure_ledger_preempts_blind_retry", "repair_queue_ready_command_required"], []));
	checks.push(markerCheck("runtime:failure-signature-priority-fixture", "fixtures/reverse-agent/failure-signature-priority.fixture.json", ["repi-failure-signature-priority-fixture", "exhausted-failure-preempts-operator-feedback", "repeated-failure-promotes-repair-command", "missing-repair-command-is-not-ready"], []));
	checks.push(markerCheck("runtime:agent-dogfood-failure-signature-binding-hard-eval", "scripts/reverse-agent/agent-dogfood-failure-signature-binding-gate.mjs", ["repi-agent-dogfood-failure-signature-binding-gate", "AgentDogfoodFailureSignatureBindingGateV1", "fixture:positive-binding", "fixture:negative-rejections"], []));
	checks.push(markerCheck("runtime:agent-dogfood-failure-signature-binding-runtime", "bench/recon-remote/agent-dogfood/parallel-run.mjs", ["AgentDogfoodFailureSignatureBindingV1", "failureSignatureManifestBindings", "failureSignatureManifestBindingsCaptured", "failureSignatureManifestBindingCount"], []));
	checks.push(markerCheck("runtime:agent-dogfood-failure-signature-binding-schema", "schemas/reverse-agent/agent-dogfood-failure-signature-binding.schema.json", ["AgentDogfoodFailureSignatureBindingGateV1", "AgentDogfoodFailureSignatureBindingV1", "dedupe_window_role_scoped_retry_key"], []));
	checks.push(markerCheck("runtime:agent-dogfood-failure-signature-binding-fixture", "fixtures/reverse-agent/agent-dogfood-failure-signature-binding.fixture.json", ["repi-agent-dogfood-failure-signature-binding-fixture", "missing-binding-in-runtime-manifest", "duplicate-role-dedupe-window-mismatch"], []));
	checks.push(markerCheck("runtime:agent-dogfood-structured-claims-hard-eval", "scripts/reverse-agent/agent-dogfood-structured-claims-gate.mjs", ["repi-agent-dogfood-structured-claims-gate", "AgentDogfoodStructuredClaimMergeGateV1", "fixture:positive-structured-claims", "fixture:negative-structured-claims"], []));
	checks.push(markerCheck("runtime:agent-dogfood-structured-claims-runtime", "bench/recon-remote/agent-dogfood/parallel-run.mjs", ["StructuredClaimMergeV1", "structuredClaimMergePath", "structuredClaimRows", "structuredClaimRef", "narrative_only_observation_never_promotes"], []));
	checks.push(markerCheck("runtime:agent-dogfood-structured-claims-schema", "schemas/reverse-agent/agent-dogfood-structured-claims.schema.json", ["AgentDogfoodStructuredClaimMergeGateV1", "narrative_only_observation_never_promotes", "runtime_manifest_artifact_ref_required"], []));
	checks.push(markerCheck("runtime:agent-dogfood-structured-claims-fixture", "fixtures/reverse-agent/agent-dogfood-structured-claims.fixture.json", ["repi-agent-dogfood-structured-claims-fixture", "narrative-only-final-pass", "missing-json-query", "unresolved-challenge-final-pass"], []));
	checks.push(markerCheck("runtime:autonomous-hardening-gap-ledger-hard-eval", "scripts/reverse-agent/autonomous-hardening-gap-ledger-gate.mjs", ["repi-autonomous-hardening-gap-ledger-gate", "AutonomousHardeningGapLedgerV1", "runtime:hardening-gap-ledger", "fixture:negative-ledger"], []));
	checks.push(markerCheck("runtime:autonomous-hardening-gap-ledger-autonomy", "scripts/reverse-agent/autonomy-control-plane.mjs", ["AutonomousHardeningGapLedgerV1", "hardeningGapLedger", "closureGate", "readyForImplementation"], []));
	checks.push(markerCheck("runtime:autonomous-hardening-gap-ledger-schema", "schemas/reverse-agent/autonomous-hardening-gap-ledger.schema.json", ["AutonomousHardeningGapLedgerV1", "AutonomousHardeningGapV1", "every_gap_has_closure_gate"], []));
	checks.push(markerCheck("runtime:autonomous-hardening-gap-ledger-fixture", "fixtures/reverse-agent/autonomous-hardening-gap-ledger.fixture.json", ["AutonomousHardeningGapLedgerV1", "missing-closure-gate", "top-autonomous-true-with-open-gaps"], []));
	checks.push(markerCheck("runtime:autonomous-closure-readiness-hard-eval", "scripts/reverse-agent/autonomous-closure-readiness-gate.mjs", ["repi-autonomous-closure-readiness-gate", "AutonomousClosureReadinessGateV1", "runtime:closure-readiness-matrix", "runtime:all-closure-gates-strict-no-write", "fixture:negative-readiness"], []));
	checks.push(markerCheck("runtime:autonomous-closure-readiness-schema", "schemas/reverse-agent/autonomous-closure-readiness.schema.json", ["AutonomousClosureReadinessGateV1", "AutonomousClosureReadinessMatrixV1", "closure_gate_strict_no_write_passes", "top_autonomous_false_until_closed"], []));
	checks.push(markerCheck("runtime:autonomous-closure-readiness-fixture", "fixtures/reverse-agent/autonomous-closure-readiness.fixture.json", ["AutonomousClosureReadinessGateV1", "missing-package-script", "closure-gate-run-failed", "top-autonomous-true-with-ready-gaps"], []));
	checks.push(markerCheck("release:capability-release-bundle-hard-eval", "scripts/reverse-agent/capability-release-bundle-gate.mjs", ["repi-capability-release-bundle-gate", "CapabilityClaimReleaseBundleGateV1", "capability_claim_release_bundle_gate", "runtime:capability-claim-release-bundle", "runtime:no-narrative-only-release-promotion"], []));
	checks.push(markerCheck("release:capability-release-bundle-schema", "schemas/reverse-agent/capability-release-bundle.schema.json", ["CapabilityClaimReleaseBundleGateV1", "CapabilityClaimReleaseBundleV1", "release_claims_require_command_evidence", "no_narrative_only_release_promotion"], []));
	checks.push(markerCheck("release:capability-release-bundle-fixture", "fixtures/reverse-agent/capability-release-bundle.fixture.json", ["CapabilityClaimReleaseBundleGateV1", "claim-without-command-evidence", "failed-command-promoted", "narrative-only-promotion"], []));
	checks.push(markerCheck("release:ci-pipeline-hard-eval", "scripts/reverse-agent/release-ci-pipeline-gate.mjs", ["repi-release-ci-pipeline-gate", "ReleaseCiPipelineGateV1", "release_ci_pipeline_gate", "runtime:release-ci-pipeline", "runtime:ci-no-live-secret-dependency"], []));
	checks.push(markerCheck("release:ci-pipeline-schema", "schemas/reverse-agent/release-ci-pipeline.schema.json", ["ReleaseCiPipelineGateV1", "ReleaseCiPipelineV1", "product_boundary_before_capability_claim", "ci_no_live_provider_or_secret_dependency"], []));
	checks.push(markerCheck("release:ci-pipeline-fixture", "fixtures/reverse-agent/release-ci-pipeline.fixture.json", ["ReleaseCiPipelineGateV1", "missing-product-boundary-gate", "live-provider-secret-required", "repository-check-before-top-harness"], []));
	checks.push(markerCheck("release:evidence-index-hard-eval", "scripts/reverse-agent/release-evidence-index-gate.mjs", ["repi-release-evidence-index-gate", "ReleaseEvidenceIndexGateV1", "release_evidence_index_gate", "runtime:release-evidence-index", "runtime:release-evidence-index-hash-chain"], []));
	checks.push(markerCheck("release:evidence-index-schema", "schemas/reverse-agent/release-evidence-index.schema.json", ["ReleaseEvidenceIndexGateV1", "ReleaseEvidenceIndexV1", "release_evidence_index_links_capability_bundle", "release_evidence_index_hash_chain_valid"], []));
	checks.push(markerCheck("release:evidence-index-fixture", "fixtures/reverse-agent/release-evidence-index.fixture.json", ["ReleaseEvidenceIndexGateV1", "missing-autonomy-gap-ledger", "missing-capability-bundle-ref", "hash-chain-drift"], []));
	checks.push(markerCheck("parallel:swarm-provider-manifest-parity-hard-eval", "scripts/reverse-agent/swarm-provider-manifest-parity-gate.mjs", ["repi-swarm-provider-manifest-parity-gate", "SwarmProviderManifestParityGateV1", "fixture:positive-parity", "fixture:negative-parity", "all_child_sessions_match_parity_rows", "child-session-nonfirst-row-drift", "live_provider_backed_multi_provider_shared_ledger_matrix", "provider_worker_retry_window_manifest_binding_chain", "provider_backed_long_window_shared_merge_ledger", "provider_worker_extended_retry_manifest_chain", "ProviderBackedLongWindowSharedMergeLedgerV1", "ProviderWorkerExtendedRetryManifestChainV1", "multi_provider_workers_share_claim_failure_merge_ledger", "provider_worker_retry_repair_rows_bound_to_worker_manifest"], []));
	checks.push(markerCheck("parallel:swarm-provider-manifest-parity-schema", "schemas/reverse-agent/swarm-provider-manifest-parity.schema.json", ["SwarmProviderManifestParityGateV1", "provider_env_refs_only", "failure_repair_refs_preserved_across_provider_worker", "all_child_sessions_match_parity_rows", "WorkerChildSessionRuntimeBatchV1", "child-session-nonfirst-row-drift", "SwarmProviderSharedMergeLedgerV1", "SwarmProviderRetryRepairBindingV1", "LiveProviderBackedSharedLedgerMatrixV1", "ProviderWorkerRetryWindowManifestBindingChainV1", "ProviderBackedLongWindowSharedMergeLedgerV1", "ProviderWorkerExtendedRetryManifestChainV1"], []));
	checks.push(markerCheck("parallel:swarm-provider-manifest-parity-fixture", "fixtures/reverse-agent/swarm-provider-manifest-parity.fixture.json", ["repi-swarm-provider-manifest-parity-fixture", "worker-id-mismatch", "literal-provider-secret", "failure-repair-unlinked", "single-provider-matrix", "retry-repair-manifest-unbound", "shared-ledger-window-provider-missing", "retry-window-nonmonotonic", "retry-window-manifest-drift", "long-shared-ledger-window-too-short", "extended-retry-chain-too-short", "long-shared-ledger-secret-leak"], []));
	checks.push(markerCheck("memory:orchestrator-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["MemoryOrchestratorV6", "buildMemoryOrchestratorReport", "formatMemoryOrchestrator", "memoryOrchestratorReportPath", "mandatory_memory_control_loop", "pre_task_retrieve_before_operator", "post_tool_writeback_contract", "post_compact_resume_memory_injection", "memory_orchestrator_report_in_context_pack"], []));
	checks.push(markerCheck("memory:orchestrator-profile", "repi-profile/extensions/reverse-pentest-core.ts", ["MemoryOrchestratorV6", "buildMemoryOrchestratorReport", "formatMemoryOrchestrator", "memoryOrchestratorReportPath", "mandatory_memory_control_loop", "pre_task_retrieve_before_operator", "post_tool_writeback_contract", "post_compact_resume_memory_injection"], []));
	checks.push(markerCheck("memory:orchestrator-hard-eval", "scripts/reverse-agent/memory-orchestrator-gate.mjs", ["repi-memory-orchestrator-gate", "runtime:pre-task-retrieval-before-operator", "runtime:post-tool-writeback-contract", "runtime:compact-resume-memory-injection", "runtime:context-pack-embeds-orchestrator"], []));
	checks.push(markerCheck("memory:orchestrator-schema", "schemas/reverse-agent/memory-orchestrator.schema.json", ["MemoryOrchestratorV6", "mandatory_memory_control_loop", "pre_task_retrieve_before_operator", "post_compact_resume_memory_injection"], []));
	checks.push(markerCheck("memory:orchestrator-fixture", "fixtures/reverse-agent/memory-orchestrator.fixture.json", ["repi-memory-orchestrator-fixture", "pre-task-retrieval-before-operator", "post-tool-writeback-contract", "compact-resume-memory-injection", "final-supervise-before-claim"], []));
	checks.push(markerCheck("memory:deposition-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["MemoryDepositionEngineV7", "appendMemoryDepositionRuntimeEvent", "buildMemoryDepositionReport", "memoryDepositionEventBusPath", "post_tool_writeback_autocapture", "runtime_step_event_bus"], []));
	checks.push(markerCheck("memory:deposition-profile", "repi-profile/extensions/reverse-pentest-core.ts", ["MemoryDepositionEngineV7", "appendMemoryDepositionRuntimeEvent", "buildMemoryDepositionReport", "memoryDepositionEventBusPath", "post_tool_writeback_autocapture"], []));
	checks.push(markerCheck("memory:deposition-hard-eval", "scripts/reverse-agent/memory-deposition-gate.mjs", ["repi-memory-deposition-gate", "runtime:manual-deposit-memory-binding", "runtime:tool-result-autocapture", "runtime:context-pack-embeds-deposition", "runtime:orchestrator-wiring"], []));
	checks.push(markerCheck("memory:deposition-schema", "schemas/reverse-agent/memory-deposition.schema.json", ["MemoryDepositionEngineV7", "MemoryDepositionRuntimeEventV7", "runtime_step_event_bus", "post_tool_writeback_autocapture", "claim_compact_resume_binding"], []));
	checks.push(markerCheck("memory:deposition-fixture", "fixtures/reverse-agent/memory-deposition.fixture.json", ["MemoryDepositionEngineV7", "manual-runtime-deposit-writes-memory-event", "tool-result-autocapture-writes-deposition-row", "context-pack-embeds-deposition-report"], []));
	checks.push(markerCheck("memory:experience-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["MemoryExperienceEngineV8", "buildMemoryExperienceReport", "formatMemoryExperienceReport", "memoryExperienceReportPath", "episode_model_v8", "structured_claim_extraction", "lesson_promotion_gate", "contradiction_resolution", "usefulness_backprop"], []));
	checks.push(markerCheck("memory:experience-profile", "repi-profile/extensions/reverse-pentest-core.ts", ["MemoryExperienceEngineV8", "buildMemoryExperienceReport", "formatMemoryExperienceReport", "memoryExperienceReportPath", "lesson_promotion_gate"], []));
	checks.push(markerCheck("memory:experience-hard-eval", "scripts/reverse-agent/memory-experience-gate.mjs", ["repi-memory-experience-gate", "runtime:episode-model", "runtime:structured-claim-extraction", "runtime:lesson-promotion-gate", "runtime:contradiction-resolution", "runtime:context-pack-embeds-experience"], []));
	checks.push(markerCheck("memory:experience-schema", "schemas/reverse-agent/memory-experience.schema.json", ["MemoryExperienceEngineV8", "MemoryExperienceReportV8", "MemoryExperienceClaimV8", "episode_model_v8", "lesson_promotion_gate", "usefulness_backprop"], []));
	checks.push(markerCheck("memory:experience-fixture", "fixtures/reverse-agent/memory-experience.fixture.json", ["repi-memory-experience-fixture", "success-event-promotes-command-strategy-lesson", "contradictory-command-enters-conflict-resolution", "context-pack-embeds-experience-report"], []));
	checks.push(markerCheck("memory:skill-capsule-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["MemorySkillCapsuleV9", "buildMemorySkillCapsuleReport", "formatMemorySkillCapsules", "memorySkillCapsuleReportPath", "skill_capsule_assetization", "verified_skill_promotion_gate", "operator_skill_injection"], []));
	checks.push(markerCheck("memory:skill-capsule-profile", "repi-profile/extensions/reverse-pentest-core.ts", ["MemorySkillCapsuleV9", "buildMemorySkillCapsuleReport", "formatMemorySkillCapsules", "memorySkillCapsuleReportPath", "skill_capsule_assetization"], []));
	checks.push(markerCheck("memory:skill-capsule-hard-eval", "scripts/reverse-agent/memory-skill-capsule-gate.mjs", ["repi-memory-skill-capsule-gate", "runtime:experience-lesson-to-operator-capsule", "runtime:operator-skill-injection", "runtime:context-pack-embeds-skill-capsules", "runtime:orchestrator-wiring"], []));
	checks.push(markerCheck("memory:skill-capsule-schema", "schemas/reverse-agent/memory-skill-capsule.schema.json", ["MemorySkillCapsuleV9", "MemorySkillCapsuleReportV9", "skill_capsule_assetization", "verified_skill_promotion_gate", "operator_skill_injection"], []));
	checks.push(markerCheck("memory:skill-capsule-fixture", "fixtures/reverse-agent/memory-skill-capsule.fixture.json", ["repi-memory-skill-capsule-fixture", "experience-lesson-becomes-operator-skill-capsule", "context-pack-embeds-skill-capsule-report"], []));
	checks.push(markerCheck("memory:distill-promotion-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["MemoryDistillPromotionV10", "buildMemoryDistillPromotionReport", "formatMemoryDistillPromotion", "memoryDistillPromotionReportPath", "provider_distill_contract", "artifact_to_claim_distillation", "verifier_backed_promotion_gate"], []));
	checks.push(markerCheck("memory:distill-promotion-profile", "repi-profile/extensions/reverse-pentest-core.ts", ["MemoryDistillPromotionV10", "buildMemoryDistillPromotionReport", "formatMemoryDistillPromotion", "memoryDistillPromotionReportPath", "provider_distill_contract"], []));
	checks.push(markerCheck("memory:distill-promotion-hard-eval", "scripts/reverse-agent/memory-distill-promotion-gate.mjs", ["repi-memory-distill-promotion-gate", "runtime:provider-contract-fallback", "runtime:artifact-backed-promotion", "runtime:context-pack-embeds-distill-promotion", "runtime:orchestrator-wiring"], []));
	checks.push(markerCheck("memory:distill-promotion-schema", "schemas/reverse-agent/memory-distill-promotion.schema.json", ["MemoryDistillPromotionV10", "MemoryDistillPromotionReportV10", "MemoryDistillProviderV10", "provider_distill_contract", "verifier_backed_promotion_gate"], []));
	checks.push(markerCheck("memory:distill-promotion-fixture", "fixtures/reverse-agent/memory-distill-promotion.fixture.json", ["repi-memory-distill-promotion-fixture", "local-provider-contract-fallback-is-deterministic", "context-pack-embeds-distill-promotion-report"], []));
	checks.push(markerCheck("memory:quality-ledger-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["MemoryQualityLedgerV11", "buildMemoryQualityLedgerReport", "formatMemoryQualityLedger", "memoryQualityReportPath", "active_memory_policy", "quality_score_feedback_loop"], []));
	checks.push(markerCheck("memory:quality-ledger-profile", "repi-profile/extensions/reverse-pentest-core.ts", ["MemoryQualityLedgerV11", "buildMemoryQualityLedgerReport", "formatMemoryQualityLedger", "memoryQualityReportPath", "active_memory_policy"], []));
	checks.push(markerCheck("memory:quality-ledger-hard-eval", "scripts/reverse-agent/memory-quality-ledger-gate.mjs", ["repi-memory-quality-ledger-gate", "runtime:positive-feedback-promotes", "runtime:negative-feedback-demotes", "runtime:context-pack-embeds-quality", "runtime:orchestrator-wiring"], []));
	checks.push(markerCheck("memory:quality-ledger-schema", "schemas/reverse-agent/memory-quality-ledger.schema.json", ["MemoryQualityLedgerV11", "MemoryQualityLedgerReportV11", "MemoryQualityLedgerRowV11", "active_memory_policy", "quality_score_feedback_loop"], []));
	checks.push(markerCheck("memory:quality-ledger-fixture", "fixtures/reverse-agent/memory-quality-ledger.fixture.json", ["repi-memory-quality-ledger-fixture", "retrieval-and-injection-increase-quality-score", "context-pack-embeds-quality-report"], []));
	checks.push(markerCheck("memory:replay-evaluator-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["MemoryReplayEvaluatorV12", "buildMemoryReplayEvaluatorReport", "formatMemoryReplayEvaluator", "memoryReplayEvaluatorReportPath", "memory_ab_replay", "causal_attribution_signal"], []));
	checks.push(markerCheck("memory:replay-evaluator-profile", "repi-profile/extensions/reverse-pentest-core.ts", ["MemoryReplayEvaluatorV12", "buildMemoryReplayEvaluatorReport", "formatMemoryReplayEvaluator", "memoryReplayEvaluatorReportPath", "memory_ab_replay"], []));
	checks.push(markerCheck("memory:replay-evaluator-hard-eval", "scripts/reverse-agent/memory-replay-evaluator-gate.mjs", ["repi-memory-replay-evaluator-gate", "runtime:ab-replay-improves-memory", "runtime:quality-ledger-consumes-replay", "runtime:context-pack-embeds-replay", "runtime:orchestrator-wiring"], []));
	checks.push(markerCheck("memory:replay-evaluator-schema", "schemas/reverse-agent/memory-replay-evaluator.schema.json", ["MemoryReplayEvaluatorV12", "MemoryReplayEvaluatorReportV12", "MemoryReplayEvaluatorRowV12", "memory_ab_replay", "causal_attribution_signal"], []));
	checks.push(markerCheck("memory:replay-evaluator-fixture", "fixtures/reverse-agent/memory-replay-evaluator.fixture.json", ["repi-memory-replay-evaluator-fixture", "memory-ab-replay-promotes-useful-memory", "quality-ledger-consumes-replay-signal", "context-pack-embeds-replay-report"], []));
	checks.push(markerCheck("memory:strategy-capsule-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["MemoryStrategyCapsuleV13", "buildMemoryStrategyCapsuleReport", "formatMemoryStrategyCapsules", "memoryStrategyCapsuleReportPath", "executable_strategy_capsule", "replay_backed_strategy_promotion"], []));
	checks.push(markerCheck("memory:strategy-capsule-profile", "repi-profile/extensions/reverse-pentest-core.ts", ["MemoryStrategyCapsuleV13", "buildMemoryStrategyCapsuleReport", "formatMemoryStrategyCapsules", "memoryStrategyCapsuleReportPath", "executable_strategy_capsule"], []));
	checks.push(markerCheck("memory:strategy-capsule-hard-eval", "scripts/reverse-agent/memory-strategy-capsule-gate.mjs", ["repi-memory-strategy-capsule-gate", "runtime:replay-backed-strategy", "runtime:executable-command-contract", "runtime:context-pack-embeds-strategy", "runtime:orchestrator-wiring"], []));
	checks.push(markerCheck("memory:strategy-capsule-schema", "schemas/reverse-agent/memory-strategy-capsule.schema.json", ["MemoryStrategyCapsuleV13", "MemoryStrategyCapsuleReportV13", "executable_strategy_capsule", "strategy_quality_gate"], []));
	checks.push(markerCheck("memory:strategy-capsule-fixture", "fixtures/reverse-agent/memory-strategy-capsule.fixture.json", ["repi-memory-strategy-capsule-fixture", "replay-improved-memory-becomes-executable-strategy", "strategy-capsule-in-context-pack"], []));
	checks.push(markerCheck("memory:active-kernel-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["MemoryActiveKernelV14", "buildMemoryActiveKernelReport", "formatMemoryActiveKernel", "memoryActiveKernelReportPath", "unified_memory_decision_engine", "active_recall_scheduler"], []));
	checks.push(markerCheck("memory:active-kernel-profile", "repi-profile/extensions/reverse-pentest-core.ts", ["MemoryActiveKernelV14", "buildMemoryActiveKernelReport", "formatMemoryActiveKernel", "memoryActiveKernelReportPath", "active_recall_scheduler"], []));
	checks.push(markerCheck("memory:active-kernel-hard-eval", "scripts/reverse-agent/memory-active-kernel-gate.mjs", ["repi-memory-active-kernel-gate", "fixture:active-kernel-policy", "quality_replay_strategy_fusion", "active_kernel_feedback"], []));
	checks.push(markerCheck("memory:active-kernel-schema", "schemas/reverse-agent/memory-active-kernel.schema.json", ["MemoryActiveKernelV14", "repi-memory-active-kernel-report", "repi-memory-active-injection-pack", "unified_memory_decision_engine"], []));
	checks.push(markerCheck("memory:active-kernel-fixture", "fixtures/reverse-agent/memory-active-kernel.fixture.json", ["repi-memory-active-kernel-fixture", "mustInjectStrategyIds", "mustAvoidEventIds", "cross_session_compact_ready"], []));
	checks.push(markerCheck("memory:maturation-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["MemoryMaturationRuntimeV15", "buildMemoryMaturationRuntimeReport", "formatMemoryMaturationRuntime", "memoryMaturationRuntimeReportPath", "automatic_memory_maturation_pipeline", "tool_result_to_strategy_loop", "closed_loop_writeback", "retention_decay_scheduler", "stale_memory_rehearsal_queue", "usefulness_backprop_to_maturation"], []));
	checks.push(markerCheck("memory:maturation-runtime-profile", "repi-profile/extensions/reverse-pentest-core.ts", ["MemoryMaturationRuntimeV15", "buildMemoryMaturationRuntimeReport", "formatMemoryMaturationRuntime", "memoryMaturationRuntimeReportPath", "automatic_memory_maturation_pipeline", "retention_decay_scheduler"], []));
	checks.push(markerCheck("memory:maturation-runtime-hard-eval", "scripts/reverse-agent/memory-maturation-runtime-gate.mjs", ["repi-memory-maturation-runtime-gate", "runtime:re-memory-mature-exit", "runtime:maturation-report", "maturation hash chain", "retention_decay_scheduler"], []));
	checks.push(markerCheck("memory:maturation-runtime-schema", "schemas/reverse-agent/memory-maturation-runtime.schema.json", ["MemoryMaturationRuntimeV15", "repi-memory-maturation-runtime-report", "automatic_memory_maturation_pipeline", "tool_result_to_strategy_loop", "retention_decay_scheduler", "stale_memory_rehearsal_queue"], []));
	checks.push(markerCheck("memory:maturation-runtime-fixture", "fixtures/reverse-agent/memory-maturation-runtime.fixture.json", ["repi-memory-maturation-runtime-fixture", "mustPromoteEventIds", "mustReplayRequiredEventIds", "mustRehearseEventIds", "maturation-runtime-ledger.jsonl"], []));
	checks.push(markerCheck("memory:ux-dashboard-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["MemoryUxDashboardV16", "buildMemoryUxDashboard", "formatMemoryUxDashboard", "memoryStatusReportPath", "user_visible_memory_status", "recall_explainability", "append_only_memory_governance"], []));
	checks.push(markerCheck("memory:ux-dashboard-profile", "repi-profile/extensions/reverse-pentest-core.ts", ["MemoryUxDashboardV16", "buildMemoryUxDashboard", "formatMemoryUxDashboard", "memoryStatusReportPath", "user_visible_memory_status", "recall_explainability", "append_only_memory_governance"], []));
	checks.push(markerCheck("memory:ux-dashboard-hard-eval", "scripts/reverse-agent/memory-ux-gate.mjs", ["repi-memory-ux-gate", "runtime:memory-ux-dashboard", "runtime:why-this-memory-visible", "runtime:append-only-governance", "runtime:memory-status-artifacts"], []));
	checks.push(markerCheck("memory:ux-dashboard-schema", "schemas/reverse-agent/memory-ux-dashboard.schema.json", ["MemoryUxDashboardV16", "user_visible_memory_status", "recall_explainability", "append_only_memory_governance", "lifecycle_governance_commands"], []));
	checks.push(markerCheck("memory:ux-dashboard-fixture", "fixtures/reverse-agent/memory-ux-dashboard.fixture.json", ["repi-memory-ux-dashboard-fixture", "MemoryUxDashboardV16", "why_this_memory_rows", "memory_status_board_written"], []));
	checks.push(markerCheck("memory:hybrid-hard-eval", "scripts/reverse-agent/memory-hybrid-gate.mjs", ["repi-memory-hybrid-gate", "memory_semantic_hybrid_reuse", "case-memory-hybrid", "artifact-hybrid"], []));
	checks.push(markerCheck("memory:hybrid-fixture", "fixtures/reverse-agent/memory-hybrid.fixture.json", ["repi-memory-hybrid-fixture", "semantic-authz-recall", "artifact-pcap-recall", "mustHaveTopReasonPrefixes"], []));
	checks.push(markerCheck("memory:vector-hard-eval", "scripts/reverse-agent/memory-vector-gate.mjs", ["repi-memory-vector-gate", "runtime:index-schema", "runtime:search-schema", "runtime:vector-rerank-used", "runtime:embedding-provider-contract", "runtime:openai-compatible-fallback", "fixture:vector-rerank-negative"], []));
	checks.push(markerCheck("memory:vector-schema", "schemas/reverse-agent/memory-vector.schema.json", ["MemoryVectorIndexV1", "MemoryVectorSearchReportV1", "MemoryEmbeddingProviderV1", "openai_compatible_embedding_contract", "repi-local-hash-embedding-v1"], []));
	checks.push(markerCheck("memory:vector-fixture", "fixtures/reverse-agent/memory-vector.fixture.json", ["repi-memory-vector-fixture", "semantic-authz-rerank", "forbidden-cross-route-vector-leak", "quality-weighted-replay-boost", "provider-contract-env-fallback"], []));
	checks.push(markerCheck("memory:usefulness-hard-eval", "scripts/reverse-agent/memory-usefulness-gate.mjs", ["repi-memory-usefulness-gate", "eval:hit-at-1", "eval:forbidden-leak", "concurrency:hash-chain", "concurrency:child-process-hash-chain"], []));
	checks.push(markerCheck("memory:usefulness-fixture", "fixtures/reverse-agent/memory-usefulness.fixture.json", ["repi-memory-usefulness-fixture", "authz-bola-recall", "pwn-crash-recall", "concurrentAppend", "mustSpawnChildProcesses"], []));
	checks.push(markerCheck("memory:v3-distiller-hard-eval", "scripts/reverse-agent/memory-distiller-gate.mjs", ["repi-memory-distiller-gate", "mandatory_memory_injection_chain", "memory_contamination_quarantine"], []));
	checks.push(markerCheck("memory:v3-distiller-fixture", "fixtures/reverse-agent/memory-distiller.fixture.json", ["repi-memory-distiller-fixture", "case-cross-route-pollution", "mustHaveInjectionStages"], []));
	checks.push(markerCheck("memory:v4-sedimentation-hard-eval", "scripts/reverse-agent/memory-sedimentation-gate.mjs", ["repi-memory-sedimentation-gate", "mandatory_memory_injection_packet", "memory_sedimentation_grade>=70", "quarantine_blocks_injection"], []));
	checks.push(markerCheck("memory:v4-sedimentation-fixture", "fixtures/reverse-agent/memory-sedimentation.fixture.json", ["repi-memory-sedimentation-fixture", "mustInjectEventIds", "mustQuarantineCaseSignatures", "feedback-demotes"], []));
	checks.push(markerCheck("memory:v5-store-hard-eval", "scripts/reverse-agent/memory-store-gate.mjs", ["repi-memory-store-gate", "hash-chain-negative", "repair-index-rebuild", "memory_store_v5"], []));
	checks.push(markerCheck("memory:v5-store-fixture", "fixtures/reverse-agent/memory-store.fixture.json", ["repi-memory-store-fixture", "broken-prevHash", "missing-case-index", "mustHaveRuntimeMarkers"], []));
	checks.push(markerCheck("memory:swarm-writeback-hard-eval", "scripts/reverse-agent/memory-swarm-writeback-gate.mjs", ["repi-memory-swarm-writeback-gate", "fixture:writeback-count", "fixture:artifact-capture", "fixture:skip-non-run-modes"], []));
	checks.push(markerCheck("memory:swarm-writeback-fixture", "fixtures/reverse-agent/memory-swarm-writeback.fixture.json", ["repi-memory-swarm-writeback-fixture", "memory-swarm-writeback", "SubagentRuntimeManifestV1", "mustSkipModes"], []));
	checks.push(markerCheck("memory:supervisor-hard-eval", "scripts/reverse-agent/memory-supervisor-gate.mjs", ["repi-memory-supervisor-gate", "runtime:report-schema", "runtime:lifecycle-board", "fixture:promotion-demotion-quarantine-merge"], []));
	checks.push(markerCheck("memory:supervisor-schema", "schemas/reverse-agent/memory-supervisor.schema.json", ["MemorySupervisorReportV1", "MemorySupervisorDecisionV1", "quarantineOverridesPromotion", "mergeByCaseSignature"], []));
	checks.push(markerCheck("memory:supervisor-fixture", "fixtures/reverse-agent/memory-supervisor.fixture.json", ["repi-memory-supervisor-fixture", "promote", "demote", "quarantine", "merge", "feedback_required_after_injection"], []));
	checks.push(markerCheck("swarm:worker-runtime-pool-hard-eval", "scripts/reverse-agent/worker-runtime-pool-gate.mjs", ["repi-worker-runtime-pool-gate", "maxConcurrency_exceeded", "timeout_without_cancel", "duplicate_mergeKey_unresolved"], []));
	checks.push(markerCheck("swarm:worker-runtime-pool-fixture", "fixtures/reverse-agent/worker-runtime-pool.fixture.json", ["repi-worker-runtime-pool-fixture", "WorkerRuntimePoolV1", "claim-aware merge"], []));
	checks.push(markerCheck("runtime:worker-lease-scheduler-core", "packages/coding-agent/src/core/recon-profile.ts", ["type WorkerLeaseSchedulerV1", "type WorkerLeaseSchedulerEventV1", "function verifyWorkerLeaseSchedulerV1", "function buildWorkerLeaseSchedulerFromSwarm", "function refreshSwarmWorkerLeaseScheduler", "workerLeaseSchedulerPath", "workerLeaseSchedulerStatus", "runtime:worker-lease-scheduler-live-wiring", "worker_lease_scheduler_stale_recovery_missing"], []));
	checks.push(markerCheck("runtime:worker-lease-scheduler", "scripts/reverse-agent/worker-lease-scheduler-gate.mjs", ["repi-worker-lease-scheduler-gate", "WorkerLeaseSchedulerV1", "runtime:worker-lease-scheduler-validation", "runtime:worker-lease-stale-recovery", "runtime:worker-lease-scheduler-live-wiring", "runtime:re-swarm-worker-lease-scheduler-exit", "negative:worker-lease-no-stale-recovery"], []));
	checks.push(markerCheck("runtime:worker-lease-scheduler-schema", "schemas/reverse-agent/worker-lease-scheduler.schema.json", ["WorkerLeaseSchedulerV1", "lease_exclusive", "stale_lease_recovery", "duplicate_completion_rejected"], []));
	checks.push(markerCheck("runtime:worker-lease-scheduler-fixture", "fixtures/reverse-agent/worker-lease-scheduler.fixture.json", ["repi-worker-lease-scheduler-fixture", "negative:worker-lease-hash-drift", "negative:worker-lease-no-stale-recovery"], []));
	checks.push(markerCheck("swarm:worker-child-session-hard-eval", "scripts/reverse-agent/worker-child-session-gate.mjs", ["repi-worker-child-session-gate", "isolated_home_invalid", "apiKeyRef_not_env_ref", "timeout_without_cancel", "runtime:re_swarm-child-session-probe-exit", "runtime:worker-child-session-artifact-wiring", "runtime:worker-child-process-smoke", "runtime:worker-provider-child-process-smoke", "runtime:worker-provider-env-ref-only", "WorkerProviderChildProcessProbeV1"], []));
	checks.push(markerCheck("swarm:worker-child-session-fixture", "fixtures/reverse-agent/worker-child-session.fixture.json", ["repi-worker-child-session-fixture", "WorkerChildSessionRuntimeBatchV1", "childSessionRuntimeCaptured"], []));
	checks.push(markerCheck("provider:runtime-matrix-hard-eval", "scripts/reverse-agent/provider-runtime-matrix-gate.mjs", ["repi-provider-runtime-matrix-gate", "ProviderRuntimeMatrixV1", "runtime:provider-matrix-openai-completions", "runtime:provider-matrix-openai-responses", "runtime:provider-matrix-anthropic-messages", "runtime:provider-matrix-env-ref-only", "negative:missing-env-ref", "negative:missing-responses-case"], []));
	checks.push(markerCheck("provider:endpoint-doctor-runtime", "scripts/reverse-agent/provider-endpoint-doctor-gate.mjs", ["repi-provider-endpoint-doctor-gate", "ProviderEndpointDoctorV1", "runtime:provider-endpoint-doctor-live", "openai-completions", "openai-responses", "anthropic-messages", "endpoint_not_found", "negative:provider-endpoint-doctor-report"], []));
	checks.push(markerCheck("toolchain:domain-capability-hard-eval", "scripts/reverse-agent/toolchain-domain-capability-gate.mjs", ["ToolchainDomainCapabilityV1", "runtime:toolchain-doctor", "domain:web-api", "domain:web-scan", "domain:frontend-js", "domain:rev-native", "domain:pwn", "domain:mobile", "domain:mobile-ios", "domain:pcap-dfir", "domain:memory-forensics", "domain:firmware-iot", "domain:crypto", "domain:cloud-identity", "domain:exploit-reliability", "fallback_available", "negative:toolchain-domain-report"], []));
	checks.push(markerCheck("toolchain:domain-proof-exit-closure-hard-eval", "scripts/reverse-agent/domain-proof-exit-closure-gate.mjs", ["DomainProofExitClosureV1", "runtime:domain-proof-exit-blocks-empty-pwn", "domain_proof_exit_missing", "negative:domain-proof-exit-closure"], []));
	checks.push(markerCheck("toolchain:domain-proof-exit-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["DomainProofExitClosureV1", "buildDomainProofExitClosure", "domain_proof_exit_closure", "domain_proof_exit_missing", "re_domain_proof_exit"], []));
	checks.push(markerCheck("toolchain:relane-specialist-command-pack-hard-eval", "scripts/reverse-agent/relane-specialist-command-pack-gate.mjs", ["ReLaneSpecialistCommandPackGateV1", "runtime:re_lane-specialist-command-pack", "relane_specialist_command_pack_gate", "route_to_domain_lane_seed_matrix", "specialist_evidence_analyzer_anchor_matrix", "self_heal_command_fallback_matrix", "proof_exit_bridge_matrix", "negative:specialist-command-pack"], []));
	checks.push(markerCheck("toolchain:relane-specialist-command-pack-schema", "schemas/reverse-agent/relane-specialist-command-pack.schema.json", ["ReLaneSpecialistCommandPackGateV1", "route_to_domain_lane_seed_matrix", "self_heal_command_fallback_matrix", "proof_exit_bridge_matrix"], []));
	checks.push(markerCheck("toolchain:relane-specialist-command-pack-fixture", "fixtures/reverse-agent/relane-specialist-command-pack.fixture.json", ["ReLaneSpecialistCommandPackGateV1", "missing-route-matchers", "missing-command-pack-markers", "runtime-tool-not-registered"], []));
	checks.push(markerCheck("toolchain:pwn-advanced-capability-hard-eval", "scripts/reverse-agent/pwn-advanced-capability-gate.mjs", ["PwnAdvancedCapabilityGateV1", "runtime:pwn-advanced-capability", "pwn_advanced_capability_gate", "pwn_advanced_command_pack_matrix", "pwn_advanced_evidence_anchor_matrix", "pwn_advanced_followup_self_heal_matrix", "pwn_advanced_toolchain_proof_exit_matrix", "negative:pwn-advanced-capability"], []));
	checks.push(markerCheck("toolchain:pwn-advanced-capability-schema", "schemas/reverse-agent/pwn-advanced-capability.schema.json", ["PwnAdvancedCapabilityGateV1", "pwn_advanced_capability_gate", "pwn_advanced_toolchain_proof_exit_matrix"], []));
	checks.push(markerCheck("toolchain:pwn-advanced-capability-fixture", "fixtures/reverse-agent/pwn-advanced-capability.fixture.json", ["PwnAdvancedCapabilityGateV1", "missing-advanced-command-pack", "missing-toolchain-proof-exits"], []));
	checks.push(markerCheck("toolchain:professional-runtime-bridges-hard-eval", "scripts/reverse-agent/professional-runtime-bridges-gate.mjs", ["ProfessionalRuntimeBridgesGateV1", "runtime:professional-runtime-bridges", "professional_runtime_bridge_gate", "runtime_execution_bridge_matrix", "real_toolchain_bridge_contract", "exploit_verifier_runtime_contract", "web_cdp_replay_contract", "mobile_frida_dynamic_bridge_contract", "negative:professional-runtime-bridges"], []));
	checks.push(markerCheck("toolchain:professional-runtime-bridges-schema", "schemas/reverse-agent/professional-runtime-bridges.schema.json", ["ProfessionalRuntimeBridgesGateV1", "professional_runtime_bridge_gate", "web_cdp_replay_contract", "mobile_frida_dynamic_bridge_contract"], []));
	checks.push(markerCheck("toolchain:professional-runtime-bridges-fixture", "fixtures/reverse-agent/professional-runtime-bridges.fixture.json", ["ProfessionalRuntimeBridgesGateV1", "tool-bridge-runtime", "exploit-verifier-runtime", "web-cdp-replay", "mobile-frida", "narrative-only-bridge"], []));
	checks.push(markerCheck("toolchain:runtime-adapter-execution-hard-eval", "scripts/reverse-agent/runtime-adapter-execution-gate.mjs", ["RuntimeAdapterExecutionGateV1", "runtime:adapter-execution", "runtime_adapter_execution_gate", "adapter_runner_parser_ingest_contract", "r2_ghidra_native_adapter_contract", "frida_mobile_adapter_contract", "web_cdp_adapter_contract", "pwntools_exploit_verifier_adapter_contract", "negative:runtime-adapter-execution"], []));
	checks.push(markerCheck("toolchain:runtime-adapter-execution-schema", "schemas/reverse-agent/runtime-adapter-execution.schema.json", ["RuntimeAdapterExecutionGateV1", "runtime_adapter_execution_gate", "adapter_runner_parser_ingest_contract", "r2_ghidra_native_adapter_contract", "frida_mobile_adapter_contract", "web_cdp_adapter_contract"], []));
	checks.push(markerCheck("toolchain:runtime-adapter-execution-fixture", "fixtures/reverse-agent/runtime-adapter-execution.fixture.json", ["RuntimeAdapterExecutionGateV1", "r2-native-xref-adapter", "ghidra-headless-summary-adapter", "frida-mobile-hook-adapter", "web-cdp-network-adapter", "pwntools-local-verifier-adapter"], []));
	checks.push(markerCheck("provider:failure-injection-hard-eval", "scripts/reverse-agent/provider-failure-injection-gate.mjs", ["repi-provider-failure-injection-gate", "ProviderFailureInjectionReportV1", "runtime:provider-failure-http-500", "runtime:provider-failure-repair-ledger", "negative:provider-failure-exhausted-unpaused-rerun"], []));
	checks.push(markerCheck("repair:rollback-policy-core-contract", "packages/coding-agent/src/core/recon-profile.ts", ["type RepairRollbackPolicyV1", "function verifyRepairRollbackPolicyV1", "function buildRepairRollbackPolicyFromAutofix", "function writeAutofixRepairRollbackPolicy", "repairRollbackPolicyPath", "runtime:repair-rollback-live-wiring", "repair_rollback_tree_hash_mismatch"], []));
	checks.push(markerCheck("repair:rollback-policy-hard-eval", "scripts/reverse-agent/repair-rollback-policy-gate.mjs", ["repi-repair-rollback-policy-gate", "RepairRollbackPolicyV1", "runtime:repair-baseline-snapshot", "runtime:repair-allowlist-enforced", "runtime:repair-rollback-restored", "runtime:repair-rollback-live-wiring", "runtime:repair-rollback-live-probe-exit", "negative:repair-rollback-not-restored"], []));
	checks.push(markerCheck("repair:rollback-policy-live-wiring", "packages/coding-agent/src/core/recon-profile.ts", ["repairRollbackPolicyPath", "repairRollbackPolicyStatus", "buildRepairRollbackPolicyFromAutofix", "writeAutofixRepairRollbackPolicy", "runtime:repair-rollback-live-wiring"], []));
	checks.push(markerCheck("repair:rollback-policy-schema", "schemas/reverse-agent/repair-rollback-policy.schema.json", ["RepairRollbackPolicyV1", "baseline_required_before_repair", "allowlist_violation_blocks_repair", "rollback_tree_hash_must_match_baseline"], []));
	checks.push(markerCheck("repair:rollback-policy-fixture", "fixtures/reverse-agent/repair-rollback-policy.fixture.json", ["repi-repair-rollback-policy-fixture", "negative:repair-allowlist-violation", "negative:repair-rollback-not-restored", "negative:repair-missing-regression-gate"], []));
	checks.push(markerCheck("repair:worker-provider-rollback-unification-hard-eval", "scripts/reverse-agent/worker-provider-repair-rollback-unification-gate.mjs", ["repi-worker-provider-repair-rollback-unification-gate", "WorkerProviderRepairRollbackUnificationGateV1", "runtime:provider-worker-state-change-rollback-policy", "runtime:provider-worker-live-state-change-repair-matrix", "runtime:multi-attempt-retry-window-completion-chain", "runtime:provider-worker-state-lineage-snapshot-matrix", "runtime:compound-provider-long-horizon-repair-completion-chain", "runtime:remote-provider-state-changing-repair-matrix", "runtime:deep-compound-provider-repair-completion-chain", "runtime:exhausted-blocks-unpaused-rerun", "fixture:negative-rejections"], []));
	checks.push(markerCheck("repair:worker-provider-rollback-unification-schema", "schemas/reverse-agent/worker-provider-repair-rollback-unification.schema.json", ["WorkerProviderRepairRollbackUnificationGateV1", "provider_worker_state_change_writes_rollback_policy", "provider_worker_live_state_change_repair_matrix", "multi_attempt_retry_window_completion_chain", "provider_worker_state_lineage_snapshot_matrix", "compound_provider_long_horizon_repair_completion_chain", "remote_provider_state_changing_repair_matrix", "deep_compound_provider_repair_completion_chain", "ProviderWorkerLiveRepairMatrixV1", "MultiAttemptRetryWindowCompletionChainV1", "ProviderWorkerStateLineageSnapshotMatrixV1", "CompoundProviderLongHorizonRepairCompletionChainV1", "RemoteProviderStateChangingRepairMatrixV1", "DeepCompoundProviderRepairCompletionChainV1", "exhausted_failure_blocks_unpaused_rerun", "regression_gate_refs_match_repair_queue"], []));
	checks.push(markerCheck("repair:worker-provider-rollback-unification-fixture", "fixtures/reverse-agent/worker-provider-repair-rollback-unification.fixture.json", ["repi-worker-provider-repair-rollback-unification-fixture", "signature-mismatch", "exhausted-unpaused-rerun", "policy-failure-repair-unlinked", "state-lineage-missing-baseline", "long-horizon-signature-drift", "remote-state-repair-matrix-too-narrow", "deep-compound-chain-too-short", "remote-state-repair-secret-leak"], []));
	checks.push(markerCheck("runtime:tool-call-trace-ledger-core", "packages/coding-agent/src/core/recon-profile.ts", ["type ToolCallTraceEventV1", "type ToolCallTraceLedgerV1", "function appendToolCallTraceFromCall", "function verifyToolCallTraceLedgerV1", "tool_call_observability_runtime"], []));
	checks.push(markerCheck("runtime:tool-call-trace-ledger", "scripts/reverse-agent/tool-call-trace-ledger-gate.mjs", ["repi-tool-call-trace-ledger-gate", "ToolCallTraceLedgerV1", "runtime:tool-call-trace-ledger-written", "runtime:tool-call-trace-secret-redaction", "negative:tool-trace-hash-drift"], []));
	checks.push(markerCheck("runtime:tool-call-trace-ledger-schema", "schemas/reverse-agent/tool-call-trace-ledger.schema.json", ["ToolCallTraceLedgerV1", "append_only_tool_trace", "secret_redaction_required", "replayable_tool_result_hashes"], []));
	checks.push(markerCheck("runtime:tool-call-trace-ledger-fixture", "fixtures/reverse-agent/tool-call-trace-ledger.fixture.json", ["repi-tool-call-trace-ledger-fixture", "negative:tool-trace-secret-leak", "negative:tool-trace-missing-replay"], []));
	checks.push(markerCheck("parallel:provider-worker-matrix-hard-eval", "scripts/reverse-agent/parallel-provider-worker-matrix-gate.mjs", ["repi-parallel-provider-worker-matrix-gate", "ParallelProviderWorkerMatrixV1", "runtime:parallel-provider-worker-concurrency", "runtime:parallel-provider-worker-timeout-cancel", "negative:parallel-worker-missing-claim-merge"], []));
	checks.push(markerCheck("provider:remote-longrun-optional-live", "scripts/reverse-agent/remote-provider-longrun-gate.mjs", ["repi-remote-provider-longrun-gate", "RemoteProviderLongRunV1", "openai-responses", "contract:remote-provider-longrun-api-coverage", "runtime:remote-provider-longrun-skipped", "runtime:remote-provider-longrun-attempts", "negative:remote-provider-live-missing-marker"], []));
	checks.push(markerCheck("provider:provider-backed-dogfood-optional-live", "scripts/reverse-agent/provider-backed-dogfood-gate.mjs", ["ProviderBackedDogfoodReleaseGateV1", "runtime:provider-backed-dogfood-skipped", "validateProviderBackedDogfood", "negative:dogfood-plan-only-promoted", "negative:dogfood-missing-model-calls"], []));
	checks.push(markerCheck("provider:provider-backed-dogfood-schema", "schemas/reverse-agent/provider-backed-dogfood.schema.json", ["ProviderBackedDogfoodReleaseGateV1", "planOnlyNotPromoted", "providerBacked", "multiWorker", "runtimeClaimLedgerCaptured"], []));
	checks.push(markerCheck("provider:provider-backed-dogfood-fixture", "fixtures/reverse-agent/provider-backed-dogfood.fixture.json", ["repi-provider-backed-dogfood-fixture", "negative:dogfood-plan-only-promoted", "negative:dogfood-missing-model-calls", "negative:dogfood-nonmock-false"], []));
	checks.push(markerCheck("claims:runtime-claim-ledger-live-re-swarm", "scripts/reverse-agent/gate-runtime-claim-ledger.mjs", ["runAgentDogfoodLiveProbe", "--write-plan-ledger", "loadedNativeRuntimeProbe", "runReSwarmLiveProbe", "runtime:re-swarm-claim-ledger-live-probe-exit", "reSwarmLiveProbeProvidesDefaultCoverage", "runCompoundFrontierLiveProbe", "runtimeLedgerQuality", "--no-live-re-swarm"], []));
	checks.push(markerCheck("claims:runtime-ledger-quality", "scripts/reverse-agent/runtime-ledger-quality-gate.mjs", ["RuntimeLedgerQualityGateV1", "validateSourceQuality", "runtimeLedgerQuality", "artifactDigests", "strictValidator", "negative:runtime-ledger-missing-event-type-count"], []));
	checks.push(markerCheck("claims:runtime-ledger-quality-schema", "schemas/reverse-agent/runtime-ledger-quality.schema.json", ["RuntimeLedgerQualityGateV1", "requireArtifactSha256", "requireStrictValidator", "eventTypeCounts", "artifactDigests"], []));
	checks.push(markerCheck("claims:runtime-ledger-quality-fixture", "fixtures/reverse-agent/runtime-ledger-quality.fixture.json", ["repi-runtime-ledger-quality-fixture", "negative:runtime-ledger-missing-event-type-count", "negative:runtime-ledger-strict-validator-failed"], []));
	checks.push(markerCheck("claims:structured-claim-merge-hard-eval", "scripts/reverse-agent/structured-claim-merge-gate.mjs", ["repi-structured-claim-merge-gate", "runtime:structured-claim-live-wiring", "runtime:re-swarm-structured-merge-exit", "runtime_conflict_loser_downgrade_missing", "runtime_loser_promoted", "final_pass_requires_json_query", "unresolved_adversary_challenge", "missing_winning_evidence"], []));
	checks.push(markerCheck("claims:structured-claim-merge-schema", "schemas/reverse-agent/structured-claim-merge.schema.json", ["StructuredClaimMergeV1", "strict_final_claim_promotion", "final_pass_requires_json_query", "unresolved_adversary_challenge_blocks_final"], []));
	checks.push(markerCheck("claims:structured-claim-merge-fixture", "fixtures/reverse-agent/structured-claim-merge.fixture.json", ["repi-structured-claim-merge-fixture", "StructuredClaimMergeV1", "final_pass_requires_json_query"], []));
	checks.push(markerCheck("claims:structured-claim-live-wiring", "packages/coding-agent/src/core/recon-profile.ts", ["function buildStructuredClaimMergeFromSwarm", "function resolveStructuredClaimConflict", "function structuredClaimConflictScore", "structured_conflict_arbitration_live_wiring", "function structuredClaimMergeGateFromSwarm", "structuredClaimMergeStatus", "status=blocked_by_structured_claim_merge", "structured claim merge blocks final claim"], []));
	checks.push(markerCheck("claims:live-conflict-arbitration-matrix-hard-eval", "scripts/reverse-agent/live-conflict-arbitration-matrix-gate.mjs", ["repi-live-conflict-arbitration-matrix-gate", "LiveConflictArbitrationMatrixGateV1", "runtime:source-coverage-all-runtimes", "runtime:provider-backed-same-window-conflict-table", "runtime:provider-backed-long-window-conflict-matrix", "runtime:long-run-synthesizer-topic-parse-matrix", "runtime:extended-synthesizer-topic-parse-matrix", "runtime:orchestration-platform-split", "fixture:negative-rejections"], []));
	checks.push(markerCheck("claims:live-conflict-arbitration-matrix-schema", "schemas/reverse-agent/live-conflict-arbitration-matrix.schema.json", ["LiveConflictArbitrationMatrixGateV1", "source_coverage_all_runtimes", "winner_evidence_json_query_verifier", "provider_backed_same_window_multi_worker_conflict_table", "provider_backed_long_window_conflict_matrix", "long_run_synthesizer_topic_parse_matrix", "synthesizer_extended_topic_parse_matrix", "orchestration_success_separate_from_platform_claim"], []));
	checks.push(markerCheck("claims:live-conflict-arbitration-matrix-fixture", "fixtures/reverse-agent/live-conflict-arbitration-matrix.fixture.json", ["repi-live-conflict-arbitration-matrix-fixture", "missing-winner-evidence", "loser-promoted", "provider-backed-conflict-single-worker", "synthesizer-topic-parse-missing", "long-window-conflict-too-short", "extended-topic-parse-missing", "provider-window-secret-leak", "orchestration-implies-platform-pass"], []));
	checks.push(markerCheck("compact:resume-chain-hard-eval", "scripts/reverse-agent/compact-resume-chain-gate.mjs", ["repi-compact-resume-chain-gate", "verifyContextPack", "verifyLedger", "verifyTransitions", "verifyTelemetry", "invalid_resume_transition"], []));
	checks.push(markerCheck("compact:resume-chain-fixture", "fixtures/reverse-agent/compact-resume-chain.fixture.json", ["repi-compact-resume-chain-fixture", "resumeTransitions", "autoResumeTelemetry", "negativeCases", "compact_resume_success_skip_low_value_lane", "memory_store_report", "memory_injection_packet"], []));
	checks.push(markerCheck("compact:resume-ledger-v2-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["CompactResumeLedgerV2", "appendCompactResumeTransition", "buildCompactResumeLedgerV2Report", "formatCompactResumeLedgerV2", "append_only_transition_ledger", "idempotent_multi_compact_replay", "auto_resume_budget_enforced", "compact_resume_transition_report_in_context_pack"], []));
	checks.push(markerCheck("compact:resume-ledger-v2-profile", "repi-profile/extensions/reverse-pentest-core.ts", ["CompactResumeLedgerV2", "appendCompactResumeTransition", "buildCompactResumeLedgerV2Report", "formatCompactResumeLedgerV2", "append_only_transition_ledger", "idempotent_multi_compact_replay", "auto_resume_budget_enforced"], []));
	checks.push(markerCheck("compact:resume-ledger-v2-hard-eval", "scripts/reverse-agent/compact-resume-ledger-v2-gate.mjs", ["repi-compact-resume-ledger-v2-gate", "runtime:queued-running-done", "runtime:idempotent-multi-compact-replay", "runtime:auto-resume-budget", "runtime:context-pack-embeds-v2"], []));
	checks.push(markerCheck("compact:resume-ledger-v2-schema", "schemas/reverse-agent/compact-resume-ledger-v2.schema.json", ["CompactResumeLedgerV2", "CompactResumeLedgerTransitionV2", "append_only_transition_ledger", "idempotent_multi_compact_replay", "auto_resume_budget_enforced"], []));
	checks.push(markerCheck("compact:resume-ledger-v2-fixture", "fixtures/reverse-agent/compact-resume-ledger-v2.fixture.json", ["repi-compact-resume-ledger-v2-fixture", "validScenarios", "invalid-done-reopen", "duplicate-idempotent-replay", "budget-exhausted"], []));
	checks.push(markerCheck("compact:multi-compact-pressure-hard-eval", "scripts/reverse-agent/multi-compact-pressure-gate.mjs", ["repi-multi-compact-pressure-gate", "MultiCompactPressureGateV1", "runtime:multi-cycle-append-only", "runtime:old-context-path-beats-latest", "runtime:operator-proof-writeback", "negative:artifact-drift"], []));
	checks.push(markerCheck("compact:multi-compact-pressure-schema", "schemas/reverse-agent/multi-compact-pressure.schema.json", ["MultiCompactPressureGateV1", "MultiCompactPressureRuntimeCycleV1", "MultiCompactPressureNegativeCaseV1", "operatorProofWriteback"], []));
	checks.push(markerCheck("compact:multi-compact-pressure-fixture", "fixtures/reverse-agent/multi-compact-pressure.fixture.json", ["repi-multi-compact-pressure-fixture", "two-independent-compact-cycles", "old-context-path-beats-latest", "operator-proof-loop-writeback", "budget-exhausted"], []));
	checks.push(markerCheck("compact:cross-session-resume-live", "scripts/reverse-agent/cross-session-resume-live-gate.mjs", ["repi-cross-session-resume-live-gate", "CrossSessionResumeLiveV1", "runtime:cross-session-provider-continuation", "runtime:cross-session-ledger-done", "negative:cross-session-latest-fallback"], []));
	checks.push(markerCheck("compact:cross-session-multi-compact-matrix-hard-eval", "scripts/reverse-agent/cross-session-multi-compact-matrix-gate.mjs", ["repi-cross-session-multi-compact-matrix-gate", "CrossSessionMultiCompactMatrixGateV1", "runtime:old-context-path-over-latest-after-multiple-compacts", "runtime:provider-continuation-after-exact-resume", "runtime:provider-continuation-matrix-multi-provider", "runtime:five-cycle-cross-session-compaction-chain", "runtime:remote-provider-continuation-sample-matrix", "runtime:longer-cross-session-compaction-chain", "runtime:compact-resume-ledger-cycle-terminal-alignment", "ledger-terminal-missing-after-rehash", "fixture:negative-rejections"], []));
	checks.push(markerCheck("compact:cross-session-multi-compact-matrix-schema", "schemas/reverse-agent/cross-session-multi-compact-matrix.schema.json", ["CrossSessionMultiCompactMatrixGateV1", "cross_session_multi_compact_same_run", "provider_continuation_after_exact_resume", "provider_continuation_matrix_multi_provider", "longer_cross_session_compaction_chain", "five_cycle_cross_session_compaction_chain", "remote_provider_continuation_sample_matrix", "ProviderContinuationMatrixV1", "RemoteProviderContinuationSampleMatrixV1", "terminal_resume_rows_not_reopened", "compact_resume_ledger_cycle_terminal_alignment", "CompactResumeLedgerCycleTerminalAlignmentV1"], []));
	checks.push(markerCheck("compact:cross-session-multi-compact-matrix-fixture", "fixtures/reverse-agent/cross-session-multi-compact-matrix.fixture.json", ["repi-cross-session-multi-compact-matrix-fixture", "latest-fallback-without-explicit-context", "provider-continuation-missing", "terminal-row-reopened", "five-cycle-chain-too-short", "remote-provider-secret-leak"], []));
	checks.push(markerCheck("compact:runtime-schema-hard-eval", "scripts/reverse-agent/context-runtime-schema-gate.mjs", ["repi-context-runtime-schema-gate", "runtime:pack-schema", "runtime:resume-schema", "runtime:memory-hash-contract", "ContextPackV2", "ResumeContractV2"], []));
	checks.push(markerCheck("ci:repi-harness-template", "docs/reverse-agent/repi-harness.github-actions.yml", ["REPI Independent Harness", "npm ci --ignore-scripts", "npm run gate:repi-harness", "npm run check", "git diff --exit-code"], []));
	checks.push(markerCheck("docs:independent-entry", "README.md", ["REPI Agent 是面向逆向工程", "基于 Pi Coding Agent 底层深度改造", "~/.repi/agent", "npm run install:repi", "npm run gate:repi-harness"], ["npm run install:recon-pi\n", "npm run gate:pi-recon-primary\n"]));
	checks.push(markerCheck("runtime:repi-storage-path-language", "repi-profile/SYSTEM.md", ["REPI", "~/.repi/agent/recon/evidence", "~/.repi/agent/recon/memory", "~/.repi/agent/recon/mission"], [/\.pi\/(?:evidence|memory|mission|reports)/]));
	checks.push(markerCheck("runtime:repi-built-in-storage-language", "packages/coding-agent/src/core/recon-profile.ts", ["REPI harness", "~/.repi/agent/models.json", "model_provider_configuration_runtime"], [/Pi harness/, /\.pi\/(?:evidence|memory|mission|reports)/]));
	checks.push(...packageIdentityChecks());
	return checks;
}

function forbiddenRuntimePatterns() {
	return [
		/update \[source\|self\|pi\]/i,
		/Update pi/i,
		/\bpi update/i,
		/Update Available/i,
		/Package Updates Available/i,
		/pi\.dev\/changelog/i,
		/default:\s*https:\/\/pi\.dev\/session/i,
		/No models match pattern/i,
		/No API key found/i,
		/collision:/i,
		/Global tools\/ directory contains custom tools/i,
	];
}

function runtimeInstallProbe() {
	const home = join(tempRoot, "home");
	const installBin = join(tempRoot, "bin");
	const npmPrefix = join(tempRoot, "npm-prefix");
	const fakePiAgent = join(home, ".pi", "agent");
	const cleanerHome = join(tempRoot, "cleaner-home");
	mkdir(installBin);
	mkdir(join(home, ".local", "bin"));
	mkdir(join(npmPrefix, "bin"));
	mkdir(cleanerHome);
	const cleanerNoAgent = run("bash", ["scripts/reverse-agent/clean-global-repi-profile.sh"], { env: { HOME: cleanerHome } });
	const cleanerCreatedPiAgent = existsSync(join(cleanerHome, ".pi", "agent"));

	const cleanerProbeHome = join(tempRoot, "cleaner-probe-home");
	const cleanerProbeAgent = join(cleanerProbeHome, ".pi", "agent");
	mkdir(join(cleanerProbeAgent, "extensions"));
	mkdir(join(cleanerProbeAgent, "prompts"));
	mkdir(join(cleanerProbeAgent, "tools"));
	writeFileSync(join(cleanerProbeAgent, "settings.json"), JSON.stringify({ extensions: ["extensions/reverse-pentest-core.ts", "user-extension.ts"], prompts: ["prompts"], enabledModels: ["stale-openai/vendor/private-model"] }, null, 2));
	writeFileSync(join(cleanerProbeAgent, "extensions", "reverse-pentest-core.ts"), "// REPI reverse-pentest legacy extension\nexport default {};\n", "utf8");
	writeFileSync(join(cleanerProbeAgent, "prompts", "websec.md"), "REPI reverse-pentest legacy prompt\n", "utf8");
	writeFileSync(join(cleanerProbeAgent, "prompts", "personal.md"), "normal pi user prompt\n", "utf8");
	writeFileSync(join(cleanerProbeAgent, "tools", "tool-index.md"), "# REPI Tool Index\n", "utf8");
	const cleanerBeforeDryHash = treeHash(cleanerProbeAgent);
	const cleanerDry = run("bash", ["scripts/reverse-agent/clean-global-repi-profile.sh"], { env: { HOME: cleanerProbeHome } });
	const cleanerAfterDryHash = treeHash(cleanerProbeAgent);
	const cleanerDryBackups = readdirSync(cleanerProbeAgent).filter((name) => name.startsWith("repi-legacy-backup."));
	const cleanerApply = run("bash", ["scripts/reverse-agent/clean-global-repi-profile.sh", "--apply"], { env: { HOME: cleanerProbeHome } });
	const cleanerBackupsAfterApply = readdirSync(cleanerProbeAgent).filter((name) => name.startsWith("repi-legacy-backup.")).sort();
	const cleanerBackupAfterApply = cleanerBackupsAfterApply.length ? join(cleanerProbeAgent, cleanerBackupsAfterApply[cleanerBackupsAfterApply.length - 1]) : "";
	const cleanerSettingsAfterApply = existsSync(join(cleanerProbeAgent, "settings.json")) ? JSON.parse(readFileSync(join(cleanerProbeAgent, "settings.json"), "utf8")) : {};
	const cleanerApplyMarkerOnly =
		cleanerApply.code === 0 &&
		existsSync(join(cleanerBackupAfterApply, "extensions", "reverse-pentest-core.ts")) &&
		existsSync(join(cleanerBackupAfterApply, "prompts", "websec.md")) &&
		existsSync(join(cleanerProbeAgent, "prompts", "personal.md")) &&
		!existsSync(join(cleanerBackupAfterApply, "prompts", "personal.md")) &&
		!JSON.stringify(cleanerSettingsAfterApply).includes("reverse-pentest-core") &&
		JSON.stringify(cleanerSettingsAfterApply).includes("user-extension.ts");
	const cleanerToolsStillOriginal = existsSync(join(cleanerProbeAgent, "tools", "tool-index.md")) && !existsSync(join(cleanerBackupAfterApply, "tools", "tool-index.md"));
	const cleanerForceTools = run("bash", ["scripts/reverse-agent/clean-global-repi-profile.sh", "--apply", "--force-tools"], { env: { HOME: cleanerProbeHome } });
	const cleanerBackupsAfterForce = readdirSync(cleanerProbeAgent).filter((name) => name.startsWith("repi-legacy-backup.")).sort();
	const cleanerToolsMovedWithForce = cleanerBackupsAfterForce.some((name) => existsSync(join(cleanerProbeAgent, name, "tools", "tool-index.md"))) && !existsSync(join(cleanerProbeAgent, "tools", "tool-index.md"));

	const legacyGlobalHome = join(tempRoot, "legacy-global-home");
	const legacyGlobalBin = join(tempRoot, "legacy-global-bin");
	mkdir(legacyGlobalHome);
	mkdir(legacyGlobalBin);
	const legacyGlobalInstall = run("bash", ["scripts/reverse-agent/install-global-profile.sh", root, legacyGlobalBin], { env: { HOME: legacyGlobalHome, PATH: `${legacyGlobalBin}:${process.env.PATH}`, PI_OFFLINE: "1", PI_SKIP_VERSION_CHECK: "1", PI_SKIP_PACKAGE_UPDATE_CHECK: "1", PI_TELEMETRY: "0" } });
	const legacyGlobalAgent = join(legacyGlobalHome, ".repi", "agent");
	const legacyGlobalForbiddenFileProfile = [
		join(legacyGlobalAgent, "SYSTEM.md"),
		join(legacyGlobalAgent, "APPEND_SYSTEM.md"),
		join(legacyGlobalAgent, "extensions", "reverse-pentest-core.ts"),
		join(legacyGlobalAgent, "skills", "reverse-pentest-orchestrator", "SKILL.md"),
		join(legacyGlobalAgent, "prompts", "websec.md"),
		join(legacyGlobalAgent, "node_modules"),
		join(legacyGlobalAgent, "vendor", "reverse-skill"),
	].filter((path) => existsSync(path));
	const legacyGlobalProfilePath = join(legacyGlobalAgent, "recon", "profile.json");
	const legacyGlobalProfile = existsSync(legacyGlobalProfilePath) ? JSON.parse(readFileSync(legacyGlobalProfilePath, "utf8")) : null;
	mkdir(fakePiAgent);

	const fakePi = join(installBin, "pi");
	writeFileSync(fakePi, "#!/usr/bin/env bash\necho UPSTREAM_PI_STUB \"$@\"\n", "utf8");
	spawnSync("chmod", ["755", fakePi]);
	try {
		symlinkSync(join(root, "pi"), join(home, ".local", "bin", "pi"));
	} catch {}
	try {
		symlinkSync(join(root, "pi"), join(npmPrefix, "bin", "pi"));
	} catch {}

	writeFileSync(join(fakePiAgent, "settings.json"), JSON.stringify({ enabledModels: ["stale-anthropic/vendor/private-model"], extensions: ["extensions/reverse-pentest-core.ts"] }, null, 2));
	mkdir(join(fakePiAgent, "extensions"));
	writeFileSync(join(fakePiAgent, "extensions", "reverse-pentest-core.ts"), "export default {};\n");
	writeFileSync(join(fakePiAgent, "auth.json"), JSON.stringify({ fake: { apiKey: "do-not-copy-by-default" } }, null, 2));
	writeFileSync(join(fakePiAgent, "models.json"), JSON.stringify({ models: [{ provider: "fake", id: "fake-model" }] }, null, 2));
	const beforePiHash = treeHash(fakePiAgent);

	const env = {
		HOME: home,
		PATH: `${installBin}:${process.env.PATH}`,
		npm_config_prefix: npmPrefix,
		PI_OFFLINE: "1",
		PI_SKIP_VERSION_CHECK: "1",
		PI_SKIP_PACKAGE_UPDATE_CHECK: "1",
		PI_TELEMETRY: "0",
	};
	const install = run("bash", ["scripts/reverse-agent/install-repi.sh", root, installBin], { env });
	const repiPath = join(installBin, "repi");
	const piProbe = run(fakePi, ["--version"], { env });
	const help = run(repiPath, ["--offline", "--help"], { env });
	const updateHelp = run(repiPath, ["update", "--help"], { env });
	const updatePi = run(repiPath, ["update", "pi"], { env });
	const listModels = run(repiPath, ["--offline", "--list-models"], { env });
	const trustProject = join(tempRoot, "trust-project");
	const trustSubdir = join(trustProject, "subdir");
	mkdir(trustSubdir);
	writeFileSync(join(trustProject, "AGENTS.md"), "REPI trust persistence probe\n", "utf8");
	const trustStatusBefore = run(repiPath, ["trust", "status", "--json"], { cwd: trustSubdir, env, maxBuffer: 4 * 1024 * 1024 });
	const trustSave = run(repiPath, ["trust", "yes", "--json"], { cwd: trustSubdir, env, maxBuffer: 4 * 1024 * 1024 });
	const trustStatusSubdirAfter = run(repiPath, ["trust", "status", "--json"], { cwd: trustSubdir, env, maxBuffer: 4 * 1024 * 1024 });
	const trustStatusRootAfter = run(repiPath, ["trust", "status", "--json"], { cwd: trustProject, env, maxBuffer: 4 * 1024 * 1024 });
	const parseTrust = (runResult) => {
		try {
			return JSON.parse(runResult.stdout);
		} catch {
			return null;
		}
	};
	const trustBeforeReport = parseTrust(trustStatusBefore);
	const trustSaveReport = parseTrust(trustSave);
	const trustSubdirAfterReport = parseTrust(trustStatusSubdirAfter);
	const trustRootAfterReport = parseTrust(trustStatusRootAfter);
	const modelsBeforeImport = existsSync(join(home, ".repi", "agent", "models.json"));
	const authBeforeImport = existsSync(join(home, ".repi", "agent", "auth.json"));
	const importRun = run(repiPath, ["--import-pi-auth", "--offline", "--list-models"], { env });
	const profilePath = join(home, ".repi", "agent", "recon", "profile.json");
	const profile = existsSync(profilePath) ? JSON.parse(readFileSync(profilePath, "utf8")) : null;
	const afterPiHash = treeHash(fakePiAgent);

	const packageHome = join(tempRoot, "package-home");
	const packagePiAgent = join(packageHome, ".pi", "agent");
	mkdir(packagePiAgent);
	writeFileSync(join(packagePiAgent, "auth.json"), JSON.stringify({ fake: { apiKey: "package-bin-do-not-copy" } }, null, 2));
	writeFileSync(join(packagePiAgent, "models.json"), JSON.stringify({ models: [{ provider: "fake", id: "package-bin-fake" }] }, null, 2));
	const packageEnv = {
		HOME: packageHome,
		PATH: env.PATH,
		PI_OFFLINE: "1",
		PI_SKIP_VERSION_CHECK: "1",
		PI_SKIP_PACKAGE_UPDATE_CHECK: "1",
		PI_TELEMETRY: "0",
	};
	const packageCliHelp = run(join(root, "node_modules", ".bin", "tsx"), ["--tsconfig", join(root, "tsconfig.json"), join(root, "packages", "coding-agent", "src", "cli.ts"), "--offline", "--help"], {
		env: packageEnv,
	});
	const packageCliHealth = run(join(root, "node_modules", ".bin", "tsx"), ["--tsconfig", join(root, "tsconfig.json"), join(root, "packages", "coding-agent", "src", "cli.ts"), "health", "--json"], {
		env: packageEnv,
		timeout: 30000,
	});
	const packageCliDoctor = run(join(root, "node_modules", ".bin", "tsx"), ["--tsconfig", join(root, "tsconfig.json"), join(root, "packages", "coding-agent", "src", "cli.ts"), "doctor", "--json"], {
		env: packageEnv,
		maxBuffer: 8 * 1024 * 1024,
	});
	const packageCliModelDoctor = run(join(root, "node_modules", ".bin", "tsx"), ["--tsconfig", join(root, "tsconfig.json"), join(root, "packages", "coding-agent", "src", "cli.ts"), "model", "doctor", "--json"], {
		env: packageEnv,
		maxBuffer: 8 * 1024 * 1024,
	});
	const packageCliMemoryDoctor = run(join(root, "node_modules", ".bin", "tsx"), ["--tsconfig", join(root, "tsconfig.json"), join(root, "packages", "coding-agent", "src", "cli.ts"), "memory", "doctor", "--json"], {
		env: packageEnv,
		maxBuffer: 8 * 1024 * 1024,
	});
	const packageCliSwarmPlan = run(join(root, "node_modules", ".bin", "tsx"), ["--tsconfig", join(root, "tsconfig.json"), join(root, "packages", "coding-agent", "src", "cli.ts"), "swarm", "plan", "package-bin-selfcheck", "--workers", "2", "--json"], {
		env: packageEnv,
		maxBuffer: 8 * 1024 * 1024,
	});
	const packageCliMissionPlan = run(join(root, "node_modules", ".bin", "tsx"), ["--tsconfig", join(root, "tsconfig.json"), join(root, "packages", "coding-agent", "src", "cli.ts"), "mission", "plan", "audit JWT API for IDOR", "--target", "https://package-bin.example.invalid", "--json"], {
		env: packageEnv,
		maxBuffer: 8 * 1024 * 1024,
	});
	const packageGuardrailMarkers = [
		"REPI_PRINT_PROGRESS",
		"REPI_PRINT_TIMEOUT_MS",
		"REPI_PRINT_MAX_TURNS",
		"REPI_PRINT_MAX_TOOL_CALLS",
		"REPI_STDIN_READ_TIMEOUT_MS",
		"REPI_BASH_DEFAULT_TIMEOUT_SECONDS",
	];
	const packageMissingGuardrails = packageGuardrailMarkers.filter((marker) => !packageCliHelp.combined.includes(marker));
	const packageProfilePath = join(packageHome, ".repi", "agent", "recon", "profile.json");
	const packageProfile = existsSync(packageProfilePath) ? JSON.parse(readFileSync(packageProfilePath, "utf8")) : null;
	const packageModelsDefaultCopied = existsSync(join(packageHome, ".repi", "agent", "models.json"));
	const packageImport = run(join(root, "node_modules", ".bin", "tsx"), ["--tsconfig", join(root, "tsconfig.json"), join(root, "packages", "coding-agent", "src", "cli.ts"), "--import-pi-auth", "--offline", "--list-models"], {
		env: packageEnv,
	});
	const packageModelsAfterImport = existsSync(join(packageHome, ".repi", "agent", "models.json"));
	const packageAuthAfterImport = existsSync(join(packageHome, ".repi", "agent", "auth.json"));

	const combined = `${install.combined}\n${piProbe.combined}\n${help.combined}\n${updateHelp.combined}\n${listModels.combined}\n${packageCliHelp.combined}\n${packageImport.combined}`;
	const forbidden = forbiddenRuntimePatterns().filter((pattern) => pattern.test(combined));
	const modelsAfterImport = existsSync(join(home, ".repi", "agent", "models.json"));
	const authAfterImport = existsSync(join(home, ".repi", "agent", "auth.json"));

	const checks = [];
	checks.push(resultCheck("runtime:cleaner-no-create-pi-agent", cleanerNoAgent.code === 0 && !cleanerCreatedPiAgent ? "pass" : "fail", { code: cleanerNoAgent.code, stdout: cleanerNoAgent.stdout.trim(), stderr: cleanerNoAgent.stderr.trim(), cleanerCreatedPiAgent }));
	checks.push(resultCheck("runtime:cleaner-default-dry-run-preserves-pi-profile", cleanerDry.code === 0 && cleanerBeforeDryHash === cleanerAfterDryHash && cleanerDry.combined.includes("DRY-RUN") && cleanerDryBackups.length === 0 ? "pass" : "fail", { code: cleanerDry.code, before: cleanerBeforeDryHash, after: cleanerAfterDryHash, backupCount: cleanerDryBackups.length, stdout: cleanerDry.stdout.slice(0, 1200), stderr: cleanerDry.stderr.slice(-1000) }));
	checks.push(resultCheck("runtime:cleaner-apply-marker-only", cleanerApplyMarkerOnly ? "pass" : "fail", { code: cleanerApply.code, backups: cleanerBackupsAfterApply, settings: cleanerSettingsAfterApply, stdout: cleanerApply.stdout.slice(0, 1200), stderr: cleanerApply.stderr.slice(-1000) }));
	checks.push(resultCheck("runtime:cleaner-tools-require-force", cleanerToolsStillOriginal && cleanerForceTools.code === 0 && cleanerToolsMovedWithForce ? "pass" : "fail", { toolsStillAfterApply: cleanerToolsStillOriginal, forceCode: cleanerForceTools.code, movedWithForce: cleanerToolsMovedWithForce, forceStdout: cleanerForceTools.stdout.slice(0, 1200), forceStderr: cleanerForceTools.stderr.slice(-1000) }));
	checks.push(resultCheck("runtime:install-global-profile-deprecated-wrapper", legacyGlobalInstall.code === 0 && legacyGlobalInstall.combined.includes("deprecated") && legacyGlobalProfile?.kind === "isolated-repi-profile" && legacyGlobalForbiddenFileProfile.length === 0 && !existsSync(join(legacyGlobalHome, ".pi")) && existsSync(join(legacyGlobalBin, "repi")) ? "pass" : "fail", { code: legacyGlobalInstall.code, stdout: legacyGlobalInstall.stdout.slice(0, 1600), stderr: legacyGlobalInstall.stderr.slice(-1200), legacyGlobalAgent, legacyGlobalProfileKind: legacyGlobalProfile?.kind ?? null, forbiddenFileProfile: legacyGlobalForbiddenFileProfile.map((path) => relative(legacyGlobalHome, path)), piDirExists: existsSync(join(legacyGlobalHome, ".pi")), repiExists: existsSync(join(legacyGlobalBin, "repi")) }));
	checks.push(resultCheck("runtime:install-repi-code", install.code === 0 ? "pass" : "fail", { code: install.code, stderrTail: install.stderr.slice(-2000) }));
	checks.push(resultCheck("runtime:repi-symlink-created", existsSync(repiPath) ? "pass" : "fail", { repiPath, target: existsSync(repiPath) ? lstatSync(repiPath).isFile() || lstatSync(repiPath).isSymbolicLink() : false }));
	checks.push(resultCheck("runtime:pi-stub-preserved", piProbe.stdout.includes("UPSTREAM_PI_STUB") ? "pass" : "fail", { stdout: piProbe.stdout.trim(), code: piProbe.code }));
	checks.push(resultCheck("runtime:stale-recon-pi-shims-removed", !existsSync(join(home, ".local", "bin", "pi")) && !existsSync(join(npmPrefix, "bin", "pi")) ? "pass" : "fail", { homeLocalPiExists: existsSync(join(home, ".local", "bin", "pi")), npmPiExists: existsSync(join(npmPrefix, "bin", "pi")) }));
	checks.push(resultCheck("runtime:normal-pi-profile-unchanged", beforePiHash === afterPiHash ? "pass" : "fail", { beforePiHash, afterPiHash }));
	checks.push(resultCheck("runtime:repi-help-product", help.code === 0 && help.combined.includes("repi - REPI reverse/pentest autonomous agent") && help.combined.includes("built-in reverse/pentest kernel is enabled") ? "pass" : "fail", { code: help.code, head: help.combined.slice(0, 1200) }));
	checks.push(resultCheck("runtime:repi-update-help-independent", updateHelp.code === 0 && (updateHelp.combined.includes("repi update [source]") || updateHelp.combined.includes("repi update [--fast|--full|--no-pull]")) && !/--self|--force|Update pi|source\|self\|pi/i.test(updateHelp.combined) ? "pass" : "fail", { code: updateHelp.code, text: updateHelp.combined.slice(0, 1200) }));
	checks.push(resultCheck("runtime:repi-update-pi-boundary", updatePi.code !== 0 && updatePi.combined.includes("does not manage upstream pi") && updatePi.combined.includes("repi update only updates REPI packages") && !/No matching package found for pi/i.test(updatePi.combined) ? "pass" : "fail", { code: updatePi.code, text: updatePi.combined.slice(0, 1200) }));
	checks.push(resultCheck("runtime:repi-trust-persistence", trustStatusBefore.code === 0 && trustSave.code === 0 && trustStatusSubdirAfter.code === 0 && trustStatusRootAfter.code === 0 && trustBeforeReport?.effectiveTrusted === false && trustSaveReport?.effectiveTrusted === true && trustSubdirAfterReport?.effectiveTrusted === true && trustRootAfterReport?.effectiveTrusted === true && existsSync(join(home, ".repi", "agent", "trust.json")) ? "pass" : "fail", { before: trustBeforeReport, save: trustSaveReport, subdirAfter: trustSubdirAfterReport, rootAfter: trustRootAfterReport, codes: { before: trustStatusBefore.code, save: trustSave.code, subdirAfter: trustStatusSubdirAfter.code, rootAfter: trustStatusRootAfter.code } }));
	checks.push(resultCheck("runtime:repi-list-models", listModels.code === 0 ? "pass" : "fail", { code: listModels.code, stdout: listModels.stdout.trim().slice(0, 1200), stderrTail: listModels.stderr.slice(-1000) }));
	checks.push(resultCheck("runtime:no-upstream-warning-leak", forbidden.length === 0 ? "pass" : "fail", { forbidden: forbidden.map(String) }));
	checks.push(resultCheck("runtime:profile-in-repi-home", profile?.agentDir === join(home, ".repi", "agent") ? "pass" : "fail", { profilePath, agentDir: profile?.agentDir ?? null }));
	checks.push(resultCheck("runtime:legacy-import-explicit-only", importRun.code === 0 && !modelsBeforeImport && modelsAfterImport && authAfterImport ? "pass" : "fail", { importCode: importRun.code, modelsBeforeImport, authBeforeImport, modelsAfterImport, authAfterImport }));
	checks.push(
		resultCheck(
			"runtime:package-bin-defaults-to-recon",
			packageCliHelp.code === 0 &&
				packageCliHelp.combined.includes("repi - REPI reverse/pentest autonomous agent") &&
				packageCliHelp.combined.includes("built-in reverse/pentest kernel is enabled") &&
				packageMissingGuardrails.length === 0 &&
				packageProfile?.agentDir === join(packageHome, ".repi", "agent") &&
				!packageModelsDefaultCopied
				? "pass"
				: "fail",
			{
				code: packageCliHelp.code,
				head: packageCliHelp.combined.slice(0, 1200),
				missingGuardrails: packageMissingGuardrails,
				packageProfilePath,
				packageAgentDir: packageProfile?.agentDir ?? null,
				packageModelsDefaultCopied,
			},
		),
	);
	checks.push(resultCheck("runtime:package-bin-import-explicit-only", packageImport.code === 0 && packageModelsAfterImport && packageAuthAfterImport ? "pass" : "fail", { importCode: packageImport.code, packageModelsAfterImport, packageAuthAfterImport }));
	checks.push(resultCheck("runtime:package-bin-product-commands", packageCliHealth.code === 0 && packageCliHealth.combined.includes("repi-health-report") && packageCliDoctor.code === 0 && packageCliDoctor.combined.includes("repi-doctor-report") && packageCliModelDoctor.code === 0 && packageCliModelDoctor.combined.includes("repi-model-doctor-report") && packageCliMemoryDoctor.code === 0 && packageCliMemoryDoctor.combined.includes("repi-memory-doctor-report") && packageCliSwarmPlan.code === 0 && packageCliSwarmPlan.combined.includes("SwarmPlannerV1") && packageCliMissionPlan.code === 0 && packageCliMissionPlan.combined.includes("repi-mission-plan") ? "pass" : "fail", {
		doctor: { code: packageCliDoctor.code, tail: packageCliDoctor.combined.slice(-1000) },
		modelDoctor: { code: packageCliModelDoctor.code, tail: packageCliModelDoctor.combined.slice(-1000) },
		memoryDoctor: { code: packageCliMemoryDoctor.code, tail: packageCliMemoryDoctor.combined.slice(-1000) },
		swarmPlan: { code: packageCliSwarmPlan.code, tail: packageCliSwarmPlan.combined.slice(-1000) },
		missionPlan: { code: packageCliMissionPlan.code, tail: packageCliMissionPlan.combined.slice(-1000) },
	}));
	return { checks, tempRoot, installBin, home };
}

function childGateChecks() {
	const gates = [
		["gate:repi-product", ["scripts/reverse-agent/assert-repi-product.mjs", root]],
		["gate:open-source-readiness", ["scripts/reverse-agent/open-source-readiness-gate.mjs", root, "--strict"]],
		["gate:repi-product-surface", ["scripts/reverse-agent/repi-product-surface-audit.mjs", root, "--strict"]],
		["gate:repi-cli-ux", ["scripts/reverse-agent/repi-cli-ux-gate.mjs", root, "--strict"]],
		["gate:repi-isolation", ["scripts/reverse-agent/assert-repi-isolated.mjs", root]],
		["gate:context-compact", ["scripts/reverse-agent/context-compact-audit.mjs", root]],
		["gate:compact-resume-chain", ["scripts/reverse-agent/compact-resume-chain-gate.mjs", root, "--strict"]],
		["gate:compact-resume-ledger-v2", ["scripts/reverse-agent/compact-resume-ledger-v2-gate.mjs", root, "--strict"]],
		// child:gate:multi-compact-pressure
		["gate:multi-compact-pressure", ["scripts/reverse-agent/multi-compact-pressure-gate.mjs", root, "--strict"]],
		["gate:cross-session-resume-live", ["scripts/reverse-agent/cross-session-resume-live-gate.mjs", root, "--strict"]],
		// child:gate:cross-session-multi-compact-matrix
		["gate:cross-session-multi-compact-matrix", ["scripts/reverse-agent/cross-session-multi-compact-matrix-gate.mjs", root, "--strict"]],
		["gate:context-runtime-schema", ["scripts/reverse-agent/context-runtime-schema-gate.mjs", root, "--strict"]],
		["gate:memory-contract", ["scripts/reverse-agent/memory-contract-gate.mjs", root, "--strict"]],
		["gate:memory-utility", ["scripts/reverse-agent/memory-utility-gate.mjs", root, "--strict"]],
		["gate:memory-feedback", ["scripts/reverse-agent/memory-feedback-gate.mjs", root, "--strict"]],
		["gate:memory-feedback-closure", ["scripts/reverse-agent/memory-feedback-closure-gate.mjs", root, "--strict"]],
			["gate:memory-scope-isolation", ["scripts/reverse-agent/memory-scope-isolation-gate.mjs", root, "--strict"]],
			["gate:knowledge-scope-isolation", ["scripts/reverse-agent/knowledge-scope-isolation-gate.mjs", root, "--strict"]],
			["gate:artifact-scope-filter", ["scripts/reverse-agent/artifact-scope-filter-gate.mjs", root, "--strict"]],
			// child:gate:latest-artifact-consumer-scope
			["gate:latest-artifact-consumer-scope", ["scripts/reverse-agent/latest-artifact-consumer-scope-gate.mjs", root, "--strict"]],
			// child:gate:failure-signature-priority
			["gate:failure-signature-priority", ["scripts/reverse-agent/failure-signature-priority-gate.mjs", root, "--strict"]],
			// child:gate:agent-dogfood-failure-signature-binding
			["gate:agent-dogfood-failure-signature-binding", ["scripts/reverse-agent/agent-dogfood-failure-signature-binding-gate.mjs", root, "--strict"]],
			// child:gate:agent-dogfood-structured-claims
			["gate:agent-dogfood-structured-claims", ["scripts/reverse-agent/agent-dogfood-structured-claims-gate.mjs", root, "--strict"]],
			// child:gate:autonomous-hardening-gap-ledger
			["gate:autonomous-hardening-gap-ledger", ["scripts/reverse-agent/autonomous-hardening-gap-ledger-gate.mjs", root, "--strict"]],
			// child:gate:autonomous-closure-readiness
			["gate:autonomous-closure-readiness", ["scripts/reverse-agent/autonomous-closure-readiness-gate.mjs", root, "--strict"]],
			// child:gate:capability-release-bundle
			["gate:capability-release-bundle", ["scripts/reverse-agent/capability-release-bundle-gate.mjs", root, "--strict"]],
			// child:gate:release-ci-pipeline
			["gate:release-ci-pipeline", ["scripts/reverse-agent/release-ci-pipeline-gate.mjs", root, "--strict"]],
			// child:gate:release-evidence-index
			["gate:release-evidence-index", ["scripts/reverse-agent/release-evidence-index-gate.mjs", root, "--strict"]],
			// child:gate:swarm-provider-manifest-parity
			["gate:swarm-provider-manifest-parity", ["scripts/reverse-agent/swarm-provider-manifest-parity-gate.mjs", root, "--strict"]],
			["gate:memory-orchestrator", ["scripts/reverse-agent/memory-orchestrator-gate.mjs", root, "--strict"]],
		["gate:memory-deposition", ["scripts/reverse-agent/memory-deposition-gate.mjs", root, "--strict"]],
		["gate:memory-experience", ["scripts/reverse-agent/memory-experience-gate.mjs", root, "--strict"]],
		["gate:memory-skill-capsule", ["scripts/reverse-agent/memory-skill-capsule-gate.mjs", root, "--strict"]],
		["gate:memory-distill-promotion", ["scripts/reverse-agent/memory-distill-promotion-gate.mjs", root, "--strict"]],
		["gate:memory-quality-ledger", ["scripts/reverse-agent/memory-quality-ledger-gate.mjs", root, "--strict"]],
		["gate:memory-replay-evaluator", ["scripts/reverse-agent/memory-replay-evaluator-gate.mjs", root, "--strict"]],
		["gate:memory-strategy-capsule", ["scripts/reverse-agent/memory-strategy-capsule-gate.mjs", root, "--strict"]],
		["gate:memory-active-kernel", ["scripts/reverse-agent/memory-active-kernel-gate.mjs", root, "--strict"]],
		["gate:memory-maturation-runtime", ["scripts/reverse-agent/memory-maturation-runtime-gate.mjs", root, "--strict"]],
		["gate:memory-ux", ["scripts/reverse-agent/memory-ux-gate.mjs", root, "--strict"]],
		["gate:memory-hybrid", ["scripts/reverse-agent/memory-hybrid-gate.mjs", root, "--strict"]],
		["gate:memory-vector", ["scripts/reverse-agent/memory-vector-gate.mjs", root, "--strict"]],
		["gate:memory-usefulness", ["scripts/reverse-agent/memory-usefulness-gate.mjs", root, "--strict"]],
		["gate:memory-distiller", ["scripts/reverse-agent/memory-distiller-gate.mjs", root, "--strict"]],
		["gate:memory-sedimentation", ["scripts/reverse-agent/memory-sedimentation-gate.mjs", root, "--strict"]],
		["gate:memory-store", ["scripts/reverse-agent/memory-store-gate.mjs", root, "--strict"]],
		["gate:memory-swarm-writeback", ["scripts/reverse-agent/memory-swarm-writeback-gate.mjs", root, "--strict"]],
		["gate:memory-supervisor", ["scripts/reverse-agent/memory-supervisor-gate.mjs", root, "--strict"]],
		["gate:worker-runtime-pool", ["scripts/reverse-agent/worker-runtime-pool-gate.mjs", root, "--strict"]],
		// child:gate:worker-lease-scheduler
		["gate:worker-lease-scheduler", ["scripts/reverse-agent/worker-lease-scheduler-gate.mjs", root, "--strict"]],
		["gate:worker-child-session", ["scripts/reverse-agent/worker-child-session-gate.mjs", root, "--strict"]],
		["gate:provider-runtime-matrix", ["scripts/reverse-agent/provider-runtime-matrix-gate.mjs", root, "--strict"]],
		// child:gate:provider-endpoint-doctor
		["gate:provider-endpoint-doctor", ["scripts/reverse-agent/provider-endpoint-doctor-gate.mjs", root, "--strict"]],
		// child:gate:toolchain-domain-capability
		["gate:toolchain-domain-capability", ["scripts/reverse-agent/toolchain-domain-capability-gate.mjs", root, "--strict"]],
		// child:gate:domain-proof-exit-closure
		["gate:domain-proof-exit-closure", ["scripts/reverse-agent/domain-proof-exit-closure-gate.mjs", root, "--strict"]],
		// child:gate:relane-specialist-command-pack
		["gate:relane-specialist-command-pack", ["scripts/reverse-agent/relane-specialist-command-pack-gate.mjs", root, "--strict"]],
		// child:gate:pwn-advanced-capability
		["gate:pwn-advanced-capability", ["scripts/reverse-agent/pwn-advanced-capability-gate.mjs", root, "--strict"]],
		// child:gate:professional-runtime-bridges
		["gate:professional-runtime-bridges", ["scripts/reverse-agent/professional-runtime-bridges-gate.mjs", root, "--strict"]],
		// child:gate:runtime-adapter-execution
		["gate:runtime-adapter-execution", ["scripts/reverse-agent/runtime-adapter-execution-gate.mjs", root, "--strict"]],
		["gate:provider-failure-injection", ["scripts/reverse-agent/provider-failure-injection-gate.mjs", root, "--strict"]],
		// child:gate:repair-rollback-policy
		["gate:repair-rollback-policy", ["scripts/reverse-agent/repair-rollback-policy-gate.mjs", root, "--strict"]],
		// child:gate:worker-provider-repair-rollback-unification
		["gate:worker-provider-repair-rollback-unification", ["scripts/reverse-agent/worker-provider-repair-rollback-unification-gate.mjs", root, "--strict"]],
		// child:gate:tool-call-trace-ledger
		["gate:tool-call-trace-ledger", ["scripts/reverse-agent/tool-call-trace-ledger-gate.mjs", root, "--strict"]],
		["gate:parallel-provider-worker-matrix", ["scripts/reverse-agent/parallel-provider-worker-matrix-gate.mjs", root, "--strict"]],
		["gate:remote-provider-longrun", ["scripts/reverse-agent/remote-provider-longrun-gate.mjs", root, "--strict"]],
		// child:gate:provider-backed-dogfood
		["gate:provider-backed-dogfood", ["scripts/reverse-agent/provider-backed-dogfood-gate.mjs", root, "--strict"]],
		["gate:structured-claim-merge", ["scripts/reverse-agent/structured-claim-merge-gate.mjs", root, "--strict"]],
		// child:gate:live-conflict-arbitration-matrix
		["gate:live-conflict-arbitration-matrix", ["scripts/reverse-agent/live-conflict-arbitration-matrix-gate.mjs", root, "--strict"]],
		["gate:runtime-claim-ledger", ["scripts/reverse-agent/gate-runtime-claim-ledger.mjs", root, "--strict"]],
		// child:gate:runtime-ledger-quality
		["gate:runtime-ledger-quality", ["scripts/reverse-agent/runtime-ledger-quality-gate.mjs", root, "--strict"]],
		["gate:autonomous-runtime", ["scripts/reverse-agent/autonomous-runtime-contracts.mjs", root, "--strict"]],
		["gate:autonomy-control", ["scripts/reverse-agent/autonomy-control-plane.mjs", root, "--strict"]],
	];
	return gates.map(([id, args]) => {
		const runResult = run(process.execPath, args, { env: { PI_OFFLINE: "1", PI_SKIP_VERSION_CHECK: "1" } });
		return resultCheck(`child:${id}`, runResult.code === 0 ? "pass" : "fail", {
			code: runResult.code,
			stdoutSha256: sha256(runResult.stdout).slice(0, 24),
			stderrSha256: sha256(runResult.stderr).slice(0, 24),
			stdoutTail: runResult.stdout.slice(-2000),
			stderrTail: runResult.stderr.slice(-2000),
		});
	});
}

function summarize(checks) {
	const failed = checks.filter((check) => check.status !== "pass");
	const byPrefix = {};
	for (const check of checks) {
		const prefix = check.id.split(":")[0];
		byPrefix[prefix] ??= { pass: 0, fail: 0 };
		byPrefix[prefix][check.status === "pass" ? "pass" : "fail"]++;
	}
	return {
		ok: failed.length === 0,
		failed: failed.map((check) => check.id),
		byPrefix,
	};
}

function formatMarkdown(result) {
	const lines = [
		"# REPI Top Harness Audit",
		"",
		`generated_at: ${result.generatedAt}`,
		`ok: ${result.ok}`,
		`current_level: ${result.currentLevel}`,
		`independence_verdict: ${result.independenceVerdict}`,
		`ability_verdict: ${result.abilityVerdict}`,
		`temp_root: ${result.tempRoot}`,
		"",
		"## Outcome",
		"",
		result.ok
			? "REPI passes the independent-product harness: install path, command ownership, profile storage, update/branding behavior, and reverse/pentest control-plane gates are all independently verified."
			: `REPI harness failed: ${result.summary.failed.join(", ")}`,
		"",
		"## Checks",
	];
	for (const check of result.checks) lines.push(`- ${check.id}: ${check.status}`);
	lines.push("", "## Child gates");
	for (const check of result.checks.filter((row) => row.id.startsWith("child:"))) lines.push(`- ${check.id}: ${check.status} code=${check.evidence.code}`);
	lines.push("", "## Next hardening");
	for (const item of result.nextHardening) lines.push(`- ${item}`);
	return `${lines.join("\n")}\n`;
}

function main() {
	let result;
	try {
		const staticChecks = staticContractChecks();
		const runtimeProbe = runtimeInstallProbe();
		const childChecks = childGateChecks();
		const checks = [...staticChecks, ...runtimeProbe.checks, ...childChecks];
		const summary = summarize(checks);
		result = {
			kind: "repi-top-harness-audit",
			version: 1,
			generatedAt: new Date().toISOString(),
			root,
			tempRoot,
			ok: summary.ok,
			currentLevel: summary.ok ? "independent professional reverse/pentest organization agent harness" : "independence/capability harness gaps",
			independenceVerdict: checks.filter((row) => ["launcher", "installer", "runtime", "code", "docs", "npm", "ci"].includes(row.id.split(":")[0])).every((row) => row.status === "pass") ? "pass" : "fail",
			abilityVerdict: checks.filter((row) => row.id.startsWith("child:gate:autonomy") || row.id.startsWith("child:gate:autonomous") || row.id.startsWith("child:gate:context")).every((row) => row.status === "pass") ? "pass" : "fail",
			summary,
			checks,
			nextHardening: [
				"Keep repi as the only REPI product command; never reintroduce pi takeover into installers or docs.",
				"Keep ProviderRuntimeMatrixV1, ProviderFailureInjectionReportV1, WorkerProviderChildProcessProbeV1, ParallelProviderWorkerMatrixV1, and RemoteProviderLongRunV1 green; optional live remotes stay opt-in so CI never requires secrets; cross-session resume must keep exact contextPath/provider continuation green.",
				"Keep command ownership, profile isolation, and update/branding checks in release CI before any capability claims.",
			],
		};
		if (json) console.log(JSON.stringify(result, null, 2));
		else process.stdout.write(formatMarkdown(result));
		if (strict && !result.ok) process.exitCode = 1;
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
}

main();
