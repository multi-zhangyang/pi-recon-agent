import { existsSync, mkdirSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { getAgentDir, getPackageDir } from "../../config.ts";
import { REPI_COMMAND_NAMES as RECON_COMMAND_NAMES, REPI_TOOL_NAMES as RECON_TOOL_NAMES } from "./profile.ts";
import { ensureReconStorage } from "./resources.ts";
import {
	builtinPromptFilePath,
	builtinSkillFilePath,
	evidenceProfileCheckDir,
	evidenceRunsDir,
	readTextFile as readText,
	toolIndexPath,
} from "./storage.ts";
import { shellQuote } from "./target.ts";
import { slug } from "./text.ts";

export type ProfileCheckStatus = "pass" | "warn" | "fail";
export type ProfileCheckMode = "quick" | "full" | "install";

export type ProfileCheckRow = {
	id: string;
	status: ProfileCheckStatus;
	evidence: string[];
	next?: string[];
};

export type ProfileCheckArtifact = {
	timestamp: string;
	mode: ProfileCheckMode;
	verdict: ProfileCheckStatus;
	checks: ProfileCheckRow[];
	capabilityMatrix: string[];
	installReadiness: string[];
	regressionGuards: string[];
	reverseCapabilityGuards: string[];
	nextActions: string[];
	sourceArtifacts: string[];
};

function findRepiRepoRoot(start?: string): string | undefined {
	let dir = resolve(start ?? process.cwd());
	for (;;) {
		if (existsSync(join(dir, "packages", "coding-agent", "src", "core", "recon-profile.ts"))) {
			return dir;
		}
		const parent = dirname(dir);
		if (parent === dir) return undefined;
		dir = parent;
	}
}

function repiRepoRoot(): string {
	return (
		findRepiRepoRoot(process.env.REPI_REPO_ROOT) ??
		findRepiRepoRoot(getPackageDir()) ??
		findRepiRepoRoot(process.cwd()) ??
		process.cwd()
	);
}

function profileCheckWorkspacePath(relativePath: string): string {
	return join(repiRepoRoot(), relativePath);
}

function profileCheckWritableDirCheck(id: string, dir: string): ProfileCheckRow {
	try {
		mkdirSync(dir, { recursive: true });
		const probe = join(dir, `.repi-profile-check-probe-${Date.now()}.tmp`);
		writeFileSync(probe, "ok\n", "utf-8");
		unlinkSync(probe);
		return { id, status: "pass", evidence: [`writable=${dir}`] };
	} catch (error) {
		return {
			id,
			status: "fail",
			evidence: [`not_writable=${dir}`, `error=${error instanceof Error ? error.message : String(error)}`],
			next: [`mkdir -p ${shellQuote(dir)}`, `re_profile_check install`],
		};
	}
}

function profileCheckFileCheck(params: {
	id: string;
	path: string;
	markers?: string[];
	missingStatus?: ProfileCheckStatus;
}): ProfileCheckRow {
	const missingStatus = params.missingStatus ?? "warn";
	if (!existsSync(params.path)) {
		return {
			id: params.id,
			status: missingStatus,
			evidence: [`missing=${params.path}`],
			next: [`restore_or_install ${params.path}`],
		};
	}
	const text = readText(params.path);
	const missingMarkers = (params.markers ?? []).filter((marker) => !text.includes(marker));
	if (missingMarkers.length > 0) {
		return {
			id: params.id,
			status: "fail",
			evidence: [`path=${params.path}`, `missing_markers=${missingMarkers.join(",")}`],
			next: [`repair markers in ${params.path}`, "re_profile_check full"],
		};
	}
	return {
		id: params.id,
		status: "pass",
		evidence: [`path=${params.path}`, ...(params.markers?.length ? [`markers=${params.markers.join(",")}`] : [])],
	};
}

function profileCheckSourceFiles(): Array<{ id: string; path: string; markers: string[] }> {
	return [
		{
			id: "source:core",
			path: profileCheckWorkspacePath("packages/coding-agent/src/core/recon-profile.ts"),
			markers: ["RECON_TOOL_NAMES", "re_profile_check", "ProfileCheckArtifact", "buildProfileCheckArtifact"],
		},
	];
}

function profileCheckInstalledFiles(
	mode: ProfileCheckMode,
): Array<{ id: string; path: string; markers: string[]; missingStatus: ProfileCheckStatus }> {
	const missingStatus: ProfileCheckStatus = mode === "install" ? "fail" : "warn";
	return [
		{
			id: "install:settings",
			path: join(getAgentDir(), "settings.json"),
			markers: ["compaction"],
			missingStatus,
		},
		{
			id: "install:profile-manifest",
			path: join(getAgentDir(), "recon", "profile.json"),
			markers: ["isolated-repi-profile", "repi"],
			missingStatus,
		},
		{
			id: "install:tool-index",
			path: join(getAgentDir(), "recon", "tools", "tool-index.md"),
			markers: ["REPI Tool Index"],
			missingStatus,
		},
	];
}

function profileCheckInstallScriptChecks(): ProfileCheckRow[] {
	return [
		profileCheckFileCheck({
			id: "install-script:install-repi",
			path: profileCheckWorkspacePath("scripts/reverse-agent/install-repi.sh"),
			markers: ["install-repi.sh", "init-repi-profile.mjs"],
			missingStatus: "warn",
		}),
		profileCheckFileCheck({
			id: "install-script:init-repi-profile",
			path: profileCheckWorkspacePath("scripts/reverse-agent/init-repi-profile.mjs"),
			markers: ["isolated-repi-profile", "settings.compaction"],
			missingStatus: "warn",
		}),
		profileCheckFileCheck({
			id: "install-script:repi-smoke",
			path: profileCheckWorkspacePath("scripts/reverse-agent/repi-smoke.mjs"),
			markers: ["repi-doctor", "model"],
			missingStatus: "warn",
		}),
	];
}

function profileCheckSourceCorpus(): { paths: string[]; text: string } {
	const paths = Array.from(
		new Set([
			...profileCheckSourceFiles().map((file) => file.path),
			...profileCheckInstalledFiles("quick").map((file) => file.path),
			builtinSkillFilePath(),
			builtinPromptFilePath("decision"),
			builtinPromptFilePath("chain"),
		]),
	).filter((path) => existsSync(path));
	return { paths, text: paths.map((path) => readText(path)).join("\n\n--- repi-profile-check-source ---\n\n") };
}

function profileCheckCriticalMarkers(): string[] {
	return [
		"re_native_runtime",
		"re_web_authz_state",
		"re_mobile_runtime",
		"re_exploit_lab",
		"re_proof_loop",
		"re_autopilot",
		"re_toolchain_domain",
		"re_runtime_bridge",
		"re_runtime_adapter",
		"ToolchainDomainCapabilityV1",
		"ProfessionalRuntimeBridgesCheckV1",
		"RuntimeAdapterExecutionCheckV1",
		"domain_toolchain_matrix",
		"runtime_execution_bridge_matrix",
		"adapter_runner_parser_ingest_contract",
		"operator_command_floor",
		"proof_exit_criteria",
		"specialist_runtime_planner",
		"re_profile_check",
		"profile_check_artifact",
		"install_readiness",
		"reverse_capability_guards",
		"regression_guards",
	];
}

function profileCheckReverseCapabilityMarkers(): string[] {
	return [
		"Native deep symbol/import/string anchors",
		"browser/XHR/WS",
		"web scanner manual replay",
		"web authz matrix anchors",
		"JS signing replay harness anchors",
		"pwn ROP/libc chain anchors",
		"Exploit PoC inventory anchors",
		"PCAP stream ranking anchors",
		"memory forensics credential",
		"Firmware image metadata anchors",
		"iOS Frida/objection hook anchors",
		"Agent prompt surface anchors",
		"Malware IOC/config anchors",
		"Cloud identity anchors",
		"Identity/AD graph edge anchors",
		"Frida/GDB trace",
		"Web/CDP replay",
		"Frida/Mobile",
		"bridge-rev-ghidra-r2-angr",
		"verifier-pwn-crash-offset-primitive-exploit",
		"cdp-network-capture",
		"mobile-frida-java-hook-template",
		"adapter-r2-native-xref-runner",
		"adapter-frida-mobile-hook-runner",
		"adapter-web-cdp-network-runner",
		"adapter-pwntools-local-verifier-runner",
		"domain:web-api",
		"domain:rev-native",
		"domain:pwn",
		"domain:frontend-js",
		"domain:web-scan",
		"domain:mobile",
		"domain:mobile-ios",
		"domain:pcap-dfir",
		"domain:memory-forensics",
		"domain:firmware-iot",
		"domain:crypto",
		"domain:cloud-identity",
		"domain:exploit-reliability",
		"fallback_available",
	];
}

function profileCheckMarkerChecks(
	idPrefix: string,
	markers: string[],
	corpus: { paths: string[]; text: string },
): ProfileCheckRow[] {
	if (corpus.paths.length === 0) {
		return [
			{
				id: `${idPrefix}:source-corpus`,
				status: "warn",
				evidence: ["source_corpus=missing"],
				next: ["run from REPI repository root or install profile, then re_profile_check full"],
			},
		];
	}
	return markers.map((marker) => {
		const present = corpus.text.includes(marker);
		return {
			id: `${idPrefix}:${slug(marker).slice(0, 72)}`,
			status: present ? "pass" : "fail",
			evidence: [present ? `present=${marker}` : `missing=${marker}`, `source_files=${corpus.paths.length}`],
			next: present ? undefined : [`restore capability marker ${marker}`, "re_profile_check full"],
		};
	});
}

function profileCheckVerdict(checks: ProfileCheckRow[]): ProfileCheckStatus {
	if (checks.some((check) => check.status === "fail")) return "fail";
	if (checks.some((check) => check.status === "warn")) return "warn";
	return "pass";
}

export function buildProfileCheckArtifact(mode: ProfileCheckMode = "quick"): ProfileCheckArtifact {
	// Profile checks explicitly inspect generated prompt/skill files, so this is
	// one of the few paths that should materialize the built-in corpus.
	ensureReconStorage({ materializeResources: true });
	const installScriptChecks = profileCheckInstallScriptChecks();
	const checks: ProfileCheckRow[] = [
		...profileCheckSourceFiles()
			.filter((file) => mode !== "install" || existsSync(file.path))
			.map((file) =>
				profileCheckFileCheck({ id: file.id, path: file.path, markers: file.markers, missingStatus: "warn" }),
			),
		...profileCheckInstalledFiles(mode).map((file) =>
			profileCheckFileCheck({
				id: file.id,
				path: file.path,
				markers: file.markers,
				missingStatus: file.missingStatus,
			}),
		),
		...(mode === "install"
			? installScriptChecks.filter((check) => !check.evidence.some((item) => item.startsWith("missing=")))
			: installScriptChecks),
		profileCheckWritableDirCheck("storage:evidence-profile-check", evidenceProfileCheckDir()),
		profileCheckWritableDirCheck("storage:evidence-runs", evidenceRunsDir()),
		profileCheckFileCheck({ id: "storage:tool-index", path: toolIndexPath(), markers: ["REPI Tool Index"] }),
	];
	const corpus = profileCheckSourceCorpus();
	const criticalChecks = profileCheckMarkerChecks("regression", profileCheckCriticalMarkers(), corpus);
	const reverseChecks = profileCheckMarkerChecks("reverse-capability", profileCheckReverseCapabilityMarkers(), corpus);
	checks.push(...criticalChecks, ...reverseChecks);
	const capabilityMatrix = [
		`registered_tools=${Array.from(RECON_TOOL_NAMES).join(",")}`,
		`registered_commands=${Array.from(RECON_COMMAND_NAMES).join(",")}`,
		"execution_chain=route/mission/kernel -> decision/map/lane/autopilot -> campaign/operation/delegate/swarm/supervisor -> operator -> verifier/compiler/replayer/autofix -> proof_loop/profile_check",
		"runtime_domains=native,web_authz,live_browser,mobile,exploit_lab,pwn,pcap,firmware,agentsec,malware,cloud,identity,frida_gdb",
		"domain_toolchain_matrix=ToolchainDomainCapabilityV1 runtime:toolchain-doctor domain:web-api domain:web-scan domain:frontend-js domain:rev-native domain:pwn domain:mobile domain:mobile-ios domain:pcap-dfir domain:memory-forensics domain:firmware-iot domain:crypto domain:cloud-identity domain:exploit-reliability fallback_available",
		"runtime_execution_bridge_matrix=ProfessionalRuntimeBridgesCheckV1 runtime:professional-runtime-bridges bridge-rev-ghidra-r2-angr verifier-pwn-crash-offset-primitive-exploit cdp-network-capture mobile-frida-java-hook-template",
		"adapter_execution_matrix=RuntimeAdapterExecutionCheckV1 runtime:adapter-execution adapter_runner_parser_ingest_contract adapter-r2-native-xref-runner adapter-frida-mobile-hook-runner adapter-web-cdp-network-runner adapter-pwntools-local-verifier-runner",
	];
	const installReadiness = [
		`agent_dir=${getAgentDir()}`,
		...checks
			.filter(
				(check) =>
					check.id.startsWith("install:") ||
					check.id.startsWith("install-script:") ||
					check.id === "storage:tool-index",
			)
			.map((check) => `${check.status}:${check.id}:${check.evidence.join(" | ")}`),
		"verify_command=node scripts/reverse-agent/repi-smoke.mjs . --json",
		"install_command=npm run install:repi",
		"help_smoke=REPI_OFFLINE=1 ./repi --offline --help",
	];
	const regressionGuards = [
		...criticalChecks.map((check) => `${check.status}:${check.id}:${check.evidence[0] ?? ""}`),
		"transpile_guard=node TypeScript transpile packages/coding-agent/src/core/recon-profile.ts",
		"focused_tests=node node_modules/vitest/dist/cli.js --run packages/coding-agent/test/recon-profile-inline-profile.test.ts packages/coding-agent/test/recon-profile-lane-quality.test.ts packages/coding-agent/test/args.test.ts",
		"repo_check=npm run check",
	];
	const reverseCapabilityGuards = reverseChecks.map(
		(check) => `${check.status}:${check.id}:${check.evidence[0] ?? ""}`,
	);
	const verdict = profileCheckVerdict(checks);
	const nextActions = Array.from(
		new Set([
			...checks.flatMap((check) => (check.status === "pass" ? [] : (check.next ?? []))),
			...(verdict === "fail"
				? ["repair failing profile checks", "re_profile_check full", "npm run check"]
				: ["re_profile_check full", "node scripts/reverse-agent/repi-smoke.mjs . --json"]),
		]),
	).slice(0, 24);
	return {
		timestamp: new Date().toISOString(),
		mode,
		verdict,
		checks,
		capabilityMatrix,
		installReadiness,
		regressionGuards,
		reverseCapabilityGuards,
		nextActions,
		sourceArtifacts: Array.from(new Set(corpus.paths)).slice(0, 48),
	};
}

export function formatProfileCheckArtifact(profileCheck: ProfileCheckArtifact, path?: string): string {
	return [
		"profile_check:",
		path ? `profile_check_artifact: ${path}` : undefined,
		`timestamp: ${profileCheck.timestamp}`,
		`mode: ${profileCheck.mode}`,
		`verdict: ${profileCheck.verdict}`,
		"capability_matrix:",
		...profileCheck.capabilityMatrix.map((item) => `- ${item}`),
		"checks:",
		...profileCheck.checks.map((check) => `- ${check.status} ${check.id}: ${check.evidence.join(" | ")}`),
		"install_readiness:",
		...profileCheck.installReadiness.map((item) => `- ${item}`),
		"reverse_capability_guards:",
		...profileCheck.reverseCapabilityGuards.map((item) => `- ${item}`),
		"regression_guards:",
		...profileCheck.regressionGuards.map((item) => `- ${item}`),
		"next_actions:",
		...(profileCheck.nextActions.length ? profileCheck.nextActions.map((item) => `- ${item}`) : ["- none"]),
		`next_profile_check_command: ${profileCheck.verdict === "pass" ? "re_profile_check show" : "re_profile_check full"}`,
		"source_artifacts:",
		...(profileCheck.sourceArtifacts.length ? profileCheck.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
	]
		.filter(Boolean)
		.join("\n");
}
