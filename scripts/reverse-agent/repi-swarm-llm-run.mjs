#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { atomicWriteFile } from "./lib/atomic-file.mjs";
import { createSwarmRunCatalog, serializeSwarmRunRef } from "./lib/swarm-run-catalog.mjs";
import {
	capabilityMatrixDoctrine,
	evidencePriorityDoctrine,
	roleLibrary,
	routeAgentToolchains,
	routeCommandPalettes,
	routeDeepTechniquePlaybooks,
	routeProfiles,
	routeProofKits,
	routeTechniqueHints,
	techniqueProofContracts,
	universalProofDoctrine,
	universalTechniqueRules,
} from "./lib/swarm-llm-domain-catalog.mjs";
import {
	buildMergeReport,
	configureSwarmLlmEvidenceRuntime,
	extractJsonObject,
} from "./lib/swarm-llm-evidence-runtime.mjs";

const argv = process.argv.slice(2);
const commands = new Set(["llm-run", "run-llm", "workers", "plan", "run", "status", "list", "resolve", "merge", "help"]);
let root = process.cwd();
if (argv[0] && !argv[0].startsWith("--") && !commands.has(argv[0])) root = resolve(argv.shift());
const command = argv[0] && commands.has(argv[0]) ? argv.shift() : "llm-run";

const sourceAgentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const swarmsRoot = join(sourceAgentDir, "recon", "evidence", "llm-swarms");
const swarmCatalog = createSwarmRunCatalog({ agentDir: sourceAgentDir });
const DEFAULT_MAX_OUTPUT_CHARS = 64 * 1024;
const MAX_HARVESTED_ARTIFACT_BYTES = 1024 * 1024;
const MAX_HARVESTED_ARTIFACTS_PER_WORKER = 24;
const DEFAULT_SWARM_BUILTIN_TOOLS = ["read", "grep", "find", "ls", "bash", "write", "edit"];
const DEFAULT_SWARM_UNIVERSAL_RE_TOOLS = [
	"re_map",
	"re_route",
	"re_techniques",
	"re_lane",
	"re_mission",
	"re_tool_index",
	"re_bootstrap",
	"re_evidence",
	"re_domain_proof_exit",
	"re_decision_core",
	"re_verifier",
	"re_replayer",
	"re_proof_loop",
	"re_operator",
	"re_compiler",
	"re_complete",
];








function commandPaletteFor(profile) {
	return routeCommandPalettes[profile?.id] ?? routeCommandPalettes["reverse-pentest-general"];
}

function uniqueList(values) {
	return [...new Set(values.filter(Boolean).map(String))];
}

function toolsCsvToList(value) {
	return uniqueList(String(value ?? "")
		.split(",")
		.map((item) => item.trim())
		.filter(Boolean));
}

function routeAgentToolsFor(profile) {
	const id = profile?.id && routeAgentToolchains[profile.id] ? profile.id : "reverse-pentest-general";
	return routeAgentToolchains[id] ?? routeAgentToolchains["reverse-pentest-general"];
}

function techniqueProofContractFor(techniqueId, options = {}) {
	const id = String(techniqueId ?? "").trim();
	if (!id) return undefined;
	const contract = techniqueProofContracts[id];
	const full = {
		id,
		proofExit:
			contract?.proofExit ??
			"bind the named technique to its re_techniques proofExit with concrete runtime/artifact evidence and an explicit negative control.",
		requiredSignals: contract?.requiredSignals ?? [
			{ gate: "named-technique-proof", any: ["proofExit", "proof exit", "replay", "accepted", "artifact", "hash"] },
		],
		negativeControls: contract?.negativeControls ?? [
			{ gate: "named-technique-control", any: ["negative control", "counter-evidence", "wrong", "tampered", "负控制", "反证"] },
		],
		source: contract ? "swarm-local-contract" : "generic-re_techniques-contract",
	};
	if (options.full) return full;
	return {
		id: full.id,
		proofExit: full.proofExit,
		requiredGates: full.requiredSignals.map((row) => row.gate),
		negativeGates: full.negativeControls.map((row) => row.gate),
		source: full.source,
	};
}

function techniqueProofContractsFor(techniqueIds) {
	return uniqueList(Array.isArray(techniqueIds) ? techniqueIds : []).map(techniqueProofContractFor).filter(Boolean);
}

function defaultToolsForProfile(profile) {
	return uniqueList([...DEFAULT_SWARM_BUILTIN_TOOLS, ...DEFAULT_SWARM_UNIVERSAL_RE_TOOLS, ...routeAgentToolsFor(profile)]).join(",");
}

function agentToolchainFor(profile, actualTools, toolsMode = "default") {
	const id = profile?.id && routeTechniqueHints[profile.id] ? profile.id : "reverse-pentest-general";
	const enabledTools = toolsMode === "disabled" ? [] : toolsCsvToList(actualTools === undefined ? defaultToolsForProfile(profile) : actualTools);
	const routeTechniqueDomains = routeTechniqueHints[id]?.domains ?? routeTechniqueHints["reverse-pentest-general"].domains;
	const primaryTechniqueDomain = routeTechniqueDomains[0] ?? "reverse-pentest-general";
	return {
		AgentToolchainV1: true,
		toolsMode,
		enabledTools,
		routeTools: routeAgentToolsFor(profile),
		requiredBeforePromotion: ["route", "techniques", "verifier/replayer", "artifact-or-transcript"],
		callOrder: [
			`re_route:${id}`,
			`re_techniques:${primaryTechniqueDomain}`,
			"re_lane:command-pack",
			"bash/write/edit:proof-harness",
			"re_verifier:proof-exit",
			"re_replayer:replay",
		],
		fallbackPolicy: "missing tool => record gap and use equivalent shell/manual proof; never promote narrative-only",
	};
}

function commandNamesFromPalette(commandPalette) {
	const names = new Set();
	const commands = [
		...(commandPalette?.passive ?? []),
		...(commandPalette?.proof ?? []),
		...(commandPalette?.negative ?? []),
	];
	for (const command of commands) {
		for (const segment of String(command).split(/\n|&&|\|\||;/)) {
			const match = segment.trim().match(/^(?:[A-Z_][A-Z0-9_]*=\S+\s+)*(?:timeout\s+\S+\s+|sudo\s+|env\s+)*([A-Za-z0-9_.+-]+)/i);
			const name = match?.[1];
			if (!name || /^(?:true|false|then|do|done|fi|esac|from|print|comparison|PY)$/i.test(name)) continue;
			names.add(name);
		}
	}
	return [...names].slice(0, 24);
}

function toolProbeCommandFor(profile) {
	const names = commandNamesFromPalette(commandPaletteFor(profile));
	if (!names.length) return undefined;
	return `for t in ${names.map(shellQuote).join(" ")}; do command -v "$t" >/dev/null 2>&1 && echo "tool:$t=ok" || echo "tool:$t=missing"; done`;
}

function techniqueHintsFor(profile) {
	const id = profile?.id && routeTechniqueHints[profile.id] ? profile.id : "reverse-pentest-general";
	return {
		...routeTechniqueHints[id],
		universalRules: universalTechniqueRules,
		playbook: routeDeepTechniquePlaybooks[id] ?? routeDeepTechniquePlaybooks["reverse-pentest-general"],
		proofContracts: techniqueProofContractsFor(routeTechniqueHints[id]?.techniqueIds),
	};
}

function compactTechniqueHintsForPrompt(hints) {
	return {
		...(hints ?? {}),
		proofContracts: (hints?.proofContracts ?? []).map((contract) => ({
			id: contract.id,
			proofExit: contract.proofExit,
			requiredGates: contract.requiredGates ?? (contract.requiredSignals ?? []).map((row) => row.gate),
			negativeGates: contract.negativeGates ?? (contract.negativeControls ?? []).map((row) => row.gate),
		})),
	};
}

function minimalTechniqueHintsForPrompt(hints) {
	return {
		domains: hints?.domains ?? [],
		techniqueIds: hints?.techniqueIds ?? [],
		proofContracts: (hints?.proofContracts ?? []).map((contract) => ({
			id: contract.id,
			proofExit: contract.proofExit,
		})),
	};
}

function proofKitFor(profile) {
	return routeProofKits[profile?.id] ?? routeProofKits["reverse-pentest-general"];
}

function usage() {
	return `Usage:
  repi swarm plan <target> --workers N [--route <id[,id...]|all>] [--roles mapper,reverser,exploiter,verifier,adversary,solo] [--json]
  repi swarm run <target> --workers N [--provider <id>] [--model <id>] [--tools bash,read,grep,ls,re_techniques] [--json]
  repi swarm status [latest|run-id] [--json]
  repi swarm list [--json]
  repi swarm resolve [latest|run-id|cli:run-id|ts:run-id] [--json]
  repi swarm merge [latest|run-id] [--json]
  repi swarm llm-run <target> --workers N [--provider <id>] [--model <id>] [--prompt <text>]

Plan/run options:
  --target <text>          Target/task label if no positional target is supplied
  --workers <N>            Number of parallel LLM workers (default: 3; broad multi-route tasks auto-expand up to 16)
  --max-concurrency <N>    Max simultaneous child processes (default: workers)
  --provider <id>          Provider id from REPI_* env (default: repi-env) or ~/.repi/agent/models.json
  --model <id>             Model id
  --route <id[,id...]|all> Force one or more route ids, or the full route catalog, instead of keyword routing
  --roles <csv>            Role order. Defaults to solo for one worker, else mapper,reverser,exploiter,verifier,adversary
  --tools <list>           Enable tools for workers (run default: route-aware RE toolchain; llm-run default: --no-tools)
  --no-tools               Disable all worker tools
  --timeout-ms <ms>        Per-worker timeout (default: REPI_SWARM_LLM_TIMEOUT_MS or 210000)
  --prompt <text>          llm-run prompt template, or extra mission guidance for swarm run
  --expect <regex>         llm-run per-worker success regex. Supports {id}/{target}
  --keep-profiles          Keep temporary isolated worker profiles for debugging
  --json                   Print JSON report only

Examples:
  repi swarm plan ./target --workers 5
  repi swarm run ./target --workers 5 --provider openai-compatible --model vendor/model --tools bash,read,grep,ls,re_route,re_techniques,re_verifier
  repi swarm list --json
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

function hasFlag(args, names) {
	return flagValue(args, names, undefined) !== undefined;
}

function parseIntFlag(args, names, fallback, min, max) {
	const raw = flagValue(args, names, "");
	const parsed = Number.parseInt(raw, 10);
	if (!Number.isFinite(parsed)) return fallback;
	return Math.max(min, Math.min(max, parsed));
}

const valueFlags = new Set([
	"--target",
	"--workers",
	"-w",
	"--max-concurrency",
	"--provider",
	"--model",
	"--route",
	"--roles",
	"--tools",
	"--timeout-ms",
	"--prompt",
	"--expect",
	"--cwd",
]);

function positionalTarget(args, offset = 0) {
	const positional = [];
	for (let index = 0; index < args.length; index++) {
		const arg = args[index];
		if (arg === "--") {
			positional.push(...args.slice(index + 1));
			break;
		}
		if (arg.startsWith("--") || arg === "-w") {
			const flagName = arg.includes("=") ? arg.slice(0, arg.indexOf("=")) : arg;
			if (!arg.includes("=") && valueFlags.has(flagName)) index++;
			continue;
		}
		positional.push(arg);
	}
	return positional[offset];
}

function redact(value) {
	return String(value ?? "")
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\b(?:A3T|AKIA|ASIA)[A-Z0-9]{16}\b/g, "<redacted:aws-access-key>")
		.replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "<redacted:jwt>")
		.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "<redacted:private-key>")
		.replace(/(?:AUTH_TOKEN|API_KEY|PASSWORD|SECRET|TOKEN|ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|CLIENT_SECRET)=\S+/gi, (match) => `${match.split("=")[0]}=<redacted>`);
}

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function shellQuote(value) {
	return `'${String(value ?? "").replace(/'/g, "'\\''")}'`;
}

function clip(value, max = 12000) {
	const text = redact(value);
	return text.length > max ? `${text.slice(0, max - 32)}\n...<truncated:${text.length - max + 32}>` : text;
}

function safeArtifactName(sourcePath, index) {
	const base = basename(sourcePath).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 96);
	return `${String(index + 1).padStart(2, "0")}-${base || "artifact"}`;
}

function extractArtifactPathCandidates(text) {
	const candidates = new Set();
	const pattern = /(?:^|[\s"'[(,])((?:\/[A-Za-z0-9._~+@%=:,-]+)+)(?=$|[\s"'\]),;])/g;
	let match;
	while ((match = pattern.exec(String(text ?? "")))) {
		const candidate = match[1];
		if (!candidate || candidate.includes("://") || candidate.length > 512) continue;
		candidates.add(candidate);
	}
	return [...candidates];
}

function harvestArtifactSourceTexts(worker) {
	const parsed = extractJsonObject(worker.stdoutPreview);
	const sources = [];
	const push = (value) => {
		if (value === undefined || value === null) return;
		if (typeof value === "string") sources.push(value);
		else if (Array.isArray(value)) value.forEach(push);
		else if (typeof value === "object") {
			push(value.artifact);
			push(value.artifacts);
			push(value.path);
			push(value.file);
			push(value.locator);
			push(value.evidence);
			push(value.summary);
			push(value.command);
		}
	};
	if (parsed && typeof parsed === "object") {
		push(parsed.artifacts);
		push(parsed.artifact);
		push(parsed.evidence);
		push(parsed.evidenceItems);
		for (const claim of Array.isArray(parsed.claims) ? parsed.claims : []) {
			push(claim?.artifacts);
			push(claim?.artifact);
			push(claim?.evidence);
			push(claim?.evidenceItems);
		}
		for (const finding of Array.isArray(parsed.findings) ? parsed.findings : []) {
			if (typeof finding === "object") {
				push(finding?.artifacts);
				push(finding?.artifact);
				push(finding?.evidence);
				push(finding?.evidenceItems);
			}
		}
		return sources;
	}
	return [`${worker.stdoutPreview}\n${worker.stderrPreview}`];
}

function harvestWorkerArtifacts(worker, evidenceRoot) {
	const artifactDir = join(evidenceRoot, `worker-${worker.workerId}-artifacts`);
	const rows = [];
	const sourcePaths = uniqueList(harvestArtifactSourceTexts(worker).flatMap(extractArtifactPathCandidates));
	for (const sourcePath of sourcePaths) {
		if (rows.length >= MAX_HARVESTED_ARTIFACTS_PER_WORKER) break;
		try {
			const stat = statSync(sourcePath);
			if (!stat.isFile() || stat.size > MAX_HARVESTED_ARTIFACT_BYTES) continue;
			mkdirSync(artifactDir, { recursive: true, mode: 0o700 });
			const content = readFileSync(sourcePath);
			const artifactPath = join(artifactDir, safeArtifactName(sourcePath, rows.length));
			atomicWriteFile(artifactPath, content, 0o600);
			rows.push({
				sourcePath: redact(sourcePath),
				artifactPath,
				size: stat.size,
				sha256: sha256(content),
			});
		} catch {
			// Path-like text is often an endpoint or a stale temp path; only harvest
			// live bounded files and keep merge robust when they are absent.
		}
	}
	if (rows.length) {
		atomicWriteFile(join(evidenceRoot, `worker-${worker.workerId}-artifacts.json`), `${JSON.stringify(rows, null, 2)}\n`, 0o600);
	}
	return rows;
}

function substitute(template, workerId, target, role = "worker", context = {}) {
	const route = context.route ?? {};
	const proofKit = context.proofKit ?? {};
	const commandPalette = context.commandPalette ?? {};
	const techniqueHints = minimalTechniqueHintsForPrompt(context.techniqueHints ?? {});
	const agentToolchain = context.agentToolchain ?? {};
	return String(template ?? "")
		.replaceAll("{{id}}", String(workerId))
		.replaceAll("{id}", String(workerId))
		.replaceAll("<id>", String(workerId))
		.replaceAll("{{role}}", role)
		.replaceAll("{role}", role)
		.replaceAll("<role>", role)
		.replaceAll("{{target}}", target)
		.replaceAll("{target}", target)
		.replaceAll("<target>", target)
		.replaceAll("{{route}}", String(route.id ?? "reverse-pentest-general"))
		.replaceAll("{route}", String(route.id ?? "reverse-pentest-general"))
		.replaceAll("<route>", String(route.id ?? "reverse-pentest-general"))
		.replaceAll("{{routeId}}", String(route.id ?? "reverse-pentest-general"))
		.replaceAll("{routeId}", String(route.id ?? "reverse-pentest-general"))
		.replaceAll("<routeId>", String(route.id ?? "reverse-pentest-general"))
		.replaceAll("{{routeDomain}}", String(route.domain ?? "Reverse/Pentest general"))
		.replaceAll("{routeDomain}", String(route.domain ?? "Reverse/Pentest general"))
		.replaceAll("<routeDomain>", String(route.domain ?? "Reverse/Pentest general"))
		.replaceAll("{{routeWorkflow}}", Array.isArray(route.workflow) ? route.workflow.join(" -> ") : "")
		.replaceAll("{routeWorkflow}", Array.isArray(route.workflow) ? route.workflow.join(" -> ") : "")
		.replaceAll("<routeWorkflow>", Array.isArray(route.workflow) ? route.workflow.join(" -> ") : "")
		.replaceAll("{{proofKit}}", JSON.stringify(proofKit))
		.replaceAll("{proofKit}", JSON.stringify(proofKit))
		.replaceAll("<proofKit>", JSON.stringify(proofKit))
		.replaceAll("{{commandPalette}}", JSON.stringify(commandPalette))
		.replaceAll("{commandPalette}", JSON.stringify(commandPalette))
		.replaceAll("<commandPalette>", JSON.stringify(commandPalette))
		.replaceAll("{{techniqueHints}}", JSON.stringify(techniqueHints))
		.replaceAll("{techniqueHints}", JSON.stringify(techniqueHints))
		.replaceAll("<techniqueHints>", JSON.stringify(techniqueHints))
		.replaceAll("{{agentToolchain}}", JSON.stringify(agentToolchain))
		.replaceAll("{agentToolchain}", JSON.stringify(agentToolchain))
		.replaceAll("<agentToolchain>", JSON.stringify(agentToolchain));
}

function readJson(path) {
	return JSON.parse(readFileSync(path, "utf8"));
}

function copyIfExists(from, to) {
	if (existsSync(from)) atomicWriteFile(to, readFileSync(from), 0o600);
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

const fallbackRouteProfile = {
	id: "reverse-pentest-general",
	domain: "Reverse/Pentest general",
	workflow: ["passive map", "smallest proof path", "verification", "report"],
	roles: {},
};

function routeProfilesFor(target) {
	const text = String(target ?? "");
	const matches = routeProfiles.filter((profile) => profile.match.test(text));
	return matches.length ? matches : [fallbackRouteProfile];
}

function forcedRouteProfiles(routeArg) {
	const requested = String(routeArg ?? "")
		.split(",")
		.map((item) => item.trim())
		.filter(Boolean);
	if (!requested.length) return undefined;
	if (requested.some((id) => /^(?:all|full|full-spectrum|\*)$/i.test(id))) return routeProfiles;
	const profiles = [];
	for (const id of requested) {
		const profile = routeProfiles.find((item) => item.id === id) || (id === fallbackRouteProfile.id ? fallbackRouteProfile : undefined);
		if (profile && !profiles.some((item) => item.id === profile.id)) profiles.push(profile);
	}
	return profiles.length ? profiles : [fallbackRouteProfile];
}

function routeProfileById(id) {
	const routeId = String(id ?? "").trim();
	if (!routeId) return undefined;
	return routeProfiles.find((profile) => profile.id === routeId) || (routeId === fallbackRouteProfile.id ? fallbackRouteProfile : undefined);
}

function routeProfile(target) {
	return routeProfilesFor(target)[0];
}

function workerSpec(role, profile, routeCandidates = [profile]) {
	const base = roleSpec(role);
	const overlay = profile.roles?.[role] ?? {};
	if (role === "solo") {
		const candidateText = routeCandidates.length > 1 ? ` 候选域：${routeCandidates.map((item) => item.domain).join(" / ")}。` : "";
		return {
			role: "solo",
			objective: `单工作者完整处理 ${profile.domain}：${profile.workflow.join(" -> ")}；必须自己完成 mapping、逆向假设、最小 replay/proof、负控制或失败反证，并输出结构化 claims/evidence/blockers/nextCommands。${candidateText}`,
			evidenceContract: [
				...(overlay.evidenceContract ?? []),
				"entry/surface map",
				"control/data-flow or request-order proof",
				"minimal replay/proof command",
				"negative control or counter-evidence",
				"artifact hashes",
			],
			mergeKeys: ["solo", "surface", "reverse", "proof", "control", "artifact"],
		};
	}
	return {
		role: base.role,
		objective: overlay.objective ?? base.objective,
		evidenceContract: overlay.evidenceContract ?? base.evidenceContract,
		mergeKeys: overlay.mergeKeys ?? base.mergeKeys,
	};
}

function routeCandidateRow(profile) {
	return {
		id: profile.id,
		domain: profile.domain,
		workflow: profile.workflow,
		proofKit: proofKitFor(profile),
		commandPalette: commandPaletteFor(profile),
		toolProbeCommand: toolProbeCommandFor(profile),
		techniqueHints: techniqueHintsFor(profile),
		agentToolchain: agentToolchainFor(profile, defaultToolsForProfile(profile), "default"),
	};
}

function routeCoverageForPackets(routeCandidates, workerPackets) {
	const coveredIds = new Set(workerPackets.map((packet) => packet.route?.id).filter(Boolean));
	const covered = routeCandidates.filter((candidate) => coveredIds.has(candidate.id));
	const uncovered = routeCandidates.filter((candidate) => !coveredIds.has(candidate.id));
	return {
		routeCount: routeCandidates.length,
		coveredCount: covered.length,
		uncoveredCount: uncovered.length,
		covered,
		uncovered,
		complete: uncovered.length === 0,
	};
}

function buildSwarmPlan(args, options = {}) {
	const target = flagValue(args, "--target") ?? positionalTarget(args) ?? "local-selfcheck";
	const profiles = forcedRouteProfiles(flagValue(args, "--route")) ?? routeProfilesFor(target);
	const explicitWorkers = hasFlag(args, ["--workers", "-w"]);
	const requestedWorkers = parseIntFlag(args, ["--workers", "-w"], 3, 1, 16);
	const workers = explicitWorkers ? requestedWorkers : profiles.length > 1 ? Math.min(16, Math.max(requestedWorkers, profiles.length)) : requestedWorkers;
	const maxConcurrency = parseIntFlag(args, "--max-concurrency", workers, 1, workers);
	const provider = flagValue(args, "--provider");
	const model = flagValue(args, "--model");
	const toolsMode = args.includes("--no-tools") ? "disabled" : hasFlag(args, "--tools") ? "explicit" : "default";
	const explicitTools = hasFlag(args, "--tools") ? flagValue(args, "--tools", "") : undefined;
	const timeoutMs = parseIntFlag(args, "--timeout-ms", Number(process.env.REPI_SWARM_LLM_TIMEOUT_MS ?? 210000), 5000, 30 * 60 * 1000);
	const roles = workers === 1 && flagValue(args, "--roles") === undefined ? ["solo"] : parseRoles(args);
	const runId = options.runId ?? makeRunId(target);
	const profile = profiles[0];
	const workerPackets = Array.from({ length: workers }, (_, index) => {
		const packetProfile = profiles.length > 1 ? profiles[index % profiles.length] : profile;
		const spec = workerSpec(roles[index % roles.length] ?? "specialist", packetProfile, profiles);
		const proofKit = proofKitFor(packetProfile);
		const commandPalette = commandPaletteFor(packetProfile);
		const toolProbeCommand = toolProbeCommandFor(packetProfile);
		const techniqueHints = techniqueHintsFor(packetProfile);
		const tools = toolsMode === "disabled" ? undefined : toolsMode === "explicit" ? explicitTools : defaultToolsForProfile(packetProfile);
		const agentToolchain = agentToolchainFor(packetProfile, tools, toolsMode);
		const workerId = index + 1;
		return {
			workerId,
			id: `worker-${workerId}`,
			role: spec.role,
			route: {
				id: packetProfile.id,
				domain: packetProfile.domain,
				workflow: packetProfile.workflow,
			},
			objective: spec.objective,
			tools,
			toolsMode,
			agentToolchain,
			dependencies: [],
			evidenceContract: spec.evidenceContract,
			mergeKeys: spec.mergeKeys,
			proofKit,
			commandPalette,
			toolProbeCommand,
			techniqueHints,
			limits: { timeoutMs, maxOutputChars: DEFAULT_MAX_OUTPUT_CHARS },
		};
	});
	const routeCandidates = profiles.map(routeCandidateRow);
	const routeCoverage = routeCoverageForPackets(routeCandidates, workerPackets);
	return {
		kind: "repi-swarm-plan",
		schemaVersion: 1,
		SwarmPlannerV1: true,
		generatedAt: new Date().toISOString(),
		runId,
		root,
		runRoot: resolve(flagValue(args, "--cwd") ?? process.cwd()),
		target: redact(target),
		route: {
			id: profile.id,
			domain: profile.domain,
			workflow: profile.workflow,
		},
		routeCandidates,
		routeCoverage,
		provider: provider ?? "default",
		model: model ?? "default",
		workers,
		autoExpandedWorkers: !explicitWorkers && profiles.length > 1,
		maxConcurrency,
		timeoutMs,
		toolsMode,
		toolsDisabled: toolsMode === "disabled",
		workerPackets,
		operatorGuidance: redact(flagValue(args, "--prompt", "")),
			proofDoctrine: universalProofDoctrine,
			evidencePriorityDoctrine,
			capabilityMatrixDoctrine,
			mergeProtocol: {
				StructuredSubagentMergeV1: true,
				requiredWorkerFields: ["claims", "evidenceItems", "conflicts", "blockers", "nextCommands"],
				promotionRule: "claim requires worker exit pass plus concrete evidence/artifact/command; narrative-only rows remain observations",
				conflictPolicy: "verifier/adversary counter-evidence downgrades mapper/reverser/exploiter claims until rechecked",
				mergeArtifacts: ["report.json", "merge-report.json", "merge-verification.json", "worker-*.stdout.txt", "worker-*.stderr.txt", "worker-*-artifacts.json", "worker-*-artifacts/*"],
			},
	};
}

function evidenceRootFor(runId) {
	return join(swarmsRoot, runId);
}

function writePlan(plan) {
	const dir = evidenceRootFor(plan.runId);
	mkdirSync(dir, { recursive: true, mode: 0o700 });
	atomicWriteFile(join(dir, "plan.json"), `${JSON.stringify(plan, null, 2)}\n`, 0o600);
	atomicWriteFile(join(dir, "report.json"), `${JSON.stringify({ kind: "repi-swarm-plan-report", schemaVersion: 1, runId: plan.runId, generatedAt: plan.generatedAt, ok: true, planPath: join(dir, "plan.json"), evidenceRoot: dir, plan }, null, 2)}\n`, 0o600);
	return dir;
}

function promptForWorker(plan, packet, promptTemplate, mode) {
	if (mode === "llm-run") {
		const operatorPrompt = substitute(promptTemplate, packet.workerId, plan.target, packet.role, packet);
		return [
			`You are REPI llm-run worker ${packet.workerId} (${packet.role}).`,
			`Target/task: ${plan.target}`,
			`Route: ${packet.route?.domain ?? plan.route?.domain ?? "Reverse/Pentest general"} (${packet.route?.id ?? plan.route?.id ?? "reverse-pentest-general"})`,
			`Route workflow: ${(packet.route?.workflow ?? plan.route?.workflow ?? []).join(" -> ")}`,
			Array.isArray(plan.routeCandidates) && plan.routeCandidates.length > 1
				? `Route candidates for broad tasks: ${plan.routeCandidates.map((route) => `${route.id}:${route.domain}`).join(" / ")}`
				: undefined,
			"Operator prompt (treat this as the mission goal; if it asks for an exact reply, reply exactly):",
			operatorPrompt,
			"Route proof kit:",
			JSON.stringify(packet.proofKit ?? proofKitFor(packet.route || { id: "reverse-pentest-general" }), null, 2),
			"Route command palette:",
			JSON.stringify(packet.commandPalette ?? commandPaletteFor(packet.route || { id: "reverse-pentest-general" }), null, 2),
			packet.toolProbeCommand ? "Route tool probe command:" : undefined,
			packet.toolProbeCommand,
			"Route technique hints:",
			JSON.stringify(minimalTechniqueHintsForPrompt(packet.techniqueHints ?? techniqueHintsFor(packet.route || { id: "reverse-pentest-general" })), null, 2),
			"Agent toolchain (LLM-callable tools; distinct from shell commands):",
			JSON.stringify(packet.agentToolchain ?? agentToolchainFor(packet.route || { id: "reverse-pentest-general" }, packet.tools, packet.toolsMode), null, 2),
			"Capability matrix doctrine:",
			JSON.stringify(plan.capabilityMatrixDoctrine ?? capabilityMatrixDoctrine, null, 2),
			"Evidence priority doctrine:",
			JSON.stringify(plan.evidencePriorityDoctrine ?? evidencePriorityDoctrine, null, 2),
		].filter(Boolean).join("\n");
	}
	return [
		`You are REPI swarm worker ${packet.workerId} (${packet.role}).`,
		`Target/task: ${plan.target}`,
		`Route: ${packet.route?.domain ?? plan.route?.domain ?? "Reverse/Pentest general"}`,
		`Route workflow: ${(packet.route?.workflow ?? plan.route?.workflow ?? []).join(" -> ")}`,
		Array.isArray(plan.routeCandidates) && plan.routeCandidates.length > 1
			? `Route candidates for broad tasks: ${plan.routeCandidates.map((route) => route.domain).join(" / ")}`
			: undefined,
		`Role objective: ${packet.objective}`,
		plan.operatorGuidance ? `Operator guidance: ${plan.operatorGuidance}` : undefined,
		"Work independently. Prefer concrete evidence over narrative.",
		"Universal proof doctrine:",
		JSON.stringify(plan.proofDoctrine ?? universalProofDoctrine, null, 2),
		"Evidence priority doctrine:",
		JSON.stringify(plan.evidencePriorityDoctrine ?? evidencePriorityDoctrine, null, 2),
		"Capability matrix doctrine:",
		JSON.stringify(plan.capabilityMatrixDoctrine ?? capabilityMatrixDoctrine, null, 2),
		packet.proofKit ? "Route proof kit:" : undefined,
		packet.proofKit ? JSON.stringify(packet.proofKit, null, 2) : undefined,
		packet.commandPalette ? "Route command palette (adapt placeholders like $TARGET/<token>; do not claim a command ran unless you actually ran it):" : undefined,
		packet.commandPalette ? JSON.stringify(packet.commandPalette, null, 2) : undefined,
		packet.toolProbeCommand ? "Route tool probe command (run first when tools are enabled; record missing tools and choose fallbacks instead of hallucinating availability):" : undefined,
		packet.toolProbeCommand,
		packet.techniqueHints ? "Route technique hints (pull with re_techniques where available; use these as starting hypotheses, not proof):" : undefined,
		packet.techniqueHints ? JSON.stringify(compactTechniqueHintsForPrompt(packet.techniqueHints), null, 2) : undefined,
		packet.agentToolchain ? "Agent toolchain (LLM-callable tools; use these to load playbooks, build harnesses, replay, and verify; if explicit --tools blocks one, record the fallback):" : undefined,
		packet.agentToolchain ? JSON.stringify(packet.agentToolchain, null, 2) : undefined,
		`Evidence contract: ${packet.evidenceContract.join("; ")}`,
		`Merge keys: ${packet.mergeKeys.join(", ")}`,
		"Every promoted claim should include at least one command/path/hash/diff/offset/status/control artifact. If the proof is only a hypothesis, lower confidence and put the missing proof in blockers.",
		"Output ONLY valid JSON. Do not use Markdown fences. If evidence is missing, put the reason in blockers instead of writing prose.",
		"Required schema:",
		JSON.stringify({
			workerId: packet.id,
			role: packet.role,
			claims: [
				{
					id: `${packet.role}-claim-1`,
					statement: "...",
					techniqueId: "optional re_techniques id when asserting a named technique",
					techniqueProof: { proofExitObserved: "what satisfied the technique proofExit", counterControls: ["wrong-key/wrong-principal/wrong-offset result"] },
					evidence: ["command/output/path"],
					confidence: 0.0,
					blockers: [],
					conflicts: [],
				},
			],
			evidenceItems: [{ class: "runtime-behavior|network-traffic|served-assets|process-config|persisted-state|artifact|source|comment", locator: "command/path/frame/offset", summary: "what proves it" }],
			conflicts: [{ claimId: `${packet.role}-claim-1`, evidenceClass: "runtime-behavior", evidence: "counter-evidence anchor", reason: "why this downgrades", nextCommand: "repair command" }],
			artifacts: ["path or command output anchor"],
			handoffs: [{ route: "route-id-if-another-domain-is-better", reason: "why this needs another route", evidence: "observed anchor", nextCommand: "replay or map command" }],
			blockers: [],
			nextCommands: [],
		}, null, 2),
	].filter(Boolean).join("\n");
}

function runWorker({ plan, packet, promptTemplate, expectTemplate, tempRoot, mode }) {
	return new Promise((resolveWorker) => {
		const startedAt = Date.now();
		let workerAgentDir;
		let prompt;
		try {
			prompt = promptForWorker(plan, packet, promptTemplate, mode);
			workerAgentDir = prepareWorkerAgentDir(tempRoot, packet.workerId);
		} catch (error) {
			const message = redact(String(error?.message || error));
			resolveWorker({
				workerId: packet.workerId,
				role: packet.role,
				status: "fail",
				exit: 1,
				signal: null,
				timedOut: false,
				ms: Date.now() - startedAt,
				provider: plan.provider,
				model: plan.model,
				route: packet.route,
				toolsMode: packet.toolsMode,
				proofKit: packet.proofKit,
				commandPalette: packet.commandPalette,
				toolProbeCommand: packet.toolProbeCommand,
				techniqueHints: packet.techniqueHints,
				agentToolchain: packet.agentToolchain,
				workerAgentDir: workerAgentDir ?? "",
				stdoutSha256: sha256(""),
				stderrSha256: sha256(message),
				stdoutPreview: "",
				stderrPreview: message,
				expect: expectTemplate ? substitute(expectTemplate, packet.workerId, plan.target, packet.role, packet) : undefined,
				expectOk: false,
				promptSha256: sha256(redact(prompt ?? "")),
			});
			return;
		}
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
		// opt #188: piped child stdio emits 'error' (EIO/EPIPE) independent of the
		// child's own 'error'/'close' — e.g. proc.kill mid-output tears the pipe.
		// A Readable with no 'error' listener → Unhandled 'error' event → crashes
		// the whole orchestrator mid-pool (runPool finally cleanup never runs).
		// Swallow so the 'close' handler still resolves the worker with whatever
		// was captured. Same doctrine as opt #36 (mcp-manager) / #40
		// (waitForChildProcess stdio).
		child.stdout?.on("error", () => {});
		child.stderr?.on("error", () => {});
		child.on("close", (code, signal) => {
			clearTimeout(timer);
			const redactedStdout = clip(stdout, packet.limits.maxOutputChars);
			const redactedStderr = clip(stderr, 6000);
			let expectOk = redactedStdout.trim().length > 0;
			let expect = undefined;
			if (expectTemplate) {
					expect = substitute(expectTemplate, packet.workerId, plan.target, packet.role, packet);
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
				route: packet.route,
				toolsMode: packet.toolsMode,
				proofKit: packet.proofKit,
				commandPalette: packet.commandPalette,
				toolProbeCommand: packet.toolProbeCommand,
				techniqueHints: packet.techniqueHints,
				agentToolchain: packet.agentToolchain,
				workerAgentDir,
				stdoutSha256: sha256(redactedStdout),
				stderrSha256: sha256(redactedStderr),
				stdoutPreview: redactedStdout,
				stderrPreview: redactedStderr,
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
				route: packet.route,
				toolsMode: packet.toolsMode,
				proofKit: packet.proofKit,
				commandPalette: packet.commandPalette,
				toolProbeCommand: packet.toolProbeCommand,
				techniqueHints: packet.techniqueHints,
				agentToolchain: packet.agentToolchain,
				workerAgentDir,
				stdoutSha256: sha256(""),
				stderrSha256: sha256(redact(String(error.message || error))),
				stdoutPreview: "",
				stderrPreview: redact(String(error.message || error)),
				expect: expectTemplate ? substitute(expectTemplate, packet.workerId, plan.target, packet.role, packet) : undefined,
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
		rows.sort((left, right) => left.workerId - right.workerId);
		for (const worker of rows) {
			atomicWriteFile(join(evidenceRoot, `worker-${worker.workerId}.stdout.txt`), worker.stdoutPreview, 0o600);
			atomicWriteFile(join(evidenceRoot, `worker-${worker.workerId}.stderr.txt`), worker.stderrPreview, 0o600);
			worker.harvestedArtifacts = harvestWorkerArtifacts(worker, evidenceRoot);
		}
		return { rows, tempRoot: keepProfiles ? tempRoot : undefined };
	} finally {
		if (!keepProfiles) rmSync(tempRoot, { recursive: true, force: true });
	}
}

function swarmLlmEvidenceRuntime() {
	return {
		agentToolchainFor,
		commandPaletteFor,
		compactTechniqueHintsForPrompt,
		defaultToolsForProfile,
		fallbackRouteProfile,
		proofKitFor,
		readJson,
		redact,
		routeCandidateRow,
		routeCoverageForPackets,
		routeProfileById,
		sha256,
		shellQuote,
		techniqueHintsFor,
		techniqueProofContractFor,
		toolProbeCommandFor,
		uniqueList,
	};
}

configureSwarmLlmEvidenceRuntime(swarmLlmEvidenceRuntime());

function compactTechniqueHintsForReport(hints) {
	return {
		domains: hints?.domains ?? [],
		techniqueIds: hints?.techniqueIds ?? [],
		proofContracts: (hints?.proofContracts ?? []).map((contract) => ({
			id: contract.id,
			proofExit: contract.proofExit,
			requiredGates: contract.requiredGates ?? (contract.requiredSignals ?? []).map((row) => row.gate),
			negativeGates: contract.negativeGates ?? (contract.negativeControls ?? []).map((row) => row.gate),
			source: contract.source,
		})),
	};
}

function compactAgentToolchainForReport(toolchain) {
	if (!toolchain) return toolchain;
	return {
		AgentToolchainV1: Boolean(toolchain.AgentToolchainV1),
		toolsMode: toolchain.toolsMode,
		enabledTools: toolchain.enabledTools ?? [],
		routeTools: toolchain.routeTools ?? [],
		requiredBeforePromotion: toolchain.requiredBeforePromotion ?? [],
		callOrder: toolchain.callOrder ?? [],
		fallbackPolicy: toolchain.fallbackPolicy,
	};
}

function compactRouteRowForReport(route) {
	if (!route) return route;
	return {
		id: route.id,
		domain: route.domain,
		workflow: route.workflow ?? [],
		proofKit: route.proofKit,
		commandPalette: route.commandPalette,
		toolProbeCommand: route.toolProbeCommand,
		techniqueHints: compactTechniqueHintsForReport(route.techniqueHints ?? {}),
		agentToolchain: compactAgentToolchainForReport(route.agentToolchain),
	};
}

function compactWorkerPacketForReport(packet) {
	if (!packet) return packet;
	return {
		workerId: packet.workerId,
		id: packet.id,
		role: packet.role,
		route: packet.route,
		objective: packet.objective,
		tools: packet.tools,
		toolsMode: packet.toolsMode,
		dependencies: packet.dependencies ?? [],
		evidenceContract: packet.evidenceContract ?? [],
		mergeKeys: packet.mergeKeys ?? [],
		proofKit: packet.proofKit,
		commandPalette: packet.commandPalette,
		toolProbeCommand: packet.toolProbeCommand,
		techniqueHints: compactTechniqueHintsForReport(packet.techniqueHints ?? {}),
		agentToolchain: compactAgentToolchainForReport(packet.agentToolchain),
		limits: packet.limits,
	};
}

function compactPlanForReport(plan, mode) {
	if (mode !== "llm-run") return plan;
	return {
		kind: plan.kind,
		schemaVersion: plan.schemaVersion,
		SwarmPlannerV1: plan.SwarmPlannerV1,
		generatedAt: plan.generatedAt,
		runId: plan.runId,
		root: plan.root,
		runRoot: plan.runRoot,
		target: plan.target,
		route: plan.route,
		routeCandidates: (plan.routeCandidates ?? []).map(compactRouteRowForReport),
		routeCoverage: plan.routeCoverage
			? {
					routeCount: plan.routeCoverage.routeCount,
					coveredCount: plan.routeCoverage.coveredCount,
					uncoveredCount: plan.routeCoverage.uncoveredCount,
					covered: (plan.routeCoverage.covered ?? []).map((route) => ({ id: route.id, domain: route.domain })),
					uncovered: (plan.routeCoverage.uncovered ?? []).map((route) => ({ id: route.id, domain: route.domain })),
					complete: plan.routeCoverage.complete,
				}
			: undefined,
		provider: plan.provider,
		model: plan.model,
		workers: plan.workers,
		autoExpandedWorkers: plan.autoExpandedWorkers,
		maxConcurrency: plan.maxConcurrency,
		timeoutMs: plan.timeoutMs,
		toolsMode: plan.toolsMode,
		toolsDisabled: plan.toolsDisabled,
		workerPackets: (plan.workerPackets ?? []).map(compactWorkerPacketForReport),
		operatorGuidance: plan.operatorGuidance,
	};
}

function compactWorkerReportForReport(worker, mode) {
	const row = {
		workerId: worker.workerId,
		role: worker.role,
		status: worker.status,
		exit: worker.exit,
		signal: worker.signal,
		timedOut: worker.timedOut,
		ms: worker.ms,
		provider: worker.provider,
		model: worker.model,
		route: worker.route,
		toolsMode: worker.toolsMode,
		proofKit: worker.proofKit,
		commandPalette: worker.commandPalette,
		toolProbeCommand: worker.toolProbeCommand,
		techniqueHints: mode === "llm-run" ? compactTechniqueHintsForReport(worker.techniqueHints ?? {}) : worker.techniqueHints,
		agentToolchain: mode === "llm-run" ? compactAgentToolchainForReport(worker.agentToolchain) : worker.agentToolchain,
		stdoutSha256: worker.stdoutSha256,
		stderrSha256: worker.stderrSha256,
		promptSha256: worker.promptSha256,
		expect: worker.expect,
		expectOk: worker.expectOk,
		stdoutTail: worker.stdoutPreview.slice(-1200),
		stderrTail: worker.stderrPreview.slice(-800),
		harvestedArtifacts: worker.harvestedArtifacts ?? [],
	};
	return row;
}

function compactMergeForOutput(merge, mode) {
	if (mode !== "llm-run" || !merge) return merge;
	return {
		kind: merge.kind,
		schemaVersion: merge.schemaVersion,
		StructuredSubagentMergeV1: merge.StructuredSubagentMergeV1,
		generatedAt: merge.generatedAt,
		runId: merge.runId,
		evidenceRoot: merge.evidenceRoot,
		workerCount: merge.workerCount,
		passedWorkers: merge.passedWorkers,
		failedWorkers: merge.failedWorkers ?? [],
		promotedClaimCount: merge.promotedClaims?.length ?? 0,
		observationCount: merge.observations?.length ?? 0,
		blockerCount: merge.blockerRows?.length ?? 0,
		proofPromotionReady: merge.proofPromotionReady,
		routeProofReady: merge.routeProofReady,
		routeCoverageReady: merge.routeCoverageReady,
		routeCoverage: merge.routeCoverage
			? {
					routeCount: merge.routeCoverage.routeCount,
					coveredCount: merge.routeCoverage.coveredCount,
					uncoveredCount: merge.routeCoverage.uncoveredCount,
					covered: (merge.routeCoverage.covered ?? []).map((route) => ({ id: route.id, domain: route.domain })),
					uncovered: (merge.routeCoverage.uncovered ?? []).map((route) => ({ id: route.id, domain: route.domain })),
					complete: merge.routeCoverage.complete,
				}
			: undefined,
		missingProofRoutes: (merge.missingProofRoutes ?? []).map((route) => ({ id: route.id ?? route.routeId, domain: route.domain })),
		mergeVerification: merge.mergeVerification
			? {
					proofReady: merge.mergeVerification.proofReady,
					finalPromotionReady: merge.mergeVerification.finalPromotionReady,
					stats: merge.mergeVerification.stats,
					blockers: merge.mergeVerification.promotionReport?.blockers ?? [],
				}
			: undefined,
		ok: merge.ok,
		finalPromotionReady: merge.finalPromotionReady,
		narrativeOnlyBlocked: merge.narrativeOnlyBlocked,
		mergeDigest: merge.mergeDigest,
	};
}

function buildRunReport({ plan, rows, tempRoot, mode }) {
	const evidenceRoot = evidenceRootFor(plan.runId);
	const reportPlan = compactPlanForReport(plan, mode);
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
		toolsMode: plan.toolsMode ?? "legacy",
		evidenceRoot,
		tempRoot,
		planPath: join(evidenceRoot, "plan.json"),
		promptTemplateSha256: mode === "llm-run" ? sha256(plan.operatorGuidance) : undefined,
		plan: reportPlan,
		workersReport: rows.map((worker) => compactWorkerReportForReport(worker, mode)),
		mergeDigest: sha256(rows.map((worker) => `${worker.workerId}:${worker.role}:${worker.status}:${worker.stdoutSha256}`).join("\n")),
		ok: rows.every((worker) => worker.status === "pass"),
	};
	atomicWriteFile(join(evidenceRoot, "report.json"), `${JSON.stringify(report, null, 2)}\n`, 0o600);
	return report;
}

function listRuns() {
	return swarmCatalog.listRuns();
}

function resolveRunRef(ref = "latest") {
	return swarmCatalog.resolveRunRef(ref);
}

function runRefErrorReport(resolution, kind) {
	return {
		kind,
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: false,
		error: resolution.error,
		message: resolution.message,
		ref: resolution.ref,
		matches: resolution.matches,
		candidateRefs: resolution.candidateRefs,
		swarmsRoot,
		catalogRoots: {
			cli: swarmsRoot,
			ts: join(sourceAgentDir, "recon", "evidence", "swarms"),
		},
	};
}

function buildStatus(ref) {
	const resolution = resolveRunRef(ref);
	if (!resolution.ok) return runRefErrorReport(resolution, "repi-swarm-status-report");
	const runRef = resolution.run;
	if (runRef.engine === "ts") {
		return {
			kind: "repi-swarm-status-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: runRef.ok,
			engine: runRef.engine,
			runRef: serializeSwarmRunRef(runRef),
			runId: runRef.runId,
			evidenceRoot: runRef.evidenceRoot,
			artifactPath: runRef.paths.artifact,
			state: runRef.state,
			target: runRef.target,
			workers: runRef.workers ?? [],
			merge: runRef.merge,
		};
	}
	const evidenceRoot = runRef.evidenceRoot;
	const report = existsSync(join(evidenceRoot, "report.json")) ? readJson(join(evidenceRoot, "report.json")) : undefined;
	const plan = existsSync(join(evidenceRoot, "plan.json")) ? readJson(join(evidenceRoot, "plan.json")) : report?.plan;
	const merge = existsSync(join(evidenceRoot, "merge-report.json")) ? readJson(join(evidenceRoot, "merge-report.json")) : undefined;
	return {
		kind: "repi-swarm-status-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: runRef.ok,
		engine: runRef.engine,
		runRef: serializeSwarmRunRef(runRef),
		runId: merge?.runId ?? report?.runId ?? plan?.runId ?? basename(evidenceRoot),
		evidenceRoot,
		state: runRef.state,
		target: merge?.target ?? report?.target ?? plan?.target,
		provider: merge?.provider ?? report?.provider ?? plan?.provider,
		model: merge?.model ?? report?.model ?? plan?.model,
		workers: report?.workersReport?.map((worker) => ({ workerId: worker.workerId, role: worker.role, status: worker.status, exit: worker.exit, ms: worker.ms })) ?? plan?.workerPackets?.map((worker) => ({ workerId: worker.workerId, role: worker.role, status: "planned" })) ?? [],
		merge: merge
			? {
					ok: merge.ok,
					promotedClaims: merge.promotedClaims?.length ?? 0,
					routeProofReady: merge.routeProofReady,
					missingProofRoutes: merge.missingProofRoutes?.map((route) => route.id ?? route.routeId).filter(Boolean) ?? [],
					narrativeOnlyBlocked: merge.narrativeOnlyBlocked,
					mergeVerificationProofReady: Boolean(merge.mergeVerification?.proofReady),
					mergeVerificationBlockers: merge.mergeVerification?.promotionReport?.blockers ?? [],
					mergeDigest: merge.mergeDigest,
				}
			: undefined,
	};
}

function buildList() {
	const runs = listRuns().map(serializeSwarmRunRef);
	return {
		kind: "repi-swarm-list-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: true,
		count: runs.length,
		runs,
	};
}

function buildResolve(ref) {
	const resolution = resolveRunRef(ref);
	if (!resolution.ok) return runRefErrorReport(resolution, "repi-swarm-resolve-report");
	return {
		kind: "repi-swarm-resolve-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: true,
		ref: resolution.ref,
		run: serializeSwarmRunRef(resolution.run),
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
	if (merge?.mergeVerification) console.log(`mergeVerification=proofReady:${merge.mergeVerification.proofReady} workers:${merge.mergeVerification.stats?.verifiedWorkers ?? 0} routes:${merge.mergeVerification.stats?.verifiedRoutes ?? 0}`);
	if (report.mergeFailureReason) console.log(`mergeFailureReason=${report.mergeFailureReason}`);
	console.log(`evidence=${report.evidenceRoot}`);
	console.log(`verdict=${report.ok ? "pass" : "fail"}`);
}

function printStatus(status) {
	if (status.error) {
		console.error(`${status.error}: ${status.message}`);
		return;
	}
	console.log("REPI Swarm Status");
	console.log(`runId=${status.runId} state=${status.state} target=${status.target ?? "none"}`);
	console.log(`provider=${status.provider ?? "default"} model=${status.model ?? "default"}`);
	for (const worker of status.workers) console.log(`- worker-${worker.workerId}/${worker.role ?? "worker"} status=${worker.status} exit=${worker.exit ?? "n/a"} ms=${worker.ms ?? "n/a"}`);
	if (status.merge) console.log(`merge ok=${status.merge.ok} promotedClaims=${status.merge.promotedClaims} routeProofReady=${status.merge.routeProofReady} missingProofRoutes=${status.merge.missingProofRoutes?.join(",") ?? ""} narrativeOnlyBlocked=${status.merge.narrativeOnlyBlocked} mergeVerificationProofReady=${status.merge.mergeVerificationProofReady}`);
	console.log(`evidence=${status.evidenceRoot}`);
}

function printList(report) {
	console.log("REPI Swarm Runs");
	for (const run of report.runs) {
		console.log(`${run.engine}:${run.runId} state=${run.state} target=${run.target ?? "none"} evidence=${run.artifactPath ?? run.evidenceRoot}`);
	}
	console.log(`count=${report.count}`);
}

function printResolve(report) {
	if (!report.ok) {
		console.error(`${report.error}: ${report.message}`);
		return;
	}
	const run = report.run;
	console.log(`engine=${run.engine} runId=${run.runId} state=${run.state} target=${run.target ?? "none"}`);
	console.log(`evidence=${run.artifactPath ?? run.evidenceRoot}`);
}

function printMerge(merge) {
	console.log("REPI Swarm Merge");
	console.log(`runId=${merge.runId} ok=${merge.ok} finalPromotionReady=${merge.finalPromotionReady}`);
	console.log(`workers=${merge.workerCount} passed=${merge.passedWorkers} promotedClaims=${merge.promotedClaims.length} observations=${merge.observations.length} blockers=${merge.blockerRows.length}`);
	if (Array.isArray(merge.proofChecklists)) {
		const ready = merge.proofChecklists.filter((row) => row.proofReady).length;
		console.log(`proofChecklists=${ready}/${merge.proofChecklists.length} ready`);
	}
	if (Array.isArray(merge.proofReadyPromotedClaims)) console.log(`proofReadyPromotedClaims=${merge.proofReadyPromotedClaims.length} proofPromotionReady=${merge.proofPromotionReady}`);
	if (merge.routeCoverage) console.log(`routeCoverage=${merge.routeCoverage.coveredCount}/${merge.routeCoverage.routeCount} covered uncovered=${merge.routeCoverage.uncoveredCount}`);
	if (Array.isArray(merge.routeReadinessRows)) console.log(`routeProofReady=${merge.routeProofReady} readyRoutes=${merge.proofReadyRouteIds?.length ?? 0}/${merge.routeReadinessRows.length} missing=${merge.missingProofRoutes?.map((route) => route.id).join(",") ?? ""}`);
	if (merge.mergeVerification) console.log(`mergeVerificationProofReady=${merge.mergeVerification.proofReady} blockers=${merge.mergeVerification.promotionReport?.blockers?.join(",") ?? ""}`);
	for (const claim of merge.promotedClaims.slice(0, 8)) console.log(`- claim=${claim.claimId} worker=${claim.workerId}/${claim.role} conf=${claim.confidence} ${claim.statement}`);
	if (merge.narrativeOnlyBlocked) console.log("narrativeOnlyBlocked=true: worker output lacked structured evidence-bearing claims; keep as observations.");
	console.log(`evidence=${merge.evidenceRoot}`);
	console.log(`mergeDigest=${merge.mergeDigest}`);
}

function writeStdout(text) {
	return new Promise((resolveWrite) => {
		process.stdout.write(text, () => resolveWrite());
	});
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
	if (json) await writeStdout(`${JSON.stringify({ kind: "repi-swarm-plan-report", schemaVersion: 1, ok: true, evidenceRoot, plan }, null, 2)}\n`);
	else printPlan(plan, evidenceRoot);
	process.exit(0);
}

if (command === "status") {
	const status = buildStatus(positionalTarget(argv));
	if (json) await writeStdout(`${JSON.stringify(status, null, 2)}\n`);
	else printStatus(status);
	process.exit(status.ok ? 0 : 1);
}

if (command === "list") {
	const report = buildList();
	if (json) await writeStdout(`${JSON.stringify(report, null, 2)}\n`);
	else printList(report);
	process.exit(0);
}

if (command === "resolve") {
	const report = buildResolve(positionalTarget(argv));
	if (json) await writeStdout(`${JSON.stringify(report, null, 2)}\n`);
	else printResolve(report);
	process.exit(report.ok ? 0 : 1);
}

if (command === "merge") {
	const resolution = resolveRunRef(positionalTarget(argv));
	if (!resolution.ok) {
		const failure = runRefErrorReport(resolution, "repi-swarm-merge-report");
		if (json) await writeStdout(`${JSON.stringify(failure, null, 2)}\n`);
		else console.error(`${failure.error}: ${failure.message}`);
		process.exit(1);
	}
	if (resolution.run.engine !== "cli") {
		const unsupported = {
			kind: "repi-swarm-merge-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: "cross-engine-merge-unsupported",
			message: "TS runtime swarm artifacts are read-only here; run `re_swarm merge` in the coding-agent runtime",
			engine: resolution.run.engine,
			runId: resolution.run.runId,
			evidenceRoot: resolution.run.evidenceRoot,
			artifactPath: resolution.run.paths.artifact,
			runRef: serializeSwarmRunRef(resolution.run),
		};
		if (json) await writeStdout(`${JSON.stringify(unsupported, null, 2)}\n`);
		else console.error(`${unsupported.error}: ${unsupported.message}`);
		process.exit(1);
	}
	const evidenceRoot = resolution.run.evidenceRoot;
	const merge = buildMergeReport(evidenceRoot);
	if (json) await writeStdout(`${JSON.stringify(merge, null, 2)}\n`);
	else printMerge(merge);
	process.exit(merge.ok ? 0 : 1);
}

const mode = command === "run" ? "run" : "llm-run";
const runId = makeRunId(flagValue(argv, "--target") ?? positionalTarget(argv) ?? "local-selfcheck");
const plan = mode === "llm-run" ? (() => {
	const target = flagValue(argv, "--target") ?? positionalTarget(argv) ?? "local-selfcheck";
	const timeoutMs = parseIntFlag(argv, "--timeout-ms", Number(process.env.REPI_SWARM_LLM_TIMEOUT_MS ?? 210000), 5000, 30 * 60 * 1000);
	const llmRunToolsMode = argv.includes("--no-tools") || !hasFlag(argv, "--tools") ? "disabled" : "explicit";
	const llmRunTools = llmRunToolsMode === "explicit" ? flagValue(argv, "--tools", "") : undefined;
	const baseArgs = [target, "--timeout-ms", String(timeoutMs)];
	if (hasFlag(argv, ["--workers", "-w"])) baseArgs.push("--workers", String(parseIntFlag(argv, ["--workers", "-w"], 3, 1, 16)));
	if (hasFlag(argv, "--max-concurrency")) baseArgs.push("--max-concurrency", String(parseIntFlag(argv, "--max-concurrency", 3, 1, 16)));
	if (flagValue(argv, "--provider")) baseArgs.push("--provider", flagValue(argv, "--provider"));
	if (flagValue(argv, "--model")) baseArgs.push("--model", flagValue(argv, "--model"));
	if (flagValue(argv, "--route")) baseArgs.push("--route", flagValue(argv, "--route"));
	if (flagValue(argv, "--tools") !== undefined) baseArgs.push("--tools", flagValue(argv, "--tools", "") || "");
	const basePlan = buildSwarmPlan(baseArgs, { runId });
	return {
		...basePlan,
		timeoutMs,
		toolsMode: llmRunToolsMode,
		toolsDisabled: llmRunToolsMode === "disabled",
		workerPackets: basePlan.workerPackets.map((packet, index) => ({
			...packet,
			workerId: index + 1,
			id: `worker-${index + 1}`,
			role: "worker",
			objective: "generic parallel llm worker",
			tools: llmRunTools,
			toolsMode: llmRunToolsMode,
			agentToolchain: agentToolchainFor(packet.route || { id: "reverse-pentest-general" }, llmRunTools, llmRunToolsMode),
			dependencies: [],
			evidenceContract: ["non-empty stdout"],
			mergeKeys: ["worker"],
			limits: { timeoutMs, maxOutputChars: DEFAULT_MAX_OUTPUT_CHARS },
		})),
		operatorGuidance: flagValue(argv, "--prompt") ?? `You are REPI parallel worker {id}. Target/task: {target}. Route: {routeDomain} ({routeId}); workflow={routeWorkflow}. Use proofKit={proofKit}. Use commandPalette={commandPalette}. Use techniqueHints={techniqueHints}. Work independently and return concise JSON with workerId, findings, evidence, blockers, nextCommands. Do not mention other workers.`,
	};
})() : buildSwarmPlan(argv, { runId });
const evidenceRoot = writePlan(plan);
const promptTemplate = mode === "llm-run" ? plan.operatorGuidance : undefined;
const expectTemplate = flagValue(argv, "--expect");
const { rows, tempRoot } = await runPool(plan, promptTemplate, expectTemplate, mode, keepProfiles);
const report = buildRunReport({ plan, rows, tempRoot, mode });
const merge = buildMergeReport(evidenceRoot);
if (mode === "run" && (!merge.finalPromotionReady || rows.some((worker) => worker.status !== "pass"))) {
	const failedWorkers = rows.filter((worker) => worker.status !== "pass");
	report.ok = false;
	report.mergeFailureReason = failedWorkers.length
		? failedWorkers.some((worker) => worker.timedOut)
			? "one or more workers timed out before producing promoted evidence"
			: "one or more workers failed before producing promoted evidence"
		: merge.routeCoverageReady === false
			? "route coverage incomplete; run generated route repair commands"
			: merge.routeProofReady === false
				? `route proof incomplete; missing proof-ready route(s): ${(merge.missingProofRoutes ?? []).map((route) => route.id ?? route.routeId ?? route.domain).filter(Boolean).join(", ") || "unknown"}`
			: merge.narrativeOnlyBlocked
				? "narrative-only worker output lacked structured evidence-bearing claims"
				: !merge.proofPromotionReady
					? "no proof-ready promoted claims after proof checklist"
					: "no promoted evidence-bearing claims after structured merge";
	atomicWriteFile(join(evidenceRoot, "report.json"), `${JSON.stringify(report, null, 2)}\n`, 0o600);
}
if (json) await writeStdout(`${JSON.stringify({ ...report, merge: compactMergeForOutput(merge, mode) }, null, 2)}\n`);
else printRun(report, merge);
process.exitCode = report.ok ? 0 : 1;
