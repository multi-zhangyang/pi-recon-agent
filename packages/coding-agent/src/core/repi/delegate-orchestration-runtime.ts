import { join } from "node:path";
import type { ArtifactScopeFilterOptions } from "./artifact-scope.ts";
import type { CampaignOperationRuntime, OperationStep } from "./campaign-operation-runtime.ts";
import type { EvidenceRecord } from "./evidence.ts";
import {
	type MissionCheckpointStatus,
	type MissionState,
	missionOperatorDirective,
	readCurrentMission,
} from "./mission.ts";
import type { createReconLaneRuntime } from "./recon-lane-runtime.ts";
import { ensureReconStorage } from "./resources.ts";
import { evidenceDelegationsDir, readTextFile as readText, writePrivateTextFile } from "./storage.ts";
import type {
	AutonomousExecutionBudget,
	DelegateArtifact,
	DelegatePacket,
	DelegateWorker,
} from "./swarm-runtime-types.ts";
import type { SwarmSupervisorRuntime } from "./swarm-supervisor-runtime.ts";
import { extractRepiTaskTarget, sanitizeTargetForCommand, shellQuote } from "./target.ts";
import { slug, truncateMiddle } from "./text.ts";

type CampaignOperationBoundary = Pick<CampaignOperationRuntime, "latestOrBuildOperation">;
type SupervisorBoundary = Pick<SwarmSupervisorRuntime, "latestSupervisorArtifactPath" | "parseSupervisorArtifact">;
type ReconLaneRuntime = ReturnType<typeof createReconLaneRuntime>;
type LaneBoundary = Pick<ReconLaneRuntime, "activeLane">;

type AppendEvidence = (
	record: Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number },
) => EvidenceRecord;

export type DelegateOrchestrationRuntimeDependencies = CampaignOperationBoundary &
	SupervisorBoundary &
	LaneBoundary & {
		latestScopedMarkdownArtifact: (
			kind: string,
			dir: string,
			options?: ArtifactScopeFilterOptions,
		) => string | undefined;
		operatorCommandConcrete: (command: string, target?: string) => { command: string; blocked?: string };
		appendEvidence: AppendEvidence;
		updateMissionCheckpoint: (name: string, status: MissionCheckpointStatus, note?: string) => MissionState;
	};

export function createDelegateOrchestrationRuntime(dependencies: DelegateOrchestrationRuntimeDependencies) {
	const {
		latestScopedMarkdownArtifact,
		latestOrBuildOperation,
		latestSupervisorArtifactPath,
		parseSupervisorArtifact,
		operatorCommandConcrete,
		activeLane,
		appendEvidence,
		updateMissionCheckpoint,
	} = dependencies;

	function commandTargetSuffix(target?: string): string {
		return target ? ` ${target}` : "";
	}

	function latestDelegateArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		return latestScopedMarkdownArtifact("delegation", evidenceDelegationsDir(), options);
	}

	function delegateWorkerForStep(step: OperationStep): DelegateWorker {
		const text = `${step.phase}\n${step.command}`;
		if (/web-authz|surface|state|poc|api|websocket|graphql|jwt|cookie|session|idor|bola|authz/i.test(text))
			return "web-authz";
		if (/credential|principal|kerberos|ldap|ntlm|ticket|hash|identity/i.test(text)) return "identity";
		if (/cloud|container|k8s|kubernetes|metadata|serviceaccount|iam|rbac|privilege/i.test(text)) return "cloud";
		if (/mobile|android|ios|apk|ipa|frida|objection|smali|jni|objc|swift|emulator/i.test(text))
			return "mobile-runtime";
		if (/pwn|exploit|primitive|mitigation|rop|heap|overflow|shellcode|pwntools|flake|bundle/i.test(text))
			return "pwn-exploit";
		if (/native|elf|pe|macho|binary|gdb|lldb|checksec|r2|radare|ghidra|ida|symbol|breakpoint|loader|libc/i.test(text))
			return "native-runtime";
		if (/firmware|pcap|dfir|forensic|rootfs|tshark|binwalk|extract|filesystem|emulate|timeline|decode/i.test(text))
			return "firmware-dfir";
		if (/agentsec|agent|prompt|tool-boundary|memory|injection|delegation|mcp|rag/i.test(text)) return "agentsec";
		if (/malware|ioc|yara|capa|floss|static-config|behavior|c2/i.test(text)) return "malware";
		if (/report|complete|scaffold|audit|writeup/i.test(text)) return "reporting";
		return "general";
	}

	function delegateObjective(worker: DelegateWorker): string {
		const objectives: Record<DelegateWorker, string> = {
			"web-authz": "证明 Web/API/WS 的认证、授权、对象所有权、状态机和 replay 边界",
			identity: "验证 credential/principal/ticket/hash/token/serviceaccount 的可用性、范围和负控",
			cloud: "证明云/K8s/container runtime config、metadata、IAM/RBAC 与最小 privilege edge",
			"mobile-runtime": "用 Frida/ADB/objection/静态清单证明移动端 runtime、hook 点、签名/加密与 native bridge",
			"native-runtime": "用 GDB/LLDB/r2/checksec 证明 native binary 的 loader/libc、符号、断点、trace 与控制流",
			"pwn-exploit": "把 binary/exploit phase 推进到 primitive、offset/leak、payload 和 replay reliability",
			"firmware-dfir": "组织 firmware/rootfs/PCAP/DFIR artifact、flow timeline、secret/config 和 transform chain",
			agentsec: "映射 prompt/tool/memory/RAG/MCP/sub-agent 边界并生成 injection replay 证据",
			malware: "提取 malware static/behavior/config/IOC 证据并沉淀可复用 rule/report",
			reporting: "合并证据、图谱、复现命令、失败路线和完成审计",
			general: "执行未归类 operation steps 并把证据回写到 ledger/checkpoints",
		};
		return objectives[worker];
	}

	function delegateEvidenceContract(worker: DelegateWorker): string[] {
		const contracts: Record<DelegateWorker, string[]> = {
			"web-authz": [
				"request/response or WS frame",
				"auth/session/storage diff",
				"object ownership or state transition proof",
				"replay command",
			],
			identity: ["credential inventory", "usable credential proof", "principal/scope", "negative control"],
			cloud: ["runtime config", "identity/metadata response", "IAM/RBAC edge", "least-privilege command proof"],
			"mobile-runtime": [
				"package/app inventory",
				"Frida/ADB hook transcript",
				"crypto/signature/native bridge trace",
				"device/emulator replay command",
			],
			"native-runtime": [
				"binary hash/header/mitigation fingerprint",
				"loader/libc/symbol map",
				"GDB/LLDB/r2 trace",
				"breakpoint or local replay command",
			],
			"pwn-exploit": [
				"mitigation fingerprint",
				"crash/control primitive",
				"offset/leak/gadget",
				"local verifier or replay matrix",
			],
			"firmware-dfir": [
				"image/pcap/sample hash",
				"extracted artifact path",
				"flow/config/IOC timeline",
				"decode/transform chain",
			],
			agentsec: [
				"prompt/resource surface",
				"tool boundary proof",
				"memory/RAG poisoning path",
				"injection replay transcript",
			],
			malware: [
				"sample hash/magic/entropy",
				"YARA/capa/FLOSS or strings",
				"IOC/config extraction",
				"behavior trace",
			],
			reporting: ["attack/campaign/operation artifacts", "evidence ledger", "completion audit", "report scaffold"],
			general: ["command output", "artifact path", "verification command", "ledger update"],
		};
		return contracts[worker];
	}

	function delegateTools(worker: DelegateWorker): string[] {
		const tools: Record<DelegateWorker, string[]> = {
			"web-authz": ["curl", "jq", "playwright", "mitmproxy", "ffuf"],
			identity: ["ldapsearch", "nxc", "impacket-secretsdump", "certipy", "bloodhound-python"],
			cloud: ["docker", "kubectl", "aws", "az", "gcloud", "jq"],
			"mobile-runtime": ["adb", "frida", "objection", "apktool", "jadx", "r2"],
			"native-runtime": ["file", "checksec", "gdb", "lldb", "r2", "objdump", "readelf"],
			"pwn-exploit": ["file", "checksec", "gdb", "r2", "ROPgadget", "python3"],
			"firmware-dfir": ["binwalk", "unsquashfs", "tshark", "capinfos", "foremost", "python3"],
			agentsec: ["rg", "jq", "node", "python3"],
			malware: ["file", "sha256sum", "strings", "yara", "capa", "floss"],
			reporting: ["rg", "python3"],
			general: ["rg", "python3", "jq"],
		};
		return tools[worker];
	}

	function isDelegateWorker(value: string): value is DelegateWorker {
		return [
			"web-authz",
			"identity",
			"cloud",
			"mobile-runtime",
			"native-runtime",
			"pwn-exploit",
			"firmware-dfir",
			"agentsec",
			"malware",
			"reporting",
			"general",
		].includes(value);
	}

	type WorkerScoreboardEntry = {
		worker: DelegateWorker;
		packetId: string;
		verdict: string;
		score: number;
		retryBudget: number;
		failureCost: number;
		next: string;
		raw: string;
	};

	function parseWorkerScoreboardLine(line: string): WorkerScoreboardEntry | undefined {
		const match =
			/^(?<worker>[a-z0-9-]+)\s+packet=(?<packet>\S+)\s+verdict=(?<verdict>\w+)\s+score=(?<score>\d+)\s+retry_budget=(?<retry>\d+)\s+failure_cost=(?<cost>\d+)\s+next=(?<next>.*)$/i.exec(
				line.trim().replace(/^- /, ""),
			);
		if (!match?.groups || !isDelegateWorker(match.groups.worker)) return undefined;
		return {
			worker: match.groups.worker,
			packetId: match.groups.packet,
			verdict: match.groups.verdict,
			score: Number(match.groups.score),
			retryBudget: Number(match.groups.retry),
			failureCost: Number(match.groups.cost),
			next: match.groups.next.trim(),
			raw: line.trim().replace(/^- /, ""),
		};
	}

	function latestWorkerScoreboard(): { path?: string; lines: string[]; entries: WorkerScoreboardEntry[] } {
		const path = latestSupervisorArtifactPath();
		const supervisor = path ? parseSupervisorArtifact(path) : undefined;
		const lines = supervisor?.workerScoreboard ?? [];
		return {
			path,
			lines,
			entries: lines
				.map(parseWorkerScoreboardLine)
				.filter((entry): entry is WorkerScoreboardEntry => Boolean(entry)),
		};
	}

	function workerAdaptiveRoutingHints(entries: WorkerScoreboardEntry[], target?: string): string[] {
		const suffix = commandTargetSuffix(target);
		return entries
			.flatMap((entry) => {
				if (entry.score >= 80 && /pass/i.test(entry.verdict)) return [];
				if (entry.score >= 60 && /watch/i.test(entry.verdict))
					return [
						`watch:${entry.worker} score=${entry.score} -> collect one more runtime/traffic/artifact anchor before expansion; command=re_swarm run${suffix} 1 1`,
					];
				const tools = delegateTools(entry.worker).slice(0, 5).join(" ");
				return [
					`repair:${entry.worker} score=${entry.score} verdict=${entry.verdict} -> reroute via evidence-repair lane; commands=re_bootstrap plan ${tools} && re_delegate plan${suffix} && re_swarm run${suffix} 1 1 && re_verifier matrix`,
					`verify:${entry.worker} packet=${entry.packetId} -> require negative control + replay artifact before merge; next=${entry.next}`,
				];
			})
			.slice(0, 24);
	}

	function buildWorkerPromotionQueue(entries: WorkerScoreboardEntry[]): string[] {
		return entries
			.filter((entry) => entry.score >= 80 && /pass/i.test(entry.verdict))
			.map(
				(entry) =>
					`promote:${entry.worker} score=${entry.score} packet=${entry.packetId} -> reuse within current mission after verifier confirmation`,
			)
			.slice(0, 16);
	}

	type DispatcherFeedbackParsedRow = {
		category: string;
		status: "passed" | "failed" | "queued";
		score: number;
		command: string;
		raw: string;
	};

	function parseShellQuotedValue(value: string | undefined): string | undefined {
		if (!value) return undefined;
		return value.replace(/'\\''/g, "'");
	}

	function parseDispatcherFeedbackRow(row: string): DispatcherFeedbackParsedRow | undefined {
		if (!/dispatcher_score/i.test(row)) return undefined;
		const category = /\bcategory=([A-Za-z0-9_-]+)/i.exec(row)?.[1] ?? "unknown";
		const statusText = /\bstatus=(passed|failed|queued)\b/i.exec(row)?.[1]?.toLowerCase() ?? "queued";
		const status = (["passed", "failed", "queued"].includes(statusText) ? statusText : "queued") as
			| "passed"
			| "failed"
			| "queued";
		const score = Math.max(0, Math.min(100, Number(/\bscore=(\d+)/i.exec(row)?.[1] ?? 0)));
		const commandMatch = /\bcommand=(?:'((?:'\\''|[^'])*)'|"([^"]+)"|(\S+))/i.exec(row);
		const command =
			parseShellQuotedValue(commandMatch?.[1]) ?? commandMatch?.[2] ?? commandMatch?.[3] ?? "re_operator dispatch";
		return { category, status, score, command: command.trim(), raw: row.trim().replace(/^- /, "") };
	}

	function dispatcherFeedbackParsedRows(rows?: string[]): DispatcherFeedbackParsedRow[] {
		const source = rows ?? [];
		const seen = new Set<string>();
		return source
			.map(parseDispatcherFeedbackRow)
			.filter((row): row is DispatcherFeedbackParsedRow => Boolean(row))
			.filter((row) => {
				const key = `${row.category}:${row.status}:${row.score}:${row.command}`;
				if (seen.has(key)) return false;
				seen.add(key);
				return true;
			});
	}

	function dispatcherScoreDecayRows(rows?: string[]): string[] {
		const parsed = dispatcherFeedbackParsedRows(rows);
		return parsed
			.map((row) => {
				const decay = row.status === "passed" ? 0 : row.status === "failed" ? 30 : row.score >= 75 ? 6 : 10;
				const effective = Math.max(0, row.score - decay);
				const action =
					row.status === "passed" && row.score >= 80
						? "promote_dispatcher"
						: row.status === "failed" || effective < 40
							? "demote_dispatcher"
							: "retry_dispatcher";
				return [
					"score_decay dispatcher",
					`category=${row.category}`,
					`status=${row.status}`,
					`score=${row.score}`,
					`decay=${decay}`,
					`effective=${effective}`,
					`action=${action}`,
					`command=${shellQuote(row.command)}`,
				].join(" ");
			})
			.slice(0, 32);
	}

	function repeatedFailureDemotionRows(rows?: string[], target?: string): string[] {
		const suffix = commandTargetSuffix(target);
		const grouped = new Map<string, DispatcherFeedbackParsedRow[]>();
		for (const row of dispatcherFeedbackParsedRows(rows)) {
			const key = `${row.category}:${row.command}`;
			grouped.set(key, [...(grouped.get(key) ?? []), row]);
		}
		const demotions: string[] = [];
		for (const group of grouped.values()) {
			const latest = group[group.length - 1];
			if (!latest) continue;
			const failed = group.filter((row) => row.status === "failed").length;
			const queued = group.filter((row) => row.status === "queued").length;
			const effective = Math.max(
				0,
				latest.score - (latest.status === "failed" ? 30 : latest.status === "queued" ? 10 : 0),
			);
			if (failed === 0 && queued < 2 && effective >= 40) continue;
			demotions.push(
				[
					"demote_dispatcher repeated_failure",
					`category=${latest.category}`,
					`failed=${failed}`,
					`queued=${queued}`,
					`effective=${effective}`,
					`command=${shellQuote(latest.command)}`,
					`-> re_autofix plan${suffix} && re_operator dispatch${suffix} 1`,
				].join(" "),
			);
		}
		return Array.from(new Set(demotions)).slice(0, 24);
	}

	function highScorePromotionRows(rows?: string[]): string[] {
		const dispatcherPromotions = dispatcherFeedbackParsedRows(rows)
			.filter((row) => row.status === "passed" && row.score >= 80)
			.map((row) =>
				[
					"promote_dispatcher high_score_route",
					`category=${row.category}`,
					`score=${row.score}`,
					`command=${shellQuote(row.command)}`,
					"-> retain for this mission after verifier confirmation",
				].join(" "),
			);
		const workerPromotions = buildWorkerPromotionQueue(latestWorkerScoreboard().entries).map(
			(row) => `promote_worker high_score_route ${row}`,
		);
		return Array.from(new Set([...dispatcherPromotions, ...workerPromotions])).slice(0, 24);
	}

	function workerScoreDemotionRows(target: string | undefined): string[] {
		const suffix = commandTargetSuffix(target);
		return latestWorkerScoreboard()
			.entries.filter((entry) => entry.score < 50 || /blocked|repair/i.test(entry.verdict))
			.map((entry) =>
				[
					"demote_worker repeated_low_score",
					`worker=${entry.worker}`,
					`verdict=${entry.verdict}`,
					`score=${entry.score}`,
					`packet=${entry.packetId}`,
					`-> re_delegate plan${suffix} && re_swarm run${suffix} 1 1 && re_supervisor repair${suffix}`,
				].join(" "),
			)
			.slice(0, 16);
	}

	function autonomousLaneDemotionRows(params: {
		dispatcherDemotions: string[];
		workerDemotions: string[];
		target?: string;
	}): string[] {
		const mission = readCurrentMission();
		const active = mission ? activeLane(mission) : undefined;
		if (!mission || !active) return [];
		if (active.name === "autonomous-dispatcher-repair") return [];
		const pressure = params.dispatcherDemotions.length + params.workerDemotions.length;
		const repeatedDispatcher = params.dispatcherDemotions.length;
		const repeatedWorker = params.workerDemotions.length;
		if (pressure < 3 && repeatedDispatcher < 3 && repeatedWorker < 3) return [];
		const directive = missionOperatorDirective(mission) ?? mission.task;
		const suffix = commandTargetSuffix(
			params.target ?? extractRepiTaskTarget(directive) ?? sanitizeTargetForCommand(directive),
		);
		return [
			[
				"demote_lane autonomous_budget",
				`active=${active.name}`,
				`pressure=${pressure}`,
				`dispatcher_repeats=${repeatedDispatcher}`,
				`worker_repeats=${repeatedWorker}`,
				"target_lane=autonomous-dispatcher-repair",
				`-> re_lane plan autonomous-dispatcher-repair${suffix} && re_operator dispatch${suffix} 1 && re_proof_loop run${suffix} 4 2`,
			].join(" "),
		];
	}

	function autonomousExecutionBudget(target?: string, rows?: string[]): AutonomousExecutionBudget {
		const scoreboardRows = rows ?? [];
		const scoreDecay = dispatcherScoreDecayRows(scoreboardRows);
		const dispatcherDemotions = repeatedFailureDemotionRows(scoreboardRows, target);
		const workerDemotions = workerScoreDemotionRows(target);
		const laneDemotions = autonomousLaneDemotionRows({ dispatcherDemotions, workerDemotions, target });
		const demotionRules = Array.from(new Set([...dispatcherDemotions, ...workerDemotions, ...laneDemotions])).slice(
			0,
			40,
		);
		const promotionRules = highScorePromotionRows(scoreboardRows);
		const queuedPressure = dispatcherFeedbackParsedRows(scoreboardRows).filter(
			(row) => row.status === "queued",
		).length;
		const failurePressure = demotionRules.length;
		const promotionPressure = promotionRules.length;
		const maxTurns = Math.max(3, Math.min(9, 5 + Math.min(2, promotionPressure) - Math.min(3, failurePressure)));
		const maxDispatch = Math.max(
			1,
			Math.min(6, 2 + Math.min(2, promotionPressure) - Math.min(3, queuedPressure + failurePressure)),
		);
		const maxProofLoops = Math.max(
			1,
			Math.min(5, 2 + (promotionPressure > 0 ? 1 : 0) - (failurePressure > 3 ? 1 : 0)),
		);
		const maxWorkerRetries = Math.max(1, Math.min(4, 2 + (failurePressure > 0 ? 1 : 0)));
		const suffix = commandTargetSuffix(target);
		const nextActions = Array.from(
			new Set([
				...(laneDemotions.length
					? [
							`re_lane plan autonomous-dispatcher-repair${suffix}`,
							`re_lane run-auto autonomous-dispatcher-repair 2`,
						]
					: []),
				...(demotionRules.length ? [`re_autofix plan${suffix}`] : []),
				`re_operator dispatch${suffix} ${Math.min(3, maxDispatch)}`,
				`re_proof_loop run${suffix} ${Math.min(6, maxProofLoops + 2)} 2`,
			]),
		).slice(0, 14);
		return {
			maxTurns,
			maxDispatch,
			maxProofLoops,
			maxWorkerRetries,
			scoreDecay,
			demotionRules,
			laneDemotions,
			workerDemotions,
			dispatcherDemotions,
			promotionRules,
			nextActions,
		};
	}

	function autonomousBudgetLines(budget: AutonomousExecutionBudget | undefined): string[] {
		const current = budget ?? autonomousExecutionBudget();
		return [
			`max_turns=${current.maxTurns}`,
			`max_dispatch=${current.maxDispatch}`,
			`max_proof_loops=${current.maxProofLoops}`,
			`max_worker_retries=${current.maxWorkerRetries}`,
			`score_decay=${current.scoreDecay.length}`,
			`demotions=${current.demotionRules.length}`,
			`lane_demotions=${current.laneDemotions.length}`,
			`worker_demotions=${current.workerDemotions.length}`,
			`dispatcher_demotions=${current.dispatcherDemotions.length}`,
			`promotions=${current.promotionRules.length}`,
			...(current.nextActions.length ? current.nextActions.map((item) => `next=${item}`) : ["next=none"]),
		];
	}

	function adaptiveToolsForWorker(worker: DelegateWorker, entries: WorkerScoreboardEntry[]): string[] {
		const entry = entries.find((item) => item.worker === worker);
		if (!entry || entry.score >= 80) return [];
		const extra: Record<DelegateWorker, string[]> = {
			"web-authz": ["re_web_authz_state", "playwright", "curl"],
			identity: ["re_verifier", "jq", "python3"],
			cloud: ["kubectl", "aws", "jq"],
			"mobile-runtime": ["frida", "adb", "jadx"],
			"native-runtime": ["gdb", "r2", "readelf"],
			"pwn-exploit": ["gdb", "python3", "ROPgadget"],
			"firmware-dfir": ["binwalk", "tshark", "python3"],
			agentsec: ["rg", "jq", "python3"],
			malware: ["yara", "capa", "strings"],
			reporting: ["re_compiler", "re_complete", "python3"],
			general: ["re_verifier", "re_replayer", "python3"],
		};
		return extra[worker];
	}

	function buildDelegate(options: { target?: string; task?: string; mode?: "plan" | "merge" } = {}): DelegateArtifact {
		ensureReconStorage();
		const { operation, path: operationArtifact } = latestOrBuildOperation(options);
		const scoreboard = latestWorkerScoreboard();
		const target = operation.target ?? options.target;
		const autonomousBudget = autonomousExecutionBudget(target);
		const adaptiveRoutingHints = Array.from(
			new Set([
				...workerAdaptiveRoutingHints(scoreboard.entries, target),
				...autonomousBudget.scoreDecay.slice(0, 8),
			]),
		).slice(0, 32);
		const workerPromotionQueue = Array.from(
			new Set([...buildWorkerPromotionQueue(scoreboard.entries), ...autonomousBudget.promotionRules]),
		).slice(0, 24);
		const groups = new Map<DelegateWorker, OperationStep[]>();
		for (const step of operation.steps) {
			const worker = delegateWorkerForStep(step);
			groups.set(worker, [...(groups.get(worker) ?? []), step]);
		}
		const packets: DelegatePacket[] = [...groups.entries()].map(([worker, steps], index) => {
			const status = steps.every((step) => step.status === "done")
				? "done"
				: steps.some((step) => step.status === "ready")
					? "ready"
					: "blocked";
			const phases = Array.from(new Set(steps.map((step) => step.phase)));
			const sourceArtifacts = Array.from(new Set(steps.flatMap((step) => step.sourceArtifacts))).slice(0, 16);
			return {
				id: `worker:${index + 1}:${worker}`,
				worker,
				objective: delegateObjective(worker),
				status,
				phases,
				steps,
				evidenceContract: Array.from(
					new Set([
						...delegateEvidenceContract(worker),
						...(scoreboard.entries.some((entry) => entry.worker === worker && entry.score < 80)
							? ["adaptive worker score closure", "negative control or replay artifact"]
							: []),
					]),
				).slice(0, 8),
				recommendedTools: Array.from(
					new Set([...delegateTools(worker), ...adaptiveToolsForWorker(worker, scoreboard.entries)]),
				).slice(0, 12),
				handoffPrompt: [
					`worker=${worker}`,
					`objective=${delegateObjective(worker)}`,
					`target=${target ?? "<target>"}`,
					`evidence_contract=${delegateEvidenceContract(worker).join(" | ")}`,
					`adaptive_score=${scoreboard.entries.find((entry) => entry.worker === worker)?.score ?? "none"}`,
					`adaptive_route=${
						adaptiveRoutingHints.find((hint) => hint.includes(`:${worker} `) || hint.includes(`:${worker}:`)) ??
						workerPromotionQueue.find((hint) => hint.includes(`:${worker} `)) ??
						"none"
					}`,
					`next_steps=${
						steps
							.filter((step) => step.status === "ready")
							.map((step) => step.command)
							.join(" || ") || "none"
					}`,
				],
				sourceArtifacts,
			};
		});
		const gaps = Array.from(
			new Set(
				[
					...operation.blocked.map((item) => `operation: ${item}`),
					...packets
						.filter((packet) => packet.status === "blocked")
						.map((packet) => `worker blocked: ${packet.worker}`),
					...adaptiveRoutingHints.map((hint) => `adaptive routing: ${hint}`),
					...autonomousBudget.demotionRules.map((item) => `budget demotion: ${item}`),
					packets.length === 0 ? "no delegate packets generated" : undefined,
				].filter((item): item is string => Boolean(item)),
			),
		).slice(0, 24);
		const mergeQueue = [
			...packets.map((packet) => `${packet.id} ${packet.worker} status=${packet.status}`),
			...workerPromotionQueue,
			...autonomousBudget.demotionRules,
		].slice(0, 32);
		const specialistCoverage = packets.map(
			(packet) => `${packet.worker}: phases=${packet.phases.length} steps=${packet.steps.length}`,
		);
		const nextActions = Array.from(
			new Set([
				...packets
					.filter((packet) => packet.status === "ready")
					.flatMap((packet) =>
						packet.steps
							.filter((step) => step.status === "ready")
							.slice(0, 2)
							.map((step) => step.command),
					),
				...adaptiveRoutingHints
					.flatMap((hint) => hint.match(/re[-_][\w-]+(?:\s+[^\s;&]+){0,4}/gi) ?? [])
					.map((command) => operatorCommandConcrete(command, target).command),
				...workerPromotionQueue
					.flatMap((hint) => hint.match(/re[-_][\w-]+(?:\s+[^\s;&]+){0,4}/gi) ?? [])
					.map((command) => operatorCommandConcrete(command, target).command),
				...autonomousBudget.nextActions,
				"re_operation run <target> 1",
				"re_delegate merge",
			]),
		).slice(0, 16);
		return {
			timestamp: new Date().toISOString(),
			missionId: operation.missionId,
			route: operation.route,
			target,
			mode: options.mode ?? "plan",
			operationArtifact,
			packets,
			mergeQueue,
			specialistCoverage,
			workerScoreboard: scoreboard.lines.slice(0, 32),
			adaptiveRoutingHints,
			workerPromotionQueue,
			autonomousBudget,
			dispatcherScoreDecay: autonomousBudget.scoreDecay,
			repeatedFailureDemotions: autonomousBudget.demotionRules,
			highScorePromotions: autonomousBudget.promotionRules,
			gaps,
			nextActions,
			sourceArtifacts: Array.from(
				new Set([operationArtifact, scoreboard.path, ...operation.sourceArtifacts].filter(Boolean) as string[]),
			).slice(0, 32),
		};
	}

	function formatDelegate(delegate: DelegateArtifact, path?: string): string {
		return [
			"delegation_plan:",
			path ? `delegation_artifact: ${path}` : undefined,
			`timestamp: ${delegate.timestamp}`,
			`mode: ${delegate.mode}`,
			`mission_id: ${delegate.missionId ?? "none"}`,
			`route: ${delegate.route ?? "none"}`,
			`target: ${delegate.target ?? "<none>"}`,
			`operation_artifact: ${delegate.operationArtifact ?? "none"}`,
			"worker_packets:",
			...(delegate.packets.length
				? delegate.packets.flatMap((packet) => [
						`- ${packet.id} [${packet.status}] worker=${packet.worker} phases=${packet.phases.join(",") || "none"} steps=${packet.steps.length}`,
						`  objective: ${packet.objective}`,
						`  evidence_contract: ${packet.evidenceContract.join(" | ")}`,
						`  recommended_tools: ${packet.recommendedTools.join(", ")}`,
						`  handoff: ${packet.handoffPrompt.join(" ; ")}`,
					])
				: ["- none"]),
			"merge_queue:",
			...(delegate.mergeQueue.length ? delegate.mergeQueue.map((item) => `- ${item}`) : ["- none"]),
			"specialist_coverage:",
			...(delegate.specialistCoverage.length ? delegate.specialistCoverage.map((item) => `- ${item}`) : ["- none"]),
			"worker_scoreboard:",
			...(delegate.workerScoreboard?.length ? delegate.workerScoreboard.map((item) => `- ${item}`) : ["- none"]),
			"adaptive_routing_hints:",
			...(delegate.adaptiveRoutingHints?.length
				? delegate.adaptiveRoutingHints.map((item) => `- ${item}`)
				: ["- none"]),
			"worker_promotion_queue:",
			...(delegate.workerPromotionQueue?.length
				? delegate.workerPromotionQueue.map((item) => `- ${item}`)
				: ["- none"]),
			"autonomous_execution_budget:",
			...autonomousBudgetLines(delegate.autonomousBudget).map((item) => `- ${item}`),
			"dispatcher_score_decay:",
			...(delegate.dispatcherScoreDecay?.length
				? delegate.dispatcherScoreDecay.map((item) => `- ${item}`)
				: ["- none"]),
			"repeated_failure_demotions:",
			...(delegate.repeatedFailureDemotions?.length
				? delegate.repeatedFailureDemotions.map((item) => `- ${item}`)
				: ["- none"]),
			"high_score_promotions:",
			...(delegate.highScorePromotions?.length
				? delegate.highScorePromotions.map((item) => `- ${item}`)
				: ["- none"]),
			"evidence_gaps:",
			...(delegate.gaps.length ? delegate.gaps.map((item) => `- ${item}`) : ["- none"]),
			"operator_next_actions:",
			...(delegate.nextActions.length ? delegate.nextActions.map((item) => `- ${item}`) : ["- none"]),
			`next_delegate_command: ${delegate.mode === "merge" ? "re_verifier matrix" : "re_delegate merge"}`,
			"source_artifacts:",
			...(delegate.sourceArtifacts.length ? delegate.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
		]
			.filter(Boolean)
			.join("\n");
	}

	function formatDelegateSummary(delegate: DelegateArtifact, path: string): string {
		const ready = delegate.packets.filter((packet) => packet.status === "ready").length;
		const done = delegate.packets.filter((packet) => packet.status === "done").length;
		const blocked = delegate.packets.filter((packet) => packet.status === "blocked").length;
		return [
			"delegation_plan:",
			`delegation_artifact: ${path}`,
			`mode: ${delegate.mode}`,
			`mission_id: ${delegate.missionId ?? "none"}`,
			`route: ${delegate.route ?? "none"}`,
			`target: ${delegate.target ?? "<none>"}`,
			`packets: total=${delegate.packets.length} ready=${ready} done=${done} blocked=${blocked}`,
			"worker_summary:",
			...(delegate.packets.length
				? delegate.packets
						.slice(0, 10)
						.map(
							(packet) =>
								`- ${packet.worker} status=${packet.status} phases=${packet.phases.join(",") || "none"} steps=${packet.steps.length}`,
						)
				: ["- none"]),
			"key_gaps:",
			...(delegate.gaps.length
				? delegate.gaps.slice(0, 6).map((item) => `- ${truncateMiddle(item, 240)}`)
				: ["- none"]),
			"next_actions:",
			...(delegate.nextActions.length
				? delegate.nextActions.slice(0, 6).map((item) => `- ${truncateMiddle(item, 240)}`)
				: ["- none"]),
			`next_delegate_command: ${delegate.mode === "merge" ? "re_verifier matrix" : "re_delegate merge"}`,
			`full_packet_count: ${delegate.packets.length}`,
			`full_merge_queue_count: ${delegate.mergeQueue.length}`,
		].join("\n");
	}

	function parseDelegateArtifact(path: string): DelegateArtifact | undefined {
		const json = /## JSON\s+```json\s+([\s\S]*?)\s+```/i.exec(readText(path))?.[1];
		if (!json) return undefined;
		try {
			return JSON.parse(json) as DelegateArtifact;
		} catch {
			return undefined;
		}
	}

	function writeDelegateArtifact(delegate: DelegateArtifact): string {
		ensureReconStorage();
		const path = join(
			evidenceDelegationsDir(),
			`${delegate.timestamp.replace(/[:.]/g, "-")}-${slug(delegate.route ?? "delegation")}-${delegate.mode}.md`,
		);
		writePrivateTextFile(
			path,
			[
				"# REPI Delegation Artifact",
				"",
				formatDelegate(delegate, path),
				"",
				"## Worker packets",
				"",
				...delegate.packets.map(
					(packet) =>
						`- ${packet.id} worker=${packet.worker} status=${packet.status} steps=${packet.steps.length}`,
				),
				"",
				"## JSON",
				"",
				"```json",
				JSON.stringify(delegate, null, 2),
				"```",
				"",
			].join("\n"),
		);
		appendEvidence({
			kind: "artifact",
			title: `delegation-${delegate.mode} ${delegate.missionId ?? "no-mission"}`,
			fact: `Built delegation plan with ${delegate.packets.length} worker packet(s), ${delegate.mergeQueue.length} merge item(s), ${delegate.gaps.length} gap(s), adaptive_routes=${delegate.adaptiveRoutingHints.length}, promotions=${delegate.workerPromotionQueue.length}`,
			command: `re_delegate ${delegate.mode}`,
			path,
			verify: `cat ${path}`,
			confidence: "operation/campaign specialist delegation",
		});
		updateMissionCheckpoint("delegation_packets_ready", "done", path);
		return path;
	}

	function buildDelegateOutput(
		action: "plan" | "show" | "merge" = "plan",
		options: { target?: string; task?: string } = {},
	): string {
		if (action === "show") {
			const path = latestDelegateArtifactPath();
			if (!path) return "delegation_plan:\nstatus: missing\nnext: re_delegate plan";
			const delegate = parseDelegateArtifact(path);
			return delegate
				? formatDelegateSummary(delegate, path)
				: `delegation_plan:\nstatus: unreadable_artifact\ndelegation_artifact: ${path}\nnext: re_delegate plan`;
		}
		const delegate = buildDelegate({ ...options, mode: action === "merge" ? "merge" : "plan" });
		const path = writeDelegateArtifact(delegate);
		return formatDelegateSummary(delegate, path);
	}

	return {
		latestDelegateArtifactPath,
		delegateWorkerForStep,
		delegateEvidenceContract,
		latestWorkerScoreboard,
		dispatcherScoreDecayRows,
		repeatedFailureDemotionRows,
		highScorePromotionRows,
		autonomousExecutionBudget,
		autonomousBudgetLines,
		buildDelegate,
		formatDelegate,
		writeDelegateArtifact,
		buildDelegateOutput,
	} as const;
}

export type DelegateOrchestrationRuntime = ReturnType<typeof createDelegateOrchestrationRuntime>;
