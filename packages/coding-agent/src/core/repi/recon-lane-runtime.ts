import { readdirSync } from "node:fs";
import { join } from "node:path";
import type { ExtensionAPI } from "../extensions/types.ts";
import { artifactMissionMatches, artifactScopeMissionId } from "./artifact-scope.ts";
import type { EvidenceRecord } from "./evidence.ts";
import {
	createMission,
	type MissionLane,
	type MissionLaneStatus,
	type MissionState,
	readCurrentMission,
} from "./mission.ts";
import { ensureReconStorage } from "./resources.ts";
import { REPI_GENERIC_TASK, type RoutePlan } from "./routes.ts";
import { appendSpecialistRuntimeCommands, type LaneCommand } from "./specialist-command-planner.ts";
import {
	analyzeAgentSecurityEvidence,
	analyzeBrowserXhrWsEvidence,
	analyzeCloudIdentityEvidence,
	analyzeCryptoStegoEvidence,
	analyzeExploitReliabilityEvidence,
	analyzeFirmwareIotEvidence,
	analyzeFridaGdbEvidence,
	analyzeIdentityAdEvidence,
	analyzeIosEvidence,
	analyzeJsSigningEvidence,
	analyzeMalwareEvidence,
	analyzeMemoryForensicsEvidence,
	analyzePcapDfirEvidence,
	analyzePwnPrimitiveEvidence,
	analyzeWebScannerEvidence,
	mergeSpecialistEvidenceAnalysis,
	type SpecialistEvidenceAnalysis,
} from "./specialist-evidence.ts";
import { evidenceMapsDir, evidenceRunsDir, readTextFile as readText, writePrivateTextFile } from "./storage.ts";
import { classifyRepiTarget, shellQuote } from "./target.ts";
import { interestingLines, metadataValue, sha256Text, slug, truncateMiddle, uniqueMatches } from "./text.ts";

export type LaneCommandPack = {
	missionId?: string;
	lane: string;
	route: string;
	target?: string;
	commands: LaneCommand[];
	notes: string[];
};

export type AutopilotExecutionStrategy = {
	mode: "direct" | "tool-index-missing" | "degraded" | "blocked";
	pack: LaneCommandPack;
	missingTools: string[];
	fallbacks: Array<{ label: string; missing: string[]; command: string }>;
	skipped: Array<{ label: string; missing: string[]; command: string }>;
	notes: string[];
};

export type LaneCommandPackRun = {
	text: string;
	executed: boolean;
};

export type PassiveMapContext = {
	path: string;
	timestamp: string;
	target?: string;
	signals: string[];
	candidates: string[];
};

type LaneRunAnalysis = {
	findings: string[];
	followups: LaneCommand[];
	critic: EvidenceCritic;
	nextLane?: string;
};

type EvidenceCritic = {
	score: number;
	verdict: "strong" | "partial" | "weak";
	deficits: string[];
	selfHeal: LaneCommand[];
};

type AppendEvidence = (
	record: Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number },
) => EvidenceRecord;

export type ReconLaneRuntimeDependencies = {
	writeCurrentMission: (mission: MissionState) => MissionState;
	routeReconTask: (task: string) => RoutePlan;
	appendEvidence: AppendEvidence;
	commandKnownTools: (command: string) => string[];
	laneExecutionStrategy: (pack: LaneCommandPack) => AutopilotExecutionStrategy;
	formatAutopilotExecutionStrategy: (strategy: AutopilotExecutionStrategy) => string;
};

export function createReconLaneRuntime(dependencies: ReconLaneRuntimeDependencies) {
	const { writeCurrentMission, routeReconTask, appendEvidence, commandKnownTools, laneExecutionStrategy } =
		dependencies;

	function findLaneIndex(mission: MissionState, name?: string): number {
		if (name) {
			const exact = mission.lanes.findIndex((lane) => lane.name === name);
			if (exact >= 0) return exact;
			const lower = name.toLowerCase();
			const partial = mission.lanes.findIndex((lane) => lane.name.toLowerCase().includes(lower));
			if (partial >= 0) return partial;
		}
		const active = mission.lanes.findIndex((lane) => lane.status === "in_progress");
		if (active >= 0) return active;
		return mission.lanes.findIndex((lane) => lane.status === "pending");
	}

	function updateMissionLane(params: {
		action: "next" | "done" | "block" | "set" | "add";
		lane?: string;
		status?: MissionLaneStatus;
		objective?: string;
		next?: string[];
		note?: string;
	}): MissionState {
		const mission = readCurrentMission() ?? createMission("manual mission", routeReconTask(REPI_GENERIC_TASK));
		const timestamp = new Date().toISOString();
		if (params.action === "add") {
			const lane: MissionLane = {
				name: params.lane ?? `lane-${mission.lanes.length + 1}`,
				objective: params.objective ?? "manual lane",
				next: params.next ?? [],
				status: mission.lanes.some((candidate) => candidate.status === "in_progress") ? "pending" : "in_progress",
				note: params.note,
				updatedAt: timestamp,
			};
			return writeCurrentMission({ ...mission, lanes: [...mission.lanes, lane] });
		}

		const index = findLaneIndex(mission, params.lane);
		if (index < 0) return mission;
		let nextStatus: MissionLaneStatus;
		if (params.action === "done") nextStatus = "done";
		else if (params.action === "block") nextStatus = "blocked";
		else if (params.action === "set") nextStatus = params.status ?? "in_progress";
		else nextStatus = "in_progress";

		const lanes = mission.lanes.map((candidate, candidateIndex) => {
			if (candidateIndex === index) {
				return { ...candidate, status: nextStatus, note: params.note ?? candidate.note, updatedAt: timestamp };
			}
			if (nextStatus === "in_progress" && candidate.status === "in_progress") {
				return { ...candidate, status: "pending" as const, updatedAt: timestamp };
			}
			return candidate;
		});
		if (params.action === "done") {
			const nextPending = lanes.findIndex(
				(candidate, candidateIndex) => candidateIndex > index && candidate.status === "pending",
			);
			if (nextPending >= 0)
				lanes[nextPending] = { ...lanes[nextPending]!, status: "in_progress", updatedAt: timestamp };
			return writeCurrentMission({ ...mission, lanes });
		}
		return writeCurrentMission({ ...mission, lanes });
	}

	function annotateMissionLane(laneName: string, note: string): MissionState | undefined {
		const mission = readCurrentMission();
		if (!mission) return undefined;
		const index = findLaneIndex(mission, laneName);
		if (index < 0) return mission;
		const timestamp = new Date().toISOString();
		const lanes = mission.lanes.map((lane, laneIndex) =>
			laneIndex === index ? { ...lane, note: truncateMiddle(note, 500), updatedAt: timestamp } : lane,
		);
		return writeCurrentMission({ ...mission, lanes });
	}

	function findLaneIndexByHint(mission: MissionState, hint?: string): number {
		if (!hint) return -1;
		const variants = hint
			.toLowerCase()
			.split(/[/|,]+/)
			.map((part) => part.trim())
			.filter(Boolean);
		for (const variant of variants) {
			const exact = mission.lanes.findIndex((lane) => lane.name.toLowerCase() === variant);
			if (exact >= 0) return exact;
			const partial = mission.lanes.findIndex((lane) => {
				const name = lane.name.toLowerCase();
				return name.includes(variant) || variant.includes(name);
			});
			if (partial >= 0) return partial;
		}
		const tokens = hint
			.toLowerCase()
			.split(/[^a-z0-9]+/)
			.filter((token) => token.length >= 3);
		return mission.lanes.findIndex((lane) => {
			const name = lane.name.toLowerCase();
			return tokens.some((token) => name.includes(token));
		});
	}

	function significantLaneFindings(analysis: LaneRunAnalysis): boolean {
		const joined = analysis.findings.join("\n");
		return !/no high-signal anchors parsed|tool\/target\/runtime error surfaced/.test(joined);
	}

	function followupNextItems(analysis: LaneRunAnalysis): string[] {
		return [...analysis.followups, ...analysis.critic.selfHeal].map((command) =>
			truncateMiddle(`[auto:${command.label}] ${command.command} # evidence: ${command.evidence}`, 900),
		);
	}

	function parseAutoLaneCommand(item: string): LaneCommand | undefined {
		const match = /^\[auto:([^\]]+)]\s+([\s\S]*?)(?:\s+# evidence:\s*([\s\S]*))?$/.exec(item.trim());
		if (!match) return undefined;
		return {
			label: match[1]?.trim() || "auto-followup",
			command: match[2]?.trim() || "",
			evidence: match[3]?.trim() || "auto follow-up command",
		};
	}

	function autoCommandsForLane(
		lane: MissionLane,
		maxCommands: number,
	): { commands: LaneCommand[]; rawItems: string[] } {
		const commands: LaneCommand[] = [];
		const rawItems: string[] = [];
		for (const item of lane.next) {
			const parsed = parseAutoLaneCommand(item);
			if (!parsed || !parsed.command) continue;
			commands.push(parsed);
			rawItems.push(item);
			if (commands.length >= maxCommands) break;
		}
		return { commands, rawItems };
	}

	function autoLaneCommandPack(
		mission: MissionState,
		lane: MissionLane,
		commands: LaneCommand[],
		target?: string,
	): LaneCommandPack {
		return {
			missionId: mission.id,
			lane: lane.name,
			route: mission.route.domain,
			target,
			commands,
			notes: [
				"run-auto 执行上一轮 analysis 挂载的 [auto:*] follow-up commands。",
				"每步执行后继续写 evidence artifact、解析输出并更新 mission lane。",
			],
		};
	}

	function removeLaneNextItems(laneName: string, rawItems: string[]): MissionState | undefined {
		if (rawItems.length === 0) return readCurrentMission();
		const mission = readCurrentMission();
		if (!mission) return undefined;
		const index = findLaneIndex(mission, laneName);
		if (index < 0) return mission;
		const remove = new Set(rawItems);
		const timestamp = new Date().toISOString();
		const lanes = mission.lanes.map((lane, laneIndex) =>
			laneIndex === index
				? { ...lane, next: lane.next.filter((item) => !remove.has(item)), updatedAt: timestamp }
				: lane,
		);
		return writeCurrentMission({ ...mission, lanes });
	}

	function applyLaneRunMissionUpdate(params: {
		pack: LaneCommandPack;
		analysis: LaneRunAnalysis;
		result: { code: number; stdout: string; stderr: string; killed?: boolean };
		artifactPath: string;
	}): { mission?: MissionState; message: string } {
		const mission = readCurrentMission();
		const critic = params.analysis.critic;
		const note = [
			`last_run exit=${params.result.code}`,
			`quality=${critic.score}`,
			`verdict=${critic.verdict}`,
			params.analysis.nextLane ? `next=${params.analysis.nextLane}` : undefined,
			params.analysis.findings[0],
			`artifact=${params.artifactPath}`,
		]
			.filter(Boolean)
			.join("; ");
		if (!mission) return { message: "auto_lane_update: no active mission" };

		const currentIndex = findLaneIndex(mission, params.pack.lane);
		if (currentIndex < 0) {
			annotateMissionLane(params.pack.lane, note);
			return { mission, message: "auto_lane_update: current lane not found" };
		}

		const targetIndex = findLaneIndexByHint(mission, params.analysis.nextLane);
		const shouldAdvance =
			params.result.code === 0 &&
			critic.score >= 45 &&
			targetIndex >= 0 &&
			targetIndex !== currentIndex &&
			significantLaneFindings(params.analysis);
		const timestamp = new Date().toISOString();
		const followups = followupNextItems(params.analysis);
		const selfHealCurrent = critic.verdict === "weak" || critic.score < 55;
		const lanes = mission.lanes.map((lane, index) => {
			if (index === currentIndex) {
				const next = [...lane.next];
				if (selfHealCurrent) {
					for (const item of followups) {
						if (!next.includes(item)) next.push(item);
					}
				}
				return {
					...lane,
					status: shouldAdvance ? ("done" as const) : ("in_progress" as const),
					next,
					note: truncateMiddle(note, 500),
					updatedAt: timestamp,
				};
			}
			if (shouldAdvance && index === targetIndex) {
				const next = [...lane.next];
				for (const item of followups) {
					if (!next.includes(item)) next.push(item);
				}
				return {
					...lane,
					status: lane.status === "done" ? lane.status : ("in_progress" as const),
					next,
					note: truncateMiddle(`auto_from=${params.pack.lane}; ${note}`, 500),
					updatedAt: timestamp,
				};
			}
			if (lane.status === "in_progress") {
				return { ...lane, status: "pending" as const, updatedAt: timestamp };
			}
			return lane;
		});
		let checkpoints = mission.checkpoints;
		if (followups.length > 0) {
			checkpoints = checkpoints.map((checkpoint) =>
				checkpoint.name === "repro_commands_ready"
					? {
							...checkpoint,
							status: "done" as const,
							note: `auto-followups:${params.pack.lane}`,
							updatedAt: timestamp,
						}
					: checkpoint,
			);
		}
		if (critic.verdict === "weak") {
			checkpoints = checkpoints.map((checkpoint) =>
				checkpoint.name === "minimal_path_proven" && checkpoint.status === "pending"
					? {
							...checkpoint,
							status: "blocked" as const,
							note: `evidence_quality=${critic.score}; self-heal queued:${params.pack.lane}`,
							updatedAt: timestamp,
						}
					: checkpoint,
			);
		}
		const updated = writeCurrentMission({ ...mission, lanes, checkpoints });
		return {
			mission: updated,
			message: shouldAdvance
				? `auto_lane_update: ${params.pack.lane} -> ${updated.lanes[targetIndex]?.name ?? params.analysis.nextLane}`
				: "auto_lane_update: annotated current lane",
		};
	}

	function formatLaneQueue(mission: MissionState): string {
		return truncateMiddle(
			[
				"lanes:",
				...mission.lanes.map((lane, index) =>
					[
						`- ${index + 1}. [${lane.status ?? "pending"}] ${truncateMiddle(lane.name, 100)}: ${truncateMiddle(lane.objective, 180)}`,
						...(lane.note ? [`  note: ${truncateMiddle(lane.note, 180)}`] : []),
						`  next_count: ${lane.next.length}`,
						...lane.next.slice(0, 3).map((step) => `  - next: ${truncateMiddle(step, 240)}`),
						...(lane.next.length > 3 ? [`  next_omitted: ${lane.next.length - 3}`] : []),
					].join("\n"),
				),
				"detail: full lane queue is stored in the current mission artifact",
			].join("\n"),
			4096,
		);
	}

	function pythonString(value: string): string {
		return JSON.stringify(value);
	}

	function activeLane(mission: MissionState, name?: string): MissionLane | undefined {
		const index = findLaneIndex(mission, name);
		return index >= 0 ? mission.lanes[index] : undefined;
	}

	function latestPassiveMapContext(): PassiveMapContext | undefined {
		ensureReconStorage();
		const missionId = readCurrentMission()?.id;
		let files: string[] = [];
		try {
			files = readdirSync(evidenceMapsDir())
				.filter((file) => file.endsWith(".md"))
				.sort()
				.reverse();
		} catch {
			return undefined;
		}
		for (const file of files) {
			const path = join(evidenceMapsDir(), file);
			const text = readText(path);
			if (!text.trim()) continue;
			if (!artifactMissionMatches(missionId, artifactScopeMissionId(text))) continue;
			const target = metadataValue(text, "target");
			const timestamp = metadataValue(text, "timestamp") ?? new Date(0).toISOString();
			const signals = text
				.split(/\r?\n/)
				.filter((line) => line.startsWith("- "))
				.map((line) => line.slice(2).trim())
				.filter(Boolean)
				.slice(0, 80);
			const candidates = uniqueMatches(
				text,
				/(?:^|\n)(\.{0,2}\/[^\s:\n]+|\/[^\s:\n]+):\s+.*(?:ELF|PE32|Mach-O|Android package|Zip archive|WebAssembly|Dalvik)/g,
				20,
			)
				.map((line) => line.replace(/^\n/, "").split(":")[0]?.trim())
				.filter((candidate): candidate is string => Boolean(candidate));
			return { path, timestamp, target, signals, candidates };
		}
		return undefined;
	}

	function mapTargetUsable(target?: string): boolean {
		if (!target) return false;
		if (target === "." || target === "<TARGET>" || target === "<URL>") return false;
		return !/^target_missing=/.test(target);
	}

	function inferTargetFromMap(map: PassiveMapContext | undefined, mission: MissionState): string | undefined {
		if (!map) return undefined;
		if (mapTargetUsable(map.target)) return map.target;
		const wantsBinary =
			mission.route.domain === "Native reverse" ||
			mission.route.domain === "Pwn / exploit" ||
			mission.route.domain === "Mobile / Android";
		if (wantsBinary && map.candidates.length > 0) return map.candidates[0];
		return undefined;
	}

	function augmentLaneCommandPackFromMap(
		mission: MissionState,
		_lane: MissionLane,
		target: string | undefined,
		commands: LaneCommand[],
		notes: string[],
	): string | undefined {
		const map = latestPassiveMapContext();
		if (!map) {
			notes.push("map_reuse: none; run re_map [target] [depth] before broad execution to anchor passive evidence.");
			return target;
		}
		const inferredTarget = target ?? inferTargetFromMap(map, mission);
		notes.push(
			[
				`map_reuse: ${map.path}`,
				`timestamp=${map.timestamp}`,
				map.target ? `map_target=${map.target}` : undefined,
				map.signals.length
					? `signals=${map.signals
							.slice(0, 6)
							.map((signal) => truncateMiddle(signal, 140))
							.join(" | ")}`
					: "signals=none",
			]
				.filter(Boolean)
				.join("; "),
		);
		if (!target && inferredTarget) notes.push(`map_inferred_target: ${inferredTarget}`);
		if (map.candidates.length > 0) {
			notes.push(`map_binary_candidates: ${map.candidates.slice(0, 8).join(", ")}`);
		}
		if (!commands.some((command) => command.label === "map-artifact-context")) {
			commands.unshift({
				label: "map-artifact-context",
				command: `sed -n '1,180p' ${shellQuote(map.path)}`,
				evidence: "latest passive map artifact context",
			});
		}
		for (const candidate of map.candidates.slice(0, 3)) {
			const command = `file ${shellQuote(candidate)} && sha256sum ${shellQuote(candidate)}`;
			if (!commands.some((item) => item.command === command)) {
				commands.push({
					label: "map-candidate-hash",
					command,
					evidence: `candidate from passive map ${map.path}`,
				});
			}
		}
		return inferredTarget;
	}

	function laneCommandPack(mission: MissionState, lane: MissionLane, target?: string): LaneCommandPack {
		const domain = mission.route.domain;
		const laneName = lane.name.toLowerCase();
		const commands: LaneCommand[] = [];
		const notes = [
			"先执行最小命令包，记录 stdout/stderr 摘要到 re_evidence；不要一上来全量深扫。",
			"命令失败时先解释错误，再用 re_bootstrap plan/install 或切换等价工具。",
		];
		const effectiveTarget = augmentLaneCommandPackFromMap(mission, lane, target, commands, notes);
		const targetArg = effectiveTarget ? shellQuote(effectiveTarget) : "<TARGET>";
		const targetPython = pythonString(effectiveTarget ?? "<TARGET>");
		const urlArg = effectiveTarget ?? "<URL>";
		const targetKind = classifyRepiTarget(effectiveTarget).kind;
		const targetIsDirectory = targetKind === "directory";
		const add = (label: string, command: string, evidence: string) => commands.push({ label, command, evidence });
		const isNativeRoute = domain === "Native reverse";
		const isAndroidRoute = domain === "Mobile / Android";
		const isPwnRoute = domain === "Pwn / exploit";
		const isWebRoute = domain === "Web / API pentest";
		const isJsRoute = domain === "Frontend JS reverse";

		if (isNativeRoute || (isPwnRoute && /triage|map|mitigation/.test(laneName))) {
			if (targetIsDirectory) {
				notes.push("target_type=directory；先做目录级候选筛选，不对目录直接执行 readelf/objdump/rabin2/checksec。");
				add(
					"directory-triage-file-list",
					`find ${targetArg} -maxdepth 4 -type f \\( -path '*/.git/*' -o -path '*/node_modules/*' \\) -prune -o -type f -printf '%p\\n' 2>/dev/null | sort | head -300`,
					"directory file inventory for target selection",
				);
				add(
					"directory-triage-file-map",
					`find ${targetArg} -maxdepth 4 -type f -exec file {} \\; 2>/dev/null | tee /tmp/repi-directory-file-map.txt | grep -E 'ELF|PE32|Mach-O|WebAssembly|script|Zip archive|Android package|pcap' | head -160`,
					"typed candidate map: binaries, scripts, archives, APKs and PCAPs",
				);
				add(
					"directory-triage-candidates",
					`awk -F: '/ELF|PE32|Mach-O|WebAssembly|script|Zip archive|Android package|pcap/ {print $1}' /tmp/repi-directory-file-map.txt 2>/dev/null | head -80`,
					"candidate files to feed into re_lane plan <lane> <candidate> or re_native_runtime plan <candidate>",
				);
			} else if (!effectiveTarget) {
				add(
					"discover-elf-candidates",
					'find . -maxdepth 3 -type f -exec sh -c \'file "$1" | grep -q "ELF" && printf "%s\\n" "$1"\' _ {} \\; | head -40',
					"candidate target paths",
				);
			} else {
				add("file-hash", `file ${targetArg} && sha256sum ${targetArg}`, "format, architecture, hash");
				add(
					"headers-imports",
					`readelf -hW ${targetArg}; readelf -dW ${targetArg} 2>/dev/null || true`,
					"ELF headers and dynamic section",
				);
				add(
					"strings-interesting",
					`strings -a -n 5 ${targetArg} | grep -iE 'license|serial|key|valid|invalid|check|verify|flag|pass|fail|error' | head -120`,
					"interesting strings",
				);
				add(
					"symbols-imports",
					`rabin2 -I ${targetArg} 2>/dev/null; rabin2 -i ${targetArg} 2>/dev/null | head -120`,
					"r2 binary info/imports",
				);
				add("checksec", `checksec --file=${targetArg} 2>/dev/null || true`, "binary mitigations");
			}
		}

		if (isAndroidRoute && /triage|map|manifest/.test(laneName)) {
			add("apk-file-hash", `file ${targetArg} && sha256sum ${targetArg}`, "APK/container format and hash");
			add("apk-list", `unzip -l ${targetArg} | head -160`, "APK top-level entries and native libraries");
			add("apk-manifest", `aapt dump badging ${targetArg} 2>/dev/null || true`, "package/activity/sdk metadata");
			add(
				"apk-interesting-strings",
				`strings -a -n 5 ${targetArg} | grep -iE 'license|serial|key|valid|invalid|check|verify|flag|token|secret|frida|root|debug' | head -160`,
				"APK/native interesting strings",
			);
		}

		if (isAndroidRoute && /control|flow|prove/.test(laneName)) {
			add(
				"jadx-keyword-map",
				`tmp=$(mktemp -d); jadx -q -d "$tmp" ${targetArg} >/dev/null 2>&1 && rg -n "license|serial|key|valid|invalid|check|verify|root|debug|frida|token|secret" "$tmp" | head -220`,
				"Java/Kotlin keyword call sites",
			);
			add(
				"native-lib-map",
				`unzip -l ${targetArg} | awk '/\\.so$/ {print $4}' | head -80`,
				"native library names for split native triage",
			);
		}

		if (isNativeRoute && /control|flow|prove/.test(laneName)) {
			add(
				"r2-xrefs",
				`r2 -A -q -c 'iz~license,key,serial,valid,invalid,check,verify,fail; afl~main; afl~sym.; ii; q' ${targetArg}`,
				"strings, functions, imports, xrefs seed",
			);
			add(
				"objdump-control",
				`objdump -d -Mintel ${targetArg} | grep -iE 'strcmp|memcmp|strncmp|license|serial|key|valid|invalid' -C 8 | head -220`,
				"control-flow hints",
			);
		}

		if (/runtime|proof|primitive|state|poc|verify/.test(laneName)) {
			if ((isNativeRoute || isPwnRoute) && !targetIsDirectory) {
				add("ldd-runtime", `ldd ${targetArg} 2>/dev/null || true`, "loader/libc dependencies");
				add(
					"trace-runtime",
					`strace -f -s 256 ${targetArg} 2>&1 | head -240`,
					"runtime syscalls / file / network evidence",
				);
				add(
					"ltrace-comparisons",
					`ltrace -f ${targetArg} 2>&1 | grep -iE 'strcmp|strncmp|memcmp|strstr|open|read|write' | head -120 || true`,
					"library comparison calls",
				);
			}
			if (isAndroidRoute) {
				add(
					"adb-device-state",
					"adb devices; adb shell getprop ro.product.cpu.abi 2>/dev/null || true",
					"device/ABI state",
				);
				add("frida-processes", "frida-ps -Uai 2>/dev/null | head -120 || true", "running/package process map");
				add(
					"frida-hook-scaffold",
					"cat > /tmp/repi-hook.js <<'JS'\nJava.perform(function(){\n  console.log('[repi] Java runtime ready');\n});\nJS\ncat /tmp/repi-hook.js",
					"minimal Frida hook scaffold",
				);
			}
			if (isWebRoute) {
				add(
					"route-auth-map",
					'rg -n "route|router|app\\.|fastify|express|auth|session|jwt|csrf|graphql|websocket|worker|queue" .',
					"routes/auth/session surface",
				);
				add(
					"state-files",
					"find . -maxdepth 4 -type f \\( -name '*route*' -o -name '*controller*' -o -name '*api*' -o -name '*auth*' -o -name '.env*' -o -name 'docker-compose*.yml' \\) | sort | head -200",
					"state-bearing files",
				);
				add("http-replay-seed", `curl -i -sS ${shellQuote(urlArg)} | sed -n '1,80p'`, "baseline HTTP response");
			}
			if (isJsRoute) {
				add(
					"js-network-surface",
					'rg -n "fetch\\(|XMLHttpRequest|axios|WebSocket|crypto|sign|timestamp|nonce|encrypt|decrypt" .',
					"JS signing/network call sites",
				);
				add(
					"source-map-search",
					"find . -maxdepth 5 -type f \\( -name '*.map' -o -name '*.js' -o -name '*.mjs' \\) | head -200",
					"JS chunks and sourcemaps",
				);
			}
		}

		if (isWebRoute && /surface|map/.test(laneName)) {
			add(
				"route-auth-map",
				'rg -n "route|router|app\\.|fastify|express|auth|session|jwt|csrf|graphql|websocket|worker|queue" .',
				"routes/auth/session surface",
			);
			add(
				"state-files",
				"find . -maxdepth 4 -type f \\( -name '*route*' -o -name '*controller*' -o -name '*api*' -o -name '*auth*' -o -name '.env*' -o -name 'docker-compose*.yml' \\) | sort | head -200",
				"state-bearing files",
			);
		}

		if (isJsRoute && /observe|map|rebuild/.test(laneName)) {
			add(
				"js-network-surface",
				'rg -n "fetch\\(|XMLHttpRequest|axios|WebSocket|crypto|sign|timestamp|nonce|encrypt|decrypt" .',
				"JS signing/network call sites",
			);
			add(
				"source-map-search",
				"find . -maxdepth 5 -type f \\( -name '*.map' -o -name '*.js' -o -name '*.mjs' \\) | head -200",
				"JS chunks and sourcemaps",
			);
		}

		if (isPwnRoute) {
			if (targetIsDirectory) {
				notes.push("pwn_target_type=directory；只枚举候选可执行文件，不对目录直接跑 checksec/ldd/crash-seed。");
				add(
					"pwn-directory-executable-candidates",
					`find ${targetArg} -maxdepth 4 -type f \\( -perm -111 -o -name '*.so' -o -name '*.elf' -o -name 'vuln' \\) -exec file {} \\; 2>/dev/null | grep -E 'ELF|PIE|shared object|executable' | tee /tmp/repi-pwn-candidates.txt | head -120`,
					"candidate executables/shared objects for pwn primitive lanes",
				);
				add(
					"pwn-directory-next-lanes",
					`awk -F: '{print $1}' /tmp/repi-pwn-candidates.txt 2>/dev/null | head -40 | sed 's#^#re_lane plan primitive #'`,
					"derive per-candidate primitive lanes instead of crashing the directory path",
				);
			} else {
				add(
					"pwn-mitigations",
					`file ${targetArg}; checksec --file=${targetArg} 2>/dev/null || true; ldd ${targetArg} || true`,
					"mitigations/loader/libc",
				);
				add(
					"crash-seed",
					`python3 - <<'PY'\nfrom subprocess import run, PIPE\np=${targetPython}\nfor n in (16,64,128,256,512):\n    r=run([p], input=b'A'*n, stdout=PIPE, stderr=PIPE, timeout=3)\n    print('n=',n,'code=',r.returncode,'out=',r.stdout[:80],'err=',r.stderr[:80])\nPY`,
					"crash/control seed",
				);
			}
		}

		if (/report/.test(laneName)) {
			add("report-scaffold", "re_complete scaffold", "report scaffold path");
		}

		appendSpecialistRuntimeCommands(mission, lane, effectiveTarget, commands, notes);

		if (commands.length === 0) {
			add("generic-map", "pwd; find . -maxdepth 3 -type f | sort | head -200", "generic passive map");
			add(
				"generic-search",
				'rg -n "TODO|secret|token|key|auth|password|flag|license|verify|admin|debug" . 2>/dev/null | head -200',
				"generic interesting strings",
			);
		}

		return {
			missionId: mission.id,
			lane: lane.name,
			route: domain,
			target: effectiveTarget,
			commands,
			notes,
		};
	}

	function renderLaneCommandPack(pack: LaneCommandPack): string {
		return [
			`mission_id: ${pack.missionId ?? "none"}`,
			`route: ${pack.route}`,
			`lane: ${pack.lane}`,
			`target: ${pack.target ?? "<TARGET>"}`,
			"notes:",
			...pack.notes.map((note) => `- ${note}`),
			"commands:",
			...pack.commands.flatMap((command, index) => [
				`## ${index + 1}. ${command.label}`,
				"```bash",
				command.command,
				"```",
				`evidence: ${command.evidence}`,
			]),
		].join("\n");
	}

	function formatLaneCommandPack(pack: LaneCommandPack, mode: "summary" | "full" = "summary"): string {
		const full = renderLaneCommandPack(pack);
		if (mode === "full") return full;
		ensureReconStorage();
		const timestamp = new Date().toISOString();
		const path = join(evidenceRunsDir(), `${timestamp.replace(/[:.]/g, "-")}-${slug(pack.lane)}-plan.md`);
		writePrivateTextFile(path, ["# REPI Lane Plan Artifact", "", `timestamp: ${timestamp}`, "", full, ""].join("\n"));
		return truncateMiddle(
			[
				"lane_plan:",
				`mission_id: ${pack.missionId ?? "none"}`,
				`route: ${truncateMiddle(pack.route, 120)}`,
				`lane: ${truncateMiddle(pack.lane, 120)}`,
				`target: ${truncateMiddle(pack.target ?? "<TARGET>", 240)}`,
				`command_count: ${pack.commands.length}`,
				`command_labels: ${
					pack.commands
						.slice(0, 16)
						.map((command) => command.label)
						.join(", ") || "none"
				}`,
				...(pack.commands.length > 16 ? [`commands_omitted: ${pack.commands.length - 16}`] : []),
				`notes: ${
					pack.notes
						.slice(0, 3)
						.map((note) => truncateMiddle(note, 180))
						.join(" | ") || "none"
				}`,
				`artifact: ${path}`,
				`verify: cat ${shellQuote(path)}`,
				"detail: full notes, commands, evidence expectations, and scripts are in artifact",
			].join("\n"),
			4096,
		);
	}

	function dedupeLaneCommands(commands: LaneCommand[]): LaneCommand[] {
		const seen = new Set<string>();
		const out: LaneCommand[] = [];
		for (const command of commands) {
			const key = `${command.label}\n${command.command}`;
			if (seen.has(key)) continue;
			seen.add(key);
			out.push(command);
		}
		return out;
	}

	function packHasSpecialistSignal(pack: LaneCommandPack, pattern: RegExp): boolean {
		return (
			pack.commands.some((command) => pattern.test(`${command.label}\n${command.evidence}\n${command.command}`)) ||
			pack.notes.some((note) => pattern.test(note))
		);
	}

	function selfHealCommandsForEvidence(params: {
		pack: LaneCommandPack;
		result: { code: number; stdout: string; stderr: string; killed?: boolean };
		findings: string[];
		deficits: string[];
	}): LaneCommand[] {
		const { pack, result, findings, deficits } = params;
		const commands: LaneCommand[] = [];
		const route = pack.route.toLowerCase();
		const combined = `${result.stdout}\n${result.stderr}`;
		const target = pack.target ? shellQuote(pack.target) : undefined;
		const add = (label: string, command: string, evidence: string) => commands.push({ label, command, evidence });
		const toolNames = dedupeLaneCommands(
			commandKnownTools(pack.commands.map((command) => command.command).join("\n")).map((tool) => ({
				label: `tool-check-${tool}`,
				command: `command -v ${shellQuote(tool)} || true`,
				evidence: `availability check for ${tool}`,
			})),
		);
		if (/command not found|not found|no such file|cannot access|permission denied/i.test(combined)) {
			for (const command of toolNames.slice(0, 5)) add(command.label, command.command, command.evidence);
			const repairItems = transcriptRepairItems(combined);
			add(
				"heal-tool-repair-matrix",
				toolRepairMatrixScript({
					pack,
					combined,
					repairItems,
					errorLines: interestingLines(
						combined,
						/command not found|not found|no such file|cannot access|permission denied|ModuleNotFoundError|ImportError|Cannot find module/i,
						12,
					),
				}),
				"runtime tool/dependency repair matrix with alternatives and bootstrap hints",
			);
			if (pack.target) {
				add(
					"heal-target-path-check",
					`ls -la ${target}; file ${target} 2>/dev/null || true`,
					"target path/format sanity",
				);
			}
		}
		if (!target) {
			if (/native|pwn|reverse|binary|elf/i.test(route)) {
				add(
					"heal-discover-binary-targets",
					'find . -maxdepth 4 -type f -exec sh -c \'file "$1" | grep -Eq "ELF|PE32|Mach-O|WebAssembly" && printf "%s\\n" "$1"\' _ {} \\; | head -80',
					"recover concrete binary targets before rerun",
				);
			} else {
				add(
					"heal-passive-target-inventory",
					"pwd; find . -maxdepth 4 -type f | sort | head -240",
					"recover concrete target candidates",
				);
			}
		}
		if (target && /native|pwn|reverse|binary|elf|mobile/.test(route)) {
			add(
				"heal-native-baseline",
				`file ${target}; sha256sum ${target}; strings -a -n 5 ${target} | grep -iE 'license|serial|key|valid|invalid|check|verify|flag|pass|fail|strcmp|memcmp' | head -180`,
				"baseline binary metadata and verification strings",
			);
			add(
				"heal-native-control-scan",
				`readelf -hW ${target}; readelf -sW ${target} 2>/dev/null | grep -iE 'main|strcmp|memcmp|license|verify|check' | head -160; objdump -d -Mintel ${target} 2>/dev/null | grep -iE 'strcmp|memcmp|strncmp|license|serial|key|valid|invalid' -C 10 | head -260 || true`,
				"alternate control-flow anchors without heavyweight tooling",
			);
			add(
				"heal-native-deep-symbol-map",
				`[ -x /tmp/repi-native-symbol-map.sh ] && /tmp/repi-native-symbol-map.sh ${target} || { readelf -SW ${target} 2>/dev/null; objdump -T ${target} 2>/dev/null; strings -a -n 5 ${target} | grep -Ei 'license|serial|key|valid|invalid|verify|check|flag|strcmp|memcmp' | head -220; }`,
				"native-deep fallback for symbol/import/section/string anchors",
			);
			add(
				"heal-native-deep-symbolic-fuzz",
				`[ -f /tmp/repi-native-symbolic-fuzz.py ] && python3 /tmp/repi-native-symbolic-fuzz.py ${target} || printf '%s\n' 'rerun native-deep-symbolic-fuzz-scaffold after lane plan'`,
				"native-deep fallback for CFG/symbolic/fuzz anchors",
			);
		}
		if (/web|api/.test(route)) {
			add(
				"heal-web-route-auth-map",
				'rg -n "route|router|app\\.|fastify|express|auth|session|jwt|csrf|graphql|websocket|controller|middleware|permission|role|owner" . | head -240',
				"widen route/auth/session evidence surface",
			);
			if (pack.target && /^https?:\/\//.test(pack.target)) {
				add(
					"heal-http-baseline",
					`curl -i -sS ${shellQuote(pack.target)} | sed -n '1,120p'`,
					"baseline HTTP status/headers/body",
				);
			}
		}
		if (
			/web vulnerability|web scan/.test(route) ||
			packHasSpecialistSignal(pack, /web-scan-|web vulnerability scanner/i)
		) {
			add(
				"heal-web-scan-scope-baseline",
				pack.target && /^https?:\/\//.test(pack.target)
					? `[ -x /tmp/repi-web-scope.sh ] && /tmp/repi-web-scope.sh ${shellQuote(pack.target)} || curl -k -sS -I --max-time 12 ${shellQuote(pack.target)} | sed -n '1,120p'`
					: 'rg -n "https?://|openapi|swagger|graphql|sitemap|robots|baseURL|apiUrl" . 2>/dev/null | head -220',
				"specialist web scanner scope/header/tech baseline fallback",
			);
			add(
				"heal-web-scan-corpus",
				pack.target && /^https?:\/\//.test(pack.target)
					? `[ -x /tmp/repi-web-crawl.sh ] && /tmp/repi-web-crawl.sh ${shellQuote(pack.target)} || printf '%s\n' 'rerun web scan crawl corpus scaffold'`
					: 'printf "%s\n" "bind an http(s) target before crawl corpus heal"',
				"specialist web scanner crawl/route corpus fallback",
			);
			add(
				"heal-web-scan-manual-replay",
				pack.target && /^https?:\/\//.test(pack.target)
					? `[ -x /tmp/repi-web-verify.py ] && python3 /tmp/repi-web-verify.py ${shellQuote(pack.target)} || curl -k -sS -L --max-time 10 ${shellQuote(pack.target)} -w '\\n%{http_code} %{url_effective}\\n' | head -80`
					: 'printf "%s\n" "bind an http(s) target before scanner replay heal"',
				"specialist scanner finding replay/status/body-hash fallback",
			);
		}
		if (/frontend|js/.test(route)) {
			add(
				"heal-js-signature-surface",
				'rg -n "fetch\\(|XMLHttpRequest|axios|WebSocket|crypto|subtle|sign|signature|nonce|timestamp|encrypt|decrypt|md5|sha256|hmac" . | head -260',
				"widen JS signing/encryption evidence surface",
			);
		}
		if (/web|api/.test(route) || packHasSpecialistSignal(pack, /browser-xhr-ws|browser\/XHR\/WS/i)) {
			add(
				"heal-browser-xhr-ws-capture",
				pack.target && /^https?:\/\//.test(pack.target)
					? `[ -f /tmp/repi-browser-xhr-ws.mjs ] && node /tmp/repi-browser-xhr-ws.mjs ${shellQuote(pack.target)} || curl -i -sS ${shellQuote(pack.target)} | sed -n '1,160p'`
					: 'rg -n "fetch\\(|XMLHttpRequest|WebSocket|Set-Cookie|Authorization|Bearer|localStorage|sessionStorage|router|auth|session|jwt" . | head -260',
				"specialist browser/XHR/WS capture or static request/auth fallback",
			);
			add(
				"heal-browser-cdp-artifact",
				pack.target && /^https?:\/\//.test(pack.target)
					? `[ -f /tmp/repi-browser-cdp-artifact.mjs ] && node /tmp/repi-browser-cdp-artifact.mjs ${shellQuote(pack.target)} /tmp/repi-browser-artifact.json || printf '%s\n' 'rerun re_lane plan to regenerate browser-cdp-artifact-scaffold'`
					: 'find /tmp -maxdepth 1 -type f ( -name "repi-browser-artifact*.json" -o -name "repi-*har*.json" ) -print 2>/dev/null | head -40',
				"specialist browser/CDP artifact capture fallback with request/response/WS/storage serialization",
			);
			add(
				"heal-browser-replay-evaluator",
				'[ -f /tmp/repi-replay-eval.mjs ] && [ -f /tmp/repi-browser-artifact.json ] && node /tmp/repi-replay-eval.mjs /tmp/repi-browser-artifact.json || printf "%s\n" "capture /tmp/repi-browser-artifact.json before replay evaluation"',
				"specialist browser replay evaluator fallback for status/body drift checks",
			);
			add(
				"heal-browser-route-graph",
				pack.target && /^https?:\/\//.test(pack.target)
					? `[ -f /tmp/repi-route-graph.mjs ] && node /tmp/repi-route-graph.mjs /tmp/repi-browser-artifact.json ${shellQuote(pack.target)} || printf '%s\n' 'rerun browser-route-graph-scaffold after browser artifact capture'`
					: 'rg -n "route|router|app\\.|fastify|express|koa|hono|controller|middleware|permission|owner|tenant|user_id|account_id|org_id" . | head -320',
				"specialist browser route graph fallback for authz surface mapping",
			);
			add(
				"heal-browser-auth-matrix",
				"[ -f /tmp/repi-auth-matrix.mjs ] && node /tmp/repi-auth-matrix.mjs " +
					(pack.target && /^https?:\/\//.test(pack.target) ? shellQuote(pack.target) : '"$REPI_URL"') +
					' || printf "%s\n" "generate route graph and set COOKIE_A/COOKIE_B or AUTH_A/AUTH_B before auth matrix"',
				"specialist browser authorization matrix fallback",
			);
			add(
				"heal-browser-idor-bola-probe",
				'[ -f /tmp/repi-idor-bola-probe.mjs ] && node /tmp/repi-idor-bola-probe.mjs || printf "%s\n" "generate route graph then set REPI_IDOR_BASELINE/REPI_IDOR_ALT for controlled object diff"',
				"specialist browser IDOR/BOLA probe fallback",
			);
			add(
				"heal-browser-authz-state-machine",
				"[ -f /tmp/repi-authz-state-machine.mjs ] && node /tmp/repi-authz-state-machine.mjs " +
					(pack.target && /^https?:\/\//.test(pack.target) ? shellQuote(pack.target) : '"$REPI_URL"') +
					' || printf "%s\n" "generate route graph and set COOKIE_A/COOKIE_B or AUTH_A/AUTH_B before authz state machine"',
				"specialist browser authz state-machine fallback",
			);
			add(
				"heal-browser-authz-sequence-replay",
				"[ -f /tmp/repi-authz-sequence-replay.mjs ] && node /tmp/repi-authz-sequence-replay.mjs " +
					(pack.target && /^https?:\/\//.test(pack.target) ? shellQuote(pack.target) : '"$REPI_URL"') +
					' || printf "%s\n" "capture route graph or set REPI_AUTHZ_SEQUENCE before sequence replay"',
				"specialist browser authz sequence replay fallback",
			);
			add(
				"heal-browser-authz-object-ownership",
				'[ -f /tmp/repi-authz-object-ownership.mjs ] && node /tmp/repi-authz-object-ownership.mjs "$REPI_URL" || printf "%s\n" "set REPI_OWNER_URL plus COOKIE_A/COOKIE_B or AUTH_A/AUTH_B before object ownership check"',
				"specialist browser object ownership authorization fallback",
			);
			add(
				"heal-browser-authz-state-rollback",
				'[ -f /tmp/repi-authz-state-rollback.mjs ] && node /tmp/repi-authz-state-rollback.mjs "$REPI_URL" || printf "%s\n" "set REPI_ROLLBACK_URL/BODY/RESTORE_BODY before rollback proof"',
				"specialist browser authz state rollback fallback",
			);
		}
		if (/frontend|js/.test(route) || packHasSpecialistSignal(pack, /js-signing-rebuild|JS signing rebuild/i)) {
			add(
				"heal-js-signing-runtime-hook",
				`[ -f /tmp/repi-js-runtime-hooks.js ] && sed -n '1,260p' /tmp/repi-js-runtime-hooks.js || rg -n "fetch\\(|XMLHttpRequest|WebSocket|crypto\\.subtle|sign|signature|nonce|timestamp|encrypt|decrypt" . | head -300`,
				"specialist JS signing hook/rebuild fallback",
			);
			add(
				"heal-js-signing-normalizer",
				`[ -f /tmp/repi-js-normalize.mjs ] && node /tmp/repi-js-normalize.mjs || printf '%s\n' 'capture REPI_JS_LOG or REPI_OBSERVED before JS signing normalizer'`,
				"specialist JS signing observed-artifact normalizer fallback",
			);
			add(
				"heal-js-first-divergence",
				`[ -f /tmp/repi-js-first-divergence.mjs ] && node /tmp/repi-js-first-divergence.mjs || printf '%s\n' 'generate observed artifact and set REPI_EXPECTED_SIGNATURE/CANDIDATE before first-divergence check'`,
				"specialist JS first-divergence fallback",
			);
			add(
				"heal-js-replay-harness",
				`[ -f /tmp/repi-js-replay-harness.mjs ] && node /tmp/repi-js-replay-harness.mjs || printf '%s\n' 'set REPI_REPLAY_URL and signature env before signed replay verification'`,
				"specialist JS signed replay harness fallback",
			);
		}
		if (/pwn|exploit/.test(route) || packHasSpecialistSignal(pack, /pwn-primitive|pwn primitive/i)) {
			add(
				"heal-pwn-primitive-crash",
				target
					? `python3 - <<'PY'\nimport pathlib\npathlib.Path('/tmp/repi-crash.bin').write_bytes(b'A'*512)\nprint('/tmp/repi-crash.bin')\nPY\ngdb -q ${target} -ex 'set pagination off' -ex 'run < /tmp/repi-crash.bin' -ex 'info registers' -ex 'bt' -ex 'x/24gx $rsp' -ex 'quit' 2>/dev/null || ${target} < /tmp/repi-crash.bin 2>&1 | head -160 || true`
					: 'find . -maxdepth 4 -type f -exec sh -c \'file "$1" | grep -q ELF && printf "%s\\n" "$1"\' _ {} \\; | head -80',
				"specialist pwn primitive crash/control fallback",
			);
			add(
				"heal-pwn-offset-analyzer",
				target
					? `[ -f /tmp/repi-pwn-offset-analyzer.py ] && python3 /tmp/repi-pwn-offset-analyzer.py || python3 - <<'PY'\nimport os, pathlib\nneedle=os.getenv('REPI_CRASH_VALUE','').lower().replace('0x','')\npat=pathlib.Path('/tmp/repi-cyclic.bin')\nif not needle or not pat.exists(): print('[pwn-offset] crash_value=<unset> offset=-1 note=rerun cyclic crash or set REPI_CRASH_VALUE')\nelse:\n data=pat.read_bytes(); raw=bytes.fromhex(needle)\n for c in (raw, raw[::-1], raw[-4:], raw[-4:][::-1]): print(f'[pwn-offset] crash_value=0x{needle} candidate={c.hex()} offset={data.find(c)}')\nPY`
					: 'printf "%s\n" "bind a concrete ELF target before pwn offset analyzer heal"',
				"specialist pwn cyclic offset analyzer fallback",
			);
			add(
				"heal-pwn-local-verifier",
				target
					? `[ -f /tmp/repi-pwn-local-verifier.py ] && python3 /tmp/repi-pwn-local-verifier.py ${target} || printf '%s\n' 'rerun pwn-primitive-local-verifier to regenerate local verifier scaffold'`
					: 'printf "%s\n" "bind a concrete ELF target before local payload verifier heal"',
				"specialist pwn local verifier fallback",
			);
			add(
				"heal-pwn-heap-tcache",
				target
					? `[ -f /tmp/repi-pwn-heap-tcache.gdb ] && gdb -q ${target} -x /tmp/repi-pwn-heap-tcache.gdb || printf '%s\\n' 'rerun pwn-advanced-heap-tcache-scaffold to regenerate heap/tcache probe'`
					: 'printf "%s\n" "bind a concrete ELF target before heap/tcache heal"',
				"specialist pwn heap/tcache allocator fallback",
			);
			add(
				"heal-pwn-format-string",
				target
					? `[ -f /tmp/repi-pwn-fmtstr.py ] && python3 /tmp/repi-pwn-fmtstr.py ${target} || printf '%s\\n' 'rerun pwn-advanced-format-string-scaffold to regenerate fmtstr probe'`
					: 'printf "%s\n" "bind a concrete ELF target before format-string heal"',
				"specialist pwn format-string probe fallback",
			);
			add(
				"heal-pwn-srop-ret2dlresolve",
				target
					? `[ -f /tmp/repi-pwn-srop-dlresolve.py ] && python3 /tmp/repi-pwn-srop-dlresolve.py ${target} || (ROPgadget --binary ${target} --only 'syscall|int|pop|ret' 2>/dev/null || objdump -d ${target} | grep -Ei 'syscall|int 0x80|sigreturn' | head -160)`
					: 'printf "%s\n" "bind a concrete ELF target before SROP/ret2dlresolve heal"',
				"specialist pwn SROP/ret2dlresolve fallback",
			);
			add(
				"heal-pwn-one-gadget-constraints",
				target
					? `LIBC=$(ldd ${target} 2>/dev/null | awk '/libc.so/{print $(NF-1); exit}'); [ -n "$LIBC" ] && one_gadget "$LIBC" 2>/dev/null | sed -n '1,160p' || printf '%s\\n' 'install one_gadget or inspect constraints manually from libc fingerprint'`
					: 'printf "%s\n" "bind a concrete ELF target before one_gadget heal"',
				"specialist pwn one_gadget constraint fallback",
			);
			add(
				"heal-pwn-seccomp-sandbox",
				target
					? `seccomp-tools dump ${target} 2>/dev/null | sed -n '1,160p' || timeout 5 strace -f -e trace=prctl,seccomp,execve,openat,read,write ${target} </dev/null 2>&1 | sed -n '1,160p' || true`
					: 'printf "%s\n" "bind a concrete ELF target before seccomp/sandbox heal"',
				"specialist pwn seccomp/sandbox fallback",
			);
		}

		if (
			/exploit reliability/.test(route) ||
			packHasSpecialistSignal(pack, /exploit-(poc|replay|environment|flake|artifact)|exploit reliability\/autopwn/i)
		) {
			add(
				"heal-exploit-poc-inventory",
				"find . -maxdepth 6 -type f \\( -iname '*exploit*' -o -iname '*poc*' -o -iname '*payload*' -o -iname '*replay*' -o -iname '*.http' -o -iname '*.har' \\) -print | head -240",
				"specialist exploit PoC/payload discovery fallback",
			);
			add(
				"heal-exploit-replay-matrix",
				"[ -f /tmp/repi-exploit-replay-matrix.py ] && python3 /tmp/repi-exploit-replay-matrix.py || printf '%s\\n' 'set REPI_POC_CMD before exploit replay heal'",
				"specialist exploit replay matrix fallback",
			);
			add(
				"heal-exploit-flake-triage",
				"[ -f /tmp/repi-exploit-flake-triage.py ] && python3 /tmp/repi-exploit-flake-triage.py || jq '.runs' /tmp/repi-exploit-replay-matrix.json 2>/dev/null || true",
				"specialist exploit flake triage fallback",
			);
			add(
				"heal-exploit-env-pin",
				`file ${target} 2>/dev/null || true; sha256sum ${target} 2>/dev/null || true; cat /proc/sys/kernel/randomize_va_space 2>/dev/null || true`,
				"specialist exploit environment pin fallback",
			);
		}

		if (
			/dfir|pcap|forensic|stego/.test(route) ||
			/\.(?:pcap|pcapng|cap)$/i.test(pack.target ?? "") ||
			packHasSpecialistSignal(pack, /pcap-flow|PCAP\/DFIR/i)
		) {
			add(
				"heal-pcap-flow-summary",
				target
					? `capinfos ${target} 2>/dev/null || file ${target}; tshark -r ${target} -q -z conv,tcp -z endpoints,ip 2>/dev/null | sed -n '1,180p'`
					: "find . -maxdepth 5 -type f \\( -iname '*.pcap' -o -iname '*.pcapng' -o -iname '*.cap' \\) -print | head -80",
				"specialist PCAP/DFIR flow summary fallback",
			);
			add(
				"heal-pcap-stream-rank",
				target
					? `[ -f /tmp/repi-pcap-stream-rank.py ] && python3 /tmp/repi-pcap-stream-rank.py ${target} || tshark -r ${target} -q -z conv,tcp -z conv,udp 2>/dev/null | sed -n '1,220p'`
					: "find . -maxdepth 5 -type f \\( -iname '*.pcap' -o -iname '*.pcapng' -o -iname '*.cap' \\) -print | head -80",
				"specialist PCAP stream ranking fallback",
			);
			add(
				"heal-pcap-secret-timeline",
				target
					? `[ -f /tmp/repi-pcap-secret-timeline.py ] && python3 /tmp/repi-pcap-secret-timeline.py ${target} || tshark -r ${target} -Y 'http.authorization || http.cookie || dns.qry.name || tls.handshake.extensions_server_name || frame contains "token" || frame contains "flag"' -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.stream -e http.host -e http.request.uri -e dns.qry.name -e tls.handshake.extensions_server_name -e http.authorization -e http.cookie 2>/dev/null | head -260`
					: 'printf "%s\n" "bind a concrete PCAP target before secret timeline heal"',
				"specialist PCAP credential/secret timeline fallback",
			);
			add(
				"heal-pcap-transform-chain",
				'[ -f /tmp/repi-pcap-transform-chain.py ] && python3 /tmp/repi-pcap-transform-chain.py || find /tmp/repi-pcap-objects /tmp/repi-carve -type f 2>/dev/null | head -80 | while read -r f; do echo "### $f"; file "$f"; strings -a -n 5 "$f" | head -40; done',
				"specialist PCAP transform-chain fallback",
			);
		}

		if (
			/memory forensics/.test(route) ||
			/\.(?:raw|vmem|mem|dmp|lime|core|crash)$/i.test(pack.target ?? "") ||
			packHasSpecialistSignal(pack, /memory-forensics|mem-image|mem-vol|mem-credential/i)
		) {
			add(
				"heal-memory-image-info",
				target
					? `[ -x /tmp/repi-memory-info.sh ] && /tmp/repi-memory-info.sh ${target} || { file ${target}; sha256sum ${target}; }`
					: "find . -maxdepth 6 -type f \\( -iname '*.raw' -o -iname '*.vmem' -o -iname '*.mem' -o -iname '*.dmp' -o -iname '*.lime' -o -iname '*.core' \\) -print | head -120",
				"specialist memory image/profile/banner fallback",
			);
			add(
				"heal-memory-process-network",
				target
					? `[ -x /tmp/repi-memory-process.sh ] && /tmp/repi-memory-process.sh ${target} || strings -a -n 8 ${target} | grep -Eai 'cmd\\.exe|powershell|/bin/sh|bash|curl|wget|http|socket|connect' | head -240`
					: 'printf "%s\n" "bind a concrete memory image before process/network heal"',
				"specialist memory process/network fallback",
			);
			add(
				"heal-memory-credential-artifact",
				target
					? `[ -x /tmp/repi-memory-creds.sh ] && /tmp/repi-memory-creds.sh ${target} || strings -a -n 6 ${target} | grep -Eai 'password|token|secret|Authorization:|Cookie:|AWS_ACCESS_KEY|BEGIN (RSA|OPENSSH)|NTLM|lsass' | head -260`
					: 'printf "%s\n" "bind a concrete memory image before credential/artifact heal"',
				"specialist memory credential/token/artifact fallback",
			);
			add(
				"heal-memory-timeline-carve",
				target
					? `[ -x /tmp/repi-memory-timeline.sh ] && /tmp/repi-memory-timeline.sh ${target} || printf '%s\n' 'rerun memory timeline/carve scaffold after volatility3 bootstrap'`
					: 'printf "%s\n" "bind a concrete memory image before timeline/carve heal"',
				"specialist memory timeline/malfind/filescan/dumpfiles fallback",
			);
		}

		if (
			/firmware|iot/.test(route) ||
			packHasSpecialistSignal(pack, /firmware-|Firmware[/]IoT rootfs|firmware-image|firmware-rootfs/i)
		) {
			add(
				"heal-firmware-extract-rootfs",
				target
					? `[ -f /tmp/repi-firmware-extract.sh ] && /tmp/repi-firmware-extract.sh ${target} || binwalk -eM ${target} 2>/dev/null || file ${target}`
					: "find . -maxdepth 6 -type f \\( -iname '*.bin' -o -iname '*.img' -o -iname '*.trx' -o -iname '*.ubi' -o -iname '*.squashfs' -o -iname '*firmware*' \\) -print | head -120",
				"specialist firmware extraction/rootfs fallback",
			);
			add(
				"heal-firmware-config-secret-map",
				"[ -f /tmp/repi-firmware-config.sh ] && /tmp/repi-firmware-config.sh || grep -RasnE 'password|passwd|secret|token|nvram|dropbear|httpd|cgi-bin' /tmp/repi-firmware-extract 2>/dev/null | head -240",
				"specialist firmware config/secret fallback",
			);
			add(
				"heal-firmware-service-surface",
				"[ -f /tmp/repi-firmware-services.sh ] && /tmp/repi-firmware-services.sh || find /tmp/repi-firmware-extract -path '*/www/*' -o -path '*/cgi-bin/*' 2>/dev/null | head -180",
				"specialist firmware service/web surface fallback",
			);
		}

		if (
			/crypto|stego/.test(route) ||
			packHasSpecialistSignal(pack, /crypto-stego|crypto\/stego|crypto-param|crypto-transform|crypto-solver/i)
		) {
			add(
				"heal-crypto-parameter-inventory",
				target
					? `[ -f /tmp/repi-crypto-inventory.py ] && python3 /tmp/repi-crypto-inventory.py ${target} || strings -a -n 4 ${target} | grep -Ei 'iv|nonce|salt|key|sig|signature|token|cipher|modulus|BEGIN|RSA|AES|base64' | head -220`
					: "find . -maxdepth 5 -type f \\( -iname '*.txt' -o -iname '*.enc' -o -iname '*.bin' -o -iname '*.png' -o -iname '*.jpg' -o -iname '*crypto*' -o -iname '*stego*' \\) -print | head -120",
				"specialist crypto parameter inventory fallback",
			);
			add(
				"heal-crypto-transform-replay",
				target
					? `[ -f /tmp/repi-crypto-transform.py ] && python3 /tmp/repi-crypto-transform.py ${target} || python3 - <<'PY'\nprint('[crypto-transform] rerun crypto-stego-transform-replay-scaffold to regenerate deterministic transform chain')\nPY`
					: "printf '%s\n' 'bind a concrete crypto/stego target before transform replay heal'",
				"specialist crypto transform replay fallback",
			);
			add(
				"heal-crypto-known-answer",
				target
					? `[ -f /tmp/repi-crypto-solver.py ] && REPI_KNOWN_ANSWER="\${REPI_KNOWN_ANSWER:-}" REPI_CANDIDATE="\${REPI_CANDIDATE:-}" python3 /tmp/repi-crypto-solver.py ${target} || printf '%s\n' 'set REPI_KNOWN_ANSWER/REPI_CANDIDATE after solver step'`
					: "printf '%s\n' 'bind target and known-answer/candidate before solver verification heal'",
				"specialist crypto solver/known-answer fallback",
			);
		}

		if (
			/agent|llm/.test(route) ||
			packHasSpecialistSignal(pack, /agent-(prompt|tool|memory|injection|delegation)|agent prompt\/tool boundary/i)
		) {
			add(
				"heal-agent-prompt-surface-map",
				'rg -n "systemPrompt|developer|instructions|prompt injection|ignore previous|tool_call|registerTool|MCP|memory|RAG|retrieval|untrusted|sanitize|schema|approval|allowlist|denylist" . 2>/dev/null | head -360',
				"specialist agent prompt/resource surface fallback",
			);
			add(
				"heal-agent-tool-boundary",
				'[ -f /tmp/repi-agent-tool-boundary.py ] && python3 /tmp/repi-agent-tool-boundary.py || rg -n "registerTool|tool_call|function_call|exec\\(|spawn\\(|subprocess|schema|validate|allowlist|denylist" . 2>/dev/null | head -320',
				"specialist agent tool-call boundary fallback",
			);
			add(
				"heal-agent-memory-poisoning",
				"[ -f /tmp/repi-agent-memory-poison.py ] && python3 /tmp/repi-agent-memory-poison.py || find . -maxdepth 5 -type f \\( -iname '*memory*' -o -iname '*journal*' -o -iname '*playbook*' -o -iname '*rag*' -o -iname '*.md' \\) -print | head -160",
				"specialist agent memory/RAG poisoning fallback",
			);
			add(
				"heal-agent-injection-replay",
				"[ -f /tmp/repi-agent-injection-replay.py ] && python3 /tmp/repi-agent-injection-replay.py || printf '%s\\n' 'rerun agent-injection-replay-harness to regenerate corpus'",
				"specialist agent injection replay fallback",
			);
		}

		if (
			/malware/.test(route) ||
			packHasSpecialistSignal(pack, /malware-|malware config\/IOC|malware-static|malware-ioc/i)
		) {
			add(
				"heal-malware-static-triage",
				target
					? `file ${target}; sha256sum ${target}; strings -a -n 5 ${target} | grep -Ei 'http|https|User-Agent|powershell|cmd\\.exe|rundll32|regsvr32|schtasks|CreateRemoteThread|VirtualAlloc|socket|connect|HKCU|HKLM|mutex|bitcoin|ransom|encrypt|decrypt|C2|beacon' | head -220`
					: "find . -maxdepth 5 -type f \\( -iname '*.exe' -o -iname '*.dll' -o -iname '*.bin' -o -iname '*.elf' -o -iname '*.scr' \\) -print | head -120",
				"specialist malware static triage fallback",
			);
			add(
				"heal-malware-ioc-extract",
				target
					? `[ -f /tmp/repi-malware-ioc.py ] && python3 /tmp/repi-malware-ioc.py ${target} || strings -a -n 5 ${target} | grep -Eio 'https?://[^ ]+|([0-9]{1,3}\\.){3}[0-9]{1,3}|([a-z0-9-]+\\.)+[a-z]{2,}' | sort -u | head -200`
					: 'printf "%s\n" "bind a concrete malware sample before IOC extraction heal"',
				"specialist malware IOC/config extraction fallback",
			);
			add(
				"heal-malware-behavior-trace",
				target
					? `[ -f /tmp/repi-malware-behavior.sh ] && REPI_MALWARE_TIMEOUT="\${REPI_MALWARE_TIMEOUT:-8}" /tmp/repi-malware-behavior.sh ${target} || timeout 8s strace -f -s 256 ${target} 2>&1 | head -220 || true`
					: 'printf "%s\n" "bind a concrete malware sample before behavior trace heal"',
				"specialist malware behavior trace fallback",
			);
		}
		if (
			/cloud|container|k8s|kubernetes/.test(route) ||
			packHasSpecialistSignal(pack, /cloud-identity|Cloud\/K8s identity|cloud-runtime|cloud-metadata/i)
		) {
			add(
				"heal-cloud-identity-map",
				"env | grep -Ei 'AWS_|AZURE_|GOOGLE_|KUBE|KUBERNETES' | sort; find ~/.aws ~/.azure ~/.config/gcloud ~/.kube /var/run/secrets/kubernetes.io/serviceaccount -maxdepth 2 -type f 2>/dev/null | head -120",
				"specialist cloud identity/config fallback",
			);
			add(
				"heal-cloud-runtime-config",
				"[ -f /tmp/repi-cloud-runtime.sh ] && /tmp/repi-cloud-runtime.sh || find . -maxdepth 5 -type f \\( -name 'Dockerfile*' -o -name 'docker-compose*.yml' -o -name '*.tf' -o -name '*deployment*.yml' -o -name '*rbac*.yml' \\) -print | head -240",
				"specialist cloud/K8s runtime config fallback",
			);
			add(
				"heal-cloud-metadata-probe",
				"[ -f /tmp/repi-cloud-metadata-probe.py ] && python3 /tmp/repi-cloud-metadata-probe.py || printf '%s\n' 'rerun cloud-metadata-probe-scaffold to regenerate bounded metadata probe'",
				"specialist cloud metadata probe fallback",
			);
		}
		if (
			/identity|windows|ad/.test(route) ||
			packHasSpecialistSignal(pack, /identity-ad|Identity\/AD graph|ad-principal|ad-credential|ad-graph/i)
		) {
			add(
				"heal-identity-ad-enum",
				"[ -f /tmp/repi-ad-enum.sh ] && /tmp/repi-ad-enum.sh || env | grep -Ei 'DOMAIN|DC_IP|LDAP|KRB5|USERNAME|TARGET' | sort",
				"specialist AD principal/protocol enumeration fallback",
			);
			add(
				"heal-identity-ad-credential-check",
				"[ -f /tmp/repi-ad-credential-check.sh ] && /tmp/repi-ad-credential-check.sh || printf '%s\n' 'set TARGET/USERNAME/PASSWORD or NTLM_HASH before credential usability heal'",
				"specialist AD credential usability fallback",
			);
			add(
				"heal-identity-ad-graph",
				"[ -f /tmp/repi-ad-graph.py ] && python3 /tmp/repi-ad-graph.py || find . /tmp -maxdepth 3 -type f \\( -iname '*.json' -o -iname '*bloodhound*' -o -iname '*certipy*' \\) -print 2>/dev/null | head -120",
				"specialist AD graph edge fallback",
			);
		}
		if (
			/mobile \/ ios|ios|ipa/.test(route) ||
			/\.(?:ipa)$/i.test(pack.target ?? "") ||
			packHasSpecialistSignal(pack, /ios-|iOS IPA|ios-frida|ios-macho/i)
		) {
			add(
				"heal-ios-ipa-inventory",
				target
					? `[ -x /tmp/repi-ios-inventory.sh ] && /tmp/repi-ios-inventory.sh ${target} || { file ${target}; unzip -l ${target} 2>/dev/null | head -120; }`
					: "find . -maxdepth 6 -type f -iname '*.ipa' -o -type d -iname '*.app' 2>/dev/null | head -120",
				"specialist iOS IPA/App inventory fallback",
			);
			add(
				"heal-ios-macho-class-map",
				target
					? `[ -x /tmp/repi-ios-macho.sh ] && /tmp/repi-ios-macho.sh ${target} || strings -a -n 5 ${target} | grep -Ei 'https?://|SecItem|NSURLSession|CCCrypt|CryptoKit|SecTrust|jailbreak|signature|token' | head -220`
					: 'printf "%s\n" "bind a concrete IPA/App before iOS Mach-O/class map heal"',
				"specialist iOS Mach-O/class/selector fallback",
			);
			add(
				"heal-ios-frida-hook-template",
				"sed -n '1,260p' /tmp/repi-ios-frida-hooks.js 2>/dev/null || printf '%s\n' 'rerun ios-frida-objection-hook-scaffold'; frida-ps -Uai 2>/dev/null | head -120 || true",
				"specialist iOS Frida/objection hook template fallback",
			);
		}
		if (/android|mobile|ios/.test(route) || packHasSpecialistSignal(pack, /frida-gdb-trace|Frida\/GDB trace/i)) {
			add(
				"heal-frida-gdb-trace",
				`[ -f /tmp/repi-frida-trace.js ] && sed -n '1,260p' /tmp/repi-frida-trace.js; frida-ps -Uai 2>/dev/null | head -120 || true`,
				"specialist Frida/GDB trace fallback",
			);
		}
		if (deficits.includes("no high-signal anchors parsed")) {
			add(
				"heal-generic-signal-search",
				'rg -n "TODO|secret|token|key|auth|password|flag|license|verify|admin|debug|strcmp|memcmp|jwt|session|sign" . 2>/dev/null | head -260',
				"generic high-signal keyword search",
			);
		}
		if (findings.some((finding) => /next command pack candidates/.test(finding))) {
			add(
				"heal-replay-followups",
				"printf '%s\\n' 'follow-up candidates already emitted; run re_lane run-auto 1 after reviewing tool strategy'",
				"operator reminder for queued follow-ups",
			);
		}
		return dedupeLaneCommands(commands).slice(0, 10);
	}

	function evaluateEvidenceQuality(params: {
		pack: LaneCommandPack;
		result: { code: number; stdout: string; stderr: string; killed?: boolean };
		findings: string[];
		followups: LaneCommand[];
		nextLane?: string;
	}): EvidenceCritic {
		const combined = `${params.result.stdout}\n${params.result.stderr}`;
		const deficits: string[] = [];
		let score = 0;
		if (params.result.code === 0) score += 20;
		else deficits.push(`nonzero exit ${params.result.code}`);
		if (params.result.killed) deficits.push("command killed or timed out");
		else score += 5;
		if (combined.trim().length >= 80) score += 10;
		else deficits.push("thin stdout/stderr transcript");
		if (params.pack.target && !/[<][A-Z_]+[>]/.test(params.pack.target)) score += 10;
		else deficits.push("no concrete target bound to lane");
		const toolOrTargetError =
			/command not found|not found|no such file|cannot access|permission denied|trace\/breakpoint trap/i.test(
				combined,
			);
		if (toolOrTargetError) deficits.push("tool/target/runtime error present");
		else score += 10;
		const highSignal = params.findings.some(
			(finding) =>
				!/no high-signal|tool\/target\/runtime error|command-pack exited|killed/i.test(finding) &&
				/(address anchors|comparison|interesting output|metadata|route\/auth|JS runtime|Android|iOS IPA|iOS Mach-O|iOS Frida|iOS network|next command pack|tool repair anchors|browser\/XHR\/WS|websocket endpoint|cookie\/storage|browser CDP artifact|browser runtime artifact|browser replay evaluator|browser route graph|browser auth matrix|browser IDOR\/BOLA|browser authz state machine|browser authz sequence replay|browser authz object ownership|browser authz state rollback|web API static authz|web API schema|web API state mutation|web scanner scope|web scanner crawl|web scanner content discovery|web scanner template|web scanner manual replay|JS signing rebuild|JS signing normalized|JS first-divergence|JS signing replay harness|crypto\.subtle|crypto parameter derivation|crypto transform replay|crypto solver script|crypto known-answer|stego extraction|pwn primitive|pwn crash register|pwn cyclic offset|pwn gadget|pwn ROP\/libc|pwn local verifier|pwn heap\/tcache|pwn format-string|pwn SROP\/ret2dlresolve|pwn one_gadget|pwn seccomp\/sandbox|Exploit PoC inventory|PoC replay matrix|Exploit environment pin|Exploit flake triage|Exploit artifact bundle|PCAP\/DFIR|PCAP stream ranking|PCAP secret timeline|PCAP transform chain|PCAP extracted|memory forensics image|memory forensics process|memory forensics credential|memory forensics timeline|Malware static|Malware IOC|Malware behavior|Malware rule|Cloud identity|Cloud\/K8s runtime|Cloud metadata|Cloud privilege|Identity\/AD principal|Identity\/AD credential|Identity\/AD graph|Native deep|Native decompiler|Native compare trace|Native patch hypothesis|Native symbolic|Native fuzz|Frida\/GDB|runtime hook return)/i.test(
					finding,
				),
		);
		if (highSignal) score += 25;
		else deficits.push("no high-signal anchors parsed");
		if (params.followups.length > 0) score += 12;
		else deficits.push("no follow-up commands generated");
		if (params.nextLane) score += 8;
		if (toolOrTargetError) score -= 15;
		if (params.result.killed) score -= 15;
		score = Math.max(0, Math.min(100, score));
		const verdict: EvidenceCritic["verdict"] = score >= 70 ? "strong" : score >= 45 ? "partial" : "weak";
		const selfHeal =
			verdict === "strong"
				? []
				: selfHealCommandsForEvidence({
						pack: params.pack,
						result: params.result,
						findings: params.findings,
						deficits,
					});
		return { score, verdict, deficits, selfHeal };
	}

	function transcriptRepairItems(combined: string): string[] {
		const values = [
			...uniqueMatches(combined, /\b(?:bash|sh|zsh):(?: line \d+:)?\s*([A-Za-z0-9_.+-]+): command not found/gi, 12),
			...uniqueMatches(combined, /\b([A-Za-z0-9_.+-]+): command not found/gi, 12),
			...uniqueMatches(combined, /\b(?:bash|sh|zsh):\s*(?:\d+:\s*)?([A-Za-z0-9_.+-]+): not found\b/gi, 12),
			...uniqueMatches(combined, /ModuleNotFoundError:\s+No module named ['"]?([A-Za-z0-9_.-]+)/gi, 12),
			...uniqueMatches(combined, /ImportError:\s+No module named ['"]?([A-Za-z0-9_.-]+)/gi, 12),
			...uniqueMatches(combined, /Cannot find module ['"]([^'"]+)['"]/gi, 12),
		];
		return [...new Set(values.map((value) => value.replace(/^node:/, "").trim()))]
			.filter((value) => /^[A-Za-z0-9_.+/@-]{2,80}$/.test(value) && !/^(line|not|found|module)$/i.test(value))
			.slice(0, 12);
	}

	function toolRepairMatrixScript(params: {
		pack: LaneCommandPack;
		combined: string;
		repairItems: string[];
		errorLines: string[];
	}): string {
		const commandTools = commandKnownTools(params.pack.commands.map((command) => command.command).join("\n"));
		const payload = {
			route: params.pack.route,
			lane: params.pack.lane,
			target: params.pack.target ?? "",
			repairItems: params.repairItems,
			commandTools,
			errorLines: params.errorLines.slice(0, 12),
		};
		return `cat > /tmp/repi-tool-repair.py <<'PY'\nimport json, pathlib, shutil\npayload=json.loads(${pythonString(JSON.stringify(payload))})\nalternatives={\n 'checksec':['rabin2','readelf','objdump','file'],\n 'r2':['rabin2','objdump','readelf','strings','ghidra'],\n 'radare2':['rabin2','objdump','readelf','strings','ghidra'],\n 'rabin2':['readelf','objdump','file'],\n 'gdb':['lldb','strace','ltrace','objdump'],\n 'ltrace':['strace','gdb'],\n 'strace':['ltrace','gdb','ldd'],\n 'binwalk':['unblob','unsquashfs','file','7z'],\n 'unblob':['binwalk','unsquashfs','file','7z'],\n 'unsquashfs':['binwalk','unblob','7z','file'],\n 'tshark':['tcpdump','capinfos','wireshark'],\n 'capinfos':['tshark','file'],\n 'tcpdump':['tshark','capinfos'],\n 'jadx':['apktool','unzip','strings'],\n 'apktool':['jadx','unzip','strings'],\n 'frida':['frida-ps','gdb','adb'],\n 'curl':['python3','node','wget'],\n 'jq':['python3','node'],\n 'node':['python3'],\n 'python3':['python','node'],\n 'ROPgadget':['ropper','objdump','rabin2'],\n 'ropper':['ROPgadget','objdump','rabin2'],\n 'nmap':['naabu','masscan','curl'],\n 'ffuf':['gobuster','wfuzz','curl'],\n 'gobuster':['ffuf','wfuzz','curl'],\n 'kubectl':['grep','rg'],\n 'aws':['env','grep'],\n 'az':['env','grep'],\n 'gcloud':['env','grep'],\n}\nitems=list(dict.fromkeys(payload.get('repairItems') or payload.get('commandTools') or []))\nprint('[tool-repair]', 'route='+payload.get('route',''), 'lane='+payload.get('lane',''), 'target='+(payload.get('target') or '<none>'), 'items='+(','.join(items) if items else 'none'))\nfor line in payload.get('errorLines', [])[:8]:\n    print('[tool-repair-error]', line[:240])\nfor item in items:\n    alts=alternatives.get(item, [])\n    present=[tool for tool in alts if shutil.which(tool)]\n    direct=shutil.which(item)\n    print('[tool-repair-candidate]', 'item='+item, 'present='+str(bool(direct)).lower(), 'direct='+(direct or ''), 'alternatives='+(','.join(present or alts) if alts else ''), 'bootstrap_hint=re_bootstrap plan '+item)\npathlib.Path('/tmp/repi-tool-repair.json').write_text(json.dumps({'payload':payload,'items':items}, indent=2))\nprint('[tool-repair-artifact]', '/tmp/repi-tool-repair.json')\nPY\npython3 /tmp/repi-tool-repair.py`;
	}

	function analyzeToolRepairEvidence(pack: LaneCommandPack, combined: string): SpecialistEvidenceAnalysis {
		const errorLines = interestingLines(
			combined,
			/command not found|not recognized|No such file|cannot stat|cannot access|ModuleNotFoundError|ImportError|Cannot find module|ERR_MODULE_NOT_FOUND|permission denied|EACCES|ENOENT|ENOTFOUND|ECONNREFUSED|CERTIFICATE_VERIFY_FAILED|SSL|timeout|trace\/breakpoint trap/i,
			18,
		);
		if (errorLines.length === 0) return { findings: [], followups: [] };
		const repairItems = transcriptRepairItems(combined);
		const findings = [`tool repair anchors: ${errorLines.map((line) => truncateMiddle(line, 220)).join(" | ")}`];
		if (repairItems.length > 0) findings.push(`tool repair missing dependency anchors: ${repairItems.join(", ")}`);
		const matrixCommand = toolRepairMatrixScript({ pack, combined, repairItems, errorLines });
		return {
			findings,
			followups: [
				{
					label: "tool-repair-matrix-scaffold",
					command: matrixCommand,
					evidence:
						"build a runtime repair matrix from command errors, missing dependencies, available alternatives, and bootstrap hints",
				},
				{
					label: "tool-repair-rerun",
					command: `[ -f /tmp/repi-tool-repair.py ] && python3 /tmp/repi-tool-repair.py || printf '%s\n' 'rerun tool-repair-matrix-scaffold after a failed lane run'`,
					evidence: "rerun tool/dependency repair matrix after refreshing tool-index or installing alternatives",
				},
			],
		};
	}

	function analyzeNativeDeepEvidence(
		pack: LaneCommandPack,
		combined: string,
		targetArg: string,
	): SpecialistEvidenceAnalysis {
		const enabled =
			/native|reverse|pwn|binary|mobile/i.test(pack.route) ||
			packHasSpecialistSignal(pack, /native-deep|native deep reverse\/pwn|native-symbol-map/i);
		if (!enabled) return { findings: [], followups: [] };
		const findings: string[] = [];
		const followups: LaneCommand[] = [];
		const symbolLines = interestingLines(
			combined,
			/\[native-symbol-map\]|\[native-header\]|\[native-section\]|\[native-symbol\]|\[native-import\]|\[native-string\]|\[native-rabin2\]/i,
			28,
		);
		if (symbolLines.length > 0) {
			findings.push(
				`Native deep symbol/import/string anchors: ${symbolLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
			);
		}
		const decompilerLines = interestingLines(
			combined,
			/\[native-decompiler\]|\[native-decompiler-fallback\]|analyzeHeadless|Ghidra|pdf @|afl|iz~/i,
			18,
		);
		if (decompilerLines.length > 0) {
			findings.push(
				`Native decompiler/control-flow anchors: ${decompilerLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
			);
		}
		const compareLines = interestingLines(
			combined,
			/\[native-compare\]|\[native-compare-trace\]|Breakpoint .*strcmp|Breakpoint .*memcmp|fn=(?:strcmp|strncmp|memcmp)/i,
			18,
		);
		if (compareLines.length > 0) {
			findings.push(
				`Native compare trace anchors: ${compareLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
			);
		}
		const patchLines = interestingLines(combined, /\[native-patch\]|\[native-patch-candidate\]/i, 18);
		if (patchLines.length > 0) {
			findings.push(
				`Native patch hypothesis anchors: ${patchLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
			);
		}
		const symbolicLines = interestingLines(
			combined,
			/\[native-symbolic\]|\[native-symbolic-fn\]|angr=present|cfg_functions/i,
			16,
		);
		if (symbolicLines.length > 0) {
			findings.push(
				`Native symbolic/CFG anchors: ${symbolicLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`,
			);
		}
		const fuzzLines = interestingLines(combined, /\[native-fuzz\]|SIGSEGV|AddressSanitizer|crash|exit=-?11/i, 18);
		if (fuzzLines.length > 0) {
			findings.push(`Native fuzz/crash anchors: ${fuzzLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
		}
		if (
			symbolLines.length > 0 ||
			decompilerLines.length > 0 ||
			compareLines.length > 0 ||
			patchLines.length > 0 ||
			symbolicLines.length > 0 ||
			fuzzLines.length > 0
		) {
			followups.push({
				label: "native-deep-symbol-map-rerun",
				command: `[ -x /tmp/repi-native-symbol-map.sh ] && /tmp/repi-native-symbol-map.sh ${targetArg} || file ${targetArg}; readelf -hW ${targetArg} 2>/dev/null; strings -a -n 5 ${targetArg} | head -220`,
				evidence: "rerun native deep symbol/import/section/string map",
			});
			followups.push({
				label: "native-deep-decompiler-rerun",
				command: `[ -x /tmp/repi-ghidra-import.sh ] && /tmp/repi-ghidra-import.sh ${targetArg} || r2 -A -q -c 'aaa; afl~main,sym.; iz~license,key,serial,valid,invalid,flag; q' ${targetArg}`,
				evidence: "rerun Ghidra/r2 decompiler control-flow scaffold",
			});
			followups.push({
				label: "native-deep-compare-trace-rerun",
				command: `[ -f /tmp/repi-native-compare-trace.gdb ] && gdb -q ${targetArg} -x /tmp/repi-native-compare-trace.gdb || gdb -q ${targetArg} -ex 'set pagination off' -ex 'break strcmp' -ex 'break memcmp' -ex 'run' -ex 'bt' -ex 'quit'`,
				evidence: "rerun native comparison breakpoint trace with narrowed inputs",
			});
			followups.push({
				label: "native-deep-symbolic-fuzz-rerun",
				command: `[ -f /tmp/repi-native-symbolic-fuzz.py ] && python3 /tmp/repi-native-symbolic-fuzz.py ${targetArg} || printf '%s\n' 'rerun native-deep-symbolic-fuzz-scaffold from re_lane plan'`,
				evidence: "rerun angr/CFG symbolic scaffold and bounded fuzz smoke tests",
			});
			followups.push({
				label: "native-deep-patch-report-scaffold",
				command:
					"python3 - <<'PY'\nimport json, pathlib\np=pathlib.Path('/tmp/repi-native-patch-candidates.json')\nprint('[native-patch-report] artifact=' + str(p) + ' exists=' + str(p.exists()))\nif p.exists():\n obj=json.loads(p.read_text()); print('[native-patch-report] target=' + str(obj.get('target')) + ' candidates=' + str(len(obj.get('candidates', []))))\nprint('Next: bind one compare/branch site to runtime trace, then prove byte patch or input constraint with replay.')\nPY",
				evidence: "consolidated native patch hypothesis report scaffold before byte mutation",
			});
		}
		return {
			findings,
			followups,
			nextLane:
				patchLines.length > 0 || compareLines.length > 0
					? "patch/proof"
					: symbolicLines.length > 0 || fuzzLines.length > 0
						? "runtime-proof/poc"
						: symbolLines.length > 0 || decompilerLines.length > 0
							? "control-flow/runtime"
							: undefined,
		};
	}

	function analyzeLaneRun(
		pack: LaneCommandPack,
		result: { code: number; stdout: string; stderr: string; killed?: boolean },
	): LaneRunAnalysis {
		const combined = `${result.stdout}\n${result.stderr}`;
		const lowerRoute = pack.route.toLowerCase();
		const lowerLane = pack.lane.toLowerCase();
		const targetArg = pack.target ? shellQuote(pack.target) : "<TARGET>";
		const findings: string[] = [];
		const followups: LaneCommand[] = [];
		const addFinding = (finding: string) => {
			if (!findings.includes(finding)) findings.push(finding);
		};
		const addFollowup = (label: string, command: string, evidence: string) =>
			followups.push({ label, command, evidence });

		if (result.code !== 0) addFinding(`command-pack exited nonzero: ${result.code}`);
		if (result.killed) addFinding("command-pack was killed or timed out");
		if (
			/command not found|not found|no such file|cannot access|permission denied|trace\/breakpoint trap/i.test(
				combined,
			)
		) {
			addFinding("tool/target/runtime error surfaced; inspect stderr and run re_bootstrap or adjust target path");
		}

		const addresses = uniqueMatches(combined, /\b0x[0-9a-f]{4,16}\b/gi, 16);
		if (addresses.length > 0) addFinding(`address anchors: ${addresses.join(", ")}`);

		const compareSymbols = uniqueMatches(
			combined,
			/\b(strcmp|strncmp|memcmp|strstr|strcasecmp|strncasecmp|crypto|decrypt|verify|check|license|serial|valid|invalid)\b/gi,
			20,
		);
		if (compareSymbols.length > 0) addFinding(`comparison/verification anchors: ${compareSymbols.join(", ")}`);

		const signalLines = interestingLines(
			combined,
			/license|serial|key|valid|invalid|strcmp|strncmp|memcmp|strstr|verify|check|flag|fail|success|denied|authorized/i,
			12,
		);
		if (signalLines.length > 0)
			addFinding(`interesting output lines: ${signalLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);

		if (/native|pwn|mobile/.test(lowerRoute)) {
			if (/RELRO|Canary|NX|PIE|RPATH|RUNPATH|ELF|Mach-O|PE32/i.test(combined)) {
				addFinding("binary format/mitigation metadata captured");
			}
			if (pack.target && /strcmp|strncmp|memcmp|strstr|license|serial|valid|invalid|verify|check/i.test(combined)) {
				addFollowup(
					"runtime-compare-breakpoints",
					`gdb -q ${targetArg} -ex 'set pagination off' -ex 'break strcmp' -ex 'break strncmp' -ex 'break memcmp' -ex 'run' -ex 'bt' -ex 'quit'`,
					"runtime comparison call stack and arguments",
				);
				addFollowup(
					"r2-focused-xrefs",
					`r2 -A -q -c 'iz~license,key,serial,valid,invalid,check,verify,fail; afl~main; axt @@ str.*; q' ${targetArg}`,
					"focused xrefs around verification strings",
				);
			}
			if (pack.target && addresses.length > 0) {
				addFollowup(
					"r2-anchor-disassembly",
					`r2 -A -q -c '${addresses
						.slice(0, 4)
						.map((address) => `pdf @ ${address}`)
						.join("; ")}; q' ${targetArg}`,
					"disassembly for discovered address anchors",
				);
			}
		}

		if (/web|api/.test(lowerRoute)) {
			const routeLines = interestingLines(
				combined,
				/route|router|app\.|auth|session|jwt|csrf|graphql|websocket|controller/i,
				16,
			);
			if (routeLines.length > 0)
				addFinding(`route/auth anchors: ${routeLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
			addFollowup(
				"request-replay-scaffold",
				'rg -n "curl|fetch\\(|axios|supertest|request\\(" .; rg -n "auth|session|jwt|csrf|role|permission|owner" .',
				"request replay and authorization boundary candidates",
			);
		}

		if (/frontend|js/.test(lowerRoute)) {
			const jsLines = interestingLines(
				combined,
				/fetch\(|XMLHttpRequest|WebSocket|crypto|sign|nonce|timestamp|encrypt|decrypt/i,
				16,
			);
			if (jsLines.length > 0)
				addFinding(`JS runtime/signing anchors: ${jsLines.map((line) => truncateMiddle(line, 180)).join(" | ")}`);
			addFollowup(
				"node-rebuild-scaffold",
				'rg -n "sign|nonce|timestamp|crypto|encrypt|decrypt|fetch\\(|XMLHttpRequest" .',
				"minimal JS signing/encryption rebuild candidates",
			);
		}

		if (/android|mobile/.test(lowerRoute)) {
			if (/frida|root|debug|emulator|jadx|smali|JNI|\\.so/i.test(combined))
				addFinding("Android anti-analysis/native split anchors captured");
			if (pack.target) {
				addFollowup(
					"jadx-focused-search",
					`tmp=$(mktemp -d); jadx -q -d "$tmp" ${targetArg} >/dev/null 2>&1 && rg -n "license|serial|key|valid|invalid|check|verify|root|debug|frida|token|secret" "$tmp" | head -240`,
					"focused Java/Kotlin verification and anti-analysis call sites",
				);
			}
		}

		const specialistNextHints = [
			mergeSpecialistEvidenceAnalysis(analyzeToolRepairEvidence(pack, combined), findings, followups),
			mergeSpecialistEvidenceAnalysis(analyzeNativeDeepEvidence(pack, combined, targetArg), findings, followups),
			mergeSpecialistEvidenceAnalysis(analyzeBrowserXhrWsEvidence(pack, combined, targetArg), findings, followups),
			mergeSpecialistEvidenceAnalysis(analyzeWebScannerEvidence(pack, combined, targetArg), findings, followups),
			mergeSpecialistEvidenceAnalysis(analyzeJsSigningEvidence(pack, combined), findings, followups),
			mergeSpecialistEvidenceAnalysis(analyzeCryptoStegoEvidence(pack, combined, targetArg), findings, followups),
			mergeSpecialistEvidenceAnalysis(analyzePwnPrimitiveEvidence(pack, combined, targetArg), findings, followups),
			mergeSpecialistEvidenceAnalysis(
				analyzeExploitReliabilityEvidence(pack, combined, targetArg),
				findings,
				followups,
			),
			mergeSpecialistEvidenceAnalysis(analyzePcapDfirEvidence(pack, combined, targetArg), findings, followups),
			mergeSpecialistEvidenceAnalysis(
				analyzeMemoryForensicsEvidence(pack, combined, targetArg),
				findings,
				followups,
			),
			mergeSpecialistEvidenceAnalysis(analyzeFirmwareIotEvidence(pack, combined, targetArg), findings, followups),
			mergeSpecialistEvidenceAnalysis(analyzeIosEvidence(pack, combined, targetArg), findings, followups),
			mergeSpecialistEvidenceAnalysis(analyzeAgentSecurityEvidence(pack, combined, targetArg), findings, followups),
			mergeSpecialistEvidenceAnalysis(analyzeMalwareEvidence(pack, combined, targetArg), findings, followups),
			mergeSpecialistEvidenceAnalysis(analyzeFridaGdbEvidence(pack, combined, targetArg), findings, followups),
			mergeSpecialistEvidenceAnalysis(analyzeCloudIdentityEvidence(pack, combined), findings, followups),
			mergeSpecialistEvidenceAnalysis(analyzeIdentityAdEvidence(pack, combined), findings, followups),
		].filter((hint): hint is string => Boolean(hint));
		if (specialistNextHints.length > 0) {
			addFinding(`specialist runtime follow-up hints: ${specialistNextHints.join(", ")}`);
		}

		let nextLane: string | undefined;
		if (specialistNextHints.length > 0) nextLane = specialistNextHints[0];
		if (!nextLane && /triage|map|surface|observe|mitigation/.test(lowerLane) && findings.length > 0)
			nextLane = "control-flow/state/prove";
		if (
			!nextLane &&
			/control|flow|state|prove|primitive/.test(lowerLane) &&
			/comparison|route\/auth|JS runtime|address anchors/.test(findings.join("\n"))
		) {
			nextLane = "runtime-proof/poc";
		}
		if (!nextLane && /runtime|proof|poc|verify|exploit/.test(lowerLane) && result.code === 0) nextLane = "report";
		if (followups.length > 0)
			addFinding(`next command pack candidates: ${followups.map((command) => command.label).join(", ")}`);
		if (findings.length === 0)
			addFinding("no high-signal anchors parsed; switch evidence surface or widen passive map");
		const critic = evaluateEvidenceQuality({ pack, result, findings, followups, nextLane });
		return { findings, followups, critic, nextLane };
	}

	function formatLaneRunSummary(params: {
		pack: LaneCommandPack;
		strategy?: AutopilotExecutionStrategy;
		runnableCount: number;
		result: { code: number; stdout: string; stderr: string; killed?: boolean };
		analysis: LaneRunAnalysis;
		artifactPath: string;
		evidence: EvidenceRecord;
		missionUpdate: string;
	}): string {
		const { pack, strategy, runnableCount, result, analysis, artifactPath, evidence, missionUpdate } = params;
		const followup = analysis.followups[0] ?? analysis.critic.selfHeal[0];
		return truncateMiddle(
			[
				"lane_run:",
				"status: executed",
				`mission_id: ${pack.missionId ?? "none"}`,
				`route: ${truncateMiddle(pack.route, 120)}`,
				`lane: ${truncateMiddle(pack.lane, 120)}`,
				`target: ${truncateMiddle(pack.target ?? "<TARGET>", 240)}`,
				`execution_strategy: ${strategy?.mode ?? "direct"}`,
				`executed_count: ${runnableCount}`,
				`fallback_count: ${strategy?.fallbacks.length ?? 0}`,
				`skipped_count: ${strategy?.skipped.length ?? 0}`,
				`missing_tools: ${strategy?.missingTools.slice(0, 12).join(", ") || "none"}`,
				`exit: ${result.code}`,
				`killed: ${result.killed ? "true" : "false"}`,
				`stdout_bytes: ${Buffer.byteLength(result.stdout)}`,
				`stdout_sha256: ${sha256Text(result.stdout)}`,
				`stderr_bytes: ${Buffer.byteLength(result.stderr)}`,
				`stderr_sha256: ${sha256Text(result.stderr)}`,
				`evidence_artifact: ${artifactPath}`,
				`evidence_ledger: ${evidence.timestamp} ${evidence.title}`,
				`verify: cat ${shellQuote(artifactPath)}`,
				missionUpdate,
				"evidence_quality:",
				`score: ${analysis.critic.score}`,
				`verdict: ${analysis.critic.verdict}`,
				...(analysis.critic.deficits.length > 0
					? ["deficits:", ...analysis.critic.deficits.slice(0, 4).map((item) => `- ${truncateMiddle(item, 180)}`)]
					: ["deficits: none"]),
				"findings:",
				...analysis.findings.slice(0, 6).map((finding) => `- ${truncateMiddle(finding, 240)}`),
				...(analysis.findings.length > 6 ? [`findings_omitted: ${analysis.findings.length - 6}`] : []),
				...(analysis.nextLane ? [`next_lane_hint: ${truncateMiddle(analysis.nextLane, 160)}`] : []),
				`followup_count: ${analysis.followups.length}`,
				`followup_labels: ${
					analysis.followups
						.slice(0, 8)
						.map((item) => item.label)
						.join(", ") || "none"
				}`,
				`self_heal_count: ${analysis.critic.selfHeal.length}`,
				`self_heal_labels: ${
					analysis.critic.selfHeal
						.slice(0, 8)
						.map((item) => item.label)
						.join(", ") || "none"
				}`,
				...(followup ? [`next_command: ${truncateMiddle(followup.command, 320)}`] : []),
				"detail: full command pack, analysis, follow-ups, self-heal commands, stdout, and stderr are in evidence_artifact",
			].join("\n"),
			4096,
		);
	}

	function formatUnexecutedLaneRunSummary(
		pack: LaneCommandPack,
		strategy: AutopilotExecutionStrategy | undefined,
	): string {
		return truncateMiddle(
			[
				"lane_run:",
				"status: blocked",
				`mission_id: ${pack.missionId ?? "none"}`,
				`route: ${truncateMiddle(pack.route, 120)}`,
				`lane: ${truncateMiddle(pack.lane, 120)}`,
				`target: ${truncateMiddle(pack.target ?? "<TARGET>", 240)}`,
				`execution_strategy: ${strategy?.mode ?? "blocked"}`,
				"executed_count: 0",
				`candidate_count: ${pack.commands.length}`,
				`fallback_count: ${strategy?.fallbacks.length ?? 0}`,
				`skipped_count: ${strategy?.skipped.length ?? 0}`,
				`missing_tools: ${strategy?.missingTools.slice(0, 12).join(", ") || "none"}`,
				`command_labels: ${
					pack.commands
						.slice(0, 12)
						.map((item) => item.label)
						.join(", ") || "none"
				}`,
				`notes: ${
					pack.notes
						.slice(0, 3)
						.map((note) => truncateMiddle(note, 180))
						.join(" | ") || "none"
				}`,
				"next: provide target/url, refresh re_tool_index, run re_bootstrap plan, or inspect re_lane plan",
			].join("\n"),
			2048,
		);
	}

	function writeLaneRunArtifact(params: {
		pack: LaneCommandPack;
		runnable: LaneCommand[];
		script: string;
		result: { code: number; stdout: string; stderr: string; killed?: boolean };
		analysis: LaneRunAnalysis;
	}): string {
		ensureReconStorage();
		const timestamp = new Date().toISOString();
		const path = join(evidenceRunsDir(), `${timestamp.replace(/[:.]/g, "-")}-${slug(params.pack.lane)}.md`);
		writePrivateTextFile(
			path,
			[
				"# REPI Lane Run Artifact",
				"",
				`timestamp: ${timestamp}`,
				`mission_id: ${params.pack.missionId ?? "none"}`,
				`route: ${params.pack.route}`,
				`lane: ${params.pack.lane}`,
				`target: ${params.pack.target ?? "<TARGET>"}`,
				`exit: ${params.result.code}`,
				`killed: ${params.result.killed ? "true" : "false"}`,
				"",
				"## Auto analysis",
				"",
				...params.analysis.findings.map((finding) => `- ${finding}`),
				...(params.analysis.nextLane ? [`- next_lane_hint: ${params.analysis.nextLane}`] : []),
				"",
				"## Evidence critic",
				"",
				`score: ${params.analysis.critic.score}`,
				`verdict: ${params.analysis.critic.verdict}`,
				"",
				"deficits:",
				...(params.analysis.critic.deficits.length > 0
					? params.analysis.critic.deficits.map((deficit) => `- ${deficit}`)
					: ["- none"]),
				"",
				"## Follow-up commands",
				"",
				...(params.analysis.followups.length > 0
					? params.analysis.followups.map((command, index) =>
							[
								`### ${index + 1}. ${command.label}`,
								"",
								"```bash",
								command.command,
								"```",
								"",
								`evidence: ${command.evidence}`,
								"",
							].join("\n"),
						)
					: ["No high-confidence follow-up commands parsed.", ""]),
				"## Self-heal commands",
				"",
				...(params.analysis.critic.selfHeal.length > 0
					? params.analysis.critic.selfHeal.map((command, index) =>
							[
								`### ${index + 1}. ${command.label}`,
								"",
								"```bash",
								command.command,
								"```",
								"",
								`evidence: ${command.evidence}`,
								"",
							].join("\n"),
						)
					: ["No self-heal commands required.", ""]),
				"## Runnable commands",
				"",
				...params.runnable.map((command, index) =>
					[
						`### ${index + 1}. ${command.label}`,
						"",
						"```bash",
						command.command,
						"```",
						"",
						`evidence: ${command.evidence}`,
						"",
					].join("\n"),
				),
				"## Script",
				"",
				"```bash",
				params.script,
				"```",
				"",
				"## stdout",
				"",
				"```",
				params.result.stdout,
				"```",
				"",
				"## stderr",
				"",
				"```",
				params.result.stderr,
				"```",
				"",
			].join("\n"),
		);
		return path;
	}

	async function runLaneCommandPackWithStatus(
		pi: ExtensionAPI,
		pack: LaneCommandPack,
		options: { strategy?: AutopilotExecutionStrategy; applyStrategy?: boolean } = {},
	): Promise<LaneCommandPackRun> {
		const strategy = options.strategy ?? (options.applyStrategy === false ? undefined : laneExecutionStrategy(pack));
		const effectivePack = strategy?.pack ?? pack;
		const runnable = effectivePack.commands.filter(
			(command) => !/[<][A-Z_]+[>]/.test(command.command) && !/^re_/.test(command.command),
		);
		if (runnable.length === 0)
			return {
				executed: false,
				text: formatUnexecutedLaneRunSummary(effectivePack, strategy),
			};
		const script = [
			"set -u",
			...runnable.map((command, index) =>
				[`echo '### lane-command ${index + 1}: ${command.label.replace(/'/g, "'\\''")}'`, command.command].join(
					"\n",
				),
			),
		].join("\n");
		const result = await pi.exec("bash", ["-lc", script], { timeout: 120000 });
		const analysis = analyzeLaneRun(effectivePack, result);
		const artifactPath = writeLaneRunArtifact({ pack: effectivePack, runnable, script, result, analysis });
		const evidence = appendEvidence({
			kind: "runtime",
			title: `lane-run ${effectivePack.lane} exit ${result.code}`,
			fact: [
				`Executed ${runnable.length} command(s) for ${effectivePack.route}/${effectivePack.lane}`,
				effectivePack.target ? `target=${effectivePack.target}` : "target=<none>",
				strategy ? `execution_strategy=${strategy.mode}` : undefined,
				strategy?.fallbacks.length ? `fallbacks=${strategy.fallbacks.length}` : undefined,
				strategy?.skipped.length ? `skipped=${strategy.skipped.length}` : undefined,
				`evidence_quality=${analysis.critic.score}`,
				`evidence_verdict=${analysis.critic.verdict}`,
				analysis.critic.selfHeal.length ? `self_heal=${analysis.critic.selfHeal.length}` : undefined,
				`exit=${result.code}`,
				`stdout=${Buffer.byteLength(result.stdout)}B`,
				`stdout_sha256=${sha256Text(result.stdout)}`,
				`stderr=${Buffer.byteLength(result.stderr)}B`,
				`stderr_sha256=${sha256Text(result.stderr)}`,
				result.killed ? "killed=true" : "killed=false",
				`findings=${analysis.findings
					.slice(0, 6)
					.map((finding) => truncateMiddle(finding, 180))
					.join(" | ")}`,
				analysis.nextLane ? `next_lane_hint=${analysis.nextLane}` : undefined,
			]
				.filter(Boolean)
				.join("; "),
			command: `re_lane run ${effectivePack.lane}${effectivePack.target ? ` ${effectivePack.target}` : ""}`,
			path: artifactPath,
			verify: `cat ${artifactPath}`,
			confidence: "auto-captured lane command run",
		});
		const missionUpdate = applyLaneRunMissionUpdate({ pack: effectivePack, analysis, result, artifactPath });
		return {
			executed: true,
			text: formatLaneRunSummary({
				pack: effectivePack,
				strategy,
				runnableCount: runnable.length,
				result,
				analysis,
				artifactPath,
				evidence,
				missionUpdate: missionUpdate.message,
			}),
		};
	}

	async function runLaneCommandPack(
		pi: ExtensionAPI,
		pack: LaneCommandPack,
		options: { strategy?: AutopilotExecutionStrategy; applyStrategy?: boolean } = {},
	): Promise<string> {
		return (await runLaneCommandPackWithStatus(pi, pack, options)).text;
	}

	return {
		findLaneIndex,
		updateMissionLane,
		autoCommandsForLane,
		autoLaneCommandPack,
		removeLaneNextItems,
		formatLaneQueue,
		pythonString,
		activeLane,
		latestPassiveMapContext,
		inferTargetFromMap,
		laneCommandPack,
		formatLaneCommandPack,
		runLaneCommandPack,
		runLaneCommandPackWithStatus,
	};
}
