import { join } from "node:path";
import type { ExtensionAPI } from "../extensions/types.ts";
import type { BootstrapPlan } from "./autopilot-runtime.ts";
import { updateMissionCheckpoint } from "./mission.ts";
import { REPI_TOOL_INDEX_CANDIDATES } from "./profile.ts";
import type { AutopilotExecutionStrategy, LaneCommandPack, PassiveMapContext } from "./recon-lane-runtime.ts";
import { ensureReconStorage } from "./resources.ts";
import type { RoutePlan } from "./routes.ts";
import type { LaneCommand } from "./specialist-command-planner.ts";
import { evidenceRunsDir, readTextFile, toolIndexPath, writePrivateTextFile } from "./storage.ts";
import { escapeRegExp, shellQuote } from "./target.ts";
import { compactStoredArtifact, truncateMiddle } from "./text.ts";
import { repiIndexedToolPresent, repiResolvedToolPresent } from "./tool-presence.ts";
import { REPI_TOOL_BOOTSTRAP_CATALOG, type RepiToolBootstrapCatalogEntry } from "./toolchain.ts";

export type ToolIndexEntry = { present: boolean; path?: string };

const SHELL_BUILTIN_OR_TEXT_TOOL =
	/^(set|echo|cat|sed|awk|grep|head|tail|find|for|if|then|else|fi|while|do|done|export|cd|pwd|ls|printf|case|esac)$/;

const COMMAND_TOOL_PROBES = [
	"file",
	"sha256sum",
	"readelf",
	"strings",
	"rabin2",
	"r2",
	"radare2",
	"objdump",
	"checksec",
	"ghidra",
	"strace",
	"ltrace",
	"gdb",
	"ROPgadget",
	"ropper",
	"patchelf",
	"jadx",
	"apktool",
	"aapt",
	"adb",
	"frida",
	"frida-ps",
	"objection",
	"ios-deploy",
	"class-dump",
	"otool",
	"nm",
	"codesign",
	"plutil",
	"curl",
	"rg",
	"jq",
	"python3",
	"node",
	"playwright",
	"mitmproxy",
	"nmap",
	"ffuf",
	"feroxbuster",
	"gobuster",
	"nikto",
	"dalfox",
	"arjun",
	"nuclei",
	"httpx",
	"katana",
	"burpsuite",
	"tshark",
	"capinfos",
	"tcpdump",
	"wireshark",
	"volatility3",
	"binwalk",
	"foremost",
	"unblob",
	"unsquashfs",
	"ubireader_extract_files",
	"qemu-mips",
	"qemu-arm",
	"yara",
	"capa",
	"floss",
	"clamscan",
	"upx",
	"docker",
	"kubectl",
	"aws",
	"az",
	"gcloud",
	"ldapsearch",
	"impacket-secretsdump",
	"nxc",
	"crackmapexec",
	"bloodhound-python",
	"certipy",
] as const;

export function buildToolDigest(): string {
	ensureReconStorage();
	const text = readTextFile(toolIndexPath()).trim();
	return text ? truncateMiddle(text, 5000) : "工具索引为空；优先调用 re_tool_index refresh。";
}

export function bootstrapCatalogFor(tool: string): RepiToolBootstrapCatalogEntry | undefined {
	return REPI_TOOL_BOOTSTRAP_CATALOG.find((entry) => entry.tool.toLowerCase() === tool.toLowerCase());
}

export function parseToolIndex(): Map<string, ToolIndexEntry> {
	ensureReconStorage();
	const rows = new Map<string, ToolIndexEntry>();
	for (const line of readTextFile(toolIndexPath()).split(/\r?\n/)) {
		const match = /^\|\s*([^|]+?)\s*\|\s*(yes|no)\s*\|\s*([^|]*?)\s*\|/i.exec(line);
		if (!match) continue;
		const tool = match[1]?.trim();
		if (!tool || tool === "Tool") continue;
		rows.set(tool, { present: match[2]?.toLowerCase() === "yes", path: match[3]?.trim() || undefined });
	}
	return rows;
}

export function createBootstrapPlan(tools: string[]): BootstrapPlan[] {
	const index = parseToolIndex();
	return tools.map((tool) => {
		const indexed = index.get(tool);
		const catalog = bootstrapCatalogFor(tool);
		return {
			tool,
			present: indexed?.present ?? false,
			path: indexed?.path,
			install: catalog?.install,
			verify: catalog?.verify,
			known: catalog !== undefined,
		};
	});
}

export function formatBootstrapPlan(plan: BootstrapPlan[]): string {
	if (plan.length === 0) return "未指定工具。用 re_bootstrap plan/install 并传入 tools。";
	return [
		"| Tool | Present | Path | Known bootstrap | Install | Verify |",
		"|---|---:|---|---:|---|---|",
		...plan.map(
			(item) =>
				`${[
					`| ${item.tool}`,
					item.present ? "yes" : "no",
					item.path ?? "",
					item.known ? "yes" : "no",
					item.install ? `\`${item.install.replace(/`/g, "\\`")}\`` : "",
					item.verify ? `\`${item.verify.replace(/`/g, "\\`")}\`` : "",
				].join(" | ")} |`,
		),
	].join("\n");
}

function toolsFromCommand(command: string): string[] {
	const firstToken = command.trim().split(/\s+/)[0]?.replace(/['"`]/g, "");
	const tools = new Set<string>();
	if (firstToken && !SHELL_BUILTIN_OR_TEXT_TOOL.test(firstToken)) tools.add(firstToken);
	for (const tool of COMMAND_TOOL_PROBES) {
		if (new RegExp(`(^|[^A-Za-z0-9_.-])${escapeRegExp(tool)}([^A-Za-z0-9_.-]|$)`).test(command)) tools.add(tool);
	}
	return Array.from(tools);
}

export function recommendedToolsForRoute(route: RoutePlan, pack?: LaneCommandPack, map?: PassiveMapContext): string[] {
	const tools = new Set<string>(["file", "sha256sum", "rg", "python3"]);
	const domain = route.domain;
	if (/Native reverse/i.test(domain)) {
		for (const tool of [
			"readelf",
			"strings",
			"objdump",
			"rabin2",
			"r2",
			"ghidra",
			"checksec",
			"gdb",
			"strace",
			"ltrace",
		])
			tools.add(tool);
	}
	if (/Pwn\s*\/\s*exploit/i.test(domain)) {
		for (const tool of ["checksec", "gdb", "ROPgadget", "ropper", "one_gadget", "patchelf"]) tools.add(tool);
	}
	if (domain === "Mobile / Android") {
		for (const tool of ["jadx", "apktool", "adb", "frida", "frida-ps", "objection", "aapt", "readelf", "r2"])
			tools.add(tool);
	}
	if (domain === "Mobile / iOS") {
		for (const tool of ["unzip", "plutil", "otool", "nm", "codesign", "class-dump", "frida", "frida-ps", "objection"])
			tools.add(tool);
	}
	if (domain === "Web / API pentest") {
		for (const tool of ["curl", "node", "nmap", "ffuf", "gobuster", "sqlmap", "burpsuite", "playwright"])
			tools.add(tool);
	}
	if (domain === "Web pentest scanning") {
		for (const tool of [
			"curl",
			"httpx",
			"katana",
			"ffuf",
			"feroxbuster",
			"gobuster",
			"nuclei",
			"nikto",
			"dalfox",
			"sqlmap",
			"burpsuite",
		])
			tools.add(tool);
	}
	if (domain === "Frontend JS reverse") {
		for (const tool of ["node", "npm", "curl", "playwright", "rg"]) tools.add(tool);
	}
	if (domain === "Firmware / IoT") {
		for (const tool of [
			"binwalk",
			"unblob",
			"unsquashfs",
			"ubireader_extract_files",
			"strings",
			"file",
			"r2",
			"qemu-mips",
			"qemu-arm",
			"qemu-aarch64",
		])
			tools.add(tool);
	}
	if (domain === "Agent / LLM boundary") {
		for (const tool of ["rg", "python3", "node", "jq", "curl", "playwright", "mitmproxy"]) tools.add(tool);
	}
	if (domain === "Exploit reliability") {
		for (const tool of ["python3", "jq", "curl", "file", "sha256sum", "node", "gdb"]) tools.add(tool);
	}
	if (/DFIR/i.test(domain)) {
		for (const tool of ["tshark", "capinfos", "tcpdump", "wireshark", "exiftool", "binwalk", "foremost"])
			tools.add(tool);
	}
	if (domain === "Memory forensics") {
		for (const tool of ["volatility3", "file", "strings", "yara", "python3", "foremost"]) tools.add(tool);
	}
	if (/Malware/i.test(domain)) {
		for (const tool of [
			"strings",
			"readelf",
			"rabin2",
			"objdump",
			"yara",
			"capa",
			"floss",
			"clamscan",
			"upx",
			"strace",
			"ltrace",
		])
			tools.add(tool);
	}
	if (/Cloud|Container/i.test(domain)) {
		for (const tool of ["docker", "kubectl", "aws", "az", "gcloud", "nmap"]) tools.add(tool);
	}
	if (/Identity|Windows/.test(domain)) {
		for (const tool of ["impacket-secretsdump", "bloodhound-python", "certipy", "ldapsearch", "nxc", "crackmapexec"])
			tools.add(tool);
	}
	for (const command of pack?.commands ?? []) {
		for (const tool of toolsFromCommand(command.command)) tools.add(tool);
	}
	for (const signal of map?.signals ?? []) {
		if (/Android|Dalvik|APK/i.test(signal)) for (const tool of ["jadx", "apktool", "adb", "frida"]) tools.add(tool);
		if (/ELF|Mach-O|PE32|WebAssembly/i.test(signal))
			for (const tool of ["readelf", "strings", "r2", "objdump"]) tools.add(tool);
		if (/graphql|websocket|route|auth|jwt/i.test(signal))
			for (const tool of ["curl", "node", "ffuf", "playwright"]) tools.add(tool);
	}
	return Array.from(tools)
		.filter((tool) => bootstrapCatalogFor(tool) !== undefined)
		.slice(0, 24);
}

export function autopilotBootstrapPlan(
	route: RoutePlan,
	pack?: LaneCommandPack,
	map?: PassiveMapContext,
): BootstrapPlan[] {
	return createBootstrapPlan(recommendedToolsForRoute(route, pack, map));
}

export function formatAutopilotBootstrap(plan: BootstrapPlan[]): string {
	const missing = plan.filter((item) => !item.present && item.known);
	return [
		"bootstrap_plan:",
		`recommended_tools: ${plan.map((item) => item.tool).join(", ") || "none"}`,
		`missing_known: ${missing.map((item) => item.tool).join(", ") || "none"}`,
		formatBootstrapPlan(plan),
		missing.length > 0
			? `next_bootstrap_command: re_bootstrap plan ${missing.map((item) => item.tool).join(" ")}`
			: "next_bootstrap_command: none",
	].join("\n");
}

function knownReconTool(tool: string): boolean {
	const lower = tool.toLowerCase();
	return (
		REPI_TOOL_INDEX_CANDIDATES.some((candidate) => candidate.toLowerCase() === lower) ||
		REPI_TOOL_BOOTSTRAP_CATALOG.some((entry) => entry.tool.toLowerCase() === lower) ||
		["aapt", "unzip", "ldd", "curl", "rg", "python", "python3"].includes(lower)
	);
}

export function commandKnownTools(command: string): string[] {
	return toolsFromCommand(command).filter((tool) => knownReconTool(tool));
}

function missingToolsForCommand(command: string, index: Map<string, ToolIndexEntry>): string[] {
	return commandKnownTools(command).filter((tool) => repiResolvedToolPresent(index, tool) === false);
}

function fallbackForMissingTools(
	command: LaneCommand,
	missingTools: string[],
	pack: LaneCommandPack,
	index: Map<string, ToolIndexEntry>,
): LaneCommand | undefined {
	const target = pack.target ? shellQuote(pack.target) : "<TARGET>";
	const label = `${command.label}:fallback`;
	const evidence = `${command.evidence}; fallback for missing tools: ${missingTools.join(", ")}`;
	const hasReplacement = (tools: string[]) => tools.some((tool) => repiResolvedToolPresent(index, tool) === true);
	if (missingTools.includes("checksec") && target !== "<TARGET>" && hasReplacement(["rabin2", "readelf"])) {
		const rabin = repiIndexedToolPresent(index, "rabin2")
			? `rabin2 -I ${target} 2>/dev/null | grep -Ei 'canary|nx|pic|relro|stripped|arch|bits' || true`
			: "";
		const readelf = `readelf -hW ${target}; readelf -lW ${target} 2>/dev/null | grep -Ei 'GNU_STACK|GNU_RELRO' || true`;
		return { label, command: [rabin, readelf].filter(Boolean).join("; "), evidence };
	}
	if (missingTools.includes("rabin2") && target !== "<TARGET>" && hasReplacement(["readelf", "objdump"])) {
		return {
			label,
			command: `readelf -hW ${target}; readelf -sW ${target} 2>/dev/null | head -160; objdump -T ${target} 2>/dev/null | head -120`,
			evidence,
		};
	}
	if (
		(missingTools.includes("r2") || missingTools.includes("radare2")) &&
		target !== "<TARGET>" &&
		hasReplacement(["strings", "objdump", "readelf"])
	) {
		return {
			label,
			command: [
				`strings -a -n 5 ${target} | grep -iE 'license|serial|key|valid|invalid|check|verify|strcmp|memcmp|flag|pass|fail' | head -160`,
				`objdump -d -Mintel ${target} 2>/dev/null | grep -iE 'strcmp|memcmp|strncmp|license|serial|key|valid|invalid' -C 8 | head -220 || true`,
				`readelf -sW ${target} 2>/dev/null | grep -iE 'main|strcmp|memcmp|license|verify|check' | head -120 || true`,
			].join("; "),
			evidence,
		};
	}
	if (missingTools.includes("ltrace") && target !== "<TARGET>" && hasReplacement(["strace"])) {
		return {
			label,
			command: `strace -f -e trace=read,write,openat,execve -s 256 ${target} 2>&1 | head -180 || true`,
			evidence,
		};
	}
	if (missingTools.includes("strace") && target !== "<TARGET>") {
		return {
			label,
			command: `ldd ${target} 2>/dev/null || true; ${target} </dev/null 2>&1 | head -120 || true`,
			evidence,
		};
	}
	if (missingTools.includes("aapt") && target !== "<TARGET>") {
		return {
			label,
			command: `unzip -l ${target} | head -180; unzip -p ${target} AndroidManifest.xml 2>/dev/null | head -80 || true`,
			evidence,
		};
	}
	if (missingTools.includes("jadx") && target !== "<TARGET>") {
		return {
			label,
			command: `strings -a -n 5 ${target} | grep -iE 'license|serial|key|valid|invalid|check|verify|root|debug|frida|token|secret' | head -220`,
			evidence,
		};
	}
	if (missingTools.includes("curl") && hasReplacement(["python3"])) {
		const urlMatch = /\bcurl\b[\s\S]*?\s((?:https?:\/\/|http:\/\/|https:\/\/)[^\s'"`]+)/.exec(command.command);
		const url = urlMatch?.[1] ?? pack.target;
		if (url) {
			return {
				label,
				command: `python3 - <<'PY'\nfrom urllib.request import Request, urlopen\nurl=${JSON.stringify(url)}\nr=urlopen(Request(url, headers={'User-Agent':'REPI'}), timeout=10)\nprint('status:', r.status)\nprint(r.read(4096).decode('utf-8','replace'))\nPY`,
				evidence,
			};
		}
	}
	return undefined;
}

export function autopilotExecutionStrategy(
	pack: LaneCommandPack,
	bootstrapPlan: BootstrapPlan[],
): AutopilotExecutionStrategy {
	const index = parseToolIndex();
	const knownMissing = bootstrapPlan.filter((item) => item.known && !item.present).map((item) => item.tool);
	if (index.size === 0) {
		return {
			mode: "tool-index-missing",
			pack,
			missingTools: knownMissing,
			fallbacks: [],
			skipped: [],
			notes: [
				"tool-index 为空：autopilot 不做破坏性安装，也不盲目裁剪命令；建议先 re_tool_index refresh 或 re_bootstrap plan。",
			],
		};
	}
	const nextCommands: LaneCommand[] = [];
	const fallbacks: AutopilotExecutionStrategy["fallbacks"] = [];
	const skipped: AutopilotExecutionStrategy["skipped"] = [];
	for (const command of pack.commands) {
		const missing = missingToolsForCommand(command.command, index);
		if (missing.length === 0) {
			nextCommands.push(command);
			continue;
		}
		const fallback = fallbackForMissingTools(command, missing, pack, index);
		if (fallback) {
			nextCommands.push(fallback);
			fallbacks.push({ label: command.label, missing, command: fallback.command });
			continue;
		}
		skipped.push({ label: command.label, missing, command: command.command });
	}
	const mode =
		nextCommands.length === 0 ? "blocked" : fallbacks.length > 0 || skipped.length > 0 ? "degraded" : "direct";
	return {
		mode,
		pack: {
			...pack,
			commands: nextCommands,
			notes: [
				...pack.notes,
				`autopilot_execution_strategy: ${mode}`,
				fallbacks.length ? `fallback_count=${fallbacks.length}` : "fallback_count=0",
				skipped.length ? `skipped_count=${skipped.length}` : "skipped_count=0",
			],
		},
		missingTools: knownMissing,
		fallbacks,
		skipped,
		notes: [
			mode === "direct"
				? "tool-index 覆盖当前命令包：直接执行。"
				: mode === "blocked"
					? "所有候选命令都依赖缺失工具且没有可用 fallback；先执行 next_bootstrap_command 或提供等价工具。"
					: "已按 tool-index 将命令包降级：优先 fallback，无法替代的命令跳过。",
		],
	};
}

export function formatAutopilotExecutionStrategy(strategy: AutopilotExecutionStrategy): string {
	return [
		"execution_strategy:",
		`mode: ${strategy.mode}`,
		`missing_tools: ${strategy.missingTools.join(", ") || "none"}`,
		`fallback_count: ${strategy.fallbacks.length}`,
		`skipped_count: ${strategy.skipped.length}`,
		"notes:",
		...strategy.notes.map((note) => `- ${note}`),
		...(strategy.fallbacks.length
			? [
					"fallback_commands:",
					...strategy.fallbacks.flatMap((fallback) => [
						`- label: ${fallback.label}`,
						`  missing: ${fallback.missing.join(", ")}`,
						`  command: ${fallback.command}`,
					]),
				]
			: []),
		...(strategy.skipped.length
			? [
					"skipped_commands:",
					...strategy.skipped.flatMap((skipped) => [
						`- label: ${skipped.label}`,
						`  missing: ${skipped.missing.join(", ")}`,
						`  command: ${skipped.command}`,
					]),
				]
			: []),
	].join("\n");
}

export function laneExecutionStrategy(pack: LaneCommandPack): AutopilotExecutionStrategy {
	const route = { domain: pack.route, intent: "", toolchain: "", skillHint: "", workflow: [] };
	return autopilotExecutionStrategy(pack, autopilotBootstrapPlan(route, pack));
}

export async function refreshToolIndex(pi: ExtensionAPI): Promise<string> {
	ensureReconStorage();
	const quoted = REPI_TOOL_INDEX_CANDIDATES.map((tool) => `'${tool.replace(/'/g, "'\\''")}'`).join(" ");
	const script = `for t in ${quoted}; do if command -v "$t" >/dev/null 2>&1; then p=$(command -v "$t"); v=$($t --version 2>&1 | head -1 | tr '\\n' ' '); printf '| %s | yes | %s | %s |\\n' "$t" "$p" "$v"; else printf '| %s | no |  |  |\\n' "$t"; fi; done; for m in angr z3; do if command -v python3 >/dev/null 2>&1 && python3 -c "import $m" >/dev/null 2>&1; then v=$(python3 -c "import $m; print(getattr($m, '__version__', 'ok'))" 2>&1 | head -1); printf '| python3:%s | yes | (module) | %s |\\n' "$m" "$v"; else printf '| python3:%s | no |  |  |\\n' "$m"; fi; done`;
	const result = await pi.exec("bash", ["-lc", script], { timeout: 20000 });
	const body = [
		"# REPI Tool Index",
		"",
		`Generated: ${new Date().toISOString()}`,
		`Command exit: ${result.code}`,
		"",
		"| Tool | Present | Path | Version probe |",
		"|---|---:|---|---|",
		result.stdout.trim(),
		"",
	].join("\n");
	writePrivateTextFile(toolIndexPath(), `${body}\n`);
	return readTextFile(toolIndexPath());
}

export async function installBootstrapTools(pi: ExtensionAPI, tools: string[]): Promise<string> {
	const plan = createBootstrapPlan(tools);
	const pending = plan.filter((item) => !item.present);
	if (pending.length === 0 || pending.every((item) => !item.install)) {
		return `${formatBootstrapPlan(plan)}\n\n无需执行安装；所有已存在或没有内置 bootstrap 命令。`;
	}
	const script = [
		"set -uo pipefail",
		...pending
			.filter((item) => item.install)
			.map(
				(item) =>
					`{ ${item.install!}; } || echo 'manual_tool_review ${item.tool}: install failed (non-fatal) — see REVERSER Phase 0 fallback'`,
			),
		...pending.filter((item) => item.verify).map((item) => `{ ${item.verify!}; } || true`),
	].join("\n");
	const result = await pi.exec("bash", ["-lc", script], { timeout: 600000 });
	const refreshed = await refreshToolIndex(pi);
	updateMissionCheckpoint(
		"tool_index_checked",
		result.code === 0 ? "done" : "blocked",
		`bootstrap exit=${result.code}`,
	);
	const artifactPath = join(
		evidenceRunsDir(),
		`${new Date().toISOString().replace(/[:.]/g, "-")}-bootstrap-install.md`,
	);
	const artifact = [
		formatBootstrapPlan(plan),
		"",
		"## Bootstrap execution",
		`exit: ${result.code}`,
		result.stdout.trim() ? ["stdout:", "```", truncateMiddle(result.stdout.trim(), 6000), "```"].join("\n") : "",
		result.stderr.trim() ? ["stderr:", "```", truncateMiddle(result.stderr.trim(), 6000), "```"].join("\n") : "",
		"",
		"## Refreshed tool index tail",
		truncateMiddle(refreshed, 6000),
	]
		.filter(Boolean)
		.join("\n");
	writePrivateTextFile(artifactPath, artifact);
	return `${compactStoredArtifact("bootstrap_install", artifactPath, readTextFile(artifactPath))}\nverify: cat ${shellQuote(artifactPath)}`;
}
