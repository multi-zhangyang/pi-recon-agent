import { existsSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { atomicWriteFile } from "./atomic-file.mjs";
import {
	capabilityMatrixDoctrine,
	evidencePriorityDoctrine,
} from "./swarm-llm-domain-catalog.mjs";

let agentToolchainFor;
let commandPaletteFor;
let compactTechniqueHintsForPrompt;
let defaultToolsForProfile;
let fallbackRouteProfile;
let proofKitFor;
let readJson;
let redact;
let routeCandidateRow;
let routeCoverageForPackets;
let routeProfileById;
let sha256;
let shellQuote;
let techniqueHintsFor;
let techniqueProofContractFor;
let toolProbeCommandFor;
let uniqueList;

export function configureSwarmLlmEvidenceRuntime(runtime) {
	({
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
	} = runtime);
}

function parseJsonObjectSpan(candidate) {
	const text = String(candidate ?? "");
	const starts = [];
	const ends = [];
	for (let index = 0; index < text.length; index += 1) {
		if (text[index] === "{") starts.push(index);
		else if (text[index] === "}") ends.push(index);
	}
	const startCandidates = [...new Set([...starts.slice(0, 80), ...starts.slice(-160)])].sort((left, right) => left - right);
	const endCandidates = [...new Set([...ends.slice(0, 20), ...ends.slice(-160)])].sort((left, right) => right - left);
	let fallback;
	for (const start of startCandidates) {
		for (const end of endCandidates) {
			if (end <= start) continue;
			try {
				const parsed = JSON.parse(text.slice(start, end + 1));
				if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) continue;
				if (Array.isArray(parsed.claims) || Array.isArray(parsed.findings)) return parsed;
				fallback ??= parsed;
			} catch {
				// Keep trying smaller/older spans. LLMs often print prose with
				// brace-like snippets before the final structured JSON.
			}
		}
	}
	return fallback;
}

export function extractJsonObject(text) {
	const trimmed = String(text ?? "").trim();
	if (!trimmed) return undefined;
	const fenced = /```(?:json)?\s*([\s\S]*?)```/i.exec(trimmed)?.[1];
	for (const candidate of [fenced, trimmed]) {
		if (!candidate) continue;
		const parsed = parseJsonObjectSpan(candidate);
		if (parsed) return parsed;
	}
	return undefined;
}

function linesMatching(text, pattern, limit = 12) {
	return String(text ?? "")
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter((line) => pattern.test(line))
		.slice(0, limit);
}

const evidenceRankByClass = new Map(evidencePriorityDoctrine.order.map((row) => [row.class, row.rank]));
const commandSignalPattern = /\b(?:curl|httpie|python3?|node|npm|go test|pytest|cargo|gdb|lldb|radare2|r2|rabin2|checksec|frida|objection|adb|jadx|apktool|tshark|tcpdump|wireshark|volatility3?|vol|binwalk|unblob|unsquashfs|yara|capa|floss|strings|file|readelf|objdump|xxd|exiftool|zsteg|steghide|john|hashcat|sqlmap|nmap|openssl|sage|z3|ldapsearch|impacket|bloodhound-python|certipy|netexec|nxc|cast|forge|docker|kubectl|helm|terraform|aws|gcloud|az)\b/i;
const artifactPathSignalPattern = /(?:^|[\s"'[(,])(?:\.{0,2}\/|\/)[A-Za-z0-9._~+@%=:,/\-]+|(?:^|[\s"'[(,])[A-Za-z]:\\[A-Za-z0-9._~+@%=:,\\/\-]+/;
const diffOrStatusSignalPattern = /\b(?:HTTP\s*[1-5][0-9]{2}|status[:= ]?[1-5][0-9]{2}|diff|before\/after|body[_ -]?hash|registers?|rip|rsp|eip|esp|offset|frame|packet|stream|exit(?:ed)?|exit[:= ]?\d+)\b|(?:状态码|响应差异|前后状态|正文哈希|寄存器|偏移|帧|数据包|流编号|退出码)/i;
const negativeControlSignalPattern = /\b(?:negative control|tampered|missing|unsigned|stale|counter[- ]?evidence|control failed|rejected|forbidden|unauthorized|invalid token|wrong principal|wrong key|wrong offset|401|403|crash vs no-crash)\b|(?:负控制|阴性对照|反证|反例|篡改|错误(?:签名|密钥|key|token|令牌|主体|principal|偏移)|未授权|禁止|拒绝|被拒绝|失败对照|崩溃对照)/i;
const exactTechniqueIdPattern = /\b(?:pwn|web|webscan|js|mobile|dfir|crypto|mem|malware|rev|fw|cloud|ad|agent|reliability)-[A-Za-z0-9_.-]+\b/g;

function techniqueTextBundle(claim, evidence = [], evidenceItems = []) {
	return [
		claim?.statement,
		claim?.title,
		claim?.techniqueProof?.proofExitObserved,
		...(Array.isArray(claim?.techniqueProof?.counterControls) ? claim.techniqueProof.counterControls : []),
		...(Array.isArray(evidence) ? evidence : []),
		...(Array.isArray(evidenceItems) ? evidenceItems.map(evidenceTextFromItem) : []),
	]
		.filter(Boolean)
		.map(String)
		.join("\n");
}

function extractTechniqueIdsFromClaim(claim, evidence = [], evidenceItems = []) {
	const ids = [];
	for (const value of [
		claim?.techniqueId,
		claim?.technique,
		...(Array.isArray(claim?.techniqueIds) ? claim.techniqueIds : []),
		...(Array.isArray(claim?.techniques) ? claim.techniques : []),
	]) {
		if (typeof value === "string" && value.trim()) ids.push(value.trim());
		else if (value && typeof value === "object" && typeof value.id === "string") ids.push(value.id.trim());
	}
	const text = techniqueTextBundle(claim, evidence, evidenceItems);
	for (const match of text.matchAll(exactTechniqueIdPattern)) ids.push(match[0]);
	return uniqueList(ids);
}

function signalGroupMatches(text, group) {
	const haystack = String(text ?? "").toLowerCase();
	return (group?.any ?? []).some((needle) => haystack.includes(String(needle).toLowerCase()));
}

function buildTechniqueProofChecks(claim, evidence = [], evidenceItems = []) {
	const text = techniqueTextBundle(claim, evidence, evidenceItems);
	return extractTechniqueIdsFromClaim(claim, evidence, evidenceItems).map((techniqueId) => {
		const contract = techniqueProofContractFor(techniqueId, { full: true });
		const required = (contract?.requiredSignals ?? []).map((group) => ({
			gate: group.gate,
			matched: signalGroupMatches(text, group),
			any: group.any,
		}));
		const controls = (contract?.negativeControls ?? []).map((group) => ({
			gate: group.gate,
			matched: signalGroupMatches(text, group) || negativeControlSignalPattern.test(text),
			any: group.any,
		}));
		const missing = [
			...required.filter((row) => !row.matched).map((row) => row.gate),
			...controls.filter((row) => !row.matched).map((row) => row.gate),
		];
		return {
			techniqueId,
			contract,
			required,
			negativeControls: controls,
			missing,
			proofReady: missing.length === 0,
		};
	});
}

function evidenceClassRank(evidenceClass) {
	return evidenceRankByClass.get(String(evidenceClass ?? "unknown")) ?? 0;
}

function classifyEvidenceText(value, explicitClass) {
	const text = String(value ?? "");
	const explicit = String(explicitClass ?? "").trim();
	if (evidenceRankByClass.has(explicit)) {
		return { class: explicit, rank: evidenceClassRank(explicit), reason: "explicit" };
	}
	const patterns = [
		["runtime-behavior", /\b(?:exits?\s*\d+|exit[:= ]?\d+|gdb|lldb|register|stack|crash|SIG[A-Z]+|runtime|transcript|replay(?:ed)?|accepted|rejected|forbidden|negative control|counter[- ]?evidence|N-run|frida|adb shell|volatility\d?|kubectl auth can-i|aws sts|get-caller-identity)\b|(?:退出码|运行时|复现|重放|接受|拒绝|被拒绝|负控制|反证|崩溃|寄存器)/i],
		["network-traffic", /\b(?:HTTP\s*[1-5][0-9]{2}|status[:= ]?[1-5][0-9]{2}|body hash|request|response|curl|XHR|fetch|WebSocket|PCAP|packet|frame|stream|tshark|tcpflow|SNI|JA3|DNS|TLS)\b|(?:状态码|请求|响应|流量|数据包|帧|会话流)/i],
		["served-assets", /\b(?:served asset|source-?map|sourcemap|chunk|webpack|vite|wasm|WebAssembly|page\.html|openapi|swagger|graphql schema|asset hash)\b/i],
		["process-config", /\b(?:config|manifest|plist|IAM|RBAC|role|principal|namespace|session|cookie|middleware|route list|loader|libc|checksec|RELRO|PIE|Canary|NX|tool availability)\b|(?:配置|清单|会话|中间件|路由|权限|命名空间|加载器)/i],
		["persisted-state", /\b(?:database|registry|storage|before\/after|state change|filesystem|ledger|artifact ledger|dumped file|carved|persisted)\b|(?:数据库|注册表|存储|状态变化|文件系统|账本|转储|持久化)/i],
		["artifact", /\b(?:sha256|sha1|md5)[:= ]?[a-f0-9]{16,64}\b|(?:^|[\s"'[(,])(?:\.{0,2}\/|\/)[A-Za-z0-9._~+@%=:,/\-]+|\boffset\b|\bhash\b|\bartifact\b|(?:偏移|哈希|证据文件|工件)/i],
		["source", /\b(?:source|grep|strings|imports?|xref|function|symbol|line \d+|code path|static triage|readelf|objdump|rabin2)\b|(?:源码|字符串|导入|交叉引用|函数|符号|代码路径|静态分析)/i],
		["comment", /\b(?:README|TODO|comment|docs?|note|hypothesis only|unverified narrative)\b/i],
	];
	for (const [evidenceClass, pattern] of patterns) {
		if (pattern.test(text)) return { class: evidenceClass, rank: evidenceClassRank(evidenceClass), reason: "pattern" };
	}
	return { class: "unknown", rank: 0, reason: "unknown" };
}

function evidenceTextFromItem(item) {
	if (!item) return "";
	if (typeof item === "string") return item;
	return [
		item.evidenceClass ? `class=${item.evidenceClass}` : item.class ? `class=${item.class}` : undefined,
		item.locator,
		item.summary,
		item.evidence,
		item.command,
		item.path,
		item.hash ? `hash=${item.hash}` : undefined,
		item.frame ? `frame=${item.frame}` : undefined,
		item.offset ? `offset=${item.offset}` : undefined,
	]
		.filter(Boolean)
		.map(String)
		.join(" ");
}

function evidencePrioritySummary(evidence, evidenceItems = []) {
	const rows = [
		...evidence.map((item) => ({
			evidence: redact(String(item)).slice(0, 240),
			...classifyEvidenceText(item),
		})),
		...evidenceItems.map((item) => {
			const evidenceText = evidenceTextFromItem(item);
			const classified = classifyEvidenceText(evidenceText, item?.evidenceClass ?? item?.class);
			return {
				evidence: redact(evidenceText).slice(0, 240),
				...classified,
			};
		}),
	];
	const strongest = rows.reduce((best, row) => (!best || row.rank > best.rank ? row : best), undefined);
	const classes = [...new Set(rows.map((row) => row.class))];
	return {
		classes,
		strongestClass: strongest?.class ?? "unknown",
		strongestRank: strongest?.rank ?? 0,
		rows: rows.slice(0, 12),
	};
}

function claimQualitySignals(evidence, blockers, evidenceItems = []) {
	const evidenceItemTexts = evidenceItems.map(evidenceTextFromItem).filter(Boolean);
	const text = [...evidence, ...evidenceItemTexts].join("\n");
	const priority = evidencePrioritySummary(evidence, evidenceItems);
	const hasCommand = commandSignalPattern.test(text);
	const hasArtifactPath = artifactPathSignalPattern.test(text);
	const hasHash = /\b(?:sha256|sha1|md5)[:= ]?[a-f0-9]{16,64}\b/i.test(text) || /\b[a-f0-9]{64}\b/i.test(text);
	const hasDiffOrStatus = diffOrStatusSignalPattern.test(text);
	const hasNegativeControl = negativeControlSignalPattern.test(text);
	const score = [hasCommand, hasArtifactPath, hasHash, hasDiffOrStatus, hasNegativeControl].filter(Boolean).length;
	return {
		evidenceCount: evidence.length,
		evidenceItemCount: evidenceItems.length,
		blockerCount: blockers.length,
		hasCommand,
		hasArtifactPath,
		hasHash,
		hasDiffOrStatus,
		hasNegativeControl,
		evidenceClasses: priority.classes,
		strongestEvidenceClass: priority.strongestClass,
		evidencePriorityRank: priority.strongestRank,
		evidencePriorityRows: priority.rows,
		score,
	};
}

function claimProofCoverage(qualitySignals) {
	return {
		passive: Number(qualitySignals?.evidenceCount ?? 0) > 0 || Number(qualitySignals?.evidenceItemCount ?? 0) > 0 || Boolean(qualitySignals?.hasArtifactPath) || Boolean(qualitySignals?.hasHash),
		proofExit: Boolean(qualitySignals?.hasCommand) || Boolean(qualitySignals?.hasHash) || Boolean(qualitySignals?.hasDiffOrStatus) || Boolean(qualitySignals?.hasArtifactPath),
		negativeControls: Boolean(qualitySignals?.hasNegativeControl),
	};
}

function claimProofReady(claim) {
	const coverage = claim?.proofCoverage ?? claimProofCoverage(claim?.qualitySignals ?? {});
	return claim?.status === "promoted" && coverage.passive && coverage.proofExit && coverage.negativeControls && claim?.techniqueProofReady !== false;
}

function parsedEvidenceBundle(parsed, parsedClaims, stdout, evidenceItems = []) {
	const evidence = [];
	const blockers = [];
	for (const claim of parsedClaims) {
		if (Array.isArray(claim?.evidence)) evidence.push(...claim.evidence.map(String));
		if (Array.isArray(claim?.evidenceItems)) evidence.push(...claim.evidenceItems.map(evidenceTextFromItem));
		if (Array.isArray(claim?.blockers)) blockers.push(...claim.blockers.map(String));
	}
	if (Array.isArray(parsed?.evidence)) evidence.push(...parsed.evidence.map(String));
	if (Array.isArray(parsed?.evidenceItems)) evidence.push(...parsed.evidenceItems.map(evidenceTextFromItem));
	if (Array.isArray(evidenceItems)) evidence.push(...evidenceItems.map(evidenceTextFromItem));
	if (Array.isArray(parsed?.artifacts)) evidence.push(...parsed.artifacts.map(String));
	if (Array.isArray(parsed?.nextCommands)) evidence.push(...parsed.nextCommands.map(String));
	if (Array.isArray(parsed?.blockers)) blockers.push(...parsed.blockers.map(String));
	if (!evidence.length && stdout) evidence.push(...linesMatching(stdout, /sha256|HTTP|status|curl|python|node|gdb|frida|jadx|apktool|tshark|volatility|binwalk|yara|capa|floss|readelf|objdump|offset|diff|artifact|evidence|proof|状态码|证据|负控制|反证/i, 20));
	return {
		evidence: evidence.map(redact).filter(Boolean).slice(0, 80),
		blockers: blockers.map(redact).filter(Boolean).slice(0, 40),
	};
}

function proofChecklistForWorker(worker, parsed, parsedClaims, stdout, evidenceItems = []) {
	const proofKit = worker.proofKit || proofKitFor(worker.route || { id: "reverse-pentest-general" });
	const commandPalette = worker.commandPalette || commandPaletteFor(worker.route || { id: "reverse-pentest-general" });
	const toolProbeCommand = worker.toolProbeCommand || toolProbeCommandFor(worker.route || { id: "reverse-pentest-general" });
	const techniqueHints = worker.techniqueHints || techniqueHintsFor(worker.route || { id: "reverse-pentest-general" });
	const agentToolchain = worker.agentToolchain || agentToolchainFor(worker.route || { id: "reverse-pentest-general" }, worker.tools, worker.toolsMode);
	const bundle = parsedEvidenceBundle(parsed, parsedClaims, stdout, evidenceItems);
	const quality = claimQualitySignals(bundle.evidence, bundle.blockers, evidenceItems);
	const coverage = {
		passive: bundle.evidence.length > 0 || quality.hasArtifactPath || quality.hasHash,
		proofExit: quality.hasCommand || quality.hasHash || quality.hasDiffOrStatus || quality.hasArtifactPath,
		negativeControls: quality.hasNegativeControl,
	};
	const missing = [];
	if (!coverage.passive) missing.push("passive evidence");
	if (!coverage.proofExit) missing.push("proof/replay evidence");
	if (!coverage.negativeControls) missing.push("negative control or counter-evidence");
	return {
		workerId: worker.workerId,
		role: worker.role ?? "worker",
		route: worker.route ?? null,
		status: worker.status,
		proofKit,
		commandPalette,
		toolProbeCommand,
		techniqueHints,
		agentToolchain,
		coverage,
		qualitySignals: quality,
		missing,
		proofReady: worker.status === "pass" && coverage.passive && coverage.proofExit && coverage.negativeControls,
		evidencePreview: bundle.evidence.slice(0, 8),
		blockers: bundle.blockers.slice(0, 8),
	};
}

function preservedRunFlags(plan) {
	const flagPairs = [];
	const bareFlags = [];
	if (plan?.provider && plan.provider !== "default") flagPairs.push(["--provider", plan.provider]);
	if (plan?.model && plan.model !== "default") flagPairs.push(["--model", plan.model]);
	if (Number.isFinite(Number(plan?.timeoutMs))) flagPairs.push(["--timeout-ms", String(plan.timeoutMs)]);
	if (plan?.runRoot) flagPairs.push(["--cwd", plan.runRoot]);
	const tools = Array.isArray(plan?.workerPackets) ? plan.workerPackets.find((packet) => packet?.tools)?.tools : undefined;
	if (tools && (plan?.toolsMode === "explicit" || !plan?.toolsMode)) flagPairs.push(["--tools", tools]);
	else if (plan?.toolsDisabled || plan?.toolsMode === "disabled") bareFlags.push("--no-tools");
	return [
		...flagPairs.map(([flag, value]) => `${flag} ${shellQuote(value)}`),
		...bareFlags,
	].join(" ");
}

function swarmRunBaseCommand(plan) {
	const target = shellQuote(plan?.target ?? "local-selfcheck");
	const flags = preservedRunFlags(plan);
	return `repi swarm run ${target}${flags ? ` ${flags}` : ""}`;
}

function proofRepairCommand(plan, checklist) {
	if (!checklist || checklist.proofReady) return undefined;
	const route = checklist.route?.domain || checklist.route?.id || "Reverse/Pentest general";
	const routeFlag = checklist.route?.id ? ` --route ${shellQuote(checklist.route.id)}` : "";
	const prompt = [
		`Close proof gaps for worker-${checklist.workerId} route ${route}.`,
		`Missing: ${checklist.missing.join(", ") || "none"}.`,
		`Use passive/proofExit/negativeControls from this proof kit: ${JSON.stringify(checklist.proofKit)}`,
		`Start from this command palette where applicable: ${JSON.stringify(checklist.commandPalette)}`,
		checklist.toolProbeCommand ? `First probe tool availability with: ${checklist.toolProbeCommand}` : undefined,
		`Pull or apply these route technique hints where applicable: ${JSON.stringify(compactTechniqueHintsForPrompt(checklist.techniqueHints))}`,
		`Use this agent toolchain when tools are enabled: ${JSON.stringify(checklist.agentToolchain)}`,
		"Return only JSON claims/evidence/blockers/nextCommands with concrete commands, paths, hashes, diffs/status, and negative controls.",
	].filter(Boolean).join(" ");
	return `${swarmRunBaseCommand(plan)} --workers 1${routeFlag} --roles verifier --prompt ${shellQuote(prompt)}`;
}

function routeCoverageRepairCommand(plan, route) {
	if (!route) return undefined;
	const prompt = [
		`Cover previously unassigned route ${route.domain || route.id}.`,
		`Use this proof kit: ${JSON.stringify(route.proofKit || proofKitFor(route))}`,
		`Start from this command palette where applicable: ${JSON.stringify(route.commandPalette || commandPaletteFor(route))}`,
		route.toolProbeCommand ? `First probe tool availability with: ${route.toolProbeCommand}` : undefined,
		`Pull or apply these route technique hints where applicable: ${JSON.stringify(compactTechniqueHintsForPrompt(route.techniqueHints || techniqueHintsFor(route)))}`,
		`Use this agent toolchain when tools are enabled: ${JSON.stringify(route.agentToolchain || agentToolchainFor(route, defaultToolsForProfile(route), "default"))}`,
		"Produce one promoted-quality claim with passive evidence, proof/replay evidence, and negative control or counter-evidence.",
	].filter(Boolean).join(" ");
	return `${swarmRunBaseCommand(plan)} --workers 1 --route ${shellQuote(route.id)} --roles solo --prompt ${shellQuote(prompt)}`;
}

function routeProofRepairCommand(plan, readiness) {
	if (!readiness || readiness.proofReady || !readiness.route?.id) return undefined;
	const route = readiness.route;
	const prompt = [
		`Close route-level proof gap for ${route.domain || route.id}.`,
		`Missing: ${readiness.missing.join(", ") || "proof-ready promoted claim"}.`,
		readiness.assignedWorkerIds.length ? `Previous assigned workers: ${readiness.assignedWorkerIds.join(", ")}.` : undefined,
		readiness.promotedClaimIds.length ? `Existing promoted-but-not-route-ready claims: ${readiness.promotedClaimIds.join(", ")}.` : undefined,
		`Use this proof kit: ${JSON.stringify(route.proofKit || proofKitFor(route))}`,
		`Start from this command palette where applicable: ${JSON.stringify(route.commandPalette || commandPaletteFor(route))}`,
		route.toolProbeCommand ? `First probe tool availability with: ${route.toolProbeCommand}` : undefined,
		`Pull or apply these route technique hints where applicable: ${JSON.stringify(compactTechniqueHintsForPrompt(route.techniqueHints || techniqueHintsFor(route)))}`,
		`Use this agent toolchain when tools are enabled: ${JSON.stringify(route.agentToolchain || agentToolchainFor(route, defaultToolsForProfile(route), "default"))}`,
		"Produce one promoted-quality claim with passive evidence, proof/replay evidence, and negative control or counter-evidence for this exact route.",
	].filter(Boolean).join(" ");
	return `${swarmRunBaseCommand(plan)} --workers 1 --route ${shellQuote(route.id)} --roles solo --prompt ${shellQuote(prompt)}`;
}

function techniqueProofRepairCommand(plan, claim) {
	const failing = (claim?.techniqueProofChecks ?? []).filter((row) => !row.proofReady);
	if (!claim || !failing.length) return undefined;
	const route = claim.route?.id ? ` --route ${shellQuote(claim.route.id)}` : "";
	const prompt = [
		`Close named-technique proof-exit gap for claim ${claim.claimId}.`,
		`Claim statement: ${claim.statement || "n/a"}.`,
		`Technique contracts: ${JSON.stringify(failing.map((row) => row.contract))}`,
		`Missing gates: ${failing.flatMap((row) => row.missing.map((gate) => `${row.techniqueId}:${gate}`)).join(", ")}.`,
		"Run or build the smallest replay/harness that satisfies each technique proofExit, include command/path/hash/status/offset evidence, and include the contract-specific negative control.",
	].join(" ");
	return `${swarmRunBaseCommand(plan)} --workers 1${route} --roles verifier --prompt ${shellQuote(prompt)}`;
}

function normalizeRouteHandoff(worker, row, index) {
	const profile = routeProfileById(row?.route ?? row?.routeId ?? row?.id);
	if (!profile) return undefined;
	return {
		handoffId: `worker-${worker.workerId}-handoff-${index + 1}`,
		workerId: worker.workerId,
		fromRoute: worker.route ?? null,
		route: routeCandidateRow(profile),
		reason: redact(String(row?.reason ?? row?.why ?? "cross-route evidence discovered")).slice(0, 600),
		evidence: redact(String(row?.evidence ?? row?.anchor ?? "")).slice(0, 600),
		nextCommand: row?.nextCommand ? redact(String(row.nextCommand)).slice(0, 1000) : undefined,
	};
}

function routeHandoffCommand(plan, handoff) {
	if (!handoff?.route?.id) return undefined;
	const prompt = [
		`Follow cross-route handoff ${handoff.handoffId} from worker-${handoff.workerId}.`,
		`Reason: ${handoff.reason || "cross-route evidence discovered"}.`,
		handoff.evidence ? `Evidence anchor: ${handoff.evidence}.` : undefined,
		`Use this proof kit: ${JSON.stringify(handoff.route.proofKit || proofKitFor(handoff.route))}`,
		`Start from this command palette where applicable: ${JSON.stringify(handoff.route.commandPalette || commandPaletteFor(handoff.route))}`,
		handoff.route.toolProbeCommand ? `First probe tool availability with: ${handoff.route.toolProbeCommand}` : undefined,
		`Pull or apply these route technique hints where applicable: ${JSON.stringify(compactTechniqueHintsForPrompt(handoff.route.techniqueHints || techniqueHintsFor(handoff.route)))}`,
		`Use this agent toolchain when tools are enabled: ${JSON.stringify(handoff.route.agentToolchain || agentToolchainFor(handoff.route, defaultToolsForProfile(handoff.route), "default"))}`,
		handoff.nextCommand ? `Seed next command: ${handoff.nextCommand}.` : undefined,
		"Produce one promoted-quality claim with passive evidence, proof/replay evidence, and negative control or counter-evidence.",
	].filter(Boolean).join(" ");
	return `${swarmRunBaseCommand(plan)} --workers 1 --route ${shellQuote(handoff.route.id)} --roles solo --prompt ${shellQuote(prompt)}`;
}

function repairQueueRow(row) {
	if (!row?.command) return undefined;
	const idSeed = [
		row.kind ?? "repair",
		row.claimId,
		row.workerId,
		row.routeId,
		row.handoffId,
		row.command,
	]
		.filter(Boolean)
		.join("|");
	return {
		id: row.id ?? `repair-${sha256(idSeed).slice(0, 16)}`,
		kind: row.kind ?? "repair",
		priority: Number.isFinite(Number(row.priority)) ? Number(row.priority) : 50,
		workerId: row.workerId,
		claimId: row.claimId,
		routeId: row.routeId,
		handoffId: row.handoffId,
		missing: Array.isArray(row.missing) ? row.missing.map(String).slice(0, 16) : [],
		reason: row.reason ? redact(String(row.reason)).slice(0, 600) : undefined,
		command: redact(String(row.command)).slice(0, 6000),
	};
}

function normalizeEvidenceItem(worker, row, index, claimId) {
	if (row === undefined || row === null) return undefined;
	const objectRow = typeof row === "object" ? row : { summary: String(row) };
	const locator = redact(String(objectRow.locator ?? objectRow.path ?? objectRow.command ?? objectRow.frame ?? objectRow.offset ?? "")).slice(0, 500);
	const summary = redact(String(objectRow.summary ?? objectRow.evidence ?? objectRow.description ?? objectRow.note ?? "")).slice(0, 1000);
	const evidenceText = evidenceTextFromItem({ ...objectRow, locator, summary });
	const classified = classifyEvidenceText(evidenceText, objectRow.evidenceClass ?? objectRow.class);
	return {
		evidenceItemId: `worker-${worker.workerId}-evidence-${index + 1}`,
		workerId: worker.workerId,
		role: worker.role ?? "worker",
		route: worker.route ?? null,
		claimId: redact(String(objectRow.claimId ?? objectRow.claim ?? claimId ?? "")).slice(0, 200),
		locator,
		summary,
		evidenceText: redact(evidenceText).slice(0, 1600),
		evidenceClass: classified.class,
		evidencePriorityRank: classified.rank,
		classificationReason: classified.reason,
	};
}

function normalizeConflict(worker, row, index, claimId) {
	if (!row || typeof row !== "object") return undefined;
	const evidence = redact(String(row.evidence ?? row.anchor ?? row.summary ?? row.reason ?? "")).slice(0, 1000);
	const classified = classifyEvidenceText(evidence, row.evidenceClass ?? row.class);
	return {
		conflictId: `worker-${worker.workerId}-conflict-${index + 1}`,
		workerId: worker.workerId,
		role: worker.role ?? "worker",
		route: worker.route ?? null,
		claimId: redact(String(row.claimId ?? row.against ?? claimId ?? "")).slice(0, 200),
		reason: redact(String(row.reason ?? "counter-evidence recorded")).slice(0, 600),
		evidence,
		evidenceClass: classified.class,
		evidencePriorityRank: classified.rank,
		nextCommand: row.nextCommand ? redact(String(row.nextCommand)).slice(0, 1000) : undefined,
	};
}

function conflictResolutionForClaim(claim, conflictRows) {
	const relevant = conflictRows.filter((row) => !row.claimId || row.claimId === claim.claimId);
	const strongest = relevant.reduce((best, row) => (!best || row.evidencePriorityRank > best.evidencePriorityRank ? row : best), undefined);
	if (!strongest) {
		return {
			status: "no_conflict",
			downgraded: false,
			strongestConflictRank: 0,
			strongestConflictClass: "none",
			relevantConflictIds: [],
		};
	}
	const claimRank = Number(claim?.qualitySignals?.evidencePriorityRank ?? 0);
	const downgraded = strongest.evidencePriorityRank >= claimRank;
	return {
		status: downgraded ? "downgraded_by_equal_or_stronger_counterevidence" : "counterevidence_recorded_lower_priority",
		downgraded,
		claimEvidencePriorityRank: claimRank,
		strongestConflictRank: strongest.evidencePriorityRank,
		strongestConflictClass: strongest.evidenceClass,
		relevantConflictIds: relevant.map((row) => row.conflictId).slice(0, 12),
	};
}

function normalizedRouteRow(route) {
	if (!route) return undefined;
	const id = String(route.id ?? route.routeId ?? "").trim();
	if (!id) return undefined;
	const profile = routeProfileById(id) || route;
	return {
		id,
		domain: route.domain ?? profile.domain ?? id,
		workflow: Array.isArray(route.workflow) ? route.workflow : Array.isArray(profile.workflow) ? profile.workflow : [],
		proofKit: route.proofKit ?? proofKitFor(profile),
		commandPalette: route.commandPalette ?? commandPaletteFor(profile),
		toolProbeCommand: route.toolProbeCommand ?? toolProbeCommandFor(profile),
		techniqueHints: route.techniqueHints ?? techniqueHintsFor(profile),
		agentToolchain: route.agentToolchain ?? agentToolchainFor(profile, defaultToolsForProfile(profile), "default"),
	};
}

function uniqueRouteRows(routes) {
	const seen = new Set();
	const rows = [];
	for (const route of routes) {
		const normalized = normalizedRouteRow(route);
		if (!normalized || seen.has(normalized.id)) continue;
		seen.add(normalized.id);
		rows.push(normalized);
	}
	return rows;
}

function requiredRouteRows(plan, workersReport, routeCoverage) {
	const candidates = uniqueRouteRows(Array.isArray(plan?.routeCandidates) ? plan.routeCandidates : []);
	if (candidates.length) return candidates;
	const covered = uniqueRouteRows(Array.isArray(routeCoverage?.covered) ? routeCoverage.covered : []);
	if (covered.length) return covered;
	const workerRoutes = uniqueRouteRows(workersReport.map((worker) => worker.route).filter(Boolean));
	if (workerRoutes.length) return workerRoutes;
	return uniqueRouteRows([plan?.route, fallbackRouteProfile]);
}

function buildRouteReadinessRows(plan, workersReport, proofChecklists, promotedClaims, proofReadyPromotedClaims, routeCoverage) {
	const workerById = new Map(workersReport.map((worker) => [String(worker.workerId), worker]));
	const checklistByWorkerId = new Map(proofChecklists.map((row) => [String(row.workerId), row]));
	const proofReadyClaimIds = new Set(proofReadyPromotedClaims.map((claim) => claim.claimId));
	return requiredRouteRows(plan, workersReport, routeCoverage).map((route) => {
		const assignedWorkers = workersReport.filter((worker) => String(worker.route?.id ?? plan?.route?.id ?? "") === route.id);
		const routePromotedClaims = promotedClaims.filter((claim) => {
			const claimWorker = workerById.get(String(claim.workerId));
			return String(claim.route?.id ?? claimWorker?.route?.id ?? "") === route.id;
		});
		const routeProofReadyPromotedClaims = routePromotedClaims.filter((claim) => proofReadyClaimIds.has(claim.claimId));
		const proofReadyWorkerIds = assignedWorkers
			.filter((worker) => checklistByWorkerId.get(String(worker.workerId))?.proofReady)
			.map((worker) => worker.workerId);
		const missing = [];
		if (!assignedWorkers.length) missing.push("assigned worker");
		if (!routePromotedClaims.length) missing.push("promoted claim");
		if (!routeProofReadyPromotedClaims.length) missing.push("proof-ready promoted claim");
		return {
			route,
			routeId: route.id,
			domain: route.domain,
			assignedWorkerIds: assignedWorkers.map((worker) => worker.workerId),
			passedWorkerIds: assignedWorkers.filter((worker) => worker.status === "pass").map((worker) => worker.workerId),
			proofReadyWorkerIds,
			promotedClaimIds: routePromotedClaims.map((claim) => claim.claimId),
			proofReadyPromotedClaimIds: routeProofReadyPromotedClaims.map((claim) => claim.claimId),
			proofReady: routeProofReadyPromotedClaims.length > 0,
			missing,
		};
	});
}

function verifySwarmTranscriptHashes(evidenceRoot, workersReport) {
	const workerChecks = workersReport.map((worker) => {
		const stdoutPath = join(evidenceRoot, `worker-${worker.workerId}.stdout.txt`);
		const stderrPath = join(evidenceRoot, `worker-${worker.workerId}.stderr.txt`);
		const stdoutExists = existsSync(stdoutPath);
		const stderrExists = existsSync(stderrPath);
		const stdoutSha256 = stdoutExists ? sha256(readFileSync(stdoutPath)) : null;
		const stderrSha256 = stderrExists ? sha256(readFileSync(stderrPath)) : null;
		return {
			workerId: worker.workerId,
			status: worker.status,
			stdoutPath,
			stderrPath,
			stdoutExists,
			stderrExists,
			stdoutSha256,
			stderrSha256,
			stdoutMatched: stdoutExists && stdoutSha256 === worker.stdoutSha256,
			stderrMatched: stderrExists && stderrSha256 === worker.stderrSha256,
		};
	});
	return {
		verified: workerChecks.length > 0 && workerChecks.every((row) => row.stdoutMatched && row.stderrMatched),
		workerCount: workerChecks.length,
		verifiedWorkers: workerChecks.filter((row) => row.stdoutMatched && row.stderrMatched).length,
		workerChecks,
	};
}

function verifySwarmHarvestedArtifacts(workersReport) {
	const artifactChecks = [];
	for (const worker of workersReport) {
		for (const artifact of worker.harvestedArtifacts ?? []) {
			const path = artifact.artifactPath;
			const exists = Boolean(path && existsSync(path));
			let size = 0;
			let sha = null;
			if (exists) {
				const data = readFileSync(path);
				size = data.length;
				sha = sha256(data);
			}
			artifactChecks.push({
				workerId: worker.workerId,
				sourcePath: artifact.sourcePath ?? null,
				artifactPath: path ?? null,
				exists,
				size,
				expectedSize: artifact.size ?? null,
				sha256: sha,
				expectedSha256: artifact.sha256 ?? null,
				verified: exists && size === artifact.size && sha === artifact.sha256,
			});
		}
	}
	return {
		verified: artifactChecks.every((row) => row.verified),
		artifactCount: artifactChecks.length,
		verifiedArtifacts: artifactChecks.filter((row) => row.verified).length,
		artifactChecks,
	};
}

function verifySwarmClaimProofGates(claimRows, proofReadyPromotedClaims, evidenceItemRows, conflictRows) {
	const evidenceItemIds = new Set(evidenceItemRows.map((row) => row.evidenceItemId));
	const conflictByClaimId = new Map();
	for (const conflict of conflictRows) {
		if (!conflict.claimId) continue;
		if (!conflictByClaimId.has(conflict.claimId)) conflictByClaimId.set(conflict.claimId, []);
		conflictByClaimId.get(conflict.claimId).push(conflict);
	}
	const claimChecks = proofReadyPromotedClaims.map((claim) => {
		const source = claimRows.find((row) => row.claimId === claim.claimId) ?? claim;
		const coverage = source.proofCoverage ?? {};
		const referencedEvidenceItems = source.evidenceItemIds ?? [];
		return {
			claimId: source.claimId,
			workerId: source.workerId,
			routeId: source.route?.id ?? null,
			status: source.status,
			proofReady: Boolean(source.proofReady),
			coverage,
			evidenceItemIds: referencedEvidenceItems,
			evidenceItemsResolved: referencedEvidenceItems.every((id) => evidenceItemIds.has(id)),
			techniqueIds: source.techniqueIds ?? [],
			techniqueProofReady: source.techniqueProofReady !== false,
			techniqueProofMissing: source.techniqueProofMissing ?? [],
			conflictStatus: source.conflictResolution?.status ?? "unknown",
			counterEvidenceCount: (conflictByClaimId.get(source.claimId) ?? []).length,
			verified:
				source.status === "promoted" &&
				Boolean(source.proofReady) &&
				Boolean(coverage.passive) &&
				Boolean(coverage.proofExit) &&
				Boolean(coverage.negativeControls) &&
				source.techniqueProofReady !== false &&
				referencedEvidenceItems.every((id) => evidenceItemIds.has(id)) &&
				source.conflictResolution?.downgraded !== true,
		};
	});
	return {
		verified: proofReadyPromotedClaims.length > 0 && claimChecks.every((row) => row.verified),
		proofReadyPromotedClaimCount: proofReadyPromotedClaims.length,
		verifiedClaims: claimChecks.filter((row) => row.verified).length,
		availableEvidenceItemIds: [...evidenceItemIds],
		claimChecks,
	};
}

function verifySwarmRouteProofGates(routeReadinessRows, proofReadyPromotedClaims) {
	const proofReadyClaimIds = new Set(proofReadyPromotedClaims.map((claim) => claim.claimId));
	const routeChecks = routeReadinessRows.map((row) => {
		const resolvedProofReadyClaims = (row.proofReadyPromotedClaimIds ?? []).filter((claimId) => proofReadyClaimIds.has(claimId));
		return {
			routeId: row.routeId,
			domain: row.domain,
			proofReady: Boolean(row.proofReady),
			assignedWorkerIds: row.assignedWorkerIds ?? [],
			promotedClaimIds: row.promotedClaimIds ?? [],
			proofReadyPromotedClaimIds: row.proofReadyPromotedClaimIds ?? [],
			resolvedProofReadyClaims,
			missing: row.missing ?? [],
			verified: Boolean(row.proofReady) ? resolvedProofReadyClaims.length > 0 : (row.missing ?? []).length > 0,
		};
	});
	return {
		verified: routeChecks.length > 0 && routeChecks.every((row) => row.verified),
		routeCount: routeChecks.length,
		readyRoutes: routeChecks.filter((row) => row.proofReady).length,
		verifiedRoutes: routeChecks.filter((row) => row.verified).length,
		routeChecks,
	};
}

function mutatedFileHash(path) {
	if (!path || !existsSync(path)) return null;
	const original = readFileSync(path);
	const mutated = original.length ? Buffer.from(original) : Buffer.from([0]);
	if (original.length) mutated[0] ^= 0xff;
	return sha256(mutated);
}

function buildSwarmMergeNegativeControls(transcriptVerification, artifactVerification, claimGateVerification, routeGateVerification) {
	const firstWorker = transcriptVerification.workerChecks[0];
	const firstArtifact = artifactVerification.artifactChecks[0];
	const firstClaim = claimGateVerification.claimChecks[0];
	const firstRoute = routeGateVerification.routeChecks[0];
	const controls = [];
	if (firstWorker) {
		const mutatedSha256 = mutatedFileHash(firstWorker.stdoutPath);
		controls.push({
			controlType: "swarm-transcript-hash-mutation-control",
			workerId: firstWorker.workerId,
			originalSha256: firstWorker.stdoutSha256,
			mutatedSha256,
			passed: Boolean(firstWorker.stdoutMatched && mutatedSha256 && mutatedSha256 !== firstWorker.stdoutSha256),
		});
	}
	if (firstArtifact) {
		const mutatedSha256 = mutatedFileHash(firstArtifact.artifactPath);
		controls.push({
			controlType: "swarm-artifact-hash-mutation-control",
			workerId: firstArtifact.workerId,
			artifactPath: firstArtifact.artifactPath,
			originalSha256: firstArtifact.sha256,
			mutatedSha256,
			passed: Boolean(firstArtifact.verified && mutatedSha256 && mutatedSha256 !== firstArtifact.sha256),
		});
	}
	if (firstClaim) {
		const knownEvidenceItemIds = new Set(claimGateVerification.availableEvidenceItemIds ?? []);
		let missingEvidenceItemId = `${firstClaim.claimId}:negative-control-missing`;
		while (knownEvidenceItemIds.has(missingEvidenceItemId)) missingEvidenceItemId += "-x";
		const mutatedEvidenceItemIds = [...firstClaim.evidenceItemIds, missingEvidenceItemId];
		const mutatedEvidenceItemsResolved = mutatedEvidenceItemIds.every((id) => knownEvidenceItemIds.has(id));
		controls.push({
			controlType: "swarm-missing-evidence-item-control",
			claimId: firstClaim.claimId,
			missingEvidenceItemId,
			mutatedEvidenceItemsResolved,
			passed: Boolean(firstClaim.verified && !mutatedEvidenceItemsResolved),
		});
	}
	if (firstRoute) {
		const mutatedResolvedProofReadyClaims = firstRoute.proofReady ? [] : firstRoute.resolvedProofReadyClaims;
		const mutatedMissing = firstRoute.proofReady ? firstRoute.missing : [];
		const mutatedVerified = firstRoute.proofReady
			? mutatedResolvedProofReadyClaims.length > 0
			: mutatedMissing.length > 0;
		controls.push({
			controlType: "swarm-route-proof-gate-control",
			routeId: firstRoute.routeId,
			mutation: firstRoute.proofReady ? "remove-resolved-proof-ready-claims" : "remove-explicit-missing-gates",
			mutatedResolvedProofReadyClaims,
			mutatedMissing,
			mutatedVerified,
			passed: Boolean(firstRoute.verified && !mutatedVerified),
		});
	}
	return {
		verified: controls.length >= 3 && controls.every((row) => row.passed),
		negativeControlsPassed: controls.filter((row) => row.passed).length,
		negativeControls: controls,
	};
}

function swarmVerificationClaim(claimLedger, claim) {
	const normalized = { verdict: "promoted", confidence: 0.8, blockers: [], ...claim };
	claimLedger.push(normalized);
	return normalized;
}

function buildSwarmMergeVerification(evidenceRoot, workersReport, mergeReport) {
	const transcriptVerification = verifySwarmTranscriptHashes(evidenceRoot, workersReport);
	const artifactVerification = verifySwarmHarvestedArtifacts(workersReport);
	const claimGateVerification = verifySwarmClaimProofGates(mergeReport.claimRows, mergeReport.proofReadyPromotedClaims, mergeReport.evidenceItemRows, mergeReport.conflictRows);
	const routeGateVerification = verifySwarmRouteProofGates(mergeReport.routeReadinessRows, mergeReport.proofReadyPromotedClaims);
	const negativeControlVerification = buildSwarmMergeNegativeControls(transcriptVerification, artifactVerification, claimGateVerification, routeGateVerification);
	const claimLedger = [];
	const composedPaths = [];
	const transcriptClaim = transcriptVerification.verified
		? swarmVerificationClaim(claimLedger, {
				id: "swarm-worker-transcript-hash-" + sha256(transcriptVerification.workerChecks.map((row) => `${row.workerId}:${row.stdoutSha256}:${row.stderrSha256}`).join("|")).slice(0, 16),
				claimType: "swarm-worker-transcript-hash-proof",
				sourceBinding: { artifact: "merge-verification.json", workers: transcriptVerification.workerChecks.map((row) => row.workerId) },
				evidenceBinding: transcriptVerification,
				statement: "Swarm verifier rebound worker stdout/stderr transcripts to hashes stored in report.json.",
			})
		: undefined;
	const artifactClaim = artifactVerification.verified
		? swarmVerificationClaim(claimLedger, {
				id: "swarm-harvested-artifact-integrity-" + sha256(artifactVerification.artifactChecks.map((row) => `${row.workerId}:${row.sha256}`).join("|")).slice(0, 16),
				claimType: "swarm-harvested-artifact-integrity-proof",
				sourceBinding: { artifact: "merge-verification.json", harvestedArtifacts: "worker-*-artifacts.json" },
				evidenceBinding: artifactVerification,
				statement: artifactVerification.artifactCount
					? "Swarm verifier matched harvested worker artifacts by size and SHA-256."
					: "Swarm verifier confirmed there were no harvested artifacts requiring size/SHA-256 verification.",
				confidence: artifactVerification.artifactCount ? 0.84 : 0.72,
			})
		: undefined;
	const claimGateClaim = claimGateVerification.verified
		? swarmVerificationClaim(claimLedger, {
				id: "swarm-claim-proof-gate-" + sha256(claimGateVerification.claimChecks.map((row) => row.claimId).join("|")).slice(0, 16),
				claimType: "swarm-claim-proof-gate-proof",
				sourceBinding: { artifact: "merge-verification.json", merge: "merge-report.json" },
				evidenceBinding: claimGateVerification,
				statement: "Swarm verifier confirmed proof-ready promoted claims carry passive, replay/proof, negative-control, evidence-item, and conflict gates.",
				confidence: 0.86,
			})
		: undefined;
	const routeGateClaim = routeGateVerification.verified
		? swarmVerificationClaim(claimLedger, {
				id: "swarm-route-proof-gate-" + sha256(routeGateVerification.routeChecks.map((row) => `${row.routeId}:${row.proofReady}`).join("|")).slice(0, 16),
				claimType: "swarm-route-proof-gate-proof",
				sourceBinding: { artifact: "merge-verification.json", merge: "merge-report.json" },
				evidenceBinding: routeGateVerification,
				statement: "Swarm verifier confirmed each route readiness row either resolves to proof-ready promoted claims or remains blocked with explicit missing gates.",
				confidence: 0.84,
			})
		: undefined;
	const negativeClaim = negativeControlVerification.verified
		? swarmVerificationClaim(claimLedger, {
				id: "swarm-merge-negative-control-" + sha256(JSON.stringify(negativeControlVerification.negativeControls)).slice(0, 16),
				claimType: "swarm-merge-negative-control-proof",
				sourceBinding: { artifact: "merge-verification.json" },
				evidenceBinding: negativeControlVerification,
				statement: "Swarm verifier executed transcript-hash, artifact-hash, missing-evidence-item, and route-gate negative controls where applicable.",
				confidence: 0.84,
			})
		: undefined;
	if (transcriptClaim && artifactClaim && claimGateClaim && routeGateClaim && negativeClaim) {
		const segments = [transcriptClaim, artifactClaim, claimGateClaim, routeGateClaim, negativeClaim];
		const composed = {
			id: "swarm-merge-verification-proof-path-" + sha256(segments.map((claim) => claim.id).join(">")).slice(0, 16),
			claimType: "swarm-merge-verification-proof-path",
			sourceBinding: { segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType, artifact: claim.sourceBinding?.artifact })) },
			evidenceBinding: {
				verifiedWorkers: transcriptVerification.verifiedWorkers,
				verifiedArtifacts: artifactVerification.verifiedArtifacts,
				verifiedClaims: claimGateVerification.verifiedClaims,
				verifiedRoutes: routeGateVerification.verifiedRoutes,
				negativeControlsPassed: negativeControlVerification.negativeControlsPassed,
			},
			statement: "Swarm merge proof path composes transcript hashes, artifact integrity, claim gates, route gates, and verifier negative controls.",
			verdict: "promoted",
			confidence: 0.88,
			blockers: [],
		};
		claimLedger.push(composed);
		composedPaths.push(composed);
	}
	const blockers = [];
	if (!transcriptVerification.verified) blockers.push("missing-swarm-transcript-hash-verification");
	if (!artifactVerification.verified) blockers.push("missing-swarm-artifact-integrity");
	if (!claimGateVerification.verified) blockers.push("missing-swarm-claim-proof-gate");
	if (!routeGateVerification.verified) blockers.push("missing-swarm-route-proof-gate");
	if (!negativeControlVerification.verified) blockers.push("missing-swarm-merge-negative-control");
	const repairActions = {
		"missing-swarm-transcript-hash-verification": "Rerun swarm merge after ensuring worker-*.stdout.txt and worker-*.stderr.txt hashes match report.json.",
		"missing-swarm-artifact-integrity": "Regenerate or re-harvest worker artifacts so every harvested artifact has matching size and SHA-256.",
		"missing-swarm-claim-proof-gate": "Require each promoted proof-ready claim to include passive evidence, replay/proof evidence, negative controls, and resolved evidence item IDs.",
		"missing-swarm-route-proof-gate": "Run route repair commands until each route has a proof-ready promoted claim or an explicit missing gate.",
		"missing-swarm-merge-negative-control": "Run transcript hash, artifact hash, missing-evidence-item, and route-gate mutation controls before promotion.",
	};
	const proofReady = blockers.length === 0 && composedPaths.length > 0;
	return {
		kind: "repi-swarm-merge-verification",
		schemaVersion: 1,
		SwarmMergeVerificationV1: true,
		generatedAt: new Date().toISOString(),
		runId: mergeReport.runId,
		evidenceRoot,
		proofReady,
		finalPromotionReady: Boolean(mergeReport.finalPromotionReady && proofReady),
		transcriptVerification,
		artifactVerification,
		claimGateVerification,
		routeGateVerification,
		negativeControlVerification,
		stats: {
			verifiedWorkers: transcriptVerification.verifiedWorkers,
			verifiedArtifacts: artifactVerification.verifiedArtifacts,
			verifiedClaims: claimGateVerification.verifiedClaims,
			verifiedRoutes: routeGateVerification.verifiedRoutes,
			negativeControlsPassed: negativeControlVerification.negativeControlsPassed,
		},
		claimLedger,
		composedPaths,
		promotionReport: {
			proofReady,
			finalPromotionReady: Boolean(mergeReport.finalPromotionReady && proofReady),
			promotedClaims: claimLedger.filter((claim) => claim.verdict === "promoted"),
			composedPaths: composedPaths.filter((path) => path.verdict === "promoted"),
			blockers,
		},
		repairQueue: blockers.map((blocker) => ({
			id: "swarm-merge-verification-" + blocker,
			blocker,
			action: repairActions[blocker] ?? "Collect verifier-bound swarm merge evidence and rerun repi swarm merge.",
			rerunCommand: `repi swarm merge ${shellQuote(mergeReport.runId)} --json`,
		})),
	};
}

export function buildMergeReport(evidenceRoot) {
	const reportPath = join(evidenceRoot, "report.json");
	const report = existsSync(reportPath) ? readJson(reportPath) : undefined;
	const plan = existsSync(join(evidenceRoot, "plan.json")) ? readJson(join(evidenceRoot, "plan.json")) : report?.plan;
	const workersReport = report?.workersReport ?? [];
	const claimRows = [];
	const observations = [];
	const blockerRows = [];
	const proofChecklists = [];
	const routeHandoffs = [];
	const conflictRows = [];
	const evidenceItemRows = [];
	const nextCommands = new Set();
	const repairQueue = [];
	const addRepair = (row) => {
		const repair = repairQueueRow(row);
		if (!repair) return;
		nextCommands.add(repair.command);
		if (!repairQueue.some((existing) => existing.id === repair.id || existing.command === repair.command)) {
			repairQueue.push(repair);
		}
	};
	for (const worker of workersReport) {
		const stdoutPath = join(evidenceRoot, `worker-${worker.workerId}.stdout.txt`);
		const stdout = existsSync(stdoutPath) ? readFileSync(stdoutPath, "utf8") : worker.stdoutTail ?? "";
		const parsed = extractJsonObject(stdout);
		const parsedClaims = Array.isArray(parsed?.claims)
			? parsed.claims
			: Array.isArray(parsed?.findings)
				? parsed.findings.map((finding, index) =>
						typeof finding === "string"
							? { id: `worker-${worker.workerId}-finding-${index + 1}`, statement: finding, evidence: parsed?.evidence ?? parsed?.artifacts ?? [] }
								: finding,
					)
				: [];
		let evidenceItemOrdinal = 0;
		const workerEvidenceItems = [];
		for (const evidenceItem of Array.isArray(parsed?.evidenceItems) ? parsed.evidenceItems : []) {
			const normalized = normalizeEvidenceItem(worker, evidenceItem, evidenceItemOrdinal++);
			if (normalized) {
				workerEvidenceItems.push(normalized);
				evidenceItemRows.push(normalized);
			}
		}
		proofChecklists.push(proofChecklistForWorker(worker, parsed, parsedClaims, stdout, workerEvidenceItems));
		for (const [index, handoff] of (Array.isArray(parsed?.handoffs) ? parsed.handoffs : []).entries()) {
			const normalized = normalizeRouteHandoff(worker, handoff, index);
			if (normalized) routeHandoffs.push(normalized);
		}
		const workerConflicts = [];
		for (const [index, conflict] of (Array.isArray(parsed?.conflicts) ? parsed.conflicts : []).entries()) {
			const normalized = normalizeConflict(worker, conflict, index);
			if (normalized) workerConflicts.push(normalized);
		}
		for (let index = 0; index < parsedClaims.length; index++) {
			const claim = parsedClaims[index] ?? {};
			const claimId = String(claim.id ?? `worker-${worker.workerId}-claim-${index + 1}`);
			const claimEvidenceItems = [];
			for (const evidenceItem of Array.isArray(claim?.evidenceItems) ? claim.evidenceItems : []) {
				const normalized = normalizeEvidenceItem(worker, evidenceItem, evidenceItemOrdinal++, claimId);
				if (normalized) {
					claimEvidenceItems.push(normalized);
					evidenceItemRows.push(normalized);
				}
			}
			const matchedWorkerEvidenceItems = workerEvidenceItems.filter((item) => item.claimId === claimId || (!item.claimId && parsedClaims.length === 1));
			const allClaimEvidenceItems = [...matchedWorkerEvidenceItems, ...claimEvidenceItems];
			for (const [conflictIndex, conflict] of (Array.isArray(claim?.conflicts) ? claim.conflicts : []).entries()) {
				const normalized = normalizeConflict(worker, conflict, workerConflicts.length + conflictIndex, claimId);
				if (normalized) workerConflicts.push(normalized);
			}
			const directEvidence = Array.isArray(claim.evidence)
				? claim.evidence.map(String).filter(Boolean)
				: Array.isArray(parsed?.evidence)
					? parsed.evidence.map(String).filter(Boolean)
					: Array.isArray(parsed?.artifacts)
						? parsed.artifacts.map(String).filter(Boolean)
						: [];
			const evidence = [...directEvidence, ...allClaimEvidenceItems.map((item) => item.evidenceText).filter(Boolean)];
			const confidence = Number.isFinite(Number(claim.confidence)) ? Number(claim.confidence) : evidence.length > 0 ? 0.6 : 0;
			const blockers = Array.isArray(claim.blockers) ? claim.blockers.map((item) => redact(String(item))).slice(0, 6) : [];
			const techniqueProofChecks = buildTechniqueProofChecks(claim, evidence, allClaimEvidenceItems);
			const techniqueIds = techniqueProofChecks.map((row) => row.techniqueId);
			const techniqueProofReady = techniqueProofChecks.every((row) => row.proofReady);
			const qualitySignals = claimQualitySignals(evidence, blockers, allClaimEvidenceItems);
			const proofCoverage = claimProofCoverage(qualitySignals);
			const baseStatus = worker.status === "pass" && evidence.length > 0 && confidence >= 0.5 ? "promoted" : "observation";
			claimRows.push({
				claimId,
				workerId: worker.workerId,
				role: worker.role ?? parsed?.role ?? "worker",
				route: worker.route ?? null,
				statement: redact(String(claim.statement ?? claim.title ?? "")),
				evidence: evidence.map(redact).slice(0, 8),
				confidence,
				baseStatus,
				status: "observation",
				blockers,
				qualitySignals,
				proofCoverage,
				proofReady: false,
				techniqueIds,
				techniqueProofChecks,
				techniqueProofReady,
				techniqueProofMissing: techniqueProofChecks.flatMap((row) => row.missing.map((gate) => `${row.techniqueId}:${gate}`)),
				evidenceItemIds: allClaimEvidenceItems.map((item) => item.evidenceItemId).slice(0, 12),
				conflictResolution: conflictResolutionForClaim({ claimId, qualitySignals }, workerConflicts),
			});
		}
		for (const conflict of workerConflicts) {
			conflictRows.push(conflict);
			if (conflict.nextCommand) {
				addRepair({
					kind: "conflict-recheck",
					priority: 75,
					workerId: conflict.workerId,
					claimId: conflict.claimId,
					routeId: conflict.route?.id,
					reason: conflict.reason,
					command: conflict.nextCommand,
				});
			}
		}
		for (const command of Array.isArray(parsed?.nextCommands) ? parsed.nextCommands : []) {
			addRepair({
				kind: "worker-suggested",
				priority: 45,
				workerId: worker.workerId,
				routeId: worker.route?.id,
				command: redact(String(command)),
			});
		}
		for (const blocker of Array.isArray(parsed?.blockers) ? parsed.blockers : []) blockerRows.push({ workerId: worker.workerId, role: worker.role, blocker: redact(String(blocker)) });
		if (!parsedClaims.length) {
			observations.push({
				workerId: worker.workerId,
				role: worker.role ?? "worker",
				status: worker.status,
				stdoutSha256: worker.stdoutSha256,
				signals: linesMatching(stdout, /claim|finding|evidence|blocker|next|发现|证据|阻塞|下一步/i, 10),
			});
		}
	}
	for (const claim of claimRows) {
		const conflictResolution = conflictResolutionForClaim(claim, conflictRows);
		claim.conflictResolution = conflictResolution;
		claim.status = claim.baseStatus === "promoted" && !conflictResolution.downgraded && claim.techniqueProofReady !== false ? "promoted" : "observation";
		delete claim.baseStatus;
	}
	for (const claim of claimRows.filter((row) => row.techniqueProofReady === false)) {
		const command = techniqueProofRepairCommand(plan, claim);
		if (command) {
			addRepair({
				kind: "named-technique-proof",
				priority: 95,
				workerId: claim.workerId,
				claimId: claim.claimId,
				routeId: claim.route?.id,
				missing: claim.techniqueProofMissing,
				reason: "named technique claim lacks contract-specific proofExit evidence or negative controls",
				command,
			});
		}
	}
	for (const checklist of proofChecklists) {
		const command = proofRepairCommand(plan, checklist);
		if (command) {
			addRepair({
				kind: "worker-proof-checklist",
				priority: 85,
				workerId: checklist.workerId,
				routeId: checklist.route?.id,
				missing: checklist.missing,
				reason: "worker did not satisfy passive/proofExit/negativeControls checklist",
				command,
			});
		}
	}
	const routeCoverage = plan?.routeCoverage || (Array.isArray(plan?.routeCandidates) && Array.isArray(plan?.workerPackets)
		? routeCoverageForPackets(plan.routeCandidates, plan.workerPackets)
		: undefined);
	for (const route of Array.isArray(routeCoverage?.uncovered) ? routeCoverage.uncovered : []) {
		const command = routeCoverageRepairCommand(plan, route);
		if (command) {
			addRepair({
				kind: "route-coverage",
				priority: 80,
				routeId: route.id,
				missing: ["assigned worker"],
				reason: "route candidate was not assigned to any worker",
				command,
			});
		}
	}
	for (const handoff of routeHandoffs) {
		if (handoff.nextCommand) {
			addRepair({
				kind: "handoff-seed",
				priority: 60,
				workerId: handoff.workerId,
				routeId: handoff.route?.id,
				handoffId: handoff.handoffId,
				reason: handoff.reason,
				command: handoff.nextCommand,
			});
		}
		const command = routeHandoffCommand(plan, handoff);
		if (command) {
			addRepair({
				kind: "route-handoff",
				priority: 78,
				workerId: handoff.workerId,
				routeId: handoff.route?.id,
				handoffId: handoff.handoffId,
				reason: handoff.reason,
				command,
			});
		}
	}
	const promotedClaims = claimRows.filter((claim) => claim.status === "promoted");
	const techniqueProofChecks = claimRows.flatMap((claim) =>
		(claim.techniqueProofChecks ?? []).map((check) => ({ claimId: claim.claimId, workerId: claim.workerId, route: claim.route, ...check })),
	);
	const missingTechniqueProofClaims = claimRows
		.filter((claim) => claim.techniqueProofReady === false)
		.map((claim) => ({ claimId: claim.claimId, workerId: claim.workerId, route: claim.route, missing: claim.techniqueProofMissing }));
	const proofReadyWorkerIds = new Set(proofChecklists.filter((row) => row.proofReady).map((row) => row.workerId));
	for (const claim of claimRows) claim.proofReady = proofReadyWorkerIds.has(claim.workerId) && claimProofReady(claim);
	const proofReadyPromotedClaims = promotedClaims.filter((claim) => claim.proofReady);
	const routeReadinessRows = buildRouteReadinessRows(plan, workersReport, proofChecklists, promotedClaims, proofReadyPromotedClaims, routeCoverage);
	for (const readiness of routeReadinessRows.filter((row) => !row.proofReady && row.assignedWorkerIds.length > 0)) {
		const command = routeProofRepairCommand(plan, readiness);
		if (command) {
			addRepair({
				kind: "route-proof",
				priority: 90,
				routeId: readiness.routeId,
				missing: readiness.missing,
				reason: "route lacks a proof-ready promoted claim",
				command,
			});
		}
	}
	const missingProofRoutes = routeReadinessRows.filter((row) => !row.proofReady).map((row) => row.route);
	const proofReadyRouteIds = routeReadinessRows.filter((row) => row.proofReady).map((row) => row.routeId);
	const routeProofReady = routeReadinessRows.length > 0 && missingProofRoutes.length === 0;
	const routeCoverageReady = routeCoverage?.complete !== false;
	const allWorkersPassed = workersReport.length > 0 && workersReport.every((worker) => worker.status === "pass");
	const prioritizedRepairQueue = repairQueue
		.sort((left, right) => right.priority - left.priority || String(left.id).localeCompare(String(right.id)))
		.slice(0, 24);
	const mergeReport = {
		kind: "repi-swarm-merge-report",
		schemaVersion: 1,
		StructuredSubagentMergeV1: true,
		generatedAt: new Date().toISOString(),
		runId: report?.runId ?? plan?.runId ?? basename(evidenceRoot),
		evidenceRoot,
		planPath: existsSync(join(evidenceRoot, "plan.json")) ? join(evidenceRoot, "plan.json") : undefined,
		reportPath: existsSync(reportPath) ? reportPath : undefined,
		workerCount: workersReport.length,
		passedWorkers: workersReport.filter((worker) => worker.status === "pass").length,
		failedWorkers: workersReport.filter((worker) => worker.status !== "pass").map((worker) => ({ workerId: worker.workerId, role: worker.role, status: worker.status, exit: worker.exit })),
		claimRows,
		promotedClaims,
		observations,
		blockerRows,
		conflictRows,
		evidenceItemRows,
		techniqueProofChecks,
		missingTechniqueProofClaims,
		proofChecklists,
		routeHandoffs,
		proofReadyPromotedClaims,
		proofPromotionReady: proofReadyPromotedClaims.length > 0 && allWorkersPassed,
		routeReadinessRows,
		proofReadyRouteIds,
		missingProofRoutes,
		routeProofReady,
		routeCoverage,
		routeCoverageReady,
		repairQueue: prioritizedRepairQueue,
		evidencePriorityDoctrine: plan?.evidencePriorityDoctrine ?? evidencePriorityDoctrine,
		capabilityMatrixDoctrine: plan?.capabilityMatrixDoctrine ?? capabilityMatrixDoctrine,
		nextCommands: [...nextCommands].slice(0, 24),
		mergeDigest: sha256(JSON.stringify({ workers: workersReport.map((worker) => [worker.workerId, worker.status, worker.stdoutSha256]), promotedClaims, blockerRows, conflictRows, evidenceItemRows })),
		ok: allWorkersPassed,
		finalPromotionReady: proofReadyPromotedClaims.length > 0 && allWorkersPassed && routeCoverageReady && routeProofReady,
		narrativeOnlyBlocked: claimRows.length === 0 && observations.length > 0,
	};
	const mergeVerification = buildSwarmMergeVerification(evidenceRoot, workersReport, mergeReport);
	mergeReport.mergeVerification = mergeVerification;
	atomicWriteFile(join(evidenceRoot, "merge-verification.json"), `${JSON.stringify(mergeVerification, null, 2)}\n`, 0o600);
	atomicWriteFile(join(evidenceRoot, "merge-report.json"), `${JSON.stringify(mergeReport, null, 2)}\n`, 0o600);
	return mergeReport;
}
