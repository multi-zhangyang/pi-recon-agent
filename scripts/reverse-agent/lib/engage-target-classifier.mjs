import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, extname, join, resolve } from "node:path";

export function isUrl(value) {
	try {
		const url = new URL(value);
		return url.protocol === "http:" || url.protocol === "https:";
	} catch {
		return false;
	}
}

export function classifyTarget(target, { commandExists, run }) {
	if (isUrl(target)) {
		const parsed = new URL(target);
		return {
			kind: "url",
			lane: "web-api",
			domain: "Web/API pentest",
			target,
			path: null,
			reason: `url protocol=${parsed.protocol} host=${parsed.host}`,
			adapter: "web-runtime",
		};
	}

	const path = resolve(target || process.cwd());
	if (!existsSync(path)) {
		return {
			kind: "text",
			lane: "reverse-pentest-general",
			domain: "Reverse/Pentest general",
			target,
			path: null,
			reason: "target is not a local path or URL; treating it as task text",
			adapter: "general-operator",
		};
	}

	const stat = statSync(path);
	if (stat.isDirectory()) {
		const directoryRoute = classifyDirectory(path, { commandExists, run });
		if (directoryRoute) return directoryTarget(path, directoryRoute.lane, directoryRoute.domain, directoryRoute.reason, directoryRoute.representativePath);
		return directoryTarget(path, "workspace", "Workspace reverse/pentest", "directory target");
	}

	const ext = extname(path).toLowerCase();
	const lowerBase = basename(path).toLowerCase();
	if ([".apk", ".dex"].includes(ext)) return fileTarget(path, "mobile", "Mobile reverse", "mobile package extension");
	if ([".ipa"].includes(ext)) return fileTarget(path, "mobile-ios", "Mobile/iOS reverse", "ios package extension");
	if ([".pcap", ".pcapng", ".cap"].includes(ext)) return fileTarget(path, "pcap-dfir", "PCAP/DFIR", "packet capture extension");
	if ([".vmem", ".mem", ".dmp"].includes(ext) || (ext === ".raw" && /mem|memory|ram|dump/.test(lowerBase))) return fileTarget(path, "memory-forensics", "Memory forensics", "memory image extension");
	if ([".evtx", ".kirbi", ".ccache", ".dit", ".hive", ".hiv"].includes(ext) || ["ntds.dit", "sam", "system", "security"].includes(lowerBase)) return fileTarget(path, "windows-ad", "Identity / Windows / AD", "Windows/AD artifact extension");
	if ([".yar", ".yara"].includes(ext) || (looksLikeMalwareName(lowerBase) && [".exe", ".dll", ".sys", ".scr", ".bin", ".dat", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta"].includes(ext))) return fileTarget(path, "malware", "Malware / sample analysis", "malware sample/rule artifact");
	if ([".bin", ".img", ".trx", ".squashfs", ".ubi", ".ubifs", ".uimage"].includes(ext)) return fileTarget(path, "firmware-iot", "Firmware/IoT reverse", "firmware-like extension");
	if ([".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".wav", ".mp3", ".ogg", ".flac", ".enc", ".cipher"].includes(ext)) return fileTarget(path, "crypto-stego", "Crypto/Stego", "crypto/stego-like extension");
	if ([".elf", ".exe", ".dll", ".so", ".dylib", ".macho"].includes(ext)) return fileTarget(path, "native-pwn", "Native reverse/pwn", "native binary extension");
	if ([".js", ".mjs", ".cjs", ".wasm"].includes(ext)) return fileTarget(path, "js-reverse", "JS/WASM reverse", "script or wasm extension");

	let magic = "";
	if (commandExists("file")) {
		const fileRun = run("file", ["-b", path], { id: "classify-file", timeout: 5000 });
		magic = fileRun.stdout.trim();
	}
	if (/ELF|PE32|Mach-O|shared object|executable/i.test(magic)) return fileTarget(path, "native-pwn", "Native reverse/pwn", magic || "native executable");
	if (/pcap|packet capture/i.test(magic)) return fileTarget(path, "pcap-dfir", "PCAP/DFIR", magic || "packet capture");
	if (/memory dump|crash dump|hibernation|vmem/i.test(magic)) return fileTarget(path, "memory-forensics", "Memory forensics", magic || "memory image");
	return fileTarget(path, "reverse", "File reverse", magic || "local file");
}

function classifyDirectory(path, { commandExists, run }) {
	const names = safeList(path);
	const lowerNames = names.map((name) => name.toLowerCase());
	const fileEntries = collectDirectoryFiles(path);
	const byExt = (extensions) => fileEntries.find((entry) => extensions.some((ext) => entry.lower.endsWith(ext)));
	const nativeExt = byExt([".elf", ".exe", ".dll", ".so", ".dylib", ".macho"]);
	const mobile = byExt([".apk", ".dex"]);
	if (lowerNames.includes("androidmanifest.xml") || fileEntries.some((entry) => entry.lower.endsWith("androidmanifest.xml")) || mobile) return { lane: "mobile", domain: "Mobile reverse", reason: "android/mobile artifacts found", representativePath: mobile?.path };
	const ios = byExt([".ipa"]);
	if (lowerNames.includes("info.plist") || fileEntries.some((entry) => entry.lower.endsWith("info.plist")) || ios) return { lane: "mobile-ios", domain: "Mobile/iOS reverse", reason: "ios/mobile artifacts found", representativePath: ios?.path };
	const pcap = byExt([".pcap", ".pcapng", ".cap"]);
	if (pcap) return { lane: "pcap-dfir", domain: "PCAP/DFIR", reason: "packet capture artifact found", representativePath: pcap.path };
	const memory = fileEntries.find((entry) => [".vmem", ".mem", ".dmp"].some((ext) => entry.lower.endsWith(ext)) || (/mem|memory|ram|dump/.test(entry.lower) && entry.lower.endsWith(".raw")));
	if (memory) return { lane: "memory-forensics", domain: "Memory forensics", reason: "memory image artifact found", representativePath: memory.path };
	const windowsAd = detectWindowsAdDirectory(fileEntries);
	if (windowsAd) return { lane: "windows-ad", domain: "Identity / Windows / AD", reason: windowsAd.reason, representativePath: windowsAd.representativePath };
	const malware = detectMalwareDirectory(fileEntries);
	if (malware) return { lane: "malware", domain: "Malware / sample analysis", reason: malware.reason, representativePath: malware.representativePath };
	const firmware = byExt([".bin", ".img", ".trx", ".squashfs", ".ubi", ".ubifs", ".uimage"]);
	if (firmware) return { lane: "firmware-iot", domain: "Firmware/IoT reverse", reason: "firmware-like artifact found", representativePath: firmware.path };
	const cryptoStego = byExt([".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".wav", ".mp3", ".ogg", ".flac", ".enc", ".cipher"]);
	const cryptoSignal = fileEntries.find((entry) => /(?:cipher|crypto|stego|secret|flag)\.(?:txt|bin|dat|enc|out)$/.test(entry.lower));
	const challengeOutput = lowerNames.includes("chall.py") && lowerNames.includes("output.txt") ? fileEntries.find((entry) => entry.lower === "output.txt") : undefined;
	if (cryptoStego || cryptoSignal || challengeOutput) {
		return { lane: "crypto-stego", domain: "Crypto/Stego", reason: "crypto/stego challenge artifacts found", representativePath: cryptoStego?.path ?? cryptoSignal?.path ?? challengeOutput?.path };
	}
	if (nativeExt) return { lane: "native-pwn", domain: "Native reverse/pwn", reason: "native binary artifact found", representativePath: nativeExt.path };
	const agentBoundary = detectAgentBoundaryDirectory(fileEntries);
	if (agentBoundary) return { lane: "agent-boundary", domain: "Agent boundary/prompt-injection pentest", reason: agentBoundary.reason, representativePath: agentBoundary.representativePath };
	const cloudIdentity = detectCloudIdentityDirectory(fileEntries, lowerNames);
	if (cloudIdentity) return { lane: "cloud-identity", domain: "Cloud/container pentest", reason: cloudIdentity.reason, representativePath: cloudIdentity.representativePath };
	if (lowerNames.includes("package.json") || lowerNames.includes("pnpm-lock.yaml") || lowerNames.includes("yarn.lock") || lowerNames.includes("vite.config.ts")) return { lane: "js-reverse", domain: "JS/Web reverse", reason: "frontend/node artifacts found", representativePath: byExt([".js", ".mjs", ".cjs", ".wasm"])?.path };
	if (commandExists("file")) {
		for (const entry of fileEntries.slice(0, 40)) {
			const magic = run("file", ["-b", entry.path], { id: "classify-directory-file", timeout: 5000 }).stdout.trim();
			if (/ELF|PE32|Mach-O|shared object|executable/i.test(magic)) return { lane: "native-pwn", domain: "Native reverse/pwn", reason: `native executable in directory: ${entry.name}`, representativePath: entry.path };
			if (/pcap|packet capture/i.test(magic)) return { lane: "pcap-dfir", domain: "PCAP/DFIR", reason: `packet capture in directory: ${entry.name}`, representativePath: entry.path };
			if (/memory dump|crash dump|hibernation|vmem/i.test(magic)) return { lane: "memory-forensics", domain: "Memory forensics", reason: `memory image in directory: ${entry.name}`, representativePath: entry.path };
		}
	}
	return undefined;
}

export function collectDirectoryFiles(base, maxDepth = 3, limit = 300) {
	const out = [];
	const skippedDirs = new Set([".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache"]);
	function walk(dir, depth, prefix) {
		if (out.length >= limit) return;
		let entries = [];
		try {
			entries = readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}
		for (const entry of entries) {
			if (out.length >= limit) return;
			const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
			const candidate = join(dir, entry.name);
			if (entry.isFile()) {
				out.push({ name: relative, lower: relative.toLowerCase(), path: candidate });
			} else if (entry.isDirectory() && depth < maxDepth && !skippedDirs.has(entry.name)) {
				walk(candidate, depth + 1, relative);
			}
		}
	}
	walk(base, 0, "");
	return out;
}

export function textLikeAgentFile(entry) {
	return /\.(?:js|mjs|cjs|ts|tsx|jsx|py|go|rs|md|mdx|txt|json|ya?ml|toml|prompt|jinja|hbs)$/i.test(entry.name) || /(?:prompt|agent|tool|mcp|llm|openai|anthropic|langchain|policy|guardrail)/i.test(entry.name);
}

export function readSmallText(path, maxBytes = 180_000) {
	try {
		const data = readFileSync(path);
		return data.subarray(0, maxBytes).toString("utf8");
	} catch {
		return "";
	}
}

function detectAgentBoundaryDirectory(fileEntries) {
	let llmScore = 0;
	let boundaryScore = 0;
	let representativePath;
	const hasCodeFile = fileEntries.some((entry) => /\.(?:js|mjs|cjs|ts|tsx|jsx|py|go|rs)$/i.test(entry.name));
	for (const entry of fileEntries.slice(0, 220)) {
		if (!textLikeAgentFile(entry)) continue;
		const text = readSmallText(entry.path, 80_000);
		if (!text) continue;
		const lowerName = entry.lower;
		const llm = /openai|anthropic|langchain|llamaindex|chat\.completions|responses\.create|generateText|streamText|mcp|model\s*[:=]|systemPrompt|tool_call|function_call/i.test(text) || /(?:agent|llm|prompt|mcp|tool)/i.test(lowerName);
		const boundary = /system\s+prompt|developer\s+message|role\s*:\s*["']system|ignore\s+(?:previous|above)|prompt\s+injection|tool\s*schema|function\s+calling|exec\(|spawn\(|child_process|shell|retrieval|vector|document|webhook|req\.body|request\.json/i.test(text);
		if (llm) {
			llmScore += 1;
			representativePath ??= entry.path;
		}
		if (boundary) {
			boundaryScore += 1;
			if (/\.(?:js|mjs|cjs|ts|tsx|jsx|py|go|rs)$/i.test(entry.name)) representativePath = entry.path;
		}
		const hasCodeRepresentative = representativePath && /\.(?:js|mjs|cjs|ts|tsx|jsx|py|go|rs)$/i.test(representativePath);
		if (llmScore >= 1 && boundaryScore >= 1 && (!hasCodeFile || hasCodeRepresentative)) {
			return {
				reason: `agent/LLM boundary artifacts found: ${entry.name}`,
				representativePath: representativePath ?? entry.path,
			};
		}
	}
	return undefined;
}

export function textLikeCloudFile(entry) {
	return /\.(?:tf|tfvars|ya?ml|json|env|ini|conf|properties|sh|Dockerfile)$/i.test(entry.name) || /(?:dockerfile|compose|k8s|kubernetes|helm|terraform|terragrunt|workflow|github\/workflows|cloudformation|serverless|sam|pulumi)/i.test(entry.name);
}

function detectCloudIdentityDirectory(fileEntries, lowerNames = []) {
	const nameHit = fileEntries.find((entry) => /\.(?:tf|tfvars)$/i.test(entry.name) || /(?:^|\/)(?:Dockerfile|docker-compose\.ya?ml|compose\.ya?ml|Chart\.yaml|values\.ya?ml|serverless\.ya?ml|template\.ya?ml)$/i.test(entry.name) || /(?:^|\/)(?:k8s|kubernetes|helm|\.github\/workflows)\//i.test(entry.name));
	if (nameHit || lowerNames.includes("dockerfile") || lowerNames.some((name) => name.endsWith(".tf") || name.includes("k8s") || name.includes("kubernetes"))) {
		return { reason: `cloud/container artifacts found: ${nameHit?.name ?? "top-level marker"}`, representativePath: nameHit?.path };
	}
	for (const entry of fileEntries.slice(0, 220)) {
		if (!textLikeCloudFile(entry)) continue;
		const text = readSmallText(entry.path, 80_000);
		if (/\b(?:provider\s+"(?:aws|azurerm|google|kubernetes)"|apiVersion:\s*(?:apps|v1|rbac|batch)|kind:\s*(?:Deployment|Pod|Secret|ServiceAccount|ClusterRoleBinding)|aws-actions\/configure-aws-credentials|permissions:\s*id-token|FROM\s+[^\n]+|resources:\s*["']?(?:aws_|azurerm_|google_))/i.test(text)) {
			return { reason: `cloud/identity content found: ${entry.name}`, representativePath: entry.path };
		}
	}
	return undefined;
}

function windowsAdBasename(entry) {
	return basename(entry.name).toLowerCase();
}

function isWindowsRegistryHiveArtifact(entry) {
	const base = windowsAdBasename(entry);
	return ["sam", "system", "security"].includes(base) || /^(?:sam|system|security)[._-].*\.(?:hive|hiv|reg)$/i.test(base);
}

function isBloodHoundArtifact(entry) {
	const lower = entry.lower;
	const base = windowsAdBasename(entry);
	return (
		/(?:^|\/)(?:bloodhound|sharphound)\//i.test(lower) && /\.(?:json|zip)$/i.test(base)
	) || /(?:bloodhound|sharphound)[^/]*\.(?:json|zip)$/i.test(base);
}

export function textLikeWindowsAdFile(entry) {
	return (
		/\.(?:txt|csv|json|xml|evtx|kirbi|ccache|dit|hive|hiv|log|ps1|bat|cmd|yml|yaml)$/i.test(entry.name) ||
		/(?:ntds\.dit|bloodhound|kerberoast|asrep|ldap|adcs|certipy|sharphound|powershell|event)/i.test(entry.name) ||
		isWindowsRegistryHiveArtifact(entry)
	);
}

function detectWindowsAdDirectory(fileEntries) {
	const artifact =
		fileEntries.find((entry) => /(?:^|\/)ntds\.dit$/i.test(entry.name)) ??
		fileEntries.find((entry) => /\.(?:evtx|kirbi|ccache|dit|hive|hiv)$/i.test(entry.name)) ??
		fileEntries.find((entry) => isWindowsRegistryHiveArtifact(entry)) ??
		fileEntries.find((entry) => isBloodHoundArtifact(entry));
	if (artifact) return { reason: `Windows/AD artifact found: ${artifact.name}`, representativePath: artifact.path };
	for (const entry of fileEntries.slice(0, 220)) {
		if (!textLikeWindowsAdFile(entry)) continue;
		const text = readSmallText(entry.path, 100_000);
		if (/\b(?:krbtgt|NTDS\.DIT|DCSync|Kerberoast|AS-REP|SPN|LDAP|ADCS|ESC[1-9]|Certipy|BloodHound|SharpHound|Domain Admins|EventID\s*(?:4624|4625|4672|4688|4768|4769|4771|4776)|S-1-5-21-[0-9-]+)\b/i.test(text)) {
			return { reason: `Windows/AD content found: ${entry.name}`, representativePath: entry.path };
		}
	}
	return undefined;
}

function malwareNameBase(name) {
	return basename(name).toLowerCase();
}

function hasStrongMalwareNameToken(name) {
	return /(?:^|[._\-/])(?:malware|trojan|ransom(?:ware)?|dropper|beacon|implant|stealer|rat|backdoor|botnet|c2|packed|upx|yara|floss|capa|ioc)(?:$|[._\-/])/i.test(name);
}

function hasWeakMalwareNameToken(name) {
	return /(?:^|[._\-/])(?:sample|payload|loader)(?:$|[._\-/])/i.test(name);
}

function isExecutableOrHighRiskScript(name) {
	return /\.(?:exe|dll|sys|scr|ps1|vbs|vbe|jse|hta|bat|cmd|lnk)$/i.test(name);
}

function isOpaqueSampleExtension(name) {
	return /\.(?:bin|dat)$/i.test(name);
}

function isMalwareRuleOrReportName(name) {
	return /\.(?:yar|yara)$/i.test(name) || /(?:^|\/)(?:capa|floss|yara|ioc|sandbox|behavior|malware|triage)[^/]*\.(?:txt|json|log|md)$/i.test(name);
}

function looksLikeMalwareName(name) {
	const base = malwareNameBase(name);
	if (hasStrongMalwareNameToken(base)) return true;
	return hasWeakMalwareNameToken(base) && (isExecutableOrHighRiskScript(base) || isOpaqueSampleExtension(base));
}

export function textLikeMalwareFile(entry) {
	const base = malwareNameBase(entry.name);
	return isMalwareRuleOrReportName(entry.name) || looksLikeMalwareName(entry.name) || (hasStrongMalwareNameToken(base) && /\.(?:txt|json|log|cfg|conf|ini|md|js)$/i.test(base));
}

export function malwareArtifactFile(entry) {
	const base = malwareNameBase(entry.name);
	if (/\.(?:yar|yara)$/i.test(base)) return true;
	if (isExecutableOrHighRiskScript(base)) return hasStrongMalwareNameToken(base) || hasWeakMalwareNameToken(base);
	if (isOpaqueSampleExtension(base)) return hasStrongMalwareNameToken(base) || hasWeakMalwareNameToken(base);
	if (/\.js$/i.test(base)) return hasStrongMalwareNameToken(base);
	return false;
}

function detectMalwareDirectory(fileEntries) {
	const ruleOrReport = fileEntries.find((entry) => isMalwareRuleOrReportName(entry.name));
	const namedSample = fileEntries.find((entry) => looksLikeMalwareName(entry.name) && malwareArtifactFile(entry));
	if (ruleOrReport) return { reason: `malware rule/report artifact found: ${ruleOrReport.name}`, representativePath: namedSample?.path ?? ruleOrReport.path };
	if (namedSample) return { reason: `malware sample-like artifact found: ${namedSample.name}`, representativePath: namedSample.path };
	for (const entry of fileEntries.slice(0, 220)) {
		if (!textLikeMalwareFile(entry)) continue;
		const text = readSmallText(entry.path, 100_000);
		if (/\b(?:YARA|capa|FLOSS|ATT&CK|CreateRemoteThread|VirtualAlloc|WriteProcessMemory|IsDebuggerPresent|NtQueryInformationProcess|CurrentVersion\\Run|schtasks|mutex|bot_id|ransom|command-and-control|beacon|UPX|VMProtect|Themida)\b|\bC2\b/i.test(text)) {
			return { reason: `malware analysis content found: ${entry.name}`, representativePath: entry.path };
		}
	}
	return undefined;
}

function directoryTarget(path, lane, domain, reason, representativePath) {
	return { kind: "directory", lane, domain, target: path, path, reason, representativePath, adapter: "workspace-runtime" };
}

export function fileTarget(path, lane, domain, reason) {
	return { kind: "file", lane, domain, target: path, path, reason, adapter: "file-runtime" };
}

function safeList(path) {
	try {
		return readdirSync(path).slice(0, 200);
	} catch {
		return [];
	}
}
