#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const root = resolve(process.argv[2] || ".");
const strict = process.argv.includes("--strict");
const sourcePath = join(root, "packages/coding-agent/src/core/recon-profile.ts");
const initPath = join(root, "scripts/reverse-agent/init-repi-profile.mjs");
const settingsPath = join(root, "repi-profile/settings.json");

const source = readFileSync(sourcePath, "utf8");
const init = readFileSync(initPath, "utf8");
const settings = JSON.parse(readFileSync(settingsPath, "utf8"));

const between = (text, start, end) => {
	const startIndex = text.indexOf(start);
	if (startIndex < 0) return "";
	const endIndex = text.indexOf(end, startIndex + start.length);
	return text.slice(startIndex, endIndex < 0 ? undefined : endIndex);
};

const beforeAgentStart = between(source, 'pi.on("before_agent_start"', 'pi.on("tool_call"');
const scopedArtifactIndex = between(source, "function scopedContextArtifactIndex", "function contextArtifactIndex");
const contextPack = between(source, "function buildContextPack", "function formatContextPack");
const toolResult = between(source, 'pi.on("tool_result"', 'pi.on("session_before_compact"');

const checks = [
	{
		id: "startup-memory-full-digest-not-default",
		pass: !/Memory digest:[\s\S]*buildMemoryDigest\(\)/.test(beforeAgentStart),
		evidence: "before_agent_start must use buildStartupMemoryDigest, not raw buildMemoryDigest",
	},
	{
		id: "startup-context-pack-not-default",
		pass: !/Context\/resume pack:[\s\S]*buildContextDigest\(\)/.test(beforeAgentStart),
		evidence: "before_agent_start must use buildStartupContextDigest, not raw buildContextDigest",
	},
	{
		id: "startup-evidence-ledger-not-default",
		pass: !/Evidence ledger tail:[\s\S]*buildEvidenceDigest\(\)/.test(beforeAgentStart),
		evidence: "before_agent_start must use buildStartupEvidenceDigest, not raw buildEvidenceDigest",
	},
	{
		id: "context-memory-tail-isolated",
		pass: /memoryTail:\s*buildContextMemoryTail/.test(contextPack),
		evidence: "context pack memoryTail must route through isolation helper",
	},
	{
		id: "context-artifact-index-memory-gated",
		pass:
			/includeGlobalMemoryInContextPack/.test(scopedArtifactIndex) &&
			/includeMemoryArtifacts/.test(scopedArtifactIndex),
		evidence: "memory artifacts in context index must be gated",
	},
	{
		id: "auto-deposit-disabled-by-default",
		pass: /repiMemorySettings\(\)\.autoDeposit/.test(toolResult),
		evidence: "post-tool memory deposition must be config-gated",
	},
	{
		id: "profile-memory-defaults-isolated",
		pass:
			settings.memory?.autoInject === false &&
			settings.memory?.autoDeposit === false &&
			settings.memory?.includeGlobalMemoryInContextPack === false &&
			settings.memory?.activeRecall === false &&
			settings.memory?.startupDigest === "status",
		evidence: "repi-profile/settings.json memory defaults must be isolated",
	},
	{
		id: "init-memory-defaults-isolated",
		pass:
			/autoInject:\s*existingMemory\.autoInject\s*\?\?\s*false/.test(init) &&
			/autoDeposit:\s*existingMemory\.autoDeposit\s*\?\?\s*false/.test(init) &&
			/includeGlobalMemoryInContextPack:\s*existingMemory\.includeGlobalMemoryInContextPack\s*\?\?\s*false/.test(init),
		evidence: "init-repi-profile must write isolated memory defaults",
	},
];

for (const check of checks) {
	console.log(`${check.pass ? "PASS" : "FAIL"} ${check.id} :: ${check.evidence}`);
}

const failed = checks.filter((check) => !check.pass);
if (failed.length && strict) {
	console.error(`memory isolation gate failed: ${failed.map((check) => check.id).join(", ")}`);
	process.exit(1);
}
