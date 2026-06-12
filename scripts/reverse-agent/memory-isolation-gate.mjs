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
const settingsMemory = settings.memory ?? {};

const checks = [
	{
		id: "startup-raw-memory-not-default",
		pass: !/Memory digest:[\s\S]*buildMemoryDigest\(\)/.test(beforeAgentStart),
		evidence: "before_agent_start uses scoped recall packet, not raw buildMemoryDigest",
	},
	{
		id: "startup-context-pack-not-default",
		pass: !/Context\/resume pack:[\s\S]*buildContextDigest\(\)/.test(beforeAgentStart),
		evidence: "before_agent_start does not inject old context packs by default",
	},
	{
		id: "startup-evidence-ledger-not-default",
		pass: !/Evidence ledger tail:[\s\S]*buildEvidenceDigest\(\)/.test(beforeAgentStart),
		evidence: "before_agent_start does not inject old evidence ledger by default",
	},
	{
		id: "scoped-recall-packet-present",
		pass:
			/formatScopedMemoryRecallPacket/.test(source) &&
			/memory_recall_packet/.test(source) &&
			/scoped_summary_cards/.test(source),
		evidence: "runtime has bounded scoped memory cards",
	},
	{
		id: "context-memory-tail-scoped-helper",
		pass: /memoryTail:\s*buildContextMemoryTail/.test(contextPack),
		evidence: "context pack memoryTail routes through scoped/global policy helper",
	},
	{
		id: "context-artifact-index-raw-memory-gated",
		pass:
			/includeGlobalMemoryInContextPack/.test(scopedArtifactIndex) &&
			/includeMemoryArtifacts/.test(scopedArtifactIndex),
		evidence: "raw memory artifacts in context index require explicit global mode",
	},
	{
		id: "high-value-auto-deposit-gated",
		pass:
			/autoDepositMode/.test(toolResult) &&
			/shouldAutoDepositToolResult/.test(toolResult) &&
			/high-value scoped auto writeback/.test(toolResult),
		evidence: "post-tool memory deposition is high-value gated, not all stdout",
	},
	{
		id: "profile-memory-defaults-scoped",
		pass:
			settingsMemory.schemaVersion === 2 &&
			settingsMemory.mode === "scoped" &&
			settingsMemory.autoRecall === true &&
			settingsMemory.autoDeposit === "high-value" &&
			settingsMemory.startupDigest === "scoped" &&
			settingsMemory.contextMemoryMode === "scoped" &&
			settingsMemory.includeGlobalMemoryInContextPack === false &&
			settingsMemory.rawAutoInject === false,
		evidence: "repi-profile/settings.json defaults to scoped auto memory, raw injection off",
	},
	{
		id: "init-memory-v2-migrates-old-isolation",
		pass:
			/schemaVersion:\s*2/.test(init) &&
			/legacyAutoDeposit/.test(init) &&
			/autoRecall:\s*existingMemory\.autoRecall\s*\?\?\s*true/.test(init) &&
			/autoDeposit:\s*legacyAutoDeposit\s*\?\?\s*"high-value"/.test(init),
		evidence: "init-repi-profile migrates previous closed memory defaults to scoped auto memory",
	},
];

for (const check of checks) {
	console.log(`${check.pass ? "PASS" : "FAIL"} ${check.id} :: ${check.evidence}`);
}

const failed = checks.filter((check) => !check.pass);
if (failed.length && strict) {
	console.error(`memory scoped gate failed: ${failed.map((check) => check.id).join(", ")}`);
	process.exit(1);
}
