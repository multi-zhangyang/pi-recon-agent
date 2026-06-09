#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const RUNTIME_MIRRORS = ["packages/coding-agent/src/core/recon-profile.ts", ".pi/extensions/reverse-pentest-core.ts"];

export const CONTEXT_COMPACT_REQUIREMENTS = [
	{
		id: "context_pack",
		description: "re_context pack/resume captures mission, V2 artifact hashes, evidence tail, memory tail, repair queues, and next commands.",
		checks: RUNTIME_MIRRORS.map((file) => ({
			file,
			markers: [
				"type ContextPackArtifact",
				"schemaVersion?: 2",
				"contextSha256",
				"function contextArtifactIndex",
				"function contextPackSha256",
				"function contextArtifactHashes",
				"function buildContextPack",
				"evidenceTail: truncateMiddle(buildEvidenceDigest()",
				"artifactIndex",
				"artifactHashes",
				"resumeBrief",
				"next_operator_commands:",
				"source_artifacts:",
				"compaction-resume-ledger.jsonl",
				"context_pack_ready",
			],
		})),
	},
	{
		id: "owned_compaction_provider",
		description: "session_before_compact is owned by Pi-RECON and returns a structured pi-recon-compaction summary/details block.",
		checks: RUNTIME_MIRRORS.map((file) => ({
			file,
			markers: [
				"session_before_compact",
				"buildReconCompactionSummary",
				"buildReconCompactionDetails",
				"pi-recon-compaction-checkpoint",
				"kind: \"pi-recon-compaction\"",
				"# Pi-RECON Compaction Summary",
				"## Evidence / artifacts",
				"autonomous_execution_budget:",
				"resumeCommand: \"re_context resume\"",
			],
		})),
	},
	{
		id: "resume_contract_continuation",
		description: "session_compact verifies the resume contract; re_context resume exact-loads a contextPath/compactionEntryId and records auto-resume telemetry.",
		checks: RUNTIME_MIRRORS.map((file) => ({
			file,
			markers: [
				"session_compact",
				"buildReconCompactionResumeContract",
				"contextPath",
				"compactionEntryId",
				"pi-recon-compaction-resume-contract",
				"compaction_resume_contract_ready",
				"pi-recon-compaction-auto-resume",
				"pi-recon-auto-resume",
				"pi-recon-compaction-resume-telemetry",
				"compact_resume_command",
				"function verifyContextPackResume",
				"function buildExactResumeContextPack",
				"function contextRefLooksExplicit",
				"exactResumeVerification",
				"artifact hash drift",
				"proofLoopEntered",
				"compactAutoResumeBudget",
			],
		})),
	},
	{
		id: "evidence_summarization",
		description: "Evidence summarization survives compaction through evidence digest, artifact index, compiler key evidence, and proof-loop evidence summary.",
		checks: RUNTIME_MIRRORS.map((file) => ({
			file,
			markers: [
				"function buildEvidenceDigest",
				"evidenceTail",
				"contextPack.artifactIndex",
				"key_evidence_block:",
				"evidenceSummary",
				"source=compact_resume",
				"Outcome → Key Evidence → Verification → Next Step",
			],
		})),
	},
	{
		id: "budget_continuation",
		description: "Autonomous dispatcher budgets and ledgers are kept in context packs and resume/proof queues.",
		checks: RUNTIME_MIRRORS.map((file) => ({
			file,
			markers: [
				"type AutonomousExecutionBudget",
				"autonomousExecutionBudget",
				"autonomous_execution_budget:",
				"autonomous-budget-ledger.md",
				"maxDispatch",
				"maxProofLoops",
				"compactAutoResumeBudget",
				"failure_budget_exhausted",
			],
		})),
	},
	{
		id: "runtime_tests",
		description: "Coding-agent tests exercise owned compaction, resume contract, telemetry, and auto-resume behavior.",
		checks: [
			{
				file: "packages/coding-agent/test/recon-profile.test.ts",
				markers: [
					"returns a Pi-RECON owned compaction result with a resume contract",
					"pi-recon-compaction-resume-contract",
					"pi-recon-compaction-resume-telemetry",
					"compact_resume_telemetry:",
					"autonomous_execution_budget",
					"source=compact_resume",
				],
			},
			{
				file: "packages/coding-agent/test/suite/agent-session-compaction.test.ts",
				markers: [
					"manually compacts through Pi-RECON",
					"pi-recon-compaction-auto-resume",
					"pi-recon-compaction-resume-telemetry",
					"auto resumed from compaction contract",
				],
			},
		],
	},
	{
		id: "docs_contract",
		description: "Public docs describe the context/compact/evidence/budget contract and this audit harness.",
		checks: [
			{
				file: "docs/reverse-agent/README.md",
				markers: [
					"Context/resume pack 闭环",
					"Pi-RECON owned compaction kernel update",
					"autonomous budget ledger update",
					"context-compact-audit.mjs",
					"context_compact_audit",
					"evidence_summarization",
					"budget_continuation",
				],
			},
		],
	},
];

function readProjectFile(root, relativePath) {
	const path = join(root, relativePath);
	if (!existsSync(path)) return { path, exists: false, text: "" };
	return { path, exists: true, text: readFileSync(path, "utf-8") };
}

export function auditContextCompact(root = process.cwd()) {
	const resolvedRoot = resolve(root);
	const categories = CONTEXT_COMPACT_REQUIREMENTS.map((category) => {
		const checks = category.checks.map((check) => {
			const file = readProjectFile(resolvedRoot, check.file);
			const missing = file.exists ? check.markers.filter((marker) => !file.text.includes(marker)) : [...check.markers];
			return {
				file: check.file,
				exists: file.exists,
				markers: check.markers.length,
				missing,
				status: file.exists && missing.length === 0 ? "pass" : "fail",
			};
		});
		const status = checks.every((check) => check.status === "pass") ? "pass" : "fail";
		return { id: category.id, description: category.description, status, checks };
	});
	const ok = categories.every((category) => category.status === "pass");
	const markerCount = categories.reduce(
		(total, category) => total + category.checks.reduce((sum, check) => sum + check.markers, 0),
		0,
	);
	return {
		ok,
		root: resolvedRoot,
		checkedAt: new Date().toISOString(),
		summary: {
			categories: categories.length,
			passed: categories.filter((category) => category.status === "pass").length,
			failed: categories.filter((category) => category.status === "fail").length,
			markers: markerCount,
		},
		categories,
	};
}

export function formatContextCompactAuditReport(audit) {
	const lines = [
		"Pi-RECON context_compact_audit",
		`status: ${audit.ok ? "pass" : "fail"}`,
		`root: ${audit.root}`,
		`summary: categories=${audit.summary.categories} passed=${audit.summary.passed} failed=${audit.summary.failed} markers=${audit.summary.markers}`,
		"",
	];
	for (const category of audit.categories) {
		lines.push(`- ${category.id}: ${category.status} — ${category.description}`);
		for (const check of category.checks) {
			if (check.status === "pass") {
				lines.push(`  - ${check.file}: pass (${check.markers} markers)`);
			} else if (!check.exists) {
				lines.push(`  - ${check.file}: fail (missing file)`);
			} else {
				lines.push(`  - ${check.file}: fail (missing ${check.missing.length}/${check.markers})`);
				for (const marker of check.missing.slice(0, 12)) lines.push(`    - ${marker}`);
				if (check.missing.length > 12) lines.push(`    - ... ${check.missing.length - 12} more`);
			}
		}
	}
	return `${lines.join("\n")}\n`;
}

function printHelp() {
	console.log(`Usage: node scripts/reverse-agent/context-compact-audit.mjs [root] [--json]\n\nChecks Pi-RECON context pack, owned compaction, resume contract, evidence summarization, budget continuation, test coverage, and docs markers.`);
}

function main(argv) {
	if (argv.includes("--help") || argv.includes("-h")) {
		printHelp();
		return;
	}
	const json = argv.includes("--json");
	const rootArg = argv.find((arg) => !arg.startsWith("-"));
	const audit = auditContextCompact(rootArg ?? process.cwd());
	if (json) {
		console.log(JSON.stringify(audit, null, 2));
	} else {
		process.stdout.write(formatContextCompactAuditReport(audit));
	}
	if (!audit.ok) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	main(process.argv.slice(2));
}
