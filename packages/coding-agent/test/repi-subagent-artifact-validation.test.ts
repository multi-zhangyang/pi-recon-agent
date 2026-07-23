import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { AgentThreadRunManifest } from "../src/core/agent-thread-contract.ts";
import { createAgentThreadManager } from "../src/core/agent-thread-manager.ts";
import { type RepiSubagentResultV1, repiSubagentResultFromManifest } from "../src/core/repi/re-subagent-contract.ts";
import {
	type RepiSubagentArtifactExpectation,
	validateRepiSubagentArtifact,
} from "../src/core/repi/repi-subagent-artifact-validation.ts";

function digest(value: string): string {
	return createHash("sha256").update(value).digest("hex");
}

function createFixture(agentDir: string): {
	expected: RepiSubagentArtifactExpectation;
	details: RepiSubagentResultV1;
	manifest: AgentThreadRunManifest;
} {
	const runId = "2026-07-23T12-00-00-000Z-verifier-deadbeef";
	const task = "verify the unfamiliar bytecode handler";
	const taskSha256 = digest(task);
	const missionId = "mission-artifact-validation";
	const promptSha256 = "a".repeat(64);
	const lineageSha256 = digest(
		JSON.stringify({
			schemaVersion: 1,
			runId,
			parentRunId: null,
			missionId,
			parentLineageSha256: null,
			taskSha256,
			promptSha256,
		}),
	);
	const runRoot = join(agentDir, "recon", "agent-threads", runId);
	const manifestPath = join(runRoot, "manifest.json");
	const handoffPath = join(runRoot, "handoff.md");
	const mergePath = join(runRoot, "merge.md");
	const handoff = [
		`run_id: ${runId}`,
		`mission_id: ${missionId}`,
		`lineage_sha256: ${lineageSha256}`,
		"Outcome: verified",
		"Verification: replayed twice",
		"",
	].join("\n");
	const handoffBytes = Buffer.byteLength(handoff);
	const handoffSha256 = digest(handoff);
	mkdirSync(runRoot, { recursive: true });
	writeFileSync(handoffPath, handoff, "utf8");
	writeFileSync(mergePath, "AgentThreadMergeV1: true\n", "utf8");
	const manifest: AgentThreadRunManifest = {
		kind: "repi-agent-thread-run",
		schemaVersion: 1,
		runId,
		specName: "verifier",
		task,
		status: "complete",
		createdAt: "2026-07-23T12:00:00.000Z",
		endedAt: "2026-07-23T12:00:01.000Z",
		exitCode: 0,
		cwd: agentDir,
		runRoot,
		agentDir: join(runRoot, "agent-home"),
		stdoutPath: join(runRoot, "stdout.txt"),
		stderrPath: join(runRoot, "stderr.txt"),
		manifestPath,
		mergePath,
		handoffPath,
		handoffPresent: true,
		handoffRecovered: false,
		handoffBytes,
		handoffSha256,
		handoffRunId: runId,
		handoffMissionId: missionId,
		handoffLineageSha256: lineageSha256,
		handoffLineageValid: true,
		taskSha256,
		promptSha256,
		missionId,
		lineageSha256,
		tools: ["read"],
	};
	writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
	return {
		expected: { missionId, spec: "verifier", task, taskSha256 },
		details: {
			kind: "RepiSubagentResultV1",
			schemaVersion: 1,
			status: "complete",
			exitCode: 0,
			runId,
			spec: "verifier",
			task,
			taskSha256,
			missionId,
			runRoot,
			mergePath,
			handoffPath,
			handoffPresent: true,
			handoffRecovered: false,
			handoffBytes,
			handoffSha256,
			handoffRunId: runId,
			handoffMissionId: missionId,
			handoffLineageSha256: lineageSha256,
			handoffLineageValid: true,
			lineageSha256,
		},
		manifest,
	};
}

describe("re_subagent artifact validation", () => {
	let agentDir: string | undefined;

	afterEach(() => {
		if (agentDir) rmSync(agentDir, { recursive: true, force: true });
		agentDir = undefined;
		delete process.env.REPI_CODING_AGENT_DIR;
	});

	function fixture() {
		agentDir = join(tmpdir(), `repi-subagent-artifact-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		process.env.REPI_CODING_AGENT_DIR = agentDir;
		return createFixture(agentDir);
	}

	it("accepts a complete manifest and current lineage-bound handoff", async () => {
		const value = fixture();
		const validation = await validateRepiSubagentArtifact(value.details, value.expected);
		expect(validation).toMatchObject({
			ok: true,
			result: { runId: value.details.runId, handoffSha256: value.details.handoffSha256 },
			manifest: { runId: value.manifest.runId, status: "complete" },
		});
	});

	it("accepts artifacts produced and merged by AgentThreadManager", async () => {
		agentDir = join(tmpdir(), `repi-subagent-manager-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		process.env.REPI_CODING_AGENT_DIR = agentDir;
		mkdirSync(agentDir, { recursive: true });
		const worker = join(agentDir, "worker.sh");
		writeFileSync(
			worker,
			[
				"#!/bin/sh",
				'mkdir -p "$(dirname "$REPI_WORKER_HANDOFF_PATH")"',
				`printf 'run_id: %s\\nmission_id: %s\\nlineage_sha256: %s\\nOutcome: verified\\n' "$REPI_WORKER_RUN_ID" "$REPI_WORKER_MISSION_ID" "$REPI_WORKER_LINEAGE_SHA256" > "$REPI_WORKER_HANDOFF_PATH"`,
				"exit 0",
				"",
			].join("\n"),
			"utf8",
		);
		chmodSync(worker, 0o700);
		const task = "verify manager artifact";
		const missionId = "mission-manager-artifact";
		const manager = createAgentThreadManager({ cwd: agentDir, agentDir, repiBinPath: worker });
		try {
			const started = await manager.spawnThread({ specName: "verifier", task, missionId, timeoutMs: 5000 });
			const final = await manager.awaitRun(started.runId);
			const merged = manager.mergeRun(final.runId);
			expect(merged).toBeDefined();
			const validation = await validateRepiSubagentArtifact(
				repiSubagentResultFromManifest(merged?.manifest ?? final),
				{ missionId, spec: "verifier", task, taskSha256: digest(task) },
			);
			expect(validation).toMatchObject({ ok: true, manifest: { runId: final.runId } });
		} finally {
			manager.dispose("test_complete");
		}
	});

	it("rejects shaped details whose run artifact does not exist", async () => {
		const value = fixture();
		const details = {
			...value.details,
			runId: "2026-07-23T12-00-00-000Z-verifier-missing",
			runRoot: "/tmp/run-real",
			mergePath: "/tmp/run-real/merge.md",
			handoffPath: "/tmp/run-real/handoff.md",
		};
		const validation = await validateRepiSubagentArtifact(details, value.expected);
		expect(validation).toEqual({ ok: false, error: "persisted AgentThread manifest is missing or invalid" });
	});

	it("rejects details that redirect fixed artifact paths", async () => {
		const value = fixture();
		const validation = await validateRepiSubagentArtifact(
			{
				...value.details,
				runRoot: "/tmp/redirected-run",
				mergePath: "/tmp/redirected-run/merge.md",
				handoffPath: "/tmp/redirected-run/handoff.md",
			},
			value.expected,
		);
		expect(validation).toEqual({ ok: false, error: "details run root is not the fixed AgentThread root" });
	});

	it("rejects a raw manifest that redirects its handoff path", async () => {
		const value = fixture();
		writeFileSync(
			value.manifest.manifestPath,
			`${JSON.stringify({ ...value.manifest, handoffPath: "/tmp/redirected-handoff.md" }, null, 2)}\n`,
			"utf8",
		);
		const validation = await validateRepiSubagentArtifact(value.details, value.expected);
		expect(validation).toEqual({
			ok: false,
			error: "raw manifest handoffPath is redirected from the fixed run path",
		});
	});

	it("rejects a run directory redirected through a symbolic link", async () => {
		const value = fixture();
		const redirectedRunRoot = `${value.manifest.runRoot}-redirected`;
		renameSync(value.manifest.runRoot, redirectedRunRoot);
		symlinkSync(redirectedRunRoot, value.manifest.runRoot, "dir");
		const validation = await validateRepiSubagentArtifact(value.details, value.expected);
		expect(validation).toEqual({ ok: false, error: "run directory must not be a symbolic link" });
	});

	it("rejects a handoff changed after manifest finalization", async () => {
		const value = fixture();
		writeFileSync(value.manifest.handoffPath ?? "", "tampered after finalization\n", "utf8");
		const validation = await validateRepiSubagentArtifact(value.details, value.expected);
		expect(validation).toMatchObject({ ok: false, error: "handoff bytes or SHA-256 does not match manifest" });
	});
});
