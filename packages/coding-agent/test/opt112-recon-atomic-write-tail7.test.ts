import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory, routeReconTask, writeCurrentMission } from "../src/core/recon-profile.ts";
import { createMission } from "../src/core/repi/mission.ts";
import {
	evidenceBrowserDir,
	evidenceDelegationsDir,
	evidenceExploitLabDir,
	evidenceMapsDir,
	evidenceMobileRuntimeDir,
	evidenceNativeRuntimeDir,
	evidenceOperationsDir,
	evidenceRunsDir,
	evidenceWebAuthzDir,
} from "../src/core/repi/storage.ts";

// opt #112: seventh tail pass of the repi atomic-write audit. Converts the
// final 9 bare-writeFileSync(..., "utf-8") REPI NEW-timestamped-file artifact
// writers in recon-profile.ts to writePrivateTextFile (atomic temp+rename,
// 0o600). A bare writeFileSync yields mode 0o644 under default umask; the
// atomic helper yields 0o600. Each writer produces evidence/<domain>/<ts>.md.
//   writeLaneRunArtifact        → evidence/runs/       (re_lane run, seeded Pwn mission)
//   writePassiveMapArtifact     → evidence/maps/        (re_map)
//   writeLiveBrowserArtifact    → evidence/browser/     (re_live_browser plan)
//   writeWebAuthzStateArtifact  → evidence/web-authz/   (re_web_authz_state plan)
//   writeExploitLabArtifact     → evidence/exploit-lab/ (re_exploit_lab plan)
//   writeMobileRuntimeArtifact  → evidence/mobile/      (re_mobile_runtime plan)
//   writeNativeRuntimeArtifact  → evidence/native/      (re_native_runtime plan)
//   writeOperationArtifact      → evidence/operations/  (re_operation plan)
//   writeDelegateArtifact       → evidence/delegates/   (re_delegate plan)
// Drives each re_* tool (×2 where practical; re_lane run ×2 against a seeded
// mission) and probes mode 0o600 on the latest artifact + no .tmp leftover.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

const testTimeout = 30_000;

type RegisteredTool = {
	name: string;
	execute: (toolCallId: string, params: Record<string, unknown>) => Promise<unknown>;
};

function latestMarkdown(dir: string): string | undefined {
	const files = readdirSync(dir)
		.filter((f) => f.endsWith(".md"))
		.sort();
	return files.length ? files[files.length - 1] : undefined;
}

function noTmpLeftover(dir: string): void {
	expect(
		readdirSync(dir).filter((f) => f.endsWith(".tmp")),
		`no .tmp leftover in ${dir}`,
	).toEqual([]);
}

function seedPwnMission(): void {
	// re_lane run needs an active lane whose command pack yields runnable
	// (non-placeholder, non-re_*) commands. A "Pwn / exploit" mission's first
	// lane "mitigations" with target "." produces `find . -maxdepth 4 ...`
	// commands that the runnable filter accepts; fakePi.exec returns code 0.
	const mission = createMission("opt112 lane run", routeReconTask("pwn exploit ro p"));
	writeCurrentMission(mission);
}

describe("recon-profile atomic writes tail7 (opt #112)", () => {
	let tempDir: string;
	let prevAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "repi-opt112-recon-"));
		const agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		prevAgentDir = process.env[ENV_AGENT_DIR];
		process.env[ENV_AGENT_DIR] = agentDir;
	});

	afterEach(() => {
		if (prevAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = prevAgentDir;
		if (tempDir) rmSync(tempDir, { recursive: true, force: true });
	});

	function registerTools(): Map<string, RegisteredTool> {
		const tools = new Map<string, RegisteredTool>();
		const fakePi = {
			registerCommand() {},
			registerTool(tool: RegisteredTool) {
				tools.set(tool.name, tool);
			},
			on() {},
			appendEntry() {},
			getSessionName: () => undefined,
			setSessionName() {},
			sendMessage() {},
			exec: async () => ({ code: 0, stdout: "", stderr: "", killed: false }),
		} as unknown as ExtensionAPI;
		createReconExtensionFactory()(fakePi);
		return tools;
	}

	async function probePlanArtifact(
		toolName: string,
		dir: string,
		label: string,
		params: Record<string, unknown> = {},
	): Promise<void> {
		const tools = registerTools();
		const tool = tools.get(toolName);
		expect(tool, `${toolName} tool registered`).toBeDefined();

		await (tool as RegisteredTool).execute("a-1", { action: "plan", ...params });

		const artifactAfter1 = latestMarkdown(dir);
		expect(artifactAfter1, `${label} artifact written (1st)`).toBeDefined();
		expect(statSync(join(dir, artifactAfter1!)).mode & 0o777, `${label} artifact mode 0o600 (1st)`).toBe(0o600);

		await new Promise((resolve) => setTimeout(resolve, 5));

		await (tool as RegisteredTool).execute("a-2", { action: "plan", ...params });

		const artifactAfter2 = latestMarkdown(dir);
		expect(artifactAfter2, `${label} artifact written (2nd)`).toBeDefined();
		expect(statSync(join(dir, artifactAfter2!)).mode & 0o777, `${label} artifact mode 0o600 (2nd)`).toBe(0o600);

		noTmpLeftover(dir);
	}

	it(
		"re_lane run ×2 writes the lane-run artifact (0o600, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_lane");
			expect(tool, "re_lane tool registered").toBeDefined();

			const runsDir = evidenceRunsDir();

			seedPwnMission();

			await (tool as RegisteredTool).execute("lr-1", { action: "run", lane: "mitigations", target: "." });

			const artifactAfter1 = latestMarkdown(runsDir);
			expect(artifactAfter1, "lane-run artifact written (1st)").toBeDefined();
			expect(statSync(join(runsDir, artifactAfter1!)).mode & 0o777, "lane-run artifact mode 0o600 (1st)").toBe(
				0o600,
			);

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("lr-2", { action: "run", lane: "mitigations", target: "." });

			const artifactAfter2 = latestMarkdown(runsDir);
			expect(artifactAfter2, "lane-run artifact written (2nd)").toBeDefined();
			expect(statSync(join(runsDir, artifactAfter2!)).mode & 0o777, "lane-run artifact mode 0o600 (2nd)").toBe(
				0o600,
			);

			noTmpLeftover(runsDir);
		},
		testTimeout,
	);

	it(
		"re_map ×2 writes the passive-map artifact (0o600, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_map");
			expect(tool, "re_map tool registered").toBeDefined();

			const mapsDir = evidenceMapsDir();

			await (tool as RegisteredTool).execute("map-1", { target: "." });

			const artifactAfter1 = latestMarkdown(mapsDir);
			expect(artifactAfter1, "passive-map artifact written (1st)").toBeDefined();
			expect(statSync(join(mapsDir, artifactAfter1!)).mode & 0o777, "passive-map artifact mode 0o600 (1st)").toBe(
				0o600,
			);

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("map-2", { target: "." });

			const artifactAfter2 = latestMarkdown(mapsDir);
			expect(artifactAfter2, "passive-map artifact written (2nd)").toBeDefined();
			expect(statSync(join(mapsDir, artifactAfter2!)).mode & 0o777, "passive-map artifact mode 0o600 (2nd)").toBe(
				0o600,
			);

			noTmpLeftover(mapsDir);
		},
		testTimeout,
	);

	it(
		"re_live_browser plan ×2 writes the live-browser artifact (0o600, no .tmp)",
		async () => probePlanArtifact("re_live_browser", evidenceBrowserDir(), "live-browser"),
		testTimeout,
	);

	it(
		"re_web_authz_state plan ×2 writes the web-authz artifact (0o600, no .tmp)",
		async () => probePlanArtifact("re_web_authz_state", evidenceWebAuthzDir(), "web-authz"),
		testTimeout,
	);

	it(
		"re_exploit_lab plan ×2 writes the exploit-lab artifact (0o600, no .tmp)",
		async () => probePlanArtifact("re_exploit_lab", evidenceExploitLabDir(), "exploit-lab"),
		testTimeout,
	);

	it(
		"re_mobile_runtime plan ×2 writes the mobile-runtime artifact (0o600, no .tmp)",
		async () => probePlanArtifact("re_mobile_runtime", evidenceMobileRuntimeDir(), "mobile-runtime"),
		testTimeout,
	);

	it(
		"re_native_runtime plan ×2 writes the native-runtime artifact (0o600, no .tmp)",
		async () => probePlanArtifact("re_native_runtime", evidenceNativeRuntimeDir(), "native-runtime"),
		testTimeout,
	);

	it(
		"re_operation plan ×2 writes the operation artifact (0o600, no .tmp)",
		async () => probePlanArtifact("re_operation", evidenceOperationsDir(), "operation"),
		testTimeout,
	);

	it(
		"re_delegate plan ×2 writes the delegate artifact (0o600, no .tmp)",
		async () => probePlanArtifact("re_delegate", evidenceDelegationsDir(), "delegate"),
		testTimeout,
	);
});
