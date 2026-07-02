import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const MISSION = fileURLToPath(new URL("../../../scripts/reverse-agent/repi-mission.mjs", import.meta.url));

function collectTmp(root: string): string[] {
	if (!existsSync(root)) return [];
	const out: string[] = [];
	for (const entry of readdirSync(root, { withFileTypes: true })) {
		const path = join(root, entry.name);
		if (entry.name.endsWith(".tmp")) out.push(path);
		if (entry.isDirectory()) out.push(...collectTmp(path));
	}
	return out;
}

type MissionReport = {
	ok?: boolean;
	mission?: {
		status?: string;
		task: string;
		target: string;
		summary?: string;
		route?: { id: string; domain: string };
		lanes?: Array<{ id: string }>;
		starterCommands?: string[];
	};
	task?: string;
	target?: string;
	plan?: { route: { id: string; domain: string }; starterCommands?: string[] };
	output?: { jsonPath: string; markdownPath: string };
};

describe("repi-mission argument parsing", () => {
	let tempRoot: string;
	let agentDir: string;
	let workspace: string;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mission-args-"));
		agentDir = join(tempRoot, "agent");
		workspace = join(tempRoot, "workspace");
		mkdirSync(workspace, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempRoot, { recursive: true, force: true });
	});

	function runMission(args: string[], options: { cwd?: string } = {}) {
		const result = spawnSync(process.execPath, args, {
			cwd: options.cwd ?? workspace,
			encoding: "utf8",
			env: {
				...process.env,
				REPI_CODING_AGENT_DIR: agentDir,
				REPI_OPERATOR_CWD: workspace,
			},
			timeout: 10_000,
		});
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		return JSON.parse(result.stdout) as MissionReport;
	}

	it("accepts command-first invocation and --flag=value mission routing", () => {
		const report = runMission([MISSION, "new", "analyze ELF", "--target=./vuln", "--domain=native-pwn", "--json"]);

		expect(report.mission).toMatchObject({
			task: "analyze ELF",
			target: "./vuln",
			route: { id: "native-pwn" },
		});
		expect(report.mission?.lanes?.map((lane) => lane.id)).toEqual(["mitigations", "primitive", "exploit", "verify"]);
		expect(report.mission?.starterCommands?.some((command) => command.includes("checksec"))).toBe(true);
	});

	it("does not let value or boolean flag placement pollute plan task text", () => {
		const report = runMission([
			MISSION,
			workspace,
			"plan",
			"--target=./api",
			"--domain=web-api",
			"--json",
			"enumerate endpoint authz",
		]);

		expect(report).toMatchObject({
			task: "enumerate endpoint authz",
			target: "./api",
			plan: { route: { id: "web-api" } },
		});
		expect(report.task).not.toContain("./api");
		expect(report.task).not.toContain("web-api");
		expect(report.plan?.starterCommands?.[0]).toContain("curl");
	});

	it("routes newer specialist reverse/pentest domains with concrete starter probes", () => {
		const mem = runMission([MISSION, workspace, "plan", "memory dump volatility credential timeline", "--json"]);
		expect(mem.plan).toMatchObject({ route: { id: "memory-forensics" } });
		expect(mem.plan?.starterCommands?.some((command) => command.includes("vol -f"))).toBe(true);

		const scan = runMission([
			MISSION,
			workspace,
			"plan",
			"nuclei web scan route corpus",
			"--target=https://target.test",
			"--json",
		]);
		expect(scan.plan).toMatchObject({ route: { id: "web-scan" } });
		expect(scan.plan?.starterCommands?.some((command) => command.includes("httpx"))).toBe(true);
	});

	it("redacts secret-like targets from generated operator commands", () => {
		const jwt = "eyJaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc";
		const report = runMission([MISSION, workspace, "plan", "audit api", `--target=${jwt}`, "--json"]);
		const serialized = JSON.stringify(report);

		expect(serialized).not.toContain(jwt);
		expect(serialized).toContain("<redacted:jwt>");
	});

	it("accepts --summary=value when closing a mission", () => {
		runMission([MISSION, workspace, "new", "pwn ELF ret2win", "--json"]);

		const report = runMission([MISSION, workspace, "close", "--summary=verified ret2win offset", "--json"]);

		expect(report.ok).toBe(true);
		expect(report.mission).toMatchObject({
			status: "closed",
			summary: "verified ret2win offset",
		});
		expect(statSync(join(agentDir, "recon", "mission", "current.json")).mode & 0o777).toBe(0o600);
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("accepts --output=value for context packs", () => {
		runMission([MISSION, workspace, "new", "analyze APK signing", "--json"]);
		const outPath = join(tempRoot, "packs", "mission-pack.json");

		const report = runMission([MISSION, workspace, "pack", `--output=${outPath}`, "--json"]);

		expect(report.output?.jsonPath).toBe(outPath);
		expect(report.output?.markdownPath).toBe(join(tempRoot, "packs", "mission-pack.md"));
		expect(existsSync(outPath)).toBe(true);
		expect(JSON.parse(readFileSync(outPath, "utf8"))).toMatchObject({
			kind: "repi-mission-context-pack",
			mission: { task: "analyze APK signing" },
		});
	});
});
