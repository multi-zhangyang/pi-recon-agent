import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const MODEL_INSPECT = fileURLToPath(new URL("../../../scripts/reverse-agent/model-inspect.mjs", import.meta.url));

describe("repi model bounded stdin reads", () => {
	let tempRoot: string;
	let agentDir: string;
	let workspace: string;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-model-stdin-"));
		agentDir = join(tempRoot, "agent");
		workspace = join(tempRoot, "workspace");
		mkdirSync(agentDir, { recursive: true });
		mkdirSync(workspace, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempRoot, { recursive: true, force: true });
	});

	it("does not hang forever when --api-key-stdin remains open without EOF", async () => {
		const child = spawn(
			process.execPath,
			[
				MODEL_INSPECT,
				workspace,
				"login",
				"--provider",
				"alpha",
				"--api-key-stdin",
				"--stdin-timeout-ms",
				"150",
				"--json",
			],
			{
				env: { ...process.env, REPI_CODING_AGENT_DIR: agentDir },
				stdio: ["pipe", "pipe", "pipe"],
			},
		);

		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => {
			stdout += String(chunk);
		});
		child.stderr.on("data", (chunk) => {
			stderr += String(chunk);
		});

		const exit = await new Promise<number | null>((resolve, reject) => {
			const timer = setTimeout(() => {
				child.kill("SIGKILL");
				reject(new Error("model-inspect login hung with open stdin"));
			}, 5000);
			child.on("close", (code) => {
				clearTimeout(timer);
				resolve(code);
			});
		});

		expect(exit, stderr).toBe(1);
		const report = JSON.parse(stdout) as { ok: boolean; error: string };
		expect(report.ok).toBe(false);
		expect(report.error).toMatch(/stdin read timed out/);
		expect(existsSync(join(agentDir, "auth.json"))).toBe(false);
	});

	it("still accepts closed stdin for model login and writes private auth", () => {
		const apiKey = "opaque-provider-secret-value";
		const result = spawnSync(
			process.execPath,
			[MODEL_INSPECT, workspace, "login", "--provider", "alpha", "--api-key-stdin", "--json"],
			{
				encoding: "utf8",
				env: { ...process.env, REPI_CODING_AGENT_DIR: agentDir },
				input: `${apiKey}\n`,
				timeout: 10_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		expect(result.stdout).not.toContain(apiKey);
		expect(JSON.parse(result.stdout)).toMatchObject({ ok: true, provider: "alpha" });
		expect(JSON.parse(result.stdout)).not.toHaveProperty("keyPreview");
		expect(JSON.parse(readFileSync(join(agentDir, "auth.json"), "utf8"))).toMatchObject({
			alpha: { type: "api_key", key: apiKey },
		});

		const humanResult = spawnSync(
			process.execPath,
			[MODEL_INSPECT, workspace, "login", "--provider", "beta", "--api-key-stdin"],
			{
				encoding: "utf8",
				env: { ...process.env, REPI_CODING_AGENT_DIR: agentDir },
				input: `${apiKey}\n`,
				timeout: 10_000,
			},
		);
		expect(humanResult.status, `${humanResult.stderr}\n${humanResult.stdout}`).toBe(0);
		expect(humanResult.stdout).not.toContain(apiKey);
		expect(humanResult.stdout).not.toContain("key=");
	});

	it("caps model import stdin size before parsing", () => {
		const result = spawnSync(
			process.execPath,
			[MODEL_INSPECT, workspace, "import", "--input", "-", "--stdin-max-bytes", "20", "--json"],
			{
				encoding: "utf8",
				env: { ...process.env, REPI_CODING_AGENT_DIR: agentDir },
				input: JSON.stringify({ providers: { alpha: { models: [] } } }),
				timeout: 10_000,
			},
		);

		expect(result.status).toBe(1);
		const report = JSON.parse(result.stdout) as { ok: boolean; error: string };
		expect(report.ok).toBe(false);
		expect(report.error).toMatch(/stdin exceeds max bytes/);
	});
});
