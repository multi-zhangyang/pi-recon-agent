import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const MODEL_INSPECT = fileURLToPath(new URL("../../../scripts/reverse-agent/model-inspect.mjs", import.meta.url));

describe("repi model argument parsing", () => {
	let tempRoot: string;
	let agentDir: string;
	let workspace: string;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-model-args-"));
		agentDir = join(tempRoot, "agent");
		workspace = join(tempRoot, "workspace");
		mkdirSync(agentDir, { recursive: true });
		mkdirSync(workspace, { recursive: true });
		writeFileSync(
			join(agentDir, "models.json"),
			`${JSON.stringify(
				{
					providers: {
						alpha: {
							api: "openai-completions",
							baseUrl: "https://example.invalid/v1",
							apiKey: "$ALPHA_KEY",
							models: [{ id: "model-a", contextWindow: 8192, maxTokens: 1024, cost: {} }],
						},
					},
				},
				null,
				2,
			)}\n`,
		);
	});

	afterEach(() => {
		rmSync(tempRoot, { recursive: true, force: true });
	});

	function run(args: string[]) {
		const result = spawnSync(process.execPath, [MODEL_INSPECT, workspace, ...args, "--json"], {
			encoding: "utf8",
			env: { ...process.env, REPI_CODING_AGENT_DIR: agentDir },
			timeout: 10_000,
		});
		return { result, json: JSON.parse(result.stdout) as Record<string, unknown> };
	}

	it("accepts provider/model as positionals for the default command", () => {
		const { result, json } = run(["default", "alpha", "model-a"]);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		expect(json).toMatchObject({ ok: true, provider: "alpha", model: "model-a" });
		expect(JSON.parse(readFileSync(join(agentDir, "settings.json"), "utf8"))).toMatchObject({
			defaultProvider: "alpha",
			defaultModel: "model-a",
		});
	});

	it("accepts a positional model after a --provider flag", () => {
		const { result, json } = run(["default", "--provider", "alpha", "model-a"]);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		expect(json).toMatchObject({ ok: true, provider: "alpha", model: "model-a" });
	});

	it("does not mistake flag values for missing positionals", () => {
		const { result, json } = run(["default", "--model", "model-a"]);
		expect(result.status).toBe(1);
		expect(json).toMatchObject({
			ok: false,
			error: "model default requires --provider <id> --model <id>",
		});
	});
});
