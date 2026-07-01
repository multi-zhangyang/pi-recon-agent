import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const HEALTH = fileURLToPath(new URL("../../../scripts/reverse-agent/repi-health.mjs", import.meta.url));

describe("repi health selfcheck forwarding", () => {
	let tempRoot: string;
	let fakeRoot: string;
	let agentDir: string;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-health-forward-"));
		fakeRoot = join(tempRoot, "repo");
		agentDir = join(tempRoot, "agent");
		const scriptDir = join(fakeRoot, "scripts", "reverse-agent");
		mkdirSync(scriptDir, { recursive: true });
		mkdirSync(agentDir, { recursive: true });

		const stubs: Record<string, string> = {
			"repi-doctor.mjs": `#!/usr/bin/env node\nconsole.log(JSON.stringify({ ok: true, checks: [] }));\n`,
			"model-inspect.mjs": `#!/usr/bin/env node\nconsole.log(JSON.stringify({ ok: true, diagnostics: [], providers: [], modelCount: 0 }));\n`,
			"memory-inspect.mjs": `#!/usr/bin/env node\nconst cmd = process.argv[3];\nif (cmd === "sanitize") console.log(JSON.stringify({ ok: true, changedFiles: 0, scannedFiles: 0 }));\nelse if (cmd === "doctor") console.log(JSON.stringify({ ok: true, diagnostics: [], status: { eventStore: { invalidLines: 0 } } }));\nelse console.log(JSON.stringify({ ok: true }));\n`,
			"repi-mission.mjs": `#!/usr/bin/env node\nconsole.log(JSON.stringify({ ok: true, mission: null, missionPath: "/tmp/none" }));\n`,
			"repi-swarm-llm-run.mjs": `#!/usr/bin/env node\nconsole.log(JSON.stringify({ ok: false, state: "none" }));\nprocess.exit(1);\n`,
			"repi-selfcheck.mjs": `#!/usr/bin/env node\nconst args = process.argv.slice(3);\nconst has = (...xs) => xs.every((x) => args.includes(x));\nconst ok = has("--deep", "--provider", "alpha", "--model", "model-a", "--timeout-ms", "7777", "--json");\nconsole.log(JSON.stringify({ ok, rows: ok ? [] : [{ id: "missing-forwarded-selfcheck-args", ok: false }], args }));\nprocess.exit(ok ? 0 : 1);\n`,
		};
		for (const [name, source] of Object.entries(stubs)) {
			const path = join(scriptDir, name);
			writeFileSync(path, source);
			chmodSync(path, 0o755);
		}
	});

	afterEach(() => {
		rmSync(tempRoot, { recursive: true, force: true });
	});

	it("passes provider/model/timeout flags through to repi-selfcheck", () => {
		const result = spawnSync(
			process.execPath,
			[HEALTH, fakeRoot, "--deep", "--provider", "alpha", "--model", "model-a", "--timeout-ms", "7777", "--json"],
			{
				encoding: "utf8",
				env: { ...process.env, REPI_CODING_AGENT_DIR: agentDir },
				timeout: 10_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			status: string;
			items: Array<{ id: string; status: string; evidence: Record<string, unknown> }>;
		};
		expect(report.status).toBe("pass");
		expect(report.items.find((item) => item.id === "live-selfcheck")).toMatchObject({
			status: "pass",
			evidence: { provider: "alpha", model: "model-a", timeoutMs: "7777", deep: true },
		});
	});
});
