import { spawnSync } from "node:child_process";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const MEMORY_INSPECT = fileURLToPath(new URL("../../../scripts/reverse-agent/memory-inspect.mjs", import.meta.url));

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

describe("repi memory maintenance atomic writes", () => {
	let tempRoot: string;
	let agentDir: string;
	let workspace: string;
	let memoryDir: string;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-memory-maint-"));
		agentDir = join(tempRoot, "agent");
		workspace = join(tempRoot, "workspace");
		memoryDir = join(agentDir, "recon", "memory");
		mkdirSync(memoryDir, { recursive: true });
		mkdirSync(workspace, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempRoot, { recursive: true, force: true });
	});

	function runMemory(args: string[]) {
		const result = spawnSync(process.execPath, [MEMORY_INSPECT, workspace, ...args, "--json"], {
			encoding: "utf8",
			env: { ...process.env, REPI_CODING_AGENT_DIR: agentDir },
			timeout: 10_000,
		});
		return { result, report: JSON.parse(result.stdout) as Record<string, unknown> };
	}

	it("sanitizes changed memory files via private temp+rename output", () => {
		const path = join(memoryDir, "core-memory.md");
		writeFileSync(path, "token=sk-testSECRET1234567890\n", { mode: 0o600 });

		const { result, report } = runMemory(["sanitize", "--apply", "--yes"]);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		expect(report).toMatchObject({ ok: true, apply: true, changedFiles: 1 });
		const sanitized = readFileSync(path, "utf8");
		expect(sanitized).toContain("<redacted>");
		expect(sanitized).not.toContain("sk-testSECRET1234567890");
		expect(statSync(path).mode & 0o777).toBe(0o600);
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("repairs invalid JSONL rows with atomic store/quarantine writes", () => {
		const eventsPath = join(memoryDir, "events.jsonl");
		writeFileSync(eventsPath, `${JSON.stringify({ kind: "repi-memory-event", id: "keep" })}\nnot-json\n`, {
			mode: 0o600,
		});

		const { result, report } = runMemory(["repair", "--apply", "--yes"]);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		expect(report).toMatchObject({ ok: true, apply: true, invalidLines: 1 });
		const repairedLines = readFileSync(eventsPath, "utf8").trim().split(/\r?\n/);
		expect(repairedLines).toHaveLength(1);
		expect(JSON.parse(repairedLines[0])).toMatchObject({ kind: "repi-memory-event", id: "keep", seq: 1 });
		const quarantinePath = (report.quarantinePath ?? "") as string;
		expect(quarantinePath).toContain("events.invalid-");
		expect(readFileSync(quarantinePath, "utf8")).toContain("not-json");
		expect(statSync(eventsPath).mode & 0o777).toBe(0o600);
		expect(statSync(quarantinePath).mode & 0o777).toBe(0o600);
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("writes governance decisions through the same private atomic path", () => {
		const { result, report } = runMemory([
			"forget",
			"--id",
			"missing-event-id",
			"--reason",
			"operator rejected stale reverse path",
		]);

		expect(result.status).toBe(1);
		expect(report).toMatchObject({ ok: false, governancePath: join(memoryDir, "governance-ledger.jsonl") });
		const governancePath = join(memoryDir, "governance-ledger.jsonl");
		const rows = readFileSync(governancePath, "utf8")
			.trim()
			.split(/\r?\n/)
			.map((line) => JSON.parse(line));
		expect(rows).toHaveLength(1);
		expect(rows[0]).toMatchObject({
			kind: "repi-memory-ux-governance-decision",
			action: "forget",
			applied: false,
			reason: "operator rejected stale reverse path",
		});
		expect(statSync(governancePath).mode & 0o777).toBe(0o600);
		expect(collectTmp(agentDir)).toEqual([]);
	});
});
