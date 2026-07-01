import { mkdirSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// F2 (HIGH CRASH): memory-distillation.ts wrote 7 artifacts via raw writeFileSync
// (truncate-then-write): distillation-report.json, quarantine.json, pattern-book.md,
// semantic-index.json, contradiction-ledger.jsonl, injection-packet.json, sedimentation-report.json.
// injection-packet.json is read back by memory-feedback.ts/memory-quality.ts to drive injection
// decisions — a torn write silently zeroes the injection set (silent correctness loss). Fix:
// route all 7 through writePrivateTextFile (atomic temp+rename, 0o600). temp+rename replaces the
// inode; the old truncate-then-write kept it — the inode-change assertion is the regression probe.
// The load-bearing proof is on injection-packet.json (the read-back file); the other 6 are
// verified as a group (all atomic, all valid, all 0o600).

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

const { buildMemorySemanticIndex } = await import("../../src/core/repi/memory-distillation.ts");
const {
	memoryContradictionLedgerPath,
	memoryDistillationReportPath,
	memoryInjectionPacketPath,
	memoryPatternBookPath,
	memoryQuarantinePath,
	memorySedimentationReportPath,
	memorySemanticIndexPath,
} = await import("../../src/core/repi/storage.ts");
const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");

describe("repi/memory-distillation F2 atomic writes (7 artifacts via writePrivateTextFile)", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-distill-atomic-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		process.env[ENV_AGENT_DIR] = agentDir;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("all 7 distillation artifacts are written atomically (inode changes on rewrite, valid JSON, 0o600, no .tmp)", () => {
		appendMemoryEventTransaction({
			source: "manual",
			task: "exploit rop gadget ret2libc",
			route: "re",
			outcome: "success",
			lessons: ["use ropper for gadgets"],
			commands: ["ropper --file b --search 'pop rdi'"],
		});
		const targets = [
			{ name: "distillation-report.json", path: memoryDistillationReportPath(), json: true },
			{ name: "quarantine.json", path: memoryQuarantinePath(), json: true },
			{ name: "pattern-book.md", path: memoryPatternBookPath(), json: false },
			{ name: "semantic-index.json", path: memorySemanticIndexPath(), json: true },
			{ name: "contradiction-ledger.jsonl", path: memoryContradictionLedgerPath(), json: false },
			{ name: "injection-packet.json", path: memoryInjectionPacketPath(), json: true },
			{ name: "sedimentation-report.json", path: memorySedimentationReportPath(), json: true },
		];
		// First build creates all 7.
		buildMemorySemanticIndex();
		const inodesBefore = new Map<string, number>();
		for (const target of targets) {
			expect(statSync(target.path).mode & 0o777).toBe(0o600);
			inodesBefore.set(target.name, statSync(target.path).ino);
		}
		// injection-packet.json is valid JSON with the kind field (the read-back contract).
		const packet = JSON.parse(readFileSync(memoryInjectionPacketPath(), "utf8"));
		expect(packet.kind).toBe("repi-memory-injection-packet");
		expect(packet.mandatory_memory_injection_packet).toBe(true);

		// A second build rewrites all 7 via temp+rename → each installs a NEW inode. The old
		// truncate-then-write (writeFileSync) kept the SAME inode — these assertions fail if any
		// write regresses. Temp-neuter the injection-packet write specifically → its inode
		// assertion fails first (the load-bearing read-back file).
		buildMemorySemanticIndex();
		for (const target of targets) {
			const inodeAfter = statSync(target.path).ino;
			expect(inodeAfter, `${target.name} inode should change on rewrite`).not.toBe(inodesBefore.get(target.name));
			expect(statSync(target.path).mode & 0o777).toBe(0o600);
			if (target.json) {
				const parsed = JSON.parse(readFileSync(target.path, "utf8"));
				expect(parsed.kind).toBeTruthy();
			}
		}
		// No stray temp files left in the memory dir.
		expect(readdirSync(dirname(memoryInjectionPacketPath())).filter((f) => f.endsWith(".tmp"))).toEqual([]);
	});
});
