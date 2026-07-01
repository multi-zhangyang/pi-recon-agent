import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// F7 (MED LEAK): eventLexicalTokenCache / caseLexicalTokenCache (Map keyed by event.id /
// caseSignature) were never cleared on generation change; each new deposit added a PERMANENT
// entry (event ids are unique, never reused), so the caches grew without bound over a session
// even though stale-generation entries are skipped on lookup. Fix (#86): lexicalTokenGeneration()
// compares the computed generation to a module-level lastLexicalGeneration; on change it clears
// both caches. The caches are lazily rebuilt on the next recall (which re-scans all events
// anyway), so clearing is lossless. The proof checks the cache SIZE drops to 0 on a generation
// change (deposit). Temp-neuter the clear → the stale entry persists → the size-0 assertion fails.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");
const { cachedEventSearchTokens, lexicalTokenCacheSizes, lexicalTokenGeneration, readMemoryEvents } = await import(
	"../../src/core/repi/memory-search.ts"
);

describe("repi/memory-search F7 lexical token-cache eviction on generation change", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-lexical-evict-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

	it("a generation change (deposit) clears the lexical token caches (size drops to 0, lossless rebuild)", () => {
		// Deposit A → build + cache its event tokens (cache size events=1).
		appendMemoryEventTransaction({
			source: "manual",
			task: "exploit rop gadget",
			route: "re",
			outcome: "success",
		});
		const eventA = readMemoryEvents()[0];
		const gen1 = lexicalTokenGeneration();
		cachedEventSearchTokens(eventA, gen1);
		expect(lexicalTokenCacheSizes().events).toBe(1);

		// A second deposit rewrites events.jsonl (atomic temp+rename → mtime+size change) → the
		// generation token changes. lexicalTokenGeneration() detects the change and CLEARS both
		// caches (#86) so the unique event.id for A does not linger as a permanent stale entry.
		appendMemoryEventTransaction({
			source: "manual",
			task: "heap tcache poisoning",
			route: "re",
			outcome: "success",
		});
		const gen2 = lexicalTokenGeneration();
		expect(gen2).not.toBe(gen1);
		// Temp-neuter the clear (`if (false && generation !== lastLexicalGeneration)`) → A's entry
		// persists → sizes.events stays 1 → this assertion fails.
		expect(lexicalTokenCacheSizes().events).toBe(0);
		expect(lexicalTokenCacheSizes().cases).toBe(0);

		// Lossless: the caches rebuild lazily on the next access. Event B's tokens are built fresh
		// and the cache repopulates with only current-generation entries.
		const eventB = readMemoryEvents()[1];
		const tokensB = cachedEventSearchTokens(eventB, gen2);
		expect(tokensB.size).toBeGreaterThan(0);
		expect(lexicalTokenCacheSizes().events).toBe(1);
		// A second access for B with the same generation hits the cache (shared ref, no rebuild).
		expect(cachedEventSearchTokens(eventB, gen2)).toBe(tokensB);
	});
});
