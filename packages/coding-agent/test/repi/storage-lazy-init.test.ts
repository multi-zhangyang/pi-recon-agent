import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ENV_AGENT_DIR } from "../../src/config.ts";
import { ensureReconStorage } from "../../src/core/repi/resources.ts";
import {
	builtinPromptFilePath,
	builtinSkillFilePath,
	ensureRepiStorage,
	evidenceLedgerPath,
	runtimeFailureLedgerPath,
	writePrivateTextFile,
} from "../../src/core/repi/storage.ts";

describe("REPI lazy storage initialization", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-lazy-storage-"));
		process.env[ENV_AGENT_DIR] = dir;
	});

	afterEach(() => {
		delete process.env[ENV_AGENT_DIR];
		rmSync(dir, { recursive: true, force: true });
	});

	it("materializes generated resources without pre-seeding unused runtime state", () => {
		ensureRepiStorage({
			skillContent: "# Focused skill",
			prompts: [{ name: "probe", description: "Probe", content: "Run the probe." }],
		});

		expect(existsSync(builtinSkillFilePath())).toBe(true);
		expect(existsSync(builtinPromptFilePath("probe"))).toBe(true);
		expect(existsSync(evidenceLedgerPath())).toBe(false);
		expect(existsSync(runtimeFailureLedgerPath())).toBe(false);
	});

	it("updates generated resources and lets the first writer create feature directories", () => {
		ensureRepiStorage({ skillContent: "old" });
		ensureRepiStorage({ skillContent: "new" });
		expect(readFileSync(builtinSkillFilePath(), "utf8")).toContain("new");

		writePrivateTextFile(runtimeFailureLedgerPath(), "row\n");
		expect(readFileSync(runtimeFailureLedgerPath(), "utf8")).toBe("row\n");
	});

	it("does not materialize the built-in corpus on ordinary runtime initialization", () => {
		ensureReconStorage();

		expect(existsSync(join(dir, "recon"))).toBe(true);
		expect(existsSync(builtinSkillFilePath())).toBe(false);
		expect(existsSync(builtinPromptFilePath("reverse"))).toBe(false);
	});

	it("materializes the built-in corpus only when explicitly requested", () => {
		ensureReconStorage({ materializeResources: true });

		expect(existsSync(builtinSkillFilePath())).toBe(true);
		expect(existsSync(builtinPromptFilePath("reverse"))).toBe(true);
	});
});
