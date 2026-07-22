import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fauxAssistantMessage, fauxToolCall } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createReconExtensionFactory } from "../../src/core/recon-profile.ts";
import { REPI_TOOL_NAMES } from "../../src/core/repi/profile.ts";
import {
	CWE_ENTRIES,
	cweEntry,
	formatCweTags,
	formatMitreTag,
	MITRE_TECHNIQUES,
	mitreTechnique,
	unresolvedTaxonomyIds,
} from "../../src/core/repi/taxonomy.ts";
import {
	ADVANCED_TECHNIQUES,
	domainLabel,
	formatTechniqueIndex,
	formatTechniquePlaybook,
	techniqueById,
	techniqueDomains,
	techniquesForDomain,
	unresolvedCatalogTaxonomyIds,
} from "../../src/core/repi/techniques.ts";
import { createHarness, getMessageText, type Harness } from "./harness.ts";

const REPI_DIR = join(__dirname, "../../src/core/repi");

describe("repi taxonomy", () => {
	it("resolves known MITRE and CWE ids", () => {
		expect(mitreTechnique("T1059.004")?.name).toContain("Unix Shell");
		expect(mitreTechnique("T1558.003")?.name).toContain("Kerberoasting");
		expect(cweEntry("CWE-78")?.title).toBe("OS Command Injection");
		expect(cweEntry("CWE-918")?.title).toContain("Server-Side Request Forgery");
	});

	it("returns undefined for unknown ids", () => {
		expect(mitreTechnique("T9999")).toBeUndefined();
		expect(cweEntry("CWE-99999")).toBeUndefined();
	});

	it("formats MITRE and CWE tag lines", () => {
		expect(formatMitreTag("T1059.004")).toBe(
			"MITRE ATT&CK T1059.004 — Command and Scripting Interpreter: Unix Shell (Execution)",
		);
		expect(formatMitreTag("T9999")).toBe("MITRE ATT&CK T9999");
		expect(formatCweTags(["CWE-78", "CWE-89"])).toBe("CWE-78 — OS Command Injection | CWE-89 — SQL Injection");
		expect(formatCweTags([])).toBe("");
	});

	it("reports unresolved taxonomy ids", () => {
		const unresolved = unresolvedTaxonomyIds(["T1059.004", "TNOPE"], ["CWE-78", "CWE-NOPE"]);
		expect(unresolved.mitre).toEqual(["TNOPE"]);
		expect(unresolved.cwe).toEqual(["CWE-NOPE"]);
	});

	it("keeps a non-empty, deduped taxonomy", () => {
		const mitreIds = MITRE_TECHNIQUES.map((e) => e.id);
		const cweIds = CWE_ENTRIES.map((e) => e.id);
		expect(new Set(mitreIds).size).toBe(mitreIds.length);
		expect(new Set(cweIds).size).toBe(cweIds.length);
		expect(mitreIds.length).toBeGreaterThan(20);
		expect(cweIds.length).toBeGreaterThan(25);
	});
});

describe("repi advanced-technique catalog", () => {
	it("every entry has id, name, domain, triggers, non-empty procedure, proofExit, tools", () => {
		for (const entry of ADVANCED_TECHNIQUES) {
			expect(entry.id).toMatch(/^[a-z0-9-]+$/);
			expect(entry.name.length).toBeGreaterThan(0);
			expect(entry.triggers.length).toBeGreaterThan(0);
			expect(entry.procedure.length).toBeGreaterThanOrEqual(3);
			expect(entry.proofExit.length).toBeGreaterThan(0);
			expect(entry.pitfalls.length).toBeGreaterThanOrEqual(1);
			expect(entry.tools.length).toBeGreaterThanOrEqual(2);
		}
	});

	it("every entry has at least one MITRE or CWE tag (or is a methodology entry)", () => {
		// exploit-reliability is a methodology entry with no standard attack class.
		const methodology = new Set(["reliability-replay-matrix"]);
		for (const entry of ADVANCED_TECHNIQUES) {
			if (methodology.has(entry.id)) continue;
			const hasTag = (entry.mitre?.length ?? 0) > 0 || (entry.cwe?.length ?? 0) > 0;
			expect(hasTag, `${entry.id} has no MITRE/CWE tag`).toBe(true);
		}
	});

	it("every MITRE/CWE id referenced by the catalog resolves in the taxonomy", () => {
		const unresolved = unresolvedCatalogTaxonomyIds();
		expect(unresolved.mitre, `unresolved MITRE: ${unresolved.mitre.join(", ")}`).toEqual([]);
		expect(unresolved.cwe, `unresolved CWE: ${unresolved.cwe.join(", ")}`).toEqual([]);
		expect(unresolved.entries).toEqual([]);
	});

	it("ids are unique", () => {
		const ids = ADVANCED_TECHNIQUES.map((e) => e.id);
		expect(new Set(ids).size).toBe(ids.length);
	});

	it("JS signing rebuild requires negative controls and table sanity checks", () => {
		const entry = techniqueById("js-signature-rebuild");
		const text = `${entry?.procedure.join("\n")}\n${entry?.proofExit}\n${entry?.pitfalls.join("\n")}`;
		expect(text).toContain("missing-signature");
		expect(text).toContain("tampered-signature");
		expect(text).toContain("byte-for-byte");
		expect(text).toContain("permutation");
		expect(text).toContain("duplicate");
	});

	it("models agent context poisoning as session-scoped, not durable memory", () => {
		const entry = techniqueById("agent-context-exfil");
		const text = `${entry?.name}\n${entry?.triggers}\n${entry?.procedure.join("\n")}\n${entry?.proofExit}`;
		expect(entry).toBeDefined();
		expect(text).toContain("session transcript");
		expect(text).toContain("tool-result");
		expect(text).toContain("clean-session");
		expect(text).not.toContain("long-term memory");
	});

	it("covers the core offensive domains", () => {
		const domains = new Set(techniqueDomains());
		for (const required of [
			"pwn",
			"web-api",
			"web-scan",
			"js-reverse",
			"crypto-stego",
			"native-reverse",
			"mobile",
			"firmware-iot",
			"identity-ad",
			"cloud-container",
			"malware",
			"agent-llm",
		] as const) {
			expect(domains.has(required), `missing domain ${required}`).toBe(true);
		}
	});

	it("each core domain has multiple techniques", () => {
		for (const domain of ["pwn", "web-api", "crypto-stego", "identity-ad", "firmware-iot"] as const) {
			expect(techniquesForDomain(domain).length).toBeGreaterThanOrEqual(3);
		}
		for (const domain of [
			"web-scan",
			"js-reverse",
			"native-reverse",
			"mobile",
			"cloud-container",
			"malware",
			"agent-llm",
			"dfir-pcap",
			"memory-forensics",
		] as const) {
			expect(
				techniquesForDomain(domain).length,
				`${domain} should have catalogued techniques`,
			).toBeGreaterThanOrEqual(2);
		}
	});

	it("techniquesForDomain returns empty array for an uncatalogued domain", () => {
		expect(techniquesForDomain("dfir-pcap").length).toBeGreaterThanOrEqual(1);
	});

	it("techniqueById resolves and misses correctly", () => {
		const t = techniqueById("pwn-tcache-poisoning");
		expect(t?.domain).toBe("pwn");
		expect(techniqueById("does-not-exist")).toBeUndefined();
	});

	it("domainLabel returns a human label", () => {
		expect(domainLabel("pwn")).toBe("Pwn / exploit");
		expect(domainLabel("identity-ad")).toContain("AD");
	});

	it("formatTechniqueIndex lists every technique grouped by domain", () => {
		const index = formatTechniqueIndex();
		for (const entry of ADVANCED_TECHNIQUES) {
			expect(index).toContain(entry.id);
			expect(index).toContain(entry.name);
		}
		expect(index).toContain("re_techniques");
	});

	it("formatTechniquePlaybook renders full procedure + proof-exit + pitfalls for a technique", () => {
		const t = techniqueById("ad-kerberoasting");
		expect(t).toBeDefined();
		const playbook = formatTechniquePlaybook([t!]);
		expect(playbook).toContain("## ad-kerberoasting");
		expect(playbook).toContain("when to use:");
		expect(playbook).toContain("procedure:");
		expect(playbook).toContain("proof-exit");
		expect(playbook).toContain("pitfalls:");
		expect(playbook).toContain("MITRE ATT&CK T1558.003");
		expect(playbook).toContain("CWE-522");
	});

	it("formatTechniquePlaybook handles an empty match set gracefully", () => {
		const playbook = formatTechniquePlaybook([]);
		expect(playbook.length).toBeGreaterThan(0);
		expect(playbook).toContain("No catalogued advanced techniques");
	});
});

describe("re_techniques tool wiring", () => {
	it("re_techniques is registered in REPI_TOOL_NAMES", () => {
		expect(REPI_TOOL_NAMES).toContain("re_techniques");
	});

	it("techniques.ts and taxonomy.ts do not import recon-profile (one-way dep)", () => {
		for (const file of ["techniques.ts", "taxonomy.ts"]) {
			const src = readFileSync(join(REPI_DIR, file), "utf8");
			expect(src, `${file} must not import recon-profile`).not.toContain("recon-profile");
		}
	});
});

describe("re_techniques tool end-to-end", () => {
	const harnesses: Harness[] = [];
	const tempDirs: string[] = [];
	let savedAgentDir: string | undefined;

	beforeEach(() => {
		savedAgentDir = process.env.REPI_CODING_AGENT_DIR;
		const dir = join(tmpdir(), `re-techniques-e2e-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(dir, { recursive: true });
		tempDirs.push(dir);
		process.env.REPI_CODING_AGENT_DIR = dir;
	});

	afterEach(() => {
		for (const harness of harnesses) {
			harness.cleanup();
		}
		harnesses.length = 0;
		if (savedAgentDir === undefined) {
			delete process.env.REPI_CODING_AGENT_DIR;
		} else {
			process.env.REPI_CODING_AGENT_DIR = savedAgentDir;
		}
		for (const dir of tempDirs) {
			rmSync(dir, { recursive: true, force: true });
		}
		tempDirs.length = 0;
	});

	it("is registered and returns the index by default", async () => {
		const harness = await createHarness({ extensionFactories: [createReconExtensionFactory()] });
		harnesses.push(harness);
		await harness.session.bindExtensions({});
		expect(harness.session.getAllTools().map((tool) => tool.name)).toContain("re_techniques");

		harness.setResponses([
			fauxAssistantMessage([fauxToolCall("re_techniques", {})], { stopReason: "toolUse" }),
			fauxAssistantMessage("done"),
		]);
		await harness.session.prompt("list techniques");

		const result = harness.session.messages.find((message) => message.role === "toolResult");
		const text = getMessageText(result);
		expect(text).toContain("REPI advanced-technique index");
		expect(text).toContain("pwn-tcache-poisoning");
		expect(text).toContain("re_techniques");
	});

	it("returns a domain playbook with MITRE/CWE tags", async () => {
		const harness = await createHarness({ extensionFactories: [createReconExtensionFactory()] });
		harnesses.push(harness);
		await harness.session.bindExtensions({});

		harness.setResponses([
			fauxAssistantMessage([fauxToolCall("re_techniques", { domain: "identity-ad" })], { stopReason: "toolUse" }),
			fauxAssistantMessage("done"),
		]);
		await harness.session.prompt("show ad techniques");

		const result = harness.session.messages.find((message) => message.role === "toolResult");
		const text = getMessageText(result);
		expect(text).toContain("ad-kerberoasting");
		expect(text).toContain("MITRE ATT&CK T1558.003");
		expect(text).toContain("proof-exit");
	});

	it("accepts web-authz route aliases for the web-api technique catalog", async () => {
		const harness = await createHarness({ extensionFactories: [createReconExtensionFactory()] });
		harnesses.push(harness);
		await harness.session.bindExtensions({});

		harness.setResponses([
			fauxAssistantMessage([fauxToolCall("re_techniques", { domain: "web-api-authz" })], { stopReason: "toolUse" }),
			fauxAssistantMessage("done"),
		]);
		await harness.session.prompt("show web authz techniques");

		const result = harness.session.messages.find((message) => message.role === "toolResult");
		const text = getMessageText(result);
		expect(text).toContain("web-idor-bola");
		expect(text).toContain("IDOR / BOLA");
		expect(text).toContain("proof-exit");
	});

	it("accepts PCAP/DFIR route aliases for the dfir-pcap technique catalog", async () => {
		const harness = await createHarness({ extensionFactories: [createReconExtensionFactory()] });
		harnesses.push(harness);
		await harness.session.bindExtensions({});

		harness.setResponses([
			fauxAssistantMessage([fauxToolCall("re_techniques", { domain: "pcap-dfir-carve" })], {
				stopReason: "toolUse",
			}),
			fauxAssistantMessage("done"),
		]);
		await harness.session.prompt("show pcap techniques");

		const result = harness.session.messages.find((message) => message.role === "toolResult");
		const text = getMessageText(result);
		expect(text).toContain("dfir-credential-pcap");
		expect(text).toContain("PCAP credential");
		expect(text).toContain("proof-exit");
	});

	it("re_verifier binds a falsifiable proof-contract from a technique's proofExit", async () => {
		const harness = await createHarness({ extensionFactories: [createReconExtensionFactory()] });
		harnesses.push(harness);
		await harness.session.bindExtensions({});

		harness.setResponses([
			fauxAssistantMessage([fauxToolCall("re_verifier", { action: "check", technique: "ad-kerberoasting" })], {
				stopReason: "toolUse",
			}),
			fauxAssistantMessage("done"),
		]);
		await harness.session.prompt("verify kerberoasting claim");

		const result = harness.session.messages.find((message) => message.role === "toolResult");
		const text = getMessageText(result);
		expect(text).toContain("technique_proof_contract:");
		expect(text).toContain("id: ad-kerberoasting");
		expect(text).toContain("assertion:");
		expect(text).toContain("counter_evidence_probes");
		expect(text).toContain("verifier_rule: mark 'proved' ONLY");
	});

	it("re_verifier reports an unknown technique id without crashing", async () => {
		const harness = await createHarness({ extensionFactories: [createReconExtensionFactory()] });
		harnesses.push(harness);
		await harness.session.bindExtensions({});

		harness.setResponses([
			fauxAssistantMessage([fauxToolCall("re_verifier", { technique: "does-not-exist" })], {
				stopReason: "toolUse",
			}),
			fauxAssistantMessage("done"),
		]);
		await harness.session.prompt("verify bogus technique");

		const result = harness.session.messages.find((message) => message.role === "toolResult");
		const text = getMessageText(result);
		expect(text).toContain("unknown technique id 'does-not-exist'");
	});
});
