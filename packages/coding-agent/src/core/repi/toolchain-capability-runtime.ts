import { join } from "node:path";
import { bootstrapCatalogFor, buildToolDigest, parseToolIndex } from "./bootstrap-runtime.ts";
import type { EvidenceRecord } from "./evidence.ts";
import { ensureReconStorage, RECON_APPEND_SYSTEM_PROMPT, RECON_SYSTEM_PROMPT } from "./resources.ts";
import { evidenceToolchainDir, toolIndexPath, writePrivateTextFile } from "./storage.ts";
import { repiIndexedToolPresent } from "./tool-presence.ts";
import {
	buildProfessionalRuntimeBridgesGate,
	buildToolchainDomainCapability,
	formatProfessionalRuntimeBridgesGate,
	formatToolchainDomainCapability,
	PROFESSIONAL_RUNTIME_BRIDGE_MATRIX,
	type ProfessionalRuntimeBridgesCheckV1,
	TOOLCHAIN_DOMAIN_CAPABILITY_MATRIX,
	type ToolchainDomainCapabilityV1,
} from "./toolchain-runtime.ts";

type AppendEvidence = (
	record: Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number },
) => EvidenceRecord;

export type ToolchainCapabilityDependencies = {
	appendEvidence: AppendEvidence;
};

export function createToolchainCapabilityRuntime(dependencies: ToolchainCapabilityDependencies) {
	const { appendEvidence } = dependencies;

	function buildProfessionalRuntimeBridges(bridgeFilter?: string): ProfessionalRuntimeBridgesCheckV1 {
		ensureReconStorage();
		const index = parseToolIndex();
		const sourceCorpus = [
			RECON_SYSTEM_PROMPT,
			RECON_APPEND_SYSTEM_PROMPT,
			JSON.stringify(PROFESSIONAL_RUNTIME_BRIDGE_MATRIX),
			buildToolDigest(),
		].join("\n");
		return buildProfessionalRuntimeBridgesGate({
			bridgeFilter,
			generatedAt: new Date().toISOString(),
			toolIndexPath: toolIndexPath(),
			sourceCorpus,
			toolPresent: (tool) => repiIndexedToolPresent(index, tool) === true,
		});
	}

	function writeProfessionalRuntimeBridges(report: ProfessionalRuntimeBridgesCheckV1): string {
		ensureReconStorage();
		const path = join(
			evidenceToolchainDir(),
			`${report.generatedAt.replace(/[:.]/g, "-")}-professional-runtime-bridges.md`,
		);
		writePrivateTextFile(
			path,
			`${formatProfessionalRuntimeBridgesGate(report, path)}\n\n## JSON\n\n\`\`\`json\n${JSON.stringify(report, null, 2)}\n\`\`\`\n`,
		);
		appendEvidence({
			kind: "artifact",
			title: "professional-runtime-bridges",
			fact: `ProfessionalRuntimeBridgesCheckV1 bridges=${report.bridges.length} fallback=${report.closure.allFallbacksAvailable} executable=${report.closure.allHaveExecutableTemplates}`,
			command: "re_runtime_bridge show",
			path,
			verify: `cat ${path}`,
			confidence:
				"runtime:professional-runtime-bridges runtime_execution_bridge_matrix artifact_backed_tool_execution_plan env_ref_secret_boundary",
		});
		return path;
	}

	function buildDomainCapability(domainFilter?: string): ToolchainDomainCapabilityV1 {
		ensureReconStorage();
		const index = parseToolIndex();
		const sourceCorpus = [
			RECON_SYSTEM_PROMPT,
			RECON_APPEND_SYSTEM_PROMPT,
			JSON.stringify(TOOLCHAIN_DOMAIN_CAPABILITY_MATRIX),
			buildToolDigest(),
		].join("\n");
		return buildToolchainDomainCapability({
			domainFilter,
			generatedAt: new Date().toISOString(),
			toolIndexPath: toolIndexPath(),
			sourceCorpus,
			toolPresent: (tool) => repiIndexedToolPresent(index, tool) === true,
			bootstrapHint: (tool) =>
				bootstrapCatalogFor(tool) ? `re_bootstrap plan ${tool}` : `manual_tool_review ${tool}`,
		});
	}

	function writeDomainCapability(report: ToolchainDomainCapabilityV1): string {
		ensureReconStorage();
		const path = join(
			evidenceToolchainDir(),
			`${report.generatedAt.replace(/[:.]/g, "-")}-toolchain-domain-capability.md`,
		);
		writePrivateTextFile(
			path,
			`${formatToolchainDomainCapability(report)}\n\n## JSON\n\n\`\`\`json\n${JSON.stringify(report, null, 2)}\n\`\`\`\n`,
		);
		appendEvidence({
			kind: "artifact",
			title: "toolchain-domain-capability",
			fact: `ToolchainDomainCapabilityV1 ready=${report.coverage.readyCount} degraded=${report.coverage.degradedCount} blocked=${report.coverage.blockedCount}`,
			command: "re_toolchain_domain show",
			path,
			verify: `cat ${path}`,
			confidence: "runtime:toolchain-doctor domain_toolchain_matrix fallback_available critical_gap",
		});
		return path;
	}

	function buildDomainCapabilityOutput(action: "show" | "refresh" = "show", domainFilter?: string): string {
		if (action === "refresh") return buildToolDigest();
		const report = buildDomainCapability(domainFilter);
		const path = writeDomainCapability(report);
		return formatToolchainDomainCapability(report, path);
	}

	return {
		buildProfessionalRuntimeBridgesGate: buildProfessionalRuntimeBridges,
		writeProfessionalRuntimeBridgesArtifact: writeProfessionalRuntimeBridges,
		buildToolchainDomainCapability: buildDomainCapability,
		writeToolchainDomainCapabilityArtifact: writeDomainCapability,
		buildToolchainDomainCapabilityOutput: buildDomainCapabilityOutput,
	};
}
