import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const profileSource = readFileSync(new URL("../src/core/recon-profile.ts", import.meta.url), "utf8");
const webRuntimeSource = readFileSync(new URL("../src/core/repi/web-runtime.ts", import.meta.url), "utf8");
const exploitMobileRuntimeSource = readFileSync(
	new URL("../src/core/repi/exploit-mobile-runtime.ts", import.meta.url),
	"utf8",
);
const nativeRuntimeSource = readFileSync(new URL("../src/core/repi/native-runtime.ts", import.meta.url), "utf8");
const evidenceRuntimeSource = readFileSync(new URL("../src/core/repi/evidence-runtime.ts", import.meta.url), "utf8");
const evidenceGraphRuntimeSource = readFileSync(
	new URL("../src/core/repi/evidence-graph-runtime.ts", import.meta.url),
	"utf8",
);
const artifactSelectionRuntimeSource = readFileSync(
	new URL("../src/core/repi/artifact-selection-runtime.ts", import.meta.url),
	"utf8",
);
const profileKernelReportRuntimeSource = readFileSync(
	new URL("../src/core/repi/profile-kernel-report-runtime.ts", import.meta.url),
	"utf8",
);
const swarmRuntimeSource = readFileSync(
	new URL("../src/core/repi/swarm-supervisor-runtime.ts", import.meta.url),
	"utf8",
);

describe("REPI profile runtime module boundaries", () => {
	it("wires split runtime modules instead of duplicating implementations", () => {
		expect(profileSource).toContain('from "./repi/web-runtime.ts"');
		expect(profileSource).toContain('from "./repi/exploit-mobile-runtime.ts"');
		expect(profileSource).toContain('from "./repi/native-runtime.ts"');
		expect(profileSource).toContain("createExploitMobileRuntime({");
		expect(profileSource).toContain("createNativeRuntime({");
		expect(profileSource).toContain("runWebRuntimeLiveBrowser(pi, options, webRuntimeDependencies)");
		expect(profileSource).toContain("runWebRuntimeAuthzState(pi, options, webRuntimeDependencies)");
		for (const marker of [
			"function liveBrowserNodeScript(",
			"function webAuthzStateNodeScript(",
			"function exploitLabRunnerScript(",
			"function mobileRuntimeFridaHookScript(",
			"function nativeRuntimeGdbScript(",
		]) {
			expect(profileSource).not.toContain(marker);
		}
	});

	it("keeps swarm artifact naming in a pure module", () => {
		expect(swarmRuntimeSource).toContain('from "./swarm-artifact-paths.ts"');
		expect(swarmRuntimeSource).not.toContain("function swarmArtifactPath(");
		expect(swarmRuntimeSource).not.toContain("function swarmWorkerLeaseSchedulerPath(");
	});

	it("keeps executable script templates valid after factory nesting", () => {
		expect(webRuntimeSource).toContain("export async function runLiveBrowser");
		expect(webRuntimeSource).toContain("export async function runWebAuthzState");
		expect(exploitMobileRuntimeSource).toContain("const stripScriptIndent");
		expect(exploitMobileRuntimeSource).toContain("stripScriptIndent(String.raw`#!/usr/bin/env python3");
		expect(exploitMobileRuntimeSource).toContain("stripScriptIndent(`'use strict';");
		expect(nativeRuntimeSource).toContain("const stripScriptIndent");
		expect(nativeRuntimeSource).toContain("stripScriptIndent(`set pagination off");
		expect(nativeRuntimeSource).toContain("stripScriptIndent(`#!/usr/bin/env python3");
	});

	it("keeps evidence, graph, artifact selection, and kernel/report behavior out of the assembly profile", () => {
		for (const runtimeImport of [
			'from "./repi/evidence-runtime.ts"',
			'from "./repi/evidence-graph-runtime.ts"',
			'from "./repi/artifact-selection-runtime.ts"',
			'from "./repi/profile-kernel-report-runtime.ts"',
		]) {
			expect(profileSource).toContain(runtimeImport);
		}
		for (const marker of [
			"function appendEvidence(",
			"function buildPentestingTaskTreeSnapshot(",
			"function writeAttackGraphArtifact(",
			"function scopedMarkdownArtifacts(",
			"function buildKernelOutput(",
			"function writeReportScaffold(",
		]) {
			expect(profileSource).not.toContain(marker);
		}
		expect(evidenceRuntimeSource).toContain("export function appendEvidence(");
		expect(evidenceGraphRuntimeSource).toContain("function buildPentestingTaskTreeSnapshot(");
		expect(artifactSelectionRuntimeSource).toContain("export function scopedMarkdownArtifacts(");
		expect(profileKernelReportRuntimeSource).toContain("function buildKernelOutput(");
	});

	it("keeps the profile below the previous monolith boundary", () => {
		expect(profileSource.split(/\r?\n/).length).toBeLessThan(21_000);
		expect(Buffer.byteLength(profileSource)).toBeLessThan(850_000);
	});
});
