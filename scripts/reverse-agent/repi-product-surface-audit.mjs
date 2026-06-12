#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const json = argv.includes("--json");
const strict = argv.includes("--strict");

const PRODUCT_SURFACE_FILES = [
	"README.md",
	"docs/reverse-agent/README.md",
	"docs/reverse-agent/repi-runtime-configuration.md",
	"docs/reverse-agent/model-provider-formats.md",
	"packages/coding-agent/README.md",
	"packages/coding-agent/docs/recon.md",
	"packages/coding-agent/docs/usage.md",
	"packages/coding-agent/docs/packages.md",
	"packages/coding-agent/docs/repi-runtime-configuration.md",
	"packages/coding-agent/docs/model-provider-formats.md",
	"packages/coding-agent/src/cli/args.ts",
	"packages/coding-agent/src/cli/repi-bootstrap.ts",
	"packages/coding-agent/src/config.ts",
	"packages/coding-agent/src/core/repi-profile-init.ts",
	"packages/coding-agent/src/core/auth-guidance.ts",
	"packages/coding-agent/src/main.ts",
	"packages/coding-agent/src/modes/interactive/interactive-mode.ts",
	"packages/coding-agent/src/utils/version-check.ts",
	"repi",
	"pi",
	"scripts/reverse-agent/install-repi.sh",
	"scripts/reverse-agent/install-global-profile.sh",
	"scripts/reverse-agent/clean-global-repi-profile.sh",
	".gitignore",
	"repi-profile/SYSTEM.md",
	"repi-profile/APPEND_SYSTEM.md",
	"repi-profile/prompts/repi-config.md",
	"repi-profile/skills/reverse-pentest-orchestrator/SKILL.md",
];

const GLOBAL_PRIVATE_PROVIDER_PATTERNS = [
	/github_pat_[A-Za-z0-9_]+/,
	/ghp_[A-Za-z0-9_]+/,
	/sk-[A-Za-z0-9_-]{12,}/,
	new RegExp([["2", "go"].join("") + "-(anthropic|openai)", "moonshot", "kimi-k2\\.6"].join("\\/")),
	new RegExp(["api", ["2", "go"].join(""), "live"].join("\\.")),
];

const PRODUCT_FORBIDDEN = [
	{ id: "old-brand-title", pattern: new RegExp(["Pi", "RECON"].join("-")) },
	{ id: "old-product-help", pattern: new RegExp(`repi\\s+-\\s+${["Pi", "RECON"].join("-")}`, "i") },
	{ id: "old-profile-kind", pattern: /isolated-pi-recon-profile/ },
	{ id: "old-offline-env-doc", pattern: /same as PI_OFFLINE=1/ },
	{ id: "legacy-dot-pi-artifact-path", pattern: /\.pi\/(?:evidence|memory|mission|reports)/ },
	{ id: "legacy-compact-reserve-default", pattern: /reserveTokens:\s*32768/ },
	{ id: "legacy-script-npm-entry", pattern: /"(?:install:recon-pi|gate:pi-recon-primary)"/ },
	{ id: "old-pi-mod-language", pattern: /对 Pi 的|魔改/ },
	{ id: "generic-coding-help-example", pattern: /List all \.ts files|Help me refactor|coding assistant prompt|Summarize this codebase|Review the code/ },
	{ id: "upstream-startup-onboarding", pattern: /Pi can explain its own features|Ask it how to use or extend Pi/ },
	{ id: "product-help-pi-env-leak", pattern: /PI_PACKAGE_DIR is accepted|(^|[^A-Z_])PI_OFFLINE=1|(^|[^A-Z_])PI_TELEMETRY=0|(^|[^A-Z_])PI_SKIP_VERSION_CHECK=1/ },
	{ id: "legacy-dot-pi-ignore", pattern: /\.pi\/evidence/ },
];

function sha256(text) {
	return createHash("sha256").update(text).digest("hex");
}

function read(path) {
	return readFileSync(join(root, path), "utf8");
}

function scanFile(path, patterns) {
	if (!existsSync(join(root, path))) return [{ path, id: "missing", match: "file does not exist" }];
	const text = read(path);
	const hits = [];
	for (const item of patterns) {
		const match = text.match(item.pattern);
		if (match) hits.push({ path, id: item.id, match: match[0].slice(0, 160) });
	}
	return hits;
}

const productHits = PRODUCT_SURFACE_FILES.flatMap((path) => scanFile(path, PRODUCT_FORBIDDEN));

const privateHits = [];
for (const path of [
	"README.md",
	"docs/reverse-agent/README.md",
	"docs/reverse-agent/repi-runtime-configuration.md",
	"docs/reverse-agent/model-provider-formats.md",
	"packages/coding-agent/docs/repi-runtime-configuration.md",
	"packages/coding-agent/docs/model-provider-formats.md",
	"scripts/reverse-agent/assert-repi-isolated.mjs",
]) {
	if (!existsSync(join(root, path))) continue;
	const text = read(path);
	for (const pattern of GLOBAL_PRIVATE_PROVIDER_PATTERNS) {
		const match = text.match(pattern);
		if (match) privateHits.push({ path, pattern: String(pattern), match: match[0].slice(0, 160) });
	}
}

const requiredMarkers = [
	["README.md", "# REPI Agent"],
	["README.md", "基于 Pi Coding Agent 底层深度改造"],
	["packages/coding-agent/src/cli/args.ts", "REPI reverse/pentest autonomous agent"],
	["packages/coding-agent/src/core/auth-guidance.ts", "~/.repi/agent/models.json"],
	["packages/coding-agent/docs/repi-runtime-configuration.md", "triggerPercent"],
	["packages/coding-agent/src/core/repi-profile-init.ts", "isolated-repi-profile"],
	["packages/coding-agent/src/package-manager-cli.ts", "does not manage upstream pi"],
	["packages/coding-agent/test/package-command-paths.test.ts", "rejects `repi update pi` as an upstream pi boundary request"],
	["repi", "REPI_PRODUCT=1"],
	["scripts/reverse-agent/install-repi.sh", "Installed REPI:"],
	["scripts/reverse-agent/install-global-profile.sh", "no longer installs a file-based global profile"],
	["scripts/reverse-agent/clean-global-repi-profile.sh", "Default is dry-run"],
	["repi-profile/SYSTEM.md", "~/.repi/agent/recon/evidence"],
];
const missingMarkers = requiredMarkers
	.map(([path, marker]) => ({ path, marker, present: existsSync(join(root, path)) && read(path).includes(marker) }))
	.filter((row) => !row.present);

const compatibilityProtocolFiles = [
	"packages/coding-agent/src/core/recon-profile.ts",
	"repi-profile/extensions/reverse-pentest-core.ts",
	"scripts/reverse-agent/verify-profile.mjs",
];
const compatibilityProtocolMarkers = compatibilityProtocolFiles.map((path) => {
	if (!existsSync(join(root, path))) return { path, exists: false, piReconProtocolMarkers: 0 };
	const text = read(path);
	return { path, exists: true, sha256: sha256(text).slice(0, 24), piReconProtocolMarkers: (text.match(/pi-recon-/g) ?? []).length };
});

const ok = productHits.length === 0 && privateHits.length === 0 && missingMarkers.length === 0;
const result = {
	ok,
	root,
	strict,
	productSurfaceFiles: PRODUCT_SURFACE_FILES.length,
	productHits,
	privateHits,
	missingMarkers,
	compatibilityProtocolMarkers,
	note:
		"Lowercase pi-recon-* protocol markers are currently treated as internal wire/artifact compatibility markers; user-facing product surface must say REPI.",
};

if (json) {
	console.log(JSON.stringify(result, null, 2));
} else {
	console.log("REPI product_surface_audit");
	console.log(`status: ${ok ? "pass" : "fail"}`);
	console.log(`root: ${root}`);
	console.log(`surface_files: ${PRODUCT_SURFACE_FILES.length}`);
	console.log(`product_hits: ${productHits.length}`);
	console.log(`private_provider_hits: ${privateHits.length}`);
	console.log(`missing_markers: ${missingMarkers.length}`);
	for (const hit of productHits) console.log(`- product:${hit.id}: ${hit.path}: ${hit.match}`);
	for (const hit of privateHits) console.log(`- private-provider: ${hit.path}: ${hit.match}`);
	for (const miss of missingMarkers) console.log(`- missing: ${miss.path}: ${miss.marker}`);
	console.log("compatibility_protocol_markers:");
	for (const row of compatibilityProtocolMarkers) console.log(`- ${row.path}: ${row.piReconProtocolMarkers}`);
}

if (strict && !ok) process.exit(1);
