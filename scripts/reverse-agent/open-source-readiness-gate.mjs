#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const json = argv.includes("--json");
const strict = argv.includes("--strict");

function read(path) {
	return readFileSync(join(root, path), "utf8");
}

function readJson(path) {
	return JSON.parse(read(path));
}

function check(id, pass, evidence = {}) {
	return { id, status: pass ? "pass" : "fail", evidence };
}

function fileCheck(path, required = []) {
	if (!existsSync(join(root, path))) return check(`file:${path}`, false, { path, exists: false });
	const text = read(path);
	const missing = required.filter((marker) => !text.includes(marker));
	return check(`file:${path}`, missing.length === 0, { path, missing });
}

function forbiddenCheck(id, path, patterns) {
	const text = existsSync(join(root, path)) ? read(path) : "";
	const hits = patterns.filter((pattern) => pattern.test(text)).map(String);
	return check(id, hits.length === 0, { path, hits });
}

function gitFiles() {
	const result = spawnSync("git", ["ls-files"], { cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
	if (result.status !== 0) return [];
	return result.stdout.split(/\r?\n/).filter(Boolean);
}

function secretScan() {
	const patterns = [
		["openai-style-key", /\bsk-[A-Za-z0-9._-]{20,}\b/g],
		["github-token", /\bghp_[A-Za-z0-9_]{20,}\b/g],
		["github-pat", /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g],
		["private-2go-url", /api\.2go\.live/gi],
		["private-aigateway-url", /api\.aigateway\.sh\/v1/gi],
	];
	const findings = [];
	for (const file of gitFiles()) {
		if (/^(?:node_modules|\.git|packages\/coding-agent\/dist|packages\/[^/]+\/dist)\//.test(file)) continue;
		let text = "";
		try {
			text = read(file);
		} catch {
			continue;
		}
		for (const [kind, pattern] of patterns) {
			pattern.lastIndex = 0;
			const match = pattern.exec(text);
			if (match) {
				if (kind === "openai-style-key" && /^sk-leaked-/i.test(match[0])) continue;
				findings.push({ file, kind, sample: match[0].slice(0, 12) + "<redacted>" });
			}
		}
	}
	return check("privacy:tracked-secret-scan", findings.length === 0, { findings });
}

const checks = [];
const rootPackage = readJson("package.json");
checks.push(
	check("package:root-metadata", rootPackage.name === "repi-monorepo" && rootPackage.private === true && rootPackage.license === "MIT" && rootPackage.repository?.url?.includes("multi-zhangyang/pi-recon-agent") && rootPackage.bugs?.url?.includes("multi-zhangyang/pi-recon-agent/issues") && rootPackage.homepage?.includes("multi-zhangyang/pi-recon-agent") && rootPackage.engines?.node, {
		name: rootPackage.name,
		private: rootPackage.private,
		license: rootPackage.license,
		repository: rootPackage.repository,
		bugs: rootPackage.bugs,
		homepage: rootPackage.homepage,
		engines: rootPackage.engines,
	}),
);
checks.push(check("package:open-source-script", Boolean(rootPackage.scripts?.["gate:open-source-readiness"]), { script: rootPackage.scripts?.["gate:open-source-readiness"] ?? null }));

checks.push(fileCheck("README.md", ["REPI Agent", "快速安装", "模型与 provider 配置", "Harness 与测试", "开源治理", "SECURITY.md", "CONTRIBUTING.md"]));
checks.push(fileCheck("LICENSE", ["MIT License", "REPI Contributors"]));
checks.push(fileCheck("CONTRIBUTING.md", ["贡献指南", "npm run check", "npm run gate:repi-harness", "npm run gate:open-source-readiness"]));
checks.push(fileCheck("SECURITY.md", ["安全政策", "GitHub Security Advisory", "~/.repi/agent", "repi bugreport --stdout"]));
checks.push(fileCheck("CODE_OF_CONDUCT.md", ["行为准则", "不接受", "执行"]));
checks.push(fileCheck("SUPPORT.md", ["支持与反馈", "repi doctor", "repi bugreport --stdout"]));
checks.push(fileCheck(".github/PULL_REQUEST_TEMPLATE.md", ["变更摘要", "npm run check", "npm run gate:open-source-readiness", "安全与隐私"]));
checks.push(fileCheck(".github/dependabot.yml", ["package-ecosystem: npm", "package-ecosystem: github-actions", "version-update:semver-major"]));
checks.push(fileCheck(".github/workflows/repi-harness.yml", ["REPI Independent Harness", "npm run gate:open-source-readiness", "npm run gate:repi-harness", "npm run check"]));
checks.push(fileCheck(".github/ISSUE_TEMPLATE/bug.yml", ["Bug Report", "不要提交 API key 或 token"]));
checks.push(fileCheck(".github/ISSUE_TEMPLATE/contribution.yml", ["Contribution Proposal", "CONTRIBUTING.md"]));

const stalePublicDocs = [/Contributing to pi/i, /pi-mono/i, /security@earendil\.com/i, /pi\.dev/i, /Discord/i, /taksies/i, /Earendil/i];
checks.push(forbiddenCheck("docs:contributing-no-upstream-stale-text", "CONTRIBUTING.md", stalePublicDocs));
checks.push(forbiddenCheck("docs:security-no-upstream-stale-text", "SECURITY.md", stalePublicDocs));
checks.push(secretScan());

const report = {
	kind: "repi-open-source-readiness-report",
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	root,
	ok: checks.every((row) => row.status === "pass"),
	checks,
};

if (json) {
	console.log(JSON.stringify(report, null, 2));
} else {
	console.log("REPI Open Source Readiness Gate");
	for (const row of checks) {
		console.log(`${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
		if (row.status !== "pass") console.log(`  ${JSON.stringify(row.evidence).slice(0, 2000)}`);
	}
	console.log(`verdict: ${report.ok ? "pass" : "fail"}`);
}

process.exit(report.ok || !strict ? 0 : 1);
