#!/usr/bin/env node
import { chmodSync, existsSync, mkdirSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { atomicWriteFile } from "./lib/atomic-file.mjs";

const argv = process.argv.slice(2);
const rootArg = argv[0] && !argv[0].startsWith("-") ? argv.shift() : process.cwd();
const root = resolve(rootArg ?? process.cwd());
const command = (argv.shift() ?? "status").toLowerCase();
const targetArg = argv.find((arg) => !arg.startsWith("-"));
const json = argv.includes("--json");
const agentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const trustPath = join(agentDir, "trust.json");
const CONTEXT_FILE_NAMES = ["AGENTS.md", "AGENTS.MD", "CLAUDE.md", "CLAUDE.MD"];

function canonical(path) {
	const resolved = resolve(path);
	try {
		return realpathSync(resolved);
	} catch {
		return resolved;
	}
}

function readTrust() {
	try {
		const parsed = JSON.parse(readFileSync(trustPath, "utf8"));
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
		return parsed;
	} catch {
		return {};
	}
}

function writeTrust(data) {
	const sorted = {};
	for (const key of Object.keys(data).sort()) {
		const value = data[key];
		if (value === true || value === false || value === null) sorted[key] = value;
	}
	mkdirSync(dirname(trustPath), { recursive: true, mode: 0o700 });
	try {
		chmodSync(dirname(trustPath), 0o700);
	} catch {
		// Best-effort on non-POSIX filesystems.
	}
	// opt #189: atomic temp+rename (mode 0o600 preserved) so a crash/SIGTERM
	// mid-write cannot leave a partially-written trust file → JSON.parse throws
	// on next read → agent treats all project-local files as untrusted until
	// manually repaired. The MAIN trust write was made atomic in the opt #43
	// audit; this separate maintenance/repair script mutates the SAME trust file
	// but was still bare writeFileSync (truncate-then-write). Reuses the opt #176
	// atomicWriteFile helper (temp+rename, same-dir, mode-preserved,
	// unlink-on-error). Post-write chmod enforces 0o600 even if the existing-mode
	// preservation branch kept a looser mode.
	atomicWriteFile(trustPath, `${JSON.stringify(sorted, null, 2)}\n`, 0o600);
	try {
		chmodSync(trustPath, 0o600);
	} catch {
		// Best-effort on non-POSIX filesystems.
	}
}

function nearestMarkerDir(start, markerCheck) {
	let current = canonical(start);
	while (true) {
		if (markerCheck(current)) return current;
		const parent = dirname(current);
		if (parent === current) return undefined;
		current = parent;
	}
}

function nearestGitRoot(start) {
	return nearestMarkerDir(start, (dir) => existsSync(join(dir, ".git")));
}

function nearestContextRoot(start) {
	return nearestMarkerDir(start, (dir) => {
		if (existsSync(join(dir, ".repi"))) return true;
		if (existsSync(join(dir, ".agents", "skills"))) return true;
		return CONTEXT_FILE_NAMES.some((name) => existsSync(join(dir, name)));
	});
}

function aliasesFor(path, options = {}) {
	const aliases = new Set();
	const targetPath = canonical(path);
	aliases.add(targetPath);
	if (options.includePwdAlias && process.env.PWD) {
		const pwdPath = canonical(process.env.PWD);
		if (pwdPath === targetPath) aliases.add(pwdPath);
	}
	const gitRoot = nearestGitRoot(path);
	if (gitRoot) aliases.add(gitRoot);
	const contextRoot = nearestContextRoot(path);
	if (contextRoot) aliases.add(contextRoot);
	return Array.from(aliases);
}

function lookup(data, path) {
	let current = canonical(path);
	while (true) {
		const value = data[current];
		if (value === true || value === false) return { decision: value, matched: current };
		const parent = dirname(current);
		if (parent === current) return { decision: null, matched: null };
		current = parent;
	}
}

function hasProjectTrustInputs(path) {
	return Boolean(nearestContextRoot(path));
}

const targetWasExplicit = Boolean(targetArg);
const target = canonical(targetArg ?? process.env.PWD ?? process.cwd());
const data = readTrust();
const current = lookup(data, target);
const aliasOptions = { includePwdAlias: !targetWasExplicit };

function finish(report, exitCode = 0) {
	if (json) console.log(JSON.stringify(report, null, 2));
	else {
		console.log(`REPI Trust ${report.action}`);
		console.log(`path: ${report.path}`);
		console.log(`trustStore: ${report.trustPath}`);
		console.log(`decision: ${report.decision === null ? "unset" : report.decision ? "trusted" : "untrusted"}`);
		if (report.matched) console.log(`matched: ${report.matched}`);
		if (report.effectiveTrusted !== undefined) console.log(`effectiveTrusted: ${report.effectiveTrusted ? "yes" : "no"}`);
		if (report.aliases?.length) console.log(`aliases: ${report.aliases.join(", ")}`);
		if (report.message) console.log(report.message);
	}
	process.exit(exitCode);
}

if (["status", "show", "doctor"].includes(command)) {
	finish({
		kind: "repi-trust-report",
		action: "status",
		root,
		path: target,
		trustPath,
		decision: current.decision,
		matched: current.matched,
		effectiveTrusted: current.decision === true || (!hasProjectTrustInputs(target) && current.decision !== false),
		projectTrustInputs: hasProjectTrustInputs(target),
		aliases: aliasesFor(target, aliasOptions),
	});
}

if (["yes", "trust", "trusted", "allow", "on"].includes(command)) {
	const aliases = aliasesFor(target, aliasOptions);
	for (const key of aliases) data[key] = true;
	writeTrust(data);
	finish({ kind: "repi-trust-report", action: "saved", root, path: target, trustPath, decision: true, matched: target, effectiveTrusted: true, aliases, message: "Saved trusted decision. Restart or /reload if a session is already open." });
}

if (["no", "untrust", "deny", "off"].includes(command)) {
	const aliases = aliasesFor(target, aliasOptions);
	for (const key of aliases) data[key] = false;
	writeTrust(data);
	finish({ kind: "repi-trust-report", action: "saved", root, path: target, trustPath, decision: false, matched: target, effectiveTrusted: false, aliases, message: "Saved untrusted decision." });
}

if (["clear", "unset", "reset"].includes(command)) {
	const aliases = aliasesFor(target, aliasOptions);
	for (const key of aliases) delete data[key];
	writeTrust(data);
	const next = lookup(data, target);
	finish({ kind: "repi-trust-report", action: "cleared", root, path: target, trustPath, decision: next.decision, matched: next.matched, effectiveTrusted: next.decision === true || (!hasProjectTrustInputs(target) && next.decision !== false), aliases });
}

console.error(`Unknown repi trust command: ${command}`);
console.error("Usage: repi trust [status|yes|no|clear] [path] [--json]");
process.exit(2);
