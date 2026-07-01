#!/usr/bin/env node
// repi uninstall — remove the REPI launcher (and optionally runtime/source).
//
// SAFE BY DEFAULT: prints what WOULD be removed and exits without changing
// anything. Pass --apply to actually remove. Never touches upstream `pi` or
// ~/.pi — REPI only manages its own launcher, runtime, and (if you ask) the
// source checkout it installed.
//
// Usage:
//   repi uninstall                       Dry-run: list what would be removed.
//   repi uninstall --apply               Remove the launcher symlink(s).
//   repi uninstall --apply --purge       Also remove ~/.repi/agent runtime.
//   repi uninstall --apply --source <dir>  Also remove a source checkout.
//   repi uninstall --yes                 Skip the confirmation prompt.
import { lstatSync, readlinkSync, rmSync, existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

const args = process.argv.slice(2);
const rootArg = args[0] && !args[0].startsWith("--") ? args.shift() : undefined;
const root = resolve(rootArg ?? process.cwd());
const apply = args.includes("--apply");
const purge = args.includes("--purge");
const yes = args.includes("--yes") || args.includes("-y");
const help = args.includes("-h") || args.includes("--help");
const sourceIdx = args.indexOf("--source");
const sourceArg = sourceIdx >= 0 ? args[sourceIdx + 1] : null;

if (help) {
	process.stdout.write(`repi uninstall — remove the REPI launcher (and optionally runtime/source)

Usage:
  repi uninstall [--apply] [--purge] [--source <dir>] [--yes]

SAFE BY DEFAULT: lists what would be removed and changes nothing unless
--apply is given. Never touches upstream \`pi\` or ~/.pi.

Options:
  --apply          Actually perform the removal (default is dry-run).
  --purge          Also remove the ~/.repi/agent runtime directory.
  --source <dir>   Also remove this source checkout (explicit; never auto-detected).
  --yes, -y        Skip the confirmation prompt.
  -h, --help       Show this help.
`);
	process.exit(0);
}

const home = homedir();
const agentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(home, ".repi", "agent");
const candidateLaunchers = [
	join(home, ".local", "bin", "repi"),
	"/usr/local/bin/repi",
];

// Only consider a launcher entry if it is a symlink (REPI installs a symlink).
// A real file at /usr/local/bin/repi could be an npm-installed binary or
// something else — do not remove files we did not create.
function launcherTarget(p) {
	try {
		const st = lstatSync(p);
		if (st.isSymbolicLink()) return realpathSync(p);
	} catch {}
	return null;
}

const targets = [];
for (const p of candidateLaunchers) {
	const target = launcherTarget(p);
	if (target) targets.push({ kind: "launcher", path: p, target });
}

const runtimeItems = [];
if (existsSync(agentDir)) runtimeItems.push({ kind: "runtime", path: agentDir });

const sourceItems = [];
if (sourceArg) {
	const src = resolve(sourceArg);
	if (existsSync(src) && existsSync(join(src, "repi")) && existsSync(join(src, ".git"))) {
		sourceItems.push({ kind: "source", path: src });
	} else if (existsSync(src)) {
		sourceItems.push({ kind: "source", path: src, warn: "does not look like a REPI checkout (no repi/ or .git/) — refusing" });
	} else {
		sourceItems.push({ kind: "source", path: src, warn: "not found" });
	}
}

// --- report ---------------------------------------------------------------
function describe() {
	process.stdout.write("REPI uninstall — removal plan\n\n");
	process.stdout.write("Launcher symlink(s):\n");
	if (targets.length === 0) process.stdout.write("  (none found)\n");
	for (const t of targets) process.stdout.write(`  ${t.path} -> ${t.target}\n`);

	process.stdout.write("\nRuntime (~/.repi/agent):\n");
	if (runtimeItems.length === 0) process.stdout.write("  (none found)\n");
	else for (const r of runtimeItems) process.stdout.write(`  ${r.path}  ${purge ? "[will remove with --purge]" : "[kept unless --purge]"}\n`);

	process.stdout.write("\nSource checkout:\n");
	if (!sourceArg) process.stdout.write("  (not specified; pass --source <dir> to remove a checkout)\n");
	else for (const s of sourceItems) process.stdout.write(`  ${s.path}${s.warn ? `  — ${s.warn}` : "  [will remove]"}\n`);

	process.stdout.write("\nNever touched (REPI does not manage these):\n");
	process.stdout.write("  upstream `pi` binary / ~/.pi / pi runtime and config\n");
}

describe();

if (!apply) {
	process.stdout.write("\nDry-run: no changes made. Pass --apply to remove the launcher symlink(s).\n");
	process.exit(0);
}

// --- build removal list ---------------------------------------------------
const removeList = [];
for (const t of targets) removeList.push(t.path);
if (purge) for (const r of runtimeItems) removeList.push(r.path);
for (const s of sourceItems) if (!s.warn) removeList.push(s.path);

if (removeList.length === 0) {
	process.stdout.write("\nNothing to remove.\n");
	process.exit(0);
}

// Safety: refuse to remove anything that resolves into ~/.pi or the upstream pi.
const piHome = join(home, ".pi");
function isForbidden(p) {
	try {
		const rp = realpathSync(p);
		if (rp === piHome || rp.startsWith(piHome + "/")) return true;
		if (rp === join(home, ".pi")) return true;
	} catch {}
	return false;
}
for (const p of removeList) {
	if (isForbidden(p)) {
		process.stderr.write(`REFUSING to remove ${p}: resolves into ~/.pi (upstream pi). Aborting.\n`);
		process.exit(2);
	}
}

if (!yes) {
	const { promptYesNo } = await import("./lib/confirm-prompt-helpers.mjs");
	process.stdout.write(`\nAbout to remove ${removeList.length} item(s):\n`);
	for (const p of removeList) process.stdout.write(`  ${p}\n`);
	const { answer, timedOut } = promptYesNo("Proceed? [y/N] ", { timeoutMs: 30000 });
	if (timedOut) {
		process.stderr.write("confirmation prompt timed out after 30s (use --yes to skip)\n");
		process.exit(1);
	}
	if (answer !== "y" && answer !== "yes") {
		process.stdout.write("aborted.\n");
		process.exit(0);
	}
}

// --- execute --------------------------------------------------------------
for (const p of removeList) {
	try {
		rmSync(p, { recursive: true, force: true });
		process.stdout.write(`  removed: ${p}\n`);
	} catch (e) {
		process.stdout.write(`  failed:  ${p} — ${e.message}\n`);
	}
}

process.stdout.write("\nREPI launcher removed. Upstream `pi` and ~/.pi were not touched.\n");
process.exit(0);
