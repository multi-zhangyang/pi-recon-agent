#!/usr/bin/env node
// repi bootstrap — install the reverse-engineering / pentest toolchain.
//
// Self-contained catalog (no dependency on the agent runtime): each tool is
// probed with `command -v`; missing tools are installed via apt (system) or
// pip (python RE tools) and re-verified. Failures are non-fatal — bootstrap
// is best-effort by design, matching the doctor/smoke graceful philosophy.
//
// Usage:
//   repi bootstrap                      Probe + install everything missing
//   repi bootstrap --dry-run            Show what would run, install nothing
//   repi bootstrap --only gdb,pwntools  Subset
//   repi bootstrap --list               Print the catalog and exit
//   repi bootstrap --yes                Skip the install confirmation prompt
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";

const args = process.argv.slice(2);
const rootArg = args[0] && !args[0].startsWith("--") ? args.shift() : undefined;
const root = resolve(rootArg ?? process.cwd());
const dryRun = args.includes("--dry-run");
const listOnly = args.includes("--list");
const yes = args.includes("--yes") || args.includes("-y");
const help = args.includes("-h") || args.includes("--help");
const onlyArg = args.find((a) => a.startsWith("--only=")) ?? (args.includes("--only") ? args[args.indexOf("--only") + 1] : undefined);
const only = onlyArg ? String(onlyArg).split(",").map((s) => s.trim().toLowerCase()).filter(Boolean) : null;

if (help) {
	process.stdout.write(`repi bootstrap — install the RE/pentest toolchain

Usage:
  repi bootstrap [--dry-run] [--only a,b] [--yes] [--list]

Each tool is probed; missing ones are installed via apt (system tools) or
pip (python RE tools) and re-verified. Failures are non-fatal.

Options:
  --dry-run      Print the commands that would run, install nothing.
  --only a,b     Only consider the listed tool ids.
  --yes, -y      Skip the confirmation prompt before installing.
  --list         Print the catalog and exit.
  -h, --help     Show this help.
`);
	process.exit(0);
}

// --- catalog --------------------------------------------------------------
// apt  : debian/ubuntu package(s) to install (system tool).
// pip  : python package to install (RE tool); installed with
//        pip install --user --break-system-packages.
// bin  : the executable(s) to probe with `command -v`.
const CATALOG = [
	{ id: "binutils", name: "binutils (file/objdump/readelf/nm/strings)", cat: "static", bin: ["file", "objdump", "readelf", "nm", "strings"], apt: ["binutils", "file"] },
	{ id: "gdb", name: "gdb", cat: "dynamic", bin: ["gdb"], apt: ["gdb"] },
	{ id: "strace", name: "strace", cat: "dynamic", bin: ["strace"], apt: ["strace"] },
	{ id: "ltrace", name: "ltrace", cat: "dynamic", bin: ["ltrace"], apt: ["ltrace"] },
	{ id: "ltrace-so", name: "ldd / libc introspection", cat: "dynamic", bin: ["ldd"], apt: ["libc-bin"] },
	{ id: "checksec", name: "checksec (pwntools)", cat: "static", bin: ["checksec"], pip: "pwntools" },
	{ id: "binwalk", name: "binwalk", cat: "firmware", bin: ["binwalk"], pip: "binwalk" },
	{ id: "radare2", name: "radare2", cat: "disasm", bin: ["r2", "radare2"], apt: ["radare2"] },
	{ id: "yara", name: "yara", cat: "malware", bin: ["yara"], apt: ["yara"] },
	{ id: "capa", name: "capa", cat: "malware", bin: ["capa"], pip: "flare-capa" },
	{ id: "floss", name: "floss (string deobfuscation)", cat: "malware", bin: ["floss"], pip: "floss" },
	{ id: "ropgadget", name: "ROPgadget", cat: "exploit", bin: ["ROPgadget"], pip: "ropgadget" },
	{ id: "ropper", name: "ropper", cat: "exploit", bin: ["ropper"], pip: "ropper" },
	{ id: "pwntools", name: "pwntools", cat: "exploit", bin: ["pwn"], pip: "pwntools" },
	{ id: "angr", name: "angr", cat: "symbolic", bin: ["python3"], pip: "angr", note: "angr imports as a python library; probed via python3 availability" },
	{ id: "z3", name: "z3-solver", cat: "symbolic", bin: ["python3"], pip: "z3-solver", note: "z3 imports as a python library" },
	{ id: "volatility3", name: "volatility3", cat: "memory", bin: ["vol", "vol.py"], pip: "volatility3" },
	{ id: "unsquashfs", name: "unsquashfs (squashfs-tools)", cat: "firmware", bin: ["unsquashfs"], apt: ["squashfs-tools"] },
	{ id: "qemu-user", name: "qemu-user (arch emulation)", cat: "emulation", bin: ["qemu-arm", "qemu-aarch64"], apt: ["qemu-user"] },
	{ id: "xxd", name: "xxd / hexdump", cat: "static", bin: ["xxd", "hexdump"], apt: ["xxd", "bsdmainutils"] },
	{ id: "socat", name: "socat", cat: "net", bin: ["socat"], apt: ["socat"] },
	{ id: "nmap", name: "nmap", cat: "net", bin: ["nmap"], apt: ["nmap"] },
	{ id: "masscan", name: "masscan", cat: "net", bin: ["masscan"], apt: ["masscan"] },
	{ id: "ffuf", name: "ffuf", cat: "web", bin: ["ffuf"], apt: ["ffuf"] },
	{ id: "sqlmap", name: "sqlmap", cat: "web", bin: ["sqlmap"], apt: ["sqlmap"] },
	{ id: "nikto", name: "nikto", cat: "web", bin: ["nikto"], apt: ["nikto"] },
	{ id: "tshark", name: "tshark (wireshark-cli)", cat: "net", bin: ["tshark"], apt: ["tshark"] },
	{ id: "frida", name: "frida-tools", cat: "dynamic", bin: ["frida"], pip: "frida-tools" },
];

if (listOnly) {
	for (const t of CATALOG) {
		const method = t.apt ? `apt: ${t.apt.join(", ")}` : `pip: ${t.pip}`;
		process.stdout.write(`${t.id.padEnd(14)} ${t.cat.padEnd(9)} ${t.name}  [${method}]\n`);
	}
	process.exit(0);
}

const selected = only ? CATALOG.filter((t) => only.includes(t.id)) : CATALOG;
if (only && selected.length === 0) {
	process.stderr.write(`no catalog entries matched --only ${onlyArg}\n`);
	process.exit(2);
}

// --- helpers --------------------------------------------------------------
function probe(bin) {
	return bin.some((b) => {
		const r = spawnSync("command", ["-v", b], { encoding: "utf8", shell: true });
		return r.status === 0 && (r.stdout || "").trim().length > 0;
	});
}

const haveApt = probe(["apt-get"]);
const havePip = probe(["pip3", "pip"]);
const isRoot = process.getuid && process.getuid() === 0;
function sudo() {
	return isRoot ? [] : ["sudo"];
}

function aptInstall(pkgs) {
	return [...sudo(), "apt-get", "install", "-y", "--no-install-recommends", ...pkgs];
}
function pipInstall(pkg) {
	return ["pip3", "install", "--user", "--break-system-packages", "--upgrade", pkg];
}

function run(cmd, opts = {}) {
	const r = spawnSync(cmd[0], cmd.slice(1), { encoding: "utf8", stdio: opts.silent ? ["ignore", "pipe", "pipe"] : "inherit", shell: cmd[0] === "sudo" || cmd[0] === "command" ? false : false });
	return r;
}

// --- probe phase ----------------------------------------------------------
const rows = [];
const missing = [];
for (const t of selected) {
	const present = probe(t.bin);
	rows.push({ ...t, present });
	if (!present) missing.push(t);
}

const padId = Math.max(...selected.map((t) => t.id.length));
process.stdout.write("REPI bootstrap — toolchain probe\n\n");
for (const r of rows) {
	process.stdout.write(`  ${r.id.padEnd(padId)}  ${r.present ? "[ok]   " : "[MISS] "} ${r.name}\n`);
}
process.stdout.write(`\n${rows.filter((r) => r.present).length}/${rows.length} present, ${missing.length} missing\n`);

if (missing.length === 0) {
	process.stdout.write("nothing to install — toolchain complete.\n");
	process.exit(0);
}

// --- plan install commands ------------------------------------------------
const aptPkgs = [];
const pipPkgs = [];
const noMethod = [];
for (const t of missing) {
	if (t.apt) aptPkgs.push(...t.apt);
	else if (t.pip) pipPkgs.push(t.pip);
	else noMethod.push(t);
}

const commands = [];
if (aptPkgs.length) {
	commands.push([...sudo(), "apt-get", "update", "-qq"]);
	commands.push(aptInstall([...new Set(aptPkgs)]));
}
for (const p of pipPkgs) commands.push(pipInstall(p));

process.stdout.write("\nPlanned installs:\n");
if (aptPkgs.length) process.stdout.write(`  apt: ${[...new Set(aptPkgs)].join(", ")}\n`);
if (pipPkgs.length) process.stdout.write(`  pip: ${pipPkgs.join(", ")}\n`);
if (noMethod.length) process.stdout.write(`  no auto-install method for: ${noMethod.map((t) => t.id).join(", ")}\n`);
process.stdout.write("\nCommands:\n");
for (const c of commands) process.stdout.write(`  ${c.join(" ")}\n`);

if (!haveApt && aptPkgs.length) {
	process.stdout.write("\nNOTE: apt-get not found on this system; apt installs will be skipped.\n");
}
if (!havePip && pipPkgs.length) {
	process.stdout.write("\nNOTE: pip3 not found on this system; pip installs will be skipped.\n");
}

if (dryRun) {
	process.stdout.write("\n--dry-run: no changes made.\n");
	process.exit(0);
}

// --- confirm + execute ----------------------------------------------------
if (!yes) {
	const { promptYesNo } = await import("./lib/confirm-prompt-helpers.mjs");
	const { answer, timedOut } = promptYesNo("\nProceed with installs? [y/N] ", { timeoutMs: 30000 });
	if (timedOut) {
		process.stderr.write("confirmation prompt timed out after 30s (use --yes to skip)\n");
		process.exit(1);
	}
	if (answer !== "y" && answer !== "yes") {
		process.stdout.write("aborted.\n");
		process.exit(0);
	}
}

const results = [];
for (const c of commands) {
	const isApt = c.includes("apt-get");
	const isPip = c.includes("pip3");
	if ((isApt && !haveApt) || (isPip && !havePip)) {
		process.stdout.write(`  skip (no manager): ${c.join(" ")}\n`);
		continue;
	}
	process.stdout.write(`  run: ${c.join(" ")}\n`);
	try {
		const r = run(c);
		results.push({ cmd: c, status: r.status });
		if (r.status !== 0) process.stdout.write(`    -> exit ${r.status} (non-fatal, continuing)\n`);
	} catch (e) {
		process.stdout.write(`    -> error: ${e.message} (non-fatal, continuing)\n`);
		results.push({ cmd: c, status: -1 });
	}
}

// --- re-verify ------------------------------------------------------------
process.stdout.write("\nRe-verify:\n");
let okCount = 0;
for (const t of missing) {
	const now = probe(t.bin);
	if (now) okCount++;
	process.stdout.write(`  ${t.id.padEnd(padId)}  ${now ? "[ok]   " : "[MISS] "} ${t.name}\n`);
}
process.stdout.write(`\nbootstrap done: ${okCount}/${missing.length} missing tools now present.\n`);
if (noMethod.length) {
	process.stdout.write(`Manual install still needed for: ${noMethod.map((t) => t.id).join(", ")}\n`);
}
process.exit(0);
