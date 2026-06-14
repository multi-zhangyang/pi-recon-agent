#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : process.cwd());
const full = process.argv.includes("--full");
const json = process.argv.includes("--json");
const scriptDir = dirname(fileURLToPath(import.meta.url));

function script(name) {
	const sourcePath = join(root, "scripts", "reverse-agent", name);
	if (existsSync(sourcePath)) return sourcePath;
	return join(scriptDir, name);
}

const repiPath = existsSync(join(root, "repi")) ? join(root, "repi") : "repi";
const steps = [
	{ id: "doctor", cmd: "node", args: [script("repi-doctor.mjs"), root] },
	{ id: "memory-status", cmd: "node", args: [script("memory-inspect.mjs"), root, "status", "--json"] },
	{ id: "model-doctor", cmd: "node", args: [script("model-inspect.mjs"), root, "doctor", "--json"] },
	{ id: "launcher-help", cmd: repiPath, args: ["--offline", "--help"] },
	{ id: "launcher-list-models", cmd: repiPath, args: ["--offline", "--list-models"] },
];
if (full) steps.push({ id: "full-check", cmd: "npm", args: ["run", "check"], timeout: 180_000 });

function runStep(step) {
	const startedAt = Date.now();
	const result = spawnSync(step.cmd, step.args, {
		cwd: root,
		env: {
			...process.env,
			REPI_OFFLINE: "1",
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
		},
		encoding: "utf8",
		timeout: step.timeout ?? (full ? 120_000 : 45_000),
		maxBuffer: 4 * 1024 * 1024,
	});
	return {
		id: step.id,
		cmd: [step.cmd, ...step.args].join(" "),
		exit: result.status ?? 1,
		ms: Date.now() - startedAt,
		stdoutTail: (result.stdout ?? "").slice(-1600),
		stderrTail: (result.stderr ?? "").slice(-1600),
		error: result.error ? String(result.error.message || result.error) : undefined,
	};
}

const rows = [];
for (const step of steps) {
	if (!json) console.log(`RUN ${step.id}: ${step.cmd} ${step.args.join(" ")}`);
	const row = runStep(step);
	rows.push(row);
	if (!json) console.log(`${row.exit === 0 ? "PASS" : "FAIL"} ${row.id} exit=${row.exit} ms=${row.ms}`);
	if (row.exit !== 0) break;
}

const report = { kind: "repi-smoke-report", schemaVersion: 1, generatedAt: new Date().toISOString(), root, full, ok: rows.every((row) => row.exit === 0) && rows.length === steps.length, rows };
if (json) console.log(JSON.stringify(report, null, 2));
else console.log(`verdict: ${report.ok ? "pass" : "fail"}`);
process.exit(report.ok ? 0 : 1);
