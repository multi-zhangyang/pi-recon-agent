#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const root = resolve(process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : process.cwd());
const full = process.argv.includes("--full");
const json = process.argv.includes("--json");

const steps = [
	{ id: "doctor", cmd: "node", args: ["scripts/reverse-agent/repi-doctor.mjs", root] },
	{ id: "memory-status", cmd: "node", args: ["scripts/reverse-agent/memory-inspect.mjs", root, "status", "--json"] },
	{ id: "model-doctor", cmd: "node", args: ["scripts/reverse-agent/model-inspect.mjs", root, "doctor", "--json"] },
	{ id: "memory-scoped-gate", cmd: "npm", args: ["run", "gate:memory-isolation-default"] },
	{ id: "shrinkwrap", cmd: "npm", args: ["run", "check:shrinkwrap"] },
	{ id: "ts-imports", cmd: "npm", args: ["run", "check:ts-imports"] },
];
if (full) steps.push({ id: "full-check", cmd: "npm", args: ["run", "check"] });

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
