import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

describe("live model contract reporting", () => {
	it("surfaces and redacts terminal provider errors", () => {
		const directory = mkdtempSync(join(tmpdir(), "repi-live-report-"));
		const fakeCli = join(directory, "fake-repi.mjs");
		const secret = "sk-test-live-contract-secret";
		try {
			writeFileSync(
				fakeCli,
				`#!/usr/bin/env node
const errorMessage = "401 Authorization: Bearer " + process.env.REPI_AUTH_TOKEN;
console.log(JSON.stringify({
  type: "agent_end",
  messages: [{ role: "assistant", content: [], stopReason: "error", errorMessage }]
}));
process.exit(1);
`,
				{ mode: 0o700 },
			);
			chmodSync(fakeCli, 0o700);

			const root = resolve(import.meta.dirname, "../../..");
			const result = spawnSync(
				process.execPath,
				[join(root, "scripts/reverse-agent/repi-live-model-contract.mjs"), root, "--json"],
				{
					encoding: "utf8",
					env: {
						...process.env,
						REPI_RUN_LIVE_MODEL: "1",
						REPI_BASE_URL: "https://example.invalid/v1",
						REPI_AUTH_TOKEN: secret,
						REPI_MODEL: "fixture/model",
						REPI_BIN_PATH: fakeCli,
					},
				},
			);

			expect(result.status).toBe(1);
			expect(result.stdout).not.toContain(secret);
			const report = JSON.parse(result.stdout) as {
				cases: Array<{ providerError?: string }>;
			};
			expect(report.cases).toHaveLength(3);
			for (const row of report.cases) {
				expect(row.providerError).toBe("401 Authorization: <redacted>");
			}
		} finally {
			rmSync(directory, { recursive: true, force: true });
		}
	});
});
