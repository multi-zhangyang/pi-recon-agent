import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const aiSrcIndex = fileURLToPath(new URL("../ai/src/index.ts", import.meta.url));
const aiSrcOAuth = fileURLToPath(new URL("../ai/src/oauth.ts", import.meta.url));
const aiSrcCompat = fileURLToPath(new URL("../ai/src/compat.ts", import.meta.url));
const agentSrcIndex = fileURLToPath(new URL("../agent/src/index.ts", import.meta.url));
const testModelCatalogSetup = fileURLToPath(new URL("./test/model-catalog-fixture.ts", import.meta.url));
const reconE2EFiles =
	process.env.REPI_RUN_RECON_E2E === "1"
		? ["test/recon-profile-full-chain.e2e.ts", "test/repi-goal-print.e2e.ts"]
		: [];

const sharedTestConfig = {
	globals: true,
	environment: "node",
	reporters: ["dot" as const],
	setupFiles: [testModelCatalogSetup],
	testTimeout: 30000,
	server: {
		deps: {
			external: [/@silvia-odwyer\/photon-node/],
		},
	},
};

export default defineConfig({
	test: {
		...sharedTestConfig,
		projects: [
			{
				extends: true,
				test: {
					...sharedTestConfig,
					name: "threads",
					include: ["test/**/*.test.ts", ...reconE2EFiles],
					exclude: ["test/footer-data-provider.test.ts", "test/package-command-paths.test.ts"],
					pool: "threads",
				},
			},
			{
				extends: true,
				test: {
					...sharedTestConfig,
					name: "forks",
					include: ["test/footer-data-provider.test.ts", "test/package-command-paths.test.ts"],
					pool: "forks",
				},
			},
		],
	},
	resolve: {
		alias: [
			{ find: /^@pi-recon\/repi-ai$/, replacement: aiSrcIndex },
			{ find: /^@pi-recon\/repi-ai\/oauth$/, replacement: aiSrcOAuth },
			{ find: /^@pi-recon\/repi-ai\/compat$/, replacement: aiSrcCompat },
			{ find: /^@pi-recon\/repi-agent-core$/, replacement: agentSrcIndex },
			{ find: /^@mariozechner\/repi-ai$/, replacement: aiSrcIndex },
			{ find: /^@mariozechner\/repi-ai\/oauth$/, replacement: aiSrcOAuth },
			{ find: /^@mariozechner\/repi-ai\/compat$/, replacement: aiSrcCompat },
			{ find: /^@mariozechner\/repi-agent-core$/, replacement: agentSrcIndex },
		],
	},
});
