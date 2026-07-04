import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const aiSrcIndex = fileURLToPath(new URL("../ai/src/index.ts", import.meta.url));
const aiSrcOAuth = fileURLToPath(new URL("../ai/src/oauth.ts", import.meta.url));
const agentSrcIndex = fileURLToPath(new URL("../agent/src/index.ts", import.meta.url));

const sharedTestConfig = {
	globals: true,
	environment: "node",
	reporters: ["dot" as const],
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
				test: {
					...sharedTestConfig,
					name: "threads",
					include: ["test/**/*.test.ts"],
					exclude: ["test/footer-data-provider.test.ts", "test/package-command-paths.test.ts"],
					pool: "threads",
				},
			},
			{
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
			{ find: /^@pi-recon\/repi-agent-core$/, replacement: agentSrcIndex },
			{ find: /^@mariozechner\/repi-ai$/, replacement: aiSrcIndex },
			{ find: /^@mariozechner\/repi-ai\/oauth$/, replacement: aiSrcOAuth },
			{ find: /^@mariozechner\/repi-agent-core$/, replacement: agentSrcIndex },
		],
	},
});
