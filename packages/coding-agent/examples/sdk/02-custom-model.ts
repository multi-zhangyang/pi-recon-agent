/**
 * Custom Model Selection
 *
 * Shows how to select a specific model and thinking level.
 */

import { AuthStorage, createAgentSession, ModelRuntime } from "@pi-recon/repi-coding-agent";

// ModelRuntime reads only explicit ~/.repi/agent/models.json and REPI_* configuration.
const authStorage = AuthStorage.create();
const modelRuntime = await ModelRuntime.create({ credentials: authStorage.asCredentialStore() });

// Option 1: Find a model explicitly declared by the host.
const configuredModel = modelRuntime.getModel("my-provider", "my-model");
if (configuredModel) {
	console.log(`Found model: ${configuredModel.provider}/${configuredModel.id}`);
}

// Option 2: Pick from explicitly configured models that have usable credentials.
const available = await modelRuntime.getAvailable();
console.log(
	"Available models:",
	available.map((m) => `${m.provider}/${m.id}`),
);

const model = configuredModel ?? available[0];
if (model) {
	const { session } = await createAgentSession({
		model,
		thinkingLevel: "medium", // off, low, medium, high
		authStorage,
		modelRuntime,
	});

	try {
		session.subscribe((event) => {
			if (event.type === "message_update" && event.assistantMessageEvent.type === "text_delta") {
				process.stdout.write(event.assistantMessageEvent.delta);
			}
		});

		await session.prompt("Say hello in one sentence.");
		console.log();
	} finally {
		session.dispose();
	}
} else {
	console.log("Configure a model with models.json or REPI_* before running this example.");
}
