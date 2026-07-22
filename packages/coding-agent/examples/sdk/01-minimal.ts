/**
 * Minimal SDK Usage
 *
 * Uses standard resource discovery and the canonical model runtime. Model
 * metadata must come from settings, models.json, REPI_*, or an extension.
 */

import { createAgentSession } from "@pi-recon/repi-coding-agent";

const { session } = await createAgentSession();

try {
	session.subscribe((event) => {
		if (event.type === "message_update" && event.assistantMessageEvent.type === "text_delta") {
			process.stdout.write(event.assistantMessageEvent.delta);
		}
	});

	await session.prompt("What files are in the current directory?");
	session.state.messages.forEach((msg) => {
		console.log(msg);
	});
	console.log();
} finally {
	session.dispose();
}
