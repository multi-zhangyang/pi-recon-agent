import type { AgentEvent } from "../types.ts";

export type AgentEventSink = (event: AgentEvent) => Promise<void> | void;

/** Event delivery failed after the loop finished balancing the active tool batch. */
export class AgentEventDeliveryError extends Error {
	readonly errors: readonly unknown[];

	constructor(errors: readonly unknown[], relatedError?: unknown) {
		const captured = [...errors];
		const causes = relatedError === undefined ? captured : [relatedError, ...captured];
		const cause = causes.length === 1 ? causes[0] : new AggregateError(causes, "Agent run and event delivery failed");
		super(`Agent event delivery failed (${captured.length} error${captured.length === 1 ? "" : "s"})`, { cause });
		this.name = "AgentEventDeliveryError";
		this.errors = captured;
	}
}

export async function emitAndCollectFailure(
	event: AgentEvent,
	emit: AgentEventSink,
	deliveryErrors: unknown[],
): Promise<void> {
	try {
		await emit(event);
	} catch (error) {
		deliveryErrors.push(error);
	}
}
