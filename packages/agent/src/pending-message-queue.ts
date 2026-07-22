import type { QueueMode } from "./types.ts";

/**
 * Queue with an explicit delivery phase.
 *
 * Draining moves items to `inFlight`; the loop claims each item at the delivery
 * boundary, and callers acknowledge it after durable handling. A failed or
 * interrupted run can then restore unacknowledged items without exposing
 * in-flight items as still pending.
 */
export class PendingMessageQueue<T> {
	public mode: QueueMode;
	private pending: T[] = [];
	private inFlight: T[] = [];
	private delivering: T[] = [];
	private cancelled = new Map<T, number>();

	constructor(mode: QueueMode) {
		this.mode = mode;
	}

	enqueue(item: T): void {
		this.pending.push(item);
	}

	hasItems(): boolean {
		return this.pending.length > 0;
	}

	/** Return only items that have not yet been handed to the consumer. */
	snapshot(): T[] {
		return this.pending.slice();
	}

	/** Move the next batch into the in-flight phase. */
	drain(): T[] {
		if (this.pending.length === 0) return [];

		const drained = this.mode === "all" ? this.pending.splice(0) : [this.pending.shift()!];
		this.inFlight.push(...drained);
		return drained;
	}

	/** Mark an item as durably handled. Identity is intentional here. */
	acknowledge(item: T): void {
		const deliveringIndex = this.delivering.indexOf(item);
		if (deliveringIndex >= 0) this.delivering.splice(deliveringIndex, 1);
		else {
			const inFlightIndex = this.inFlight.indexOf(item);
			if (inFlightIndex >= 0) this.inFlight.splice(inFlightIndex, 1);
		}
		this.consumeCancellation(item);
	}

	isInFlight(item: T): boolean {
		return this.inFlight.includes(item);
	}

	/** Mark the synchronous boundary after which clear() cannot retract an item. */
	beginDelivery(item: T): void {
		const index = this.inFlight.indexOf(item);
		if (index < 0) return;
		this.inFlight.splice(index, 1);
		this.delivering.push(item);
	}

	/** Consume a cancellation marker for a batch already handed to a loop. */
	consumeCancellation(item: T): boolean {
		const count = this.cancelled.get(item);
		if (count === undefined) return false;
		if (count === 1) this.cancelled.delete(item);
		else this.cancelled.set(item, count - 1);
		return true;
	}

	clearCancellationMarkers(): void {
		this.cancelled.clear();
	}

	/** Return unacknowledged items to the front of the pending queue. */
	restoreUnacknowledged(): T[] {
		if (this.delivering.length === 0 && this.inFlight.length === 0) return [];
		const restored = [...this.delivering, ...this.inFlight];
		this.pending = [...restored, ...this.pending];
		this.delivering = [];
		this.inFlight = [];
		return restored;
	}

	/** Drop retractable items and invalidate any batch still held by the loop. */
	clear(): T[] {
		const cleared = [...this.inFlight, ...this.pending];
		for (const item of this.inFlight) {
			this.cancelled.set(item, (this.cancelled.get(item) ?? 0) + 1);
		}
		this.pending = [];
		this.inFlight = [];
		// `beginDelivery()` is the commit barrier: once a consumer has crossed it,
		// clear cannot know whether durable handling already started. Keep those
		// items tracked so message_end can acknowledge them, or run settlement can
		// restore them if delivery fails before the durable boundary completes.
		return cleared;
	}
}
