/**
 * Small insertion-ordered LRU used for process-local REPI caches.
 *
 * REPI can stay alive for many RPC jobs. A plain Map keyed by artifact paths
 * would retain every path ever seen, even after its session is gone. Keeping a
 * fixed entry bound preserves the fast-path for active jobs while making the
 * retention cost predictable. Values are intentionally not cloned or
 * truncated; eviction only affects a later cache miss.
 */
export class LruCache<K, V> {
	private readonly entries = new Map<K, V>();
	private readonly maxEntries: number;

	constructor(maxEntries: number) {
		this.maxEntries = Number.isFinite(maxEntries) ? Math.max(0, Math.floor(maxEntries)) : 0;
	}

	get size(): number {
		return this.entries.size;
	}

	get(key: K): V | undefined {
		if (!this.entries.has(key)) return undefined;
		const value = this.entries.get(key) as V;
		this.promote(key, value);
		return value;
	}

	has(key: K): boolean {
		if (!this.entries.has(key)) return false;
		const value = this.entries.get(key) as V;
		this.promote(key, value);
		return true;
	}

	set(key: K, value: V): void {
		if (this.maxEntries === 0) return;
		this.entries.delete(key);
		while (this.entries.size >= this.maxEntries) {
			const oldest = this.entries.keys().next();
			if (oldest.done) break;
			this.entries.delete(oldest.value);
		}
		this.entries.set(key, value);
	}

	delete(key: K): boolean {
		return this.entries.delete(key);
	}

	clear(): void {
		this.entries.clear();
	}

	private promote(key: K, value: V): void {
		this.entries.delete(key);
		this.entries.set(key, value);
	}
}
