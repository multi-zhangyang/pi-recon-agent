export type RuntimeBinding<T> = {
	readonly name: string;
	bind(runtime: T): T;
	get(): T;
	isBound(): boolean;
};

export function createRuntimeBinding<T>(name: string): RuntimeBinding<T> {
	const state: { runtime?: T } = {};
	return {
		name,
		bind(runtime) {
			if (state.runtime !== undefined) throw new Error(`REPI runtime binding already initialized: ${name}`);
			state.runtime = runtime;
			return runtime;
		},
		get() {
			if (state.runtime === undefined)
				throw new Error(`REPI runtime binding accessed before initialization: ${name}`);
			return state.runtime;
		},
		isBound() {
			return state.runtime !== undefined;
		},
	};
}

export function assertRuntimeBindings(bindings: ReadonlyArray<RuntimeBinding<unknown>>): void {
	const missing = bindings.filter((binding) => !binding.isBound()).map((binding) => binding.name);
	if (missing.length > 0) throw new Error(`REPI runtime topology incomplete: ${missing.join(", ")}`);
}
