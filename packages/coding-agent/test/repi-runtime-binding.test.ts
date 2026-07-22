import { describe, expect, it } from "vitest";
import { assertRuntimeBindings, createRuntimeBinding } from "../src/core/repi/runtime-binding.ts";

describe("REPI runtime binding", () => {
	it("fails with the port name when accessed before initialization", () => {
		const binding = createRuntimeBinding<{ run(): string }>("operator");
		expect(() => binding.get()).toThrow("REPI runtime binding accessed before initialization: operator");
	});

	it("binds exactly once and returns the bound runtime", () => {
		const binding = createRuntimeBinding<{ run(): string }>("swarm-supervisor");
		const runtime = { run: () => "ok" };
		expect(binding.bind(runtime)).toBe(runtime);
		expect(binding.get().run()).toBe("ok");
		expect(() => binding.bind(runtime)).toThrow("REPI runtime binding already initialized: swarm-supervisor");
	});

	it("audits the complete composition root", () => {
		const operator = createRuntimeBinding<object>("operator");
		const delegate = createRuntimeBinding<object>("delegate");
		operator.bind({});
		expect(() => assertRuntimeBindings([operator, delegate])).toThrow("REPI runtime topology incomplete: delegate");
		delegate.bind({});
		expect(() => assertRuntimeBindings([operator, delegate])).not.toThrow();
	});
});
