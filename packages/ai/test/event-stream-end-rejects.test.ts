import { EventStream } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";

describe("EventStream end(undefined) rejects result()", () => {
	it("rejects when end() is called with no result and no terminal event was pushed", async () => {
		const stream = new EventStream<string, string>(
			(event) => event === "done",
			(event) => event,
		);
		stream.push("a");
		stream.push("b");
		// End without a terminal "done" event and without an explicit result.
		stream.end();

		const consumed: string[] = [];
		for await (const event of stream) {
			consumed.push(event);
		}
		expect(consumed).toEqual(["a", "b"]);

		// Pre-fix: result() hung forever (promise never resolved nor rejected).
		// Post-fix: it rejects with a typed error so callers awaiting result()
		// don't hang.
		await expect(stream.result()).rejects.toThrow(/EventStream ended without a result/);
	});

	it("still resolves result() when end() is given an explicit result", async () => {
		const stream = new EventStream<string, string>(
			(event) => event === "done",
			(event) => event,
		);
		stream.end("explicit");
		await expect(stream.result()).resolves.toBe("explicit");
	});

	it("still resolves result() when a terminal event was pushed before end()", async () => {
		const stream = new EventStream<string, string>(
			(event) => event === "done",
			(event) => event,
		);
		stream.push("done");
		stream.end();
		await expect(stream.result()).resolves.toBe("done");
	});
});
