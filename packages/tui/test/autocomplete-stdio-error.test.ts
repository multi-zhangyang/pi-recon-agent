import assert from "node:assert";
import { EventEmitter } from "node:events";
import { describe, it } from "node:test";
import { attachChildStdioErrorListeners } from "../src/autocomplete.ts";

describe("attachChildStdioErrorListeners (FIX 3)", () => {
	it("swallows a stdout stream 'error' event without throwing and routes to onError", () => {
		const stdout = new EventEmitter();
		const stderr = new EventEmitter();
		let onErrorCalls = 0;
		attachChildStdioErrorListeners(stdout, stderr, () => {
			onErrorCalls += 1;
		});

		// Emitting 'error' with no listener on a plain EventEmitter throws.
		// The attached swallow listener must prevent the Unhandled 'error' event.
		stdout.emit("error", new Error("EIO"));

		assert.equal(onErrorCalls, 1, "stdout error must route to onError");
	});

	it("swallows a stderr stream 'error' event without throwing and routes to onError", () => {
		const stdout = new EventEmitter();
		const stderr = new EventEmitter();
		let onErrorCalls = 0;
		attachChildStdioErrorListeners(stdout, stderr, () => {
			onErrorCalls += 1;
		});

		stderr.emit("error", new Error("EPIPE"));

		assert.equal(onErrorCalls, 1, "stderr error must route to onError");
	});

	it("does not route anything when no error is emitted (happy path unchanged)", () => {
		const stdout = new EventEmitter();
		const stderr = new EventEmitter();
		let onErrorCalls = 0;
		attachChildStdioErrorListeners(stdout, stderr, () => {
			onErrorCalls += 1;
		});

		stdout.emit("data", "chunk");
		stderr.emit("data", "chunk");

		assert.equal(onErrorCalls, 0, "no error routing on the happy path");
	});
});
