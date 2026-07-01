import assert from "node:assert";
import { describe, it } from "node:test";
import { CancellableLoader } from "../src/components/cancellable-loader.ts";
import { Loader } from "../src/components/loader.ts";
import { TUI } from "../src/tui.ts";
import { VirtualTerminal } from "./virtual-terminal.ts";

const identity = (s: string): string => s;

function createTestTUI(): TUI {
	return new TUI(new VirtualTerminal(80, 24));
}

describe("Loader dispose (FIX 4)", () => {
	it("dispose() clears the spinner interval via stop()", () => {
		const loader = new Loader(createTestTUI(), identity, identity, "Working...");
		// Constructor starts the spinner animation, creating a ref'd interval.
		let stopCalls = 0;
		const originalStop = loader.stop.bind(loader);
		loader.stop = () => {
			stopCalls += 1;
			originalStop();
		};

		try {
			assert.equal(typeof loader.dispose, "function", "base Loader must define dispose()");
			(loader as unknown as { dispose: () => void }).dispose();
			assert.equal(stopCalls, 1, "dispose() must call stop() to clear the interval");
		} finally {
			// Defensive cleanup: if dispose is missing/neutered the ref'd spinner
			// interval would keep the process alive (the very leak this fix
			// addresses). Always clear it so the test exits cleanly.
			loader.stop();
		}
	});

	it("dispose() is defined on the base Loader class", () => {
		const loader = new Loader(createTestTUI(), identity, identity, "Working...");
		try {
			assert.equal(typeof loader.dispose, "function");
			(loader as unknown as { dispose: () => void }).dispose();
		} finally {
			loader.stop();
		}
	});
});

describe("CancellableLoader dispose (FIX 1)", () => {
	it("dispose() aborts the AbortController so tied async work cancels", () => {
		const loader = new CancellableLoader(createTestTUI(), identity, identity, "Working...");
		assert.equal(loader.signal.aborted, false, "sanity: not aborted before dispose");

		try {
			loader.dispose();
			assert.equal(loader.signal.aborted, true, "dispose() must abort the controller");
		} finally {
			// Defensive cleanup of the spinner interval.
			loader.stop();
		}
	});

	it("dispose() is idempotent (double dispose does not throw)", () => {
		const loader = new CancellableLoader(createTestTUI(), identity, identity, "Working...");
		try {
			loader.dispose();
			loader.dispose();
			assert.equal(loader.signal.aborted, true);
		} finally {
			loader.stop();
		}
	});
});
