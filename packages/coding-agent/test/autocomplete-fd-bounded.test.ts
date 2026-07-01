import { describe, expect, it, vi } from "vitest";
import { appendBounded, resolveAutocompleteMaxBytes } from "../../tui/src/autocomplete-buffer.ts";

// opt #174: the fd-path autocomplete child accumulates stdout with no bound.
// --max-results bounds at the source; appendBounded + REPI_AUTOCOMPLETE_MAX_BYTES
// is the defense-in-depth buffer cap. Verify the helper, the cap routing, and
// the --max-results source-bound assertion.

const hoisted = vi.hoisted(() => {
	let capturedArgs: string[] | null = null;
	let pendingLines: string[] = [];
	const getCapturedArgs = () => capturedArgs;
	const setPendingLines = (v: string[]) => {
		pendingLines = v;
	};
	const makeSpawn =
		() =>
		(_cmd: string, args: string[]): unknown => {
			capturedArgs = args;
			const handlers: Record<string, Array<(...a: unknown[]) => void>> = {};
			const fakeChild = {
				exitCode: 0 as number | null,
				stdout: {
					setEncoding: () => undefined,
					on: (ev: string, cb: (...a: unknown[]) => void) => {
						if (handlers[ev] === undefined) handlers[ev] = [];
						handlers[ev].push(cb);
					},
				},
				stderr: {
					on: (ev: string, cb: (...a: unknown[]) => void) => {
						if (handlers[ev] === undefined) handlers[ev] = [];
						handlers[ev].push(cb);
					},
				},
				on: (ev: string, cb: (...a: unknown[]) => void) => {
					if (handlers[ev] === undefined) handlers[ev] = [];
					handlers[ev].push(cb);
				},
				kill: () => true,
			};
			Promise.resolve().then(() => {
				const blob = `${pendingLines.join("\n")}\n`;
				for (let i = 0; i < blob.length; i += 1024) {
					for (const cb of handlers.data ?? []) cb(blob.slice(i, i + 1024));
				}
				for (const cb of handlers.close ?? []) cb(0);
			});
			return fakeChild;
		};
	return { getCapturedArgs, setPendingLines, makeSpawn };
});

vi.mock("child_process", async (importOriginal) => {
	const real = await importOriginal<typeof import("node:child_process")>();
	return { ...real, spawn: hoisted.makeSpawn() as typeof real.spawn };
});

// Import AFTER vi.mock so autocomplete.ts picks up the mocked spawn.
const { walkDirectoryWithFd } = await import("../../tui/src/autocomplete.ts");

describe("appendBounded", () => {
	it("under-cap appends byte-identically", () => {
		const max = 16;
		let acc = "";
		acc = appendBounded(acc, "hello", max);
		acc = appendBounded(acc, " world", max);
		expect(acc).toBe("hello world");
		expect(acc.length).toBeLessThanOrEqual(max);
	});

	it("over-cap stops appending at the cap (final length <= max)", () => {
		const max = 10;
		let acc = "";
		acc = appendBounded(acc, "0123456789ABCDEF", max);
		expect(acc).toBe("0123456789");
		expect(acc.length).toBe(max);
		// further chunks are dropped
		acc = appendBounded(acc, "more", max);
		expect(acc).toBe("0123456789");
		expect(acc.length).toBeLessThanOrEqual(max);
	});

	it("cap reached across multiple chunks", () => {
		const max = 12;
		let acc = "";
		acc = appendBounded(acc, "aaaa", max);
		acc = appendBounded(acc, "bbbb", max);
		acc = appendBounded(acc, "cccccccc", max); // only 4 fit
		expect(acc).toBe("aaaabbbbcccc");
		expect(acc.length).toBe(max);
	});
});

describe("resolveAutocompleteMaxBytes", () => {
	it("defaults to 2 MB when env unset", () => {
		const before = process.env.REPI_AUTOCOMPLETE_MAX_BYTES;
		delete process.env.REPI_AUTOCOMPLETE_MAX_BYTES;
		try {
			expect(resolveAutocompleteMaxBytes()).toBe(2 * 1024 * 1024);
		} finally {
			if (before !== undefined) process.env.REPI_AUTOCOMPLETE_MAX_BYTES = before;
		}
	});

	it("explicit 0 disables (returns undefined)", () => {
		const before = process.env.REPI_AUTOCOMPLETE_MAX_BYTES;
		process.env.REPI_AUTOCOMPLETE_MAX_BYTES = "0";
		try {
			expect(resolveAutocompleteMaxBytes()).toBeUndefined();
		} finally {
			if (before === undefined) delete process.env.REPI_AUTOCOMPLETE_MAX_BYTES;
			else process.env.REPI_AUTOCOMPLETE_MAX_BYTES = before;
		}
	});

	it("explicit positive value wins", () => {
		const before = process.env.REPI_AUTOCOMPLETE_MAX_BYTES;
		process.env.REPI_AUTOCOMPLETE_MAX_BYTES = "4096";
		try {
			expect(resolveAutocompleteMaxBytes()).toBe(4096);
		} finally {
			if (before === undefined) delete process.env.REPI_AUTOCOMPLETE_MAX_BYTES;
			else process.env.REPI_AUTOCOMPLETE_MAX_BYTES = before;
		}
	});
});

describe("walkDirectoryWithFd routing", () => {
	it("spawn args include --max-results (source-bound) and stdout cap is applied", async () => {
		// Emit 200 lines of ~25 bytes each = ~5000 bytes > 256 cap.
		const lines: string[] = [];
		for (let i = 0; i < 200; i += 1) lines.push(`path/entry-${String(i).padStart(6, "0")}.ts`);
		hoisted.setPendingLines(lines);

		const controller = new AbortController();
		const results = await walkDirectoryWithFd(
			"/tmp",
			"fd",
			"",
			100,
			controller.signal,
			256, // explicit small cap
		);

		// Source-bound assertion: --max-results is present with value 100.
		const captured = hoisted.getCapturedArgs();
		expect(captured).not.toBeNull();
		const maxResultsIdx = captured!.indexOf("--max-results");
		expect(maxResultsIdx).toBeGreaterThan(-1);
		expect(captured![maxResultsIdx + 1]).toBe("100");

		// Buffer cap applied: total emitted bytes far exceed the cap, so the
		// cap must have bounded the parsed results to only complete lines that
		// fit within 256 bytes (partial trailing line dropped).
		const totalBytes = results.reduce((n, r) => n + r.path.length + 1, 0);
		expect(totalBytes).toBeLessThanOrEqual(256);
		expect(results.length).toBeGreaterThan(0);
		// No partial entry: every path matches our emitted pattern.
		for (const r of results) {
			expect(r.path).toMatch(/^path\/entry-\d{6}\.ts$/);
		}
	});
});
