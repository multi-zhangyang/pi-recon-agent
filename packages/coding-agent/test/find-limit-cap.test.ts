import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";

// Foundational opt #264: the find tool's `limit` arg is a bare Type.Number
// with NO upper bound. A model passing `limit:1e8` made fd emit up to 100M
// paths, each pushed into the `lines` array via rl.on("line") BEFORE the close
// handler truncates → OOM (the agent-core tool-result cap #15/#33 only trims
// what reaches the model AFTER the tool returns; it does not bound the tool's
// own in-memory array). Same class as grep opt #262. Cap env-overridable
// (REPI_FIND_MAX_LIMIT, default 10000, 0 disables).

vi.mock("../src/core/utils/tools-manager.ts", () => ({
	ensureTool: vi.fn(async () => "/fake/fd"),
}));

vi.mock("child_process", async (importActual) => {
	const actual = await importActual<typeof import("child_process")>();
	return { ...actual, spawn: vi.fn() };
});

const { spawn } = await import("child_process");
const { createFindToolDefinition } = await import("../src/core/tools/find.ts");

function makeFakeChild(): EventEmitter & {
	stdout: PassThrough;
	stderr: PassThrough;
	killed: boolean;
	kill: () => boolean;
} {
	const stdout = new PassThrough();
	const stderr = new PassThrough();
	const child = Object.assign(new EventEmitter(), {
		stdout,
		stderr,
		killed: false,
		kill() {
			this.killed = true;
			return true;
		},
	});
	return child as ReturnType<typeof makeFakeChild>;
}

describe("find limit cap (opt #264)", () => {
	afterEach(() => {
		vi.mocked(spawn).mockReset();
		delete process.env.REPI_FIND_MAX_LIMIT;
	});

	it("caps an absurd limit so fd's --max-results and the in-memory lines array stay bounded", async () => {
		process.env.REPI_FIND_MAX_LIMIT = "5";
		const fakeChild = makeFakeChild();
		vi.mocked(spawn).mockReturnValue(fakeChild as never);

		const def = createFindToolDefinition(process.cwd());

		// Request an absurd limit; emit 12 matches. The cap clamps effectiveLimit
		// to 5 → fd is launched with --max-results 5 and the close handler's
		// resultLimitReached notice names 5 (not 1e8).
		const promise = def.execute(
			"call-cap",
			{ pattern: "*.ts", path: ".", limit: 1_000_000 },
			undefined,
			undefined,
			undefined as never,
		);
		await new Promise<void>((r) => setImmediate(r));

		for (let i = 1; i <= 12; i++) {
			fakeChild.stdout.emit("data", Buffer.from(`file${i}.ts\n`));
		}
		await new Promise<void>((r) => setTimeout(r, 10));
		fakeChild.emit("close", 0);

		const result = await Promise.race([
			promise,
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("find promise hung")), 15_000)),
		]);

		expect(result).not.toBeInstanceOf(Error);
		const text = (result as { content: { type: string; text: string }[] }).content[0].text;
		// The limit was capped at 5 → the resultLimitReached notice names 5.
		expect(text).toMatch(/5 results limit reached/);
		// The fd --max-results arg was capped at 5 (the spawn args carry "5", not
		// "1000000") — assert via the captured spawn call.
		const spawnArgs = vi.mocked(spawn).mock.calls[0]?.[1] as string[];
		const maxResultsIdx = spawnArgs.indexOf("--max-results");
		expect(maxResultsIdx).toBeGreaterThan(-1);
		expect(spawnArgs[maxResultsIdx + 1]).toBe("5");
	});

	it("REPI_FIND_MAX_LIMIT=0 disables the cap (passes the requested limit through)", async () => {
		process.env.REPI_FIND_MAX_LIMIT = "0";
		const fakeChild = makeFakeChild();
		vi.mocked(spawn).mockReturnValue(fakeChild as never);

		const def = createFindToolDefinition(process.cwd());

		const promise = def.execute(
			"call-nocap",
			{ pattern: "*.ts", path: ".", limit: 999_999 },
			undefined,
			undefined,
			undefined as never,
		);
		await new Promise<void>((r) => setImmediate(r));
		fakeChild.stdout.emit("data", Buffer.from("file1.ts\n"));
		await new Promise<void>((r) => setTimeout(r, 10));
		fakeChild.emit("close", 0);

		const result = await Promise.race([
			promise,
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("find promise hung")), 15_000)),
		]);
		expect(result).not.toBeInstanceOf(Error);
		// 0 disables the cap → the requested 999999 is passed through to fd.
		const spawnArgs = vi.mocked(spawn).mock.calls[0]?.[1] as string[];
		const maxResultsIdx = spawnArgs.indexOf("--max-results");
		expect(spawnArgs[maxResultsIdx + 1]).toBe("999999");
	});
});
