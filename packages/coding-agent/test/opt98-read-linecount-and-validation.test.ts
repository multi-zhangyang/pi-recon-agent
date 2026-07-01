import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ExtensionContext } from "../src/core/extensions/types.ts";
import { createReadToolDefinition } from "../src/core/tools/read.ts";

// opt #98 F4: split("\n") on a file ending in "\n" leaves a trailing "" that
// inflated totalFileLines by 1. The OOB check `startLine >= allLines.length`
// let offset = realLineCount+1 through (slice returned a phantom [""] → empty
// read with no error and no continuation hint), and "Showing N of M" / "more
// lines" notices were off by one. Post-fix the real line count (trailing ""
// popped for endsWith("\n")) drives the OOB check and the notices.
//
// opt #98 F9: offset:0 silently became line 1; limit:0 yielded zero lines then
// fell into the "N more lines" continuation branch with an empty body; limit:<0
// → negative slice → same confusing empty-with-continue. Post-fix clear
// up-front validation errors.

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
	const dir = mkdtempSync(join(tmpdir(), "pi-read-offbyone-"));
	tempDirs.push(dir);
	return dir;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) {
		rmSync(dir, { recursive: true, force: true });
	}
});

function readResultText(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content.map((c) => (c.type === "text" ? (c.text ?? "") : "")).join("");
}

const NO_CTX = undefined as unknown as ExtensionContext;

describe("read tool line-count off-by-one (F4)", () => {
	it("rejects offset one past the last real line with the real line count", async () => {
		const dir = await makeTempDir();
		const file = join(dir, "f.txt");
		writeFileSync(file, "a\nb\nc\n");
		const def = createReadToolDefinition(dir);
		const err = await def
			.execute("call-f4-oob", { path: file, offset: 4 }, undefined, undefined, NO_CTX)
			.catch((e) => e);
		expect(err).toBeInstanceOf(Error);
		expect(String((err as Error).message)).toContain("beyond end of file");
		expect(String((err as Error).message)).toContain("3 lines total");
	});

	it("accepts offset at the last real line", async () => {
		const dir = await makeTempDir();
		const file = join(dir, "f.txt");
		writeFileSync(file, "a\nb\nc\n");
		const def = createReadToolDefinition(dir);
		const result = await def.execute("call-f4-last", { path: file, offset: 3 }, undefined, undefined, NO_CTX);
		// Reading from line 3 to EOF yields "c" plus the file's trailing newline.
		expect(readResultText(result)).toBe("c\n");
	});

	it("truncation notice reports the real line count (of 3000, not of 3001)", async () => {
		const dir = await makeTempDir();
		const file = join(dir, "big.txt");
		// 3000 lines, each ending in "\n" → split yields 3001 entries (phantom "").
		const content = `${Array.from({ length: 3000 }, (_, i) => `line${i}`).join("\n")}\n`;
		writeFileSync(file, content);
		const def = createReadToolDefinition(dir);
		const result = await def.execute("call-f4-trunc", { path: file }, undefined, undefined, NO_CTX);
		const text = readResultText(result);
		expect(text).toContain("of 3000");
		expect(text).not.toContain("of 3001");
	});

	it("user-limit continuation notice reports the real remaining line count", async () => {
		const dir = await makeTempDir();
		const file = join(dir, "lim.txt");
		writeFileSync(file, "a\nb\nc\nd\ne\n");
		const def = createReadToolDefinition(dir);
		const result = await def.execute(
			"call-f4-lim",
			{ path: file, offset: 1, limit: 2 },
			undefined,
			undefined,
			NO_CTX,
		);
		const text = readResultText(result);
		// 5 real lines, read 2 → 3 more lines.
		expect(text).toContain("3 more lines");
		expect(text).not.toContain("4 more lines");
	});
});

describe("read tool invalid offset/limit validation (F9)", () => {
	it("rejects offset:0 with a clear validation error (not silent line 1)", async () => {
		const dir = await makeTempDir();
		const file = join(dir, "f.txt");
		writeFileSync(file, "a\nb\nc\n");
		const def = createReadToolDefinition(dir);
		const err = await def
			.execute("call-f9-off0", { path: file, offset: 0 }, undefined, undefined, NO_CTX)
			.catch((e) => e);
		expect(err).toBeInstanceOf(Error);
		expect(String((err as Error).message)).toMatch(/offset must be/i);
	});

	it("rejects limit:0 with a clear validation error (not empty body + 'more lines')", async () => {
		const dir = await makeTempDir();
		const file = join(dir, "f.txt");
		writeFileSync(file, "a\nb\nc\n");
		const def = createReadToolDefinition(dir);
		const err = await def
			.execute("call-f9-lim0", { path: file, limit: 0 }, undefined, undefined, NO_CTX)
			.catch((e) => e);
		expect(err).toBeInstanceOf(Error);
		const msg = String((err as Error).message);
		expect(msg).toMatch(/limit must be/i);
		// Must NOT be the confusing empty-body + continuation branch.
		expect(msg).not.toMatch(/more lines/);
	});

	it("rejects a negative limit with a clear validation error", async () => {
		const dir = await makeTempDir();
		const file = join(dir, "f.txt");
		writeFileSync(file, "a\nb\nc\n");
		const def = createReadToolDefinition(dir);
		const err = await def
			.execute("call-f9-limneg", { path: file, limit: -5 }, undefined, undefined, NO_CTX)
			.catch((e) => e);
		expect(err).toBeInstanceOf(Error);
		expect(String((err as Error).message)).toMatch(/limit must be/i);
	});

	it("still reads normally for valid offset/limit (behavior-preserving)", async () => {
		const dir = await makeTempDir();
		const file = join(dir, "f.txt");
		writeFileSync(file, "a\nb\nc\nd\n");
		const def = createReadToolDefinition(dir);
		// offset=2, limit past EOF reads lines 2-4 to the end (no continuation notice).
		const result = await def.execute(
			"call-f9-ok",
			{ path: file, offset: 2, limit: 10 },
			undefined,
			undefined,
			NO_CTX,
		);
		expect(readResultText(result)).toBe("b\nc\nd");
	});
});
