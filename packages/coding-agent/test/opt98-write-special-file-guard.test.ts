import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ExtensionContext } from "../src/core/extensions/types.ts";
import { createWriteToolDefinition } from "../src/core/tools/write.ts";

// opt #98 F6: the write tool had NO special-file guard. atomicWriteFile writes
// a temp regular file then renames it over the target; `rename(temp, fifo)`
// REPLACES the FIFO entry with a regular file — silently destroying a named
// pipe (or socket/device). Post-fix write.ts stats the target before mkdir and
// rejects non-regular files with the same "device/FIFO/socket — use bash
// instead" message the edit/read tools use, so the FIFO is left intact.

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
	const dir = mkdtempSync(join(tmpdir(), "pi-write-special-"));
	tempDirs.push(dir);
	return dir;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) {
		rmSync(dir, { recursive: true, force: true });
	}
});

async function rejectAfter(ms: number): Promise<never> {
	return new Promise((_, reject) => setTimeout(() => reject(new Error("write did not reject (hung)")), ms));
}

const NO_CTX = undefined as unknown as ExtensionContext;

describe("write tool special-file guard (F6)", () => {
	it("rejects a FIFO target and leaves the FIFO intact (no silent replacement)", async () => {
		if (process.platform === "win32") return; // mkfifo unavailable
		const dir = await makeTempDir();
		const fifo = join(dir, "named-pipe");
		spawnSync("mkfifo", [fifo]);
		if (!existsSync(fifo)) return; // mkfifo unavailable — skip gracefully

		const def = createWriteToolDefinition(dir);
		const err = await Promise.race([
			def.execute("call-f6", { path: fifo, content: "x" }, undefined, undefined, NO_CTX).catch((e) => e),
			rejectAfter(4000),
		]);

		expect(err).toBeInstanceOf(Error);
		const msg = String((err as Error).message);
		expect(msg).toMatch(/not a regular file/i);
		expect(msg).toMatch(/device|FIFO|socket/i);
		expect(msg).toContain("bash");
		// The FIFO entry must still be a FIFO (not replaced by a regular file).
		expect(existsSync(fifo)).toBe(true);
		expect(lstatSync(fifo).isFIFO()).toBe(true);
	});

	it("rejects a directory target with a directory hint", async () => {
		const dir = await makeTempDir();
		const sub = join(dir, "subdir");
		mkdirSync(sub, { recursive: true });
		if (!existsSync(sub)) return;
		const def = createWriteToolDefinition(dir);
		const err = await Promise.race([
			def.execute("call-f6-dir", { path: sub, content: "x" }, undefined, undefined, NO_CTX).catch((e) => e),
			rejectAfter(4000),
		]);
		expect(err).toBeInstanceOf(Error);
		expect(String((err as Error).message)).toMatch(/directory/i);
	});

	it("still writes a regular new file (behavior-preserving)", async () => {
		const dir = await makeTempDir();
		const file = join(dir, "new.txt");
		const def = createWriteToolDefinition(dir);
		const result = await Promise.race([
			def.execute("call-f6-ok", { path: file, content: "hello\n" }, undefined, undefined, NO_CTX),
			rejectAfter(4000),
		]);
		const text = (result as { content: Array<{ type: string; text?: string }> }).content
			.map((c) => c.text || "")
			.join("");
		expect(text).toMatch(/Successfully wrote/);
		expect(existsSync(file)).toBe(true);
	});
});
