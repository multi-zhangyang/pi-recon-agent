import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ExtensionContext } from "../src/core/extensions/types.ts";
import { createEditToolDefinition } from "../src/core/tools/edit.ts";
import { computeEditsDiff } from "../src/core/tools/edit-diff.ts";

// The edit tool read its target with NO special-file guard: a FIFO passes
// `access` (which checks only mode bits), then ops.readFile calls fs.readFile
// on a FIFO → on Linux opening a FIFO for reading blocks until a writer opens
// it → readFile never resolves → the tool call hangs forever, blocking the
// agent loop. Same gap in computeEditsDiff (fire-and-forget preview). The fix
// stats the path after access and rejects non-regular files. Mirrors the read
// tool's opt #30 guard.

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
	const dir = mkdtempSync(join(tmpdir(), "pi-edit-special-"));
	tempDirs.push(dir);
	return dir;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) {
		rmSync(dir, { recursive: true, force: true });
	}
});

async function rejectAfter(ms: number): Promise<never> {
	return new Promise((_, reject) => setTimeout(() => reject(new Error("edit did not reject (hung)")), ms));
}

describe("edit tool special-file guard (F5)", () => {
	it("execute rejects a FIFO promptly with the not-a-regular-file message (no hang)", async () => {
		if (process.platform === "win32") return; // mkfifo unavailable
		const dir = await makeTempDir();
		const fifo = join(dir, "named-pipe");
		spawnSync("mkfifo", [fifo]);
		if (!existsSync(fifo)) return; // mkfifo unavailable — skip gracefully

		const def = createEditToolDefinition(dir);

		// Race the tool against a hang. Pre-fix: readFile on the FIFO blocks
		// forever → the timeout branch rejects this test. Post-fix: the stat
		// guard rejects before readFile is ever called.
		const err = await Promise.race([
			def
				.execute(
					"call-f5",
					{ path: fifo, edits: [{ oldText: "a", newText: "b" }] },
					undefined,
					undefined,
					undefined as unknown as ExtensionContext,
				)
				.catch((e) => e),
			rejectAfter(4000),
		]);

		expect(err).toBeInstanceOf(Error);
		expect(String((err as Error).message)).toMatch(/not a regular file/i);
		// Must point the model at bash so it can still inspect/replace the file.
		expect(String((err as Error).message)).toContain("bash");
	});

	it("execute rejects a directory with a directory hint (not the not-a-regular-file message)", async () => {
		const dir = await makeTempDir();
		const sub = join(dir, "subdir");
		// make a subdir inside the temp dir
		mkdirSync(sub, { recursive: true });
		if (!existsSync(sub)) return;

		const def = createEditToolDefinition(dir);
		const err = await Promise.race([
			def
				.execute(
					"call-f5-dir",
					{ path: sub, edits: [{ oldText: "a", newText: "b" }] },
					undefined,
					undefined,
					undefined as unknown as ExtensionContext,
				)
				.catch((e) => e),
			rejectAfter(4000),
		]);

		expect(err).toBeInstanceOf(Error);
		expect(String((err as Error).message)).toMatch(/directory/i);
	});

	it("computeEditsDiff (preview) rejects a FIFO with the not-a-regular-file message (no hang)", async () => {
		if (process.platform === "win32") return;
		const dir = await makeTempDir();
		const fifo = join(dir, "named-pipe-preview");
		spawnSync("mkfifo", [fifo]);
		if (!existsSync(fifo)) return;

		const result = await Promise.race([
			computeEditsDiff(fifo, [{ oldText: "a", newText: "b" }], dir),
			rejectAfter(4000).then(() => ({ error: "hung" }) as { error: string }),
		]);

		expect(result).toHaveProperty("error");
		expect((result as { error: string }).error).toMatch(/not a regular file/i);
	});

	it("a regular-file edit still applies (behavior-preserving)", async () => {
		const dir = await makeTempDir();
		const file = join(dir, "regular.txt");
		writeFileSync(file, "hello world\n");
		if (!existsSync(file)) return;

		const def = createEditToolDefinition(dir);
		const result = await Promise.race([
			def.execute(
				"call-f5-ok",
				{ path: file, edits: [{ oldText: "hello", newText: "goodbye" }] },
				undefined,
				undefined,
				undefined as unknown as ExtensionContext,
			),
			rejectAfter(4000),
		]);

		const text = (result as { content: Array<{ type: string; text?: string }> }).content
			.map((c) => c.text || "")
			.join("");
		expect(text).toMatch(/Successfully replaced/);
		expect(readFileSync(file, "utf-8")).toContain("goodbye world");
	});
});
