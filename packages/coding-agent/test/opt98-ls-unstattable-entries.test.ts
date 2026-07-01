import { lstatSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ExtensionContext } from "../src/core/extensions/types.ts";
import { createLsToolDefinition } from "../src/core/tools/ls.ts";

// opt #98 F7: entries that failed stat (broken symlink, perm denied, ELOOP,
// deleted between readdir and stat) were silently `continue`'d out of the
// listing — the model saw a shorter listing with no marker and no indication
// the entry existed. Post-fix the entry name is still emitted with a `?`
// marker (type unknown) and a trailing notice tallies the unstattable count.

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
	const dir = mkdtempSync(join(tmpdir(), "pi-ls-unstattable-"));
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

describe("ls tool unstattable entries (F7)", () => {
	it("still emits a broken-symlink entry name with a marker (not silently dropped)", async () => {
		if (process.platform === "win32") return; // symlinks need privilege
		const dir = await makeTempDir();
		// A regular file plus a broken symlink (target does not exist). stat on
		// the broken symlink follows the link and throws ENOENT → pre-fix the
		// entry was dropped from the listing entirely.
		writeFileSync(join(dir, "real.txt"), "x");
		const broken = join(dir, "broken-link");
		symlinkSync(join(dir, "no-such-target"), broken);
		// Note: existsSync() follows the link and returns FALSE for a broken
		// symlink, so use lstatSync to confirm the symlink entry itself exists.
		if (!lstatSync(broken, { throwIfNoEntry: false })?.isSymbolicLink()) return; // symlink creation failed — skip

		const def = createLsToolDefinition(dir);
		const result = await def.execute("call-f7", { path: dir }, undefined, undefined, NO_CTX);
		const text = readResultText(result);
		// The broken symlink's name must still appear in the listing.
		expect(text).toContain("broken-link");
		// The regular file is listed as a normal entry.
		expect(text).toContain("real.txt");
		// A notice or marker indicates an entry could not be stat'd.
		expect(text.match(/broken-link\?/) || text.match(/could not be stat/i)).toBeTruthy();
	});

	it("lists a clean directory without an unstattable notice (behavior-preserving)", async () => {
		const dir = await makeTempDir();
		writeFileSync(join(dir, "a.txt"), "a");
		const sub = join(dir, "sub");
		mkdirSync(sub, { recursive: true });
		const def = createLsToolDefinition(dir);
		const result = await def.execute("call-f7-clean", { path: dir }, undefined, undefined, NO_CTX);
		const text = readResultText(result);
		expect(text).toContain("a.txt");
		expect(text).toContain("sub/");
		expect(text).not.toMatch(/could not be stat/i);
	});
});
