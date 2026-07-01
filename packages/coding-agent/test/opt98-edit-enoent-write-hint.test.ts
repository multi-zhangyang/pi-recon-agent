import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ExtensionContext } from "../src/core/extensions/types.ts";
import { createEditToolDefinition } from "../src/core/tools/edit.ts";
import { computeEditsDiff } from "../src/core/tools/edit-diff.ts";

// opt #98 F3: editing a missing file threw a bare "Error code: ENOENT" with no
// actionable hint. The model would retry edit against the missing path instead
// of switching to the write tool. Post-fix the ENOENT error appends a "does
// not exist. Use the write tool to create it" hint, mirrored in the
// computeEditsDiff preview path.

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
	const dir = mkdtempSync(join(tmpdir(), "pi-edit-enoent-"));
	tempDirs.push(dir);
	return dir;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) {
		rmSync(dir, { recursive: true, force: true });
	}
});

const NO_CTX = undefined as unknown as ExtensionContext;

describe("edit tool ENOENT write hint (F3)", () => {
	it("execute rejects a missing file with a hint pointing at the write tool", async () => {
		const dir = await makeTempDir();
		const missing = join(dir, "does-not-exist.txt");
		const def = createEditToolDefinition(dir);
		const err = await def
			.execute("call-f3", { path: missing, edits: [{ oldText: "a", newText: "b" }] }, undefined, undefined, NO_CTX)
			.catch((e) => e);
		expect(err).toBeInstanceOf(Error);
		const msg = String((err as Error).message);
		expect(msg).toContain("ENOENT");
		expect(msg).toContain("does not exist");
		expect(msg).toContain("write");
		expect(msg).toContain(missing);
	});

	it("computeEditsDiff (preview) returns the same write hint for a missing file", async () => {
		const dir = await makeTempDir();
		const missing = join(dir, "preview-missing.txt");
		const result = await computeEditsDiff(missing, [{ oldText: "a", newText: "b" }], dir);
		expect(result).toHaveProperty("error");
		const msg = (result as { error: string }).error;
		expect(msg).toContain("ENOENT");
		expect(msg).toContain("does not exist");
		expect(msg).toContain("write");
	});
});
