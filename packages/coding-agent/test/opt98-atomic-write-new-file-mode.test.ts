import { chmodSync, existsSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { atomicWriteFile } from "../src/core/tools/atomic-write.ts";

// opt #98 F10: the async atomicWriteFile created its temp via
// `fs.writeFile(temp, content, "utf-8")` with no explicit mode → 0o666 & ~umask
// ≈ 0o644. For a NEW target there is no existing mode to chmod-copy, so the
// renamed file was world-readable — leaking secrets written via the write/edit
// tools. The sync counterpart already used 0o600. Post-fix the temp is created
// with explicit 0o600 (open "wx" 0o600), then chmod-copied to the existing
// target's mode if it pre-exists.

const tempDirs: string[] = [];

function makeTempDir(): string {
	const dir = mkdtempSync(join(tmpdir(), "pi-atomic-mode-"));
	tempDirs.push(dir);
	return dir;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) {
		rmSync(dir, { recursive: true, force: true });
	}
});

describe("atomicWriteFile new-file mode 0o600 (F10)", () => {
	it("creates a NEW file with owner-only mode 0o600, not world-readable 0o644", async () => {
		const dir = makeTempDir();
		const target = join(dir, "secret.txt");
		await atomicWriteFile(target, "private content\n");
		expect(existsSync(target)).toBe(true);
		const mode = statSync(target).mode & 0o777;
		expect(mode).toBe(0o600);
	});

	it("preserves an existing target's mode on overwrite (executable bit)", async () => {
		const dir = makeTempDir();
		const target = join(dir, "exec.sh");
		writeFileSync(target, "original\n");
		chmodSync(target, 0o755);
		await atomicWriteFile(target, "replaced\n");
		expect(statSync(target).mode & 0o777).toBe(0o755);
	});

	it("still writes content fully and leaves no temp file behind", async () => {
		const dir = makeTempDir();
		const target = join(dir, "new.txt");
		const content = "line one\nline two\n";
		await atomicWriteFile(target, content);
		expect(statSync(target).mode & 0o777).toBe(0o600);
		// content intact, no temp leaked.
		const { readFileSync } = await import("node:fs");
		expect(readFileSync(target, "utf-8")).toBe(content);
		expect(readdirSync(dir).filter((n) => n.endsWith(".tmp"))).toEqual([]);
	});
});
