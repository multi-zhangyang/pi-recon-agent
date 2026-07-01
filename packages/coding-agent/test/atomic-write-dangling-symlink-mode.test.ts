import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { atomicWriteFile } from "../src/core/tools/atomic-write.ts";

// opt #274: the async atomicWriteFile dangling-symlink fallback wrote through
// the link via a bare `fsWriteFile(absolutePath, content, "utf-8")` with NO
// explicit mode → 0o666 & ~umask ≈ 0o644 (world-readable), while the
// temp+rename path explicitly creates with 0o600. A secret written through a
// dangling symlink (a symlinked config whose target doesn't exist yet) was
// silently world-readable on a multi-user system. Post-fix the fallback passes
// `{ encoding: "utf-8", mode: 0o600 }` so the dangling case is no less private
// than the non-dangling one.

const tempDirs: string[] = [];

function makeTempDir(): string {
	const dir = join(tmpdir(), `pi-atomic-dangling-${process.pid}-${Math.random().toString(36).slice(2)}`);
	mkdirSync(dir, { recursive: true });
	tempDirs.push(dir);
	return dir;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) {
		rmSync(dir, { recursive: true, force: true });
	}
});

describe("atomicWriteFile dangling-symlink fallback mode 0o600 (opt #274)", () => {
	it("writes through a dangling symlink with owner-only mode 0o600, not 0o644", async () => {
		const dir = makeTempDir();
		// The target dir exists but the pointed-to file does not → dangling symlink.
		const targetDir = join(dir, "secrets");
		const realFile = join(targetDir, "token");
		const linkDir = join(dir, "config");
		const link = join(linkDir, "token");
		mkdirSync(targetDir, { recursive: true });
		mkdirSync(linkDir, { recursive: true });
		symlinkSync(realFile, link);
		expect(existsSync(realFile)).toBe(false);

		await atomicWriteFile(link, "super-secret-api-key\n");

		// The write went THROUGH the link to the real file (link preserved).
		expect(existsSync(realFile)).toBe(true);
		expect(existsSync(link)).toBe(true);
		expect(readFileSync(realFile, "utf-8")).toBe("super-secret-api-key\n");

		// The real file is owner-only — the bug left it 0o644 (world-readable).
		expect(statSync(realFile).mode & 0o777).toBe(0o600);

		// No temp artifact leaked in either dir.
		expect(readdirSync(linkDir).filter((n) => n.endsWith(".tmp"))).toEqual([]);
		expect(readdirSync(targetDir).filter((n) => n.endsWith(".tmp"))).toEqual([]);
	});

	it("still preserves an existing real file's mode when the symlink resolves", async () => {
		const dir = makeTempDir();
		const realFile = join(dir, "real.txt");
		const { writeFileSync, chmodSync } = await import("node:fs");
		writeFileSync(realFile, "orig\n");
		chmodSync(realFile, 0o640);
		const link = join(dir, "link.txt");
		symlinkSync(realFile, link);

		await atomicWriteFile(link, "replaced\n");

		// Non-dangling symlink → temp+rename the REAL file, preserving its mode.
		expect(statSync(realFile).mode & 0o777).toBe(0o640);
		expect(readFileSync(realFile, "utf-8")).toBe("replaced\n");
	});
});
