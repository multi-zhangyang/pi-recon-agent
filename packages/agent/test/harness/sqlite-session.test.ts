import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SqliteSessionRepo } from "../../src/harness/session/sqlite-repo.ts";
import type { SqliteSessionStorage } from "../../src/harness/session/sqlite-storage.ts";

describe("SQLite WAL session backend", () => {
	const roots: string[] = [];

	afterEach(() => {
		for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
	});

	it("persists the active branch and exports a JSONL compatibility view", async () => {
		const root = mkdtempSync(join(tmpdir(), "repi-sqlite-session-"));
		roots.push(root);
		const repo = new SqliteSessionRepo({ sessionsRoot: root });
		const session = await repo.create({ cwd: "/workspace" });
		const first = await session.appendMessage({
			role: "user",
			content: [{ type: "text", text: "inspect target" }],
			timestamp: Date.now(),
		});
		await session.appendCustomEntry("repi-mission", { id: "mission-1" });
		const storage = session.getStorage() as SqliteSessionStorage;
		expect(await session.getLeafId()).not.toBeNull();
		expect((await session.getBranch()).map((entry) => entry.id)).toHaveLength(2);
		expect(storage.exportJsonl()).toContain('"type":"session"');
		expect(storage.exportJsonl()).toContain('"customType":"repi-mission"');
		const metadata = await session.getMetadata();
		expect(metadata.path).toMatch(/\.sqlite$/);
		expect(existsSync(metadata.path)).toBe(true);

		storage.close();
		const reopened = await repo.open(metadata);
		expect(await reopened.getLeafId()).toBe((await reopened.getEntries()).at(-1)?.id);
		expect((await reopened.getEntry(first))?.type).toBe("message");
		(reopened.getStorage() as SqliteSessionStorage).close();
	});

	it("serializes concurrent appends without losing tree parents", async () => {
		const root = mkdtempSync(join(tmpdir(), "repi-sqlite-concurrent-"));
		roots.push(root);
		const repo = new SqliteSessionRepo({ sessionsRoot: root });
		const session = await repo.create({ cwd: "/workspace" });
		await Promise.all(
			Array.from({ length: 24 }, (_, index) =>
				session.appendMessage({
					role: "user",
					content: [{ type: "text", text: `message-${index}` }],
					timestamp: Date.now(),
				}),
			),
		);
		const entries = await session.getEntries();
		expect(entries).toHaveLength(24);
		for (let index = 1; index < entries.length; index++)
			expect(entries[index]?.parentId).toBe(entries[index - 1]?.id);
		(session.getStorage() as SqliteSessionStorage).close();
	});
});
