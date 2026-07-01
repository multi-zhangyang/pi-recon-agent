import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { NodeExecutionEnv } from "../../src/harness/env/nodejs.ts";
import { JsonlSessionStorage, loadJsonlSessionMetadata } from "../../src/harness/session/jsonl-storage.ts";
import { InMemorySessionStorage } from "../../src/harness/session/memory-storage.ts";
import { type MessageEntry, ok, type SessionMetadata } from "../../src/harness/types.ts";
import { createAssistantMessage, createTempDir, createUserMessage } from "./session-test-utils.ts";

describe("InMemorySessionStorage", () => {
	it("returns configured session metadata", async () => {
		const metadata: SessionMetadata = { id: "session-1", createdAt: "2026-01-01T00:00:00.000Z" };
		const storage = new InMemorySessionStorage({ metadata });
		expect(await storage.getMetadata()).toEqual(metadata);
	});

	it("copies initial entries and persists leaf changes", async () => {
		const entry: MessageEntry = {
			type: "message",
			id: "entry-1",
			parentId: null,
			timestamp: "2026-01-01T00:00:00.000Z",
			message: createUserMessage("one"),
		};
		const initialEntries = [entry];
		const storage = new InMemorySessionStorage({ entries: initialEntries });
		initialEntries.push({ ...entry, id: "entry-2" });
		expect((await storage.getEntries()).map((storedEntry) => storedEntry.id)).toEqual(["entry-1"]);
		expect(await storage.getLeafId()).toBe("entry-1");
		await storage.setLeafId(null);
		expect(await storage.getLeafId()).toBeNull();
		expect((await storage.getEntries()).at(-1)).toMatchObject({ type: "leaf", targetId: null });
	});

	it("rejects invalid leaf ids", async () => {
		const storage = new InMemorySessionStorage();
		await expect(storage.setLeafId("missing")).rejects.toThrow("Entry missing not found");
	});

	it("finds entries by type", async () => {
		const entry: MessageEntry = {
			type: "message",
			id: "entry-1",
			parentId: null,
			timestamp: "2026-01-01T00:00:00.000Z",
			message: createUserMessage("one"),
		};
		const storage = new InMemorySessionStorage({ entries: [entry] });
		expect((await storage.findEntries("message")).map((found) => found.id)).toEqual(["entry-1"]);
		expect(await storage.findEntries("session_info")).toEqual([]);
	});

	it("maintains label lookup", async () => {
		const entry: MessageEntry = {
			type: "message",
			id: "entry-1",
			parentId: null,
			timestamp: "2026-01-01T00:00:00.000Z",
			message: createUserMessage("one"),
		};
		const storage = new InMemorySessionStorage({ entries: [entry] });
		expect(await storage.getLabel("entry-1")).toBeUndefined();
		await storage.appendEntry({
			type: "label",
			id: "label-1",
			parentId: "entry-1",
			timestamp: "2026-01-01T00:00:01.000Z",
			targetId: "entry-1",
			label: "checkpoint",
		});
		expect(await storage.getLabel("entry-1")).toBe("checkpoint");
		await storage.appendEntry({
			type: "label",
			id: "label-2",
			parentId: "label-1",
			timestamp: "2026-01-01T00:00:02.000Z",
			targetId: "entry-1",
			label: undefined,
		});
		expect(await storage.getLabel("entry-1")).toBeUndefined();
	});

	it("walks paths to root", async () => {
		const root: MessageEntry = {
			type: "message",
			id: "root",
			parentId: null,
			timestamp: "2026-01-01T00:00:00.000Z",
			message: createUserMessage("root"),
		};
		const child: MessageEntry = {
			...root,
			id: "child",
			parentId: "root",
			message: createAssistantMessage("child"),
		};
		const storage = new InMemorySessionStorage({ entries: [root, child] });
		expect((await storage.getPathToRoot("child")).map((entry) => entry.id)).toEqual(["root", "child"]);
		expect(await storage.getPathToRoot(null)).toEqual([]);
	});

	it("walks a deep linear chain to root in order (regression: unshift→push+reverse)", async () => {
		// getPathToRoot builds leaf→root then reverses once (O(n)) instead of
		// unshift-per-step (O(n²)). A deep linear chain (depth ≈ total session
		// entries, since every appendEntry advances the leaf) is the pessimistic
		// case: assert the result is root→leaf ordered and complete, which a
		// broken reverse (e.g. forgotten reverse, or wrong direction) would fail.
		const depth = 1000;
		const entries: MessageEntry[] = [];
		for (let i = 0; i < depth; i++) {
			entries.push({
				type: "message",
				id: `entry-${i}`,
				parentId: i === 0 ? null : `entry-${i - 1}`,
				timestamp: "2026-01-01T00:00:00.000Z",
				message: i % 2 === 0 ? createUserMessage(`m${i}`) : createAssistantMessage(`m${i}`),
			});
		}
		const storage = new InMemorySessionStorage({ entries });
		const path = await storage.getPathToRoot(`entry-${depth - 1}`);
		expect(path.length).toBe(depth);
		expect(path[0]!.id).toBe("entry-0"); // root first
		expect(path[depth - 1]!.id).toBe(`entry-${depth - 1}`); // leaf last
		// Root→leaf ordering: every element's parentId matches the predecessor's id.
		for (let i = 1; i < depth; i++) {
			expect(path[i]!.parentId).toBe(path[i - 1]!.id);
		}
	});
});

describe("JsonlSessionStorage", () => {
	it("throws for missing files when opening", async () => {
		const dir = createTempDir();
		const env = new NodeExecutionEnv({ cwd: dir });
		const filePath = join(dir, "session.jsonl");
		await expect(JsonlSessionStorage.open(env, filePath)).rejects.toMatchObject({ code: "not_found" });
	});

	it("writes the header on create", async () => {
		const dir = createTempDir();
		const env = new NodeExecutionEnv({ cwd: dir });
		const filePath = join(dir, "session.jsonl");
		const storage = await JsonlSessionStorage.create(env, filePath, { cwd: dir, sessionId: "session-1" });
		expect(existsSync(filePath)).toBe(true);
		expect(readFileSync(filePath, "utf8").trim().split("\n")).toHaveLength(1);
		expect(await storage.getLeafId()).toBeNull();
		expect(await storage.getEntries()).toEqual([]);
		await storage.appendEntry({
			type: "message",
			id: "user-1",
			parentId: null,
			timestamp: "2026-01-01T00:00:00.000Z",
			message: createUserMessage("one"),
		});
		const lines = readFileSync(filePath, "utf8").trim().split("\n");
		expect(JSON.parse(lines[0]!).type).toBe("session");
		expect(JSON.parse(lines[1]!).id).toBe("user-1");
		expect(lines).toHaveLength(2);
	});

	it("throws for malformed session headers", async () => {
		const dir = createTempDir();
		const env = new NodeExecutionEnv({ cwd: dir });
		const filePath = join(dir, "session.jsonl");
		writeFileSync(filePath, "not json\n");
		await expect(JsonlSessionStorage.open(env, filePath)).rejects.toThrow("first line is not a valid session header");
	});

	it("throws for malformed entry lines", async () => {
		const dir = createTempDir();
		const env = new NodeExecutionEnv({ cwd: dir });
		const filePath = join(dir, "session.jsonl");
		const header = {
			type: "session",
			version: 3,
			id: "session-1",
			timestamp: "2026-01-01T00:00:00.000Z",
			cwd: dir,
		};
		const entry: MessageEntry = {
			type: "message",
			id: "entry-1",
			parentId: null,
			timestamp: "2026-01-01T00:00:00.000Z",
			message: createUserMessage("one"),
		};
		writeFileSync(filePath, `${JSON.stringify(header)}\nnot json\n${JSON.stringify(entry)}\n`);
		await expect(JsonlSessionStorage.open(env, filePath)).rejects.toMatchObject({ code: "invalid_entry" });
	});

	it("creates and reads session metadata from the header", async () => {
		const dir = createTempDir();
		const env = new NodeExecutionEnv({ cwd: dir });
		const filePath = join(dir, "session.jsonl");
		const storage = await JsonlSessionStorage.create(env, filePath, {
			cwd: dir,
			sessionId: "session-1",
			parentSessionPath: "/tmp/parent.jsonl",
		});
		const metadata = await storage.getMetadata();
		expect(metadata).toMatchObject({
			id: "session-1",
			cwd: dir,
			path: filePath,
			parentSessionPath: "/tmp/parent.jsonl",
		});
		await storage.appendEntry({
			type: "message",
			id: "user-1",
			parentId: null,
			timestamp: "2026-01-01T00:00:00.000Z",
			message: createUserMessage("one"),
		});
		expect(await loadJsonlSessionMetadata(env, filePath)).toEqual(metadata);
	});

	it("loads existing entries and reconstructs leaf", async () => {
		const dir = createTempDir();
		const env = new NodeExecutionEnv({ cwd: dir });
		const filePath = join(dir, "session.jsonl");
		const storage = await JsonlSessionStorage.create(env, filePath, { cwd: dir, sessionId: "session-1" });
		const root: MessageEntry = {
			type: "message",
			id: "root",
			parentId: null,
			timestamp: "2026-01-01T00:00:00.000Z",
			message: createUserMessage("root"),
		};
		const child: MessageEntry = {
			...root,
			id: "child",
			parentId: "root",
			message: createAssistantMessage("child"),
		};
		await storage.appendEntry(root);
		await storage.appendEntry(child);
		const loaded = await JsonlSessionStorage.open(env, filePath);
		expect(await loaded.getLeafId()).toBe("child");
		expect((await loaded.getEntries()).map((entry) => entry.id)).toEqual(["root", "child"]);
		await loaded.setLeafId("root");
		const reloaded = await JsonlSessionStorage.open(env, filePath);
		expect(await reloaded.getLeafId()).toBe("root");
		expect((await reloaded.getEntries()).at(-1)).toMatchObject({ type: "leaf", targetId: "root" });
		expect((await loaded.getPathToRoot("child")).map((entry) => entry.id)).toEqual(["root", "child"]);
	});

	it("finds entries by type", async () => {
		const dir = createTempDir();
		const env = new NodeExecutionEnv({ cwd: dir });
		const filePath = join(dir, "session.jsonl");
		const storage = await JsonlSessionStorage.create(env, filePath, { cwd: dir, sessionId: "session-1" });
		await storage.appendEntry({
			type: "message",
			id: "entry-1",
			parentId: null,
			timestamp: "2026-01-01T00:00:00.000Z",
			message: createUserMessage("one"),
		});
		expect((await storage.findEntries("message")).map((found) => found.id)).toEqual(["entry-1"]);
		expect(await storage.findEntries("session_info")).toEqual([]);
	});

	it("maintains label lookup", async () => {
		const dir = createTempDir();
		const env = new NodeExecutionEnv({ cwd: dir });
		const filePath = join(dir, "session.jsonl");
		const storage = await JsonlSessionStorage.create(env, filePath, { cwd: dir, sessionId: "session-1" });
		await storage.appendEntry({
			type: "message",
			id: "entry-1",
			parentId: null,
			timestamp: "2026-01-01T00:00:00.000Z",
			message: createUserMessage("one"),
		});
		expect(await storage.getLabel("entry-1")).toBeUndefined();
		await storage.appendEntry({
			type: "label",
			id: "label-1",
			parentId: "entry-1",
			timestamp: "2026-01-01T00:00:01.000Z",
			targetId: "entry-1",
			label: "checkpoint",
		});
		expect(await storage.getLabel("entry-1")).toBe("checkpoint");
		await storage.appendEntry({
			type: "label",
			id: "label-2",
			parentId: "label-1",
			timestamp: "2026-01-01T00:00:02.000Z",
			targetId: "entry-1",
			label: undefined,
		});
		expect(await storage.getLabel("entry-1")).toBeUndefined();
		const loaded = await JsonlSessionStorage.open(env, filePath);
		expect(await loaded.getLabel("entry-1")).toBeUndefined();
	});

	it("reads session metadata through the line-reading filesystem operation", async () => {
		const dir = createTempDir();
		const filePath = join(dir, "session.jsonl");
		const header = {
			type: "session",
			version: 3,
			id: "session-1",
			timestamp: "2026-01-01T00:00:00.000Z",
			cwd: dir,
		};
		const metadata = await loadJsonlSessionMetadata(
			{
				readTextLines: async () => ok([JSON.stringify(header)]),
				readTextFile: async () => {
					throw new Error("readTextFile should not be called for metadata");
				},
				writeFile: async () => ok(undefined),
				appendFile: async () => ok(undefined),
			},
			filePath,
		);
		expect(metadata).toEqual({
			id: "session-1",
			createdAt: "2026-01-01T00:00:00.000Z",
			cwd: dir,
			path: filePath,
			parentSessionPath: undefined,
		});
	});
});
