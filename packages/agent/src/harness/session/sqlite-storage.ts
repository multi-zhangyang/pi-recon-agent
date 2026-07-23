import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { LeafEntry, SessionStorage, SessionTreeEntry, SqliteSessionMetadata } from "../types.ts";
import { SessionError } from "../types.ts";
import { uuidv7 } from "./uuid.ts";

type SqliteRow = Record<string, unknown>;

function generateEntryId(existing: (id: string) => boolean): string {
	for (let attempt = 0; attempt < 100; attempt++) {
		const id = uuidv7();
		if (!existing(id)) return id;
	}
	return uuidv7();
}

function rowString(row: SqliteRow, key: string): string | undefined {
	const value = row[key];
	return typeof value === "string" ? value : undefined;
}

function requireMetadata(row: SqliteRow | undefined, path: string): SqliteSessionMetadata {
	if (!row) throw new SessionError("not_found", `SQLite session not found: ${path}`);
	const id = rowString(row, "id");
	const createdAt = rowString(row, "created_at");
	const cwd = rowString(row, "cwd");
	if (!id || !createdAt || !cwd) throw new SessionError("invalid_session", `Invalid SQLite session metadata: ${path}`);
	const parentSessionPath = rowString(row, "parent_session_path");
	return { id, createdAt, cwd, path, ...(parentSessionPath ? { parentSessionPath } : {}) };
}

function leafIdAfterEntry(entry: SessionTreeEntry): string | null {
	return entry.type === "leaf" ? entry.targetId : entry.id;
}

function updateSchema(db: DatabaseSync): void {
	db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;");
	db.exec(`
		CREATE TABLE IF NOT EXISTS session_meta (
			id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			cwd TEXT NOT NULL,
			parent_session_path TEXT
		);
		CREATE TABLE IF NOT EXISTS session_entries (
			seq INTEGER PRIMARY KEY AUTOINCREMENT,
			id TEXT NOT NULL UNIQUE,
			parent_id TEXT,
			type TEXT NOT NULL,
			timestamp TEXT NOT NULL,
			payload TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS session_entries_parent_idx ON session_entries(parent_id);
		CREATE TABLE IF NOT EXISTS session_state (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			leaf_id TEXT
		);
		INSERT OR IGNORE INTO session_state(id, leaf_id) VALUES (1, NULL);
	`);
}

export function exportSqliteSessionJsonl(storage: SqliteSessionStorage): string {
	return storage.exportJsonl();
}

/** SQLite WAL-backed session storage. JSONL is intentionally an export boundary, not the write path. */
export class SqliteSessionStorage implements SessionStorage<SqliteSessionMetadata> {
	private readonly db: DatabaseSync;
	private readonly filePath: string;
	private readonly metadata: SqliteSessionMetadata;

	private constructor(db: DatabaseSync, filePath: string, metadata: SqliteSessionMetadata) {
		this.db = db;
		this.filePath = filePath;
		this.metadata = metadata;
		updateSchema(db);
	}

	static create(
		filePath: string,
		options: { cwd: string; sessionId: string; parentSessionPath?: string },
	): SqliteSessionStorage {
		mkdirSync(dirname(filePath), { recursive: true });
		const db = new DatabaseSync(filePath);
		updateSchema(db);
		const createdAt = new Date().toISOString();
		db.prepare("INSERT INTO session_meta(id, created_at, cwd, parent_session_path) VALUES (?, ?, ?, ?)").run(
			options.sessionId,
			createdAt,
			options.cwd,
			options.parentSessionPath ?? null,
		);
		return new SqliteSessionStorage(db, filePath, {
			id: options.sessionId,
			createdAt,
			cwd: options.cwd,
			path: filePath,
			...(options.parentSessionPath ? { parentSessionPath: options.parentSessionPath } : {}),
		});
	}

	static open(filePath: string): SqliteSessionStorage {
		const db = new DatabaseSync(filePath);
		updateSchema(db);
		const row = db.prepare("SELECT id, created_at, cwd, parent_session_path FROM session_meta LIMIT 1").get() as
			| SqliteRow
			| undefined;
		return new SqliteSessionStorage(db, filePath, requireMetadata(row, filePath));
	}

	getMetadata(): Promise<SqliteSessionMetadata> {
		return Promise.resolve(this.metadata);
	}

	getLeafId(): Promise<string | null> {
		const row = this.db.prepare("SELECT leaf_id FROM session_state WHERE id = 1").get() as SqliteRow | undefined;
		const leafId = row?.leaf_id;
		if (leafId !== null && leafId !== undefined && typeof leafId !== "string") {
			throw new SessionError("invalid_session", `Invalid SQLite leaf id: ${this.filePath}`);
		}
		return Promise.resolve((leafId as string | null | undefined) ?? null);
	}

	setLeafId(leafId: string | null): Promise<void> {
		if (leafId !== null && !this.hasEntry(leafId)) throw new SessionError("not_found", `Entry ${leafId} not found`);
		const current = this.getLeafIdSync();
		const entry: LeafEntry = {
			type: "leaf",
			id: generateEntryId((id) => this.hasEntry(id)),
			parentId: current,
			timestamp: new Date().toISOString(),
			targetId: leafId,
		};
		this.insertEntry(entry, leafId);
		return Promise.resolve();
	}

	createEntryId(): Promise<string> {
		return Promise.resolve(generateEntryId((id) => this.hasEntry(id)));
	}

	appendEntry(entry: SessionTreeEntry): Promise<void> {
		this.insertEntry(entry, leafIdAfterEntry(entry));
		return Promise.resolve();
	}

	getEntry(id: string): Promise<SessionTreeEntry | undefined> {
		const row = this.db.prepare("SELECT payload FROM session_entries WHERE id = ?").get(id) as SqliteRow | undefined;
		if (!row) return Promise.resolve(undefined);
		try {
			return Promise.resolve(JSON.parse(String(row.payload)) as SessionTreeEntry);
		} catch (error) {
			throw new SessionError("invalid_session", `Invalid entry ${id} in ${this.filePath}`, error as Error);
		}
	}

	async findEntries<TType extends SessionTreeEntry["type"]>(
		type: TType,
	): Promise<Array<Extract<SessionTreeEntry, { type: TType }>>> {
		const entries = await this.getEntries();
		return entries.filter((entry): entry is Extract<SessionTreeEntry, { type: TType }> => entry.type === type);
	}

	async getLabel(id: string): Promise<string | undefined> {
		const entries = await this.findEntries("label");
		const matching = [...entries].reverse().find((entry) => entry.targetId === id);
		return matching?.label?.trim() || undefined;
	}

	async getPathToRoot(leafId: string | null): Promise<SessionTreeEntry[]> {
		if (leafId === null) return [];
		const entries = await this.getEntries();
		const byId = new Map(entries.map((entry) => [entry.id, entry]));
		const path: SessionTreeEntry[] = [];
		const visited = new Set<string>();
		let current = byId.get(leafId);
		if (!current) throw new SessionError("not_found", `Entry ${leafId} not found`);
		while (current) {
			if (visited.has(current.id))
				throw new SessionError("invalid_session", `Cycle detected at entry ${current.id}`);
			visited.add(current.id);
			path.push(current);
			current = current.parentId ? byId.get(current.parentId) : undefined;
			if (current === undefined && path.at(-1)?.parentId) {
				throw new SessionError("invalid_session", `Missing parent ${path.at(-1)?.parentId}`);
			}
		}
		return path.reverse();
	}

	async getEntries(): Promise<SessionTreeEntry[]> {
		const rows = this.db.prepare("SELECT payload FROM session_entries ORDER BY seq ASC").all() as SqliteRow[];
		return rows.map((row) => {
			try {
				return JSON.parse(String(row.payload)) as SessionTreeEntry;
			} catch (error) {
				throw new SessionError("invalid_session", `Invalid entry in ${this.filePath}`, error as Error);
			}
		});
	}

	exportJsonl(): string {
		const header = {
			type: "session",
			version: 3,
			id: this.metadata.id,
			timestamp: this.metadata.createdAt,
			cwd: this.metadata.cwd,
			...(this.metadata.parentSessionPath ? { parentSession: this.metadata.parentSessionPath } : {}),
		};
		const rows = this.db.prepare("SELECT payload FROM session_entries ORDER BY seq ASC").all() as SqliteRow[];
		return `${JSON.stringify(header)}\n${rows.map((row) => String(row.payload)).join("\n")}${rows.length ? "\n" : ""}`;
	}

	close(): void {
		this.db.close();
	}

	private hasEntry(id: string): boolean {
		return Boolean(this.db.prepare("SELECT 1 FROM session_entries WHERE id = ? LIMIT 1").get(id));
	}

	private getLeafIdSync(): string | null {
		const row = this.db.prepare("SELECT leaf_id FROM session_state WHERE id = 1").get() as SqliteRow | undefined;
		return typeof row?.leaf_id === "string" ? row.leaf_id : null;
	}

	private insertEntry(entry: SessionTreeEntry, leafId: string | null): void {
		try {
			this.db.exec("BEGIN IMMEDIATE");
			this.db
				.prepare("INSERT INTO session_entries(id, parent_id, type, timestamp, payload) VALUES (?, ?, ?, ?, ?)")
				.run(entry.id, entry.parentId, entry.type, entry.timestamp, JSON.stringify(entry));
			this.db.prepare("UPDATE session_state SET leaf_id = ? WHERE id = 1").run(leafId);
			this.db.exec("COMMIT");
		} catch (error) {
			try {
				this.db.exec("ROLLBACK");
			} catch {
				// Preserve the original storage error.
			}
			throw new SessionError("storage", `Failed to append SQLite session entry ${entry.id}`, error as Error);
		}
	}
}
