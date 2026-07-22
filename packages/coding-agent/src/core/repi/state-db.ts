import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { reconDir } from "./storage.ts";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS repi_state (
  namespace TEXT NOT NULL,
  state_key TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  value_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (namespace, state_key)
);
CREATE INDEX IF NOT EXISTS repi_state_updated_at ON repi_state(updated_at);
`;

export function repiStateDbPath(): string {
	return `${reconDir()}/state.sqlite3`;
}

function openStateDb(): DatabaseSync {
	const path = repiStateDbPath();
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const db = new DatabaseSync(path);
	db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;");
	db.exec(SCHEMA);
	try {
		chmodSync(path, 0o600);
	} catch {
		// File modes are not available on every supported filesystem.
	}
	return db;
}

function parseState<T>(value: unknown): T | undefined {
	if (typeof value !== "string") return undefined;
	try {
		return JSON.parse(value) as T;
	} catch {
		return undefined;
	}
}

export type RepiStateEntry<T> = { found: false; value: undefined } | { found: true; value: T | undefined };

export function readRepiStateEntry<T>(namespace: string, key: string): RepiStateEntry<T> {
	const db = openStateDb();
	try {
		const row = db
			.prepare("SELECT value_json FROM repi_state WHERE namespace = ? AND state_key = ?")
			.get(namespace, key) as { value_json?: unknown } | undefined;
		return row ? { found: true, value: parseState<T>(row.value_json) } : { found: false, value: undefined };
	} finally {
		db.close();
	}
}

export function readRepiState<T>(namespace: string, key: string): T | undefined {
	return readRepiStateEntry<T>(namespace, key).value;
}

export function mutateRepiState<T>(
	namespace: string,
	key: string,
	initial: () => T | undefined,
	mutate: (current: T | undefined) => T,
): T {
	const db = openStateDb();
	db.exec("BEGIN IMMEDIATE");
	try {
		const row = db
			.prepare("SELECT value_json FROM repi_state WHERE namespace = ? AND state_key = ?")
			.get(namespace, key) as { value_json?: unknown } | undefined;
		const current = row ? parseState<T>(row.value_json) : initial();
		if (row && current === undefined) throw new Error(`Invalid REPI state JSON for ${namespace}:${key}`);
		const next = mutate(current);
		db.prepare(
			`INSERT INTO repi_state(namespace, state_key, version, value_json, updated_at)
			 VALUES (?, ?, 1, ?, ?)
			 ON CONFLICT(namespace, state_key) DO UPDATE SET
			   version = repi_state.version + 1,
			   value_json = excluded.value_json,
			   updated_at = excluded.updated_at`,
		).run(namespace, key, JSON.stringify(next), new Date().toISOString());
		db.exec("COMMIT");
		return next;
	} catch (error) {
		try {
			db.exec("ROLLBACK");
		} catch {
			// Preserve the original transaction error.
		}
		throw error;
	} finally {
		db.close();
	}
}
