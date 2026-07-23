import { existsSync, readdirSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import type {
	Session,
	SessionTreeEntry,
	SqliteSessionCreateOptions,
	SqliteSessionListOptions,
	SqliteSessionMetadata,
	SqliteSessionRepoApi,
} from "../types.ts";
import { SessionError } from "../types.ts";
import { createSessionId, createTimestamp, getEntriesToFork, toSession } from "./repo-utils.ts";
import { SqliteSessionStorage } from "./sqlite-storage.ts";

function encodeCwd(cwd: string): string {
	return `--${cwd.replace(/^[/\\]/, "").replace(/[/\\:]/g, "-")}--`;
}

/** Filesystem repository backed by one SQLite WAL database per session. */
export class SqliteSessionRepo implements SqliteSessionRepoApi {
	private readonly sessionsRoot: string;

	constructor(options: { sessionsRoot: string }) {
		this.sessionsRoot = resolve(options.sessionsRoot);
	}

	private sessionDir(cwd: string): string {
		return join(this.sessionsRoot, encodeCwd(cwd));
	}

	private sessionPath(cwd: string, id: string, createdAt: string): string {
		return join(this.sessionDir(cwd), `${createdAt.replace(/[:.]/g, "-")}_${id}.sqlite`);
	}

	async create(options: SqliteSessionCreateOptions): Promise<Session<SqliteSessionMetadata>> {
		const id = options.id ?? createSessionId();
		const createdAt = createTimestamp();
		const path = this.sessionPath(options.cwd, id, createdAt);
		const storage = SqliteSessionStorage.create(path, {
			cwd: options.cwd,
			sessionId: id,
			parentSessionPath: options.parentSessionPath,
		});
		return toSession(storage);
	}

	async open(metadata: SqliteSessionMetadata): Promise<Session<SqliteSessionMetadata>> {
		if (!existsSync(metadata.path)) throw new SessionError("not_found", `Session not found: ${metadata.path}`);
		return toSession(SqliteSessionStorage.open(metadata.path));
	}

	async list(options: SqliteSessionListOptions = {}): Promise<SqliteSessionMetadata[]> {
		const roots = options.cwd ? [this.sessionDir(options.cwd)] : this.listSessionDirs();
		const result: SqliteSessionMetadata[] = [];
		for (const dir of roots) {
			if (!existsSync(dir)) continue;
			for (const file of readdirSync(dir, { withFileTypes: true })) {
				if (!file.isFile() || !file.name.endsWith(".sqlite")) continue;
				const path = join(dir, file.name);
				const storage = SqliteSessionStorage.open(path);
				result.push(await storage.getMetadata());
				storage.close();
			}
		}
		return result.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
	}

	async delete(metadata: SqliteSessionMetadata): Promise<void> {
		if (!existsSync(metadata.path)) return;
		rmSync(metadata.path, { force: true });
		rmSync(`${metadata.path}-wal`, { force: true });
		rmSync(`${metadata.path}-shm`, { force: true });
	}

	async fork(
		sourceMetadata: SqliteSessionMetadata,
		options: SqliteSessionCreateOptions & { entryId?: string; position?: "before" | "at" },
	): Promise<Session<SqliteSessionMetadata>> {
		const source = await this.open(sourceMetadata);
		const entries = await getEntriesToFork(source.getStorage(), options);
		const fork = await this.create({
			...options,
			parentSessionPath: options.parentSessionPath ?? sourceMetadata.path,
		});
		for (const entry of entries) await fork.getStorage().appendEntry(entry as SessionTreeEntry);
		return fork;
	}

	private listSessionDirs(): string[] {
		if (!existsSync(this.sessionsRoot)) return [];
		return readdirSync(this.sessionsRoot, { withFileTypes: true })
			.filter((entry) => entry.isDirectory())
			.map((entry) => join(this.sessionsRoot, entry.name));
	}
}
