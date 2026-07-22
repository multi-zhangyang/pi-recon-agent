import { randomBytes } from "node:crypto";
import {
	chmodSync,
	closeSync,
	openSync,
	renameSync,
	statSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";

/** Atomically replace a file using a same-directory temporary file. */
export function atomicWriteFile(absolutePath, content, mode = 0o600) {
	const tempPath = join(
		dirname(absolutePath),
		`.${basename(absolutePath)}.${process.pid}.${Date.now()}.${randomBytes(4).toString("hex")}.tmp`,
	);
	try {
		const fd = openSync(tempPath, "wx", mode);
		try {
			writeFileSync(fd, content);
		} finally {
			closeSync(fd);
		}
		try {
			chmodSync(tempPath, statSync(absolutePath).mode & 0o777);
		} catch {
			// A new target keeps the mode supplied to openSync.
		}
		renameSync(tempPath, absolutePath);
	} catch (error) {
		try {
			unlinkSync(tempPath);
		} catch {
			// The temporary file may not exist or may already have been renamed.
		}
		throw error instanceof Error ? error : new Error(String(error));
	}
}
