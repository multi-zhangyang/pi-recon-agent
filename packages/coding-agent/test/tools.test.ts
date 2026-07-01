import { applyPatch } from "diff";
import {
	chmodSync,
	existsSync,
	lstatSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	symlinkSync,
	writeFileSync,
} from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeBashWithOperations } from "../src/core/bash-executor.ts";
import { atomicWriteFile } from "../src/core/tools/atomic-write.ts";
import { type BashOperations, createBashTool, createLocalBashOperations } from "../src/core/tools/bash.ts";
import { computeEditsDiff } from "../src/core/tools/edit-diff.ts";
import { OutputAccumulator } from "../src/core/tools/output-accumulator.ts";
import {
	createEditTool,
	createFindTool,
	createGrepTool,
	createLsTool,
	createReadTool,
	createWriteTool,
} from "../src/index.ts";
import * as shellModule from "../src/utils/shell.ts";

const readTool = createReadTool(process.cwd());
const writeTool = createWriteTool(process.cwd());
const editTool = createEditTool(process.cwd());
const bashTool = createBashTool(process.cwd());
const grepTool = createGrepTool(process.cwd());
const findTool = createFindTool(process.cwd());
const lsTool = createLsTool(process.cwd());

// Helper to extract text from content blocks
function getTextOutput(result: any): string {
	return (
		result.content
			?.filter((c: any) => c.type === "text")
			.map((c: any) => c.text)
			.join("\n") || ""
	);
}

describe("Coding Agent Tools", () => {
	let testDir: string;

	beforeEach(() => {
		// Create a unique temporary directory for each test
		testDir = join(tmpdir(), `coding-agent-test-${Date.now()}`);
		mkdirSync(testDir, { recursive: true });
	});

	afterEach(() => {
		// Clean up test directory
		rmSync(testDir, { recursive: true, force: true });
	});

	describe("read tool", () => {
		it("should read file contents that fit within limits", async () => {
			const testFile = join(testDir, "test.txt");
			const content = "Hello, world!\nLine 2\nLine 3";
			writeFileSync(testFile, content);

			const result = await readTool.execute("test-call-1", { path: testFile });

			expect(getTextOutput(result)).toBe(content);
			// No truncation message since file fits within limits
			expect(getTextOutput(result)).not.toContain("Use offset=");
			expect(result.details).toBeUndefined();
		});

		it("should handle non-existent files", async () => {
			const testFile = join(testDir, "nonexistent.txt");

			await expect(readTool.execute("test-call-2", { path: testFile })).rejects.toThrow(/ENOENT|not found/i);
		});

		it("should reject binary files with an actionable hint instead of dumping garbage", async () => {
			const testFile = join(testDir, "binary.elf");
			// A NUL byte in the leading bytes is the binary signature.
			writeFileSync(testFile, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x01, 0x02, 0x03]));

			await expect(readTool.execute("test-call-binary", { path: testFile })).rejects.toThrow(/binary file/i);
			const err = await readTool.execute("test-call-binary-2", { path: testFile }).catch((e) => e);
			expect(err.message).toContain("strings");
			expect(err.message).toContain("file");
		});

		it("should read text files that contain no NUL bytes normally", async () => {
			// Ensure the binary detector does not false-positive on normal text.
			const testFile = join(testDir, "plain.txt");
			writeFileSync(testFile, "just text\nwith newlines\nand unicode “quotes”\n");
			const result = await readTool.execute("test-call-plain", { path: testFile });
			expect(getTextOutput(result)).toContain("just text");
		});

		it("should strip a leading UTF-8 BOM instead of surfacing it on line 1", async () => {
			// A leading BOM (U+FEFF) is invisible metadata. It must not appear in
			// read output — otherwise the model copies it into edit oldText and the
			// edit tool (which strips BOM from the file) fails to match.
			const testFile = join(testDir, "bom.txt");
			writeFileSync(testFile, "﻿first line\nsecond line\n");
			const result = await readTool.execute("test-call-bom", { path: testFile });
			const output = getTextOutput(result);
			expect(output).toContain("first line");
			expect(output).toContain("second line");
			expect(output.charCodeAt(0)).not.toBe(0xfeff);
			expect(output).not.toContain("﻿");
		});

		it("should reject a directory with an actionable ls hint instead of EISDIR", async () => {
			const subDir = join(testDir, "subdir");
			mkdirSync(subDir, { recursive: true });
			await expect(readTool.execute("test-call-dir", { path: subDir })).rejects.toThrow(/directory/i);
			const err = await readTool.execute("test-call-dir-2", { path: subDir }).catch((e) => e);
			expect(err.message).toContain("ls");
			expect(err.message).not.toContain("EISDIR");
		});

		it("should reject a special file (device) with an actionable bash hint instead of hanging/OOM", async () => {
			// Regression: read used to call fs.readFile on the path BEFORE any
			// regular-file check. /dev/zero never returns EOF, so readFile would
			// hang or OOM — the binary/NUL heuristic runs only AFTER the full read
			// resolves, too late. Now a stat guard rejects non-regular files.
			// /dev/zero is a character device on linux/darwin; skip on win32.
			if (process.platform === "win32") return;
			const err = await readTool.execute("test-call-devzero", { path: "/dev/zero" }).catch((e) => e);
			expect(err).toBeInstanceOf(Error);
			expect(err.message).toMatch(/not a regular file|special file/i);
			// Must point the model at a bash fallback so it can still inspect the file.
			expect(err.message).toContain("file");
			expect(err.message).not.toMatch(/^[\x00]+$/); // never returned the raw zero bytes
		});

		it("should reject a named pipe (FIFO) with the special-file hint", async () => {
			// A FIFO has no writer, so readFile would block forever without the guard.
			if (process.platform === "win32") return;
			const fifo = join(testDir, "named-pipe");
			const { spawnSync } = await import("child_process");
			spawnSync("mkfifo", [fifo]);
			if (!existsSync(fifo)) return; // mkfifo unavailable — skip gracefully
			try {
				const err = await readTool.execute("test-call-fifo", { path: fifo }).catch((e) => e);
				expect(err).toBeInstanceOf(Error);
				expect(err.message).toMatch(/not a regular file|special file/i);
			} finally {
				try {
					rmSync(fifo);
				} catch {
					// ignore
				}
			}
		});

		it("should reject a pathologically large file BEFORE loading it into memory, with a bash-streaming hint", async () => {
			// Regression: read loads the WHOLE file into a Buffer, decodes it to a
			// string, and splits into an array of ALL lines before truncating
			// (offset/limit slice in memory too). A multi-GB file would OOM the
			// agent. Now a stat-size guard rejects oversized files before readFile
			// is ever called and steers the model to streaming bash commands.
			let readFileCalled = false;
			const bigFileTool = createReadTool(testDir, {
				operations: {
					access: async () => {},
					readFile: async () => {
						readFileCalled = true;
						return Buffer.from("x");
					},
					stat: async () => ({
						isFile: () => true,
						isDirectory: () => false,
						isBlockDevice: () => false,
						isCharacterDevice: () => false,
						isFIFO: () => false,
						isSocket: () => false,
						size: 2 * 1024 * 1024 * 1024, // 2GB — over the 16MB default limit
					}),
					detectImageMimeType: async () => undefined,
				},
			});
			const err = await bigFileTool.execute("test-call-bigfile", { path: "huge.log" }).catch((e) => e);
			expect(err).toBeInstanceOf(Error);
			expect(err.message).toMatch(/exceeds the .* in-memory read limit/i);
			// Must point the model at a streaming bash fallback.
			expect(err.message).toContain("head");
			expect(err.message).toContain("sed");
			// The guard MUST reject before readFile loads the file into memory.
			expect(readFileCalled).toBe(false);
		});

		it("should still read a file under the in-memory size limit (size guard does not over-trigger)", async () => {
			// Same mock shape, but size under the 16MB limit → readFile IS called
			// and the content is returned, proving the guard only catches oversized
			// files and does not change behavior for normal reads.
			const smallFileTool = createReadTool(testDir, {
				operations: {
					access: async () => {},
					readFile: async () => Buffer.from("hello world\n"),
					stat: async () => ({
						isFile: () => true,
						isDirectory: () => false,
						isBlockDevice: () => false,
						isCharacterDevice: () => false,
						isFIFO: () => false,
						isSocket: () => false,
						size: 12, // under the 16MB limit
					}),
					detectImageMimeType: async () => undefined,
				},
			});
			const result = await smallFileTool.execute("test-call-smallfile", { path: "small.txt" });
			expect(getTextOutput(result)).toContain("hello world");
		});

		it("should truncate files exceeding line limit", async () => {
			const testFile = join(testDir, "large.txt");
			const lines = Array.from({ length: 2500 }, (_, i) => `Line ${i + 1}`);
			writeFileSync(testFile, lines.join("\n"));

			const result = await readTool.execute("test-call-3", { path: testFile });
			const output = getTextOutput(result);

			expect(output).toContain("Line 1");
			expect(output).toContain("Line 2000");
			expect(output).not.toContain("Line 2001");
			expect(output).toContain("[Showing lines 1-2000 of 2500. Use offset=2001 to continue.]");
		});

		it("should truncate when byte limit exceeded", async () => {
			const testFile = join(testDir, "large-bytes.txt");
			// Create file that exceeds 50KB byte limit but has fewer than 2000 lines
			const lines = Array.from({ length: 500 }, (_, i) => `Line ${i + 1}: ${"x".repeat(200)}`);
			writeFileSync(testFile, lines.join("\n"));

			const result = await readTool.execute("test-call-4", { path: testFile });
			const output = getTextOutput(result);

			expect(output).toContain("Line 1:");
			// Should show byte limit message
			expect(output).toMatch(/\[Showing lines 1-\d+ of 500 \(.* limit\)\. Use offset=\d+ to continue\.\]/);
		});

		it("should handle offset parameter", async () => {
			const testFile = join(testDir, "offset-test.txt");
			const lines = Array.from({ length: 100 }, (_, i) => `Line ${i + 1}`);
			writeFileSync(testFile, lines.join("\n"));

			const result = await readTool.execute("test-call-5", { path: testFile, offset: 51 });
			const output = getTextOutput(result);

			expect(output).not.toContain("Line 50");
			expect(output).toContain("Line 51");
			expect(output).toContain("Line 100");
			// No truncation message since file fits within limits
			expect(output).not.toContain("Use offset=");
		});

		it("should handle limit parameter", async () => {
			const testFile = join(testDir, "limit-test.txt");
			const lines = Array.from({ length: 100 }, (_, i) => `Line ${i + 1}`);
			writeFileSync(testFile, lines.join("\n"));

			const result = await readTool.execute("test-call-6", { path: testFile, limit: 10 });
			const output = getTextOutput(result);

			expect(output).toContain("Line 1");
			expect(output).toContain("Line 10");
			expect(output).not.toContain("Line 11");
			expect(output).toContain("[90 more lines in file. Use offset=11 to continue.]");
		});

		it("should handle offset + limit together", async () => {
			const testFile = join(testDir, "offset-limit-test.txt");
			const lines = Array.from({ length: 100 }, (_, i) => `Line ${i + 1}`);
			writeFileSync(testFile, lines.join("\n"));

			const result = await readTool.execute("test-call-7", {
				path: testFile,
				offset: 41,
				limit: 20,
			});
			const output = getTextOutput(result);

			expect(output).not.toContain("Line 40");
			expect(output).toContain("Line 41");
			expect(output).toContain("Line 60");
			expect(output).not.toContain("Line 61");
			expect(output).toContain("[40 more lines in file. Use offset=61 to continue.]");
		});

		it("should show error when offset is beyond file length", async () => {
			const testFile = join(testDir, "short.txt");
			writeFileSync(testFile, "Line 1\nLine 2\nLine 3");

			await expect(readTool.execute("test-call-8", { path: testFile, offset: 100 })).rejects.toThrow(
				/Offset 100 is beyond end of file \(3 lines total\)/,
			);
		});

		it("should include truncation details when truncated", async () => {
			const testFile = join(testDir, "large-file.txt");
			const lines = Array.from({ length: 2500 }, (_, i) => `Line ${i + 1}`);
			writeFileSync(testFile, lines.join("\n"));

			const result = await readTool.execute("test-call-9", { path: testFile });

			expect(result.details).toBeDefined();
			expect(result.details?.truncation).toBeDefined();
			expect(result.details?.truncation?.truncated).toBe(true);
			expect(result.details?.truncation?.truncatedBy).toBe("lines");
			expect(result.details?.truncation?.totalLines).toBe(2500);
			expect(result.details?.truncation?.outputLines).toBe(2000);
		});

		it("should detect image MIME type from file magic (not extension)", async () => {
			const png1x1Base64 =
				"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgYGD4DwABBAEAX+XDSwAAAABJRU5ErkJggg==";
			const pngBuffer = Buffer.from(png1x1Base64, "base64");

			const testFile = join(testDir, "image.txt");
			writeFileSync(testFile, pngBuffer);

			const result = await readTool.execute("test-call-img-1", { path: testFile });

			expect(result.content[0]?.type).toBe("text");
			expect(getTextOutput(result)).toContain("Read image file [image/png]");

			const imageBlock = result.content.find(
				(c): c is { type: "image"; mimeType: string; data: string } => c.type === "image",
			);
			expect(imageBlock).toBeDefined();
			expect(imageBlock?.mimeType).toBe("image/png");
			expect(typeof imageBlock?.data).toBe("string");
			expect((imageBlock?.data ?? "").length).toBeGreaterThan(0);
		});

		it("should treat files with image extension but non-image content as text", async () => {
			const testFile = join(testDir, "not-an-image.png");
			writeFileSync(testFile, "definitely not a png");

			const result = await readTool.execute("test-call-img-2", { path: testFile });
			const output = getTextOutput(result);

			expect(output).toContain("definitely not a png");
			expect(result.content.some((c: any) => c.type === "image")).toBe(false);
		});
	});

	describe("write tool", () => {
		it("should write file contents", async () => {
			const testFile = join(testDir, "write-test.txt");
			const content = "Test content";

			const result = await writeTool.execute("test-call-3", { path: testFile, content });

			expect(getTextOutput(result)).toContain("Successfully wrote");
			expect(getTextOutput(result)).toContain(testFile);
			expect(result.details).toBeUndefined();
		});

		it("should create parent directories", async () => {
			const testFile = join(testDir, "nested", "dir", "test.txt");
			const content = "Nested content";

			const result = await writeTool.execute("test-call-4", { path: testFile, content });

			expect(getTextOutput(result)).toContain("Successfully wrote");
		});
	});

	describe("edit tool", () => {
		it("should replace text in file", async () => {
			const testFile = join(testDir, "edit-test.txt");
			const originalContent = "Hello, world!";
			writeFileSync(testFile, originalContent);

			const result = await editTool.execute("test-call-5", {
				path: testFile,
				edits: [{ oldText: "world", newText: "testing" }],
			});

			expect(getTextOutput(result)).toContain("Successfully replaced");
			expect(result.details).toBeDefined();
			expect(result.details.diff).toBeDefined();
			expect(typeof result.details.diff).toBe("string");
			expect(result.details.diff).toContain("testing");
			expect(result.details.patch).toContain("--- ");
			expect(result.details.patch).toContain("+++ ");
			expect(result.details.patch).toContain("@@");
			expect(result.details.patch).toContain("-Hello, world!");
			expect(result.details.patch).toContain("+Hello, testing!");
			expect(applyPatch(originalContent, result.details.patch)).toBe("Hello, testing!");
		});

		it("should report the first changed line in the success message", async () => {
			const testFile = join(testDir, "edit-line.txt");
			writeFileSync(testFile, ["alpha", "beta", "gamma", "delta"].join("\n"));
			const result = await editTool.execute("test-call-edit-line", {
				path: testFile,
				edits: [{ oldText: "gamma", newText: "GAMMA" }],
			});
			const output = getTextOutput(result);
			expect(output).toContain("Successfully replaced 1 block(s)");
			// "gamma" is line 3 — the model sees where the edit landed.
			expect(output).toContain("first change at line 3");
		});

		it("should fail if text not found", async () => {
			const testFile = join(testDir, "edit-test.txt");
			const originalContent = "Hello, world!";
			writeFileSync(testFile, originalContent);

			await expect(
				editTool.execute("test-call-6", {
					path: testFile,
					edits: [{ oldText: "nonexistent", newText: "testing" }],
				}),
			).rejects.toThrow(/Could not find the exact text/);
		});

		it("should include ENOENT when the edit target does not exist", async () => {
			const missingFile = join(testDir, "missing.txt");

			await expect(
				editTool.execute("test-call-6b", {
					path: missingFile,
					edits: [{ oldText: "hello", newText: "world" }],
				}),
			).rejects.toThrow(`Could not edit file: ${missingFile}. Error code: ENOENT.`);
		});

		it("should fail if text appears multiple times", async () => {
			const testFile = join(testDir, "edit-test.txt");
			const originalContent = "foo foo foo";
			writeFileSync(testFile, originalContent);

			await expect(
				editTool.execute("test-call-7", {
					path: testFile,
					edits: [{ oldText: "foo", newText: "bar" }],
				}),
			).rejects.toThrow(/Found 3 occurrences/);
		});

		it("should replace multiple disjoint regions in one call", async () => {
			const testFile = join(testDir, "edit-multi.txt");
			writeFileSync(testFile, "alpha\nbeta\ngamma\ndelta\n");

			const result = await editTool.execute("test-call-8", {
				path: testFile,
				edits: [
					{ oldText: "alpha\n", newText: "ALPHA\n" },
					{ oldText: "gamma\n", newText: "GAMMA\n" },
				],
			});

			expect(getTextOutput(result)).toContain("Successfully replaced 2 block(s)");
			expect(readFileSync(testFile, "utf-8")).toBe("ALPHA\nbeta\nGAMMA\ndelta\n");
			expect(result.details?.diff).toContain("ALPHA");
			expect(result.details?.diff).toContain("GAMMA");
		});

		it("should collapse large unchanged gaps in multi-edit diffs", async () => {
			const testFile = join(testDir, "edit-multi-large-gap.txt");
			const lines = Array.from({ length: 600 }, (_, i) => `line ${String(i + 1).padStart(3, "0")}`);
			writeFileSync(testFile, `${lines.join("\n")}\n`);

			const result = await editTool.execute("test-call-8b", {
				path: testFile,
				edits: [
					{ oldText: "line 100\n", newText: "LINE 100\n" },
					{ oldText: "line 300\n", newText: "LINE 300\n" },
					{ oldText: "line 500\n", newText: "LINE 500\n" },
				],
			});

			const diff = result.details?.diff ?? "";
			expect(diff).toContain("LINE 100");
			expect(diff).toContain("LINE 300");
			expect(diff).toContain("LINE 500");
			expect(diff).toContain("...");
			expect(diff).not.toContain("line 250");
			expect(diff.split("\n").length).toBeLessThan(50);
		});

		it("should match edits against the original file, not incrementally", async () => {
			const testFile = join(testDir, "edit-multi-original.txt");
			writeFileSync(testFile, "foo\nbar\nbaz\n");

			await editTool.execute("test-call-9", {
				path: testFile,
				edits: [
					{ oldText: "foo\n", newText: "foo bar\n" },
					{ oldText: "bar\n", newText: "BAR\n" },
				],
			});

			expect(readFileSync(testFile, "utf-8")).toBe("foo bar\nBAR\nbaz\n");
		});

		it("should fail when edits is empty", async () => {
			const testFile = join(testDir, "edit-empty-edits.txt");
			writeFileSync(testFile, "hello\nworld\n");

			await expect(
				editTool.execute("test-call-11", {
					path: testFile,
					edits: [],
				}),
			).rejects.toThrow(/edits must contain at least one replacement/);
		});

		it("should fail when multi-edit regions overlap", async () => {
			const testFile = join(testDir, "edit-overlap.txt");
			writeFileSync(testFile, "one\ntwo\nthree\n");

			await expect(
				editTool.execute("test-call-12", {
					path: testFile,
					edits: [
						{ oldText: "one\ntwo\n", newText: "ONE\nTWO\n" },
						{ oldText: "two\nthree\n", newText: "TWO\nTHREE\n" },
					],
				}),
			).rejects.toThrow(/overlap/);
		});

		it("should not partially apply edits when one edit fails", async () => {
			const testFile = join(testDir, "edit-no-partial.txt");
			const originalContent = "alpha\nbeta\ngamma\n";
			writeFileSync(testFile, originalContent);

			await expect(
				editTool.execute("test-call-13", {
					path: testFile,
					edits: [
						{ oldText: "alpha\n", newText: "ALPHA\n" },
						{ oldText: "missing\n", newText: "MISSING\n" },
					],
				}),
			).rejects.toThrow(/Could not find/);

			expect(readFileSync(testFile, "utf-8")).toBe(originalContent);
		});

		it("should include EACCES for read-only files", async () => {
			const testFile = join(testDir, "edit-readonly.txt");
			writeFileSync(testFile, "hello\n");
			chmodSync(testFile, 0o444);

			await expect(
				editTool.execute("test-call-14", {
					path: testFile,
					edits: [{ oldText: "hello", newText: "world" }],
				}),
			).rejects.toThrow(`Could not edit file: ${testFile}. Error code: EACCES.`);
		});

		it("should include the original error message for unknown edit access errors", async () => {
			const genericFailureTool = createEditTool(testDir, {
				operations: {
					access: async () => {
						throw new Error("disk offline");
					},
					readFile: async () => Buffer.from("hello\n", "utf-8"),
					writeFile: async () => {},
				},
			});

			await expect(
				genericFailureTool.execute("test-call-16", {
					path: "broken.txt",
					edits: [{ oldText: "hello", newText: "world" }],
				}),
			).rejects.toThrow("Could not edit file: broken.txt. Error: disk offline.");
		});

		it("should include ENOENT in diff preview for missing files", async () => {
			const missingFile = join(testDir, "missing-preview.txt");
			const result = await computeEditsDiff(missingFile, [{ oldText: "hello", newText: "world" }], testDir);

			// Source surfaces an actionable "use the write tool" hint after the code.
			expect(result).toEqual({
				error: `Could not edit file: ${missingFile}. Error code: ENOENT. ${missingFile} does not exist. Use the write tool to create it, e.g. write ${missingFile} with the full content.`,
			});
		});

		it("should include EACCES in diff preview for unreadable files", async () => {
			const unreadableFile = join(testDir, "unreadable-preview.txt");
			writeFileSync(unreadableFile, "hello\n");
			chmodSync(unreadableFile, 0o222);

			const result = await computeEditsDiff(unreadableFile, [{ oldText: "hello", newText: "world" }], testDir);

			expect(result).toEqual({ error: `Could not edit file: ${unreadableFile}. Error code: EACCES.` });
		});
	});

	describe("atomic writes", () => {
		it("atomicWriteFile writes content fully and leaves no temp file behind", async () => {
			const target = join(testDir, "atomic-new.txt");
			const content = "line one\nline two\n";
			await atomicWriteFile(target, content);
			expect(readFileSync(target, "utf-8")).toBe(content);
			// The temp file must have been renamed into place, not leaked.
			const leftover = readdirSync(testDir).filter((name) => name.endsWith(".tmp"));
			expect(leftover).toEqual([]);
		});

		it("atomicWriteFile preserves the existing file mode on overwrite (executable bit)", async () => {
			const target = join(testDir, "atomic-exec.sh");
			writeFileSync(target, "original\n");
			chmodSync(target, 0o755);
			expect(statSync(target).mode & 0o777).toBe(0o755);

			await atomicWriteFile(target, "replaced\n");

			expect(readFileSync(target, "utf-8")).toBe("replaced\n");
			// A naive temp+rename would reset this to 0o666; mode preservation keeps 0o755.
			expect(statSync(target).mode & 0o777).toBe(0o755);
		});

		it("atomicWriteFile cleans up the temp file and leaves the target intact when the write fails", async () => {
			const target = join(testDir, "atomic-preserve.txt");
			writeFileSync(target, "untouched\n");
			// Point at a path inside a non-existent directory so the temp-file write
			// fails before any rename. The target must remain unchanged and no temp
			// artifact may leak in the parent dir.
			const badPath = join(testDir, "missing-subdir", "nope.txt");
			await expect(atomicWriteFile(badPath, "anything\n")).rejects.toThrow();
			expect(readFileSync(target, "utf-8")).toBe("untouched\n");
			expect(readdirSync(testDir).filter((name) => name.endsWith(".tmp"))).toEqual([]);
		});

		it("atomicWriteFile writes through a symlink to its target and preserves the link", async () => {
			// Regression: rename(temp, symlinkPath) replaces the symlink ENTRY with a
			// regular file, breaking the link and leaving the real target unchanged.
			// atomicWriteFile must resolve the symlink and write the REAL file.
			const real = join(testDir, "symlink-real.txt");
			writeFileSync(real, "original\n");
			const link = join(testDir, "symlink-link.txt");
			symlinkSync(real, link);
			expect(lstatSync(link).isSymbolicLink()).toBe(true);

			await atomicWriteFile(link, "edited-through-link\n");

			// The link is still a symlink...
			expect(lstatSync(link).isSymbolicLink()).toBe(true);
			// ...and the REAL target was updated (writing through the link).
			expect(readFileSync(real, "utf-8")).toBe("edited-through-link\n");
			expect(readFileSync(link, "utf-8")).toBe("edited-through-link\n");
			// No temp artifact leaked.
			expect(readdirSync(testDir).filter((name) => name.endsWith(".tmp"))).toEqual([]);
		});

		it("atomicWriteFile creates the target through a dangling symlink without breaking the link", async () => {
			// A dangling symlink (target doesn't exist yet) can't be realpath-resolved.
			// Writing through the link creates the pointed-to file and keeps the link.
			const real = join(testDir, "dangling-real.txt");
			const link = join(testDir, "dangling-link.txt");
			symlinkSync(real, link);
			expect(lstatSync(link).isSymbolicLink()).toBe(true);
			expect(existsSync(real)).toBe(false);

			await atomicWriteFile(link, "created-through-dangling\n");

			expect(lstatSync(link).isSymbolicLink()).toBe(true);
			expect(readFileSync(real, "utf-8")).toBe("created-through-dangling\n");
			expect(readFileSync(link, "utf-8")).toBe("created-through-dangling\n");
		});

		it("write tool leaves no temp file behind after a successful write", async () => {
			const target = join(testDir, "write-atomic.txt");
			const content = "hello atomic\n";
			const result = await writeTool.execute("test-call-write-atomic", { path: target, content });
			expect(getTextOutput(result)).toContain("Successfully wrote");
			expect(readFileSync(target, "utf-8")).toBe(content);
			expect(readdirSync(testDir).filter((name) => name.endsWith(".tmp"))).toEqual([]);
		});

		it("write tool reports accurate UTF-8 byte count for multi-byte content", async () => {
			const target = join(testDir, "write-bytes.txt");
			// 4 CJK chars = 12 UTF-8 bytes, but content.length (UTF-16 code units) = 4.
			const content = "你好世界";
			const result = await writeTool.execute("test-call-write-bytes", { path: target, content });
			const output = getTextOutput(result);
			expect(output).toContain("Successfully wrote 12 bytes");
			expect(output).not.toContain("Successfully wrote 4 bytes");
		});

		it("edit tool preserves an existing executable bit through an edit", async () => {
			const target = join(testDir, "edit-atomic.sh");
			writeFileSync(target, ["alpha", "beta", "gamma"].join("\n"));
			chmodSync(target, 0o755);

			const result = await editTool.execute("test-call-edit-atomic", {
				path: target,
				edits: [{ oldText: "beta", newText: "BETA" }],
			});
			expect(getTextOutput(result)).toContain("Successfully replaced");
			expect(readFileSync(target, "utf-8")).toBe(["alpha", "BETA", "gamma"].join("\n"));
			expect(statSync(target).mode & 0o777).toBe(0o755);
			expect(readdirSync(testDir).filter((name) => name.endsWith(".tmp"))).toEqual([]);
		});

		it("write tool refuses to clobber a directory with a clear error and leaves no temp behind", async () => {
			const dirTarget = join(testDir, "a-subdir");
			mkdirSync(dirTarget, { recursive: true });
			await expect(writeTool.execute("test-call-write-dir", { path: dirTarget, content: "nope\n" })).rejects.toThrow(
				/is a directory, not a file/i,
			);
			// No stray temp file leaked inside the target directory.
			expect(readdirSync(dirTarget).filter((name) => name.endsWith(".tmp"))).toEqual([]);
		});
	});

	describe("bash tool", () => {
		it("should execute simple commands", async () => {
			const result = await bashTool.execute("test-call-8", { command: "echo 'test output'" });

			expect(getTextOutput(result)).toContain("test output");
			expect(result.details).toBeUndefined();
		});

		it("should handle command errors", async () => {
			await expect(bashTool.execute("test-call-9", { command: "exit 1" })).rejects.toThrow(
				/(Command failed|code 1)/,
			);
		});

		it("should surface a signal-termination status when exitCode is null", async () => {
			// null exit code = killed by a signal that was NOT our abort/timeout
			// (e.g. OOM SIGKILL / external SIGTERM). The model must not mistake the
			// partial output for success.
			const operations: BashOperations = {
				exec: async (_command, _cwd, { onData }) => {
					onData(Buffer.from("partial output before kill\n", "utf-8"));
					return { exitCode: null };
				},
			};
			const bash = createBashTool(testDir, { operations });
			await expect(bash.execute("test-call-signal", { command: "oom-bait" })).rejects.toThrow(
				/terminated by a signal/i,
			);
			const err = await bash.execute("test-call-signal-2", { command: "oom-bait" }).catch((e) => e);
			expect(err.message).toContain("no exit code");
			expect(err.message).toContain("partial output before kill");
		});

		it("OutputAccumulator persists truncated output to a temp file the model can read", async () => {
			// Truncated output is spilled to a temp file so the model can read/tail it.
			// This locks the ensureTempFile path (which now also registers exit cleanup).
			const acc = new OutputAccumulator({ maxBytes: 64, maxLines: 2, tempFilePrefix: "pi-test-acc" });
			acc.append(Buffer.from("line one is long enough to exceed the small byte budget\n"));
			acc.append(Buffer.from("line two keeps spilling\n"));
			acc.finish();
			const snapshot = acc.snapshot({ persistIfTruncated: true });
			expect(snapshot.truncation.truncated).toBe(true);
			expect(snapshot.fullOutputPath).toBeDefined();
			expect(snapshot.fullOutputPath).toContain("pi-test-acc");
			// Flush the write stream so the file is on disk before we read it.
			await acc.closeTempFile();
			expect(existsSync(snapshot.fullOutputPath!)).toBe(true);
			expect(readFileSync(snapshot.fullOutputPath!, "utf-8")).toContain("line one");
			// Clean up the tracked temp file for the test (the exit handler handles real runs).
			try {
				rmSync(snapshot.fullOutputPath!);
			} catch {
				// ignore
			}
		});

		it("OutputAccumulator degrades gracefully when the temp-file stream errors mid-stream", async () => {
			// Regression: ensureTempFile created a WriteStream with NO "error"
			// listener. A mid-stream write failure (disk full / EACCES / ENOTDIR)
			// would emit an unhandled "error" event → uncaught → agent crash, AND
			// snapshot() would point the model at a broken "Full output" path.
			// Force a real ENOTDIR by making the temp file's parent a regular file:
			// createWriteStream succeeds lazily, the first .write() emits "error".
			const blocker = join(tmpdir(), "pi-err-parent");
			writeFileSync(blocker, "x");
			try {
				const acc = new OutputAccumulator({
					maxBytes: 64,
					maxLines: 2,
					tempFilePrefix: "pi-err-parent/child",
				});
				// Large enough to exceed the 64-byte budget and trigger ensureTempFile.
				acc.append(Buffer.from("this line is long enough to exceed the small byte budget for sure\n"));
				acc.append(Buffer.from("a second line keeps spilling past the budget\n"));
				// Wait for the async ENOTDIR "error" event to fire and be absorbed by
				// the persistent listener (no unhandled-error crash = test passes).
				for (let i = 0; i < 50; i++) {
					const snap = acc.snapshot({ persistIfTruncated: true });
					if (snap.fullOutputPath === undefined) break;
					await new Promise((resolve) => setTimeout(resolve, 5));
				}
				// Appending after the error must not throw (graceful degradation to
				// the rolling tail rather than crashing on a nullled stream). Do this
				// BEFORE finish() — a finished accumulator rightly rejects appends.
				expect(() => acc.append(Buffer.from("post-failure line that simply drops\n"))).not.toThrow();
				acc.finish();
				const snapshot = acc.snapshot({ persistIfTruncated: true });
				// The broken temp path must be withheld so the model is never told to
				// read a partial/missing "Full output" file.
				expect(snapshot.fullOutputPath).toBeUndefined();
				// The rolling tail still works after the temp file died — the
				// post-failure append reached the in-memory snapshot (maxLines=2
				// trims earlier lines, so check the most recent one).
				expect(snapshot.content).toContain("post-failure line that simply drops");
			} finally {
				try {
					rmSync(blocker);
				} catch {
					// ignore
				}
			}
		});

		it("should respect timeout", async () => {
			await expect(bashTool.execute("test-call-10", { command: "sleep 5", timeout: 1 })).rejects.toThrow(
				/timed out/i,
			);
		});

		it("should include full output path for truncated timeout and abort errors", async () => {
			for (const testCase of [
				{ error: "timeout:5", expected: "Command timed out after 5 seconds" },
				{ error: "aborted", expected: "Command aborted" },
			]) {
				const operations: BashOperations = {
					exec: async (_command, _cwd, { onData }) => {
						for (let i = 1; i <= 3000; i++) {
							onData(Buffer.from(`${i}\n`, "utf-8"));
						}
						throw new Error(testCase.error);
					},
				};
				const bash = createBashTool(testDir, { operations });

				let error: unknown;
				try {
					await bash.execute(`test-call-${testCase.error}`, { command: "chatty-fail" });
				} catch (err) {
					error = err;
				}

				expect(error).toBeInstanceOf(Error);
				const message = (error as Error).message;
				expect(message).toContain(testCase.expected);
				expect(message).toMatch(/\[Showing lines \d+-\d+ of \d+\. Full output: /);
				expect(message).not.toContain("Full output: undefined");
				const fullOutputPath = message.match(/Full output: ([^\]\n]+)/)?.[1];
				expect(fullOutputPath).toBeDefined();
				expect(existsSync(fullOutputPath!)).toBe(true);
				const fullOutput = readFileSync(fullOutputPath!, "utf-8");
				expect(fullOutput).toContain("1\n2\n3");
				expect(fullOutput).toContain("2998\n2999\n3000");
			}
		});

		it("should throw error when cwd does not exist", async () => {
			const nonexistentCwd = "/this/directory/definitely/does/not/exist/12345";

			const bashToolWithBadCwd = createBashTool(nonexistentCwd);

			await expect(bashToolWithBadCwd.execute("test-call-11", { command: "echo test" })).rejects.toThrow(
				/Working directory does not exist/,
			);
		});

		it("should handle process spawn errors", async () => {
			vi.spyOn(shellModule, "getShellConfig").mockReturnValueOnce({
				shell: "/nonexistent-shell-path-xyz123",
				args: ["-c"],
			});

			const bashWithBadShell = createBashTool(testDir);

			await expect(bashWithBadShell.execute("test-call-12", { command: "echo test" })).rejects.toThrow(/ENOENT/);
		});

		it("should pass shellPath through to shell resolution", async () => {
			const getShellConfigSpy = vi.spyOn(shellModule, "getShellConfig");
			const bashWithCustomShell = createBashTool(testDir, {
				shellPath: "/custom/bash",
				operations: {
					exec: async () => ({ exitCode: 0 }),
				},
			});

			await bashWithCustomShell.execute("test-call-12b", { command: "echo test" });

			expect(getShellConfigSpy).not.toHaveBeenCalled();

			const ops = createLocalBashOperations({ shellPath: "/custom/bash" });
			await expect(
				ops.exec("echo test", testDir, {
					onData: () => {},
				}),
			).rejects.toThrow("Custom shell path not found: /custom/bash");
			expect(getShellConfigSpy).toHaveBeenCalledWith("/custom/bash");
		});

		it("should prepend command prefix when configured", async () => {
			const bashWithPrefix = createBashTool(testDir, {
				commandPrefix: "export TEST_VAR=hello",
			});

			const result = await bashWithPrefix.execute("test-prefix-1", { command: "echo $TEST_VAR" });
			expect(getTextOutput(result).trim()).toBe("hello");
		});

		it("should include output from both prefix and command", async () => {
			const bashWithPrefix = createBashTool(testDir, {
				commandPrefix: "echo prefix-output",
			});

			const result = await bashWithPrefix.execute("test-prefix-2", { command: "echo command-output" });
			expect(getTextOutput(result).trim()).toBe("prefix-output\ncommand-output");
		});

		it("should work without command prefix", async () => {
			const bashWithoutPrefix = createBashTool(testDir, {});

			const result = await bashWithoutPrefix.execute("test-prefix-3", { command: "echo no-prefix" });
			expect(getTextOutput(result).trim()).toBe("no-prefix");
		});

		it("should coalesce streaming updates for chatty output", async () => {
			const operations: BashOperations = {
				exec: async (_command, _cwd, { onData }) => {
					for (let i = 0; i < 5000; i++) {
						onData(Buffer.from(`line ${i}\n`, "utf-8"));
					}
					return { exitCode: 0 };
				},
			};
			const updates: Array<{ content: Array<{ type: string; text?: string }>; details?: unknown }> = [];
			const bash = createBashTool(testDir, { operations });

			const result = await bash.execute("test-call-chatty-updates", { command: "chatty" }, undefined, (update) =>
				updates.push(update),
			);

			expect(updates.length).toBeLessThan(25);
			expect(getTextOutput(result)).toContain("line 4999");
		});

		it("should not count a trailing newline as an extra truncated bash output line", async () => {
			const operations: BashOperations = {
				exec: async (_command, _cwd, { onData }) => {
					for (let i = 1; i <= 4000; i++) {
						onData(Buffer.from(`line-${String(i).padStart(4, "0")}\n`, "utf-8"));
					}
					return { exitCode: 0 };
				},
			};
			const bash = createBashTool(testDir, { operations });

			const result = await bash.execute("test-call-trailing-newline-line-count", { command: "many-lines" });
			const output = getTextOutput(result);

			expect(result.details?.truncation?.totalLines).toBe(4000);
			expect(result.details?.truncation?.outputLines).toBe(2000);
			expect(output).toContain("line-2001");
			expect(output).toContain("line-4000");
			expect(output).toMatch(/\[Showing lines 2001-4000 of 4000\. Full output: /);
			expect(output).not.toContain("4001");
		});

		it("should decode UTF-8 characters split across output chunks", async () => {
			const euro = Buffer.from("€\n", "utf-8");
			const operations: BashOperations = {
				exec: async (_command, _cwd, { onData }) => {
					onData(euro.subarray(0, 1));
					onData(euro.subarray(1));
					return { exitCode: 0 };
				},
			};
			const bash = createBashTool(testDir, { operations });

			const result = await bash.execute("test-call-split-utf8", { command: "split-utf8" });

			expect(getTextOutput(result).trim()).toBe("€");
		});

		it("should expose local bash operations for extension reuse", async () => {
			const ops = createLocalBashOperations();
			const chunks: Buffer[] = [];

			const result = await ops.exec("echo $TEST_LOCAL_BASH_OPS", testDir, {
				onData: (data) => chunks.push(data),
				env: { ...process.env, TEST_LOCAL_BASH_OPS: "from-local-ops" },
			});

			expect(result.exitCode).toBe(0);
			expect(Buffer.concat(chunks).toString("utf-8").trim()).toBe("from-local-ops");
		});

		it("should preserve executeBash sanitization when using local bash operations", async () => {
			const result = await executeBashWithOperations(
				"printf '\\033[31mred\\033[0m\\r\\n'",
				process.cwd(),
				createLocalBashOperations(),
			);

			expect(result.exitCode).toBe(0);
			expect(result.output).toBe("red\n");
		});

		it("should persist full output when truncation happens by line count only", async () => {
			const bash = createBashTool(testDir);
			const result = await bash.execute("test-call-line-truncation", { command: "seq 3000" });
			const output = getTextOutput(result);
			const fullOutputPath = result.details?.fullOutputPath;

			expect(result.details?.truncation?.truncated).toBe(true);
			expect(result.details?.truncation?.truncatedBy).toBe("lines");
			expect(fullOutputPath).toBeDefined();
			expect(output).toMatch(/\[Showing lines \d+-\d+ of \d+\. Full output: /);
			expect(output).not.toContain("Full output: undefined");

			for (let i = 0; i < 20 && (!fullOutputPath || !existsSync(fullOutputPath)); i++) {
				await new Promise((resolve) => setTimeout(resolve, 10));
			}

			expect(fullOutputPath).toBeDefined();
			expect(existsSync(fullOutputPath!)).toBe(true);
			const fullOutput = readFileSync(fullOutputPath!, "utf-8");
			expect(fullOutput).toContain("1\n2\n3");
			expect(fullOutput).toContain("2998\n2999\n3000");
		});

		it("executeBash should persist full output when truncation happens by line count only", async () => {
			const result = await executeBashWithOperations("seq 3000", process.cwd(), createLocalBashOperations());
			const fullOutputPath = result.fullOutputPath;

			expect(result.truncated).toBe(true);
			expect(fullOutputPath).toBeDefined();

			for (let i = 0; i < 20 && (!fullOutputPath || !existsSync(fullOutputPath)); i++) {
				await new Promise((resolve) => setTimeout(resolve, 10));
			}

			expect(fullOutputPath).toBeDefined();
			expect(existsSync(fullOutputPath!)).toBe(true);
			const fullOutput = readFileSync(fullOutputPath!, "utf-8");
			expect(fullOutput).toContain("1\n2\n3");
			expect(fullOutput).toContain("2998\n2999\n3000");
		});

		it("executeBash should flush the temp file before returning so fullOutputPath is immediately readable", async () => {
			// Regression: executeBashWithOperations used to call tempFileStream.end()
			// WITHOUT awaiting 'finish', then return fullOutputPath — the caller could
			// read the path before writes were flushed to disk (the older test above
			// had to poll existsSync to work around this). Now the stream is awaited,
			// so the file is readable the instant the call resolves.
			const result = await executeBashWithOperations("seq 4000", process.cwd(), createLocalBashOperations());
			const fullOutputPath = result.fullOutputPath;

			expect(result.truncated).toBe(true);
			expect(fullOutputPath).toBeDefined();
			// No polling: the file must already exist and be fully flushed.
			expect(existsSync(fullOutputPath!)).toBe(true);
			const fullOutput = readFileSync(fullOutputPath!, "utf-8");
			expect(fullOutput).toContain("1\n2\n3");
			expect(fullOutput).toContain("3998\n3999\n4000");
			try {
				rmSync(fullOutputPath!);
			} catch {
				// ignore
			}
		});
	});

	describe("grep tool", () => {
		it("should include filename when searching a single file", async () => {
			const testFile = join(testDir, "example.txt");
			writeFileSync(testFile, "first line\nmatch line\nlast line");

			const result = await grepTool.execute("test-call-11", {
				pattern: "match",
				path: testFile,
			});

			const output = getTextOutput(result);
			expect(output).toContain("example.txt:2: match line");
		});

		it("should respect global limit and include context lines", async () => {
			const testFile = join(testDir, "context.txt");
			const content = ["before", "match one", "after", "middle", "match two", "after two"].join("\n");
			writeFileSync(testFile, content);

			const result = await grepTool.execute("test-call-12", {
				pattern: "match",
				path: testFile,
				limit: 1,
				context: 1,
			});

			const output = getTextOutput(result);
			expect(output).toContain("context.txt-1- before");
			expect(output).toContain("context.txt:2: match one");
			expect(output).toContain("context.txt-3- after");
			expect(output).toContain("[1 matches limit reached. Use limit=2 for more, or refine pattern]");
			// Ensure second match is not present
			expect(output).not.toContain("match two");
		});

		it("should treat flag-like patterns as search text", async () => {
			const marker = join(testDir, "grep-injection-marker");
			const payload = join(testDir, "payload.sh");
			const testFile = join(testDir, "target.txt");
			writeFileSync(payload, `#!/bin/sh\necho executed > ${marker}\ncat "$1"\n`);
			chmodSync(payload, 0o755);
			writeFileSync(testFile, "target\n");

			const result = await grepTool.execute("test-call-grep-injection", {
				pattern: `--pre=${payload}`,
				path: testDir,
			});

			expect(getTextOutput(result)).toContain("No matches found");
			expect(existsSync(marker)).toBe(false);
		});

		it("should convert an invalid regex into an actionable hint (literal:true or escape)", async () => {
			await expect(
				grepTool.execute("test-call-grep-invalid-regex", {
					pattern: "(unclosed",
					path: testDir,
				}),
			).rejects.toThrow(/Invalid regex pattern.*Hint.*literal:true/is);
		});
	});

	describe("find tool", () => {
		it("should include hidden files that are not gitignored", async () => {
			const hiddenDir = join(testDir, ".secret");
			mkdirSync(hiddenDir);
			writeFileSync(join(hiddenDir, "hidden.txt"), "hidden");
			writeFileSync(join(testDir, "visible.txt"), "visible");

			const result = await findTool.execute("test-call-13", {
				pattern: "**/*.txt",
				path: testDir,
			});

			const outputLines = getTextOutput(result)
				.split("\n")
				.map((line) => line.trim())
				.filter(Boolean);

			expect(outputLines).toContain("visible.txt");
			expect(outputLines).toContain(".secret/hidden.txt");
		});

		it("should respect .gitignore", async () => {
			writeFileSync(join(testDir, ".gitignore"), "ignored.txt\n");
			writeFileSync(join(testDir, "ignored.txt"), "ignored");
			writeFileSync(join(testDir, "kept.txt"), "kept");

			const result = await findTool.execute("test-call-14", {
				pattern: "**/*.txt",
				path: testDir,
			});

			const output = getTextOutput(result);
			expect(output).toContain("kept.txt");
			expect(output).not.toContain("ignored.txt");
		});

		it("should surface fd glob parse errors", async () => {
			await expect(
				findTool.execute("test-call-15", {
					pattern: "[",
					path: testDir,
				}),
			).rejects.toThrow(/Invalid glob pattern.*Hint.*backslash/is);
		});

		it("should treat flag-like patterns as search text", async () => {
			const result = await findTool.execute("test-call-find-flag-pattern", {
				pattern: "--help",
				path: testDir,
			});

			expect(getTextOutput(result)).toContain("No files found matching pattern");
		});
	});

	describe("ls tool", () => {
		it("should list dotfiles and directories", async () => {
			writeFileSync(join(testDir, ".hidden-file"), "secret");
			mkdirSync(join(testDir, ".hidden-dir"));

			const result = await lsTool.execute("test-call-15", { path: testDir });
			const output = getTextOutput(result);

			expect(output).toContain(".hidden-file");
			expect(output).toContain(".hidden-dir/");
		});

		it("should reject a file path with an actionable read hint instead of 'Not a directory'", async () => {
			const filePath = join(testDir, "a-file.txt");
			writeFileSync(filePath, "hello\n");
			await expect(lsTool.execute("test-call-ls-file", { path: filePath })).rejects.toThrow(/is a file/i);
			const err = await lsTool.execute("test-call-ls-file-2", { path: filePath }).catch((e) => e);
			expect(err.message).toContain("read");
			expect(err.message).not.toContain("Not a directory");
		});
	});
});

describe("edit tool fuzzy matching", () => {
	let testDir: string;

	beforeEach(() => {
		testDir = join(tmpdir(), `coding-agent-fuzzy-test-${Date.now()}`);
		mkdirSync(testDir, { recursive: true });
	});

	afterEach(() => {
		rmSync(testDir, { recursive: true, force: true });
	});

	it("should match text with trailing whitespace stripped", async () => {
		const testFile = join(testDir, "trailing-ws.txt");
		// File has trailing spaces on lines
		writeFileSync(testFile, "line one   \nline two  \nline three\n");

		// oldText without trailing whitespace should still match
		const result = await editTool.execute("test-fuzzy-1", {
			path: testFile,
			edits: [{ oldText: "line one\nline two\n", newText: "replaced\n" }],
		});

		expect(getTextOutput(result)).toContain("Successfully replaced");
		const content = readFileSync(testFile, "utf-8");
		expect(content).toBe("replaced\nline three\n");
	});

	it("should match fullwidth punctuation in Chinese text", async () => {
		const testFile = join(testDir, "chinese-punctuation.txt");
		writeFileSync(testFile, "你好，世界\n你好（世界）\n");

		const result = await editTool.execute("test-fuzzy-chinese", {
			path: testFile,
			edits: [{ oldText: "你好,世界\n你好(世界)\n", newText: "你好，pi\n你好(pi)\n" }],
		});

		expect(getTextOutput(result)).toContain("Successfully replaced");
		const content = readFileSync(testFile, "utf-8");
		expect(content).toBe("你好，pi\n你好(pi)\n");
	});

	it("should match compatibility-equivalent Unicode forms", async () => {
		const testFile = join(testDir, "unicode-compatibility.txt");
		writeFileSync(testFile, "ＡＢＣ１２３\ncafe\u0301\n");

		const result = await editTool.execute("test-fuzzy-unicode", {
			path: testFile,
			edits: [{ oldText: "ABC123\ncafé\n", newText: "XYZ789\ncoffee\n" }],
		});

		expect(getTextOutput(result)).toContain("Successfully replaced");
		const content = readFileSync(testFile, "utf-8");
		expect(content).toBe("XYZ789\ncoffee\n");
	});

	it("should match smart single quotes to ASCII quotes", async () => {
		const testFile = join(testDir, "smart-quotes.txt");
		// File has smart/curly single quotes (U+2018, U+2019)
		writeFileSync(testFile, "console.log(\u2018hello\u2019);\n");

		// oldText with ASCII quotes should match
		const result = await editTool.execute("test-fuzzy-2", {
			path: testFile,
			edits: [{ oldText: "console.log('hello');", newText: "console.log('world');" }],
		});

		expect(getTextOutput(result)).toContain("Successfully replaced");
		const content = readFileSync(testFile, "utf-8");
		expect(content).toContain("world");
	});

	it("should match smart double quotes to ASCII quotes", async () => {
		const testFile = join(testDir, "smart-double-quotes.txt");
		// File has smart/curly double quotes (U+201C, U+201D)
		writeFileSync(testFile, "const msg = \u201CHello World\u201D;\n");

		// oldText with ASCII quotes should match
		const result = await editTool.execute("test-fuzzy-3", {
			path: testFile,
			edits: [{ oldText: 'const msg = "Hello World";', newText: 'const msg = "Goodbye";' }],
		});

		expect(getTextOutput(result)).toContain("Successfully replaced");
		const content = readFileSync(testFile, "utf-8");
		expect(content).toContain("Goodbye");
	});

	it("should match Unicode dashes to ASCII hyphen", async () => {
		const testFile = join(testDir, "unicode-dashes.txt");
		// File has en-dash (U+2013) and em-dash (U+2014)
		writeFileSync(testFile, "range: 1\u20135\nbreak\u2014here\n");

		// oldText with ASCII hyphens should match
		const result = await editTool.execute("test-fuzzy-4", {
			path: testFile,
			edits: [{ oldText: "range: 1-5\nbreak-here", newText: "range: 10-50\nbreak--here" }],
		});

		expect(getTextOutput(result)).toContain("Successfully replaced");
		const content = readFileSync(testFile, "utf-8");
		expect(content).toContain("10-50");
	});

	it("should match non-breaking space to regular space", async () => {
		const testFile = join(testDir, "nbsp.txt");
		// File has non-breaking space (U+00A0)
		writeFileSync(testFile, "hello\u00A0world\n");

		// oldText with regular space should match
		const result = await editTool.execute("test-fuzzy-5", {
			path: testFile,
			edits: [{ oldText: "hello world", newText: "hello universe" }],
		});

		expect(getTextOutput(result)).toContain("Successfully replaced");
		const content = readFileSync(testFile, "utf-8");
		expect(content).toContain("universe");
	});

	it("should prefer exact match over fuzzy match", async () => {
		const testFile = join(testDir, "exact-preferred.txt");
		// File has both exact and fuzzy-matchable content
		writeFileSync(testFile, "const x = 'exact';\nconst y = 'other';\n");

		const result = await editTool.execute("test-fuzzy-6", {
			path: testFile,
			edits: [{ oldText: "const x = 'exact';", newText: "const x = 'changed';" }],
		});

		expect(getTextOutput(result)).toContain("Successfully replaced");
		const content = readFileSync(testFile, "utf-8");
		expect(content).toBe("const x = 'changed';\nconst y = 'other';\n");
	});

	it("should still fail when text is not found even with fuzzy matching", async () => {
		const testFile = join(testDir, "no-match.txt");
		writeFileSync(testFile, "completely different content\n");

		await expect(
			editTool.execute("test-fuzzy-7", {
				path: testFile,
				edits: [{ oldText: "this does not exist", newText: "replacement" }],
			}),
		).rejects.toThrow(/Could not find the exact text/);
	});

	it("should embed a surrounding-line snippet in the not-found hint so the model can retry without a read", async () => {
		// The anchor line ("gamma") exists, but the full block doesn't — the hint
		// must locate it, name a cause, and embed the real surrounding lines so the
		// model can copy the exact text instead of issuing a separate read.
		const testFile = join(testDir, "hint-snippet.txt");
		writeFileSync(testFile, ["alpha", "beta", "gamma", "delta", "epsilon"].join("\n"));

		const err = await editTool
			.execute("test-hint-snippet", {
				path: testFile,
				edits: [{ oldText: "gamma\nWRONG", newText: "GAMMA\nRIGHT" }],
			})
			.catch((e) => e);
		expect(err.message).toContain("Could not find the exact text");
		expect(err.message).toContain("line 3");
		// The actual file lines around the anchor are embedded in the error.
		expect(err.message).toContain("beta");
		expect(err.message).toContain("gamma");
		expect(err.message).toContain("delta");
	});

	it("should detect duplicates after fuzzy normalization", async () => {
		const testFile = join(testDir, "fuzzy-dups.txt");
		// Two lines that are identical after trailing whitespace is stripped
		writeFileSync(testFile, "hello world   \nhello world\n");

		await expect(
			editTool.execute("test-fuzzy-8", {
				path: testFile,
				edits: [{ oldText: "hello world", newText: "replaced" }],
			}),
		).rejects.toThrow(/Found 2 occurrences/);
	});

	it("should support fuzzy matching in multi-edit mode", async () => {
		const testFile = join(testDir, "fuzzy-multi.txt");
		writeFileSync(testFile, "console.log(\u2018hello\u2019);\nhello\u00A0world\n");

		await editTool.execute("test-fuzzy-9", {
			path: testFile,
			edits: [
				{ oldText: "console.log('hello');\n", newText: "console.log('world');\n" },
				{ oldText: "hello world\n", newText: "hello universe\n" },
			],
		});

		expect(readFileSync(testFile, "utf-8")).toBe("console.log('world');\nhello universe\n");
	});
});

describe("edit tool CRLF handling", () => {
	let testDir: string;

	beforeEach(() => {
		testDir = join(tmpdir(), `coding-agent-crlf-test-${Date.now()}`);
		mkdirSync(testDir, { recursive: true });
	});

	afterEach(() => {
		rmSync(testDir, { recursive: true, force: true });
	});

	it("should match LF oldText against CRLF file content", async () => {
		const testFile = join(testDir, "crlf-test.txt");

		writeFileSync(testFile, "line one\r\nline two\r\nline three\r\n");

		const result = await editTool.execute("test-crlf-1", {
			path: testFile,
			edits: [{ oldText: "line two\n", newText: "replaced line\n" }],
		});

		expect(getTextOutput(result)).toContain("Successfully replaced");
	});

	it("should preserve CRLF line endings after edit", async () => {
		const testFile = join(testDir, "crlf-preserve.txt");
		writeFileSync(testFile, "first\r\nsecond\r\nthird\r\n");

		await editTool.execute("test-crlf-2", {
			path: testFile,
			edits: [{ oldText: "second\n", newText: "REPLACED\n" }],
		});

		const content = readFileSync(testFile, "utf-8");
		expect(content).toBe("first\r\nREPLACED\r\nthird\r\n");
	});

	it("should preserve LF line endings for LF files", async () => {
		const testFile = join(testDir, "lf-preserve.txt");
		writeFileSync(testFile, "first\nsecond\nthird\n");

		await editTool.execute("test-lf-1", {
			path: testFile,
			edits: [{ oldText: "second\n", newText: "REPLACED\n" }],
		});

		const content = readFileSync(testFile, "utf-8");
		expect(content).toBe("first\nREPLACED\nthird\n");
	});

	it("should detect duplicates across CRLF/LF variants", async () => {
		const testFile = join(testDir, "mixed-endings.txt");

		writeFileSync(testFile, "hello\r\nworld\r\n---\r\nhello\nworld\n");

		await expect(
			editTool.execute("test-crlf-dup", {
				path: testFile,
				edits: [{ oldText: "hello\nworld\n", newText: "replaced\n" }],
			}),
		).rejects.toThrow(/Found 2 occurrences/);
	});

	it("should preserve UTF-8 BOM after edit", async () => {
		const testFile = join(testDir, "bom-test.txt");
		writeFileSync(testFile, "\uFEFFfirst\r\nsecond\r\nthird\r\n");

		await editTool.execute("test-bom", {
			path: testFile,
			edits: [{ oldText: "second\n", newText: "REPLACED\n" }],
		});

		const content = readFileSync(testFile, "utf-8");
		expect(content).toBe("\uFEFFfirst\r\nREPLACED\r\nthird\r\n");
	});

	it("should preserve CRLF line endings and BOM in multi-edit mode", async () => {
		const testFile = join(testDir, "bom-crlf-multi.txt");
		writeFileSync(testFile, "\uFEFFfirst\r\nsecond\r\nthird\r\nfourth\r\n");

		await editTool.execute("test-crlf-multi", {
			path: testFile,
			edits: [
				{ oldText: "second\n", newText: "SECOND\n" },
				{ oldText: "fourth\n", newText: "FOURTH\n" },
			],
		});

		const content = readFileSync(testFile, "utf-8");
		expect(content).toBe("\uFEFFfirst\r\nSECOND\r\nthird\r\nFOURTH\r\n");
	});
});
