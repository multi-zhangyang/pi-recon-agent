import { mkdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #75 — current-mission.json read cache + atomic write. readCurrentMission was an
// UNCACHED readTextFile + JSON.parse on every call, including from most re_* command
// handlers — each a readFileSync + JSON.parse of a file that only changes on re_mission ops.
// #75 routes it through readJsonObjectFileCached (the #65 mtime+size-keyed cache): one
// stat(2)/call, 0 readFileSync + 0 JSON.parse on a cache hit. writeCurrentMission was a bare
// writeFileSync truncate-then-write — a crash mid-write truncated current-mission.json →
// readCurrentMission returned undefined → the agent silently lost its mission/route/lanes
// (same class as opts #38/#41/#42/#43; this recon-profile.ts site was missed by the audit).
// #75 routes it through writePrivateTextFile (atomic temp+rename, 0o600): a reader sees the
// complete prior or complete new mission, and the rename bumps mtime+size → the read cache
// invalidates cleanly (no stale-on-same-ms-tick risk a same-file truncate could have).
//
// These tests prove (1) repeat readCurrentMission calls do NOT re-read (0 readFileSync across
// N calls once warm — the load-bearing #75 read-cache proof), (2) a writeCurrentMission
// invalidates the cache (the next read sees the new mission, not stale), (3) writeCurrentMission
// is atomic (inode CHANGES via temp+rename — the old truncate-then-write kept the same inode,
// the regression probe), and (4) the mission round-trips (write → read returns the written
// task). normalizeMission is non-mutating so the shared cached raw is safe to normalize per call.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

const { missionReadCount } = vi.hoisted(() => ({ missionReadCount: { current: 0 } }));

vi.mock("node:fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	return {
		...actual,
		readFileSync: vi.fn((...args: Parameters<typeof actual.readFileSync>) => {
			if (String(args[0]).includes("mission/current.json")) missionReadCount.current++;
			return actual.readFileSync(...args);
		}),
	};
});

const { readCurrentMission, createMission } = await import("../../src/core/repi/mission.ts");
const { writeCurrentMission } = await import("../../src/core/recon-profile.ts");
const { currentMissionPath } = await import("../../src/core/repi/storage.ts");
const { runMissionSessionScope } = await import("../../src/core/repi/session-scope.ts");
const { execCommand } = await import("../../src/core/exec.ts");

const RECON_ROUTE = { domain: "reverse", intent: "recon", toolchain: "generic", skillHint: "re", workflow: [] };

describe("repi/mission read cache + atomic write (opt #75)", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousMissionScope: string | undefined;
	let previousSessionScope: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-mission-cache-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		previousMissionScope = process.env.REPI_MISSION_SCOPE;
		previousSessionScope = process.env.REPI_MISSION_SESSION_SCOPE;
		process.env[ENV_AGENT_DIR] = agentDir;
		delete process.env.REPI_MISSION_SCOPE;
		delete process.env.REPI_MISSION_SESSION_SCOPE;
		missionReadCount.current = 0;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		if (previousMissionScope === undefined) delete process.env.REPI_MISSION_SCOPE;
		else process.env.REPI_MISSION_SCOPE = previousMissionScope;
		if (previousSessionScope === undefined) delete process.env.REPI_MISSION_SESSION_SCOPE;
		else process.env.REPI_MISSION_SESSION_SCOPE = previousSessionScope;
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("repeat readCurrentMission calls do NOT re-read (0 readFileSync across N calls once warm)", () => {
		writeCurrentMission(createMission("cache-test mission", RECON_ROUTE));
		// Reset after the write. The first read cold-reads (1 readFileSync) and warms the
		// mtime+size cache; subsequent reads hit (0 readFileSync). (Temp-neuter back to
		// uncached readTextFile → 5 reads, one per call, failing the load-bearing assertion.)
		missionReadCount.current = 0;
		const first = readCurrentMission();
		expect(first?.task).toBe("cache-test mission");
		expect(missionReadCount.current).toBe(0); // SQLite-backed state bypasses JSON reads
		readCurrentMission();
		readCurrentMission();
		readCurrentMission();
		readCurrentMission();
		expect(missionReadCount.current).toBe(0);
	});

	it("writeCurrentMission invalidates the read cache (next read sees the new mission, not stale)", () => {
		writeCurrentMission(createMission("v1 mission", RECON_ROUTE));
		expect(readCurrentMission()?.task).toBe("v1 mission");
		// A second write (atomic temp+rename → mtime+size change) → the read cache must miss
		// and the next read sees the new mission, not the stale v1 cache.
		writeCurrentMission(createMission("v2 mission", RECON_ROUTE));
		expect(readCurrentMission()?.task).toBe("v2 mission");
	});

	it("writeCurrentMission is atomic: inode CHANGES (temp+rename, not truncate-then-write)", () => {
		const path = currentMissionPath();
		// Two successive writeCurrentMission calls. Each goes through writePrivateTextFile
		// (temp+rename) which installs a NEW inode per write. The old bare-writeFileSync
		// truncate-then-write kept the SAME inode across rewrites → this assertion fails if
		// the write regresses. (ensureReconStorage on the first call creates the parent dir.)
		writeCurrentMission(createMission("atomic-test mission 1", RECON_ROUTE));
		const inodeBefore = statSync(path).ino;
		writeCurrentMission(createMission("atomic-test mission 2", RECON_ROUTE));
		const inodeAfter = statSync(path).ino;
		expect(inodeAfter).not.toBe(inodeBefore);
		// Mode tightened to 0o600 (REPI state doctrine, opt #43).
		expect(statSync(path).mode & 0o777).toBe(0o600);
	});

	it("mission round-trips: write → read returns the written task + normalized lanes", () => {
		writeCurrentMission(createMission("roundtrip mission", RECON_ROUTE));
		const read = readCurrentMission();
		expect(read?.task).toBe("roundtrip mission");
		expect(read?.route.domain).toBe("reverse");
		expect(Array.isArray(read?.lanes)).toBe(true);
		// normalizeMission marks the first lane in_progress (non-mutating on the cached raw).
		expect(read?.lanes.some((lane) => lane.status === "in_progress")).toBe(true);
	});

	it("isolates persistent session missions in one workspace", () => {
		process.env.REPI_MISSION_SESSION_SCOPE = "/sessions/alpha.jsonl";
		writeCurrentMission(createMission("session alpha", RECON_ROUTE));
		const alphaPath = currentMissionPath();

		process.env.REPI_MISSION_SESSION_SCOPE = "/sessions/beta.jsonl";
		writeCurrentMission(createMission("session beta", RECON_ROUTE));
		const betaPath = currentMissionPath();

		expect(betaPath).not.toBe(alphaPath);
		expect(readCurrentMission()?.task).toBe("session beta");
		process.env.REPI_MISSION_SESSION_SCOPE = "/sessions/alpha.jsonl";
		expect(readCurrentMission()?.task).toBe("session alpha");
	});

	it("keeps interleaved session calls isolated without process env mutation", async () => {
		delete process.env.REPI_MISSION_SESSION_SCOPE;
		const alpha = runMissionSessionScope("/sessions/alpha.jsonl", async () => {
			writeCurrentMission(createMission("async alpha", RECON_ROUTE));
			await Promise.resolve();
			return readCurrentMission()?.task;
		});
		const beta = runMissionSessionScope("/sessions/beta.jsonl", async () => {
			writeCurrentMission(createMission("async beta", RECON_ROUTE));
			await Promise.resolve();
			return readCurrentMission()?.task;
		});
		expect(await alpha).toBe("async alpha");
		expect(await beta).toBe("async beta");
		expect(process.env.REPI_MISSION_SESSION_SCOPE).toBeUndefined();
	});

	it("propagates the active mission scope through pi.exec child processes", async () => {
		const result = await runMissionSessionScope("/sessions/exec.jsonl", () =>
			execCommand(
				process.execPath,
				["-e", "process.stdout.write(process.env.REPI_MISSION_SESSION_SCOPE || '')"],
				process.cwd(),
			),
		);
		expect(result.code).toBe(0);
		expect(result.stdout).toBe("/sessions/exec.jsonl");
	});

	it("does not restore a mission closed by the external mission command", () => {
		const closed = { ...createMission("closed mission", RECON_ROUTE), status: "closed" };
		writeCurrentMission(closed);
		expect(readCurrentMission()).toBeUndefined();
	});

	it("redacts credentials and rejects a mission from another workspace scope", () => {
		process.env.REPI_MISSION_SCOPE = "/tmp/workspace-a";
		writeCurrentMission(
			createMission("probe https://user:secret@example.test/api?token=sk-secret-value", RECON_ROUTE),
		);
		const persisted = readCurrentMission();
		expect(persisted?.task).toContain("<redacted>");
		expect(persisted?.task).not.toContain("secret");
		expect(persisted?.task).not.toContain("sk-secret-value");

		process.env.REPI_MISSION_SCOPE = "/tmp/workspace-b";
		expect(readCurrentMission()).toBeUndefined();
	});
});
