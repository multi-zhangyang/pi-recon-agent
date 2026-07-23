import { describe, expect, it } from "vitest";
import { resolveSwarmExecutionMode } from "../src/core/repi/swarm-supervisor-runtime.ts";

describe("REPI swarm execution mode", () => {
	it("allows the simulated dispatcher only when it is explicitly selected", () => {
		expect(resolveSwarmExecutionMode({ execution: "simulated", agentThread: true })).toBe("simulated");
	});

	it("fails closed when real execution has no cwd", () => {
		expect(() => resolveSwarmExecutionMode({ execution: "real", cwd: "  ", agentThread: false })).toThrow(
			"RE_SWARM_REAL_CWD_REQUIRED",
		);
	});

	it("fails closed instead of recursively simulating inside an agent thread", () => {
		expect(() => resolveSwarmExecutionMode({ execution: "real", cwd: "/tmp/workspace", agentThread: true })).toThrow(
			"RE_SWARM_REAL_RECURSION_BLOCKED",
		);
	});

	it("keeps real execution when all process-isolation prerequisites are present", () => {
		expect(resolveSwarmExecutionMode({ execution: "real", cwd: "/tmp/workspace", agentThread: false })).toBe("real");
	});
});
