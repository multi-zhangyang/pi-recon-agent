import { describe, expect, it } from "vitest";
import { createOperatorFeedbackRuntime } from "../src/core/repi/operator-feedback-runtime.ts";

const runtime = createOperatorFeedbackRuntime({
	latestSwarmRetryQueue: () => ({ rows: [], commands: [] }),
});

function source(command: string, output: string, status: "done" | "blocked" = "done") {
	return {
		target: "package.json",
		commanderDispatchReport: [],
		executed: [{ stepId: "operator:1", command, status, output }],
	};
}

describe("operator feedback runtime", () => {
	it("does not classify successful control-plane plans as runtime evidence", () => {
		const rows = runtime.classifyOperatorFeedback(
			source(
				"re_kernel build package.json",
				"artifact: kernel.md next: re_map <target> payload exploit failed error blocked",
			),
		);

		expect(rows).toEqual([]);
		expect(
			runtime.classifyOperatorFeedback(
				source("re_tool_index refresh", "Tool | Present | exploit_lab | playwright | payload"),
			),
		).toEqual([]);
	});

	it("classifies unresolved targets from the executed command or an explicit diagnostic", () => {
		expect(runtime.classifyOperatorFeedback(source("re_map <target> 2", "plan"))[0]).toMatch(
			/category=unresolved_target/,
		);
		expect(
			runtime.classifyOperatorFeedback(source("re_map package.json 2", "target placeholder is unresolved"))[0],
		).toMatch(/category=unresolved_target/);
	});

	it("requires structured runtime-failure evidence instead of generic prose", () => {
		expect(
			runtime.classifyOperatorFeedback(source("re_map package.json 2", "failed hypotheses are blocked")),
		).toEqual([]);
		expect(runtime.classifyOperatorFeedback(source("re_map package.json 2", "exit_code=2"))[0]).toMatch(
			/category=runtime_failure/,
		);
		expect(runtime.classifyOperatorFeedback(source("re_map package.json 2", "anything", "blocked"))[0]).toMatch(
			/category=runtime_failure/,
		);
	});

	it("promotes concrete data-plane exploit signals", () => {
		const rows = runtime.classifyOperatorFeedback(
			source("re_native_runtime run ./sample", "crash RIP offset=72 payload artifact=/tmp/crash"),
		);

		expect(rows[0]).toMatch(/category=replay_or_exploit_candidate/);
		expect(rows[0]).toContain("next=re_exploit_lab run package.json 3 60000");
	});
});
