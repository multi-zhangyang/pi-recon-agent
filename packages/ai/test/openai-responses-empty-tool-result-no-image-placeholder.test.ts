import { describe, expect, it } from "vitest";
import { getModel } from "../src/models.ts";
import { convertResponsesMessages } from "../src/providers/openai-responses-shared.ts";
import type { AssistantMessage, Context, ImageContent, ToolResultMessage, Usage } from "../src/types.ts";

// opt #215: an openai-responses tool result with NO text used to always emit
// "(see attached image)" on the function_call_output, even when there were no
// images (e.g. a genuinely-empty result). The model was told an image was
// attached when none existed → it could hallucinate image content or ask for
// the image. The fix only claims an image when one is actually present (but
// couldn't be sent because the model lacks image input).

const usage: Usage = {
	input: 0,
	output: 0,
	cacheRead: 0,
	cacheWrite: 0,
	totalTokens: 0,
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
};

function buildAssistant(toolCallId: string, now: number): AssistantMessage {
	const model = getModel("openai-codex", "gpt-5.5");
	return {
		role: "assistant",
		content: [{ type: "toolCall", id: toolCallId, name: "edit", arguments: { path: "x.ts" } }],
		api: "openai-responses",
		provider: "openai-codex",
		model: model.id,
		usage,
		stopReason: "toolUse",
		timestamp: now - 1,
	};
}

function buildContext(
	toolCallId: string,
	content: ToolResultMessage["content"],
	isError: boolean,
	now: number,
): Context {
	const toolResult: ToolResultMessage = {
		role: "toolResult",
		toolCallId,
		toolName: "edit",
		content,
		isError,
		timestamp: now,
	};
	return {
		messages: [{ role: "user", content: "edit it", timestamp: now - 2 }, buildAssistant(toolCallId, now), toolResult],
	};
}

function stringOutput(input: ReturnType<typeof convertResponsesMessages>): string | undefined {
	const item = input.find(
		(i): i is { type: "function_call_output"; call_id: string; output: string } =>
			i.type === "function_call_output" && typeof (i as { output?: unknown }).output === "string",
	);
	return item?.output;
}

describe("opt #215: empty responses tool result does not claim an attached image", () => {
	it("emits empty output for a genuinely-empty successful tool result", () => {
		const now = Date.now();
		const model = getModel("openai-codex", "gpt-5.5");
		// Force a text-only model so the image branch is not taken.
		const textOnlyModel = { ...model, input: ["text"] as ("image" | "text")[] };
		const input = convertResponsesMessages(
			textOnlyModel,
			buildContext("call_empty|fc_empty", [], false, now),
			new Set(["openai", "openai-codex", "opencode"]),
		);
		const output = stringOutput(input);
		expect(output).toBeDefined();
		expect(output).toBe("");
		expect(output).not.toContain("(see attached image)");
	});

	it("emits only the error prefix for an empty failed tool result", () => {
		const now = Date.now();
		const model = getModel("openai-codex", "gpt-5.5");
		const textOnlyModel = { ...model, input: ["text"] as ("image" | "text")[] };
		const input = convertResponsesMessages(
			textOnlyModel,
			buildContext("call_err|fc_err", [], true, now),
			new Set(["openai", "openai-codex", "opencode"]),
		);
		const output = stringOutput(input);
		expect(output).toBeDefined();
		expect(output).toContain("[tool error]");
		expect(output).not.toContain("(see attached image)");
	});

	it("does not claim an attached image when the model cannot receive images (downgraded to a text placeholder)", () => {
		// For a non-vision model, transform-messages downgrades tool-result
		// images to a text placeholder BEFORE convertResponsesMessages sees them,
		// so hasImages is false here. The misleading "(see attached image)"
		// placeholder must NOT fire; the downgrade placeholder flows through.
		const now = Date.now();
		const model = getModel("openai-codex", "gpt-5.5");
		const textOnlyModel = { ...model, input: ["text"] as ("image" | "text")[] };
		const image: ImageContent = {
			type: "image",
			mimeType: "image/png",
			data: "iVBORw0KGgo=",
		};
		const input = convertResponsesMessages(
			textOnlyModel,
			buildContext("call_img|fc_img", [image], false, now),
			new Set(["openai", "openai-codex", "opencode"]),
		);
		const output = stringOutput(input);
		expect(output).toBeDefined();
		expect(output).toContain("(tool image omitted: model does not support images)");
		expect(output).not.toContain("(see attached image)");
	});

	it("replays a text tool result unchanged", () => {
		const now = Date.now();
		const model = getModel("openai-codex", "gpt-5.5");
		const textOnlyModel = { ...model, input: ["text"] as ("image" | "text")[] };
		const input = convertResponsesMessages(
			textOnlyModel,
			buildContext(
				"call_txt|fc_txt",
				[{ type: "text", text: "Successfully replaced 1 block(s) in x.ts." }],
				false,
				now,
			),
			new Set(["openai", "openai-codex", "opencode"]),
		);
		const output = stringOutput(input);
		expect(output).toContain("Successfully replaced");
		expect(output).not.toContain("(see attached image)");
	});
});
