import type { AssistantMessage } from "@pi-recon/repi-ai";
import { Container } from "@pi-recon/repi-tui";
import { beforeAll, describe, expect, it, vi } from "vitest";
import type { SessionStats } from "../src/core/agent-session.ts";
import type { ModelPriceSource } from "../src/core/cache-stats.ts";
import { initTheme } from "../src/core/presentation/theme-runtime.ts";
import type { SessionEntry } from "../src/core/session-manager.ts";
import { InteractiveCommandRuntime } from "../src/modes/interactive/interactive-command-runtime.ts";
import { addCacheMissNotice } from "../src/modes/interactive/interactive-event-runtime.ts";
import { stripAnsi } from "../src/utils/ansi.ts";

interface SessionCommandContext {
	session: {
		getSessionStats(): SessionStats;
		modelRegistry: ModelPriceSource;
		sessionManager: SessionCommandContext["sessionManager"];
	};
	sessionManager: {
		getSessionName(): string | undefined;
		getEntries(): SessionEntry[];
	};
	chatContainer: Container;
	ui: { requestRender(): void };
}

function assistant(options: {
	id: string;
	cacheRead?: number;
	cacheWrite?: number;
	cost: AssistantMessage["usage"]["cost"];
	responseModel: string;
	timestamp: number;
}): SessionEntry {
	const message: AssistantMessage = {
		role: "assistant",
		content: [],
		api: "anthropic-messages",
		provider: "test",
		model: "router",
		responseModel: options.responseModel,
		usage: {
			input: 0,
			output: 10,
			cacheRead: options.cacheRead ?? 0,
			cacheWrite: options.cacheWrite ?? 0,
			totalTokens: 0,
			cost: options.cost,
		},
		stopReason: "stop",
		timestamp: options.timestamp,
	};
	return { type: "message", id: options.id, parentId: null, timestamp: "", message };
}

beforeAll(() => {
	initTheme("dark");
});

describe("cache miss interactive UI", () => {
	it("renders significant idle misses and suppresses low-signal notices", () => {
		const chatContainer = new Container();
		const context = { chatContainer };
		addCacheMissNotice(context as never, {
			missedTokens: 25_000,
			missedCost: 0.12,
			idleMs: 6 * 60_000,
			modelChanged: false,
		});
		expect(stripAnsi(chatContainer.render(120).join("\n"))).toContain(
			"Cache miss after 6m idle: 25k tokens re-billed (~$0.12)",
		);

		const childCount = chatContainer.children.length;
		addCacheMissNotice(context as never, {
			missedTokens: 2_000,
			missedCost: 0.001,
			idleMs: 0,
			modelChanged: false,
		});
		expect(chatContainer.children).toHaveLength(childCount);
	});

	it("shows authoritative total cost once and labels cache waste as included", () => {
		const zero = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 };
		const entries = [
			assistant({
				id: "one",
				cacheWrite: 100_000,
				cost: { ...zero, cacheWrite: 0.375, total: 0.375 },
				responseModel: "model-a",
				timestamp: 0,
			}),
			assistant({
				id: "two",
				cacheWrite: 110_000,
				cost: { ...zero, cacheWrite: 0.4125, total: 0.4125 },
				responseModel: "model-b",
				timestamp: 60_000,
			}),
		];
		const stats: SessionStats = {
			sessionFile: undefined,
			sessionId: "session-id",
			userMessages: 0,
			assistantMessages: 2,
			toolCalls: 0,
			toolResults: 0,
			totalMessages: 2,
			tokens: { input: 0, output: 20, cacheRead: 0, cacheWrite: 210_000, total: 210_020 },
			cost: 0.7875,
		};
		const chatContainer = new Container();
		const context: SessionCommandContext = {
			session: {
				getSessionStats: () => stats,
				sessionManager: { getSessionName: () => undefined, getEntries: () => entries },
				modelRegistry: {
					find: () => ({ cost: { input: 3, cacheRead: 0.3, cacheWrite: 3.75 } }),
				},
			},
			sessionManager: { getSessionName: () => undefined, getEntries: () => entries },
			chatContainer,
			ui: { requestRender: vi.fn() },
		};

		new InteractiveCommandRuntime(context as never).handleSessionCommand();
		const output = stripAnsi(chatContainer.render(160).join("\n"));
		expect(output).toContain("Total: $0.787");
		expect(output).toContain("test/model-a: $0.375");
		expect(output).toContain("test/model-b: $0.412");
		expect(output).toContain("Cache Re-billed (included): $0.345");
		expect(output).not.toContain("Total: $1.150");
	});
});
