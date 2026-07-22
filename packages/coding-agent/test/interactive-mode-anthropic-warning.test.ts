import { describe, expect, test, vi } from "vitest";
import { InteractiveSelectorRuntime } from "../src/modes/interactive/interactive-selector-runtime.ts";

function createSettingsManager(warnings: { anthropicExtraUsage?: boolean } = {}) {
	return {
		getWarnings: vi.fn().mockReturnValue(warnings),
	};
}

describe("InteractiveMode.maybeWarnAboutAnthropicSubscriptionAuth", () => {
	test("warns once when Anthropic subscription auth is detected", async () => {
		const fakeThis: any = {
			anthropicSubscriptionWarningShown: false,
			settingsManager: createSettingsManager(),
			session: {
				modelRegistry: {
					authStorage: {
						get: vi.fn().mockReturnValue(undefined),
					},
					getApiKeyForProvider: vi.fn().mockResolvedValue("sk-ant-oat01-test"),
				},
			},
			showWarning: vi.fn(),
		};

		const runtime = new InteractiveSelectorRuntime(fakeThis);
		await runtime.maybeWarnAboutAnthropicSubscriptionAuth({
			provider: "anthropic",
		});
		await runtime.maybeWarnAboutAnthropicSubscriptionAuth({
			provider: "anthropic",
		});

		expect(fakeThis.showWarning).toHaveBeenCalledTimes(1);
		expect(fakeThis.session.modelRegistry.getApiKeyForProvider).toHaveBeenCalledTimes(1);
	});

	test("warns when Anthropic OAuth is stored even if token refresh lookup would fail", async () => {
		const fakeThis: any = {
			anthropicSubscriptionWarningShown: false,
			settingsManager: createSettingsManager(),
			session: {
				modelRegistry: {
					authStorage: {
						get: vi.fn().mockReturnValue({ type: "oauth" }),
					},
					getApiKeyForProvider: vi.fn().mockResolvedValue(undefined),
				},
			},
			showWarning: vi.fn(),
		};

		await new InteractiveSelectorRuntime(fakeThis).maybeWarnAboutAnthropicSubscriptionAuth({
			provider: "anthropic",
		});

		expect(fakeThis.showWarning).toHaveBeenCalledTimes(1);
		expect(fakeThis.session.modelRegistry.getApiKeyForProvider).not.toHaveBeenCalled();
	});

	test("does not warn for non-Anthropic models", async () => {
		const fakeThis: any = {
			anthropicSubscriptionWarningShown: false,
			settingsManager: createSettingsManager(),
			session: {
				modelRegistry: {
					authStorage: {
						get: vi.fn(),
					},
					getApiKeyForProvider: vi.fn(),
				},
			},
			showWarning: vi.fn(),
		};

		await new InteractiveSelectorRuntime(fakeThis).maybeWarnAboutAnthropicSubscriptionAuth({
			provider: "openai",
		});

		expect(fakeThis.showWarning).not.toHaveBeenCalled();
		expect(fakeThis.session.modelRegistry.getApiKeyForProvider).not.toHaveBeenCalled();
	});

	test("does not warn when Anthropic extra usage warning is disabled", async () => {
		const fakeThis: any = {
			anthropicSubscriptionWarningShown: false,
			settingsManager: createSettingsManager({ anthropicExtraUsage: false }),
			session: {
				modelRegistry: {
					authStorage: {
						get: vi.fn(),
					},
					getApiKeyForProvider: vi.fn(),
				},
			},
			showWarning: vi.fn(),
		};

		await new InteractiveSelectorRuntime(fakeThis).maybeWarnAboutAnthropicSubscriptionAuth({
			provider: "anthropic",
		});

		expect(fakeThis.showWarning).not.toHaveBeenCalled();
		expect(fakeThis.session.modelRegistry.authStorage.get).not.toHaveBeenCalled();
		expect(fakeThis.session.modelRegistry.getApiKeyForProvider).not.toHaveBeenCalled();
	});
});
