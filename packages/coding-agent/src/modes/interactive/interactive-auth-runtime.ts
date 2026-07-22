import type { Model, OAuthProviderId, OAuthSelectPrompt } from "@pi-recon/repi-ai";
import type { Component, Container, EditorComponent, TUI } from "@pi-recon/repi-tui";
import { getAuthPath } from "../../config.ts";
import type { AgentSession } from "../../core/agent-session.ts";
import { ExtensionSelectorComponent } from "./components/extension-selector.ts";
import { LoginDialogComponent } from "./components/login-dialog.ts";
import { type AuthSelectorProvider, OAuthSelectorComponent } from "./components/oauth-selector.ts";

type SelectorFactory = (done: () => void) => { component: Component; focus: Component };

export type InteractiveAuthHost = {
	readonly session: AgentSession;
	readonly ui: TUI;
	readonly editorContainer: Container;
	readonly editor: EditorComponent;
	readonly footer: { invalidate(): void };
	showSelector(create: SelectorFactory): void;
	showStatus(message: string): void;
	showError(message: string): void;
	updateAvailableProviderCount(): Promise<void>;
	updateEditorBorderColor(): void;
	maybeWarnAboutAnthropicSubscriptionAuth(model?: Model<any>): Promise<void>;
};

function isUnknownModel(model: Model<any> | undefined): boolean {
	return !!model && model.provider === "unknown" && model.id === "unknown" && model.api === "unknown";
}

export function isApiKeyLoginProvider(providerId: string, oauthProviderIds: ReadonlySet<string>): boolean {
	// Provider IDs are user-defined. Only an explicitly registered OAuth flow
	// changes the login surface; every other configured provider uses an API key.
	return !oauthProviderIds.has(providerId);
}

function getLoginProviderOptions(host: InteractiveAuthHost, authType?: "oauth" | "api_key"): AuthSelectorProvider[] {
	const authStorage = host.session.modelRegistry.authStorage;
	const oauthProviders = authStorage.getOAuthProviders();
	const oauthProviderIds = new Set(oauthProviders.map((provider) => provider.id));
	const options: AuthSelectorProvider[] = oauthProviders.map((provider) => ({
		id: provider.id,
		name: provider.name,
		authType: "oauth",
	}));

	const modelProviders = new Set(host.session.modelRegistry.getAll().map((model) => model.provider));
	for (const providerId of modelProviders) {
		if (!isApiKeyLoginProvider(providerId, oauthProviderIds)) {
			continue;
		}
		options.push({
			id: providerId,
			name: host.session.modelRegistry.getProviderDisplayName(providerId),
			authType: "api_key",
		});
	}

	const filteredOptions = authType ? options.filter((option) => option.authType === authType) : options;
	return filteredOptions.sort((a, b) => a.name.localeCompare(b.name));
}

function getLogoutProviderOptions(host: InteractiveAuthHost): AuthSelectorProvider[] {
	const authStorage = host.session.modelRegistry.authStorage;
	const options: AuthSelectorProvider[] = [];

	for (const providerId of authStorage.list()) {
		const credential = authStorage.get(providerId);
		if (!credential) {
			continue;
		}
		options.push({
			id: providerId,
			name: host.session.modelRegistry.getProviderDisplayName(providerId),
			authType: credential.type,
		});
	}

	return options.sort((a, b) => a.name.localeCompare(b.name));
}

function showLoginAuthTypeSelector(host: InteractiveAuthHost): void {
	const subscriptionLabel = "Use a subscription";
	const apiKeyLabel = "Use an API key";
	host.showSelector((done) => {
		const selector = new ExtensionSelectorComponent(
			"Select authentication method:",
			[subscriptionLabel, apiKeyLabel],
			(option) => {
				done();
				const authType = option === subscriptionLabel ? "oauth" : "api_key";
				showLoginProviderSelector(host, authType);
			},
			() => {
				done();
				host.ui.requestRender();
			},
		);
		return { component: selector, focus: selector };
	});
}

function showLoginProviderSelector(host: InteractiveAuthHost, authType: "oauth" | "api_key"): void {
	const providerOptions = getLoginProviderOptions(host, authType);
	if (providerOptions.length === 0) {
		host.showStatus(
			authType === "oauth" ? "No subscription providers available." : "No API key providers available.",
		);
		return;
	}

	host.showSelector((done) => {
		const selector = new OAuthSelectorComponent(
			"login",
			host.session.modelRegistry.authStorage,
			providerOptions,
			async (providerId: string) => {
				done();

				const providerOption = providerOptions.find((provider) => provider.id === providerId);
				if (!providerOption) {
					return;
				}

				if (providerOption.authType === "oauth") {
					await showLoginDialog(host, providerOption.id, providerOption.name);
				} else {
					await showApiKeyLoginDialog(host, providerOption.id, providerOption.name);
				}
			},
			() => {
				done();
				showLoginAuthTypeSelector(host);
			},
			(providerId) => host.session.modelRegistry.getProviderAuthStatus(providerId),
		);
		return { component: selector, focus: selector };
	});
}

export async function showInteractiveAuthSelector(host: InteractiveAuthHost, mode: "login" | "logout"): Promise<void> {
	if (mode === "login") {
		showLoginAuthTypeSelector(host);
		return;
	}

	const providerOptions = getLogoutProviderOptions(host);
	if (providerOptions.length === 0) {
		host.showStatus(
			"No stored credentials to remove. /logout only removes credentials saved by /login; environment variables and models.json config are unchanged.",
		);
		return;
	}

	host.showSelector((done) => {
		const selector = new OAuthSelectorComponent(
			mode,
			host.session.modelRegistry.authStorage,
			providerOptions,
			async (providerId: string) => {
				done();

				const providerOption = providerOptions.find((provider) => provider.id === providerId);
				if (!providerOption) {
					return;
				}

				try {
					host.session.modelRegistry.authStorage.logout(providerOption.id);
					await host.session.modelRegistry.refresh();
					await host.updateAvailableProviderCount();
					const message =
						providerOption.authType === "oauth"
							? `Logged out of ${providerOption.name}`
							: `Removed stored API key for ${providerOption.name}. Environment variables and models.json config are unchanged.`;
					host.showStatus(message);
				} catch (error: unknown) {
					host.showError(`Logout failed: ${error instanceof Error ? error.message : String(error)}`);
				}
			},
			() => {
				done();
				host.ui.requestRender();
			},
		);
		return { component: selector, focus: selector };
	});
}

async function completeProviderAuthentication(
	host: InteractiveAuthHost,
	providerId: string,
	providerName: string,
	authType: "oauth" | "api_key",
	previousModel: Model<any> | undefined,
): Promise<void> {
	await host.session.modelRegistry.refresh();

	const actionLabel = authType === "oauth" ? `Logged in to ${providerName}` : `Saved API key for ${providerName}`;

	let selectedModel: Model<any> | undefined;
	let selectionError: string | undefined;
	if (isUnknownModel(previousModel)) {
		const availableModels = host.session.modelRegistry.getAvailable();
		const providerModels = availableModels.filter((model) => model.provider === providerId);
		if (providerModels.length === 0) {
			selectionError = `${actionLabel}, but no models are available for that provider. Use /model to select a model.`;
		} else {
			selectedModel = providerModels[0];
			try {
				await host.session.setModel(selectedModel);
			} catch (error: unknown) {
				selectedModel = undefined;
				const errorMessage = error instanceof Error ? error.message : String(error);
				selectionError = `${actionLabel}, but selecting the first available model failed: ${errorMessage}. Use /model to select a model.`;
			}
		}
	}

	await host.updateAvailableProviderCount();
	host.footer.invalidate();
	host.updateEditorBorderColor();
	if (selectedModel) {
		host.showStatus(`${actionLabel}. Selected ${selectedModel.id}. Credentials saved to ${getAuthPath()}`);
		void host.maybeWarnAboutAnthropicSubscriptionAuth(selectedModel);
	} else {
		host.showStatus(`${actionLabel}. Credentials saved to ${getAuthPath()}`);
		if (selectionError) {
			host.showError(selectionError);
		} else {
			void host.maybeWarnAboutAnthropicSubscriptionAuth();
		}
	}
}

async function showApiKeyLoginDialog(
	host: InteractiveAuthHost,
	providerId: string,
	providerName: string,
): Promise<void> {
	const previousModel = host.session.model;

	const dialog = new LoginDialogComponent(
		host.ui,
		providerId,
		(_success, _message) => {
			// Completion handled below
		},
		providerName,
	);

	host.editorContainer.clear();
	host.editorContainer.addChild(dialog);
	host.ui.setFocus(dialog);
	host.ui.requestRender();

	const restoreEditor = () => {
		host.editorContainer.clear();
		host.editorContainer.addChild(host.editor);
		host.ui.setFocus(host.editor);
		host.ui.requestRender();
	};

	try {
		const apiKey = (await dialog.showPrompt("Enter API key:")).trim();
		if (!apiKey) {
			throw new Error("API key cannot be empty.");
		}

		host.session.modelRegistry.authStorage.set(providerId, { type: "api_key", key: apiKey });

		restoreEditor();
		await completeProviderAuthentication(host, providerId, providerName, "api_key", previousModel);
	} catch (error: unknown) {
		restoreEditor();
		const errorMsg = error instanceof Error ? error.message : String(error);
		if (errorMsg !== "Login cancelled") {
			host.showError(`Failed to save API key for ${providerName}: ${errorMsg}`);
		}
	}
}

function showOAuthLoginSelect(
	host: InteractiveAuthHost,
	dialog: LoginDialogComponent,
	prompt: OAuthSelectPrompt,
): Promise<string | undefined> {
	return new Promise((resolve) => {
		const restoreDialog = () => {
			host.editorContainer.clear();
			host.editorContainer.addChild(dialog);
			host.ui.setFocus(dialog);
			host.ui.requestRender();
		};
		const labels = prompt.options.map((option) => option.label);
		const selector = new ExtensionSelectorComponent(
			prompt.message,
			labels,
			(optionLabel) => {
				restoreDialog();
				resolve(prompt.options.find((option) => option.label === optionLabel)?.id);
			},
			() => {
				restoreDialog();
				resolve(undefined);
			},
		);
		host.editorContainer.clear();
		host.editorContainer.addChild(selector);
		host.ui.setFocus(selector);
		host.ui.requestRender();
	});
}

async function showLoginDialog(host: InteractiveAuthHost, providerId: string, providerName: string): Promise<void> {
	const providerInfo = host.session.modelRegistry.authStorage
		.getOAuthProviders()
		.find((provider) => provider.id === providerId);
	const previousModel = host.session.model;

	// Providers that use callback servers (can paste redirect URL)
	const usesCallbackServer = providerInfo?.usesCallbackServer ?? false;

	// Create login dialog component
	const dialog = new LoginDialogComponent(
		host.ui,
		providerId,
		(_success, _message) => {
			// Completion handled below
		},
		providerName,
	);

	// Show dialog in editor container
	host.editorContainer.clear();
	host.editorContainer.addChild(dialog);
	host.ui.setFocus(dialog);
	host.ui.requestRender();

	// Promise for manual code input (racing with callback server)
	let manualCodeResolve: ((code: string) => void) | undefined;
	let manualCodeReject: ((err: Error) => void) | undefined;
	const manualCodePromise = new Promise<string>((resolve, reject) => {
		manualCodeResolve = resolve;
		manualCodeReject = reject;
	});

	// Restore editor helper
	const restoreEditor = () => {
		host.editorContainer.clear();
		host.editorContainer.addChild(host.editor);
		host.ui.setFocus(host.editor);
		host.ui.requestRender();
	};

	try {
		await host.session.modelRegistry.authStorage.login(providerId as OAuthProviderId, {
			onAuth: (info: { url: string; instructions?: string }) => {
				dialog.showAuth(info.url, info.instructions);

				if (usesCallbackServer) {
					// Show input for manual paste, racing with callback
					dialog
						.showManualInput("Paste redirect URL below, or complete login in browser:")
						.then((value) => {
							if (value && manualCodeResolve) {
								manualCodeResolve(value);
								manualCodeResolve = undefined;
							}
						})
						.catch(() => {
							if (manualCodeReject) {
								manualCodeReject(new Error("Login cancelled"));
								manualCodeReject = undefined;
							}
						});
				}
				// For Anthropic: onPrompt is called immediately after
			},

			onDeviceCode: (info) => {
				dialog.showDeviceCode(info);
				dialog.showWaiting("Waiting for authentication...");
			},

			onPrompt: async (prompt: { message: string; placeholder?: string }) => {
				return dialog.showPrompt(prompt.message, prompt.placeholder);
			},

			onProgress: (message: string) => {
				dialog.showProgress(message);
			},

			onSelect: (prompt: OAuthSelectPrompt) => showOAuthLoginSelect(host, dialog, prompt),

			onManualCodeInput: () => manualCodePromise,

			signal: dialog.signal,
		});

		// Success
		restoreEditor();
		await completeProviderAuthentication(host, providerId, providerName, "oauth", previousModel);
	} catch (error: unknown) {
		restoreEditor();
		const errorMsg = error instanceof Error ? error.message : String(error);
		if (errorMsg !== "Login cancelled") {
			host.showError(`Failed to login to ${providerName}: ${errorMsg}`);
		}
	}
}
